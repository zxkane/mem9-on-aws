#!/usr/bin/env node
/**
 * Provision the AgentCore GatewayTarget (a **Lambda target**) via the direct
 * bedrock-agentcore-control `CreateGatewayTarget` API, wrapped by an SST
 * `command.local.Command` (see infra/gateway.ts).
 *
 * WHY A LAMBDA TARGET: the earlier ALB + self-managed-VPC-Lattice privateEndpoint
 * target failed to stabilize 100% of the time in the full CI deploy (an AgentCore
 * control-plane internal error on that combination in ap-northeast-1). A Lambda
 * target is AgentCore's out-of-the-box private path — no privateEndpoint, no
 * Lattice — so it sidesteps that failure. The gateway invokes a VPC-attached proxy
 * Lambda that reaches mnemo-server over Cloud Map DNS (see infra/gateway/
 * proxy-handler.mjs). This Command drives the target's lifecycle (create → poll to
 * READY; delete on teardown) so SST gets a real dependency edge on the Lambda.
 *
 * Contract (driven entirely by env vars, so the SST Command can pass Outputs):
 *   MEM9_TGT_OP           create | delete
 *   MEM9_TGT_GATEWAY_ID   gateway id (CreateGatewayTarget target)
 *   MEM9_TGT_NAME         target name (unique within the gateway)
 *   MEM9_TGT_REGION       AWS region
 *   -- create only --
 *   MEM9_TGT_DESCRIPTION  human description
 *   MEM9_TGT_LAMBDA_ARN   the proxy Lambda's ARN (AgentCore invokes it)
 *   MEM9_TGT_TOOL_SCHEMA  JSON array of ToolDefinition {name,description,inputSchema}
 *
 * create prints the created target id as the last stdout line (SST captures
 * stdout → the Command's `stdout` output). Idempotent: if a target with the
 * same name already exists it is reused (READY) or deleted+recreated (FAILED).
 */

import {
  BedrockAgentCoreControlClient,
  CreateGatewayTargetCommand,
  DeleteGatewayTargetCommand,
  GetGatewayTargetCommand,
  ListGatewayTargetsCommand,
} from "@aws-sdk/client-bedrock-agentcore-control";

const env = (k, required = true) => {
  const v = process.env[k];
  if (required && (v === undefined || v === "")) {
    throw new Error(`missing required env ${k}`);
  }
  return v;
};

const REGION = env("MEM9_TGT_REGION");
const GATEWAY_ID = env("MEM9_TGT_GATEWAY_ID");
const NAME = env("MEM9_TGT_NAME");
const OP = env("MEM9_TGT_OP");

const client = new BedrockAgentCoreControlClient({ region: REGION });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Find an existing target by name (list is small — one gateway, few targets). */
async function findTargetByName(name) {
  let nextToken;
  do {
    const res = await client.send(
      new ListGatewayTargetsCommand({ gatewayIdentifier: GATEWAY_ID, nextToken }),
    );
    const hit = (res.items ?? []).find((t) => t.name === name);
    if (hit) return hit;
    nextToken = res.nextToken;
  } while (nextToken);
  return undefined;
}

async function deleteTarget(targetId) {
  await client.send(
    new DeleteGatewayTargetCommand({ gatewayIdentifier: GATEWAY_ID, targetId }),
  );
  // Wait for it to actually disappear so a recreate with the same name won't
  // collide with a still-DELETING target. A FAILED/READY target deletes in
  // seconds in practice; cap at ~2 min so a slow delete can't dominate the
  // retry loop's wall-clock budget.
  for (let i = 0; i < 20; i++) {
    try {
      await client.send(
        new GetGatewayTargetCommand({ gatewayIdentifier: GATEWAY_ID, targetId }),
      );
    } catch (e) {
      if (e?.name === "ResourceNotFoundException") return;
      throw e;
    }
    await sleep(6_000);
  }
  throw new Error(`target ${targetId} did not finish deleting in time`);
}

// TargetStatus values that mean "still working" — keep polling. Anything else
// that isn't READY is a terminal error (FAILED, *_UNSUCCESSFUL) or a stuck
// pending-auth state; surfacing it with statusReasons is the whole point of this
// script (the CloudControl handler obscured exactly these).
const IN_PROGRESS_STATUSES = new Set([
  "CREATING",
  "CREATE_PENDING_AUTH",
  "SYNCHRONIZING",
  "SYNCHRONIZE_PENDING_AUTH",
  "UPDATING",
  "UPDATE_PENDING_AUTH",
]);

/** Poll a target to READY; throw with statusReasons on any terminal-error/stuck status or timeout. */
async function waitReady(targetId) {
  // ~6 min budget (target reaches READY in ~3.5 min in practice).
  for (let i = 0; i < 60; i++) {
    const res = await client.send(
      new GetGatewayTargetCommand({ gatewayIdentifier: GATEWAY_ID, targetId }),
    );
    if (res.status === "READY") return;
    if (!IN_PROGRESS_STATUSES.has(res.status)) {
      // FAILED / *_UNSUCCESSFUL / DELETING / any unexpected status — terminal.
      throw new Error(
        `GatewayTarget ${targetId} did not reach READY (status ${res.status}): ` +
          JSON.stringify(res.statusReasons ?? []),
      );
    }
    await sleep(6_000);
  }
  throw new Error(`GatewayTarget ${targetId} did not reach READY within the timeout`);
}

// One create-and-wait attempt. Returns the READY targetId, or throws (leaving no
// target — a FAILED one is deleted before throwing so the caller can cleanly retry).
async function createOnce(input) {
  const res = await client.send(new CreateGatewayTargetCommand(input));
  const targetId = res.targetId;
  console.error(`created target ${NAME} (${targetId}); waiting for READY...`);
  try {
    await waitReady(targetId);
  } catch (e) {
    // Clean up the non-READY target so a retry (same name) doesn't collide.
    console.error(`create attempt failed (${e?.message ?? e}); deleting ${targetId}`);
    await deleteTarget(targetId).catch((de) =>
      console.error(`  (cleanup delete failed, continuing: ${de?.message ?? de})`),
    );
    throw e;
  }
  console.error(`target ${NAME} (${targetId}) is READY`);
  return targetId;
}

/** Names of the tools an existing target exposes, for a schema-drift check on reuse. */
async function existingToolNames(targetId) {
  const res = await client.send(
    new GetGatewayTargetCommand({ gatewayIdentifier: GATEWAY_ID, targetId }),
  );
  const inline = res?.targetConfiguration?.mcp?.lambda?.toolSchema?.inlinePayload ?? [];
  return new Set(inline.map((t) => t.name));
}

async function create() {
  const lambdaArn = env("MEM9_TGT_LAMBDA_ARN");
  const toolSchema = JSON.parse(env("MEM9_TGT_TOOL_SCHEMA"));
  const description = env("MEM9_TGT_DESCRIPTION", false) ?? "";

  // Idempotency: a same-named target may already exist (retry/re-run). Reuse ONLY
  // if READY *and* its tool set matches the desired schema — otherwise delete and
  // recreate. Reusing a READY-but-stale target is exactly what silently kept the
  // old 2-tool schema on a tool-schema change (and, combined with a create-then-
  // delete replace, wiped the target entirely — see gateway.ts deleteBeforeReplace).
  const existing = await findTargetByName(NAME);
  if (existing) {
    const wantNames = new Set(toolSchema.map((t) => t.name));
    let sameTools = false;
    if (existing.status === "READY") {
      try {
        const haveNames = await existingToolNames(existing.targetId);
        sameTools =
          haveNames.size === wantNames.size && [...wantNames].every((n) => haveNames.has(n));
      } catch (e) {
        console.error(`  (could not read existing tools, will recreate: ${e?.message ?? e})`);
      }
    }
    if (existing.status === "READY" && sameTools) {
      console.error(
        `target ${NAME} already READY with matching tools (${existing.targetId}); reusing`,
      );
      console.log(existing.targetId);
      return;
    }
    const why = existing.status === "READY" ? "tool schema changed" : `status ${existing.status}`;
    console.error(`target ${NAME} exists (${why}); deleting to recreate`);
    await deleteTarget(existing.targetId);
  }

  // A LAMBDA target: AgentCore invokes the proxy Lambda (which reaches mnemo-server
  // privately via Cloud Map). toolSchema is the inline ToolDefinition[]; no
  // privateEndpoint (Lambda targets need none). Outbound auth to the Lambda is the
  // gateway's own IAM role (it holds lambda:InvokeFunction) → credentialProviderType
  // GATEWAY_IAM_ROLE. This block is REQUIRED even for a Lambda target — omitting it
  // is rejected with "Credential provider configurations is not defined". The
  // mnemo-server X-API-Key is injected downstream BY the Lambda, not here.
  const input = {
    gatewayIdentifier: GATEWAY_ID,
    name: NAME,
    description,
    targetConfiguration: {
      mcp: { lambda: { lambdaArn, toolSchema: { inlinePayload: toolSchema } } },
    },
    credentialProviderConfigurations: [{ credentialProviderType: "GATEWAY_IAM_ROLE" }],
  };

  // A light retry for generic control-plane transients. Unlike the removed
  // privateEndpoint path (which had a persistent internal-error flake needing a
  // heavy spaced-retry loop), a Lambda target reaches READY quickly, so a few
  // short-backoff attempts suffice. Bounded well under the 45-min CI budget.
  const BACKOFF_MS = 15_000;
  const MAX_ATTEMPTS = 3;
  let lastErr;
  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    try {
      const targetId = await createOnce(input);
      // Last stdout line = the id (SST Command captures stdout).
      console.log(targetId);
      return;
    } catch (e) {
      lastErr = e;
      console.error(`attempt ${attempt}/${MAX_ATTEMPTS} did not reach READY`);
      if (attempt < MAX_ATTEMPTS) await sleep(BACKOFF_MS);
    }
  }
  throw new Error(
    `GatewayTarget ${NAME} failed to reach READY after ${MAX_ATTEMPTS} attempt(s): ${lastErr?.message ?? lastErr}`,
  );
}

async function del() {
  // Deletes are best-effort: on stage teardown the gateway is deleted too, so a
  // missing target — or a missing GATEWAY (list throws ResourceNotFound) — is
  // success, not an error. Pulumi deletes this Command before its dependsOn
  // (gateway, proxy Lambda), so normally the gateway is still there; but a
  // partial/interrupted teardown could leave it gone, and we must not block.
  let existing;
  try {
    existing = await findTargetByName(NAME);
  } catch (e) {
    if (e?.name === "ResourceNotFoundException") {
      console.error(`gateway ${GATEWAY_ID} already gone; nothing to delete`);
      return;
    }
    throw e;
  }
  if (!existing) {
    console.error(`target ${NAME} not found; nothing to delete`);
    return;
  }
  console.error(`deleting target ${NAME} (${existing.targetId})`);
  await deleteTarget(existing.targetId);
  console.error(`target ${NAME} deleted`);
}

try {
  if (OP === "create") await create();
  else if (OP === "delete") await del();
  else throw new Error(`unknown MEM9_TGT_OP: ${OP}`);
} catch (e) {
  console.error(`provision-target ${OP} failed:`, e?.message ?? e);
  process.exit(1);
}
