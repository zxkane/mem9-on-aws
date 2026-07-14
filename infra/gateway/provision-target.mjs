#!/usr/bin/env node
/**
 * Provision the AgentCore GatewayTarget via the DIRECT bedrock-agentcore-control
 * API — NOT CloudControl.
 *
 * WHY THIS SCRIPT EXISTS (proven root cause, 2026-07-14): the identical target
 * config (self-managed VPC Lattice privateEndpoint + inline OpenAPI schema +
 * API-key credential provider, servers.url = mem9.aws.kane.mx) reaches READY in
 * ~3.5 min via a direct `CreateGatewayTarget` SDK/boto3 call, but FAILEDs every
 * time (~20 CI iterations) when created through `aws.cloudcontrol.Resource`
 * (AWS::BedrockAgentCore::GatewayTarget): CloudControl's handler returns
 * "NotStabilized: FAILED, internal error". So CloudControl's GatewayTarget
 * handler is broken for the PrivateEndpoint path in ap-northeast-1, while the
 * underlying API is fine. This script drives that proven-working API directly,
 * wrapped by an SST `command.local.Command` (see infra/gateway.ts).
 *
 * Contract (driven entirely by env vars, so the SST Command can pass Outputs):
 *   MEM9_TGT_OP                  create | delete
 *   MEM9_TGT_GATEWAY_ID          gateway id (CreateGatewayTarget target)
 *   MEM9_TGT_NAME                target name (unique within the gateway)
 *   MEM9_TGT_REGION              AWS region
 *   -- create only --
 *   MEM9_TGT_DESCRIPTION         human description
 *   MEM9_TGT_SCHEMA              inline OpenAPI schema (string)
 *   MEM9_TGT_APIKEY_PROVIDER_ARN API-key credential-provider ARN
 *   MEM9_TGT_APIKEY_HEADER       header name (X-API-Key)
 *   MEM9_TGT_LATTICE_RC_ARN      self-managed Lattice ResourceConfiguration ARN
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

async function create() {
  const schema = env("MEM9_TGT_SCHEMA");
  const apiKeyProviderArn = env("MEM9_TGT_APIKEY_PROVIDER_ARN");
  const apiKeyHeader = env("MEM9_TGT_APIKEY_HEADER");
  const latticeRcArn = env("MEM9_TGT_LATTICE_RC_ARN");
  const description = env("MEM9_TGT_DESCRIPTION", false) ?? "";

  // Idempotency: a same-named target may already exist (retry/re-run). Reuse if
  // READY; otherwise delete the stale/failed one and recreate cleanly.
  const existing = await findTargetByName(NAME);
  if (existing) {
    if (existing.status === "READY") {
      console.error(`target ${NAME} already READY (${existing.targetId}); reusing`);
      console.log(existing.targetId);
      return;
    }
    console.error(
      `target ${NAME} exists in status ${existing.status}; deleting to recreate`,
    );
    await deleteTarget(existing.targetId);
  }

  const input = {
    gatewayIdentifier: GATEWAY_ID,
    name: NAME,
    description,
    targetConfiguration: { mcp: { openApiSchema: { inlinePayload: schema } } },
    credentialProviderConfigurations: [
      {
        credentialProviderType: "API_KEY",
        credentialProvider: {
          apiKeyCredentialProvider: {
            providerArn: apiKeyProviderArn,
            credentialLocation: "HEADER",
            credentialParameterName: apiKeyHeader,
          },
        },
      },
    ],
    privateEndpoint: {
      selfManagedLatticeResource: { resourceConfigurationIdentifier: latticeRcArn },
    },
  };

  // Retry on the AgentCore control-plane flake: CreateGatewayTarget with a
  // self-managed-Lattice privateEndpoint sometimes lands the target in FAILED with
  // "The server encountered an internal error while processing the request. Retry
  // the request later."
  //
  // NATURE (measured across several live runs): a genuinely INTERMITTENT flake, NOT
  // deterministic. Observed BOTH: (a) a CI deploy where every attempt in a tight
  // ~35s burst FAILED (~7s each), and (b) fresh-gateway targets that reached READY
  // on the FIRST attempt at +0s. So the error clusters in short windows — the cure
  // is SPACED retries (independent samples across minutes), plus a small upfront
  // settle for the freshness-correlated case.
  //
  // We bound BOTH by attempt count AND wall-clock, whichever hits first. The
  // wall-clock cap is the real guard: an individual attempt can, in the worst case,
  // burn ~6 min in waitReady + ~4 min in the post-FAILED delete-wait, so a pure
  // count bound could blow the 45-min CI Deploy budget. DEADLINE_MS (25 min from the
  // first attempt) keeps the whole loop safely under it, leaving room for the rest
  // of the stack. In practice attempts fail/succeed in seconds, so many samples fit.
  const SETTLE_MS = 30_000; // brief settle for the freshness-correlated failures
  const BACKOFF_MS = 60_000; // space attempts so they sample different flake windows
  const MAX_ATTEMPTS = 12;
  const DEADLINE_MS = 25 * 60_000;
  console.error(`waiting ${SETTLE_MS / 1000}s before the first create attempt...`);
  await sleep(SETTLE_MS);
  const startedAt = Date.now();
  let lastErr;
  let attempts = 0;
  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    if (Date.now() - startedAt > DEADLINE_MS) {
      console.error(`retry deadline (${DEADLINE_MS / 60_000} min) reached; giving up`);
      break;
    }
    attempts = attempt;
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
    `GatewayTarget ${NAME} failed to reach READY after ${attempts} attempt(s): ${lastErr?.message ?? lastErr}`,
  );
}

async function del() {
  // Deletes are best-effort: on stage teardown the gateway is deleted too, so a
  // missing target — or a missing GATEWAY (list throws ResourceNotFound) — is
  // success, not an error. Pulumi deletes this Command before its dependsOn
  // (gateway, api-key provider), so normally the gateway is still there; but a
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
