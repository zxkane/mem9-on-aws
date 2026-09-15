import { HumanAcceptanceError } from "./human-namespace-acceptance.mjs";
import { setTimeout as delay } from "node:timers/promises";
import { HumanMcpClient } from "./human-namespace-browser.mjs";

const check = (condition, name) => {
  if (!condition) throw new HumanAcceptanceError(name);
};
async function poll(work, complete, failure, seconds = 180) {
  const deadline = Date.now() + seconds * 1000;
  while (Date.now() < deadline) {
    const value = await work();
    if (complete(value)) return value;
    await delay(1500);
  }
  throw new HumanAcceptanceError(failure);
}

export async function runHumanNamespaceScenarios({
  fixture,
  oauth,
  gatewayUrl,
  onToken = () => {},
  signal,
  readDenialStatus,
}) {
  const clients = new Map();
  const login = async (alias) => {
    await fixture.user(alias);
    const token = await oauth.login({
      ...fixture.identity(alias),
      subject: fixture.subjects.get(alias),
    });
    onToken(token);
    const client = await new HumanMcpClient({
      url: gatewayUrl,
      token,
      signal,
      readDenialStatus,
    }).initialize();
    clients.set(alias, client);
    return client;
  };
  const report = fixture.report;
  const marker = (purpose) =>
    `namespace-human-${fixture.plan.runId}-${purpose}`;
  const add = async (client, label, extra = {}) =>
    client.call("add_memory", {
      content: `Synthetic shared team fixture ${label} α🌱`,
      memory_type: "pinned",
      agent_id: fixture.agentId,
      ...extra,
    });
  const find = async (client, label) => {
    const result = await poll(
      () => client.search(label),
      (x) => x.memories.some((m) => m.content?.includes(label)),
      "memory_visibility_timeout",
    );
    const matches = result.memories.filter((m) => m.content?.includes(label));
    check(
      matches.length === 1 && typeof matches[0].id === "string",
      "memory_identity_not_unique",
    );
    return matches[0].id;
  };
  const absent = async (client, label) => {
    const result = await client.search(label);
    check(
      result.total === 0 && result.memories.length === 0,
      "foreign_memory_visible",
    );
  };
  let denialSequence = 0;
  const deny = (client, expectedStatus = 403) =>
    client.call(
      "search_memories",
      { q: marker(`denial-${++denialSequence}`), search_mode: "keyword" },
      { denied: true, expectedStatus },
    );
  const ingest = async (client, session) => {
    const result = await client.call("ingest_messages", {
      agent_id: fixture.agentId,
      session_id: session,
      mode: "smart",
      messages: [
        {
          role: "user",
          content: `The synthetic project ${session} uses blue as its established documentation accent color.`,
        },
      ],
    });
    check(
      typeof result.job_id === "string" && result.job_id.length > 0,
      "ingest_job_id_missing",
    );
    return result.job_id;
  };
  const succeeded = async (client, id) =>
    poll(
      async () => {
        const result = await client.call("get_ingest_job_status", {
          job_id: id,
        });
        check(
          result.job_id === id && result.state !== "dead",
          "durable_job_failed",
        );
        return result;
      },
      (x) => x.state === "succeeded",
      "durable_job_completion_timeout",
      300,
    );

  for (const alias of [
    "writer",
    "peer",
    "other",
    "none",
    "multi",
    "mover",
    "revoked",
    "never_used",
    "emergency",
    "concurrent",
    "viewer",
  ])
    await login(alias);
  report("real_human_oauth_pkce_and_15_minute_tokens");
  const writer = clients.get("writer"),
    peer = clients.get("peer"),
    other = clients.get("other");
  await add(writer, marker("alpha"), {
    namespace_id: "forged-namespace",
    namespace_slug: "preview-beta",
    __mem9_auth_v2: { v: 0, principal_key: "forged" },
  });
  const alphaId = await find(writer, marker("alpha"));
  check(
    (await find(peer, marker("alpha"))) === alphaId,
    "same_team_did_not_share_memory",
  );
  await absent(other, marker("alpha"));
  await add(other, marker("beta"));
  const betaId = await find(other, marker("beta"));
  check(alphaId !== betaId, "cross_namespace_memory_id_coalesced");
  await absent(writer, marker("beta"));
  await absent(peer, marker("beta"));
  report(
    "same_group_sharing_cross_group_denial_and_caller_context_replacement",
  );
  for (const alias of ["none", "multi"])
    await deny(clients.get(alias), alias === "multi" ? 409 : 403);
  for (const alias of ["mover", "revoked", "emergency"])
    await clients.get(alias).search(marker("jit"));
  await Promise.all([
    clients.get("concurrent").search(marker("jit-a")),
    clients.get("concurrent").search(marker("jit-b")),
  ]);
  await fixture.assertInitialJit();
  report("zero_multiple_unrelated_groups_and_concurrent_first_use");

  check(
    (await fixture.access("never_used", "show-user")).principal_status ===
      "absent",
    "unused_user_already_enrolled",
  );
  await fixture.access("never_used", "revoke-user");
  await deny(clients.get("never_used"));
  const unused = await fixture.access("never_used", "show-user");
  check(
    unused.active_memberships === 0 && unused.revoked_memberships >= 2,
    "unused_user_revocation_not_tombstoned",
  );
  report("managed_revoke_before_first_use_blocks_stale_token_jit");

  await fixture.access("viewer", "assign-user", { target: 1, role: "viewer" });
  check(
    (await find(clients.get("viewer"), marker("beta"))) === betaId,
    "viewer_read_denied",
  );
  await clients
    .get("viewer")
    .call(
      "add_memory",
      {
        content: `Synthetic forbidden viewer write ${marker("viewer-denial")}`,
        memory_type: "pinned",
      },
      { denied: true },
    );
  report("membership_role_and_token_scope_intersection");

  await fixture.changeGroup("concurrent", 0, false);
  await fixture.changeGroup("concurrent", 1, true);
  await deny(await login("concurrent"), 409);
  check(
    (await fixture.access("concurrent", "show-user")).active_memberships === 1,
    "group_drift_created_second_membership",
  );
  await fixture.changeGroup("concurrent", 1, false);
  await fixture.changeGroup("concurrent", 0, true);
  await find(await login("concurrent"), marker("alpha"));
  report("direct_group_drift_fails_closed");

  let mover = await login("mover");
  const staleA = mover;
  await add(mover, marker("mover-alpha"));
  await find(peer, marker("mover-alpha"));
  await fixture.failedMove();
  await deny(staleA);
  await deny(await login("mover"));
  await fixture.access("mover", "move-user", { target: 1 });
  await fixture.assertPlacement("mover", 1);
  mover = await login("mover");
  const staleB = mover;
  await absent(mover, marker("mover-alpha"));
  await find(mover, marker("beta"));
  await add(mover, marker("mover-beta"));
  await find(other, marker("mover-beta"));
  await fixture.access("mover", "move-user", { target: 0 });
  await fixture.assertPlacement("mover", 0);
  await deny(staleB);
  mover = await login("mover");
  await find(mover, marker("mover-alpha"));
  await absent(mover, marker("mover-beta"));
  await find(other, marker("mover-beta"));
  report("failed_grant_retry_a_b_a_and_original_team_data_ownership");
  await fixture.faultMatrix();
  await fixture.concurrentMoves();

  // Observe the server's actual tenant/app ordering fields from a human job.
  const probe = await ingest(writer, marker("scope-probe"));
  await succeeded(peer, probe);
  await fixture.observeJobScope("writer", probe);
  for (const [alias, emergency] of [
    ["revoked", false],
    ["emergency", true],
  ]) {
    const client = await login(alias),
      session = marker(alias);
    await fixture.blockSession(alias, session);
    const id = await ingest(client, session);
    check(
      (await fixture.jobState(alias, id)) === "queued",
      "fixture_fifo_barrier_did_not_hold_job",
    );
    await fixture.access(alias, emergency ? "emergency" : "revoke-user");
    await fixture.assertPlacement(alias, null, { disabled: emergency });
    await deny(client);
    if (emergency) {
      check(
        (await fixture.jobState(alias, id)) === "dead",
        "emergency_revoke_did_not_cancel",
      );
      const status = await peer.call("get_ingest_job_status", { job_id: id });
      check(
        status.state === "dead" &&
          status.error_class === "principal_emergency_revoked",
        "team_job_cancel_status_wrong",
      );
    } else {
      check(
        (await fixture.jobState(alias, id)) === "queued",
        "normal_revoke_cancelled_accepted_work",
      );
      await fixture.releaseSession(alias);
      await succeeded(peer, id);
    }
    await fixture.releaseSession(alias);
    report(
      emergency
        ? "emergency_revocation_cancels_queued_work"
        : "normal_revocation_preserves_accepted_team_work",
    );
  }
}
