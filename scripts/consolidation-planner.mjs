import { performance } from 'node:perf_hooks';
import { pathToFileURL } from 'node:url';
import { requireNamespaceId } from './lib/maintenance-scope.mjs';
import { createPlannerModelClient, plannerNeedsReview } from './lib/consolidation-model.mjs';

export const PLANNER_RUNTIME_MS = 50 * 60_000;
export const MODEL_TIMEOUT_MS = 110_000;
export const FINISH_MARGIN_MS = 15_000;
export const DISPATCH_MARGIN_MS = 11_000;

export function parsePlannerVerdict(text) {
  if (typeof text !== 'string' || Buffer.byteLength(text) > 4096) throw Error('invalid planner verdict');
  let value;
  try { value = JSON.parse(text); } catch { throw Error('invalid planner verdict'); }
  if (!value || Array.isArray(value) || Object.keys(value).length !== 1 ||
      !['MERGE', 'KEEP', 'REVIEW'].includes(value.result)) throw Error('invalid planner verdict');
  return value.result;
}

export async function runConsolidationPlanner(deps, {
  runtimeMs = PLANNER_RUNTIME_MS, providerTimeoutMs = MODEL_TIMEOUT_MS, finishMarginMs = FINISH_MARGIN_MS,
  dispatchMarginMs = DISPATCH_MARGIN_MS, now = () => performance.now(),
} = {}) {
  if (!Number.isSafeInteger(runtimeMs) || runtimeMs < 1000 || runtimeMs > 50 * 60_000 ||
      !Number.isSafeInteger(providerTimeoutMs) || providerTimeoutMs < 1 || providerTimeoutMs > 110_000 ||
      !Number.isSafeInteger(finishMarginMs) || finishMarginMs < 1 || finishMarginMs > FINISH_MARGIN_MS ||
      !Number.isSafeInteger(dispatchMarginMs) || dispatchMarginMs < 1 || dispatchMarginMs > DISPATCH_MARGIN_MS) throw Error('invalid planner runtime');
  const deadline = now() + runtimeMs;
  const report = { claimed: 0, cacheHits: 0, modelCalls: 0, queued: 0, existing: 0, keep: 0, review: 0,
    blocked: 0, deferred: 0, stopReason: 'deadline' };
  await deps.maintain();
  while (now() < deadline) {
    await deps.consume?.();
    if (now() >= deadline) break;
    if (report.claimed > 0 && report.claimed % 100 === 0) await deps.maintain();
    const work = await deps.claim();
    if (work.status === 'retry') { report.deferred++; continue; }
    if (work.status === 'idle') { report.stopReason = 'idle'; break; }
    if (work.status === 'blocked') { report.blocked++; continue; }
    if (work.status !== 'leased' || !Array.isArray(work.members) || work.members.length > 10) throw Error('invalid planner lease');
    report.claimed++;
    if (now() >= deadline) { await deps.defer(work, 'deadline'); break; }
    let verdict;
    if (work.forced_result) verdict = parsePlannerVerdict(JSON.stringify({ result: work.forced_result }));
    else if (work.cached) {
      verdict = parsePlannerVerdict(JSON.stringify({ result: work.cached.payload?.result }));
      report.cacheHits++;
    } else if (work.members.length < 2) verdict = 'KEEP';
    else if (work.members.every(m => typeof m.memory?.content === 'string' && m.memory.content === work.members[0].memory.content)) verdict = 'MERGE';
    else if (deps.needsReview && await deps.needsReview(work)) verdict = 'REVIEW';
    else {
      if (deadline - now() < providerTimeoutMs + finishMarginMs + dispatchMarginMs) { await deps.defer(work, 'deadline'); break; }
      const admission = await deps.reserve(work, Math.floor(deadline - now()));
      if (admission.status !== 'admitted') {
        if (!['budget_wait', 'capacity_wait', 'uncertainty_wait', 'model_disabled', 'policy_wait', 'deadline', 'existing'].includes(admission.status)) throw Error('invalid model admission');
        await deps.defer(work, admission.status); report.deferred++; continue;
      }
      let response;
      try {
        // The transport also checks the remaining run margin after bearer mint
        // and before its single dispatch; an admitted retry is a separate lease.
        response = await deps.infer(work, admission, providerTimeoutMs, () => deadline - now() >= providerTimeoutMs + finishMarginMs + dispatchMarginMs);
        report.modelCalls++;
      } catch (error) {
        if (error?.dispatchStarted === false) {
          await deps.cancel?.(admission);
          await deps.defer(work, error.deferReason === 'policy_wait' ? 'policy_wait' : 'invalid_result'); report.deferred++; continue;
        }
        report.modelCalls++;
        await deps.settle(work, admission, null);
        await deps.defer(work, 'model_failed'); report.deferred++; continue;
      }
      const settled = await deps.settle(work, admission, response.usage ?? { invalid: true });
      if (settled.status === 'contract_violation') { report.stopReason = 'contract_violation'; break; }
      if (settled.status !== 'settled') { await deps.defer(work, 'invalid_result'); report.deferred++; continue; }
      try { verdict = parsePlannerVerdict(response.text); }
      catch { await deps.defer(work, 'invalid_result'); report.deferred++; continue; }
    }
    let finished;
    try { finished = await deps.finish(work, verdict); }
    catch (error) {
      finished = await deps.recover(work);
      if (!finished) {
        if (error.code === '55000' || error.code === '40P01' || error.code === '55P03' || (error.code === '22023' && work.cached)) {
          await deps.defer(work, 'inputs_changed'); report.deferred++; continue;
        }
        report.stopReason = 'pending_publication'; break;
      }
    }
    if (!['queued', 'existing', 'keep', 'review'].includes(finished.status)) throw Error('invalid planner publication');
    report[finished.status]++;
  }
  report.backlog = await deps.status();
  return report;
}

export function createPlannerDatabase(db, namespaceId) {
  const scalar = async (sql, args = []) => (await db.query(sql, [namespaceId, ...args])).rows[0].result;
  const lease = work => [work.anchor_id, work.lease_generation];
  return {
    consume: () => scalar('SELECT mem9_maintenance.consume_planner_changes($1,1000) AS result'),
    maintain: async () => {
      await scalar('SELECT mem9_maintenance.consume_planner_changes($1,1000) AS result');
      await scalar('SELECT mem9_maintenance.sweep_due($1,100) AS result');
      await scalar('SELECT mem9_maintenance.audit_planner($1,1000) AS result');
      await scalar('SELECT mem9_maintenance.planner_status($1) AS result');
    },
    claim: () => scalar('SELECT mem9_maintenance.claim_neighborhood($1) AS result'),
    reserve: (work, remaining) => scalar('SELECT mem9_maintenance.reserve_planner_model($1,$2,$3,$4) AS result', [...lease(work), remaining]),
    dispatch: admission => scalar('SELECT mem9_maintenance.dispatch_planner_model($1,$2) AS result', [admission.attempt_id]),
    cancel: admission => scalar('SELECT mem9_maintenance.cancel_planner_model($1,$2) AS result', [admission.attempt_id]),
    settle: (_work, admission, usage) => scalar('SELECT mem9_maintenance.settle_planner_model($1,$2,$3) AS result', [admission.attempt_id, usage]),
    finish: (work, verdict) => scalar('SELECT mem9_maintenance.finish_neighborhood($1,$2,$3,$4) AS result', [...lease(work), verdict]),
    recover: work => scalar('SELECT mem9_maintenance.planner_receipt($1,$2,$3) AS result', lease(work)),
    defer: (work, reason) => scalar('SELECT mem9_maintenance.defer_neighborhood($1,$2,$3,$4) AS result', [...lease(work), reason]),
    status: () => scalar('SELECT mem9_maintenance.planner_status($1) AS result'),
  };
}

async function main() {
  const started = performance.now();
  // Includes initialization/final status and catches a stalled credential
  // provider. Database receipts/leases, not this process, own crash recovery.
  const watchdog = setTimeout(() => {
    process.stdout.write(JSON.stringify({ event: 'consolidation_planner_failed', errorClass: 'Deadline' }) + '\n');
    process.exit(1);
  }, PLANNER_RUNTIME_MS);
  watchdog.unref();
  const namespace = requireNamespaceId(process.env.MEM9_NAMESPACE_ID);
  const stage = process.env.MEM9_STAGE;
  if (!stage || !/^[a-zA-Z0-9][a-zA-Z0-9-]{0,63}$/.test(stage)) throw Error('planner stage required');
  const credentials = JSON.parse(process.env.MEM9_PLANNER_DB_SECRET || 'null');
  if (!credentials || typeof credentials.username !== 'string' || typeof credentials.password !== 'string' ||
      !process.env.MEM9_DB_HOST || !process.env.MEM9_DB_NAME) throw Error('planner configuration incomplete');
  const { default: pg } = await import('pg');
  const db = new pg.Client({ host: process.env.MEM9_DB_HOST, port: Number(process.env.MEM9_DB_PORT || 5432),
    database: process.env.MEM9_DB_NAME, user: credentials.username, password: credentials.password, ssl: { rejectUnauthorized: true },
    connectionTimeoutMillis: 3000, statement_timeout: 10000, query_timeout: 11000, application_name: 'mem9-consolidation-planner' });
  await db.connect();
  try {
    const deps = createPlannerDatabase(db, namespace);
    deps.needsReview = work => plannerNeedsReview(work, process.env);
    const mintToken = async region => {
      const [{ getToken }, { fromNodeProviderChain }] = await Promise.all([
        import('@aws/bedrock-token-generator'), import('@aws-sdk/credential-providers'),
      ]);
      return getToken({ credentials: await fromNodeProviderChain()(), region, expiresInSeconds: 3600 });
    };
    deps.infer = createPlannerModelClient({ mintToken, dispatch: deps.dispatch, env: process.env });
    const slice = process.env.MEM9_CONSOLIDATION_SLICE_SECONDS;
    if (slice !== undefined && (!/^[1-9][0-9]*$/.test(slice) || Number(slice) > 3000)) throw Error('invalid planner slice');
    const runtimeMs = Math.floor(Math.min(PLANNER_RUNTIME_MS - (performance.now() - started) - FINISH_MARGIN_MS,
      slice === undefined ? PLANNER_RUNTIME_MS : Number(slice) * 1000));
    const report = await runConsolidationPlanner(deps, { runtimeMs });
    process.stdout.write(JSON.stringify({ event: 'consolidation_planner', stage, ...report }) + '\n');
    if (['contract_violation', 'pending_publication'].includes(report.stopReason)) process.exitCode = 1;
  } finally { clearTimeout(watchdog); await db.end(); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(error => {
    process.stdout.write(JSON.stringify({ event: 'consolidation_planner_failed', errorClass: /^[A-Z0-9]{5}$/.test(error.code || '') ? error.code : 'PlannerError' }) + '\n');
    process.exitCode = 1;
  });
}
