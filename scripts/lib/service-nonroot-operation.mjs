import {isDeepStrictEqual as equal} from 'node:util';
import {registrationInput, hardenServiceRegistration, serviceNonrootHash as hash} from './service-nonroot.mjs';

const MAX_AGE = 30 * 60_000, POLLS = 120, INTERVAL = 5_000;
const need = (value, code) => {if (!value) throw Error(`service-nonroot:${code}`);};
const object = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const digest = v => typeof v === 'string' && /^[a-f0-9]{64}$/.test(v);
const copy = v => JSON.parse(JSON.stringify(v)); // Normalize SDK Date values to immutable JSON evidence.
const freeze = v => {if (object(v) || Array.isArray(v)) {Object.values(v).forEach(freeze); Object.freeze(v);} return v;};
const observations = new Set(['events', 'deployments', 'runningCount', 'pendingCount', 'createdAt', 'updatedAt']);
const config = service => Object.fromEntries(Object.entries(service).filter(([key]) => !observations.has(key)));
const records = ['register-intent', 'register-result', 'update-intent', 'update-result', 'complete'];
const recordName = (plan, name) => `service-nonroot-${plan.hash}-${name}.json`;
async function bounded(action, timeout) {
  let timer;
  try {
    return await Promise.race([Promise.resolve().then(action), new Promise((_, reject) => {
      timer = setTimeout(() => reject(Error('service-nonroot:adapter-timeout')), Math.max(1, timeout));
    })]);
  } finally {clearTimeout(timer);}
}
function checkSource(source) {
  need(object(source) && source.clean === true && ['commit', 'tree'].every(k => typeof source[k] === 'string' && /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/.test(source[k])), 'source');
}
function checkScope(scope, service) {
  need(object(scope) && /^\d{12}$/.test(scope.accountId) && /^[a-z]{2}(?:-[a-z]+)+-\d+$/.test(scope.region), 'scope');
  const root = `arn:aws:ecs:${scope.region}:${scope.accountId}:`;
  need(typeof scope.clusterArn === 'string' && scope.clusterArn.startsWith(`${root}cluster/`), 'cluster');
  const cluster = scope.clusterArn.slice(`${root}cluster/`.length);
  need(/^[\w-]+$/.test(cluster) && scope.serviceArn === `${root}service/${cluster}/${service.serviceName}`, 'service-identity');
  need(service.serviceArn === scope.serviceArn && service.clusterArn === scope.clusterArn && service.status === 'ACTIVE', 'service-identity');
  return root;
}
function checkDefinition(response, arn) {
  need(response?.taskDefinition?.taskDefinitionArn === arn && response.taskDefinition.status === 'ACTIVE' && Array.isArray(response.tags), 'definition-tags-or-identity');
  return registrationInput(response);
}
function settled(service, arn) {
  return service.taskDefinition === arn && service.runningCount === service.desiredCount && service.pendingCount === 0 &&
    Array.isArray(service.deployments) && service.deployments.length === 1 && service.deployments.every(d =>
      d.status === 'PRIMARY' && d.taskDefinition === arn && d.rolloutState === 'COMPLETED' &&
      d.desiredCount === service.desiredCount && d.runningCount === service.desiredCount && d.pendingCount === 0);
}
function deploymentConfiguration(plan) {
  const original = plan.baseline.service.deploymentConfiguration;
  return {...original, minimumHealthyPercent: 100, maximumPercent: 200,
    deploymentCircuitBreaker: {...original?.deploymentCircuitBreaker, enable: true, rollback: false}};
}

/** Pure data, not authority. Evidence values are SHA-256 hashes of independently
 * reviewed artifacts; the static adapter must authenticate/check their contents.
 * scope: {accountId,region,clusterArn,serviceArn}; source: {commit,tree,clean:true}.
 * evidence: {review,images,local,preview,fences,maintenance}; owner: operator ID.
 * definition is DescribeTaskDefinition with TAGS; service is the full service.
 * now is epoch milliseconds. No historical maintenance evidence is rewritten. */
export function buildServiceNonrootPlan({scope, source, service, definition, evidence, owner, now = Date.now()}) {
  checkSource(source);
  need(object(service), 'service');
  const root = checkScope(scope, service), original = checkDefinition(definition, service.taskDefinition);
  need(typeof original.family === 'string' && /^[\w-]+$/.test(original.family) &&
    service.taskDefinition === `${root}task-definition/${original.family}:${definition.taskDefinition.revision}` &&
    Number.isSafeInteger(definition.taskDefinition.revision) && definition.taskDefinition.revision > 0, 'baseline-arn');
  need(Number.isSafeInteger(service.desiredCount) && service.desiredCount > 0 && settled(service, service.taskDefinition), 'baseline-not-stable');
  need(service.deploymentController?.type === 'ECS' && object(service.deploymentConfiguration) &&
    service.deploymentConfiguration.alarms?.rollback !== true &&
    [undefined, 'ROLLING'].includes(service.deploymentConfiguration.strategy), 'deployment-controller-or-rollback');
  need(typeof owner === 'string' && owner.trim() === owner && owner.length > 0 && owner.length <= 256, 'owner');
  need(object(evidence) && ['review', 'images', 'local', 'preview', 'fences', 'maintenance'].every(k => digest(evidence[k])), 'evidence');
  need(Number.isSafeInteger(now) && now >= 0 && now <= Number.MAX_SAFE_INTEGER - MAX_AGE, 'time');
  const target = hardenServiceRegistration(original);
  need(target.containerDefinitions.every(c => typeof c.image === 'string' && /@sha256:[a-f0-9]{64}$/.test(c.image)), 'unpinned-image');
  const body = copy({version: 1, scope, source, owner, evidence, createdAt: now, expiresAt: now + MAX_AGE,
    baseline: {service, definition, serviceHash: hash(config(service)), definitionHash: hash(original)}, target});
  return freeze({...body, hash: hash(body)});
}
function validate(plan, expectedHash, io) {
  need(object(plan) && digest(expectedHash) && plan.hash === expectedHash, 'hash');
  const {hash: ignored, ...body} = plan;
  need(hash(body) === expectedHash, 'hash');
  const rebuilt = buildServiceNonrootPlan({scope: plan.scope, source: plan.source, service: plan.baseline?.service,
    definition: plan.baseline?.definition, evidence: plan.evidence, owner: plan.owner, now: plan.createdAt});
  need(equal(plan, rebuilt), 'plan-not-derived');
  need(equal(io.scope, plan.scope), 'fixed-scope');
}
function candidateArn(plan, arn) {
  const base = plan.baseline.definition.taskDefinition;
  const prefix = `arn:aws:ecs:${plan.scope.region}:${plan.scope.accountId}:task-definition/${base.family}:`;
  need(typeof arn === 'string' && arn.startsWith(prefix) && /^[1-9]\d*$/.test(arn.slice(prefix.length)) &&
    Number.isSafeInteger(Number(arn.slice(prefix.length))) && Number(arn.slice(prefix.length)) > base.revision, 'candidate-arn');
}
function runtimeReceipt(plan, arn, receipt) {
  need(object(receipt) && digest(receipt.evidenceHash) && Array.isArray(receipt.tasks) && receipt.tasks.length === plan.baseline.service.desiredCount, 'runtime-receipt');
  need(new Set(receipt.tasks.map(t => t.taskArn)).size === receipt.tasks.length, 'runtime-duplicates');
  const taskPrefix = plan.scope.clusterArn.replace(':cluster/', ':task/') + '/';
  for (const task of receipt.tasks) {
    need(typeof task.taskArn === 'string' && task.taskArn.startsWith(taskPrefix) && task.taskArn.length > taskPrefix.length &&
      task.taskDefinitionArn === arn && task.lastStatus === 'RUNNING' && task.healthStatus === 'HEALTHY', 'runtime-task');
    need(Array.isArray(task.containers) && task.containers.length === plan.target.containerDefinitions.length, 'runtime-containers');
    for (const expected of plan.target.containerDefinitions) {
      const matches = task.containers.filter(c => c.name === expected.name), c = matches[0];
      need(matches.length === 1 && c.image === expected.image && c.imageDigest === expected.image.split('@')[1] &&
        c.lastStatus === 'RUNNING' && c.healthStatus === 'HEALTHY', 'runtime-image-or-health');
    }
  }
}

/** io is statically constructed, never obtained from plan/plugins/environment.
 * readRecord(name): null/undefined if absent. persistOnce(name,value): atomic,
 * durable create; returns true ONLY to its winning writer (false/throw otherwise).
 * Records must survive restart and be shared by all operators for this service.
 * assertEvidence(plan) authenticates evidence, reviewed source and owner authority.
 * acquireFences(plan), assertFences(), assertPaused() throw on failure and bind
 * the reviewed fence/maintenance artifacts. No automatic expiry/stealing.
 * register(target) -> ARN; update(ARN,{deploymentConfiguration}) -> void. Both
 * adapters MUST disable automatic SDK mutation retries and bind exact scope.
 * verifyRuntime(ARN,{plan,deadline}) performs process/security/MCP checks and
 * enumerates ALL service tasks (including pending/old), returning {tasks,evidenceHash}.
 * It must throw for any omitted/nonconforming task; booleans are not receipts.
 * wait(ms), readService(), readDefinition(ARN), releaseFences() are also required.
 * source is an async fresh clean-tree reader, now an epoch-ms clock function.
 * All failures after acquisition retain fences. No mutation can be resumed here. */
export async function applyServiceNonrootPlan(input, {expectedHash, source, io, now = Date.now}) {
  const plan = freeze(copy(input));
  validate(plan, expectedHash, io);
  need(typeof source === 'function' && typeof now === 'function', 'source-reader-or-clock');
  for (const name of ['readRecord', 'persistOnce', 'assertEvidence', 'readService', 'readDefinition', 'assertPaused', 'acquireFences', 'assertFences', 'register', 'update', 'verifyRuntime', 'wait', 'releaseFences']) need(typeof io[name] === 'function', `io-${name}`);
  const started = Date.now();
  const remaining = () => Math.min(plan.expiresAt - now(), MAX_AGE - (Date.now() - started));
  const time = () => need(Number.isSafeInteger(now()) && now() >= plan.createdAt && remaining() > 0, 'expired');
  // Promise timeout also bounds hung adapters; an uncertain send is never retried.
  const call = (name, ...args) => bounded(() => io[name](...args), remaining());
  async function unused() {
    for (const name of records) need(await call('readRecord', recordName(plan, name)) == null, 'reconcile-required');
  }
  async function save(name, value) {
    need(await call('persistOnce', recordName(plan, name), {planHash: plan.hash, owner: plan.owner, ...value}) === true, 'reconcile-required');
  }
  async function sourceAndTime() {
    time(); const current = await bounded(source, remaining()); checkSource(current);
    need(equal(current, plan.source), 'source-drift'); time();
  }
  async function guardedService(arn = plan.baseline.service.taskDefinition) {
    need(equal(io.scope, plan.scope), 'fixed-scope');
    await sourceAndTime(); await call('assertFences'); await call('assertPaused');
    const service = await call('readService'); checkScope(plan.scope, service);
    const expected = {...config(plan.baseline.service), taskDefinition: arn};
    if (arn !== plan.baseline.service.taskDefinition) expected.deploymentConfiguration = deploymentConfiguration(plan);
    need(equal(config(service), expected), 'service-drift');
    time(); return service;
  }
  async function beforeMutation() {
    const service = await guardedService();
    need(settled(service, plan.baseline.service.taskDefinition), 'baseline-not-stable');
    const original = checkDefinition(await call('readDefinition', service.taskDefinition), service.taskDefinition);
    need(hash(original) === plan.baseline.definitionHash, 'definition-drift');
    await sourceAndTime(); await call('assertFences'); await call('assertPaused'); time();
    const latest = await call('readService');
    need(hash(config(latest)) === plan.baseline.serviceHash && settled(latest, plan.baseline.service.taskDefinition), 'service-drift'); time();
  }
  async function candidateDefinition(arn) {
    candidateArn(plan, arn);
    need(equal(checkDefinition(await call('readDefinition', arn), arn), plan.target), 'candidate-readback');
  }
  await unused(); // A repeated invocation never acquires/releases another owner's fences.
  await sourceAndTime(); await call('assertEvidence', plan);
  await call('acquireFences', plan); await unused(); await beforeMutation();
  await save('register-intent', {targetHash: hash(plan.target)});
  await beforeMutation();
  let arn;
  try {arn = await call('register', plan.target);} catch {throw Error('service-nonroot:register-outcome-unknown');}
  await save('register-result', {taskDefinitionArn: arn});
  await candidateDefinition(arn); await beforeMutation();
  await save('update-intent', {taskDefinitionArn: arn, deploymentConfiguration: deploymentConfiguration(plan)});
  await candidateDefinition(arn); await beforeMutation();
  try {await call('update', arn, {deploymentConfiguration: deploymentConfiguration(plan)});} catch {throw Error('service-nonroot:update-outcome-unknown');}
  await save('update-result', {taskDefinitionArn: arn});
  let ready = false;
  for (let attempt = 0; attempt < POLLS; attempt++) {
    const service = await guardedService(arn);
    need(!service.deployments?.some(d => d.rolloutState === 'FAILED'), 'rollout-failed');
    if (settled(service, arn)) {ready = true; break;}
    await call('wait', Math.min(INTERVAL, remaining()));
  }
  need(ready, 'rollout-timeout'); await candidateDefinition(arn);
  const receipt = await call('verifyRuntime', arn, {plan, deadline: plan.expiresAt});
  runtimeReceipt(plan, arn, receipt);
  need(settled(await guardedService(arn), arn), 'runtime-drift'); await candidateDefinition(arn);
  await save('complete', {taskDefinitionArn: arn, runtimeEvidenceHash: hash(receipt)});
  need(settled(await guardedService(arn), arn), 'release-drift');
  await call('releaseFences');
  return {status: 'remediated', planHash: plan.hash, taskDefinitionArn: arn};
}

/** Read-only reconciliation evidence, including after expiry. Never adopts an
 * uncertain registration, retries a send, releases fences or renews old proofs. */
export async function inspectServiceNonrootOperation(input, {expectedHash, io}) {
  const plan = freeze(copy(input)); validate(plan, expectedHash, io);
  const journal = {};
  for (const name of records) journal[name] = await bounded(() => io.readRecord(recordName(plan, name)), 30_000);
  const service = await bounded(() => io.readService(), 30_000); checkScope(plan.scope, service);
  return {status: Object.values(journal).some(v => v != null) ? 'reconcile-required' : 'not-started', journal, service};
}
