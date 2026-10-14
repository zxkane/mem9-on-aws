import {describe, it, expect} from 'vitest';
import {buildServiceNonrootPlan, applyServiceNonrootPlan, inspectServiceNonrootOperation} from './lib/service-nonroot-operation.mjs';
import {serviceNonrootHash} from './lib/service-nonroot.mjs';

const stamp = Date.parse('2026-10-14T12:00:00Z');
const root = 'arn:aws:ecs:us-east-1:123456789012:';
const oldArn = `${root}task-definition/fixture-runtime:7`;
const newArn = `${root}task-definition/fixture-runtime:8`;
const source = {commit: 'a'.repeat(40), tree: 'b'.repeat(40), clean: true};
const scope = {accountId: '123456789012', region: 'us-east-1', clusterArn: `${root}cluster/fixture`, serviceArn: `${root}service/fixture/Mem9Server`};
const copy = v => structuredClone(v);
const deployment = arn => ({id: 'deployment', status: 'PRIMARY', taskDefinition: arn, desiredCount: 1, runningCount: 1, pendingCount: 0, rolloutState: 'COMPLETED'});
function inputs() {
  return {scope, source, owner: 'fixture-operator', now: stamp,
    evidence: Object.fromEntries(['review', 'images', 'local', 'preview', 'fences', 'maintenance'].map(k => [k, 'd'.repeat(64)])),
    service: {serviceArn: scope.serviceArn, clusterArn: scope.clusterArn, serviceName: 'Mem9Server', status: 'ACTIVE', launchType: 'FARGATE', desiredCount: 1, runningCount: 1, pendingCount: 0, taskDefinition: oldArn, enableExecuteCommand: true, deploymentController: {type: 'ECS'}, deploymentConfiguration: {minimumHealthyPercent: 0, maximumPercent: 100, alarms: {alarmNames: ['fixture'], enable: true, rollback: false}}, networkConfiguration: {awsvpcConfiguration: {subnets: ['fixture-subnet']}}, deployments: [deployment(oldArn)], events: [], futureConfiguration: {retain: true}},
    definition: {taskDefinition: {taskDefinitionArn: oldArn, family: 'fixture-runtime', revision: 7, status: 'ACTIVE', cpu: '2048', memory: '6144', networkMode: 'awsvpc', containerDefinitions: ['mnemo-server', 'qwen3-embed', 'llm-proxy'].map((name, i) => ({name, image: `example.invalid/${name}@sha256:${String(i + 1).repeat(64)}`, linuxParameters: {initProcessEnabled: true}, environment: [{name: 'MNEMO_NAMESPACE_EXACT_VECTOR_MAX_ROWS', value: '30000'}, {name: 'MNEMO_NAMESPACE_EXACT_VECTOR_TIMEOUT', value: '2s'}]}))}, tags: [{key: 'fixture', value: 'preserved'}]},
  };
}
function harness() {
  const input = inputs(), plan = buildServiceNonrootPlan(input), records = new Map(), calls = [];
  let service = copy(input.service), registered, clock = stamp, currentSource = copy(source);
  const io = {
    scope: copy(scope),
    readRecord: async name => copy(records.get(name)),
    persistOnce: async (name, value) => {calls.push(name.slice(`service-nonroot-${plan.hash}-`.length, -5)); if (records.has(name)) return false; records.set(name, copy(value)); return true;},
    assertEvidence: async () => {calls.push('evidence');},
    readService: async () => copy(service),
    readDefinition: async arn => arn === oldArn ? copy(input.definition) : copy(registered),
    assertPaused: async () => {calls.push('paused');},
    acquireFences: async () => {calls.push('acquire');},
    assertFences: async () => {calls.push('fences');},
    register: async target => {calls.push('register'); const {tags, ...d} = copy(target); registered = {taskDefinition: {...d, taskDefinitionArn: newArn, status: 'ACTIVE', revision: 8}, tags}; return newArn;},
    update: async (arn, {deploymentConfiguration}) => {calls.push('update'); service = {...service, taskDefinition: arn, deploymentConfiguration: copy(deploymentConfiguration), deployments: [deployment(arn)]};},
    verifyRuntime: async arn => {calls.push('runtime'); return {evidenceHash: 'e'.repeat(64), tasks: [{taskArn: `${root}task/fixture/new-task`, taskDefinitionArn: arn, lastStatus: 'RUNNING', healthStatus: 'HEALTHY', containers: plan.target.containerDefinitions.map(c => ({name: c.name, image: c.image, imageDigest: c.image.split('@')[1], lastStatus: 'RUNNING', healthStatus: 'HEALTHY'}))}]};},
    wait: async ms => {clock += ms;},
    releaseFences: async () => {calls.push('release');},
  };
  return {input, plan, io, calls, records, apply: options => applyServiceNonrootPlan(plan, {expectedHash: plan.hash, source: async () => copy(currentSource), io, now: () => clock, ...options}),
    get service() {return service;}, get registered() {return registered;}, setSource: s => {currentSource = s;}, advance: ms => {clock += ms;}};
}

describe('bounded service nonroot operation', () => {
  it('builds deterministic detached data, binding full original definition/tags and configuration', () => {
    const input = inputs(), before = copy(input), plan = buildServiceNonrootPlan(input);
    expect(input).toEqual(before); expect(plan).toEqual(buildServiceNonrootPlan(copy(input)));
    expect(plan.expiresAt - plan.createdAt).toBe(30 * 60_000);
    expect(plan.baseline.definition).toEqual(input.definition);
    expect(plan.target.tags).toEqual(input.definition.tags);
    expect(plan.target.containerDefinitions.map(c => c.image)).toEqual(input.definition.taskDefinition.containerDefinitions.map(c => c.image));
    input.service.futureConfiguration.retain = false;
    expect(plan.baseline.service.futureConfiguration.retain).toBe(true);
  });
  it('sends exactly register/update, journals each intent first, preserves deployment options and awaits runtime before release', async () => {
    const h = harness(); let finish;
    const verify = h.io.verifyRuntime;
    h.io.verifyRuntime = async arn => {const receipt = await verify(arn); await new Promise(resolve => {finish = resolve;}); return receipt;};
    const pending = h.apply();
    await new Promise(resolve => setImmediate(resolve));
    expect(finish).toBeTypeOf('function'); expect(h.calls).not.toContain('release'); finish();
    expect(await pending).toMatchObject({status: 'remediated', taskDefinitionArn: newArn});
    expect(h.calls.filter(c => ['register', 'update'].includes(c))).toEqual(['register', 'update']);
    expect(h.calls.indexOf('register-intent')).toBeLessThan(h.calls.indexOf('register'));
    expect(h.calls.indexOf('update-intent')).toBeLessThan(h.calls.indexOf('update'));
    expect(h.calls.indexOf('complete')).toBeLessThan(h.calls.indexOf('release'));
    expect(h.service.deploymentConfiguration).toEqual({...h.input.service.deploymentConfiguration, minimumHealthyPercent: 100, maximumPercent: 200, deploymentCircuitBreaker: {enable: true, rollback: false}});
    expect(h.calls).not.toContain('maintenance-write');
  });
  it.each(['hash', 'source', 'dirty', 'expired', 'future', 'scope'])('rejects %s before acquiring fences', async kind => {
    const h = harness(), options = {};
    if (kind === 'hash') options.expectedHash = 'f'.repeat(64);
    if (kind === 'source') h.setSource({...source, tree: 'c'.repeat(40)});
    if (kind === 'dirty') h.setSource({...source, clean: false});
    if (kind === 'expired') h.advance(30 * 60_000);
    if (kind === 'future') h.advance(-1);
    if (kind === 'scope') h.io.scope.accountId = '0'.repeat(12);
    await expect(h.apply(options)).rejects.toThrow(); expect(h.calls).not.toContain('acquire');
  });
  it('rejects an altered target even if its hash is externally supplied', async () => {
    const h = harness(), plan = copy(h.plan); plan.target.memory = '12288';
    const {hash, ...body} = plan; plan.hash = serviceNonrootHash(body);
    await expect(applyServiceNonrootPlan(plan, {expectedHash: plan.hash, source: async () => source, io: h.io, now: () => stamp})).rejects.toThrow();
    expect(h.calls).not.toContain('register');
  });
  it.each(['unpinned', 'tags', 'owner', 'evidence', 'pending', 'deployment'])('rejects invalid %s plan input', kind => {
    const input = inputs();
    if (kind === 'unpinned') input.definition.taskDefinition.containerDefinitions[0].image = 'example.invalid/image:latest';
    if (kind === 'tags') delete input.definition.tags;
    if (kind === 'owner') input.owner = '';
    if (kind === 'evidence') input.evidence.preview = true;
    if (kind === 'pending') input.service.pendingCount = 1;
    if (kind === 'deployment') input.service.deployments[0].rolloutState = 'IN_PROGRESS';
    expect(() => buildServiceNonrootPlan(input)).toThrow();
  });
  it.each(['unknown-config', 'network', 'definition', 'tags'])('rejects %s drift with fences retained', async kind => {
    const h = harness();
    if (kind === 'unknown-config') h.service.futureConfiguration.retain = false;
    if (kind === 'network') h.service.networkConfiguration.awsvpcConfiguration.subnets.push('other');
    if (kind === 'definition') h.input.definition.taskDefinition.cpu = '4096';
    if (kind === 'tags') h.input.definition.tags[0].value = 'changed';
    await expect(h.apply()).rejects.toThrow(); expect(h.calls).not.toContain('register'); expect(h.calls).not.toContain('release');
  });
  it('allows events/timestamps to change without losing unknown configuration binding', async () => {
    const h = harness(); h.service.events.push({message: 'observation'}); h.service.updatedAt = 'later';
    await expect(h.apply()).resolves.toMatchObject({status: 'remediated'});
  });
  it.each(['register', 'update'])('retains fences on ambiguous %s and never repeats either send', async phase => {
    const h = harness(), send = h.io[phase]; h.io[phase] = async (...args) => {await send(...args); throw Error('response lost after mutation');};
    await expect(h.apply()).rejects.toThrow('outcome-unknown');
    const count = h.calls.length;
    await expect(h.apply()).rejects.toThrow('reconcile-required');
    expect(h.calls.slice(count)).not.toContain('acquire'); expect(h.calls).not.toContain('release');
    expect(h.calls.filter(c => c === phase)).toHaveLength(1);
    const report = await inspectServiceNonrootOperation(h.plan, {expectedHash: h.plan.hash, io: h.io});
    expect(report.status).toBe('reconcile-required');
    expect(h.calls.filter(c => c === phase)).toHaveLength(1);
  });
  it('refuses sending when conditional intent persistence loses the race', async () => {
    const h = harness(); h.io.persistOnce = async () => false;
    await expect(h.apply()).rejects.toThrow('reconcile-required'); expect(h.calls).not.toContain('register'); expect(h.calls).not.toContain('release');
  });
  it.each(['arn', 'readback', 'source', 'expiry', 'baseline', 'fences', 'paused'])('blocks update after registration when %s changes', async kind => {
    const h = harness(), register = h.io.register;
    h.io.register = async target => {
      const arn = await register(target);
      if (kind === 'arn') return arn.replace(':8', ':7');
      if (kind === 'readback') h.registered.taskDefinition.cpu = '4096';
      if (kind === 'source') h.setSource({...source, tree: 'f'.repeat(40)});
      if (kind === 'expiry') h.advance(30 * 60_000);
      if (kind === 'baseline') h.service.futureConfiguration.retain = false;
      if (kind === 'fences') h.io.assertFences = async () => {throw Error('lost fence');};
      if (kind === 'paused') h.io.assertPaused = async () => {throw Error('maintenance unpaused');};
      return arn;
    };
    await expect(h.apply()).rejects.toThrow(); expect(h.calls).not.toContain('update'); expect(h.calls).not.toContain('release');
    await expect(h.apply()).rejects.toThrow('reconcile-required');
  });
  it('rechecks baseline after persisting update intent', async () => {
    const h = harness(), persist = h.io.persistOnce;
    h.io.persistOnce = async (name, value) => {const result = await persist(name, value); if (name.endsWith('-update-intent.json')) h.service.desiredCount = 2; return result;};
    await expect(h.apply()).rejects.toThrow(); expect(h.calls).not.toContain('update'); expect(h.calls).not.toContain('release');
  });
  it.each(['boolean', 'throws', 'image', 'pending', 'baseline', 'empty', 'duplicate'])('never releases on %s runtime evidence', async kind => {
    const h = harness(), verify = h.io.verifyRuntime, update = h.io.update;
    if (['pending', 'baseline'].includes(kind)) h.io.update = async (...args) => {await update(...args); if (kind === 'pending') h.service.pendingCount = 1; else h.service.deployments.push(deployment(oldArn));};
    h.io.verifyRuntime = async arn => {
      if (kind === 'boolean') return true;
      if (kind === 'throws') throw Error('smoke failed');
      const receipt = await verify(arn);
      if (kind === 'image') receipt.tasks[0].containers[0].imageDigest = 'sha256:' + 'f'.repeat(64);
      if (kind === 'empty') receipt.tasks = [];
      if (kind === 'duplicate') receipt.tasks.push(copy(receipt.tasks[0]));
      return receipt;
    };
    await expect(h.apply()).rejects.toThrow(); expect(h.calls).not.toContain('release');
  });
  it('bounds observation and rejects a failed deployment without root recovery', async () => {
    const h = harness(), update = h.io.update;
    h.io.update = async (...args) => {await update(...args); h.service.deployments[0].rolloutState = 'FAILED';};
    await expect(h.apply()).rejects.toThrow();
    expect(h.calls.filter(c => c === 'update')).toHaveLength(1); expect(h.calls).not.toContain('release');
  });
  it('detects drift during runtime verification before releasing', async () => {
    const h = harness(), verify = h.io.verifyRuntime;
    h.io.verifyRuntime = async arn => {const receipt = await verify(arn); h.service.futureConfiguration.retain = false; return receipt;};
    await expect(h.apply()).rejects.toThrow(); expect(h.calls).not.toContain('release');
  });
  it('requires independently authenticated evidence before fence acquisition', async () => {
    const h = harness(); h.io.assertEvidence = async () => {throw Error('review signature invalid');};
    await expect(h.apply()).rejects.toThrow('review signature invalid');
    expect(h.calls).not.toContain('acquire'); expect(h.calls).not.toContain('register');
  });
  it('rejects an existing alarm rollback path rather than preserving root recovery', () => {
    const input = inputs(); input.service.deploymentConfiguration.alarms.rollback = true;
    expect(() => buildServiceNonrootPlan(input)).toThrow('rollback');
  });
  it.each(['foreign-account', 'foreign-region', 'foreign-family'])('rejects a %s registration response', async kind => {
    const h = harness();
    h.io.register = async () => kind === 'foreign-account' ? newArn.replace('123456789012', '0'.repeat(12)) : kind === 'foreign-region' ? newArn.replace('us-east-1', 'us-west-2') : newArn.replace('fixture-runtime', 'other');
    await expect(h.apply()).rejects.toThrow('candidate-arn'); expect(h.calls).not.toContain('update'); expect(h.calls).not.toContain('release');
  });
  it.each(['source', 'register', 'runtime'])('bounds a hung %s callback and retains fences', async kind => {
    const h = harness(), options = {now: () => stamp + 30 * 60_000 - 20};
    const hang = () => new Promise(() => {});
    if (kind === 'source') options.source = hang;
    if (kind === 'register') h.io.register = hang;
    if (kind === 'runtime') h.io.verifyRuntime = hang;
    await expect(h.apply(options)).rejects.toThrow(kind === 'register' ? 'outcome-unknown' : 'adapter-timeout');
    expect(h.calls).not.toContain('release');
    if (kind === 'register') await expect(h.apply()).rejects.toThrow('reconcile-required');
  });
  it('detects service drift during the definition read immediately before sending', async () => {
    const h = harness(), read = h.io.readDefinition;
    h.io.readDefinition = async arn => {const result = await read(arn); h.service.futureConfiguration.retain = false; return result;};
    await expect(h.apply()).rejects.toThrow('service-drift'); expect(h.calls).not.toContain('register');
  });
  it('does not repeat a successful operation or release fences twice', async () => {
    const h = harness(); await h.apply();
    await expect(h.apply()).rejects.toThrow('reconcile-required');
    expect(h.calls.filter(c => c === 'release')).toHaveLength(1);
    expect(h.calls.filter(c => c === 'register')).toHaveLength(1);
  });
  it('retains the durable intent when persistence acknowledges ambiguously', async () => {
    const h = harness(), persist = h.io.persistOnce;
    h.io.persistOnce = async (...args) => {await persist(...args); throw Error('journal response lost');};
    await expect(h.apply()).rejects.toThrow('journal response lost');
    await expect(h.apply()).rejects.toThrow('reconcile-required');
    expect(h.calls).not.toContain('register'); expect(h.calls).not.toContain('release');
  });
  it('rejects boolean runtime permission and static source snapshots', async () => {
    const h = harness(); h.io.verifyRuntime = true;
    await expect(h.apply()).rejects.toThrow('io-verifyRuntime');
    await expect(h.apply({source})).rejects.toThrow('source-reader-or-clock');
    expect(h.calls).not.toContain('acquire');
  });
  it('does not release when runtime verification completes after expiry', async () => {
    const h = harness(), verify = h.io.verifyRuntime;
    h.io.verifyRuntime = async arn => {const result = await verify(arn); h.advance(30 * 60_000); return result;};
    await expect(h.apply()).rejects.toThrow('expired'); expect(h.calls).not.toContain('release');
  });
  it('binds scope again after fences are acquired', async () => {
    const h = harness(), acquire = h.io.acquireFences;
    h.io.acquireFences = async plan => {await acquire(plan); h.io.scope.region = 'us-west-2';};
    await expect(h.apply()).rejects.toThrow('fixed-scope'); expect(h.calls).not.toContain('register');
  });
});
