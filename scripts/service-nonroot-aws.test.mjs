import {afterEach, describe, expect, it, vi} from 'vitest';
import {serviceNonrootHash as hash} from './lib/service-nonroot.mjs';

// Exercise the actual adapter; intercept every SDK, filesystem and subprocess
// boundary. No credentials, network, subprocesses or temporary files are used.
const mocks = vi.hoisted(() => {
  const m = {send: vi.fn(), exec: vi.fn(), configurations: [],
    fs: Object.fromEntries(['readFile', 'open', 'lstat', 'mkdir'].map(name => [name, vi.fn()]))};
  m.sdk = (client, commands) => ({
    [client]: class {
      constructor(configuration) {m.configurations.push(configuration);}
      send(command, options) {return m.send(command.kind, command.input, options);}
      destroy() {}
    },
    ...Object.fromEntries(commands.map(kind => [kind, class {constructor(input) {this.kind = kind; this.input = input;}}])),
  });
  m.execFile = () => {throw Error('Unexpected unpromisified subprocess');};
  m.execFile[Symbol.for('nodejs.util.promisify.custom')] = (...args) => m.exec(...args);
  return m;
});
vi.mock('@aws-sdk/client-ecs', () => mocks.sdk('ECSClient', ['DescribeServicesCommand', 'DescribeTaskDefinitionCommand', 'ListTasksCommand', 'DescribeTasksCommand', 'RegisterTaskDefinitionCommand', 'UpdateServiceCommand']));
vi.mock('@aws-sdk/client-s3', () => mocks.sdk('S3Client', ['GetObjectCommand', 'PutObjectCommand', 'DeleteObjectCommand', 'GetPublicAccessBlockCommand', 'GetBucketEncryptionCommand', 'GetBucketLifecycleConfigurationCommand']));
vi.mock('@aws-sdk/client-ssm', () => mocks.sdk('SSMClient', ['GetParametersCommand']));
vi.mock('@aws-sdk/client-scheduler', () => mocks.sdk('SchedulerClient', ['ListScheduleGroupsCommand', 'ListSchedulesCommand']));
vi.mock('@aws-sdk/client-sts', () => mocks.sdk('STSClient', ['GetCallerIdentityCommand']));
vi.mock('node:fs/promises', () => mocks.fs);
vi.mock('node:child_process', () => ({execFile: mocks.execFile}));
import {createServiceNonrootAws} from './lib/service-nonroot-aws.mjs';

const operationId = 'a'.repeat(32), directory = '/private/service-nonroot-fixture';
const lockKey = 'runtime-publication-locks/prod/witness.json';
const scope = {account: '123456789012', region: 'us-east-1', cluster: 'mem9-on-aws-prod-fixture', service: 'Mem9Server', bucket: 'mem9-audit-123456789012', lockKey};
const journalKey = name => `runtime-service-hardening/${operationId}/${name}`;
const localPath = name => `${directory}/${name}`;
const failure = name => Object.assign(Error(name), {name, code: name});
const clone = value => structuredClone(value);
let active;
afterEach(() => {active?.close(); active = undefined;});

async function harness({bucket=scope.bucket,configuredBucket}={}) {
  vi.clearAllMocks(); mocks.configurations.length = 0;
  const h = {cloud: new Map(), local: new Map(), requests: [], controls: [], events: [], destroyed: [],
    gate: {name: 'DEPLOYMENT_MAINTENANCE_PAUSED', value: 'false', updated_at: 'before'}, plan: {version: 1, owner: operationId},
    variables: configuredBucket===undefined?[]:[{name:'MEM9_DECISION_ARTIFACT_BUCKET',value:configuredBucket}]};
  let sequence = 0;
  h.putCloud = (name, value) => h.cloud.set(journalKey(name), {body: JSON.stringify(value), etag: `fixture-${++sequence}`});
  h.putLocal = (name, value) => h.local.set(localPath(name), JSON.stringify(value));
  mocks.fs.mkdir.mockImplementation(async path => {expect(path).toBe(directory);});
  mocks.fs.lstat.mockImplementation(async path => {
    if (path === directory) return {isDirectory: () => true, isSymbolicLink: () => false, mode: 0o700};
    if (!h.local.has(path)) throw failure('ENOENT');
    return {isFile: () => true, isSymbolicLink: () => false, uid: process.getuid(), mode: 0o600, size: Buffer.byteLength(h.local.get(path))};
  });
  mocks.fs.readFile.mockImplementation(async path => {
    if (!h.local.has(path)) throw failure('ENOENT');
    return h.local.get(path);
  });
  mocks.fs.open.mockImplementation(async (path, flags, mode) => {
    expect(flags).toBe('wx'); expect(mode).toBe(0o600);
    if (h.beforeOpen) await h.beforeOpen(path);
    if (h.local.has(path)) throw failure('EEXIST');
    h.local.set(path, '');
    return {
      writeFile: async body => {h.local.set(path, body); h.events.push(`local-write:${path}`);},
      sync: async () => {h.events.push(`local-sync:${path}`);},
      close: async () => {},
    };
  });
  mocks.exec.mockImplementation(async (file, args) => {
    expect(file).toBe('gh');
    const path = args.find(arg => arg.startsWith('repos/'));
    let value;
    if (path?.includes('/actions/runs?')) value = {total_count: 0, workflow_runs: []};
    else if(path?.endsWith('/actions/variables?per_page=100')) value=h.variableResponse??{total_count:h.variables.length,variables:clone(h.variables)};
    else if (path?.endsWith('/actions/variables/DEPLOYMENT_MAINTENANCE_PAUSED')) {
      if (args.includes('PATCH')) {
        const setting = args.find(arg => arg.startsWith('value=')).slice(6);
        h.controls.push(`gate-${setting}`); h.events.push(`gate-${setting}`);
        h.gate = {...h.gate, value: setting, updated_at: `gate-${++sequence}`};
        if (h.afterGatePatch) await h.afterGatePatch(setting);
      }
      value = clone(h.gate);
    } else throw Error(`Unexpected mocked GitHub path: ${path}`);
    return {stdout: JSON.stringify(value), stderr: ''};
  });
  mocks.send.mockImplementation(async (kind, input, options) => {
    expect(options.abortSignal).toBeInstanceOf(AbortSignal);
    h.requests.push({kind, input: clone(input)});
    if (h.beforeRequest) await h.beforeRequest(kind, input);
    if (kind === 'GetCallerIdentityCommand') return {Account: scope.account};
    if (input.Bucket) {expect(input.Bucket).toBe(bucket); expect(input.ExpectedBucketOwner).toBe(scope.account);}
    if (kind === 'GetPublicAccessBlockCommand') return {PublicAccessBlockConfiguration: {BlockPublicAcls: true, IgnorePublicAcls: true, BlockPublicPolicy: true, RestrictPublicBuckets: true}};
    if (kind === 'GetBucketEncryptionCommand') return {ServerSideEncryptionConfiguration: {Rules: [{ApplyServerSideEncryptionByDefault: {SSEAlgorithm: 'aws:kms'}}]}};
    if (kind === 'GetBucketLifecycleConfigurationCommand') return {Rules: []};
    if (kind === 'GetObjectCommand') {
      const object = h.cloud.get(input.Key);
      if (!object) throw failure('NoSuchKey');
      return {ContentLength: Buffer.byteLength(object.body), ETag: object.etag,
        Body: {transformToString: async () => object.body, destroy: () => h.destroyed.push(input.Key)}, ...object.metadata};
    }
    if (kind === 'PutObjectCommand') {
      expect(input.IfNoneMatch).toBe('*');
      if (h.cloud.has(input.Key)) throw failure('PreconditionFailed');
      h.cloud.set(input.Key, {body: input.Body, etag: `fixture-${++sequence}`});
      h.events.push(`cloud-write:${input.Key}`);
      if (input.Key === lockKey) h.controls.push('mutex-put');
      if (h.afterPut) await h.afterPut(input);
      return {};
    }
    if (kind === 'DeleteObjectCommand') {
      expect(input.Key).toBe(lockKey);
      if (h.cloud.get(lockKey)?.etag !== input.IfMatch) throw failure('PreconditionFailed');
      h.cloud.delete(lockKey); h.controls.push('mutex-delete'); h.events.push('mutex-delete'); return {};
    }
    throw Error(`Unexpected mocked AWS operation: ${kind}`);
  });
  h.io = active = await createServiceNonrootAws({scope: {...clone(scope),bucket}, directory, root: '/private/source-fixture', operationId});
  return h;
}

describe('shared configured audit bucket',()=>{
 it('uses the configured custom bucket for both publication mutex and journal',async()=>{
  const bucket='fixture-audit-123456789012',h=await harness({bucket,configuredBucket:bucket});
  await h.io.acquireFences(h.plan);await h.io.releaseFences();
  const writes=h.requests.filter(r=>r.kind==='PutObjectCommand');
  expect(writes.some(r=>r.input.Key===lockKey)).toBe(true);
  expect(writes.some(r=>r.input.Key.startsWith('runtime-service-hardening/'))).toBe(true);
  expect(writes.every(r=>r.input.Bucket===bucket)).toBe(true);
 });
 it('rejects the default bucket when deployment configuration selects another bucket',async()=>{
  await expect(harness({configuredBucket:'fixture-audit-123456789012'})).rejects.toThrow('ConfiguredAuditBucketMismatch');
  expect(mocks.send.mock.calls.some(([kind])=>kind==='PutObjectCommand')).toBe(false);
 });
 it('does not release fences after the configured bucket changes',async()=>{
  const h=await harness();await h.io.acquireFences(h.plan);
  h.variables=[{name:'MEM9_DECISION_ARTIFACT_BUCKET',value:'fixture-audit-123456789012'}];
  await expect(h.io.assertFences()).rejects.toThrow('ConfiguredAuditBucketMismatch');
  await expect(h.io.releaseFences()).rejects.toThrow('ConfiguredAuditBucketMismatch');
  expect(h.gate.value).toBe('true');expect(h.cloud.has(lockKey)).toBe(true);
 });
 it('fails closed on incomplete configuration inventory before acquisition',async()=>{
  const h=await harness();h.variableResponse={total_count:101,variables:[]};
  await expect(h.io.acquireFences(h.plan)).rejects.toThrow('AuditBucketConfigurationIncomplete');
  expect(h.controls).toEqual([]);
 });
});

describe('actual task lifetime inventory',()=>{
 const current='arn:fixture/current',old='arn:fixture/old';
 async function setup(tasks,{missing=false}={}){
  const h=await harness(),fallback=mocks.send.getMockImplementation();
  mocks.send.mockImplementation(async(kind,input,...rest)=>{
   if(kind==='ListTasksCommand')return {taskArns:input.desiredStatus==='RUNNING'?[current]:[old,current]};
   if(kind==='DescribeTasksCommand')return {tasks:missing?tasks.slice(0,1):tasks,failures:[]};
   return fallback(kind,input,...rest);
  });return h;
 }
 it('rejects a draining administrator even after desired status became STOPPED',async()=>{
  const h=await setup([{taskArn:current,group:'service:Mem9Server',lastStatus:'RUNNING'},{taskArn:old,group:'family:Control',lastStatus:'STOPPING'}]);
  await expect(h.io.inventory()).rejects.toThrow('ActiveAdministrationOrWorker');
 });
 it('retains old service tasks until actual STOPPED and deduplicates both listings',async()=>{
  const tasks=[{taskArn:current,group:'service:Mem9Server',lastStatus:'RUNNING'},{taskArn:old,group:'service:Mem9Server',lastStatus:'STOPPING'}],h=await setup(tasks);
  expect(await h.io.inventory()).toEqual(tasks);tasks[1].lastStatus='STOPPED';expect(await h.io.inventory()).toEqual([tasks[0]]);
 });
 it('rejects an incomplete DescribeTasks response',async()=>{
  const h=await setup([{taskArn:current,group:'service:Mem9Server',lastStatus:'RUNNING'},{taskArn:old,group:'service:Mem9Server',lastStatus:'STOPPED'}],{missing:true});
  await expect(h.io.inventory()).rejects.toThrow('TaskDescribeIncomplete');
 });
});

describe('authoritative service nonroot journal', () => {
  const name = 'register-intent.json', value = {planHash: 'b'.repeat(64), owner: operationId};
  it('returns absent only when both copies are absent', async () => {
    const h = await harness(); expect(await h.io.readRecord(name)).toBeNull();
    expect(h.requests.at(-1)).toMatchObject({kind: 'GetObjectCommand', input: {Key: journalKey(name)}});
  });
  it('returns a cloud-only intent after a crash without recreating the local cache', async () => {
    const h = await harness(); h.putCloud(name, value);
    expect(await h.io.readRecord(name)).toEqual(value); expect(h.local.size).toBe(0);
    expect(await h.io.persistOnce(name, value)).toBe(false);
    expect(h.requests.filter(r => r.kind === 'PutObjectCommand')).toHaveLength(0);
  });
  it('accepts matching records and checks the cloud again for every read', async () => {
    const h = await harness(); h.putCloud(name, value); h.putLocal(name, value);
    expect(await h.io.readRecord(name)).toEqual(value); h.cloud.delete(journalKey(name));
    await expect(h.io.readRecord(name)).rejects.toThrow('RemoteJournalMissing');
  });
  it('rejects local-only intent rather than treating it as absent or authorizing replay', async () => {
    const h = await harness(); h.putLocal(name, value);
    await expect(h.io.readRecord(name)).rejects.toThrow('RemoteJournalMissing');
    await expect(h.io.persistOnce(name, value)).rejects.toThrow('RemoteJournalMissing');
    expect(h.requests.filter(r => r.kind === 'PutObjectCommand')).toHaveLength(0);
  });
  it.each([{different: true}, null, false, 0, ''])('rejects local/cloud disagreement for local JSON %j', async local => {
    const h = await harness(); h.putLocal(name, local); h.putCloud(name, value);
    await expect(h.io.readRecord(name)).rejects.toThrow('JournalCopiesDiffer');
    expect(h.destroyed).toContain(journalKey(name));
  });
  it('rejects a different authoritative intent instead of overwriting it', async () => {
    const h = await harness(); h.putCloud(name, value);
    await expect(h.io.persistOnce(name, {...value, owner: 'other'})).rejects.toThrow('JournalRecordChanged');
    expect(h.requests.filter(r => r.kind === 'PutObjectCommand')).toHaveLength(0);
  });
  it.each(['AccessDenied', 'RequestTimeout'])('does not interpret %s as cloud absence', async error => {
    const h = await harness(); h.beforeRequest = kind => {if (kind === 'GetObjectCommand') throw failure(error);};
    await expect(h.io.readRecord(name)).rejects.toThrow(error);
  });
  it.each([{ContentLength: 0}, {ContentLength: 8 * 1024 * 1024 + 1}, {DeleteMarker: true}])('rejects invalid remote metadata %j and closes the body', async metadata => {
    const h = await harness(); h.putCloud(name, value); h.cloud.get(journalKey(name)).metadata = metadata;
    await expect(h.io.readRecord(name)).rejects.toThrow('RemoteJournalInvalid');
    expect(h.destroyed).toContain(journalKey(name));
  });
  it('rejects malformed cloud JSON even when the local copy is valid', async () => {
    const h = await harness(); h.putLocal(name, value); h.putCloud(name, value); h.cloud.get(journalKey(name)).body = '{';
    await expect(h.io.readRecord(name)).rejects.toThrow(); expect(h.destroyed).toContain(journalKey(name));
  });
  it.each([null, false, 0, '', [], 'not-a-record'])('rejects remote JSON %j rather than treating it as an absent intent', async invalid => {
    const h = await harness(); h.putCloud(name, invalid);
    await expect(h.io.readRecord(name)).rejects.toThrow('RemoteJournalInvalid');
    await expect(h.io.persistOnce(name, value)).rejects.toThrow('RemoteJournalInvalid');
    expect(h.requests.filter(r => r.kind === 'PutObjectCommand')).toHaveLength(0);
    expect(h.destroyed).toContain(journalKey(name));
  });
  it('returns true only once and persists cloud before exclusive local creation and fsync', async () => {
    const h = await harness(); expect(await h.io.persistOnce(name, value)).toBe(true);
    expect(h.events).toEqual([`cloud-write:${journalKey(name)}`, `local-write:${localPath(name)}`, `local-sync:${localPath(name)}`]);
    expect(await h.io.persistOnce(name, value)).toBe(false);
    expect(h.requests.filter(r => r.kind === 'PutObjectCommand')).toHaveLength(1);
    expect(mocks.configurations.every(c => c.maxAttempts === 1)).toBe(true);
  });
  it('retains a cloud intent after local atomic creation loses a race', async () => {
    const h = await harness(); h.beforeOpen = path => {h.local.set(path, JSON.stringify(value));};
    await expect(h.io.persistOnce(name, value)).rejects.toThrow('EEXIST');
    h.beforeOpen = undefined;
    expect(await h.io.readRecord(name)).toEqual(value); expect(await h.io.persistOnce(name, value)).toBe(false);
    expect(h.requests.filter(r => r.kind === 'PutObjectCommand')).toHaveLength(1);
  });
  it('does not retry after cloud persistence succeeds but its acknowledgment is lost', async () => {
    const h = await harness(); h.afterPut = () => {throw failure('RequestTimeout');};
    await expect(h.io.persistOnce(name, value)).rejects.toThrow('RequestTimeout');
    expect(h.local.size).toBe(0); h.afterPut = undefined;
    expect(await h.io.readRecord(name)).toEqual(value); expect(await h.io.persistOnce(name, value)).toBe(false);
    expect(h.requests.filter(r => r.kind === 'PutObjectCommand')).toHaveLength(1);
  });
});

describe('service nonroot fence mutation intent gates', () => {
  const phases = ['mutex-intent.json', 'gate-intent.json', 'gate-release-intent.json', 'mutex-release-intent.json'];
  const forbidden = {'mutex-intent.json': 'mutex-put', 'gate-intent.json': 'gate-true', 'gate-release-intent.json': 'gate-false', 'mutex-release-intent.json': 'mutex-delete'};
  for (const mode of ['existing', 'collision']) {
    it.each(phases)(`stops before the protected mutation on ${mode} %s`, async name => {
      const h = await harness(), releasing = name.includes('release');
      const fences = releasing ? await h.io.acquireFences(h.plan) : undefined;
      h.controls.length = 0;
      const value = name === 'mutex-intent.json' ? {body: JSON.stringify({version: 1, kind: 'service-nonroot', owner: h.plan.owner, planHash: hash(h.plan)})}
        : name === 'gate-intent.json' ? clone(h.gate)
          : name === 'gate-release-intent.json' ? {before: fences.before, acquired: fences.gate} : {etag: fences.mutex.etag};
      if (mode === 'existing') {
        if (name === 'mutex-intent.json') {
          // Win after acquire's initial absence check, before persistOnce reads.
          h.beforeRequest = kind => {if (kind === 'GetBucketLifecycleConfigurationCommand') h.putCloud(name, value);};
        } else h.putCloud(name, value);
      } else h.beforeRequest = (kind, input) => {if (kind === 'PutObjectCommand' && input.Key === journalKey(name)) h.putCloud(name, {competing: true});};
      const action = releasing ? () => h.io.releaseFences() : () => h.io.acquireFences(h.plan);
      await expect(action()).rejects.toThrow(mode === 'existing' ? 'FenceReconciliationRequired' : 'PreconditionFailed');
      expect(h.controls).not.toContain(forbidden[name]);
      expect(h.controls).not.toContain('mutex-delete');
      if (name !== 'mutex-intent.json') expect(h.cloud.has(lockKey)).toBe(true);
      expect(h.requests.filter(r => ['RegisterTaskDefinitionCommand', 'UpdateServiceCommand'].includes(r.kind))).toHaveLength(0);
    });
  }
  it('acquires/releases once in order and retains every durable intent', async () => {
    const h = await harness(); await h.io.acquireFences(h.plan); await h.io.assertFences(); await h.io.releaseFences();
    expect(h.controls).toEqual(['mutex-put', 'gate-true', 'gate-false', 'mutex-delete']);
    for (const name of phases) expect(h.cloud.has(journalKey(name))).toBe(true);
    expect(h.gate.value).toBe('false'); expect(h.cloud.has(lockKey)).toBe(false);
    await expect(h.io.acquireFences(h.plan)).rejects.toThrow('ExistingOperationRequiresReconciliation');
    expect(h.controls).toHaveLength(4);
  });
  it('does not steal another mutex after winning its own intent', async () => {
    const h = await harness(); const other = {body: '{"owner":"other"}', etag: 'other'}; h.cloud.set(lockKey, other);
    await expect(h.io.acquireFences(h.plan)).rejects.toThrow('PreconditionFailed');
    expect(h.cloud.get(lockKey)).toEqual(other); expect(h.controls).toEqual([]);
  });
  it('stops a second release after an ambiguous gate request with the first intent retained', async () => {
    const h = await harness(); await h.io.acquireFences(h.plan); const acquired = clone(h.gate);
    h.afterGatePatch = () => {h.gate = acquired; throw failure('RequestTimeout');};
    await expect(h.io.releaseFences()).rejects.toThrow('RequestTimeout');
    h.afterGatePatch = undefined; h.controls.length = 0;
    await expect(h.io.releaseFences()).rejects.toThrow('FenceReconciliationRequired');
    expect(h.controls).toEqual([]); expect(h.cloud.has(lockKey)).toBe(true);
  });
});
