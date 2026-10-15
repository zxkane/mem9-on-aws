import {afterEach, describe, expect, it, vi} from 'vitest';
import {createHash} from 'node:crypto';
import {hardenServiceRegistration, serviceNonrootHash as hash} from './lib/service-nonroot.mjs';
const mock = vi.hoisted(() => {
  const m = {send: vi.fn(), exec: vi.fn(), source: vi.fn(), roles: vi.fn(), runtime: vi.fn(), sleep: vi.fn(),
    fs: Object.fromEntries(['readFile', 'lstat', 'realpath', 'mkdtemp', 'open', 'unlink'].map(k => [k, vi.fn()]))};
  m.sdk = (client, commands) => ({[client]: class {constructor(config) {if (config.maxAttempts !== 1) throw Error('Retries enabled');} send(c) {return m.send(c.kind, c.input);} destroy() {}},
    ...Object.fromEntries(commands.map(kind => [kind, class {constructor(input) {this.kind = kind; this.input = input;}}]))});
  m.execFile = () => {throw Error('Real subprocess forbidden');};
  m.execFile[Symbol.for('nodejs.util.promisify.custom')] = (...args) => m.exec(...args);
  return m;
});
vi.mock('@aws-sdk/client-ecs', () => mock.sdk('ECSClient', ['DescribeServicesCommand', 'DescribeTaskDefinitionCommand', 'ListTasksCommand', 'DescribeTasksCommand', 'RegisterTaskDefinitionCommand', 'UpdateServiceCommand', 'DeregisterTaskDefinitionCommand']));
vi.mock('@aws-sdk/client-ssm', () => mock.sdk('SSMClient', ['GetParametersCommand']));
vi.mock('@aws-sdk/client-sts', () => mock.sdk('STSClient', ['GetCallerIdentityCommand']));
vi.mock('@aws-sdk/client-scheduler', () => mock.sdk('SchedulerClient', ['ListScheduleGroupsCommand', 'ListSchedulesCommand']));
vi.mock('@aws-sdk/client-iam', () => mock.sdk('IAMClient', []));
vi.mock('@aws-sdk/client-ecr', () => mock.sdk('ECRClient', ['BatchGetImageCommand']));
vi.mock('node:fs/promises', () => mock.fs);
vi.mock('node:child_process', () => ({execFile: mock.execFile}));
vi.mock('node:timers/promises', () => ({setTimeout: (...args) => mock.sleep(...args)}));
vi.mock('./lib/service-nonroot-aws.mjs', () => ({currentSource: (...args) => mock.source(...args)}));
vi.mock('./lib/application-region.mjs', () => ({resolveApplicationRegion: async () => 'us-east-1'}));
vi.mock('./lib/runtime-live-verification.mjs', () => ({runtimeServerContract: () => ({fixture: true}), verifyRuntimeRoles: (...args) => mock.roles(...args)}));
vi.mock('./lib/service-nonroot-runtime.mjs', () => ({verifyServiceRuntime: (...args) => mock.runtime(...args)}));
import {runServiceNonrootPreview, parsePreviewArgs} from './run-service-nonroot-preview.mjs';

const account = '123456789012', stage = 'pr-17', region = 'us-east-1', cluster = `mem9-on-aws-${stage}-fixture`;
const prefix = `arn:aws:ecs:${region}:${account}:`, oldArn = `${prefix}task-definition/${cluster}-Mem9RuntimeServer:7`, newArn = `${prefix}task-definition/${cluster}-Mem9RuntimeServer:8`;
const source = {commit: 'a'.repeat(40), tree: 'b'.repeat(40), clean: true};
const mergeSha = 'c'.repeat(40), baseSha = 'd'.repeat(40);
const baselinePath = '/private/baseline.local.json', evidenceRoot = '/private/evidence', output = evidenceRoot + '/preview-fixture';
const names = ['mnemo-server', 'qwen3-embed', 'llm-proxy'], repository = 'zxkane/mem9-on-aws';
const copy = v => structuredClone(v);
const fail = code => Object.assign(Error(code), {code, name: code});
afterEach(() => {vi.restoreAllMocks(); vi.unstubAllEnvs();});
function harness() {
  vi.clearAllMocks(); let clock = Date.parse('2026-10-14T12:00:00Z'); vi.spyOn(Date, 'now').mockImplementation(() => clock);
  vi.stubEnv('GITHUB_ACTIONS', 'false');
  mock.sleep.mockImplementation(async ms => {clock += ms;}); mock.source.mockResolvedValue(copy(source));
  const runtimeEnv = [{name: 'MNEMO_SCHEMA_MODE', value: 'verify'}, {name: 'MNEMO_NAMESPACE_REQUIRED', value: '1'}];
  const before = hardenServiceRegistration({family: `${cluster}-Mem9RuntimeServer`, taskRoleArn: `arn:aws:iam::${account}:role/${cluster}-task`, executionRoleArn: `arn:aws:iam::${account}:role/${cluster}-execution`, networkMode: 'awsvpc', cpu: '2048', memory: '6144', runtimePlatform: {cpuArchitecture: 'ARM64', operatingSystemFamily: 'LINUX'}, volumes: [], tags: [{key: 'Stage', value: stage}],
    containerDefinitions: names.map((name, i) => ({name, image: `${account}.dkr.ecr.${region}.amazonaws.com/mem9-on-aws/${name}@sha256:${String(i + 5).repeat(64)}`, linuxParameters: {initProcessEnabled: true}, environment: [{name: 'MEM9_STAGE', value: stage}, {name: 'MEM9_DB_HOST', value: 'preview-db.example.com'}, ...runtimeEnv], secrets: [{name: 'MEM9_DB_SECRET', valueFrom: `arn:aws:ssm:${region}:${account}:parameter/mem9-on-aws/${stage}/runtime/database-credential`}]}))});
  const baseline = {taskDefinition: {family: 'mem9-on-aws-prod-fixture-Mem9RuntimeServer', runtimePlatform: copy(before.runtimePlatform), containerDefinitions: names.map((name, i) => ({name, image: `${account}.dkr.ecr.${region}.amazonaws.com/mem9-on-aws/${name}@sha256:${String(i + 1).repeat(64)}`, environment: [{name: 'DO_NOT_COPY', value: 'production-only'}, ...runtimeEnv]}))}, tags: []};
  const deployment = arn => ({status: 'PRIMARY', taskDefinition: arn, desiredCount: 1, runningCount: 1, pendingCount: 0, rolloutState: 'COMPLETED'});
  const service = {serviceArn: `${prefix}service/${cluster}/Mem9Server`, clusterArn: `${prefix}cluster/${cluster}`, serviceName: 'Mem9Server', status: 'ACTIVE', desiredCount: 1, runningCount: 1, pendingCount: 0, taskDefinition: oldArn, enableExecuteCommand: true,
    deploymentController: {type: 'ECS'}, deploymentConfiguration: {minimumHealthyPercent: 100, maximumPercent: 200, deploymentCircuitBreaker: {enable: true, rollback: false}}, networkConfiguration: {awsvpcConfiguration: {subnets: ['preview-subnet'], securityGroups: ['preview-sg']}}, deployments: [deployment(oldArn)]};
  const h = {before, baseline, service, files: new Map(), synced: new Set(), definitions: new Map([[oldArn, before]]), mutations: [], requests: [], githubCalls: [],
    originalDigests: Object.fromEntries(before.containerDefinitions.map(c => [c.name, c.image.split('@')[1]])), registryDigests: {},
    commit: {sha: mergeSha, parents: [{sha: source.commit}, {sha: baseSha}], commit: {tree: {sha: source.tree}}},
    pr: {number: 17, state: 'open', user: {login: 'fixture-owner'}, head: {sha: source.commit, ref: 'codex/fixture', repo: {full_name: repository}}, base: {ref: 'main', sha: baseSha, repo: {full_name: repository}}},
    ci: {id: 123, name: 'Infra CI', path: '.github/workflows/infra-ci.yml', event: 'pull_request', status: 'completed', conclusion: 'success', head_sha: mergeSha, head_repository: {full_name: repository}, pull_requests: [{number: 17, head: {sha: source.commit}}]},
    ownRun: {id: 234, path: '.github/workflows/infra-ci.yml', event: 'workflow_dispatch', status: 'in_progress', head_sha: source.commit, head_branch: 'codex/fixture', head_repository: {full_name: repository}},
    job: {id: 456, name: 'Deploy PR Preview', status: 'completed', conclusion: 'success', steps: ['Verify preview runtime credentials (hard)', 'MCP write-search E2E (preview, hard)'].map(name => ({name, conclusion: 'success'}))}};
  const values = {'meta/stage': stage, 'ecs/cluster-name': cluster, 'ecs/service-name': 'Mem9Server', 'ecs/task-definition': oldArn,
    'ecs/image-selection': JSON.stringify({version: 1, mode: 'tag', controlTag: `pr-${mergeSha.slice(0, 7)}`, dataTag: `pr-${mergeSha.slice(0, 7)}`}),
    'ecs/image': `${account}.dkr.ecr.${region}.amazonaws.com/mem9-on-aws/preview/mnemo-server:pr-${mergeSha.slice(0, 7)}`,
    'tenant/secret-arn': `arn:aws:secretsmanager:${region}:${account}:secret:${cluster}-tenant`, 'db/host': 'preview-db.example.com',
    'runtime/production-manifest': JSON.stringify({mode: 'active', stage, account, region, cluster, clusterArn: service.clusterArn, service: service.serviceName})};
  h.metadata = values;
  mock.fs.realpath.mockImplementation(async p => p); mock.fs.mkdtemp.mockResolvedValue(output);
  mock.fs.lstat.mockImplementation(async p => ({isFile: () => p === baselinePath, isDirectory: () => p === evidenceRoot, isSymbolicLink: () => false, uid: process.getuid(), mode: p === baselinePath ? 0o600 : 0o700, size: 1000}));
  mock.fs.readFile.mockImplementation(async p => {if (p === baselinePath) return Buffer.from(JSON.stringify(h.baseline)); throw fail('ENOENT');});
  mock.fs.open.mockImplementation(async (p, flags) => {
    if (flags === 'r') return {sync: async () => {}, close: async () => {}};
    expect(flags).toBe('wx'); if (h.files.has(p)) throw fail('EEXIST'); h.files.set(p, '');
    return {writeFile: async body => {h.files.set(p, body);}, sync: async () => {h.synced.add(p);}, close: async () => {}};
  });
  mock.fs.unlink.mockImplementation(async p => {if (!h.files.delete(p)) throw fail('ENOENT');});
  mock.exec.mockImplementation(async (file, args) => {
    if (file === 'git') return {stdout: '', stderr: ''};
    expect(file).toBe('gh'); const path = args.at(-1); h.githubCalls.push(path); let value;
    if (path === 'user') value = {login: 'fixture-owner'};
    else if (path.endsWith('/pulls/17')) value = h.pr;
    else if (path.endsWith('/actions/runs/123')) value = h.ci;
    else if (path.endsWith('/actions/runs/234')) value = h.ownRun;
    else if (path.includes('/commits/')) value = h.commit;
    else if (path.includes('/actions/runs/123/jobs')) value = {total_count: 1, jobs: [h.job]};
    else if (path.includes('/actions/runs?')) {const runs = [...(h.activeRun ? [h.activeRun] : []), ...(h.otherRun ? [h.otherRun] : [])]; value = {total_count: runs.length, workflow_runs: runs};}
    else throw Error('Unexpected mocked GitHub request: ' + path);
    return {stdout: JSON.stringify(value), stderr: ''};
  });
  const originalObservedDigest=name=>h.reportIndexDigests?'sha256:'+createHash('sha256').update(JSON.stringify({schemaVersion:2,manifests:[{platform:{architecture:'arm64',os:'linux'},digest:h.originalDigests[name]}]})).digest('hex'):h.originalDigests[name];
  const tasks = () => [{taskArn: `${prefix}task/${cluster}/fixture-task`, clusterArn: service.clusterArn, group: 'service:Mem9Server', taskDefinitionArn: service.taskDefinition, lastStatus: 'RUNNING', healthStatus: 'HEALTHY',
    containers: h.definitions.get(service.taskDefinition).containerDefinitions.map(c => ({name: c.name, image: c.image, imageDigest: c.image.split('@')[1] ?? (h.restoredBadImage ? 'sha256:' + '0'.repeat(64) : originalObservedDigest(c.name)), runtimeId: 'fixture', lastStatus: 'RUNNING', healthStatus: 'HEALTHY'}))}, ...(h.worker ? [{taskArn: `${prefix}task/${cluster}/worker`, clusterArn: service.clusterArn, group: 'family:worker', lastStatus: 'PENDING'}] : [])];
  mock.send.mockImplementation(async (kind, input) => {
    h.requests.push({kind, input: copy(input)});
    if (kind === 'GetCallerIdentityCommand') return {Account: account};
    if (kind === 'BatchGetImageCommand') {
      const name = input.repositoryName.split('/').at(-1), leaf = h.registryDigests[name] ?? h.originalDigests[name];
      const imageManifest = JSON.stringify({schemaVersion: 2, manifests: [{platform: {architecture: 'arm64', os: 'linux'}, digest: leaf}]});
      return {images: [{registryId: account, repositoryName: input.repositoryName, imageId: {imageTag: input.imageIds[0].imageTag, imageDigest: 'sha256:' + createHash('sha256').update(imageManifest).digest('hex')}, imageManifest}], failures: []};
    }
    if (kind === 'GetParametersCommand') return {Parameters: input.Names.map(Name => ({Name, ARN: `arn:aws:ssm:${region}:${account}:parameter${Name}`, Version: 1, Type: 'String', Value: values[Name.replace(`/mem9-on-aws/${stage}/`, '')]})), InvalidParameters: []};
    if (kind === 'DescribeServicesCommand') return {services: [copy(service)], failures: []};
    if (kind === 'DescribeTaskDefinitionCommand') {
      const {tags, ...d} = h.definitions.get(input.taskDefinition); return {taskDefinition: {...copy(d), taskDefinitionArn: input.taskDefinition, revision: input.taskDefinition === oldArn ? 7 : 8, status: h.inactive && input.taskDefinition === newArn ? 'INACTIVE' : 'ACTIVE'}, tags: copy(tags)};
    }
    if (kind === 'ListTasksCommand') return {taskArns: input.desiredStatus === 'STOPPED' ? [] : tasks().map(t => t.taskArn)};
    if (kind === 'DescribeTasksCommand') return {tasks: tasks().filter(t => input.tasks.includes(t.taskArn)), failures: []};
    if (kind === 'ListScheduleGroupsCommand') return {ScheduleGroups: [{Name: `mem9-on-aws-${stage}-workers`}]};
    if (kind === 'ListSchedulesCommand') return {Schedules: h.schedule ? [{Name: 'fixture', State: 'ENABLED'}] : []};
    if (kind === 'RegisterTaskDefinitionCommand') {
      expect(h.synced.has(output + '/register-intent.json')).toBe(true);
      h.mutations.push('register'); h.definitions.set(newArn, copy(input)); if (h.registerUnknown) throw fail('RequestTimeout');
      if (h.readbackDrift) h.definitions.get(newArn).memory = '9999';
      return {taskDefinition: {taskDefinitionArn: newArn}};
    }
    if (kind === 'UpdateServiceCommand') {
      expect(h.synced.has(output + (input.taskDefinition === oldArn ? '/restore-intent.json' : '/update-intent.json'))).toBe(true);
      h.mutations.push(input.taskDefinition === oldArn ? 'restore' : 'update');
      service.taskDefinition = input.taskDefinition; service.deploymentConfiguration = copy(input.deploymentConfiguration); service.deployments = [deployment(input.taskDefinition)];
      if(h.deploymentObservations){service.currentServiceDeployment=`${prefix}service-deployment/${cluster}/Mem9Server/deployment-${h.mutations.length}`;service.currentServiceRevisions=[{arn:`${prefix}service-revision/${cluster}/Mem9Server/revision-${h.mutations.length}`,requestedTaskCount:1,runningTaskCount:1,pendingTaskCount:0}];}
      h.afterServiceUpdate?.(service,input);
      if (h.restoreUnknown && input.taskDefinition === oldArn) throw fail('RequestTimeout');
      if (h.wrongRestore && input.taskDefinition === oldArn) h.restoredBadImage = true;
      service.pendingCount = h.neverStable && input.taskDefinition === newArn ? 1 : 0;
      if (h.updateUnknown && input.taskDefinition === newArn) throw fail('RequestTimeout');
      return {service: copy(service)};
    }
    if (kind === 'DeregisterTaskDefinitionCommand') {expect(h.synced.has(output + '/deregister-intent.json')).toBe(true); expect(input.taskDefinition).toBe(newArn); h.mutations.push('deregister'); h.inactive = true; return {taskDefinition: {taskDefinitionArn: newArn, status: 'INACTIVE'}};}
    throw Error('Unexpected mocked SDK call: ' + kind);
  });
  mock.roles.mockResolvedValue(undefined);
  mock.runtime.mockImplementation(async (arn, {scope: runtimeScope, aws, authMode}) => {
    expect(runtimeScope.stage).toBe(stage); expect(authMode).toBe('managed'); expect(arn).toBe(newArn);
    if (h.runtimeFailure) throw fail('RuntimeMismatch');
    if (h.retagDuringProbe) h.registryDigests['mnemo-server'] = 'sha256:' + '0'.repeat(64);
    const observed = await aws.inventory();
    const evidence = {processEvidence: observed.flatMap(t => t.containers.map(c => ({taskArn: t.taskArn, container: c.name, runtimeId: c.runtimeId,
      processes: [{pid: '/proc/7', Application: c.name === 'mnemo-server' ? 'mnemo-server' : 'node-server', IdentitySource: 'proc-cmdline-prefix', Uid: '1000 1000 1000 1000', Gid: '1000 1000 1000 1000', CapInh: '0000', CapPrm: '0000', CapEff: '0000', CapBnd: '0000', CapAmb: '0000', NoNewPrivs: '1'}]}))),
      mcp: {kind: 'service-mcp-read-verification', observedMs: Date.now(), unauthenticatedStatus: 401, readScopeIsolated: true, results: ['semantic', 'keyword'].map(mode => ({mode, returned: 0, responseHash: 'f'.repeat(64)}))}};
    await aws.persistOnce('runtime-verification.json', evidence);
    return {tasks: await aws.inventory(), evidenceHash: hash(evidence)};
  });
  h.options = () => ({stage, baselinePath, baselineHash: createHash('sha256').update(JSON.stringify(h.baseline)).digest('hex'), evidenceRoot, expectedSource: source.commit, ciRunId: '123'});
  h.run = options => runServiceNonrootPreview({...h.options(), ...options});
  return h;
}

describe('actual frozen image preview rehearsal', () => {
  it('verifies and restores a deployment whose ECS revision observations change on each update',async()=>{
    const h=harness();h.deploymentObservations=true;
    h.service.currentServiceRevisions=[{arn:`${prefix}service-revision/${cluster}/Mem9Server/original`,requestedTaskCount:1,runningTaskCount:1,pendingTaskCount:0}];
    const result=await h.run();expect(result.outcome).toBe('PASS');expect(result.cleanup.complete).toBe(true);
    expect(h.mutations).toEqual(['register','update','restore','deregister']);expect(mock.runtime).toHaveBeenCalled();
  });
  it.each(['network','desired','unknown','circuit-breaker'])('holds real %s changes even when deployment observations are expected to change',async kind=>{
    const h=harness();h.deploymentObservations=true;
    h.afterServiceUpdate=(service,input)=>{if(input.taskDefinition!==newArn)return;
      if(kind==='network')service.networkConfiguration.awsvpcConfiguration.subnets=['other-subnet'];
      if(kind==='desired')service.desiredCount=2;
      if(kind==='unknown')service.futureConfiguration={changed:true};
      if(kind==='circuit-breaker')service.deploymentConfiguration.deploymentCircuitBreaker.rollback=true;
    };
    const result=await h.run();expect(result.outcome).toBe('HELD');expect(result.failures).toContain('PreviewNonrootServiceChanged');
    expect(result.cleanup.complete).toBe(false);expect(h.mutations).toEqual(['register','update']);expect(mock.runtime).not.toHaveBeenCalled();
  });
  it('uses preview credentials, verifies real-helper scope, restores and deregisters exactly its revision', async () => {
    const h = harness(), result = await h.run();
    expect(result.outcome).toBe('PASS'); expect(result.cleanup.complete).toBe(true);
    expect(h.mutations).toEqual(['register', 'update', 'restore', 'deregister']);
    const target = h.definitions.get(newArn);
    expect({...target, containerDefinitions: h.before.containerDefinitions}).toEqual(h.before);
    for (const c of target.containerDefinitions) expect({...c, image: h.before.containerDefinitions.find(v => v.name === c.name).image}).toEqual(h.before.containerDefinitions.find(v => v.name === c.name));
    expect(JSON.stringify(result)).not.toContain('production-only');
    expect(result.sourceTree).toBe(source.tree); expect(result.processEvidence).toHaveLength(3);
    expect(result.github.imageProof).toEqual({namespace: 'mem9-on-aws/preview', tag: 'pr-ccccccc', commit: mergeSha});
    expect(result.productionRegistrationHash).toMatch(/^[a-f0-9]{64}$/);
    expect(result.targetDefinition.taskDefinition.status).toBe('ACTIVE'); expect(result.cleanup.verified).toBe(true);
    expect(result.evidenceHash).toBe(createHash('sha256').update(h.files.get(output + '/report.local.json')).digest('hex'));
    expect(mock.roles).toHaveBeenCalled(); expect(h.service.taskDefinition).toBe(oldArn);
  });
  it.each(['prod', 'pr-0', 'pr-17-extra'])('rejects invalid preview stage %s before cloud access', async badStage => {
    const h = harness(); await expect(h.run({stage: badStage})).rejects.toThrow(); expect(h.requests).toHaveLength(0);
  });
  it.each(['owner', 'source', 'ci', 'skipped', 'active', 'ssm', 'root', 'worker', 'schedule', 'roles', 'digest', 'registry', 'baseline-hash'])('holds %s failures before registration', async kind => {
    const h = harness(), options = {};
    if (kind === 'owner') h.pr.user.login = 'someone-else';
    if (kind === 'source') h.pr.head.sha = 'c'.repeat(40);
    if (kind === 'ci') h.ci.conclusion = 'failure';
    if (kind === 'skipped') h.job.steps[0].conclusion = 'skipped';
    if (kind === 'active') h.activeRun = {head_branch: h.pr.head.ref, status: 'in_progress'};
    if (kind === 'ssm') h.metadata['meta/stage'] = 'prod';
    if (kind === 'root') delete h.before.containerDefinitions[0].user;
    if (kind === 'worker') h.worker = true;
    if (kind === 'schedule') h.schedule = true;
    if (kind === 'roles') mock.roles.mockRejectedValue(Error('RuntimeRoleBoundaryMismatch'));
    if (kind === 'digest') h.baseline.taskDefinition.containerDefinitions[0].image = 'example.invalid/mnemo:latest';
    if (kind === 'registry') h.baseline.taskDefinition.containerDefinitions[0].image = h.baseline.taskDefinition.containerDefinitions[0].image.replace(account, '0'.repeat(12));
    if (kind === 'baseline-hash') options.baselineHash = '0'.repeat(64);
    const result = await h.run(options); expect(result.outcome).toBe('HELD'); expect(h.mutations).toEqual([]);
  });
  it.each(['register', 'update'])('does not retry or automatically restore after an ambiguous %s', async phase => {
    const h = harness(); h[phase + 'Unknown'] = true;
    const result = await h.run(); expect(result.outcome).toBe('HELD'); expect(result.cleanup.complete).toBe(false);
    expect(h.mutations).toEqual(phase === 'register' ? ['register'] : ['register', 'update']);
    expect([...h.files.keys()].some(k => k.endsWith(`/${phase}-intent.json`))).toBe(true);
  });
  it('cleans up a known runtime failure without reporting success', async () => {
    const h = harness(); h.runtimeFailure = true;
    const result = await h.run(); expect(result.outcome).toBe('HELD'); expect(result.cleanup.complete).toBe(true);
    expect(h.mutations).toEqual(['register', 'update', 'restore', 'deregister']);
  });
  it('rejects changed registration readback before update', async () => {
    const h = harness(); h.readbackDrift = true;
    const result = await h.run(); expect(result.outcome).toBe('HELD'); expect(h.mutations).not.toContain('update');
  });
  it('parses only the documented explicit CLI options', () => {
    expect(parsePreviewArgs(['--stage', stage, '--baseline', baselinePath, '--baseline-hash', 'a'.repeat(64), '--evidence-root', evidenceRoot, '--ci-run', '123'])).toMatchObject({stage, baselinePath, ciRunId: '123'});
    expect(() => parsePreviewArgs(['--stage', stage, '--module', 'unsafe'])).toThrow();
  });
  it.each(['tag', 'merge-tree', 'head-parent', 'base-parent', 'ci-commit', 'active-mode', 'schema-mode', 'namespace', 'platform'])('rejects %s mismatch without changing the disposable fixture', async kind => {
    const h = harness();
    if (kind === 'tag') {const s = JSON.parse(h.metadata['ecs/image-selection']); s.controlTag = 'pr-fffffff'; h.metadata['ecs/image-selection'] = JSON.stringify(s);}
    if (kind === 'merge-tree') h.commit.commit.tree.sha = 'f'.repeat(40);
    if (kind === 'head-parent') h.commit.parents[0].sha = 'f'.repeat(40);
    if (kind === 'base-parent') h.commit.parents[1].sha = 'f'.repeat(40);
    if (kind === 'ci-commit') h.ci.head_sha = 'f'.repeat(40);
    if (kind === 'active-mode') {const m = JSON.parse(h.metadata['runtime/production-manifest']); m.mode = 'ready'; h.metadata['runtime/production-manifest'] = JSON.stringify(m);}
    if (kind === 'schema-mode') h.before.containerDefinitions[0].environment.find(e => e.name === 'MNEMO_SCHEMA_MODE').value = 'bootstrap';
    if (kind === 'namespace') h.before.containerDefinitions[0].environment.find(e => e.name === 'MNEMO_NAMESPACE_REQUIRED').value = '0';
    if (kind === 'platform') h.before.runtimePlatform.cpuArchitecture = 'X86_64';
    const result = await h.run(); expect(result.outcome).toBe('HELD'); expect(h.mutations).toEqual([]);
  });
  it('accepts a retained selection only with the exact existing pinned images and leaf digests', async () => {
    const h = harness(), images = Object.fromEntries(h.before.containerDefinitions.map(c => [c.name, c.image]));
    h.metadata['ecs/image-selection'] = JSON.stringify({version: 1, mode: 'retained', controlTag: 'pr-ccccccc', dataTag: 'pr-eeeeeee', images, dataReleaseHash: 'f'.repeat(64), arm64Digests: Object.fromEntries(Object.entries(images).map(([k, v]) => [k, v.split('@')[1]]))});
    expect((await h.run()).outcome).toBe('PASS');
  });
  function ci(h) {
    vi.stubEnv('GITHUB_ACTIONS', 'true'); vi.stubEnv('GITHUB_REPOSITORY', repository); vi.stubEnv('GITHUB_RUN_ID', '234'); vi.stubEnv('GITHUB_SHA', source.commit);
    h.activeRun = h.ownRun; h.pr.user.login = 'app-owned-pr';
  }
  it('allows exactly its verified active dispatch without calling the GitHub user endpoint', async () => {
    const h = harness(); ci(h); const result = await h.run();
    expect(result.outcome).toBe('PASS'); expect(result.github.activeRunId).toBe(234); expect(h.githubCalls).not.toContain('user');
  });
  it.each(['event', 'path', 'head', 'repository', 'branch', 'completed', 'other-run'])('does not exempt an untrusted active CI context: %s', async kind => {
    const h = harness(); ci(h);
    if (kind === 'event') h.ownRun.event = 'pull_request';
    if (kind === 'path') h.ownRun.path = '.github/workflows/other.yml';
    if (kind === 'head') h.ownRun.head_sha = mergeSha;
    if (kind === 'repository') h.ownRun.head_repository.full_name = 'other/repo';
    if (kind === 'branch') h.ownRun.head_branch = 'main';
    if (kind === 'completed') h.ownRun.status = 'completed';
    if (kind === 'other-run') h.otherRun = {...copy(h.ownRun), id: 345};
    const result = await h.run(); expect(result.outcome).toBe('HELD'); expect(h.mutations).toEqual([]);
  });
  it('bounds rollout observation and restores the already nonroot baseline after a known timeout', async () => {
    const h = harness(); h.neverStable = true; const result = await h.run();
    expect(result.outcome).toBe('HELD'); expect(result.cleanup.verified).toBe(true);
    expect(h.mutations).toEqual(['register', 'update', 'restore', 'deregister']);
  });
  it('never retries an ambiguous restore or deregisters a potentially serving revision', async () => {
    const h = harness(); h.restoreUnknown = true; const result = await h.run();
    expect(result.outcome).toBe('HELD'); expect(result.cleanup.verified).toBe(false);
    expect(h.mutations).toEqual(['register', 'update', 'restore']);
    expect(h.files.has(evidenceRoot + '/pr-17-nonroot.lock.json')).toBe(true);
  });
  function tagged(h) {for (const c of h.before.containerDefinitions) c.image = `${account}.dkr.ecr.${region}.amazonaws.com/mem9-on-aws/preview/${c.name}:pr-${mergeSha.slice(0, 7)}`;}
  it('accepts finalized CI-tagged active images and preserves their original declarations and observed digests', async () => {
    const h = harness(); tagged(h); ci(h); const result = await h.run();
    expect(result.outcome).toBe('PASS'); expect(h.mutations).toEqual(['register', 'update', 'restore', 'deregister']);
    expect(result.originalDefinition.taskDefinition.containerDefinitions.map(c => c.image)).toEqual(h.before.containerDefinitions.map(c => c.image));
    for (const c of h.before.containerDefinitions) expect(result.originalImageEvidence[c.name]).toMatchObject({image: c.image, imageDigest: h.originalDigests[c.name]});
    expect(result.cleanup.restoredTasks[0].containers.map(c => c.imageDigest)).toEqual(names.map(n => h.originalDigests[n]));
    expect(result.evidenceFiles.some(f => f.name === 'original-images.json')).toBe(true);
    for (const f of result.evidenceFiles) {const body = h.files.get(output + '/' + f.name); expect(f.sha256).toBe(createHash('sha256').update(body).digest('hex')); expect(f.bytes).toBe(Buffer.byteLength(body));}
  });
  it('accepts and restores verified index digests reported by ECS for tagged originals',async()=>{
    const h=harness();tagged(h);ci(h);h.reportIndexDigests=true;const result=await h.run();
    expect(result.outcome).toBe('PASS');expect(h.mutations).toEqual(['register','update','restore','deregister']);
    for(const c of result.cleanup.restoredTasks[0].containers)expect(c.imageDigest).toBe(result.originalImageEvidence[c.name].registryDigest);
  });
  it.each(['unrelated-tag', 'running-digest', 'retagged-before-restore', 'changed-after-restore'])('holds tagged original image mismatch: %s', async kind => {
    const h = harness(); tagged(h);
    if (kind === 'unrelated-tag') h.before.containerDefinitions[0].image = h.before.containerDefinitions[0].image.replace('pr-ccccccc', 'pr-eeeeeee');
    if (kind === 'running-digest') h.registryDigests['mnemo-server'] = 'sha256:' + '0'.repeat(64);
    if (kind === 'retagged-before-restore') h.retagDuringProbe = true;
    if (kind === 'changed-after-restore') h.wrongRestore = true;
    const result = await h.run(); expect(result.outcome).toBe('HELD');
    if (['unrelated-tag', 'running-digest'].includes(kind)) expect(h.mutations).toEqual([]);
    else {expect(result.cleanup.verified).toBe(false); expect(h.mutations).not.toContain('deregister');}
    if (kind === 'retagged-before-restore') expect(h.mutations).not.toContain('restore');
  });
});
