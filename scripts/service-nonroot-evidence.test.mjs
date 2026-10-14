import {it, expect, afterEach} from 'vitest';
import {mkdtemp, mkdir, writeFile, rm, chmod, symlink} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
import {validateServiceEvidence} from './lib/service-nonroot-evidence.mjs';
import {hardenServiceRegistration, frozenServiceRegistration, registrationInput, serviceNonrootHash as hash} from './lib/service-nonroot.mjs';
import {taggedServiceDefinition} from './test-fixtures/service-nonroot-images.mjs';

const directories = [], sha = v => createHash('sha256').update(v).digest('hex'), copy = structuredClone;
const names = ['mnemo-server', 'qwen3-embed', 'llm-proxy'], ecs = 'arn:aws:ecs:us-east-1:123456789012:';
const status = () => ({Uid: '1000\t1000\t1000\t1000', Gid: '1000 1000 1000 1000', NoNewPrivs: '1',
  ...Object.fromEntries(['CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb'].map(k => [k, '0000000000000000']))});
afterEach(async () => {await Promise.all(directories.splice(0).map(path => rm(path, {recursive: true, force: true})));});
async function fixture({tagged=false}={}) {
  const root = await mkdtemp(join(tmpdir(), 'nonroot-evidence-test-')); directories.push(root);
  await mkdir(join(root, 'scripts/lib'), {recursive: true});
  await writeFile(join(root, 'scripts/run-service-nonroot-smoke.mjs'), 'synthetic reviewed smoke source');
  await writeFile(join(root, 'scripts/lib/service-nonroot.mjs'), 'synthetic reviewed transform source');
  await writeFile(join(root, 'scripts/lib/service-nonroot-runtime.mjs'), 'synthetic reviewed runtime source');
  const registration = {family: 'synthetic-prod-runtime', networkMode: 'awsvpc', cpu: '2048', memory: '6144',
    runtimePlatform: {cpuArchitecture: 'ARM64', operatingSystemFamily: 'LINUX'}, tags: [],
    containerDefinitions: names.map((name, i) => ({name, image: `example.com/${name}@sha256:${String(i + 1).repeat(64)}`,
      linuxParameters: {initProcessEnabled: true}, environment: [{name: 'MNEMO_LLM_MODEL', value: 'synthetic-model'}, {name: 'MNEMO_SCHEMA_MODE', value: 'verify'}]}))};
  const definition = (registration, revision) => {const {tags, ...rest} = copy(registration); return {tags, taskDefinition: {...rest,
    taskDefinitionArn: `${ecs}task-definition/${rest.family}:${revision}`, revision, status: 'ACTIVE'}};};
  const rawBaseline=definition(registration,7),boundService={clusterArn:ecs+'cluster/synthetic-prod',serviceName:'Mem9Server',taskDefinition:rawBaseline.taskDefinition.taskDefinitionArn,desiredCount:1};
  const baseline = tagged?taggedServiceDefinition(rawBaseline,boundService):rawBaseline, plan = {baseline: {definition: copy(baseline),...(tagged?{service:boundService}:{})}, target: hardenServiceRegistration(frozenServiceRegistration(baseline)),
    source: {tree: 'a'.repeat(40)}, scope: {accountId: '123456789012', region: 'us-east-1', clusterArn: ecs + 'cluster/synthetic-prod', serviceArn: ecs + 'service/synthetic-prod/Mem9Server'}};
  const images = Object.fromEntries(plan.target.containerDefinitions.map(c => [c.name, c.image]));
  const checks = Object.fromEntries(['internalNetwork', 'proxyExactEntrypointHealth', 'proxySyntheticHttpUpstream', 'frozenRuntimeBootstrap',
    'verifyRejectsUnreadySchema', 'mnemoVerifyEntrypointHealth', 'runtimeRoleReadinessAndDdlDenial', 'missingSignature', 'wrongTenant',
    'expiredSignature', 'semanticNamespaceSearch', 'keywordNamespaceSearch', 'crossNamespaceReadDenied'].map(k => [k, true]));
  const localImages = tagged?Object.fromEntries(['mnemo-server','llm-proxy'].map(n=>[n,JSON.parse(baseline.imageBindings.images[n].leafManifest).config.digest])):{'mnemo-server': 'sha256:' + '4'.repeat(64), 'llm-proxy': 'sha256:' + '5'.repeat(64)};
  for (const [prefix, name, paths] of [['mnemo', 'mnemo-server', ['/usr/local/bin/mnemo-server', '/usr/local/bin/entrypoint.sh', '/usr/local/share/mem9']],
    ['proxy', 'llm-proxy', ['/app/server.mjs', '/app/node_modules', '/app']]]) {
    checks[prefix + 'Process'] = {status: {Pid: '7', ...status()}, writableTmp: true, deniedWrites: paths};
    checks[prefix + 'RootObserver'] = {observer: {...status(), Uid: '0 0 0 0', Gid: '0 0 0 0', NoNewPrivs: '0'},
      processes: [{pid: '/proc/7', Application: name === 'mnemo-server' ? 'mnemo-server' : 'node-server', IdentitySource: 'proc-cmdline-prefix', ...status()}]};
    checks[prefix + 'ContainerConfiguration'] = {image: localImages[name], user: '1000:1000', init: true, capDrop: ['ALL']};
    if(tagged)Object.assign(checks[prefix+'ContainerConfiguration'],{reference:images[name],descriptor:null});
  }
  checks.proxyModule = Object.fromEntries(['exportedModule', 'realTokenGenerator', 'syntheticSessionsOnly', 'healthBeforeMint', 'healthAfterMint', 'authRemint', 'timedRefresh', 'credentialFailure', 'invalidRequest'].map(k => [k, true]));
  Object.assign(checks, {missingSignatureObservation: {status: 403}, expiredSignatureObservation: {status: 403}, wrongTenantObservation: {status: 400},
    syntheticDependencyCalls: {embeddings: 1, upstream: 1}, fixtureContainerConfiguration: {}, postgresContainerConfiguration: {}});
  const suite = {version: 1, scope: 'local-actual-images-synthetic-only', outcome: 'PASS', phase: 'complete', checks, images: localImages,
    source: {scriptHash: sha('synthetic reviewed smoke source'), transformHash: sha('synthetic reviewed transform source'), runtimeHash: sha('synthetic reviewed runtime source')}, failures: [], cleanup: {complete: true, failures: []}};
  const embedding = {image: images['qwen3-embed'], isolatedNetwork: 'none', result: {status: 200, dimensions: 1024, norm: 1.00000007},
    applicationIdentity: Object.entries(status()).map(([key, value]) => key + ': ' + value).join('\n')};
  if(tagged){suite.imagePlatforms=Object.fromEntries(['mnemo-server','llm-proxy'].map(n=>[n,{os:'linux',architecture:'arm64'}]));embedding.imageId=JSON.parse(baseline.imageBindings.images['qwen3-embed'].leafManifest).config.digest;embedding.platform={os:'linux',architecture:'arm64'};}
  const old = hardenServiceRegistration({...frozenServiceRegistration(baseline), family: 'synthetic-pr-123-runtime'}), target = hardenServiceRegistration(old), targetDefinition = definition(target, 8);
  const taskArn = ecs + 'task/synthetic-pr-123/task-one', clusterArn = ecs + 'cluster/synthetic-pr-123';
  const service = {serviceArn: ecs + 'service/synthetic-pr-123/Preview', clusterArn, serviceName: 'Preview', status: 'ACTIVE',
    taskDefinition: targetDefinition.taskDefinition.taskDefinitionArn, desiredCount: 1, runningCount: 1, pendingCount: 0,
    deployments: [{taskDefinition: targetDefinition.taskDefinition.taskDefinitionArn, rolloutState: 'COMPLETED'}]};
  const tasks = [{taskArn, clusterArn, group: 'service:Preview', taskDefinitionArn: service.taskDefinition, lastStatus: 'RUNNING', healthStatus: 'HEALTHY',
    containers: names.map(name => ({name, image: images[name], imageDigest: images[name].split('@')[1], runtimeId: name + '-runtime', lastStatus: 'RUNNING', healthStatus: 'HEALTHY'}))}];
  const preview = {outcome: 'PASS', stage: 'pr-123', sourceTree: plan.source.tree, productionRegistrationHash: hash(plan.target),
    originalDefinition: definition(old, 7), targetDefinition, service, tasks,
    processEvidence: names.map(name => ({taskArn, container: name, runtimeId: name + '-runtime', processes: [{pid: '/proc/7',
      Application: name === 'mnemo-server' ? 'mnemo-server' : 'node-server', IdentitySource: 'proc-cmdline-prefix', ...status()}]})),
    mcp: {kind: 'service-mcp-read-verification', unauthenticatedStatus: 401, readScopeIsolated: true,
      results: ['semantic', 'keyword'].map(mode => ({mode, returned: 1, responseHash: '6'.repeat(64)}))},
    cleanup: {verified: true, remainingCandidateTasks: [], failures: []}};
  const values = {local: {images, registrationHash: hash(plan.target)}, preview: {images, registrationHash: hash(plan.target)}};
  if(tagged)values.images={images,imageBindings:copy(baseline.imageBindings)};
  const save = async (name, value) => {const path = join(root, name + '.local.json'), bytes = JSON.stringify(value); await writeFile(path, bytes, {mode: 0o600}); return {path, hash: sha(bytes)};};
  const write = async () => {
    const b = await save('baseline', baseline); suite.baselineHash = b.hash;
    if(tagged&&preview.baselineHash===undefined)preview.baselineHash=b.hash;
    for (const [key, ref] of [['baseline', b], ['suite', await save('suite', suite)], ['embedding', await save('embedding', embedding)]])
      Object.assign(values.local, {[key + 'Path']: ref.path, [key + 'Hash']: ref.hash});
    const p = await save('preview', preview); Object.assign(values.preview, {receiptPath: p.path, receiptHash: p.hash});
  };
  await write(); return {root, baseline, plan, values, suite, embedding, preview, write, validate: () => validateServiceEvidence(plan, values, {root})};
}
it('accepts complete candidate-bound receipts with actual process, source, query and cleanup evidence', async () => {
  const f = await fixture(); expect(await f.validate()).toEqual({registrationHash: hash(f.plan.target), suiteHash: f.values.local.suiteHash,
    embeddingHash: f.values.local.embeddingHash, previewHash: f.values.preview.receiptHash});
});
it('binds a tagged baseline and its image proof across local, preview and plan evidence',async()=>{
  const f=await fixture({tagged:true});await expect(f.validate()).resolves.toHaveProperty('registrationHash',hash(f.plan.target));
});
it('binds containerd platform-manifest IDs and actual container descriptors to the same verified leaf',async()=>{
  const f=await fixture({tagged:true});f.suite.imageDescriptors={};
  for(const [prefix,name] of [['mnemo','mnemo-server'],['proxy','llm-proxy'],['embedding','qwen3-embed']]){
    const raw=f.baseline.imageBindings.images[name].leafManifest,id='sha256:'+sha(raw),descriptor={digest:id,mediaType:JSON.parse(raw).mediaType,platform:{os:'linux',architecture:'arm64'}};
    if(prefix==='embedding'){f.embedding.imageId=id;f.embedding.descriptor=descriptor;}
    else{f.suite.images[name]=id;f.suite.imageDescriptors[name]=descriptor;Object.assign(f.suite.checks[prefix+'ContainerConfiguration'],{image:id,descriptor});}
  }
  await f.write();await expect(f.validate()).resolves.toHaveProperty('previewHash');
  f.suite.checks.mnemoContainerConfiguration.descriptor={...f.suite.checks.mnemoContainerConfiguration.descriptor,digest:'sha256:'+'f'.repeat(64)};
  await f.write();await expect(f.validate()).rejects.toThrow();
});
it.each(['local-proof','review-proof','preview-baseline','service-count','local-image-config','local-platform','embedding-config','embedding-platform','injected-image-id','injected-embedding-id'])('rejects %s substitution even when the frozen images are unchanged',async kind=>{
  const f=await fixture({tagged:true});
  if(kind==='local-proof')f.baseline.imageBindings.tasks[0].taskArn=f.baseline.imageBindings.tasks[0].taskArn.replace(/a{32}$/,'b'.repeat(32));
  if(kind==='review-proof')f.values.images.imageBindings.tasks[0].taskArn=f.values.images.imageBindings.tasks[0].taskArn.replace(/a{32}$/,'b'.repeat(32));
  if(kind==='preview-baseline')f.preview.baselineHash='f'.repeat(64);
  if(kind==='service-count')f.plan.baseline.service.desiredCount=2;
  if(kind==='local-image-config'){f.suite.images['mnemo-server']='sha256:'+'f'.repeat(64);f.suite.checks.mnemoContainerConfiguration.image=f.suite.images['mnemo-server'];}
  if(kind==='local-platform')f.suite.imagePlatforms['mnemo-server'].architecture='amd64';
  if(kind==='embedding-config')f.embedding.imageId='sha256:'+'f'.repeat(64);
  if(kind==='embedding-platform')f.embedding.platform.os='windows';
  if(kind==='injected-image-id'){f.suite.imagePlatforms['mnemo-server'].id=f.suite.images['mnemo-server'];f.suite.images['mnemo-server']='sha256:'+'f'.repeat(64);f.suite.checks.mnemoContainerConfiguration.image=f.suite.images['mnemo-server'];}
  if(kind==='injected-embedding-id'){f.embedding.platform.id=f.embedding.imageId;f.embedding.imageId='sha256:'+'f'.repeat(64);}
  await f.write();await expect(f.validate()).rejects.toThrow();
});
it.each(['local', 'preview'])('rejects summary-only %s evidence', async key => {
  const f = await fixture(); f.values[key] = {images: f.values[key].images, outcome: 'passed'}; await expect(f.validate()).rejects.toThrow();
});
const mutations = {
  baseline: f => {f.baseline.taskDefinition.cpu = '4096';},
  rootCandidate: f => {f.plan.target.containerDefinitions[0].user = '0';},
  localImage: f => {f.values.local.images = {...f.values.local.images, 'mnemo-server': 'wrong'};},
  localRegistration: f => {f.values.local.registrationHash = '0'.repeat(64);},
  suiteBaseline: f => {f.suite.source.scriptHash = '0'.repeat(64);},
  transformSource: f => {f.suite.source.transformHash = '0'.repeat(64);},
  runtimeSource: f => {f.suite.source.runtimeHash = '0'.repeat(64);},
  rootObserverMissing: f => {delete f.suite.checks.mnemoRootObserver;},
  rootObserverPrivileged: f => {f.suite.checks.proxyRootObserver.observer.CapEff = '0001';},
  rootObserverWrongPid: f => {f.suite.checks.proxyRootObserver.processes[0].pid = '/proc/8';},
  rootObserverWrongApplication: f => {f.suite.checks.proxyRootObserver.processes[0].Application = 'mnemo-server';},
  rootObserverWrongSource: f => {f.suite.checks.proxyRootObserver.processes[0].IdentitySource = 'unverified';},
  obsoleteExecutableClaim: f => {f.preview.processEvidence[0].processes[0].Executable = '/usr/local/bin/mnemo-server';},
  localFailure: f => {f.suite.failures.push('failed');},
  localCleanup: f => {f.suite.cleanup.complete = false;},
  rootProcess: f => {f.suite.checks.mnemoProcess.status.Uid = '1000 1000 0 1000';},
  capabilities: f => {f.suite.checks.proxyProcess.status.CapAmb = '0001';},
  escalation: f => {f.suite.checks.proxyProcess.status.NoNewPrivs = '0';},
  writableCode: f => {f.suite.checks.proxyProcess.deniedWrites = [];},
  runtimeReadiness: f => {f.suite.checks.runtimeRoleReadinessAndDdlDenial = false;},
  missingAuth: f => {delete f.suite.checks.missingSignature;},
  expiredAuth: f => {f.suite.checks.expiredSignature = false;},
  namespaceLeak: f => {f.suite.checks.crossNamespaceReadDenied = false;},
  proxyRefresh: f => {f.suite.checks.proxyModule.timedRefresh = false;},
  qwenImage: f => {f.embedding.image = f.values.local.images['llm-proxy'];},
  qwenNetwork: f => {f.embedding.isolatedNetwork = 'bridge';},
  qwenDimensions: f => {f.embedding.result.dimensions = 1536;},
  qwenNorm: f => {f.embedding.result.norm = 0.9;},
  qwenIdentity: f => {f.embedding.applicationIdentity = 'Uid: 1000 1000 1000 1000';},
  qwenDuplicateIdentity: f => {f.embedding.applicationIdentity += '\nNoNewPrivs: 1';},
  previewRoot: f => {f.preview.targetDefinition.taskDefinition.containerDefinitions[0].user = '0';},
  previewCapabilities: f => {f.preview.targetDefinition.taskDefinition.containerDefinitions[0].linuxParameters.capabilities.drop = [];},
  previewRuntime: f => {f.preview.targetDefinition.taskDefinition.memory = '4096';},
  previewModel: f => {for (const def of [f.preview.originalDefinition, f.preview.targetDefinition]) def.taskDefinition.containerDefinitions[0].environment[0].value = 'different-model';},
  previewSource: f => {f.preview.sourceTree = 'b'.repeat(40);},
  previewProductionBinding: f => {f.preview.productionRegistrationHash = '0'.repeat(64);},
  previewPending: f => {f.preview.service.pendingCount = 1;},
  previewOldTask: f => {f.preview.tasks[0].taskDefinitionArn = f.preview.originalDefinition.taskDefinition.taskDefinitionArn;},
  previewWrongImage: f => {f.preview.tasks[0].containers[1].imageDigest = 'sha256:' + '9'.repeat(64);},
  previewMissingProcess: f => {f.preview.processEvidence.pop();},
  previewProcessRestart: f => {f.preview.processEvidence[0].runtimeId = 'old-runtime';},
  previewRootProcess: f => {f.preview.processEvidence[1].processes[0].Gid = '0 0 0 0';},
  previewMissingSemantic: f => {f.preview.mcp.results[0].mode = 'keyword';},
  previewUnauthenticated: f => {f.preview.mcp.unauthenticatedStatus = 200;},
  previewWriteScope: f => {f.preview.mcp.readScopeIsolated = false;},
  previewCleanup: f => {f.preview.cleanup.verified = false;},
  previewTasksRemain: f => {f.preview.cleanup.remainingCandidateTasks.push('owned-task');},
};
it.each(Object.keys(mutations))('rejects %s even with recomputed receipt hashes', async name => {
  const f = await fixture(); mutations[name](f); await f.write(); await expect(f.validate()).rejects.toThrow();
});
it('binds SHA-256 to raw bytes rather than parsed JSON', async () => {
  const f = await fixture(); await writeFile(f.values.local.suitePath, JSON.stringify(f.suite, null, 2)); await expect(f.validate()).rejects.toThrow('ReceiptHash');
});
it('rejects changed on-disk source', async () => {
  const f = await fixture(); await writeFile(join(f.root, 'scripts/run-service-nonroot-smoke.mjs'), 'changed'); await expect(f.validate()).rejects.toThrow('SmokeSource');
});
it('rejects group-readable evidence and symbolic links', async () => {
  const f = await fixture(); await chmod(f.values.local.suitePath, 0o640); await expect(f.validate()).rejects.toThrow('ReceiptPermissions');
  await chmod(f.values.local.suitePath, 0o600); const link = join(f.root, 'linked.json'); await symlink(f.values.local.suitePath, link);
  f.values.local.suitePath = link; await expect(f.validate()).rejects.toThrow('ReceiptSymlink');
});
it('never includes changed environment values in validation errors', async () => {
  const f = await fixture(); f.preview.targetDefinition.taskDefinition.containerDefinitions[0].environment.push({name: 'SYNTHETIC', value: 'do-not-print-this-fixture-value'});
  await f.write(); try {await f.validate(); throw Error('unexpected pass');} catch (error) {expect(error.message).toBe('ServiceEvidencePreviewCandidate');}
});
async function taggedFixture() {
  const f = await fixture(), p = f.preview, head = 'b'.repeat(40), merge = 'c'.repeat(40), base = 'd'.repeat(40);
  p.source = {commit: head, tree: p.sourceTree};
  p.github = {ciHeadSha: merge, baseSha: base, imageProof: {namespace: 'mem9-on-aws/preview', tag: 'pr-ccccccc', commit: merge}, imageCommit: {sha: merge, tree: p.sourceTree, parents: [base, head]}};
  p.originalImageEvidence = {};
  for (const c of p.originalDefinition.taskDefinition.containerDefinitions) {
    const imageDigest = c.image.split('@')[1];
    c.image = `123456789012.dkr.ecr.us-east-1.amazonaws.com/mem9-on-aws/preview/${c.name}:pr-ccccccc`;
    const imageManifest = JSON.stringify({schemaVersion: 2, manifests: [{platform: {architecture: 'arm64', os: 'linux'}, digest: imageDigest}]});
    p.originalImageEvidence[c.name] = {image: c.image, imageDigest, registryDigest: 'sha256:' + sha(imageManifest), imageManifest};
  }
  p.originalTasks = copy(p.tasks); p.originalTasks[0].taskDefinitionArn = p.originalDefinition.taskDefinition.taskDefinitionArn;
  for (const c of p.originalTasks[0].containers) c.image = p.originalDefinition.taskDefinition.containerDefinitions.find(o => o.name === c.name).image;
  p.cleanup.restoredTasks = copy(p.originalTasks); p.cleanup.restoredTasks[0].taskArn = p.service.clusterArn.replace(':cluster/', ':task/') + '/restored';
  p.cleanup.restoredDefinition = p.originalDefinition.taskDefinition.taskDefinitionArn;
  await f.write(); return f;
}
it('accepts CI-bound tagged originals only with manifest, original-task and exact restoration evidence', async () => {
  const f = await taggedFixture(); await expect(f.validate()).resolves.toHaveProperty('previewHash', f.values.preview.receiptHash);
});
it('accepts either verified index or platform digest in original and restored ECS observations',async()=>{
  const f=await taggedFixture();
  for(const tasks of [f.preview.originalTasks,f.preview.cleanup.restoredTasks])for(const t of tasks)for(const c of t.containers)c.imageDigest=f.preview.originalImageEvidence[c.name].registryDigest;
  await f.write();await expect(f.validate()).resolves.toHaveProperty('previewHash',f.values.preview.receiptHash);
});
const tagMutations = {
  unrelatedTag: p => {p.originalDefinition.taskDefinition.containerDefinitions[0].image = p.originalDefinition.taskDefinition.containerDefinitions[0].image.replace('pr-ccccccc', 'pr-eeeeeee');},
  unverifiedTree: p => {p.github.imageCommit.tree = 'f'.repeat(40);},
  unrelatedParent: p => {p.github.imageCommit.parents[0] = 'f'.repeat(40);},
  invalidManifestHash: p => {p.originalImageEvidence['mnemo-server'].registryDigest = 'sha256:' + '0'.repeat(64);},
  changedManifestLeaf: p => {p.originalImageEvidence['mnemo-server'].imageDigest = 'sha256:' + '0'.repeat(64);},
  missingOriginalTasks: p => {delete p.originalTasks;},
  missingRestore: p => {delete p.cleanup.restoredTasks;},
  wrongRestoredDefinition: p => {p.cleanup.restoredDefinition = p.targetDefinition.taskDefinition.taskDefinitionArn;},
  retaggedRestore: p => {p.cleanup.restoredTasks[0].containers[0].imageDigest = 'sha256:' + '0'.repeat(64);},
  wrongOriginalDigest: p => {p.originalTasks[0].containers[0].imageDigest = 'sha256:' + '0'.repeat(64);},
  unsafeOriginal: p => {p.originalDefinition.taskDefinition.containerDefinitions[0].user = '0';},
};
it.each(Object.keys(tagMutations))('rejects tagged original %s despite recomputed evidence hashes', async kind => {
  const f = await taggedFixture(); tagMutations[kind](f.preview); await f.write(); await expect(f.validate()).rejects.toThrow();
});
it('keeps production candidates digest-only when tagged preview originals are permitted', async () => {
  const f = await taggedFixture(); f.plan.target.containerDefinitions[0].image = f.preview.originalDefinition.taskDefinition.containerDefinitions[0].image;
  await expect(f.validate()).rejects.toThrow('ServiceEvidenceImageDigest');
});
