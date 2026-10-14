import {open, realpath, readFile} from 'node:fs/promises';
import {constants} from 'node:fs';
import {resolve, join} from 'node:path';
import {createHash} from 'node:crypto';
import {isDeepStrictEqual} from 'node:util';
import {registrationInput, hardenServiceRegistration, serviceNonrootHash as hash} from './service-nonroot.mjs';

const need = (value, code) => {if (!value) throw Error('ServiceEvidence' + code);};
const equal = (a, b, code) => need(isDeepStrictEqual(a, b), code);
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const digest = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const empty = value => Array.isArray(value) && value.length === 0;
const names = ['mnemo-server', 'qwen3-embed', 'llm-proxy'];
const required = ['internalNetwork', 'proxyExactEntrypointHealth', 'proxySyntheticHttpUpstream', 'frozenRuntimeBootstrap',
  'verifyRejectsUnreadySchema', 'mnemoVerifyEntrypointHealth', 'runtimeRoleReadinessAndDdlDenial', 'missingSignature',
  'wrongTenant', 'expiredSignature', 'semanticNamespaceSearch', 'keywordNamespaceSearch', 'crossNamespaceReadDenied'];
async function receipt(path, expected) {
  need(typeof path === 'string' && resolve(path) === path && digest(expected), 'ReceiptReference');
  need(await realpath(path) === path, 'ReceiptSymlink');
  const fd = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const stat = await fd.stat();
    need(stat.isFile() && stat.uid === process.getuid() && (stat.mode & 0o777) === 0o600 && stat.size <= 8 * 1024 * 1024, 'ReceiptPermissions');
    const bytes = await fd.readFile(); equal(sha(bytes), expected, 'ReceiptHash'); return JSON.parse(bytes);
  } finally {await fd.close();}
}
function identity(rows) {
  need(rows && typeof rows === 'object', 'ProcessMissing');
  for (const key of ['Uid', 'Gid']) equal(rows[key]?.trim().split(/\s+/), ['1000', '1000', '1000', '1000'], 'ProcessIdentity');
  for (const key of ['CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb']) need(typeof rows[key] === 'string' && /^0+$/.test(rows[key]), 'ProcessCapabilities');
  equal(rows.NoNewPrivs, '1', 'ProcessNoNewPrivs');
}
function applicationIdentity(process, name) {
  need(process && /^\/proc\/[1-9]\d*$/.test(process.pid ?? ''), 'ApplicationPid');
  equal(Object.keys(process).sort(), ['pid', 'Application', 'IdentitySource', 'Uid', 'Gid', 'CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb', 'NoNewPrivs'].sort(), 'ApplicationFields');
  equal(process.Application, name === 'mnemo-server' ? 'mnemo-server' : 'node-server', 'ApplicationCommand');
  equal(process.IdentitySource, 'proc-cmdline-prefix', 'ApplicationIdentitySource');
  identity(process);
}
function identityText(text) {
  need(typeof text === 'string', 'EmbeddingIdentity'); const rows = {};
  for (const line of text.trim().split(/\r?\n/)) {const i = line.indexOf(':'); need(i > 0 && !Object.hasOwn(rows, line.slice(0, i)), 'IdentityFraming'); rows[line.slice(0, i)] = line.slice(i + 1).trim();}
  identity(rows);
}
function imageMap(registration) {
  equal(registration.containerDefinitions.map(c => c.name).sort(), [...names].sort(), 'ContainerSet');
  const images = Object.fromEntries(registration.containerDefinitions.map(c => [c.name, c.image]));
  need(Object.values(images).every(v => typeof v === 'string' && /^[^\s@]+@sha256:[a-f0-9]{64}$/.test(v)), 'ImageDigest'); return images;
}
function previewOriginal(p, old, plan) {
  equal(old, hardenServiceRegistration(old), 'PreviewRestoreNonroot');
  const tagged = old.containerDefinitions.filter(c => !c.image.includes('@'));
  if (!tagged.length) {imageMap(old); return;}
  const proof = p.github?.imageProof, commit = p.github?.imageCommit;
  need(/^[a-f0-9]{40}$/.test(p.source?.commit ?? '') && p.source.tree === p.sourceTree && ['mem9-on-aws', 'mem9-on-aws/preview'].includes(proof?.namespace) &&
    /^[a-f0-9]{40}$/.test(proof?.commit ?? '') && proof.tag === 'pr-' + proof.commit.slice(0, 7) && commit?.sha === proof.commit && commit.tree === p.sourceTree &&
    [p.source.commit, proof.commit].includes(p.github.ciHeadSha), 'PreviewTagSource');
  if (proof.commit !== p.source.commit) {
    need(/^[a-f0-9]{40}$/.test(p.github.baseSha ?? '') && p.github.baseSha !== p.source.commit, 'PreviewMergeBase');
    equal(commit.parents?.slice().sort(), [p.source.commit, p.github.baseSha].sort(), 'PreviewMergeParents');
  }
  equal(Object.keys(p.originalImageEvidence ?? {}).sort(), tagged.map(c => c.name).sort(), 'PreviewOriginalImageEvidence');
  const digests = {};
  for (const c of old.containerDefinitions) {
    if (c.image.includes('@')) {need(/@sha256:[a-f0-9]{64}$/.test(c.image), 'PreviewOriginalDigest'); digests[c.name] = c.image.split('@')[1]; continue;}
    equal(c.image, `${plan.scope.accountId}.dkr.ecr.${plan.scope.region}.amazonaws.com/${proof.namespace}/${c.name}:${proof.tag}`, 'PreviewOriginalTag');
    const e = p.originalImageEvidence[c.name]; equal(e.image, c.image, 'PreviewOriginalImage');
    need(typeof e.imageManifest === 'string' && Buffer.byteLength(e.imageManifest) <= 256 * 1024, 'PreviewOriginalManifest');
    equal(e.registryDigest, 'sha256:' + sha(e.imageManifest), 'PreviewOriginalManifestHash');
    const manifest = JSON.parse(e.imageManifest); need(manifest.schemaVersion === 2, 'PreviewOriginalManifest'); let leaf = e.registryDigest;
    if (manifest.manifests) {const arm = manifest.manifests.filter(m => m.platform?.architecture === 'arm64' && m.platform?.os === 'linux'); need(arm.length === 1 && /^sha256:[a-f0-9]{64}$/.test(arm[0].digest), 'PreviewOriginalPlatform'); leaf = arm[0].digest;}
    else need(/^sha256:[a-f0-9]{64}$/.test(manifest.config?.digest) && Array.isArray(manifest.layers), 'PreviewOriginalManifest');
    equal(e.imageDigest, leaf, 'PreviewOriginalLeaf'); digests[c.name] = leaf;
  }
  equal(p.cleanup?.restoredDefinition, p.originalDefinition.taskDefinition.taskDefinitionArn, 'PreviewRestoredDefinition');
  for (const tasks of [p.originalTasks, p.cleanup.restoredTasks]) {
    need(Array.isArray(tasks) && tasks.length === p.service?.desiredCount && new Set(tasks.map(t => t.taskArn)).size === tasks.length, 'PreviewRestoreInventory');
    for (const task of tasks) {
      need(task.taskArn?.startsWith(p.service.clusterArn.replace(':cluster/', ':task/') + '/') && task.clusterArn === p.service.clusterArn && task.group === 'service:' + p.service.serviceName &&
        task.taskDefinitionArn === p.originalDefinition.taskDefinition.taskDefinitionArn && task.lastStatus === 'RUNNING' && task.healthStatus === 'HEALTHY', 'PreviewRestoredTask');
      equal(task.containers?.map(c => c.name).sort(), [...names].sort(), 'PreviewRestoredContainers');
      for (const c of task.containers) need(c.image === old.containerDefinitions.find(o => o.name === c.name).image && c.imageDigest === digests[c.name] && c.lastStatus === 'RUNNING' && c.healthStatus === 'HEALTHY', 'PreviewRestoredImage');
    }
  }
}
/** Offline validation only; caller authenticates review/plan authority and the clean source tree.
 * Local references bind raw bytes. Preview references use the same wrapper and contain
 * productionRegistrationHash, stage/sourceTree, full old/new definitions and runtime receipts. */
export async function validateServiceEvidence(plan, values, {root}) {
  need(typeof root === 'string' && resolve(root) === root && await realpath(root) === root, 'SourceRoot');
  const original = registrationInput(plan.baseline.definition), images = imageMap(plan.target), registrationHash = hash(plan.target);
  equal(plan.target, hardenServiceRegistration(original), 'ProductionCandidate');
  const local = values.local, preview = values.preview;
  need(local && preview, 'ReceiptsRequired');
  for (const wrapper of [local, preview]) {equal(wrapper.images, images, 'ImageBindings'); equal(wrapper.registrationHash, registrationHash, 'RegistrationBinding');}
  const baseline = await receipt(local.baselinePath, local.baselineHash), suite = await receipt(local.suitePath, local.suiteHash);
  const embedding = await receipt(local.embeddingPath, local.embeddingHash), p = await receipt(preview.receiptPath, preview.receiptHash);
  equal(registrationInput(baseline), original, 'BaselineRegistration'); equal(suite.baselineHash, local.baselineHash, 'SuiteBaseline');
  equal(suite.source?.scriptHash, sha(await readFile(join(root, 'scripts/run-service-nonroot-smoke.mjs'))), 'SmokeSource');
  equal(suite.source?.transformHash, sha(await readFile(join(root, 'scripts/lib/service-nonroot.mjs'))), 'TransformSource');
  equal(suite.source?.runtimeHash, sha(await readFile(join(root, 'scripts/lib/service-nonroot-runtime.mjs'))), 'RuntimeSource');
  need(suite.version === 1 && suite.scope === 'local-actual-images-synthetic-only' && suite.outcome === 'PASS' && suite.phase === 'complete' &&
    empty(suite.failures) && suite.cleanup?.complete === true && empty(suite.cleanup.failures), 'LocalCompletion');
  const checks = suite.checks; need(checks && Object.keys(checks).length >= 24 && required.every(k => checks[k] === true), 'LocalChecks');
  for (const [prefix, name, denied] of [['mnemo', 'mnemo-server', ['/usr/local/bin/mnemo-server', '/usr/local/bin/entrypoint.sh', '/usr/local/share/mem9']],
    ['proxy', 'llm-proxy', ['/app/server.mjs', '/app/node_modules', '/app']]]) {
    const process = checks[prefix + 'Process'], config = checks[prefix + 'ContainerConfiguration']; identity(process?.status);
    need(process.writableTmp === true && denied.every(path => process.deniedWrites?.includes(path)), 'FilesystemChecks');
    need(/^sha256:[a-f0-9]{64}$/.test(suite.images?.[name] ?? '') && config?.image === suite.images[name] && config.user === '1000:1000' && config.init === true, 'LocalContainer');
    equal(config.capDrop, ['ALL'], 'LocalCapabilities');
    const rootObserver = checks[prefix + 'RootObserver'];
    for (const key of ['Uid', 'Gid']) equal(rootObserver?.observer?.[key]?.split(/\s+/), ['0', '0', '0', '0'], 'RootObserverIdentity');
    for (const key of ['CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb']) need(/^0+$/.test(rootObserver?.observer?.[key] ?? ''), 'RootObserverCapabilities');
    need(rootObserver?.processes?.length === 1, 'RootObserverProcesses');
    applicationIdentity(rootObserver.processes[0], name);
    equal(rootObserver.processes[0].pid, '/proc/' + process.status.Pid, 'RootObserverPid');
  }
  need(['exportedModule', 'realTokenGenerator', 'syntheticSessionsOnly', 'healthBeforeMint', 'healthAfterMint', 'authRemint', 'timedRefresh', 'credentialFailure', 'invalidRequest']
    .every(k => checks.proxyModule?.[k] === true), 'ProxyChecks');
  for (const key of ['missingSignature', 'expiredSignature']) need([401, 403].includes(checks[key + 'Observation']?.status), 'AuthObservation');
  need([400, 401, 403, 404].includes(checks.wrongTenantObservation?.status) && checks.syntheticDependencyCalls?.embeddings > 0 && checks.syntheticDependencyCalls?.upstream > 0, 'DependencyChecks');
  equal(embedding.image, images['qwen3-embed'], 'EmbeddingImage'); equal(embedding.isolatedNetwork, 'none', 'EmbeddingIsolation');
  need(embedding.result?.status === 200 && embedding.result.dimensions === 1024 && Number.isFinite(embedding.result.norm) && Math.abs(embedding.result.norm - 1) <= 0.001, 'EmbeddingResult');
  identityText(embedding.applicationIdentity);
  need(p.outcome === 'PASS' && /^pr-[1-9][0-9]*$/.test(p.stage ?? '') && p.sourceTree === plan.source.tree && p.productionRegistrationHash === registrationHash, 'PreviewBinding');
  const old = registrationInput(p.originalDefinition), target = registrationInput(p.targetDefinition), expected = structuredClone(old);
  previewOriginal(p, old, plan); need(new RegExp('(^|[-/])' + p.stage + '($|[-/])').test(old.family), 'PreviewStage');
  expected.containerDefinitions.forEach(c => {c.image = images[c.name];}); equal(target, hardenServiceRegistration(expected), 'PreviewCandidate');
  equal(target.runtimePlatform, plan.target.runtimePlatform, 'PreviewPlatform');
  for (const c of target.containerDefinitions) {
    const env = Object.fromEntries((c.environment ?? []).map(e => [e.name, e.value]));
    const prod = Object.fromEntries((plan.target.containerDefinitions.find(x => x.name === c.name).environment ?? []).map(e => [e.name, e.value]));
    for (const key of ['MNEMO_SCHEMA_MODE', 'MNEMO_NAMESPACE_REQUIRED', 'MNEMO_EMBED_MODEL', 'MNEMO_EMBED_DIMS', 'MNEMO_LLM_MODEL', 'MNEMO_NAMESPACE_EXACT_VECTOR_MAX_ROWS', 'MNEMO_NAMESPACE_EXACT_VECTOR_TIMEOUT']) equal(env[key], prod[key], 'PreviewRuntime');
  }
  const arn = p.targetDefinition.taskDefinition.taskDefinitionArn, service = p.service;
  const ecs = `arn:aws:ecs:${plan.scope.region}:${plan.scope.accountId}:`;
  need(p.targetDefinition.taskDefinition.status === 'ACTIVE' && Number.isSafeInteger(p.targetDefinition.taskDefinition.revision) &&
    p.targetDefinition.taskDefinition.revision > p.originalDefinition.taskDefinition.revision && arn === `${ecs}task-definition/${target.family}:${p.targetDefinition.taskDefinition.revision}`, 'PreviewDefinition');
  need(service && service.clusterArn?.startsWith(ecs + 'cluster/') && service.clusterArn !== plan.scope.clusterArn &&
    service.serviceArn === service.clusterArn.replace(':cluster/', ':service/') + '/' + service.serviceName && service.serviceArn !== plan.scope.serviceArn &&
    service.taskDefinition === arn && service.status === 'ACTIVE' && Number.isSafeInteger(service.desiredCount) && service.desiredCount > 0 &&
    service.runningCount === service.desiredCount && service.pendingCount === 0 && service.deployments?.length === 1 &&
    service.deployments[0].taskDefinition === arn && service.deployments[0].rolloutState === 'COMPLETED', 'PreviewService');
  need(Array.isArray(p.tasks) && p.tasks.length === service.desiredCount && new Set(p.tasks.map(t => t.taskArn)).size === p.tasks.length &&
    Array.isArray(p.processEvidence) && p.processEvidence.length === p.tasks.length * 3, 'PreviewInventory');
  for (const task of p.tasks) {
    need(task.taskArn?.startsWith(service.clusterArn.replace(':cluster/', ':task/') + '/') && task.clusterArn === service.clusterArn && task.group === 'service:' + service.serviceName &&
      task.taskDefinitionArn === arn && task.lastStatus === 'RUNNING' && task.healthStatus === 'HEALTHY', 'PreviewTask');
    equal(task.containers?.map(c => c.name).sort(), [...names].sort(), 'PreviewContainers');
    for (const c of task.containers) {
      need(c.image === images[c.name] && c.imageDigest === images[c.name].split('@')[1] && c.lastStatus === 'RUNNING' && c.healthStatus === 'HEALTHY' && typeof c.runtimeId === 'string' && c.runtimeId.length > 0, 'PreviewImage');
      const matches = p.processEvidence.filter(e => e.taskArn === task.taskArn && e.container === c.name && e.runtimeId === c.runtimeId);
      need(matches.length === 1 && Array.isArray(matches[0].processes) && matches[0].processes.length > 0, 'PreviewProcesses');
      for (const process of matches[0].processes) applicationIdentity(process, c.name);
    }
  }
  need(p.mcp?.kind === 'service-mcp-read-verification' && [401, 403].includes(p.mcp.unauthenticatedStatus) && p.mcp.readScopeIsolated === true && p.mcp.results?.length === 2, 'PreviewMcp');
  equal(p.mcp.results.map(r => r.mode).sort(), ['keyword', 'semantic'], 'PreviewSearchModes');
  need(p.mcp.results.every(r => Number.isSafeInteger(r.returned) && r.returned >= 0 && digest(r.responseHash)), 'PreviewSearchResults');
  need(p.cleanup?.verified === true && empty(p.cleanup.remainingCandidateTasks) && empty(p.cleanup.failures), 'PreviewCleanup');
  return {registrationHash, suiteHash: local.suiteHash, embeddingHash: local.embeddingHash, previewHash: preview.receiptHash};
}
