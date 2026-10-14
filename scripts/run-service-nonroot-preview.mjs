#!/usr/bin/env node
// Existing owned active-runtime preview only; never provisions a stage or changes credentials.
// node scripts/run-service-nonroot-preview.mjs --stage pr-N --ci-run RUN_ID \
//   --baseline /private/definition.json --baseline-hash RAW_FILE_SHA256 \
//   --evidence-root /private/evidence [--expected-source FULL_COMMIT_SHA]
// Baseline: full production DescribeTaskDefinition response including TAGS;
// tagged deployments also carry the explicit, reviewed imageBindings proof.
// Evidence root must be private and outside this checkout. HELD never auto-resumes.
// CI execution is inside the verified workflow_dispatch preview cutover job,
// after runtime finalization and before its existing teardown. --ci-run is the
// earlier successful PR Infra CI run, not the currently executing dispatch.
import assert from 'node:assert/strict';
import {execFile} from 'node:child_process';
import {promisify, isDeepStrictEqual as equal} from 'node:util';
import {createHash, randomUUID} from 'node:crypto';
import {readFile, lstat, realpath, mkdtemp, open, unlink} from 'node:fs/promises';
import {resolve, dirname, join} from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {setTimeout as wait} from 'node:timers/promises';
import {ECSClient, DescribeServicesCommand, DescribeTaskDefinitionCommand, ListTasksCommand, DescribeTasksCommand, RegisterTaskDefinitionCommand, UpdateServiceCommand, DeregisterTaskDefinitionCommand} from '@aws-sdk/client-ecs';
import {SSMClient, GetParametersCommand} from '@aws-sdk/client-ssm';
import {STSClient, GetCallerIdentityCommand} from '@aws-sdk/client-sts';
import {SchedulerClient, ListScheduleGroupsCommand, ListSchedulesCommand} from '@aws-sdk/client-scheduler';
import {IAMClient} from '@aws-sdk/client-iam';
import {ECRClient, BatchGetImageCommand} from '@aws-sdk/client-ecr';
import {currentSource} from './lib/service-nonroot-aws.mjs';
import {resolveApplicationRegion} from './lib/application-region.mjs';
import {runtimeServerContract, verifyRuntimeRoles} from './lib/runtime-live-verification.mjs';
import {verifyServiceRuntime} from './lib/service-nonroot-runtime.mjs';
import {verifyRuntimeImage} from './run-production-runtime.mjs';
import {registrationInput, frozenServiceRegistration, hardenServiceRegistration, SERVICE_CONTAINERS, serviceNonrootHash as hash} from './lib/service-nonroot.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..'), repo = 'zxkane/mem9-on-aws', exec = promisify(execFile);
const need = (condition, code) => assert(condition, 'PreviewNonroot' + code);
const json = value => JSON.parse(JSON.stringify(value));
const environment = c => Object.fromEntries((c.environment ?? []).map(e => [e.name, e.value]));
const taskEvidence = tasks => tasks.map(t => ({taskArn: t.taskArn, clusterArn: t.clusterArn, group: t.group, taskDefinitionArn: t.taskDefinitionArn, lastStatus: t.lastStatus, healthStatus: t.healthStatus,
  containers: t.containers.map(c => ({name: c.name, image: c.image, imageDigest: c.imageDigest, runtimeId: c.runtimeId, lastStatus: c.lastStatus, healthStatus: c.healthStatus}))}));
const config = s => Object.fromEntries(Object.entries(s).filter(([k]) => !['events', 'deployments', 'runningCount', 'pendingCount', 'createdAt', 'updatedAt'].includes(k)));
const runtimeFields = ['MNEMO_SCHEMA_MODE', 'MNEMO_NAMESPACE_REQUIRED', 'MNEMO_EMBED_MODEL', 'MNEMO_EMBED_DIMS', 'MNEMO_LLM_MODEL', 'MNEMO_NAMESPACE_EXACT_VECTOR_MAX_ROWS', 'MNEMO_NAMESPACE_EXACT_VECTOR_TIMEOUT'];
async function boundedRead(action, deadline) {
  need(Date.now() < deadline, 'Deadline'); let timer;
  try {return await Promise.race([action(), new Promise((_, reject) => {timer = setTimeout(() => reject(Error('PreviewNonrootReadDeadline')), deadline - Date.now());})]);}
  finally {clearTimeout(timer);}
}
export function parsePreviewArgs(args) {
  const fields = {'--stage': 'stage', '--ci-run': 'ciRunId', '--baseline': 'baselinePath', '--baseline-hash': 'baselineHash', '--evidence-root': 'evidenceRoot', '--expected-source': 'expectedSource'}, result = {};
  for (let i = 0; i < args.length; i += 2) {const key = fields[args[i]]; need(key && args[i + 1] && result[key] === undefined, 'Arguments'); result[key] = args[i + 1];}
  need(['stage', 'ciRunId', 'baselinePath', 'baselineHash', 'evidenceRoot'].every(k => result[k]), 'Arguments'); return result;
}

export async function runServiceNonrootPreview({stage, baselinePath, baselineHash, evidenceRoot, expectedSource, ciRunId}) {
  need(/^pr-[1-9][0-9]*$/.test(stage) && /^[1-9][0-9]*$/.test(String(ciRunId)), 'StageOrRun');
  need(/^[a-f0-9]{64}$/.test(baselineHash) && (!expectedSource || /^[a-f0-9]{40}$/.test(expectedSource)), 'Hashes');
  for (const path of [baselinePath, evidenceRoot]) need(typeof path === 'string' && resolve(path) === path && await realpath(path) === path, 'PrivatePath');
  const dir = await lstat(evidenceRoot);
  need(dir.isDirectory() && dir.uid === process.getuid() && (dir.mode & 0o077) === 0 && evidenceRoot !== root && !evidenceRoot.startsWith(root + '/'), 'EvidenceDirectory');
  const started = Date.now(), deadline = started + 900_000, verificationDeadline = started + 660_000, runId = randomUUID();
  const output = await mkdtemp(join(evidenceRoot, `${stage}-nonroot-`)), lock = join(evidenceRoot, `${stage}-nonroot.lock.json`), records = new Map();
  const inCi = process.env.GITHUB_ACTIONS === 'true', activeRunId = inCi ? process.env.GITHUB_RUN_ID : undefined;
  const report = {version: 1, stage, runId, sourceTree: null, outcome: 'HELD', checks: {}, cleanup: {verified: false, complete: false, remainingCandidateTasks: [], failures: []}, failures: []};
  const durable = async (path, value) => {const fd = await open(path, 'wx', 0o600); try {await fd.writeFile(JSON.stringify(value) + '\n'); await fd.sync();} finally {await fd.close();} const parent = await open(dirname(path), 'r'); try {await parent.sync();} finally {await parent.close();}};
  const persistOnce = async (name, value) => {need((/^[a-z][a-z0-9-]*\.json$/.test(name) || name === 'report.local.json') && !records.has(name), 'ReconcileRequired'); await durable(join(output, name), value); records.set(name, json(value)); return true;};
  let clients, scope, source, metadata, beforeService, original, target, candidate, switched = false, uncertain = false, dirty = false, locked = false, failure;
  const send = async (client, command) => {need(Date.now() < deadline, 'Deadline'); return client.send(command, {abortSignal: AbortSignal.timeout(Math.max(1, Math.min(30_000, deadline - Date.now())))});};
  const gh = async path => JSON.parse((await exec('gh', ['api', '--hostname', 'github.com', path], {timeout: Math.max(1, Math.min(30_000, deadline - Date.now())), maxBuffer: 4 * 1024 * 1024})).stdout);
  async function ownership(initial = false) {
    need(equal(await currentSource(root), source), 'SourceChanged');
    const pr = await gh(`repos/${repo}/pulls/${stage.slice(3)}`);
    need(pr.state === 'open' && pr.number === Number(stage.slice(3)) && pr.head?.sha === source.commit && pr.head.repo.full_name === repo && pr.base?.repo.full_name === repo && pr.base.ref === 'main', 'PullRequestSource');
    need(/^[a-f0-9]{40}$/.test(pr.base.sha), 'PullRequestBase');
    if (inCi) {
      need(process.env.GITHUB_REPOSITORY === repo && /^[1-9][0-9]*$/.test(activeRunId) && process.env.GITHUB_SHA === source.commit, 'CiContext');
      const own = await gh(`repos/${repo}/actions/runs/${activeRunId}`);
      need(String(own.id) === activeRunId && own.event === 'workflow_dispatch' && own.path === '.github/workflows/infra-ci.yml' && own.status === 'in_progress' && own.head_sha === source.commit && own.head_branch === pr.head.ref && own.head_repository?.full_name === repo, 'CiDispatchIdentity');
      report.github.activeRunId = own.id;
    } else need(pr.user?.login === report.github.owner, 'PullRequestOwner');
    if (!initial) need(pr.base.sha === report.github.baseSha, 'PullRequestBaseChanged');
    const runs = await Promise.all(['queued', 'in_progress', 'waiting', 'pending', 'requested'].map(status => gh(`repos/${repo}/actions/runs?status=${status}&per_page=100`)));
    for (const page of runs) {
      need(Number.isSafeInteger(page.total_count) && page.total_count <= 100 && page.workflow_runs?.length === page.total_count, 'RunInventoryIncomplete');
      need(!page.workflow_runs.some(r => !(inCi && String(r.id) === activeRunId) && (r.head_branch === pr.head.ref || r.pull_requests?.some(p => p.number === pr.number) || r.event === 'workflow_dispatch' || r.path === '.github/workflows/runtime-recovery.yml')), 'ActiveDeployment');
    }
    if (initial) {
      const ci = await gh(`repos/${repo}/actions/runs/${ciRunId}`), jobs = await gh(`repos/${repo}/actions/runs/${ciRunId}/jobs?per_page=100`);
      need(String(ci.id) === String(ciRunId) && ci.name === 'Infra CI' && ci.path === '.github/workflows/infra-ci.yml' && ci.event === 'pull_request' && ci.status === 'completed' && ci.conclusion === 'success' && /^[a-f0-9]{40}$/.test(ci.head_sha) && ci.head_repository?.full_name === repo && ci.pull_requests?.some(p => p.number === pr.number && p.head.sha === source.commit), 'CiSource');
      need(jobs.total_count <= 100 && jobs.jobs?.length === jobs.total_count, 'JobInventoryIncomplete');
      const deploy = jobs.jobs.filter(j => j.name === 'Deploy PR Preview');
      need(deploy.length === 1 && deploy[0].status === 'completed' && deploy[0].conclusion === 'success' && ['Verify preview runtime credentials (hard)', 'MCP write-search E2E (preview, hard)'].every(name => deploy[0].steps?.some(s => s.name === name && s.conclusion === 'success')), 'CiPreviewSkipped');
      report.github = {...report.github, pr: pr.number, runId: ci.id, jobId: deploy[0].id, ciHeadSha: ci.head_sha, baseSha: pr.base.sha};
    }
  }
  async function parameters() {
    const paths = ['meta/stage', 'ecs/cluster-name', 'ecs/service-name', 'ecs/task-definition', 'ecs/image-selection', 'ecs/image', 'tenant/secret-arn', 'db/host', 'runtime/production-manifest'];
    const Names = paths.map(p => `/mem9-on-aws/${stage}/${p}`), r = await send(clients.ssm, new GetParametersCommand({Names, WithDecryption: true}));
    need(!r.InvalidParameters?.length && r.Parameters?.length === Names.length && new Set(r.Parameters.map(p => p.Name)).size === Names.length, 'MetadataMissing');
    for (const p of r.Parameters) need(Names.includes(p.Name) && p.ARN === `arn:aws:ssm:${scope.region}:${scope.account}:parameter${p.Name}` && Number.isSafeInteger(p.Version) && p.Version > 0, 'MetadataIdentity');
    return Object.fromEntries(r.Parameters.map(p => [p.Name.slice(`/mem9-on-aws/${stage}/`.length), {value: p.Value, version: p.Version}]));
  }
  async function service() {const r = await send(clients.ecs, new DescribeServicesCommand({cluster: scope.cluster, services: [scope.service], include: ['TAGS']})); need(!r.failures?.length && r.services?.length === 1, 'ServiceMissing'); return json(r.services[0]);}
  async function definition(arn) {const r = await send(clients.ecs, new DescribeTaskDefinitionCommand({taskDefinition: arn, include: ['TAGS']})); need(r.taskDefinition?.taskDefinitionArn === arn && Array.isArray(r.tags), 'DefinitionIdentity'); return json(r);}
  async function inventory() {
    const arns = new Set();
    for (const desiredStatus of ['RUNNING', 'STOPPED']) {const r = await send(clients.ecs, new ListTasksCommand({cluster: scope.cluster, desiredStatus, maxResults: 100})); need(!r.nextToken && Array.isArray(r.taskArns), 'TaskInventoryIncomplete'); r.taskArns.forEach(a => arns.add(a));}
    need(arns.size <= 100, 'TaskInventoryIncomplete'); if (!arns.size) return [];
    const r = await send(clients.ecs, new DescribeTasksCommand({cluster: scope.cluster, tasks: [...arns]}));
    need(!r.failures?.length && r.tasks?.length === arns.size && new Set(r.tasks.map(t => t.taskArn)).size === arns.size && r.tasks.every(t => arns.has(t.taskArn)), 'TaskInventoryIncomplete');
    const active = r.tasks.filter(t => t.lastStatus !== 'STOPPED');
    need(active.every(t => t.group === 'service:' + scope.service && t.clusterArn === beforeService.clusterArn), 'ActiveWorker');
    return json(active);
  }
  async function schedules() {
    const groups = await send(clients.scheduler, new ListScheduleGroupsCommand({NamePrefix: `mem9-on-aws-${stage}`, MaxResults: 100})); need(!groups.NextToken, 'ScheduleInventoryIncomplete');
    for (const group of groups.ScheduleGroups ?? []) {const r = await send(clients.scheduler, new ListSchedulesCommand({GroupName: group.Name, MaxResults: 100})); need(!r.NextToken && (r.Schedules ?? []).every(s => s.State === 'DISABLED'), 'SchedulesEnabled');}
  }
  async function originalImageResolution() {
    const evidence = {};
    for (const c of original.containerDefinitions.filter(c => !c.image.includes('@'))) {
      const repositoryName = report.github.imageProof.namespace + '/' + c.name, tag = report.github.imageProof.tag;
      const r = await send(clients.ecr, new BatchGetImageCommand({registryId: scope.account, repositoryName, imageIds: [{imageTag: tag}]}));
      need(!r.failures?.length && r.images?.length === 1, 'OriginalImageUnavailable'); const im = r.images[0];
      need(im.registryId === scope.account && im.repositoryName === repositoryName && im.imageId?.imageTag === tag && typeof im.imageManifest === 'string' && Buffer.byteLength(im.imageManifest) <= 256 * 1024, 'OriginalImageIdentity');
      const registryDigest = 'sha256:' + createHash('sha256').update(im.imageManifest).digest('hex'); need(im.imageId.imageDigest === registryDigest, 'OriginalManifestHash');
      const manifest = JSON.parse(im.imageManifest); need(manifest.schemaVersion === 2, 'OriginalManifest'); let imageDigest = registryDigest;
      if (manifest.manifests) {const arm = manifest.manifests.filter(m => m.platform?.architecture === 'arm64' && m.platform?.os === 'linux'); need(arm.length === 1 && /^sha256:[a-f0-9]{64}$/.test(arm[0].digest), 'OriginalManifestPlatform'); imageDigest = arm[0].digest;}
      else need(/^sha256:[a-f0-9]{64}$/.test(manifest.config?.digest) && Array.isArray(manifest.layers), 'OriginalManifest');
      evidence[c.name] = {image: c.image, registryDigest, imageDigest, imageManifest: im.imageManifest};
    }
    return evidence;
  }
  function originalTaskImages(tasks) {
    need(tasks.length === beforeService.desiredCount && tasks.every(t => t.taskDefinitionArn === beforeService.taskDefinition), 'OriginalTaskIdentity');
    for (const t of tasks) {
      need(equal(t.containers.map(c => c.name).sort(), [...SERVICE_CONTAINERS].sort()), 'OriginalContainerSet');
      for (const c of original.containerDefinitions) {const actual = t.containers.find(x => x.name === c.name), proof=report.originalImageEvidence[c.name];
        const digests=c.image.includes('@')?[c.image.split('@')[1]]:[proof?.registryDigest,proof?.imageDigest];
        need(actual.image === c.image && digests.includes(actual.imageDigest) && actual.lastStatus === 'RUNNING' && actual.healthStatus === 'HEALTHY', 'OriginalImageChanged');}
    }
  }
  const deployedConfig = () => ({...beforeService.deploymentConfiguration, minimumHealthyPercent: 100, maximumPercent: 200, deploymentCircuitBreaker: {...beforeService.deploymentConfiguration.deploymentCircuitBreaker, enable: true, rollback: false}});
  async function guard(arn, stable = false) {
    await ownership(); need(equal(await parameters(), metadata), 'MetadataChanged'); await schedules();
    const s = await service(), expected = {...config(beforeService), taskDefinition: arn, deploymentConfiguration: arn === candidate ? deployedConfig() : beforeService.deploymentConfiguration};
    need(equal(config(s), expected), 'ServiceChanged'); const tasks = await inventory();
    if (stable) need(s.runningCount === s.desiredCount && s.pendingCount === 0 && s.deployments?.length === 1 && s.deployments[0].taskDefinition === arn && s.deployments[0].rolloutState === 'COMPLETED' && tasks.length === s.desiredCount && tasks.every(t => t.taskDefinitionArn === arn && t.lastStatus === 'RUNNING' && t.healthStatus === 'HEALTHY'), 'ServiceNotStable');
    return {s, tasks};
  }
  async function stable(arn, until) {
    while (Date.now() < until) {
      const {s, tasks} = await guard(arn);
      need(!s.deployments?.some(d => d.rolloutState === 'FAILED'), 'DeploymentFailed');
      if (s.runningCount === s.desiredCount && s.pendingCount === 0 && s.deployments?.length === 1 && s.deployments[0].taskDefinition === arn && s.deployments[0].rolloutState === 'COMPLETED' && tasks.length === s.desiredCount && tasks.every(t => t.taskDefinitionArn === arn && t.lastStatus === 'RUNNING' && t.healthStatus === 'HEALTHY')) return s;
      await wait(Math.min(5_000, Math.max(1, until - Date.now())));
    }
    throw Error('PreviewNonrootStabilizationDeadline');
  }
  async function mutate(name, command, expectedArn, requireStable = false) {
    await persistOnce(name + '-intent.json', {stage, runId, command: command.input}); await guard(expectedArn, requireStable);
    if (name === 'restore') need(equal(await originalImageResolution(), report.originalImageEvidence), 'RestoreTagChanged');
    need(Date.now() < (['register', 'update'].includes(name) ? verificationDeadline : deadline), 'Deadline'); uncertain = true; dirty = true;
    const result = await send(clients.ecs, command); uncertain = false;
    await persistOnce(name + '-result.json', {taskDefinitionArn: result.taskDefinition?.taskDefinitionArn ?? command.input.taskDefinition}); return result;
  }
  try {
    await durable(lock, {stage, runId, output}); locked = true;
    const stat = await lstat(baselinePath); need(stat.isFile() && stat.uid === process.getuid() && (stat.mode & 0o777) === 0o600 && stat.size <= 8 * 1024 * 1024, 'BaselinePermissions');
    const bytes = await readFile(baselinePath); need(createHash('sha256').update(bytes).digest('hex') === baselineHash, 'BaselineHash');
    const baseline = JSON.parse(bytes), production = hardenServiceRegistration(frozenServiceRegistration(baseline));
    source = await currentSource(root); need(source.clean && /^[a-f0-9]{40}$/.test(source.commit) && /^[a-f0-9]{40}$/.test(source.tree) && (!expectedSource || expectedSource === source.commit), 'Source');
    await exec('git', ['-C', root, 'ls-files', '--error-unmatch', 'scripts/run-service-nonroot-preview.mjs', 'scripts/lib/service-nonroot-runtime.mjs', 'scripts/lib/service-nonroot.mjs'], {timeout: 10_000});
    report.sourceTree = source.tree; report.source = source; report.github = inCi ? {} : {owner: (await gh('user')).login}; if (!inCi) need(report.github.owner, 'OperatorIdentity'); await ownership(true);
    const region = await resolveApplicationRegion(), configuration = {region, maxAttempts: 1};
    clients = {ecs: new ECSClient(configuration), ssm: new SSMClient(configuration), sts: new STSClient(configuration), scheduler: new SchedulerClient(configuration), iam: new IAMClient(configuration), ecr: new ECRClient(configuration)};
    const account = (await send(clients.sts, new GetCallerIdentityCommand({}))).Account; need(/^\d{12}$/.test(account), 'Account'); scope = {account, region, stage};
    const images = Object.fromEntries(production.containerDefinitions.map(c => [c.name, c.image]));
    for (const name of SERVICE_CONTAINERS) need(new RegExp(`^${account}\\.dkr\\.ecr\\.${region}\\.amazonaws\\.com/mem9-on-aws/${name}@sha256:[a-f0-9]{64}$`).test(images[name]), 'ImageScope');
    report.images = images; report.productionRegistrationHash = hash(production); report.baselineHash = baselineHash;
    metadata = await parameters(); const v = Object.fromEntries(Object.entries(metadata).map(([k, p]) => [k, p.value]));
    need(v['meta/stage'] === stage && new RegExp(`^mem9-on-aws-${stage}-[A-Za-z0-9-]+$`).test(v['ecs/cluster-name']) && v['ecs/service-name'] === 'Mem9Server', 'PreviewMetadata');
    scope.cluster = v['ecs/cluster-name']; scope.service = v['ecs/service-name'];
    const active = JSON.parse(v['runtime/production-manifest']), arnRoot = `arn:aws:ecs:${region}:${account}:`, oldArn = v['ecs/task-definition'];
    need(active.mode === 'active' && active.stage === stage && active.account === account && active.region === region && active.cluster === scope.cluster && active.clusterArn === `${arnRoot}cluster/${scope.cluster}` && active.service === scope.service, 'ActiveRuntimeRequired');
    need(new RegExp(`^${arnRoot}task-definition/${scope.cluster}-Mem9RuntimeServer:[1-9][0-9]*$`).test(oldArn), 'PreviewDefinitionScope');
    beforeService = await service(); need(beforeService.serviceArn === `${arnRoot}service/${scope.cluster}/${scope.service}` && beforeService.clusterArn === active.clusterArn && beforeService.taskDefinition === oldArn && beforeService.status === 'ACTIVE' && beforeService.desiredCount === 1 && beforeService.enableExecuteCommand && beforeService.deploymentController?.type === 'ECS' && beforeService.deploymentConfiguration?.alarms?.rollback !== true, 'PreviewService');
    const beforeResponse = await definition(oldArn); original = registrationInput(beforeResponse);
    need(beforeResponse.taskDefinition.status === 'ACTIVE' && equal(original, hardenServiceRegistration(original)), 'UnsafeRestoreBaseline');
    const selection = JSON.parse(v['ecs/image-selection']), oldImages = Object.fromEntries(original.containerDefinitions.map(c => [c.name, c.image]));
    need(selection.version === 1 && ['tag', 'retained'].includes(selection.mode) && /^pr-[a-f0-9]{7}$/.test(selection.controlTag), 'DeployedSource');
    const imagePrefix = v['ecs/image'].match(new RegExp(`^(${account}\\.dkr\\.ecr\\.${region}\\.amazonaws\\.com/mem9-on-aws(?:/preview)?/mnemo-server)(?::pr-[a-f0-9]{7}|@sha256:[a-f0-9]{64})$`));
    need(imagePrefix, 'PreviewImageSource');
    if (selection.mode === 'tag') need(selection.dataTag === selection.controlTag && (!v['ecs/image'].includes(':pr-') || v['ecs/image'] === imagePrefix[1] + ':' + selection.controlTag), 'DataTag');
    else need(/^[a-f0-9]{64}$/.test(selection.dataReleaseHash) && equal(selection.images, oldImages) && SERVICE_CONTAINERS.every(n => selection.arm64Digests?.[n] === oldImages[n].split('@')[1]), 'RetainedImageSelection');
    const imageProof = await verifyRuntimeImage(imagePrefix[1] + ':' + selection.controlTag, {...scope, revision: source.commit, sourceTree: source.tree, readCommit: short => gh(`repos/${repo}/commits/${short}`)});
    const commit = await gh(`repos/${repo}/commits/${imageProof.commit}`);
    need(commit.sha === imageProof.commit && commit.commit?.tree?.sha === source.tree && [source.commit, commit.sha].includes(report.github.ciHeadSha), 'CiImageCommit');
    if (commit.sha !== source.commit) need(commit.parents?.length === 2 && equal(commit.parents.map(p => p.sha).sort(), [source.commit, report.github.baseSha].sort()), 'CiMergeParents');
    report.github.imageProof = imageProof;
    report.github.imageCommit = {sha: commit.sha, tree: commit.commit.tree.sha, parents: commit.parents?.map(p => p.sha) ?? []};
    need(equal(original.runtimePlatform, production.runtimePlatform), 'RuntimePlatform');
    for (const c of original.containerDefinitions) {
      const env = environment(c), prod = environment(production.containerDefinitions.find(p => p.name === c.name));
      const pinned = new RegExp(`^${account}\\.dkr\\.ecr\\.${region}\\.amazonaws\\.com/mem9-on-aws(?:/preview)?/${c.name}@sha256:[a-f0-9]{64}$`).test(c.image);
      const tagged = selection.mode === 'tag' && c.image === `${account}.dkr.ecr.${region}.amazonaws.com/${imageProof.namespace}/${c.name}:${imageProof.tag}`;
      need((pinned || tagged) && runtimeFields.every(k => env[k] === prod[k]), 'RuntimeConfiguration');
      if (c.name === 'mnemo-server') need(env.MNEMO_SCHEMA_MODE === 'verify' && env.MNEMO_NAMESPACE_REQUIRED === '1' && env.MEM9_DB_HOST === v['db/host'], 'ActiveVerifyRequired');
    }
    const meta = {...scope, serverTaskDefinition: oldArn, productionRuntime: true};
    await boundedRead(() => verifyRuntimeRoles({iam: {send: command => {need(Date.now() < verificationDeadline, 'Deadline'); return send(clients.iam, command);}}, definition: beforeResponse.taskDefinition, meta, contract: runtimeServerContract(beforeResponse.taskDefinition, meta, v['tenant/secret-arn'])}), verificationDeadline);
    target = hardenServiceRegistration({...original, containerDefinitions: original.containerDefinitions.map(c => ({...c, image: images[c.name]}))});
    report.originalDefinition = beforeResponse; report.checks = {ownedPrCi: true, activeRuntime: true, roles: true, matchingRuntime: true};
    report.originalImageEvidence = await originalImageResolution(); report.originalTasks = taskEvidence((await guard(oldArn, true)).tasks); originalTaskImages(report.originalTasks);
    await persistOnce('original-images.json', {tasks: report.originalTasks, images: report.originalImageEvidence});
    await persistOnce('prepared.json', {source, scope, metadata, beforeService, originalDefinition: beforeResponse, target, productionRegistrationHash: report.productionRegistrationHash});
    const registered = await mutate('register', new RegisterTaskDefinitionCommand(target), oldArn, true), arn = registered.taskDefinition?.taskDefinitionArn;
    need(typeof arn === 'string' && arn.startsWith(`${arnRoot}task-definition/${original.family}:`) && /^[1-9][0-9]*$/.test(arn.split(':').at(-1)) && Number(arn.split(':').at(-1)) > beforeResponse.taskDefinition.revision, 'RegisteredIdentity'); candidate = arn;
    const readback = await definition(candidate); need(readback.taskDefinition.status === 'ACTIVE' && equal(registrationInput(readback), target), 'FullRegistrationReadback'); report.targetDefinition = readback;
    await mutate('update', new UpdateServiceCommand({cluster: scope.cluster, service: scope.service, taskDefinition: candidate, deploymentConfiguration: deployedConfig()}), oldArn, true); switched = true;
    report.service = await stable(candidate, verificationDeadline);
    const receipt = await boundedRead(() => verifyServiceRuntime(candidate, {plan: {baseline: {service: beforeService}, target}, deadline: verificationDeadline, aws: {inventory, persistOnce}, scope, authMode: 'managed'}), verificationDeadline);
    need(records.has('runtime-verification.json') && /^[a-f0-9]{64}$/.test(receipt.evidenceHash), 'RuntimeEvidenceMissing');
    const raw = records.get('runtime-verification.json'); need(hash(raw) === receipt.evidenceHash, 'RuntimeEvidenceHash');
    need(Array.isArray(receipt.tasks) && raw.processEvidence?.length === receipt.tasks.length * 3 && raw.mcp?.kind === 'service-mcp-read-verification' && [401, 403].includes(raw.mcp.unauthenticatedStatus) && equal(raw.mcp.results?.map(r => r.mode).sort(), ['keyword', 'semantic']), 'RuntimeReceiptShape');
    report.processEvidence = raw.processEvidence; report.mcp = raw.mcp;
    report.tasks = taskEvidence(receipt.tasks);
    await guard(candidate, true); report.checks.fullReadback = true; report.checks.runtime = true;
  } catch (error) {failure = String(error.message).startsWith('PreviewNonroot') ? error.message : uncertain ? 'PreviewNonrootMutationOutcomeUnknown' : 'PreviewNonrootVerificationFailed'; report.failures.push(failure);}
  try {
    if (candidate && !uncertain) {
      const oldArn = beforeService.taskDefinition;
      need(equal(registrationInput(await definition(oldArn)), original) && equal(original, hardenServiceRegistration(original)), 'RestoreDefinitionChanged');
      if (switched) {await mutate('restore', new UpdateServiceCommand({cluster: scope.cluster, service: scope.service, taskDefinition: oldArn, deploymentConfiguration: beforeService.deploymentConfiguration}), candidate); await stable(oldArn, deadline - 30_000);}
      const restored = await guard(oldArn, true); originalTaskImages(restored.tasks);
      need(equal(await originalImageResolution(), report.originalImageEvidence), 'RestoredTagChanged'); report.cleanup.restoredTasks = taskEvidence(restored.tasks);
      await mutate('deregister', new DeregisterTaskDefinitionCommand({taskDefinition: candidate}), oldArn, true);
      need((await definition(candidate)).taskDefinition.status === 'INACTIVE', 'DeregisterReadback');
      report.cleanup.remainingCandidateTasks = (await inventory()).filter(t => t.taskDefinitionArn === candidate).map(t => t.taskArn); need(!report.cleanup.remainingCandidateTasks.length, 'CandidateStillRunning');
      report.cleanup.restoredDefinition = oldArn; report.cleanup.deregisteredDefinition = candidate; dirty = false;
    }
    report.cleanup.verified = report.cleanup.complete = !dirty && !uncertain;
    if (!report.cleanup.verified) report.cleanup.failures.push('ReconciliationRequired');
  } catch {report.cleanup.failures.push('CleanupUnverified'); report.cleanup.verified = report.cleanup.complete = false;}
  finally {Object.values(clients ?? {}).forEach(c => c.destroy());}
  if (locked && report.cleanup.verified) try {await unlink(lock);} catch {report.cleanup.verified = report.cleanup.complete = false; report.cleanup.failures.push('LocalLockCleanupUnverified');}
  report.outcome = !failure && report.checks.runtime && report.cleanup.verified ? 'PASS' : 'HELD'; report.finishedAt = new Date().toISOString();
  await persistOnce('report.local.json', report);
  const evidenceFiles=[...records].map(([name,value])=>{const bytes=Buffer.from(JSON.stringify(value)+'\n');return {name,sha256:createHash('sha256').update(bytes).digest('hex'),bytes:bytes.length};});
  return {...report, evidence: join(output, 'report.local.json'), evidenceHash: createHash('sha256').update(JSON.stringify(report) + '\n').digest('hex'),evidenceFiles};
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  runServiceNonrootPreview(parsePreviewArgs(process.argv.slice(2))).then(r => {console.log(JSON.stringify({outcome: r.outcome, evidence: r.evidence, evidenceHash: r.evidenceHash, cleanup: r.cleanup.verified})); if (r.outcome !== 'PASS') process.exitCode = 1;}).catch(() => {console.error('PreviewNonrootHeld'); process.exitCode = 1;});
}
