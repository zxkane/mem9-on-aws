#!/usr/bin/env node
// Local, synthetic smoke only. Never pulls images or copies baseline credentials.
// Usage: node scripts/run-service-nonroot-smoke.mjs --baseline /private/baseline.local.json --evidence-root /private/evidence
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {createHash, randomBytes, randomUUID} from 'node:crypto';
import {readFile, writeFile, mkdir, mkdtemp, lstat, chmod, readdir, rm, realpath, rmdir} from 'node:fs/promises';
import {resolve, join, dirname} from 'node:path';
import {isIP} from 'node:net';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {hardenServiceContainer} from './lib/service-nonroot.mjs';

const exec = promisify(execFile);
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const LABEL = 'local.service-nonroot-smoke';
const need = (value, code) => { if (!value) throw Error(code); };
const hash = value => createHash('sha256').update(value).digest('hex');
const delay = ms => new Promise(r => setTimeout(r, ms));
const cleanEnv = {PATH: process.env.PATH, HOME: process.env.HOME, LANG: 'C.UTF-8'};

export function parseArgs(args) {
  const options = {};
  for (let i = 0; i < args.length; i += 2) {
    need(['--baseline', '--evidence-root'].includes(args[i]) && args[i + 1] && !options[args[i]], 'InvalidArguments');
    options[args[i]] = resolve(args[i + 1]);
  }
  need(options['--baseline'] && options['--evidence-root'], 'BaselineAndEvidenceRequired');
  return {baseline: options['--baseline'], evidenceRoot: options['--evidence-root']};
}

export function imageReferences(baseline) {
  const containers = baseline?.taskDefinition?.containerDefinitions;
  need(Array.isArray(containers) && containers.length === 3 &&
    new Set(containers.map(c => c.name)).size === 3 &&
    ['mnemo-server', 'llm-proxy', 'qwen3-embed'].every(n => containers.some(c => c.name === n)), 'UnexpectedContainerSet');
  return Object.fromEntries(['mnemo-server', 'llm-proxy'].map(name => {
    const container = containers.find(c => c.name === name);
    need(typeof container.image === 'string' && /^[^\s@]+@sha256:[a-f0-9]{64}$/.test(container.image), 'DigestPinnedImageRequired');
    hardenServiceContainer(container);
    return [name, container.image];
  }));
}

export function verifyProcessStatus(text) {
  const fields = Object.fromEntries(text.trim().split('\n').map(line => {
    const index = line.indexOf(':'); return [line.slice(0, index), line.slice(index + 1).trim()];
  }));
  need(['Uid', 'Gid'].every(key => fields[key]?.split(/\s+/).length === 4 &&
    fields[key].split(/\s+/).every(id => id === '1000')), 'ApplicationIdentityMismatch');
  need(['CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb'].every(key => /^0+$/.test(fields[key] ?? '')), 'ApplicationCapabilitiesPresent');
  need(fields.NoNewPrivs === '1', 'ApplicationNoNewPrivilegesMissing');
  return fields;
}

// Total simultaneous limits: postgres 1536 MiB/.5 CPU, fixture 512/.25,
// proxy 512/.5, mnemo 1536/.75 = 4096 MiB/2 CPU. No swap or restart policy.
export function containerLimits(kind) {
  const resources = {postgres: [1536, '.5'], fixture: [512, '.25'], proxy: [512, '.5'], mnemo: [1536, '.75']};
  need(Object.hasOwn(resources, kind), 'UnknownContainerKind');
  const [memory, cpu] = resources[kind];
  return ['--pull=never', '--memory', `${memory}m`, '--memory-swap', `${memory}m`, '--cpus', cpu,
    '--pids-limit', '160', '--restart=no', '--log-driver', 'local', '--log-opt', 'max-size=1m', '--log-opt', 'max-file=1', '--log-opt', 'compress=false'];
}

async function fixtureProgram() {
  const {createServer} = await import('node:http');
  let embeddings = 0, upstream = 0;
  createServer(async (req, res) => {
    let body = ''; for await (const chunk of req) {body += chunk; if (body.length > 65536) {res.writeHead(413).end(); return;}}
    res.setHeader('content-type', 'application/json');
    if (req.url === '/stats') {res.end(JSON.stringify({embeddings, upstream})); return;}
    if (req.url === '/v1/embeddings') {
      embeddings++;
      const input = JSON.parse(body).input;
      const items = Array.isArray(input) ? input : [input];
      res.end(JSON.stringify({object: 'list', data: items.map((_, index) => ({object: 'embedding', index,
        embedding: Array.from({length: 1024}, (_, i) => i === 0 ? 1 : 0)})), usage: {prompt_tokens: 1, total_tokens: 1}})); return;
    }
    if (req.url === '/v1/chat/completions') {
      upstream++;
      if (!req.headers.authorization?.startsWith('Bearer ')) {res.writeHead(401).end('{}'); return;}
      res.end(JSON.stringify({id: 'synthetic', object: 'chat.completion', choices: [{index: 0,
        message: {role: 'assistant', content: 'synthetic response'}, finish_reason: 'stop'}], usage: {prompt_tokens: 1, completion_tokens: 1}})); return;
    }
    res.writeHead(404).end('{}');
  }).listen(9090, '0.0.0.0');
}

// Runs inside the unchanged proxy image; uses the image's exported implementation
// and installed token generator with freshly generated, deliberately fake sessions.
async function proxyModuleProgram() {
  const {createProxyServer, makeDefaultMintToken, readConfig} = await import('/app/server.mjs');
  const {createRequire} = await import('node:module');
  const {getToken} = await import(createRequire('/app/server.mjs').resolve('@aws/bedrock-token-generator'));
  const {randomBytes} = await import('node:crypto');
  const assert = (v, code) => {if (!v) throw Error(code);};
  const originalLog = console.log; console.log = () => {}; console.error = () => {};
  let providers = 0, fail = false, calls = 0;
  const seen = new Set();
  const cfg = readConfig({LLM_PROXY_REGION: 'us-east-1', LLM_PROXY_REFRESH_INTERVAL_MS: '100', LLM_PROXY_UPSTREAM_BASE: 'http://127.0.0.1:1/v1'});
  const mintToken = makeDefaultMintToken(cfg, {getToken, createProvider: () => {
    providers++; return async () => {
      if (fail) throw Error('SyntheticCredentialsUnavailable');
      return {accessKeyId: 'ASIA' + randomBytes(8).toString('hex').toUpperCase(), secretAccessKey: randomBytes(30).toString('base64'),
        sessionToken: randomBytes(32).toString('base64'), expiration: new Date(Date.now() + 3600000)};
    };
  }});
  const proxy = createProxyServer(cfg, {mintToken, log: () => {}, fetchImpl: async (_url, options) => {
    calls++; const authorization = new Headers(options.headers).get('authorization');
    assert(authorization?.startsWith('Bearer ') && authorization.length > 100, 'SyntheticBearerMissing'); seen.add(authorization);
    return new Response(JSON.stringify(calls === 1 ? {error: {message: 'synthetic'}} : {choices: [{message: {role: 'assistant', content: 'synthetic'}}]}),
      {status: calls === 1 ? 401 : 200, headers: {'content-type': 'application/json'}});
  }});
  await new Promise(r => proxy.server.listen(8083, '127.0.0.1', r));
  const request = (path, options) => fetch('http://127.0.0.1:8083' + path, {...options, signal: AbortSignal.timeout(10000)});
  try {
    assert((await request('/health')).status === 503, 'UnmintedHealthAccepted');
    await proxy.start();
    assert((await request('/health')).status === 200, 'MintedHealthRejected');
    const response = await request('/v1/chat/completions', {method: 'POST', headers: {'content-type': 'application/json'},
      body: JSON.stringify({model: 'synthetic-chat', messages: [{role: 'user', content: 'synthetic'}], max_tokens: 16})});
    assert(response.status === 200 && calls === 2 && seen.size === 2, 'AuthRemintFailed');
    const before = providers; await new Promise(r => setTimeout(r, 250)); assert(providers > before, 'TimedRefreshMissing');
    fail = true; let rejected = false; try {await mintToken();} catch {rejected = true;} assert(rejected, 'CredentialFailureAccepted');
    clearInterval(proxy.state.refreshTimer);
    const invalid = await request('/v1/chat/completions', {method: 'POST', headers: {'content-type': 'application/json'}, body: '{}'});
    assert(invalid.status === 400, 'InvalidRequestAccepted');
    const unavailable = createProxyServer({...cfg, port: 8084}, {mintToken, log: () => {}, fetchImpl: async () => {throw Error('UnexpectedUpstream');}});
    await new Promise(r => unavailable.server.listen(8084, '127.0.0.1', r));
    try {
      rejected = false; try {await unavailable.start();} catch {rejected = true;}
      assert(rejected && (await fetch('http://127.0.0.1:8084/health', {signal: AbortSignal.timeout(5000)})).status === 503, 'FailedMintHealthAccepted');
    } finally {clearInterval(unavailable.state.refreshTimer); await new Promise(r => unavailable.server.close(r));}
    originalLog(JSON.stringify({exportedModule: true, realTokenGenerator: true, syntheticSessionsOnly: true,
      healthBeforeMint: true, healthAfterMint: true, authRemint: true, timedRefresh: true, credentialFailure: true, invalidRequest: true}));
  } finally {clearInterval(proxy.state.refreshTimer); await new Promise(r => proxy.server.close(r));}
}

async function privatePath(path, directory = false) {
  const stat = await lstat(path);
  need(!stat.isSymbolicLink() && stat.uid === process.getuid() && (stat.mode & 0o077) === 0 &&
    (directory ? stat.isDirectory() : stat.isFile()), 'OwnerOnlyPathRequired');
  need(await realpath(path) === path, 'SymlinkPathRejected');
}

export async function runSmoke(options) {
  process.umask(0o077);
  await privatePath(options.baseline); await privatePath(options.evidenceRoot, true);
  need(!options.evidenceRoot.startsWith(ROOT + '/') && options.evidenceRoot !== ROOT, 'EvidenceMustBeOutsideRepository');
  const output = await mkdtemp(join(options.evidenceRoot, 'local-smoke-'));
  const temporary = join(output, 'temporary'); await mkdir(temporary, {mode: 0o700});
  const runId = randomUUID(), network = `nonroot-${runId}`;
  const report = {version: 1, scope: 'local-actual-images-synthetic-only', runId, startedAt: new Date().toISOString(),
    outcome: 'running', limits: {memoryMiB: 4096, cpus: 2, deadlineSeconds: 840}, checks: {}, failures: []};
  const containers = [], activeChildren = new Set(), clients = new Set();
  let networkCreated = false, database, lockAcquired = false;
  const localLock = join(options.evidenceRoot, 'local-image-smoke.lock');
  const deadline = Date.now() + 840000;
  const cleanupDeadline = deadline + 60000;
  let interrupted = false;
  const interrupt = () => {
    interrupted = true;
    for (const child of activeChildren) child.kill('SIGTERM');
    for (const client of clients) client.end().catch(() => {});
  };
  process.on('SIGINT', interrupt); process.on('SIGTERM', interrupt);
  const watchdog = setTimeout(interrupt, Math.max(1, deadline - Date.now())); watchdog.unref();
  const save = () => writeFile(join(output, 'report.local.json'), JSON.stringify(report, null, 2) + '\n', {mode: 0o600});
  async function command(binary, args, {input, timeout = 30000, cleanup = false} = {}) {
    need(cleanup || (!interrupted && Date.now() < deadline), 'SmokeDeadlineOrSignal');
    try {
      // execFile never interpolates shell text; all secrets travel in files/stdin.
      const child = exec(binary, args, {env: cleanEnv, timeout: Math.min(timeout, Math.max(1, (cleanup ? cleanupDeadline : deadline) - Date.now())),
        killSignal: 'SIGKILL', maxBuffer: 4 * 1024 * 1024});
      if (!cleanup) activeChildren.add(child.child);
      if (input !== undefined) {child.child.stdin.end(input);} else child.child.stdin.end();
      try {return (await child).stdout;} finally {activeChildren.delete(child.child);}
    } catch (error) {
      const diagnostic = String(error.stderr ?? '');
      report.commandFailure = {program: binary, operation: binary === 'docker' ? args.slice(2, 4) : [args[0]],
        exitCode: typeof error.code === 'number' ? error.code : null,
        diagnosticHash: hash(diagnostic),
        reason: ['address pools', 'executable file not found', 'No such image', 'unknown flag', 'permission denied',
          'invalid argument', 'Cannot find module', 'not found', 'requires at least', 'requires exactly', 'No such object']
          .find(text => diagnostic.includes(text)) ?? 'UnclassifiedLocalFailure',
        ...( /^[A-Z][A-Za-z0-9_]{1,80}$/.test(String(error.stdout ?? '')) ? {fixtureError: error.stdout} : {})};
      throw Error('LocalCommandFailed');
    }
  }
  const docker = (args, opts) => command('docker', ['--host', 'unix:///var/run/docker.sock', ...args], opts);
  const inspect = async name => JSON.parse(await docker(['inspect', name]))[0];
  async function endpoint(name, port) {
    const item = await inspect(name), net = JSON.parse(await docker(['network', 'inspect', network]))[0];
    need(item.Config.Labels?.[LABEL] === runId && net.Labels?.[LABEL] === runId && net.Internal === true, 'EndpointOwnershipMismatch');
    const published = item.NetworkSettings.Ports?.[`${port}/tcp`];
    if (published?.length) {
      need(published.length === 1 && published[0].HostIp === '127.0.0.1', 'NonLoopbackPort');
      return {host: '127.0.0.1', port: Number(published[0].HostPort)};
    }
    // Some local daemons suppress published ports on internal networks. The
    // host harness can address only this run's verified bridge endpoint instead.
    const attachment = item.NetworkSettings.Networks[network];
    need(Object.keys(item.NetworkSettings.Networks).length === 1 && attachment?.NetworkID === net.Id &&
      isIP(attachment.IPAddress) === 4, 'OwnedInternalEndpointMissing');
    return {host: attachment.IPAddress, port};
  }
  const mark = async (key, value = true) => {report.checks[key] = value; await save();};
  async function waitFor(check, code, seconds = 90) {
    const until = Math.min(deadline, Date.now() + seconds * 1000);
    while (Date.now() < until && !interrupted) {try {if (await check()) return;} catch (error) {if (error.terminal) throw error;} await delay(500);}
    throw Error(code);
  }
  async function envFile(name, environment) {
    const file = join(temporary, name + '.env');
    for (const [key, value] of Object.entries(environment)) need(/^[A-Z][A-Z0-9_]*$/.test(key) && !/[\r\n\0]/.test(String(value)), 'InvalidFixtureEnvironment');
    await writeFile(file, Object.entries(environment).map(([key, value]) => `${key}=${value}\n`).join(''), {mode: 0o600}); return file;
  }
  async function create(kind, image, args = [], env = {}, entry = []) {
    const name = `nonroot-${kind}-${runId}`; containers.push(name);
    await docker(['create', '--name', name, '--label', `${LABEL}=${runId}`, ...containerLimits(kind),
      '--network', network, '--network-alias', kind, '--dns', '127.0.0.1',
      '--env-file', await envFile(kind, env), ...args, ...(entry.length ? ['--entrypoint', entry[0]] : []), image, ...entry.slice(1)]);
    const actual = await inspect(name), limits = containerLimits(kind);
    need(actual.Config.Image === image && actual.HostConfig.Memory === parseInt(limits[limits.indexOf('--memory') + 1]) * 1024 * 1024 &&
      actual.HostConfig.MemorySwap === actual.HostConfig.Memory && actual.HostConfig.NanoCpus === Number(limits[limits.indexOf('--cpus') + 1]) * 1e9 &&
      actual.HostConfig.RestartPolicy.Name === 'no' && !actual.HostConfig.Privileged &&
      actual.Config.Labels?.[LABEL] === runId, 'ContainerLimitsReadbackMismatch');
    if (kind !== 'postgres') need(actual.Config.User === '1000:1000' && JSON.stringify(actual.HostConfig.CapDrop) === '["ALL"]' &&
      actual.HostConfig.Init === true, 'ContainerHardeningReadbackMismatch');
    await mark(`${kind}ContainerConfiguration`, {image: actual.Config.Image, user: actual.Config.User,
      memoryBytes: actual.HostConfig.Memory, nanoCpus: actual.HostConfig.NanoCpus, capDrop: actual.HostConfig.CapDrop, init: actual.HostConfig.Init});
    return name;
  }
  async function health(name, spec) {
    need(spec.healthCheck?.command[0] === 'CMD', 'HealthContractMissing');
    if (!(await inspect(name)).State.Running) throw Object.assign(Error('ApplicationExitedBeforeHealthy'), {terminal: true});
    await docker(['exec', '--user', '1000:1000', name, ...spec.healthCheck.command.slice(1)]);
  }
  async function identity(name, kind) {
    const output = await docker(['exec', '--user', '1000:1000', name, '/bin/sh', '-c',
      kind === 'mnemo' ? 'for p in /proc/[0-9]*; do [ "$(cat "$p/comm" 2>/dev/null)" = mnemo-server ] && cat "$p/status"; done; true' :
        'for p in /proc/[0-9]*; do case "$(cat "$p/comm" 2>/dev/null)" in node|MainThread) case "$(tr "\\000" " " < "$p/cmdline" 2>/dev/null)" in "node server.mjs ") cat "$p/status";; esac;; esac; done; true']);
    const statuses = output.split(/(?=^Name:)/m).filter(v => v.trim());
    need(statuses.length === 1, 'ApplicationProcessNotUnique');
    const status = verifyProcessStatus(statuses[0]);
    const primitive = kind === 'mnemo' ? '/bin/setpriv' : '/usr/bin/setpriv';
    const paths = kind === 'mnemo' ? ['/usr/local/bin/mnemo-server', '/usr/local/bin/entrypoint.sh', '/usr/local/share/mem9'] : ['/app/server.mjs', '/app/node_modules', '/app'];
    // Opening for write without truncation tests actual permission, including files.
    await docker(['exec', '--user', '1000:1000', name, primitive, '--no-new-privs', '--', '/bin/sh', '-c',
      'set -eu; f=$(mktemp /tmp/nonroot-write.XXXXXX); printf test > "$f"; rm "$f"; for p do if [ -d "$p" ]; then if (touch "$p/.nonroot-smoke-denied") 2>/dev/null; then rm "$p/.nonroot-smoke-denied"; exit 21; fi; else if (exec 3>>"$p") 2>/dev/null; then exit 22; fi; fi; done', 'probe', ...paths]);
    await mark(`${kind}Process`, {status, writableTmp: true, deniedWrites: paths});
  }
  try {
    try {await mkdir(localLock, {mode: 0o700}); lockAcquired = true;}
    catch {throw Error('LocalSmokeLockUnavailable');}
    await writeFile(join(localLock, 'owner.local.json'), JSON.stringify({runId, pid: process.pid, output}), {mode: 0o600});
    const baselineBytes = await readFile(options.baseline), baseline = JSON.parse(baselineBytes);
    const references = imageReferences(baseline); report.baselineHash = hash(baselineBytes);
    report.source = {head: (await command('git', ['-C', ROOT, 'rev-parse', 'HEAD'])).trim(),
      scriptHash: hash(await readFile(fileURLToPath(import.meta.url))), transformHash: hash(await readFile(join(ROOT, 'scripts/lib/service-nonroot.mjs')))};
    const images = {};
    for (const [name, ref] of Object.entries(references)) {
      const image = JSON.parse(await docker(['image', 'inspect', ref]))[0];
      need(image.RepoDigests?.includes(ref), 'LoadedImageDigestMismatch');
      need(JSON.stringify(image.Config.Entrypoint) === JSON.stringify(name === 'mnemo-server' ? ['/usr/local/bin/entrypoint.sh'] : ['node', 'server.mjs']) &&
        (!image.Config.Cmd || image.Config.Cmd.length === 0), 'ActualImageEntrypointMismatch');
      need(!image.Config.Env?.some(v => /^(AWS_(ACCESS_KEY_ID|SECRET_ACCESS_KEY|SESSION_TOKEN|CONTAINER_CREDENTIALS)|MNEMO_DSN|MEM9_DB_SECRET)=/.test(v)), 'ImageContainsCredentialEnvironment');
      images[name] = image.Id;
    }
    report.images = images;
    const pgImage = JSON.parse(await docker(['image', 'inspect', 'pgvector/pgvector:pg17']))[0].Id;
    report.postgresImage = pgImage;
    await docker(['network', 'create', '--internal', '--label', `${LABEL}=${runId}`, network]); networkCreated = true;
    need((await inspect(network)).Internal === true, 'NetworkNotInternal');
    await mark('internalNetwork');
    const hardened = Object.fromEntries(baseline.taskDefinition.containerDefinitions.filter(c => c.name !== 'qwen3-embed').map(c => [c.name, hardenServiceContainer(c)]));
    const fixture = await create('fixture', images['llm-proxy'], ['--user', '1000:1000', '--cap-drop=ALL', '--init'], {},
      ['/usr/bin/setpriv', '--no-new-privs', '--', 'node', '--input-type=module', '-e', `(${fixtureProgram.toString()})();`]);
    await docker(['start', fixture]);
    const proxySecret = {AWS_ACCESS_KEY_ID: 'ASIA' + randomBytes(8).toString('hex').toUpperCase(), AWS_SECRET_ACCESS_KEY: randomBytes(30).toString('base64'),
      AWS_SESSION_TOKEN: randomBytes(32).toString('base64'), AWS_EC2_METADATA_DISABLED: 'true',
      AWS_SHARED_CREDENTIALS_FILE: '/nonexistent', AWS_CONFIG_FILE: '/nonexistent',
      LLM_PROXY_REGION: 'us-east-1', LLM_PROXY_UPSTREAM_BASE: 'http://fixture:9090/v1', LLM_PROXY_REFRESH_INTERVAL_MS: '1000'};
    const proxy = await create('proxy', images['llm-proxy'], ['--user', '1000:1000', '--cap-drop=ALL', '--init'], proxySecret, hardened['llm-proxy'].entryPoint);
    await docker(['start', proxy]);
    await waitFor(async () => {await health(proxy, hardened['llm-proxy']); return true;}, 'ProxyHealthFailed');
    await identity(proxy, 'proxy'); await mark('proxyExactEntrypointHealth');
    const realUpstream = await docker(['exec', '-i', '--user', '1000:1000', proxy, '/usr/bin/setpriv', '--no-new-privs', '--', 'node', '--input-type=module'],
      {input: "const r=await fetch('http://127.0.0.1:8082/v1/chat/completions',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({model:'synthetic-chat',messages:[{role:'user',content:'synthetic'}],max_tokens:16}),signal:AbortSignal.timeout(10000)});if(r.status!==200)process.exit(1);const b=await r.json();if(b.choices[0].message.content!=='synthetic response')process.exit(2);console.log('ok');"});
    need(realUpstream.trim() === 'ok', 'ProxySyntheticUpstreamFailed'); await mark('proxySyntheticHttpUpstream');
    const moduleResult = await docker(['exec', '-i', '--user', '1000:1000', proxy, '/usr/bin/setpriv', '--no-new-privs', '--', 'node', '--input-type=module'],
      {input: `(${proxyModuleProgram.toString()})().catch(e=>{process.stdout.write(/^[A-Z][A-Za-z0-9_]{1,80}$/.test(e.message)?e.message:(e.code||'ModuleSmokeFailed'));process.exitCode=1;});`});
    await mark('proxyModule', JSON.parse(moduleResult));

    // Copy frozen schema assets without running any apply-mode mnemo process.
    const mnemo = await create('mnemo', images['mnemo-server'], ['--user', '1000:1000', '--cap-drop=ALL', '--init', '-p', '127.0.0.1::8080'], {}, hardened['mnemo-server'].entryPoint);
    const assets = join(temporary, 'frozen-schema'); await mkdir(assets, {mode: 0o700});
    await docker(['cp', `${mnemo}:/usr/local/share/mem9/.`, assets]);
    async function secureTree(path) {for (const e of await readdir(path, {withFileTypes: true})) {need(!e.isSymbolicLink(), 'SchemaSymlinkRejected'); const p = join(path, e.name); await chmod(p, e.isDirectory() ? 0o700 : 0o600); if (e.isDirectory()) await secureTree(p);}}
    await secureTree(assets);
    const {runtimeSchemaDigest, runtimeRoleName} = await import('./lib/runtime-credentials.mjs');
    const frozenDigest = (await readFile(join(assets, 'schema.sha256'), 'utf8')).trim();
    need(await runtimeSchemaDigest(assets) === frozenDigest, 'FrozenSchemaDigestMismatch'); report.frozenSchemaHash = frozenDigest;
    // Re-create only this owned, never-started container after preparing its env.
    await docker(['rm', mnemo]); containers.splice(containers.indexOf(mnemo), 1);
    const adminPassword = randomBytes(24).toString('hex');
    const pg = await create('postgres', pgImage, ['--tmpfs', '/var/lib/postgresql/data:rw,size=1073741824', '-p', '127.0.0.1::5432'],
      {POSTGRES_PASSWORD: adminPassword, POSTGRES_DB: 'nonroot_smoke'}, ['/bin/sh', '-c',
        'chown postgres:postgres /tmp/smoke.key /tmp/smoke.crt; chmod 600 /tmp/smoke.key; exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/tmp/smoke.crt -c ssl_key_file=/tmp/smoke.key -c log_statement=none -c log_min_error_statement=panic -c log_error_verbosity=terse']);
    await command('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=postgres',
      '-keyout', join(temporary, 'tls.key'), '-out', join(temporary, 'tls.crt')]);
    await chmod(join(temporary, 'tls.key'), 0o600); await chmod(join(temporary, 'tls.crt'), 0o600);
    await docker(['cp', join(temporary, 'tls.key'), `${pg}:/tmp/smoke.key`]); await docker(['cp', join(temporary, 'tls.crt'), `${pg}:/tmp/smoke.crt`]);
    await docker(['start', pg]);
    await waitFor(async () => {await docker(['exec', pg, 'pg_isready', '-U', 'postgres', '-d', 'nonroot_smoke']); return true;}, 'PostgresReadinessFailed');
    report.phase = 'postgres-port-binding'; await save();
    const pgEndpoint = await endpoint(pg, 5432);
    const {default: Pg} = await import('pg');
    const connect = async credentials => {const client = new Pg.Client({host: pgEndpoint.host, port: pgEndpoint.port, database: 'nonroot_smoke',
      user: credentials.username, password: credentials.password, ssl: {rejectUnauthorized: false}, connectionTimeoutMillis: 5000, statement_timeout: 15000, query_timeout: 20000});
      client.on('error', () => {}); clients.add(client); client.once('end', () => clients.delete(client));
      try {await client.connect(); return client;} catch (error) {await client.end().catch(() => {}); throw error;}};
    report.phase = 'synthetic-postgres-tls'; await save();
    await waitFor(async () => {database = await connect({username: 'postgres', password: adminPassword}); return true;}, 'PostgresTlsConnectionFailed', 30);
    const stage = 'pr-987654321', tenant = randomBytes(16).toString('hex');
    const credentials = {username: runtimeRoleName(stage), password: randomBytes(24).toString('hex'), salt: randomBytes(18).toString('hex')};
    const namespace = randomUUID(), otherNamespace = randomUUID(), principal = randomUUID(), otherPrincipal = randomUUID();
    const auth = await import('../infra/gateway/namespace-auth.mjs');
    const issuer = 'https://synthetic.example.com', clientId = 'synthetic-smoke';
    const principalKey = auth.derivePrincipalKey(issuer, 'm2m', clientId), clientKey = auth.deriveClientKey(issuer, clientId);
    const {bootstrapRuntime} = await import('./runtime-bootstrap.mjs');
    const {ensureNamespaceIndexes} = await import('./migrate-memory-namespaces.mjs');
    report.phase = 'frozen-runtime-bootstrap'; await save();
    await bootstrapRuntime({db: database, config: {stage, tenant, host: 'postgres', port: 5432, database: 'nonroot_smoke', credentials},
      schemaRoot: assets, deadline, connectRuntime: () => connect(credentials), prepareNamespaces: async db => {
        for (const [ns, actor, key] of [[namespace, principal, principalKey], [otherNamespace, otherPrincipal, hash('synthetic-other')]]) {
          await db.query("INSERT INTO memory_namespaces(namespace_id,slug,display_name) VALUES($1,$1,'synthetic smoke')", [ns]);
          await db.query("INSERT INTO memory_principals(principal_id,principal_key,principal_type) VALUES($1,$2,'m2m')", [actor, key]);
          await db.query("INSERT INTO memory_namespace_memberships(namespace_id,principal_id,role,source_type) VALUES($1,$2,'member','m2m_binding')", [ns, actor]);
        }
        await db.query('INSERT INTO memory_m2m_namespace_bindings(client_key,principal_id,namespace_id) VALUES($1,$2,$3)', [clientKey, principal, namespace]);
        await db.query("UPDATE memory_namespace_migration_state SET phase='application_ready',legacy_namespace_id=$1,legacy_namespace_slug=$1,legacy_namespace_display_name='synthetic',legacy_principal_id=$2,legacy_principal_key=$3 WHERE singleton_id", [namespace, principal, principalKey]);
        await ensureNamespaceIndexes(db);
        await db.query(await readFile(join(assets, 'migrations/003_enforce_memory_namespaces.sql'), 'utf8'));
      }});
    await mark('frozenRuntimeBootstrap');
    const signingRaw = JSON.stringify({active: 'a', a: randomBytes(32).toString('base64url'), b: randomBytes(32).toString('base64url')}), keys = auth.parseSigningKeys(signingRaw);
    const environment = {MEM9_STAGE: stage, MEM9_TENANT_ID: tenant, MEM9_DB_HOST: 'postgres', MEM9_DB_PORT: '5432', MEM9_DB_NAME: 'nonroot_smoke',
      MEM9_DB_SECRET: JSON.stringify(credentials), MNEMO_SCHEMA_MODE: 'verify', MNEMO_NAMESPACE_REQUIRED: '1', MNEMO_DB_BACKEND: 'postgres',
      MNEMO_PORT: '8080', MNEMO_UPLOAD_DIR: '/tmp', MNEMO_INGEST_MODE: 'raw', MNEMO_TIDB_ZERO_ENABLED: 'false',
      MNEMO_EMBED_BASE_URL: 'http://fixture:9090/v1', MNEMO_EMBED_MODEL: 'synthetic', MNEMO_EMBED_API_KEY: 'local', MNEMO_EMBED_DIMS: '1024',
      MNEMO_TRANSPORT_ISSUER: 'gateway-target', MNEMO_TRANSPORT_SIGNING_KEYS: signingRaw,
      MNEMO_CONSOLIDATION_EXECUTION_ENABLED: 'false', MNEMO_UPLOAD_WORKER_ENABLED: 'false', MNEMO_WEBHOOKS_ENABLED: 'false', MNEMO_SPACE_CHAINS_ENABLED: 'false',
      MNEMO_NAMESPACE_EXACT_VECTOR_MAX_ROWS: '30000', MNEMO_NAMESPACE_EXACT_VECTOR_TIMEOUT: '2s', MNEMO_MIGRATION_MAX_ATTEMPTS: '2',
      MNEMO_MIGRATION_RETRY_DELAY_SECONDS: '1', PGCONNECT_TIMEOUT: '3', AWS_EC2_METADATA_DISABLED: 'true'};
    const server = await create('mnemo', images['mnemo-server'], ['--user', '1000:1000', '--cap-drop=ALL', '--init', '-p', '127.0.0.1::8080'], environment, hardened['mnemo-server'].entryPoint);
    // Negative startup: use the real ready_for contract, never a fabricated stub.
    await database.query('UPDATE mem9_runtime.readiness SET ready=false WHERE singleton');
    await docker(['start', server]);
    await waitFor(async () => !(await inspect(server)).State.Running, 'UnreadySchemaWasAccepted', 30);
    need((await inspect(server)).State.ExitCode !== 0, 'UnreadySchemaExitedSuccessfully'); await mark('verifyRejectsUnreadySchema');
    await database.query('UPDATE mem9_runtime.readiness SET ready=true WHERE singleton');
    await docker(['start', server]);
    report.phase = 'mnemo-verify-startup'; await save();
    await waitFor(async () => {await health(server, hardened['mnemo-server']); return true;}, 'MnemoVerifyReadinessFailed');
    await identity(server, 'mnemo'); await mark('mnemoVerifyEntrypointHealth');
    const runtime = await connect(credentials);
    try {
      need((await runtime.query('SELECT mem9_runtime.ready_for($1,$2) AS ready', [stage, frozenDigest])).rows[0].ready, 'RuntimeReadinessFalse');
      let denied = false; try {await runtime.query('CREATE TABLE public.nonroot_should_be_denied(id int)');} catch (error) {denied = error.code === '42501';}
      need(denied, 'RuntimeDdlAllowed');
    } finally {await runtime.end();}
    await mark('runtimeRoleReadinessAndDdlDenial');
    const vector = JSON.stringify(Array.from({length: 1024}, (_, i) => i === 0 ? 1 : 0));
    const memory = randomUUID(), otherMemory = randomUUID();
    for (const [id, ns, actor] of [[memory, namespace, principal], [otherMemory, otherNamespace, otherPrincipal]])
      await database.query("INSERT INTO memories(id,namespace_id,content,memory_type,embedding,created_by_principal_id,updated_by_principal_id) VALUES($1,$2,'synthetic telescope calibration','pinned',$3::vector,$4,$4)", [id, ns, vector, actor]);
    const serverEndpoint = await endpoint(server, 8080);
    const request = async (path, {key = tenant, signed = true, expired = false} = {}) => {
      const headers = {'X-API-Key': key};
      if (signed) headers['X-Mem9-Transport'] = auth.createTransportEnvelope({issuer: 'gateway-target', method: 'GET', path, keys,
        identity: {principal_key: principalKey, principal_type: 'm2m', client_key: clientKey, group_keys: []},
        ...(expired ? {now: Math.floor(Date.now() / 1000) - 120} : {})});
      const response = await fetch(`http://${serverEndpoint.host}:${serverEndpoint.port}${path}`, {headers, signal: AbortSignal.timeout(15000)});
      return {status: response.status, body: await response.text()};
    };
    const path = '/v1alpha2/mem9s/memories';
    for (const [name, opts] of [['missingSignature', {signed: false}], ['wrongTenant', {key: randomBytes(16).toString('hex')}], ['expiredSignature', {expired: true}]]) {
      const response = await request(path, opts);
      await mark(`${name}Observation`, {status: response.status});
      // The frozen API also uses 400 for an unknown tenant key. Require a
      // client rejection and absence of either fixture memory, never a 5xx.
      need((name === 'wrongTenant' ? [400, 401, 403, 404] : [401, 403]).includes(response.status) &&
        !response.body.includes(memory) && !response.body.includes(otherMemory), 'AuthorizationNegativeFailed'); await mark(name);
    }
    for (const mode of ['semantic', 'keyword']) {
      const result = await request(`${path}?q=telescope&search_mode=${mode}&limit=10`);
      need(result.status === 200 && result.body.includes(memory) && !result.body.includes(otherMemory), 'NamespaceSearchFailed'); await mark(`${mode}NamespaceSearch`);
    }
    const denied = await request(`${path}/${otherMemory}`); need([403, 404].includes(denied.status), 'CrossNamespaceReadAllowed'); await mark('crossNamespaceReadDenied');
    const stats = JSON.parse(await docker(['exec', fixture, 'node', '--input-type=module', '-e', "console.log(JSON.stringify(await(await fetch('http://127.0.0.1:9090/stats')).json()))"]));
    need(stats.embeddings > 0 && stats.upstream > 0, 'SyntheticDependencyNotExercised'); await mark('syntheticDependencyCalls', stats);
    need(!interrupted && Date.now() < deadline, 'SmokeDeadlineOrSignal');
    delete report.commandFailure;
    report.outcome = 'PASS'; report.phase = 'complete';
  } catch (error) {
    report.outcome = 'BLOCKED';
    report.failures.push({phase: report.phase ?? 'local-preflight-or-proxy', code: /^[A-Z][A-Za-z0-9]{1,90}$/.test(error.message ?? '') ? error.message : 'SmokeFailure',
      ...( /^[0-9A-Z_]{2,40}$/.test(error.code ?? '') ? {errorCode: error.code} : {}),
      reason: ['SSL', 'ECONNREFUSED', 'authentication', 'does not exist', 'permission denied', 'syntax error', 'Cannot find module']
        .find(value => String(error.message).includes(value)) ?? 'SeePhaseAndChecks',
      location: String(error.stack ?? '').split('\n').slice(1, 3).map(line => line.replace(ROOT, '<repo>'))});
  } finally {
    clearTimeout(watchdog);
    await Promise.allSettled([...clients].map(client => client.end()));
    const failures = [];
    for (const name of [...containers].reverse()) {
      try {
        const item = JSON.parse(await docker(['inspect', name], {cleanup: true, timeout: 5000}))[0];
        need(item.Config.Labels?.[LABEL] === runId, 'CleanupOwnershipMismatch');
        await docker(['rm', '-f', '-v', name], {cleanup: true, timeout: 10000});
      } catch {failures.push('OwnedContainerCleanupUnverified');}
    }
    if (networkCreated) try {
      const item = JSON.parse(await docker(['network', 'inspect', network], {cleanup: true, timeout: 5000}))[0];
      need(item.Labels?.[LABEL] === runId, 'CleanupOwnershipMismatch'); await docker(['network', 'rm', network], {cleanup: true, timeout: 10000});
    } catch {failures.push('OwnedNetworkCleanupUnverified');}
    await rm(temporary, {recursive: true, force: true});
    if (lockAcquired && failures.length === 0) try {
      need(JSON.parse(await readFile(join(localLock, 'owner.local.json'), 'utf8')).runId === runId, 'LocalLockOwnershipMismatch');
      await rm(join(localLock, 'owner.local.json')); await rmdir(localLock);
    } catch {failures.push('OwnedLocalLockCleanupUnverified');}
    report.cleanup = {complete: failures.length === 0, failures};
    if (failures.length) report.outcome = 'BLOCKED';
    report.finishedAt = new Date().toISOString(); await save();
    process.off('SIGINT', interrupt); process.off('SIGTERM', interrupt);
  }
  return {outcome: report.outcome, evidence: join(output, 'report.local.json'), failures: report.failures};
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  runSmoke(parseArgs(process.argv.slice(2))).then(result => {console.log(JSON.stringify(result)); if (result.outcome !== 'PASS') process.exitCode = 1;})
    .catch(() => {console.error('Local smoke preflight failed; owner-only baseline and evidence directory required.'); process.exitCode = 1;});
}
