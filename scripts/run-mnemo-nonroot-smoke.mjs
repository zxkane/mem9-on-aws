import {spawn} from 'node:child_process';
import {randomBytes} from 'node:crypto';
import {mkdirSync,mkdtempSync,writeFileSync,readFileSync,lstatSync,existsSync,readdirSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {resolve,join,dirname} from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {setTimeout as pause} from 'node:timers/promises';
import {nonrootHash as hash} from './lib/production-nonroot-contracts.mjs';
import {CI_SMOKE_CHECKS,CI_SMOKE_HEALTH_COMMAND,CI_SMOKE_REDACTED_VALUE,ciSmokeBindingHash,inspectCiSmokeRecord} from './lib/ci-smoke-evidence.mjs';
import {extractSamplerEventFromDockerLogs,validateSamplerEvent} from './validate-emf-event.mjs';
import {sha,need,fail,command,docker,dockerJson,privateJson,scanBytes,allZero,localImageMetadata} from './lib/mnemo-nonroot-smoke-helper.mjs';

const ROOT=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const HELPER=join(ROOT,'scripts/lib/mnemo-nonroot-smoke-helper.mjs');
const MAX_BYTES=8*1024*1024,MAX_MS=900000,RESERVE_MS=60000;
const LABEL='mem9-ci-smoke-invocation';
const ROLES=['server','database','busybox','invalid-migration','invalid-timeout','no-server-health'];
const filePin=path=>{const file=join(ROOT,path),bytes=readFileSync(file),s=lstatSync(file);return {path,gitMode:(s.mode&0o111)?'100755':'100644',sha256:sha(bytes),bytes:bytes.length};};
const SOURCE_PATHS=['scripts/run-mnemo-nonroot-smoke.sh','scripts/run-mnemo-nonroot-smoke.mjs','scripts/lib/mnemo-nonroot-smoke-helper.mjs','scripts/validate-emf-event.mjs','scripts/lib/ci-smoke-evidence.mjs','scripts/lib/production-nonroot-contracts.mjs','scripts/lib/production-canary-verification.mjs'];
const exact=(v,keys)=>need(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===keys.slice().sort().join(),'SmokeInputFields');
const now=()=>Date.now();
export const NONROOT_SMOKE_DATABASE_IMAGE=Object.freeze({
 qualifiedImage:'pgvector/pgvector@sha256:cf134a767f474095eeba57e0117be8e568e011a63f33fbf252f14c9b760f8e6f',
 rootDigest:'sha256:cf134a767f474095eeba57e0117be8e568e011a63f33fbf252f14c9b760f8e6f',
 arm64Digest:'sha256:de5bb95ded567f98e342a29f188f8053b2e8d344cb9ccd52cbdfe15f720cfde7',
 configDigest:'sha256:9f6f5e8f6bf64903df0a7743c4580477c14139cdaac1c17056b21721cf34369e',
});
/** Serialize independently acquired job/image identities; this pure builder
 * does not authenticate CI jobs or grant production admission. */
export function createCiSmokeProducerInput({identity,isolationHash,images,...unknown}){
 exact(unknown,[]);
 exact(identity,['repository','runId','runAttempt','workflowPath','sourceRevision','sourceTree','buildJobId','smokeJobId','stepId','outputDigest','qualifiedImage','arm64Digest','configDigest']);
 ciSmokeBindingHash(identity);need(/^[a-f0-9]{64}$/.test(isolationHash),'SmokeIsolationHash');
 exact(images,['server','database']);
 for(const image of Object.values(images)){
  exact(image,['qualifiedImage','rootDigest','arm64Digest','configDigest']);
  need(typeof image.qualifiedImage==='string'&&/^[A-Za-z0-9._:/-]+@sha256:[a-f0-9]{64}$/.test(image.qualifiedImage)&&image.qualifiedImage.endsWith('@'+image.rootDigest),'SmokeImageInput');
  for(const key of ['rootDigest','arm64Digest','configDigest'])need(/^sha256:[a-f0-9]{64}$/.test(image[key]),'SmokeImageInput');
 }
 need(hash(images.database)===hash(NONROOT_SMOKE_DATABASE_IMAGE),'SmokeDatabaseImage');
 need(identity.qualifiedImage===images.server.qualifiedImage&&identity.outputDigest===images.server.rootDigest&&identity.arm64Digest===images.server.arm64Digest&&identity.configDigest===images.server.configDigest,'SmokeBuildDigestMismatch');
 return structuredClone({version:1,kind:'ci-smoke-producer-input',identity,isolationHash,images});
}
function secretEnvFile(path,values){writeFileSync(path,Object.entries(values).map(([k,v])=>{need(!/[\r\n\0]/.test(v),'SmokeEnvironment');return k+'='+v;}).join('\n')+'\n',{mode:0o600,flag:'wx'});}

const DB_SCRIPT=`set -eu
umask 077
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=mnemo-smoke-db -keyout /tls/server.key -out /tls/server.crt >/dev/null 2>&1
printf '%s' "$POSTGRES_PASSWORD" > /tls/password
initdb --pgdata=/pgdata --username=mnemo --pwfile=/tls/password --auth-local=trust --auth-host=scram-sha-256 --no-sync >/dev/null
rm /tls/password
printf 'local all all trust\nhostssl all all all scram-sha-256\nhostnossl all all all reject\n' > /tls/pg_hba.conf
printf 'CREATE DATABASE mnemo;\n' | postgres --single -D /pgdata template1 >/dev/null
exec postgres -D /pgdata -c listen_addresses=* -c unix_socket_directories=/var/run/postgresql -c ssl=on -c ssl_cert_file=/tls/server.crt -c ssl_key_file=/tls/server.key -c hba_file=/tls/pg_hba.conf -c log_min_error_statement=panic -c log_error_verbosity=terse -c log_statement=none -c log_connections=off -c log_disconnections=off -c logging_collector=off -c shared_buffers=32MB -c max_connections=20`;
const waitThen=script=>`IFS= read -r ready; [ "$ready" = go ]; ${script}`;
const roleCommand=role=>role==='server'?['-ceu','exec /usr/local/bin/entrypoint.sh']:role==='database'?['-ceu',DB_SCRIPT]:
 role==='busybox'?['-ceu',waitThen('command -v wget; exec busybox --list')]:role==='no-server-health'?['-ceu',waitThen("exec /bin/sh -c '"+CI_SMOKE_HEALTH_COMMAND+"'")]:['-ceu',waitThen('exec /usr/local/bin/entrypoint.sh')];
const mountPlans=role=>role==='database'?[['/pgdata',536870912,0o700],['/tls',16777216,0o700],['/var/run/postgresql',16777216,0o755],['/var/lib/postgresql/data',1048576,0o700]]:role==='server'?[['/tmp',268435456,0o700]]:[];
function containerCreateArgs(role,{invocationId,images,workDirectory}){
 const user=role==='database'?'999:999':'1000:1000',name='mem9-smoke-'+invocationId.slice(0,24)+'-'+role;
 const args=['create','--pull','never','--platform','linux/arm64','--name',name,'--label',LABEL+'='+invocationId,'--user',user,'--cap-drop','ALL','--security-opt','no-new-privileges=true',
  '--read-only','--tty=false','--pids-limit',role==='database'?'96':'64','--memory',role==='database'?'768m':'512m','--cpus','1','--network',['server','database'].includes(role)?'mem9-ci-smoke-'+invocationId.slice(0,24):'none','--env-file',join(workDirectory,role+'.env')];
 if(!['server','database'].includes(role))args.push('--interactive');
 for(const [path,size,mode]of mountPlans(role))args.push('--tmpfs',`${path}:rw,noexec,nosuid,nodev,uid=${user.split(':')[0]},gid=${user.split(':')[1]},mode=${mode.toString(8)},size=${size}`);
 args.push('--entrypoint','/bin/sh',images[role==='database'?'database':'server'].qualifiedImage,...roleCommand(role));return args;
}

/** Resolve only the pinned producer's finite argv templates. Bindings must
 * come from the independently authenticated host journal/image selection.
 * This validates arguments, not job provenance or the fourteen result checks. */
export function expectedCiSmokeCommandCatalog({catalog,bindings,...unknown}){
 exact(unknown,[]);exact(bindings,['invocationId','rootDirectory','nodeExecutable','workDirectory','outputDirectory','images','containers','networkId']);
 const b=bindings;need(/^[a-f0-9]{64}$/.test(b.invocationId)&&/^[a-f0-9]{64}$/.test(b.networkId),'SmokeCatalogBindings');
 for(const key of ['rootDirectory','nodeExecutable','workDirectory','outputDirectory'])need(typeof b[key]==='string'&&b[key].startsWith('/')&&!/[\0\r\n]/.test(b[key])&&resolve(b[key])===b[key],'SmokeCatalogBindings');
 exact(b.containers,ROLES);need(new Set(Object.values(b.containers)).size===ROLES.length&&Object.values(b.containers).every(id=>/^[a-f0-9]{64}$/.test(id)),'SmokeCatalogBindings');
 exact(b.images,['server','database']);for(const i of Object.values(b.images)){exact(i,['qualifiedImage','rootDigest','arm64Digest','configDigest']);need(typeof i.qualifiedImage==='string'&&/^[A-Za-z0-9._:/-]+@sha256:[a-f0-9]{64}$/.test(i.qualifiedImage)&&i.qualifiedImage.endsWith('@'+i.rootDigest),'SmokeCatalogBindings');for(const k of ['rootDigest','arm64Digest','configDigest'])need(/^sha256:[a-f0-9]{64}$/.test(i[k]),'SmokeCatalogBindings');}
 need(Array.isArray(catalog)&&catalog.length>0&&catalog.length<=1024,'SmokeCommandLimit');
 const helper=(mode,...args)=>[b.nodeExecutable,join(b.rootDirectory,'scripts/lib/mnemo-nonroot-smoke-helper.mjs'),mode,...args];
 return catalog.map((row,index)=>{
  exact(row,['sequence','commandKey','containerId','argv']);need(row.sequence===index&&Array.isArray(row.argv)&&row.argv.length>=1&&row.argv.length<=128&&row.argv.every(a=>typeof a==='string'&&a.length>0&&!a.includes('\0')),'SmokeCatalogRow');
  const role=ROLES.find(r=>b.containers[r]===row.containerId),id=row.containerId,user=role==='database'?'999:999':'1000:1000',key=row.commandKey,allowed=[];
  const add=(condition,argv)=>{if(condition)allowed.push(argv);};
  add(key==='create-network'&&id===null,['docker','network','create','--driver','bridge','--internal','--label',LABEL+'='+b.invocationId,'mem9-ci-smoke-'+b.invocationId.slice(0,24)]);
  if(key==='create-container'&&role)allowed.push(['docker',...containerCreateArgs(role,b)]);
  if(key==='inspect-container'&&role){allowed.push(['docker','inspect',id],['docker','inspect','--format','{{json .State}}',id]);if(['server','database'].includes(role))allowed.push(['docker','inspect','--format','{{json .HostConfig}}',id]);}
  if(key==='inspect-processes'&&role){allowed.push(helper('pids',id,user));const pid=row.argv.at(-1);if(/^[1-9][0-9]{0,9}$/.test(pid))allowed.push(helper('process',id,user,pid));}
  const negativeRoles={'busybox-wget':'busybox','reject-migration':'invalid-migration','reject-timeout':'invalid-timeout','health-absent':'no-server-health'};
  add(Object.hasOwn(negativeRoles,key)&&negativeRoles[key]===role,['docker','start','--attach','--interactive',id]);
  add(key==='start-container'&&role==='server',['docker','start',id]);
  add(key==='start-container'&&role==='database',['docker','exec','--user','999:999',id,'pg_isready','--username','mnemo','--dbname','mnemo']);
  add(key==='generate-tls'&&role==='database',['docker','start',id]);
  add(['health-before','health-after'].includes(key)&&role==='server',['docker','exec','--user','1000:1000',id,'/bin/sh','-c',CI_SMOKE_HEALTH_COMMAND]);
  add(['stat-tls','tls-query','plaintext-query','relations-query'].includes(key)&&role==='database',helper(key,id));
  add(key==='collect-logs'&&['server','database'].includes(role),['docker','logs',id]);
  add(key==='scan-logs'&&id===null,helper('scan-logs',join(b.workDirectory,'scan.json')));
  add(key==='validate-emf'&&id===null,[b.nodeExecutable,join(b.rootDirectory,'scripts/validate-emf-event.mjs'),'--docker-stream']);
  add(key==='inspect-network'&&id===null,['docker','network','inspect',b.networkId]);
  add(key==='stop-server'&&role==='server',['docker','stop','--timeout','10',id]);
  add(['remove-owned','inventory-owned'].includes(key)&&id===null,helper(key,join(b.outputDirectory,'owned-resources.json')));
  need(allowed.some(argv=>hash(argv)===hash(row.argv)),'SmokeUnplannedCommandArguments');return structuredClone(row);
 });
}

class Recorder{
 constructor(output,common,password,deadline,scannerPin){this.output=output;this.common=common;this.password=password;this.deadline=deadline;this.scannerPin=scannerPin;this.sequence=0;this.catalog=[];this.logs=[];this.commands=[];this.total=0;mkdirSync(join(output,'objects'),{recursive:true,mode:0o700});}
 bytes(value){const bytes=Buffer.from(value),digest=sha(bytes);need(bytes.length<=MAX_BYTES,'SmokeCaptureLimit');const file=join(this.output,'objects',digest+'.bin');
  if(!existsSync(file)){this.total+=bytes.length;need(this.total<=32*1024*1024,'SmokeArchiveLimit');writeFileSync(file,bytes,{mode:0o600,flag:'wx'});}return {sha256:digest,bytesLength:bytes.length};}
 json(value){const bytes=Buffer.from(JSON.stringify(value)),ref=this.bytes(bytes);return {bytesHash:ref.sha256,canonicalHash:hash(value),bytesLength:bytes.length};}
 makeLogs(cmd,raw,inspect){
  const refs=[];for(const stream of ['stdout','stderr']){
   const bytes=raw[stream],scan=scanBytes(bytes,this.password),special=inspect&&stream==='stdout';
   if(special)need(allZero({cloud:scan.cloudCredentialMatches,key:scan.privateKeyMatches,token:scan.tokenMatches}),'SmokeCredentialLeak');else need(allZero(scan),'SmokeCredentialLeak');
   const capture={version:1,kind:'ci-smoke-log',...this.common,containerId:cmd.containerId,stream,collectionCommand:cmd.ref,
    startedMs:cmd.startedMs,completedMs:cmd.completedMs,rawSha256:sha(bytes),rawBytes:bytes.length,redactedBytes:cmd[stream],
    redactions:special?inspect.ranges:[],scanner:this.scannerPin,scan,complete:true};
   refs.push(capture);this.logs.push(this.json(capture));
  }return refs;
 }
 begin(commandKey,containerId,file,args,{input,interactive=false,timeoutMs=30000,cleanup=false,inspectTransform,idFromStdout=false}={}){
  const remaining=this.deadline-now()-(cleanup?0:RESERVE_MS);need(remaining>0,'SmokeDeadline');timeoutMs=Math.min(timeoutMs,remaining);
  const sequence=this.sequence++,startedMs=now();need(sequence<1024,'SmokeCommandLimit');
  const argv=[file,...args],child=spawn(file,args,{cwd:ROOT,stdio:['pipe','pipe','pipe'],detached:true});
  const stdout=[],stderr=[];let size=0,incomplete=false;
  child.stdin.on('error',()=>{incomplete=true;child.kill('SIGKILL');});
  const finished=new Promise((resolvePromise,reject)=>{
   const kill=()=>{incomplete=true;try{process.kill(-child.pid,'SIGKILL');}catch{child.kill('SIGKILL');}};
   const timer=setTimeout(kill,timeoutMs);
   const collect=(list,bytes)=>{size+=bytes.length;if(size>MAX_BYTES)kill();else list.push(bytes);};
   child.stdout.on('data',b=>collect(stdout,b));child.stderr.on('data',b=>collect(stderr,b));child.on('error',reject);
   child.on('close',(exitCode,signal)=>{
    clearTimeout(timer);try{
     need(!incomplete&&signal===null&&Number.isInteger(exitCode),'SmokeCommandIncomplete');
     const raw={stdout:Buffer.concat(stdout),stderr:Buffer.concat(stderr)},completedMs=now();
     const inspected=inspectTransform?inspectTransform(raw.stdout):undefined;
     if(idFromStdout){containerId=raw.stdout.toString().trim();need(/^[a-f0-9]{64}$/.test(containerId),'SmokeContainerId');}
     for(const stream of ['stdout','stderr']){const scan=scanBytes(raw[stream],this.password);if(!(inspected&&stream==='stdout'))need(allZero(scan),'SmokeCredentialLeak');}
     const cmd={version:1,kind:'ci-smoke-command',...this.common,sequence,commandKey,containerId,argv,startedMs,completedMs,exitCode,signal:null,timedOut:false,
      stdout:this.bytes(inspected?inspected.bytes:raw.stdout),stderr:this.bytes(raw.stderr)};
     this.catalog.push({sequence,commandKey,containerId,argv});const ref=this.json(cmd),record={...cmd,ref};this.commands.push(record);
     const logs=this.makeLogs(record,raw,inspected);
     resolvePromise({...record,raw:{stdout:inspected?inspected.bytes:raw.stdout,stderr:raw.stderr},logs,inspect:inspected});
    }catch(error){reject(error);}
   });
  });
  // The caller attaches handling immediately; interactive negatives are held
  // on stdin only while their real main process identity is captured.
  finished.catch(()=>{});
  if(input!==undefined)child.stdin.end(input);else if(!interactive)child.stdin.end();
  return {child,finished,startedMs};
 }
 run(...args){return this.begin(...args).finished;}
}

function redactInspection(bytes,secretNames){
 const raw=JSON.parse(bytes.toString()),redactedFields=[],ranges=[];need(Array.isArray(raw)&&raw.length===1,'SmokeInspect');
 const env=raw[0].Config.Env;need(Array.isArray(env),'SmokeInspect');
 for(let i=0;i<env.length;i++){
  const name=env[i].split('=')[0];if(!secretNames.includes(name))continue;
  const literal=Buffer.from(JSON.stringify(env[i])),start=bytes.indexOf(literal);need(start>=0,'SmokeRedaction');
  redactedFields.push({pointer:'/0/Config/Env/'+i,valueHash:sha(env[i])});ranges.push({start,end:start+literal.length,class:'synthetic-credential'});
  env[i]=name+'='+CI_SMOKE_REDACTED_VALUE;
 }
 ranges.sort((a,b)=>a.start-b.start);return {value:raw,bytes:Buffer.from(JSON.stringify(raw)),redactedFields,ranges,rawSha256:sha(bytes),rawBytes:bytes.length};
}
function processRecord(capture,containerId,observedMs,expectedUid){
 const fields=new Map(capture.status.split('\n').filter(l=>l.includes(':')).map(l=>[l.slice(0,l.indexOf(':')),l.slice(l.indexOf(':')+1).trim()]));
 const stat=capture.stat.match(/^(\d+) \(.*\) \S (.*)$/s);need(stat,'SmokeProcessStat');const rest=stat[2].trim().split(/\s+/);
 const uid=fields.get('Uid').split(/\s+/).map(Number),gid=fields.get('Gid').split(/\s+/).map(Number);
 need([...uid,...gid].every(n=>n===expectedUid)&&fields.get('CapEff')==='0000000000000000'&&fields.get('CapBnd')==='0000000000000000'&&fields.get('NoNewPrivs')==='1','SmokeProcessIsolation');
 return {pid:Number(stat[1]),ppid:Number(rest[0]),startTimeTicks:Number(rest[18]),executablePath:capture.exe,executableSha256:capture.executableSha256,uid,gid,
  capEff:fields.get('CapEff'),capBnd:fields.get('CapBnd'),noNewPrivs:Number(fields.get('NoNewPrivs')),containerId,observedMs};
}

export async function runNonrootSmoke({input,outputDirectory,local=false}){
 exact(input,local?['version','kind','images']:['version','kind','identity','isolationHash','images']);
 need(input.version===1&&input.kind===(local?'local-smoke-producer-input':'ci-smoke-producer-input'),'SmokeInputKind');
  exact(input.images,['server','database']);
  for(const image of Object.values(input.images)){
   const keys=['qualifiedImage','rootDigest','arm64Digest','configDigest'];
   if(local)need(image&&typeof image==='object'&&Object.hasOwn(image,'qualifiedImage')&&Object.keys(image).every(k=>keys.includes(k)),'SmokeImageInput');
   else exact(image,keys);
  }
  if(!local){
   createCiSmokeProducerInput({identity:input.identity,isolationHash:input.isolationHash,images:input.images});
   const i=input.identity;ciSmokeBindingHash(i);
   need(process.env.GITHUB_ACTIONS==='true'&&process.env.GITHUB_REPOSITORY===i.repository&&String(i.runId)===process.env.GITHUB_RUN_ID&&String(i.runAttempt)===process.env.GITHUB_RUN_ATTEMPT&&process.env.GITHUB_SHA===i.sourceRevision,'SmokeActualCiIdentityRequired');
   need(/^[a-f0-9]{64}$/.test(input.isolationHash),'SmokeIsolationHash');
  }
  const startedMs=now(),deadline=startedMs+MAX_MS,invocationId=randomBytes(32).toString('hex');
  const sourceFiles=SOURCE_PATHS.map(filePin),sourceBytes=new Map(sourceFiles.map(pin=>[pin.path,readFileSync(join(ROOT,pin.path))]));
  const scannerPin=sourceFiles.find(p=>p.path==='scripts/lib/mnemo-nonroot-smoke-helper.mjs'),validatorPin=sourceFiles.find(p=>p.path==='scripts/validate-emf-event.mjs');
 outputDirectory=resolve(outputDirectory);need(!existsSync(outputDirectory),'SmokeOutputExists');mkdirSync(outputDirectory,{recursive:true,mode:0o700});
 const workDirectory=mkdtempSync(join(tmpdir(),'mem9-ci-smoke-')),owned=[],networkName='mem9-ci-smoke-'+invocationId.slice(0,24);
 let networkId,recorder,stateFile,cleanupConfirmed=false;
 try{
  const images={};for(const role of ['server','database']){
   const given=input.images[role];need(given&&typeof given.qualifiedImage==='string','SmokeImageInput');
   images[role]=await localImageMetadata(given.qualifiedImage);
   const imageEnv=images[role].config.config?.Env??[];
   need(Array.isArray(imageEnv)&&!imageEnv.some(e=>/^(?:AWS_|GITHUB_|GH_|SSH_|DOCKER_AUTH|REGISTRY_|CI_JOB_TOKEN)/.test(e))&&allZero(scanBytes(JSON.stringify(imageEnv))),'SmokeCloudCredentialEnvironment');
   for(const key of ['rootDigest','arm64Digest','configDigest'])if(given[key]!==undefined)need(given[key]===images[role][key],'SmokeImageDigestMismatch');
  }
  need(images.database.qualifiedImage.startsWith('pgvector/pgvector@'),'SmokeDatabaseImage');
  if(!local){
   const i=input.identity;
   const git=args=>{const r=command('git',args,{cwd:ROOT});need(r.exitCode===0,'SmokeSourceIdentity');return r.stdout.toString().trim();};
   need(git(['rev-parse','HEAD'])===i.sourceRevision&&git(['rev-parse','HEAD^{tree}'])===i.sourceTree,'SmokeSourceIdentity');git(['diff','--quiet']);git(['diff','--cached','--quiet']);
   for(const pin of sourceFiles){
    const listed=git(['ls-files','--stage','--',pin.path]);need(listed.startsWith(pin.gitMode+' ')&&listed.endsWith('\t'+pin.path),'SmokeSourceIdentity');
    const blob=command('git',['show','HEAD:'+pin.path],{cwd:ROOT});need(blob.exitCode===0&&sha(blob.stdout)===pin.sha256,'SmokeSourceIdentity');
   }
   need(i.qualifiedImage===images.server.qualifiedImage&&i.outputDigest===images.server.rootDigest&&i.arm64Digest===images.server.arm64Digest&&i.configDigest===images.server.configDigest,'SmokeBuildDigestMismatch');
   need(/^[a-f0-9]{64}$/.test(input.isolationHash),'SmokeIsolationHash');ciSmokeBindingHash(i);
  }
  const common={bindingHash:local?hash({kind:'local-smoke',invocationId,images:Object.fromEntries(Object.entries(images).map(([k,v])=>[k,{rootDigest:v.rootDigest,configDigest:v.configDigest}]))}):ciSmokeBindingHash(input.identity),invocationId};
  const password=randomBytes(16).toString('hex')+':@/?#retry';
  recorder=new Recorder(outputDirectory,common,password,deadline,scannerPin);
  const secretFile=join(workDirectory,'password');writeFileSync(secretFile,password,{mode:0o600});
  const imageBindings=Object.fromEntries(Object.entries(images).map(([key,i])=>[key,{qualifiedImage:i.qualifiedImage,rootDigest:i.rootDigest,arm64Digest:i.arm64Digest,configDigest:i.configDigest}]));
  for(const image of Object.values(images))for(const bytes of Object.values(image.bytes))recorder.bytes(bytes);
  const checks={},metadata={},processes={},secretNames={server:['MEM9_DB_SECRET'],database:['POSTGRES_PASSWORD'],busybox:[], 'invalid-migration':[],'invalid-timeout':[],'no-server-health':[]};
  const check=(name,kind,start,end,payload,dependencies=[])=>{const value={version:1,kind:'ci-smoke-'+kind,...common,startedMs:start,completedMs:end,dependencies,payload};inspectCiSmokeRecord('CheckV1',value);checks[name]={value,ref:recorder.json(value)};return value;};
  const success=r=>{need(r.exitCode===0,'SmokeCommandFailed');return r;};
  const networkCreate=success(await recorder.run('create-network',null,'docker',['network','create','--driver','bridge','--internal','--label',LABEL+'='+invocationId,networkName]));
  networkId=networkCreate.raw.stdout.toString().trim();need(/^[a-f0-9]{64}$/.test(networkId),'SmokeNetworkId');
  const inspectFull=async role=>{
   const c=metadata[role],inspect=success(await recorder.run('inspect-container',c.id,'docker',['inspect',c.id],{inspectTransform:bytes=>redactInspection(bytes,secretNames[role])}));
   const capture={version:1,kind:'ci-smoke-inspect-capture',...common,command:inspect.ref,rawSha256:inspect.inspect.rawSha256,rawBytes:inspect.inspect.rawBytes,
    redactedJson:recorder.json(inspect.inspect.value),redactedFields:inspect.inspect.redactedFields,scanner:scannerPin,scan:{cloudCredentialMatches:0,privateKeyMatches:0,tokenMatches:0},complete:true};
   c.inspect=inspect;c.inspectCapture=recorder.json(capture);c.raw=inspect.inspect.value[0];
  };
  for(const role of ROLES){
   const user=role==='database'?'999:999':'1000:1000',name='mem9-smoke-'+invocationId.slice(0,24)+'-'+role;
   const env=role==='server'?{MEM9_DB_HOST:'mem9-smoke-'+invocationId.slice(0,24)+'-database',MEM9_DB_PORT:'5432',MEM9_DB_NAME:'mnemo',MEM9_DB_SECRET:JSON.stringify({username:'mnemo',password}),
    MNEMO_DB_BACKEND:'postgres',MNEMO_INGEST_MODE:'raw',MNEMO_MIGRATION_MAX_ATTEMPTS:'60',PGCONNECT_TIMEOUT:'2',MNEMO_MIGRATION_RETRY_DELAY_SECONDS:'1',MNEMO_TIDB_ZERO_ENABLED:'false',
    MNEMO_DURABLE_INGEST_ENABLED:'true',MEM9_TENANT_ID:'emf-smoke-tenant',MNEMO_DURABLE_INGEST_METRIC_STAGE:'prod',MNEMO_UPLOAD_DIR:'/tmp'}:
    role==='database'?{POSTGRES_USER:'mnemo',POSTGRES_PASSWORD:password,POSTGRES_DB:'mnemo',PGDATA:'/pgdata'}:
    role==='invalid-migration'?{MNEMO_DSN:'postgres://unused/unused',MNEMO_MIGRATION_MAX_ATTEMPTS:'00'}:role==='invalid-timeout'?{MNEMO_DSN:'postgres://unused/unused',PGCONNECT_TIMEOUT:'0'}:{};
   const envFile=join(workDirectory,role+'.env');secretEnvFile(envFile,env);
   const image=images[role==='database'?'database':'server'],mounts=mountPlans(role);
   need(Object.keys(image.config.config?.Volumes??{}).every(path=>mounts.some(m=>m[0]===path)),'SmokeUnownedImageVolume');
   const args=containerCreateArgs(role,{invocationId,images,workDirectory});
   const create=success(await recorder.run('create-container',null,'docker',args,{idFromStdout:true}));const id=create.containerId;owned.push({id,name,role});
   metadata[role]={role,id,name,user,image,create,environmentNames:[],startedMs:0};processes[role]=[];
   if(!['server','database'].includes(role))await inspectFull(role);
   else{
    const inspected=success(await recorder.run('inspect-container',id,'docker',['inspect','--format','{{json .HostConfig}}',id]));
    const h=JSON.parse(inspected.raw.stdout);need(h.Privileged===false&&h.ReadonlyRootfs===true&&!h.Binds?.length&&!h.CapAdd?.length&&hash(h.CapDrop)===hash(['ALL']),'SmokePrestartIsolation');
   }
  }
  const helper=(key,role,mode,args=[],opts={})=>recorder.run(key,role?metadata[role].id:null,process.execPath,[HELPER,mode,...args],opts);
  const state=async role=>{
   const c=metadata[role],r=success(await recorder.run('inspect-container',c.id,'docker',['inspect','--format','{{json .State}}',c.id]));
   const data=JSON.parse(r.raw.stdout);if(data.Running)c.startedMs=Date.parse(data.StartedAt);return data;
  };
  const captureProcesses=async(role,mainOnly=false)=>{
   const c=metadata[role];
   const pids=mainOnly?[1]:JSON.parse(success(await helper('inspect-processes',role,'pids',[c.id,c.user])).raw.stdout);
   for(const pid of pids){
    const r=success(await helper('inspect-processes',role,'process',[c.id,c.user,String(pid)]));
    const value=processRecord(JSON.parse(r.raw.stdout),c.id,r.completedMs,Number(c.user.split(':')[0]));
    processes[role].push({...value,statusCapture:r.stdout});
   }
  };
  const negative=async(role,key)=>{
   const c=metadata[role],ticket=recorder.begin(key,c.id,'docker',['start','--attach','--interactive',c.id],{interactive:true,timeoutMs:60000});
   let running=false;for(let i=0;i<60&&!running;i++){running=(await state(role)).Running;if(!running)await pause(50);}need(running,'SmokeNegativeNotRunning');
   await captureProcesses(role);ticket.child.stdin.end('go\n');return ticket.finished;
  };
  const busy=success(await negative('busybox','busybox-wget')),applets=busy.raw.stdout.toString().trim().split('\n');
  need(applets.includes('wget')&&applets[0].startsWith('/'),'SmokeBusybox');
  check('busybox-wget','busybox-wget',busy.startedMs,busy.completedMs,{command:busy.ref,containerId:metadata.busybox.id,wgetPath:applets[0],busyboxApplets:busy.stdout});
  for(const [role,key,name,variable,value,error]of [
   ['invalid-migration','reject-migration','reject-zero-migration-attempts','MNEMO_MIGRATION_MAX_ATTEMPTS','00','entrypoint: MNEMO_MIGRATION_MAX_ATTEMPTS must be an integer from 1 to 100'],
   ['invalid-timeout','reject-timeout','reject-zero-connect-timeout','PGCONNECT_TIMEOUT','0','entrypoint: PGCONNECT_TIMEOUT must be an integer from 1 to 60']]){
   const r=await negative(role,key);need(r.exitCode>0&&r.exitCode<125&&r.raw.stderr.toString().trim()===error,'SmokeNegativeDiagnostic');
   check(name,key,r.startedMs,r.completedMs,{command:r.ref,containerId:metadata[role].id,variable,value,error});
  }
  success(await recorder.run('start-container',metadata.server.id,'docker',['start',metadata.server.id]));await state('server');await inspectFull('server');
  // Capture the unchanged entrypoint before migrations, then the actual
  // server and its descendant tree after it becomes healthy.
  await captureProcesses('server',true);
  const health=key=>recorder.run(key,metadata.server.id,'docker',['exec','--user','1000:1000',metadata.server.id,'/bin/sh','-c',CI_SMOKE_HEALTH_COMMAND]);
  const before=await health('health-before');need(before.exitCode===1,'SmokeEarlyHealth');
  check('unhealthy-before-migration','health-before',before.startedMs,before.completedMs,{command:before.ref,serverId:metadata.server.id,databaseStarted:false,healthCommand:CI_SMOKE_HEALTH_COMMAND});
  const logs=role=>recorder.run('collect-logs',metadata[role].id,'docker',['logs',metadata[role].id]);
  let retry;for(let i=0;i<60;i++){const r=success(await logs('server'));if(r.raw.stderr.toString().includes('migration attempt 1/60 failed')){retry=r;break;}await pause(500);}need(retry,'SmokeRetryMissing');
  await pause(1);
  const dbStart=success(await recorder.run('generate-tls',metadata.database.id,'docker',['start',metadata.database.id]));await state('database');await inspectFull('database');
  let ready=false;for(let i=0;i<90;i++){
   const r=await recorder.run('start-container',metadata.database.id,'docker',['exec','--user','999:999',metadata.database.id,'pg_isready','--username','mnemo','--dbname','mnemo']);
   if(r.exitCode===0){ready=true;break;}await pause(500);
  }need(ready,'SmokeDatabaseNotReady');
  const tls=success(await helper('stat-tls','database','stat-tls',[metadata.database.id])),tlsValue=JSON.parse(tls.raw.stdout),generatedMs=JSON.parse(tls.raw.stderr).generatedMs;
  need(tlsValue.keyUid===999&&tlsValue.keyGid===999&&tlsValue.keyMode===0o600,'SmokeTlsOwner');
  const lineIndex=(bytes,pattern)=>bytes.toString().split('\n').findIndex(l=>pattern.test(l));
  const retryLine=lineIndex(retry.raw.stderr,/migration attempt 1\/60 failed/);
  const retryCheck=check('migration-retry','migration-retry',retry.startedMs,retry.completedMs,{serverId:metadata.server.id,log:retry.logs[1],lineStart:retryLine,lineEnd:retryLine,attempt:1,maxAttempts:60,databaseStartCommand:dbStart.ref},[hash(checks['unhealthy-before-migration'].value)]);
  let after;for(let i=0;i<120;i++){const r=await health('health-after');if(r.exitCode===0){after=r;break;}need(r.exitCode===1,'SmokeHealthTransport');await pause(500);}need(after,'SmokeServerNotHealthy');
  let serverLogs=success(await logs('server'));const recoveryLine=lineIndex(serverLogs.raw.stdout,/migration applied after [1-9][0-9]* retries/);need(recoveryLine>=0,'SmokeRecoveryMissing');
  const retries=Number(serverLogs.raw.stdout.toString().split('\n')[recoveryLine].match(/after (\d+) retries/)[1]);
  check('healthy-after-migration','health-after',after.startedMs,serverLogs.completedMs,{command:after.ref,serverId:metadata.server.id,databaseId:metadata.database.id,retryCheckHash:hash(retryCheck),recoveryLog:serverLogs.logs[0],lineStart:recoveryLine,lineEnd:recoveryLine,retries},[hash(retryCheck)]);
  await captureProcesses('server');await captureProcesses('database');
  const sqlTls=success(await helper('tls-query','database','tls-query',[metadata.database.id])),sqlValue=JSON.parse(sqlTls.raw.stdout);need(sqlValue.tlsEnabled===true&&Number.isSafeInteger(sqlValue.backendPid),'SmokeTlsRequired');
  check('tls-required','tls-required',sqlTls.startedMs,sqlTls.completedMs,{command:sqlTls.ref,databaseId:metadata.database.id,sslmode:'require',tlsEnabled:true,backendPid:sqlValue.backendPid,queryResult:sqlTls.stdout});
  const plaintext=await helper('plaintext-query','database','plaintext-query',[metadata.database.id]);need(plaintext.exitCode>0&&plaintext.exitCode<125&&plaintext.raw.stderr.toString().includes('pg_hba.conf rejects connection for host "127.0.0.1", user "mnemo", database "mnemo", no encryption'),'SmokePlaintextDiagnostic');
  check('plaintext-rejected','plaintext-rejected',plaintext.startedMs,plaintext.completedMs,{command:plaintext.ref,databaseId:metadata.database.id,sslmode:'disable',errorClass:'hostnossl-reject',diagnostic:plaintext.logs[1]});
  const relations=success(await helper('relations-query','database','relations-query',[metadata.database.id])),rel=JSON.parse(relations.raw.stdout);
  need(hash(rel)===hash({relations:['public.ingest_jobs','public.ingest_job_plans','public.sessions'],present:[true,true,true]}),'SmokeRelations');
  check('atomic-ingest-relations','atomic-relations',relations.startedMs,relations.completedMs,{command:relations.ref,databaseId:metadata.database.id,...rel,queryResult:relations.stdout});
  let emfReady=false;for(let i=0;i<120;i++){serverLogs=success(await logs('server'));try{extractSamplerEventFromDockerLogs(serverLogs.raw.stdout);emfReady=true;break;}catch{}await pause(500);}need(emfReady,'SmokeEmfMissing');
  const dbLogs=success(await logs('database'));
  const scanPlan=join(workDirectory,'scan.json');writeFileSync(scanPlan,JSON.stringify({secretFile,objectsDirectory:join(outputDirectory,'objects'),logs:[...serverLogs.logs,...dbLogs.logs].map(l=>({bytesHash:l.redactedBytes.sha256,bytesLength:l.redactedBytes.bytesLength})),logHashes:[...serverLogs.logs,...dbLogs.logs].map(hash)}),{mode:0o600});
  const scanned=success(await helper('scan-logs',null,'scan-logs',[scanPlan]));
  check('password-absent-from-logs','password-log-scan',scanned.startedMs,scanned.completedMs,{serverLogs:serverLogs.logs,databaseLogs:dbLogs.logs,scanner:scannerPin,scanCommand:scanned.ref,syntheticCredentialFingerprint:sha(password),rawMatches:0,encodedMatches:0,credentialPatternMatches:0});
  const emf=success(await recorder.run('validate-emf',null,process.execPath,[join(ROOT,'scripts/validate-emf-event.mjs'),'--docker-stream'],{input:serverLogs.raw.stdout}));
  const frames=[];let offset=0;for(let i=0;i<serverLogs.raw.stdout.length;i++)if(serverLogs.raw.stdout[i]===10){const bytes=serverLogs.raw.stdout.subarray(offset,i+1);if(bytes.includes(Buffer.from('"SamplerHeartbeat"'))){validateSamplerEvent(bytes);frames.push({offset,length:bytes.length,sha256:sha(bytes)});}offset=i+1;}
  check('non-tty-emf-framing','emf-framing',emf.startedMs,emf.completedMs,{command:emf.ref,serverId:metadata.server.id,stdout:serverLogs.logs[0],validator:validatorPin,frames});
  const networkInspect=success(await recorder.run('inspect-network',null,'docker',['network','inspect',networkId])),networkRaw=JSON.parse(networkInspect.raw.stdout)[0];
  need(networkRaw.Internal===true&&Object.keys(networkRaw.Containers).sort().join()===[metadata.server.id,metadata.database.id].sort().join(),'SmokeNetworkIsolation');
  const network={version:1,kind:'ci-smoke-network',...common,id:networkId,name:networkName,driver:networkRaw.Driver,internal:networkRaw.Internal,createdMs:Date.parse(networkRaw.Created),observedMs:networkInspect.completedMs,
   attachedContainerIds:Object.keys(networkRaw.Containers),createCommand:networkCreate.ref,inspectCapture:networkInspect.stdout};
  const stop=success(await recorder.run('stop-server',metadata.server.id,'docker',['stop','--timeout','10',metadata.server.id]));const stopped=await state('server');need(!stopped.Running,'SmokeServerNotStopped');
  const stoppedMs=now(),absent=await negative('no-server-health','health-absent');need(absent.exitCode===1,'SmokeAbsentHealth');
  check('unhealthy-without-server','health-absent',stop.startedMs,absent.completedMs,{stopCommand:stop.ref,negativeCommand:absent.ref,stoppedServerId:metadata.server.id,negativeContainerId:metadata['no-server-health'].id,serverStoppedMs:stoppedMs,healthCommand:CI_SMOKE_HEALTH_COMMAND});
  const containers=ROLES.map(role=>{
   const c=metadata[role],d=c.raw,h=d.HostConfig;need(c.startedMs>0&&processes[role].length,'SmokeRuntimeCoverage');
   if(['server','database'].includes(role))need(hash(Object.values(d.NetworkSettings.Networks).map(n=>n.NetworkID))===hash([networkId]),'SmokeContainerNetworkBinding');
   else need(h.NetworkMode==='none','SmokeContainerNetworkBinding');
   need(!h.Binds?.length&&!h.VolumesFrom?.length&&!h.Devices?.length&&!h.ExtraHosts?.length&&!Object.keys(h.PortBindings??{}).length,'SmokeHostBinding');
   need(!d.Config.Env.some(e=>/^(?:AWS_|GITHUB_|GH_|SSH_|DOCKER_AUTH|REGISTRY_|CI_JOB_TOKEN)/.test(e)),'SmokeCloudCredentialEnvironment');
   const mounts=Object.entries(h.Tmpfs??{}).map(([destination,flags])=>{const m=new Map(String(flags).split(',').map(s=>s.split('=')));const size=/^(\d+)([kmg])?$/i.exec(m.get('size'));need(size,'SmokeMountSize');return {type:'tmpfs',destination,rw:m.has('rw'),uid:Number(m.get('uid')),gid:Number(m.get('gid')),mode:parseInt(m.get('mode'),8),sizeBytes:Number(size[1])*({k:1024,m:1048576,g:1073741824}[size[2]?.toLowerCase()]??1),noexec:m.has('noexec'),nosuid:m.has('nosuid'),nodev:m.has('nodev')};});
   return {role,containerId:c.id,name:c.name,invocationId,imageRootDigest:c.image.rootDigest,imageConfigDigest:c.image.configDigest,platform:'linux/arm64',createdMs:Date.parse(d.Created),startedMs:c.startedMs,inspectMs:c.inspect.completedMs,
    user:d.Config.User,privileged:h.Privileged,readonlyRootfs:h.ReadonlyRootfs,capAdd:h.CapAdd??[],capDrop:h.CapDrop??[],noNewPrivileges:(h.SecurityOpt??[]).some(s=>s==='no-new-privileges=true'||s==='no-new-privileges:true'||s==='no-new-privileges'),tty:d.Config.Tty,
    networkMode:h.NetworkMode==='none'?'none':'owned-internal',networkId:h.NetworkMode==='none'?null:networkId,publishedPorts:Object.keys(h.PortBindings??{}),extraHosts:h.ExtraHosts??[],hostBindings:h.Binds??[],
    environmentNames:d.Config.Env.map(e=>e.split('=')[0]),entryPoint:d.Config.Entrypoint,command:d.Config.Cmd,mounts,createCommand:c.create.ref,inspectCapture:c.inspectCapture,processes:processes[role]};
  });
  const runtime={version:1,kind:'ci-smoke-runtime',...common,containers,network,databaseTls:{containerId:metadata.database.id,...tlsValue,generatedMs,statCommand:tls.ref}};
  inspectCiSmokeRecord('RuntimeV1',runtime);const runtimeRef=recorder.json(runtime),isolationEnd=now();
  check('nonroot-capabilities-nnp','isolation',startedMs,isolationEnd,{runtime:runtimeRef,observedContainerIds:containers.map(c=>c.containerId),processObservationHashes:containers.flatMap(c=>c.processes.map(hash)),networkObservationHash:hash(network)});
  stateFile=join(outputDirectory,'owned-resources.json');writeFileSync(stateFile,JSON.stringify({invocationId,containers:owned,network:networkId,workDirectory}),{mode:0o600});
  const removed=success(await helper('remove-owned',null,'remove-owned',[stateFile],{cleanup:true,timeoutMs:60000}));
  const inventory=success(await helper('inventory-owned',null,'inventory-owned',[stateFile],{cleanup:true}));
  need(hash(JSON.parse(inventory.raw.stdout))===hash({containerIds:[],networkIds:[],volumeNames:[],temporaryEntries:[]}),'SmokeCleanupIncomplete');
  cleanupConfirmed=true;
  const completedMs=now();
  check('owned-resource-cleanup','cleanup',removed.startedMs,completedMs,{runtimeHash:hash(runtime),removeCommands:[removed.ref],inventoryCommands:[inventory.ref],containerIds:owned.map(c=>c.id),networkIds:[networkId],volumeNames:[],
   remainingContainerIds:[],remainingNetworkIds:[],remainingVolumeNames:[],remainingTemporaryEntries:[],completedMs});
  need(Object.keys(checks).length===CI_SMOKE_CHECKS.length,'SmokeCheckCoverage');
  const logRef=recorder.json({version:1,kind:'ci-smoke-logs',...common,captures:recorder.logs});
  const evidence={startedMs,completedMs,checks:Object.fromEntries(CI_SMOKE_CHECKS.map(name=>[name,checks[name].ref])),runtimeEvidence:runtimeRef,logRef,cleanupRef:checks['owned-resource-cleanup'].ref};
  const result=local?{version:1,kind:'local-nonroot-smoke-observation',invocationId,bindingHash:common.bindingHash,images:imageBindings,...evidence}:
   {version:1,kind:'ci-smoke-isolation-result',isolationHash:input.isolationHash,...input.identity,...evidence};
  if(!local)inspectCiSmokeRecord('CiSmokeIsolationResultV1',result);
  for(const pin of sourceFiles){need(hash(filePin(pin.path))===hash(pin),'SmokeSourceChangedDuringRun');recorder.bytes(sourceBytes.get(pin.path));}
  const commandBindings={invocationId,rootDirectory:ROOT,nodeExecutable:process.execPath,workDirectory,outputDirectory,images:imageBindings,containers:Object.fromEntries(owned.map(c=>[c.role,c.id])),networkId};
  const commandCatalog=expectedCiSmokeCommandCatalog({catalog:recorder.catalog.sort((a,b)=>a.sequence-b.sequence),bindings:commandBindings});
  writeFileSync(join(outputDirectory,local?'local-result.json':'result.json'),JSON.stringify(result),{mode:0o600});
  writeFileSync(join(outputDirectory,'command-catalog.json'),JSON.stringify(commandCatalog),{mode:0o600});
  writeFileSync(join(outputDirectory,'command-bindings.json'),JSON.stringify(commandBindings),{mode:0o600});
  writeFileSync(join(outputDirectory,'producer-observations.json'),JSON.stringify({invocationId,images:imageBindings,sourceFiles,scanner:scannerPin,emfValidator:validatorPin,environmentNames:Object.fromEntries(containers.map(c=>[c.role,c.environmentNames])),secretEnvironmentNames:secretNames,
   executables:Object.fromEntries(containers.map(c=>[c.role,[...new Map(c.processes.map(p=>[p.executablePath+'\0'+p.executableSha256,{path:p.executablePath,sha256:p.executableSha256}])).values()]])),database:{host:'127.0.0.1',user:'mnemo',name:'mnemo'},migrationMaxAttempts:60}),{mode:0o600});
  return {result,outputDirectory};
 }catch(error){
  // Failure cleanup is bounded to this invocation's labels and known names.
  // It never produces a successful CI result or suppresses uncertainty.
  const failures=[];
  const bounded=args=>{need(now()<deadline,'SmokeCleanupDeadline');return docker(args,{timeoutMs:Math.min(10000,deadline-now())});};
  if(!cleanupConfirmed&&recorder){
   // A create response can be lost. Discover by this invocation's immutable
   // label, then check exact planned names before deleting any discovered ID.
   try{
    const listed=bounded(['ps','--all','--no-trunc','--filter','label='+LABEL+'='+invocationId,'--format','{{.ID}} {{.Names}}']);need(listed.exitCode===0,'SmokeInventoryFailed');
    for(const line of listed.stdout.toString().trim().split('\n').filter(Boolean)){
     const [id,name]=line.split(' ');need(/^[a-f0-9]{64}$/.test(id)&&ROLES.some(r=>name==='mem9-smoke-'+invocationId.slice(0,24)+'-'+r),'SmokeOwnership');
     const removed=bounded(['rm','--force','--volumes',id]);if(removed.exitCode!==0)failures.push(id);
    }
   }catch{failures.push('container-cleanup-unresolved');}
   try{
    const listed=bounded(['network','ls','--no-trunc','--filter','label='+LABEL+'='+invocationId,'--format','{{.ID}} {{.Name}}']);need(listed.exitCode===0,'SmokeInventoryFailed');
    for(const line of listed.stdout.toString().trim().split('\n').filter(Boolean)){
     const [id,name]=line.split(' ');need(/^[a-f0-9]{64}$/.test(id)&&name===networkName,'SmokeOwnership');
     if(bounded(['network','rm',id]).exitCode!==0)failures.push(id);
    }
   }catch{failures.push('network-cleanup-unresolved');}
   for(const [kind,args]of [['containers',['ps','--all','--no-trunc']],['networks',['network','ls','--no-trunc']],['volumes',['volume','ls']]])try{
    const r=bounded([...args,'--filter','label='+LABEL+'='+invocationId,'--format',kind==='volumes'?'{{.Name}}':'{{.ID}}']);
    if(r.exitCode!==0||r.stdout.toString().trim())failures.push(kind+'-remaining-or-unobserved');
   }catch{failures.push(kind+'-inventory-unresolved');}
  }
  try{if(existsSync(workDirectory))rmSync(workDirectory,{recursive:true});}catch{failures.push('work-directory');}
  writeFileSync(join(outputDirectory,'failure.json'),JSON.stringify({version:1,kind:'nonroot-smoke-failure',errorClass:/^[A-Za-z]+$/.test(error.message)?error.message:'SmokeFailed',cleanupUnresolved:failures,startedMs,completedMs:now()}),{mode:0o600});
  throw error;
 }
}

async function main(){
 const args=process.argv.slice(2),seen=new Set();let inputFile,outputDirectory,local=false;
 for(let i=0;i<args.length;i++){need(!seen.has(args[i]),'SmokeArguments');seen.add(args[i]);if(args[i]==='--input')inputFile=args[++i];else if(args[i]==='--output-dir')outputDirectory=args[++i];else if(args[i]==='--local')local=true;else fail('SmokeArguments');}
 need(inputFile&&outputDirectory,'SmokeArguments');const result=await runNonrootSmoke({input:privateJson(resolve(inputFile)),outputDirectory,local});
 process.stdout.write(JSON.stringify({event:'nonroot_smoke',kind:result.result.kind,checks:CI_SMOKE_CHECKS.length,resultHash:hash(result.result),outputDirectory:result.outputDirectory})+'\n');
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)main().catch(error=>{process.stderr.write(JSON.stringify({event:'nonroot_smoke_failed',errorClass:/^[A-Za-z]+$/.test(error.message)?error.message:'SmokeFailed'})+'\n');process.exitCode=1;});
