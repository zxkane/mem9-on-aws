// Reproducible synthetic evidence only. This fixture does not run Docker,
// PostgreSQL, GitHub or a workflow, and never supplies an approval capability.
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {nonrootHash as hash} from './lib/production-nonroot-contracts.mjs';
import {CI_SMOKE_CHECKS,CI_SMOKE_HEALTH_COMMAND,CI_SMOKE_REDACTED_VALUE,ciSmokeBindingHash} from './lib/ci-smoke-evidence.mjs';

export function ciSmokeEvidenceFixture({inspectSecret=false,earlyCleanup=false,local=false,prestartInspect=false,supplementalHostConfig=false,nativeStop=false,latestLogScan=false,retryExtraLine='',sourceTree='b'.repeat(40),repository='example/control-plane'}={}){
 const objects=new Map(),sha=raw=>createHash('sha256').update(raw).digest('hex'),H=n=>n.toString(16).padStart(64,'0'),D=n=>'sha256:'+H(n);
 const bytes=value=>{const raw=Buffer.from(value),ref={sha256:sha(raw),bytesLength:raw.length};objects.set(ref.sha256,raw);return ref;};
 const json=value=>{const raw=Buffer.from(JSON.stringify(value)),ref={bytesHash:sha(raw),canonicalHash:hash(value),bytesLength:raw.length};objects.set(ref.bytesHash,raw);return ref;};
 const get=ref=>JSON.parse(objects.get(ref.bytesHash??ref.sha256).toString());
 const pin=(path,raw)=>{const ref=bytes(raw);return {path,gitMode:'100644',sha256:ref.sha256,bytes:ref.bytesLength};};
 const scanner=pin('scripts/ci-smoke-runner.mjs','// synthetic scanner source fixture\n'),validator=pin('scripts/validate-emf-event.mjs',readFileSync(new URL('./validate-emf-event.mjs',import.meta.url)));
 const base=1700000000000,invocationId=H(91),isolationHash=H(92),qualifiedImage='123456789012.dkr.ecr.us-east-1.amazonaws.com/mem9-on-aws/preview/mnemo-server@'+D(1);
 const identity={repository,runId:100,runAttempt:1,workflowPath:'.github/workflows/infra-ci.yml',sourceRevision:'a'.repeat(40),sourceTree,buildJobId:101,smokeJobId:102,stepId:'mnemo',outputDigest:D(1),qualifiedImage,arm64Digest:D(2),configDigest:D(3)},bindingHash=local?hash({kind:'local-smoke',invocationId,images:{server:{rootDigest:D(1),configDigest:D(3)},database:{rootDigest:D(4),configDigest:D(6)}}}):ciSmokeBindingHash(identity);
 const shared={bindingHash,invocationId},records=[],catalog=[],logRecords=[],commandsByKey=new Map();let sequence=0;
 const allChecks={},containers=[],earlyRemoves=[],earlyRemoved=new Set(),networkId='synthetic-network',networkName='synthetic-internal';
 const expected={identity,isolationHash,invocationId,buildJob:{id:101,runId:100,runAttempt:1,sourceRevision:identity.sourceRevision,status:'completed',conclusion:'success',startedMs:base-2000,completedMs:base-1000},smokeJob:{id:102,runId:100,runAttempt:1,sourceRevision:identity.sourceRevision,status:'completed',conclusion:'success',startedMs:base-100,completedMs:base+10000},sourceFiles:[scanner,validator],scanner,emfValidator:validator,commandCatalog:catalog,
  images:{server:{rootDigest:D(1),arm64Digest:D(2),configDigest:D(3),qualifiedImage},database:{rootDigest:D(4),arm64Digest:D(5),configDigest:D(6),qualifiedImage:'pgvector/pgvector@'+D(4)}},environmentNames:{},secretEnvironmentNames:{},executables:{},database:{host:'127.0.0.1',user:'fixture',name:'fixture'},migrationMaxAttempts:10};
 const scans=()=>({rawPasswordMatches:0,encodedPasswordMatches:0,cloudCredentialMatches:0,privateKeyMatches:0,tokenMatches:0});
 const command=(key,cid,stdout='',stderr='',exitCode=0,duration=5,argv)=>{
  const n=sequence++,startedMs=base+n*100,value={version:1,kind:'ci-smoke-command',...shared,sequence:n,commandKey:key,containerId:cid,argv:argv??['synthetic-command',key,cid??'owned'],startedMs,completedMs:startedMs+duration,exitCode,signal:null,timedOut:false,stdout:bytes(stdout),stderr:bytes(stderr)},ref=json(value);
  catalog.push({sequence:n,commandKey:key,containerId:cid,argv:structuredClone(value.argv)});records.push(value);const pair={value,ref};commandsByKey.set(key,[...(commandsByKey.get(key)??[]),pair]);
  const logs=Object.fromEntries(['stdout','stderr'].map(stream=>{const data=value[stream],row={version:1,kind:'ci-smoke-log',...shared,containerId:cid,stream,collectionCommand:ref,startedMs,completedMs:value.completedMs,rawSha256:data.sha256,rawBytes:data.bytesLength,redactedBytes:data,redactions:[],scanner,scan:scans(),complete:true};logRecords.push(row);return [stream,row];}));
  return {...pair,logs};
 };
 const check=(name,suffix,payload,startedMs,completedMs,dependencies=[])=>{const value={version:1,kind:'ci-smoke-'+suffix,...shared,startedMs,completedMs,dependencies,payload};allChecks[name]=value;return value;};
 const networkCreate=command('create-network',null,networkId+'\n');
 const network={version:1,kind:'ci-smoke-network',...shared,id:networkId,name:networkName,driver:'bridge',internal:true,createdMs:networkCreate.value.startedMs+2,observedMs:base,attachedContainerIds:['synthetic-server','synthetic-database'],createCommand:networkCreate.ref,inspectCapture:bytes('[]')};
 const rawInspects=new Map(),stateReads=new Map();
 function container(role,startedMs){
  const uid=role==='database'?999:1000,cid='synthetic-'+role,image=role==='database'?expected.images.database:expected.images.server,connected=['server','database'].includes(role);
  const env=role==='server'?['MNEMO_UPLOAD_DIR=/tmp','MNEMO_MIGRATION_MAX_ATTEMPTS=10']:role==='invalid-migration'?['MNEMO_MIGRATION_MAX_ATTEMPTS=00']:role==='invalid-timeout'?['PGCONNECT_TIMEOUT=0']:[];
  if(role==='database'&&inspectSecret)env.push('POSTGRES_PASSWORD='+CI_SMOKE_REDACTED_VALUE);
  const mounts=(role==='database'?[['/pgdata',536870912,448],['/tls',16777216,448],['/var/run/postgresql',16777216,493],['/var/lib/postgresql/data',1048576,448]]:role==='server'?[['/tmp',268435456,448]]:[]).map(([destination,sizeBytes,mode])=>({type:'tmpfs',destination,rw:true,uid,gid:uid,mode,sizeBytes,noexec:true,nosuid:true,nodev:true}));
  const created=command('create-container',cid,cid+'\n'),c={role,containerId:cid,name:cid,invocationId,imageRootDigest:image.rootDigest,imageConfigDigest:image.configDigest,platform:'linux/arm64',createdMs:created.value.startedMs+2,startedMs:startedMs??created.value.completedMs+1,inspectMs:base+(sequence*100)+2,user:`${uid}:${uid}`,privileged:false,readonlyRootfs:true,capAdd:[],capDrop:['ALL'],noNewPrivileges:true,tty:false,networkMode:connected?'owned-internal':'none',networkId:connected?networkId:null,publishedPorts:[],extraHosts:[],hostBindings:[],environmentNames:env.map(s=>s.split('=')[0]),entryPoint:['/bin/setpriv','--no-new-privs','--','/synthetic/application'],command:[],mounts,createCommand:created.ref,inspectCapture:undefined,processes:[]};
  const raw=[{Id:cid,Name:'/'+cid,Image:image.configDigest,Platform:'linux',Config:{Image:image.qualifiedImage,User:c.user,Tty:false,Entrypoint:c.entryPoint,Cmd:[],Env:env},HostConfig:{Privileged:false,ReadonlyRootfs:true,PublishAllPorts:false,CapDrop:['ALL'],CapAdd:[],SecurityOpt:['no-new-privileges:true'],Binds:[],VolumesFrom:[],Devices:[],DeviceRequests:[],ExtraHosts:[],PortBindings:{},NetworkMode:connected?networkName:'none',Tmpfs:Object.fromEntries(mounts.map(m=>[m.destination,`rw,noexec,nosuid,nodev,uid=${uid},gid=${uid},mode=${m.mode.toString(8)},size=${m.sizeBytes}`]))},Mounts:mounts.map(m=>({Type:'tmpfs',Destination:m.destination})),NetworkSettings:{Networks:connected?{[networkName]:{NetworkID:networkId}}:{none:{NetworkID:'docker-none'}}}}];
  if(connected&&!prestartInspect)c.startedMs=created.value.startedMs+3;
  const initiallyRunning=connected&&!prestartInspect;
  raw[0].Created=new Date(c.createdMs).toISOString();raw[0].State={StartedAt:initiallyRunning?new Date(c.startedMs).toISOString():'0001-01-01T00:00:00Z',Status:initiallyRunning?'running':'created',Running:initiallyRunning};
  if(connected&&prestartInspect)raw[0].NetworkSettings.Networks[networkName].NetworkID='';
  Object.assign(raw[0].HostConfig,{Memory:role==='database'?805306368:268435456,NanoCpus:1000000000,PidsLimit:96,PidMode:'',UTSMode:'',IpcMode:'private',UsernsMode:''});
  const inspected=command('inspect-container',cid,JSON.stringify(raw)),rawRef=json(raw),capture={version:1,kind:'ci-smoke-inspect-capture',...shared,command:inspected.ref,rawSha256:rawRef.bytesHash,rawBytes:rawRef.bytesLength,redactedJson:rawRef,redactedFields:[],scanner,scan:{cloudCredentialMatches:0,privateKeyMatches:0,tokenMatches:0},complete:true};c.inspectCapture=json(capture);
  if(role==='database'&&inspectSecret){
   // The raw synthetic value exists only during capture. It is deliberately
   // absent from the returned archive, which retains hashes and redacted bytes.
   const synthetic='synthetic-only-not-a-real-password',original=structuredClone(raw);original[0].Config.Env[0]='POSTGRES_PASSWORD='+synthetic;const rawText=JSON.stringify(original),start=rawText.indexOf(synthetic);
   capture.rawSha256=sha(rawText);capture.rawBytes=Buffer.byteLength(rawText);capture.redactedFields=[{pointer:'/0/Config/Env/0',valueHash:sha(JSON.stringify(original[0].Config.Env[0]))}];c.inspectCapture=json(capture);
   Object.assign(inspected.logs.stdout,{rawSha256:capture.rawSha256,rawBytes:capture.rawBytes,redactions:[{start,end:start+synthetic.length,class:'synthetic-credential'}],scan:{...scans(),rawPasswordMatches:1}});
  }
  containers.push(c);rawInspects.set(role,{raw,capture});expected.environmentNames[role]=c.environmentNames.slice();expected.secretEnvironmentNames[role]=role==='database'&&inspectSecret?['POSTGRES_PASSWORD']:[];expected.executables[role]=[{path:'/synthetic/application',sha256:H(200+containers.length)}];
  if(connected&&supplementalHostConfig)command('inspect-container',cid,JSON.stringify(raw[0].HostConfig),'',0,5,['docker','inspect','--format={{json .HostConfig}}',cid]);
  let started=created;
  if(connected&&prestartInspect){
   started=command('start-container',cid,cid+'\n');c.startedMs=started.value.startedMs+2;
   const observed=command('inspect-container',cid,JSON.stringify({Running:true,Status:'running',StartedAt:new Date(c.startedMs).toISOString()}),'',0,5,['docker','inspect','--format','{{json .State}}',cid]);stateReads.set(role+'-running',observed.ref);
  }
  return {c,created,inspected,started};
 }
 function processCapture(c){
  const uid=c.role==='database'?999:1000,pid=17,startTimeTicks=1000+containers.indexOf(c),exe=expected.executables[c.role][0],rest=Array(20).fill('0');rest[18]=String(startTimeTicks);
  const status=`Pid:\t${pid}\nPPid:\t0\nUid:\t${uid} ${uid} ${uid} ${uid}\nGid:\t${uid} ${uid} ${uid} ${uid}\nCapEff:\t0000000000000000\nCapBnd:\t0000000000000000\nNoNewPrivs:\t1\n`,capture={status,stat:`${pid} (synthetic) S ${rest.join(' ')}`,exe:exe.path,executableSha256:exe.sha256};
  const cmd=command('inspect-processes',c.containerId,JSON.stringify(capture));c.processes.push({pid,ppid:0,startTimeTicks,executablePath:exe.path,executableSha256:exe.sha256,uid:Array(4).fill(uid),gid:Array(4).fill(uid),capEff:'0000000000000000',capBnd:'0000000000000000',noNewPrivs:1,containerId:c.containerId,observedMs:cmd.value.startedMs+2,statusCapture:cmd.value.stdout});return cmd;
 }
 for(const [role,name,key,suffix,error]of [
  ['busybox','busybox-wget','busybox-wget','busybox-wget',null],
  ['invalid-migration','reject-zero-migration-attempts','reject-migration','reject-migration','entrypoint: MNEMO_MIGRATION_MAX_ATTEMPTS must be an integer from 1 to 100'],
  ['invalid-timeout','reject-zero-connect-timeout','reject-timeout','reject-timeout','entrypoint: PGCONNECT_TIMEOUT must be an integer from 1 to 60']]){
  const {c}=container(role,base+(sequence+2)*100),action=command(key,c.containerId,error?'':'/usr/bin/wget\nwget\n',error?error+'\n':'',error?1:0,250);processCapture(c);
  const payload=error?{command:action.ref,containerId:c.containerId,variable:role==='invalid-migration'?'MNEMO_MIGRATION_MAX_ATTEMPTS':'PGCONNECT_TIMEOUT',value:role==='invalid-migration'?'00':'0',error}:{command:action.ref,containerId:c.containerId,wgetPath:'/usr/bin/wget',busyboxApplets:action.value.stdout};
  check(name,suffix,payload,action.value.startedMs,action.value.completedMs);
  if(role==='busybox'&&earlyCleanup){command('collect-logs',c.containerId);const removed=command('remove-owned',null,JSON.stringify({containerIds:[c.containerId],networkIds:[],volumeNames:[]}));earlyRemoves.push(removed.ref);earlyRemoved.add(c.containerId);}
 }
 const {c:server}=container('server');processCapture(server);
 const before=command('health-before',server.containerId,'','',1);check('unhealthy-before-migration','health-before',{command:before.ref,serverId:server.containerId,databaseStarted:false,healthCommand:CI_SMOKE_HEALTH_COMMAND},before.value.startedMs,before.value.completedMs);
 const retry=command('collect-logs',server.containerId,'','entrypoint: migration attempt 1/10 failed\n'+retryExtraLine);
 const {c:database,started:dbStart}=container('database');processCapture(database);
 const tls={containerId:database.containerId,keyPath:'/tls/server.key',certificatePath:'/tls/server.crt',keyUid:999,keyGid:999,keyMode:384,certificateSha256:H(500),generatedMs:database.startedMs+2,statCommand:undefined};
 const tlsStat=command('stat-tls',database.containerId,JSON.stringify({keyPath:tls.keyPath,certificatePath:tls.certificatePath,keyUid:999,keyGid:999,keyMode:384,certificateSha256:tls.certificateSha256}));tls.statCommand=tlsStat.ref;
 const net=command('inspect-network',null,JSON.stringify([{Id:networkId,Name:networkName,Driver:'bridge',Internal:true,Containers:{[server.containerId]:{},[database.containerId]:{}}}]));network.inspectCapture=net.value.stdout;network.observedMs=net.value.startedMs+2;
 const recoveryText='entrypoint: migration applied after 1 retries\n',recovery=command('collect-logs',server.containerId,recoveryText,'entrypoint: migration attempt 1/10 failed\n');
 const retryCheck=check('migration-retry','migration-retry',{serverId:server.containerId,log:retry.logs.stderr,lineStart:0,lineEnd:0,attempt:1,maxAttempts:10,databaseStartCommand:dbStart.ref},retry.value.startedMs,retry.value.completedMs,[hash(allChecks['unhealthy-before-migration'])]);
 const after=command('health-after',server.containerId);const afterCheck=check('healthy-after-migration','health-after',{command:after.ref,serverId:server.containerId,databaseId:database.containerId,retryCheckHash:hash(retryCheck),recoveryLog:recovery.logs.stdout,lineStart:0,lineEnd:0,retries:1},after.value.startedMs,after.value.completedMs,[hash(retryCheck)]);
 const tlsQuery=command('tls-query',database.containerId,JSON.stringify({backendPid:123,tlsEnabled:true}));check('tls-required','tls-required',{command:tlsQuery.ref,databaseId:database.containerId,sslmode:'require',tlsEnabled:true,backendPid:123,queryResult:tlsQuery.value.stdout},tlsQuery.value.startedMs,tlsQuery.value.completedMs,[hash(afterCheck)]);
 const plain=command('plaintext-query',database.containerId,'','FATAL: pg_hba.conf rejects connection for host "127.0.0.1", user "fixture", database "fixture", no encryption\n',2);check('plaintext-rejected','plaintext-rejected',{command:plain.ref,databaseId:database.containerId,sslmode:'disable',errorClass:'hostnossl-reject',diagnostic:plain.logs.stderr},plain.value.startedMs,plain.value.completedMs,[hash(afterCheck)]);
 const relations=['public.ingest_jobs','public.ingest_job_plans','public.sessions'],relationQuery=command('relations-query',database.containerId,JSON.stringify({relations,present:[true,true,true]}));check('atomic-ingest-relations','atomic-relations',{command:relationQuery.ref,databaseId:database.containerId,relations,present:[true,true,true],queryResult:relationQuery.value.stdout},relationQuery.value.startedMs,relationQuery.value.completedMs,[hash(afterCheck)]);
 const frame=JSON.stringify({_aws:{Timestamp:base,CloudWatchMetrics:[{Namespace:'mem9-on-aws/DurableIngest',Dimensions:[['stage']],Metrics:[{Name:'SamplerHeartbeat',Unit:'Count'}]}]},stage:'prod',SamplerHeartbeat:1})+'\n';
 const serverLogs=command('collect-logs',server.containerId,recoveryText+frame,'entrypoint: migration attempt 1/10 failed\n'),dbLogs=command('collect-logs',database.containerId,'database ready\n','');
 const serverStreams=latestLogScan?[serverLogs.logs.stdout,serverLogs.logs.stderr]:[retry.logs.stdout,retry.logs.stderr,recovery.logs.stdout,recovery.logs.stderr,serverLogs.logs.stdout,serverLogs.logs.stderr],databaseStreams=[dbLogs.logs.stdout,dbLogs.logs.stderr],streams=[...serverStreams,...databaseStreams],fingerprint=H(501),scanned=command('scan-logs',null,JSON.stringify({logHashes:streams.map(hash),syntheticCredentialFingerprint:fingerprint,rawMatches:0,encodedMatches:0,credentialPatternMatches:0}));
 check('password-absent-from-logs','password-log-scan',{serverLogs:serverStreams,databaseLogs:databaseStreams,scanner,scanCommand:scanned.ref,syntheticCredentialFingerprint:fingerprint,rawMatches:0,encodedMatches:0,credentialPatternMatches:0},scanned.value.startedMs,scanned.value.completedMs);
 const emf=command('validate-emf',null,'validated SamplerHeartbeat stage=prod framing=LF\n','',0,5,['node','scripts/validate-emf-event.mjs','--docker-stream']);check('non-tty-emf-framing','emf-framing',{command:emf.ref,serverId:server.containerId,stdout:serverLogs.logs.stdout,validator,frames:[{offset:Buffer.byteLength(recoveryText),length:Buffer.byteLength(frame),sha256:sha(frame)}]},emf.value.startedMs,emf.value.completedMs);
 let stoppedAt=base+sequence*100+2;
 const stop=command('stop-server',server.containerId,nativeStop?'Flag --time has been deprecated, use --timeout instead\n'+server.containerId+'\n':JSON.stringify({containerId:server.containerId,status:'exited',running:false,observedMs:stoppedAt}));
 if(nativeStop){const observed=command('inspect-container',server.containerId,JSON.stringify({Running:false,Status:'exited',StartedAt:new Date(server.startedMs).toISOString()}),'',0,5,['docker','inspect','--format','{{json .State}}',server.containerId]);stateReads.set('server-stopped',observed.ref);stoppedAt=observed.value.completedMs;}
 const {c:noServer}=container('no-server-health',base+(sequence+2)*100),negative=command('health-absent',noServer.containerId,'','',1,250);processCapture(noServer);command('collect-logs',noServer.containerId);
 const absence=check('unhealthy-without-server','health-absent',{stopCommand:stop.ref,negativeCommand:negative.ref,stoppedServerId:server.containerId,negativeContainerId:noServer.containerId,serverStoppedMs:stoppedAt,healthCommand:CI_SMOKE_HEALTH_COMMAND},stop.value.startedMs,negative.value.completedMs);
 const runtime={version:1,kind:'ci-smoke-runtime',...shared,containers,network,databaseTls:tls},runtimeEvidence=json(runtime);
 const isolation=check('nonroot-capabilities-nnp','isolation',{runtime:runtimeEvidence,observedContainerIds:containers.map(c=>c.containerId),processObservationHashes:containers.flatMap(c=>c.processes.map(hash)),networkObservationHash:hash(network)},base,negative.value.completedMs);
 const remove=command('remove-owned',null,JSON.stringify({containerIds:containers.map(c=>c.containerId).filter(id=>!earlyRemoved.has(id)),networkIds:[networkId],volumeNames:[]})),inventory=command('inventory-owned',null,JSON.stringify({containerIds:[],networkIds:[],volumeNames:[],temporaryEntries:[]})),completedMs=inventory.value.completedMs+1;
 check('owned-resource-cleanup','cleanup',{runtimeHash:hash(runtime),removeCommands:[...earlyRemoves,remove.ref],inventoryCommands:[inventory.ref],containerIds:containers.map(c=>c.containerId),networkIds:[networkId],volumeNames:[],remainingContainerIds:[],remainingNetworkIds:[],remainingVolumeNames:[],remainingTemporaryEntries:[],completedMs},remove.value.startedMs,completedMs,[hash(absence),hash(isolation)]);
 const checks=Object.fromEntries(CI_SMOKE_CHECKS.map(name=>[name,json(allChecks[name])])),evidence={startedMs:base,completedMs,checks,runtimeEvidence,logRef:json({version:1,kind:'ci-smoke-logs',...shared,captures:logRecords.map(json)}),cleanupRef:checks['owned-resource-cleanup']};
 const result=local?{version:1,kind:'local-nonroot-smoke-observation',...shared,images:expected.images,...evidence}:{version:1,kind:'ci-smoke-isolation-result',isolationHash,...identity,...evidence};
 const selectedExpected=local?Object.fromEntries(Object.entries(expected).filter(([key])=>!['identity','isolationHash','buildJob','smokeJob'].includes(key))):expected;
 const options=()=>({readJson:async ref=>objects.get(ref.bytesHash),readBytes:async ref=>objects.get(ref.sha256),expected:selectedExpected,now:base+20000});
 const rewriteCheck=(name,mutate)=>{const value=get(result.checks[name]);mutate(value);result.checks[name]=json(value);if(name==='owned-resource-cleanup')result.cleanupRef=result.checks[name];return value;};
 const rewriteRuntime=mutate=>{
  const value=get(result.runtimeEvidence);mutate(value);result.runtimeEvidence=json(value);
  const oldIsolation=result.checks['nonroot-capabilities-nnp'].canonicalHash;
  rewriteCheck('nonroot-capabilities-nnp',c=>{c.payload.runtime=result.runtimeEvidence;c.payload.observedContainerIds=value.containers.map(c=>c.containerId);c.payload.processObservationHashes=value.containers.flatMap(c=>c.processes.map(hash));c.payload.networkObservationHash=hash(value.network);});
  rewriteCheck('owned-resource-cleanup',c=>{c.payload.runtimeHash=hash(value);c.dependencies=c.dependencies.map(x=>x===oldIsolation?result.checks['nonroot-capabilities-nnp'].canonicalHash:x);});return value;
 };
 const rewriteInspect=(role,mutate)=>rewriteRuntime(runtime=>{
  const c=runtime.containers.find(c=>c.role===role),capture=get(c.inspectCapture),oldCommand=capture.command.canonicalHash,raw=get(capture.redactedJson);mutate(raw[0]);const rawRef=json(raw),cmd=get(capture.command);cmd.stdout={sha256:rawRef.bytesHash,bytesLength:rawRef.bytesLength};
  capture.command=json(cmd);capture.redactedJson=rawRef;capture.rawSha256=rawRef.bytesHash;capture.rawBytes=rawRef.bytesLength;c.inspectCapture=json(capture);
  const aggregate=get(result.logRef);aggregate.captures=aggregate.captures.map(ref=>{const l=get(ref);if(l.collectionCommand.canonicalHash!==oldCommand)return ref;l.collectionCommand=capture.command;l.redactedBytes=cmd[l.stream];if(l.stream==='stdout'){l.rawSha256=rawRef.bytesHash;l.rawBytes=rawRef.bytesLength;}return json(l);});result.logRef=json(aggregate);
 });
 // Extra state/config observations are referenced only by the log inventory.
 // Keep their raw output, command plan and both log streams consistent so
 // negative tests exercise semantic binding rather than a stale reference.
 const rewriteAuxiliaryCommand=(ref,mutate)=>{
  const value=get(ref);mutate(value);const next=json(value),index=catalog.findIndex(c=>c.sequence===value.sequence);
  catalog[index]={sequence:value.sequence,commandKey:value.commandKey,containerId:value.containerId,argv:structuredClone(value.argv)};
  const aggregate=get(result.logRef);aggregate.captures=aggregate.captures.map(logRef=>{
   const l=get(logRef);if(l.collectionCommand.canonicalHash!==ref.canonicalHash)return logRef;
   l.collectionCommand=next;l.containerId=value.containerId;l.startedMs=value.startedMs;l.completedMs=value.completedMs;
   l.redactedBytes=value[l.stream];l.rawSha256=l.redactedBytes.sha256;l.rawBytes=l.redactedBytes.bytesLength;return json(l);
  });result.logRef=json(aggregate);
  return next;
 };
 return {result,expected:selectedExpected,options,objects,bytes,json,get,records,commandsByKey,allChecks,runtime,logRecords,rawInspects,stateReads,rewriteCheck,rewriteRuntime,rewriteInspect,rewriteAuxiliaryCommand};
}
