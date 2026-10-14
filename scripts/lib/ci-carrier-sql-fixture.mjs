/** Owned local PostgreSQL/TLS fixture. No registry access, production database
 * configuration, ambient credentials, or authority-bearing result. */
import {randomBytes,createHash,X509Certificate} from 'node:crypto';
import {spawn} from 'node:child_process';
import {mkdtemp,realpath,lstat,rm,open,mkdir,readFile,writeFile,readdir} from 'node:fs/promises';
import {join,resolve,dirname} from 'node:path';
import {constants} from 'node:fs';
import {deflateRawSync} from 'node:zlib';
import {createServer,connect as connectTcp,isIPv4} from 'node:net';
import {setTimeout as delay} from 'node:timers/promises';
import pg from 'pg';
import {CARRIER_PROBE_SUPERVISOR_SOURCE} from './production-nonroot-carrier-probe-supervisor.mjs';
import {parseAcquisitionJson,zero,sha,need,hash} from './ci-smoke-acquisition-format.mjs';
import {CARRIER_SQL_DATABASE_ROOT,CARRIER_SQL_NOJIT_FIXTURE,CARRIER_SQL_CASES,deriveCarrierSqlTestManifest,verifyCarrierSqlTlsRejection} from './ci-carrier-sql-acceptance-format.mjs';
import {inspectCarrierOfflineBuild} from './production-nonroot-carrier-build.mjs';
import {controlImageGraphBinding} from './production-image-graph.mjs';
import {inspectImageFilesystemFile} from './production-image-filesystem.mjs';
import {controlSourcePaths,readControlSourceFile} from './production-control-source.mjs';
import {seedCarrierSqlState} from './ci-carrier-sql-state.mjs';
import {consumeCarrierSqlPackage} from './ci-carrier-sql-package.mjs';
import {CARRIER_SQL_FIXTURE_LIMITS,carrierSqlDockerOutputLimit,carrierSqlDockerCommandBudget,carrierSqlCaseSecurityBytes} from './ci-carrier-sql-runtime-budget.mjs';
export {CARRIER_SQL_FIXTURE_LIMITS,carrierSqlFixtureFixedRuntimeBudget,carrierSqlRuntimeFixedBudget,carrierSqlRuntimeBudget} from './ci-carrier-sql-runtime-budget.mjs';

// Public upstream dependency pin; use only the existing cache, never pull.
export const CARRIER_SQL_DATABASE_IMAGE='pgvector/pgvector@'+CARRIER_SQL_DATABASE_ROOT;
const states=new WeakMap(),MAX=CARRIER_SQL_FIXTURE_LIMITS;
const tmpfs={'/tmp':'rw,nosuid,nodev,size='+MAX.tmpDataBytes+',uid=999,gid=999,mode=700','/var/run/postgresql':'rw,nosuid,nodev,size='+MAX.tmpSocketBytes+',uid=999,gid=999,mode=700'};
const fixtureScript=jitOff=>[
 'umask 077',
 'openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=mem9-carrier-db-$FIXTURE_NONCE" -addext "subjectAltName=DNS:localhost,DNS:$FIXTURE_HOST,IP:127.0.0.1" -keyout /tmp/server.key -out /tmp/server.crt >/tmp/cert.log 2>&1',
 'initdb -D /tmp/pgdata -U postgres --auth-local=trust --auth-host=scram-sha-256 >/tmp/initdb.log',
 'printf "local all all trust\\nhostssl all postgres 0.0.0.0/0 trust\\nhostssl all all 0.0.0.0/0 scram-sha-256\\nhostnossl all all 0.0.0.0/0 reject\\n" > /tmp/pgdata/pg_hba.conf',
 'exec postgres -D /tmp/pgdata -c listen_addresses=* -c ssl=on -c ssl_cert_file=/tmp/server.crt -c ssl_key_file=/tmp/server.key -c log_statement=none -c log_connections=on -c log_hostname=off -c "log_line_prefix=mem9_fixture|%m|%c|%p|%r|" -c log_min_error_statement=panic -c log_parameter_max_length=0 -c log_parameter_max_length_on_error=0'+(jitOff?' -c jit=off':''),
].join('\n');
const held=()=>Object.assign(Error('CarrierSqlFixtureCleanup'),{code:'ECLEANUP',cleanupComplete:false});
const id=value=>typeof value==='string'&&/^[a-f0-9]{64}$/.test(value);
const parse=value=>parseAcquisitionJson(Buffer.from(value),MAX.maxDockerOutputBytes);

// Retain the reviewed child pidfd/subreaper/ECHILD loop. The only new grammar
// is one exact invocation selected by the private fixed fixture operations.
const first=CARRIER_PROBE_SUPERVISOR_SOURCE.indexOf('\ndef valid_args('),last=CARRIER_PROBE_SUPERVISOR_SOURCE.indexOf('\ndef main():');
need(first>0&&last>first,'CarrierSqlSupervisorSource');
const supervisor=(hash)=>[
 CARRIER_PROBE_SUPERVISOR_SOURCE.slice(0,first),
 '\ndef valid_args(args):\n    return isinstance(args, list) and hashlib.sha256(json.dumps(args, ensure_ascii=False, separators=(",", ":")).encode("utf-8")).hexdigest() == "'+hash+'"\n',
 CARRIER_PROBE_SUPERVISOR_SOURCE.slice(last),
].join('').replaceAll('carrier-native-probe-subreaper','carrier-sql-fixture-subreaper').replaceAll('mem9-prerequisites-','mem9-carrier-sql-').replace('TIMEOUT > 30000','TIMEOUT > 140000');

function runDocker(args,{directory,timeoutMs,signal,input}){
 const raw=Buffer.from(JSON.stringify(args)),source=supervisor(sha(raw)),outputLimit=carrierSqlDockerOutputLimit(args);
 need(Buffer.byteLength(source)<=MAX.maxSupervisorBytes&&raw.length<=MAX.maxDockerArgumentBytes&&Number.isSafeInteger(timeoutMs)&&timeoutMs>0&&timeoutMs<=140000&&(!input||args[0]==='cp'&&args[1]==='-'&&input instanceof Uint8Array&&input.length<=MAX.maxFixtureCaBytes+MAX.maxManifestBytes+3072),'CarrierSqlDockerInput');
 return new Promise((resolvePromise,reject)=>{
  let child,closed=false,inputDone=!input,done=false,cancelled=false,problem=false,status,sig,timer,total=0,ackBytes=0;const out=[],err=[],ack=[];
  const stop=()=>{problem=true;if(!cancelled&&child?.stdio[4]){cancelled=true;child.stdio[4].end('X');}};
  const finish=()=>{
   if(done||!closed||!inputDone)return;done=true;clearTimeout(timer);signal?.removeEventListener('abort',stop);child?.stdio[4]?.end();let proof;
   try{if(status===0&&!sig){const p=parseAcquisitionJson(Buffer.concat(ack),4096);
    need(p.version===1&&p.kind==='carrier-sql-fixture-subreaper-echild'&&p.supervisorPid===child.pid&&p.cleanupComplete===true&&p.leaderEnded===true&&Number.isSafeInteger(p.leaderPid)&&p.leaderPid>1&&Number.isSafeInteger(p.reaped)&&p.reaped>=1&&Number.isSafeInteger(p.killedDescendants)&&p.killedDescendants>=0&&p.killedDescendants<p.reaped&&p.reason===null&&p.signal===null&&Number.isInteger(p.status)&&p.status>=0&&p.status<=255,'CarrierSqlDockerTermination');proof=p;
   }}catch{problem=true;}
   if(problem||!proof)reject(held());else resolvePromise({status:proof.status,stdout:Buffer.concat(out).toString('utf8'),stderr:Buffer.concat(err).toString('utf8'),termination:proof,bytes:total});
  };
  const collect=into=>b=>{total+=b.length;if(total>outputLimit)stop();else into.push(Buffer.from(b));};
  try{
   signal?.throwIfAborted();
   child=spawn('/usr/bin/python3',['-I','-B','-c',source,String(process.pid),directory,raw.toString('base64'),sha(raw),String(timeoutMs)],{cwd:directory,env:{PATH:'/usr/bin:/bin',HOME:directory,DOCKER_CONFIG:directory,LANG:'C',LC_ALL:'C'},detached:true,stdio:[input?'pipe':'ignore','pipe','pipe','pipe','pipe']});
   if(input){child.stdin.on('error',()=>{inputDone=true;stop();finish();});child.stdin.end(input,()=>{inputDone=true;finish();});}
   child.stdout.on('data',collect(out));child.stderr.on('data',collect(err));child.stdio[3].on('data',b=>{ackBytes+=b.length;if(ackBytes>MAX.maxDockerProofBytes)stop();else ack.push(Buffer.from(b));});child.stdio[4].on('error',()=>{});
   child.on('error',stop);child.on('close',(code,signal)=>{closed=true;status=code;sig=signal;finish();});timer=setTimeout(stop,timeoutMs);signal?.addEventListener('abort',stop,{once:true});if(signal?.aborted)stop();
  }catch{closed=!child;inputDone=true;stop();finish();}
 });
}

export async function openCarrierSqlFixture({tempRoot,metadataReads,deadlineMs,signal,databasePackage}={}){
 need(process.platform==='linux'&&process.arch==='arm64','CarrierSqlNativeArm64');
 need(Number.isSafeInteger(deadlineMs)&&deadlineMs>Date.now()+MAX.cleanupMs&&typeof metadataReads?.reserveLocal==='function','CarrierSqlFixtureBudget');
 need(typeof tempRoot==='string'&&resolve(tempRoot)===tempRoot&&await realpath(tempRoot)===tempRoot,'CarrierSqlFixtureDirectory');
 const parent=await lstat(tempRoot);need(parent.isDirectory()&&parent.uid===process.getuid(),'CarrierSqlFixtureDirectory');
 const jitOff=Boolean(databasePackage&&metadataReads.admission.config.plan.template.sqlFixture.rootDigest===CARRIER_SQL_NOJIT_FIXTURE.rootDigest),script=fixtureScript(jitOff);let jitObservation;
 const nonce=randomBytes(16).toString('hex'),name='mem9-carrier-sql-'+nonce,hostAlias='mem9-on-aws-prod-fixture.cluster-'+nonce+'.ap-northeast-1.rds.amazonaws.com';
 const check=()=>{signal?.throwIfAborted();need(Date.now()<deadlineMs-MAX.cleanupMs,'CarrierSqlFixtureExpired');metadataReads.reserveLocal(zero());};check();
 // Reserve the exact four cleanup command ceilings first. Their execution
 // remains available after a normal local/relay allocation is exhausted.
 const cleanupPerCall=carrierSqlDockerCommandBudget();
 metadataReads.reserveLocal({...zero(),logicalBytes:MAX.fixtureCleanupCalls*cleanupPerCall,processedEntries:MAX.fixtureCleanupCalls});
 const directory=await mkdtemp(join(tempRoot,'mem9-carrier-sql-'));
 const materialDirectory=join(directory,'material');await mkdir(materialDirectory,{mode:0o700});
 let network,container,relay,root,certificate,address,closing,normalCalls=0,cleanupCalls=0,cleanupLimit=MAX.fixtureCleanupCalls,connections=0,relayBytes=0,normalProblem,uncertain=false;
 const caseContainers=new Set(),caseCleanupStarted=new Set();
 let databaseImage=CARRIER_SQL_DATABASE_IMAGE,databaseTag,tagged=false,loadAttempted=false;
 const sockets=new Set(),clients=new Set(),endings=new WeakMap(),journal=[];
 const end=client=>{if(endings.has(client))return endings.get(client);const p=client.end();endings.set(client,p);return p;};
 const docker=async(args,cleanup=false,input)=>{
  if(cleanup)need(++cleanupCalls<=cleanupLimit,'CarrierSqlCleanupBudget');else{check();need(++normalCalls<=MAX.maxDockerCalls,'CarrierSqlDockerBudget');metadataReads.reserveLocal({...zero(),logicalBytes:Buffer.byteLength(supervisor(sha(JSON.stringify(args))))+2*Buffer.byteLength(JSON.stringify(args))+carrierSqlDockerOutputLimit(args)+MAX.maxDockerProofBytes+2*(input?.length??0)});}
  const mutation=args[0]==='cp'||['create','start','rm','load','tag'].includes(args[1]);
  if(mutation){const bytes=Buffer.from(JSON.stringify({name,action:args.slice(0,2),requestHash:sha(JSON.stringify(args))}));need(bytes.length<=MAX.maxIntentBytes,'CarrierSqlIntentBytes');if(!cleanup)metadataReads.reserveLocal({...zero(),logicalBytes:bytes.length,processedEntries:1});const f=await open(join(directory,'intent-'+normalCalls+'-'+cleanupCalls+'.json'),'wx',0o600);try{await f.writeFile(bytes);await f.sync();}finally{await f.close();}}
  let result;try{result=await runDocker(args,{directory,timeoutMs:cleanup?5000:Math.min(args.includes('--attach')?140000:30000,deadlineMs-MAX.cleanupMs-Date.now()),signal:cleanup?undefined:signal,input});}catch(error){uncertain=true;throw error;}
  journal.push({action:args.slice(0,2).join('/'),requestHash:sha(JSON.stringify(args)),responseHash:sha(result.stdout+'\0'+result.stderr),bytes:result.bytes,outputLimit:carrierSqlDockerOutputLimit(args),status:result.status,termination:result.termination});return result;
 };
 const checked=async args=>{const result=await docker(args);need(result.status===0,'CarrierSqlDockerCommand');return result.stdout.trim();};
 const object=async args=>{const rows=parse(await checked(args));need(Array.isArray(rows)&&rows.length===1,'CarrierSqlDockerObject');return rows[0];};
 const cleanupCase=async caseId=>{
  need(caseContainers.has(caseId)&&!caseCleanupStarted.has(caseId),'CarrierSqlCaseCleanup');caseCleanupStarted.add(caseId);
  const removed=await docker(['container','rm','--force','--volumes',caseId],true),absent=await docker(['container','inspect',caseId],true);
  need(removed.status===0&&absent.status===1&&new RegExp('(?:No such container|No such object): '+caseId+'(?:\\s|$)').test(absent.stderr),'CarrierSqlCaseCleanup');caseContainers.delete(caseId);
  return {removed:true,absenceStatus:absent.status,absenceHash:sha(absent.stderr)};
 };
 const close=()=>closing??=(async()=>{
  if(loadAttempted&&!tagged)uncertain=true;
  const failures=[];for(const c of clients)c.connection?.stream?.destroy();
  let timer;try{const results=await Promise.race([Promise.allSettled([...clients].map(end)),new Promise((_,reject)=>{timer=setTimeout(()=>reject(held()),1000);})]);failures.push(...results.filter(r=>r.status==='rejected').map(r=>r.reason));}catch(e){failures.push(e);}finally{clearTimeout(timer);}
  for(const socket of sockets)socket.destroy();
  if(relay)try{await new Promise((ok,bad)=>relay.close(e=>e?bad(e):ok()));}catch(e){failures.push(e);}
  for(const caseId of caseContainers)try{if(!caseCleanupStarted.has(caseId))await cleanupCase(caseId);else throw held();}catch(e){failures.push(e);}
  if(container)try{const removed=await docker(['container','rm','--force','--volumes',container],true);need(removed.status===0,'CarrierSqlContainerCleanup');const absent=await docker(['container','inspect',container],true);need(absent.status===1&&new RegExp('(?:No such container|No such object): '+container+'(?:\\s|$)').test(absent.stderr),'CarrierSqlContainerCleanup');}catch(e){failures.push(e);}
  if(network)try{const removed=await docker(['network','rm',network],true);need(removed.status===0,'CarrierSqlNetworkCleanup');const absent=await docker(['network','inspect',network],true);need(absent.status===1&&absent.stderr.includes(network)&&/not found|No such network/.test(absent.stderr),'CarrierSqlNetworkCleanup');}catch(e){failures.push(e);}
  if(tagged&&!uncertain)try{const removed=await docker(['image','rm',databaseTag],true),absent=await docker(['image','inspect',databaseTag],true);need(removed.status===0&&absent.status===1&&absent.stderr.includes(databaseTag)&&/No such image|No such object/.test(absent.stderr),'CarrierSqlImageCleanup');}catch(e){failures.push(e);}
  if(uncertain)failures.push(held());
  if(failures.length)throw Object.assign(held(),{cause:new AggregateError(failures),operationDirectory:directory});
  await rm(directory,{recursive:true});
 })();
 try{
  let packageReceipt;
  if(databasePackage){
   const source=await consumeCarrierSqlPackage(databasePackage,{consumer:metadataReads});packageReceipt=source.receipt;databaseTag='mem9-carrier-pg-'+nonce+':fixture';
   metadataReads.reserveLocal({...zero(),logicalBytes:MAX.packageCleanupCalls*cleanupPerCall,processedEntries:MAX.packageCleanupCalls});cleanupLimit+=MAX.packageCleanupCalls;
   const absent=await docker(['image','inspect',databaseTag]);need(absent.status===1&&absent.stderr.includes(databaseTag)&&/No such image|No such object/.test(absent.stderr),'CarrierSqlImageCollision');
   // A cold daemon reads the archive and may materialize compressed content
   // plus the unpacked layers. Prepay that work even on a warm local test host.
   await source.check();metadataReads.reserveLocal({...zero(),logicalBytes:2*packageReceipt.archive.bytesLength+packageReceipt.uncompressedBytes,uncompressedBytes:packageReceipt.uncompressedBytes,processedEntries:metadataReads.admission.config.plan.template.sqlFixture.processedEntries});
   loadAttempted=true;const loaded=await docker(['image','load','--input',source.path]);need(loaded.status===0,'CarrierSqlImageLoad');await source.check();
   const actual=await object(['image','inspect',packageReceipt.rootDigest]);need(actual.Descriptor?.digest===packageReceipt.rootDigest&&[packageReceipt.rootDigest,packageReceipt.configDigest].includes(actual.Id)&&actual.Architecture==='arm64'&&actual.Os==='linux'&&hash(actual.RootFS?.Layers)===hash(source.diffIds),'CarrierSqlImportedImage');
   await checked(['image','tag',packageReceipt.rootDigest,databaseTag]);tagged=true;databaseImage=databaseTag;
  }
  const image=await object(['image','inspect',databaseImage]);
  need(image.Os==='linux'&&image.Architecture==='arm64'&&image.Descriptor?.digest===(packageReceipt?.rootDigest??CARRIER_SQL_DATABASE_ROOT)&&(packageReceipt?[packageReceipt.rootDigest,packageReceipt.configDigest].includes(image.Id):image.RepoDigests?.includes(CARRIER_SQL_DATABASE_IMAGE)),'CarrierSqlCachedImage');
  network=await checked(['network','create','--internal',name]);need(id(network),'CarrierSqlNetworkId');
  const networkInfo=await object(['network','inspect',network]);need(networkInfo.Id===network&&networkInfo.Name===name&&networkInfo.Internal===true&&networkInfo.Driver==='bridge'&&Object.keys(networkInfo.Containers??{}).length===0,'CarrierSqlNetwork');
  metadataReads.reserveLocal({...zero(),logicalBytes:MAX.tmpfsBytes,uncompressedBytes:MAX.tmpfsBytes,processedEntries:MAX.tmpfsEntries});
  container=await checked(['container','create','--pull=never','--name',name,'--network',network,'--network-alias',hostAlias,'--add-host',hostAlias+':127.0.0.1','--user','999:999','--read-only','--cap-drop=ALL','--security-opt','no-new-privileges:true','--pids-limit','128','--memory','512m','--cpus','1','--restart=no','--no-healthcheck','--tmpfs','/tmp:'+tmpfs['/tmp'],'--tmpfs','/var/run/postgresql:'+tmpfs['/var/run/postgresql'],'--mount','type=bind,src='+materialDirectory+',dst=/fixture-transfer','-e','FIXTURE_NONCE='+nonce,'-e','FIXTURE_HOST='+hostAlias,'--entrypoint','/bin/sh',databaseImage,'-ec',script]);need(id(container),'CarrierSqlContainerId');
  const inspect=async running=>{const v=await object(['container','inspect',container]),h=v.HostConfig,c=v.Config,n=v.NetworkSettings;
   need(v.Id===container&&v.Name==='/'+name&&c.Image===databaseImage&&c.User==='999:999'&&c.Entrypoint?.join()==='/bin/sh'&&JSON.stringify(c.Cmd)===JSON.stringify(['-ec',script]),'CarrierSqlContainerBinding');
   need(h.ReadonlyRootfs===true&&h.Privileged===false&&h.NetworkMode===network&&h.CapDrop?.join()==='ALL'&&!h.CapAdd?.length&&h.SecurityOpt?.length===1&&['no-new-privileges','no-new-privileges:true'].includes(h.SecurityOpt[0])&&h.PidsLimit===128&&h.Memory===536870912&&h.NanoCpus===1000000000&&!Object.keys(h.PortBindings??{}).length,'CarrierSqlContainerIsolation');
   need(hash(h.Tmpfs)===hash(tmpfs),'CarrierSqlTmpfsCapacity');
   const binds=v.Mounts.filter(m=>m.Type==='bind');need(!h.Binds?.length&&!h.Devices?.length&&!h.VolumesFrom?.length&&Object.keys(n.Networks??{}).length===1&&Object.keys(n.Ports??{}).every(k=>n.Ports[k]===null)&&binds.length===1&&binds[0].Source===materialDirectory&&binds[0].Destination==='/fixture-transfer'&&binds[0].RW===true,'CarrierSqlContainerIsolation');
   need(v.State.Running===running&&(!running||v.State.Pid>0),'CarrierSqlContainerState');
   return v;
  };
  await inspect(false);await checked(['container','start',container]);
  const readyDeadline=Math.min(deadlineMs-MAX.cleanupMs,Date.now()+MAX.maxSetupMs);let ready=false;
  for(let i=0;i<MAX.maxReadyAttempts;i++){check();need(Date.now()<readyDeadline,'CarrierSqlDatabaseReady');const result=await docker(['exec',container,'/usr/lib/postgresql/17/bin/pg_isready','-h','127.0.0.1','-U','postgres']);if(result.status===0){ready=true;break;}await inspect(true);await delay(MAX.readyPollMs,undefined,{signal});}
  need(ready,'CarrierSqlDatabaseReady');
  const fixtureCa=await checked(['exec',container,'cat','/tmp/server.crt']);need(Buffer.byteLength(fixtureCa)<=16384,'CarrierSqlFixtureCertificate');certificate=new X509Certificate(fixtureCa);
  need(certificate.subject==='CN=mem9-carrier-db-'+nonce&&certificate.checkIssued(certificate)&&certificate.verify(certificate.publicKey)&&certificate.checkHost(hostAlias)===hostAlias&&certificate.checkHost('localhost')==='localhost'&&certificate.checkIP('127.0.0.1')==='127.0.0.1','CarrierSqlFixtureCertificate');
  const v=await inspect(true),entry=Object.values(v.NetworkSettings.Networks)[0];address=entry.IPAddress;
  need(isIPv4(address)&&entry.NetworkID===network&&entry.Aliases?.includes(hostAlias),'CarrierSqlFixtureAddress');
  const relayFailure=e=>{normalProblem??=e;for(const socket of sockets)socket.destroy();};
  metadataReads.reserveLocal({...zero(),logicalBytes:MAX.maxRelayBytes+MAX.relayBufferBytes});
  relay=createServer(socket=>{
   let peer;try{check();need(!closing&&!normalProblem&&++connections<=MAX.maxConnections&&sockets.size<2*MAX.maxConcurrentConnections&&socket.remoteAddress==='127.0.0.1','CarrierSqlConnectionBudget');peer=connectTcp({host:address,port:5432});
    for(const s of [socket,peer]){sockets.add(s);s.once('close',()=>sockets.delete(s));s.on('error',()=>{socket.destroy();peer.destroy();});s.on('data',b=>{try{check();need((relayBytes+=b.length)<=MAX.maxRelayBytes,'CarrierSqlRelayBytes');}catch(e){relayFailure(e);}});}
    socket.pipe(peer).pipe(socket);
   }catch(e){socket.destroy();peer?.destroy();relayFailure(e);}
  });
  await new Promise((ok,bad)=>{relay.once('error',bad);relay.listen(0,'127.0.0.1',ok);});
  const connect=async(credential,database,options={})=>{
   check();need(!closing&&!normalProblem,'CarrierSqlFixtureClosed');need(Object.keys(options).every(k=>['signal','deadlineMs'].includes(k)),'CarrierSqlConnectionOptions');
   need(credential&&Object.keys(credential).every(k=>['username','password','salt'].includes(k))&&/^[a-z][a-z0-9_]{0,62}$/.test(credential.username)&&(['postgres','runtime_credentials_test'].includes(database)||/^prod_workers_[a-f0-9]{32}$/.test(database)),'CarrierSqlConnectionInput');
   const until=Math.min(deadlineMs-MAX.cleanupMs,options.deadlineMs??deadlineMs),abortSignal=options.signal??signal;need(until>Date.now()&&!abortSignal?.aborted,'CarrierSqlFixtureExpired');
   const client=new pg.Client({host:'127.0.0.1',port:relay.address().port,database,user:credential.username,password:credential.password,ssl:{ca:fixtureCa,rejectUnauthorized:true,servername:hostAlias},connectionTimeoutMillis:Math.min(5000,until-Date.now()),statement_timeout:MAX.maxQueryMs,query_timeout:Math.min(20000,until-Date.now())});
   client.on('error',()=>{});clients.add(client);const abort=()=>client.connection?.stream?.destroy(Error('CarrierSqlFixtureExpired'));abortSignal?.addEventListener('abort',abort,{once:true});const timer=setTimeout(abort,until-Date.now());timer.unref();
   client.once('end',()=>{clients.delete(client);clearTimeout(timer);abortSignal?.removeEventListener('abort',abort);});
   try{await client.connect();check();need(!abortSignal?.aborted&&client.connection.stream.encrypted&&client.connection.stream.authorized&&Buffer.from(client.connection.stream.getPeerCertificate().raw).equals(certificate.raw),'CarrierSqlFixtureTls');return client;}catch(e){await end(client);throw e;}
  };
  const setup=await connect({username:'postgres'},'postgres');await setup.query('CREATE DATABASE runtime_credentials_test');await end(setup);
  root=await connect({username:'postgres'},'runtime_credentials_test');
  if(jitOff){const observed=await root.query("SELECT setting,source FROM pg_settings WHERE name='jit'");need(observed.rows.length===1&&observed.rows[0].setting==='off'&&observed.rows[0].source==='command line','CarrierSqlJitSetting');jitObservation=Object.freeze({...observed.rows[0]});}
  const handle=Object.freeze({kind:'carrier-sql-fixture'});states.set(handle,{directory,materialDirectory,network,container,nonce,address,hostsPath:v.HostsPath,hostAlias,fixtureCa,packageReceipt,jitObservation,root,connect,close,docker,checked,object,cleanupCase,caseContainers,caseCleanupStarted,reserveCaseCleanup(){metadataReads.reserveLocal({...zero(),logicalBytes:MAX.caseCleanupCalls*cleanupPerCall,processedEntries:MAX.caseCleanupCalls});cleanupLimit+=MAX.caseCleanupCalls;},check:()=>{check();need(!closing&&!normalProblem,'CarrierSqlFixtureClosed');},clients,journal,image,deadlineMs,metadataReads,record:()=>({version:1,kind:'local-carrier-sql-fixture',imageDigest:image.Descriptor.digest,nonce,networkId:network,containerId:container,hostAlias,certificateHash:sha(certificate.raw),relayBytes,connections,journal:[...journal]})});return handle;
 }catch(error){try{await close();}catch(cleanup){throw new AggregateError([error,cleanup],'CarrierSqlFixtureCleanup');}throw error;}
}
export function inspectCarrierSqlFixture(handle){const s=states.get(handle);need(s,'CarrierSqlFixtureHandle');s.check();return Object.freeze({root:s.root,connect:s.connect,fixtureCa:s.fixtureCa,hostAlias:s.hostAlias,deadlineMs:s.deadlineMs,record:s.record()});}
/** Numeric/hash observations remain readable after cleanup; never a socket,
 * credential, executable handle, or authority to reopen a closed fixture. */
export function inspectCarrierSqlFixtureUsage(handle){const s=states.get(handle);need(s,'CarrierSqlFixtureHandle');return Object.freeze(s.record());}
export async function closeCarrierSqlFixture(handle){const s=states.get(handle);need(s,'CarrierSqlFixtureHandle');await s.close();}

function twoFileTar(rows){
 const blocks=[];for(const [name,bytes]of rows){const h=Buffer.alloc(512),oct=(v,at,n)=>h.write(v.toString(8).padStart(n-1,'0')+'\0',at,n);
  need(['ca.pem','manifest.json'].includes(name),'CarrierSqlTransferMember');h.write(name);oct(0o444,100,8);oct(0,108,8);oct(0,116,8);oct(bytes.length,124,12);oct(0,136,12);h.fill(32,148,156);h[156]=48;h.write('ustar\0',257);h.write('00',263);h.write([...h].reduce((n,v)=>n+v,0).toString(8).padStart(6,'0')+'\0 ',148);blocks.push(h,bytes,Buffer.alloc((512-bytes.length%512)%512));
 }return Buffer.concat([...blocks,Buffer.alloc(1024)]);
}
async function sourceFileProof(path,bytes,prior){
 const stat=await lstat(path,{bigint:true});if(!(stat.isFile()&&stat.uid===0n&&stat.gid===0n&&(stat.mode&511n)===292n&&stat.nlink===1n&&stat.size===BigInt(bytes.length)&&await realpath(path)===path))throw Object.assign(Error('CarrierSqlOverlayFile'),{observed:{uid:Number(stat.uid),gid:Number(stat.gid),mode:Number(stat.mode&511n),links:Number(stat.nlink),bytes:Number(stat.size),expectedBytes:bytes.length}});
 const proof={path,dev:String(stat.dev),ino:String(stat.ino),uid:0,gid:0,mode:0o444,nlink:1,size:bytes.length,mtimeNs:String(stat.mtimeNs),ctimeNs:String(stat.ctimeNs),sha256:sha(bytes)};
 if(prior)need(hash(prior)===hash(proof),'CarrierSqlOverlayChanged');
 const fd=await open(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);try{const read=await fd.readFile();need(read.equals(bytes),'CarrierSqlOverlayChanged');const after=await fd.stat({bigint:true});need(after.dev===stat.dev&&after.ino===stat.ino&&after.mtimeNs===stat.mtimeNs&&after.ctimeNs===stat.ctimeNs,'CarrierSqlOverlayChanged');}finally{await fd.close();}
 return proof;
}

/** Only genuine verified build bytes may acquire this test-only overlay. */
export async function prepareCarrierSqlAcceptanceFixture(handle,{built,sourceContext,oldSource}){
 const s=states.get(handle);need(s&&!s.preparing,'CarrierSqlFixtureHandle');s.check();s.preparing=true;
 const b=inspectCarrierOfflineBuild(built),{graphHash,...image}=controlImageGraphBinding(b.graph);
 need(sourceContext?.tree&&oldSource&&Object.keys(oldSource).sort().join()==='revision,tree'&&Object.values(oldSource).every(v=>/^[a-f0-9]{40}$/.test(v)),'CarrierSqlOriginalSource');
 const originalRow=b.derivedRecord?.files.find(f=>f.path==='rootfs/carrier/manifest.json');need(originalRow?.bytesBase64,'CarrierSqlOriginalManifest');
 const original=Buffer.from(originalRow.bytesBase64,'base64'),actual=inspectImageFilesystemFile(b.filesystem,'/carrier/manifest.json');need(sha(original)===actual.sha256&&original.length===actual.size&&original.length<=MAX.maxManifestBytes,'CarrierSqlOriginalManifest');
 const ca=Buffer.from(s.fixtureCa),test=deriveCarrierSqlTestManifest(original,ca),archive=twoFileTar([['ca.pem',ca],['manifest.json',test]]);
 need(ca.length<=MAX.maxFixtureCaBytes&&test.length<=MAX.maxManifestBytes,'CarrierSqlOverlayBytes');
 need((await readdir(s.materialDirectory)).length===0,'CarrierSqlOverlayDirectory');s.metadataReads.reserveLocal({...zero(),logicalBytes:original.length+3*(ca.length+test.length),processedEntries:2});
 const copied=await s.docker(['cp','-',s.container+':/fixture-transfer'],false,archive);need(copied.status===0,'CarrierSqlOverlayTransfer');
 const sources=[await sourceFileProof(join(s.materialDirectory,'ca.pem'),ca),await sourceFileProof(join(s.materialDirectory,'manifest.json'),test)];
 const schemaRoot=join(s.directory,'source','docker','bootstrap')+'/';
 const paths=controlSourcePaths(sourceContext).filter(p=>p.startsWith('docker/bootstrap/')&&(p.endsWith('.sql')||p==='docker/bootstrap/schema-digest.sh'));
 need(paths.length>0&&paths.length<=MAX.maxSchemaFiles,'CarrierSqlSchemaClosure');let schemaBytes=0;
 for(const path of paths){s.check();const row=await readControlSourceFile(sourceContext,path);schemaBytes+=row.bytes.length;need(schemaBytes<=MAX.maxSchemaBytes,'CarrierSqlSchemaBytes');s.metadataReads.reserveLocal({...zero(),logicalBytes:10*row.bytes.length,processedEntries:1});const target=join(s.directory,'source',path);await mkdir(dirname(target),{recursive:true,mode:0o700});await writeFile(target,row.bytes,{flag:'wx',mode:0o444});}
 const seederSource=await readControlSourceFile(sourceContext,'scripts/lib/ci-carrier-sql-state.mjs');
 need(seederSource.bytes.length<=MAX.maxSeederSourceBytes,'CarrierSqlSeederBytes');
 need(seederSource.bytes.equals(await readFile(new URL('./ci-carrier-sql-state.mjs',import.meta.url))),'CarrierSqlSeederSource');
 s.metadataReads.reserveLocal({...zero(),logicalBytes:2*seederSource.bytes.length});
 const seed=await seedCarrierSqlState({root:s.root,connect:s.connect,fixtureCa:s.fixtureCa,schemaRoot,hostAlias:s.hostAlias,deadlineMs:s.deadlineMs-MAX.cleanupMs});
 need(seed.parent.verification.changedRows===10&&seed.parent.verification.receipts===5,'CarrierSqlSeederRoot');
 s.acceptance={built,b,sourceContext,oldSource,image,original,test,ca,sources,seed,seederSourceHash:seederSource.file.sha256,cursor:0,failed:false};
 return Object.freeze({image,original:Buffer.from(original),test:Buffer.from(test),ca:Buffer.from(ca),fixture:{...(s.jitObservation?{jit:s.jitObservation}:{}),...(s.packageReceipt?{package:s.packageReceipt}:{}),imageDigest:s.image.Descriptor.digest,containerId:s.container,networkId:s.network,hostAlias:s.hostAlias,certificateHash:sha(new X509Certificate(ca).raw),seederSourceHash:seederSource.file.sha256,rootIdentity:seed.rootIdentity}});
}

export async function executeCarrierSqlCase(handle,name){
 const s=states.get(handle),a=s?.acceptance;need(a&&!a.failed&&name===CARRIER_SQL_CASES[a.cursor],'CarrierSqlCaseOrder');s.check();const ordinal=a.cursor++,startedMs=Date.now(),tls=name==='untrusted-fixture-ca';let containerId,cleanup;
 const b=inspectCarrierOfflineBuild(a.built);need(b.record.rootDigest===a.image.rootDigest,'CarrierSqlImageChanged');
 const input={invocation:randomBytes(16).toString('hex'),owner:s.nonce,runtimeNonce:a.seed.nonce,rootBinding:{parentProofHash:hash(a.seed.parent.verification),validationId:a.seed.parent.verification.validationId,generation:a.seed.rootConfig.generation,spent:10,cap:20},rootConfig:a.seed.rootConfig,certificate:a.seed.certificate,parent:{verification:a.seed.parent.verification},dependencyHash:b.runtimeManifest.dependencyHash,deployed:{revision:a.oldSource.revision,sourceTree:a.oldSource.tree}};
 const inputBytes=Buffer.from(JSON.stringify(input));need(inputBytes.length<=MAX.maxCaseInputBytes,'CarrierSqlCaseInput');
 const credential=name==='wrong-database-role'?a.seed.runtime:a.seed.administrator;
 const env={MEM9_SUPERSESSION_ROOT_INPUT:deflateRawSync(inputBytes).toString('base64'),MEM9_SUPERSESSION_ROOT_HASH:sha(inputBytes),MEM9_SUPERSESSION_ROOT_CODE_HASH:b.runtimeManifest.legacyCodeHash,MEM9_DB_HOST:s.hostAlias,MEM9_DB_PORT:'5432',MEM9_DB_NAME:a.seed.rootConfig.database,MEM9_DB_SECRET:JSON.stringify(credential)};
 if(name==='changed-input-hash')env.MEM9_SUPERSESSION_ROOT_HASH='0'.repeat(64);if(name==='wrong-encoding')env.MEM9_SUPERSESSION_ROOT_INPUT='not-base64';
 const envBytes=Buffer.from(Object.entries(env).map(([k,v])=>k+'='+v+'\n').join('')),envPath=join(s.directory,'case-'+ordinal+'.env');need(envBytes.length<=MAX.maxCaseEnvironmentBytes,'CarrierSqlCaseEnvironment');
 const security=carrierSqlCaseSecurityBytes({runtimeFilesBytes:b.runtimeManifest.files.reduce((n,f)=>n+f.bytes,0),originalSourceBytes:b.runtimeManifest.files.filter(f=>f.path.startsWith('/bootstrap/operator/')&&!f.path.startsWith('/bootstrap/operator/node_modules/')&&/\.(?:mjs|js)$/.test(f.path)).reduce((n,f)=>n+f.bytes,0),nodeBytes:inspectImageFilesystemFile(b.filesystem,'/usr/local/bin/node').size,setprivBytes:inspectImageFilesystemFile(b.filesystem,'/bin/setpriv').size});
 s.metadataReads.reserveLocal({...zero(),logicalBytes:envBytes.length+2*inputBytes.length+security+(tls?a.original:a.test).length+MAX.maxCaseProcessEvidenceBytes+MAX.maxDockerOutputBytes,processedEntries:1});
 await writeFile(envPath,envBytes,{mode:0o600,flag:'wx'});s.reserveCaseCleanup();
 if(name==='changed-root-counters')await a.seed.wrongCounter();
 const mounts=[];
 if(!tls)for(const [i,path]of ['/bootstrap/global-bundle.pem','/carrier/manifest.json'].entries()){const bytes=i===0?a.ca:a.test;s.metadataReads.reserveLocal({...zero(),logicalBytes:2*bytes.length});const source=await sourceFileProof(a.sources[i].path,bytes,a.sources[i]);mounts.push({destination:path,readOnly:true,source});}
 // Share only the owned fixture's isolated network namespace. PID, mount and
 // user namespaces remain independent; its fixed hosts entry selects loopback.
 const args=['container','create','--pull=never','--platform=linux/arm64','--name','mem9-carrier-case-'+s.nonce+'-'+ordinal,'--network','container:'+s.container,'--read-only','--user',name==='root-uid'?'0:0':'1000:1000','--cap-drop=ALL','--pids-limit','32','--memory','256m','--cpus','1','--restart=no','--no-healthcheck','--env-file',envPath];
 if(name!=='missing-nnp')args.push('--security-opt','no-new-privileges:true');else args.push('--entrypoint','/usr/local/bin/node');
 for(const m of mounts)args.push('--mount','type=bind,src='+m.source.path+',dst='+m.destination+',readonly');
 args.push(a.image.rootDigest);if(name==='missing-nnp')args.push('/carrier/guard-first.mjs','audit-original-root');
 let beforeLogs;
 try{
  if(tls)beforeLogs=await s.docker(['container','logs',s.container]);
  containerId=await s.checked(args);need(id(containerId),'CarrierSqlCaseId');s.caseContainers.add(containerId);
  const inspect=async exited=>{const v=await s.object(['container','inspect',containerId]),h=v.HostConfig,c=v.Config;
   need(v.Id===containerId&&c.Image===a.image.rootDigest&&c.User===(name==='root-uid'?'0:0':'1000:1000')&&[a.image.rootDigest,a.image.arm64Digest,a.image.configDigest].includes(v.Image),'CarrierSqlCaseImage');
   need(h.NetworkMode==='container:'+s.container&&h.ReadonlyRootfs===true&&!h.Privileged&&h.CapDrop?.join()==='ALL'&&!h.CapAdd?.length&&h.PidsLimit===32&&h.Memory===268435456&&h.NanoCpus===1000000000&&!Object.keys(h.PortBindings??{}).length&&!h.Binds?.length&&!h.VolumesFrom?.length&&!h.Devices?.length&&h.PidMode!=='host'&&h.IpcMode!=='host','CarrierSqlCaseIsolation');
   need(!h.ExtraHosts?.length&&(!exited||v.HostsPath===s.hostsPath),'CarrierSqlCaseNetwork');
   need(name==='missing-nnp'?!h.SecurityOpt?.length:h.SecurityOpt?.length===1&&['no-new-privileges','no-new-privileges:true'].includes(h.SecurityOpt[0]),'CarrierSqlCaseNnp');
   need(JSON.stringify(c.Entrypoint)===JSON.stringify(name==='missing-nnp'?['/usr/local/bin/node']:['/bin/setpriv','--no-new-privs','--','/usr/local/bin/node','/carrier/guard-first.mjs','audit-original-root'])&&JSON.stringify(c.Cmd??[])===JSON.stringify(name==='missing-nnp'?['/carrier/guard-first.mjs','audit-original-root']:[]),'CarrierSqlCaseCommand');
   need(v.Mounts.length===mounts.length&&mounts.every(m=>v.Mounts.some(x=>x.Type==='bind'&&x.Source===m.source.path&&x.Destination===m.destination&&x.RW===false)),'CarrierSqlCaseMounts');
   const actualEnv=Object.fromEntries(c.Env.map(e=>{const at=e.indexOf('=');return [e.slice(0,at),e.slice(at+1)];}));need(Object.entries(env).every(([k,value])=>actualEnv[k]===value),'CarrierSqlCaseEnvironment');
   need(v.State.Running===false&&v.State.Status===(exited?'exited':'created')&&(!exited||v.State.Pid===0&&!v.State.OOMKilled),'CarrierSqlCaseState');return v;
  };
  await inspect(false);const output=await s.docker(['container','start','--attach',containerId]),after=await inspect(true),networkAddress='127.0.0.1';
  const exitCode=after.State.ExitCode;if(!(output.status===exitCode&&(ordinal===0?exitCode===0:exitCode===1))){let rejection;try{const r=JSON.parse(output.stderr.trim());if(r.event==='carrier_guard_rejected')rejection={event:r.event,stage:r.stage,code:r.code};}catch{}throw Object.assign(Error('CarrierSqlCaseExit'),{observed:{case:name,exitCode,commandStatus:output.status,rejection,stdoutHash:sha(output.stdout),stderrHash:sha(output.stderr)}});}
  let tlsFailure,tlsLog;
  if(tls){const afterLogs=await s.docker(['container','logs',s.container]);need(beforeLogs.status===0&&afterLogs.status===0&&afterLogs.stdout===beforeLogs.stdout&&afterLogs.stderr.startsWith(beforeLogs.stderr),'CarrierSqlTlsLogScope');tlsLog=Buffer.from(afterLogs.stderr.slice(beforeLogs.stderr.length));tlsFailure={...verifyCarrierSqlTlsRejection(tlsLog.toString(),undefined,parseAcquisitionJson(Buffer.from(output.stderr.trim()),1048576)),fixtureContainerId:s.container};need(tlsFailure.peer.startsWith(networkAddress+'('),'CarrierSqlTlsPeer');}
  for(const [i,m]of mounts.entries())await sourceFileProof(m.source.path,i===0?a.ca:a.test,m.source);
  cleanup=await s.cleanupCase(containerId);
  const row={name,image:a.image,containerId,networkAddress,startedMs,completedMs:Date.now(),manifestHash:sha(tls?a.original:a.test),mounts,exitCode,state:Object.fromEntries(['Running','Pid','ExitCode','OOMKilled','Status'].map(k=>[k,after.State[k]])),commandHash:hash({args,envHash:sha(envBytes)}),cleanup,...(tls?{tlsFailure}:{})};
  return {row,inputBytes,stdout:Buffer.from(output.stdout),stderr:Buffer.from(output.stderr),...(tls?{tlsLog}:{})};
 }catch(error){a.failed=true;throw error;}
 finally{if(containerId&&!s.caseCleanupStarted.has(containerId))await s.cleanupCase(containerId);if(!containerId||!s.caseContainers.has(containerId))await rm(envPath,{force:true});}
}

export async function closeCarrierSqlAcceptanceFixture(handle){const s=states.get(handle);need(s?.acceptance,'CarrierSqlFixtureHandle');await s.acceptance.seed.close();}
