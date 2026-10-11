/** Host-only collector. The opaque result is created only after actual local
 * Docker observations and positively verified container/process cleanup. */
import {spawn} from 'node:child_process';
import {readFileSync} from 'node:fs';
import {mkdtemp,rm,lstat} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,posix} from 'node:path';
import {randomBytes,createHash} from 'node:crypto';
import {copyNonrootJson,parseNonrootJson,nonrootHash as hash} from './production-nonroot-contracts.mjs';
import {NONROOT_FORBIDDEN_ENVIRONMENT} from './production-nonroot-launch.mjs';
import {controlImageGraphBinding,imageGraphState,readImageJson} from './production-image-graph.mjs';
import {inspectImageFilesystemEntries} from './production-image-filesystem.mjs';
import {verifyNonrootControlArtifactFiles} from './production-nonroot-artifact.mjs';

const observations=new WeakMap(),sha=bytes=>createHash('sha256').update(bytes).digest('hex');
let probeSource;
function runtimeProbe(){
 if(!probeSource){
  const probe=readFileSync(new URL('./production-nonroot-path-probe.mjs',import.meta.url));
  probeSource={probe,probeCodeHash:sha(probe)};
 }
 return probeSource;
}
const need=(ok,code='NonrootRuntimeObservationInvalid')=>{if(!ok)throw Object.assign(Error(code),{code,hold:true});};
const same=(a,b,code)=>need(hash(a)===hash(b),code);
const exact=(value,keys)=>need(value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join()===keys.slice().sort().join());
const cleanError=(code,id)=>Object.assign(Error(code),{code,hold:true,cleanupConfirmed:false,...(id?{containerId:id}:{})});
const capNames=['CapInh','CapPrm','CapEff','CapBnd','CapAmb'];
const canonical=path=>typeof path==='string'&&path.length<=4096&&/^\/[A-Za-z0-9_./+-]*$/.test(path)&&posix.normalize(path)===path&&(path==='/'||!path.endsWith('/'));

// A successful CLI close is insufficient if descendants retained the group.
function command(args,{directory,timeoutMs,signal}){
 return new Promise((resolve,reject)=>{
  const child=spawn('/usr/bin/docker',['--host','unix:///var/run/docker.sock','--config',directory,...args],{cwd:directory,env:{PATH:'/usr/bin:/bin',HOME:directory,DOCKER_CONFIG:directory,LANG:'C',LC_ALL:'C'},detached:true,stdio:['ignore','pipe','pipe']});
  const out=[],err=[];let bytes=0,closed=false,finished=false,status,problem,timer,drainTimer,killTimer;
  const exists=()=>{if(!child.pid)return false;try{process.kill(-child.pid,0);return true;}catch(error){if(error.code==='ESRCH')return false;throw error;}};
  const kill=()=>{try{if(child.pid)process.kill(-child.pid,'SIGKILL');}catch(error){if(error.code!=='ESRCH')problem=cleanError('ECLEANUP');}};
  const finish=()=>{if(finished)return;finished=true;clearTimeout(timer);clearTimeout(drainTimer);clearTimeout(killTimer);signal?.removeEventListener('abort',abort);if(problem)reject(problem);else resolve({status,stdout:Buffer.concat(out).toString('utf8'),stderr:Buffer.concat(err).toString('utf8')});};
  const drain=until=>{let alive;try{alive=exists();}catch{alive=true;}if(closed&&!alive)return finish();if(Date.now()>=until){problem=cleanError('ECLEANUP');return finish();}drainTimer=setTimeout(()=>drain(until),10);};
  const stop=code=>{problem??=cleanError(code);kill();if(!killTimer)killTimer=setTimeout(()=>drain(Date.now()+1000),10);};
  const abort=()=>stop('NonrootRuntimeObservationAborted');
  const collect=chunks=>chunk=>{bytes+=chunk.length;if(bytes>1048576)stop('NonrootRuntimeObservationOutputLimit');else chunks.push(chunk);};
  child.stdout.on('data',collect(out));child.stderr.on('data',collect(err));
  child.on('error',()=>{closed=true;problem??=cleanError('NonrootRuntimeDockerUnavailable');if(child.pid)stop('ECLEANUP');else finish();});
  child.on('close',code=>{closed=true;status=code;try{if(exists()){problem??=cleanError('NonrootRuntimeDockerDescendant');kill();drain(Date.now()+1000);}else finish();}catch{problem=cleanError('ECLEANUP');finish();}});
  timer=setTimeout(()=>stop('NonrootRuntimeObservationTimeout'),timeoutMs);signal?.addEventListener('abort',abort,{once:true});if(signal?.aborted)abort();
 });
}

function realPath(nodes,path){
 let parts=path.slice(1).split('/').filter(Boolean),prefix=[],hops=0;
 while(parts.length){prefix.push(parts.shift());const name=prefix.join('/'),node=nodes.get(name);if(node?.type==='symlink'){need(++hops<=16,'NonrootRuntimePathLink');const target=posix.resolve('/',posix.dirname(name),node.link);parts=[...target.slice(1).split('/').filter(Boolean),...parts];prefix=[];}}
 return '/'+prefix.join('/');
}
function pathPlan(facts,filesystem){
 const nodes=new Map(inspectImageFilesystemEntries(filesystem).map(({path,...node})=>[path,node])),paths=new Set(['/']);
 const add=path=>{need(canonical(path),'NonrootRuntimePathScope');paths.add(path);while(path!=='/'){path=posix.dirname(path);paths.add(path);}};
 for(const f of facts.files){add(f.path);add(f.resolvedPath);for(const row of [...f.parents,...f.symlinkChain])add(row.path);}
 for(const path of [...paths])add(realPath(nodes,path));
 need(paths.size<=512,'NonrootRuntimePathLimit');
 const expected=[...paths].sort().map(path=>{const resolvedPath=realPath(nodes,path),node=nodes.get(path.slice(1))??nodes.get(resolvedPath.slice(1));need(path==='/'||node,'NonrootRuntimePathMissing');return {path,resolvedPath,node};});
 need(Buffer.byteLength(JSON.stringify(expected.map(row=>row.path)))<=65536,'NonrootRuntimePathLimit');
 return {paths:expected.map(row=>row.path),expected,nodes};
}
async function preflight(value,options){
 const facts=await verifyNonrootControlArtifactFiles(value,options),graph=options.controlVerification.graph,filesystem=options.controlVerification.filesystem,state=imageGraphState(graph),binding=controlImageGraphBinding(graph);
 const descriptor=state.images.get('bootstrap').config,config=await readImageJson(state.store.open(descriptor),{maxBytes:8388608,budget:state.budget});
 need(config.architecture==='arm64'&&config.os==='linux'&&descriptor.digest===binding.configDigest,'NonrootRuntimeConfigBinding');
 const env=config.config?.Env??[];need(Array.isArray(env)&&env.length<=32,'NonrootRuntimeImageEnvironment');const seen=new Set();
 for(const row of env){need(typeof row==='string'&&row.length<=4096&&row.includes('='),'NonrootRuntimeImageEnvironment');const at=row.indexOf('='),name=row.slice(0,at),v=row.slice(at+1);need(!seen.has(name)&&!name.startsWith('LD_')&&!NONROOT_FORBIDDEN_ENVIRONMENT.includes(name),'NonrootRuntimeImageEnvironment');seen.add(name);
  need(['PATH','NODE_VERSION','YARN_VERSION','NODE_EXTRA_CA_CERTS'].includes(name),'NonrootRuntimeImageEnvironment');
  if(name==='PATH')need(v.split(':').every(canonical),'NonrootRuntimeImageEnvironment');
  else if(name==='NODE_EXTRA_CA_CERTS')need(['/bootstrap/global-bundle.pem','/app/global-bundle.pem'].includes(v)&&facts.files.some(f=>f.path===v),'NonrootRuntimeCaBinding');
  else need(/^\d+\.\d+\.\d+$/.test(v),'NonrootRuntimeImageEnvironment');
 }
 need(!Object.keys(config.config?.Volumes??{}).length,'NonrootRuntimeImageVolumes');
 const plan=pathPlan(facts,filesystem);need(!plan.nodes.has(realPath(plan.nodes,'/etc/ld.so.preload').slice(1)),'NonrootRuntimeLoaderPreload');
 need(value.guardImports.nodeRuntime.executablePath==='/usr/local/bin/node'&&facts.files.some(f=>f.path==='/bin/setpriv'),'NonrootRuntimeExecutableScope');
 return {facts,graph,filesystem,binding,config,...plan};
}
function checkImage(raw,p,platform=false){
 need(Array.isArray(raw)&&raw.length===1,'NonrootRuntimeDockerImage');const image=raw[0],wanted=platform?p.binding.arm64Digest:p.binding.rootDigest;
 need(image.Os==='linux'&&image.Architecture==='arm64','NonrootRuntimeDockerImage');
 if(image.Descriptor)need(image.Descriptor.digest===wanted&&image.Id===wanted,'NonrootRuntimeDockerImage');
 else need(image.Id===p.binding.configDigest&&Array.isArray(image.RepoDigests)&&image.RepoDigests.some(r=>r.endsWith('@'+p.binding.rootDigest)),'NonrootRuntimeDockerImage');
 same(image.Config,p.config.config,'NonrootRuntimeDockerConfig');same(image.RootFS,{Type:'layers',Layers:p.config.rootfs.diff_ids},'NonrootRuntimeDockerConfig');
 return image;
}
function checkContainer(raw,p,{id,name,args,label},exited){
 need(Array.isArray(raw)&&raw.length===1,'NonrootRuntimeContainer');const c=raw[0],h=c.HostConfig,config=c.Config;
 need(c.Id===id&&c.Name==='/'+name&&config.Image===p.binding.rootDigest&&config.User==='1000:1000','NonrootRuntimeContainerIdentity');
 need(c.Image===p.binding.configDigest||c.Image===p.binding.rootDigest||c.Image===p.binding.arm64Digest,'NonrootRuntimeContainerIdentity');
 if(c.ImageManifestDescriptor)need(c.ImageManifestDescriptor.digest===p.binding.arm64Digest,'NonrootRuntimeContainerIdentity');else need(c.Image===p.binding.configDigest,'NonrootRuntimeContainerIdentity');
 same(config.Entrypoint,['/bin/setpriv']);same(config.Cmd,args);same(config.Env,p.config.config?.Env??[]);need(config.Labels?.['mem9-artifact-probe']===label,'NonrootRuntimeContainerIdentity');
 need(h.NetworkMode==='none'&&h.ReadonlyRootfs===true&&h.Privileged===false&&h.PublishAllPorts===false&&h.PidMode!== 'host'&&h.IpcMode!=='host'&&h.UTSMode!=='host'&&!h.UsernsMode,'NonrootRuntimeContainerIsolation');
 same(h.CapDrop,['ALL']);need(!h.CapAdd?.length&&h.SecurityOpt?.length===1&&['no-new-privileges','no-new-privileges:true'].includes(h.SecurityOpt[0]),'NonrootRuntimeContainerIsolation');
 need(h.PidsLimit===32&&h.Memory===268435456&&h.NanoCpus===1000000000&&h.RestartPolicy?.Name==='no'&&config.Healthcheck?.Test?.[0]==='NONE','NonrootRuntimeContainerIsolation');
 for(const field of ['Binds','Devices','DeviceRequests','VolumesFrom'])need(!h[field]?.length,'NonrootRuntimeContainerMounts');need(!Object.keys(h.Tmpfs??{}).length&&!c.Mounts?.length,'NonrootRuntimeContainerMounts');
 if(exited)need(c.State?.Running===false&&c.State.Status==='exited'&&c.State.Pid===0&&c.State.ExitCode===0&&c.State.OOMKilled===false&&!c.State.Error,'NonrootRuntimeProbeExit');
 else need(c.State?.Running===false&&c.State.Status==='created','NonrootRuntimeContainerState');
 return c;
}
function validateProbe(raw,p){
 const result=parseNonrootJson(raw,{maxBytes:262144});exact(result,['version','kind','identity','observations']);need(result.version===1&&result.kind==='control-runtime-path-observation');
 const identity=result.identity;exact(identity,['uid','gid','groups',...capNames,'noNewPrivs']);need(identity.uid.length===4&&identity.gid.length===4&&[...identity.uid,...identity.gid].every(n=>n===1000)&&identity.groups.every(n=>n===1000)&&identity.noNewPrivs===1&&capNames.every(k=>identity[k]==='0000000000000000'),'NonrootRuntimeIdentity');
 need(result.observations.length===p.expected.length,'NonrootRuntimePathCoverage');
 for(const [i,row]of result.observations.entries()){
  exact(row,['path','resolvedPath','type','uid','gid','mode']);const expected=p.expected[i];need(row.path===expected.path&&row.resolvedPath===expected.resolvedPath,'NonrootRuntimePathBinding');
  need(Number.isSafeInteger(row.mode)&&row.mode>=0&&row.mode<=4095&&row.uid===0&&row.gid===0&&(row.mode&0o6000)===0,'NonrootRuntimePathPrivilege');
  if(row.type!=='symlink')need((row.mode&0o022)===0,'NonrootRuntimePathWritable');
  if(expected.node&&!expected.node.implicit){const node=expected.node;need(row.type===node.type,'NonrootRuntimePathType');for(const key of ['mode','uid','gid'])need(row[key]===(node.pax?.[key]===undefined?node[key]:Number(node.pax[key])),'NonrootRuntimePathMetadata');}
  else need(row.type==='directory','NonrootRuntimePathType');
  if(row.type==='directory')need((row.mode&0o001)!==0,'NonrootRuntimePathUnsearchable');
 }
 return result;
}

/** Revalidates captured bytes against live graph/FS facts. This parser returns
 * plain data and cannot create the collector's opaque observation handle. */
export async function inspectNonrootControlRuntimeProbe(raw,value,options){
 return copyNonrootJson(validateProbe(raw,await preflight(value,options)));
}

export async function collectNonrootControlRuntime(value,options){
 value=copyNonrootJson(value);
 const p=await preflight(value,options),startedMs=Date.now(),deadline=startedMs+120000,name='mem9-artifact-probe-'+randomBytes(16).toString('hex'),label=name.slice('mem9-artifact-probe-'.length);
 // Infrastructure bundles import proof validators but do not run this host
 // collector. Resolve its fixed sidecar only for an actual Docker observation.
 const {probe,probeCodeHash}=runtimeProbe();
 need((await lstat('/var/run/docker.sock')).isSocket(),'NonrootRuntimeLocalDockerRequired');
 const directory=await mkdtemp(join(tmpdir(),'mem9-artifact-docker-'));let id,createAttempted=false,created=false,cleanupConfirmed=false,sticky=false,primary,record,removal;
 const run=async(stage,args,{cleanup=false}={})=>{
  // This code-only fault/observation hook cannot supply output or evidence.
  if(options.beforeDocker!==undefined){need(typeof options.beforeDocker==='function','NonrootRuntimeCodeHook');await options.beforeDocker(Object.freeze({stage,containerId:id,args:Object.freeze([...args])}));}
  if(!cleanup){controlImageGraphBinding(p.graph);need(Date.now()<deadline&&!options.signal?.aborted,'NonrootRuntimeObservationExpired');}
  if(stage==='create')createAttempted=true;
  try{return await command(args,{directory,timeoutMs:cleanup?10000:Math.min(30000,deadline-Date.now()),signal:cleanup?undefined:options.signal});}catch(error){if(error.code==='ECLEANUP')sticky=true;throw error;}
 };
 const checked=async(stage,args,extra)=>{const r=await run(stage,args,extra);need(r.status===0,'NonrootRuntimeDockerCommand');return r;};
 const inspect=async(stage,args)=>parseNonrootJson((await checked(stage,args)).stdout,{maxBytes:1048576});
 try{
  const root=checkImage(await inspect('inspect-root',['image','inspect',p.binding.rootDigest]),p);
  const platform=checkImage(await inspect('inspect-platform',['image','inspect','--platform','linux/arm64',p.binding.rootDigest]),p,true);
  const args=['--no-new-privs','--','/usr/local/bin/node','--input-type=module','-e',probe.toString('utf8'),'--',JSON.stringify(p.paths)];
  const creation=await checked('create',['container','create','--pull=never','--platform=linux/arm64','--network=none','--read-only','--user=1000:1000','--cap-drop=ALL','--security-opt=no-new-privileges:true','--pids-limit=32','--memory=256m','--cpus=1','--restart=no','--no-healthcheck','--label','mem9-artifact-probe='+label,'--name',name,'--entrypoint','/bin/setpriv',p.binding.rootDigest,...args]);
  const returnedId=creation.stdout.trim();need(/^[a-f0-9]{64}$/.test(returnedId),'NonrootRuntimeContainerId');id=returnedId;created=true;const binding={id,name,args,label};
  const before=checkContainer(await inspect('inspect-created',['container','inspect',id]),p,binding,false);
  const output=await checked('start',['container','start','--attach',id]);
  const after=checkContainer(await inspect('inspect-exited',['container','inspect',id]),p,binding,true),result=validateProbe(output.stdout,p);
  record={version:1,kind:'verified-control-runtime-paths',buildHash:hash(value),image:copyNonrootJson(value.image),graphHash:p.binding.graphHash,filesystemHash:p.facts.filesystemHash,filesHash:hash(p.facts.files),pathsHash:hash(p.paths),probeCodeHash,containerId:id,configDigest:p.binding.configDigest,rootInspectHash:hash(root),platformInspectHash:hash(platform),createdInspectHash:hash(before),exitedInspectHash:hash(after),probeOutputHash:sha(output.stdout),identity:result.identity,observations:result.observations,startedMs};
  record.container={id,name,imageId:after.Image,arm64Digest:after.ImageManifestDescriptor?.digest??p.binding.arm64Digest,configDigest:p.binding.configDigest,exitCode:after.State.ExitCode,pid:after.State.Pid,startedAt:after.State.StartedAt,finishedAt:after.State.FinishedAt};
 }catch(error){primary=error;}
 try{
  if(created){const removed=await checked('remove',['container','rm','--force','--volumes',id],{cleanup:true});const absent=await run('inspect-removed',['container','inspect',id],{cleanup:true});need(absent.status===1&&new RegExp('(?:No such container|No such object): '+id+'(?:\\s|$)').test(absent.stderr),'ECLEANUP');removal={containerId:id,removeExitCode:removed.status,absenceExitCode:absent.status,absenceEvidenceHash:sha(absent.stderr)};}
  else if(createAttempted)sticky=true;
  cleanupConfirmed=!sticky;need(cleanupConfirmed,'ECLEANUP');await rm(directory,{recursive:true,force:true});
 }catch{throw Object.assign(cleanError('ECLEANUP',id),{containerName:name,operationDirectory:directory});}
 if(primary){primary.cleanupConfirmed=cleanupConfirmed;throw primary;}
 try{controlImageGraphBinding(p.graph);need(Date.now()<=deadline&&!options.signal?.aborted,'NonrootRuntimeObservationExpired');}catch(error){error.cleanupConfirmed=true;throw error;}
 record.completedMs=Date.now();record.cleanupConfirmed=true;record.removal=removal;
 const handle=Object.freeze({kind:'verified-control-runtime-observation'});observations.set(handle,{record:copyNonrootJson(record),graph:p.graph,filesystem:p.filesystem});return handle;
}

export function verifyNonrootControlRuntimeObservation(handle,value,options){
 const state=observations.get(handle);need(state,'NonrootRuntimeObservationRequired');
 need(state.graph===options?.controlVerification?.graph&&state.filesystem===options?.controlVerification?.filesystem,'NonrootRuntimeObservationContext');
 controlImageGraphBinding(state.graph);const r=state.record,now=options.now??Date.now();
 need(r.buildHash===hash(value)&&r.probeCodeHash===probeSource?.probeCodeHash&&r.cleanupConfirmed===true,'NonrootRuntimeObservationBinding');
 need(r.startedMs<=r.completedMs&&r.completedMs<=now&&now-r.completedMs<=300000,'NonrootRuntimeObservationExpired');
 return copyNonrootJson(r);
}
