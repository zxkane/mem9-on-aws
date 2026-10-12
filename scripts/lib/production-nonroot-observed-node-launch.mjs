/** Fixed Node DATA launch source. This compiler returns DATA, never a payer,
 * registration approval or evidence that a task has run. */
import {copyNonrootJson,nonrootHash} from './production-nonroot-contracts.mjs';
import {dataLaunchPolicy} from './production-nonroot-launch.mjs';
import {inspectDataObservationPlan,describeDataObservationSchedule} from './production-nonroot-data-observer.mjs';
import {inspectObservationGateFiles,nodeObservationCommonGateSource} from './production-nonroot-observation-gate.mjs';
import {nodeObservationCollectorSource} from './production-nonroot-observation-collector.mjs';
import {observationNodeOutputSource} from './production-nonroot-observation-node-output.mjs';
import {createHash} from 'node:crypto';
import {gzipSync} from 'node:zlib';
import * as nodeFs from 'node:fs';
import * as nodeNet from 'node:net';
import * as nodeCrypto from 'node:crypto';
import * as nodeChild from 'node:child_process';
import {runNodeObservationCommonGate} from './production-nonroot-observation-gate.mjs';

// All source factories below have explicit builtin dependencies. No caller
// callback, executable source, provider or credentials enter the compiler.
function nodeLifecyclePrimitives(fs,net,crypto,pollLimit){
 const need=(v,c)=>{if(!v)throw Error(c);};
 need(Number.isSafeInteger(pollLimit)&&pollLimit>0,'DataObservationPollInput');let polls=0,cleanupPolls=0;
 const hash=b=>crypto.createHash('sha256').update(b).digest('hex');
 const read=(path,cap)=>{
  const fd=fs.openSync(path,fs.constants.O_RDONLY|fs.constants.O_NONBLOCK);
  try{const b=Buffer.alloc(cap+1),n=fs.readSync(fd,b);need(n<=cap,'DataObservationLifecycleReadBound');return b.subarray(0,n);}
  finally{fs.closeSync(fd);}
 };
 const identity=pid=>{
  const text=read('/proc/'+pid+'/stat',4096).toString(),fields=text.slice(text.lastIndexOf(') ')+2).trim().split(/\s+/);
  need(text.startsWith(pid+' (')&&fields.length>=20,'DataObservationLifecycleIdentity');
  const ppid=Number(fields[1]),ticks=Number(fields[19]);need(Number.isSafeInteger(ppid)&&ppid>=0&&Number.isSafeInteger(ticks)&&ticks>0,'DataObservationLifecycleIdentity');
  return {pid,ppid,ticks};
 };
 const absent=who=>{try{need(identity(who.pid).ticks===who.ticks,'DataObservationLifecycleReused');return false;}catch(e){if(['ENOENT','ESRCH'].includes(e.code))return true;throw e;}};
 const pause=(cleanup=false)=>{need((cleanup?++cleanupPolls:++polls)<=pollLimit,cleanup?'DataObservationCleanupPollBound':'DataObservationPollBound');return new Promise(resolve=>setTimeout(resolve,1));};
 const send=async(text,deadline)=>{
  need(Buffer.byteLength(text)<=512&&Date.now()<deadline,'DataObservationArmExpired');
  const socket=new net.Socket({fd:3,readable:false,writable:true});
  await new Promise((resolve,reject)=>{
   let problem;const timer=setTimeout(()=>{problem=Error('DataObservationArmExpired');socket.destroy();},Math.max(1,deadline-Date.now()));
   socket.on('error',()=>{problem??=Error('DataObservationArmChannel');socket.destroy();});
   socket.on('close',()=>{clearTimeout(timer);if(problem)reject(problem);else resolve();});
   // Relay and observer inherit the same channel. Closing this descriptor
   // must not shutdown the socket's shared write direction for the other.
   socket.write(text,error=>{if(error)problem??=error;socket.destroy();});
  });
 };
 return {need,hash,read,identity,absent,pause,send};
}

function observerEntry(primitives,gate,collect,write,spec){
 return async function observe(){
  const {need,hash,read,identity,pause,send}=primitives;
  const [parentText,startText,armText]=process.argv.slice(2),parentPid=Number(parentText),parentStartTimeTicks=Number(startText),armingDeadlineMs=Number(armText);
  need([parentPid,parentStartTimeTicks,armingDeadlineMs].every(n=>Number.isSafeInteger(n)&&n>0)&&armingDeadlineMs<=spec.plan.latestArmMs+spec.plan.armingLimitMs,'DataObservationArmInput');
  const parent=()=>need(identity(parentPid).ticks===parentStartTimeTicks,'DataObservationParentChanged');
  // Relay exits before ARMED, so this process belongs to init before the
  // application replaces its coordinator. It is never an unreaped app child.
  while(process.ppid!==1){need(Date.now()<armingDeadlineMs,'DataObservationArmExpired');parent();await pause();}
  await gate(spec.files);parent();need(Date.now()<armingDeadlineMs,'DataObservationArmExpired');
  const self=identity(process.pid);await send('A|'+self.pid+'|'+self.ticks+'|'+spec.plan.launchNonce+'\n',armingDeadlineMs);
  for(;;){
   parent();need(Date.now()<spec.schedule.episodes[0].startedMs,'DataObservationMainNotExecuted');
   if(fslessExe(read,parentPid,spec.mainCmdlineHash,hash))break;
   await pause();
  }
  for(const episode of spec.schedule.episodes){
   const raw=await collect({planHash:spec.schedule.planHash,role:spec.plan.role,launchNonce:spec.plan.launchNonce,episodeIndex:episode.index,
    parentPid,parentStartTimeTicks,mainExecutable:'/usr/local/bin/node',mainCmdlineHashes:[spec.mainCmdlineHash],healthRequired:spec.healthHashes.length>0,healthCmdlineHashes:spec.healthHashes,
    startMs:episode.startedMs,endMs:episode.completedMs,sampleEveryMs:episode.sampleEveryMs,deadlineMs:spec.plan.observationEndMs,pollLimit:spec.plan.observationEndMs-spec.plan.startedMs});
   const bytes=Buffer.from(JSON.stringify({...raw,launch:{observerStartTimeTicks:self.ticks,armingDeadlineMs}})),capture=hash(Buffer.from(JSON.stringify({nonce:spec.plan.launchNonce,pid:self.pid,ticks:self.ticks,episode:episode.index}))).slice(0,32);
   await write({fd:2,stdoutFd:1,binding:spec.binding,capture,bytes,deadlineMs:spec.plan.observationEndMs});
  }
 };
 // Only a commitment is retained; application command/environment bytes are
 // never emitted. collect() subsequently checks actual executable identity.
 function fslessExe(read,pid,wanted,hash){return hash(read('/proc/'+pid+'/cmdline',16384))===wanted;}
}

function relayEntry(cp,primitives,spec,observerSource){
 return async function relay(){
  const {need,identity,send}=primitives;const args=process.argv.slice(2);
  need(args.length===3&&args.every(v=>/^[1-9][0-9]*$/.test(v)),'DataObservationArmInput');
  const child=cp.spawn('/usr/local/bin/node',['--input-type=module','-e',observerSource,'observer',...args],{
   env:{PATH:'/usr/local/bin:/usr/bin:/bin'},stdio:['ignore','inherit','inherit',3]});
  child.on('error',()=>{process.exitCode=1;});
  need(Number.isSafeInteger(child.pid)&&child.pid>0,'DataObservationObserverStart');
  const born=identity(child.pid);
  await send('B|'+born.pid+'|'+born.ticks+'|'+spec.plan.launchNonce+'\n',Number(args[2]));
  child.unref();
 };
}

function coordinatorEntry(cp,primitives,gate,spec,relaySource){
 return async function coordinate(){
  const {need,identity,absent,pause}=primitives;
  let cancelled;const term=()=>{cancelled='SIGTERM';},interrupt=()=>{cancelled='SIGINT';};
  process.on('SIGTERM',term);process.on('SIGINT',interrupt);
  const active=()=>need(!cancelled,'DataObservationLaunchCancelled');
  try{
  const execute=()=>{
   active();
   need(typeof process.execve==='function','DataObservationExecUnavailable');
   // Pass the existing application environment in memory, without inspection,
   // duplication to observer children, serialization, or logging.
   process.execve('/usr/local/bin/node',spec.argv,process.env);
   throw Error('DataObservationExecReturned');
  };
  await gate(spec.files);
  if(Date.now()<spec.plan.startedMs||Date.now()>=spec.plan.latestArmMs)return execute();
  const parent=identity(process.pid),armingDeadlineMs=Math.min(Date.now()+spec.plan.armingLimitMs,spec.plan.latestArmMs+spec.plan.armingLimitMs);
  let child,born,armed,exit,problem,wire='',channelBytes=0,channelClosed=false;
  try{
   child=cp.spawn('/usr/local/bin/node',['--input-type=module','-e',relaySource,'relay',String(parent.pid),String(parent.ticks),String(armingDeadlineMs)],{
    env:{PATH:'/usr/local/bin:/usr/bin:/bin'},stdio:['ignore','inherit','inherit','pipe']});
   child.on('error',()=>{problem??=Error('DataObservationRelayStart');});child.on('exit',(code,signal)=>{exit={code,signal};});
   child.stdio[3].on('error',()=>{problem??=Error('DataObservationArmChannel');});
   child.stdio[3].on('close',()=>{channelClosed=true;});
   child.stdio[3].on('data',bytes=>{
    try{
     channelBytes+=bytes.length;need(channelBytes<=1024,'DataObservationArmBound');
     need(bytes.every(byte=>byte<=127),'DataObservationArmBinding');wire+=bytes.toString('ascii');
     for(;;){const at=wire.indexOf('\n');if(at<0)break;const line=wire.slice(0,at);wire=wire.slice(at+1);
      const m=/^([BA])\|([1-9][0-9]*)\|([1-9][0-9]*)\|([a-f0-9]{32})$/.exec(line);
      need(m&&m[4]===spec.plan.launchNonce,'DataObservationArmBinding');const value={pid:Number(m[2]),ticks:Number(m[3])};
      need(Number.isSafeInteger(value.pid)&&Number.isSafeInteger(value.ticks),'DataObservationArmBinding');
      if(m[1]==='B'){need(!born,'DataObservationArmDuplicate');born=value;}else{need(!armed,'DataObservationArmDuplicate');armed=value;}
     }
    }catch(e){problem??=e;}
   });
   while(!exit||!armed||!born){active();if(problem)throw problem;need(Date.now()<armingDeadlineMs,'DataObservationArmExpired');if(exit)need(exit.code===0&&!exit.signal,'DataObservationRelayExit');await pause();}
   if(problem)throw problem;
   need(!wire&&exit.code===0&&!exit.signal&&born.pid===armed.pid&&born.ticks===armed.ticks,'DataObservationArmBinding');
   const actual=identity(born.pid);need(actual.ticks===born.ticks&&actual.ppid===1,'DataObservationObserverReparent');
   child.stdio[3].destroy();
   while(!channelClosed){active();if(problem)throw problem;need(Date.now()<armingDeadlineMs,'DataObservationArmExpired');await pause();}
   if(problem)throw problem;
   need(Date.now()<armingDeadlineMs,'DataObservationArmExpired');
   return execute();
  }catch(error){
   // No normal fallback until the relay has been reaped and the exact known
   // observer has disappeared. Missing birth evidence is unknown cleanup.
   if(child&&!exit)child.kill('SIGTERM');
   if(born&&!absent(born))process.kill(born.pid,'SIGTERM');
   while(child&&!exit||born&&!absent(born)){need(Date.now()<spec.plan.deadlineMs,'DataObservationHelperCleanup');await pause(true);}
   child?.stdio[3]?.destroy();
   while(child&&!channelClosed){need(Date.now()<spec.plan.deadlineMs,'DataObservationHelperCleanup');await pause(true);}
   need(!child||born,'DataObservationCleanupUnknown');
   if(error.message==='DataObservationArmExpired'){if(problem)throw problem;await gate(spec.files);return execute();}
   throw error;
  }
  }finally{process.off('SIGTERM',term);process.off('SIGINT',interrupt);}
 };
}

const sha=b=>createHash('sha256').update(b).digest('hex');
const encode=value=>JSON.stringify(value).replace(/</g,'\\u003c');
// Only fixed factories assembled below reach this helper. The public compiler
// accepts no executable source, callback, compressed payload or hash override.
function fixedPackedBootstrap(descriptor){
 return `import {gunzipSync as observationGunzip} from 'node:zlib';
import {createHash as observationHash} from 'node:crypto';
try{const descriptor=${JSON.stringify(descriptor)},body=observationGunzip(Buffer.from(descriptor.base64,'base64'),{maxOutputLength:descriptor.bytes});
if(body.length!==descriptor.bytes||observationHash('sha256').update(body).digest('hex')!==descriptor.sha256)throw Error('DataObservationSourceBinding');
await (await import('data:text/javascript;base64,'+body.toString('base64'))).runPackedObservation(descriptor);}catch{process.exitCode=1;}`;
}
function packedNodeSource(source,argumentCount){
 const bytes=Buffer.from(source),compressed=gzipSync(bytes,{level:9}),sourceHash=sha(bytes);
 const bootstrap=fixedPackedBootstrap({bytes:bytes.length,sha256:sourceHash,base64:compressed.toString('base64')});
 // Preserve the original proc cmdline cap. All dynamic arguments below are
 // positive safe integers (at most16 decimal digits plus their NUL delimiter).
 const cmdlineBytes=Buffer.byteLength(['/usr/local/bin/node','--input-type=module','-e',bootstrap].join('\0')+'\0')+17*argumentCount;
 if(cmdlineBytes>16384)throw Error('DataObservationSourceArgvBound');
 return {bootstrap,binding:{sourceHash,sourceBytes:bytes.length,compressedBytes:compressed.length,
  compressedHash:sha(compressed),bootstrapHash:sha(Buffer.from(bootstrap)),bootstrapBytes:Buffer.byteLength(bootstrap),cmdlineBytes}};
}
function sharedSource(pollLimit){return `import * as lifecycleFs from 'node:fs';
import * as lifecycleNet from 'node:net';
import * as lifecycleCrypto from 'node:crypto';
import * as lifecycleChild from 'node:child_process';
const lifecycle=(${Function.prototype.toString.call(nodeLifecyclePrimitives)})(lifecycleFs,lifecycleNet,lifecycleCrypto,${pollLimit});\n`;}

function prepareObservedNodeDataLaunch(input){
 const value=copyNonrootJson(input),need=(v,c)=>{if(!v)throw Error(c);};
 need(value&&Object.keys(value).sort().join()==='files,original,plan','DataObservationLaunchInput');
 const plan=inspectDataObservationPlan(value.plan);need(plan.role!=='mnemo-server','DataObservationNodeRole');
 const files=inspectObservationGateFiles(value.files),normal=dataLaunchPolicy(plan.role,value.original),schedule=describeDataObservationSchedule(plan);
 need(schedule.episodes.at(-1).completedMs<plan.observationEndMs,'DataObservationEmissionWindow');
 need(typeof normal.image==='string'&&normal.image.endsWith('@'+plan.image.rootDigest),'DataObservationLaunchImage');
 need(normal.linuxParameters?.initProcessEnabled===true,'DataObservationInitRequired');
 const argv=[...normal.entryPoint.slice(3),...(normal.command??[])];
 need(argv[0]==='node'&&argv.length===2,'DataObservationLaunchArgv');
 const script=argv[1].startsWith('/')?argv[1]:'/app/'+argv[1];
 need(files.some(f=>f.path==='/usr/local/bin/node')&&files.some(f=>f.path===script),'DataObservationLaunchFiles');
 const health=normal.healthCheck?.command;
 if(['llm-proxy','qwen3-embed'].includes(plan.role))need(health?.[0]==='CMD'&&health[4]==='node'&&files.some(f=>f.path==='/app/healthcheck.mjs'),'DataObservationHealthSource');
 const spec={plan,files,schedule,argv,mainCmdlineHash:sha(Buffer.from(argv.join('\0')+'\0')),healthHashes:health?[sha(Buffer.from(health.slice(4).join('\0')+'\0'))]:[]};
 spec.binding=nonrootHash({planHash:schedule.planHash,normal,files});
 const source=sharedSource(plan.deadlineMs-plan.startedMs)+nodeObservationCommonGateSource()+'\n'+nodeObservationCollectorSource()+'\n'+observationNodeOutputSource()+
  `\nconst sourceBootstrap=(${Function.prototype.toString.call(fixedPackedBootstrap)});
const observe=(${Function.prototype.toString.call(observerEntry)});
const relay=(${Function.prototype.toString.call(relayEntry)});
const coordinate=(${Function.prototype.toString.call(coordinatorEntry)});
const spec=${encode(spec)};
export async function runPackedObservation(descriptor){
 const bootstrap=sourceBootstrap(descriptor);
 if(process.execArgv.length!==3||process.execArgv[0]!=='--input-type=module'||process.execArgv[1]!=='-e'||process.execArgv[2]!==bootstrap)throw Error('DataObservationSourceInvocation');
 if(process.argv[1]==='observer')return observe(lifecycle,fixedNodeObservationCommonGate,collectNodeObservationEpisode,writeNodeObservationFrames,spec)();
 if(process.argv[1]==='relay')return relay(lifecycleChild,lifecycle,spec,bootstrap)();
 if(process.argv.length!==1)throw Error('DataObservationSourceMode');
 return coordinate(lifecycleChild,lifecycle,fixedNodeObservationCommonGate,spec,bootstrap)();
}`;
 const packed=packedNodeSource(source,4);
 const target={...normal,entryPoint:[...normal.entryPoint.slice(0,3),'/usr/local/bin/node','--input-type=module','-e',packed.bootstrap],command:[]};
 const contract=copyNonrootJson({version:2,kind:'observed-node-data-launch',plan,normal,target,binding:spec.binding,sourceHash:packed.binding.bootstrapHash,
  sourceBytes:packed.binding.bootstrapBytes,observerSourceHash:packed.binding.sourceHash,relaySourceHash:packed.binding.sourceHash,
  delivery:{kind:'fixed-gzip-source-v1',...packed.binding,processes:['coordinator','relay','observer'],maximumInvocations:3},snapshotCount:schedule.snapshotCount+schedule.episodes.length});
 return {contract,spec,relay:packed.bootstrap};
}
export function compileObservedNodeDataLaunch(input){return prepareObservedNodeDataLaunch(input).contract;}
/** Same fixed coordinator as the inline source; no injected lifecycle hooks. */
export async function runObservedNodeDataLaunch(input){
 const {spec,relay}=prepareObservedNodeDataLaunch(input);
 return coordinatorEntry(nodeChild,nodeLifecyclePrimitives(nodeFs,nodeNet,nodeCrypto,spec.plan.deadlineMs-spec.plan.startedMs),runNodeObservationCommonGate,spec,relay)();
}
