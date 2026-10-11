/** Load only an already verified OCI cache into the local Docker store. No
 * registry login, pull, container start, credential forwarding or host extract. */
import {execFile,spawn} from 'node:child_process';
import {Readable} from 'node:stream';
import {pipeline} from 'node:stream/promises';
import {promisify} from 'node:util';
import {mkdtemp,open,writeFile,lstat,realpath,readdir,rm} from 'node:fs/promises';
import {constants} from 'node:fs';
import {join,resolve} from 'node:path';
import {createHash,randomBytes} from 'node:crypto';
import {controlImageGraphBinding,imageGraphState,IMAGE_MEDIA} from './production-image-graph.mjs';
import {parseNonrootJson,nonrootHash as hash} from './production-nonroot-contracts.mjs';
import {inspectAllocatedControlResources,beginControlImageLoad,recordControlImageLoad} from './ci-smoke-control-resources.mjs';
import {DOCKER_STDIN_SUPERVISOR_SOURCE} from './production-nonroot-control-docker-supervisor.mjs';

const execute=promisify(execFile),need=(ok,code='NonrootControlDockerInvalid')=>{if(!ok)throw Error(code);};
const zero=()=>({ecrRequests:0,httpBodyBytes:0,logicalBytes:0,uncompressedBytes:0,processedEntries:0});
const keys=['dev','ino','size','mtimeMs','ctimeMs','mode','uid','nlink'];
const sameFile=(a,b)=>keys.every(k=>a[k]===b[k]);
const cleanup=details=>Object.assign(Error('ECLEANUP'),{code:'ECLEANUP',...details});
const uncertain=error=>error?.killed||error?.signal||error?.name==='AbortError'||error?.code==='ERR_CHILD_PROCESS_STDIO_MAXBUFFER';
const terminations=new WeakSet();
const padded=size=>Math.ceil(size/512)*512;
function tarHeader(name,size,mtimeMs){
 need(/^(?:blobs\/sha256\/[a-f0-9]{64}|index\.json|oci-layout)$/.test(name)&&Number.isSafeInteger(size)&&size>=0&&Number.isFinite(mtimeMs)&&mtimeMs>=0,'NonrootControlTarMember');
 const b=Buffer.alloc(512),octal=(n,at,length)=>{const text=Math.trunc(n).toString(8);need(text.length<length,'NonrootControlTarSize');b.write(text.padStart(length-1,'0')+'\0',at,length,'ascii');};
 b.write(name,0,100,'ascii');octal(0o600,100,8);octal(0,108,8);octal(0,116,8);octal(size,124,12);octal(mtimeMs/1000,136,12);
 b.fill(32,148,156);b[156]=48;b.write('ustar\0',257,6,'ascii');b.write('00',263,2,'ascii');
 b.write([...b].reduce((n,v)=>n+v,0).toString(8).padStart(6,'0')+'\0 ',148,8,'ascii');return b;
}

/** One fixed Docker child and a bounded stdin pipeline. A broken stream or
 * uncertain child outcome never falls through to image cleanup or retry. */
function streamDocker(args,input,{directory,check,signal,details}){
 return new Promise((resolve,reject)=>{
  const controller=new AbortController(),out=[],err=[],ack=[];let child,closed=false,pipeDone=false,pipeSettled=false,settled=false,problem=false,cancelSent=false,status,exitSignal,outputBytes=0,ackBytes=0,timer;
  const terminal=()=>{
   const t=parseNonrootJson(Buffer.concat(ack).toString('utf8'),{maxBytes:4096});
   need(Object.keys(t).sort().join()==='cleanupComplete,killedDescendants,kind,leaderEnded,leaderPid,reaped,reason,signal,status,supervisorPid,version','NonrootControlDockerTermination');
   need(t.version===1&&t.kind==='docker-stdin-subreaper-echild','NonrootControlDockerTermination');
   need(t.supervisorPid===child.pid&&t.cleanupComplete===true&&Number.isSafeInteger(t.reaped)&&t.reaped>=0&&Number.isSafeInteger(t.killedDescendants)&&t.killedDescendants>=0,'NonrootControlDockerTermination');
   need(t.leaderPid===null?t.leaderEnded===false&&t.reaped===0&&t.status===null&&t.signal===null&&t.reason!==null:Number.isSafeInteger(t.leaderPid)&&t.leaderPid>1&&t.leaderEnded===true&&t.reaped>=1&&t.killedDescendants<t.reaped,'NonrootControlDockerTermination');
   need(t.status===null||Number.isInteger(t.status)&&t.status>=0&&t.status<=255,'NonrootControlDockerTermination');need(t.signal===null||typeof t.signal==='string'&&/^SIG[A-Z0-9]+$/.test(t.signal),'NonrootControlDockerTermination');
   need(t.leaderPid===null?t.killedDescendants===0:(t.status===null)!==(t.signal===null),'NonrootControlDockerTermination');
   need([null,'DockerStdinCancelled','DockerStdinTimeout','DockerDescendantSurvived','DockerSupervisionFault'].includes(t.reason),'NonrootControlDockerTermination');
   terminations.add(t);return Object.freeze(t);
  };
  const finish=()=>{
   if(settled||!closed||!pipeSettled)return;settled=true;clearTimeout(timer);signal?.removeEventListener('abort',stop);child?.stdio[4]?.end();
   let proof;try{if(status===0&&!exitSignal)proof=terminal();}catch{problem=true;}
   if(!proof||problem||!pipeDone||proof.reason!==null||proof.signal!==null)reject(cleanup({...details(),processStopped:Boolean(proof),...(proof?{termination:proof}:{})}));
   else resolve({status:proof.status,stdout:Buffer.concat(out).toString('utf8'),stderr:Buffer.concat(err).toString('utf8'),termination:proof});
  };
  function stop(){
   if(settled)return;problem=true;controller.abort();
   // Never kill the subreaper or address a recycled leader PID/PGID. It owns
   // cancellation and remains alive until all adopted children reach ECHILD.
   if(!cancelSent&&child?.stdio[4]){cancelSent=true;child.stdio[4].end('X');}
   finish();
  }
  const collect=chunks=>chunk=>{if(settled)return;outputBytes+=chunk.length;if(outputBytes>1048576)stop();else chunks.push(chunk);};
  try{
   need(process.platform==='linux'&&JSON.stringify(args)===JSON.stringify(['--host','unix:///var/run/docker.sock','--config',directory,'image','load']),'NonrootControlDockerSupervisor');
   check();signal?.throwIfAborted();
   child=spawn('/usr/bin/python3',['-I','-B','-c',DOCKER_STDIN_SUPERVISOR_SOURCE,String(process.pid),directory],{cwd:directory,env:{PATH:'/usr/bin:/bin',HOME:directory,LANG:'C',LC_ALL:'C'},detached:true,stdio:['pipe','pipe','pipe','pipe','pipe']});
   child.stdout.on('data',collect(out));child.stderr.on('data',collect(err));child.on('error',stop);
   child.stdio[3].on('data',chunk=>{ackBytes+=chunk.length;if(ackBytes>4096)stop();else ack.push(chunk);});child.stdio[4].on('error',()=>{});
   child.on('close',(code,sig)=>{closed=true;status=code;exitSignal=sig;if(!pipeDone)stop();finish();});
   timer=setTimeout(stop,120000);signal?.addEventListener('abort',stop,{once:true});if(signal?.aborted)stop();
   pipeline(Readable.from(input(controller.signal),{objectMode:false,highWaterMark:65536}),child.stdin,{signal:controller.signal}).then(()=>{pipeDone=true;pipeSettled=true;finish();},()=>{pipeSettled=true;stop();});
  }catch{closed=!child;pipeSettled=true;stop();}
 });
}

export async function loadNonrootControlImage({graph,cacheDirectory,metadataReads,tempRoot,resourceHandle,signal},{beforeCommand}={}){
 const binding=controlImageGraphBinding(graph),state=imageGraphState(graph),nodes=graph.inventory.nodes;
 const allocation=resourceHandle===undefined?null:await inspectAllocatedControlResources(resourceHandle);
 if(allocation)need(allocation.tempRoot===tempRoot&&allocation.rootDigest===binding.rootDigest&&allocation.configDigest===binding.configDigest,'NonrootControlDockerResource');
 need(state.side==='control'&&typeof metadataReads?.reserveLocal==='function','NonrootControlDockerBudget');
 for(const path of [cacheDirectory,tempRoot])need(typeof path==='string'&&resolve(path)===path&&await realpath(path)===path,'NonrootControlDockerDirectory');
 need(tempRoot!==cacheDirectory&&!tempRoot.startsWith(cacheDirectory+'/'),'NonrootControlDockerDirectory');
 const directoryStat=await lstat(cacheDirectory);need(directoryStat.isDirectory()&&directoryStat.uid===process.getuid()&&(directoryStat.mode&511)===0o700,'NonrootControlDockerDirectory');
 need((await lstat('/var/run/docker.sock')).isSocket(),'NonrootControlDockerSocket');
 const expectedNames=nodes.map(d=>d.digest.slice(7)).sort();need(hash((await readdir(cacheDirectory)).sort())===hash(expectedNames),'NonrootControlDockerCache');
 const check=()=>{signal?.throwIfAborted();controlImageGraphBinding(graph);metadataReads.reserveLocal(zero());};check();
 const identities=new Map();
 // Rehash the actual files used by tar, even when graph.store has another
 // authenticated backing store. Local identity alone is not byte evidence.
 for(const d of nodes){
  check();metadataReads.reserveLocal({...zero(),logicalBytes:d.size});
  const path=join(cacheDirectory,d.digest.slice(7)),fd=await open(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
  try{
   const before=await fd.stat();need(before.isFile()&&before.uid===process.getuid()&&(before.mode&511)===0o600&&before.nlink===1&&before.size===d.size,'NonrootControlDockerCache');
   const digest=createHash('sha256'),buffer=Buffer.alloc(65536);let count=0;
   while(true){check();const {bytesRead}=await fd.read(buffer,0,buffer.length,null);if(!bytesRead)break;count+=bytesRead;need(count<=d.size,'NonrootControlDockerCache');digest.update(buffer.subarray(0,bytesRead));}
   need(count===d.size&&'sha256:'+digest.digest('hex')===d.digest&&sameFile(before,await fd.stat())&&sameFile(before,await lstat(path)),'NonrootControlDockerCache');identities.set(path,before);
  }finally{await fd.close();}
 }
 const directory=await mkdtemp(join(tempRoot,'mem9-control-docker-')),tag=allocation?.tag??'mem9-control-check:'+randomBytes(16).toString('hex');
 let loaded=false,attempted=false,closed=false,unknown=false,recordedIntent=false;
 const hook=async(program,args,cleanupOnly)=>{
  if(beforeCommand===undefined)return;
  try{need(typeof beforeCommand==='function');await beforeCommand(Object.freeze({program,args:Object.freeze([...args]),cleanupOnly}));}
  catch(e){if(uncertain(e)){unknown=true;throw cleanup({operationDirectory:directory,tag});}throw Error('NonrootControlDockerHook');}
 };
 const run=async(program,args,{cleanupOnly=false,timeout=30000}={})=>{
  if(!cleanupOnly)check();
  // Hook failures never enter the native-process exit/output decoding path.
  await hook(program,args,cleanupOnly);if(!cleanupOnly)check();
  try{return {...await execute(program,args,{cwd:directory,env:{PATH:'/usr/bin:/bin',HOME:directory,DOCKER_CONFIG:directory,LANG:'C',LC_ALL:'C'},encoding:'utf8',maxBuffer:1048576,timeout,...(!cleanupOnly&&signal?{signal}:{})}),status:0};}
  catch(e){if(uncertain(e)){unknown=true;throw cleanup({operationDirectory:directory,tag});}if(Number.isInteger(e.code)&&e.code>0&&e.code<=255)return {status:e.code,stdout:e.stdout??'',stderr:e.stderr??''};throw Error('NonrootControlDockerCommand');}
 };
 const docker=(args,options)=>run('/usr/bin/docker',['--host','unix:///var/run/docker.sock','--config',directory,...args],options);
 const ownImage=async(cleanupOnly=false)=>{
  const r=await docker(['image','inspect',tag],{cleanupOnly});
  if(r.status===1&&r.stderr.includes('No such image: '+tag))return null;
  need(r.status===0,'NonrootControlDockerInspect');const rows=parseNonrootJson(r.stdout,{maxBytes:1048576});
  need(rows.length===1&&rows[0].Os==='linux'&&rows[0].Architecture==='arm64'&&rows[0].RepoTags?.includes(tag),'NonrootControlDockerImage');
  const image=rows[0];need(image.Descriptor?.digest===binding.rootDigest&&image.Id===binding.rootDigest||image.Id===binding.configDigest&&image.RepoDigests?.some(d=>d.endsWith('@'+binding.rootDigest)),'NonrootControlDockerImage');
  return image;
 };
 const close=async()=>{
  if(allocation){closed=true;return;} // the recorded CI owner performs final cleanup
  if(closed)return;need(!unknown,'ECLEANUP');
  try{
   if(loaded||attempted){const image=await ownImage(true);if(image){const r=await docker(['image','rm',tag],{cleanupOnly:true});need(r.status===0&&!await ownImage(true),'ECLEANUP');}}
   await rm(directory,{recursive:true,force:true});closed=true;
  }catch{throw cleanup({operationDirectory:directory,tag});}
 };
 try{
  const absent=await docker(['image','inspect',tag]);need(absent.status===1&&absent.stderr.includes('No such image: '+tag),'NonrootControlDockerTagExists');
  const index={schemaVersion:2,mediaType:IMAGE_MEDIA.index,manifests:[{...state.roots[0].root,annotations:{'io.containerd.image.name':'docker.io/library/'+tag,'org.opencontainers.image.ref.name':tag.split(':')[1]}}]};
  const metadata=new Map([['index.json',Buffer.from(JSON.stringify(index))],['oci-layout',Buffer.from('{"imageLayoutVersion":"1.0.0"}')]]),metadataStats=new Map();
  const metadataBytes=[...metadata.values()].reduce((n,b)=>n+b.length,0);metadataReads.reserveLocal({...zero(),logicalBytes:metadataBytes});
  for(const [name,bytes]of metadata){await writeFile(join(directory,name),bytes,{mode:0o600,flag:'wx'});metadataStats.set(name,await lstat(join(directory,name)));}
  const rawBytes=nodes.reduce((n,d)=>n+d.size,0),archiveBytes=[...nodes.map(d=>d.size),...[...metadata.values()].map(b=>b.length)].reduce((n,size)=>n+512+padded(size),1024);
  need(Number.isSafeInteger(archiveBytes)&&archiveBytes<=rawBytes+nodes.length*1536+32768,'NonrootControlDockerArchive');
  const unchanged=async()=>{for(const [path,before]of identities)need(sameFile(before,await lstat(path)),'NonrootControlDockerCache');for(const [name,before]of metadataStats)need(sameFile(before,await lstat(join(directory,name))),'NonrootControlDockerCache');};
  await unchanged();
  // Prepay the entire bounded stream before Docker dispatch. This covers its
  // cache read plus every metadata/header/padding byte; unknown gets no refund.
  metadataReads.reserveLocal({...zero(),logicalBytes:archiveBytes});check();
  const transport={kind:'oci-tar-stdin',archiveBytes,blobBytes:rawBytes};
  if(allocation){await beginControlImageLoad(resourceHandle,{loaderDirectory:directory,transport});recordedIntent=true;check();}
  const args=['--host','unix:///var/run/docker.sock','--config',directory,'image','load'];await hook('/usr/bin/docker',args,false);await unchanged();check();
  let streamed=0,readBytes=0;
  const stream=async function*(abort){
   const verify=()=>{abort.throwIfAborted();check();};
   const emit=bytes=>{verify();streamed+=bytes.length;need(streamed<=archiveBytes,'NonrootControlTarSize');return bytes;};
   for(const name of expectedNames){
    verify();const path=join(cacheDirectory,name),before=identities.get(path),fd=await open(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
    try{
     need(sameFile(before,await fd.stat())&&sameFile(before,await lstat(path)),'NonrootControlDockerCache');yield emit(tarHeader('blobs/sha256/'+name,before.size,before.mtimeMs));
     const digest=createHash('sha256');let count=0;
     while(count<before.size){verify();const buffer=Buffer.alloc(Math.min(65536,before.size-count)),{bytesRead}=await fd.read(buffer,0,buffer.length,null);need(bytesRead>0,'NonrootControlDockerCache');count+=bytesRead;readBytes+=bytesRead;digest.update(buffer.subarray(0,bytesRead));yield emit(buffer.subarray(0,bytesRead));}
     need(digest.digest('hex')===name&&sameFile(before,await fd.stat())&&sameFile(before,await lstat(path)),'NonrootControlDockerCache');
     if(padded(count)>count)yield emit(Buffer.alloc(padded(count)-count));
    }finally{await fd.close();}
   }
   // Publish the index only after all streamed blob hashes and identities have
   // been rechecked. Truncated/changed input is never a completed OCI archive.
   await unchanged();verify();
   for(const [name,bytes]of metadata){yield emit(tarHeader(name,bytes.length,metadataStats.get(name).mtimeMs));yield emit(bytes);if(padded(bytes.length)>bytes.length)yield emit(Buffer.alloc(padded(bytes.length)-bytes.length));}
   yield emit(Buffer.alloc(1024));need(streamed===archiveBytes&&readBytes===rawBytes,'NonrootControlTarSize');
  };
  attempted=true;
  let result;try{result=await streamDocker(args,stream,{directory,check,signal,details:()=>({operationDirectory:directory,tag,producedBytes:streamed,cacheReadBytes:readBytes})});}catch(error){unknown=true;throw error;}
  need(result.status===0,'NonrootControlDockerLoad');
  const image=await ownImage();need(image,'NonrootControlDockerLoad');loaded=true;
  for(const [path,before]of identities)need(sameFile(before,await lstat(path)),'NonrootControlDockerCache');check();
  if(allocation)await recordControlImageLoad(resourceHandle,{outcome:'loaded',completedMs:Date.now()});
  return Object.freeze({authority:false,tag,rootDigest:binding.rootDigest,image,loaderDirectory:directory,archiveBytes,io:Object.freeze({cacheVerificationBytes:rawBytes,cacheStreamingBytes:readBytes,metadataWriteBytes:metadataBytes,tarFramingBytes:archiveBytes-rawBytes,logicalBytes:rawBytes+archiveBytes+metadataBytes}),close});
 }catch(error){
  const held=()=>cleanup({operationDirectory:directory,tag,...(typeof error?.processStopped==='boolean'?{processStopped:error.processStopped}:{}),...(terminations.has(error?.termination)?{termination:error.termination}:{}),
   ...Object.fromEntries(['producedBytes','cacheReadBytes'].filter(key=>Number.isSafeInteger(error?.[key])&&error[key]>=0).map(key=>[key,error[key]]))});
  if(allocation){
   if(recordedIntent)try{await recordControlImageLoad(resourceHandle,{outcome:unknown?'unknown':'failed',completedMs:Date.now()});}catch{throw held();}
   if(unknown)throw held();throw error;
  }
  if(unknown)throw held();try{await close();}catch(e){throw e;}throw error;
 }
}
