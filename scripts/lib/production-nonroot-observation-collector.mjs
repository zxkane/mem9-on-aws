/** Fixed read-only collector for a source-bound observation episode. This
 * produces kernel DATA only; it never grants authority, launches health work,
 * accesses environment/credentials, or reports its own eventual process exit. */
import * as collectorFs from 'node:fs';
import * as collectorCrypto from 'node:crypto';
import {copyNonrootJson} from './production-nonroot-contracts.mjs';

function observationCollectorFactory(fs,crypto){
 return async function collectNodeObservationEpisode(spec){
  const need=(v,c='DataObservationCollection')=>{if(!v)throw Error(c);};
  const hash=b=>crypto.createHash('sha256').update(b).digest('hex');
  const owned=new Set(),cache=new Map();let readBytes=0,cancelled=false;
  const stop=()=>{cancelled=true;};process.on('SIGTERM',stop);process.on('SIGINT',stop);
  const check=()=>need(!cancelled&&Date.now()<spec.deadlineMs,'DataObservationCollectionExpired');
  const charge=n=>{readBytes+=n;need(Number.isSafeInteger(readBytes)&&readBytes<=268435456,'DataObservationCollectionBound');check();};
  const readInto=(fd,buffer)=>{check();need(readBytes+buffer.length<=268435456,'DataObservationCollectionBound');const n=fs.readSync(fd,buffer);charge(n);return n;};
  const close=fd=>{fs.closeSync(fd);owned.delete(fd);};
  const open=path=>{check();const fd=fs.openSync(path,fs.constants.O_RDONLY|fs.constants.O_NONBLOCK);owned.add(fd);return fd;};
  const read=(path,cap)=>{
   const fd=open(path);try{const chunks=[];let size=0;
    while(size<=cap){const b=Buffer.alloc(Math.min(65536,cap+1-size)),n=readInto(fd,b);if(!n)break;size+=n;need(size<=cap,'DataObservationProcBound');chunks.push(b.subarray(0,n));}
    return Buffer.concat(chunks,size);
   }finally{close(fd);}
  };
  const stat=pid=>{
   const raw=read('/proc/'+pid+'/stat',4096).toString('utf8');need(raw.startsWith(pid+' (')&&raw.includes(') '));
   const values=raw.slice(raw.lastIndexOf(') ')+2).trim().split(/\s+/),ppid=Number(values[1]),startTimeTicks=Number(values[19]);
   need(Number.isSafeInteger(ppid)&&ppid>=0&&Number.isSafeInteger(startTimeTicks)&&startTimeTicks>0);return {ppid,startTimeTicks};
  };
  const stamp=s=>[s.dev,s.ino,s.size,s.mode,s.uid,s.gid,s.mtimeNs??s.mtimeMs,s.ctimeNs??s.ctimeMs].join(':');
  const executable=pid=>{
   const path='/proc/'+pid+'/exe',resolved=fs.readlinkSync(path);charge(Buffer.byteLength(resolved));
   need(resolved.startsWith('/')&&Buffer.byteLength(resolved)<=4096&&!/[\0\r\n]/.test(resolved)&&!resolved.endsWith(' (deleted)'));
   const fd=open(path),before=fs.fstatSync(fd,{bigint:true}),key=stamp(before),fileSize=Number(before.size);need(before.isFile()&&Number.isSafeInteger(fileSize)&&fileSize>0&&fileSize<=201326592);
   let retained=cache.get(key),sha256=retained?.sha256;
   if(retained){need(stamp(fs.fstatSync(fd,{bigint:true}))===key&&stamp(fs.fstatSync(retained.fd,{bigint:true}))===key,'DataObservationProcessChanged');close(fd);}
   else{
    const h=crypto.createHash('sha256');let size=0;
    while(size<=fileSize){const b=Buffer.alloc(Math.min(65536,fileSize+1-size)),n=readInto(fd,b);if(!n)break;size+=n;need(size<=fileSize);h.update(b.subarray(0,n));}
    need(size===fileSize&&stamp(fs.fstatSync(fd,{bigint:true}))===key,'DataObservationProcessChanged');sha256=h.digest('hex');cache.set(key,{sha256,fd});
    // Keep the original inode open until the complete episode is finished.
   }
   return {path:resolved,sha256,file:{mode:Number(before.mode)&4095,uid:Number(before.uid),gid:Number(before.gid),device:String(before.dev),inode:String(before.ino)}};
  };
  const proc=pid=>{
   const before=stat(pid),text=read('/proc/'+pid+'/status',65536).toString('utf8'),fields=new Map();
   for(const line of text.trimEnd().split('\n')){const at=line.indexOf(':');need(at>0&&!fields.has(line.slice(0,at)));fields.set(line.slice(0,at),line.slice(at+1).trim());}
   const ids=name=>{const s=fields.get(name);need(typeof s==='string'&&/^(?:[0-9]+(?:\s+[0-9]+)*)?$/.test(s));return s?s.split(/\s+/).map(Number):[];};
   const cmd=read('/proc/'+pid+'/cmdline',16384),exe=executable(pid),after=stat(pid);
   need(before.startTimeTicks===after.startTimeTicks&&before.ppid===after.ppid&&hash(read('/proc/'+pid+'/cmdline',16384))===hash(cmd)&&fs.readlinkSync('/proc/'+pid+'/exe')===exe.path,'DataObservationProcessChanged');
   const row={pid,...before,executablePath:exe.path,executableDigest:'sha256:'+exe.sha256,file:exe.file,cmdlineHash:hash(cmd),uid:ids('Uid'),gid:ids('Gid'),groups:ids('Groups'),noNewPrivs:Number(fields.get('NoNewPrivs'))};
   need(row.uid.length===4&&row.gid.length===4&&[...row.uid,...row.gid,...row.groups].every(Number.isSafeInteger)&&['0','1'].includes(fields.get('NoNewPrivs')));
   for(const name of ['Inh','Prm','Eff','Bnd','Amb']){const value=fields.get('Cap'+name);need(/^[a-f0-9]{16}$/.test(value));row['cap'+name]=value;}
   return row;
  };
  const secure=(row,code)=>need([...row.uid,...row.gid,...row.groups].every(n=>n===1000)&&row.noNewPrivs===1&&
   ['Inh','Prm','Eff','Bnd','Amb'].every(k=>row['cap'+k]==='0000000000000000')&&row.file.uid===0&&row.file.gid===0&&(row.file.mode&0o6022)===0,code);
  const ids=()=>{const values=fs.readdirSync('/proc').filter(n=>/^[1-9][0-9]*$/.test(n));charge(values.reduce((n,s)=>n+s.length+1,0));need(values.length>0&&values.length<=128,'DataObservationProcessCount');return values.map(Number).sort((a,b)=>a-b);};
  const snapshot=()=>{const startedMs=Date.now(),processes=ids().map(proc),completedMs=Date.now();return {startedMs,completedMs,processes};};
  const parent=()=>{const p=stat(spec.parentPid);need(p.startTimeTicks===spec.parentStartTimeTicks,'DataObservationParentChanged');return p;};
  const health=[];let retainedBytes=1024;
  const retain=value=>{retainedBytes+=Buffer.byteLength(JSON.stringify(value));need(retainedBytes<=1048576,'DataObservationOutputBound');};
  const healthRow=row=>{
   secure(row,'DataObservationHealthSecurity');
   need(spec.healthCmdlineHashes.includes(row.cmdlineHash)&&row.executablePath===spec.mainExecutable&&
    row.executableDigest===main.executableDigest&&row.file.device===main.file.device&&row.file.inode===main.file.inode,'DataObservationHealthBinding');
  };
  const pollHealth=()=>{
   if(!spec.healthRequired||health.length||Date.now()<spec.startMs||Date.now()>spec.endMs)return;
   for(const pid of ids()){
    if(pid===process.pid)continue;
    try{
     if(spec.healthCmdlineHashes.includes(hash(read('/proc/'+pid+'/cmdline',16384)))){
      const row=proc(pid);healthRow(row);
      const value={atMs:Date.now(),process:row};retain(value);health.push(value);return;
     }
    }catch(e){if(!['ENOENT','ESRCH'].includes(e.code))throw e;}
   }
  };
  const wait=async at=>{while(Date.now()<at){check();parent();pollHealth();await new Promise(resolve=>setTimeout(resolve,Math.min(spec.healthRequired&&!health.length?1:10,at-Date.now())));}};
  let result,main;
  try{
   check();parent();
   // The coordinator must have execed the genuine application before the
   // caller starts the episode; no coordinator/Node-basename substitution.
   main=proc(spec.parentPid);need(main.executablePath===spec.mainExecutable&&spec.mainCmdlineHashes.includes(main.cmdlineHash),'DataObservationMainNotExecuted');
   secure(main,'DataObservationMainSecurity');
   need(Date.now()<=spec.startMs,'DataObservationEpisodeLate');
   const initial=snapshot();need(initial.completedMs<=spec.startMs,'DataObservationEpisodeLate');retain(initial);
   const snapshots=[];let next=spec.startMs;
   while(next<=spec.endMs){
    await wait(next);parent();const sample=snapshot();retain(sample);snapshots.push(sample);
    if(!health.length)for(const p of sample.processes)if(spec.healthCmdlineHashes.includes(p.cmdlineHash)){
     healthRow(p);
     const value={atMs:sample.completedMs,process:p};retain(value);health.push(value);break;
    }
    if(next===spec.endMs)break;next=Math.min(spec.endMs,next+spec.sampleEveryMs);
   }
   const final=snapshots.at(-1),unique=new Set([initial,...snapshots].flatMap(s=>s.processes.map(p=>p.pid+':'+p.startTimeTicks)));
   need(unique.size<=256,'DataObservationIdentityCount');need(!spec.healthRequired||health.length>0,'DataObservationHealthMissing');
   for(const sample of [initial,...snapshots]){
    const matches=sample.processes.filter(p=>p.pid===spec.parentPid&&p.startTimeTicks===spec.parentStartTimeTicks);
    need(matches.length===1&&matches[0].executablePath===spec.mainExecutable&&spec.mainCmdlineHashes.includes(matches[0].cmdlineHash),'DataObservationMainChanged');
    secure(matches[0],'DataObservationMainSecurity');
    need(matches[0].executableDigest===main.executableDigest&&matches[0].file.device===main.file.device&&matches[0].file.inode===main.file.inode,'DataObservationProcessChanged');
   }
   for(const [key,entry]of cache)need(stamp(fs.fstatSync(entry.fd,{bigint:true}))===key,'DataObservationProcessChanged');
   result={version:1,kind:'data-observation-episode',planHash:spec.planHash,role:spec.role,launchNonce:spec.launchNonce,episodeIndex:spec.episodeIndex,
    observerPid:process.pid,parentPid:spec.parentPid,parentStartTimeTicks:spec.parentStartTimeTicks,
    requestedStartMs:spec.startMs,requestedEndMs:spec.endMs,startedMs:initial.startedMs,completedMs:final.completedMs,
    initial,final,snapshots,health,readBytes};
  }finally{
   let failure;for(const fd of [...owned])try{close(fd);}catch(e){failure??=e;}
   process.off('SIGTERM',stop);process.off('SIGINT',stop);if(failure)throw failure;
  }
  need(owned.size===0,'DataObservationFileCleanup');
  // No subprocess is launched by this collector. Kernel readback is retained
  // separately from END and cannot stand for eventual observer process exit.
  check();const childFd=fs.openSync('/proc/self/task/'+process.pid+'/children',fs.constants.O_RDONLY|fs.constants.O_NONBLOCK);
  try{const b=Buffer.alloc(4097),n=readInto(childFd,b);need(n<=4096&&b.subarray(0,n).toString().trim()==='','DataObservationHelperCleanup');}
  finally{fs.closeSync(childFd);}
  result.readBytes=readBytes;result.collectorResources={heldImageFiles:0,childProcesses:0};
  need(readBytes<=268435456&&Buffer.byteLength(JSON.stringify(result))<=1048576,'DataObservationOutputBound');return result;
 };
}
const collect=observationCollectorFactory(collectorFs,collectorCrypto);
export function collectNodeObservationEpisode(input){
 const s=copyNonrootJson(input),keys=['planHash','role','launchNonce','episodeIndex','parentPid','parentStartTimeTicks','mainExecutable','mainCmdlineHashes','healthRequired','healthCmdlineHashes','startMs','endMs','sampleEveryMs','deadlineMs'];
 if(!s||Object.keys(s).length!==keys.length||!keys.every(k=>Object.hasOwn(s,k))||!/^[a-f0-9]{64}$/.test(s.planHash)||!/^[a-f0-9]{32}$/.test(s.launchNonce)||
  !['llm-proxy','qwen3-embed','planner','executor'].includes(s.role)||s.mainExecutable!=='/usr/local/bin/node'||
  ![s.parentPid,s.parentStartTimeTicks,s.startMs,s.endMs,s.sampleEveryMs,s.deadlineMs].every(n=>Number.isSafeInteger(n)&&n>0)||
  !Number.isSafeInteger(s.episodeIndex)||s.episodeIndex<0||s.startMs>=s.endMs||s.endMs>=s.deadlineMs||s.sampleEveryMs>s.endMs-s.startMs||
  s.healthRequired!==!['planner','executor'].includes(s.role)||![s.mainCmdlineHashes,s.healthCmdlineHashes].every(a=>Array.isArray(a)&&a.every(h=>/^[a-f0-9]{64}$/.test(h)))||
  s.mainCmdlineHashes.length===0||s.healthRequired&&s.healthCmdlineHashes.length===0||!s.healthRequired&&s.healthCmdlineHashes.length!==0)throw Error('DataObservationCollectorInput');
 return collect(s);
}
export function nodeObservationCollectorSource(){
 return `import * as observationCollectorFs from 'node:fs';
import * as observationCollectorCrypto from 'node:crypto';
const collectNodeObservationEpisode=(${Function.prototype.toString.call(observationCollectorFactory)})(observationCollectorFs,observationCollectorCrypto);`;
}
