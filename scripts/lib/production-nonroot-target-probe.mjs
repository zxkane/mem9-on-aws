import {need,sha} from './ci-smoke-acquisition-format.mjs';
import {nonrootHash as hash} from './production-nonroot-contracts.mjs';
import {TARGET_BUSYBOX_SOURCE,decodeBusyboxSample} from './production-nonroot-target-busybox.mjs';
export {TARGET_BUSYBOX_SOURCE} from './production-nonroot-target-busybox.mjs';

/** Serialized only as this fixed reviewed program. It reads proc/file bytes;
 * it never reads environment, memory, credentials, DB state, or writes files. */
async function observe(spec){
 const fs=await import('node:fs'),crypto=await import('node:crypto');
 const fail=()=>{throw Error('TargetProbeRejected');},need=v=>{if(!v)fail();},digest=b=>crypto.createHash('sha256').update(b).digest('hex');
 let used=0;const cache=new Map(),held=[];
 const charge=n=>{used+=n;need(used<=spec.readBytes&&Date.now()<spec.deadlineMs);};
 const read=(path,cap)=>{const fd=fs.openSync(path,fs.constants.O_RDONLY|fs.constants.O_NONBLOCK);try{const chunks=[];let n=0;for(;;){const b=Buffer.alloc(Math.min(65536,cap+1-n));const count=fs.readSync(fd,b);charge(count);if(!count)break;n+=count;need(n<=cap);chunks.push(b.subarray(0,count));}return Buffer.concat(chunks,n);}finally{fs.closeSync(fd);}};
 const executable=pid=>{
  const path='/proc/'+pid+'/exe',resolved=fs.readlinkSync(path);charge(Buffer.byteLength(resolved));need(resolved.startsWith('/')&&!resolved.endsWith(' (deleted)'));
  const fd=fs.openSync(path,fs.constants.O_RDONLY|fs.constants.O_NONBLOCK),before=fs.fstatSync(fd);need(before.isFile()&&before.size<=192*1048576);
  const stamp=s=>[s.dev,s.ino,s.size,s.mtimeMs,s.ctimeMs,s.mode,s.uid,s.gid].join('/'),key=stamp(before);let value=cache.get(key);
  if(!value){const h=crypto.createHash('sha256');let n=0;for(;;){const b=Buffer.alloc(Math.min(65536,before.size+1-n)),count=fs.readSync(fd,b);charge(count);if(!count)break;n+=count;need(n<=before.size);h.update(b.subarray(0,count));}need(n===before.size&&stamp(fs.fstatSync(fd))===key);value={sha256:h.digest('hex'),stamp:key};cache.set(key,value);held.push(fd);}else{need(stamp(fs.fstatSync(fd))===value.stamp);fs.closeSync(fd);}
  return {path:resolved,sha256:value.sha256,mode:before.mode&4095,uid:before.uid,gid:before.gid};
 };
 const proc=pid=>{
  const base='/proc/'+pid,stat=read(base+'/stat',4096).toString(),rest=stat.slice(stat.lastIndexOf(')')+2).split(' '),startTimeTicks=Number(rest[19]),status=Object.fromEntries(read(base+'/status',65536).toString().trim().split('\n').map(line=>{const at=line.indexOf(':');return [line.slice(0,at),line.slice(at+1).trim()];}));
  const cmd=read(base+'/cmdline',16384),exe=executable(pid),again=read(base+'/stat',4096).toString().split(') ').at(-1).split(' ');need(Number(again[19])===startTimeTicks&&digest(read(base+'/cmdline',16384))===digest(cmd)&&fs.readlinkSync(base+'/exe')===exe.path);
  return {pid,ppid:Number(rest[1]),startTimeTicks,executablePath:exe.path,executableDigest:'sha256:'+exe.sha256,file:{mode:exe.mode,uid:exe.uid,gid:exe.gid},cmdlineHash:digest(cmd),uid:status.Uid.split(/\s+/).map(Number),gid:status.Gid.split(/\s+/).map(Number),groups:status.Groups.split(/\s+/).filter(Boolean).map(Number),noNewPrivs:Number(status.NoNewPrivs),...Object.fromEntries(['Inh','Prm','Eff','Bnd','Amb'].map(k=>['cap'+k,status['Cap'+k]]))};
 };
 const ids=()=>{const names=fs.readdirSync('/proc').filter(n=>/^[1-9][0-9]*$/.test(n));charge(names.reduce((n,v)=>n+v.length+1,0));need(names.length<=128);return names.map(Number).sort((a,b)=>a-b);};
 const startedMs=Date.now(),initial=ids().map(proc);let health,healthObservedMs;
 try{
  // Observe an actual scheduled health process; no extra unmetered health
  // command or network request is launched by the sampler.
  for(let i=0;i<30000&&Date.now()<spec.deadlineMs;i++){
   for(const pid of ids()){
    if(pid===process.pid)continue;
    try{const cmd=read('/proc/'+pid+'/cmdline',16384);if(spec.healthCmdlineHashes.includes(digest(cmd))){const row=proc(pid);if(row.uid.every(n=>n===1000)&&row.noNewPrivs===1){health=row;healthObservedMs=Date.now();break;}}}catch(e){if(!['ENOENT','ESRCH'].includes(e.code))throw e;}
   }
   if(health)break;await new Promise(resolve=>setTimeout(resolve,1));
  }
  need(health);const final=ids().map(proc),completedMs=Date.now();
  const result={version:1,kind:'native-target-proc-sample',nonce:spec.nonce,probePid:process.pid,startedMs,completedMs,initial,final,health,healthObservedMs,readBytes:used};
  const raw=JSON.stringify(result);need(Buffer.byteLength(raw)<=1048576);process.stdout.write(raw+'\n');
 }finally{for(const fd of held)fs.closeSync(fd);}
}
const quote=s=>"'"+s.replaceAll("'","'\"'\"'")+"'";
export const TARGET_PROBE_SOURCE=observe.toString();
export const TARGET_PROBE_HASH=hash({node:sha(TARGET_PROBE_SOURCE),busybox:sha(TARGET_BUSYBOX_SOURCE)});
export function targetProbeRuntime(launch){
 need(['mnemo-server','qwen3-embed','llm-proxy'].includes(launch.containerName),'TargetProbeComponent');
 return launch.containerName==='mnemo-server'?'busybox':'node';
}
export function decodeTargetProbeSample(raw,launch){
 if(targetProbeRuntime(launch)==='busybox')return decodeBusyboxSample(raw);
 need(raw.version===1&&raw.kind==='native-target-proc-sample','TargetProbeRuntime');return raw;
}
export function targetHealthArgv(launch){
 need(launch.healthLaunch.kind==='fixed-health-nnp','TargetHealthRequired');const h=launch.healthLaunch.after,values=[];
 if(h[0]==='CMD'){
  need(h[1]===launch.prefix[0]&&h[2]==='--no-new-privs'&&h[3]==='--','TargetHealthPrefix');values.push(h.slice(4));if(h[4]==='node')values.push(['/usr/local/bin/node',...h.slice(5)]);
 }else{
  need(h[0]==='CMD-SHELL'&&h.length===2,'TargetHealthCommand');
  // This is the fixed command produced by dataLaunchPolicy, not an arbitrary
  // shell expression accepted from a receipt.
  const old=launch.healthLaunch.before;need(old[0]==='CMD-SHELL'&&old.length===2,'TargetHealthCommand');values.push(['/bin/sh','-c',old[1]],['sh','-c',old[1]]);
 }
 return values;
}
export const targetCmdlineHash=argv=>sha(Buffer.from(argv.join('\0')+'\0'));
export function createTargetProbe({launch,paths,nonce,deadlineMs}){
 need(/^[a-f0-9]{64}$/.test(nonce)&&Number.isSafeInteger(deadlineMs),'TargetProbeInput');
 const runtime=targetProbeRuntime(launch),tools=runtime==='busybox'?['/bin/busybox']:['/usr/local/bin/node','/usr/bin/env'];
 need(Array.isArray(paths),'TargetProbeTool');
 for(const path of tools){const f=paths.filter(f=>'/'+f.path.replace(/^\//,'')===path);need(f.length===1&&f[0].type==='file'&&f[0].uid===0&&Number.isInteger(f[0].mode)&&(f[0].mode&0o022)===0&&(f[0].mode&0o111)!==0&&/^[a-f0-9]{64}$/.test(f[0].content?.sha256),'TargetProbeTool');}
 const healthArgv=targetHealthArgv(launch),spec={nonce,deadlineMs,readBytes:256*1048576,healthCmdlineHashes:healthArgv.map(targetCmdlineHash)},program=`(${TARGET_PROBE_SOURCE})(${JSON.stringify(spec)}).catch(()=>{process.stderr.write('TargetProbeRejected\\n');process.exitCode=1;});`;
 const shell=`nonce=${quote(nonce)}\ndeadline=${deadlineMs}\nhealthHex=${quote(healthArgv.map(argv=>Buffer.from(argv.join('\0')+'\0').toString('hex')).join(' '))}\n${TARGET_BUSYBOX_SOURCE}`;
 const command=runtime==='busybox'?'/bin/busybox env -i PATH=/bin:/usr/bin /bin/busybox sh -c '+quote(shell):'/usr/bin/env -i PATH=/usr/local/bin:/usr/bin:/bin /usr/local/bin/node --input-type=module -e '+quote(program);
 need(Buffer.byteLength(command)<=15000,'TargetProbeCommandCap');return Object.freeze({command,commandHash:sha(command),spec,healthArgv,runtime,collectorCodeHash:TARGET_PROBE_HASH,healthCommandHash:hash(launch.healthLaunch.after)});
}
