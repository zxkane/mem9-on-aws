/** Original pure DATA prerequisite plan/output checks. No collector, Docker,
 * credential source, filesystem brand or execution handle is created here. */
import {posix} from 'node:path';
import {createHash} from 'node:crypto';
import {nonrootHash as hash} from './production-nonroot-contracts.mjs';
import {DATA_PROBE_HASH,NATIVE_SHA256,ORIGINAL_PROBE_SHA256,dataProbeArguments} from './production-nonroot-observer-primitive-source.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');
const need=(v,c='DataPrimitiveRejected')=>{if(!v)throw Object.assign(Error(c),{code:c,held:true});};
const same=(a,b,c)=>need(hash(a)===hash(b),c);
const caps=['CapInh','CapPrm','CapEff','CapBnd','CapAmb'];
const exact=(v,keys)=>need(v&&Object.keys(v).sort().join()===keys.slice().sort().join(),'DataPrimitiveFields');
const safe=p=>typeof p==='string'&&/^\/[A-Za-z0-9_./+-]+$/.test(p)&&posix.normalize(p)===p&&p.length<=4096;
const getBytes=s=>{need(typeof s==='string'&&s.length<=90000&&/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(s),'DataProbeEncoding');const b=Buffer.from(s,'base64');need(b.length<=65536&&b.toString('base64')===s,'DataProbeEncoding');return b;};

/** Pure preparation only. The live entry below creates getFile from the
 * ORIGINAL filesystem handle; callers cannot supply this map as authority. */
export function compileDataProbePlan({component,image,config,entries,getFile}){
 need(['mnemo-server','llm-proxy','qwen3-embed'].includes(component),'DataProbeComponent');
 need(config.architecture==='arm64'&&config.os==='linux'&&!Object.keys(config.config?.Volumes??{}).length,'DataProbeImageConfig');
 const flavour=component==='mnemo-server'?'busybox':'glibc',prefix=flavour==='busybox'?'/bin/setpriv':'/usr/bin/setpriv',loader=flavour==='busybox'?'/lib/ld-musl-aarch64.so.1':'/lib/ld-linux-aarch64.so.1';
 const files=new Map(),add=path=>{
  need(safe(path),'DataProbeFilePath');if(files.has(path))return files.get(path);const f=getFile(path);
  need(f.type==='file'&&f.uid===0&&f.gid===0&&(f.mode&0o6022)===0&&f.privilegeAttributes.length===0,'DataProbeFilePrivilege');
  for(const p of f.parents)need(p.implicit!==true&&p.uid===0&&p.gid===0&&!p.privilegeAttributes.length&&(p.type==='symlink'||(p.mode&0o022)===0),'DataProbeParentPrivilege');
  files.set(path,f);return f;
 };
 const primitive=add(prefix);need(primitive.mode===0o755,'DataProbePrimitiveMode');
 for(const p of ['/bin/sh',loader,...(flavour==='busybox'?['/bin/busybox']:['/usr/local/bin/node',...['base64','head','readlink','sha256sum','stat','chmod','rm'].map(n=>'/usr/bin/'+n)])])add(p);
 // The primitive's mapped libraries are discovered by the real loader. Their
 // original filesystem metadata is checked below, never a guessed empty list.
 const candidates=entries.filter(e=>e.type==='file'&&/^(?:usr\/)?lib\/(?:aarch64-linux-gnu\/)?[^/]+\.so(?:\.[0-9.]+)?$/.test(e.path));
 need(candidates.length>0&&candidates.length<=128,'DataProbeLibraryBound');
 need(!entries.some(e=>e.path==='etc/ld.so.preload'),'DataProbeLoaderPreload');
 for(const e of config.config?.Env??[])need(typeof e==='string'&&!/^(?:LD_|NODE_OPTIONS=)/.test(e),'DataProbeImageEnvironment');
 const plan={component,image,flavour,prefix,loader,primitive,files:[...files.values()],libraryCandidates:candidates.map(e=>({path:'/'+e.path,sha256:e.content.sha256,size:e.content.size})),sourceOnly:true};
 const args=dataProbeArguments(plan),argumentBytes=Buffer.byteLength(JSON.stringify(args));
 need(argumentBytes<=65536&&plan.files.length<=16,'DataProbeProgramBound');
 // Bounded explicit file reads, small proc/loader records, wire capture and
 // archive encoding. This is a charge request, not an allowance or a refund.
 const fileBytes=plan.files.reduce((n,f)=>n+f.size,0),libraryBytes=candidates.reduce((n,f)=>n+f.content.size,0);
 plan.work={logicalBytes:8*(fileBytes+libraryBytes)+32*65536+8*1048576+4*argumentBytes,uncompressedBytes:0,processedEntries:0,httpBodyBytes:0,ecrRequests:0};
 return plan;
}

function proc(row,plan){
 need(row.length===6&&['before','after','child','node','final'].includes(row[1]),'DataProbeProcessRow');const pid=Number(row[2]);need(Number.isSafeInteger(pid)&&pid>0,'DataProbePid');
 const text=getBytes(row[3]).toString('utf8'),values=new Map();for(const line of text.trim().split('\n')){const at=line.indexOf(':');need(at>0&&!values.has(line.slice(0,at)),'DataProbeStatus');values.set(line.slice(0,at),line.slice(at+1).trim());}
 const stat=getBytes(row[4]).toString('utf8');need(stat.startsWith(pid+' (')&&stat.includes(') '),'DataProbeStat');const fields=stat.slice(stat.lastIndexOf(') ')+2).trim().split(/\s+/),ppid=Number(fields[1]),startTimeTicks=Number(fields[19]);
 need(Number.isSafeInteger(ppid)&&ppid>=0&&Number.isSafeInteger(startTimeTicks)&&startTimeTicks>0,'DataProbeStat');
 const ids=k=>{const s=values.get(k);need(typeof s==='string'&&/^(?:\d+(?:\s+\d+)*)?$/.test(s),'DataProbeIds');return s?s.split(/\s+/).map(Number):[];};
 const uid=ids('Uid'),gid=ids('Gid'),groups=ids('Groups');need(uid.length===4&&gid.length===4&&[...uid,...gid,...groups].every(n=>n===1000),'DataProbeIdentity');
 need(caps.every(k=>values.get(k)==='0000000000000000'),'DataProbeCapabilities');const noNewPrivs=Number(values.get('NoNewPrivs'));need(noNewPrivs===(row[1]==='before'?0:1),'DataProbeNoNewPrivs');
 const wanted=plan.files.find(f=>f.path===(row[1]==='node'?'/usr/local/bin/node':'/bin/sh'));
 need(wanted&&row[5]===wanted.resolvedPath,'DataProbeExecutable');
 return {phase:row[1],pid,ppid,startTimeTicks,executablePath:row[5],executableSha256:wanted.sha256,uid,gid,groups,noNewPrivs,...Object.fromEntries(caps.map(k=>[k,values.get(k)]))};
}

/** Validate raw output against a prepared source view. This pure function
 * issues no native handle; only the actual lifecycle below can do that. */
export function inspectDataProbeOutput(raw,plan,{getFile}){
 need(typeof raw==='string'&&Buffer.byteLength(raw)<=1048576&&!raw.includes('\r'),'DataProbeOutputBound');
 const rows=raw.trimEnd().split('\n').map(l=>l.split('|')),processes=rows.filter(r=>r[0]==='P').map(r=>proc(r,plan));
 const phases=plan.flavour==='glibc'?['before','after','child','node','final']:['before','after','child','final'];same(processes.map(p=>p.phase),phases,'DataProbeProcessCoverage');
 const [before,parent,child]=processes,final=processes.at(-1);
 need(before.pid===parent.pid&&before.startTimeTicks===parent.startTimeTicks&&before.ppid===parent.ppid,'DataProbePrefixContinuity');same({...parent,phase:'final'},final,'DataProbeProcessChanged');
 for(const p of processes.filter(p=>['child','node'].includes(p.phase)))need(p.ppid===parent.pid&&p.pid!==parent.pid,'DataProbeInheritance');
 const kernel=rows.filter(r=>r[0]==='K');need(kernel.length===1&&kernel[0].length===2,'DataProbeKernelRow');const binary=getBytes(kernel[0][1]);need(binary.length===112,'DataProbeKernelSize');const results=Array.from({length:14},(_,i)=>Number(binary.readBigInt64LE(i*8)));same(results,[1,1000,1000,1000,1000,-22,1,-1,-1,1000,1000,1000,1000,1],'DataProbeKernelChecks');
 const fileRows=rows.filter(r=>r[0]==='F');need(fileRows.length===plan.files.length,'DataProbeFileCoverage');
 const seen=new Set();for(const r of fileRows){need(r.length===5&&!seen.has(r[1]),'DataProbeFileRow');seen.add(r[1]);const f=plan.files.find(f=>f.path===r[1]);need(f&&r[2]===f.resolvedPath&&r[3]===f.sha256,'DataProbeFileBinding');const m=r[4].split(':');need(m.length===8&&m.slice(0,3).every(x=>/^\d+$/.test(x))&&/^[a-f0-9]+$/.test(m[3]),'DataProbeFileMetadata');const mode=parseInt(m[3],16);need(Number(m[2])===f.size&&(mode&0o170000)===0o100000&&(mode&0o7777)===f.mode&&Number(m[4])===f.uid&&Number(m[5])===f.gid,'DataProbeFileMetadata');}
 const libraries={},loaderRows=rows.filter(r=>r[0]==='L'),targets=[plan.prefix,'/bin/sh',...(plan.flavour==='glibc'?['/usr/local/bin/node']:[])];same(loaderRows.map(r=>r[1]),targets,'DataProbeLoaderCoverage');
 for(const r of loaderRows){need(r.length===3,'DataProbeLoaderRow');const files=new Map();
  for(const line of getBytes(r[2]).toString('utf8').trim().split('\n')){
   if(/^\s*linux-vdso\.so\.1 \(0x[a-f0-9]+\)$/.test(line))continue;
   const m=/^\s*(?:(\S+) => )?(\/[^\s]+) \((?:0x)?[a-f0-9]+\)$/.exec(line);need(m&&safe(m[2]),'DataProbeLoaderOutput');const f=getFile(m[2]);
   need(f.type==='file'&&f.uid===0&&f.gid===0&&(f.mode&0o6022)===0&&!f.privilegeAttributes.length&&plan.libraryCandidates.some(c=>c.path===f.resolvedPath&&c.sha256===f.sha256),'DataProbeLibraryBinding');files.set(f.resolvedPath,{path:f.resolvedPath,sha256:f.sha256});
  }
  need(files.size>0&&files.size<=64,'DataProbeLibraryCoverage');libraries[r[1]]={files:[...files.values()].sort((a,b)=>a.path.localeCompare(b.path))};
 }
 const maps=rows.filter(r=>r[0]==='M');need(maps.length===1&&maps[0].length===2,'DataProbeMaps');const allowed=new Set([plan.files.find(f=>f.path==='/bin/sh').resolvedPath,...libraries['/bin/sh'].files.map(f=>f.path)]);
 for(const line of getBytes(maps[0][1]).toString('utf8').trim().split('\n')){const m=/^\S+\s+\S+\s+\S+\s+\S+\s+\S+(?:\s+(.+))?$/.exec(line.trimEnd());need(m,'DataProbeMapRow');if(m[1]&&!m[1].startsWith('['))need(allowed.has(m[1]),'DataProbeMappedFile');}
 need(rows.length===processes.length+fileRows.length+loaderRows.length+2,'DataProbeUnexpectedRow');
 return {processes,kernel:results,libraries,rawHash:sha(raw),collectorCodeHash:DATA_PROBE_HASH,nativeProbeHash:NATIVE_SHA256,originalProbeSourceHash:ORIGINAL_PROBE_SHA256};
}
