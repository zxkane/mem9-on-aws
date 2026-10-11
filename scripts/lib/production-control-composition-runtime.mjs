/** The trusted initial GitHub process observes itself under its original
 * SOURCE child. Runtime copies are evidence, never executed or restored. */
import {open,lstat,realpath,mkdir,unlink,rmdir} from 'node:fs/promises';
import {constants} from 'node:fs';
import {join,resolve} from 'node:path';
import {createHash} from 'node:crypto';
import {nonrootHash as hash,copyNonrootJson,inspectNonrootRecord} from './production-nonroot-contracts.mjs';
import {compositionCharge,compositionNeed as need,encodeCompositionJson} from './production-control-composition.mjs';
import {requireProductionControlCompositionAllocation,reserveProductionControlComposition,recordProductionControlComposition,holdProductionControlComposition,productionControlCompositionSnapshot} from './production-control-composition-lifetime.mjs';
import {PRODUCTION_CONTROL_COMPOSITION_RUNTIME_POLICY as P,CONTROL_COMPOSITION_RUNTIME_PHASES as PHASES} from './production-control-composition-runtime-policy.mjs';
import {compositionRuntimeStat,sameCompositionRuntimeStat,compositionRuntimeDevice,parseCompositionRuntimeMaps,
 compositionRuntimeFileSetHash,compositionRuntimeHashesHash,inspectProductionControlCompositionRuntimeTerminal} from './production-control-composition-runtime-evidence.mjs';

const allocations=new WeakMap(),handles=new WeakMap(),sha=b=>createHash('sha256').update(b).digest('hex'),D=4096;
const frozen=v=>{if(v&&typeof v==='object'){Object.values(v).forEach(frozen);Object.freeze(v);}return v;};
const check=s=>{const a=requireProductionControlCompositionAllocation(s.allocation);s.signal?.throwIfAborted();need(!s.closed,'ControlCompositionRuntimeClosed');
 need(process.platform==='linux'&&process.arch===s.architecture&&process.versions.node===s.nodeVersion&&process.versions.node.split('.')[0]==='24'&&
  !process.env.NODE_OPTIONS&&!process.env.LD_PRELOAD&&!process.env.LD_LIBRARY_PATH&&!s.env.NODE_OPTIONS&&!s.env.LD_PRELOAD&&!s.env.LD_LIBRARY_PATH,'ControlCompositionRuntimeEnvironment');return a;};
function charge(s,n,entries=0,cleanup=false){
 const row=compositionCharge({logicalBytes:n,processedEntries:entries}),limit=cleanup?s.plan.runtime.physicalCleanupCharge:s.plan.runtime.normalCharge,key=cleanup?'cleanupUsed':'used';
 need(s[key].logicalBytes+n<=limit.logicalBytes&&s[key].processedEntries+entries<=limit.processedEntries,'ControlCompositionRuntimeCost');
 reserveProductionControlComposition(s.allocation,row,{cleanup});s[key].logicalBytes+=n;s[key].processedEntries+=entries;
}
async function writeAll(fd,b){for(let at=0;at<b.length;){const r=await fd.write(b,at,b.length-at);need(r.bytesWritten>0,'ControlCompositionRuntimeWrite');at+=r.bytesWritten;}}
async function save(s,name,bytes){
 check(s);const path=join(s.directory,name),fd=await open(path,constants.O_CREAT|constants.O_EXCL|constants.O_WRONLY|constants.O_NOFOLLOW,0o600);s.paths.push(path);
 try{await writeAll(fd,bytes);await fd.sync();}finally{await fd.close();}
 const read=await open(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
 try{const before=await read.stat({bigint:true});need(before.isFile()&&before.size===BigInt(bytes.length)&&before.nlink===1n&&(before.mode&511n)===384n,'ControlCompositionRuntimeSaved');
  const b=Buffer.alloc(bytes.length);let at=0;while(at<b.length){check(s);const r=await read.read(b,at,b.length-at,at);need(r.bytesRead>0);at+=r.bytesRead;}
  need(b.equals(bytes)&&sameCompositionRuntimeStat(before,await read.stat({bigint:true}))&&sameCompositionRuntimeStat(before,await lstat(path,{bigint:true})),'ControlCompositionRuntimeSaved');
 }finally{await read.close();}
}
async function maps(s,label){
 check(s);charge(s,8*(P.mapsBytes+1),1);const fd=await open('/proc/self/maps',constants.O_RDONLY|constants.O_NOFOLLOW),raw=s.mapBuffer;let n=0;
 try{while(n<raw.length){check(s);const r=await fd.read(raw,n,raw.length-n,null);if(!r.bytesRead)break;n+=r.bytesRead;}need(n<=P.mapsBytes,'ControlCompositionRuntimeMapsBound');}
 finally{await fd.close();}
 const bytes=raw.subarray(0,n),rows=parseCompositionRuntimeMaps(bytes),record={sha256:sha(bytes),bytesLength:n,bytesBase64:bytes.toString('base64')};
 await save(s,label+'.maps',bytes);return {rows,record};
}
export function inspectProductionControlCompositionRuntimeLengths(files){
 need(Array.isArray(files)&&files.length>0&&files.length<=P.totalFiles,'ControlCompositionRuntimeFileCount');let total=0n;
 for(const row of files){need(typeof row.size==='bigint'&&row.size>=0n,'ControlCompositionRuntimeStatPrecision');total+=row.size;need(total<=BigInt(P.runtimeBytes),'ControlCompositionRuntimeBytes');}return Number(total);
}
async function inventory(s,mapped){
 check(s);const expected=new Map();for(const row of mapped)expected.set(row.path,{path:row.path,roles:['mapped'],mapped:row});
 const node=await realpath(process.execPath);if(!expected.has(node))expected.set(node,{path:node,roles:[]});expected.get(node).roles.push('node');
 need(expected.size<=P.mappedFilesIncludingNode,'ControlCompositionRuntimeFileCount');
 for(const k of ['entry','toolchain']){const path=s[k];if(!expected.has(path))expected.set(path,{path,roles:[]});expected.get(path).roles.push(k);}
 need(expected.size<=P.totalFiles,'ControlCompositionRuntimeFileCount');charge(s,8*expected.size*D);
 const out=[];
 for(const row of [...expected.values()].sort((a,b)=>a.path<b.path?-1:1)){
  check(s);need(await realpath(row.path)===row.path,'ControlCompositionRuntimePath');const stat=await lstat(row.path,{bigint:true});
  need(stat.isFile()&&stat.nlink===1n&&(stat.mode&18n)===0n,'ControlCompositionRuntimeFile');
  if(row.mapped){const dev=compositionRuntimeDevice(stat.dev);need(stat.ino.toString()===row.mapped.ino&&dev.major.toString()===row.mapped.major&&dev.minor.toString()===row.mapped.minor,'ControlCompositionRuntimeMappedIdentity');}
  out.push({...row,stat});
 }
 inspectProductionControlCompositionRuntimeLengths(out.map(r=>r.stat));return out;
}
async function content(s,rows,initial){
 const total=inspectProductionControlCompositionRuntimeLengths(rows.map(r=>r.stat));charge(s,(initial?5:2)*total,rows.length*(initial?2:1));
 if(initial)charge(s,12*rows.length*D);
 const files=[];
 for(const [index,row]of rows.entries()){
  check(s);const old=s.files?.[index];if(old)need(row.path===old.path&&hash(compositionRuntimeStat(row.stat))===hash(old.stat),'ControlCompositionRuntimeChanged');
  const fd=await open(row.path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK),target=join(s.directory,'file-'+index);let retained,digest=createHash('sha256'),at=0,header=false;
  try{
   need(sameCompositionRuntimeStat(row.stat,await fd.stat({bigint:true})),'ControlCompositionRuntimeChanged');
   if(initial){retained=await open(target,constants.O_CREAT|constants.O_EXCL|constants.O_WRONLY|constants.O_NOFOLLOW,0o600);s.paths.push(target);}
   const size=Number(row.stat.size);
   while(at<size){check(s);const r=await fd.read(s.buffer,0,Math.min(s.buffer.length,size-at),at);need(r.bytesRead>0,'ControlCompositionRuntimeTruncated');
    if(!header){header=true;const elf=r.bytesRead>=4&&s.buffer[0]===127&&s.buffer.toString('ascii',1,4)==='ELF';
     if(elf)need(r.bytesRead>=20&&s.buffer[4]===2&&s.buffer[5]===1&&s.buffer.readUInt16LE(18)===(s.architecture==='arm64'?183:62),'ControlCompositionRuntimeElf');
     if(row.roles.includes('node')||row.mapped?.executable)need(elf,'ControlCompositionRuntimeElf');}
    const b=s.buffer.subarray(0,r.bytesRead);digest.update(b);if(retained)await writeAll(retained,b);at+=r.bytesRead;
   }
   need(!row.roles.includes('node')||header,'ControlCompositionRuntimeElf');
   need((await fd.read(s.buffer,0,1,at)).bytesRead===0&&sameCompositionRuntimeStat(row.stat,await fd.stat({bigint:true}))&&sameCompositionRuntimeStat(row.stat,await lstat(row.path,{bigint:true}))&&await realpath(row.path)===row.path,'ControlCompositionRuntimeChanged');
   if(retained)await retained.sync();
  }finally{try{await retained?.close();}finally{await fd.close();}}
  const sha256=digest.digest('hex');if(old)need(sha256===old.sha256,'ControlCompositionRuntimeChanged');
  for(const k of ['entry','toolchain'])if(row.roles.includes(k))need(sha256===s.plan.runtime[k].sha256&&at===s.plan.runtime[k].bytes,'ControlCompositionRuntimeSource');
  if(initial){const copy=await open(target,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
   try{const before=await copy.stat({bigint:true});need(before.isFile()&&before.nlink===1n&&before.size===row.stat.size&&(before.mode&511n)===384n,'ControlCompositionRuntimeCopy');
    const h=createHash('sha256');let n=0;while(n<at){check(s);const r=await copy.read(s.buffer,0,Math.min(s.buffer.length,at-n),n);need(r.bytesRead>0);h.update(s.buffer.subarray(0,r.bytesRead));n+=r.bytesRead;}
    need(h.digest('hex')===sha256&&sameCompositionRuntimeStat(before,await copy.stat({bigint:true}))&&sameCompositionRuntimeStat(before,await lstat(target,{bigint:true})),'ControlCompositionRuntimeCopy');
   }finally{await copy.close();}}
  files.push({path:row.path,roles:row.roles,stat:compositionRuntimeStat(row.stat),sha256,bytesLength:at});
 }
 return files;
}
async function cleanup(s){
 if(s.closed)return;let error;
 try{charge(s,4*(s.paths.length+(s.created?1:0))*D,s.paths.length+(s.created?1:0),true);}catch(e){error=e;}
 for(const path of [...s.paths].reverse())try{await unlink(path);}catch(e){if(e.code!=='ENOENT')error??=e;}
 if(s.created)try{await rmdir(s.directory);}catch(e){if(e.code!=='ENOENT')error??=e;}
 s.closed=true;s.cleanupComplete=!error;if(error)throw Object.assign(Error('ControlCompositionRuntimeCleanup'),{cause:error,cleanupComplete:false});
}
export async function captureProductionControlCompositionRuntime({allocation,actualMain,env,signal}){
 const a=requireProductionControlCompositionAllocation(allocation);need(a.plan.version===2&&!allocations.has(allocation),'ControlCompositionRuntimeAdmission');
 const main=inspectNonrootRecord('ActualMainV1',actualMain),b=a.binding.source;
 for(const k of ['repository','candidateRevision','candidateTree','baseRevision','mainRevision','mainTree','parents','prNumber','workflowPath','workflowSha'])need(hash(main[k])===hash(b[k]),'ControlCompositionRuntimeMain');
 need(main.workflowRun===b.runId&&main.workflowAttempt===b.runAttempt,'ControlCompositionRuntimeMain');
 const s={allocation,plan:a.plan,env,signal,nodeVersion:process.versions.node,architecture:process.arch,paths:[],directory:join(a.directory,'runtime'),created:false,closed:false,cleanupComplete:false,
  used:compositionCharge(),cleanupUsed:compositionCharge(),checks:[],pass:0,entry:null,toolchain:null};allocations.set(allocation,s);
 try{
  const snapshot=productionControlCompositionSnapshot(allocation);need(snapshot.spent.logicalBytes+a.plan.runtime.normalCharge.logicalBytes<=snapshot.normal.logicalBytes&&snapshot.spent.processedEntries+a.plan.runtime.normalCharge.processedEntries<=snapshot.normal.processedEntries,'ControlCompositionRuntimeAdmission');
  recordProductionControlComposition(allocation,'runtime-admitted',{policyHash:a.plan.runtime.policyHash,charge:a.plan.runtime.normalCharge,refund:0});
  charge(s,8*P.streamBytes+(12*21+3)*D);check(s);s.buffer=Buffer.alloc(P.streamBytes);s.mapBuffer=Buffer.alloc(P.mapsBytes+1);
  need(typeof env.GITHUB_WORKSPACE==='string'&&Buffer.byteLength(env.GITHUB_WORKSPACE)<=4096&&resolve(env.GITHUB_WORKSPACE)===env.GITHUB_WORKSPACE,'ControlCompositionRuntimeWorkspace');
  s.entry=await realpath(join(env.GITHUB_WORKSPACE,a.plan.runtime.entry.path));s.toolchain=await realpath(join(env.GITHUB_WORKSPACE,a.plan.runtime.toolchain.path));
  need(s.entry===await realpath(process.argv[1])&&s.entry===join(env.GITHUB_WORKSPACE,a.plan.runtime.entry.path)&&s.toolchain===join(env.GITHUB_WORKSPACE,a.plan.runtime.toolchain.path),'ControlCompositionRuntimeEntry');
  await mkdir(s.directory,{mode:0o700});s.created=true;
  const before=await maps(s,'initial-before'),rows=await inventory(s,before.rows);s.files=await content(s,rows,true);const after=await maps(s,'initial-after');
  need(hash(before.rows)===hash(after.rows),'ControlCompositionRuntimeMapChanged');
  s.initial={version:1,kind:'native-control-composition-runtime-observation',allocationId:a.id,planHash:a.plan.planHash,policyHash:a.plan.runtime.policyHash,actualMainHash:hash(main),
   nodeVersion:s.nodeVersion,architecture:s.architecture,files:s.files,mapped:before.rows,maps:{before:before.record,after:after.record},fileSetHash:compositionRuntimeFileSetHash(s.files),hashesHash:compositionRuntimeHashesHash(s.files),capturedMs:Date.now()};
  charge(s,8*P.manifestBytes,1);await save(s,'initial.json',encodeCompositionJson(s.initial,P.manifestBytes));
  const handle=Object.freeze({kind:'native-control-composition-runtime'});handles.set(handle,s);s.handle=handle;
  recordProductionControlComposition(allocation,'runtime-bound',{observationHash:hash(s.initial),runtimeBytes:s.files.reduce((n,f)=>n+f.bytesLength,0),runtimeFiles:s.files.length,refund:0});return handle;
 }catch(e){holdProductionControlComposition(allocation,e.message);try{await cleanup(s);}catch(clean){throw Object.assign(clean,{operationError:e});}throw Object.assign(e,{cleanupComplete:true});}
}
export function requireProductionControlCompositionRuntime(handle,allocation){const s=handles.get(handle);need(s&&s.allocation===allocation&&s.initial,'ControlCompositionRuntimeCapability');check(s);return frozen(s.initial);}
export function requireBoundProductionControlCompositionRuntime(allocation){const s=allocations.get(allocation);need(s?.handle&&s.initial,'ControlCompositionRuntimeRequired');check(s);}
export async function verifyProductionControlCompositionRuntime(handle,allocation,phase){
 const s=handles.get(handle);need(s&&s.allocation===allocation,'ControlCompositionRuntimeCapability');check(s);need(PHASES[s.pass]===phase,'ControlCompositionRuntimeOrder');const ordinal=++s.pass;
 try{const before=await maps(s,phase+'-before');need(hash(before.rows)===hash(s.initial.mapped),'ControlCompositionRuntimeMapChanged');const rows=await inventory(s,before.rows),files=await content(s,rows,false),after=await maps(s,phase+'-after');
  need(hash(after.rows)===hash(s.initial.mapped)&&hash(files)===hash(s.files),'ControlCompositionRuntimeChanged');
  const record={phase,ordinal,checkedMs:Date.now(),mapsBeforeHash:before.record.sha256,identitySetHash:s.initial.fileSetHash,hashesHash:s.initial.hashesHash,mapsAfterHash:after.record.sha256};
  charge(s,8*P.recheckRecordBytes,1);await save(s,phase+'.json',encodeCompositionJson(record,P.recheckRecordBytes));s.checks.push({record,maps:{before:before.record,after:after.record}});
  recordProductionControlComposition(allocation,'runtime-checked',{phase,pass:ordinal,observationHash:hash(s.initial),runtimeBytes:files.reduce((n,f)=>n+f.bytesLength,0),runtimeFiles:files.length});return frozen(copyNonrootJson(record));
 }catch(e){holdProductionControlComposition(allocation,e.message);throw e;}
}
export function productionControlCompositionRuntimeCapture(allocation){const s=allocations.get(allocation);need(s?.initial&&s.pass===5&&s.checks.length===5,'ControlCompositionRuntimeCaptureOrder');check(s);return frozen(copyNonrootJson({version:1,kind:'native-control-composition-runtime-evidence',initial:s.initial,checks:s.checks}));}
export async function closeProductionControlCompositionRuntime(handle,allocation){const s=handles.get(handle);need(s&&s.allocation===allocation,'ControlCompositionRuntimeCapability');await cleanup(s);}
/** Controller cleanup uses the original allocation, even if a foreign or
 * missing caller-supplied handle caused admission to fail. No handle is minted. */
export async function closeProductionControlCompositionRuntimeAllocation(allocation){productionControlCompositionSnapshot(allocation);const s=allocations.get(allocation);if(s)await cleanup(s);}
export function assertProductionControlCompositionRuntimeClosed(allocation,{success}){const s=allocations.get(allocation);need(!s||s.closed&&s.cleanupComplete,'ControlCompositionRuntimeCleanup');if(success)need(s?.pass===6&&s.checks.length===6,'ControlCompositionRuntimeIncomplete');}
export function productionControlCompositionRuntimeTerminal(handle,allocation){
 const s=handles.get(handle),snapshot=productionControlCompositionSnapshot(allocation);need(s&&s.allocation===allocation&&s.closed&&s.cleanupComplete&&s.pass===6&&s.checks.length===6&&snapshot.closed&&!snapshot.held,'ControlCompositionRuntimeTerminal');
 return inspectProductionControlCompositionRuntimeTerminal({version:1,kind:'native-control-composition-runtime-terminal',allocationId:s.initial.allocationId,planHash:s.plan.planHash,runtimePolicyHash:s.plan.runtime.policyHash,
  observationHash:hash(s.initial),fileSetHash:s.initial.fileSetHash,hashesHash:s.initial.hashesHash,passes:s.checks.map(c=>c.record),cleanupComplete:true});
}
