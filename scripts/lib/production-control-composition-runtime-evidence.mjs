/** Data inspection only. These observations never reconstruct a native actor. */
import {createHash} from 'node:crypto';
import {copyNonrootJson,nonrootHash as hash} from './production-nonroot-contracts.mjs';
import {PRODUCTION_CONTROL_COMPOSITION_RUNTIME_POLICY as P,PRODUCTION_CONTROL_COMPOSITION_RUNTIME_POLICY_HASH as PH,CONTROL_COMPOSITION_RUNTIME_PHASES as PHASES} from './production-control-composition-runtime-policy.mjs';

const need=(v,c='ControlCompositionRuntimeEvidence')=>{if(!v)throw Error(c);};
const exact=(v,k)=>need(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===k.slice().sort().join());
const sha=b=>createHash('sha256').update(b).digest('hex'),hex=v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
export const CONTROL_COMPOSITION_STAT_KEYS=Object.freeze(['dev','ino','mode','uid','gid','nlink','size','ctimeNs','mtimeNs']);
export function compositionRuntimeStat(s){
 const row={};for(const k of CONTROL_COMPOSITION_STAT_KEYS){need(typeof s[k]==='bigint','ControlCompositionRuntimeStatPrecision');row[k]=s[k].toString(10);}return row;
}
export function inspectCompositionRuntimeStat(s){
 exact(s,CONTROL_COMPOSITION_STAT_KEYS);
 for(const k of CONTROL_COMPOSITION_STAT_KEYS)need(typeof s[k]==='string'&&(k.endsWith('Ns')?/^(0|-?[1-9][0-9]*)$/:/^(0|[1-9][0-9]*)$/).test(s[k]),'ControlCompositionRuntimeStatPrecision');
 return s;
}
export function sameCompositionRuntimeStat(a,b){return CONTROL_COMPOSITION_STAT_KEYS.every(k=>typeof a[k]==='bigint'&&a[k]===b[k]);}
export function compositionRuntimeDevice(d){need(typeof d==='bigint'&&d>=0n);return {major:((d>>8n)&0xfffn)|((d>>32n)&0xfffff000n),minor:(d&255n)|((d>>12n)&0xffffff00n)};}
export function parseCompositionRuntimeMaps(bytes){
 need(bytes instanceof Uint8Array&&bytes.length>0&&bytes.length<=P.mapsBytes,'ControlCompositionRuntimeMapsBound');
 const rows=new Map(),text=new TextDecoder('utf-8',{fatal:true}).decode(bytes);need(text.endsWith('\n'),'ControlCompositionRuntimeMaps');
 for(const line of text.slice(0,-1).split('\n')){
  const m=/^([a-f0-9]+)-([a-f0-9]+)\s+([r-][w-][x-][ps])\s+([a-f0-9]+)\s+([a-f0-9]+):([a-f0-9]+)\s+([0-9]+)(?:\s+(.*))?$/.exec(line);
  need(m&&BigInt('0x'+m[1])<BigInt('0x'+m[2]),'ControlCompositionRuntimeMaps');
  const ino=BigInt(m[7]),path=m[8];
  // Exact kernel pseudo-file classification, not a general pathname filter.
  // The caller retains all original map bytes, including these shared rings.
  if(path===P.kernelPseudoFile.name){
   need(ino>0n&&m[3]===P.kernelPseudoFile.permissions&&BigInt('0x'+m[5])===0n,'ControlCompositionRuntimeKernelMapping');continue;
  }
  if(ino===0n)continue;
  need(typeof path==='string'&&path.startsWith('/')&&!path.endsWith(' (deleted)')&&!/[\x00-\x1f\x7f\\]/.test(path),'ControlCompositionRuntimeMappedPath');
  const row={path,major:BigInt('0x'+m[5]).toString(),minor:BigInt('0x'+m[6]).toString(),ino:ino.toString(),executable:m[3][2]==='x'},old=rows.get(path);
  if(old){need(old.major===row.major&&old.minor===row.minor&&old.ino===row.ino,'ControlCompositionRuntimeMappedIdentity');old.executable||=row.executable;}
  else{need(rows.size<P.mappedFilesIncludingNode,'ControlCompositionRuntimeFileCount');rows.set(path,row);}
 }
 return [...rows.values()].sort((a,b)=>a.path<b.path?-1:a.path>b.path?1:0);
}
export function compositionRuntimeFileSetHash(files){return hash(files.map(f=>({path:f.path,roles:f.roles,stat:f.stat})));}
export function compositionRuntimeHashesHash(files){return hash(files.map(f=>({path:f.path,bytesLength:f.bytesLength,sha256:f.sha256})));}
function maps(value){
 exact(value,['sha256','bytesLength','bytesBase64']);need(hex(value.sha256)&&Number.isSafeInteger(value.bytesLength)&&value.bytesLength>0&&value.bytesLength<=P.mapsBytes&&typeof value.bytesBase64==='string'&&value.bytesBase64.length===4*Math.ceil(value.bytesLength/3));
 const raw=Buffer.from(value.bytesBase64,'base64');need(raw.length===value.bytesLength&&raw.toString('base64')===value.bytesBase64&&sha(raw)===value.sha256);return parseCompositionRuntimeMaps(raw);
}
function pass(row,ordinal,initial){
 exact(row,['phase','ordinal','checkedMs','mapsBeforeHash','identitySetHash','hashesHash','mapsAfterHash']);
 need(row.ordinal===ordinal&&row.phase===PHASES[ordinal-1]&&Number.isSafeInteger(row.checkedMs)&&row.checkedMs>=initial.capturedMs&&hex(row.mapsBeforeHash)&&hex(row.mapsAfterHash)&&row.identitySetHash===initial.fileSetHash&&row.hashesHash===initial.hashesHash,'ControlCompositionRuntimePass');
}
export function inspectProductionControlCompositionRuntimeObservation(value,plan,actualMain){
 const v=copyNonrootJson(value);exact(v,['version','kind','initial','checks']);need(v.version===1&&v.kind==='native-control-composition-runtime-evidence'&&plan.version===2);
 const i=v.initial;exact(i,['version','kind','allocationId','planHash','policyHash','actualMainHash','nodeVersion','architecture','files','mapped','maps','fileSetHash','hashesHash','capturedMs']);
 need(i.version===1&&i.kind==='native-control-composition-runtime-observation'&&hex(i.allocationId)&&i.planHash===plan.planHash&&i.policyHash===PH&&i.actualMainHash===hash(actualMain)&&/^24\.[0-9]+\.[0-9]+$/.test(i.nodeVersion)&&P.architectures.includes(i.architecture)&&Number.isSafeInteger(i.capturedMs)&&i.capturedMs>0);
 need(Array.isArray(i.files)&&i.files.length>0&&i.files.length<=P.totalFiles);let size=0;const paths=new Set();
 for(const f of i.files){
  exact(f,['path','roles','stat','sha256','bytesLength']);inspectCompositionRuntimeStat(f.stat);
  need(typeof f.path==='string'&&f.path.startsWith('/')&&!paths.has(f.path)&&hex(f.sha256)&&Number.isSafeInteger(f.bytesLength)&&f.bytesLength>=0&&BigInt(f.stat.size)===BigInt(f.bytesLength)&&BigInt(f.stat.nlink)===1n&&Array.isArray(f.roles)&&f.roles.length>0&&f.roles.every(k=>['node','mapped','entry','toolchain'].includes(k))&&new Set(f.roles).size===f.roles.length);
  paths.add(f.path);size+=f.bytesLength;need(Number.isSafeInteger(size)&&size<=P.runtimeBytes);
  need((BigInt(f.stat.mode)&61440n)===32768n&&(BigInt(f.stat.mode)&18n)===0n,'ControlCompositionRuntimeFile');
 }
 need(i.files.filter(f=>f.roles.includes('node')).length===1);
 for(const k of ['entry','toolchain']){const f=i.files.filter(f=>f.roles.includes(k));need(f.length===1&&f[0].sha256===plan.runtime[k].sha256&&f[0].bytesLength===plan.runtime[k].bytes,'ControlCompositionRuntimeSource');}
 need(hash(i.files.map(f=>f.path))===hash([...paths].sort())&&i.fileSetHash===compositionRuntimeFileSetHash(i.files)&&i.hashesHash===compositionRuntimeHashesHash(i.files));
 exact(i.maps,['before','after']);const before=maps(i.maps.before),after=maps(i.maps.after);need(hash(before)===hash(after)&&hash(before)===hash(i.mapped),'ControlCompositionRuntimeMapChanged');
 for(const row of i.mapped){const f=i.files.find(f=>f.path===row.path&&f.roles.includes('mapped'));need(f,'ControlCompositionRuntimeMappedIdentity');const d=compositionRuntimeDevice(BigInt(f.stat.dev));need(f.stat.ino===row.ino&&d.major.toString()===row.major&&d.minor.toString()===row.minor,'ControlCompositionRuntimeMappedIdentity');}
 need(i.files.filter(f=>f.roles.includes('mapped')).length===i.mapped.length&&i.mapped.length<=P.mappedFilesIncludingNode);
 need(Array.isArray(v.checks)&&v.checks.length===5);let at=i.capturedMs;
 for(const [n,c]of v.checks.entries()){exact(c,['record','maps']);exact(c.maps,['before','after']);pass(c.record,n+1,i);need(c.record.checkedMs>=at);at=c.record.checkedMs;
  need(c.record.mapsBeforeHash===c.maps.before.sha256&&c.record.mapsAfterHash===c.maps.after.sha256&&hash(maps(c.maps.before))===hash(i.mapped)&&hash(maps(c.maps.after))===hash(i.mapped),'ControlCompositionRuntimeMapChanged');}
 return v;
}
export function inspectProductionControlCompositionRuntimeTerminal(value){
 const t=copyNonrootJson(value);exact(t,['version','kind','allocationId','planHash','runtimePolicyHash','observationHash','fileSetHash','hashesHash','passes','cleanupComplete']);
 need(t.version===1&&t.kind==='native-control-composition-runtime-terminal'&&t.cleanupComplete===true&&t.runtimePolicyHash===PH&&['allocationId','planHash','observationHash','fileSetHash','hashesHash'].every(k=>hex(t[k]))&&Array.isArray(t.passes)&&t.passes.length===6);
 need(Buffer.byteLength(JSON.stringify(t))<=P.recheckRecordBytes,'ControlCompositionRuntimeTerminalBound');
 let at=1;for(const [n,row]of t.passes.entries()){pass(row,n+1,{capturedMs:at,fileSetHash:t.fileSetHash,hashesHash:t.hashesHash});at=row.checkedMs;}return t;
}
export function verifyProductionControlCompositionRuntimeTerminal(value,evidence,{capture,job,now}){
 const t=inspectProductionControlCompositionRuntimeTerminal(value),i=evidence.initial;
 need(t.allocationId===i.allocationId&&t.planHash===i.planHash&&t.observationHash===hash(i)&&t.fileSetHash===i.fileSetHash&&t.hashesHash===i.hashesHash&&hash(t.passes.slice(0,5))===hash(evidence.checks.map(c=>c.record)),'ControlCompositionRuntimeTerminalBinding');
 need(t.passes[0].checkedMs>=i.capturedMs&&t.passes[5].checkedMs>=capture.completedMs&&t.passes[5].checkedMs<=Date.parse(job.completed_at)&&Date.parse(job.completed_at)<=now,'ControlCompositionRuntimeTerminalTime');return t;
}
