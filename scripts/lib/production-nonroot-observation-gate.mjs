/** Shared kernel/file gate for both observation and normal launch branches.
 * The source is serialized only from these fixed functions. No caller-selected
 * executable code, read callback, environment dump or provider is accepted. */
import {copyNonrootJson} from './production-nonroot-contracts.mjs';
import * as nodeGateFs from 'node:fs';
import * as nodeGateCrypto from 'node:crypto';

// Keep this function self-contained: the same source runs in the fixed inline
// coordinator and verifies retained status during independent replay.
export function inspectObservationKernelStatus(status){
 const need=v=>{if(!v)throw Error('DataObservationSecurityGate');};
 need(typeof status==='string'&&status.length<=65536);
 const fields=new Map();
 for(const line of status.trimEnd().split('\n')){
  const at=line.indexOf(':');need(at>0);const name=line.slice(0,at);
  need(!fields.has(name));fields.set(name,line.slice(at+1).trim());
 }
 const ids=(name,count)=>{
  const s=fields.get(name);need(typeof s==='string'&&(count===null&&s===''||/^[0-9]+(?:\s+[0-9]+)*$/.test(s)));
  const values=s?s.split(/\s+/).map(Number):[];
  need((count===null||values.length===count)&&values.every(n=>n===1000));return values;
 };
 const uid=ids('Uid',4),gid=ids('Gid',4),groups=ids('Groups',null);
 for(const name of ['CapInh','CapPrm','CapEff','CapBnd','CapAmb'])need(fields.get(name)==='0000000000000000');
 need(fields.get('NoNewPrivs')==='1');
 return {uid,gid,groups,noNewPrivs:1};
}

const safePath=p=>typeof p==='string'&&p.length<=4096&&/^\/[A-Za-z0-9_.+/-]+$/.test(p)&&
 !p.includes('//')&&!p.split('/').some(x=>x==='.'||x==='..');
const exact=(v,keys)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).length===keys.length&&keys.every(k=>Object.hasOwn(v,k));

/** Input rows come from the original independent image/primitive verification.
 * This compiler checks their closed representation, not their provenance. */
export function inspectObservationGateFiles(value){
 const files=copyNonrootJson(value);const seen=new Set();
 if(!Array.isArray(files)||files.length===0||files.length>256)throw Error('DataObservationGateFiles');
 for(const f of files){
  if(!exact(f,['path','resolvedPath','sha256','size','mode','uid','gid'])||!safePath(f.path)||!safePath(f.resolvedPath)||
   seen.has(f.path)||!/^([a-f0-9]{64})$/.test(f.sha256)||!Number.isSafeInteger(f.size)||f.size<1||f.size>201326592||
   !Number.isSafeInteger(f.mode)||f.mode<0||f.mode>4095||(f.mode&0o6022)!==0||f.uid!==0||f.gid!==0)throw Error('DataObservationGateFiles');
  seen.add(f.path);
 }
 return files;
}

/** The fixed Node coordinator invokes this against actual local kernel/file
 * bytes. Its arguments are generated and bound before registration/funding. */
function nodeCommonGateFactory(fs,crypto,inspectStatus){
 return async function fixedNodeObservationCommonGate(files){
 const need=v=>{if(!v)throw Error('DataObservationSecurityGate');};
 need(process.arch==='arm64'&&/^v24\.[0-9]+\.[0-9]+$/.test(process.version));
 // The generator embeds the already validated fixed rows, not a runtime map
 // supplied through environment or a callback.
 let readBytes=0;
 const maximumReadBytes=files.reduce((n,f)=>n+f.size+1,0)+2*65537+262145;
 need(Number.isSafeInteger(maximumReadBytes));
 const chargedRead=(fd,buffer)=>{
  need(readBytes+buffer.length<=maximumReadBytes);
  const n=fs.readSync(fd,buffer);readBytes+=n;return n;
 };
 const small=(path,cap)=>{
  const fd=fs.openSync(path,fs.constants.O_RDONLY|fs.constants.O_NONBLOCK);
  try{
   const parts=[];let size=0;
   while(size<=cap){const b=Buffer.alloc(Math.min(65536,cap+1-size)),n=chargedRead(fd,b);if(!n)break;size+=n;need(size<=cap);parts.push(b.subarray(0,n));}
   return Buffer.concat(parts,size);
  }finally{fs.closeSync(fd);}
 };
 const identity=inspectStatus(small('/proc/self/status',65536).toString('utf8'));
 const uint=v=>{need(typeof v==='bigint'?v>=0n:Number.isSafeInteger(v)&&v>=0);return BigInt(v);};
 const stamp=s=>[s.dev,s.ino,s.size,s.mode,s.uid,s.gid,s.mtimeNs??s.mtimeMs,s.ctimeNs??s.ctimeMs].join(':');
 const held=new Set(),verified=new Map(),openedFiles=[],observations=[];
 const openHeld=path=>{const fd=fs.openSync(path,fs.constants.O_RDONLY|fs.constants.O_NONBLOCK);held.add(fd);return fd;};
 try{
 const executablePath=fs.realpathSync('/proc/self/exe');need(executablePath==='/usr/local/bin/node');
 const executableFd=openHeld('/proc/self/exe'),executableBefore=fs.fstatSync(executableFd,{bigint:true});
 for(const f of files){
  const resolved=fs.realpathSync(f.path);need(resolved===f.resolvedPath);
  const fd=openHeld(f.path);
   const before=fs.fstatSync(fd,{bigint:true});need(before.isFile()&&uint(before.size)===BigInt(f.size)&&(uint(before.mode)&4095n)===BigInt(f.mode)&&uint(before.uid)===BigInt(f.uid)&&uint(before.gid)===BigInt(f.gid));
   const digest=crypto.createHash('sha256');let size=0;
   while(size<=f.size){const b=Buffer.alloc(Math.min(65536,f.size+1-size)),n=chargedRead(fd,b);if(!n)break;size+=n;need(size<=f.size);digest.update(b.subarray(0,n));}
   need(size===f.size&&digest.digest('hex')===f.sha256&&stamp(before)===stamp(fs.fstatSync(fd,{bigint:true}))&&fs.realpathSync(f.path)===resolved);
   need(stamp(before)===stamp(fs.statSync(f.path,{bigint:true})));
   if(verified.has(resolved))need(stamp(verified.get(resolved).before)===stamp(before));
   const file={fd,before,path:f.path,resolved};verified.set(resolved,file);openedFiles.push(file);
   observations.push({path:f.path,resolvedPath:resolved,sha256:f.sha256,bytes:f.size});
 }
 const interpreter=verified.get(executablePath);
 need(interpreter&&stamp(interpreter.before)===stamp(executableBefore));
 // Keep each verified inode open through maps validation. Path membership
 // alone cannot bind a mapped, renamed or replaced file to the bytes hashed.
 const mapped=small('/proc/self/maps',262144).toString('utf8').split('\n').filter(Boolean);
 need(mapped.length>0);let interpreterExecutable=false;
 for(const line of mapped){
  const m=/^([a-f0-9]{1,16})-([a-f0-9]{1,16})\s+([r-][w-][x-][ps])\s+([a-f0-9]{1,16})\s+([a-f0-9]{1,8}):([a-f0-9]{1,8})\s+([0-9]{1,20})(?:\s+(.*))?$/.exec(line);need(m);
  need(BigInt('0x'+m[1])<BigInt('0x'+m[2]));
  const path=m[8]??'',inode=BigInt(m[7]);need(inode<=0xffffffffffffffffn);
  if(path==='anon_inode:[io_uring]'){
   need(m[3]==='rw-s'&&BigInt('0x'+m[5])===0n&&inode>0n);continue;
  }
  if(!path.startsWith('/')){need(path===''||/^\[[^\]\r\n]+\]$/.test(path));continue;}
  const file=verified.get(path);need(file&&inode>0n&&uint(file.before.ino)===inode);
  const major=BigInt('0x'+m[5]),minor=BigInt('0x'+m[6]);
  // Linux dev_t encoding (including high major/minor bits), without lossy
  // Number conversion of either the device or the mapped inode.
  const device=((major&0xfffn)<<8n)|((major&0xfffff000n)<<32n)|(minor&0xffn)|((minor&0xffffff00n)<<12n);
  need(uint(file.before.dev)===device);
  if(path===executablePath&&m[3][2]==='x')interpreterExecutable=true;
 }
 need(interpreterExecutable);
 for(const f of openedFiles){
  need(stamp(f.before)===stamp(fs.fstatSync(f.fd,{bigint:true}))&&stamp(f.before)===stamp(fs.statSync(f.path,{bigint:true}))&&fs.realpathSync(f.path)===f.resolved);
 }
 need(stamp(executableBefore)===stamp(fs.fstatSync(executableFd,{bigint:true}))&&fs.realpathSync('/proc/self/exe')===executablePath);
 inspectStatus(small('/proc/self/status',65536).toString('utf8'));
 return {identity,files:observations,readBytes};
 }finally{
  let failure;for(const fd of held)try{fs.closeSync(fd);}catch(e){failure??=e;}if(failure)throw failure;
 }
 };
}
const fixedNodeObservationCommonGate=nodeCommonGateFactory(nodeGateFs,nodeGateCrypto,inspectObservationKernelStatus);

export function runNodeObservationCommonGate(files){
 return fixedNodeObservationCommonGate(inspectObservationGateFiles(files));
}

export function nodeObservationCommonGateSource(){
 return `import * as observationGateFs from 'node:fs';
import * as observationGateCrypto from 'node:crypto';
const fixedNodeObservationCommonGate=(${Function.prototype.toString.call(nodeCommonGateFactory)})(observationGateFs,observationGateCrypto,(${Function.prototype.toString.call(inspectObservationKernelStatus)}));`;
}
