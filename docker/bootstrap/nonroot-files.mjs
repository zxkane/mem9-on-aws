import {openSync,closeSync,fstatSync,readFileSync,lstatSync,readlinkSync,constants} from 'node:fs';
import {createHash} from 'node:crypto';
import {dirname,resolve} from 'node:path';
import {Buffer} from 'node:buffer';
import {parseGuardJson} from './nonroot-identity.mjs';

const fail=()=>{throw Error('NonrootArtifact');};
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const allowed=path=>path==='/usr/local/bin/node'||path.startsWith('/bootstrap/')||path.startsWith('/carrier/');
const exact=(object,keys)=>object&&typeof object==='object'&&!Array.isArray(object)&&Object.keys(object).sort().join()===keys.toSorted().join();

function immutablePath(path){
 if(typeof path!=='string'||path.length>4096||!allowed(path)||resolve(path)!==path)fail();
 // Check every component of every link expansion. Checking only the original
 // name and realpath skips a writable intermediate link with a safe endpoint.
 let pending=path.slice(1).split('/'),current='/',links=0,steps=0;
 const check=stat=>{
  if(stat.uid!==0||stat.gid!==0||!stat.isSymbolicLink()&&(stat.mode&0o7022)!==0)fail();
  if(stat.isDirectory()&&(stat.mode&0o005)!==0o005)fail();
 };
 check(lstatSync('/'));
 while(pending.length){
  if(++steps>512)fail();
  current=resolve(current,pending.shift());
  const stat=lstatSync(current);check(stat);
  if(stat.isSymbolicLink()){
   if(++links>40)fail();
   const target=readlinkSync(current);
   if(!target||target.length>4096)fail();
   // Preserve '..' until preceding symlinks have been resolved, as the kernel
   // does. Lexical normalization here could omit another intermediate hop.
   pending=[...target.split('/').filter(Boolean),...pending];
   current=target.startsWith('/')?'/':dirname(current);
  }else if(pending.length?!stat.isDirectory():!stat.isFile())fail();
 }
 if(!allowed(current))fail();return current;
}

/** All paths originate in the image's fixed root-owned manifest. No caller
 * supplied path, URL, package resolver or filesystem write is admitted. */
export function readGuardArtifact(path,maxBytes){
 const realPath=immutablePath(path);
 const fd=openSync(realPath,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
 try{
  const before=fstatSync(fd);
  if(!before.isFile()||before.uid!==0||before.gid!==0||(before.mode&0o7022)!==0||(before.mode&0o004)===0||before.nlink!==1||before.size>maxBytes)fail();
  const bytes=readFileSync(fd),after=fstatSync(fd);
  if(bytes.length!==before.size||['dev','ino','size','mode','uid','gid','mtimeMs','ctimeMs'].some(key=>before[key]!==after[key])||immutablePath(path)!==realPath)fail();
  return {bytes,realPath,sha256:sha(bytes),size:bytes.length};
 }finally{closeSync(fd);}
}

export function inspectGuardManifest(raw){
 const value=parseGuardJson(raw,8388608);
 if(!exact(value,['version','kind','files','node'])||value.version!==1||value.kind!=='guarded-control-files'||
  !Array.isArray(value.files)||value.files.length<3||value.files.length>20000)fail();
 const seen=new Set();let size=0,last='';
 for(const row of [...value.files,value.node]){
  if(!exact(row,['path','realPath','sha256','size'])||typeof row.path!=='string'||!allowed(row.path)||resolve(row.path)!==row.path||
   typeof row.realPath!=='string'||!allowed(row.realPath)||resolve(row.realPath)!==row.realPath||
   !/^[a-f0-9]{64}$/.test(row.sha256??'')||!Number.isSafeInteger(row.size)||row.size<0||row.size>134217728||seen.has(row.path))fail();
  if(row!==value.node&&row.path<=last)fail();last=row.path;seen.add(row.path);size+=row.size;
 }
 if(value.node.path!=='/usr/local/bin/node'||value.node.realPath!=='/usr/local/bin/node'||size>2147483648||
  !['/bootstrap/nonroot-dispatch.mjs','/bootstrap/nonroot-identity.mjs','/bootstrap/nonroot-files.mjs'].every(path=>seen.has(path)))fail();
 return value;
}

export function verifyGuardFiles(manifest,module){
 if(!manifest.files.some(row=>row.path===module))fail();
 for(const row of [...manifest.files,manifest.node]){
  const actual=readGuardArtifact(row.path,row.size);
  if(actual.realPath!==row.realPath||actual.size!==row.size||actual.sha256!==row.sha256)fail();
 }
 return Object.freeze({closureHash:sha(Buffer.from(JSON.stringify(manifest))),files:manifest.files.length});
}
