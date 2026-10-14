/** Read-only private snapshot for the original /17 or /19 LOCAL replay.
 * The acquisition supplies prepaid credits and keeps this object private.
 * This module creates no budget, claim, session or execution authority. */
import {openSync,closeSync,readSync,fstatSync,lstatSync,realpathSync,constants} from 'node:fs';
import {join,resolve} from 'node:path';
import {createHash} from 'node:crypto';
import {CI_ROOT_REQUEST_POLICY as P} from './ci-smoke-root-request.mjs';
import {calculateCiRootRequestCost,CI_ROOT_COST_MODEL,CI_ROOT_REPLAY_CHECKPOINTS} from './ci-smoke-root-request-cost.mjs';
const need=(v,c='CiRootReplaySnapshot')=>{if(!v)throw Error(c);};
const sha=b=>createHash('sha256').update(b).digest('hex');
const keys=['dev','ino','uid','mode','nlink','size','mtimeMs','ctimeMs'];
const same=(a,b)=>keys.every(k=>a[k]===b[k]);

export function createCiRootReplaySnapshot({directory,prefix,scope,consume},test={}){
 need(CI_ROOT_REPLAY_CHECKPOINTS.includes(scope?.checkpoint)&&scope.kind==='target'&&scope.jobKey==='deploy-prod'&&scope.route==='deploy-prod'&&scope.phase===(scope.checkpoint==='deploy-prod/17'?'preconfigure':'presst'),'CiRootReplayScope');
 need(typeof directory==='string'&&resolve(directory)===directory&&realpathSync(directory)===directory&&/^target-[a-f0-9]{64}$/.test(prefix)&&typeof consume==='function');
 const directoryIdentity=lstatSync(directory);
 const checkDirectory=()=>{const d=lstatSync(directory);need(d.isDirectory()&&!d.isSymbolicLink()&&d.uid===process.getuid()&&(d.mode&0o777)===0o700&&d.dev===directoryIdentity.dev&&d.ino===directoryIdentity.ino&&realpathSync(directory)===directory,'CiRootReplayDirectory');};checkDirectory();
 const q=calculateCiRootRequestCost({checkpoint:scope.checkpoint}),retained=new Map();let closed=false,finished=false,entryBytes=0,finishBytes=0;
 const nameOf=ref=>{
  need(ref&&Object.keys(ref).sort().join()==='path,sha256'&&/^[a-f0-9]{64}$/.test(ref.sha256));
  need(typeof ref.path==='string'&&Buffer.byteLength(ref.path)<=CI_ROOT_COST_MODEL.referencePathBytes,'CiRootReplayPathBound');
  const name=ref.path.slice((directory+'/'+prefix+'-').length);
  need(ref.path===join(directory,prefix+'-'+name)&&/^(?:root-exchange-complete|root-local-accounting|root-request|root-put-(?:intent|dispatch|complete)|root-ready-(?:[1-9]|[1-9][0-9]|1[01][0-9]|12[0-8])-(?:intent|response|complete))\.json$/.test(name),'CiRootReplayPath');
  return name;
 };
 const read=(ref,maxBytes,expected,phase)=>{
  need(!closed&&!finished);checkDirectory();nameOf(ref);
  const named=lstatSync(ref.path);need(!named.isSymbolicLink()&&realpathSync(ref.path)===ref.path,'CiRootReplayAlias');
  const fd=openSync(ref.path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
  try{
   const before=fstatSync(fd);
   need(before.isFile()&&before.uid===process.getuid()&&(before.mode&0o777)===0o600&&before.nlink===1&&before.size<=maxBytes&&same(before,named),'CiRootReplayIdentity');
   if(expected)need(same(expected,before),'CiRootReplayChanged');
   const bytes=before.size+1,fee=phase==='entry'?8*bytes:bytes;
   const paid=consume(fee);need(!paid||typeof paid.then!=='function','CiRootReplaySynchronousBudget');
   if(phase==='entry')entryBytes+=bytes;else finishBytes+=bytes;
   const buffer=Buffer.alloc(bytes);let length=0;
   while(length<buffer.length){const n=readSync(fd,buffer,length,Math.min(65536,buffer.length-length),length);if(!n)break;length+=n;test.afterRead?.({path:ref.path,phase,length});}
   const after=fstatSync(fd),current=lstatSync(ref.path);
   need(length===before.size&&same(before,after)&&same(before,current)&&!current.isSymbolicLink()&&realpathSync(ref.path)===ref.path,'CiRootReplayChanged');
   const raw=buffer.subarray(0,length);need(sha(raw)===ref.sha256,'CiRootReplayHash');return {raw,identity:before};
  }finally{closeSync(fd);}
 };
 return Object.freeze({
  read(ref){try{
   const name=nameOf(ref);need(!retained.has(ref.path)&&retained.size<q.replay.files,'CiRootReplayDuplicate');
   const maxBytes=name==='root-exchange-complete.json'?q.records.exchange:name==='root-local-accounting.json'?q.records.accounting:P.requestBytes;
   const value=read(ref,maxBytes,undefined,'entry');retained.set(ref.path,{ref:{...ref},identity:value.identity,maxBytes,raw:value.raw});return value.raw;
  }catch(e){closed=true;throw e;}},
  finish(){try{
   need(!closed&&!finished&&retained.size>0,'CiRootReplayClosed');
   for(const {ref,identity,maxBytes} of retained.values())read(ref,maxBytes,identity,'finish');
   finished=true;retained.clear();return Object.freeze({entryBytes,finishBytes,contentScans:2});
  }catch(e){closed=true;throw e;}},
  close(){closed=true;retained.clear();},
 });
}
