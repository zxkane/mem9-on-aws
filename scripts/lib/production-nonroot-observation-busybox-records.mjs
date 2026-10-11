/** Decode inert BusyBox process DATA only. Original source/image/policy,
 * task identity, raw retention and original prepayment belong to the caller.
 * UID/NNP/capability values are observations, never an approval predicate. */
import {types} from 'node:util';
import {copyNonrootJson} from './production-nonroot-contracts.mjs';

const KEYS=['pid','stat','statAfter','status','cmdlineHash','path','stamp','digest'];
const HEX_CAPS={stat:4096,statAfter:4096,status:65536,path:4096};
const UINT64=(1n<<64n)-1n,UINT32=(1n<<32n)-1n,SAFE=BigInt(Number.MAX_SAFE_INTEGER);
const need=(value,code)=>{if(!value)throw Error('BusyboxObservation'+code);};
const positive=n=>Number.isSafeInteger(n)&&n>0;
const hash=s=>typeof s==='string'&&/^[a-f0-9]{64}$/.test(s);

function inertRow(value){
 need(value&&typeof value==='object'&&!types.isProxy(value)&&!Array.isArray(value),'Input');
 const proto=Object.getPrototypeOf(value);need(proto===Object.prototype||proto===null,'Input');
 const descriptors=Object.getOwnPropertyDescriptors(value),keys=Reflect.ownKeys(descriptors);
 need(keys.length===KEYS.length&&keys.every(k=>typeof k==='string'&&KEYS.includes(k)),'Fields');
 const result=Object.create(null);
 for(const key of KEYS){
  const d=descriptors[key];need(d?.enumerable&&Object.hasOwn(d,'value'),'Input');
  const v=d.value;
  if(key==='pid')need(positive(v),'Pid');
  else if(Object.hasOwn(HEX_CAPS,key)){
   need(typeof v==='string'&&v.length>0&&v.length<=2*HEX_CAPS[key]&&v.length%2===0,'HexBound');
   need(/^[a-f0-9]+$/.test(v),'Hex');
  }else if(key==='stamp'){
   // The retained writer already bounds the complete stat string to1024.
   need(typeof v==='string'&&v.length>0&&v.length<=1024&&/^[\x20-\x7e]+$/.test(v),'StampBound');
  }else need(hash(v),'Hash');
  result[key]=v;
 }
 // Reuse the existing inert JSON copy after bounding every primitive field.
 // No caller getter, proxy trap, toJSON, iterator or conversion is invoked.
 return copyNonrootJson(result);
}
function text(hex){
 try{return new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(Buffer.from(hex,'hex'));}
 catch{throw Error('BusyboxObservationUtf8');}
}
function unsigned(s,maximum){
 need(typeof s==='string'&&s.length<=20&&/^(0|[1-9][0-9]*)$/.test(s),'Integer');
 const n=BigInt(s);need(n<=maximum,'IntegerBound');return n;
}
function parseStat(value,pid){
 const prefix=pid+' (',end=value.lastIndexOf(')');
 need(value.startsWith(prefix)&&end>=prefix.length&&!value.includes('\0')&&value[end+1]===' ','Stat');
 const fields=value.slice(end+2).trim().split(/\s+/);
 need(fields.length>=20&&/^[A-Za-z]$/.test(fields[0]),'Stat');
 const ppid=Number(unsigned(fields[1],SAFE)),start=unsigned(fields[19],SAFE);
 need(start>0n,'StartTime');return {ppid,startTimeTicks:Number(start)};
}
function parseStatus(value){
 need(!/[\x00-\x08\x0b-\x1f\x7f]/.test(value),'Status');
 const lines=value.split('\n');if(lines.at(-1)==='')lines.pop();
 need(lines.length>0,'Status');const fields=new Map();
 for(const line of lines){
  const at=line.indexOf(':'),name=line.slice(0,at);
  need(at>0&&/^[A-Za-z][A-Za-z0-9_]*$/.test(name)&&!fields.has(name),'Status');
  fields.set(name,line.slice(at+1).replace(/^[ \t]+|[ \t]+$/g,''));
 }
 return fields;
}
function ids(fields,name,count){
 const value=fields.get(name);need(typeof value==='string','Status');
 if(value===''){need(count===null,'Ids');return [];}
 need(/^(0|[1-9][0-9]*)(?:[ \t]+(?:0|[1-9][0-9]*))*$/.test(value),'Ids');
 const values=value.split(/[ \t]+/);
 // At least one digit plus a separator per group; the64KiB status cap
 // therefore bounds this array without introducing a smaller policy cap.
 need(count===null?values.length<=32768:values.length===count,'Ids');
 return values.map(v=>Number(unsigned(v,UINT32)));
}
function executableFile(stamp){
 const fields=stamp.split(',');need(fields.length===8,'Stamp');
 const device=unsigned(fields[0],UINT64),inode=unsigned(fields[1],UINT64),size=unsigned(fields[2],UINT64);
 need(size>0n&&size<=201326592n,'FileSize');
 need(/^(0|[1-9a-f][a-f0-9]*)$/.test(fields[3])&&fields[3].length<=4,'FileMode');
 const mode=BigInt('0x'+fields[3]);need((mode&0xf000n)===0x8000n,'FileType');
 const uid=Number(unsigned(fields[4],UINT32)),gid=Number(unsigned(fields[5],UINT32));
 // Keep full timestamp text; do not parse it through Date or round away ns.
 const timestamp=/^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{9} [+-][0-9]{4}$/;
 need(timestamp.test(fields[6])&&timestamp.test(fields[7]),'StampTime');
 return {mode:Number(mode&4095n),uid,gid,device:device.toString(),inode:inode.toString()};
}

export function decodeBusyboxObservationProcess(value){
 const r=inertRow(value),before=parseStat(text(r.stat),r.pid),after=parseStat(text(r.statAfter),r.pid);
 need(before.ppid===after.ppid&&before.startTimeTicks===after.startTimeTicks,'IdentityChanged');
 const status=parseStatus(text(r.status));
 need(Number(unsigned(status.get('Pid'),SAFE))===r.pid&&Number(unsigned(status.get('PPid'),SAFE))===before.ppid,'IdentityChanged');
 const uid=ids(status,'Uid',4),gid=ids(status,'Gid',4),groups=ids(status,'Groups',null),nnp=status.get('NoNewPrivs');
 need(nnp==='0'||nnp==='1','NoNewPrivs');
 const capabilities={};for(const suffix of ['Inh','Prm','Eff','Bnd','Amb']){
  const v=status.get('Cap'+suffix);need(typeof v==='string'&&/^[a-f0-9]{16}$/.test(v),'Capabilities');capabilities['cap'+suffix]=v;
 }
 const path=text(r.path);
 need(path.startsWith('/')&&path.length>1&&!path.endsWith('/')&&!path.endsWith(' (deleted)')&&
  !/[\\\x00-\x1f\x7f-\x9f]/.test(path)&&path.slice(1).split('/').every(p=>p!==''&&p!=='.'&&p!=='..'),'Path');
 return copyNonrootJson({pid:r.pid,...before,executablePath:path,executableDigest:'sha256:'+r.digest,file:executableFile(r.stamp),
  cmdlineHash:r.cmdlineHash,uid,gid,groups,noNewPrivs:Number(nnp),...capabilities});
}
