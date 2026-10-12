/** Original bounded engineering JSON domain, separate from proof JSON. */
import {createHash} from 'node:crypto';
import {types} from 'node:util';
export const COUNTERS=Object.freeze(['ecrRequests','logicalBytes','httpBodyBytes','uncompressedBytes','processedEntries']);
export const need=(v,code)=>{if(!v)throw Object.assign(Error(code),{code});};
export const sha=b=>createHash('sha256').update(b).digest('hex');
export const hex=(s,n=64)=>typeof s==='string'&&new RegExp('^[a-f0-9]{'+n+'}$').test(s);
export function exact(v,keys){need(v&&!types.isProxy(v)&&!Array.isArray(v)&&[Object.prototype,null].includes(Object.getPrototypeOf(v)),'Fields');const d=Object.getOwnPropertyDescriptors(v);need(Reflect.ownKeys(d).every(k=>typeof k==='string'&&d[k].enumerable&&Object.hasOwn(d[k],'value'))&&Object.keys(d).sort().join()===keys.toSorted().join(),'Fields');}
export function canonical(value){let nodes=0;const active=new Set();const copy=(v,depth)=>{need(++nodes<=1000000&&depth<=64,'DataBound');if(v===null||typeof v==='boolean')return v;if(typeof v==='number'){need(Number.isSafeInteger(v),'Integer');return v;}if(typeof v==='string'){need(v.isWellFormed(),'Utf8');return v;}need(v&&typeof v==='object'&&!types.isProxy(v)&&!active.has(v),'Data');active.add(v);const d=Object.getOwnPropertyDescriptors(v);let out;if(Array.isArray(v)){need(Object.getPrototypeOf(v)===Array.prototype&&Reflect.ownKeys(d).length===v.length+1,'Data');out=Array.from({length:v.length},(_,i)=>{need(d[i]?.enumerable&&Object.hasOwn(d[i],'value'),'Data');return copy(d[i].value,depth+1);});}else{exact(v,Object.keys(d));out=Object.create(null);for(const k of Object.keys(d).sort())out[k]=copy(d[k].value,depth+1);}active.delete(v);return out;};return JSON.stringify(copy(value,0));}
export const hash=v=>sha(canonical(v));
export const same=(a,b,code='Binding')=>need(hash(a)===hash(b),code);
export const zero=()=>Object.fromEntries(COUNTERS.map(k=>[k,0]));
export function counter(v){exact(v,COUNTERS);need(COUNTERS.every(k=>Number.isSafeInteger(v[k])&&v[k]>=0),'Counter');return v;}
export function add(...rows){const out=zero();for(const r of rows){counter(r);for(const k of COUNTERS){out[k]+=r[k];need(Number.isSafeInteger(out[k]),'Counter');}}return out;}
export const local=n=>({...zero(),logicalBytes:n});
export function ref(v){exact(v,['path','sha256','bytesLength']);need(typeof v.path==='string'&&v.path.startsWith('/')&&!v.path.split('/').includes('..')&&hex(v.sha256)&&Number.isSafeInteger(v.bytesLength)&&v.bytesLength>=0,'Ref');return v;}
export function json(raw,cap){
 need(raw instanceof Uint8Array&&raw.length<=cap,'JsonBound');
 const text=new TextDecoder('utf-8',{fatal:true}).decode(raw);let at=0,nodes=0;
 const ws=()=>{while(/[\x20\t\r\n]/.test(text[at]??'!'))at++;};
 const string=()=>{const start=at;need(text[at++]==='"','Json');let escaped=false;while(at<text.length){const c=text[at++];if(!escaped&&c==='"')return JSON.parse(text.slice(start,at));if(escaped)escaped=false;else if(c==='\\')escaped=true;}throw Error('Json');};
 const scan=depth=>{
  need(depth<=64&&++nodes<=1000000,'JsonDepth');ws();const c=text[at];
  if(c==='{'){at++;ws();const keys=new Set();if(text[at]==='}'){at++;return;}while(true){ws();const k=string();need(!keys.has(k),'DuplicateJsonKey');keys.add(k);ws();need(text[at++]===':','Json');scan(depth+1);ws();if(text[at]==='}'){at++;return;}need(text[at++ ]===',','Json');}}
  if(c==='['){at++;ws();if(text[at]===']'){at++;return;}while(true){scan(depth+1);ws();if(text[at]===']'){at++;return;}need(text[at++ ]===',','Json');}}
  if(c==='"'){string();return;}const start=at;while(at<text.length&&!/[\x20\t\r\n,}\]]/.test(text[at]))at++;need(at>start,'Json');JSON.parse(text.slice(start,at));
 };
 scan(0);ws();need(at===text.length,'Json');const v=JSON.parse(text);canonical(v);return v;
}
export const immutable=v=>{if(v&&typeof v==='object'){Object.freeze(v);for(const x of Object.values(v))immutable(x);}return v;};

export const parseEngineeringJson=json,canonicalEngineeringJson=canonical;
