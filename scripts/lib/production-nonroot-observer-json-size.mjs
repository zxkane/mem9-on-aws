/** Original bounded JSON sizing; never a reservation or authority source. */
import {need} from './production-nonroot-engineering-json.mjs';
import {NONROOT_FINALIZATION_LIMITS as L} from './production-nonroot-finalization-accounting.mjs';
export function finalizationJsonSize(value,limit=L.objectBytes,reserveLocal=()=>{}){
 need(Number.isSafeInteger(limit)&&limit>=0,'FinalizationJsonLimit');let bytes=0,nodes=0;
 const add=n=>{bytes+=n;need(Number.isSafeInteger(bytes)&&bytes<=limit,'FinalizationJsonLimit');};
 const string=s=>{
  add(2);
  for(let i=0;i<s.length;i++){
   const c=s.charCodeAt(i);
   if(c===34||c===92||[8,9,10,12,13].includes(c))add(2);
   else if(c<32)add(6);
   else if(c<128)add(1);
   else if(c<2048)add(2);
   else if(c>=0xd800&&c<=0xdbff){const next=s.charCodeAt(i+1);if(next>=0xdc00&&next<=0xdfff){add(4);i++;}else add(6);}
   else if(c>=0xdc00&&c<=0xdfff)add(6);else add(3);
  }
 };
 const visit=(v,depth)=>{
  need(depth<=128&&++nodes<=1000000,'FinalizationJsonDepth');reserveLocal(32);
  if(v===null){add(4);return;}
  if(typeof v==='string'){string(v);return;}
  if(typeof v==='boolean'){add(v?4:5);return;}
  if(typeof v==='number'){need(Number.isFinite(v),'FinalizationJsonNumber');add(JSON.stringify(v).length);return;}
  need(v&&typeof v==='object'&&(Array.isArray(v)||Object.getPrototypeOf(v)===Object.prototype||Object.getPrototypeOf(v)===null),'FinalizationJsonType');
  add(2);let count=0;
  if(Array.isArray(v)){
   for(let i=0;i<v.length;i++){const d=Object.getOwnPropertyDescriptor(v,String(i));need(d&&Object.hasOwn(d,'value'),'FinalizationJsonProperty');if(count++)add(1);visit(d.value,depth+1);}
  }else for(const k of Object.keys(v)){
   const d=Object.getOwnPropertyDescriptor(v,k);need(d&&Object.hasOwn(d,'value'),'FinalizationJsonProperty');if(count++)add(1);string(k);add(1);visit(d.value,depth+1);
  }
 };
 visit(value,0);return bytes;
}
