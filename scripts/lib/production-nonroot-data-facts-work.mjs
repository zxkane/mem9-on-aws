/** Paid geometry for genuine native/full-proof DATA; no source/IO capability. */
const need=(v,c)=>{if(!v)throw Error(c);};
function boundedGeometry(value,maxBytes,maxNodes,{beforeNode=()=>{},beforeString=()=>{}}={}){
 let bytes=0,nodes=0;
 const add=n=>{bytes+=n;need(Number.isSafeInteger(bytes)&&bytes<=maxBytes,'NonrootDataFactsFilesystemBytes');};
 const string=s=>{beforeString(s.length);add(2);for(let i=0;i<s.length;i++){
  const c=s.charCodeAt(i);if(c===34||c===92||[8,9,10,12,13].includes(c))add(2);
  else if(c<32)add(6);else if(c<128)add(1);else if(c<2048)add(2);
  else if(c>=0xd800&&c<=0xdbff&&s.charCodeAt(i+1)>=0xdc00&&s.charCodeAt(i+1)<=0xdfff){add(4);i++;}
  else if(c>=0xd800&&c<=0xdfff)add(6);else add(3);
 }};
 const visit=v=>{
  beforeNode();need(Number.isSafeInteger(++nodes)&&nodes<=maxNodes,'NonrootDataFactsFilesystemNodes');
  if(typeof v==='string')return string(v);
  if(v===null)return add(4);if(typeof v==='boolean')return add(v?4:5);
  if(typeof v==='number'){need(Number.isFinite(v),'NonrootDataFactsFilesystemValue');return add(String(v).length);}
  need(v&&typeof v==='object','NonrootDataFactsFilesystemValue');add(2);
  const array=Array.isArray(v),keys=Object.keys(v);if(array)need(keys.length===v.length,'NonrootDataFactsFilesystemValue');
  for(let i=0;i<keys.length;i++){if(i)add(1);const key=keys[i],d=Object.getOwnPropertyDescriptor(v,key);need(d&&Object.hasOwn(d,'value'),'NonrootDataFactsFilesystemValue');if(!array){string(key);add(1);}visit(d.value);}
 };visit(value);return {bytes,nodes};
}

export function measureNonrootDataFacts(value,paid){
 const pay=n=>{paid.debit(n);paid.current();};paid.current();
 const geometry=boundedGeometry(value,Number.MAX_SAFE_INTEGER,Number.MAX_SAFE_INTEGER,{beforeNode:()=>pay(32),beforeString:n=>pay(8*n+32)});
 paid.current();return geometry;
}
export function copyNonrootDataFacts(value,paid){
 const g=measureNonrootDataFacts(value,paid);paid.debit(8*g.bytes+32*g.nodes);paid.current();const result=structuredClone(value);paid.current();return result;
}
