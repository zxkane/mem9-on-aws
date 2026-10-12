/** Complete fixed CONTROL slot quote from the installed consumers. Inert DATA
 * only: no source retrieval, owner, permit, clock or success is created here. */
import {inspectObserverControlDelivery,OBSERVER_RUNTIME_SLOTS,OBSERVER_CONTROL_ROUTE_SLOTS,observerZeroCounter,observerCounter,observerDataHash as hash,observerNeed as need} from './production-nonroot-observer-delivery.mjs';
import {describeObserverRouteProbeWork} from './production-nonroot-observer-route-protocol.mjs';
import {describeObserverProviderFinalization} from './production-nonroot-observer-finalization-work.mjs';
const local=n=>({...observerZeroCounter(),logicalBytes:n});
const retainedRaw=new Set(['runtime/container-metadata','runtime/task-metadata','source/jwks']);
const parsed64k=new Set(['runtime/task-credentials','source/token']);
export function compileObserverControlSlots(input){
 inspectObserverControlDelivery(input);const value=structuredClone(input),slots=value.allocation.slots;
 need(slots.length===21&&OBSERVER_RUNTIME_SLOTS.every(id=>slots.some(s=>s.id===id)),'CompleteRuntimeSlots');
 const byId=new Map(slots.map(s=>[s.id,s]));
 for(const row of slots){
  // P retains each WHOLE original metadata/JWKS body as base64 inside its
  // <=65536-byte output. 4*ceil(raw/3)<=65536 is therefore necessary for any
  // admissible complete record. No successful raw body is truncated/narrowed.
  if(retainedRaw.has(row.id))row.responseBytes=Math.min(row.responseBytes,49152);
  else if(parsed64k.has(row.id))row.responseBytes=Math.min(row.responseBytes,65536);
  if(row.kind==='http'&&!OBSERVER_CONTROL_ROUTE_SLOTS.includes(row.id)){
   // Full source HTTP path: request serialize/sign/header copies; raw chunk
   // copies, concatenation, duplicate-key parse, value hash/adapter copies,
   // public provenance/base64 or secret zeroing; completion/cleanup records.
   // Keep the entire declared envelope for SSM/Secrets. Exact secret VALUE
   // length does not bound optional service envelope fields or whitespace.
   row.counter={...observerZeroCounter(),logicalBytes:32*row.requestBytes+96*row.responseBytes+8*65536,httpBodyBytes:row.requestBytes+row.responseBytes};
  }
 }
 const lengths={accessToken:byId.get('source/token').responseBytes,jwks:byId.get('source/jwks').responseBytes,registry:Buffer.byteLength(value.registry),...Object.fromEntries(['identitySigningKeys','transportSigningKeys','tenantKey'].map(k=>[k,value.credentialBindings[k].bytesLength]))};
 byId.get('credential-adapter').counter=local(8*Object.values(lengths).reduce((n,v)=>n+v,0)+2*65536);
 byId.get('source/registry').counter=local(32*262144+2*65536);
 byId.get('runtime-finalization').counter=local(describeObserverProviderFinalization(value).logicalBytes);
 // Inspectors require every interim allocation to cover its slots; summing
 // here is DATA validation, never granting the corresponding original work.
 const sum=()=>{const total=observerZeroCounter();for(const row of slots)for(const k of Object.keys(total))total[k]+=row.counter[k];observerCounter(total);return total;};
 value.allocation.charge=sum();
 const route=describeObserverRouteProbeWork(value);
 for(const term of [route.context,route.output,...route.slots])byId.get(term.id).counter=structuredClone(term.charge);
 const charge=sum();charge.logicalBytes+=route.preProvider.logicalBytes;observerCounter(charge);value.allocation.charge=charge;
 inspectObserverControlDelivery(value);
 const withoutAllocation=v=>Object.fromEntries(Object.entries(v).filter(([k])=>k!=='allocation'));
 need(hash(withoutAllocation(value))===hash(withoutAllocation(input)),'SlotQuoteChangedOriginalInput');
 return Object.freeze({authority:false,delivery:value,charge:structuredClone(charge),preProvider:route.preProvider,credentialByteBounds:lengths,
  unresolvedResponseBounds:slots.filter(s=>s.id.startsWith('source/')&&Object.hasOwn(value.credentialBindings,s.id.slice(7))).map(s=>({id:s.id,responseBytes:s.responseBytes,reason:'Original complete service envelope bound retained; value byte commitment alone is insufficient.'}))});
}
