/** Pure finalization processing quote. No provider, permit or clock is created. */
import {observerNeed as need} from './production-nonroot-observer-delivery.mjs';

export function describeObserverProviderFinalization(delivery){
 const raw=delivery.allocation.slots.filter(r=>['runtime/container-metadata','runtime/task-metadata','source/jwks'].includes(r.id)).reduce((n,r)=>n+r.responseBytes,0);
 const snapshotBytes=262144+4*Math.ceil(raw/3)+65536+delivery.allocation.slots.length*4096;
 const logicalBytes=16*9*snapshotBytes+65536*delivery.allocation.slots.length;
 need(Number.isSafeInteger(logicalBytes),'RuntimeFinalizationQuote');return Object.freeze({authority:false,logicalBytes,maxSnapshots:8,snapshotBytes});
}
