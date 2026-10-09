import {assertImageTransitionDataRelease,imageTransitionContextBindings} from './production-image-transition-proof.mjs';
import {canaryEvidenceHash as hash} from './production-canary-verification.mjs';
import {nonrootAuthorizationBindings,assertNonrootDataRelease} from './production-nonroot-proof.mjs';

const registrations=new WeakMap();
const fail=code=>{throw Error(code);};
const clientKey=v=>{if(!v||typeof v!=='object'||Array.isArray(v))fail('ImageAuthorizationClientsInvalid');};

/** Registration is code-only and requires a real admission proof with its bound
 * final owner review. The selected descriptor is checked before any registry
 * mutation. No property on a client or JSON object can supply this association. */
export function installImageAuthorization(clients,context,options){
 clientKey(clients);
 if(!options||typeof options!=='object'||Array.isArray(options)||Object.keys(options).some(k=>!['data','controlSourceTree','now'].includes(k)))fail('ImageAuthorizationOptionsInvalid');
 const {data,controlSourceTree,now=Date.now()}=options;
 const nonroot=data?.version===3,bindings=nonroot?nonrootAuthorizationBindings(context):imageTransitionContextBindings(context);
 if(bindings.verificationMode!=='admission'||![2,3].includes(data?.version))fail('ImageAuthorizationAdmissionRequired');
 (nonroot?assertNonrootDataRelease:assertImageTransitionDataRelease)(context,{current:data,controlSourceTree,now,mode:'admission'});
 if((nonroot?bindings.reviewHash:context.reviewHash)!==data.policyHash)fail('ImageAuthorizationReviewRequired');
 const dataHash=hash(data),prior=registrations.get(clients);
 if(prior){
  if(prior.dataHash!==dataHash||prior.controlSourceTree!==controlSourceTree)fail('ImageAuthorizationRebind');
  // All derived client collections share this holder. Only a fully validated
  // refresh of the same immutable authorization can replace its context.
  prior.context=context;
 }else registrations.set(clients,{context,dataHash,controlSourceTree});
 return context;
}

/** Lookup is not an admission check. A loader must revalidate its actual
 * selected descriptor and current time before admitting work. Expired contexts
 * remain registered; they never disappear into a legacy fallback. */
export function getImageAuthorization(clients){return registrations.get(clients)?.context;}

export function resolveImageAuthorization(clients,explicitContext){
 const registered=getImageAuthorization(clients);
 if(registered&&explicitContext!==undefined&&explicitContext!==registered)fail('ImageAuthorizationConflict');
 if(explicitContext!==undefined){
  if(typeof explicitContext?.kind==='string'&&explicitContext.kind.startsWith('nonroot-'))nonrootAuthorizationBindings(explicitContext);else imageTransitionContextBindings(explicitContext);
  return explicitContext;
 }
 return registered;
}

export function inheritImageAuthorization(source,target){
 const entry=registrations.get(source),existing=registrations.get(target);
 if(!entry){if(existing)fail('ImageAuthorizationConflict');return target;}
 clientKey(target);
 if(existing&&existing!==entry&&existing.context!==entry.context)fail('ImageAuthorizationConflict');
 if(existing&&(existing.dataHash!==entry.dataHash||existing.controlSourceTree!==entry.controlSourceTree))fail('ImageAuthorizationConflict');
 registrations.set(target,entry);return target;
}
