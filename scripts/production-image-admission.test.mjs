import {it,expect} from 'vitest';
import {RunTaskCommand} from '@aws-sdk/client-ecs';
import {imageTransitionFixture,imageTransitionServingFixture} from './production-image-transition.fixture.mjs';
import {buildImageTransitionProof,bindImageTransitionAuthorization,verifyImageTransitionProof} from './lib/production-image-transition-proof.mjs';
import {installImageAuthorization,getImageAuthorization,resolveImageAuthorization,inheritImageAuthorization} from './lib/production-image-admission.mjs';
import {inheritMaintenanceAdmission,requireMaintenanceAdmission,assertMaintenanceDispatch,consumeMaintenancePermit,sendMaintenanceCommand} from './lib/production-maintenance-admission.mjs';

async function fixture(){
 const f=await imageTransitionFixture(),built=await buildImageTransitionProof(f.input,f),s=imageTransitionServingFixture(f,built);
 return {f,built,s,context:s.authorizationContext,options:{data:s.data,controlSourceTree:s.data.controlSourceTree,now:f.now}};
}
it('registers only a real proof/final-review context against its selected V2 descriptor without decorating clients',async()=>{
 const f=await fixture(),clients=Object.freeze({}),keys=Reflect.ownKeys(clients);
 expect(installImageAuthorization(clients,f.context,f.options)).toBe(f.context);
 expect(getImageAuthorization(clients)).toBe(f.context);expect(resolveImageAuthorization(clients)).toBe(f.context);
 expect(resolveImageAuthorization(clients,f.context)).toBe(f.context);expect(Reflect.ownKeys(clients)).toEqual(keys);
});
it('rejects serialized, cloned, unbound-review and inspection contexts without installing anything',async()=>{
 const f=await fixture(),inspection=await verifyImageTransitionProof(f.built.proof,{...f.f,proofHash:f.built.proofHash,mode:'inspection'});
 const inspected=bindImageTransitionAuthorization(inspection,{review:f.s.review,now:f.f.now,mode:'inspection'});
 for(const context of [JSON.parse(JSON.stringify(f.context)),{...f.context},f.built.context,inspected]){
  const clients={};expect(()=>installImageAuthorization(clients,context,f.options)).toThrow();expect(getImageAuthorization(clients)).toBeUndefined();
 }
});
it('rejects V1, changed selected data, wrong control tree, expiry and extra install fields',async()=>{
 const f=await fixture();
 for(const patch of [{data:f.f.predecessor},{data:{...f.s.data,policyHash:f.f.expected.policyHash}},{controlSourceTree:'0'.repeat(40)},{now:f.s.data.expiresMs},{review:f.s.review}]){
  const clients={};expect(()=>installImageAuthorization(clients,f.context,{...f.options,...patch})).toThrow();expect(getImageAuthorization(clients)).toBeUndefined();
 }
});
it('JSON properties cannot supply or override a registration',async()=>{
 const f=await fixture(),clients={imageAuthorization:f.context,imageTransition:f.context};
 Object.defineProperty(clients,'authorizationContext',{get(){throw Error('must not read a JSON property');}});
 expect(getImageAuthorization(clients)).toBeUndefined();expect(resolveImageAuthorization(clients)).toBeUndefined();
 installImageAuthorization(clients,f.context,f.options);expect(resolveImageAuthorization(clients)).toBe(f.context);
});
it('rejects a conflicting explicit context and preserves the prior registration',async()=>{
 const f=await fixture(),clients={};installImageAuthorization(clients,f.context,f.options);
 const refreshed=bindImageTransitionAuthorization(f.built.context,{review:f.s.review,now:f.f.now});
 expect(()=>resolveImageAuthorization(clients,refreshed)).toThrow('ImageAuthorizationConflict');
 expect(()=>resolveImageAuthorization(clients,{})).toThrow('ImageAuthorizationConflict');expect(getImageAuthorization(clients)).toBe(f.context);
});
it('inherited clients share validated same-authorization refreshes and cannot rebind to different data',async()=>{
 const f=await fixture(),parent={},child={},grandchild={};installImageAuthorization(parent,f.context,f.options);
 expect(inheritImageAuthorization(parent,child)).toBe(child);inheritImageAuthorization(child,grandchild);
 const refreshed=bindImageTransitionAuthorization(f.built.context,{review:f.s.review,now:f.f.now});
 installImageAuthorization(parent,refreshed,f.options);expect(getImageAuthorization(child)).toBe(refreshed);expect(getImageAuthorization(grandchild)).toBe(refreshed);
 const different={...f.s.data,authorizationId:'8'.repeat(32)};
 expect(()=>installImageAuthorization(child,refreshed,{...f.options,data:different})).toThrow('ImageAuthorizationRebind');
 expect(getImageAuthorization(parent)).toBe(refreshed);
});
it('maintenance client wrapping inherits both gates without permitting a legacy dispatch fallback',async()=>{
 const f=await fixture(),parent=requireMaintenanceAdmission({});installImageAuthorization(parent,f.context,f.options);
 const wrapped=inheritMaintenanceAdmission(parent,{ecs:{send:async()=>{throw Error('must not dispatch');}}});
 expect(getImageAuthorization(wrapped)).toBe(f.context);
 await expect(assertMaintenanceDispatch(wrapped,{kind:'admin',operation:'canary'})).rejects.toThrow('MaintenanceAdmissionRequired');
});
it('conflicting inheritance fails before changing either registry',async()=>{
 const f=await fixture(),parent={},child={};installImageAuthorization(parent,f.context,f.options);
 const refreshed=bindImageTransitionAuthorization(f.built.context,{review:f.s.review,now:f.f.now});installImageAuthorization(child,refreshed,f.options);
 expect(()=>inheritMaintenanceAdmission(parent,child)).toThrow('ImageAuthorizationConflict');expect(getImageAuthorization(child)).toBe(refreshed);
 expect(()=>inheritImageAuthorization({},child)).toThrow('ImageAuthorizationConflict');
});
it('ordinary clients and their clones remain unregistered',()=>{
 const parent={},child={};expect(inheritMaintenanceAdmission(parent,child)).toBe(child);expect(getImageAuthorization(child)).toBeUndefined();
});
it('an installed image authorization cannot make a plain client take the legacy write path',async()=>{
 const f=await fixture();let writes=0;const clients={ecs:{send:async()=>{writes++;}}};installImageAuthorization(clients,f.context,f.options);
 await expect(sendMaintenanceCommand(clients,'ecs',new RunTaskCommand({}),{kind:'admin',operation:'canary',transitionRequired:false})).rejects.toThrow('MaintenanceAdmissionRequired');
 expect(writes).toBe(0);
});
it('registration invalidates a previously obtained null legacy permit',async()=>{
 const f=await fixture(),clients={},event={kind:'admin',operation:'canary'};
 const permit=await assertMaintenanceDispatch(clients,event);expect(permit).toBeNull();installImageAuthorization(clients,f.context,f.options);
 expect(()=>consumeMaintenancePermit(clients,permit,event)).toThrow('MaintenanceAdmissionRequired');
});
it('a failed expired refresh retains the registration instead of enabling legacy fallback',async()=>{
 const f=await fixture(),clients={};installImageAuthorization(clients,f.context,f.options);
 expect(()=>installImageAuthorization(clients,f.context,{...f.options,now:f.s.data.expiresMs})).toThrow();
 expect(getImageAuthorization(clients)).toBe(f.context);expect(resolveImageAuthorization(clients)).toBe(f.context);
 await expect(assertMaintenanceDispatch(clients,{kind:'admin',operation:'canary'})).rejects.toThrow('MaintenanceAdmissionRequired');
});
