// Only control-host entrypoints install a verifier. It must authenticate the
// transition/joint records and current source/image/role/parameter/owner state;
// JSON configuration cannot install one. Ordinary data-plane clients are not
// wrapped or changed by this module.
import {createHash} from 'node:crypto';
import {getImageAuthorization,inheritImageAuthorization} from './production-image-admission.mjs';
const guards=new WeakMap(),required=new WeakSet(),permits=new WeakMap();
const fail=code=>{throw Error(code);};
const freeze=value=>{if(value&&typeof value==='object'){Object.values(value).forEach(freeze);Object.freeze(value);}return value;};
const canonical=v=>Array.isArray(v)?v.map(canonical):v&&typeof v==='object'?Object.fromEntries(Object.keys(v).sort().map(k=>[k,canonical(v[k])])):v;
const hash=v=>createHash('sha256').update(JSON.stringify(canonical(v))).digest('hex');
const exact=(v,keys)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===keys.slice().sort().join();
const bindingKeys=['owner','operationHash','fenceHash','sourceTree'];
const purposes={
  'before-deployment':new Set(['legacy-root-audit','supersession','target-deploy','owned-cleanup']),
  'before-witness':new Set(['target-verify','witness','owned-cleanup']),
  ready:new Set(['admin','wake','activate','benchmark','target-verify','owned-cleanup']),
};
export function assertMaintenancePhase(phase,kind){
  if(!Object.hasOwn(purposes,phase)||!purposes[phase].has(kind))fail('MaintenancePhaseDenied');
}
export function requireMaintenanceAdmission(clients){
  if(!clients||typeof clients!=='object'||Array.isArray(clients))fail('MaintenanceAdmissionInvalid');required.add(clients);return clients;
}
export function installMaintenanceAdmission(clients,{binding,verify,assertCurrent,now=Date.now}={}){
  requireMaintenanceAdmission(clients);
  if(guards.has(clients)||!exact(binding,bindingKeys)||typeof verify!=='function'||typeof assertCurrent!=='function'||typeof now!=='function'||
    !/^[a-f0-9]{32}$/.test(binding.owner)||!['operationHash','fenceHash'].every(k=>/^[a-f0-9]{64}$/.test(binding[k]))||!/^[a-f0-9]{40}$/.test(binding.sourceTree))fail('MaintenanceAdmissionInvalid');
  const entry={binding:freeze(structuredClone(binding)),verify,assertCurrent,now};guards.set(clients,entry);
  return (event,checkpoint)=>{
    if(!exact(checkpoint,[...bindingKeys,'phase','observedMs','expiresMs'])||bindingKeys.some(k=>checkpoint[k]!==entry.binding[k]))fail('MaintenancePermitBinding');
    assertMaintenancePhase(checkpoint.phase,event.kind);
    const at=now();if(!Number.isSafeInteger(at)||!Number.isSafeInteger(checkpoint.observedMs)||checkpoint.observedMs>at||!Number.isSafeInteger(checkpoint.expiresMs)||checkpoint.expiresMs<=at||checkpoint.expiresMs>checkpoint.observedMs+300000)fail('MaintenancePermitExpired');
    const permit=Object.freeze({});permits.set(permit,{entry,eventHash:hash(event),checkpoint:freeze(structuredClone(checkpoint)),used:false});return permit;
  };
}
export function inheritMaintenanceAdmission(source,target){
  inheritImageAuthorization(source,target);
  if(required.has(source))required.add(target);if(guards.has(source))guards.set(target,guards.get(source));return target;
}
export async function assertMaintenanceDispatch(clients,event){
  const entry=guards.get(clients);
  if(!entry){if(required.has(clients)||getImageAuthorization(clients)||event.transitionRequired)fail('MaintenanceAdmissionRequired');return null;}
  if(!event||!Object.values(purposes).some(k=>k.has(event.kind))||typeof event.operation!=='string'||!event.operation)fail('MaintenanceDispatchInvalid');
  const permit=await entry.verify(freeze(structuredClone(event))),record=permits.get(permit);
  if(!record||record.entry!==entry||record.eventHash!==hash(event))fail('MaintenancePermitInvalid');return permit;
}
export function consumeMaintenancePermit(clients,permit,event){
  if(permit===null){if(required.has(clients)||getImageAuthorization(clients)||event.transitionRequired)fail('MaintenanceAdmissionRequired');return;}
  const record=permits.get(permit),entry=guards.get(clients);
  if(!record||record.entry!==entry||record.used||record.eventHash!==hash(event))fail('MaintenancePermitInvalid');record.used=true;
  const c=record.checkpoint,at=entry.now();if(!Number.isSafeInteger(at)||at<c.observedMs||at>=c.expiresMs||at-c.observedMs>300000)fail('MaintenancePermitExpired');
  assertMaintenancePhase(c.phase,event.kind);
  if(entry.assertCurrent(c,event)!==undefined)fail('MaintenancePermitCheckMustBeSynchronous');
  const finalAt=entry.now();if(!Number.isSafeInteger(finalAt)||finalAt<c.observedMs||finalAt>=c.expiresMs||finalAt-c.observedMs>300000)fail('MaintenancePermitExpired');
}
export async function sendMaintenanceCommand(clients,service,command,details,options={}){
  const key=clients?.[service+'Write']?service+'Write':service,client=clients?.[key];
  if(!['ecs','ssm','scheduler'].includes(service)||typeof client?.send!=='function'||!command?.input||typeof command.constructor!=='function')fail('MaintenanceDispatchInvalid');
  const input=freeze(structuredClone(command.input)),Command=command.constructor,event=freeze({...structuredClone(details),service,api:command.operation??Command.name.replace(/Command$/,''),input});
  const permit=await assertMaintenanceDispatch(clients,event),outgoing=new Command(input);
  const sendingOptions={abortSignal:AbortSignal.timeout(30000),...options};
  if(clients[key]!==client)fail('MaintenanceDispatchClientChanged');sendingOptions.abortSignal?.throwIfAborted();
  consumeMaintenancePermit(clients,permit,event);
  return client.send(outgoing,sendingOptions);
}
/** The callback starts the actual dispatch synchronously; it must not perform
 * another awaited preflight before starting the request. */
export async function dispatchMaintenanceAction(clients,details,input,dispatch){
  const event=freeze({...structuredClone(details),input:structuredClone(input)});
  const permit=await assertMaintenanceDispatch(clients,event);
  consumeMaintenancePermit(clients,permit,event);
  return dispatch(event.input);
}
export function maintenanceWorkerTarget(target){
  return Object.fromEntries(['account','region','image','taskDefinitionArn','taskRoleArn','executionRoleArn','generation','controlSourceTag'].map(k=>[k,target[k]]).concat([
    ['dataReleaseHash',target.dataRelease?.hash],['parameterVersion',target.dataRelease?.parameterVersion],['sourceTree',target.dataRelease?.data?.controlSourceTree],
  ]));
}
