import {it,expect} from 'vitest';
import {RunTaskCommand} from '@aws-sdk/client-ecs';
import {PutParameterCommand} from '@aws-sdk/client-ssm';
import {installMaintenanceAdmission,requireMaintenanceAdmission,inheritMaintenanceAdmission,assertMaintenanceDispatch,consumeMaintenancePermit,sendMaintenanceCommand,assertMaintenancePhase} from './lib/production-maintenance-admission.mjs';

const binding={owner:'a'.repeat(32),operationHash:'b'.repeat(64),fenceHash:'c'.repeat(64),sourceTree:'d'.repeat(40)};
function install(clients,verify,{now=Date.now,assertCurrent=()=>{}}={}){
 let mint;mint=installMaintenanceAdmission(clients,{binding,now,assertCurrent,verify:async event=>{const phase=await verify(event);const at=now();return mint(event,{...binding,phase:phase??'ready',observedMs:at,expiresMs:at+300000});}});return mint;
}
const mutationKinds=['admin','wake','activate','benchmark'];
for(const phase of ['before-deployment','before-witness'])for(const kind of mutationKinds)it(`${phase} denies ${kind} even when legacy selection matches`,()=>{
 expect(()=>assertMaintenancePhase(phase,kind)).toThrow('MaintenancePhaseDenied');
});
it('allows only fixed transition purposes before deployment and verification/publication before witness',()=>{
 for(const kind of ['legacy-root-audit','supersession','target-deploy','owned-cleanup'])expect(assertMaintenancePhase('before-deployment',kind)).toBeUndefined();
 for(const kind of ['target-verify','witness','owned-cleanup'])expect(assertMaintenancePhase('before-witness',kind)).toBeUndefined();
 for(const kind of mutationKinds)expect(assertMaintenancePhase('ready',kind)).toBeUndefined();
 expect(()=>assertMaintenancePhase('before-witness','supersession')).toThrow();expect(()=>assertMaintenancePhase('ready','unknown')).toThrow();
});
it('an absent host gate cannot dispatch an administration task or its invocation record',async()=>{
 let writes=0;const clients={ecs:{send:async()=>{writes++;}},ssm:{send:async()=>{writes++;}}};requireMaintenanceAdmission(clients);
 for(const [service,command]of [['ecs',new RunTaskCommand({taskDefinition:'old-control'})],['ssm',new PutParameterCommand({Name:'/synthetic/invocation',Value:'{}'})]])await expect(sendMaintenanceCommand(clients,service,command,{kind:'admin',operation:'begin-continuation'})).rejects.toThrow('MaintenanceAdmissionRequired');
 expect(writes).toBe(0);
});
it('the actual request is checked after prior awaits and cannot be changed while admission waits',async()=>{
 let resume,entered;const waiting=new Promise(r=>entered=r),blocked=new Promise(r=>resume=r),seen=[];
 const clients={ecs:{send:async command=>{seen.push(command.input);return {};}}};
 install(clients,async event=>{entered();await blocked;expect(event.input.taskDefinition).toBe('reviewed-control');assertMaintenancePhase('ready',event.kind);});
 const command=new RunTaskCommand({taskDefinition:'reviewed-control'}),pending=sendMaintenanceCommand(clients,'ecs',command,{kind:'admin',operation:'canary'});await waiting;command.input.taskDefinition='substituted';resume();await pending;
 expect(seen).toEqual([{taskDefinition:'reviewed-control'}]);
});
it('phase changes during awaited verification reject before SDK send',async()=>{
 let phase='ready',writes=0;const clients={ecs:{send:async()=>{writes++;}}};
 install(clients,async event=>{await Promise.resolve();phase='before-witness';assertMaintenancePhase(phase,event.kind);});
 await expect(sendMaintenanceCommand(clients,'ecs',new RunTaskCommand({}),{kind:'admin',operation:'promote'})).rejects.toThrow('MaintenancePhaseDenied');expect(writes).toBe(0);
});
it('control registration cannot be replaced or supplied as plain JSON and foreground clients remain untouched',async()=>{
 let reads=0;const client={send:async()=>{reads++;return {}; }},clients={ecs:client};
 expect(()=>installMaintenanceAdmission(clients,{approved:true})).toThrow();install(clients,async()=>{});expect(()=>install(clients,async()=>{})).toThrow();
 await client.send({input:{foreground:true}});expect(reads).toBe(1);
});
it('legacy clients outside a transition retain their dispatch behavior',async()=>{
 let calls=0;const clients={ecs:{send:async()=>{calls++;}}};await sendMaintenanceCommand(clients,'ecs',new RunTaskCommand({taskDefinition:'legacy'}),{kind:'admin',operation:'status'});expect(calls).toBe(1);
});
it('expired or owner-changed permits reject after asynchronous verification and before writer SDK send',async()=>{
 for(const change of ['clock','owner']){
  let at=1000,owned=true,calls=0,mint;const clients={ecs:{send:async()=>{throw Error('ReadClientUsed');}},ecsWrite:{send:async()=>{calls++;}}};
  mint=installMaintenanceAdmission(clients,{binding,now:()=>at,assertCurrent:()=>{if(!owned)throw Error('OwnershipChanged');},verify:async event=>{const permit=mint(event,{...binding,phase:'ready',observedMs:1000,expiresMs:2000});await Promise.resolve();if(change==='clock')at=2000;else owned=false;return permit;}});
  await expect(sendMaintenanceCommand(clients,'ecs',new RunTaskCommand({}),{kind:'admin',operation:'promote'})).rejects.toThrow();expect(calls).toBe(0);
 }
});
it('permits are branded, event-bound, one-shot, and consume checks must be synchronous',async()=>{
 const clients={ecs:{send:async()=>{}}};install(clients,async()=>{});const event={kind:'admin',operation:'canary',input:{value:1}},permit=await assertMaintenanceDispatch(clients,event);
 expect(()=>consumeMaintenancePermit(clients,{},event)).toThrow();expect(()=>consumeMaintenancePermit(clients,permit,{...event,operation:'promote'})).toThrow();consumeMaintenancePermit(clients,permit,event);expect(()=>consumeMaintenancePermit(clients,permit,event)).toThrow();
 const other={ecs:{send:async()=>{throw Error('MustNotSend');}}};install(other,async()=>{},{assertCurrent:async()=>{}});await expect(sendMaintenanceCommand(other,'ecs',new RunTaskCommand({}),{kind:'admin',operation:'canary'})).rejects.toThrow('Synchronous');
});
it('writer clients are selected for marked transitions',async()=>{
 let calls=0;const clients={ssm:{send:async()=>{throw Error('ReadClientUsed');}},ssmWrite:{send:async()=>{calls++;return {};}}};install(clients,async()=>{});
 await sendMaintenanceCommand(clients,'ssm',new PutParameterCommand({Name:'/synthetic',Value:'{}'}),{kind:'admin',operation:'canary'});expect(calls).toBe(1);
});
it('expiry reached inside the final synchronous ownership check prevents the SDK write',async()=>{
 let at=1000,writes=0;
 const clients={ecsWrite:{send:async()=>{writes++;}}};
 install(clients,async()=>{},{now:()=>at,assertCurrent:()=>{at=301000;}});
 await expect(sendMaintenanceCommand(clients,'ecs',new RunTaskCommand({taskDefinition:'reviewed'}),{kind:'admin',operation:'promote'})).rejects.toThrow('MaintenancePermitExpired');
 expect(writes).toBe(0);
});
it('required state survives client wrapping and omission or false transition flags cannot enable legacy fallback',async()=>{
 let writes=0;const source=requireMaintenanceAdmission({}),clients=inheritMaintenanceAdmission(source,{ecsWrite:{send:async()=>{writes++;}}});
 for(const flag of [{},{transitionRequired:false}])await expect(sendMaintenanceCommand(clients,'ecs',new RunTaskCommand({}),{kind:'admin',operation:'promote',...flag})).rejects.toThrow('MaintenanceAdmissionRequired');
 expect(writes).toBe(0);
});
