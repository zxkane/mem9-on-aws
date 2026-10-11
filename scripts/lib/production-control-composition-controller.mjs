/** One foreground lifetime; all authority is the original native main child.
 * No SOURCE receipt, completed JSON capture or callback can create it. */
import {nonrootHash as hash,inspectNonrootRecord} from './production-nonroot-contracts.mjs';
import {compositionNeed as need} from './production-control-composition.mjs';
import {requireProductionControlCompositionAllocation,holdProductionControlComposition,closeProductionControlCompositionAllocation} from './production-control-composition-lifetime.mjs';
import {openProductionControlCompositionTransport} from './production-control-composition-transport.mjs';
import {materializeProductionControlCompositionPacks,requireProductionControlCompositionPacks,verifyProductionControlCompositionRuntime as verifyLegacyRuntime,verifyProductionControlCompositionSource,closeProductionControlCompositionPacks} from './production-control-composition-packs.mjs';
import {requireProductionControlCompositionRuntime,verifyProductionControlCompositionRuntime,closeProductionControlCompositionRuntimeAllocation,productionControlCompositionRuntimeTerminal} from './production-control-composition-runtime.mjs';
import {acquireProductionControlCompositionBase,requireProductionControlCompositionBase,closeProductionControlCompositionBase} from './production-control-composition-base.mjs';
import {composeProductionControl,closeProductionControlCompositionOutput} from './production-control-composition-producer.mjs';
import {publishProductionControlComposition} from './production-control-composition-publisher.mjs';

export async function runProductionControlComposition({allocation,actualMain,runtimeHandle,env,tempRoot,signal},seams={}){
 const a=requireProductionControlCompositionAllocation(allocation);
 let transport,packs,base,output,capture,error,cleanupError,snapshot;
 const checkRuntime=async phase=>{if(a.plan.version===2){await verifyProductionControlCompositionSource(packs,allocation,phase);await verifyProductionControlCompositionRuntime(runtimeHandle,allocation,phase);}else await verifyLegacyRuntime(packs,allocation,phase);};
 try{
  if(a.plan.version===2)requireProductionControlCompositionRuntime(runtimeHandle,allocation);else need(runtimeHandle===undefined,'ControlCompositionRuntimeVersion');
  const main=inspectNonrootRecord('ActualMainV1',actualMain),b=a.binding.source;
  need(Object.keys(seams).every(k=>k==='requestHandler'),'ControlCompositionControllerSeam');
  for(const key of ['repository','candidateRevision','candidateTree','baseRevision','mainRevision','mainTree','parents','prNumber','workflowPath','workflowSha'])
   need(hash(main[key])===hash(b[key]),'ControlCompositionActualMain');
  need(main.workflowRun===b.runId&&main.workflowAttempt===b.runAttempt,'ControlCompositionActualMain');
  transport=await openProductionControlCompositionTransport({allocation,env,signal},seams);
  packs=await materializeProductionControlCompositionPacks({allocation,transport});
  await checkRuntime('packs');
  const {sourceContext}=requireProductionControlCompositionPacks(packs,allocation);
  need(sourceContext.tree===main.mainTree&&sourceContext.tree===a.plan.input.source.candidateTree,'ControlCompositionSourceTree');
  await checkRuntime('source');
  base=await acquireProductionControlCompositionBase({allocation,transport});
  await checkRuntime('base');
  output=await composeProductionControl({allocation,plan:a.plan,actualMain:main,sourceContext,...requireProductionControlCompositionBase(base,allocation),tempRoot:a.plan.version===2?a.directory:tempRoot,signal});
  await checkRuntime('composed');
  await publishProductionControlComposition({allocation,transport,output});
  await checkRuntime('published');
  capture=await transport.capture();
  await checkRuntime('captured');
 }catch(e){error=e;holdProductionControlComposition(allocation,e.message);}
 finally{
  // Raw streams/credentials drain before any cache disappears. Failure of one
  // cleanup never prevents the remaining local resources from being closed.
  const finish=async operation=>{try{await operation();}catch(e){cleanupError??=e;}};
  if(transport)await finish(()=>transport.close());
  if(output)await finish(()=>closeProductionControlCompositionOutput(output));
  if(base)await finish(()=>closeProductionControlCompositionBase(base));
  if(packs)await finish(()=>closeProductionControlCompositionPacks(packs));
  if(a.plan.version===2)await finish(()=>closeProductionControlCompositionRuntimeAllocation(allocation));
  try{snapshot=closeProductionControlCompositionAllocation(allocation,{cleanupComplete:!cleanupError});}catch(e){cleanupError??=e;}
 }
 if(cleanupError)throw Object.assign(Error('ControlCompositionControllerCleanup'),{cause:cleanupError,operationError:error});
 if(error)throw error;
 return Object.freeze({version:a.plan.version,kind:'native-control-composition-completed',authority:false,capture,accounting:snapshot,
  ...(a.plan.version===2?{runtimeTerminal:productionControlCompositionRuntimeTerminal(runtimeHandle,allocation)}:{})});
}
