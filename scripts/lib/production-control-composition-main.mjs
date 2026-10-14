/** The fixed foreground action owns SOURCE, protected source, composition and
 * cleanup. Only raw service/host transports may be substituted in tests. */
import {resolve} from 'node:path';
import {openProductionControlCompositionSourceGate} from '../verify-ci-smoke-isolation.mjs';
import {ciSmokeHost,removeSmokeDirectory} from './ci-smoke-host.mjs';
import {compositionNeed as need} from './production-control-composition.mjs';
import {verifyProductionControlCompositionProtectedSource,requireProductionControlCompositionProtectedSource} from './production-control-composition-protected-source.mjs';
import {runProductionControlComposition} from './production-control-composition-controller.mjs';
import {captureProductionControlCompositionRuntime,closeProductionControlCompositionRuntime} from './production-control-composition-runtime.mjs';
import {productionControlCompositionCommitment} from './production-control-composition-reader.mjs';
import {requireProductionControlCompositionAllocation,reserveProductionControlComposition,holdProductionControlComposition,closeProductionControlCompositionAllocation,productionControlCompositionSnapshot} from './production-control-composition-lifetime.mjs';
import {CONTROL_COMPOSITION_MAIN_OUTPUT_BYTES,CONTROL_COMPOSITION_MAIN_OUTPUT_CHARGE} from './production-control-composition-main-policy.mjs';

export function validateProductionControlCompositionMainEnvironment(env){
 need(process.versions.node.split('.')[0]==='24'&&env.GITHUB_ACTIONS==='true'&&env.GITHUB_EVENT_NAME==='push'&&env.GITHUB_REF==='refs/heads/main'&&
  env.GITHUB_JOB==='build-image-transition-control'&&env.STAGE==='prod','ControlCompositionMainScope');
 need(typeof env.RUNNER_TEMP==='string'&&resolve(env.RUNNER_TEMP)===env.RUNNER_TEMP&&
  typeof env.GITHUB_WORKSPACE==='string'&&resolve(env.GITHUB_WORKSPACE)===env.GITHUB_WORKSPACE,'ControlCompositionMainPaths');
 need(!Object.keys(env).some(key=>key.startsWith('INPUT_')),'ControlCompositionMainInput');
 return env;
}

export async function runProductionControlCompositionMain({env=process.env,host,signal}={},seams={}){
 validateProductionControlCompositionMainEnvironment(env);signal?.throwIfAborted();
 need(Object.keys(seams).every(k=>['source','protectedSource','composition'].includes(k)),'ControlCompositionMainSeam');
 host??=ciSmokeHost(env,env.GITHUB_WORKSPACE);
 need(host.env===env,'ControlCompositionMainHost');
 let allocation,runtimeHandle,sourceOwned=false,compositionStarted=false,operationError,cleanupError,result;
 try{
  const source=await openProductionControlCompositionSourceGate({host,tempRoot:env.RUNNER_TEMP,signal},seams.source);
  allocation=source.compositionAllocation;sourceOwned=true;
  const current=requireProductionControlCompositionAllocation(allocation);
  const price=current.plan.parts.actionOutput;
  need(price&&Object.keys(price).length===5&&Object.entries(CONTROL_COMPOSITION_MAIN_OUTPUT_CHARGE).every(([k,n])=>price[k]===n),'ControlCompositionMainOutputFunding');
  reserveProductionControlComposition(allocation,CONTROL_COMPOSITION_MAIN_OUTPUT_CHARGE);
  if(current.plan.version===2){
   runtimeHandle=await captureProductionControlCompositionRuntime({allocation,actualMain:source.actualMain,env,signal});
  }
  // The direct protected-source verifier consumes the native source and its
  // receipt hash. No later process reloads the SOURCE files or revives it.
  await removeSmokeDirectory(env,'mem9-ci-smoke-source');sourceOwned=false;
  const protectedSource=await verifyProductionControlCompositionProtectedSource({allocation,env,host,sourceReceiptHash:source.sourceReceipt.sha256,signal},seams.protectedSource);
  requireProductionControlCompositionProtectedSource(protectedSource,allocation);
  signal?.throwIfAborted();compositionStarted=true;
  const completed=await runProductionControlComposition({allocation,actualMain:source.actualMain,...(runtimeHandle?{runtimeHandle}:{}),env,tempRoot:env.RUNNER_TEMP,signal},seams.composition);
  need(completed.version===current.plan.version&&completed.accounting.closed===true&&completed.accounting.held===false,'ControlCompositionMainCompletion');
  const publication=completed.capture;
  need(publication.version===current.plan.version,'ControlCompositionMainCaptureVersion');
  if(current.plan.version===2)need(completed.runtimeTerminal?.cleanupComplete===true,'ControlCompositionMainRuntimeCompletion');
  const commitment=productionControlCompositionCommitment({grantSetId:current.config.startup.grantSetId,ref:publication.ref,capture:publication.capture,
   ...(current.plan.version===2?{runtimeTerminal:completed.runtimeTerminal}:{})});
  need(commitment.version===current.plan.version,'ControlCompositionMainCommitmentVersion');
  result=Object.freeze({version:current.plan.version,kind:'native-control-composition-action-result',imageTag:'mem9-'+source.actualMain.mainRevision.slice(0,7),
   digest:publication.capture.image.rootDigest,commitment});
  need(Buffer.byteLength(JSON.stringify(result))<=CONTROL_COMPOSITION_MAIN_OUTPUT_BYTES,'ControlCompositionMainOutputBound');
 }catch(error){operationError=error;}
 finally{
  if(sourceOwned)try{await removeSmokeDirectory(env,'mem9-ci-smoke-source');}catch(error){cleanupError=error;}
  if(runtimeHandle&&!compositionStarted)try{await closeProductionControlCompositionRuntime(runtimeHandle,allocation);}catch(error){cleanupError??=error;}
  if(allocation&&!productionControlCompositionSnapshot(allocation).closed){
   try{
    holdProductionControlComposition(allocation,operationError?.message??'ControlCompositionMainIncomplete');
    // The controller owns its transport/output/cache cleanup after entry.
    // Before that handoff, a protected-reader failure needs explicit cleanup
    // evidence rather than an optimistic success label.
    closeProductionControlCompositionAllocation(allocation,{cleanupComplete:!cleanupError&&!compositionStarted&&operationError?.cleanupComplete===true});
   }catch(error){cleanupError??=error;}
  }
 }
 if(cleanupError)throw Object.assign(Error('ControlCompositionMainCleanup'),{cause:cleanupError,operationError,cleanupComplete:false});
 if(operationError)throw operationError;
 return result;
}
