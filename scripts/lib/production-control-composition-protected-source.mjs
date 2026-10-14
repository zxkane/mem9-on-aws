/** Preserve the existing protected-source verifier and both fresh source
 * passes. This reader has no image/S3 publication or parameter-write action. */
import {verifyImageSecurityDeployment} from '../verify-image-security-deployment.mjs';
import {nonrootHash as hash} from './production-nonroot-contracts.mjs';
import {compositionNeed as need} from './production-control-composition.mjs';
import {openProductionControlCompositionProtectedSourceTransport,productionControlCompositionLocations} from './production-control-composition-transport.mjs';
import {requireProductionControlCompositionAllocation,reserveProductionControlCompositionProtectedSource,recordProductionControlComposition,holdProductionControlComposition} from './production-control-composition-lifetime.mjs';

const verified=new WeakMap();
const commands=[['diff','--quiet'],['diff','--cached','--quiet'],['show','-s','--format=%H%n%T%n%P','HEAD']];
export async function verifyProductionControlCompositionProtectedSource({allocation,env,host,sourceReceiptHash,signal},seams={}){
 const a=requireProductionControlCompositionAllocation(allocation),q=productionControlCompositionLocations(allocation);
 let transport,gitCalls=0,result,handle,operationError,cleanupError,attempted=false;
 try{
  need(host?.env===env&&typeof host.run==='function'&&/^[a-f0-9]{64}$/.test(sourceReceiptHash),'ControlCompositionProtectedSourceInput');
  reserveProductionControlCompositionProtectedSource(allocation);attempted=true;
  transport=await openProductionControlCompositionProtectedSourceTransport({allocation,env,signal},seams);
  const git=async args=>{
   requireProductionControlCompositionAllocation(allocation);need(gitCalls<12&&hash(args)===hash(commands[gitCalls%3]),'ControlCompositionProtectedGit');gitCalls++;
   const out=await host.run('git',args,{maxBytes:8388608,timeoutMs:Math.min(30000,a.deadlineMs-Date.now())});
   requireProductionControlCompositionAllocation(allocation);need(typeof out==='string'&&Buffer.byteLength(out)<=8388608,'ControlCompositionProtectedGitOutput');return out;
  };
  result=await verifyImageSecurityDeployment({clients:transport.clients,git,api:transport.github},
   {env:{...env,STAGE:'prod',MEM9_DEPLOY_ROLE_ARN:q.roleArn,MEM9_DECISION_ARTIFACT_BUCKET:q.bucket},region:q.region,
    phase:'source',minimumValidityMs:35*60*1000,sourceReceiptHash});
  need(result.phase==='nonroot-security-source-verified'&&result.bundle&&gitCalls===12,'ControlCompositionProtectedSourceResult');
  const b=result.bundle;
  need(hash(b.source)===hash(a.source),'ControlCompositionProtectedSourceChanged');
  const evidence=Object.freeze({version:1,kind:'native-control-composition-protected-source',planHash:a.plan.planHash,
   descriptorHash:a.config.startup.descriptorHash,proofHash:a.config.startup.proofHash,parameterVersion:a.config.target.parameterVersion,
   sourceHash:hash(a.source),sourceReceiptHash,checkedMs:Date.now(),gitCalls});
  recordProductionControlComposition(allocation,'protected-source-verified',evidence);
  handle=Object.freeze({kind:'native-control-composition-protected-source'});verified.set(handle,{allocation,evidence,bundle:b});
 }catch(error){operationError=error;holdProductionControlComposition(allocation,error.message);}
 finally{if(transport)try{await transport.close();}catch(error){cleanupError=error;}}
 if(cleanupError){holdProductionControlComposition(allocation,cleanupError.message);throw Object.assign(Error('ControlCompositionProtectedSourceCleanup'),{cause:cleanupError,operationError,cleanupComplete:false});}
 if(operationError){
  const cleanupComplete=Boolean(transport)||!attempted||operationError.cleanupComplete===true;
  if(Object.isExtensible(operationError)){operationError.cleanupComplete=cleanupComplete;throw operationError;}
  throw Object.assign(new Error(operationError.message,{cause:operationError}),{name:operationError.name,cleanupComplete});
 }
 return handle;
}
export function requireProductionControlCompositionProtectedSource(handle,allocation){
 const s=verified.get(handle);need(s&&s.allocation===allocation,'ControlCompositionNativeProtectedSource');
 requireProductionControlCompositionAllocation(allocation);return s;
}
