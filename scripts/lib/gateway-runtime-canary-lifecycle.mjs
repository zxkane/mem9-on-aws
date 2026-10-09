import {createHash} from 'node:crypto';
import {isDeepStrictEqual} from 'node:util';
import {setTimeout as sleep} from 'node:timers/promises';
import {verifyGatewayRuntimeCanaryPlan,gatewayCanaryDocumentHash,GATEWAY_CANARY_LIMITS as L} from './gateway-runtime-canary-resources.mjs';
import {gatewayCanaryInternalReason as safeError} from './gateway-runtime-canary-evidence.mjs';

const check=(ok,reason)=>{if(!ok)throw Error('GatewayRuntimeCanary'+reason);};
const sha=value=>createHash('sha256').update(value).digest('hex');
const hex=value=>typeof value==='string'&&/^[a-f0-9]{64}$/.test(value);
const exact=(v,keys)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===keys.slice().sort().join();
const freeze=v=>{if(v&&typeof v==='object'){Object.values(v).forEach(freeze);Object.freeze(v);}return v;};
const OPS=['assertAbsent','createStack','describeStack','readState','changeBoundary','collectPhase','discoverOwnedKeys','deleteStack','verifyCleanup'];
const STATE=['stackId','roleArn','roleId','functionArn','keyArn','boundaryArn','originalPolicyHash','comparisonPolicyHash',
  'handlerHash','codeHash','configurationHash','identityPolicyHash','keyPolicyHash','keyGrantsHash'];
const UUID='[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}';

/** Finite orchestration, not an AWS client or a business-authority issuer.
 * ops is a trusted, same-process native adapter, never serialized configuration.
 * It authenticates the source, code, raw service responses and transport stop;
 * readState includes hashes derived from complete native readbacks, not caller
 * assertions. collectPhase reuses one prepared ciphertext/context for all three
 * phases and journals bounded diagnostics before validating each response.
 * verifyPhase is the independently owned handler/evidence verifier. It must
 * reject non-service errors and altered bindings, not merely return a flag.
 * Returned observations still require the native acceptance/provenance gate.
 */
export async function runGatewayRuntimeCanaryLifecycle(input,test={}){
  check(exact(input,['plan','ops','record','verifyPhase'])||exact(input,['plan','ops','record','verifyPhase','signal']),'LifecycleInput');
  check(Object.keys(test).every(k=>['now','wait'].includes(k)),'TestOptions');
  const {ops,record,verifyPhase}=input;
  check(exact(ops,OPS)&&OPS.every(k=>typeof ops[k]==='function')&&typeof record==='function'&&typeof verifyPhase==='function','NativeAdapter');
  const plan=verifyGatewayRuntimeCanaryPlan(input.plan),s=plan.scope;
  check(typeof plan.templateBody==='string'&&Buffer.byteLength(plan.templateBody)<=L.maximumTemplateBytes&&
    sha(plan.templateBody)===plan.templateHash&&isDeepStrictEqual(JSON.parse(plan.templateBody),plan.template),'TemplateBinding');
  check(hex(plan.handlerHash)&&plan.template.Metadata.HandlerHash===plan.handlerHash&&
    plan.template.Metadata.OriginalBoundaryHash===plan.comparison.originalHash&&
    plan.template.Metadata.ComparisonBoundaryHash===plan.comparison.comparisonHash,'PlanBinding');
  const now=test.now??Date.now,wait=test.wait??((ms,signal)=>sleep(ms,undefined,{signal}));
  const started=now();check(Number.isSafeInteger(started)&&started>=0,'Clock');
  const normal=AbortSignal.any([AbortSignal.timeout(L.operationMs),...(input.signal?[input.signal]:[])]);
  let attempted=false,cleanupComplete=false,stackId,keyArn,reference,failed,unknown=false,transportUnclean=false,diagnosticWriteFailed=false;
  const phases=[];
  const stackPattern=new RegExp('^'+RegExp.escape(s.stackArnPattern.slice(0,-1))+UUID+'$');
  const keyPattern=new RegExp('^'+RegExp.escape(s.keyArnPattern.slice(0,-1))+UUID+'$');
  const checkTime=(deadline,signal)=>{signal.throwIfAborted();check(now()<deadline,'Deadline');};
  const normalDeadline=started+L.operationMs;
  const write=async recordValue=>record(freeze({version:1,verificationId:s.verificationId,templateHash:plan.templateHash,...recordValue}));
  async function settledStack(target,deadline,signal,deleted=false){
    for(let i=0;i<L.stackPolls;i++){
      checkTime(deadline,signal);
      const value=await ops.describeStack({StackName:target,signal});
      if(deleted&&value===null)return;
      check(value&&stackPattern.test(value.StackId)&&(!stackId||value.StackId===stackId),'StackIdentity');
      if(deleted?value.StackStatus==='DELETE_COMPLETE':['CREATE_COMPLETE','UPDATE_COMPLETE'].includes(value.StackStatus))return;
      check(!/FAILED|ROLLBACK/.test(value.StackStatus),'StackFailed');
      await wait(L.stackPollDelayMs,signal);
    }
    throw Error('GatewayRuntimeCanaryStackDeadline');
  }
  function validateState(value,mode){
    check(exact(value,STATE),'StateShape');
    check(value.stackId===stackId&&value.roleArn===s.roleArn&&value.functionArn===s.functionArn&&
      /^AROA[A-Z0-9]{12,124}$/.test(value.roleId)&&keyPattern.test(value.keyArn),'ResourceIdentity');
    check(value.handlerHash===plan.handlerHash&&value.originalPolicyHash===plan.comparison.originalHash&&
      value.comparisonPolicyHash===plan.comparison.comparisonHash,'PolicyOrCodeChanged');
    check(STATE.filter(k=>k.endsWith('Hash')).every(k=>hex(value[k])),'StateHash');
    const resolve=v=>Array.isArray(v)?v.map(resolve):v&&typeof v==='object'
      ?v['Fn::GetAtt']?v['Fn::GetAtt'][0]==='SyntheticKey'?value.keyArn:s.roleArn:Object.fromEntries(Object.entries(v).map(([k,x])=>[k,resolve(x)])):v;
    check(value.identityPolicyHash===gatewayCanaryDocumentHash(resolve(plan.template.Resources.CanaryIdentityPolicy.Properties.PolicyDocument))&&
      value.keyPolicyHash===gatewayCanaryDocumentHash(resolve(plan.template.Resources.SyntheticKey.Properties.KeyPolicy))&&
      value.keyGrantsHash===gatewayCanaryDocumentHash([]),'UnexpectedResourcePolicy');
    const boundary=mode==='original'?s.originalBoundaryArn:s.comparisonArn;
    check(value.boundaryArn===boundary,'BoundaryNotPropagated');
    if(reference){const expected={...reference,boundaryArn:boundary};check(isDeepStrictEqual(value,expected),'StateDrift');}
    else{reference=freeze(structuredClone(value));keyArn=value.keyArn;}
    return freeze(structuredClone(value));
  }
  async function inspect(mode){
    for(let i=0;i<L.propagationAttempts;i++){
      checkTime(normalDeadline,normal);const value=await ops.readState({scope:s,stackId,signal:normal});
      // Only the previous, known boundary can be an IAM propagation lag. Any
      // other identity/policy change fails, and runtime service failures do not
      // trigger a hidden rebuild or an additional create operation.
      if(value?.boundaryArn!== (mode==='original'?s.originalBoundaryArn:s.comparisonArn)){
        check([s.originalBoundaryArn,s.comparisonArn].includes(value?.boundaryArn),'ForeignBoundary');
        if(i+1<L.propagationAttempts){await wait(L.propagationDelayMs,normal);continue;}
      }
      return validateState(value,mode);
    }
  }
  try{
    checkTime(normalDeadline,normal);await ops.assertAbsent({scope:s,signal:normal});
    await write({event:'create-intent'});checkTime(normalDeadline,normal);attempted=true;
    const created=await ops.createStack({StackName:s.stackName,TemplateBody:plan.templateBody,Capabilities:['CAPABILITY_NAMED_IAM'],
      Parameters:[{ParameterKey:'BoundaryMode',ParameterValue:'comparison'}],ClientRequestToken:'gateway-'+s.verificationId+'-create',OnFailure:'DELETE',signal:normal});
    check(created&&stackPattern.test(created.StackId),'StackIdentity');stackId=created.StackId;
    await write({event:'create-complete',stackId});await settledStack(stackId,normalDeadline,normal);
    for(const [phase,mode]of [['A1','comparison'],['B','original'],['A2','comparison']]){
      if(phase!=='A1'){
        checkTime(normalDeadline,normal);await write({event:'boundary-intent',phase,mode,stackId});
        const changed=await ops.changeBoundary({StackName:stackId,UsePreviousTemplate:true,Capabilities:['CAPABILITY_NAMED_IAM'],
          Parameters:[{ParameterKey:'BoundaryMode',ParameterValue:mode}],ClientRequestToken:'gateway-'+s.verificationId+'-'+phase,signal:normal});
        check(changed?.StackId===stackId,'StackIdentity');await settledStack(stackId,normalDeadline,normal);
      }
      const before=await inspect(mode);
      await write({event:'phase-intent',phase,stateHash:gatewayCanaryDocumentHash(before)});
      checkTime(normalDeadline,normal);
      const evidence=await ops.collectPhase({phase,scope:s,stackId,keyArn,handlerHash:plan.handlerHash,reference,signal:normal,timeoutMs:L.invokeTimeoutMs});
      const after=await inspect(mode);check(isDeepStrictEqual(before,after),'StateDrift');
      const verified=await verifyPhase(evidence,{phase,scope:s,reference,before,after,plan});
      check(verified&&typeof verified==='object'&&!Array.isArray(verified),'PhaseEvidence');
      const captured=freeze(structuredClone(verified));
      await write({event:'phase-complete',phase,evidenceHash:gatewayCanaryDocumentHash(captured)});
      phases.push(freeze({phase,evidence:captured,state:after}));
    }
  }catch(error){failed=safeError(error);unknown=error?.unknown===true;
    transportUnclean=error?.code==='ECLEANUP'||error?.cleanupComplete===false;
    diagnosticWriteFailed=error?.diagnosticWriteFailed===true;
    try{await write({event:'held',reason:failed,unknown,...(diagnosticWriteFailed?{diagnosticWriteFailed:true}:{})});}catch{}
  }finally{
    if(transportUnclean)cleanupComplete=false;
    else if(attempted){
      // Normal cancellation must not close the scoped cleanup transport. No
      // source refresh or replacement session is requested here.
      const cleanupSignal=AbortSignal.timeout(L.cleanupMs),deadline=now()+L.cleanupMs;
      try{
        checkTime(deadline,cleanupSignal);
        const keys=await ops.discoverOwnedKeys({scope:s,stackId:stackId??null,signal:cleanupSignal});
        check(Array.isArray(keys)&&keys.length<=1&&keys.every(k=>keyPattern.test(k))&&(!keyArn||keys.includes(keyArn)),'CleanupKeyIdentity');
        await write({event:'cleanup-intent',stackId:stackId??null,keys});checkTime(deadline,cleanupSignal);
        await ops.deleteStack({StackName:stackId??s.stackName,ClientRequestToken:'gateway-'+s.verificationId+'-delete',signal:cleanupSignal});
        await settledStack(stackId??s.stackName,deadline,cleanupSignal,true);
        const cleanup=await ops.verifyCleanup({scope:s,stackId:stackId??null,keys,signal:cleanupSignal});
        check(exact(cleanup,['stackAbsent','functionAbsent','roleAbsent','comparisonAbsent','logGroupAbsent','keys'])&&
          ['stackAbsent','functionAbsent','roleAbsent','comparisonAbsent','logGroupAbsent'].every(k=>cleanup[k]===true)&&
          Array.isArray(cleanup.keys)&&cleanup.keys.length===keys.length&&cleanup.keys.every(k=>
            exact(k,['arn','state','pendingWindowInDays'])&&keys.includes(k.arn)&&k.state==='PendingDeletion'&&k.pendingWindowInDays===7),'CleanupIncomplete');
        await write({event:'cleanup-complete',cleanupHash:gatewayCanaryDocumentHash(cleanup)});cleanupComplete=true;
      }catch(error){failed??=safeError(error);cleanupComplete=false;
        transportUnclean ||= error?.code==='ECLEANUP'||error?.cleanupComplete===false;
      }
    }else cleanupComplete=true;
  }
  // Resource cleanup is still attempted when its transport is joined. Missing
  // diagnostics cannot be certified as a complete audited lifecycle afterward.
  if(diagnosticWriteFailed)cleanupComplete=false;
  return freeze({version:1,kind:'gateway-runtime-canary-observations',status:!failed&&cleanupComplete&&phases.length===3?'OBSERVATIONS_COMPLETE':'HELD',
    verificationId:s.verificationId,templateHash:plan.templateHash,stackId:stackId??null,phases,cleanupComplete,
    cleanupUnconfirmed:transportUnclean,reason:failed??null,unknown,...(diagnosticWriteFailed?{diagnosticWriteFailed:true}:{})});
}
