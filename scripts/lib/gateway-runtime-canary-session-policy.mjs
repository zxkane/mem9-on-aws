import {isDeepStrictEqual} from 'node:util';
import {buildGatewayCanaryOperatorPolicies,buildGatewayCanarySessionPolicyBootstrap,gatewayCanaryDocumentHash} from './gateway-runtime-canary-resources.mjs';

const check=(ok,reason)=>{if(!ok)throw Error('GatewayRuntimeCanary'+reason);};
const exact=(v,keys)=>v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===keys.slice().sort().join();
const freeze=v=>{if(v&&typeof v==='object'){Object.values(v).forEach(freeze);Object.freeze(v);}return v;};

/** A fixed, single-version temporary session restriction, not a role, a grant to
 * an identity, or a general policy publisher. ops comes from the reviewed native
 * adapter with its separate exact-ARN bootstrap session. The callback must stop
 * and clean its resource operation before returning cleanupComplete=true.
 * On unknown creation or incomplete resource cleanup, preserve the record and
 * return HELD; do not delete an unproven policy or recreate the same name.
 */
export async function withGatewayCanaryProvisioningPolicy({scope,ops,record,run}){
  check(exact(ops,['assertSessionPolicyAbsent','createSessionPolicy','readSessionPolicy','deleteSessionPolicy'])&&
    Object.values(ops).every(v=>typeof v==='function')&&typeof record==='function'&&typeof run==='function','SessionAdapter');
  const compiled=buildGatewayCanaryOperatorPolicies(scope),bootstrap=buildGatewayCanarySessionPolicyBootstrap(scope);
  const arn=bootstrap.temporaryPolicyArn,tags=[{Key:'Project',Value:'mem9-on-aws'},{Key:'Stage',Value:scope.stage},{Key:'VerificationId',Value:scope.verificationId}];
  const audit=event=>record(freeze({version:1,verificationId:scope.verificationId,policyArn:arn,policyHash:compiled.provisionHash,...event}));
  let created=false,creationAttempted=false,resourcesCleaned=false,cleanupComplete=false,transportUnclean=false,result,reason;
  function verify(value){
    check(exact(value,['arn','policyId','defaultVersionId','versions','document','tags','attachmentCount','boundaryUsageCount']),'SessionPolicyShape');
    check(value.arn===arn&&typeof value.policyId==='string'&&/^ANPA[A-Z0-9]{12,124}$/.test(value.policyId)&&
      value.defaultVersionId==='v1'&&isDeepStrictEqual(value.versions,['v1'])&&value.attachmentCount===0&&value.boundaryUsageCount===0,'SessionPolicyIdentity');
    check(gatewayCanaryDocumentHash(value.document)===compiled.provisionHash,'SessionPolicyChanged');
    check(Array.isArray(value.tags)&&isDeepStrictEqual([...value.tags].sort((a,b)=>a.Key.localeCompare(b.Key)),[...tags].sort((a,b)=>a.Key.localeCompare(b.Key))),'SessionPolicyTags');
    return value.policyId;
  }
  let policyId;
  try{
    await ops.assertSessionPolicyAbsent({PolicyArn:arn});
    await audit({event:'session-policy-create-intent'});creationAttempted=true;
    const response=await ops.createSessionPolicy({PolicyName:arn.split('/').at(-1),Path:'/',PolicyDocument:JSON.stringify(compiled.provision),Tags:tags});
    check(response?.Policy?.Arn===arn&&response.Policy.DefaultVersionId==='v1'&&/^ANPA[A-Z0-9]{12,124}$/.test(response.Policy.PolicyId),'SessionPolicyCreate');created=true;
    policyId=response.Policy.PolicyId;
    const current=await ops.readSessionPolicy({PolicyArn:arn});check(verify(current)===policyId,'SessionPolicyReplaced');
    await audit({event:'session-policy-created',policyId});
    result=await run(freeze({PolicyArns:[{arn}],expectedPolicyHash:compiled.provisionHash,expectedPolicyId:policyId,expectedVersionId:'v1',maximumDurationSeconds:3600}));
    resourcesCleaned=result?.cleanupComplete===true;
    check(resourcesCleaned,'ResourceCleanupIncomplete');
  }catch(error){transportUnclean=error?.code==='ECLEANUP'||error?.cleanupComplete===false;
    reason=/^GatewayRuntimeCanary[A-Za-z]+$/.test(error?.message??'')?error.message:'GatewayRuntimeCanarySessionOperationFailed';}
  finally{
    if(created&&resourcesCleaned&&!transportUnclean){
      try{
        check(verify(await ops.readSessionPolicy({PolicyArn:arn}))===policyId,'SessionPolicyReplaced');
        await audit({event:'session-policy-delete-intent',policyId});
        await ops.deleteSessionPolicy({PolicyArn:arn});
        check(await ops.readSessionPolicy({PolicyArn:arn})===null,'SessionPolicyStillExists');
        await audit({event:'session-policy-deleted',policyId});cleanupComplete=true;
      }catch{reason??='GatewayRuntimeCanarySessionCleanupHeld';}
    }else if(!creationAttempted&&!transportUnclean)cleanupComplete=true;
  }
  return freeze({version:1,kind:'gateway-runtime-canary-session-policy',status:!reason&&cleanupComplete?'CLOSED':'HELD',
    policyArn:arn,policyId:policyId??null,policyHash:compiled.provisionHash,cleanupComplete,reason:reason??null,result:result??null});
}
