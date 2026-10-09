import {describe,it,expect} from 'vitest';
import {compileGatewayRuntimeCanaryScope,renderGatewayRuntimeCanaryTemplate,gatewayCanaryDocumentHash} from './lib/gateway-runtime-canary-resources.mjs';
import {expectedGatewayBoundaryPolicyDocument} from './lib/gateway-workload-boundary.mjs';
import {runGatewayRuntimeCanaryLifecycle} from './lib/gateway-runtime-canary-lifecycle.mjs';

const hash=c=>c.repeat(64),scope=compileGatewayRuntimeCanaryScope({accountId:'123456789012',applicationRegion:'ap-northeast-1',verificationId:'abcdef012345',vpcId:'vpc-0123456789abcdef0',ownerRoleArn:'arn:aws:iam::123456789012:role/example-runtime-operator'});
const plan=renderGatewayRuntimeCanaryTemplate({scope,originalBoundary:expectedGatewayBoundaryPolicyDocument({partition:'aws',accountId:scope.accountId,applicationRegion:scope.applicationRegion,policyRevision:'r1'}),handlerSource:'exports.handler=async()=>{};\n'});
function fixture(change={}){
  const calls=[],records=[];let mode='comparison',deleted=false,time=1000,phase=0;
  const stackId=scope.stackArnPattern.replace('*','11111111-1111-1111-1111-'+'1'.repeat(12));
  const keyArn=scope.keyArnPattern.replace('*','22222222-2222-2222-2222-'+'2'.repeat(12));
  const resolve=v=>Array.isArray(v)?v.map(resolve):v&&typeof v==='object'?v['Fn::GetAtt']?v['Fn::GetAtt'][0]==='SyntheticKey'?keyArn:scope.roleArn:Object.fromEntries(Object.entries(v).map(([k,x])=>[k,resolve(x)])):v;
  const state=()=>({stackId,roleArn:scope.roleArn,roleId:'AROASYNTHETIC0000001',functionArn:scope.functionArn,keyArn,
    boundaryArn:mode==='original'?scope.originalBoundaryArn:scope.comparisonArn,
    originalPolicyHash:plan.comparison.originalHash,comparisonPolicyHash:plan.comparison.comparisonHash,
    handlerHash:plan.handlerHash,codeHash:hash('1'),configurationHash:hash('2'),
    identityPolicyHash:gatewayCanaryDocumentHash(resolve(plan.template.Resources.CanaryIdentityPolicy.Properties.PolicyDocument)),
    keyPolicyHash:gatewayCanaryDocumentHash(resolve(plan.template.Resources.SyntheticKey.Properties.KeyPolicy)),keyGrantsHash:gatewayCanaryDocumentHash([])});
  const ops={
    async assertAbsent(){calls.push('absent');},
    async createStack(request){calls.push('create');expect(request.TemplateBody).toBe(plan.templateBody);return {StackId:stackId};},
    async describeStack(){calls.push('describe');return {StackId:stackId,StackStatus:deleted?'DELETE_COMPLETE':'UPDATE_COMPLETE'};},
    async readState(){calls.push('state');return {...state(),...(phase===2?change.drift??{}:{})};},
    async changeBoundary(request){calls.push('boundary:'+request.Parameters[0].ParameterValue);expect(request.UsePreviousTemplate).toBe(true);expect(request.TemplateBody).toBeUndefined();mode=request.Parameters[0].ParameterValue;return {StackId:stackId};},
    async collectPhase(request){calls.push('phase:'+request.phase);phase++;if(change.failPhase===request.phase)throw Error('SyntheticServiceFailure');return {phase:request.phase,invocation:'synthetic-invocation-'+phase};},
    async discoverOwnedKeys(){calls.push('keys');return [keyArn];},
    async deleteStack(){calls.push('delete');deleted=true;},
    async verifyCleanup(){calls.push('cleanup');return {stackAbsent:true,functionAbsent:true,roleAbsent:true,comparisonAbsent:true,logGroupAbsent:true,keys:[{arn:keyArn,state:change.keyState??'PendingDeletion',pendingWindowInDays:7}]};},
  };
  Object.assign(ops,change.ops??{});
  const input={plan,ops,async record(record){records.push(record);},verifyPhase(record,context){expect(record.phase).toBe(context.phase);if(change.rejectEvidence)throw Error('SyntheticProofRejected');return record;}};
  const test={now:()=>time,wait:async(ms)=>{time+=ms;}};
  return{input,test,calls,records,keyArn,stackId};
}
describe('finite Gateway canary lifecycle',()=>{
  it.each(['GatewayRuntimeEvidenceServiceAuthorization','GatewayRuntimeEvidenceFields','GatewayCanaryAwsInvokeResponse','GatewayCanaryAwsServiceError'])('retains closed internal reason %s without replay',async reason=>{
    const f=fixture({ops:{async collectPhase(){throw Error(reason);}}});
    const r=await runGatewayRuntimeCanaryLifecycle(f.input,f.test);
    expect(r.reason).toBe(reason);expect(f.records.find(v=>v.event==='held').reason).toBe(reason);
    expect(r.status).toBe('HELD');expect(r.cleanupComplete).toBe(true);
  });
  it.each(['GatewayRuntimeEvidenceSECRET','GatewayRuntimeCanarySECRET','GatewayCanaryAwsSECRET','GatewayRuntimeEvidenceFields secret'])('never logs an unrecognized internal-looking message %s',async reason=>{
    const f=fixture({ops:{async collectPhase(){throw Error(reason);}}});
    const r=await runGatewayRuntimeCanaryLifecycle(f.input,f.test);
    expect(r.reason).toBe('GatewayRuntimeCanaryOperationFailed');expect(JSON.stringify(f.records)).not.toContain(reason);
  });
  it('runs comparison A1, original B, comparison A2 on unchanged identity/code and then cleans',async()=>{
    const f=fixture(),r=await runGatewayRuntimeCanaryLifecycle(f.input,f.test);
    expect(r.status).toBe('OBSERVATIONS_COMPLETE');expect(r.cleanupComplete).toBe(true);
    expect(f.calls.filter(c=>c.startsWith('phase:'))).toEqual(['phase:A1','phase:B','phase:A2']);
    expect(f.calls.filter(c=>c.startsWith('boundary:'))).toEqual(['boundary:original','boundary:comparison']);
    expect(f.calls.filter(c=>c==='create')).toHaveLength(1);
    expect(f.calls.slice(-4)).toEqual(['keys','delete','describe','cleanup']);
    expect(r.phases.map(p=>p.phase)).toEqual(['A1','B','A2']);
    expect(r).not.toHaveProperty('securityPass');expect(r).not.toHaveProperty('productionApproved');
    expect(f.records.find(r=>r.event==='create-intent').templateHash).toBe(plan.templateHash);
  });
  it('records intent before dispatch and never creates when durable recording fails',async()=>{
    const f=fixture();f.input.record=async r=>{if(r.event==='create-intent')throw Error('DiskFull');};
    const r=await runGatewayRuntimeCanaryLifecycle(f.input,f.test);
    expect(r.status).toBe('HELD');expect(f.calls).not.toContain('create');expect(f.calls).not.toContain('delete');
  });
  it('always cleans after a service/proof failure without replaying any phase',async()=>{
    for(const delta of [{failPhase:'B'},{rejectEvidence:true}]){
      const f=fixture(delta),r=await runGatewayRuntimeCanaryLifecycle(f.input,f.test);
      expect(r.status).toBe('HELD');expect(r.cleanupComplete).toBe(true);expect(f.calls).toContain('delete');
      expect(f.calls.filter(c=>c==='create')).toHaveLength(1);expect(f.calls).not.toContain('phase:A2');
    }
  });
  it.each(['roleId','codeHash','keyPolicyHash','keyGrantsHash','configurationHash','identityPolicyHash','originalPolicyHash'])('rejects drift of %s and retains cleanup',async field=>{
    const f=fixture({drift:{[field]:field==='roleId'?'AROAREPLACED00000001':hash('f')}}),r=await runGatewayRuntimeCanaryLifecycle(f.input,f.test);
    expect(r.status).toBe('HELD');expect(f.calls).not.toContain('phase:A2');expect(r.cleanupComplete).toBe(true);
  });
  it('does not claim cleanup while the key remains enabled',async()=>{
    const f=fixture({keyState:'Enabled'}),r=await runGatewayRuntimeCanaryLifecycle(f.input,f.test);
    expect(r.status).toBe('HELD');expect(r.cleanupComplete).toBe(false);
  });
  it('attempts fixed-scope cleanup after an unknown create and never creates again',async()=>{
    const f=fixture({ops:{async createStack(){throw Object.assign(Error('Unknown'),{unknown:true});}}});
    const r=await runGatewayRuntimeCanaryLifecycle(f.input,f.test);
    expect(r.status).toBe('HELD');expect(f.calls).toContain('keys');expect(f.calls).toContain('delete');
    expect(f.calls.some(c=>c.startsWith('phase:'))).toBe(false);
  });
  it('keeps cleanup usable after normal cancellation',async()=>{
    const abort=new AbortController(),f=fixture({ops:{async collectPhase(){abort.abort();throw Error('Aborted');},async deleteStack(request){expect(request.signal.aborted).toBe(false);f.calls.push('delete');}}});
    f.input.signal=abort.signal;const r=await runGatewayRuntimeCanaryLifecycle(f.input,f.test);
    expect(r.status).toBe('HELD');expect(f.calls).toContain('delete');
  });
  it('does not delete a preexisting same-name stack',async()=>{
    const f=fixture({ops:{async assertAbsent(){throw Error('AlreadyExists');}}});
    const r=await runGatewayRuntimeCanaryLifecycle(f.input,f.test);
    expect(r.status).toBe('HELD');expect(f.calls).not.toContain('delete');expect(f.calls).not.toContain('create');
  });
  it('rejects a modified template before any operation',async()=>{
    const f=fixture();f.input.plan={...plan,templateBody:plan.templateBody+' '};
    await expect(runGatewayRuntimeCanaryLifecycle(f.input,f.test)).rejects.toThrow();expect(f.calls).toEqual([]);
  });
  it('rejects a self-rehashed privilege expansion before any operation',async()=>{
    const f=fixture(),changed=structuredClone(plan);
    changed.template.Resources.CanaryIdentityPolicy.Properties.PolicyDocument.Statement.push({Effect:'Allow',Action:'iam:*',Resource:'*'});
    changed.templateBody=JSON.stringify(changed.template);
    const {createHash}=await import('node:crypto');changed.templateHash=createHash('sha256').update(changed.templateBody).digest('hex');
    f.input.plan=changed;await expect(runGatewayRuntimeCanaryLifecycle(f.input,f.test)).rejects.toThrow(/PlanChanged/);expect(f.calls).toEqual([]);
  });
});
