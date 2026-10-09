import {describe,it,expect} from 'vitest';
import {compileGatewayRuntimeCanaryScope,buildGatewayCanaryOperatorPolicies,buildGatewayCanarySessionPolicyBootstrap} from './lib/gateway-runtime-canary-resources.mjs';
import {withGatewayCanaryProvisioningPolicy} from './lib/gateway-runtime-canary-session-policy.mjs';
const scope=compileGatewayRuntimeCanaryScope({accountId:'123456789012',applicationRegion:'ap-northeast-1',verificationId:'abcdef012345',vpcId:'vpc-0123456789abcdef0',ownerRoleArn:'arn:aws:iam::123456789012:role/example-runtime-operator'});
function fixture(){
  const calls=[],records=[];let current=null;
  const ops={async assertSessionPolicyAbsent(){calls.push('absent');},async createSessionPolicy(request){calls.push('create');
    current={arn:scope.temporaryPolicyArn,policyId:'ANPASYNTHE0000000001',defaultVersionId:'v1',versions:['v1'],document:JSON.parse(request.PolicyDocument),tags:request.Tags,attachmentCount:0,boundaryUsageCount:0};
    return{Policy:{Arn:current.arn,PolicyId:current.policyId,DefaultVersionId:'v1'}};},
    async readSessionPolicy(){calls.push('read');return current;},async deleteSessionPolicy(){calls.push('delete');current=null;}};
  return{calls,records,ops,input:{scope,ops,record:async r=>records.push(r),run:async descriptor=>{calls.push('run');expect(descriptor.PolicyArns).toEqual([{arn:scope.temporaryPolicyArn}]);return{status:'OBSERVATIONS_COMPLETE',cleanupComplete:true};}},mutate(fn){fn(current);}};
}
describe('single-version temporary canary session restriction',()=>{
  it('requires the measured managed policy only for provisioning; bootstrap/read sessions fit inline',()=>{
    const p=buildGatewayCanaryOperatorPolicies(scope),b=buildGatewayCanarySessionPolicyBootstrap(scope);
    expect(p.bytes.provision).toBeGreaterThan(2048);expect(p.bytes.provision).toBeLessThanOrEqual(6144);
    expect(p.bytes.observe).toBeLessThanOrEqual(2048);expect(b.policyJson.length).toBeLessThanOrEqual(2048);
    for(const s of b.policy.Statement)expect(s.Resource).toBe(scope.temporaryPolicyArn);
    expect(b.policy.Statement[0].Action).toEqual(['iam:CreatePolicy','iam:TagPolicy']);
    expect(b.policy.Statement[0].Condition.StringEquals).toEqual({'aws:RequestTag/Project':'mem9-on-aws','aws:RequestTag/Stage':scope.stage,'aws:RequestTag/VerificationId':scope.verificationId});
    for(const forbidden of ['iam:CreatePolicyVersion','iam:DeletePolicyVersion','iam:SetDefaultPolicyVersion','iam:AttachRolePolicy','iam:PutRolePolicy','sts:AssumeRole'])expect(b.policy.Statement.flatMap(s=>[].concat(s.Action))).not.toContain(forbidden);
  });
  it('creates once, authenticates version/body before use and removes after physical/resource cleanup',async()=>{
    const f=fixture(),r=await withGatewayCanaryProvisioningPolicy(f.input);
    expect(r.status).toBe('CLOSED');expect(r.cleanupComplete).toBe(true);
    expect(f.calls).toEqual(['absent','create','read','run','read','delete','read']);
    expect(f.records.map(r=>r.event)).toEqual(['session-policy-create-intent','session-policy-created','session-policy-delete-intent','session-policy-deleted']);
  });
  it('does not publish after durable intent failure',async()=>{
    const f=fixture();f.input.record=async()=>{throw Error('DiskFull');};
    const r=await withGatewayCanaryProvisioningPolicy(f.input);expect(r.status).toBe('HELD');expect(f.calls).toEqual(['absent']);
  });
  it('does not retry or delete an unknown creation',async()=>{
    const f=fixture();f.ops.createSessionPolicy=async()=>{f.calls.push('create');throw Error('Unknown');};
    const r=await withGatewayCanaryProvisioningPolicy(f.input);expect(r.status).toBe('HELD');expect(r.cleanupComplete).toBe(false);expect(f.calls).toEqual(['absent','create']);
  });
  it.each([{code:'ECLEANUP'},{cleanupComplete:false}])('never certifies cleanup or proceeds after an unreaped pre-creation read: %j',flags=>{
    const f=fixture();f.ops.assertSessionPolicyAbsent=async()=>{f.calls.push('absent');throw Object.assign(Error('Unreaped read'),flags);};
    return withGatewayCanaryProvisioningPolicy(f.input).then(r=>{
      expect(r.status).toBe('HELD');expect(r.cleanupComplete).toBe(false);expect(f.calls).toEqual(['absent']);
    });
  });
  it('retains the scoped policy when resource cleanup is incomplete',async()=>{
    const f=fixture();f.input.run=async()=>({status:'HELD',cleanupComplete:false});
    const r=await withGatewayCanaryProvisioningPolicy(f.input);expect(r.status).toBe('HELD');expect(r.cleanupComplete).toBe(false);expect(f.calls).not.toContain('delete');
  });
  it.each(['version','document','attachment','replacement'])('holds on unexpected %s rather than mutating policy history',async kind=>{
    const f=fixture();f.input.run=async()=>{f.mutate(p=>{
      if(kind==='version')p.versions.push('v2');
      if(kind==='document')p.document.Statement.push({Effect:'Allow',Action:'iam:*',Resource:'*'});
      if(kind==='attachment')p.attachmentCount=1;
      if(kind==='replacement')p.policyId='ANPAREPLACED00000001';
    });return{cleanupComplete:true};};
    const r=await withGatewayCanaryProvisioningPolicy(f.input);expect(r.status).toBe('HELD');expect(r.cleanupComplete).toBe(false);expect(f.calls).not.toContain('delete');
  });
});
