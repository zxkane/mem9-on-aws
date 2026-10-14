import {describe,it,expect} from 'vitest';
import {policyForAction,simulationDecisions,auditAdditionalCredentialReaders,compactWriterInventory} from './lib/production-runtime-aws.mjs';

const account='123456789012',region='ap-northeast-1',stage='prod';
const role={RoleName:'mem9-on-aws-prod-SyntheticRole',Arn:`arn:aws:iam::${account}:role/mem9-on-aws-prod-SyntheticRole`};
const boundaryArn=`arn:aws:iam::${account}:policy/mem9-on-aws-workload-boundary`;
const document=Statement=>({Version:'2012-10-17',Statement});
const allow={Effect:'Allow',Action:'ssm:GetParameters',Resource:'*'};
function fixture(statements,{decision='implicitDeny',missing=[],boundary=document([allow]),perResource,selectedRole=role,selectedBoundary=boundaryArn,tags=[],boundaryChanged=false}={}){
  const calls=[];
  const reads=new Map();
  const send=async command=>{
    const {input}=command,name=command.constructor.name;calls.push({name,input});
    if(name==='GetPolicyCommand'){const count=(reads.get(input.PolicyArn)??0)+1;reads.set(input.PolicyArn,count);return {Policy:{DefaultVersionId:(boundaryChanged===true||boundaryChanged===input.PolicyArn)&&count>1?'v2':'v1'}};}
    if(name==='GetPolicyVersionCommand')return {PolicyVersion:{Document:boundary}};
    if(name==='ListRolesCommand')return {Roles:[selectedRole]};
    if(name==='GetRoleCommand')return {Role:{...selectedRole,Tags:tags,PermissionsBoundary:{PermissionsBoundaryArn:selectedBoundary}}};
    if(name==='ListRolePoliciesCommand')return {PolicyNames:['synthetic']};
    if(name==='ListAttachedRolePoliciesCommand')return {AttachedPolicies:[]};
    if(name==='GetRolePolicyCommand')return {PolicyDocument:document(statements)};
    if(name==='SimulateCustomPolicyCommand')return {EvaluationResults:input.ActionNames.map(EvalActionName=>({EvalActionName,EvalDecision:'explicitDeny',
      ResourceSpecificResults:input.ResourceArns.map((EvalResourceName,index)=>({EvalResourceName,EvalResourceDecision:perResource?.[index]??decision,MissingContextValues:missing}))}))};
    throw Error('UnexpectedCommand');
  };
  return {calls,clients:{iam:{send}}};
}

describe('credential reader policy audit',()=>{
  const gatewayBoundary=`arn:aws:iam::${account}:policy/mem9-on-aws-gateway-boundary`;
  const gatewayRole=token=>({RoleName:`mem9-on-aws-prod-${token}-fixture`,Arn:`arn:aws:iam::${account}:role/mem9-on-aws-prod-${token}-fixture`});
  const gatewayTags=[{Key:'Project',Value:'mem9-on-aws'},{Key:'Stage',Value:stage}];
  it.each(['Mem9IdentityInterceptorFnRole','Mem9ProxyFnRole'])('audits the existing dedicated boundary for %s without exempting its policies',async token=>{
    const f=fixture([allow],{selectedRole:gatewayRole(token),selectedBoundary:gatewayBoundary,tags:gatewayTags,decision:'explicitDeny'});
    await auditAdditionalCredentialReaders(f.clients,{stage,region,account},{roles:[]});
    expect(f.calls.filter(c=>c.name==='GetPolicyCommand').map(c=>c.input.PolicyArn)).toContain(gatewayBoundary);
    expect(f.calls.some(c=>c.name==='GetRolePolicyCommand')).toBe(true);
    expect(f.calls.some(c=>c.name==='SimulateCustomPolicyCommand')).toBe(true);
  });
  it.each(['unrelated-role','wrong-stage','wrong-project','missing-tags','duplicate-stage','unknown-boundary'])('rejects a dedicated boundary with %s',kind=>{
    const options={selectedRole:gatewayRole('Mem9ProxyFnRole'),selectedBoundary:gatewayBoundary,tags:gatewayTags};
    if(kind==='unrelated-role')options.selectedRole=role;
    if(kind==='wrong-stage')options.tags=[gatewayTags[0],{Key:'Stage',Value:'pr-7'}];
    if(kind==='wrong-project')options.tags=[{Key:'Project',Value:'other'},gatewayTags[1]];
    if(kind==='missing-tags')options.tags=[];
    if(kind==='duplicate-stage')options.tags=[...gatewayTags,gatewayTags[1]];
    if(kind==='unknown-boundary')options.selectedBoundary=gatewayBoundary+'-other';
    const f=fixture([allow],options);
    return expect(auditAdditionalCredentialReaders(f.clients,{stage,region,account},{roles:[]})).rejects.toThrow('CredentialReaderBoundaryMismatch');
  });
  it('still rejects a Gateway role allowed to read administrator credentials',async()=>{
    const f=fixture([allow],{selectedRole:gatewayRole('Mem9ProxyFnRole'),selectedBoundary:gatewayBoundary,tags:gatewayTags,decision:'allowed'});
    await expect(auditAdditionalCredentialReaders(f.clients,{stage,region,account},{roles:[]})).rejects.toThrow('UninventoriedCredentialReader');
    const calls=f.calls.filter(c=>c.name==='SimulateCustomPolicyCommand');
    expect(calls.at(-1).input.PermissionsBoundaryPolicyInputList).toEqual([JSON.stringify(document([allow]))]);
    expect(calls.at(-1).input.ContextEntries).toEqual(expect.arrayContaining(gatewayTags.map(t=>({ContextKeyName:'aws:PrincipalTag/'+t.Key,ContextKeyType:'string',ContextKeyValues:[t.Value]}))));
  });
  it('rejects a boundary revision changed during the audit',async()=>{
    const f=fixture([],{selectedRole:gatewayRole('Mem9ProxyFnRole'),selectedBoundary:gatewayBoundary,tags:gatewayTags,boundaryChanged:gatewayBoundary});
    await expect(auditAdditionalCredentialReaders(f.clients,{stage,region,account},{roles:[]})).rejects.toThrow('CredentialBoundaryChanged');
  });
  it('keeps hundreds of historical definitions out of bounded routing metadata while binding their complete digest',()=>{
    const definitions=Array.from({length:400},(_,i)=>`arn:aws:ecs:${region}:${account}:task-definition/mem9-on-aws-prod-SyntheticMem9Bootstrap:${i+1}`);
    const inventory={definitions,roles:[role.Arn],families:['synthetic'],clusters:['synthetic']};
    const compact=compactWriterInventory(inventory);
    expect(Buffer.byteLength(JSON.stringify(compact))).toBeLessThan(4096);
    expect(compact.definitionCount).toBe(400);expect(compact.definitions).toBeUndefined();
    expect(compactWriterInventory({...inventory,definitions:[...definitions].reverse()})).toEqual(compact);
    expect(compactWriterInventory({...inventory,definitions:definitions.slice(1)}).definitionDigest).not.toBe(compact.definitionDigest);
  });
  it('ignores unrelated PassRole conditions without dropping relevant Action or NotAction statements',()=>{
    const pass={Effect:'Allow',Action:'iam:PassRole',Resource:'*',Condition:{StringEquals:{'iam:PassedToService':'ecs-tasks.amazonaws.com'}}};
    const wildcard={...allow,Action:'SSM:g?t*',Condition:{StringEquals:{'aws:PrincipalTag/environment':'prod'}}};
    const inverse={Effect:'Deny',NotAction:['ec2:*','logs:*'],Resource:'*'};
    expect(policyForAction(document([pass,wildcard,inverse]),'ssm:GetParameters').Statement).toEqual([wildcard,inverse]);
    expect(policyForAction(document([{...inverse,NotAction:'ssm:Get*'}]),'ssm:GetParameters')).toBeNull();
    expect(()=>policyForAction(document([{...allow,NotAction:'iam:*'}]),'ssm:GetParameters')).toThrow('InvalidCredentialReaderPolicy');
  });
  it('does not simulate a role with only unrelated conditional permissions',async()=>{
    const f=fixture([{Effect:'Allow',Action:'iam:PassRole',Resource:'*',Condition:{StringEquals:{'iam:PassedToService':'ecs-tasks.amazonaws.com'}}}]);
    await auditAdditionalCredentialReaders(f.clients,{stage,region,account},{roles:[]});
    expect(f.calls.some(c=>c.name==='SimulateCustomPolicyCommand')).toBe(false);
  });
  it('preserves conditional SSM ambiguity and blocks the unknown reader',async()=>{
    const condition={StringEquals:{'aws:PrincipalTag/environment':'prod'}};
    const f=fixture([{...allow,Condition:condition}],{missing:['aws:PrincipalTag/environment']});
    await expect(auditAdditionalCredentialReaders(f.clients,{stage,region,account},{roles:[]})).rejects.toThrow('UninventoriedCredentialReader');
    expect(JSON.parse(f.calls.find(c=>c.name==='SimulateCustomPolicyCommand').input.PolicyInputList[0]).Statement[0].Condition).toEqual(condition);
  });
  it('checks runtime credentials and rejects a single allowed resource hidden by the aggregate deny',async()=>{
    const f=fixture([allow],{perResource:['explicitDeny','explicitDeny','explicitDeny','allowed']});
    await expect(auditAdditionalCredentialReaders(f.clients,{stage,region,account},{roles:[]})).rejects.toThrow('UninventoriedCredentialReader');
    expect(f.calls.find(c=>c.name==='SimulateCustomPolicyCommand').input.ResourceArns.at(-1)).toMatch(/database-credential$/);
  });
  it.each(['ssm:GetParameter','ssm:GetParameterHistory','ssm:GetParametersByPath'])('does not overlook %s grants',async action=>{
    const f=fixture([{...allow,Action:action}],{decision:'allowed',boundary:document([{...allow,Action:'ssm:*'}])});
    await expect(auditAdditionalCredentialReaders(f.clients,{stage,region,account},{roles:[]})).rejects.toThrow('UninventoriedCredentialReader');
  });
});

describe('IAM resource decision coverage',()=>{
  const action='ssm:GetParameters',resources=['one','two'];
  const result={EvaluationResults:[{EvalActionName:action,EvalDecision:'explicitDeny',ResourceSpecificResults:[
    {EvalResourceName:'one',EvalResourceDecision:'explicitDeny'},
    {EvalResourceName:'two',EvalResourceDecision:'allowed'},
  ]}]};
  it('uses complete per-resource decisions in aggregate and repeated legacy responses',()=>{
    expect(simulationDecisions(result,[action],resources).map(r=>r.decision)).toEqual(['explicitDeny','allowed']);
    expect(simulationDecisions({EvaluationResults:[...result.EvaluationResults,...result.EvaluationResults]},[action],resources)).toHaveLength(2);
  });
  it('rejects truncated, incomplete, conflicting or aggregate-only multi-resource evidence',()=>{
    expect(()=>simulationDecisions({...result,IsTruncated:true},[action],resources)).toThrow('Incomplete');
    expect(()=>simulationDecisions(result,[action],[...resources,'three'])).toThrow('Incomplete');
    expect(()=>simulationDecisions({EvaluationResults:[{EvalActionName:action,EvalDecision:'explicitDeny',EvalResourceName:'*'}]},[action],resources)).toThrow('Incomplete');
    const conflicting=structuredClone(result);conflicting.EvaluationResults[0].ResourceSpecificResults.push({EvalResourceName:'one',EvalResourceDecision:'allowed'});
    expect(()=>simulationDecisions(conflicting,[action],resources)).toThrow('Incomplete');
  });
});
