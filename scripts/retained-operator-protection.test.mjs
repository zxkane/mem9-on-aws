import {describe,it,expect} from 'vitest';
import {readFileSync} from 'node:fs';
import {parseDocument} from 'yaml';

const identity={partition:'aws',accountId:'123456789012'};
const roles=['github-actions-mem9-on-aws','github-actions-mem9-on-aws-preview','github-actions-mem9-on-aws-prod'];
const arn=name=>`arn:aws:iam::${identity.accountId}:role/${name}`;
const context=roleName=>({...identity,roleName});
const helper=()=>import('./lib/retained-operator-protection.mjs');

describe('retained operator permanent CI protection',()=>{
  it('uses separate source-owned inline resources on all three CI identities',()=>{
    const doc=parseDocument(readFileSync(new URL('../infra/cloudformation/github-actions-role.yaml',import.meta.url),'utf8'),{customTags:[
      ...['Ref','Sub','GetAtt'].map(name=>({tag:'!'+name,resolve:value=>({[name]:value})})),
      ...['If','Equals','Not'].map(name=>({tag:'!'+name,collection:'seq',resolve:value=>({[name]:value.toJSON()})})),
    ]});
    expect(doc.errors).toEqual([]);
    const policies=Object.values(doc.toJS().Resources).filter(r=>r.Type==='AWS::IAM::Policy');
    expect(policies).toHaveLength(3);
    expect(policies.flatMap(r=>r.Properties.Roles.map(role=>role.Ref)).sort()).toEqual(['GitHubActionsRole','GitHubPreviewActionsRole','GitHubProductionActionsRole']);
    for(const policy of policies){expect(policy.Condition).toBeUndefined();expect(policy.Properties.PolicyName).not.toContain('quarantine');}
  });

  for(const roleName of roles)it(`binds the exact protection and probe contract for ${roleName}`,async()=>{
    const h=await helper(),c=context(roleName),policy=h.expectedRetainedOperatorProtectionPolicy(c);
    expect(h.retainedOperatorProtectionPolicyName(roleName)).toBe(roleName+'-retained-operator-protection');
    expect(h.verifyRetainedOperatorProtectionDocuments([policy],c)).toBe(true);
    expect(policy.Statement.every(s=>s.Effect==='Deny')).toBe(true);
    const probes=h.retainedOperatorProtectionProbes(c);
    const human=probes.filter(p=>p.resource===arn('mem9-on-aws-preview-human-acceptance')&&p.action==='iam:PassRole');
    expect(human.find(p=>p.context?.['iam:PassedToService']==='ecs-tasks.amazonaws.com').decision)
      .toBe(roleName.endsWith('-prod')?'explicitDeny':'allowed');
    expect(human.find(p=>!p.context).decision).toBe('explicitDeny');
    expect(human.find(p=>p.context?.['iam:PassedToService']==='lambda.amazonaws.com').decision).toBe('explicitDeny');
    for(const action of h.RETAINED_OPERATOR_MUTATION_ACTIONS)for(const name of ['mem9-on-aws-namespace-operator','mem9-on-aws-preview-human-acceptance'])
      expect(probes).toContainEqual({action,resource:arn(name),decision:'explicitDeny'});
    for(const action of h.RETAINED_OPERATOR_CLOUDFORMATION_MUTATIONS)
      expect(probes).toContainEqual({action,resource:'*',decision:'explicitDeny'});
  });

  it('rejects missing, duplicated or modified permanent protection; quarantine is not proof',async()=>{
    const h=await helper(),c=context(roles[0]),policy=h.expectedRetainedOperatorProtectionPolicy(c);
    const quarantine={Version:'2012-10-17',Statement:[{Effect:'Deny',Action:'*',Resource:'*'}]};
    expect(()=>h.verifyRetainedOperatorProtectionDocuments([quarantine],c)).toThrow();
    for(const mutate of [p=>p.Statement.pop(),p=>p.Statement.push(p.Statement[0]),p=>p.Statement[0].Resource='*',
      p=>p.Statement.find(s=>s.Condition).Condition.StringNotEquals['iam:PassedToService']='lambda.amazonaws.com']){
      const changed=structuredClone(policy);mutate(changed);
      expect(()=>h.verifyRetainedOperatorProtectionDocuments([changed,quarantine],c)).toThrow();
    }
  });

  it('rejects self and peer mutation allows regardless of conditions or installed denies',async()=>{
    const h=await helper(),c=context(roles[0]),policy=h.expectedRetainedOperatorProtectionPolicy(c);
    for(const target of roles)for(const statement of [
      {Effect:'Allow',Action:'iam:DeleteRolePolicy',Resource:arn(target)},
      {Effect:'Allow',Action:'iam:*Role*',Resource:'*',Condition:{StringEquals:{'aws:PrincipalTag/example':'never-assume'}}},
      {Effect:'Allow',NotAction:['iam:GetRole'],Resource:arn(target)},
      {Effect:'Allow',Action:'iam:PutRolePolicy',NotResource:arn('unrelated')},
      {Effect:'Allow',Action:'iam:DeleteRolePolicy',Resource:`arn:aws:iam::${identity.accountId}:role/\${aws:PrincipalTag/Role}`},
    ])expect(()=>h.verifyRetainedOperatorProtectionDocuments([policy,{Version:'2012-10-17',Statement:[statement]}],c)).toThrow();
    expect(h.verifyRetainedOperatorProtectionDocuments([policy,{Version:'2012-10-17',Statement:[
      {Effect:'Allow',Action:['iam:DeleteRolePolicy','iam:PutRolePolicy'],Resource:arn('mem9-on-aws-*')},
    ]}],c)).toBe(true);
  });

  it('preserves unrelated duplicate values during coverage but rejects duplicates in permanent protection',async()=>{
    const h=await helper(),c=context(roles[0]),policy=h.expectedRetainedOperatorProtectionPolicy(c);
    const document=Action=>({Version:'2012-10-17',Statement:[{Sid:'ApiGatewayV2AccessLogs',Effect:'Allow',Action,Resource:['*','*']}]});
    expect(h.verifyRetainedOperatorProtectionDocuments([policy,document(['logs:DescribeLogGroups','logs:DescribeLogGroups'])],c)).toBe(true);
    expect(()=>h.verifyRetainedOperatorProtectionDocuments([policy,document(['iam:DeleteRolePolicy','iam:DeleteRolePolicy'])],c)).toThrow(/self\/peer/u);
    const duplicate=structuredClone(policy);duplicate.Statement[0].Action.push(duplicate.Statement[0].Action[0]);
    expect(()=>h.verifyRetainedOperatorProtectionDocuments([duplicate],c)).toThrow(/duplicate/u);
  });

  it('closes CloudFormation mutation coverage without removing reads or validation',async()=>{
    const h=await helper(),c=context(roles[1]),policy=h.expectedRetainedOperatorProtectionPolicy(c);
    const document=Action=>({Version:'2012-10-17',Statement:[{Effect:'Allow',Action,Resource:'*'}]});
    expect(h.verifyRetainedOperatorProtectionDocuments([policy,document(['cloudformation:DescribeStacks','cloudformation:GetTemplate','cloudformation:ValidateTemplate','cloudformation:UpdateStack'])],c)).toBe(true);
    for(const action of ['cloudformation:*','cloudformation:FutureMutation'])
      expect(()=>h.verifyRetainedOperatorProtectionDocuments([policy,document(action)],c)).toThrow();
    for(const Action of ['*:DeleteStackInstances','*Delete*','cloud*:DeleteStackInstances','${aws:PrincipalTag/Service}:DeleteStackInstances'])
      expect(()=>h.verifyRetainedOperatorProtectionDocuments([policy,{Version:'2012-10-17',Statement:[{
        Effect:'Allow',Action,Resource:`arn:aws:cloudformation:ap-northeast-1:${identity.accountId}:stack/unrelated/*`,
      }]}],c)).toThrow();
    expect(()=>h.verifyRetainedOperatorProtectionDocuments([policy,{Version:'2012-10-17',Statement:[{Effect:'Allow',NotAction:'s3:*',Resource:'*'}]}],c)).toThrow();
  });
});
