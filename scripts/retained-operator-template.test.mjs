import {describe,it,expect} from 'vitest';
import {readFileSync} from 'node:fs';
import {parseDocument} from 'yaml';
import {verifyAuthorizationDeploymentTemplate} from './lib/authorization-maintenance-isolation.mjs';
import {quarantinePolicyDocument} from './lib/workload-permissions-boundary.mjs';

const source=readFileSync(new URL('../infra/cloudformation/github-actions-role.yaml',import.meta.url),'utf8');
const accountId='123456789012',region='ap-northeast-1';
const parameters={
  'AWS::Partition':'aws','AWS::AccountId':accountId,'AWS::Region':'us-west-2','AWS::URLSuffix':'amazonaws.com',
  ApplicationRegion:region,DecisionArtifactBucketName:'a'.repeat(33),LegacyRoleEnabled:'false',
  ApplicationVpcArn:`arn:aws:ec2:${region}:${accountId}:vpc/vpc-${'a'.repeat(17)}`,
  ApplicationPrivateSubnetArns:['a','b','c'].map(c=>`arn:aws:ec2:${region}:${accountId}:subnet/subnet-${c.repeat(17)}`),
  ProductionHostedZoneArn:'arn:aws:route53:::hostedzone/Z'+'X'.repeat(20),
};
function edited(mutate){
  const doc=parseDocument(source,{uniqueKeys:true,customTags:[
    ...['Ref','Sub','GetAtt'].map(name=>({tag:'!'+name,resolve:value=>value})),
    ...['If','Equals','Not'].map(name=>({tag:'!'+name,collection:'seq',resolve:value=>value})),
  ]});
  expect(doc.errors).toEqual([]);mutate(doc);return doc.toString({lineWidth:0});
}
const rolePolicies=['Resources','GitHubPreviewActionsRole','Properties','Policies'];
const extraPolicy=Statement=>({PolicyName:'synthetic-extra',PolicyDocument:{Version:'2012-10-17',Statement}});

describe('retained operator deployment preflight',()=>{
  it.each(['true','false'])('renders managed, role-inline and separate policy resources with legacy=%s',async LegacyRoleEnabled=>{
    const sizes=await verifyAuthorizationDeploymentTemplate(source,{...parameters,LegacyRoleEnabled});
    expect(Object.values(sizes).every(size=>size<=6144)).toBe(true);
    await expect(verifyAuthorizationDeploymentTemplate(edited(()=>{}),{...parameters,LegacyRoleEnabled,ProductionHostedZoneArn:''})).resolves.toBeDefined();
  });
  it('keeps the quota reserve identical to the separately owned quarantine document',()=>{
    expect(JSON.stringify(quarantinePolicyDocument()).length).toBe(123);
  });
  it('includes quarantine at the exact aggregate inline quota boundary',async()=>{
    // Independently rendered preview fixture: existing stage isolation plus the
    // separate protection total 5812 bytes before the 123-byte quarantine.
    const available=10240-5812-JSON.stringify(quarantinePolicyDocument()).length;
    for(const excess of [0,1]){
      const extra=extraPolicy([{Effect:'Deny',Action:'s3:GetObject',Resource:[
        `arn:aws:s3:::synthetic-${accountId}/${'x'.repeat(2000)}`,
        `arn:aws:s3:::synthetic-${accountId}/`,
      ]}]);
      extra.PolicyDocument.Statement[0].Resource[1]+='y'.repeat(available+excess-JSON.stringify(extra.PolicyDocument).length);
      expect(JSON.stringify(extra.PolicyDocument).length).toBe(available+excess);
      const changed=edited(doc=>doc.getIn(rolePolicies).add(extra));
      if(excess)await expect(verifyAuthorizationDeploymentTemplate(changed,parameters)).rejects.toThrow(/inline policy quota/u);
      else await expect(verifyAuthorizationDeploymentTemplate(changed,parameters)).resolves.toBeDefined();
    }
  });
  for(const kind of ['missing','wrong-role','duplicate-name','quarantine-adoption','self-grant','unknown-cf','inline-quota'])
    it(`rejects ${kind} before template upload`,async()=>{
      const changed=edited(doc=>{
        if(kind==='missing')doc.deleteIn(['Resources','LegacyRetainedOperatorProtection']);
        if(kind==='wrong-role')doc.setIn(['Resources','LegacyRetainedOperatorProtection','Properties','Roles'],[{Ref:'GitHubPreviewActionsRole'}]);
        if(kind==='duplicate-name')doc.getIn(rolePolicies).add({PolicyName:'github-actions-mem9-on-aws-preview-retained-operator-protection',PolicyDocument:{Version:'2012-10-17',Statement:[{Effect:'Deny',Action:'s3:PutObject',Resource:'*'}]}});
        if(kind==='quarantine-adoption')doc.getIn(rolePolicies).add({PolicyName:'mem9-on-aws-workload-boundary-quarantine',PolicyDocument:quarantinePolicyDocument()});
        if(kind==='self-grant')doc.getIn(rolePolicies).add(extraPolicy([{Effect:'Allow',Action:'iam:DeleteRolePolicy',Resource:`arn:aws:iam::${accountId}:role/github-actions-*`}]));
        if(kind==='unknown-cf')doc.getIn(['Resources','CorePolicy','Properties','PolicyDocument','Statement',0,'Action']).add('cloudformation:FutureMutation');
        if(kind==='inline-quota')doc.getIn(rolePolicies).add(extraPolicy([{Effect:'Deny',Action:'s3:GetObject',Resource:Array.from({length:100},(_,i)=>`arn:aws:s3:::synthetic-${accountId}/${'x'.repeat(100)}-${i}`)}]));
      });
      expect(changed).not.toBe(source);
      await expect(verifyAuthorizationDeploymentTemplate(changed,parameters)).rejects.toThrow();
    });
});
