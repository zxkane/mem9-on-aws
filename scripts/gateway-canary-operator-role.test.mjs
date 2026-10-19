import {describe,it,expect} from 'vitest';
import {spawnSync} from 'node:child_process';
import {chmod,mkdtemp,readFile,rm,writeFile} from 'node:fs/promises';
import {existsSync,readFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {dirname,join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {parse} from 'yaml';
import {compileGatewayRuntimeCanaryScope,buildGatewayCanaryOperatorPolicies,buildGatewayCanarySessionPolicyBootstrap,gatewayCanaryDocumentHash as hash} from './lib/gateway-runtime-canary-resources.mjs';
import {GATEWAY_CANARY_OPERATOR_ROLE_NAME,GATEWAY_CANARY_OPERATOR_POLICY_NAME,gatewayCanaryOperatorRoleArn,gatewayCanaryOperatorPolicy,gatewayCanaryOperatorTrustPolicy,
  renderGatewayCanaryOperatorRoleTemplate,gatewayCanaryOwnerRoleRefusal,gatewayCanaryOperatorSimulationCases,gatewayCanarySimulationDecisions,compareGatewayCanaryOwnerToOperator,
  readGatewayCanaryOwnerPolicies,gatewayCanaryOwnerSimulationRequests,gatewayCanaryOperatorSimulationRequests,verifyGatewayCanaryOwnerHoldsOperator,
  checkGatewayCanaryOrganizationPolicies,gatewayCanaryOrganizationPoliciesAcknowledged,gatewayCanaryExpectedOperatorDenials,verifyGatewayCanaryOperatorDecisions,
  organizationPolicyKeysPrincipal} from './lib/gateway-canary-operator-role.mjs';
import {installFakeAwsCli,simulateCustomPolicy} from './test-fixtures/gateway-runtime-canary/fake-aws-cli.mjs';
import {resolveApplicationRegion} from './lib/application-region.mjs';

const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const templatePath=join(root,'infra/cloudformation/gateway-canary-operator-role.yaml');
const accountId='123456789012',applicationRegion='ap-northeast-1',owner='arn:aws:iam::123456789012:role/operators/synthetic-owner';
const tags=[{Key:'Project',Value:'mem9-on-aws'},{Key:'usage',Value:'cc-mem9-on-aws'}];

/** The CloudFormation intrinsics the template uses, evaluated for one stack. */
function render(template,parameters){
  const values={...parameters,'AWS::AccountId':accountId};
  const conditions={HasSessionTags:parameters.SessionTagProject!==''};
  const NO=Symbol('NoValue');
  const walk=v=>{
    if(Array.isArray(v))return v.map(walk).filter(x=>x!==NO);
    if(!v||typeof v!=='object')return v;
    if('Fn::Sub' in v)return v['Fn::Sub'].replace(/\$\{([^}]+)\}/g,(_,k)=>{expect(values).toHaveProperty([k]);return values[k];});
    if('Fn::If' in v){const [c,a,b]=v['Fn::If'];expect(conditions).toHaveProperty([c]);return walk(conditions[c]?a:b);}
    if('Ref' in v)return v.Ref==='AWS::NoValue'?NO:values[v.Ref];
    return Object.fromEntries(Object.entries(v).map(([k,x])=>[k,walk(x)]).filter(([,x])=>x!==NO));
  };
  return walk(template.Resources.GatewayCanaryOperatorRole.Properties);
}
const glob=pattern=>new RegExp('^'+pattern.split('').map(c=>c==='*'?'.*':c==='?'?'.':RegExp.escape(c)).join('')+'$');

describe('Gateway canary operator role',()=>{
  it('TC-GW-BROKER-025 the committed template is exactly the compiler output',async()=>{
    expect(readFileSync(templatePath,'utf8')).toBe(await renderGatewayCanaryOperatorRoleTemplate());
  });

  it.for([[null,''],[tags,'mem9-on-aws']])('TC-GW-BROKER-026 the template renders the lane-union policy and the exact owner trust (tags %j)',([sessionTags,project])=>{
    const template=parse(readFileSync(templatePath,'utf8')),resource=template.Resources.GatewayCanaryOperatorRole;
    // Ephemeral: deleting the stack removes the role.
    expect(resource).toMatchObject({Type:'AWS::IAM::Role',DeletionPolicy:'Delete',UpdateReplacePolicy:'Delete'});
    const properties=render(template,{OwnerRoleName:'operators/synthetic-owner',ApplicationRegion:applicationRegion,SessionTagProject:project,SessionTagUsage:project&&'cc-'+project});
    expect(properties.RoleName).toBe(GATEWAY_CANARY_OPERATOR_ROLE_NAME);expect(properties.MaxSessionDuration).toBe(3600);
    expect(`arn:aws:iam::${accountId}:role/${properties.RoleName}`).toBe(gatewayCanaryOperatorRoleArn(accountId));
    expect(hash(properties.AssumeRolePolicyDocument)).toBe(hash(gatewayCanaryOperatorTrustPolicy({ownerRoleArn:owner,tags:sessionTags})));
    expect(properties.Policies).toHaveLength(1);expect(properties.Policies[0].PolicyName).toBe(GATEWAY_CANARY_OPERATOR_POLICY_NAME);
    expect(hash(properties.Policies[0].PolicyDocument)).toBe(hash(gatewayCanaryOperatorPolicy({accountId,applicationRegion})));
    expect(properties.ManagedPolicyArns).toBeUndefined();expect(properties.PermissionsBoundary).toBeUndefined();
  });

  it('TC-GW-BROKER-026 the operator policy is exactly the three lane policies, generalized only in the verification id',()=>{
    const policy=gatewayCanaryOperatorPolicy({accountId,applicationRegion});
    // The role cannot assume itself or anything else, and is outside the deploy role's mem9-on-aws-* namespace.
    expect(JSON.stringify(policy)).not.toMatch(/"sts:/);expect(GATEWAY_CANARY_OPERATOR_ROLE_NAME.startsWith('mem9-on-a')).toBe(false);
    expect(gatewayCanaryOperatorTrustPolicy({ownerRoleArn:owner}).Statement).toEqual([{Effect:'Allow',Principal:{AWS:owner},Action:['sts:AssumeRole']}]);
    // With tags: Project and usage stay exact; aws:TagKeys also admits the chained caller's transitive User and Host, nothing else.
    expect(gatewayCanaryOperatorTrustPolicy({ownerRoleArn:owner,tags}).Statement).toEqual([{Effect:'Allow',Principal:{AWS:owner},Action:['sts:AssumeRole','sts:TagSession'],
      Condition:{StringEquals:{'aws:RequestTag/Project':'mem9-on-aws','aws:RequestTag/usage':'cc-mem9-on-aws'},'ForAllValues:StringEquals':{'aws:TagKeys':['Project','usage','User','Host']}}}]);
    expect(readFileSync(templatePath,'utf8')).toContain('# With session tags, aws:TagKeys also admits User and Host');
    for(const verificationId of ['abcdef012345','0'.repeat(12),'ffffffffffff']){
      const scope=compileGatewayRuntimeCanaryScope({accountId,applicationRegion,verificationId,vpcId:'vpc-12345678',ownerRoleArn:gatewayCanaryOperatorRoleArn(accountId)});
      const lanes=buildGatewayCanaryOperatorPolicies(scope);
      const concrete=[...lanes.observe.Statement,...lanes.provision.Statement,...buildGatewayCanarySessionPolicyBootstrap(scope).policy.Statement];
      expect(policy.Statement).toHaveLength(concrete.length);
      concrete.forEach((statement,i)=>{
        const general=policy.Statement[i];
        expect(general.Effect).toBe(statement.Effect);expect(general.Action).toEqual(statement.Action);
        const resources=[statement.Resource].flat(),patterns=[general.Resource].flat();
        expect(patterns).toHaveLength(resources.length);
        resources.forEach((r,j)=>expect(r).toMatch(glob(patterns[j])));
        // Only the twelve verification-id characters may be wildcarded.
        patterns.forEach((p,j)=>expect(p.replaceAll('?'.repeat(12),verificationId)).toBe(resources[j]));
        const flat=c=>Object.entries(c??{}).flatMap(([op,entries])=>Object.entries(entries).map(([k,v])=>[k,op,v]));
        const generalConditions=new Map(flat(general.Condition).map(([k,op,v])=>[k,{op,v}]));
        expect(generalConditions.size).toBe(flat(statement.Condition).length);
        for(const [key,op,value] of flat(statement.Condition)){
          const g=generalConditions.get(key);
          expect(JSON.stringify(g.v).replaceAll('?'.repeat(12),verificationId)).toBe(JSON.stringify(value));
          expect(g.op).toBe(JSON.stringify(g.v).includes('?'.repeat(12))?{StringEquals:'StringLike',ArnEquals:'ArnLike'}[op]:op);
        }
      });
    }
    expect(JSON.stringify(policy).length).toBeLessThanOrEqual(10240);
  });

  it('TC-GW-BROKER-022 refuses owner roles that would renew themselves or that CI reaches',()=>{
    for(const [arn,reason] of [
      ['arn:aws:iam::123456789012:role/gateway-canary-operator-mem9-on-aws','operator'],
      ['arn:aws:iam::123456789012:role/some/path/GATEWAY-CANARY-OPERATOR-MEM9-ON-AWS','operator'],
      ['arn:aws:iam::123456789012:role/mem9-on-aws-prod-Mem9ProxyFnRole-abc','project-role'],
      ['arn:aws:iam::123456789012:role/mem9-on-a-truncated','project-role'],
      ['arn:aws:iam::123456789012:role/Mem9-On-Aws-x','project-role'],
      ['arn:aws:iam::123456789012:role/github-actions-mem9-on-aws','deploy-role'],
      ['arn:aws:iam::123456789012:role/github-actions-mem9-on-aws-preview','deploy-role'],
      ['arn:aws:iam::123456789012:user/operator','malformed'],
      ['arn:aws:iam::123456789012:role/','malformed'],
      ['arn:aws:iam::123456789012:role/x//y','malformed'],
      // Path variants: IAM's `*` crosses `/`, so CI's role/mem9-on-aws-* reaches these.
      ['arn:aws:iam::123456789012:role/mem9-on-aws-ops/Admin','project-role'],
      ['arn:aws:iam::123456789012:role/ops/Mem9-On-Aws-x/Admin','project-role'],
      ['arn:aws:iam::123456789012:role/github-actions-mem9-on-aws/x','deploy-role'],
      ['arn:aws:iam::123456789012:role/ops/GitHub-Actions-Mem9-On-Aws-prod/x','deploy-role'],
      ['arn:aws:iam::123456789012:role/ops/gateway-canary-operator-mem9-on-aws','operator'],
      // Any other role the CI template grants, matched as a glob against the whole ARN.
      ['arn:aws:iam::123456789012:role/aws-service-role/rds.amazonaws.com/AWSServiceRoleForRDS','ci-granted'],
    ]){
      expect(gatewayCanaryOwnerRoleRefusal(arn),arn).toBe(reason);
      expect(()=>gatewayCanaryOperatorTrustPolicy({ownerRoleArn:arn}),arn).toThrow(/GatewayCanaryOperatorOwner/);
    }
    for(const arn of [owner,'arn:aws:iam::123456789012:role/BedrockOwner','arn:aws:iam::123456789012:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Admin_0123456789abcdef'])
      expect(gatewayCanaryOwnerRoleRefusal(arn),arn).toBe(null);
    // Every role glob in the CI template refuses an ARN it matches.
    const ci=readFileSync(join(root,'infra/cloudformation/github-actions-role.yaml'),'utf8');
    const globs=[...ci.matchAll(/arn:(?:\$\{AWS::Partition\}|aws):iam::\$\{AWS::AccountId\}:role\/[^\s"',\]]+/g)].map(m=>m[0].replace('${AWS::Partition}','aws')
      .replace('${AWS::AccountId}',accountId).replaceAll('${ProjectName}','mem9-on-aws').replaceAll('${GitHubRepo}','mem9-on-aws'));
    expect(globs.length).toBeGreaterThan(10);
    for(const g of globs)for(const arn of [g.replaceAll('*','x').replaceAll('?','a'),g.replaceAll('*','ops/x').replaceAll('?','a')])
      if(/^arn:aws:iam::\d{12}:role\/[\w+=,.@/-]+$/.test(arn))expect(gatewayCanaryOwnerRoleRefusal(arn),arn).not.toBe(null);
  });

  it('TC-GW-BROKER-026 simulates the owner for exactly every operator action/resource pair, on concrete samples',()=>{
    const cases=gatewayCanaryOperatorSimulationCases({accountId,applicationRegion,ownerRoleArn:owner}),policy=gatewayCanaryOperatorPolicy({accountId,applicationRegion});
    // One request per combination of condition values, in statement order.
    const statementOf=policy.Statement.flatMap(s=>Array(Object.values(s.Condition??{}).flatMap(e=>Object.values(e)).reduce((n,v)=>n*[v].flat().length,1)).fill(s));
    expect(cases).toHaveLength(statementOf.length);expect(cases.length).toBeGreaterThan(policy.Statement.length);
    const boundary=cases.filter(c=>c.ActionNames.includes('iam:PutRolePermissionsBoundary')).map(c=>c.ContextEntries.find(e=>e.ContextKeyName==='iam:PermissionsBoundary').ContextKeyValues[0]);
    expect(boundary).toEqual([`arn:aws:iam::${accountId}:policy/mem9-on-aws-gateway-comparison-abcdef012345`,`arn:aws:iam::${accountId}:policy/mem9-on-aws-gateway-boundary`]);
    cases.forEach((c,i)=>{
      const general=statementOf[i];
      expect(c.PolicySourceArn).toBeUndefined();expect(c.ActionNames).toEqual([general.Action].flat());
      expect(c.ContextEntries.at(-1)).toEqual({ContextKeyName:'aws:PrincipalArn',ContextKeyValues:[owner],ContextKeyType:'string'});
      const patterns=[general.Resource].flat();expect(c.ResourceArns).toHaveLength(patterns.length);
      c.ResourceArns.forEach((r,j)=>{expect(r).toMatch(glob(patterns[j]));if(patterns[j]!=='*')expect(r).not.toMatch(/[*?]/);});
      const keys=Object.values(general.Condition??{}).flatMap(e=>Object.keys(e)).sort();
      expect(c.ContextEntries.slice(0,-1).map(e=>e.ContextKeyName).sort()).toEqual(keys);
      for(const e of c.ContextEntries??[])expect(e.ContextKeyValues).toHaveLength(1);
    });
    const request=cases[1],allowed={IsTruncated:false,EvaluationResults:request.ActionNames.flatMap(a=>request.ResourceArns.map(r=>({EvalActionName:a,EvalResourceName:r,EvalDecision:'allowed'})))};
    const all=gatewayCanarySimulationDecisions(request,allowed);
    expect([...all.values()].every(Boolean)).toBe(true);expect(all.size).toBe(request.ActionNames.length*request.ResourceArns.length);
    // Grouped per action with resource-specific results is the same answer.
    expect(gatewayCanarySimulationDecisions(request,{EvaluationResults:request.ActionNames.map(a=>({EvalActionName:a.toLowerCase(),EvalResourceName:'*',EvalDecision:'allowed',
      ResourceSpecificResults:request.ResourceArns.map(r=>({EvalResourceName:r,EvalResourceDecision:'allowed'}))}))})).toEqual(all);
    const denied=gatewayCanarySimulationDecisions(request,{...allowed,EvaluationResults:allowed.EvaluationResults.map((r,i)=>i===0?{...r,EvalDecision:'explicitDeny'}:r)});
    expect([...denied.values()].filter(v=>!v)).toHaveLength(1);
    for(const response of [{...allowed,IsTruncated:true},{...allowed,EvaluationResults:allowed.EvaluationResults.slice(1)},{}])
      expect(()=>gatewayCanarySimulationDecisions(request,response)).toThrow(/Simulation/);
    // Operator-allowed pairs must be owner-allowed; operator-denied pairs are ignored.
    expect(compareGatewayCanaryOwnerToOperator(all,all)).toBe(all.size);
    expect(compareGatewayCanaryOwnerToOperator(denied,denied)).toBe(all.size-1);
    expect(()=>compareGatewayCanaryOwnerToOperator(all,denied)).toThrow(/OwnerLacksPermission/);
  });

  it('TC-GW-BROKER-031 pins the operator decisions: exactly 89 of 102 pairs, the 13 exceptions derived from the statements',async()=>{
    const requests=gatewayCanaryOperatorSimulationRequests({accountId,applicationRegion,ownerRoleArn:owner});
    const pairs=requests.reduce((n,r)=>n+r.ActionNames.length*r.ResourceArns.length,0),denials=requests.flatMap(r=>[...gatewayCanaryExpectedOperatorDenials(r)]);
    expect(pairs).toBe(102);expect(denials).toHaveLength(13);
    expect(denials.filter(d=>d.startsWith('iam:')&&d.includes(':policy/'))).toHaveLength(8);
    expect(denials.filter(d=>d.startsWith('iam:')&&d.includes(':role/'))).toHaveLength(4);
    expect(denials.filter(d=>d.startsWith('logs:getlogevents ')&&d.includes(':log-stream:'))).toHaveLength(1);
    // No core grant is ever an exception.
    for(const core of ['cloudformation:createstack','iam:createrole','iam:putrolepolicy','iam:createpolicy','iam:passrole','lambda:createfunction'])
      expect(denials.some(d=>d.startsWith(core+' '))).toBe(false);
    // The synthetic simulator, modelled on the real one, gives exactly the expected decisions.
    let allowed=0;for(const r of requests)allowed+=verifyGatewayCanaryOperatorDecisions(r,gatewayCanarySimulationDecisions(r,simulateCustomPolicy(r)));
    expect(allowed).toBe(89);
    // Drift in either direction is refused.
    const create=requests.find(r=>r.ActionNames.includes('cloudformation:CreateStack'));
    const flip=(request,pair)=>new Map([...gatewayCanarySimulationDecisions(request,simulateCustomPolicy(request))].map(([k,v])=>[k,k===pair?!v:v]));
    expect(()=>verifyGatewayCanaryOperatorDecisions(create,flip(create,'cloudformation:createstack '+create.ResourceArns[0]))).toThrow(/OperatorSimulationDrift/);
    const reads=requests.find(r=>r.ActionNames.includes('iam:GetRole')&&r.ResourceArns.length===3);
    expect(()=>verifyGatewayCanaryOperatorDecisions(reads,flip(reads,`iam:getrole arn:aws:iam::${accountId}:policy/mem9-on-aws-gateway-boundary`))).toThrow(/OperatorSimulationDrift/);
    // End to end: an operator newly denied a core pair is refused, though the owner holds everything.
    const admin={Version:'2012-10-17',Statement:[{Effect:'Allow',Action:'*',Resource:'*'}]},operatorPolicy=JSON.stringify(gatewayCanaryOperatorPolicy({accountId,applicationRegion}));
    const iam=deny=>async(operation,body)=>{
      const fixed={'get-role':{Role:{Arn:owner}},'list-role-policies':{PolicyNames:[],IsTruncated:false},'list-attached-role-policies':{AttachedPolicies:[{PolicyArn:'arn:aws:iam::aws:policy/AdministratorAccess'}],IsTruncated:false},
        'get-policy':{Policy:{Arn:body.PolicyArn,DefaultVersionId:'v1'}},'get-policy-version':{PolicyVersion:{VersionId:'v1',IsDefaultVersion:true,Document:admin}}}[operation];
      if(fixed)return fixed;
      const result=simulateCustomPolicy(body);
      if(body.PolicyInputList[0]===operatorPolicy)for(const r of result.EvaluationResults)if(deny(r))r.EvalDecision=r.EvalDecision==='allowed'?'implicitDeny':'allowed';
      return result;
    };
    await expect(verifyGatewayCanaryOwnerHoldsOperator({iam:iam(()=>false),accountId,applicationRegion,ownerRoleArn:owner})).resolves.toMatchObject({operatorPairs:89,simulations:22});
    for(const action of ['cloudformation:CreateStack','iam:CreateRole','iam:PutRolePolicy','iam:CreatePolicy','iam:PassRole','lambda:CreateFunction'])
      await expect(verifyGatewayCanaryOwnerHoldsOperator({iam:iam(r=>r.EvalActionName===action),accountId,applicationRegion,ownerRoleArn:owner}),action).rejects.toThrow(/^GatewayCanaryOperatorOperatorSimulationDrift$/);
    // ...and so is one newly allowed an exception pair.
    await expect(verifyGatewayCanaryOwnerHoldsOperator({iam:iam(r=>r.EvalActionName==='logs:GetLogEvents'),accountId,applicationRegion,ownerRoleArn:owner})).rejects.toThrow(/^GatewayCanaryOperatorOperatorSimulationDrift$/);
  });

  it('TC-GW-BROKER-030 scans every readable SCP and RCP on the account and OU chain for principal-specific keys',async()=>{
    expect(gatewayCanaryOrganizationPoliciesAcknowledged({GATEWAY_CANARY_ORG_POLICIES_PRINCIPAL_NEUTRAL:'true'})).toBe(true);
    for(const value of [undefined,'','1','TRUE','yes'])expect(gatewayCanaryOrganizationPoliciesAcknowledged({GATEWAY_CANARY_ORG_POLICIES_PRINCIPAL_NEUTRAL:value})).toBe(false);
    const full={Version:'2012-10-17',Statement:[{Effect:'Allow',Action:'*',Resource:'*'}]};
    const error=code=>Object.assign(Error('synthetic'),{code:254,stderr:`An error occurred (${code}) when calling the X operation: synthetic`});
    const orgFor=({policies={},parents={[accountId]:{Id:'ou-a',Type:'ORGANIZATIONAL_UNIT'},'ou-a':{Id:'r-a',Type:'ROOT'}},fail={},nextToken=false}={})=>{
      const calls=[];
      const organizations=async(operation,body)=>{
        calls.push([operation,body]);
        if(fail[operation])throw error(fail[operation]);
        if(operation==='list-parents')return {Parents:[parents[body.ChildId]]};
        if(operation==='list-policies-for-target')return {Policies:(policies[body.TargetId+' '+body.Filter]??[]).map(([Id])=>({Id})),...(nextToken?{NextToken:'n'}:{})};
        if(operation==='describe-policy')return {Policy:{Content:JSON.stringify(Object.values(policies).flat().find(([id])=>id===body.PolicyId)[1])}};
        throw Error('unexpected '+operation);
      };
      return {organizations,calls};
    };
    const base={'r-a SERVICE_CONTROL_POLICY':[['p-full',full]],'r-a RESOURCE_CONTROL_POLICY':[['p-rcp',full]]};
    const clean=orgFor({policies:base});
    expect(await checkGatewayCanaryOrganizationPolicies({organizations:clean.organizations,accountId})).toEqual({status:'principal-neutral',policies:2});
    // Every target on the chain is listed for both policy types.
    expect(clean.calls.filter(([o])=>o==='list-policies-for-target').map(([,b])=>b.TargetId+' '+b.Filter)).toEqual(
      [accountId,'ou-a','r-a'].flatMap(t=>[t+' SERVICE_CONTROL_POLICY',t+' RESOURCE_CONTROL_POLICY']));
    const scoped=(condition,where='ou-a SERVICE_CONTROL_POLICY')=>({policies:{...base,[where]:[['p-narrow',{Version:'2012-10-17',Statement:[{Effect:'Deny',Action:'*',Resource:'*',...condition}]}]]}});
    for(const [condition,where] of [
      [{Condition:{ArnNotLike:{'aws:PrincipalArn':'arn:aws:iam::*:role/AWSReservedSSO_Admin*'}}}],
      [{Condition:{StringNotEquals:{'AWS:PrincipalTag/Team':'platform'}}},`${accountId} SERVICE_CONTROL_POLICY`],
      [{Condition:{StringNotLike:{'aws:userid':'AROA*:admin@example.com'}}},'r-a RESOURCE_CONTROL_POLICY'],
      [{Condition:{StringNotEquals:{'aws:SourceIdentity':'admin'}}},'ou-a RESOURCE_CONTROL_POLICY'],
      [{NotResource:'arn:aws:s3:::${aws:PrincipalTag/team}-*'}],
      [{Condition:{StringNotEquals:{'aws:PrincipalOrgID':'o-abcdefghij'}}},'r-a RESOURCE_CONTROL_POLICY'],
      [{Condition:{Bool:{'aws:PrincipalIsAWSService':'false'}}}],
    ])await expect(checkGatewayCanaryOrganizationPolicies({organizations:orgFor(scoped(condition,where)).organizations,accountId})).rejects.toThrow(/^GatewayCanaryOperatorOrgPolicyPrincipalScoped$/);
    // Parsed, not only searched: \u escapes cannot hide a principal key or variable; unparseable content fails.
    expect(organizationPolicyKeysPrincipal('{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"StringNotEquals":{"aws:\\u0050rincipalArn":"x"}}}]}')).toBe(true);
    expect(organizationPolicyKeysPrincipal('{"Statement":[{"Effect":"Deny","Action":"*","NotResource":"arn:aws:s3:::${aws:\\u0055serid}"}]}')).toBe(true);
    expect(organizationPolicyKeysPrincipal('{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*","Condition":{"Bool":{"aws:\\u0053ourceIdentity":"x"}}}]}')).toBe(true);
    expect(organizationPolicyKeysPrincipal(JSON.stringify(full))).toBe(false);
    expect(()=>organizationPolicyKeysPrincipal('{not json')).toThrow(/OrgPolicyUnparseable/);
    // The real account's shape: one condition-free Deny-S3 SCP attached at the account, OU and root, no RCPs.
    const denyS3=['p-denys3',{Version:'2012-10-17',Statement:[{Sid:'DenyS3',Effect:'Deny',Action:'s3:*',Resource:'*'}]}];
    expect(await checkGatewayCanaryOrganizationPolicies({organizations:orgFor({policies:{[`${accountId} SERVICE_CONTROL_POLICY`]:[denyS3],'ou-a SERVICE_CONTROL_POLICY':[denyS3],'r-a SERVICE_CONTROL_POLICY':[denyS3]}}).organizations,accountId}))
      .toEqual({status:'principal-neutral',policies:1});
    // A principal-neutral narrowing SCP is fine.
    expect((await checkGatewayCanaryOrganizationPolicies({organizations:orgFor(scoped({Condition:{StringNotEquals:{'aws:RequestedRegion':['ap-northeast-1','us-east-1']}}})).organizations,accountId})).status).toBe('principal-neutral');
    expect(await checkGatewayCanaryOrganizationPolicies({organizations:orgFor({fail:{'list-parents':'AWSOrganizationsNotInUseException'}}).organizations,accountId})).toEqual({status:'not-in-organization',policies:0});
    expect((await checkGatewayCanaryOrganizationPolicies({organizations:orgFor({policies:{'r-a SERVICE_CONTROL_POLICY':[['p-full',full]]},fail:{}}).organizations,accountId})).status).toBe('principal-neutral');
    // RCPs not enabled: skipped. Anything else unreadable: say so, never claim neutrality.
    const rcpOff=orgFor({policies:base});const original=rcpOff.organizations;
    expect((await checkGatewayCanaryOrganizationPolicies({organizations:async(o,b)=>{if(o==='list-policies-for-target'&&b.Filter==='RESOURCE_CONTROL_POLICY')throw error('PolicyTypeNotEnabledException');return original(o,b);},accountId})).status).toBe('principal-neutral');
    for(const options of [{policies:base,fail:{'list-parents':'AccessDeniedException'}},{policies:base,fail:{'list-policies-for-target':'AccessDeniedException'}},
      {policies:base,fail:{'describe-policy':'AccessDeniedException'}},{policies:base,nextToken:true},{policies:base,parents:{[accountId]:{Id:'ou-a',Type:'ORGANIZATIONAL_UNIT'},'ou-a':{Id:'ou-a',Type:'ORGANIZATIONAL_UNIT'}}}])
      expect((await checkGatewayCanaryOrganizationPolicies({organizations:orgFor(options).organizations,accountId})).status).toBe('unreadable');
  });

  it('TC-GW-BROKER-029 compares the owner symmetrically with the operator, so simulator type mismatches are not owner gaps',async()=>{
    const operatorRequests=gatewayCanaryOperatorSimulationRequests({accountId,applicationRegion,ownerRoleArn:owner});
    const operatorPolicy=JSON.stringify(gatewayCanaryOperatorPolicy({accountId,applicationRegion}));
    expect(operatorRequests.every(r=>r.PolicyInputList.length===1&&r.PolicyInputList[0]===operatorPolicy&&r.PermissionsBoundaryPolicyInputList===undefined)).toBe(true);
    const decisions=operatorRequests.map(r=>gatewayCanarySimulationDecisions(r,simulateCustomPolicy(r)));
    // The synthetic simulator, like IAM's, denies the IAM read statement's cross-type pairs and GetLogEvents on a log stream.
    const reads=operatorRequests.findIndex(r=>r.ActionNames.includes('iam:GetRole')&&r.ResourceArns.length===3);
    expect(decisions[reads].get(`iam:getrole arn:aws:iam::${accountId}:policy/mem9-on-aws-gateway-boundary`)).toBe(false);
    expect(decisions[reads].get(`iam:getpolicy arn:aws:iam::${accountId}:role/mem9-on-aws-runtime-check-Mem9ProxyFnRole-abcdef012345`)).toBe(false);
    expect(decisions[reads].get(`iam:getrole arn:aws:iam::${accountId}:role/mem9-on-aws-runtime-check-Mem9ProxyFnRole-abcdef012345`)).toBe(true);
    const logs=operatorRequests.findIndex(r=>r.ActionNames.includes('logs:GetLogEvents'));
    expect([...decisions[logs].values()]).toEqual([false]);
    // Every other pair is an operator permission: the cases are not vacuous.
    expect(decisions.reduce((n,d)=>n+[...d.values()].filter(Boolean).length,0)).toBeGreaterThan(80);
    // An operator simulation that allows nothing fails rather than passing.
    const nothing=async(operation,body)=>operation==='simulate-custom-policy'&&body.PolicyInputList[0]===operatorPolicy
      ?{IsTruncated:false,EvaluationResults:body.ActionNames.flatMap(a=>body.ResourceArns.map(r=>({EvalActionName:a,EvalResourceName:r,EvalDecision:'implicitDeny'})))}
      :owners(operation,body);
    const admin={Version:'2012-10-17',Statement:[{Effect:'Allow',Action:'*',Resource:'*'}]};
    const owners=async(operation,body)=>({'get-role':{Role:{Arn:owner}},'list-role-policies':{PolicyNames:[],IsTruncated:false},'list-attached-role-policies':{AttachedPolicies:[{PolicyArn:'arn:aws:iam::aws:policy/AdministratorAccess'}],IsTruncated:false},
      'get-policy':{Policy:{Arn:body.PolicyArn,DefaultVersionId:'v1'}},'get-policy-version':{PolicyVersion:{VersionId:'v1',IsDefaultVersion:true,Document:admin}}})[operation]??simulateCustomPolicy(body);
    await expect(verifyGatewayCanaryOwnerHoldsOperator({iam:owners,accountId,applicationRegion,ownerRoleArn:owner})).resolves.toMatchObject({simulations:operatorRequests.length});
    await expect(verifyGatewayCanaryOwnerHoldsOperator({iam:nothing,accountId,applicationRegion,ownerRoleArn:owner})).rejects.toThrow(/^GatewayCanaryOperatorOperatorSimulationDrift$/);
    // An owner denied only a pair the operator is also denied still passes; one the operator is allowed does not.
    const ownerDenied=pair=>async(operation,body)=>{
      const response=await owners(operation,body);
      if(operation!=='simulate-custom-policy'||body.PolicyInputList[0]===operatorPolicy)return response;
      return {...response,EvaluationResults:response.EvaluationResults.map(r=>`${r.EvalActionName} ${r.EvalResourceName}`===pair?{...r,EvalDecision:'implicitDeny'}:r)};
    };
    await expect(verifyGatewayCanaryOwnerHoldsOperator({iam:ownerDenied(`iam:GetRole arn:aws:iam::${accountId}:policy/mem9-on-aws-gateway-boundary`),accountId,applicationRegion,ownerRoleArn:owner})).resolves.toBeDefined();
    await expect(verifyGatewayCanaryOwnerHoldsOperator({iam:ownerDenied(`iam:GetRole arn:aws:iam::${accountId}:role/mem9-on-aws-runtime-check-Mem9ProxyFnRole-abcdef012345`),accountId,applicationRegion,ownerRoleArn:owner})).rejects.toThrow(/OwnerLacksPermission/);
  });

  it('TC-GW-BROKER-028 reads every owner identity policy and boundary for SimulateCustomPolicy, and fails closed on any doubt',async()=>{
    const allow={Version:'2012-10-17',Statement:[{Effect:'Allow',Action:'*',Resource:'*'}]},guard={Version:'2012-10-17',Statement:[{Sid:'BlastRadiusGuard',Effect:'Deny',Action:'organizations:LeaveOrganization',Resource:'*'}]};
    const iamFor=({role={Arn:owner,Tags:[{Key:'team',Value:'platform'}]},inline={guard},attached={'arn:aws:iam::aws:policy/AdministratorAccess':allow},boundary,truncated=false,fail})=>async(operation,body)=>{
      if(fail===operation)throw Error('synthetic read failure');
      if(operation==='get-role')return {Role:{...role,...(boundary?{PermissionsBoundary:{PermissionsBoundaryType:'Policy',PermissionsBoundaryArn:'arn:aws:iam::123456789012:policy/b'}}:{})}};
      if(operation==='list-role-policies')return {PolicyNames:Object.keys(inline),IsTruncated:truncated};
      if(operation==='get-role-policy')return {PolicyName:body.PolicyName,PolicyDocument:encodeURIComponent(JSON.stringify(inline[body.PolicyName]))};
      if(operation==='list-attached-role-policies')return {AttachedPolicies:Object.keys(attached).map(PolicyArn=>({PolicyArn})),IsTruncated:false};
      if(operation==='get-policy')return {Policy:{Arn:body.PolicyArn,DefaultVersionId:'v2'}};
      if(operation==='get-policy-version')return {PolicyVersion:{VersionId:body.VersionId,IsDefaultVersion:true,Document:body.PolicyArn.endsWith('/b')?boundary:attached[body.PolicyArn]}};
      if(operation==='simulate-custom-policy')return simulateCustomPolicy(body);
      throw Error('unexpected '+operation);
    };
    const read=options=>readGatewayCanaryOwnerPolicies({iam:iamFor(options),ownerRoleArn:owner});
    const documents=await read({boundary:allow});
    // Explicit denies are kept, attached policies are read at their default version, and the boundary is separate.
    expect(documents.policies.map(p=>JSON.parse(p))).toEqual([guard,allow]);expect(JSON.parse(documents.boundary)).toEqual(allow);
    expect((await read({})).boundary).toBe(null);
    const requests=gatewayCanaryOwnerSimulationRequests({accountId,applicationRegion,ownerRoleArn:owner,owner:documents});
    expect(requests).toHaveLength(gatewayCanaryOperatorSimulationCases({accountId,applicationRegion,ownerRoleArn:owner}).length);
    // The owner role's tags are its aws:PrincipalTag context, so a tag-keyed Deny applies.
    expect(documents.tags).toEqual([{Key:'team',Value:'platform'}]);
    for(const r of requests)expect(r.ContextEntries).toContainEqual({ContextKeyName:'aws:PrincipalTag/team',ContextKeyValues:['platform'],ContextKeyType:'string'});
    const tagDeny={Version:'2012-10-17',Statement:[{Effect:'Deny',Action:'iam:CreateRole',Resource:'*',Condition:{StringEquals:{'aws:PrincipalTag/team':'platform'}}}]};
    await expect(verifyGatewayCanaryOwnerHoldsOperator({iam:iamFor({inline:{guard:tagDeny}}),accountId,applicationRegion,ownerRoleArn:owner})).rejects.toThrow(/OwnerLacksPermission/);
    await expect(verifyGatewayCanaryOwnerHoldsOperator({iam:iamFor({inline:{guard:tagDeny},role:{Arn:owner,Tags:[{Key:'team',Value:'other'}]}}),accountId,applicationRegion,ownerRoleArn:owner})).resolves.toBeDefined();
    for(const r of requests){expect(r.PolicyInputList).toEqual(documents.policies);expect(r.PermissionsBoundaryPolicyInputList).toEqual([documents.boundary]);expect(r.PolicySourceArn).toBeUndefined();expect(r.OrderedOrganizationPolicyInputList).toBeUndefined();}
    await expect(verifyGatewayCanaryOwnerHoldsOperator({iam:iamFor({}),accountId,applicationRegion,ownerRoleArn:owner})).resolves.toMatchObject({simulations:requests.length,policies:2,boundary:false});
    // A narrower identity policy, an explicit deny, or a narrower boundary is refused.
    for(const options of [
      {attached:{'arn:aws:iam::aws:policy/PowerUserAccess':{Version:'2012-10-17',Statement:[{Effect:'Allow',NotAction:['iam:*','organizations:*'],Resource:'*'}]}}},
      {inline:{guard:{Version:'2012-10-17',Statement:[{Effect:'Deny',Action:'kms:ScheduleKeyDeletion',Resource:'*'}]}}},
      {boundary:{Version:'2012-10-17',Statement:[{Effect:'Allow',NotAction:'lambda:*',Resource:'*'}]}},
    ])await expect(verifyGatewayCanaryOwnerHoldsOperator({iam:iamFor(options),accountId,applicationRegion,ownerRoleArn:owner})).rejects.toThrow(/^GatewayCanaryOperatorOwnerLacksPermission$/);
    // Truncated lists, too many policies, an oversize document, a foreign role or any read error fail closed.
    const many=Object.fromEntries(Array.from({length:11},(_,i)=>[`arn:aws:iam::123456789012:policy/p${i}`,allow]));
    for(const [options,reason] of [
      [{truncated:true},/OwnerPolicies$/],[{attached:many,inline:{}},/OwnerPolicyCount$/],[{inline:{},attached:{}},/OwnerPolicyCount$/],
      [{inline:{big:{Version:'2012-10-17',Statement:[{Effect:'Deny',Action:'s3:GetObject',Resource:'x'.repeat(131072)}]}}},/OwnerPolicyTooLarge$/],
      [{role:{Arn:'arn:aws:iam::123456789012:role/other'}},/OwnerPolicies$/],
      ...['get-role','list-role-policies','get-role-policy','list-attached-role-policies','get-policy','get-policy-version','simulate-custom-policy'].map(fail=>[{fail},/synthetic read failure/]),
    ])await expect(verifyGatewayCanaryOwnerHoldsOperator({iam:iamFor(options),accountId,applicationRegion,ownerRoleArn:owner})).rejects.toThrow(reason);
  });

  it('TC-GW-BROKER-032 the deploy script checks the committed template against the compiler before validating it',async test=>{
    const script=readFileSync(join(root,'scripts/deploy-gateway-canary-operator-role.sh'),'utf8');
    expect(script.indexOf('gateway-canary-operator-owner.mjs" check-template')).toBeGreaterThan(-1);
    expect(script.indexOf('gateway-canary-operator-owner.mjs" check-template')).toBeLessThan(script.indexOf('aws cloudformation validate-template'));
    const directory=await mkdtemp(join(tmpdir(),'gateway-operator-template-'));test.onTestFinished(()=>rm(directory,{recursive:true,force:true}));
    const edited=join(directory,'template.yaml');
    await writeFile(edited,readFileSync(templatePath,'utf8').replace('MaxSessionDuration: 3600','MaxSessionDuration: 43200'));
    const run=file=>spawnSync(process.execPath,[join(root,'scripts/gateway-canary-operator-owner.mjs'),'check-template',file],{encoding:'utf8'});
    expect(run(templatePath).status).toBe(0);
    const stale=run(edited);expect(stale.status).toBe(1);expect(stale.stderr).toContain('differs from the compiler output');
  });

  describe('TC-GW-BROKER-027 deploy-gateway-canary-operator-role.sh',()=>{
    const scopedOwner='arn:aws:iam::123456789012:role/operators/synthetic-scoped-owner';
    async function deploy(test,{ownerArn=scopedOwner,account=accountId,liveOwner=ownerArn,stack,environment={},faults={}}={}){
      const directory=await mkdtemp(join(tmpdir(),'gateway-operator-deploy-'));test.onTestFinished(()=>rm(directory,{recursive:true,force:true}));
      const calls=join(directory,'calls'),params=join(directory,'params.json');
      if(stack)await writeFile(params,JSON.stringify(stack));
      // The owner-policy reads and SimulateCustomPolicy go through the shared AWS
      // CLI request shape; the synthetic CLI answers those from the owner's documents.
      const iam=installFakeAwsCli({directory,liveBoundaryPath:join(directory,'unused.json'),faults});
      await writeFile(join(directory,'aws'),`#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "$*" >> "${calls}"
if [[ "$1" == --region ]]; then exec "${iam.awsExecutable}" "$@"; fi
case "$1 $2" in
  "sts get-caller-identity") echo "${account}" ;;
  "iam get-role") echo "${liveOwner}" ;;
  "cloudformation validate-template") echo '{}' ;;
  "cloudformation describe-stacks")
    if [[ ! -f "${params}" ]]; then echo "An error occurred (ValidationError) when calling the DescribeStacks operation: Stack with id x does not exist" >&2; exit 254; fi
    jq '{Stacks:[{StackStatus:"CREATE_COMPLETE",Parameters:.,Outputs:[{OutputKey:"RoleArn",OutputValue:"synthetic"}]}]}' "${params}" ;;
  "cloudformation create-stack"|"cloudformation update-stack")
    for a in "$@"; do if [[ "$a" =~ ^ParameterKey=([A-Za-z]+),ParameterValue=(.*)$ ]]; then printf '%s\\t%s\\n' "\${BASH_REMATCH[1]}" "\${BASH_REMATCH[2]}"; fi; done |
      jq -R -s 'split("\\n") | map(select(length>0) | split("\\t") | {ParameterKey:.[0],ParameterValue:(.[1] // "")})' > "${params}"
    echo '{}' ;;
  "cloudformation wait") ;;
  *) exit 1 ;;
esac
`);
      await chmod(join(directory,'aws'),0o755);
      const result=spawnSync('bash',[join(root,'scripts/deploy-gateway-canary-operator-role.sh')],{cwd:root,encoding:'utf8',timeout:60_000,
        env:{PATH:`${directory}:${process.env.PATH}`,HOME:directory,GATEWAY_CANARY_SKIP_DOTENV:'true',GATEWAY_CANARY_ORG_POLICIES_PRINCIPAL_NEUTRAL:'true',GATEWAY_CANARY_OWNER_ROLE_ARN:ownerArn,...environment}});
      return {result,calls:existsSync(calls)?readFileSync(calls,'utf8').trim().split('\n'):[],params:existsSync(params)?JSON.parse(readFileSync(params,'utf8')):null};
    }
    const value=(params,key)=>params.find(p=>p.ParameterKey===key)?.ParameterValue;
    it('creates the stack in us-west-2 after template validation, with the owner as a same-account path and name',async test=>{
      const region=await resolveApplicationRegion();
      const f=await deploy(test,{environment:{CC_PROJECT:'mem9-on-aws',CC_USAGE:'cc-mem9-on-aws'}});
      expect(f.result.status,f.result.stderr).toBe(0);
      const validate=f.calls.findIndex(c=>c.startsWith('cloudformation validate-template')),create=f.calls.findIndex(c=>c.startsWith('cloudformation create-stack'));
      expect(validate).toBeGreaterThan(-1);expect(create).toBeGreaterThan(validate);
      expect(f.calls[create]).toContain('--region us-west-2');expect(f.calls[create]).toContain('CAPABILITY_NAMED_IAM');
      expect(f.calls[create]).toContain('gateway-canary-operator-role.yaml');
      expect(value(f.params,'OwnerRoleName')).toBe('operators/synthetic-scoped-owner');expect(value(f.params,'ApplicationRegion')).toBe(region);
      expect(value(f.params,'SessionTagProject')).toBe('mem9-on-aws');expect(value(f.params,'SessionTagUsage')).toBe('cc-mem9-on-aws');
      expect(f.calls).toContain('iam get-role --role-name synthetic-scoped-owner --query Role.Arn --output text');
      // The owner's own documents are simulated for every operator permission before any stack call.
      const simulations=f.calls.filter(c=>c.includes(' iam simulate-custom-policy '));
      // Each case is simulated twice: the operator's own policy, then the owner's documents.
      expect(simulations).toHaveLength(2*gatewayCanaryOperatorSimulationCases({accountId,applicationRegion:region,ownerRoleArn:scopedOwner}).length);
      expect(f.calls.findLastIndex(c=>c.includes(' iam simulate-custom-policy '))).toBeLessThan(validate);
      expect(f.calls.some(c=>c.includes('simulate-principal-policy'))).toBe(false);
      expect(f.result.stdout).toContain('owner holds every operator permission');
      expect(f.result.stdout).toContain('organization policies: principal-neutral (2 scanned)');
      const untagged=await deploy(test);
      expect(untagged.result.status,untagged.result.stderr).toBe(0);
      expect(value(untagged.params,'SessionTagProject')).toBe('');expect(value(untagged.params,'SessionTagUsage')).toBe('');
    },120_000);
    it('refuses a malformed, cross-account or unknown owner, and malformed tags, before any stack call',async test=>{
      for(const [options,status] of [
        [{ownerArn:'arn:aws:iam::123456789012:user/someone'},2],
        [{ownerArn:'*'},2],
        [{ownerArn:`arn:aws:iam::${'0'.repeat(12)}:role/synthetic-owner`},2],
        [{liveOwner:'arn:aws:iam::123456789012:role/other/synthetic-scoped-owner'},1],
        [{environment:{CC_PROJECT:'mem9-on-aws'}},2],
        [{environment:{CC_PROJECT:'mem9-on-aws',CC_USAGE:'ci-mem9-on-aws'}},2],
        [{ownerArn:'arn:aws:iam::123456789012:role/gateway-canary-operator-mem9-on-aws'},2],
        [{ownerArn:'arn:aws:iam::123456789012:role/mem9-on-aws-prod-Mem9ProxyFnRole-x'},2],
        [{ownerArn:'arn:aws:iam::123456789012:role/github-actions-mem9-on-aws-prod'},2],
        [{ownerArn:'arn:aws:iam::123456789012:role/mem9-on-aws-ops/Admin'},2],
        [{ownerArn:'arn:aws:iam::123456789012:role/github-actions-mem9-on-aws/x'},2],
        [{ownerArn:'arn:aws:iam::123456789012:role/aws-service-role/rds.amazonaws.com/AWSServiceRoleForRDS'},2],
        // An owner lacking any operator permission would gain it through the role.
        [{faults:{ownerDenies:['iam:PutRolePolicy']}},1],
        [{faults:{ownerDenies:['lambda:CreateFunction']}},1],
        [{faults:{ownerNarrow:true}},1],
        [{faults:{ownerBoundary:{Version:'2012-10-17',Statement:[{Effect:'Allow',NotAction:'kms:*',Resource:'*'}]}}},1],
        [{faults:{ownerExtraPolicies:10}},1],
        [{faults:{ownerListTruncated:true}},1],
        [{faults:{ownerTagDeny:true}},1],
        // The SCP/RCP exclusion needs the explicit acknowledgement, and a visible principal-keyed policy refuses even with it.
        [{environment:{GATEWAY_CANARY_ORG_POLICIES_PRINCIPAL_NEUTRAL:''}},2],
        [{faults:{orgPrincipalScoped:{filter:'SERVICE_CONTROL_POLICY',content:{Version:'2012-10-17',Statement:[{Effect:'Deny',Action:'iam:*',Resource:'*',Condition:{ArnNotLike:{'aws:PrincipalArn':'arn:aws:iam::*:role/admin'}}}]}}}},1],
      ]){
        const f=await deploy(test,options);
        expect(f.result.status,JSON.stringify(options)).toBe(status);
        expect(f.calls.some(c=>c.startsWith('cloudformation'))).toBe(false);
      }
    },120_000);
    it('without the acknowledgement makes no AWS call at all; unreadable Organizations policies rely on it and say so',async test=>{
      const missing=await deploy(test,{environment:{GATEWAY_CANARY_ORG_POLICIES_PRINCIPAL_NEUTRAL:'false'}});
      expect(missing.result.status).toBe(2);expect(missing.calls).toEqual([]);
      expect(missing.result.stderr).toContain('GATEWAY_CANARY_ORG_POLICIES_PRINCIPAL_NEUTRAL=true');
      const unreadable=await deploy(test,{faults:{orgUnreadable:true}});
      expect(unreadable.result.status,unreadable.result.stderr).toBe(0);
      expect(unreadable.result.stdout).toContain('organization policies are not fully readable; relying on GATEWAY_CANARY_ORG_POLICIES_PRINCIPAL_NEUTRAL=true');
    },120_000);
    it('refuses to retarget an existing stack to another application region',async test=>{
      const f=await deploy(test,{stack:[{ParameterKey:'OwnerRoleName',ParameterValue:'operators/synthetic-scoped-owner'},{ParameterKey:'ApplicationRegion',ParameterValue:'eu-west-9'},
        {ParameterKey:'SessionTagProject',ParameterValue:''},{ParameterKey:'SessionTagUsage',ParameterValue:''}]});
      expect(f.result.status).toBe(1);expect(f.result.stderr).toContain('refusing to retarget');
      expect(f.calls.some(c=>/^cloudformation (create|update)-stack/.test(c))).toBe(false);
    },60_000);
  });

  describe('TC-GW-BROKER-036 deploy-gateway-canary-operator-role.sh --delete',()=>{
    // A stateful shell mock: the stack (with a Retain or Delete template), the role and its policies.
    async function remove(test,{stack=true,template='delete',role=true,attached=0,updateFails=false,waitFails=false,deleteRoleNoop=false,args=['--delete']}={}){
      const directory=await mkdtemp(join(tmpdir(),'gateway-operator-delete-'));test.onTestFinished(()=>rm(directory,{recursive:true,force:true}));
      const state=name=>join(directory,name),calls=state('calls');
      if(stack)await writeFile(state('stack'),'');await writeFile(state('template'),template);
      if(role){await writeFile(state('role'),'');await writeFile(state('inline'),'');}
      await writeFile(join(directory,'aws'),`#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "$*" >> "${calls}"
missing(){ echo "An error occurred ($1) when calling the $2 operation: \${3:-synthetic}" >&2; exit 254; }
case "$1 $2" in
  "cloudformation describe-stacks") [[ -f "${state('stack')}" ]] || missing ValidationError DescribeStacks 'Stack with id x does not exist'; echo '{"Stacks":[{"StackStatus":"CREATE_COMPLETE"}]}' ;;
  "cloudformation get-template") printf 'Resources:\\n  GatewayCanaryOperatorRole:\\n    DeletionPolicy: %s\\n' "$(cat "${state('template')}" | sed 's/retain/Retain/;s/delete/Delete/')" ;;
  "cloudformation update-stack") ${updateFails?'missing ValidationError UpdateStack':`printf delete > "${state('template')}"; echo '{}'`} ;;
  "cloudformation delete-stack") ;;
  "cloudformation wait")
    if [[ "$3" == stack-delete-complete ]]; then
      ${waitFails?'exit 255':`rm -f "${state('stack')}"; if [[ "$(cat "${state('template')}")" == delete ]]; then rm -f "${state('role')}" "${state('inline')}"; fi`}
    fi ;;
  "iam get-role") [[ -f "${state('role')}" ]] || missing NoSuchEntity GetRole; echo gateway-canary-operator-mem9-on-aws ;;
  "iam list-attached-role-policies") echo ${attached} ;;
  "iam list-role-policies") if [[ -f "${state('inline')}" ]]; then echo gateway-canary-operator; fi ;;
  "iam delete-role-policy") rm -f "${state('inline')}" ;;
  "iam delete-role") ${deleteRoleNoop?':':`[[ ! -f "${state('inline')}" ]] || missing DeleteConflict DeleteRole; rm -f "${state('role')}"`} ;;
  *) exit 1 ;;
esac
`);
      await chmod(join(directory,'aws'),0o755);
      // No owner, tag or Organizations settings are needed to remove the role.
      const result=spawnSync('bash',[join(root,'scripts/deploy-gateway-canary-operator-role.sh'),...args],{cwd:root,encoding:'utf8',timeout:60_000,
        env:{PATH:`${directory}:${process.env.PATH}`,HOME:directory,GATEWAY_CANARY_SKIP_DOTENV:'true'}});
      return {result,calls:existsSync(calls)?readFileSync(calls,'utf8').trim().split('\n'):[],roleLeft:existsSync(state('role'))};
    }
    const index=(f,prefix)=>f.calls.findIndex(c=>c.startsWith(prefix));
    it('deletes a Delete-policy stack, which removes the role, and verifies NoSuchEntity',async test=>{
      const f=await remove(test);
      expect(f.result.status,f.result.stderr).toBe(0);expect(f.result.stdout).toContain('gateway canary operator role: deleted');
      expect(f.roleLeft).toBe(false);expect(index(f,'cloudformation update-stack')).toBe(-1);expect(index(f,'iam delete-role ')).toBe(-1);
      expect(index(f,'cloudformation wait stack-delete-complete')).toBeGreaterThan(index(f,'cloudformation delete-stack'));
      expect(f.calls.filter(c=>c.startsWith('iam get-role'))).toHaveLength(2);
    },60_000);
    it('moves an older Retain stack to the Delete template before deleting it',async test=>{
      const f=await remove(test,{template:'retain'});
      expect(f.result.status,f.result.stderr).toBe(0);expect(f.roleLeft).toBe(false);
      expect(index(f,'cloudformation update-stack')).toBeGreaterThan(-1);
      expect(f.calls[index(f,'cloudformation update-stack')]).toContain('UsePreviousValue=true');
      expect(index(f,'cloudformation update-stack')).toBeLessThan(index(f,'cloudformation delete-stack'));
    },60_000);
    it.for([
      ['a Retain stack that cannot be updated',{template:'retain',updateFails:true}],
      ['a role whose stack is already gone',{stack:false}],
    ])('deletes the inline policy and then the role directly for %s',async([,options],test)=>{
      const f=await remove(test,options);
      expect(f.result.status,f.result.stderr).toBe(0);expect(f.roleLeft).toBe(false);
      expect(index(f,'iam delete-role-policy')).toBeGreaterThan(-1);
      expect(index(f,'iam delete-role-policy')).toBeLessThan(index(f,'iam delete-role '));
    },60_000);
    it('succeeds when nothing is left to delete',async test=>{
      const f=await remove(test,{stack:false,role:false});
      expect(f.result.status,f.result.stderr).toBe(0);expect(index(f,'cloudformation delete-stack')).toBe(-1);
    },60_000);
    it.for([
      ['attached managed policies',{stack:false,attached:1},1],
      ['a role that does not go away',{stack:false,deleteRoleNoop:true},1],
      ['a stack deletion that does not complete',{waitFails:true},1],
      ['an extra argument',{args:['--delete','now']},2],
    ])('fails closed on %s',async([,options,status],test)=>{
      const f=await remove(test,options);
      expect(f.result.status).toBe(status);
      if(options.attached)expect(index(f,'iam delete-role ')).toBe(-1);
      if(options.args)expect(f.calls).toEqual([]);
    },60_000);
  });
});
