import {createGithubMaintenanceController} from './rollout-workload-permissions-boundary.mjs';
import {describe, it, expect} from 'vitest';
import {runBoundaryPostUpdateFinalization, expectedRolePatterns} from './lib/workload-permissions-boundary.mjs';
import {createRetainedOperatorInventory} from './lib/retained-operator-inventory.mjs';
import {createRetainedOperatorFixture} from './test-fixtures/retained-operator.mjs';

const identity = {partition:'aws', accountId:'123456789012'};
const roleName = 'mem9-on-aws-prod-task-role';
const ci = ['github-actions-mem9-on-aws','github-actions-mem9-on-aws-preview','github-actions-mem9-on-aws-prod'].sort();
const boundaryArn = `arn:aws:iam::${identity.accountId}:policy/mem9-on-aws-workload-boundary`;
function fixture(defect) {
  const calls=[]; let snapshots=0;
  const pass = name => async () => {calls.push(name); if(defect===name) throw Error(name); return true;};
  const adapter={
    verifyBoundaryRegion:pass('region'), verifyRetainedOperators:pass('retained'),
    verifyCompletedDeployment:async()=>{calls.push('completed-stack'); return ci;},
    verifyFinalizationBoundary:pass('native-boundary'), verifyProductionBoundaryActive:pass('activation-read'),
    verifyQuarantine:pass('quarantine'), verifyFinalGithubInterlock:pass('github'),
    listAttachedPolicies:async()=>({policies:[]}),
    listInlinePolicies:async()=>({policyNames:['scope']}),
    getInlinePolicy:async()=>({document:{Version:'2012-10-17',Statement:[{Effect:'Allow',Action:'iam:PassRole',Resource:expectedRolePatterns(identity),Condition:{StringEquals:{'iam:PassedToService':['ecs-tasks.amazonaws.com','lambda.amazonaws.com']}}}]}}),
    listRoles:async()=>({roles:[{name:roleName,arn:`arn:aws:iam::${identity.accountId}:role/${roleName}`,assumeRolePolicyDocument:{Version:'2012-10-17',Statement:[{Effect:'Allow',Principal:{Service:'ecs-tasks.amazonaws.com'},Action:'sts:AssumeRole'}]}}]}),
    getRole:async()=>({permissionsBoundaryArn:boundaryArn}),
    verifyProductionRuntimeBindings:async()=>[roleName],
    readFinalizationState:async()=>{calls.push('snapshot'); return {roles:[roleName],policies:[++snapshots===2&&defect==='drift'?'changed':'original']};},
    verifyPermanentEnforcement:pass('complete-enforcement'),
    verifyRetainedOperatorEnforcement:pass('complete-retained'),
    deleteQuarantines:pass('release'), resumeDeployments:pass('resume'),
  };
  for(const name of ['deployBoundary','deployPermanentEnforcement','putRoleBoundary','updateAssumeRolePolicy','activateProductionBoundary','putQuarantine']) {
    adapter[name]=()=>{throw Error('Forbidden mutation '+name);};
  }
  return {adapter,calls,input:{...identity,boundaryArn,reviewedCommit:'a'.repeat(40),deadlineAt:Date.now()+3000000}};
}

describe('post-update finalization',()=>{
  it('runs one complete verification then current checks and coordinated release without redeployment',async()=>{
    const f=fixture(); await expect(runBoundaryPostUpdateFinalization(f.adapter,f.input)).resolves.toMatchObject({status:'complete'});
    expect(f.calls.filter(x=>x==='complete-enforcement')).toHaveLength(1);
    expect(f.calls.filter(x=>x==='complete-retained')).toHaveLength(1);
    expect(f.calls.filter(x=>x==='snapshot')).toHaveLength(2);
    expect(f.calls.slice(-2)).toEqual(['release','resume']);
  });
  it.each(['region','retained','native-boundary','activation-read','quarantine','github','complete-enforcement','complete-retained','drift'])('holds on %s without release or a repair',async defect=>{
    const f=fixture(defect); await expect(runBoundaryPostUpdateFinalization(f.adapter,f.input)).rejects.toThrow();
    expect(f.calls).not.toContain('release'); expect(f.calls).not.toContain('resume');
  });
  it('preserves coordinated release failure and never resumes deployments',async()=>{
    const f=fixture('release'); await expect(runBoundaryPostUpdateFinalization(f.adapter,f.input)).rejects.toThrow('release');
    expect(f.calls).not.toContain('resume');
  });
  it('does not reset or extend an expired deadline',async()=>{
    const f=fixture(); f.input.deadlineAt=Date.now()-1;
    await expect(runBoundaryPostUpdateFinalization(f.adapter,f.input)).rejects.toThrow(/deadline/);
    expect(f.calls).toEqual([]);
  });
});

describe('completed deployment catalog',()=>{
  const stack='github-actions-mem9-on-aws';
  const create=f=>createRetainedOperatorInventory({invokeAws:f.invokeAws,identity,applicationRegion:'ap-northeast-1'});
  it('requires the complete current source template and pins all parameters across reads',async()=>{
    const f=createRetainedOperatorFixture(); f.stacks[stack].StackStatus='UPDATE_COMPLETE';
    for(const [name,spec] of Object.entries(f.templates[stack].Parameters)) if(!f.stacks[stack].Parameters.some(p=>p.ParameterKey===name)) f.stacks[stack].Parameters.push({ParameterKey:name,ParameterValue:String(spec.Default??'synthetic-value')});
    const inventory=create(f); await inventory.verifyCompletedDeploymentRoleCatalog();
    f.stacks[stack].Parameters.find(p=>p.ParameterKey==='DecisionArtifactBucketName').ParameterValue='different-example-bucket';
    await expect(inventory.verifyCompletedDeploymentRoleCatalog()).rejects.toThrow();
  });
  it.each(['UPDATE_ROLLBACK_COMPLETE','UPDATE_IN_PROGRESS','UPDATE_FAILED','CREATE_COMPLETE'])('does not adopt %s as completed update',async status=>{
    const f=createRetainedOperatorFixture(); f.stacks[stack].StackStatus=status;
    await expect(create(f).verifyCompletedDeploymentRoleCatalog()).rejects.toThrow();
  });
  it('rejects a managed-policy template change even when role declarations remain identical',async()=>{
    const f=createRetainedOperatorFixture(); f.stacks[stack].StackStatus='UPDATE_COMPLETE';
    const original=f.invokeAws;
    const inventory=create({...f,invokeAws:async args=>{
      const value=await original(args);
      if(args[0]==='cloudformation'&&args[1]==='get-template'&&args.includes(f.stacks[stack].StackId)) {
        // Add a top-level section without disturbing the existing declarations.
        return {...value,TemplateBody: typeof value.TemplateBody==='string'?value.TemplateBody+'\nMetadata: {Unreviewed: true}\n':{...value.TemplateBody,Metadata:{Unreviewed:true}}};
      }
      return value;
    }});
    await expect(inventory.verifyCompletedDeploymentRoleCatalog()).rejects.toThrow();
  });
});


describe('existing production activation',()=>{
  it.each(['true','false','','TRUE',undefined])('reads the exact current value %s without setting it',async value=>{
    const calls=[];
    const owner=createGithubMaintenanceController({deadlineAt:Date.now()+60000,runGh:async args=>{calls.push(args);return value;}});
    if(value==='true')await expect(owner.verifyProductionBoundaryActive()).resolves.toBe(true);
    else await expect(owner.verifyProductionBoundaryActive()).rejects.toThrow();
    expect(calls).toHaveLength(1);
    expect(calls[0].slice(0,3)).toEqual(['variable','get','WORKLOAD_BOUNDARY_PROD_ENABLED']);
    expect(calls[0].slice(-4)).toEqual(['--json','value','--jq','.value']);
  });
});


describe('exact three-description presentation compatibility',()=>{
  const stack='github-actions-mem9-on-aws';
  const paths=[['Description'],['Parameters','ProjectName','Description'],['Parameters','OIDCProviderArn','Description']];
  function fixture(){
    const f=createRetainedOperatorFixture();
    for(const [name,spec] of Object.entries(f.templates[stack].Parameters)) if(!f.stacks[stack].Parameters.some(p=>p.ParameterKey===name)) f.stacks[stack].Parameters.push({ParameterKey:name,ParameterValue:String(spec.Default??'synthetic-value')});
    return f;
  }
  const inventory=f=>createRetainedOperatorInventory({invokeAws:f.invokeAws,identity,applicationRegion:'ap-northeast-1'});
  const leaf=(document,path)=>path.slice(0,-1).reduce((value,key)=>value[key],document);
  for(const mask of [1,2,4,7]) it('accepts only source em dash at its single authenticated position, mask '+mask,async()=>{
    const f=fixture();
    paths.forEach((path,index)=>{if(mask&(1<<index)){
      const node=leaf(f.templates[stack],path),key=path.at(-1),text=node[key];
      expect(text.indexOf('\u2014')).toBeGreaterThanOrEqual(0);
      expect(text.indexOf('\u2014')).toBe(text.lastIndexOf('\u2014'));
      node[key]=text.replace('\u2014','?');
    }});
    const before=JSON.stringify(f.templates[stack]);
    await expect(inventory(f).verifyCompletedDeploymentRoleCatalog()).resolves.toBeUndefined();
    expect(JSON.stringify(f.templates[stack])).toBe(before);
  });
  it.each(['wrong-character','extra-character','missing-description','permission','condition','resource','parameter'])('rejects %s alongside the accepted representation',async defect=>{
    const f=fixture(),template=f.templates[stack];
    for(const path of paths){const node=leaf(template,path),key=path.at(-1);node[key]=node[key].replace('\u2014','?');}
    if(defect==='wrong-character')template.Description=template.Description.replace('?', '-');
    if(defect==='extra-character')template.Parameters.ProjectName.Description+='?';
    if(defect==='missing-description')delete template.Parameters.OIDCProviderArn.Description;
    const resource=Object.values(template.Resources).find(r=>r.Type==='AWS::IAM::ManagedPolicy');
    const statement=resource.Properties.PolicyDocument.Statement[0];
    if(defect==='permission')statement.Action='iam:*';
    if(defect==='condition')statement.Condition={StringEquals:{'aws:PrincipalAccount':'123456789012'}};
    if(defect==='resource')statement.Resource='arn:aws:s3:::bucket';
    if(defect==='parameter')template.Parameters.ProjectName.Default='different-project';
    await expect(inventory(f).verifyCompletedDeploymentRoleCatalog()).rejects.toThrow();
  });
});
