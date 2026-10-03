import {describe,it,expect,vi,afterEach} from 'vitest';
import {createHash} from 'node:crypto';
import {buildCanaryCompatibility,inspectCanaryMaterialCompatibility,captureCanaryMaterial,normalizeCanaryAuthority} from './lib/production-canary-producer.mjs';
import {normalizeCanaryTask} from './lib/production-canary-material.mjs';
import {validateCanaryCompatibility} from './lib/production-canary-compatibility.mjs';
import {canaryEvidenceHash as hash} from './lib/production-canary-verification.mjs';
import * as delivery from './lib/production-canary-delivery.mjs';
import * as scheduling from './lib/production-scheduling.mjs';
import * as runtimeTasks from './lib/production-runtime-tasks.mjs';
import * as runtimeVerification from './lib/runtime-live-verification.mjs';

afterEach(()=>vi.restoreAllMocks());

const account='123456789012',region='ap-northeast-1',hex=n=>n.toString(16).padStart(64,'0'),digest=n=>'sha256:'+hex(n);
function fixture(){
  const snapshot=next=>{
    const root=next?2:1,sourceTag=next?'mem9-bbbbbbb':'mem9-aaaaaaa';
    const ref=repo=>`${account}.dkr.ecr.${region}.amazonaws.com/mem9-on-aws/${repo}@${digest(root)}`;
    const image=repo=>({registryId:account,repositoryName:'mem9-on-aws/'+repo,rootDigest:digest(root),arm64Digest:digest(3)});
    const make=(kind,containers)=>({taskDefinitionArn:`arn:aws:ecs:${region}:${account}:task-definition/mem9-on-aws-prod-Fixture-${kind}:${next?2:1}`,
      family:'mem9-on-aws-prod-Fixture-'+kind,revision:next?2:1,status:'ACTIVE',networkMode:'awsvpc',cpu:'512',memory:'1024',runtimePlatform:{cpuArchitecture:'ARM64',operatingSystemFamily:'LINUX'},requiresCompatibilities:['FARGATE'],
      taskRoleArn:`arn:aws:iam::${account}:role/mem9-on-aws-prod-${kind}-task`,executionRoleArn:`arn:aws:iam::${account}:role/mem9-on-aws-prod-${kind}-exec`,containerDefinitions:containers});
    const definitions={planner:make('Planner',[{name:'planner',image:ref('llm-proxy'),environment:[],secrets:[]}]),executor:make('Executor',[{name:'executor',image:ref('llm-proxy'),environment:[],secrets:[]}]),
      backend:make('Mem9RuntimeServer',['llm-proxy','mnemo-server','qwen3-embed'].map(name=>({name,image:ref(name),environment:[],secrets:[]})))};
    const images=new Map(['llm-proxy','mnemo-server','qwen3-embed'].map(repo=>[ref(repo),image(repo)]));
    const backendBinding={taskArn:`arn:aws:ecs:${region}:${account}:task/mem9-on-aws-prod-Fixture/${(next?'b':'a').repeat(32)}`,taskDefinitionArn:definitions.backend.taskDefinitionArn,
      containers:['llm-proxy','mnemo-server','qwen3-embed'].map(name=>({name,imageDigest:digest(root)}))};
    const authority=Object.values(definitions).flatMap(d=>[d.taskRoleArn,d.executionRoleArn]).sort().map(arn=>({arn,roleId:arn.split('/').at(-1),trust:{},policies:[]}));
    const scheduler={roleArn:`arn:aws:iam::${account}:role/mem9-on-aws-prod-Mem9ConsolidationSchedulerRole-role`,groupName:'mem9-on-aws-prod-consolidation-fixture'};
    authority.push({arn:scheduler.roleArn,roleId:'scheduler-role-id',trust:{Version:'2012-10-17',Statement:[{Effect:'Allow',Action:'sts:AssumeRole',Principal:{Service:'scheduler.amazonaws.com'},
      Condition:{StringEquals:{'aws:SourceAccount':account,'aws:SourceArn':`arn:aws:scheduler:${region}:${account}:schedule-group/${scheduler.groupName}`}}}]},
      inlinePolicies:[{name:'scheduler',document:{Version:'2012-10-17',Statement:[
        {Effect:'Deny',Action:'ecs:RunTask',Resource:`arn:aws:ecs:${region}:${account}:task-definition/mem9-on-aws-prod-Fixture-Mem9Consolidation:*`},
        {Effect:'Allow',Action:'ecs:RunTask',Resource:[definitions.planner.taskDefinitionArn,definitions.executor.taskDefinitionArn],Condition:{ArnEquals:{'ecs:cluster':`arn:aws:ecs:${region}:${account}:cluster/mem9-on-aws-prod-Fixture`}}},
        {Effect:'Allow',Action:'iam:PassRole',Resource:[definitions.planner.taskRoleArn,definitions.planner.executionRoleArn,definitions.executor.taskRoleArn,definitions.executor.executionRoleArn],Condition:{StringEquals:{'iam:PassedToService':'ecs-tasks.amazonaws.com'}}},
      ]}}],attachedPolicies:[],boundary:{arn:`arn:aws:iam::${account}:policy/mem9-on-aws-workload-boundary`,document:{}}});
    authority.sort((a,b)=>a.arn.localeCompare(b.arn));
    const value={version:2,account,region,revision:(next?'b':'a').repeat(40),sourceTree:(next?'b':'a').repeat(40),coordinatorDigest:hex(next?5:4),
      generation:hex(6),sourceTag,workerImage:ref('llm-proxy'),backendBinding,definitions,
      runtime:{schemaDigest:hex(7),operatorDigest:hex(8),runtimeNonce:'c'.repeat(32)},
      components:{worker:image('llm-proxy'),...Object.fromEntries(['llm-proxy','mnemo-server','qwen3-embed'].map(repo=>[repo,image(repo)]))},
      backendTask:{taskArn:backendBinding.taskArn,taskDefinitionArn:backendBinding.taskDefinitionArn,
        clusterArn:`arn:aws:ecs:${region}:${account}:cluster/mem9-on-aws-prod-Fixture`,lastStatus:'RUNNING',
        containers:definitions.backend.containerDefinitions.map(c=>({name:c.name,image:c.image,imageDigest:digest(root)}))},
      scheduler,authority,credentials:[],network:{cluster:`arn:aws:ecs:${region}:${account}:cluster/mem9-on-aws-prod-Fixture`,subnets:['subnet-abcd'],securityGroups:['sg-abcd'],assignPublicIp:'DISABLED'},material:{}};
    for(const kind of ['planner','executor','backend'])value.material[kind]=hash(normalizeCanaryTask(definitions[kind],{account,region,images}));
    for(const kind of ['network','credentials'])value.material[kind]=hash(value[kind]);
    value.material.authority=hash(normalizeCanaryAuthority(value));
    return value;
  };
  const previous=snapshot(false),current=snapshot(true);
  const release={sourceTree:previous.sourceTree,coordinatorDigest:previous.coordinatorDigest,sourceTag:previous.sourceTag,workerImage:previous.workerImage,...previous.runtime};
  const parent={generation:previous.generation,targets:['namespace-a'],workerImage:previous.workerImage,sourceTag:previous.sourceTag,backendBindingHash:hash(previous.backendBinding),releaseHash:hash(release)};
  return {previous,current,parent};
}
describe('authenticated canary material producer',()=>{
  it('recomputes retained authorization and binds its actual data roots and parent',()=>{
    const f=fixture(),now=1800000000000,current=structuredClone(f.previous);
    current.revision='c'.repeat(40);current.sourceTree='d'.repeat(40);current.coordinatorDigest=hex(55);
    const data={version:1,stage:'prod',account,region,controlSourceTree:current.sourceTree,dataRevision:f.previous.revision,dataSourceTree:f.previous.sourceTree,dataSourceTag:f.previous.sourceTag,
      images:Object.fromEntries(['llm-proxy','mnemo-server','qwen3-embed'].map(name=>[name,{rootDigest:current.components[name].rootDigest,arm64Digest:current.components[name].arm64Digest}])),
      parentProofHash:hash(f.parent),backendBindingHash:f.parent.backendBindingHash,runtimeNonce:current.runtime.runtimeNonce,generation:current.generation,targetsHash:hash(f.parent.targets),
      schemaDigest:current.runtime.schemaDigest,operatorDigest:current.runtime.operatorDigest,buildInputsHash:hex(21),securityEvidenceHash:hex(22),policyHash:hex(23),
      authorizationId:'e'.repeat(32),issuedMs:now-1000,expiresMs:now+1000};
    current.dataRelease={data,hash:hash(data)};
    expect(buildCanaryCompatibility(f.previous,current,f.parent,{now})).toMatchObject({version:2,dataReleaseHash:hash(data)});
    const altered=structuredClone(current);altered.dataRelease.data.securityEvidenceHash=hex(66);
    expect(()=>buildCanaryCompatibility(f.previous,altered,f.parent,{now})).toThrow();
    expect(()=>buildCanaryCompatibility(f.previous,current,f.parent,{now:data.expiresMs})).toThrow('DataReleaseAuthorizationExpired');
    expect(inspectCanaryMaterialCompatibility(f.previous,current,f.parent)).toEqual(buildCanaryCompatibility(f.previous,current,f.parent,{now}));
    expect(()=>inspectCanaryMaterialCompatibility(f.previous,altered,f.parent)).toThrow();
  });
  it('captures complete Scheduler authority and credential fingerprints from mocked AWS reads',async()=>{
    const source=fixture().current;
    const imageManifest=JSON.stringify({schemaVersion:2,mediaType:'application/vnd.oci.image.index.v1+json',manifests:[
      {digest:digest(3),mediaType:'application/vnd.oci.image.manifest.v1+json',platform:{os:'linux',architecture:'arm64'}}]});
    const rootDigest='sha256:'+createHash('sha256').update(imageManifest).digest('hex');
    for(const definition of Object.values(source.definitions))for(const c of definition.containerDefinitions)c.image=c.image.split('@')[0]+'@'+rootDigest;
    for(const c of source.backendBinding.containers)c.imageDigest=rootDigest;
    const task={...source.backendTask,launchType:'FARGATE',healthStatus:'HEALTHY',attributes:[{name:'ecs.cpu-architecture',value:'arm64'}],
      containers:source.definitions.backend.containerDefinitions.map(c=>({name:c.name,image:c.image,imageDigest:rootDigest,healthStatus:'HEALTHY'}))};
    const reference=`arn:aws:ssm:${region}:${account}:parameter/mem9-on-aws/prod/consolidation-runtime/executor-credential`,value='synthetic-credential-only';
    source.definitions.executor.containerDefinitions[0].secrets=[{name:'DB',valueFrom:reference}];
    const targets=['planner','executor'].map(kind=>({kind,...source.scheduler,clusterArn:task.clusterArn,taskDefinitionArn:source.definitions[kind].taskDefinitionArn,
      image:source.definitions[kind].containerDefinitions[0].image,sourceTag:source.sourceTag,generation:source.generation,subnets:['subnet-abcd'],securityGroup:'sg-abcd',template:{Name:kind}}));
    vi.spyOn(delivery,'loadProductionCanaryWorker').mockImplementation(async(_clients,{kind})=>targets.find(t=>t.kind===kind));
    vi.spyOn(scheduling,'verifyProductionScheduling').mockResolvedValue({enabled:false});
    vi.spyOn(scheduling,'captureProductionBackend').mockResolvedValue(source.backendBinding);
    vi.spyOn(runtimeTasks,'loadProductionManifest').mockResolvedValue({mode:'active'});
    vi.spyOn(runtimeVerification,'runtimeServerContract').mockReturnValue({});
    vi.spyOn(runtimeVerification,'verifyRuntimeRoles').mockResolvedValue(undefined);
    const calls=[],boundary=`arn:aws:iam::${account}:policy/mem9-on-aws-workload-boundary`;
    const send=async command=>{
      const name=command.constructor.name,input=command.input;calls.push({name,input});
      if(name==='GetCallerIdentityCommand')return {Account:account};
      if(name==='ListAccountAliasesCommand')return {AccountAliases:['example-account']};
      if(name==='ListSchedulesCommand')return {Schedules:targets.map(t=>({Name:t.template.Name,State:'DISABLED'}))};
      if(name==='DescribeTaskDefinitionCommand')return {taskDefinition:Object.values(source.definitions).find(d=>d.taskDefinitionArn===input.taskDefinition)};
      if(name==='DescribeTasksCommand')return {tasks:[task]};
      if(name==='DescribeServicesCommand')return {services:[{taskDefinition:task.taskDefinitionArn,networkConfiguration:{awsvpcConfiguration:{assignPublicIp:'DISABLED',subnets:['subnet-abcd'],securityGroups:['sg-abcd']}}}]};
      if(name==='GetParametersCommand')return {Parameters:input.Names.map(Name=>({Name,ARN:Name,Version:1,Type:'SecureString',Value:Name===reference?value:
        JSON.stringify({stage:'prod',phase:'complete',status:'running',nonce:source.runtime.runtimeNonce,...source.runtime})}))};
      const role=source.authority.find(r=>r.arn.split('/').at(-1)===input.RoleName);
      if(name==='GetRoleCommand')return {Role:{Arn:role.arn,RoleId:role.roleId,Path:'/',MaxSessionDuration:3600,AssumeRolePolicyDocument:role.trust,PermissionsBoundary:{PermissionsBoundaryArn:boundary}}};
      if(name==='ListRolePoliciesCommand')return {PolicyNames:(role.inlinePolicies??[]).map(p=>p.name)};
      if(name==='ListAttachedRolePoliciesCommand')return {AttachedPolicies:[]};
      if(name==='GetRolePolicyCommand')return {RoleName:input.RoleName,PolicyName:input.PolicyName,PolicyDocument:role.inlinePolicies.find(p=>p.name===input.PolicyName).document};
      if(name==='GetPolicyCommand')return {Policy:{Arn:input.PolicyArn,DefaultVersionId:'v1'}};
      if(name==='GetPolicyVersionCommand')return {PolicyVersion:{VersionId:'v1',Document:{Version:'2012-10-17',Statement:[]}}};
      throw Error('UnexpectedMockCommand:'+name);
    };
    const clients=Object.fromEntries(['ssm','ecs','iam','sts','secrets','scheduler'].map(k=>[k,{send}]));
    const captured=await captureCanaryMaterial(clients,{account,region,expectedAccountAlias:'example-account',release:{revision:source.revision,sourceTree:source.sourceTree,coordinatorDigest:source.coordinatorDigest,
      imageDigests:Object.fromEntries(['llm-proxy','mnemo-server','qwen3-embed'].map(k=>[k,rootDigest]))},
      batchGetImage:async input=>({images:[{registryId:account,repositoryName:input.repositoryName,imageId:{imageDigest:rootDigest},imageManifest}]})});
    expect(captured.version).toBe(2);expect(captured.authority).toHaveLength(7);
    expect(captured.authority.find(r=>r.arn===source.scheduler.roleArn).roleId).toBe('scheduler-role-id');
    expect(captured.material.authority).toBe(hash(normalizeCanaryAuthority(captured)));
    expect(captured.credentials).toEqual([{reference,version:'1',type:'SecureString',valueHash:createHash('sha256').update(value).digest('hex')}]);
    expect(JSON.stringify(captured)).not.toContain(value);
    expect(calls.filter(c=>c.name==='GetRoleCommand')).toHaveLength(7);
    expect(calls.some(c=>/^(Put|Create|Delete|Update|Run|Stop)/.test(c.name))).toBe(false);
  });
  it('constructs a certificate accepted by the operator from equal material content',()=>{
    const f=fixture(),certificate=buildCanaryCompatibility(f.previous,f.current,f.parent);
    const acceptance={sourceTree:f.current.sourceTree,coordinatorDigest:f.current.coordinatorDigest,
      continuation:{version:1,parentProofHash:hash(f.parent),certificateHash:hash(certificate),sourceTree:f.current.sourceTree,
        fixture:{hash:hex(33),runId:'12345',runAttempt:1}}};
    expect(validateCanaryCompatibility(certificate,f.parent,{generation:f.current.generation,targets:f.parent.targets,sourceTag:f.current.sourceTag,workerImage:f.current.workerImage,acceptance},
      {operation_nonce:f.current.runtime.runtimeNonce,identity:{schemaDigest:f.current.runtime.schemaDigest,operatorDigest:f.current.runtime.operatorDigest,
        clusterArn:`arn:aws:ecs:${region}:${account}:cluster/mem9-on-aws-prod-Fixture`}}).backendBinding).toEqual(f.current.backendBinding);
  });
  it('recomputes material hashes rather than trusting copied hash fields',()=>{
    const f=fixture();f.current.definitions.executor.cpu='2048';
    expect(()=>buildCanaryCompatibility(f.previous,f.current,f.parent)).toThrow();
  });
  it.each(['previous','current'])('binds %s tagged backend mappings to the actual archived task and definition',side=>{
    for(const mutate of [s=>{s.components['mnemo-server'].rootDigest=digest(77);},
      s=>{s.backendTask.containers[0].imageDigest=digest(77);},s=>{s.backendBinding.taskDefinitionArn+='0';},
      s=>{s.backendTask.containers[0].image='unrelated';},s=>{s.backendTask.containers.push(s.backendTask.containers[0]);}]){
      const f=fixture(),s=f[side];
      for(const c of s.definitions.backend.containerDefinitions){
        c.image=c.image.split('@')[0]+':'+s.sourceTag;s.backendTask.containers.find(t=>t.name===c.name).image=c.image;
      }
      mutate(s);expect(()=>buildCanaryCompatibility(f.previous,f.current,f.parent)).toThrow('CanaryMaterialCaptureFailed');
    }
  });
  it('rejects missing authority/credential coverage and changed image children',()=>{
    for(const mutate of [f=>{f.current.authority.pop();},f=>{f.current.components.worker.arm64Digest=digest(99);},
      f=>{f.current.definitions.executor.containerDefinitions[0].secrets=[{name:'DB',valueFrom:'unrepresented'}];},
      f=>{f.current.network.assignPublicIp='ENABLED';f.current.material.network=hash(f.current.network);}]){
      const f=fixture();mutate(f);expect(()=>buildCanaryCompatibility(f.previous,f.current,f.parent)).toThrow();
    }
  });
  it.each(['wrong-revision','extra-resource','missing-deny','widened-trust','foreign-role','missing-scheduler'])('rejects Scheduler authority %s',kind=>{
    const f=fixture(),role=f.current.authority.find(r=>r.arn===f.current.scheduler.roleArn),statements=role.inlinePolicies[0].document.Statement;
    if(kind==='wrong-revision')statements[1].Resource[0]=statements[1].Resource[0].replace(/:2$/,':3');
    if(kind==='extra-resource')statements[1].Resource.push('arn:aws:ecs:'+region+':'+account+':task-definition/unrelated:1');
    if(kind==='missing-deny')statements.shift();
    if(kind==='widened-trust')delete role.trust.Statement[0].Condition;
    if(kind==='foreign-role')statements[2].Resource[0]=`arn:aws:iam::${'0'.repeat(12)}:role/foreign`;
    if(kind==='missing-scheduler')f.current.authority=f.current.authority.filter(r=>r!==role);
    expect(()=>buildCanaryCompatibility(f.previous,f.current,f.parent)).toThrow('CanaryMaterialCaptureFailed');
  });
  it('rejects a wrong account before reading application configuration',async()=>{
    let touched=false;
    const clients={sts:{send:async()=>({Account:'0'.repeat(12)})},iam:{send:async()=>{touched=true;throw Error('unexpected');}}};
    await expect(captureCanaryMaterial(clients,{account,region,expectedAccountAlias:'example-account',release:{revision:'a'.repeat(40),sourceTree:'a'.repeat(40),coordinatorDigest:hex(2)},batchGetImage:async()=>{throw Error('unexpected');}})).rejects.toThrow('CanaryMaterialCaptureFailed');
    expect(touched).toBe(false);
  });
});
