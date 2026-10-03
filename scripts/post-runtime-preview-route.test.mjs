import {describe,it,expect} from 'vitest';
import {validatePostRuntimeRoute,validatePostRuntimeDefinition,postRuntimeExecutionPolicy,postRuntimeTaskTrust,POST_RUNTIME_OPERATOR} from './lib/post-runtime-preview-route.mjs';
import {loadPostRuntimeOperator,revalidatePostRuntimeOperator} from './lib/post-runtime-preview-aws.mjs';
const stage='pr-7',account='123456789012',region='ap-northeast-1',generation='a'.repeat(64),context={kind:'post-runtime',runtimeNonce:'b'.repeat(32)},tree='c'.repeat(40);
const cluster=`mem9-on-aws-${stage}-Cluster-example`,prefix=`arn:aws:ssm:${region}:${account}:parameter/mem9-on-aws/${stage}`;
const credentials={MEM9_DB_SECRET:prefix+'/runtime/schema-administrator-credential',MEM9_CONSOLIDATION_PREVIEW_CONFIG:prefix+'/consolidation-preview/config',
  ...Object.fromEntries(['planner','executor','backend','seed'].map(k=>['MEM9_PREVIEW_'+k.toUpperCase()+'_CREDENTIAL',prefix+'/consolidation-preview/'+k+'-credential']))};
const route=()=>({version:1,kind:'post-runtime-preview-operator',stage,account,region,generation,context,controlSourceTree:tree,
  clusterArn:`arn:aws:ecs:${region}:${account}:cluster/${cluster}`,taskDefinitionArn:`arn:aws:ecs:${region}:${account}:task-definition/${cluster}-${POST_RUNTIME_OPERATOR}:7`,
  containerName:POST_RUNTIME_OPERATOR,image:`${account}.dkr.ecr.${region}.amazonaws.com/mem9-on-aws/preview/bootstrap@sha256:${'d'.repeat(64)}`,
  taskRoleArn:`arn:aws:iam::${account}:role/mem9-on-aws-${stage}-${POST_RUNTIME_OPERATOR}TaskRole-role-test`,
  executionRoleArn:`arn:aws:iam::${account}:role/mem9-on-aws-${stage}-${POST_RUNTIME_OPERATOR}ExecutionRole-role-test`,
  subnets:['subnet-aaaabbbb'],securityGroup:'sg-aaaabbbb',host:'writer.example.com',port:5432,database:'mem9',
  kmsKeyArn:`arn:aws:kms:${region}:${account}:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee`,credentials});
const expected=()=>({stage,account,region,generation,context,controlSourceTree:tree,
  runtime:{stage,nonce:context.runtimeNonce,phase:'complete',status:'running'},
  manifest:{stage,mode:'active',account,region,clusterArn:route().clusterArn,subnets:route().subnets,securityGroup:route().securityGroup,host:route().host,port:5432,database:'mem9',administratorCredential:credentials.MEM9_DB_SECRET}});
const definition=r=>({taskDefinitionArn:r.taskDefinitionArn,networkMode:'awsvpc',requiresCompatibilities:['FARGATE'],runtimePlatform:{cpuArchitecture:'ARM64',operatingSystemFamily:'LINUX'},cpu:'256',memory:'512',taskRoleArn:r.taskRoleArn,executionRoleArn:r.executionRoleArn,
  containerDefinitions:[{name:r.containerName,image:r.image,entryPoint:['node'],command:['/bootstrap/operator/scripts/consolidation-preview-fixture.mjs'],user:'node',readonlyRootFilesystem:true,
    linuxParameters:{capabilities:{drop:['ALL']}},environment:Object.entries({AWS_REGION:region,MEM9_STAGE:stage,MEM9_DB_HOST:r.host,MEM9_DB_PORT:'5432',MEM9_DB_NAME:r.database,
      MEM9_PREVIEW_GENERATION:generation,MEM9_BOOTSTRAP_OPERATION:'consolidation-preview-pause',MEM9_PRODUCTION_RUNTIME_MODE:'active',MEM9_PREVIEW_ACCEPTANCE_CONTEXT:'post-runtime',MEM9_PREVIEW_RUNTIME_NONCE:context.runtimeNonce}).map(([name,value])=>({name,value})),
    secrets:Object.entries(credentials).map(([name,valueFrom])=>({name,valueFrom})),logConfiguration:{logDriver:'awslogs',options:{'awslogs-group':'/sst/mem9-on-aws/pr-7/operator','awslogs-region':region,'awslogs-stream-prefix':'ecs'}}}]});
describe('post-runtime operator routing boundary',()=>{
  it('admits only the exact completed preview context and dedicated definition',()=>{
    const r=validatePostRuntimeRoute(route(),expected());expect(r.containerName).toBe(POST_RUNTIME_OPERATOR);
    expect(()=>validatePostRuntimeDefinition(definition(r),r)).not.toThrow();
  });
  it.each([
    r=>{r.stage='prod';},r=>{r.context={...context,runtimeNonce:'e'.repeat(32)};},r=>{r.credentials={...credentials,MEM9_RUNTIME_DB_SECRET:prefix+'/runtime/database-credential'};},
    r=>{r.image=r.image.replace('@sha256:',':');},r=>{r.taskRoleArn=r.taskRoleArn.replace(stage,'prod');},r=>{r.command=['arbitrary'];},
  ])('rejects substituted or extensible routes',mutate=>{const r=structuredClone(route());mutate(r);expect(()=>validatePostRuntimeRoute(r,expected())).toThrow();});
  it.each(['prepare','paused','ready'])('rejects %s runtime routing',mode=>{const e=expected();e.manifest.mode=mode;expect(()=>validatePostRuntimeRoute(route(),e)).toThrow();});
  it('rejects stale complete state and changed network/source',()=>{
    for(const mutate of [e=>{e.runtime.nonce='e'.repeat(32);},e=>{e.controlSourceTree='f'.repeat(40);},e=>{e.manifest.subnets=['subnet-ccccdddd'];}]){const e=expected();mutate(e);expect(()=>validatePostRuntimeRoute(route(),e)).toThrow();}
  });
  it.each([
    d=>{d.containerDefinitions[0].environment.push({name:'NODE_OPTIONS',value:'--inspect'});},d=>{d.containerDefinitions[0].secrets.push({name:'OTHER',valueFrom:prefix+'/runtime/transition-credential'});},
    d=>{d.containerDefinitions[0].user='root';},d=>{d.containerDefinitions[0].readonlyRootFilesystem=false;},d=>{d.containerDefinitions[0].command=['arbitrary'];},
    d=>{d.executionRoleArn=d.taskRoleArn;},d=>{d.containerDefinitions[0].image=d.containerDefinitions[0].image.replace('d'.repeat(64),'e'.repeat(64));},
  ])('rejects execution material drift before RunTask',mutate=>{const d=definition(route());mutate(d);expect(()=>validatePostRuntimeDefinition(d,route())).toThrow();});
  it('constructs same-account trust and exact six-parameter/KMS access',()=>{
    const r=route(),policy=postRuntimeExecutionPolicy(Object.values(r.credentials),r.kmsKeyArn,region);
    expect(policy.Statement[0].Resource).toHaveLength(6);expect(policy.Statement[1].Resource).toBe(r.kmsKeyArn);
    expect(policy.Statement[1].Condition.StringEquals['kms:ViaService']).toBe('ssm.'+region+'.amazonaws.com');
    expect(JSON.stringify(policy)).not.toContain('ssm:PutParameter');
    expect(postRuntimeTaskTrust(account,region).Statement[0].Condition.StringEquals['aws:SourceAccount']).toBe(account);
  });
  it('loads actual scoped metadata and rejects route or role drift before launch',async()=>{
    const r=route(),def=definition(r),e=expected();let version=1,extraPolicy=false;const calls=[];
    const values=new Map([
      ['/mem9-on-aws/pr-7/consolidation-preview/operator',JSON.stringify(r)],
      ['/mem9-on-aws/pr-7/runtime/production-state',JSON.stringify(e.runtime)],
      ['/mem9-on-aws/pr-7/runtime/production-manifest',JSON.stringify(e.manifest)],
    ]);
    const client={send:async command=>{
      const name=command.constructor.name,input=command.input;calls.push(name);
      if(name==='GetCallerIdentityCommand')return {Account:account};
      if(name==='GetParametersCommand')return {Parameters:input.Names.map(Name=>({Name,Value:values.get(Name),Version:version,Type:Name.endsWith('/operator')?'String':'SecureString',ARN:`arn:aws:ssm:${region}:${account}:parameter${Name}`})),InvalidParameters:[]};
      if(name==='DescribeTaskDefinitionCommand')return {taskDefinition:def};
      const execution=input.RoleName===r.executionRoleArn.split('/').at(-1);
      if(name==='GetRoleCommand')return {Role:{Arn:execution?r.executionRoleArn:r.taskRoleArn,AssumeRolePolicyDocument:JSON.stringify(postRuntimeTaskTrust(account,region)),PermissionsBoundary:{PermissionsBoundaryArn:`arn:aws:iam::${account}:policy/mem9-on-aws-workload-boundary`}}};
      if(name==='ListRolePoliciesCommand')return {PolicyNames:execution?['PostRuntimePreviewSecrets',...(extraPolicy?['unexpected']:[])]:[]};
      if(name==='ListAttachedRolePoliciesCommand')return {AttachedPolicies:execution?[{PolicyArn:'arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy'}]:[]};
      if(name==='GetRolePolicyCommand')return {PolicyDocument:JSON.stringify(postRuntimeExecutionPolicy(Object.values(r.credentials),r.kmsKeyArn,region))};
      throw Error('UnexpectedWrite');
    }};
    const clients={ssm:client,ecs:client,iam:client,sts:client};
    const options={stage,region,generation,context,controlSourceTree:tree};
    const checks={artifact:async()=>({rootDigest:r.image.split('@')[1],arm64Digest:'sha256:'+'e'.repeat(64)}),key:async()=>r.kmsKeyArn};
    const binding=await loadPostRuntimeOperator(clients,options,checks);expect(binding.route).toEqual(r);
    await expect(revalidatePostRuntimeOperator(clients,binding,options,checks)).resolves.toBeUndefined();
    version++;await expect(revalidatePostRuntimeOperator(clients,binding,options,checks)).rejects.toThrow('PostRuntimeRouteChanged');
    extraPolicy=true;await expect(loadPostRuntimeOperator(clients,options,checks)).rejects.toThrow('PostRuntimeRoleMismatch');
    expect(calls.every(name=>/^(Get|List|Describe)/.test(name))).toBe(true);
  });
});
