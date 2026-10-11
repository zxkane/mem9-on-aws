// Synthetic source/readback fixture shared by the preview caller tests.
import {previewBootstrapRegistration,buildNonrootPreviewPurposeMap} from './lib/nonroot-preview-source.mjs';
import {POST_RUNTIME_PURPOSES,postRuntimeOperatorEnvironment,bindPostRuntimePurposeMap} from './lib/post-runtime-preview-route.mjs';
import {controlLaunchPolicy} from './lib/production-nonroot-launch.mjs';
export function nonrootPreviewFixture({stage='pr-7',region='ap-northeast-1',account='123456789012',cluster='mem9-on-aws-pr-7-Cluster-example',sourceTree='a'.repeat(40),
 purposes=['bootstrap-runtime-bootstrap','bootstrap-runtime-verify','bootstrap-admin-probe','bootstrap-admin-probe-cleanup'],environment=[],secrets=[],logGroup='/sst/synthetic',logStreamPrefix='bootstrap'}={}){
 const scope={stage,region,account,sourceTree},family=cluster+'-Mem9Bootstrap';
 const base={family,networkMode:'awsvpc',requiresCompatibilities:['FARGATE'],runtimePlatform:{cpuArchitecture:'ARM64',operatingSystemFamily:'LINUX'},cpu:'256',memory:'512',
  taskRoleArn:`arn:aws:iam::${account}:role/preview-task`,executionRoleArn:`arn:aws:iam::${account}:role/preview-execution`,
  containerDefinitions:[{name:'Mem9Bootstrap',image:`${account}.dkr.ecr.${region}.amazonaws.com/mem9-on-aws/preview/bootstrap@sha256:${'b'.repeat(64)}`,
   environment:[{name:'MEM9_STAGE',value:stage},{name:'MEM9_RUNTIME_BOOTSTRAP_VERSION',value:'1'},...environment],secrets,
   logConfiguration:{logDriver:'awslogs',options:{'awslogs-group':logGroup,'awslogs-stream-prefix':logStreamPrefix,'awslogs-region':region}},linuxParameters:{initProcessEnabled:true}}],tags:[{key:'Stage',value:stage}]};
 const records=purposes.map((purpose,i)=>{
  const registration=previewBootstrapRegistration(base,purpose,scope),{tags,...body}=registration,revision=100+i;
  return {purpose,registration,observation:{taskDefinition:{...body,taskDefinitionArn:`arn:aws:ecs:${region}:${account}:task-definition/${family}:${revision}`,revision,status:'ACTIVE',
   registeredAt:'2026-10-08T00:00:00.000Z',registeredBy:`arn:aws:sts::${account}:assumed-role/preview/session`,requiresAttributes:[{name:'ecs.capability.task-eni'}],compatibilities:['FARGATE']},tags}};
 });
 const map=buildNonrootPreviewPurposeMap({scope,defaultPurpose:purposes[0],records});
 const prefix=`/mem9-on-aws/${stage}/bootstrap/`,values={'purpose-bindings':JSON.stringify(map),'cluster-name':cluster,'subnet-ids':'subnet-0123456789abcdef0','task-sg-id':'sg-0123456789abcdef0'};
 const parameters=new Map(Object.entries(values).map(([suffix,Value])=>{const Name=prefix+suffix;return [Name,{Name,Value,ARN:`arn:aws:ssm:${region}:${account}:parameter${Name}`,Version:1,Type:suffix==='subnet-ids'?'StringList':'String'}];}));
 return {scope,map,records,parameters,definitions:new Map(records.map(r=>[r.observation.taskDefinition.taskDefinitionArn,r.observation]))};
}
export function nonrootPostRuntimeFixture(base){
 const family=base.taskDefinitionArn.split('/').at(-1).split(':')[0],firstRevision=Number(base.taskDefinitionArn.split(':').at(-1));
 const records=POST_RUNTIME_PURPOSES.map((purpose,index)=>{
  const launchPurpose=purpose==='preview-fixture-pause'?'post-runtime-fixture':purpose;
  const env=postRuntimeOperatorEnvironment({...base,version:2,launch:{purpose:launchPurpose}});
  const container=controlLaunchPolicy(launchPurpose,{name:base.containerName,image:base.image,readonlyRootFilesystem:true,
   environment:Object.entries(env).map(([name,value])=>({name,value})),secrets:Object.entries(base.credentials).map(([name,valueFrom])=>({name,valueFrom})),
   logConfiguration:{logDriver:'awslogs',options:{'awslogs-group':'/sst/mem9-on-aws/'+base.stage+'/operator','awslogs-region':base.region,'awslogs-stream-prefix':'ecs'}}});
  const registration={family,networkMode:'awsvpc',requiresCompatibilities:['FARGATE'],runtimePlatform:{cpuArchitecture:'ARM64',operatingSystemFamily:'LINUX'},
   cpu:'256',memory:'512',taskRoleArn:base.taskRoleArn,executionRoleArn:base.executionRoleArn,containerDefinitions:[container],tags:[]};
  const {tags,...body}=registration,revision=firstRevision+index;
  return {purpose,registration,observation:{taskDefinition:{...body,taskDefinitionArn:base.taskDefinitionArn.replace(/:[0-9]+$/,':'+revision),revision,status:'ACTIVE',
   registeredAt:'2026-10-08T00:00:00.000Z',registeredBy:`arn:aws:sts::${base.account}:assumed-role/preview/session`,requiresAttributes:[],compatibilities:['FARGATE']},tags}};
 });
 const map=bindPostRuntimePurposeMap(base,records);
 const routes=new Map(records.map((r,index)=>[r.purpose,{...base,version:2,taskDefinitionArn:map.bindings[index].taskDefinitionArn,
  launch:{version:1,purpose:r.purpose==='preview-fixture-pause'?'post-runtime-fixture':r.purpose,definitionHash:map.bindings[index].definitionHash}}]));
 return {map,records,routes,definitions:new Map(records.map(r=>[r.observation.taskDefinition.taskDefinitionArn,r.observation]))};
}
