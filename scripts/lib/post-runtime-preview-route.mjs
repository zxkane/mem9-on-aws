import {isConsolidationPreview,validatePreviewContext} from './consolidation-preview-config.mjs';

export const POST_RUNTIME_OPERATOR='Mem9PostFixture';
const fail=()=>{throw Error('InvalidPostRuntimePreviewRoute');};
const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join()===[...keys].sort().join();
const equal=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const sameSet=(a,b)=>Array.isArray(a)&&Array.isArray(b)&&new Set(a).size===a.length&&equal([...a].sort(),[...b].sort());

export function postRuntimeCredentialReferences(stage,account,region){
  const prefix=`arn:aws:ssm:${region}:${account}:parameter/mem9-on-aws/${stage}`;
  return {MEM9_DB_SECRET:prefix+'/runtime/schema-administrator-credential',MEM9_CONSOLIDATION_PREVIEW_CONFIG:prefix+'/consolidation-preview/config',
    ...Object.fromEntries(['planner','executor','backend','seed'].map(kind=>['MEM9_PREVIEW_'+kind.toUpperCase()+'_CREDENTIAL',prefix+'/consolidation-preview/'+kind+'-credential']))};
}

export function postRuntimeTaskTrust(account,region){
  return {Version:'2012-10-17',Statement:[{Effect:'Allow',Principal:{Service:'ecs-tasks.amazonaws.com'},Action:'sts:AssumeRole',
    Condition:{StringEquals:{'aws:SourceAccount':account},ArnLike:{'aws:SourceArn':`arn:aws:ecs:${region}:${account}:*`}}}]};
}

export function postRuntimeExecutionPolicy(parameters,kmsKeyArn,region){
  if(!Array.isArray(parameters)||parameters.length!==6||new Set(parameters).size!==6||parameters.some(p=>typeof p!=='string')||typeof kmsKeyArn!=='string')fail();
  return {Version:'2012-10-17',Statement:[
    {Effect:'Allow',Action:['ssm:GetParameters'],Resource:[...parameters].sort()},
    {Effect:'Allow',Action:['kms:Decrypt'],Resource:kmsKeyArn,
      Condition:{StringEquals:{'kms:ViaService':`ssm.${region}.amazonaws.com`,'kms:EncryptionContext:PARAMETER_ARN':[...parameters].sort()}}},
  ]};
}

export function inspectPostRuntimeRoute(value,scope){
  const keys=['version','kind','stage','account','region','generation','context','controlSourceTree','clusterArn','taskDefinitionArn','containerName','image',
    'taskRoleArn','executionRoleArn','subnets','securityGroup','host','port','database','kmsKeyArn','credentials'];
  if(!exact(value,keys)||value.version!==1||value.kind!=='post-runtime-preview-operator'||!isConsolidationPreview(value.stage)||
    !/^[0-9]{12}$/.test(value.account??'')||!/^[a-z]{2}(?:-[a-z]+)+-[0-9]$/.test(value.region??'')||
    !/^[a-f0-9]{64}$/.test(value.generation??'')||!/^[a-f0-9]{40}$/.test(value.controlSourceTree??'')||Buffer.byteLength(JSON.stringify(value))>4096)fail();
  validatePreviewContext(value.context);
  for(const key of ['stage','account','region'])if(value[key]!==scope[key])fail();
  const clusterPrefix=`arn:aws:ecs:${value.region}:${value.account}:cluster/`,cluster=value.clusterArn?.slice(clusterPrefix.length);
  if(!value.clusterArn?.startsWith(clusterPrefix)||!cluster?.startsWith('mem9-on-aws-'+value.stage+'-')||!/^[-A-Za-z0-9]+$/.test(cluster))fail();
  const taskPrefix=`arn:aws:ecs:${value.region}:${value.account}:task-definition/${cluster}-${POST_RUNTIME_OPERATOR}:`;
  if(value.containerName!==POST_RUNTIME_OPERATOR||!value.taskDefinitionArn?.startsWith(taskPrefix)||!/^[1-9][0-9]*$/.test(value.taskDefinitionArn.slice(taskPrefix.length))||
    Number(value.taskDefinitionArn.slice(taskPrefix.length))<1)fail();
  const imagePrefix=`${value.account}.dkr.ecr.${value.region}.amazonaws.com/mem9-on-aws/preview/bootstrap@`;
  if(!value.image?.startsWith(imagePrefix)||!/^sha256:[a-f0-9]{64}$/.test(value.image.slice(imagePrefix.length)))fail();
  const rolePrefix=`arn:aws:iam::${value.account}:role/`;
  for(const field of ['taskRoleArn','executionRoleArn'])if(!value[field]?.startsWith(rolePrefix)||
    !new RegExp('^mem9-on-a(?:ws|w)?-'+value.stage+'-'+POST_RUNTIME_OPERATOR+'(?:Task|Execution)Role[-A-Za-z0-9]*$').test(value[field].slice(rolePrefix.length)))fail();
  if(value.taskRoleArn===value.executionRoleArn||!Array.isArray(value.subnets)||!value.subnets.length||value.subnets.length>16||
    value.subnets.some(id=>!/^subnet-(?:[a-f0-9]{8}|[a-f0-9]{17})$/.test(id))||new Set(value.subnets).size!==value.subnets.length||
    !/^sg-(?:[a-f0-9]{8}|[a-f0-9]{17})$/.test(value.securityGroup??'')||typeof value.host!=='string'||!value.host||
    !Number.isInteger(value.port)||value.port<1||value.port>65535||typeof value.database!=='string'||!value.database)fail();
  if(!new RegExp('^arn:aws:kms:'+value.region+':'+value.account+':key/[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$').test(value.kmsKeyArn??''))fail();
  const refs=postRuntimeCredentialReferences(value.stage,value.account,value.region);
  if(!exact(value.credentials,Object.keys(refs))||Object.keys(refs).some(key=>value.credentials[key]!==refs[key]))fail();
  return structuredClone(value);
}

export function validatePostRuntimeRoute(value,expected){
  const route=inspectPostRuntimeRoute(value,expected),context=validatePreviewContext(expected.context),{runtime,manifest}=expected;
  if(!equal(route.context,context)||route.generation!==expected.generation||route.controlSourceTree!==expected.controlSourceTree||
    runtime?.nonce!==context.runtimeNonce||runtime.stage!==route.stage||runtime.phase!=='complete'||runtime.status!=='running'||
    manifest?.mode!=='active'||manifest.stage!==route.stage||manifest.account!==route.account||manifest.region!==route.region||
    manifest.administratorCredential!==route.credentials.MEM9_DB_SECRET)fail();
  for(const key of ['clusterArn','securityGroup','host','port','database'])if(value[key]!==manifest[key])fail();
  if(!sameSet(value.subnets,manifest.subnets))fail();
  return route;
}

export function postRuntimeOperatorEnvironment(route){
  return {AWS_REGION:route.region,MEM9_STAGE:route.stage,MEM9_DB_HOST:route.host,MEM9_DB_PORT:String(route.port),MEM9_DB_NAME:route.database,
    MEM9_PREVIEW_GENERATION:route.generation,MEM9_BOOTSTRAP_OPERATION:'consolidation-preview-pause',MEM9_PRODUCTION_RUNTIME_MODE:'active',
    MEM9_PREVIEW_ACCEPTANCE_CONTEXT:'post-runtime',MEM9_PREVIEW_RUNTIME_NONCE:route.context.runtimeNonce};
}

export function validatePostRuntimeDefinition(definition,route){
  if(definition?.taskDefinitionArn!==route.taskDefinitionArn||definition.networkMode!=='awsvpc'||!sameSet(definition.requiresCompatibilities,['FARGATE'])||
    definition.runtimePlatform?.cpuArchitecture!=='ARM64'||definition.runtimePlatform.operatingSystemFamily!=='LINUX'||
    definition.cpu!=='256'||definition.memory!=='512'||definition.taskRoleArn!==route.taskRoleArn||definition.executionRoleArn!==route.executionRoleArn||
    definition.volumes?.length||definition.pidMode||definition.ipcMode||definition.containerDefinitions?.length!==1)fail();
  const c=definition.containerDefinitions[0];
  if(c.name!==POST_RUNTIME_OPERATOR||c.image!==route.image||!equal(c.entryPoint,['node'])||
    !equal(c.command,['/bootstrap/operator/scripts/consolidation-preview-fixture.mjs'])||c.user!=='node'||c.readonlyRootFilesystem!==true||
    c.privileged||c.mountPoints?.length||c.environmentFiles?.length||c.repositoryCredentials||c.extraHosts?.length||
    c.dnsServers?.length||c.dnsSearchDomains?.length||c.linuxParameters?.capabilities?.add?.length||
    !sameSet(c.linuxParameters?.capabilities?.drop,['ALL'])||Object.keys(c.linuxParameters??{}).some(k=>!['capabilities','initProcessEnabled'].includes(k)))fail();
  const env=postRuntimeOperatorEnvironment(route),actual=Object.fromEntries((c.environment??[]).map(e=>[e.name,e.value]));
  if(Object.keys(actual).length!==c.environment?.length)fail();
  if(actual.SST_RESOURCE_App!==undefined){
    let app;try{app=JSON.parse(actual.SST_RESOURCE_App);}catch{fail();}
    if(!exact(app,['name','stage'])||app.name!=='mem9-on-aws'||app.stage!==route.stage)fail();delete actual.SST_RESOURCE_App;
  }
  if(!exact(actual,Object.keys(env))||Object.keys(env).some(key=>actual[key]!==env[key]))fail();
  const secrets=Object.fromEntries((c.secrets??[]).map(s=>[s.name,s.valueFrom]));
  if(c.secrets?.length!==6||!exact(secrets,Object.keys(route.credentials))||Object.keys(secrets).some(key=>secrets[key]!==route.credentials[key]))fail();
  const log=c.logConfiguration,options=log?.options;
  if(log?.logDriver!=='awslogs'||log.secretOptions?.length||options?.['awslogs-region']!==route.region||
    !options?.['awslogs-group']?.startsWith('/sst/')||!new RegExp('(?:/|-)'+route.stage+'(?:/|-)').test(options['awslogs-group'])||
    !/^[A-Za-z0-9/_-]+$/.test(options?.['awslogs-stream-prefix']??'')||
    Object.keys(options).some(key=>!['awslogs-region','awslogs-group','awslogs-stream-prefix','mode','max-buffer-size'].includes(key)))fail();
  return definition;
}
