import {isConsolidationPreview,validatePreviewContext} from './consolidation-preview-config.mjs';
import {copyNonrootJson,nonrootHash} from './production-nonroot-contracts.mjs';
import {verifyPreviewRegistrationReadback} from './nonroot-preview-source.mjs';

export const POST_RUNTIME_OPERATOR='Mem9PostFixture';
export const POST_RUNTIME_PURPOSES=Object.freeze(['preview-fixture-pause','preview-fixture-setup','preview-fixture-verify-planned','preview-fixture-verify-executed','preview-fixture-verify-repeated']);
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
  if(value?.version===2)keys.push('launch');
  if(!exact(value,keys)||![1,2].includes(value.version)||value.kind!=='post-runtime-preview-operator'||!isConsolidationPreview(value.stage)||
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
  if(value.version===2&&(!exact(value.launch,['version','purpose','definitionHash'])||value.launch.version!==1||
    !['post-runtime-fixture',...POST_RUNTIME_PURPOSES].includes(value.launch.purpose)||!/^[a-f0-9]{64}$/.test(value.launch.definitionHash??'')))fail();
  if(scope.requiredVersion!==undefined&&value.version!==scope.requiredVersion)fail();
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

/** New workflows use this entry point; historical v1 inspection stays strict. */
export function validateGuardedPostRuntimeRoute(value,expected){
  return validatePostRuntimeRoute(value,{...expected,requiredVersion:2});
}

export function bindGuardedPostRuntimeRoute(value,registration,observation){
  const prior=inspectPostRuntimeRoute(value,value);
  if(prior.version!==1)fail();
  const observed=verifyPreviewRegistrationReadback(registration,observation);
  const route={...prior,version:2,launch:{version:1,purpose:'post-runtime-fixture',definitionHash:nonrootHash(observed)}};
  validatePostRuntimeDefinition(observed.taskDefinition,route,observed);return copyNonrootJson(route);
}

/** The protected parameter contains this closed map. Its legacy-shaped route
 * holds common metadata only; it is never selected for an application launch. */
export function inspectPostRuntimePurposeMap(input,scope){
  const value=copyNonrootJson(input);
  if(!exact(value,['version','kind','route','bindings'])||value.version!==1||value.kind!=='post-runtime-preview-purpose-map'||
    Buffer.byteLength(JSON.stringify(value))>4096||!Array.isArray(value.bindings)||value.bindings.length<1||value.bindings.length>POST_RUNTIME_PURPOSES.length)fail();
  const base=inspectPostRuntimeRoute(value.route,scope);if(base.version!==1)fail();
  for(const b of value.bindings){
    if(!exact(b,['purpose','taskDefinitionArn','definitionHash'])||!POST_RUNTIME_PURPOSES.includes(b.purpose)||!/^[a-f0-9]{64}$/.test(b.definitionHash??''))fail();
    inspectPostRuntimeRoute({...base,taskDefinitionArn:b.taskDefinitionArn},scope);
  }
  if(new Set(value.bindings.map(b=>b.purpose)).size!==value.bindings.length||new Set(value.bindings.map(b=>b.taskDefinitionArn)).size!==value.bindings.length)fail();
  return value;
}
export function selectGuardedPostRuntimeRoute(input,expected,purpose='preview-fixture-pause'){
  const map=inspectPostRuntimePurposeMap(input,expected),base=validatePostRuntimeRoute(map.route,expected);
  const selected=map.bindings.find(b=>b.purpose===purpose);if(!selected)throw Error('NonrootPreviewPurposeUnavailable');
  return inspectPostRuntimeRoute({...base,version:2,taskDefinitionArn:selected.taskDefinitionArn,
    launch:{version:1,purpose:purpose==='preview-fixture-pause'?'post-runtime-fixture':purpose,definitionHash:selected.definitionHash}},expected);
}
export function bindPostRuntimePurposeMap(base,records){
  const route=inspectPostRuntimeRoute(base,base);if(route.version!==1||!Array.isArray(records))fail();
  const bindings=records.map(r=>{
    if(!exact(r,['purpose','registration','observation'])||!POST_RUNTIME_PURPOSES.includes(r.purpose))fail();
    const observation=verifyPreviewRegistrationReadback(r.registration,r.observation);
    const selected={...route,version:2,taskDefinitionArn:observation.taskDefinition.taskDefinitionArn,
      launch:{version:1,purpose:r.purpose==='preview-fixture-pause'?'post-runtime-fixture':r.purpose,definitionHash:nonrootHash(observation)}};
    inspectPostRuntimeRoute(selected,route);validatePostRuntimeDefinition(observation.taskDefinition,selected,observation);
    return {purpose:r.purpose,taskDefinitionArn:selected.taskDefinitionArn,definitionHash:selected.launch.definitionHash};
  });
  return inspectPostRuntimePurposeMap({version:1,kind:'post-runtime-preview-purpose-map',route,bindings},route);
}

export function postRuntimeOperatorEnvironment(route){
  const purpose=route.version===2?route.launch?.purpose:undefined;
  const operation=purpose?.startsWith('preview-fixture-')?'consolidation-preview-'+purpose.slice('preview-fixture-'.length):'consolidation-preview-pause';
  return {AWS_REGION:route.region,MEM9_STAGE:route.stage,MEM9_DB_HOST:route.host,MEM9_DB_PORT:String(route.port),MEM9_DB_NAME:route.database,
    MEM9_PREVIEW_GENERATION:route.generation,MEM9_BOOTSTRAP_OPERATION:operation,MEM9_PRODUCTION_RUNTIME_MODE:'active',
    MEM9_PREVIEW_ACCEPTANCE_CONTEXT:'post-runtime',MEM9_PREVIEW_RUNTIME_NONCE:route.context.runtimeNonce};
}

export function validatePostRuntimeDefinition(definition,route,observation){
  if(route.version===2){
    const observed=copyNonrootJson(observation);
    if(!exact(observed,['taskDefinition','tags'])||nonrootHash(observed)!==route.launch.definitionHash||
      nonrootHash(observed.taskDefinition)!==nonrootHash(definition))fail();
  }
  if(definition?.taskDefinitionArn!==route.taskDefinitionArn||definition.networkMode!=='awsvpc'||!sameSet(definition.requiresCompatibilities,['FARGATE'])||
    definition.runtimePlatform?.cpuArchitecture!=='ARM64'||definition.runtimePlatform.operatingSystemFamily!=='LINUX'||
    definition.cpu!=='256'||definition.memory!=='512'||definition.taskRoleArn!==route.taskRoleArn||definition.executionRoleArn!==route.executionRoleArn||
    definition.volumes?.length||definition.pidMode||definition.ipcMode||definition.containerDefinitions?.length!==1)fail();
  const c=definition.containerDefinitions[0];
  const entry=route.version===2?['/bin/setpriv','--no-new-privs','--','/usr/local/bin/node','/bootstrap/nonroot-dispatch.mjs',route.launch.purpose]:['node'];
  const command=route.version===2?[]:['/bootstrap/operator/scripts/consolidation-preview-fixture.mjs'];
  if(c.name!==POST_RUNTIME_OPERATOR||c.image!==route.image||!equal(c.entryPoint,entry)||
    !equal(c.command,command)||c.user!==(route.version===2?'1000:1000':'node')||c.readonlyRootFilesystem!==true||
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
