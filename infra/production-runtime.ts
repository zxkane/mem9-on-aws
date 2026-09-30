import type {RuntimeCredentials} from "./runtime-credentials";
import type {TenantIdentityOutputs} from "./tenant-identity";
import type {NamespaceIdentityOutputs,MaintenanceIdentityOutputs} from "./namespace-identity";
import {accountId,applicationRegion} from "./ecr";
import {workloadImage} from "./ecr";
import type {EcsOutputs} from "./ecs";
import type {DbOutputs} from "./db";
import {resolveVpc} from "./vpc";
import {runtimeRoleName,runtimePreviewStage} from "../scripts/lib/runtime-credentials.mjs";
import {schemaAdministratorRole} from "../scripts/lib/production-runtime-config.mjs";

export interface ProductionRuntimeResources {
  mode:"prepare"|"paused"|"ready"|"active";
  active:boolean;
  runtime:RuntimeCredentials;
  administratorArn:Output<string>;
  administratorBackupArn:Output<string>;
  transitionArn:Output<string>;
  executionRoleArn:Output<string>;
  bootstrapExecutionRoleArn:Output<string>;
}

export function productionFallbackImages():Record<string,string>{
  let images:Record<string,string>;
  try{images=JSON.parse(process.env.MEM9_RUNTIME_FALLBACK_IMAGES??"");}catch{throw Error("RuntimeFallbackDigestRequired");}
  if(!images||Object.keys(images).sort().join()!==["mnemo-server","qwen3-embed","llm-proxy"].sort().join()||
    Object.values(images).some(image=>typeof image!=="string"||!/@sha256:[a-f0-9]{64}$/.test(image)))throw Error("RuntimeFallbackDigestRequired");
  return images;
}

export function runtimeExecutionPolicy(parameters:Input<string>[],secrets:Input<string>[]){
  const region=applicationRegion();
  return {Version:"2012-10-17",Statement:[
    ...(parameters.length?[
      {Effect:"Allow",Action:["ssm:GetParameters"],Resource:parameters},
      {Effect:"Allow",Action:["kms:Decrypt"],Resource:"*",Condition:{StringEquals:{
        "kms:ViaService":$interpolate`ssm.${region}.amazonaws.com`,"kms:EncryptionContext:PARAMETER_ARN":parameters}}},
    ]:[]),
    ...(secrets.length?[
      {Effect:"Allow",Action:["secretsmanager:GetSecretValue"],Resource:secrets},
      {Effect:"Allow",Action:["kms:Decrypt"],Resource:"*",Condition:{StringEquals:{
        "kms:ViaService":$interpolate`secretsmanager.${region}.amazonaws.com`,"kms:EncryptionContext:SecretARN":secrets}}},
    ]:[]),
  ]};
}

export function runtimeTaskTrust(){
  return {Version:"2012-10-17",Statement:[{Effect:"Allow",Action:"sts:AssumeRole",Principal:{Service:"ecs-tasks.amazonaws.com"},
    Condition:{StringEquals:{"aws:SourceAccount":accountId()},ArnLike:{"aws:SourceArn":$interpolate`arn:aws:ecs:${applicationRegion()}:${accountId()}:*`}}}]};
}

export function productionRuntimeEnabled(){return (process.env.MEM9_PRODUCTION_RUNTIME_MODE??"off")!=="off";}

/** Old execution/task identities never gain the replacement administrative keys. */
export function protectLegacyRuntimeCredentials(args:Record<string,unknown>,allowPreviewRuntime=false){
  if(!productionRuntimeEnabled())return;
  args.assumeRolePolicy=$jsonStringify(runtimeTaskTrust());
  const retired=process.env.MEM9_PRODUCTION_RUNTIME_MODE!=="prepare";
  const prefix=$interpolate`arn:aws:ssm:${applicationRegion()}:${accountId()}:parameter/mem9-on-aws/${$app.stage}/runtime/`;
  const suffixes=['schema-administrator-credential','schema-administrator-backup','transition-credential',
    ...($app.stage==='prod'||!allowPreviewRuntime?['database-credential']:[])];
  const paths=suffixes.map(suffix=>$interpolate`${prefix}${suffix}`);
  const policy=$jsonStringify({Version:"2012-10-17",Statement:retired?[{
    Effect:"Deny",Action:["ssm:GetParameter","ssm:GetParameters","ssm:GetParameterHistory","ssm:GetParametersByPath","secretsmanager:GetSecretValue","kms:Decrypt"],Resource:"*"},
  ]:[
    {Effect:"Deny",Action:["ssm:GetParameter","ssm:GetParameters","ssm:GetParameterHistory"],Resource:paths},
    {Effect:"Deny",Action:["ssm:GetParametersByPath"],Resource:"*"},
    {Effect:"Deny",Action:["kms:Decrypt"],Resource:"*",Condition:{StringEquals:{"kms:EncryptionContext:PARAMETER_ARN":paths}}},
  ]});
  type Inline={name:Input<string>;policy:Input<string>};
  const append=(policies:Inline[]|undefined)=>[...(policies??[]),{name:"ProductionCredentialFence",policy}];
  const prior=args.inlinePolicies;
  if(prior===undefined||Array.isArray(prior))args.inlinePolicies=append(prior as Inline[]|undefined);
  else if(prior&&typeof (prior as Output<Inline[]>).apply==='function')args.inlinePolicies=(prior as Output<Inline[]>).apply(append);
  else throw Error("UnsupportedLegacyRolePolicies");
}

/** Preparation creates dormant credentials and a new execution identity. */
export function productionRuntimeResources(existing:RuntimeCredentials|undefined,identity:TenantIdentityOutputs,
  namespace:NamespaceIdentityOutputs,maintenance:MaintenanceIdentityOutputs):ProductionRuntimeResources|undefined {
  const stage=$app.stage;
  const selected=process.env.MEM9_PRODUCTION_RUNTIME_MODE??"off";
  if(!["off","prepare","paused","ready","active"].includes(selected))throw Error("InvalidProductionRuntimeMode");
  if(selected==="off")return;
  if(stage!=="prod"&&!runtimePreviewStage(stage))throw Error("InvalidProductionRuntimeStage");
  if(process.env.MEM9_NAMESPACE_REQUIRED!=="1")throw Error("ProductionRuntimeRequiresNamespaces");
  productionFallbackImages();
  const mode=selected as "prepare"|"paused"|"ready"|"active",prefix=`/mem9-on-aws/${stage}/runtime`;
  const tags={Project:"mem9-on-aws",Stage:stage,ManagedBy:"sst"};
  const parameter=(name:string,path:string,value:Input<string>)=>new aws.ssm.Parameter(name,{name:prefix+"/"+path,type:"SecureString",value,tags});
  let runtime=existing;
  if(!runtime){
    const password=new random.RandomPassword("RuntimeDatabasePassword",{length:48,special:false});
    const salt=new random.RandomPassword("RuntimeDatabaseSalt",{length:32,special:false});
    const value=parameter("RuntimeDatabaseCredential","database-credential",$jsonStringify({username:runtimeRoleName(stage),password:password.result,salt:salt.result}));
    runtime={parameterArn:value.arn,ready:false};
  }
  const adminPassword=new random.RandomPassword("SchemaAdministratorPassword",{length:48,special:false});
  const adminSalt=new random.RandomPassword("SchemaAdministratorSalt",{length:32,special:false});
  const adminValue=$jsonStringify({username:schemaAdministratorRole(stage),password:adminPassword.result,salt:adminSalt.result});
  const admin=parameter("SchemaAdministratorCredential","schema-administrator-credential",adminValue);
  // Recovery can restore the same credential without reviving the retired
  // master. Only the trusted operator reads this backup; no task receives it.
  const backup=parameter("SchemaAdministratorBackup","schema-administrator-backup",adminValue);
  const transitionPassword=new random.RandomPassword("TransitionDatabasePassword",{length:48,special:false});
  const transitionSalt=new random.RandomPassword("TransitionDatabaseSalt",{length:32,special:false});
  const transition=parameter("TransitionDatabaseCredential","transition-credential",$jsonStringify({password:transitionPassword.result,salt:transitionSalt.result}));
  const execution=new aws.iam.Role("RuntimeMem9ServerExecutionRole",{
    assumeRolePolicy:$jsonStringify(runtimeTaskTrust()),
    managedPolicyArns:["arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"],
    inlinePolicies:[{name:"RuntimeSecrets",policy:$jsonStringify(runtimeExecutionPolicy(
      [runtime.parameterArn,namespace.transportSigningParameterArn,maintenance.bundleParameterArn],[identity.tenantSecretArn]))}],tags,
  });
  const bootstrapExecution=new aws.iam.Role("SchemaMem9BootstrapExecutionRole",{
    assumeRolePolicy:$jsonStringify(runtimeTaskTrust()),
    managedPolicyArns:["arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"],
    inlinePolicies:[{name:"SchemaSecrets",policy:$jsonStringify(runtimeExecutionPolicy(
      [admin.arn,runtime.parameterArn],[identity.tenantSecretArn]))}],tags,
  });
  return {mode,active:mode!=="prepare",runtime:{...runtime,ready:mode==="ready"||mode==="active",executionRoleArn:execution.arn},
    administratorArn:admin.arn,administratorBackupArn:backup.arn,transitionArn:transition.arn,executionRoleArn:execution.arn,
    bootstrapExecutionRoleArn:bootstrapExecution.arn};
}

export function productionRuntimeTasks(ecs:EcsOutputs,db:DbOutputs,identity:TenantIdentityOutputs,config:ProductionRuntimeResources){
  if(!ecs.serverTaskDefinition)throw Error("RuntimeDefinitionMissing");
  const source=ecs.serverTaskDefinition,stage=$app.stage,tags={Project:"mem9-on-aws",Stage:stage,ManagedBy:"sst"};
  const fallbackImages=productionFallbackImages();
  const fallbackImage=fallbackImages["mnemo-server"];
  const containers=source.apply(definition=>definition.containerDefinitions.apply(raw=>{
    const list=JSON.parse(raw) as Array<{name:string;image:string;environment?:Array<{name:string;value:string}>;
      secrets?:Array<{name:string;valueFrom:string}>;mountPoints?:unknown[]}>;
    const server=list.find(c=>c.name==="mnemo-server");
    if(!server||list.some(c=>c.mountPoints?.length)||server.environment?.some(e=>["MNEMO_DSN","MEM9_DB_SECRET"].includes(e.name)))throw Error("UnsupportedRuntimeFallback");
    if(list.length!==3)throw Error("UnsupportedRuntimeFallback");
    for(const container of list){
      const repository=container.image.split("@")[0].replace(/:[^/]+$/,"");
      if(!fallbackImages[container.name]?.startsWith(repository+"@sha256:"))throw Error("RuntimeFallbackRepositoryMismatch");
      container.image=fallbackImages[container.name];
    }
    const previous=server.secrets?.find(s=>s.name==="MEM9_DB_SECRET");
    if(!previous)throw Error("RuntimeFallbackCredentialMissing");
    const env=Object.fromEntries((server.environment??[]).map(e=>[e.name,e.value]));
    Object.assign(env,{MEM9_STAGE:stage,MNEMO_SCHEMA_MODE:"verify",MNEMO_NAMESPACE_REQUIRED:"1",MNEMO_CONSOLIDATION_EXECUTION_ENABLED:"false"});
    server.environment=Object.entries(env).sort(([a],[b])=>a.localeCompare(b)).map(([name,value])=>({name,value}));server.image=fallbackImage;
    return config.runtime.parameterArn.apply(arn=>{previous.valueFrom=arn;server.secrets?.sort((a,b)=>a.name.localeCompare(b.name));return JSON.stringify(list);});
  }));
  const fallback=new aws.ecs.TaskDefinition("ProductionRuntimeFallback",{
    family:$interpolate`${ecs.clusterName}-Mem9RuntimeServer`,networkMode:"awsvpc",requiresCompatibilities:["FARGATE"],
    cpu:source.apply(d=>d.cpu),memory:source.apply(d=>d.memory),runtimePlatform:{cpuArchitecture:"ARM64",operatingSystemFamily:"LINUX"},
    taskRoleArn:source.apply(d=>d.taskRoleArn),executionRoleArn:config.executionRoleArn,containerDefinitions:containers,
    skipDestroy:true,tags,
  });
  const active=config.mode==="active";
  const references:Record<string,Output<string>>=active?{}:{MEM9_DB_SECRET:db.secretArn,
    MEM9_SCHEMA_ADMIN_CREDENTIAL:config.administratorArn,MEM9_RUNTIME_DB_SECRET:config.runtime.parameterArn,
    MEM9_TRANSITION_CREDENTIAL:config.transitionArn,MEM9_TENANT_ID:identity.tenantSecretArn};
  const transition=new sst.aws.Task("TransitionMem9Bootstrap",{
    cluster:ecs.cluster,architecture:"arm64",cpu:"0.5 vCPU",memory:"1 GB",
    image:workloadImage("bootstrap",process.env.MEM9_IMAGE_TAG||"latest"),entrypoint:["node"],
    command:["/bootstrap/operator/scripts/production-runtime-operator.mjs"],
    environment:{MEM9_STAGE:stage,MEM9_DB_HOST:db.host,MEM9_DB_PORT:db.port.apply(String),MEM9_DB_NAME:db.database,
      MEM9_RUNTIME_OPERATOR_VERSION:"1",MEM9_RUNTIME_OPERATOR_RETIRED:active?"1":"0"},ssm:references,permissions:[],logging:{retention:"1 month"},
    transform:{taskDefinition:args=>{args.tags={...(args.tags??{}),...tags};},taskRole:args=>{args.assumeRolePolicy=$jsonStringify(runtimeTaskTrust());},
      executionRole:args=>{
        args.assumeRolePolicy=$jsonStringify(runtimeTaskTrust());
        args.inlinePolicies=[{name:"TransitionSecrets",policy:active?JSON.stringify({Version:"2012-10-17",Statement:[{
          Effect:"Deny",Action:["ssm:GetParameter","ssm:GetParameters","ssm:GetParametersByPath","secretsmanager:GetSecretValue","kms:Decrypt"],Resource:"*"}]}):
          $jsonStringify(runtimeExecutionPolicy([config.administratorArn,config.runtime.parameterArn,config.transitionArn],[db.secretArn,identity.tenantSecretArn]))}];
      }},
  });
  const manifest=new aws.ssm.Parameter("ProductionRuntimeManifest",{
    name:`/mem9-on-aws/${stage}/runtime/production-manifest`,type:"SecureString",tags,
    value:$jsonStringify({version:1,stage,mode:config.mode,region:applicationRegion(),account:accountId(),
      cluster:ecs.clusterName,clusterArn:ecs.cluster.nodes.cluster.arn,service:ecs.serviceName,
      subnets:resolveVpc().privateSubnetIds,securityGroup:db.taskSecurityGroupId,host:db.host,port:db.port,database:db.database,
      originalOwnerSecret:db.secretArn,administratorCredential:config.administratorArn,administratorBackup:config.administratorBackupArn,
      transitionCredential:config.transitionArn,runtimeCredential:config.runtime.parameterArn,tenantSecret:identity.tenantSecretArn,
      runtimeExecutionRole:config.executionRoleArn,bootstrapExecutionRole:config.bootstrapExecutionRoleArn,
      fallbackTaskDefinition:fallback.arn,fallbackImage,fallbackImages,
      transitionTaskDefinition:transition.taskDefinition,transitionContainer:"TransitionMem9Bootstrap"}),
  });
  return {fallback,transition,manifest};
}
