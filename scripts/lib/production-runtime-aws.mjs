import {GetParametersCommand} from '@aws-sdk/client-ssm';
import {DescribeServicesCommand,DescribeTaskDefinitionCommand,ListTasksCommand,DescribeTasksCommand,ListTaskDefinitionsCommand,
  UpdateServiceCommand,StopTaskCommand} from '@aws-sdk/client-ecs';
import {ListClustersCommand} from '@aws-sdk/client-ecs';
import {GetRoleCommand,PutRolePolicyCommand,GetRolePolicyCommand,SimulateCustomPolicyCommand,ListRolesCommand,
  ListRolePoliciesCommand,ListAttachedRolePoliciesCommand,GetPolicyCommand,GetPolicyVersionCommand} from '@aws-sdk/client-iam';
import {setTimeout as delay} from 'node:timers/promises';
import {createHash} from 'node:crypto';
import {rolloutStage} from './production-runtime-config.mjs';
import {expectedRoleBoundaryArn,verifyGatewayBoundaryPolicyDocument} from './workload-permissions-boundary.mjs';

const send=(client,command)=>client.send(command,{abortSignal:AbortSignal.timeout(30000)});
const fail=code=>{throw Error(code);};
const env=container=>Object.fromEntries((container?.environment??[]).map(e=>[e.name,e.value]));
function decode(value){if(typeof value==='object')return value;try{return JSON.parse(value);}catch{return JSON.parse(decodeURIComponent(value));}}

// Remove only statements whose Action/NotAction cannot apply. Preserve every
// resource, condition and effect for IAM to evaluate; unrelated condition keys
// must not turn a role with no credential grant into an ambiguous reader.
export function policyForAction(document,action){
  const statements=Array.isArray(document.Statement)?document.Statement:[document.Statement];
  const Statement=statements.filter(statement=>{
    if(!statement||!['Allow','Deny'].includes(statement.Effect)||
      Object.hasOwn(statement,'Action')===Object.hasOwn(statement,'NotAction'))fail('InvalidCredentialReaderPolicy');
    const inverse=Object.hasOwn(statement,'NotAction'),raw=inverse?statement.NotAction:statement.Action;
    const patterns=Array.isArray(raw)?raw:[raw];
    if(!patterns.length||patterns.some(p=>typeof p!=='string'||!p.length))fail('InvalidCredentialReaderPolicy');
    const matches=patterns.some(p=>new RegExp('^'+p.split('*').map(part=>part.split('?').map(RegExp.escape).join('.')).join('.*')+'$','i').test(action));
    return inverse?!matches:matches;
  });
  return Statement.length?{...document,Statement}:null;
}

export function simulationDecisions(result,actions,resources){
  if(result.IsTruncated||!result.EvaluationResults?.length)fail('CredentialReaderSimulationIncomplete');
  const found=new Map();
  for(const row of result.EvaluationResults){
    if(!actions.includes(row.EvalActionName))fail('CredentialReaderSimulationIncomplete');
    const entries=row.ResourceSpecificResults?.length?row.ResourceSpecificResults:
      [{EvalResourceName:row.EvalResourceName,EvalResourceDecision:row.EvalDecision,MissingContextValues:row.MissingContextValues}];
    for(const entry of entries){
      const key=row.EvalActionName+'\0'+entry.EvalResourceName;
      if(!resources.includes(entry.EvalResourceName)||!['allowed','explicitDeny','implicitDeny'].includes(entry.EvalResourceDecision))fail('CredentialReaderSimulationIncomplete');
      const value={decision:entry.EvalResourceDecision,missing:entry.MissingContextValues??[]};
      // Older responses repeated aggregate rows. Identical per-resource
      // evidence is harmless; contradictory or missing evidence fails closed.
      if(found.has(key)&&JSON.stringify(found.get(key))!==JSON.stringify(value))fail('CredentialReaderSimulationIncomplete');
      found.set(key,value);
    }
  }
  if(found.size!==actions.length*resources.length)fail('CredentialReaderSimulationIncomplete');
  return [...found.values()];
}

export function compactWriterInventory(inventory){
  const {definitions,...rest}=inventory;
  if(!Array.isArray(definitions)||!definitions.length)fail('LegacyWriterInventoryMissing');
  return {...rest,definitionCount:definitions.length,
    definitionDigest:createHash('sha256').update(JSON.stringify([...definitions].sort())).digest('hex')};
}

export async function serviceTasks(clients,meta){
  const arns=[];let nextToken;
  for(let page=0;page<100;page++){
    const result=await send(clients.ecs,new ListTasksCommand({cluster:meta.clusterArn,serviceName:'Mem9Server',desiredStatus:'RUNNING',nextToken,maxResults:100}));
    arns.push(...(result.taskArns??[]));if(!result.nextToken)break;
    if(result.nextToken===nextToken||page===99)fail('ServiceTaskInventoryIncomplete');nextToken=result.nextToken;
  }
  if(!arns.length)return [];
  const result=await send(clients.ecs,new DescribeTasksCommand({cluster:meta.clusterArn,tasks:arns}));
  if(result.failures?.length||result.tasks?.length!==arns.length)fail('ServiceTaskObservationFailed');return result.tasks;
}

export async function captureProductionService(clients,{stage,region,account}){
  if(!rolloutStage(stage))fail('InvalidRolloutStage');
  const prefix=`/mem9-on-aws/${stage}`,keys=['bootstrap/cluster-name','ecs/service-name','db/secret-arn','db/host','db/name'];
  const response=await send(clients.ssm,new GetParametersCommand({Names:keys.map(k=>prefix+'/'+k),WithDecryption:false}));
  if(response.InvalidParameters?.length||response.Parameters?.length!==keys.length)fail('ProductionSourceMetadataMissing');
  const values=Object.fromEntries(response.Parameters.map(p=>[p.Name.slice(prefix.length+1),p.Value]));
  const cluster=values['bootstrap/cluster-name'];
  if(!cluster?.startsWith(`mem9-on-aws-${stage}-`)||values['ecs/service-name']!=='Mem9Server')fail('ProductionSourceMismatch');
  const meta={stage,region,account,cluster,clusterArn:`arn:aws:ecs:${region}:${account}:cluster/${cluster}`,
    originalOwnerSecret:values['db/secret-arn'],host:values['db/host'],database:values['db/name']};
  const services=await send(clients.ecs,new DescribeServicesCommand({cluster:meta.clusterArn,services:['Mem9Server']}));
  const service=services.services?.[0];
  if(services.failures?.length||service?.desiredCount!==1||service.runningCount!==1||service.pendingCount||
    service.deployments?.length!==1||service.deployments[0].rolloutState!=='COMPLETED')fail('ProductionSourceNotStable');
  const tasks=await serviceTasks(clients,meta);
  if(tasks.length!==1||tasks[0].lastStatus!=='RUNNING'||tasks[0].taskDefinitionArn!==service.taskDefinition)fail('ProductionSourceNotStable');
  const definition=(await send(clients.ecs,new DescribeTaskDefinitionCommand({taskDefinition:service.taskDefinition}))).taskDefinition;
  const server=definition.containerDefinitions.find(c=>c.name==='mnemo-server'),environment=env(server);
  if(environment.MEM9_DB_HOST!==meta.host||environment.MEM9_DB_NAME!==meta.database||environment.MNEMO_NAMESPACE_REQUIRED!=='1')fail('ProductionSourceConfigurationMismatch');
  const fallbackImages={};
  for(const name of ['mnemo-server','qwen3-embed','llm-proxy']){
    const declared=definition.containerDefinitions.find(c=>c.name===name),live=tasks[0].containers?.find(c=>c.name===name);
    if(!declared?.image?.startsWith(`${account}.dkr.ecr.${region}.amazonaws.com/`)||!/^sha256:[a-f0-9]{64}$/.test(live?.imageDigest??''))fail('ProductionImageDigestMissing');
    fallbackImages[name]=declared.image.split('@')[0].replace(/:[^/]+$/,'')+'@'+live.imageDigest;
  }
  return {...meta,originalTaskDefinition:service.taskDefinition,fallbackImages,definition};
}

export async function inventoryLegacyRoles(clients,meta){
  const definitions=[],roles=new Set(),families=new Set();
  for(const status of ['ACTIVE','INACTIVE']){
    let nextToken;
    for(let page=0;page<100;page++){
      // ListTaskDefinitions.familyPrefix requires a complete family name; it is
      // not a textual prefix filter. Enumerate and filter ARN metadata before
      // describing any stage-owned definition.
      const result=await send(clients.ecs,new ListTaskDefinitionsCommand({status,maxResults:100,nextToken}));
      for(const arn of result.taskDefinitionArns??[]){
        if(!arn.startsWith(`arn:aws:ecs:${meta.region}:${meta.account}:task-definition/mem9-on-aws-${meta.stage}-`))continue;
        if(definitions.length>=2000)fail('LegacyDefinitionInventoryTooLarge');
        const d=(await send(clients.ecs,new DescribeTaskDefinitionCommand({taskDefinition:arn}))).taskDefinition;
        if(d.family.endsWith('-TransitionMem9Bootstrap')||d.family.endsWith('-Mem9RuntimeServer'))continue;
        const legacy=d.containerDefinitions?.some(c=>c.secrets?.some(s=>s.valueFrom===meta.originalOwnerSecret)||
          (env(c).MEM9_DB_HOST===meta.host&&env(c).MEM9_DB_NAME===meta.database));
        // The existing preview service is already restricted; its prior execution
        // identity is still part of the credential handoff rehearsal.
        const oldService=d.taskDefinitionArn===meta.originalTaskDefinition;
        if(!legacy&&!oldService)continue;
        definitions.push(d.taskDefinitionArn);families.add(d.family);
        for(const key of ['taskRoleArn','executionRoleArn'])if(d[key])roles.add(d[key]);
      }
      if(!result.nextToken)break;if(result.nextToken===nextToken||page===99)fail('LegacyDefinitionInventoryIncomplete');nextToken=result.nextToken;
    }
  }
  if(!roles.size||!families.size)fail('LegacyWriterInventoryMissing');
  const clusters=[];let token;
  for(let page=0;page<100;page++){
    const result=await send(clients.ecs,new ListClustersCommand({maxResults:100,nextToken:token}));
    clusters.push(...(result.clusterArns??[]).filter(arn=>arn.startsWith(`arn:aws:ecs:${meta.region}:${meta.account}:cluster/mem9-on-aws-${meta.stage}-`)));
    if(!result.nextToken)break;if(result.nextToken===token||page===99)fail('LegacyClusterInventoryIncomplete');token=result.nextToken;
  }
  if(!clusters.includes(meta.clusterArn))fail('CurrentClusterMissing');
  return {definitions,roles:[...roles].sort(),families:[...families].sort(),clusters};
}

export async function fenceLegacyRoles(clients,meta,inventory,{retired=false}={}){
  const prefix=`arn:aws:ssm:${meta.region}:${meta.account}:parameter/mem9-on-aws/${meta.stage}/runtime/`;
  const paths=['schema-administrator-credential','schema-administrator-backup','transition-credential',...(meta.stage==='prod'?['database-credential']:[])].map(s=>prefix+s);
  const policy={Version:'2012-10-17',Statement:retired?[{Effect:'Deny',Action:['ssm:GetParameter','ssm:GetParameters','ssm:GetParameterHistory','ssm:GetParametersByPath','secretsmanager:GetSecretValue','kms:Decrypt'],Resource:'*'}]:[
    {Effect:'Deny',Action:['ssm:GetParameter','ssm:GetParameters','ssm:GetParameterHistory'],Resource:paths},
    {Effect:'Deny',Action:['ssm:GetParametersByPath'],Resource:'*'},
    {Effect:'Deny',Action:['kms:Decrypt'],Resource:'*',Condition:{StringEquals:{'kms:EncryptionContext:PARAMETER_ARN':paths}}},
  ]};
  for(const arn of inventory.roles){
    const name=arn.split('/').at(-1);
    if(!arn.startsWith(`arn:aws:iam::${meta.account}:role/`)||!/^mem9-on-a(?:ws|w)?-/.test(name)||!name.includes('-'+meta.stage+'-'))fail('LegacyRoleScopeMismatch');
    let role;try{role=(await send(clients.iam,new GetRoleCommand({RoleName:name}))).Role;}catch(error){if(error.name==='NoSuchEntityException')continue;throw error;}
    if(role.PermissionsBoundary?.PermissionsBoundaryArn!==`arn:aws:iam::${meta.account}:policy/mem9-on-aws-workload-boundary`)fail('LegacyRoleBoundaryMismatch');
    const trust=decode(role.AssumeRolePolicyDocument);
    if(!Array.isArray(trust.Statement)||trust.Statement.some(s=>s.Effect!=='Allow'||s.Principal?.AWS||s.Principal?.Federated||
      JSON.stringify(Array.isArray(s.Principal?.Service)?s.Principal.Service:[s.Principal?.Service])!==JSON.stringify(['ecs-tasks.amazonaws.com'])))fail('LegacyRoleTrustMismatch');
    await send(clients.iam,new PutRolePolicyCommand({RoleName:name,PolicyName:'ProductionCredentialFence',PolicyDocument:JSON.stringify(policy)}));
    const actual=decode((await send(clients.iam,new GetRolePolicyCommand({RoleName:name,PolicyName:'ProductionCredentialFence'}))).PolicyDocument);
    if(JSON.stringify(actual)!==JSON.stringify(policy))fail('LegacyFenceReadbackMismatch');
    // Read-back proves attachment. A custom simulation proves the attached
    // explicit deny, which no other allow or permissions boundary can override.
    const simulation=await send(clients.iam,new SimulateCustomPolicyCommand({PolicyInputList:[JSON.stringify(actual)],
      ActionNames:['ssm:GetParameter','ssm:GetParameters','ssm:GetParameterHistory'],ResourceArns:paths,
      ContextEntries:[{ContextKeyName:'aws:RequestedRegion',ContextKeyType:'string',ContextKeyValues:[meta.region]},
        {ContextKeyName:'aws:PrincipalArn',ContextKeyType:'string',ContextKeyValues:[arn]}]}));
    if(simulationDecisions(simulation,['ssm:GetParameter','ssm:GetParameters','ssm:GetParameterHistory'],paths).some(r=>r.decision!=='explicitDeny'))fail('LegacyFenceSimulationFailed');
  }
}

export async function auditAdditionalCredentialReaders(clients,meta,inventory){
  const boundaryArn=`arn:aws:iam::${meta.account}:policy/mem9-on-aws-workload-boundary`;
  const boundary=(await send(clients.iam,new GetPolicyCommand({PolicyArn:boundaryArn}))).Policy;
  const version=(await send(clients.iam,new GetPolicyVersionCommand({PolicyArn:boundaryArn,VersionId:boundary.DefaultVersionId}))).PolicyVersion;
  const boundaryDocument=decode(version.Document),known=new Set(inventory.roles),roles=[];
  const boundaryStates=new Map([[boundaryArn,{document:boundaryDocument,version:boundary.DefaultVersionId}]]);
  let Marker;
  for(let page=0;page<100;page++){
    const result=await send(clients.iam,new ListRolesCommand({MaxItems:100,Marker}));
    roles.push(...(result.Roles??[]).filter(r=>/^mem9-on-a(?:ws|w)?-/.test(r.RoleName)&&r.RoleName.includes('-'+meta.stage+'-')));
    if(!result.IsTruncated)break;if(!result.Marker||result.Marker===Marker||page===99)fail('RoleInventoryIncomplete');Marker=result.Marker;
  }
  const harmless=new Set(['arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy',
    'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole','arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole',
    'arn:aws:iam::aws:policy/AWSXRayDaemonWriteAccess']);
  const resources=['schema-administrator-credential','schema-administrator-backup','transition-credential',...(meta.stage==='prod'?['database-credential']:[])].map(suffix=>
    `arn:aws:ssm:${meta.region}:${meta.account}:parameter/mem9-on-aws/${meta.stage}/runtime/${suffix}`);
  for(const role of roles){
    if(known.has(role.Arn))continue;
    // This audit runs before creating the new consumers. A role name alone is
    // never authority to exclude an existing principal from discovery.
    const full=(await send(clients.iam,new GetRoleCommand({RoleName:role.RoleName}))).Role;
    const selectedBoundary=expectedRoleBoundaryArn(role.RoleName,{partition:'aws',accountId:meta.account});
    if(full.PermissionsBoundary?.PermissionsBoundaryArn!==selectedBoundary)fail('CredentialReaderBoundaryMismatch');
    if(selectedBoundary!==boundaryArn && (!Array.isArray(full.Tags)||new Set(full.Tags.map(t=>t.Key)).size!==full.Tags.length||
      full.Tags.find(t=>t.Key==='Project')?.Value!=='mem9-on-aws'||full.Tags.find(t=>t.Key==='Stage')?.Value!==meta.stage))fail('CredentialReaderBoundaryMismatch');
    if(!boundaryStates.has(selectedBoundary)){
      const metadata=(await send(clients.iam,new GetPolicyCommand({PolicyArn:selectedBoundary}))).Policy;
      const current=(await send(clients.iam,new GetPolicyVersionCommand({PolicyArn:selectedBoundary,VersionId:metadata.DefaultVersionId}))).PolicyVersion;
      const document=decode(current.Document),revision=document.Statement?.find(s=>typeof s.Sid==='string'&&/^Gr[0-9]+$/.test(s.Sid))?.Sid.slice(1);
      if(!verifyGatewayBoundaryPolicyDocument(document,{partition:'aws',accountId:meta.account,applicationRegion:meta.region,policyRevision:revision}))fail('CredentialReaderBoundaryMismatch');
      boundaryStates.set(selectedBoundary,{document,version:metadata.DefaultVersionId});
    }
    const policies=[],attached=[];
    for(const [Command,key,destination] of [[ListRolePoliciesCommand,'PolicyNames',policies],[ListAttachedRolePoliciesCommand,'AttachedPolicies',attached]]){
      let marker;
      for(let page=0;page<50;page++){
        const result=await send(clients.iam,new Command({RoleName:role.RoleName,Marker:marker,MaxItems:100}));destination.push(...(result[key]??[]));
        if(!result.IsTruncated)break;if(!result.Marker||result.Marker===marker||page===49)fail('RolePolicyInventoryIncomplete');marker=result.Marker;
      }
    }
    if(attached.some(p=>!harmless.has(p.PolicyArn)))fail('UnreviewedCredentialReaderPolicy');
    if(!policies.length)continue;
    const documents=[];
    for(const PolicyName of policies)documents.push(decode((await send(clients.iam,new GetRolePolicyCommand({RoleName:role.RoleName,PolicyName}))).PolicyDocument));
    for(const action of ['ssm:GetParameter','ssm:GetParameters','ssm:GetParameterHistory','ssm:GetParametersByPath']){
    const applicable=documents.map(document=>policyForAction(document,action)).filter(Boolean);
    if(!applicable.some(document=>document.Statement.some(s=>s.Effect==='Allow')))continue;
    const input={PolicyInputList:applicable.map(document=>JSON.stringify(document)),ActionNames:[action],ResourceArns:resources,
      ContextEntries:[{ContextKeyName:'aws:RequestedRegion',ContextKeyType:'string',ContextKeyValues:[meta.region]},
        {ContextKeyName:'aws:PrincipalArn',ContextKeyType:'string',ContextKeyValues:[role.Arn]},
        ...(full.Tags??[]).filter(t=>['Project','Stage'].includes(t.Key)).map(t=>({ContextKeyName:'aws:PrincipalTag/'+t.Key,ContextKeyType:'string',ContextKeyValues:[t.Value]}))]};
    const identity=await send(clients.iam,new SimulateCustomPolicyCommand(input));
    // A boundary cannot add an identity allow. Avoid manufacturing ambiguity
    // from its unrelated KMS/Lambda condition keys for roles with no SSM grant.
    if(simulationDecisions(identity,[action],resources).every(r=>r.decision==='explicitDeny'||(r.decision==='implicitDeny'&&!r.missing.length)))continue;
    const scopedBoundary=policyForAction(boundaryStates.get(selectedBoundary).document,action);
    // A boundary with no applicable allow cannot add permission.
    if(!scopedBoundary?.Statement.some(s=>s.Effect==='Allow'))continue;
    const result=await send(clients.iam,new SimulateCustomPolicyCommand({...input,PermissionsBoundaryPolicyInputList:[JSON.stringify(scopedBoundary)]}));
    if(simulationDecisions(result,[action],resources).some(r=>
      r.decision==='allowed'||(r.decision!=='explicitDeny'&&r.missing.length)))fail('UninventoriedCredentialReader');
    }
  }
  for(const [arn,state]of boundaryStates)if((await send(clients.iam,new GetPolicyCommand({PolicyArn:arn}))).Policy.DefaultVersionId!==state.version)fail('CredentialBoundaryChanged');
}

export async function stopLegacyWriters(clients,meta,inventory,{deadline=Date.now()+600000,sleep=delay}={}){
  await send(clients.ecs,new UpdateServiceCommand({cluster:meta.clusterArn,service:'Mem9Server',desiredCount:0,deploymentConfiguration:{deploymentCircuitBreaker:{enable:true,rollback:false}}}));
  let quiet=0;
  while(Date.now()<deadline){
    const arns=new Set();
    const taskClusters=new Map();
    for(const cluster of inventory.clusters??[meta.clusterArn])for(const desiredStatus of ['RUNNING','STOPPED']){
      let nextToken;
      for(let page=0;page<100;page++){
        const result=await send(clients.ecs,new ListTasksCommand({cluster,desiredStatus,maxResults:100,nextToken}));
        for(const arn of result.taskArns??[]){arns.add(arn);taskClusters.set(arn,cluster);}
        if(!result.nextToken)break;if(result.nextToken===nextToken||page===99)fail('LegacyTaskInventoryIncomplete');nextToken=result.nextToken;
      }
    }
    let active=0;
    for(const cluster of inventory.clusters??[meta.clusterArn]){
      const ids=[...arns].filter(arn=>taskClusters.get(arn)===cluster);
      for(let i=0;i<ids.length;i+=100){
      const result=await send(clients.ecs,new DescribeTasksCommand({cluster,tasks:ids.slice(i,i+100)}));
      if(result.failures?.length)fail('LegacyTaskObservationFailed');
      for(const task of result.tasks??[]){
        const family=task.taskDefinitionArn.split('/').at(-1).replace(/:[0-9]+$/,'');
        if(task.lastStatus!=='STOPPED'&&(task.group==='service:Mem9Server'||inventory.families.includes(family))){
          active++;await send(clients.ecs,new StopTaskCommand({cluster,task:task.taskArn,reason:'Production credential cutover'}));
        }
      }
      }
    }
    const service=(await send(clients.ecs,new DescribeServicesCommand({cluster:meta.clusterArn,services:['Mem9Server']}))).services?.[0];
    if(!active&&service?.desiredCount===0&&!service.runningCount&&!service.pendingCount)quiet++;else quiet=0;
    if(quiet>=3)return {clusters:(inventory.clusters??[meta.clusterArn]).length,families:inventory.families.length,observations:3,running:0,pending:0};await sleep(5000);
  }
  fail('LegacyDrainDeadline');
}

export async function restorePinnedRuntime(clients,meta,state,{deadline=Date.now()+1200000,sleep=delay}={}){
  const taskDefinition=state.identity.fallbackTaskDefinition;
  const definition=(await send(clients.ecs,new DescribeTaskDefinitionCommand({taskDefinition}))).taskDefinition;
  const server=definition?.containerDefinitions?.find(c=>c.name==='mnemo-server'),configuration=env(server);
  if(definition?.executionRoleArn!==meta.runtimeExecutionRole||configuration.MNEMO_SCHEMA_MODE!=='verify'||configuration.MNEMO_NAMESPACE_REQUIRED!=='1'||
    server.secrets?.find(s=>s.name==='MEM9_DB_SECRET')?.valueFrom!==meta.runtimeCredential||
    !server.image?.endsWith('@'+state.identity.fallbackImageDigest)||definition.containerDefinitions.some(c=>!/@sha256:[a-f0-9]{64}$/.test(c.image)))fail('RuntimeFallbackMismatch');
  await send(clients.ecs,new UpdateServiceCommand({cluster:meta.clusterArn,service:'Mem9Server',taskDefinition,desiredCount:1,
    deploymentConfiguration:{deploymentCircuitBreaker:{enable:true,rollback:false}}}));
  while(Date.now()<deadline){
    const service=(await send(clients.ecs,new DescribeServicesCommand({cluster:meta.clusterArn,services:['Mem9Server']}))).services?.[0];
    if(service?.taskDefinition===taskDefinition&&service.desiredCount===1&&service.runningCount===1&&!service.pendingCount&&
      service.deployments?.length===1&&service.deployments[0].rolloutState==='COMPLETED')return taskDefinition;
    await sleep(5000);
  }
  fail('RuntimeRestorationDeadline');
}
