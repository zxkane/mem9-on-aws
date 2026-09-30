import {GetRoleCommand,ListRolePoliciesCommand,GetRolePolicyCommand,ListAttachedRolePoliciesCommand} from '@aws-sdk/client-iam';

const fail=message=>{throw Error(message);};
const array=value=>Array.isArray(value)?value:[value];
const environment=container=>Object.fromEntries((container?.environment??[]).map(e=>[e.name,e.value]));
function decoded(value){
  if(typeof value==='object')return value;
  try{return JSON.parse(value);}catch{return JSON.parse(decodeURIComponent(value));}
}
function canonical(value,key=''){
  if(['Action','Resource','Statement'].includes(key))value=array(value);
  if(Array.isArray(value))return value.map(v=>canonical(v)).sort((a,b)=>JSON.stringify(a).localeCompare(JSON.stringify(b)));
  if(value&&typeof value==='object')return Object.fromEntries(Object.keys(value).filter(k=>k!=='Sid').sort().map(k=>[k,canonical(value[k],k)]));
  return value;
}
const same=(a,b)=>JSON.stringify(canonical(a))===JSON.stringify(canonical(b));

export function runtimeServerContract(definition,meta,tenantSecret){
  if(definition.taskDefinitionArn!==meta.serverTaskDefinition||definition.family!==meta.cluster+'-Mem9Server')fail('RuntimeServerRevisionMismatch');
  const server=definition.containerDefinitions?.find(c=>c.name==='mnemo-server'),env=environment(server);
  const base=`arn:aws:ssm:${meta.region}:${meta.account}:parameter/mem9-on-aws/${meta.stage}`;
  const secrets={MEM9_DB_SECRET:base+'/runtime/database-credential',MEM9_TENANT_ID:tenantSecret,
    MNEMO_TRANSPORT_SIGNING_KEYS:base+'/namespace/transport-signing-keys',MNEMO_SERVICE_TRANSPORT_SIGNING_KEYS:base+'/namespace/service-transport-signing-keys'};
  if(!tenantSecret?.startsWith(`arn:aws:secretsmanager:${meta.region}:${meta.account}:secret:mem9-on-aws-${meta.stage}-`)||
    env.MEM9_STAGE!==meta.stage||env.MNEMO_SCHEMA_MODE!=='verify'||env.MNEMO_NAMESPACE_REQUIRED!=='1'||env.MNEMO_DSN||env.MEM9_DB_SECRET||
    !same(Object.fromEntries((server?.secrets??[]).map(s=>[s.name,s.valueFrom])),secrets)||
    definition.containerDefinitions.some(c=>c.name!=='mnemo-server'&&(c.secrets?.length||c.environmentFiles?.length)))fail('RuntimeServerCredentialMismatch');
  const parameters=Object.values(secrets).filter(s=>s!==tenantSecret);
  const execution={Version:'2012-10-17',Statement:[
    {Effect:'Allow',Action:['ssm:GetParameters'],Resource:parameters},
    {Effect:'Allow',Action:['secretsmanager:GetSecretValue'],Resource:[tenantSecret]},
    {Effect:'Allow',Action:['kms:Decrypt'],Resource:'*',Condition:{StringEquals:{'kms:ViaService':`ssm.${meta.region}.amazonaws.com`,'kms:EncryptionContext:PARAMETER_ARN':parameters}}},
    {Effect:'Allow',Action:['kms:Decrypt'],Resource:'*',Condition:{StringEquals:{'kms:ViaService':`secretsmanager.${meta.region}.amazonaws.com`,'kms:EncryptionContext:SecretARN':tenantSecret}}},
  ]};
  const proxy=environment(definition.containerDefinitions.find(c=>c.name==='llm-proxy'));
  const project=(region,id)=>`arn:aws:bedrock-mantle:${region}:${meta.account}:project/${id}`;
  const task={Version:'2012-10-17',Statement:[
    {Effect:'Allow',Action:['bedrock-mantle:CreateInference'],Resource:[proxy.LLM_PROXY_OPENAI_PROJECT?project(meta.region,proxy.LLM_PROXY_OPENAI_PROJECT):'*',
      ...(proxy.LLM_PROXY_RESPONSES_OPENAI_PROJECT?[project(proxy.LLM_PROXY_RESPONSES_REGION,proxy.LLM_PROXY_RESPONSES_OPENAI_PROJECT)]:[])]},
    {Effect:'Allow',Action:['bedrock-mantle:CallWithBearerToken','bedrock-mantle:GetProject','bedrock-mantle:ListProjects','bedrock-mantle:ListTagsForResource'],Resource:['*']},
    {Effect:'Allow',Action:['ssmmessages:CreateControlChannel','ssmmessages:CreateDataChannel','ssmmessages:OpenControlChannel','ssmmessages:OpenDataChannel'],Resource:['*']},
  ]};
  return {execution,task};
}

export async function verifyRuntimeRoles({iam,definition,meta,contract}){
  const send=command=>iam.send(command,{abortSignal:AbortSignal.timeout(30000)});
  for(const kind of ['task','execution']){
    const arn=definition[kind+'RoleArn'];
    const prefix=`arn:aws:iam::${meta.account}:role/mem9-on-aws-${meta.stage}-Mem9Server${kind==='task'?'Task':'Execution'}Role-`;
    if(!arn?.startsWith(prefix)||!/^[a-zA-Z0-9-]+$/.test(arn.slice(prefix.length)))fail('RuntimeRoleScopeMismatch');
    const RoleName=arn.split('/').at(-1);
    const role=(await send(new GetRoleCommand({RoleName}))).Role;
    if(role?.Arn!==arn||role.PermissionsBoundary?.PermissionsBoundaryArn!==`arn:aws:iam::${meta.account}:policy/mem9-on-aws-workload-boundary`)fail('RuntimeRoleBoundaryMismatch');
    const trust=decoded(role.AssumeRolePolicyDocument);
    if(!same(trust,{Version:'2012-10-17',Statement:[{Effect:'Allow',Action:'sts:AssumeRole',Principal:{Service:'ecs-tasks.amazonaws.com'}}]}))fail('RuntimeRoleTrustMismatch');
    const policies=[],attached=[];
    for(const [Command,key,destination] of [[ListRolePoliciesCommand,'PolicyNames',policies],[ListAttachedRolePoliciesCommand,'AttachedPolicies',attached]]){
      let Marker;
      for(let page=0;page<50;page++){
        const result=await send(new Command({RoleName,Marker,MaxItems:100}));destination.push(...(result[key]??[]));
        if(!result.IsTruncated)break;
        if(!result.Marker||result.Marker===Marker||page===49)fail('RuntimeRoleInventoryIncomplete');Marker=result.Marker;
      }
    }
    const name=kind==='task'?'inline':'RuntimeSecrets';
    if(policies.length!==1||policies[0]!==name)fail('RuntimeRolePolicyMismatch');
    // The one permitted AWS-owned baseline (documented v1) grants only ECR
    // pulls/log writes; customers cannot edit it. No customer-managed policy
    // attachment or other AWS-managed policy is accepted.
    const allowed=kind==='execution'?['arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy']:[];
    if(!same(attached.map(p=>p.PolicyArn),allowed))fail('RuntimeRoleAttachmentMismatch');
    const actual=decoded((await send(new GetRolePolicyCommand({RoleName,PolicyName:name}))).PolicyDocument);
    if(!same(actual,contract[kind]))fail('RuntimeRolePolicyMismatch');
  }
}
