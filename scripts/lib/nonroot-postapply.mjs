/** Closed production deployment material. This is evidence, never permission
 * to deploy, read secrets, choose another endpoint or enlarge a prepaid slot. */
import {createHash} from 'node:crypto';
import {deflateRawSync,inflateRawSync} from 'node:zlib';
import {nonrootHash as hash,parseNonrootJson,copyNonrootJson} from './production-nonroot-contracts.mjs';
import {controlSourceEntries} from './production-control-source.mjs';
import {GATEWAY_BOUNDARY_POLICY_NAME,GATEWAY_LOGICAL_ROLES} from './gateway-workload-boundary.mjs';
import {decodeRootPolicy} from './production-nonroot-prerequisites.mjs';

const need=(v,c='NonrootPostApplyInvalid')=>{if(!v)throw Error(c);};
const exact=(v,k)=>need(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===k.toSorted().join(),'NonrootPostApplyFields');
const same=(a,b,c='NonrootPostApplyBinding')=>need(hash(a)===hash(b),c);
const sha=v=>createHash('sha256').update(v).digest('hex');
const hex=(v,n=64)=>typeof v==='string'&&new RegExp('^[a-f0-9]{'+n+'}$').test(v);
const positive=n=>Number.isSafeInteger(n)&&n>0;
const list=v=>Array.isArray(v)?v:[v];
const sorted=v=>[...v].sort();
export const NONROOT_POSTAPPLY_LIMITS=Object.freeze({version:1,jsonBytes:262144,compressedBytes:8192,zipBytes:16777216,zipCount:4,captureLocalBytes:100663296,captureWorkBytes:62914560,completionWorkBytes:37748736,readerLocalBytes:4194304,requestBytes:16384});
export const NONROOT_POSTAPPLY_FUNCTIONS=Object.freeze(['Mem9ProxyFn','Mem9IdentityInterceptorFn','Mem9OauthFacadeFn','Mem9AlertRouter']);
export const NONROOT_POSTAPPLY_SOURCE_PATHS=Object.freeze(['sst.config.ts','infra/nonroot-deployment-capture.ts','infra/gateway.ts','infra/gateway-network.ts','infra/runtime-secret-permissions.ts','infra/lambda-execution-role.ts','infra/workload-permissions-boundary.ts','infra/namespace-identity.ts','infra/tenant-identity.ts','infra/oauth-facade.ts','infra/observability.ts','infra/gateway/runtime-secrets.mjs','infra/gateway/secret-endpoint.mjs','scripts/record-nonroot-deployment.mjs','scripts/lib/nonroot-postapply.mjs','scripts/lib/nonroot-postapply-capture.mjs','infra/pnpm-lock.yaml']);
export const NONROOT_POSTAPPLY_RESOURCES=Object.freeze({
 Mem9GatewaySsmEndpoint:{type:'aws:ec2/vpcEndpoint:VpcEndpoint',fields:['id','vpcId','subnetIds','securityGroupIds','serviceName','vpcEndpointType','privateDnsEnabled','ipAddressType','policy','dnsEntries','state']},
 Mem9GatewaySecretsManagerEndpoint:{type:'aws:ec2/vpcEndpoint:VpcEndpoint',fields:['id','vpcId','subnetIds','securityGroupIds','serviceName','vpcEndpointType','privateDnsEnabled','ipAddressType','policy','dnsEntries','state']},
 Mem9GatewayProxySg:{type:'aws:ec2/securityGroup:SecurityGroup',fields:['id','vpcId','ingress','egress']},
 Mem9GatewaySecretEndpointSg:{type:'aws:ec2/securityGroup:SecurityGroup',fields:['id','vpcId','ingress','egress']},
 Mem9TaskFromProxyLambda:{type:'aws:ec2/securityGroupRule:SecurityGroupRule',fields:['id','type','securityGroupId','sourceSecurityGroupId','protocol','fromPort','toPort']},
 Mem9GatewaySecretEndpointIngress:{type:'aws:ec2/securityGroupRule:SecurityGroupRule',fields:['id','type','securityGroupId','sourceSecurityGroupId','protocol','fromPort','toPort']},
 Mem9TransportSigningKeys:{type:'aws:ssm/parameter:Parameter',fields:['arn','name','type','keyId','version']},
 SsmOauthStateHmacKey:{type:'aws:ssm/parameter:Parameter',fields:['arn','name','type','keyId','version']},
 Mem9AlertWebhookParameter:{type:'aws:ssm/parameter:Parameter',fields:['arn','name','type','keyId','version']},
 Mem9TenantApiKey:{type:'aws:secretsmanager/secret:Secret',fields:['arn','name','kmsKeyId']},
 Mem9IdentitySigningKeys:{type:'aws:secretsmanager/secret:Secret',fields:['arn','name','kmsKeyId']},
 AlertExecutionFailureQueue:{type:'aws:sqs/queue:Queue',fields:['arn']},
 Mem9Discovery:{type:'aws:servicediscovery/service:Service',fields:['id','arn','name']},
 Mem9Gateway:{type:'aws:bedrock/agentcoreGateway:AgentcoreGateway',fields:['gatewayId','gatewayArn','gatewayUrl','roleArn']},
 Mem9GatewayServiceRole:{type:'aws:iam/role:Role',fields:['arn','name','uniqueId','assumeRolePolicy','permissionsBoundary']},
 Mem9GatewayInvokeLambda:{type:'aws:iam/rolePolicy:RolePolicy',fields:['name','role','policy']},
 Mem9GatewayTarget:{type:'command:local:Command',fields:['stdout','environment']},
 Mem9ProxyFnEnvironmentUpdate:{type:'sst:aws:FunctionEnvironmentUpdate',fields:['environment']},
});
export const NONROOT_POSTAPPLY_ENVIRONMENT=Object.freeze({
 Mem9ProxyFn:['MEM9_SERVER_BASE_URL','MEM9_API_KEY_SECRET_ARN','MEM9_IDENTITY_SIGNING_KEYS_SECRET_ARN','MEM9_TRANSPORT_SIGNING_KEYS_PARAMETER_ARN','STAGE','MEM9_SECRET_ACCOUNT_ID','MEM9_TRANSPORT_ISSUER','MEM9_SECRET_ENDPOINT_MODE','MEM9_ACCEPTANCE_STAGE','MEM9_SECRET_SSM_VPCE_ID','MEM9_SECRET_SSM_ENDPOINT_DNS','MEM9_SECRET_SECRETSMANAGER_VPCE_ID','MEM9_SECRET_SECRETSMANAGER_ENDPOINT_DNS'],
 Mem9IdentityInterceptorFn:['MEM9_TOOL_SCOPES','MEM9_CLIENT_REGISTRY','MEM9_IDENTITY_SIGNING_KEYS_SECRET_ARN','STAGE','MEM9_SECRET_ACCOUNT_ID','MEM9_IDENTITY_JWKS_URI','MEM9_ACCEPTANCE_STAGE'],
 Mem9OauthFacadeFn:['SSM_PREFIX','STAGE','AUTH_MODE','AUTH_CREDENTIAL_PREFIX','AUTH_TOKEN_AUTH_METHOD','AUTH_CONTEXT_VERSION','AUTH_CLIENT_SECRET_VERSION','COGNITO_AUTHORIZE_ENDPOINT','COGNITO_TOKEN_ENDPOINT','COGNITO_USERINFO_ENDPOINT','COGNITO_REVOCATION_ENDPOINT','COGNITO_JWKS_URI','RESOURCE_SCOPES','OAUTH_STATE_HMAC_KEY_PARAMETER_ARN','MEM9_SECRET_ACCOUNT_ID','OAUTH_ALLOWED_CALLBACK_URLS_VERSION'],
 Mem9AlertRouter:['SLACK_WEBHOOK_URL_PARAMETER_ARN','STAGE','MEM9_SECRET_ACCOUNT_ID'],
});
/** SST's resource encryption key is neither business configuration nor public
 * evidence. Validate the fixed internal names but never retain their values. */
export function projectNonrootPostApplyEnvironment(name,value){
 const keys=NONROOT_POSTAPPLY_ENVIRONMENT[name];need(keys&&value&&Object.values(value).every(v=>typeof v==='string'),'NonrootPostApplyEnvironment');
 const internal=['SST_RESOURCE_App','SST_KEY','SST_KEY_FILE'];need(Object.keys(value).every(k=>keys.includes(k)||internal.includes(k)),'NonrootPostApplyEnvironment');
 if(internal.some(k=>Object.hasOwn(value,k))){need(internal.every(k=>Object.hasOwn(value,k))&&value.SST_KEY_FILE==='resource.enc'&&value.SST_KEY.length>0&&value.SST_KEY.length<=4096,'NonrootPostApplySstEnvironment');same(JSON.parse(value.SST_RESOURCE_App),{name:'mem9-on-aws',stage:'prod'},'NonrootPostApplySstEnvironment');}
 const projected=Object.fromEntries(keys.map(k=>[k,value[k]]));exact(projected,keys);need(Object.values(projected).every(v=>typeof v==='string'),'NonrootPostApplyEnvironment');return projected;
}
function recordShape(value){
 exact(value,['version','kind','policyHash','source','sourceFiles','functions','resources','capturedMs','completedMs']);
 exact(value.functions,NONROOT_POSTAPPLY_FUNCTIONS);exact(value.resources,Object.keys(NONROOT_POSTAPPLY_RESOURCES));
 for(const [name,spec]of Object.entries(NONROOT_POSTAPPLY_RESOURCES))exact(value.resources[name],spec.fields);
 for(const name of NONROOT_POSTAPPLY_FUNCTIONS){const f=value.functions[name];exact(f,['arn','codeSha256','s3Key','runtime','architectures','handler','role','environment','vpcConfig','zip']);exact(f.role,['arn','name','uniqueId','assumeRolePolicy','inlinePolicies','managedPolicyArns','permissionsBoundary']);exact(f.environment,NONROOT_POSTAPPLY_ENVIRONMENT[name]);projectNonrootPostApplyEnvironment(name,f.environment);
  need(Array.isArray(f.role.inlinePolicies)&&f.role.inlinePolicies.length===1,'NonrootPostApplyPolicy');for(const p of f.role.inlinePolicies)exact(p,['name','policy']);
  if(f.vpcConfig!==null){exact(f.vpcConfig,['securityGroupIds','subnetIds',...(Object.hasOwn(f.vpcConfig,'vpcId')?['vpcId']:[]),...(Object.hasOwn(f.vpcConfig,'ipv6AllowedForDualStack')?['ipv6AllowedForDualStack']:[])]);need(!f.vpcConfig.ipv6AllowedForDualStack,'NonrootPostApplyVpc');}
 }
 for(const name of ['Mem9GatewaySsmEndpoint','Mem9GatewaySecretsManagerEndpoint']){const e=value.resources[name];need(Array.isArray(e.dnsEntries)&&e.dnsEntries.length<=16,'NonrootPostApplyDns');for(const d of e.dnsEntries)exact(d,['dnsName','hostedZoneId']);}
 exact(value.resources.Mem9GatewayTarget.environment,['MEM9_TGT_REGION','MEM9_TGT_GATEWAY_ID','MEM9_TGT_NAME','MEM9_TGT_LAMBDA_ARN']);
 exact(value.resources.Mem9ProxyFnEnvironmentUpdate.environment,['MEM9_SECRET_ENDPOINT_MODE','MEM9_SECRET_SSM_VPCE_ID','MEM9_SECRET_SSM_ENDPOINT_DNS','MEM9_SECRET_SECRETSMANAGER_VPCE_ID','MEM9_SECRET_SECRETSMANAGER_ENDPOINT_DNS']);
}
export const NONROOT_POSTAPPLY_POLICY_HASH=hash({limits:NONROOT_POSTAPPLY_LIMITS,functions:NONROOT_POSTAPPLY_FUNCTIONS,resources:NONROOT_POSTAPPLY_RESOURCES,sourcePaths:NONROOT_POSTAPPLY_SOURCE_PATHS,environment:NONROOT_POSTAPPLY_ENVIRONMENT});
export const isNonrootPostApplyCheckpoint=scope=>scope?.route==='deploy-prod'&&['deploy-prod/21','deploy-prod/23'].includes(scope.checkpoint)&&scope.phase===(scope.checkpoint==='deploy-prod/21'?'preupdate':'prereadiness');

export function nonrootPostApplySourceScope(context){
 const entries=controlSourceEntries(context),rows=[];
 for(const path of NONROOT_POSTAPPLY_SOURCE_PATHS){const row=entries.find(r=>r.path===path);need(row?.type==='blob'&&['100644','100755'].includes(row.mode),'NonrootPostApplySourceMissing');rows.push({path,mode:row.mode,oid:row.oid});}
 return {tree:context.tree,files:rows,policyHash:NONROOT_POSTAPPLY_POLICY_HASH};
}
export function encodeNonrootPostApplyArtifact(value){
 const raw=Buffer.from(JSON.stringify(value));need(raw.length<=NONROOT_POSTAPPLY_LIMITS.jsonBytes,'NonrootPostApplySize');
 const compressed=deflateRawSync(raw);need(compressed.length<=NONROOT_POSTAPPLY_LIMITS.compressedBytes,'NonrootPostApplySize');
 return {version:1,kind:'bounded-sst-deployment-artifact',encoding:'deflate-raw-base64',sha256:sha(raw),bytes:raw.length,compressedBytes:compressed.length,body:compressed.toString('base64')};
}
export function decodeNonrootPostApplyArtifact(value){
 exact(value,['version','kind','encoding','sha256','bytes','compressedBytes','body']);
 need(value.version===1&&value.kind==='bounded-sst-deployment-artifact'&&value.encoding==='deflate-raw-base64'&&hex(value.sha256)&&positive(value.bytes)&&value.bytes<=NONROOT_POSTAPPLY_LIMITS.jsonBytes&&positive(value.compressedBytes)&&value.compressedBytes<=NONROOT_POSTAPPLY_LIMITS.compressedBytes&&typeof value.body==='string'&&value.body.length===4*Math.ceil(value.compressedBytes/3),'NonrootPostApplyEncoding');
 const compressed=Buffer.from(value.body,'base64');need(compressed.length===value.compressedBytes&&compressed.toString('base64')===value.body,'NonrootPostApplyEncoding');
 const {buffer,engine}=inflateRawSync(compressed,{maxOutputLength:NONROOT_POSTAPPLY_LIMITS.jsonBytes,info:true});need(engine.bytesWritten===compressed.length&&buffer.length===value.bytes&&sha(buffer)===value.sha256,'NonrootPostApplyDigest');
 return parseNonrootJson(buffer.toString('utf8'),{maxBytes:NONROOT_POSTAPPLY_LIMITS.jsonBytes});
}
export function inspectNonrootPostApplyIdentity(value,{binding,config,scope,now}){
 need(isNonrootPostApplyCheckpoint(scope),'NonrootPostApplyCheckpoint');recordShape(value);
 need(value.version===1&&value.kind==='sst-owned-deployment-capture'&&value.policyHash===NONROOT_POSTAPPLY_POLICY_HASH,'NonrootPostApplyKind');
 same(value.source,{repository:binding.source.repository,runId:binding.source.runId,runAttempt:binding.source.runAttempt,jobKey:'deploy-prod',revision:binding.source.mainRevision,tree:binding.source.mainTree,grantSetId:config.startup.grantSetId,descriptorHash:config.startup.descriptorHash,proofHash:config.startup.proofHash},'NonrootPostApplyRun');
 need(positive(value.capturedMs)&&positive(value.completedMs)&&value.capturedMs<=value.completedMs&&value.completedMs<=now&&now<config.startup.notAfter,'NonrootPostApplyTime');
 exact(value.functions,NONROOT_POSTAPPLY_FUNCTIONS);exact(value.resources,Object.keys(NONROOT_POSTAPPLY_RESOURCES));
 need(Array.isArray(value.sourceFiles)&&value.sourceFiles.length===NONROOT_POSTAPPLY_SOURCE_PATHS.length,'NonrootPostApplySource');
 for(const [i,f]of value.sourceFiles.entries()){exact(f,['path','mode','oid','sha256']);need(f.path===NONROOT_POSTAPPLY_SOURCE_PATHS[i]&&['100644','100755'].includes(f.mode)&&hex(f.oid,40)&&hex(f.sha256),'NonrootPostApplySource');}
 return value;
}

const policyDocument=value=>decodeRootPolicy(value);
function policyRows(value){const p=policyDocument(value);exact(p,['Statement',...(Object.hasOwn(p,'Version')?['Version']:[])]);return list(p.Statement).map(s=>{exact(s,['Effect','Action','Resource',...(Object.hasOwn(s,'Condition')?['Condition']:[]),...(Object.hasOwn(s,'Sid')?['Sid']:[])]);need(s.Effect==='Allow'&&(!Object.hasOwn(s,'Sid')||typeof s.Sid==='string')&&list(s.Action).length>0&&list(s.Resource).length>0&&[...list(s.Action),...list(s.Resource)].every(v=>typeof v==='string'&&v.length>0&&!v.includes('${')),'NonrootPostApplyPolicy');return s;});}
function serviceTrust(value,service){const p=policyDocument(value);same(p,{Version:'2012-10-17',Statement:[{Effect:'Allow',Action:'sts:AssumeRole',Principal:{Service:service}}]},'NonrootPostApplyTrust');}

function endpointPolicy(service,role,resources){return {Version:'2012-10-17',Statement:[{Effect:'Allow',Principal:{AWS:role},Action:service==='ssm'?'ssm:GetParameters':'secretsmanager:GetSecretValue',Resource:resources}]};}
function sgRule(v,from,to){need(v.type==='ingress'&&v.securityGroupId===to&&v.sourceSecurityGroupId===from&&v.protocol==='tcp'&&v.fromPort===v.toPort&&[443,8080].includes(v.fromPort),'NonrootPostApplySecurityGroup');}

/** Exact source-owned associations plus independently pinned old identities.
 * Dynamic IDs are admitted only in their two declared endpoint/group slots. */
export function verifyNonrootPostApplyDeployment(value,{sourceScope,before,backendSecurityGroupId,subnetIds,boundaryArn,keyArns}){
 recordShape(value);
 same(value.sourceFiles.map(({sha256,...r})=>r),sourceScope.files,'NonrootPostApplySource');need(value.source.tree===sourceScope.tree&&sourceScope.policyHash===value.policyHash,'NonrootPostApplySource');
 const r=value.resources,fn=value.functions,proxy=fn.Mem9ProxyFn,account=before.account,region=before.region;
 const arn=(v,service)=>typeof v==='string'&&v.startsWith(`arn:aws:${service}:${service==='iam'?'':region}:${account}:`)&&!/[?*\s]/.test(v);
 const parameters={Mem9TransportSigningKeys:'/namespace/transport-signing-keys',SsmOauthStateHmacKey:'/oauth/state-hmac-key',Mem9AlertWebhookParameter:'/observability/slack-webhook-url'};
 for(const [key,path]of Object.entries(parameters)){const p=r[key];need(p.name==='/mem9-on-aws/prod'+path&&p.arn===`arn:aws:ssm:${region}:${account}:parameter${p.name}`&&p.type==='SecureString'&&positive(p.version),'NonrootPostApplyParameter');}
 for(const key of ['Mem9TenantApiKey','Mem9IdentitySigningKeys']){
  const secret=r[key],prefix='mem9-on-aws-prod-'+(key==='Mem9TenantApiKey'?'tenant-api-key':'identity-'+'signing-keys')+'-';
  need(typeof secret.name==='string'&&secret.name.startsWith(prefix)&&secret.name.length>prefix.length&&/^[A-Za-z0-9/_+=.@-]+$/.test(secret.name)&&arn(secret.arn,'secretsmanager')&&new RegExp('^'+RegExp.escape(`arn:aws:secretsmanager:${region}:${account}:secret:${secret.name}`)+'-[A-Za-z0-9]{6}$').test(secret.arn),'NonrootPostApplySecret');
 }
 need(proxy.arn===before.proxyArn&&r.Mem9Gateway.gatewayId===before.gatewayId&&r.Mem9Gateway.gatewayArn===before.gatewayArn&&r.Mem9Gateway.gatewayUrl===before.auth.gatewayUrl&&r.Mem9Discovery.id===before.cloudMapServiceId&&r.Mem9Discovery.arn===before.cloudMapServiceArn,'NonrootPostApplyRetainedIdentity');
 for(const name of NONROOT_POSTAPPLY_FUNCTIONS){
  const f=fn[name];exact(f,['arn','codeSha256','s3Key','runtime','architectures','handler','role','environment','vpcConfig','zip']);
  need(arn(f.arn,'lambda')&&new RegExp(':function:mem9-on-aws-prod-'+name+'Function-[A-Za-z0-9]+$').test(f.arn)&&typeof f.handler==='string'&&/^(?:[A-Za-z0-9_-]+\/)*(?:server-index|handler|proxy-handler|identity-interceptor)\.handler$/.test(f.handler)&&f.runtime==='nodejs24.x'&&hash(f.architectures)===hash(['arm64'])&&typeof f.codeSha256==='string'&&Buffer.from(f.codeSha256,'base64').toString('base64')===f.codeSha256&&Buffer.from(f.codeSha256,'base64').length===32,'NonrootPostApplyLambda');
  exact(f.zip,['sha256','bytes']);need(hex(f.zip.sha256)&&positive(f.zip.bytes)&&f.zip.bytes<=NONROOT_POSTAPPLY_LIMITS.zipBytes&&Buffer.from(f.codeSha256,'base64').toString('hex')===f.zip.sha256&&f.s3Key===`assets/${name}-code-${f.zip.sha256}.zip`,'NonrootPostApplyLambdaBytes');
  const role=f.role,expectedBoundary=GATEWAY_LOGICAL_ROLES.includes(name+'Role')?`arn:aws:iam::${account}:policy/${GATEWAY_BOUNDARY_POLICY_NAME}`:boundaryArn;need(arn(role.arn,'iam')&&role.arn===`arn:aws:iam::${account}:role/${role.name}`&&new RegExp('^(?:mem9-on-aws|mem9-on-aw|mem9-on-a)-prod-'+name+'Role-[A-Za-z0-9]+$').test(role.name)&&role.permissionsBoundary===expectedBoundary&&typeof role.uniqueId==='string'&&/^AROA[A-Z0-9]+$/.test(role.uniqueId),'NonrootPostApplyRole');
  serviceTrust(role.assumeRolePolicy,'lambda.amazonaws.com');
  need(Array.isArray(role.inlinePolicies)&&role.inlinePolicies.length===1&&role.inlinePolicies[0].name==='inline','NonrootPostApplyPolicy');
  const managed=['arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole',...(name==='Mem9ProxyFn'?['arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole']:[])];same(sorted(role.managedPolicyArns),sorted(managed),'NonrootPostApplyManagedPolicy');
  need(f.environment.STAGE==='prod'&&f.environment.MEM9_SECRET_ACCOUNT_ID===account&&!Object.keys(f.environment).some(k=>['MEM9_API_KEY','MEM9_IDENTITY_SIGNING_KEYS','MEM9_TRANSPORT_SIGNING_KEYS','OAUTH_STATE_HMAC_KEY','SLACK_WEBHOOK_URL','NODE_OPTIONS','NODE_PATH','LD_PRELOAD'].includes(k)),'NonrootPostApplyEnvironment');
  for(const s of policyRows(role.inlinePolicies[0].policy))for(const action of list(s.Action)){
   const resources=list(s.Resource);need(resources.every(v=>typeof v==='string'),'NonrootPostApplyPolicy');
   if(action==='secretsmanager:GetSecretValue'){const wanted=name==='Mem9ProxyFn'?[r.Mem9TenantApiKey.arn,r.Mem9IdentitySigningKeys.arn]:name==='Mem9IdentityInterceptorFn'?[r.Mem9IdentitySigningKeys.arn]:[];need(wanted.length>0&&resources.every(v=>wanted.includes(v))&&!s.Condition,'NonrootPostApplySecretPermission');}
   else if(action==='ssm:GetParameters'){
    const wanted=name==='Mem9ProxyFn'?[r.Mem9TransportSigningKeys.arn]:name==='Mem9AlertRouter'?[r.Mem9AlertWebhookParameter.arn]:name==='Mem9OauthFacadeFn'?[r.SsmOauthStateHmacKey.arn]:[];
    const prefix='/mem9-on-aws/prod',credential=f.environment.AUTH_CREDENTIAL_PREFIX,facadePaths=[prefix+'/gateway/url',credential+'/client-id',credential+'/client-secret',prefix+'/oauth/allowed-callback-urls',prefix+'/slack/signing-secret',...['cluster-name','task-def-arn','task-sg-id','subnet-ids'].map(k=>prefix+'/cleanup/'+k),prefix+'/approvals/*'].map(path=>`arn:aws:ssm:${region}:${account}:parameter${path}`);
    need(wanted.length>0&&!s.Condition&&resources.every(v=>wanted.includes(v)||name==='Mem9OauthFacadeFn'&&facadePaths.includes(v)),'NonrootPostApplyParameterPermission');
   }else if(action==='kms:Decrypt'){
    need(s.Condition&&Object.keys(s.Condition).every(k=>['StringEquals','ArnEquals','ArnLike'].includes(k)),'NonrootPostApplyKeyPermission');
    exact(s.Condition,['StringEquals',...(Object.hasOwn(s.Condition,'ArnEquals')?['ArnEquals']:['ArnLike'])]);exact(s.Condition.StringEquals,['kms:ViaService']);const via=list(s.Condition.StringEquals?.['kms:ViaService']);need(via.length===1&&[`ssm.${region}.amazonaws.com`,`secretsmanager.${region}.amazonaws.com`].includes(via[0]),'NonrootPostApplyKeyPermission');
    const context=s.Condition.ArnEquals??s.Condition.ArnLike;need(context&&Object.keys(context).length===1,'NonrootPostApplyKeyPermission');const [key,values]=Object.entries(context)[0];
    need(key===(via[0].startsWith('ssm.')?'kms:EncryptionContext:PARAMETER_ARN':'kms:EncryptionContext:SecretARN'),'NonrootPostApplyKeyPermission');
    const permitted=via[0].startsWith('ssm.')?policyRows(role.inlinePolicies[0].policy).filter(x=>list(x.Action).includes('ssm:GetParameters')).flatMap(x=>list(x.Resource)):policyRows(role.inlinePolicies[0].policy).filter(x=>list(x.Action).includes('secretsmanager:GetSecretValue')).flatMap(x=>list(x.Resource));
    need(list(values).every(v=>permitted.includes(v))&&resources.every(v=>keyArns.includes(v)||v==='*'&&name==='Mem9OauthFacadeFn'&&s.Condition.ArnLike&&via[0].startsWith('ssm.')),'NonrootPostApplyKeyPermission');
   }else need(action==='sqs:SendMessage'&&name==='Mem9AlertRouter'&&hash(resources)===hash([r.AlertExecutionFailureQueue.arn])&&!s.Condition,'NonrootPostApplyPolicyAction');
  }
  const rows=policyRows(role.inlinePolicies[0].policy),granted=action=>[...new Set(rows.filter(s=>list(s.Action).includes(action)).flatMap(s=>list(s.Resource)))].sort();
  const requiredSecrets=name==='Mem9ProxyFn'?[r.Mem9TenantApiKey.arn,r.Mem9IdentitySigningKeys.arn]:name==='Mem9IdentityInterceptorFn'?[r.Mem9IdentitySigningKeys.arn]:[];
  const requiredParameters=name==='Mem9ProxyFn'?[r.Mem9TransportSigningKeys.arn]:name==='Mem9AlertRouter'?[r.Mem9AlertWebhookParameter.arn]:name==='Mem9OauthFacadeFn'?[r.SsmOauthStateHmacKey.arn,...['/gateway/url',...['client-id','client-secret'].map(k=>f.environment.AUTH_CREDENTIAL_PREFIX.replace('/mem9-on-aws/prod','')+'/'+k),'/oauth/allowed-callback-urls','/slack/signing-secret',...['cluster-name','task-def-arn','task-sg-id','subnet-ids'].map(k=>'/cleanup/'+k),'/approvals/*'].map(path=>`arn:aws:ssm:${region}:${account}:parameter/mem9-on-aws/prod${path}`)]:[];
  same(granted('secretsmanager:GetSecretValue'),sorted(requiredSecrets),'NonrootPostApplyRequiredPermissions');same(granted('ssm:GetParameters'),sorted(requiredParameters),'NonrootPostApplyRequiredPermissions');same(granted('sqs:SendMessage'),name==='Mem9AlertRouter'?[r.AlertExecutionFailureQueue.arn]:[],'NonrootPostApplyRequiredPermissions');
  for(const resource of [...requiredSecrets,...requiredParameters])need(rows.some(s=>list(s.Action).includes('kms:Decrypt')&&Object.values(s.Condition?.ArnEquals??s.Condition?.ArnLike??{}).some(v=>list(v).includes(resource))),'NonrootPostApplyRequiredDecrypt');
  if(name!=='Mem9ProxyFn')need(f.vpcConfig===null||f.vpcConfig.securityGroupIds.length===0&&f.vpcConfig.subnetIds.length===0,'NonrootPostApplyVpc');
 }
 const facade=fn.Mem9OauthFacadeFn.environment;need(facade.SSM_PREFIX==='/mem9-on-aws/prod'&&facade.AUTH_MODE===before.auth.mode&&facade.COGNITO_TOKEN_ENDPOINT===before.auth.tokenEndpoint&&facade.RESOURCE_SCOPES==='mem9-mcp/read,mem9-mcp/write'&&['client_secret_post','client_secret_basic'].includes(facade.AUTH_TOKEN_AUTH_METHOD)&&(facade.AUTH_MODE==='managed'?facade.AUTH_CREDENTIAL_PREFIX==='/mem9-on-aws/prod/cognito/reader':/^\/mem9-on-aws\/prod\/auth\/providers\/[a-zA-Z0-9_-]+\/browser$/.test(facade.AUTH_CREDENTIAL_PREFIX)),'NonrootPostApplyAuth');
 const gatewayRole=r.Mem9GatewayServiceRole;need(gatewayRole.name==='mem9-on-aws-prod-gateway-service-role'&&gatewayRole.arn===`arn:aws:iam::${account}:role/${gatewayRole.name}`&&/^AROA[A-Z0-9]+$/.test(gatewayRole.uniqueId)&&gatewayRole.permissionsBoundary===boundaryArn&&r.Mem9Gateway.roleArn===gatewayRole.arn,'NonrootPostApplyGatewayRole');serviceTrust(gatewayRole.assumeRolePolicy,'bedrock-agentcore.amazonaws.com');
 const invoke=r.Mem9GatewayInvokeLambda;need(invoke.role===gatewayRole.name&&typeof invoke.name==='string','NonrootPostApplyGatewayRole');const invokeRows=policyRows(invoke.policy);need(invokeRows.length===1&&hash(list(invokeRows[0].Action))===hash(['lambda:InvokeFunction'])&&!invokeRows[0].Condition,'NonrootPostApplyGatewayPermission');same(sorted(list(invokeRows[0].Resource)),sorted([proxy.arn,fn.Mem9IdentityInterceptorFn.arn]),'NonrootPostApplyGatewayPermission');
 const e=proxy.environment;
 need(e.MEM9_TRANSPORT_ISSUER==='gateway-target'&&e.MEM9_ACCEPTANCE_STAGE===''&&fn.Mem9IdentityInterceptorFn.environment.MEM9_ACCEPTANCE_STAGE==='','NonrootPostApplyEnvironment');
 for(const [k,v]of Object.entries(r.Mem9ProxyFnEnvironmentUpdate.environment))need(e[k]===v,'NonrootPostApplyLateEnvironment');same({tenant:e.MEM9_API_KEY_SECRET_ARN,identity:e.MEM9_IDENTITY_SIGNING_KEYS_SECRET_ARN,transport:e.MEM9_TRANSPORT_SIGNING_KEYS_PARAMETER_ARN},{tenant:r.Mem9TenantApiKey.arn,identity:r.Mem9IdentitySigningKeys.arn,transport:r.Mem9TransportSigningKeys.arn},'NonrootPostApplySecretEnvironment');
 need(e.MEM9_SERVER_BASE_URL===before.serverBaseUrl&&fn.Mem9IdentityInterceptorFn.environment.MEM9_IDENTITY_SIGNING_KEYS_SECRET_ARN===r.Mem9IdentitySigningKeys.arn&&fn.Mem9OauthFacadeFn.environment.OAUTH_STATE_HMAC_KEY_PARAMETER_ARN===r.SsmOauthStateHmacKey.arn&&fn.Mem9AlertRouter.environment.SLACK_WEBHOOK_URL_PARAMETER_ARN===r.Mem9AlertWebhookParameter.arn,'NonrootPostApplySecretEnvironment');
 const epSg=r.Mem9GatewaySecretEndpointSg,proxySg=r.Mem9GatewayProxySg;need(epSg.id!==proxySg.id&&proxySg.id!==backendSecurityGroupId&&epSg.id!==backendSecurityGroupId&&before.vpcIds.includes(epSg.vpcId)&&epSg.vpcId===proxySg.vpcId,'NonrootPostApplyVpc');
 const sgPermissions=rows=>{need(Array.isArray(rows),'NonrootPostApplySecurityGroup');return rows.map(row=>{need(Object.keys(row).every(k=>['protocol','fromPort','toPort','securityGroups','cidrBlocks','ipv6CidrBlocks','prefixListIds','self','description'].includes(k))&&[...(row.cidrBlocks??[]),...(row.ipv6CidrBlocks??[]),...(row.prefixListIds??[])].length===0&&!row.self,'NonrootPostApplySecurityGroup');return {protocol:row.protocol,fromPort:row.fromPort,toPort:row.toPort,securityGroups:sorted(row.securityGroups??[])};}).sort((a,b)=>a.fromPort-b.fromPort);};
 same(sgPermissions(proxySg.ingress??[]),[],'NonrootPostApplySecurityGroup');same(sgPermissions(epSg.ingress??[]),[],'NonrootPostApplySecurityGroup');same(sgPermissions(epSg.egress??[]),[],'NonrootPostApplySecurityGroup');same(sgPermissions(proxySg.egress),[{protocol:'tcp',fromPort:443,toPort:443,securityGroups:[epSg.id]},{protocol:'tcp',fromPort:8080,toPort:8080,securityGroups:[backendSecurityGroupId]}],'NonrootPostApplySecurityGroup');
 same(sorted(proxy.vpcConfig.securityGroupIds),[proxySg.id],'NonrootPostApplyVpc');same(sorted(proxy.vpcConfig.subnetIds),sorted(subnetIds),'NonrootPostApplyVpc');
 for(const [service,key]of [['ssm','Mem9GatewaySsmEndpoint'],['secretsmanager','Mem9GatewaySecretsManagerEndpoint']]){
  const ep=r[key];need(/^vpce-[a-f0-9]+$/.test(ep.id)&&ep.vpcId===proxySg.vpcId&&ep.vpcEndpointType==='Interface'&&ep.privateDnsEnabled===false&&ep.ipAddressType==='ipv4'&&ep.serviceName===`com.amazonaws.${region}.${service}`&&ep.state==='available','NonrootPostApplyEndpoint');same(sorted(ep.subnetIds),sorted(subnetIds));same(ep.securityGroupIds,[epSg.id]);
  const prefix=service==='ssm'?'MEM9_SECRET_SSM':'MEM9_SECRET_SECRETSMANAGER',dns=ep.dnsEntries.filter(d=>new RegExp(`^${ep.id}-[a-z0-9]+\\.${service}\\.${region}\\.vpce\\.amazonaws\\.com$`).test(d.dnsName));
  need(dns.length===1&&e[prefix+'_VPCE_ID']===ep.id&&e[prefix+'_ENDPOINT_DNS']===dns[0].dnsName&&e.MEM9_SECRET_ENDPOINT_MODE==='private','NonrootPostApplyDns');
  same(policyDocument(ep.policy),endpointPolicy(service,proxy.role.arn,service==='ssm'?[r.Mem9TransportSigningKeys.arn]:[r.Mem9TenantApiKey.arn,r.Mem9IdentitySigningKeys.arn]),'NonrootPostApplyEndpointPolicy');
 }
 sgRule(r.Mem9TaskFromProxyLambda,proxySg.id,backendSecurityGroupId);need(r.Mem9TaskFromProxyLambda.fromPort===8080,'NonrootPostApplySecurityGroup');sgRule(r.Mem9GatewaySecretEndpointIngress,proxySg.id,epSg.id);need(r.Mem9GatewaySecretEndpointIngress.fromPort===443,'NonrootPostApplySecurityGroup');
 const target=r.Mem9GatewayTarget;need(target.environment.MEM9_TGT_REGION===region&&target.environment.MEM9_TGT_GATEWAY_ID===before.gatewayId&&target.environment.MEM9_TGT_LAMBDA_ARN===proxy.arn&&target.environment.MEM9_TGT_NAME===before.targetName,'NonrootPostApplyTarget');const targetId=target.stdout.trim();need(/^[A-Za-z0-9-]{1,128}$/.test(targetId),'NonrootPostApplyTarget');
 return copyNonrootJson({proxyCodeSha256:proxy.codeSha256,targetId,artifactHash:hash(value),proxy,resources:r});
}

/** Keep original raw endpoint observations. Only the two source-declared
 * additions may have a newly observed encoding of their verified policy. */
export function verifyPostApplyEndpoints(actual,{baseline,deployment,account}){
 need(Array.isArray(actual)&&actual.length===baseline.length+2&&new Set(actual.map(e=>e.VpcEndpointId)).size===actual.length,'NonrootPostApplyEndpointSet');
 for(const old of baseline){const current=actual.find(e=>e.VpcEndpointId===old.VpcEndpointId);same(current,old,'NonrootPostApplyOldEndpoint');}
 for(const key of ['Mem9GatewaySsmEndpoint','Mem9GatewaySecretsManagerEndpoint']){
  const e=deployment.resources[key],a=actual.find(x=>x.VpcEndpointId===e.id);need(a&&!baseline.some(x=>x.VpcEndpointId===e.id),'NonrootPostApplyEndpointSet');
  exact(a,['VpcEndpointId','VpcId','OwnerId','PolicyDocument','ServiceName','State','SubnetIds','Groups','VpcEndpointType','PrivateDnsEnabled','IpAddressType','DnsEntries']);need(a.OwnerId===account&&a.VpcId===e.vpcId&&a.ServiceName===e.serviceName&&a.State==='available','NonrootPostApplyEndpointReadback');same(policyDocument(a.PolicyDocument),policyDocument(e.policy),'NonrootPostApplyEndpointPolicy');same(sorted(a.SubnetIds),sorted(e.subnetIds),'NonrootPostApplyEndpointNetwork');same(a.Groups.map(g=>g.GroupId).sort(),sorted(e.securityGroupIds),'NonrootPostApplyEndpointNetwork');need(a.VpcEndpointType===e.vpcEndpointType&&a.PrivateDnsEnabled===e.privateDnsEnabled&&a.IpAddressType===e.ipAddressType,'NonrootPostApplyEndpointNetwork');same(a.DnsEntries.map(d=>({dnsName:d.DnsName,hostedZoneId:d.HostedZoneId})).sort((a,b)=>a.dnsName.localeCompare(b.dnsName)),e.dnsEntries.toSorted((a,b)=>a.dnsName.localeCompare(b.dnsName)),'NonrootPostApplyEndpointNetwork');
 }
 return hash(actual);
}

export function rootSecurityGroupProjection(groups){
 need(Array.isArray(groups)&&groups.length<=3,'NonrootPostApplyGroups');
 const permissions=rows=>rows.flatMap(p=>[
  ...(p.UserIdGroupPairs??[]).map(g=>({protocol:p.IpProtocol,from:p.FromPort??null,to:p.ToPort??null,group:g.GroupId,owner:g.UserId??null,peering:g.VpcPeeringConnectionId??null})),
  ...(p.IpRanges??[]).map(r=>({protocol:p.IpProtocol,from:p.FromPort??null,to:p.ToPort??null,ipv4:r.CidrIp})),
  ...(p.Ipv6Ranges??[]).map(r=>({protocol:p.IpProtocol,from:p.FromPort??null,to:p.ToPort??null,ipv6:r.CidrIpv6})),
  ...(p.PrefixListIds??[]).map(r=>({protocol:p.IpProtocol,from:p.FromPort??null,to:p.ToPort??null,prefix:r.PrefixListId})),
 ]).sort((a,b)=>hash(a).localeCompare(hash(b)));
 return groups.map(g=>({id:g.GroupId,vpc:g.VpcId,owner:g.OwnerId,ingress:permissions(g.IpPermissions??[]),egress:permissions(g.IpPermissionsEgress??[])})).sort((a,b)=>a.id.localeCompare(b.id));
}
export function verifyPostApplySecurityGroups(groups,{baseline,oldProxySecurityGroupIds,backendSecurityGroupId,deployment,account}){
 const actual=rootSecurityGroupProjection(groups),before=rootSecurityGroupProjection(baseline),r=deployment.resources,proxy=r.Mem9GatewayProxySg.id,endpoint=r.Mem9GatewaySecretEndpointSg.id;
 const expectedIds=sorted([backendSecurityGroupId,proxy,endpoint]);same(actual.map(g=>g.id),expectedIds,'NonrootPostApplyGroups');
 need(actual.every(g=>g.owner===account&&g.vpc===r.Mem9GatewayProxySg.vpcId),'NonrootPostApplyGroupOwner');
 const pair=(group,port)=>({protocol:'tcp',from:port,to:port,group,owner:account,peering:null}),order=rows=>rows.sort((a,b)=>hash(a).localeCompare(hash(b)));
 const p=actual.find(g=>g.id===proxy),e=actual.find(g=>g.id===endpoint),b=actual.find(g=>g.id===backendSecurityGroupId),old=before.find(g=>g.id===backendSecurityGroupId);need(old,'NonrootPostApplyBaselineGroup');
 same(p.ingress,[],'NonrootPostApplyProxyIngress');same(p.egress,order([pair(backendSecurityGroupId,8080),pair(endpoint,443)]),'NonrootPostApplyProxyEgress');same(e.ingress,[pair(proxy,443)],'NonrootPostApplyEndpointIngress');same(e.egress,[],'NonrootPostApplyEndpointEgress');
 const retained=old.ingress.filter(x=>!(x.protocol==='tcp'&&x.from===8080&&x.to===8080&&oldProxySecurityGroupIds.includes(x.group)&&x.owner===account&&x.peering===null));
 same(b.ingress,order([...retained,pair(proxy,8080)]),'NonrootPostApplyBackendIngress');same(b.egress,old.egress,'NonrootPostApplyBackendEgress');return true;
}
export function verifyPostApplyProxyConfiguration(lambda,deployment){
 const f=deployment.proxy;need(lambda.FunctionArn===f.arn&&lambda.CodeSha256===f.codeSha256&&lambda.Role===f.role.arn&&lambda.Runtime===f.runtime&&lambda.State==='Active'&&lambda.LastUpdateStatus==='Successful','NonrootPostApplyProxyReadback');
 same(projectNonrootPostApplyEnvironment('Mem9ProxyFn',lambda.Environment?.Variables),f.environment,'NonrootPostApplyProxyEnvironment');same(sorted(lambda.VpcConfig?.SecurityGroupIds??[]),sorted(f.vpcConfig.securityGroupIds),'NonrootPostApplyProxyVpc');same(sorted(lambda.VpcConfig?.SubnetIds??[]),sorted(f.vpcConfig.subnetIds),'NonrootPostApplyProxyVpc');return true;
}
