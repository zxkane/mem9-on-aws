/** Closed Gateway role family and its operator-owned boundary. This is policy
 * construction, not a caller-selected boundary or runtime authority. */
export const GATEWAY_BOUNDARY_POLICY_NAME = 'mem9-on-aws-gateway-boundary';
export const GATEWAY_ROLE_TOKENS = Object.freeze(['Mem9IdentityInterceptorFnRole', 'Mem9ProxyFnRole']);
export const GATEWAY_LOGICAL_ROLES = GATEWAY_ROLE_TOKENS;
const rolePrefixes = ['mem9-on-aws','mem9-on-aw','mem9-on-a'];
const stageVariable = '${aws:PrincipalTag/Stage}';

export function gatewayRoleStage(name) {
  if (typeof name !== 'string' || name.length > 64) return undefined;
  const match = /^(?:mem9-on-aws|mem9-on-aw|mem9-on-a)-([a-z][a-z0-9-]*)-(Mem9IdentityInterceptorFnRole|Mem9ProxyFnRole)-[A-Za-z0-9_+=,.@-]+$/.exec(name);
  return match?.[1];
}
export function gatewayRoleArnPatterns({partition, accountId}, stage = '*') {
  return GATEWAY_ROLE_TOKENS.flatMap(token => rolePrefixes.map(prefix => `arn:${partition}:iam::${accountId}:role/${prefix}-${stage}-${token}-*`));
}
export function gatewayBoundaryArn({partition, accountId}) {
  return `arn:${partition}:iam::${accountId}:policy/${GATEWAY_BOUNDARY_POLICY_NAME}`;
}

export function expectedGatewayBoundaryPolicyDocument({partition, accountId, applicationRegion: region, policyRevision = 'r1'}) {
  if (!/^[a-z0-9-]{1,16}$/.test(partition ?? '') || !/^\d{12}$/.test(accountId ?? '') ||
      !/^[a-z]{2}(?:-[a-z]+)+-\d+$/.test(region ?? '') || region.length > 24 || !/^r[0-9]{1,20}$/.test(policyRevision)) {
    throw new Error('invalid Gateway boundary contract');
  }
  const suffix = partition === 'aws-cn' ? 'amazonaws.com.cn' : 'amazonaws.com';
  const roles = gatewayRoleArnPatterns({partition, accountId}, stageVariable);
  // These suffix checks only narrow the full account/stage/family guard above
  // them. They cannot admit an additional principal on their own.
  const interceptor = '*Mem9IdentityInterceptorFnRole-*', proxy = '*Mem9ProxyFnRole-*';
  const functions = ['Mem9IdentityInterceptorFn', 'Mem9ProxyFn'].map(token => `arn:${partition}:lambda:${region}:${accountId}:function:mem9-on-aws-${stageVariable}-${token}Function-*`);
  const secrets = ['identity-signing-keys', 'tenant-api-key'].map(token => `arn:${partition}:secretsmanager:${region}:${accountId}:secret:mem9-on-aws-${stageVariable}-${token}-*`);
  const parameter = `arn:${partition}:ssm:${region}:${accountId}:parameter/mem9-on-aws/${stageVariable}/namespace/transport-signing-keys`;
  const via = ['ssm', 'secretsmanager'].map(service => `${service}.${region}.${suffix}`);
  const deny = (Action, Condition, extra = {}) => ({Effect:'Deny',Action,Resource:'*',...(Condition ? {Condition} : {}),...extra});
  const scoped = (Action, NotResource, Condition) => ({Effect:'Deny',Action,NotResource,...(Condition ? {Condition} : {})});
  const actions = ['logs:CreateLogGroup','logs:CreateLogStream','logs:PutLogEvents','secretsmanager:GetSecretValue','ssm:GetParameters','kms:Decrypt',
    'ec2:AssignPrivateIpAddresses','ec2:CreateNetworkInterface','ec2:DeleteNetworkInterface','ec2:DescribeNetworkInterfaces','ec2:DescribeSubnets','ec2:UnassignPrivateIpAddresses'];
  const document = {Version:'2012-10-17',Statement:[
    {Effect:'Allow',Action:'*',Resource:'*'},
    {Sid:`G${policyRevision}`,Effect:'Deny',NotAction:actions,Resource:'*'},
    deny('*',{ArnNotLike:{'aws:PrincipalArn':roles}}),
    deny('*',{StringNotEquals:{'aws:PrincipalTag/Project':'mem9-on-aws'}}),
    scoped('logs:*', functions.map(arn => arn.replace(`:lambda:${region}:${accountId}:function:`,`:logs:${region}:${accountId}:log-group:/aws/lambda/`))),
    scoped('secretsmanager:GetSecretValue',secrets),
    deny('secretsmanager:GetSecretValue',{StringNotEquals:{'secretsmanager:ResourceTag/Stage':stageVariable}}),
    scoped('ssm:GetParameters',parameter),
    deny('ssm:GetParameters',{StringNotEquals:{'ssm:resourceTag/Stage':stageVariable}}),
    deny('ssm:GetParameters',{StringLike:{'aws:PrincipalArn':interceptor}}),
    deny('secretsmanager:GetSecretValue',{StringLike:{'aws:PrincipalArn':interceptor}},{Resource:secrets[1]}),
    scoped('kms:Decrypt',`arn:${partition}:kms:${region}:${accountId}:key/*`),
    deny('kms:Decrypt',{StringNotLikeIfExists:{'kms:EncryptionContext:SecretARN':secrets,'kms:EncryptionContext:PARAMETER_ARN':parameter,'kms:EncryptionContext:aws:lambda:FunctionArn':functions}}),
    deny('kms:Decrypt',{StringNotEqualsIfExists:{'kms:ViaService':via},StringNotLikeIfExists:{'kms:EncryptionContext:aws:lambda:FunctionArn':functions}}),
    ...[['SecretARN',via[1]],['PARAMETER_ARN',via[0]]].map(([key,service])=>deny('kms:Decrypt',{Null:{['kms:EncryptionContext:'+key]:'false'},StringNotEqualsIfExists:{'kms:ViaService':service}})),
    deny('kms:Decrypt',{StringLike:{'aws:PrincipalArn':interceptor,'kms:EncryptionContext:SecretARN':secrets[1]}}),
    deny('kms:Decrypt',{StringLike:{'aws:PrincipalArn':interceptor},Null:{'kms:EncryptionContext:PARAMETER_ARN':'false'}}),
    deny('kms:Decrypt',{Null:{'lambda:SourceFunctionArn':'false'},StringNotEqualsIfExists:{'kms:ViaService':via}}),
    deny('ec2:*',{StringNotLike:{'aws:PrincipalArn':proxy}}),
    deny('ec2:*',{Null:{'lambda:SourceFunctionArn':'false'}}),
  ]};
  if (JSON.stringify(document).length > 6144) throw new Error('Gateway boundary exceeds IAM policy quota');
  return document;
}

/** Fixed IAM simulation inputs, never observations or a production grant. */
export function gatewayBoundaryProbeCases(contract) {
  expectedGatewayBoundaryPolicyDocument(contract);
  const {partition,accountId,applicationRegion:region}=contract;
  const resource=`arn:${partition}:kms:${region}:${accountId}:key/00000000-0000-0000-0000-${"0".repeat(11)}1`;
  const via=`secretsmanager.${region}.${partition==='aws-cn'?'amazonaws.com.cn':'amazonaws.com'}`;
  const cases=[];
  for(const stage of ['prod','pr-7']) {
    const role=token=>`arn:${partition}:iam::${accountId}:role/mem9-on-aws-${stage}-${token}-fixture`;
    const secret=token=>`arn:${partition}:secretsmanager:${region}:${accountId}:secret:mem9-on-aws-${stage}-${token}-fixture`;
    const base={'aws:PrincipalArn':role('Mem9ProxyFnRole'),'aws:PrincipalTag/Project':'mem9-on-aws','aws:PrincipalTag/Stage':stage,'kms:ViaService':via,'kms:EncryptionContext:SecretARN':secret('identity-signing-keys')};
    const add=(name,expected,context,selectedResource=resource)=>cases.push({name:stage+'/'+name,expected,resource:selectedResource,context:Object.entries(context).map(([key,value])=>`ContextKeyName=${key},ContextKeyType=string,ContextKeyValues=${value}`)});
    add('proxy-identity','allowed',base);
    add('proxy-tenant','allowed',{...base,'kms:EncryptionContext:SecretARN':secret('tenant-api-key')});
    add('interceptor-identity','allowed',{...base,'aws:PrincipalArn':role('Mem9IdentityInterceptorFnRole')});
    add('interceptor-tenant','explicitDeny',{...base,'aws:PrincipalArn':role('Mem9IdentityInterceptorFnRole'),'kms:EncryptionContext:SecretARN':secret('tenant-api-key')});
    add('ecs-identity','explicitDeny',{...base,'aws:PrincipalArn':role('Mem9ServerExecutionRole')});
    add('wrong-secret','explicitDeny',{...base,'kms:EncryptionContext:SecretARN':secret('Mem9DbSecret')});
    add('wrong-stage','explicitDeny',{...base,'aws:PrincipalTag/Stage':stage==='prod'?'pr-7':'prod'});
    add('wrong-key-account','explicitDeny',base,resource.replace(accountId,'0'.repeat(12)));
    const direct={...base};delete direct['kms:ViaService'];add('direct-kms','explicitDeny',direct);
    const missing={...base};delete missing['aws:PrincipalTag/Stage'];add('missing-stage','explicitDeny',missing);
    const transport={...base,'kms:ViaService':via.replace('secretsmanager.','ssm.'),'kms:EncryptionContext:PARAMETER_ARN':`arn:${partition}:ssm:${region}:${accountId}:parameter/mem9-on-aws/${stage}/namespace/transport-signing-keys`};
    delete transport['kms:EncryptionContext:SecretARN'];add('proxy-transport','allowed',transport);
    add('interceptor-transport','explicitDeny',{...transport,'aws:PrincipalArn':role('Mem9IdentityInterceptorFnRole')});
    for(const token of ['Mem9ProxyFn','Mem9IdentityInterceptorFn']) {
      const fn=`arn:${partition}:lambda:${region}:${accountId}:function:mem9-on-aws-${stage}-${token}Function-fixture`;
      const cold={'aws:PrincipalArn':role(token+'Role'),'aws:PrincipalTag/Project':'mem9-on-aws','aws:PrincipalTag/Stage':stage,'kms:EncryptionContext:aws:lambda:FunctionArn':fn};
      add(token+'/cold-start','allowed',cold);
      add(token+'/direct-forged-lambda','explicitDeny',{...cold,'lambda:SourceFunctionArn':fn});
    }
  }
  return cases;
}

/** Source predicates require actual Lambda credentials. Preserve every
 * original case/expectation; dispatch only these four cases to the native gate. */
export function gatewayBoundaryVerificationPlan(contract){
  const all=gatewayBoundaryProbeCases(contract),runtime=all.filter(p=>p.context.some(c=>c.startsWith('ContextKeyName=lambda:SourceFunctionArn,')));
  if(runtime.length!==4||runtime.some(p=>p.expected!=='explicitDeny'))throw Error('GatewayRuntimeCaseCoverage');
  return {simulation:all.filter(p=>!runtime.includes(p)),runtime};
}
