import {inspectCiOwnerTargetRequest,ciOwnerPostApplyDeployment} from './lib/ci-smoke-allowance-owner.mjs';
import {it,expect,beforeAll} from 'vitest';
import {deflateRawSync} from 'node:zlib';
import {postApplyFixture,sha} from './nonroot-postapply.fixture.mjs';
import {verifyNonrootPostApplyDeployment as verify,encodeNonrootPostApplyArtifact as encode,decodeNonrootPostApplyArtifact as decode,inspectNonrootPostApplyIdentity as identity,projectNonrootPostApplyEnvironment as project,verifyPostApplyEndpoints,verifyPostApplySecurityGroups} from './lib/nonroot-postapply.mjs';
let f;beforeAll(async()=>{f=await postApplyFixture();});
for(const [key,suffix]of [['Mem9TenantApiKey','tenant-api-key'],['Mem9IdentitySigningKeys','identity-signing-keys']]){
 it('accepts the IaC-generated secret name and separate ARN suffix: '+key,()=>{
  const secret=f.value.resources[key];expect(secret.name).toBe('mem9-on-aws-prod-'+suffix+'-synthetic7f3c9a');expect(secret.arn.endsWith(':secret:'+secret.name+'-ABCDEF')).toBe(true);
  expect(verify(f.value,f.expected).resources[key]).toEqual(secret);
 });
 it.each(['foreign-prefix','wrong-arn-name','empty-name-suffix','old-unsuffixed-name'])('rejects consistently rebound generated secret %s: '+key,defect=>{
  let v=structuredClone(f.value);const secret=v.resources[key],oldArn=secret.arn,prefix='mem9-on-aws-prod-'+suffix+'-';
  if(defect==='foreign-prefix')secret.name=secret.name.replace('mem9-on-aws-prod-','mem9-on-aws-preview-');
  if(defect==='empty-name-suffix')secret.name=prefix;
  if(defect==='old-unsuffixed-name')secret.name=prefix.slice(0,-1);
  const arnName=defect==='wrong-arn-name'?secret.name+'other':secret.name,newArn=oldArn.slice(0,oldArn.indexOf(':secret:'))+':secret:'+arnName+'-ABCDEF';
  // Keep every policy/environment reference consistent: only the independently
  // checked prefix or full name/ARN relationship is wrong.
  v=JSON.parse(JSON.stringify(v).replaceAll(oldArn,newArn));expect(()=>verify(v,f.expected)).toThrow('NonrootPostApplySecret');
 });
}
it('binds actual source blob hashes, four ZIP identities and source-owned resource associations',()=>{const result=verify(f.value,f.expected);expect(result.proxyCodeSha256).toBe(f.value.functions.Mem9ProxyFn.codeSha256);expect(result.targetId).toBe('new-target-id');expect(decode(encode(f.value))).toEqual(f.value);});
it.each([
 ['extra resource',v=>v.resources.unreviewed={}],['extra nested field',v=>v.resources.Mem9GatewaySsmEndpoint.extra=true],
 ['wrong role family',v=>v.functions.Mem9OauthFacadeFn.role.name='another-role'],['wrong function',v=>v.functions.Mem9OauthFacadeFn.arn=v.functions.Mem9ProxyFn.arn],
 ['wrong ZIP',v=>v.functions.Mem9ProxyFn.zip.sha256='f'.repeat(64)],['wrong source',v=>v.sourceFiles[0].oid='f'.repeat(40)],
 ['ordinary boundary on gateway',v=>v.functions.Mem9ProxyFn.role.permissionsBoundary=f.expected.boundaryArn],
 ['extra trust statement',v=>v.functions.Mem9ProxyFn.role.assumeRolePolicy.Statement.push(v.functions.Mem9ProxyFn.role.assumeRolePolicy.Statement[0])],
 ['missing permission',v=>v.functions.Mem9ProxyFn.role.inlinePolicies[0].policy.Statement.shift()],
 ['missing decryption',v=>v.functions.Mem9ProxyFn.role.inlinePolicies[0].policy.Statement=v.functions.Mem9ProxyFn.role.inlinePolicies[0].policy.Statement.filter(s=>s.Action!=='kms:Decrypt')],
 ['extra policy condition',v=>v.functions.Mem9ProxyFn.role.inlinePolicies[0].policy.Statement[1].Condition.StringEquals.other='yes'],
 ['identity principal injection',v=>v.functions.Mem9ProxyFn.role.inlinePolicies[0].policy.Statement[0].Principal='*'],
 ['wildcard resource',v=>v.functions.Mem9ProxyFn.role.inlinePolicies[0].policy.Statement[0].Resource=['*']],
 ['changed gateway invocation',v=>v.resources.Mem9GatewayInvokeLambda.policy.Statement[0].Resource=['*']],
 ['unrelated secret',v=>v.resources.Mem9TenantApiKey.name='other'],['wrong target region',v=>v.resources.Mem9GatewayTarget.environment.MEM9_TGT_REGION='us-west-2'],
 ['unapproved environment',v=>v.functions.Mem9ProxyFn.environment.NODE_OPTIONS='--import /tmp/code.mjs'],
 ['wrong auth endpoint',v=>v.functions.Mem9OauthFacadeFn.environment.COGNITO_TOKEN_ENDPOINT='https://other.example.com'],
 ['SG open egress',v=>v.resources.Mem9GatewayProxySg.egress[0].cidrBlocks=['0.0.0.0/0']],
 ['extra endpoint principal',v=>v.resources.Mem9GatewaySsmEndpoint.policy.Statement[0].Principal.AWS='*'],
])('rejects %s without accepting newly rehashed material',(_,change)=>{const v=structuredClone(f.value);change(v);expect(()=>verify(v,f.expected)).toThrow();});
it('never serializes the SST encryption key and rejects unknown environment names',()=>{const base=f.value.functions.Mem9ProxyFn.environment,env={...base,SST_RESOURCE_App:JSON.stringify({name:'mem9-on-aws',stage:'prod'}),SST_KEY:'synthetic-private-key',SST_KEY_FILE:'resource.enc'};expect(project('Mem9ProxyFn',env)).toEqual(base);expect(JSON.stringify(project('Mem9ProxyFn',env))).not.toContain('synthetic-private-key');expect(()=>project('Mem9ProxyFn',{...env,AWS_SECRET_ACCESS_KEY:'synthetic'})).toThrow();});
it.each(['digest','trailing','bomb','noncanonical'])('bounded codec rejects %s',defect=>{const e=encode(f.value);if(defect==='digest')e.sha256='0'.repeat(64);if(defect==='trailing'){const raw=Buffer.concat([Buffer.from(e.body,'base64'),Buffer.from('trailing')]);e.body=raw.toString('base64');e.compressedBytes=raw.length;}if(defect==='bomb'){const raw=Buffer.alloc(300000,32),c=deflateRawSync(raw);e.body=c.toString('base64');e.compressedBytes=c.length;e.bytes=262144;e.sha256=sha(raw);}if(defect==='noncanonical')e.body+='\n';expect(()=>decode(e)).toThrow();});
it.each(['run','attempt','phase','expired'])('binds %s to the original run/checkpoint/deadline',defect=>{const v=structuredClone(f.value),binding={source:{repository:v.source.repository,runId:v.source.runId,runAttempt:v.source.runAttempt,mainRevision:v.source.revision,mainTree:v.source.tree}},config={startup:{...v.source,notAfter:Date.now()+10000}},scope={route:'deploy-prod',checkpoint:'deploy-prod/21',phase:'preupdate'};identity(v,{binding,config,scope,now:Date.now()});if(defect==='run')v.source.runId++;if(defect==='attempt')v.source.runAttempt++;if(defect==='phase')scope.phase='prereadiness';if(defect==='expired')config.startup.notAfter=1;expect(()=>identity(v,{binding,config,scope,now:Date.now()})).toThrow();});
it('live endpoint population retains every old endpoint and rejects extras',()=>{const d=verify(f.value,f.expected),actual=['Mem9GatewaySsmEndpoint','Mem9GatewaySecretsManagerEndpoint'].map(k=>{const e=d.resources[k];return {VpcEndpointId:e.id,VpcId:e.vpcId,OwnerId:f.expected.before.account,PolicyDocument:e.policy,ServiceName:e.serviceName,State:'available',SubnetIds:e.subnetIds,Groups:e.securityGroupIds.map(GroupId=>({GroupId})),VpcEndpointType:e.vpcEndpointType,PrivateDnsEnabled:e.privateDnsEnabled,IpAddressType:e.ipAddressType,DnsEntries:e.dnsEntries.map(d=>({DnsName:d.dnsName,HostedZoneId:d.hostedZoneId}))};});expect(verifyPostApplyEndpoints(actual,{baseline:[],deployment:d,account:f.expected.before.account})).toMatch(/^[a-f0-9]{64}$/);const changed=structuredClone(actual);changed[0].Groups=[{GroupId:'sg-ffffffff'}];expect(()=>verifyPostApplyEndpoints(changed,{baseline:[],deployment:d,account:f.expected.before.account})).toThrow('NonrootPostApplyEndpointNetwork');expect(()=>verifyPostApplyEndpoints([...actual,actual[0]],{baseline:[],deployment:d,account:f.expected.before.account})).toThrow();});
it('fresh SG census requires exact proxy/endpoint/backend rules and retained backend egress',()=>{const d=verify(f.value,f.expected),account=f.expected.before.account,p='sg-22222222',e='sg-33333333',b='sg-11111111',rule=(id,port)=>({IpProtocol:'tcp',FromPort:port,ToPort:port,UserIdGroupPairs:[{GroupId:id,UserId:account}]}),group=(id,ingress,egress)=>({GroupId:id,VpcId:'vpc-11111111',OwnerId:account,IpPermissions:ingress,IpPermissionsEgress:egress}),groups=[group(p,[],[rule(b,8080),rule(e,443)]),group(e,[rule(p,443)],[]),group(b,[rule(p,8080)],[])],expected={baseline:[group(b,[],[])],oldProxySecurityGroupIds:['sg-44444444'],backendSecurityGroupId:b,deployment:d,account};expect(verifyPostApplySecurityGroups(groups,expected)).toBe(true);groups[0].IpPermissionsEgress.push({IpProtocol:'-1',IpRanges:[{CidrIp:'0.0.0.0/0'}]});expect(()=>verifyPostApplySecurityGroups(groups,expected)).toThrow();});

it('owner verifies the entire bounded raw TARGET request and never accepts a serialized owner receipt',()=>{
 const v=f.value,scope={kind:'target',jobKey:'deploy-prod',route:'deploy-prod',checkpoint:'deploy-prod/21',phase:'preupdate'},binding={source:{repository:v.source.repository,runId:v.source.runId,runAttempt:v.source.runAttempt,mainRevision:v.source.revision,mainTree:v.source.tree}},config={version:3,startup:{...v.source,notAfter:Date.now()+10000}},receipt={nonce:'a'.repeat(64),artifactId:7,artifactDigest:'b'.repeat(64)},bindingHash=f.hash(binding),q={version:2,kind:'ci-prepaid-acquisition-request',bindingHash,scope,...receipt,sourceReceiptHash:'c'.repeat(64),postApply:encode(v)},raw=Buffer.from(JSON.stringify(q));
 expect(raw.length).toBeLessThanOrEqual(16384);expect(inspectCiOwnerTargetRequest(raw,receipt,scope,bindingHash,config,binding)).toBe(f.hash(q));
 for(const change of [q=>delete q.postApply,q=>q.version=1,q=>q.nonce='d'.repeat(64),q=>q.scope.phase='prereadiness',q=>q.extra=true,q=>{const v=structuredClone(decode(q.postApply));v.source.runAttempt++;q.postApply=encode(v);}]){const bad=structuredClone(q);change(bad);expect(()=>inspectCiOwnerTargetRequest(Buffer.from(JSON.stringify(bad)),receipt,scope,bindingHash,config,binding)).toThrow();}
 expect(()=>inspectCiOwnerTargetRequest(Buffer.concat([raw,Buffer.alloc(16384,32)]),receipt,scope,bindingHash,config,binding)).toThrow();
 for(const value of [{},{artifact:q.postApply,scope,binding,config},{phase:'owner-allowance-published',verified:true}])expect(()=>ciOwnerPostApplyDeployment(value)).toThrow('CiOwnerPostApplyReceipt');
});
