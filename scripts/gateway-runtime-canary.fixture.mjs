import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {crc32,deflateRawSync} from 'node:zlib';
import vm from 'node:vm';
import {compileGatewayRuntimeCanaryScope,renderGatewayRuntimeCanaryTemplate,gatewayCanaryDocumentHash as hash} from './lib/gateway-runtime-canary-resources.mjs';
import {expectedGatewayBoundaryPolicyDocument} from './lib/gateway-workload-boundary.mjs';
import {GATEWAY_CANARY_PLAINTEXT,gatewayCanaryInvocation} from './lib/gateway-runtime-canary-evidence.mjs';
export const handlerSource=readFileSync(new URL('./test-fixtures/gateway-runtime-canary/handler.cjs',import.meta.url),'utf8');
export const sha=v=>createHash('sha256').update(v).digest('hex');
export function codeZip(source=handlerSource,name='index.js'){
 const raw=Buffer.from(source),n=Buffer.from(name),compressed=deflateRawSync(raw),local=Buffer.alloc(30),central=Buffer.alloc(46),end=Buffer.alloc(22),crc=crc32(raw);
 local.writeUInt32LE(0x04034b50);local.writeUInt16LE(20,4);local.writeUInt16LE(8,8);local.writeUInt32LE(crc,14);local.writeUInt32LE(compressed.length,18);local.writeUInt32LE(raw.length,22);local.writeUInt16LE(n.length,26);
 central.writeUInt32LE(0x02014b50);central.writeUInt16LE(20,4);central.writeUInt16LE(20,6);central.writeUInt16LE(8,10);central.writeUInt32LE(crc,16);central.writeUInt32LE(compressed.length,20);central.writeUInt32LE(raw.length,24);central.writeUInt16LE(n.length,28);
 end.writeUInt32LE(0x06054b50);end.writeUInt16LE(1,8);end.writeUInt16LE(1,10);end.writeUInt32LE(central.length+n.length,12);end.writeUInt32LE(local.length+n.length+compressed.length,16);
 return Buffer.concat([local,n,compressed,central,n,end]);
}
export function harness({phase='A1',defect,number=1,clock=Date.now(),event:providedEvent,environment={}}={}){
 const scope=compileGatewayRuntimeCanaryScope({accountId:'0'.repeat(12),applicationRegion:'ap-northeast-1',verificationId:'abcdef012345',vpcId:'vpc-12345678',ownerRoleArn:'arn:aws:iam::'+'0'.repeat(12)+':role/synthetic-scoped-owner'}),keyArn=scope.keyArnPattern.replace('*','a'.repeat(8)+'-'+['a'.repeat(4),'a'.repeat(4),'a'.repeat(4),'a'.repeat(12)].join('-'));
 const event=providedEvent??gatewayCanaryInvocation({nonce:'b'.repeat(64),ciphertextBase64:Buffer.from('synthetic encrypted test bytes').toString('base64')});
 const calls=[],closed=[],plaintext=Buffer.from(GATEWAY_CANARY_PLAINTEXT);let at=clock;
 const metadata=(service,status)=>({requestId:`service-${service}-${number}-request`,httpStatusCode:status,attempts:1});
 const command=class{constructor(input){this.input=input;}};
 function client(service){return class{constructor(options){this.options=options;}async send(c,options){calls.push({service,input:c.input,client:this.options,options});
  if(defect==='network')throw Error('synthetic network');
  if(defect==='missing-id')throw Object.assign(Error('synthetic'),{name:'AccessDeniedException',$metadata:{httpStatusCode:400}});
  if(service==='kms'&&phase!=='B')return {Plaintext:defect==='plaintext'?Buffer.from('wrong synthetic bytes'):plaintext,KeyId:keyArn,EncryptionAlgorithm:'SYMMETRIC_DEFAULT',$metadata:metadata(service,200)};
  if(defect==='ec2-success')return {$metadata:metadata(service,200),Subnets:[]};
  const name=service==='kms'?'AccessDeniedException':phase==='B'?'UnauthorizedOperation':'DryRunOperation',status=service==='kms'?400:phase==='B'?403:412;
  throw Object.assign(Error('do not retain raw error, synthetic-secret'),{name: defect==='wrong-error'?'InvalidCiphertextException':name,$metadata:metadata(service,status)});
 }destroy(){closed.push(service);}};}
 const sandbox={exports:{},Buffer,Uint8Array,AbortController,setTimeout,clearTimeout,Date:{now:()=>++at},process:{arch:'arm64',version:'v24.1.0',env:{AWS_REGION:scope.applicationRegion,AWS_LAMBDA_FUNCTION_NAME:scope.functionName,AWS_ACCESS_KEY_ID:'ASIA'+'A'.repeat(16),AWS_SECRET_ACCESS_KEY:'s'.repeat(40),AWS_SESSION_TOKEN:'synthetic-token',CANARY_KEY_ARN:keyArn,CANARY_VPC_ID:scope.vpcId,...environment}},require(name){if(name==='node:crypto')return {createHash};if(name==='@aws-sdk/client-kms')return {KMSClient:client('kms'),DecryptCommand:command};if(name==='@aws-sdk/client-ec2')return {EC2Client:client('ec2'),DescribeSubnetsCommand:command};if(name.endsWith('/package.json'))return {version:'3.1143.0'};throw Error('UnexpectedImport');}};
 vm.runInNewContext(handlerSource,sandbox,{filename:'index.js'});
 const context={invokedFunctionArn:scope.functionArn,awsRequestId:`lambda-invocation-${number}`,getRemainingTimeInMillis:()=>30000};
 return {scope,keyArn,event,context,sandbox,calls,closed,plaintext,async run(){return JSON.parse(JSON.stringify(await sandbox.exports.handler(event,context)));},get now(){return at;}};
}

export async function evidenceFixture(){
 const first=harness(),{scope,keyArn,event:request}=first,originalBoundary=expectedGatewayBoundaryPolicyDocument({partition:'aws',accountId:scope.accountId,applicationRegion:scope.applicationRegion,policyRevision:'r1'}),plan=renderGatewayRuntimeCanaryTemplate({scope,originalBoundary,handlerSource}),zip=codeZip(),codeSha256=createHash('sha256').update(zip).digest('base64');
 const resolve=v=>Array.isArray(v)?v.map(resolve):v&&typeof v==='object'?v['Fn::GetAtt']?v['Fn::GetAtt'][0]==='SyntheticKey'?keyArn:scope.roleArn:Object.fromEntries(Object.entries(v).map(([k,x])=>[k,resolve(x)])):v;
 let tick=Date.now();const startedMs=tick;
 function readback(phase){const start=++tick;return {startedMs:start,completedMs:++tick,function:{FunctionArn:scope.functionArn,Runtime:'nodejs24.x',Architectures:['arm64'],Handler:'index.handler',Role:scope.roleArn,CodeSha256:codeSha256,State:'Active',LastUpdateStatus:'Successful',Environment:{Variables:{CANARY_KEY_ARN:keyArn,CANARY_VPC_ID:scope.vpcId}},RevisionId:'synthetic-code-revision'},role:{Arn:scope.roleArn,RoleId:'AROASYNTHETIC0000001',AssumeRolePolicyDocument:plan.template.Resources.CanaryRole.Properties.AssumeRolePolicyDocument,Tags:plan.template.Resources.CanaryRole.Properties.Tags,PermissionsBoundary:{PermissionsBoundaryArn:phase==='B'?scope.originalBoundaryArn:scope.comparisonArn}},identityPolicy:resolve(plan.template.Resources.CanaryIdentityPolicy.Properties.PolicyDocument),attachedPolicies:[],boundary:{arn:phase==='B'?scope.originalBoundaryArn:scope.comparisonArn,versionId:'v1',document:phase==='B'?originalBoundary:plan.comparison.document},key:{Arn:keyArn,KeyId:keyArn.split('/').at(-1),Enabled:true,KeyState:'Enabled',KeyManager:'CUSTOMER',KeyUsage:'ENCRYPT_DECRYPT',KeySpec:'SYMMETRIC_DEFAULT'},keyPolicy:resolve(plan.template.Resources.SyntheticKey.Properties.KeyPolicy),keyGrants:[]};}
 const rounds=[];for(const [i,phase]of ['A1','B','A2'].entries()){
  const before=readback(phase),start=++tick,h=harness({phase,number:i+1,clock:tick,event:request}),result=await h.run();tick=h.now+1;
  const invoke={startedMs:start,completedMs:tick,request:{FunctionName:scope.functionArn,InvocationType:'RequestResponse',Payload:Buffer.from(JSON.stringify(request)).toString('base64')},response:{StatusCode:200,ExecutedVersion:'$LATEST',$metadata:{httpStatusCode:200,requestId:`invoke-sdk-request-${i+1}`},Payload:Buffer.from(JSON.stringify(result)).toString('base64')}};
  rounds.push({phase,before,invoke,after:readback(phase)});
 }
 const evidence={version:1,kind:'gateway-runtime-canary-evidence',scope,originalBoundary,handlerSource,codeZipBase64:zip.toString('base64'),keyArn,request,startedMs,completedMs:++tick,rounds},expected={evidenceHash:hash(evidence),handlerHash:plan.handlerHash,originalBoundaryHash:plan.comparison.originalHash,comparisonBoundaryHash:plan.comparison.comparisonHash};
 return {evidence,expected,plan,hash,zip,scope};
}
