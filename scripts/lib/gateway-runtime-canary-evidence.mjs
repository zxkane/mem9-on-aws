import {createHash} from 'node:crypto';
import {inflateRawSync,crc32} from 'node:zlib';
import {compileGatewayRuntimeCanaryScope,renderGatewayRuntimeCanaryTemplate,gatewayCanaryDocumentHash as hash} from './gateway-runtime-canary-resources.mjs';

export const GATEWAY_CANARY_PLAINTEXT='mem9-gateway-runtime-canary-v1';
const sha=b=>createHash('sha256').update(b).digest('hex');
const need=(ok,reason)=>{if(!ok)throw Error('GatewayRuntimeEvidence'+reason);};
const same=(a,b,reason)=>need(hash(a)===hash(b),reason);
const exact=(v,keys)=>need(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===keys.toSorted().join(),'Fields');
const hex=v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
const id=v=>typeof v==='string'&&/^[A-Za-z0-9-]{8,128}$/.test(v);
const time=v=>Number.isSafeInteger(v)&&v>0;
const doc=v=>typeof v==='string'?JSON.parse(v):v;
const freeze=v=>{if(v&&typeof v==='object'){Object.values(v).forEach(freeze);Object.freeze(v);}return v;};
const bytes=(text,maximum)=>{need(typeof text==='string'&&text.length<=4*Math.ceil(maximum/3),'Bytes');const raw=Buffer.from(text,'base64');need(raw.length>0&&raw.length<=maximum&&raw.toString('base64')===text,'Bytes');return raw;};

export function gatewayCanaryInvocation(input){
 exact(input,['nonce','ciphertextBase64']);need(hex(input.nonce),'Nonce');bytes(input.ciphertextBase64,6144);
 return freeze({version:1,nonce:input.nonce,ciphertextBase64:input.ciphertextBase64});
}

/** Validate actual GetFunction ZIP bytes against CodeSha256 and the reviewed
 * inline handler. Only CloudFormation's single index.js entry is executable. */
export function verifyGatewayCanaryCode(zip,handlerSource,codeSha256){
 need(Buffer.isBuffer(zip)&&zip.length>=98&&zip.length<=65536&&typeof handlerSource==='string'&&Buffer.byteLength(handlerSource)<=24000,'CodeBytes');
 need(sha(zip)===Buffer.from(codeSha256??'','base64').toString('hex'),'CodeSha256');
 let end=-1;for(let i=zip.length-22;i>=Math.max(0,zip.length-65557);i--)if(zip.readUInt32LE(i)===0x06054b50&&i+22+zip.readUInt16LE(i+20)===zip.length){end=i;break;}
 need(end>=0&&zip.readUInt16LE(end+4)===0&&zip.readUInt16LE(end+6)===0&&zip.readUInt16LE(end+8)===1&&zip.readUInt16LE(end+10)===1,'CodeArchive');
 const central=zip.readUInt32LE(end+16),centralSize=zip.readUInt32LE(end+12);need(central+centralSize===end&&centralSize>=46&&zip.readUInt32LE(central)===0x02014b50,'CodeArchive');
 const flags=zip.readUInt16LE(central+8),method=zip.readUInt16LE(central+10),crc=zip.readUInt32LE(central+16),compressed=zip.readUInt32LE(central+20),length=zip.readUInt32LE(central+24),nameLength=zip.readUInt16LE(central+28),extra=zip.readUInt16LE(central+30),comment=zip.readUInt16LE(central+32);
 need((flags&~0x808)===0&&[0,8].includes(method)&&length<=24000&&centralSize===46+nameLength+extra+comment&&zip.readUInt32LE(central+42)===0&&zip.readUInt16LE(central+34)===0,'CodeArchive');
 need(zip.subarray(central+46,central+46+nameLength).toString()==='index.js'&&zip.readUInt32LE(0)===0x04034b50&&zip.readUInt16LE(6)===flags&&zip.readUInt16LE(8)===method,'CodeEntry');
 const localName=zip.readUInt16LE(26),localExtra=zip.readUInt16LE(28),offset=30+localName+localExtra;
 need(localName===nameLength&&zip.subarray(30,30+localName).toString()==='index.js'&&offset+compressed<=central,'CodeEntry');
 if(flags&8){let at=offset+compressed;if(zip.readUInt32LE(at)===0x08074b50)at+=4;need(at+12===central&&zip.readUInt32LE(at)===crc&&zip.readUInt32LE(at+4)===compressed&&zip.readUInt32LE(at+8)===length,'CodeDescriptor');}
 else need(offset+compressed===central&&zip.readUInt32LE(14)===crc&&zip.readUInt32LE(18)===compressed&&zip.readUInt32LE(22)===length,'CodeEntry');
 const body=zip.subarray(offset,offset+compressed),inflated=method===8?inflateRawSync(body,{maxOutputLength:24000,info:true}):null,raw=inflated?inflated.buffer:body;
 if(inflated)need(inflated.engine.bytesWritten===compressed,'CodeTrailingData');
 need(raw.length===length&&crc32(raw)===crc&&raw.equals(Buffer.from(handlerSource)),'HandlerBytes');
 return freeze({handlerHash:sha(raw),codeSha256,zipHash:sha(zip)});
}

export function validateGatewayCanaryResult(value,{scope,keyArn,request,phase}){
 exact(value,['version','kind','verificationId','functionArn','functionName','invocationRequestId','nonce','keyArn','vpcId','ciphertextHash','eventHash','runtime','startedMs','completedMs','results']);
 need(value.version===1&&value.kind==='gateway-runtime-canary-observation'&&['A1','B','A2'].includes(phase),'Kind');
 need(value.verificationId===scope.verificationId&&value.functionArn===scope.functionArn&&value.functionName===scope.functionName&&value.keyArn===keyArn&&value.vpcId===scope.vpcId&&value.nonce===request.nonce&&value.ciphertextHash===sha(bytes(request.ciphertextBase64,6144))&&value.eventHash===hash(request),'InvocationBinding');
 need(id(value.invocationRequestId)&&time(value.startedMs)&&time(value.completedMs)&&value.completedMs>=value.startedMs&&value.completedMs-value.startedMs<=30000,'InvocationTime');
 exact(value.runtime,['node','architecture','sdk']);exact(value.runtime.sdk,['kms','ec2']);need(/^v24\.\d+\.\d+$/.test(value.runtime.node)&&value.runtime.architecture==='arm64'&&Object.values(value.runtime.sdk).every(v=>/^3\.\d+\.\d+$/.test(v)),'Runtime');
 const requests={kms:{KeyId:keyArn,CiphertextBlob:request.ciphertextBase64,EncryptionAlgorithm:'SYMMETRIC_DEFAULT',EncryptionContext:{'aws:lambda:FunctionArn':scope.functionArn}},ec2:{DryRun:true,Filters:[{Name:'vpc-id',Values:[scope.vpcId]}]}};
 need(Array.isArray(value.results)&&value.results.length===2,'Results');let previous=value.startedMs;
 for(const [i,service]of ['kms','ec2'].entries()){
  const r=value.results[i],success=service==='kms'&&phase!=='B';
  exact(r,['service','action','requestHash','outcome','requestId','httpStatus','startedMs','completedMs',...(success?['plaintextHash']:['errorCode'])]);
  need(r.service===service&&r.action===(service==='kms'?'Decrypt':'DescribeSubnets')&&r.requestHash===hash(requests[service])&&id(r.requestId),'ServiceBinding');
  need(time(r.startedMs)&&time(r.completedMs)&&r.startedMs>=previous&&r.completedMs>=r.startedMs&&r.completedMs<=value.completedMs,'ServiceTime');previous=r.completedMs;
  if(success)need(r.outcome==='success'&&r.httpStatus===200&&r.plaintextHash===sha(GATEWAY_CANARY_PLAINTEXT),'PositiveControl');
  else need(r.outcome==='service-error'&&r.httpStatus===(service==='kms'?400:service==='ec2'&&phase!=='B'?412:403)&&r.errorCode===(service==='kms'?'AccessDeniedException':phase==='B'?'UnauthorizedOperation':'DryRunOperation'),'ServiceAuthorization');
 }
 return value;
}

/** Direct callback for runGatewayRuntimeCanaryLifecycle. The native adapter
 * owns readState's provenance; its independently retained before/after hashes
 * are not fields selected by this Lambda's payload. */
export function verifyGatewayCanaryPhase(evidence,{phase,scope,reference,before,after,plan}){
 exact(evidence,['version','kind','request','invoke']);need(evidence.version===1&&evidence.kind==='gateway-runtime-canary-phase','Phase');
 same(scope,plan.scope,'Scope');same(before,after,'StateDrift');
 const boundaryArn=phase==='B'?scope.originalBoundaryArn:scope.comparisonArn;
 same(before,{...reference,boundaryArn},'StateDrift');need(before.handlerHash===plan.handlerHash&&before.originalPolicyHash===plan.comparison.originalHash&&before.comparisonPolicyHash===plan.comparison.comparisonHash,'SourcePolicy');
 const request=gatewayCanaryInvocation({nonce:evidence.request.nonce,ciphertextBase64:evidence.request.ciphertextBase64});same(evidence.request,request,'Request');
 const invoke=evidence.invoke;exact(invoke,['startedMs','completedMs','request','response']);
 need(time(invoke.startedMs)&&time(invoke.completedMs)&&invoke.completedMs>=invoke.startedMs&&invoke.completedMs-invoke.startedMs<=45000,'InvokeTime');
 same(invoke.request,{FunctionName:scope.functionArn,InvocationType:'RequestResponse',Payload:Buffer.from(JSON.stringify(request)).toString('base64')},'InvokeRequest');
 const response=invoke.response;need(response.StatusCode===200&&!Object.hasOwn(response,'FunctionError')&&response.ExecutedVersion==='$LATEST'&&id(response.$metadata?.requestId)&&response.$metadata.httpStatusCode===200,'InvokeResponse');
 const result=validateGatewayCanaryResult(JSON.parse(bytes(response.Payload,16384).toString()),{scope,keyArn:reference.keyArn,request,phase});
 need(result.startedMs>=invoke.startedMs&&result.completedMs<=invoke.completedMs,'InvokeTime');
 return freeze({version:1,kind:'gateway-runtime-canary-phase-validation',authority:false,phase,evidenceHash:hash(evidence),stateHash:hash(before),requestHash:hash(request),ciphertextHash:result.ciphertextHash,nonce:result.nonce,invocationRequestId:result.invocationRequestId,serviceRequestIds:result.results.map(r=>r.requestId),runtime:structuredClone(result.runtime)});
}

/** Deterministic semantic validation, NOT an authority constructor. expected's
 * hashes must be retained independently by the scoped operator from its native
 * read/invoke journal and reviewed source. A JSON `pass` cannot replace them. */
export function validateGatewayRuntimeCanaryEvidence(evidence,expected){
 exact(expected,['evidenceHash','handlerHash','originalBoundaryHash','comparisonBoundaryHash']);need(Object.values(expected).every(hex),'IndependentPins');
 exact(evidence,['version','kind','scope','originalBoundary','handlerSource','codeZipBase64','keyArn','request','startedMs','completedMs','rounds']);
 need(evidence.version===1&&evidence.kind==='gateway-runtime-canary-evidence'&&hash(evidence)===expected.evidenceHash,'EvidencePin');
 const {scope,originalBoundary,handlerSource,keyArn,request,rounds}=evidence;
 same(scope,compileGatewayRuntimeCanaryScope(Object.fromEntries(['accountId','applicationRegion','verificationId','vpcId','ownerRoleArn'].map(k=>[k,scope[k]]))),'Scope');
 const plan=renderGatewayRuntimeCanaryTemplate({scope,originalBoundary,handlerSource});
 need(plan.handlerHash===expected.handlerHash&&plan.comparison.originalHash===expected.originalBoundaryHash&&plan.comparison.comparisonHash===expected.comparisonBoundaryHash,'SourcePolicy');
 need(new RegExp('^arn:aws:kms:'+scope.applicationRegion+':'+scope.accountId+':key/[a-f0-9-]{36}$').test(keyArn),'Key');
 same(request,gatewayCanaryInvocation({nonce:request.nonce,ciphertextBase64:request.ciphertextBase64}),'Request');
 need(time(evidence.startedMs)&&time(evidence.completedMs)&&evidence.completedMs>=evidence.startedMs&&evidence.completedMs-evidence.startedMs<=1200000&&rounds?.length===3,'Window');
 const zip=bytes(evidence.codeZipBase64,65536),codeSha256=createHash('sha256').update(zip).digest('base64');verifyGatewayCanaryCode(zip,handlerSource,codeSha256);
 const resolve=v=>Array.isArray(v)?v.map(resolve):v&&typeof v==='object'?v['Fn::GetAtt']?v['Fn::GetAtt'][0]==='SyntheticKey'?keyArn:scope.roleArn:Object.fromEntries(Object.entries(v).map(([k,x])=>[k,resolve(x)])):v;
 const expectedIdentity=resolve(plan.template.Resources.CanaryIdentityPolicy.Properties.PolicyDocument),expectedKeyPolicy=resolve(plan.template.Resources.SyntheticKey.Properties.KeyPolicy);
 const ids=new Set(),invokeIds=new Set(),versions=new Map();let stable,roleId,runtime,last=evidence.startedMs;
 const readback=(r,mode)=>{
  exact(r,['startedMs','completedMs','function','role','identityPolicy','attachedPolicies','boundary','key','keyPolicy','keyGrants']);
  need(time(r.startedMs)&&time(r.completedMs)&&r.startedMs>=last&&r.completedMs>=r.startedMs&&r.completedMs<=evidence.completedMs,'ReadbackTime');last=r.completedMs;
  const f=r.function,role=r.role,k=r.key,b=r.boundary;
  need(f.FunctionArn===scope.functionArn&&f.Runtime==='nodejs24.x'&&hash(f.Architectures)===hash(['arm64'])&&f.Handler==='index.handler'&&f.Role===scope.roleArn&&f.CodeSha256===codeSha256&&f.State==='Active'&&f.LastUpdateStatus==='Successful'&&!f.KMSKeyArn&&(f.Layers===undefined||Array.isArray(f.Layers)&&f.Layers.length===0)&&(!f.VpcConfig||f.VpcConfig.SubnetIds?.length===0&&f.VpcConfig.SecurityGroupIds?.length===0),'Function');
  same(f.Environment?.Variables,{CANARY_KEY_ARN:keyArn,CANARY_VPC_ID:scope.vpcId},'Environment');
  need(role.Arn===scope.roleArn&&typeof role.RoleId==='string'&&/^AROA[A-Z0-9]+$/.test(role.RoleId),'Role');roleId??=role.RoleId;need(roleId===role.RoleId,'RoleRecreated');
  same(doc(role.AssumeRolePolicyDocument),plan.template.Resources.CanaryRole.Properties.AssumeRolePolicyDocument,'Trust');
  const tags=Object.fromEntries((role.Tags??[]).map(t=>[t.Key,t.Value]));need(tags.Project==='mem9-on-aws'&&tags.Stage===scope.stage&&tags.VerificationId===scope.verificationId,'RoleTags');
  same(r.attachedPolicies,[],'AttachedPolicies');same(doc(r.identityPolicy),expectedIdentity,'IdentityPolicy');same(doc(r.keyPolicy),expectedKeyPolicy,'KeyPolicy');same(r.keyGrants,[],'KeyGrants');
  need(k.Arn===keyArn&&keyArn.endsWith('/'+k.KeyId)&&k.Enabled===true&&k.KeyState==='Enabled'&&k.KeyManager==='CUSTOMER'&&k.KeyUsage==='ENCRYPT_DECRYPT'&&k.KeySpec==='SYMMETRIC_DEFAULT','KeyState');
  exact(b,['arn','versionId','document']);const arn=mode==='original'?scope.originalBoundaryArn:scope.comparisonArn;
  need(b.arn===arn&&role.PermissionsBoundary?.PermissionsBoundaryArn===arn&&/^v[1-9][0-9]*$/.test(b.versionId),'Boundary');same(doc(b.document),mode==='original'?originalBoundary:plan.comparison.document,'BoundaryDocument');
  if(versions.has(arn))need(versions.get(arn)===b.versionId,'PolicyVersionDrift');else versions.set(arn,b.versionId);
  const projection={function:f,role:{Arn:role.Arn,RoleId:role.RoleId,trust:doc(role.AssumeRolePolicyDocument),tags},identity:doc(r.identityPolicy),key:k,keyPolicy:doc(r.keyPolicy),keyGrants:r.keyGrants};
  if(stable)same(projection,stable,'PermissionDrift');else stable=projection;
 };
 for(const [i,phase]of ['A1','B','A2'].entries()){
  const round=rounds[i];exact(round,['phase','before','invoke','after']);need(round.phase===phase,'Sequence');readback(round.before,phase==='B'?'original':'comparison');
  const invoke=round.invoke;exact(invoke,['startedMs','completedMs','request','response']);need(time(invoke.startedMs)&&time(invoke.completedMs)&&invoke.startedMs>=last&&invoke.completedMs>=invoke.startedMs,'InvokeTime');
  same(invoke.request,{FunctionName:scope.functionArn,InvocationType:'RequestResponse',Payload:Buffer.from(JSON.stringify(request)).toString('base64')},'InvokeRequest');
  const response=invoke.response;need(response.StatusCode===200&&!Object.hasOwn(response,'FunctionError')&&response.ExecutedVersion==='$LATEST'&&id(response.$metadata?.requestId)&&response.$metadata.httpStatusCode===200,'InvokeResponse');
  need(!invokeIds.has(response.$metadata.requestId),'ReplayedInvoke');invokeIds.add(response.$metadata.requestId);
  const result=validateGatewayCanaryResult(JSON.parse(bytes(response.Payload,16384).toString()),{scope,keyArn,request,phase});
  need(result.startedMs>=invoke.startedMs&&result.completedMs<=invoke.completedMs,'InvokeTime');
  for(const value of [result.invocationRequestId,...result.results.map(r=>r.requestId)]){need(!ids.has(value),'ReplayedRequest');ids.add(value);}
  if(runtime)same(runtime,result.runtime,'RuntimeDrift');else runtime=result.runtime;last=invoke.completedMs;readback(round.after,phase==='B'?'original':'comparison');
 }
 return freeze({version:1,kind:'gateway-runtime-canary-validation',authority:false,evidenceHash:expected.evidenceHash,handlerHash:plan.handlerHash,originalBoundaryHash:plan.comparison.originalHash,comparisonBoundaryHash:plan.comparison.comparisonHash,roleId,coverage:['kms-source-condition','ec2-source-condition']});
}
