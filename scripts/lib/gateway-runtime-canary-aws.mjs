import {lstat,realpath,writeFile,unlink} from 'node:fs/promises';
import {isAbsolute,join} from 'node:path';
import {randomUUID,randomBytes,createHash} from 'node:crypto';
import {LambdaClient,InvokeCommand} from '@aws-sdk/client-lambda';
import {fromIni} from '@aws-sdk/credential-providers';
import {runBoundedCommand} from './bounded-subprocess.mjs';
import {compileGatewayRuntimeCanaryScope,gatewayCanaryDocumentHash as hash} from './gateway-runtime-canary-resources.mjs';
import {GATEWAY_CANARY_PLAINTEXT,gatewayCanaryInvocation,verifyGatewayCanaryCode,validateGatewayCanaryResult,validateGatewayRuntimeCanaryEvidence,gatewayCanaryPhaseDiagnostic,gatewayCanaryInternalReason} from './gateway-runtime-canary-evidence.mjs';

const owners=new WeakMap(),DAY=86400000;
async function execute(command,args,options){
  const result=await runBoundedCommand(command,args,{env:options.env,signal:options.signal,timeoutMs:30000,maxBufferBytes:1048576});
  if(result.status!==0)throw Object.assign(Error('GatewayCanaryAwsServiceError'),{code:result.status,stderr:result.stderr});
  return result;
}
const need=(ok,why)=>{if(!ok)throw Error('GatewayCanaryAws'+why);};
const same=(a,b,why)=>need(hash(a)===hash(b),why);
const sha=b=>createHash('sha256').update(b).digest('hex');
const doc=v=>{if(typeof v!=='string')return v;try{return JSON.parse(v);}catch{return JSON.parse(decodeURIComponent(v));}};
const freeze=v=>{if(v&&typeof v==='object'){Object.values(v).forEach(freeze);Object.freeze(v);}return v;};
const optionalKeys=(v,keys)=>v&&typeof v==='object'&&Object.keys(v).every(k=>keys.includes(k));
const single=(rows,predicate,why)=>{need(Array.isArray(rows),why);const found=rows.filter(predicate);need(found.length===1,why);return found[0];};
function serviceError(error,operation){
  if(![254,255].includes(error?.code)||typeof error.stderr!=='string')return null;
  const match=/^\s*(?:aws: \[ERROR\]: )?An error occurred \(([A-Za-z0-9]+)\) when calling the ([A-Za-z0-9]+) operation(?: \(reached max retries: [0-9]+\))?: ([\s\S]*)$/.exec(error.stderr);
  return match&&match[2]===operation?{code:match[1],message:match[3]}:null;
}

/** Only this exact live adapter can expose evidence to the recovery gate.
 * Returned hashes are derived from retained service responses and fixed source;
 * callers cannot substitute a serialized lifecycle result or a test adapter. */
export function inspectGatewayCanaryAwsEvidence(ops){
  const state=owners.get(ops);
  need(state&&!state.testing&&!state.transportHeld&&!state.diagnosticWriteFailed&&state.cleanupVerified&&state.rounds.length===3,'NativeCompletion');
  const evidence=state.evidence();
  need(state.cleanup?.length===1&&state.cleanup[0].Arn===evidence.keyArn&&state.cleanup[0].KeyState==='PendingDeletion','NativeKeyCleanup');
  const expected={evidenceHash:hash(evidence),handlerHash:state.plan.handlerHash,
    originalBoundaryHash:state.plan.comparison.originalHash,comparisonBoundaryHash:state.plan.comparison.comparisonHash};
  const validation=validateGatewayRuntimeCanaryEvidence(evidence,expected);
  return freeze({evidence,expected,validation,cleanup:structuredClone(state.cleanup)});
}

/** Fixed operator adapter. sessions is the original scoped-session owner with
 * check() and environment(lane), not an environment object from JSON. The
 * provision and observe lanes are kept separate. No default AWS credentials,
 * endpoint override, shell command, retrying mutation or automatic reissuance.
 * recordPhaseDiagnostic is the original owner's bounded journal callback. */
export async function createGatewayCanaryAwsAdapter(input,test={}){
  need(optionalKeys(input,['plan','sessions','directory','awsExecutable','recordPhaseDiagnostic'])&&Object.keys(input).length===5,'Input');
  need(optionalKeys(test,['execute','fetch','invoke']),'TestOptions');
  const {sessions,directory,awsExecutable,recordPhaseDiagnostic}=input,plan=freeze(structuredClone(input.plan)),s=plan.scope;
  need(typeof recordPhaseDiagnostic==='function','DiagnosticWriter');
  same(s,compileGatewayRuntimeCanaryScope(Object.fromEntries(['accountId','applicationRegion','verificationId','vpcId','ownerRoleArn'].map(k=>[k,s[k]]))),'Scope');
  need(sha(plan.templateBody)===plan.templateHash&&hash(JSON.parse(plan.templateBody))===hash(plan.template),'Plan');
  need(sessions&&typeof sessions.check==='function'&&typeof sessions.environment==='function','OriginalSessions');
  need(isAbsolute(directory)&&await realpath(directory)===directory&&isAbsolute(awsExecutable),'Paths');
  const initial=await lstat(directory);need(initial.isDirectory()&&initial.uid===process.getuid()&&(initial.mode&0o777)===0o700,'PrivateDirectory');
  const state={plan,testing:Object.keys(test).length>0,rounds:[],cleanupVerified:false,cleanup:null};
  const diagnostics=new Map();
  let stackId,keyArn,codeZip,request,created=false,lastRead,deleteStartedMs,startedMs=Date.now();
  const cli=test.execute??execute;
  async function env(lane){
    await sessions.check();const environment=await sessions.environment(lane);
    need(environment&&environment.AWS_PROFILE==='cc-tracked'&&environment.AWS_EC2_METADATA_DISABLED==='true'&&
      isAbsolute(environment.AWS_CONFIG_FILE??'')&&isAbsolute(environment.AWS_SHARED_CREDENTIALS_FILE??'')&&
      !Object.keys(environment).some(k=>k.startsWith('AWS_ENDPOINT_URL')||['AWS_ACCESS_KEY_ID','AWS_SECRET_ACCESS_KEY','AWS_SESSION_TOKEN','AWS_WEB_IDENTITY_TOKEN_FILE','AWS_CONTAINER_CREDENTIALS_FULL_URI','AWS_CONTAINER_CREDENTIALS_RELATIVE_URI'].includes(k)),'ScopedEnvironment');
    return environment;
  }
  async function call(lane,service,operation,body,signal){
    if(state.transportHeld)throw Object.assign(Error('GatewayCanaryAwsTransportCleanupHeld'),{code:'ECLEANUP',cleanupComplete:false});
    signal?.throwIfAborted();const environment=await env(lane),current=await lstat(directory);
    need(current.dev===initial.dev&&current.ino===initial.ino&&(current.mode&0o777)===0o700&&await realpath(directory)===directory,'DirectoryChanged');
    const file=join(directory,'canary-request-'+randomUUID()+'.json');
    await writeFile(file,JSON.stringify(body),{mode:0o600,flag:'wx'});
    try{
      const region=service==='iam'?'us-east-1':s.applicationRegion;
      const result=await cli(awsExecutable,['--region',region,'--output','json','--no-cli-pager','--no-paginate','--cli-binary-format','base64','--cli-connect-timeout','10','--cli-read-timeout','20',service,operation,'--cli-input-json','file://'+file],
        {env:environment,encoding:'utf8',timeout:30000,maxBuffer:1048576,signal,killSignal:'SIGKILL'});
      await sessions.check();return result.stdout.trim()?JSON.parse(result.stdout):{};
    }catch(error){
      if(error?.code==='ECLEANUP'||error?.cleanupComplete===false){state.transportHeld=true;throw Object.assign(Error('GatewayCanaryAwsTransportCleanupHeld'),{code:'ECLEANUP',cleanupComplete:false});}
      throw error;
    }finally{if(!state.transportHeld)await unlink(file);}
  }
  async function absent(lane,service,operation,body,awsOperation,code,signal){
    try{return {absent:false,value:await call(lane,service,operation,body,signal)};}
    catch(error){const e=serviceError(error,awsOperation);
      if(!e&&/^GatewayCanaryAws[A-Za-z]+$/.test(error?.message??''))throw error;
      if(e?.code===code){
        if(service==='cloudformation')need(e.message.trim()===`Stack with id ${body.StackName} does not exist`,'UnexpectedStackAbsence');
        return {absent:true};
      }
      throw Error('GatewayCanaryAwsObservationFailed');
    }
  }
  async function describe(StackName,signal){
    need(StackName===s.stackName||StackName===stackId,'StackScope');
    const r=await absent('observe','cloudformation','describe-stacks',{StackName},'DescribeStacks','ValidationError',signal);
    if(r.absent)return null;
    const value=single(r.value.Stacks,x=>x.StackName===s.stackName,'StackIdentity');
    need(value.StackId.startsWith(s.stackArnPattern.slice(0,-1))&&(!stackId||value.StackId===stackId),'StackIdentity');
    return value;
  }
  async function resources(signal){
    const stack=await describe(stackId??s.stackName,signal);need(stack,'UnknownCreation');stackId=stack.StackId;
    const result=await call('observe','cloudformation','list-stack-resources',{StackName:stackId},signal);
    need(!result.NextToken&&Array.isArray(result.StackResourceSummaries)&&result.StackResourceSummaries.length<=6,'ResourceInventory');
    const rows=result.StackResourceSummaries;
    for(const r of rows)need(plan.template.Resources[r.LogicalResourceId]?.Type===r.ResourceType,'ResourceType');
    const keys=rows.filter(r=>r.LogicalResourceId==='SyntheticKey'&&r.PhysicalResourceId);
    need(keys.length<=1,'KeyInventory');
    if(keys.length){const id=keys[0].PhysicalResourceId;need(/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(id),'KeyIdentity');
      const arn=s.keyArnPattern.replace('*',id);need(!keyArn||keyArn===arn,'KeyIdentity');keyArn=arn;}
    return rows;
  }
  async function policy(arn,signal){
    need([s.originalBoundaryArn,s.comparisonArn].includes(arn),'PolicyScope');
    const metadata=await call('observe','iam','get-policy',{PolicyArn:arn},signal);
    const versionId=metadata.Policy?.DefaultVersionId;need(metadata.Policy?.Arn===arn&&/^v[1-9][0-9]*$/.test(versionId),'PolicyIdentity');
    const version=await call('observe','iam','get-policy-version',{PolicyArn:arn,VersionId:versionId},signal);
    need(version.PolicyVersion?.VersionId===versionId&&version.PolicyVersion.IsDefaultVersion===true,'PolicyVersion');
    return {arn,versionId,document:doc(version.PolicyVersion.Document)};
  }
  async function functionZip(signal){
    const actual=await call('observe','lambda','get-function',{FunctionName:s.functionArn},signal);
    need(actual.Configuration?.FunctionArn===s.functionArn,'FunctionIdentity');
    const location=new URL(actual.Code?.Location);
    need(location.protocol==='https:'&&!location.username&&!location.password&&!location.port&&!location.hash&&
      (location.hostname.endsWith('.s3.'+s.applicationRegion+'.amazonaws.com')||location.hostname.endsWith('.s3.amazonaws.com')),'CodeLocation');
    // The presigned URL is never written to the evidence journal or returned.
    const response=await (test.fetch??fetch)(location,{redirect:'error',signal,headers:{'accept-encoding':'identity'}});
    need(response.status===200&&response.body,'CodeDownload');
    const reader=response.body.getReader(),chunks=[];let length=0;
    try{for(;;){const r=await reader.read();if(r.done)break;length+=r.value.byteLength;need(length<=65536,'CodeSize');chunks.push(Buffer.from(r.value));}}
    finally{await reader.cancel().catch(()=>{});reader.releaseLock();}
    codeZip=Buffer.concat(chunks);verifyGatewayCanaryCode(codeZip,plan.template.Resources.CanaryFunction.Properties.Code.ZipFile,actual.Configuration.CodeSha256);
    return actual.Configuration;
  }
  async function readback(signal){
    const begin=Date.now();need(stackId&&keyArn,'Uninitialized');
    const f=await call('observe','lambda','get-function-configuration',{FunctionName:s.functionArn},signal);
    need(f.Layers===undefined||Array.isArray(f.Layers)&&f.Layers.length===0,'ExecutableLayers');
    if(!codeZip)await functionZip(signal);
    const role=(await call('observe','iam','get-role',{RoleName:s.roleName},signal)).Role;
    const names=await call('observe','iam','list-role-policies',{RoleName:s.roleName},signal);
    need(!names.IsTruncated&&!names.Marker,'PolicyInventory');same(names.PolicyNames,['synthetic-verification'],'PolicyInventory');
    const identity=await call('observe','iam','get-role-policy',{RoleName:s.roleName,PolicyName:'synthetic-verification'},signal);
    const attached=await call('observe','iam','list-attached-role-policies',{RoleName:s.roleName},signal);
    need(!attached.IsTruncated&&!attached.Marker,'AttachedInventory');
    const original=await policy(s.originalBoundaryArn,signal),comparison=await policy(s.comparisonArn,signal);
    same(original.document,state.originalBoundary,'OriginalBoundary');
    same(comparison.document,plan.comparison.document,'ComparisonBoundary');
    const boundaryArn=role?.PermissionsBoundary?.PermissionsBoundaryArn;
    need([s.originalBoundaryArn,s.comparisonArn].includes(boundaryArn),'Boundary');
    const key=(await call('observe','kms','describe-key',{KeyId:keyArn},signal)).KeyMetadata;
    const keyPolicy=await call('observe','kms','get-key-policy',{KeyId:keyArn,PolicyName:'default'},signal);
    const keyGrants=await call('observe','kms','list-grants',{KeyId:keyArn,Limit:100},signal);
    need(!keyGrants.Truncated&&!keyGrants.NextMarker,'GrantInventory');
    const tags=await call('observe','kms','list-resource-tags',{KeyId:keyArn,Limit:50},signal);
    need(!tags.Truncated&&!tags.NextMarker,'KeyTags');
    const tagMap=Object.fromEntries((tags.Tags??[]).map(t=>[t.TagKey,t.TagValue]));
    need(tagMap.Project==='mem9-on-aws'&&tagMap.Stage===s.stage&&tagMap.VerificationId===s.verificationId,'KeyTags');
    const raw={startedMs:begin,completedMs:Date.now(),function:f,role,identityPolicy:doc(identity.PolicyDocument),attachedPolicies:attached.AttachedPolicies,
      boundary:boundaryArn===s.originalBoundaryArn?original:comparison,key,keyPolicy:doc(keyPolicy.Policy),keyGrants:keyGrants.Grants};
    lastRead=raw;
    return {raw,state:{stackId,roleArn:role.Arn,roleId:role.RoleId,functionArn:f.FunctionArn,keyArn,boundaryArn,
      originalPolicyHash:hash(original.document),comparisonPolicyHash:hash(comparison.document),handlerHash:plan.handlerHash,
      codeHash:Buffer.from(f.CodeSha256,'base64').toString('hex'),configurationHash:hash(f),identityPolicyHash:hash(raw.identityPolicy),keyPolicyHash:hash(raw.keyPolicy),keyGrantsHash:hash(raw.keyGrants)}};
  }
  async function ownLogs(signal){
    const r=await call('observe','logs','describe-log-groups',{logGroupNamePrefix:s.logGroupName,limit:50},signal);
    need(!r.nextToken&&Array.isArray(r.logGroups),'LogInventory');return r.logGroups.filter(x=>x.logGroupName===s.logGroupName);
  }
  const ops={
    async assertAbsent({signal}){
      if(created)throw Object.assign(Error('GatewayCanaryAwsAlreadyCreated'),{cleanupComplete:state.cleanupVerified&&!state.transportHeld});
      need(await describe(s.stackName,signal)===null,'StackExists');
      need((await absent('observe','iam','get-role',{RoleName:s.roleName},'GetRole','NoSuchEntity',signal)).absent,'RoleExists');
      need((await absent('observe','iam','get-policy',{PolicyArn:s.comparisonArn},'GetPolicy','NoSuchEntity',signal)).absent,'PolicyExists');
      need((await absent('observe','lambda','get-function-configuration',{FunctionName:s.functionArn},'GetFunctionConfiguration','ResourceNotFoundException',signal)).absent,'FunctionExists');
      need((await ownLogs(signal)).length===0,'LogsExist');
    },
    async createStack({signal,...body}){
      same(body,{StackName:s.stackName,TemplateBody:plan.templateBody,Capabilities:['CAPABILITY_NAMED_IAM'],Parameters:[{ParameterKey:'BoundaryMode',ParameterValue:'comparison'}],ClientRequestToken:'gateway-'+s.verificationId+'-create',OnFailure:'DELETE'},'CreateRequest');
      need(!created,'CreateRepeated');created=true;
      const value=await call('provision','cloudformation','create-stack',body,signal);stackId=value.StackId;
      need(typeof stackId==='string'&&stackId.startsWith(s.stackArnPattern.slice(0,-1)),'StackIdentity');return value;
    },
    async describeStack({StackName,signal}){return describe(StackName,signal);},
    async readState({signal}){
      if(!keyArn)await resources(signal);need(keyArn,'KeyMissing');
      const template=await call('observe','cloudformation','get-template',{StackName:stackId,TemplateStage:'Original'},signal);
      same(doc(template.TemplateBody),plan.template,'DeployedTemplate');
      if(!state.originalBoundary){const original=await policy(s.originalBoundaryArn,signal);need(hash(original.document)===plan.comparison.originalHash,'OriginalBoundary');state.originalBoundary=original.document;}
      return (await readback(signal)).state;
    },
    async changeBoundary({signal,...body}){
      need(stackId&&body.StackName===stackId&&body.UsePreviousTemplate===true&&
        body.Parameters?.length===1&&body.Parameters[0].ParameterKey==='BoundaryMode'&&['original','comparison'].includes(body.Parameters[0].ParameterValue),'BoundaryRequest');
      same(Object.keys(body).sort(),['Capabilities','ClientRequestToken','Parameters','StackName','UsePreviousTemplate'].sort(),'BoundaryRequest');
      same(body.Capabilities,['CAPABILITY_NAMED_IAM'],'BoundaryRequest');
      need(body.ClientRequestToken==='gateway-'+s.verificationId+'-'+(body.Parameters[0].ParameterValue==='original'?'B':'A2'),'BoundaryRequest');
      return call('provision','cloudformation','update-stack',body,signal);
    },
    async collectPhase({phase,signal}){
      need(['A1','B','A2'][state.rounds.length]===phase&&lastRead&&codeZip,'PhaseSequence');
      need(!diagnostics.has(phase),'DiagnosticLimit');
      let stage='readback-before',begin=Date.now(),response,diagnosticFailed=false;
      const diagnostic=async(observation,error)=>{
        const count=(diagnostics.get(phase)??0)+1;need(count<=5,'DiagnosticLimit');diagnostics.set(phase,count);
        try{await recordPhaseDiagnostic(gatewayCanaryPhaseDiagnostic({verificationId:s.verificationId,templateHash:plan.templateHash,phase,stage,observation,startedMs:begin,completedMs:Date.now(),response,error}));}
        catch(cause){diagnosticFailed=true;state.diagnosticWriteFailed=true;throw Object.assign(Error('GatewayCanaryAwsDiagnosticWriteFailed'),
          {diagnosticWriteFailed:true,unknown:cause?.unknown===true},
          cause?.code==='ECLEANUP'||cause?.cleanupComplete===false?{code:'ECLEANUP',cleanupComplete:false}:{});}
      };
      try{
      await diagnostic('start');
      if(!request){
        const encrypted=await call('observe','kms','encrypt',{KeyId:keyArn,Plaintext:Buffer.from(GATEWAY_CANARY_PLAINTEXT).toString('base64'),EncryptionAlgorithm:'SYMMETRIC_DEFAULT',EncryptionContext:{'aws:lambda:FunctionArn':s.functionArn}},signal);
        need(encrypted.KeyId===keyArn&&encrypted.EncryptionAlgorithm==='SYMMETRIC_DEFAULT','Encryption');
        request=gatewayCanaryInvocation({nonce:randomBytes(32).toString('hex'),ciphertextBase64:encrypted.CiphertextBlob});
      }
      const before=(await readback(signal)).raw;
      stage='invoke';begin=Date.now();await diagnostic('start');
      const environment=await env('observe'),payload=Buffer.from(JSON.stringify(request));
      const invokeRequest={FunctionName:s.functionArn,InvocationType:'RequestResponse',Payload:payload};
      begin=Date.now();
      if(test.invoke)response=await test.invoke(invokeRequest,signal);
      else{
        const credentials=fromIni({profile:'cc-tracked',filepath:environment.AWS_SHARED_CREDENTIALS_FILE,configFilepath:environment.AWS_CONFIG_FILE,ignoreCache:true});
        const client=new LambdaClient({region:s.applicationRegion,endpoint:'https://lambda.'+s.applicationRegion+'.amazonaws.com',credentials,maxAttempts:1,requestHandler:{connectionTimeout:10000,requestTimeout:45000}});
        try{response=await client.send(new InvokeCommand(invokeRequest),{abortSignal:signal});}finally{client.destroy();}
      }
      await sessions.check();const invokeCompletedMs=Date.now();stage='response-validation';await diagnostic('response');
      need(response.Payload instanceof Uint8Array&&response.Payload.byteLength<=16384,'InvokePayload');
      const invoke={startedMs:begin,completedMs:invokeCompletedMs,request:{...invokeRequest,Payload:payload.toString('base64')},response:{...response,Payload:Buffer.from(response.Payload).toString('base64')}};
      need(response.StatusCode===200&&!response.FunctionError&&response.$metadata?.requestId,'InvokeResponse');
      validateGatewayCanaryResult(JSON.parse(Buffer.from(response.Payload).toString()),{scope:s,keyArn,request,phase});
      stage='readback-after';await diagnostic('start');
      const after=(await readback(signal)).raw,round=freeze({phase,before,invoke,after});state.rounds.push(round);return round;
      }catch(error){
        // Capture the first failure before an asynchronous diagnostic writer can
        // fail. A later journal fault cannot replace its reason or erase unknown.
        const unsafe=error?.code==='ECLEANUP'||error?.cleanupComplete===false;
        const failure=Object.assign(Error(gatewayCanaryInternalReason(error)),{unknown:error?.unknown===true},
          unsafe?{code:'ECLEANUP',cleanupComplete:false}:{},diagnosticFailed?{diagnosticWriteFailed:true}:{});
        if(unsafe)state.transportHeld=true;
        if(!diagnosticFailed)try{await diagnostic('failure',error);}catch(recordError){
          failure.diagnosticWriteFailed=true;
          if(recordError?.code==='ECLEANUP'||recordError?.cleanupComplete===false){state.transportHeld=true;failure.code='ECLEANUP';failure.cleanupComplete=false;}
        }
        throw failure;
      }
    },
    async discoverOwnedKeys({signal}){await resources(signal);return keyArn?[keyArn]:[];},
    async deleteStack({signal,...body}){
      need(body.StackName===(stackId??s.stackName)&&body.ClientRequestToken==='gateway-'+s.verificationId+'-delete','DeleteRequest');
      need(Object.keys(body).length===2,'DeleteRequest');deleteStartedMs=Date.now();return call('provision','cloudformation','delete-stack',body,signal);
    },
    async verifyCleanup({keys,signal}){
      need(deleteStartedMs&&Array.isArray(keys)&&keys.length<=1&&keys.every(k=>k===keyArn),'CleanupScope');
      same(keys,keyArn?[keyArn]:[],'CleanupKeyInventory');
      const stack=await describe(stackId??s.stackName,signal),role=await absent('observe','iam','get-role',{RoleName:s.roleName},'GetRole','NoSuchEntity',signal),comparison=await absent('observe','iam','get-policy',{PolicyArn:s.comparisonArn},'GetPolicy','NoSuchEntity',signal),fn=await absent('observe','lambda','get-function-configuration',{FunctionName:s.functionArn},'GetFunctionConfiguration','ResourceNotFoundException',signal);
      const cleaned=[];state.cleanup=[];
      for(const arn of keys){
        const metadata=(await call('observe','kms','describe-key',{KeyId:arn},signal)).KeyMetadata,at=Date.parse(metadata?.DeletionDate);
        need(metadata?.Arn===arn&&metadata.KeyState==='PendingDeletion'&&metadata.MultiRegion===false&&Number.isFinite(at)&&at>=deleteStartedMs+7*DAY-60000&&at<=Date.now()+8*DAY,'KeyDeletion');
        // The immutable deployed template selects seven days. DescribeKey
        // exposes DeletionDate for a single-region key, not the multi-region
        // PendingDeletionWindowInDays field.
        need(plan.template.Resources.SyntheticKey.Properties.PendingWindowInDays===7,'KeyDeletionWindow');
        state.cleanup.push(metadata);cleaned.push({arn,state:'PendingDeletion',pendingWindowInDays:7});
      }
      const result={stackAbsent:stack===null||stack.StackStatus==='DELETE_COMPLETE',functionAbsent:fn.absent,roleAbsent:role.absent,comparisonAbsent:comparison.absent,logGroupAbsent:(await ownLogs(signal)).length===0,keys:cleaned};
      state.cleanupVerified=['stackAbsent','functionAbsent','roleAbsent','comparisonAbsent','logGroupAbsent'].every(k=>result[k]);return result;
    },
  };
  state.evidence=()=>({version:1,kind:'gateway-runtime-canary-evidence',scope:s,originalBoundary:state.originalBoundary,
    handlerSource:plan.template.Resources.CanaryFunction.Properties.Code.ZipFile,codeZipBase64:codeZip.toString('base64'),keyArn,request,startedMs,
    completedMs:state.rounds.at(-1)?.after.completedMs,rounds:structuredClone(state.rounds)});
  owners.set(ops,state);return Object.freeze(ops);
}
