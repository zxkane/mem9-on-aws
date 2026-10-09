import {describe,it,expect} from 'vitest';
import {mkdtemp,writeFile,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
import {createServer} from 'node:http';
import {runBoundedCommand} from './lib/bounded-subprocess.mjs';
import {compileGatewayRuntimeCanaryScope,renderGatewayRuntimeCanaryTemplate} from './lib/gateway-runtime-canary-resources.mjs';
import {expectedGatewayBoundaryPolicyDocument} from './lib/gateway-workload-boundary.mjs';
import {createGatewayCanaryAwsAdapter,inspectGatewayCanaryAwsEvidence} from './lib/gateway-runtime-canary-aws.mjs';
import {runGatewayRuntimeCanaryLifecycle} from './lib/gateway-runtime-canary-lifecycle.mjs';
import {validateGatewayRuntimeCanaryEvidence} from './lib/gateway-runtime-canary-evidence.mjs';
import {gatewayCanaryDocumentHash as hash} from './lib/gateway-runtime-canary-resources.mjs';
import {evidenceFixture,harness} from './gateway-runtime-canary.fixture.mjs';

const scope=compileGatewayRuntimeCanaryScope({accountId:'123456789012',applicationRegion:'ap-northeast-1',verificationId:'abcdef012345',vpcId:'vpc-0123456789abcdef0',ownerRoleArn:'arn:aws:iam::123456789012:role/example-runtime-operator'});
const plan=renderGatewayRuntimeCanaryTemplate({scope,originalBoundary:expectedGatewayBoundaryPolicyDocument({partition:'aws',accountId:scope.accountId,applicationRegion:scope.applicationRegion,policyRevision:'r1'}),handlerSource:'exports.handler=async()=>{};\n'});
async function fixture(test,execute,options={}){
  const directory=await mkdtemp(join(tmpdir(),'gateway-native-'));
  test.onTestFinished(()=>rm(directory,{recursive:true,force:true}));
  const config=join(directory,'config'),credentials=join(directory,'credentials');
  await writeFile(config,'[profile cc-tracked]\n',{mode:0o600});await writeFile(credentials,'[cc-tracked]\n',{mode:0o600});
  const env={PATH:process.env.PATH,AWS_PROFILE:'cc-tracked',AWS_CONFIG_FILE:config,AWS_SHARED_CREDENTIALS_FILE:credentials,AWS_EC2_METADATA_DISABLED:'true',CC_PROJECT:'mem9-on-aws',CC_USAGE:'cc-mem9-on-aws'};
  const calls=[],diagnostics=[],diagnosticAttempts=[],sessions={check(){},async environment(lane){calls.push({lane});return env;}};
  const run=async(executable,args,options)=>{
    const at=args.indexOf('--cli-input-json'),request=JSON.parse(await readFile(args[at+1].slice(7),'utf8'));
    const operation=args[args.indexOf('--cli-read-timeout')+2],action=args[args.indexOf('--cli-read-timeout')+3];
    calls.push({executable,operation,action,request,env:options.env});return execute({operation,action,request});
  };
  const recordPhaseDiagnostic=async value=>{diagnosticAttempts.push(value);await options.diagnostic?.(value);diagnostics.push(value);};
  const ops=await createGatewayCanaryAwsAdapter({plan:options.plan??plan,sessions,directory,awsExecutable:'/usr/local/bin/aws',recordPhaseDiagnostic},{execute:run,...(options.fetch?{fetch:options.fetch}:{}),...(options.invoke?{invoke:options.invoke}:{})});
  return{ops,calls,directory,env,sessions,diagnostics,diagnosticAttempts};
}
function absent(service,operation,name,status=254){
  const code=service==='cloudformation'?'ValidationError':service==='iam'?'NoSuchEntity':'ResourceNotFoundException';
  const error=Error('synthetic AWS response');error.code=status;error.stderr=`An error occurred (${code}) when calling the ${operation} operation: ${service==='cloudformation'?`Stack with id ${name} does not exist`:'synthetic resource absent'}`;throw error;
}
describe('native Gateway canary AWS adapter',()=>{
  it('requires a real owner diagnostic callback before any service call',async test=>{
    const f=await fixture(test,()=>{throw Error('must not call');});
    const input={plan,sessions:f.sessions,directory:f.directory,awsExecutable:'/usr/local/bin/aws'};
    await expect(createGatewayCanaryAwsAdapter(input)).rejects.toThrow(/Input/);
    for(const recordPhaseDiagnostic of [undefined,null,{},'record'])await expect(createGatewayCanaryAwsAdapter({...input,recordPhaseDiagnostic})).rejects.toThrow(/DiagnosticWriter/);
    expect(f.calls).toHaveLength(0);
  });
  it.for([254,255])('uses only scoped observe sessions and exact resource names for absence with CLI status %i',async(status,test)=>{
    const f=await fixture(test,({operation,action})=>{
      if(operation==='logs')return{stdout:JSON.stringify({logGroups:[]})};
      absent(operation,action==='describe-stacks'?'DescribeStacks':action==='get-role'?'GetRole':action==='get-policy'?'GetPolicy':'GetFunctionConfiguration',scope.stackName,status);
    });
    await expect(f.ops.assertAbsent({scope,signal:new AbortController().signal})).resolves.toBeUndefined();
    expect(f.calls.filter(c=>c.lane).every(c=>c.lane==='observe')).toBe(true);
    const calls=f.calls.filter(c=>c.operation);expect(calls).toHaveLength(5);
    expect(calls[0].request).toEqual({StackName:scope.stackName});
    expect(calls.find(c=>c.action==='get-role').request).toEqual({RoleName:scope.roleName});
    expect(calls.find(c=>c.action==='get-policy').request).toEqual({PolicyArn:scope.comparisonArn});
    expect(calls.every(c=>c.env===f.env)).toBe(true);
  });
  it.for([254,255])('does not treat stack access denied as resource absence with CLI status %i',async(status,test)=>{
    const f=await fixture(test,()=>{const e=Error('denied');e.code=status;e.stderr='An error occurred (AccessDenied) when calling the DescribeStacks operation: denied';throw e;});
    await expect(f.ops.assertAbsent({scope,signal:new AbortController().signal})).rejects.toThrow(/GatewayCanaryAws/);
    expect(f.calls.filter(c=>c.operation)).toHaveLength(1);
  });
  it.for([254,255])('requires NoSuchEntity for IAM policy absence with CLI status %i',async(status,test)=>{
    const f=await fixture(test,({operation,action})=>{
      if(action!=='get-policy')absent(operation,action==='describe-stacks'?'DescribeStacks':'GetRole',scope.stackName,status);
      throw Object.assign(Error('denied'),{code:status,stderr:'An error occurred (AccessDenied) when calling the GetPolicy operation: denied'});
    });
    await expect(f.ops.assertAbsent({scope,signal:new AbortController().signal})).rejects.toThrow(/ObservationFailed/);
    expect(f.calls.filter(c=>c.operation).map(c=>c.action)).toEqual(['describe-stacks','get-role','get-policy']);
  });
  it.for([254,255])('does not accept absence for a different CloudFormation stack with CLI status %i',async(status,test)=>{
    const f=await fixture(test,()=>absent('cloudformation','DescribeStacks','unrelated',status));
    await expect(f.ops.describeStack({StackName:scope.stackName,signal:new AbortController().signal})).rejects.toThrow(/UnexpectedStackAbsence/);
  });
  it.for([254,255])('requires a matching operation in the formatted service error with CLI status %i',async(status,test)=>{
    const f=await fixture(test,()=>absent('cloudformation','GetPolicy',scope.stackName,status));
    await expect(f.ops.describeStack({StackName:scope.stackName,signal:new AbortController().signal})).rejects.toThrow(/ObservationFailed/);
  });
  it.for([254,255])('does not infer absence from a bare service exit status %i',async(status,test)=>{
    const f=await fixture(test,()=>{throw Object.assign(Error('synthetic failure'),{code:status,stderr:'NoSuchEntity'});});
    await expect(f.ops.describeStack({StackName:scope.stackName,signal:new AbortController().signal})).rejects.toThrow(/ObservationFailed/);
  });
  it.for(['ETIMEDOUT','ABORT_ERR',252,253])('does not treat transport or configuration failure %s as absence even with matching stderr',async(status,test)=>{
    const f=await fixture(test,()=>absent('cloudformation','DescribeStacks',scope.stackName,status));
    await expect(f.ops.describeStack({StackName:scope.stackName,signal:new AbortController().signal})).rejects.toThrow(/ObservationFailed/);
    expect(f.calls.filter(c=>c.operation)).toHaveLength(1);
  });
  it.for([254,255].flatMap(status=>['','aws: [ERROR]: '].flatMap(prefix=>['',' (reached max retries: 0)',' (reached max retries: 2)'].map(annotation=>({status,prefix,annotation})))))('accepts only matching AWS formatter fields: %j',async({status,prefix,annotation},test)=>{
    const f=await fixture(test,({operation,action})=>{
      if(operation==='logs')return{stdout:JSON.stringify({logGroups:[]})};
      const code=operation==='cloudformation'?'ValidationError':operation==='iam'?'NoSuchEntity':'ResourceNotFoundException';
      const name=action==='describe-stacks'?'DescribeStacks':action==='get-role'?'GetRole':action==='get-policy'?'GetPolicy':'GetFunctionConfiguration';
      const message=operation==='cloudformation'?`Stack with id ${scope.stackName} does not exist`:'synthetic resource absent';
      throw Object.assign(Error('synthetic service response'),{code:status,stderr:`\n${prefix}An error occurred (${code}) when calling the ${name} operation${annotation}: ${message}\n`});
    });
    await expect(f.ops.assertAbsent({scope,signal:new AbortController().signal})).resolves.toBeUndefined();
    expect(f.calls.filter(c=>c.operation)).toHaveLength(5);
  });
  it.for([
    ['aws: [WARNING]: ','DescribeStacks',' (reached max retries: 0)',scope.stackName],
    ['unrelated diagnostic: ','DescribeStacks',' (reached max retries: 0)',scope.stackName],
    ['aws: [ERROR]: ','GetPolicy',' (reached max retries: 0)',scope.stackName],
    ['aws: [ERROR]: ','DescribeStacks',' (reached max retries: -1)',scope.stackName],
    ['aws: [ERROR]: ','DescribeStacks',' (reached max retries: 0 extra)',scope.stackName],
    ['aws: [ERROR]: ','DescribeStacks',' (reached max retries: 0)','unrelated'],
  ])('rejects mismatched or malformed AWS formatter fields: %j',async([prefix,operation,annotation,stack],test)=>{
    const f=await fixture(test,()=>{throw Object.assign(Error('synthetic service response'),{code:254,stderr:`\n${prefix}An error occurred (ValidationError) when calling the ${operation} operation${annotation}: Stack with id ${stack} does not exist\n`});});
    await expect(f.ops.describeStack({StackName:scope.stackName,signal:new AbortController().signal})).rejects.toThrow(/GatewayCanaryAws/);
  });
  // Opt in with the installed pinned CLI; every request is unsigned and loopback-only.
  it.skipIf(!process.env.MEM9_TEST_AWS_CLI).for(['NoSuchEntity','AccessDenied'])('parses real pinned CLI output from synthetic localhost IAM: %s',async(code,test)=>{
    const requests=[],server=createServer((request,response)=>{
      let body='';request.on('data',chunk=>{body+=chunk;});
      request.on('end',()=>{
        requests.push({method:request.method,url:request.url,authorization:request.headers.authorization,body});
        response.writeHead(code==='NoSuchEntity'?404:403,{'content-type':'text/xml'});
        response.end(`<ErrorResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><Error><Type>Sender</Type><Code>${code}</Code><Message>synthetic missing policy</Message></Error><RequestId>synthetic-request</RequestId></ErrorResponse>`);
      });
    });
    test.onTestFinished(async()=>{server.closeAllConnections();await new Promise((resolve,reject)=>server.close(error=>error?reject(error):resolve()));});
    await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(0,'127.0.0.1',resolve);});
    let result;
    const f=await fixture(test,async({operation,action,request})=>{
      if(operation==='logs')return{stdout:JSON.stringify({logGroups:[]})};
      if(action!=='get-policy')absent(operation,action==='describe-stacks'?'DescribeStacks':action==='get-role'?'GetRole':'GetFunctionConfiguration',scope.stackName);
      expect(request).toEqual({PolicyArn:scope.comparisonArn});
      result=await runBoundedCommand(process.env.MEM9_TEST_AWS_CLI,[
        '--endpoint-url',`http://127.0.0.1:${server.address().port}`,'--no-sign-request','--no-cli-pager',
        '--region','us-east-1','--cli-connect-timeout','1','--cli-read-timeout','2',
        'iam','get-policy','--policy-arn',request.PolicyArn,
      ],{env:{...f.env,HOME:f.directory,AWS_MAX_ATTEMPTS:'1',AWS_RETRY_MODE:'standard',AWS_EC2_METADATA_V1_DISABLED:'true',BOTO_CONFIG:'/dev/null'},timeoutMs:5000,maxBufferBytes:16384});
      throw Object.assign(Error('GatewayCanaryAwsServiceError'),{code:result.status,stderr:result.stderr});
    });
    const version=await runBoundedCommand(process.env.MEM9_TEST_AWS_CLI,['--version'],{env:{PATH:process.env.PATH},timeoutMs:5000,maxBufferBytes:4096});
    expect(version.status).toBe(0);expect(version.stdout).toMatch(/^aws-cli\/2\.34\.53 /);
    const observed=f.ops.assertAbsent({scope,signal:new AbortController().signal});
    if(code==='NoSuchEntity')await expect(observed).resolves.toBeUndefined();
    else await expect(observed).rejects.toThrow(/GatewayCanaryAwsObservationFailed/);
    expect(result.status).toBe(254);
    expect(result.stderr).toContain(`aws: [ERROR]: An error occurred (${code}) when calling the GetPolicy operation (reached max retries: 0): synthetic missing policy`);
    expect(requests).toHaveLength(1);expect(requests[0].method).toBe('POST');expect(requests[0].url).toBe('/');
    expect(requests[0].authorization).toBeUndefined();
    expect(Object.fromEntries(new URLSearchParams(requests[0].body))).toEqual({Action:'GetPolicy',Version:'2010-05-08',PolicyArn:scope.comparisonArn});
    expect(()=>inspectGatewayCanaryAwsEvidence(f.ops)).toThrow(/NativeCompletion/);
  },15000);
  it('rejects replacement templates before issuing a mutation',async test=>{
    const f=await fixture(test,()=>{throw Error('must not call');});
    await expect(f.ops.createStack({StackName:scope.stackName,TemplateBody:plan.templateBody+' ',signal:new AbortController().signal})).rejects.toThrow();
    expect(f.calls.filter(c=>c.operation)).toHaveLength(0);
  });
  it('cannot certify cleanup if a failed create never revealed its key inventory',async test=>{
    const f=await fixture(test,()=>absent('cloudformation','DescribeStacks',scope.stackName));
    await expect(f.ops.discoverOwnedKeys({scope,stackId:null,signal:new AbortController().signal})).rejects.toThrow(/Unknown/);
  });
  it('rejects ambient credentials before any service call',async test=>{
    const f=await fixture(test,()=>{throw Error('must not call');});delete f.env.AWS_SHARED_CREDENTIALS_FILE;
    await expect(f.ops.assertAbsent({scope,signal:new AbortController().signal})).rejects.toThrow(/ScopedEnvironment/);
    expect(f.calls.filter(c=>c.operation)).toHaveLength(0);
  });
  it('cannot turn partial or reconstructed adapter objects into runtime evidence',async test=>{
    const f=await fixture(test,()=>{throw Error('must not call');});
    expect(()=>inspectGatewayCanaryAwsEvidence(f.ops)).toThrow();
    expect(()=>inspectGatewayCanaryAwsEvidence({...f.ops})).toThrow();
    expect(()=>inspectGatewayCanaryAwsEvidence({status:'OBSERVATIONS_COMPLETE',cleanupComplete:true})).toThrow();
  });
  it('holds cleanup permanently when the process runner could not join descendants',async test=>{
    const f=await fixture(test,()=>{throw Object.assign(Error('synthetic unjoined descendant'),{code:'ECLEANUP'});});
    const result=await runGatewayRuntimeCanaryLifecycle({plan,ops:f.ops,record:async()=>{},verifyPhase:x=>x});
    expect(result.status).toBe('HELD');expect(result.cleanupComplete).toBe(false);expect(result.cleanupUnconfirmed).toBe(true);
    const replay=await runGatewayRuntimeCanaryLifecycle({plan,ops:f.ops,record:async()=>{},verifyPhase:x=>x});
    expect(replay.status).toBe('HELD');expect(replay.cleanupComplete).toBe(false);expect(replay.cleanupUnconfirmed).toBe(true);
    await expect(f.ops.describeStack({StackName:scope.stackName,signal:new AbortController().signal})).rejects.toThrow(/TransportCleanupHeld/);
    expect(f.calls.filter(c=>c.operation)).toHaveLength(1);
  });
  it.for([254,255])('recognizes synthetic CLI service status %i through the actual bounded runner',async(status,test)=>{
    const f=await fixture(test,()=>{throw Error('unused');}),script=join(f.directory,'synthetic-aws');
    await writeFile(script,`#!/usr/bin/env node
const args=process.argv.slice(2),action=args[args.indexOf('--cli-read-timeout')+3];
if(action==='describe-log-groups')process.stdout.write('{"logGroups":[]}');
else{
  const codes={'describe-stacks':['ValidationError','DescribeStacks'],'get-role':['NoSuchEntity','GetRole'],'get-policy':['NoSuchEntity','GetPolicy'],'get-function-configuration':['ResourceNotFoundException','GetFunctionConfiguration']};
  const [code,operation]=codes[action];
  const message=action==='describe-stacks'?'Stack with id ${scope.stackName} does not exist':'synthetic resource absent';
  process.stderr.write('An error occurred ('+code+') when calling the '+operation+' operation: '+message+'\\n');
  process.exitCode=${status};
}
`,{mode:0o700});
    const ops=await createGatewayCanaryAwsAdapter({plan,sessions:f.sessions,directory:f.directory,awsExecutable:script,recordPhaseDiagnostic:async()=>{}});
    await expect(ops.assertAbsent({scope,signal:new AbortController().signal})).resolves.toBeUndefined();
    expect(()=>inspectGatewayCanaryAwsEvidence(ops)).toThrow();
  });
  for(const scenario of ['success','layers','readback-B','readback-after-B','unexpected-B','transport-B','malformed-B','secret-fields-B','unknown-class-B','function-error-B','function-init-error-B','function-unknown-error-B','cleanup-B','cleanup-and-journal-B','journal-failure-B','unknown-and-journal-B','validation-and-journal-B'])it('runs native lifecycle with real handler and simulated services: '+scenario,async test=>{
    const withLayers=scenario==='layers',secret='DO_NOT_LOG_secret_credentials_url_ciphertext';
    const f=await evidenceFixture(),s=f.scope,stackId=s.stackArnPattern.replace('*','11111111-1111-1111-1111-'+'1'.repeat(12));
    if(withLayers)for(const round of f.evidence.rounds)for(const at of ['before','after'])round[at].function.Layers=[{Arn:'arn:aws:lambda:ap-northeast-1:'+s.accountId+':layer:unapproved-sdk:1'}];
    let created=false,deleted=false,mode='comparison',invocations=0,bPayload,activeStage,activePhase;
    const before=()=>f.evidence.rounds[mode==='original'?1:0].before;
    const response=value=>({stdout:JSON.stringify(value)});
    const a=await fixture(test,({operation,action,request})=>{
      if(operation==='cloudformation'){
        if(action==='create-stack'){created=true;return response({StackId:stackId});}
        if(action==='update-stack'){mode=request.Parameters[0].ParameterValue;return response({StackId:stackId});}
        if(action==='delete-stack'){deleted=true;return response({});}
        if(action==='describe-stacks'){
          if(!created||deleted)absent(operation,'DescribeStacks',request.StackName);
          return response({Stacks:[{StackName:s.stackName,StackId:stackId,StackStatus:'UPDATE_COMPLETE'}]});
        }
        if(action==='get-template')return response({TemplateBody:f.plan.template});
        if(action==='list-stack-resources')return response({StackResourceSummaries:Object.entries(f.plan.template.Resources).map(([LogicalResourceId,r])=>({LogicalResourceId,ResourceType:r.Type,PhysicalResourceId:LogicalResourceId==='SyntheticKey'?f.evidence.keyArn.split('/').at(-1):'synthetic'}))});
      }
      if(operation==='iam'){
        if(action==='get-role'){
          if(!created||deleted)absent(operation,'GetRole',s.roleName);
          return response({Role:before().role});
        }
        if(action==='get-policy'){
          if(request.PolicyArn===s.comparisonArn&&(!created||deleted))absent(operation,'GetPolicy',s.comparisonArn);
          return response({Policy:{Arn:request.PolicyArn,DefaultVersionId:'v1'}});
        }
        if(action==='get-policy-version')return response({PolicyVersion:{VersionId:'v1',IsDefaultVersion:true,Document:request.PolicyArn===s.originalBoundaryArn?f.evidence.originalBoundary:f.plan.comparison.document}});
        if(action==='list-role-policies')return response({PolicyNames:['synthetic-verification'],IsTruncated:false});
        if(action==='get-role-policy')return response({PolicyDocument:before().identityPolicy});
        if(action==='list-attached-role-policies')return response({AttachedPolicies:[],IsTruncated:false});
      }
      if(operation==='lambda'){
        if(!created||deleted)absent(operation,'GetFunctionConfiguration',s.functionName);
        if(mode==='original'&&activePhase==='B'&&action==='get-function-configuration'&&
          (scenario==='readback-B'&&activeStage==='readback-before'||scenario==='readback-after-B'&&activeStage==='readback-after'))throw Object.assign(Error('GatewayCanaryAwsServiceError'),{code:254,stderr:secret});
        if(action==='get-function-configuration')return response(before().function);
        if(action==='get-function')return response({Configuration:before().function,Code:{Location:'https://awslambda-synthetic.s3.ap-northeast-1.amazonaws.com/code?signature=synthetic'}});
      }
      if(operation==='logs')return response({logGroups:created&&!deleted?[{logGroupName:s.logGroupName}]:[]});
      if(operation==='kms'){
        if(action==='describe-key')return response({KeyMetadata:deleted?{...before().key,MultiRegion:false,Enabled:false,KeyState:'PendingDeletion',DeletionDate:new Date(Date.now()+7*86400000).toISOString()}:before().key});
        if(action==='get-key-policy')return response({Policy:JSON.stringify(before().keyPolicy)});
        if(action==='list-grants')return response({Grants:[],Truncated:false});
        if(action==='list-resource-tags')return response({Tags:[{TagKey:'Project',TagValue:'mem9-on-aws'},{TagKey:'Stage',TagValue:s.stage},{TagKey:'VerificationId',TagValue:s.verificationId}],Truncated:false});
        if(action==='encrypt')return response({KeyId:f.evidence.keyArn,EncryptionAlgorithm:'SYMMETRIC_DEFAULT',CiphertextBlob:f.evidence.request.ciphertextBase64});
      }
      throw Error('Unexpected service operation '+operation+' '+action);
    },{plan:f.plan,fetch:async()=>new Response(f.zip),diagnostic:async value=>{
      activeStage=value.stage;activePhase=value.phase;
      if(value.phase==='B'&&(['cleanup-and-journal-B','unknown-and-journal-B','validation-and-journal-B'].includes(scenario)&&value.observation==='failure'||scenario==='journal-failure-B'&&value.observation==='response'))throw Error(secret);
    },invoke:async request=>{
      const phase=['A1','B','A2'][invocations++],event=JSON.parse(Buffer.from(request.Payload).toString()),h=harness({phase,number:invocations,event});
      if(phase==='B'&&scenario==='transport-B')throw Object.assign(Error(secret),{code:'ETIMEDOUT'});
      if(phase==='B'&&scenario==='unknown-and-journal-B')throw Object.assign(Error('GatewayCanaryAwsInvokeResponse'),{unknown:true});
      if(phase==='B'&&scenario.startsWith('cleanup-'))throw Object.assign(Error(secret),{code:'ECLEANUP',cleanupComplete:false});
      const observed=await h.run();await new Promise(resolve=>setTimeout(resolve,20));
      if(phase==='B'&&['unexpected-B','validation-and-journal-B'].includes(scenario)){observed.results[0].outcome='success';delete observed.results[0].errorCode;observed.results[0].plaintextHash='a'.repeat(64);}
      if(phase==='B'&&scenario==='secret-fields-B'){
        observed.credentials=secret;observed.url=secret;observed.ciphertext=secret;observed.plaintext=secret;
        observed.results[0].unexpected=secret;observed.results[0].requestId=secret;
      }
      if(phase==='B'&&scenario==='unknown-class-B')observed.results[0].errorCode=secret;
      const functionError=phase==='B'&&scenario.startsWith('function-');
      const functionFailure={errorType:scenario==='function-error-B'?'Error':scenario==='function-init-error-B'?'Runtime.ImportModuleError':secret,
        errorMessage:scenario==='function-error-B'?'GatewayCanaryCredentials':secret,stackTrace:[secret],unknown:secret};
      const payload=phase==='B'&&scenario==='malformed-B'?Buffer.from('{"secret":"'+secret):Buffer.from(JSON.stringify(functionError?functionFailure:observed));
      if(phase==='B')bPayload=payload;
      return{StatusCode:200,ExecutedVersion:'$LATEST',$metadata:{requestId:'00000000-0000-4000-8000-'+String(invocations).padStart(12,'0'),httpStatusCode:200,...(phase==='B'?{unknown:secret}:{})},Payload:payload,...(phase==='B'?{unknown:secret}:{}),...(functionError?{FunctionError:'Unhandled'}:{})};
    }});
    const result=await runGatewayRuntimeCanaryLifecycle({plan:f.plan,ops:a.ops,record:async()=>{},verifyPhase:round=>round});
    if(withLayers){expect(result.status).toBe('HELD');expect(result.cleanupComplete).toBe(true);expect(invocations).toBe(0);return;}
    if(scenario!=='success'){
      expect(result.status).toBe('HELD');expect(invocations).toBe(scenario==='readback-B'?1:2);expect(result.phases.map(p=>p.phase)).toEqual(['A1']);
      expect(a.calls.filter(c=>c.action==='create-stack')).toHaveLength(1);expect(a.calls.filter(c=>c.action==='encrypt')).toHaveLength(1);
      expect(a.calls.filter(c=>c.action==='update-stack')).toHaveLength(1);
      const unsafe=scenario.startsWith('cleanup-'),writeFailed=['cleanup-and-journal-B','journal-failure-B','unknown-and-journal-B','validation-and-journal-B'].includes(scenario);
      expect(result.cleanupComplete).toBe(!unsafe&&!writeFailed);
      expect(a.calls.filter(c=>c.action==='delete-stack')).toHaveLength(unsafe?0:1);
      if(unsafe){expect(result.cleanupUnconfirmed).toBe(true);await expect(a.ops.describeStack({StackName:s.stackName,signal:new AbortController().signal})).rejects.toThrow(/TransportCleanupHeld/);}
      const diagnostic=a.diagnostics.filter(d=>d.phase==='B');
      expect(a.diagnosticAttempts.filter(d=>d.phase==='B').length).toBeLessThanOrEqual(5);
      expect(JSON.stringify(a.diagnostics)).not.toContain(secret);expect(JSON.stringify(result)).not.toContain(secret);
      for(const d of a.diagnostics)expect(Buffer.byteLength(JSON.stringify(d))).toBeLessThanOrEqual(4096);
      if(writeFailed){
        const accepted=scenario==='validation-and-journal-B'?3:2;
        expect(diagnostic).toHaveLength(accepted);expect(a.diagnosticAttempts.filter(d=>d.phase==='B')).toHaveLength(accepted+1);
        expect(result.diagnosticWriteFailed).toBe(true);
        if(scenario==='journal-failure-B')expect(result.reason).toBe('GatewayCanaryAwsDiagnosticWriteFailed');
        if(scenario==='validation-and-journal-B')expect(result.reason).toBe('GatewayRuntimeEvidenceFields');
        if(scenario==='unknown-and-journal-B'){expect(result.reason).toBe('GatewayCanaryAwsInvokeResponse');expect(result.unknown).toBe(true);}
      }else if(['readback-B','readback-after-B'].includes(scenario)){
        const stage=scenario==='readback-B'?'readback-before':'readback-after';
        expect(diagnostic.at(-2).stage).toBe(stage);expect(diagnostic.at(-2).observation).toBe('start');
        expect(diagnostic.at(-1).stage).toBe(stage);expect(diagnostic.at(-1).observation).toBe('failure');
        expect(result.reason).toBe('GatewayCanaryAwsServiceError');
      }else if(['transport-B','cleanup-B'].includes(scenario)){
        expect(diagnostic).toHaveLength(3);expect(diagnostic.at(-1).stage).toBe('invoke');expect(diagnostic.at(-1).payloadBytes).toBe(null);
        expect(diagnostic.at(-1).errorClass).toBe(unsafe?'ECLEANUP':'ETIMEDOUT');
      }else{
        expect(diagnostic.map(d=>d.observation)).toEqual(['start','start','response','failure']);
        const observed=diagnostic[2];
        expect(observed.payloadHash).toBe(createHash('sha256').update(bPayload).digest('hex'));
        expect(observed.payloadBytes).toBe(bPayload.length);expect(observed.httpStatus).toBe(200);
        expect(observed.stage).toBe('response-validation');
        if(scenario==='malformed-B')expect(observed.payloadFormat).toBe('malformed-json');
        else if(scenario.startsWith('function-')){
          expect(result.reason).toBe('GatewayCanaryAwsInvokeResponse');expect(observed.functionError).toBe('Unhandled');
          if(scenario==='function-error-B'){expect(observed.functionErrorType).toBe('Error');expect(observed.handlerReason).toBe('GatewayCanaryCredentials');}
          else{
            expect(observed.functionErrorType).toBe(scenario==='function-init-error-B'?'Runtime.ImportModuleError':'unrecognized');
            expect(observed.handlerReason).toBe('unrecognized');expect(observed.handlerReasonHash).toBe(createHash('sha256').update(secret).digest('hex'));
          }
        }
        else expect(result.reason).toMatch(/^GatewayRuntimeEvidence(?:Fields|ServiceAuthorization)$/);
        if(scenario==='unexpected-B')expect(observed.services[0].outcome).toBe('success');
        if(scenario==='unknown-class-B'){expect(observed.services[0].errorClass).toBe('unrecognized');expect(observed.services[0].errorClassHash).toBe(createHash('sha256').update(secret).digest('hex'));}
        if(scenario==='secret-fields-B'){expect(observed.services[0].requestId).toBe(null);expect(observed.services[0].requestIdHash).toBe(createHash('sha256').update(secret).digest('hex'));}
      }
      return;
    }
    expect(result.reason).toBe(null);expect(result.status).toBe('OBSERVATIONS_COMPLETE');expect(result.cleanupComplete).toBe(true);
    const rounds=result.phases.map(p=>p.evidence),evidence={...f.evidence,request:JSON.parse(Buffer.from(rounds[0].invoke.request.Payload,'base64').toString()),startedMs:rounds[0].before.startedMs,completedMs:rounds.at(-1).after.completedMs,rounds};
    expect(validateGatewayRuntimeCanaryEvidence(evidence,{...f.expected,evidenceHash:hash(evidence)}).coverage).toEqual(['kms-source-condition','ec2-source-condition']);
    expect(a.calls.filter(c=>c.action==='create-stack')).toHaveLength(1);
    expect(a.calls.filter(c=>c.action==='encrypt')).toHaveLength(1);
    expect(invocations).toBe(3);expect(()=>inspectGatewayCanaryAwsEvidence(a.ops)).toThrow(/NativeCompletion/);
    expect(a.diagnostics.map(d=>[d.phase,d.stage,d.observation])).toEqual(['A1','B','A2'].flatMap(phase=>[
      [phase,'readback-before','start'],[phase,'invoke','start'],[phase,'response-validation','response'],[phase,'readback-after','start']]));
    await expect(a.ops.verifyCleanup({keys:[],signal:new AbortController().signal})).rejects.toThrow(/CleanupKeyInventory/);
  });
});
