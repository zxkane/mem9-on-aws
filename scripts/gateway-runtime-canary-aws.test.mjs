import {describe,it,expect} from 'vitest';
import {mkdtemp,writeFile,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
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
  const calls=[],sessions={check(){},async environment(lane){calls.push({lane});return env;}};
  const run=async(executable,args,options)=>{
    const at=args.indexOf('--cli-input-json'),request=JSON.parse(await readFile(args[at+1].slice(7),'utf8'));
    const operation=args[args.indexOf('--cli-read-timeout')+2],action=args[args.indexOf('--cli-read-timeout')+3];
    calls.push({executable,operation,action,request,env:options.env});return execute({operation,action,request});
  };
  const ops=await createGatewayCanaryAwsAdapter({plan:options.plan??plan,sessions,directory,awsExecutable:'/usr/local/bin/aws'},{execute:run,...(options.fetch?{fetch:options.fetch}:{}),...(options.invoke?{invoke:options.invoke}:{})});
  return{ops,calls,directory,env,sessions};
}
function absent(service,operation,name){
  const code=service==='cloudformation'?'ValidationError':service==='iam'?'NoSuchEntity':'ResourceNotFoundException';
  const error=Error('synthetic AWS response');error.code=255;error.stderr=`An error occurred (${code}) when calling the ${operation} operation: ${service==='cloudformation'?`Stack with id ${name} does not exist`:'synthetic resource absent'}`;throw error;
}
describe('native Gateway canary AWS adapter',()=>{
  it('uses only scoped observe sessions and exact resource names for absence',async test=>{
    const f=await fixture(test,({operation,action})=>{
      if(operation==='logs')return{stdout:JSON.stringify({logGroups:[]})};
      absent(operation,action==='describe-stacks'?'DescribeStacks':action==='get-role'?'GetRole':action==='get-policy'?'GetPolicy':'GetFunctionConfiguration',scope.stackName);
    });
    await expect(f.ops.assertAbsent({scope,signal:new AbortController().signal})).resolves.toBeUndefined();
    expect(f.calls.filter(c=>c.lane).every(c=>c.lane==='observe')).toBe(true);
    const calls=f.calls.filter(c=>c.operation);expect(calls).toHaveLength(5);
    expect(calls[0].request).toEqual({StackName:scope.stackName});
    expect(calls.find(c=>c.action==='get-role').request).toEqual({RoleName:scope.roleName});
    expect(calls.every(c=>c.env===f.env)).toBe(true);
  });
  it('does not treat access denied or a transport timeout as resource absence',async test=>{
    const f=await fixture(test,()=>{const e=Error('denied');e.code=255;e.stderr='An error occurred (AccessDenied) when calling the DescribeStacks operation: denied';throw e;});
    await expect(f.ops.assertAbsent({scope,signal:new AbortController().signal})).rejects.toThrow(/GatewayCanaryAws/);
    expect(f.calls.filter(c=>c.operation)).toHaveLength(1);
  });
  it('does not accept absence for a different CloudFormation stack',async test=>{
    const f=await fixture(test,()=>absent('cloudformation','DescribeStacks','unrelated'));
    await expect(f.ops.describeStack({StackName:scope.stackName,signal:new AbortController().signal})).rejects.toThrow();
  });
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
  it('recognizes genuine CLI status and service errors through the bounded runner',async test=>{
    const f=await fixture(test,()=>{throw Error('unused');}),script=join(f.directory,'synthetic-aws');
    await writeFile(script,'#!/usr/bin/env node\nprocess.stderr.write("An error occurred (ValidationError) when calling the DescribeStacks operation: Stack with id '+scope.stackName+' does not exist\\n");process.exitCode=255;\n',{mode:0o700});
    const ops=await createGatewayCanaryAwsAdapter({plan,sessions:f.sessions,directory:f.directory,awsExecutable:script});
    await expect(ops.describeStack({StackName:scope.stackName,signal:new AbortController().signal})).resolves.toBeNull();
    expect(()=>inspectGatewayCanaryAwsEvidence(ops)).toThrow();
  });
  for(const withLayers of [false,true])it('runs native lifecycle with real handler and simulated services; forbidden Layers='+withLayers,async test=>{
    const f=await evidenceFixture(),s=f.scope,stackId=s.stackArnPattern.replace('*','11111111-1111-1111-1111-'+'1'.repeat(12));
    if(withLayers)for(const round of f.evidence.rounds)for(const at of ['before','after'])round[at].function.Layers=[{Arn:'arn:aws:lambda:ap-northeast-1:'+s.accountId+':layer:unapproved-sdk:1'}];
    let created=false,deleted=false,mode='comparison',invocations=0;
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
    },{plan:f.plan,fetch:async()=>new Response(f.zip),invoke:async request=>{
      const phase=['A1','B','A2'][invocations++],event=JSON.parse(Buffer.from(request.Payload).toString()),h=harness({phase,number:invocations,event});
      const observed=await h.run();await new Promise(resolve=>setTimeout(resolve,20));
      return{StatusCode:200,ExecutedVersion:'$LATEST',$metadata:{requestId:'sdk-invoke-request-'+invocations,httpStatusCode:200},Payload:Buffer.from(JSON.stringify(observed))};
    }});
    const result=await runGatewayRuntimeCanaryLifecycle({plan:f.plan,ops:a.ops,record:async()=>{},verifyPhase:round=>round});
    if(withLayers){expect(result.status).toBe('HELD');expect(result.cleanupComplete).toBe(true);expect(invocations).toBe(0);return;}
    expect(result.reason).toBe(null);expect(result.status).toBe('OBSERVATIONS_COMPLETE');expect(result.cleanupComplete).toBe(true);
    const rounds=result.phases.map(p=>p.evidence),evidence={...f.evidence,request:JSON.parse(Buffer.from(rounds[0].invoke.request.Payload,'base64').toString()),startedMs:rounds[0].before.startedMs,completedMs:rounds.at(-1).after.completedMs,rounds};
    expect(validateGatewayRuntimeCanaryEvidence(evidence,{...f.expected,evidenceHash:hash(evidence)}).coverage).toEqual(['kms-source-condition','ec2-source-condition']);
    expect(a.calls.filter(c=>c.action==='create-stack')).toHaveLength(1);
    expect(a.calls.filter(c=>c.action==='encrypt')).toHaveLength(1);
    expect(invocations).toBe(3);expect(()=>inspectGatewayCanaryAwsEvidence(a.ops)).toThrow(/NativeCompletion/);
    await expect(a.ops.verifyCleanup({keys:[],signal:new AbortController().signal})).rejects.toThrow(/CleanupKeyInventory/);
  });
});
