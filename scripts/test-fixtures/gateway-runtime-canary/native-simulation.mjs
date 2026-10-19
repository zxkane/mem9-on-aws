// Synthetic Lambda and code-download services for broker tests. The native
// adapter is used unmodified (no test hooks), so these replace the network
// edge only: LambdaClient#send runs the reviewed handler in the fixture
// sandbox, and fetch returns the deployed inline code. Not AWS provenance.
import {readFileSync} from 'node:fs';
import {LambdaClient} from '@aws-sdk/client-lambda';
import {compileGatewayRuntimeCanaryScope} from '../../lib/gateway-runtime-canary-resources.mjs';
import {codeZip,harness} from '../../gateway-runtime-canary.fixture.mjs';

/** Install the simulation; returns restore(). defect selects one service fault. */
export function installGatewayCanaryServiceSimulation({statePath,configPath,defect}){
  const originalSend=Object.getOwnPropertyDescriptor(LambdaClient.prototype,'send'),originalFetch=globalThis.fetch;
  const invocations=[];
  const current=()=>{
    const state=JSON.parse(readFileSync(statePath,'utf8')),config=JSON.parse(readFileSync(configPath,'utf8'));
    const r=state.template.Resources,verificationId=r.CanaryFunction.Properties.FunctionName.slice(-12);
    const ownerRoleArn=r.SyntheticKey.Properties.KeyPolicy.Statement[0].Principal.AWS;
    const scope=compileGatewayRuntimeCanaryScope({accountId:config.accountId,applicationRegion:config.region,verificationId,vpcId:r.CanaryFunction.Properties.Environment.Variables.CANARY_VPC_ID,ownerRoleArn});
    return {state,scope};
  };
  LambdaClient.prototype.send=async function(command){
    const {state,scope}=current(),input=command.input,credentials=await this.config.credentials();
    if(input.FunctionName!==scope.functionArn||input.InvocationType!=='RequestResponse')throw Error('synthetic Lambda: unexpected invoke');
    const phase=state.mode==='original'?'B':'A1',number=invocations.length+1,event=JSON.parse(Buffer.from(input.Payload).toString());
    invocations.push({phase,accessKeyId:credentials.accessKeyId,functionArn:input.FunctionName});
    if(defect==='invoke-transport'&&phase==='B')throw Object.assign(Error('synthetic transport'),{code:'ETIMEDOUT'});
    const observed=await harness({phase,number,event,scope}).run();
    if(defect==='unexpected-B'&&phase==='B'){observed.results[0].outcome='success';delete observed.results[0].errorCode;observed.results[0].plaintextHash='a'.repeat(64);}
    await new Promise(resolve=>setTimeout(resolve,20));
    return {StatusCode:200,ExecutedVersion:'$LATEST',$metadata:{httpStatusCode:200,requestId:'00000000-0000-4000-8000-'+String(number).padStart(12,'0'),attempts:1,totalRetryDelay:0},
      Payload:new Uint8Array(Buffer.from(JSON.stringify(observed)))};
  };
  globalThis.fetch=async url=>{
    const {state}=current();
    if(!/^https:\/\/awslambda-synthetic\.s3\.[a-z0-9-]+\.amazonaws\.com\//.test(String(url)))throw Error('synthetic fetch: unexpected URL');
    return new Response(codeZip(state.template.Resources.CanaryFunction.Properties.Code.ZipFile));
  };
  return {invocations,restore(){
    if(originalSend)Object.defineProperty(LambdaClient.prototype,'send',originalSend);else delete LambdaClient.prototype.send;
    globalThis.fetch=originalFetch;
  }};
}
