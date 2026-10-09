import {it,expect} from 'vitest';
import {readFile,mkdtemp,rm,chmod} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import net from 'node:net';
import {execFile} from 'node:child_process';
import {gatewayBoundaryProbeCases,gatewayBoundaryVerificationPlan,expectedGatewayBoundaryPolicyDocument} from './lib/gateway-workload-boundary.mjs';
import {verifyGatewayRuntimeSourceMaterial,requestGatewayRuntimeSourceGate} from './lib/gateway-runtime-source-gate.mjs';
import {validateGatewayRuntimeCanaryEvidence} from './lib/gateway-runtime-canary-evidence.mjs';
import {inspectGatewayCanaryAwsEvidence} from './lib/gateway-runtime-canary-aws.mjs';
import {evidenceFixture,handlerSource} from './gateway-runtime-canary.fixture.mjs';
import {classifyChangedPaths} from './classify-infra-changes.mjs';
const contract={partition:'aws',accountId:'123456789012',applicationRegion:'ap-northeast-1',policyRevision:'r1'};

it('preserves all original cases and explicit denies; only four source cases require real runtime evidence',()=>{
 const original=gatewayBoundaryProbeCases(contract),plan=gatewayBoundaryVerificationPlan(contract);
 expect(plan.runtime).toHaveLength(4);expect(plan.simulation).toHaveLength(28);
 expect(plan.runtime.every(p=>p.expected==='explicitDeny'&&p.name.endsWith('/direct-forged-lambda'))).toBe(true);
 expect([...plan.simulation,...plan.runtime].sort((a,b)=>a.name.localeCompare(b.name))).toEqual(original.sort((a,b)=>a.name.localeCompare(b.name)));
 expect(plan.simulation.filter(p=>p.name.endsWith('/cold-start'))).toHaveLength(4);
});
async function fixture(){
 const f=await evidenceFixture(),material={evidence:f.evidence,expected:f.expected,validation:validateGatewayRuntimeCanaryEvidence(f.evidence,f.expected),cleanup:[{Arn:f.evidence.keyArn,KeyState:'PendingDeletion'}]};
 const options={boundary:f.evidence.originalBoundary,contract:{...contract,accountId:f.scope.accountId},policyVersion:'v1',handlerSource,source:{commit:'a'.repeat(40),tree:'b'.repeat(40)}};
 return {material,options};
}
it('semantic gate joins actual full A/B/A schema to exact reviewed code and current boundary version',async()=>{
 const f=await fixture(),r=verifyGatewayRuntimeSourceMaterial(f.material,f.options);
 expect(r.kind).toBe('gateway-source-condition-verified');expect(r.source).toEqual(f.options.source);expect(r).not.toHaveProperty('EvalDecision');expect(r.coverage).toEqual(['kms-source-condition','ec2-source-condition']);
});
it.each(['policy-version','handler','scope','boundary','manual-pass','cleanup','missing-round','changed-validation'])('semantic gate rejects %s',async defect=>{
 const f=await fixture();
 if(defect==='policy-version')f.options.policyVersion='v2';if(defect==='handler')f.options.handlerSource+='\n';if(defect==='scope')f.options.contract.applicationRegion='us-west-2';if(defect==='boundary')f.options.boundary={Version:'2012-10-17',Statement:[]};
 if(defect==='manual-pass')f.material={pass:true};if(defect==='cleanup')f.material.cleanup[0].KeyState='Enabled';if(defect==='missing-round')f.material.evidence.rounds.pop();if(defect==='changed-validation')f.material.validation={authority:true};
 expect(()=>verifyGatewayRuntimeSourceMaterial(f.material,f.options)).toThrow();
});
it('JSON cannot supply native provenance to the actual owner getter',()=>{
 for(const value of [{},{cleanupVerified:true,rounds:[1,2,3]},{status:'OBSERVATIONS_COMPLETE',cleanupComplete:true},{kind:'boundary-read-only',verified:true}])expect(()=>inspectGatewayCanaryAwsEvidence(value)).toThrow(/NativeCompletion/);
});
it('runtime request without an owner channel fails before any network or cloud operation',async()=>{
 await expect(requestGatewayRuntimeSourceGate({boundary:expectedGatewayBoundaryPolicyDocument(contract),contract,policyVersion:'v1',socketPath:null})).rejects.toThrow(/NativeOwnerRequired/);
});
it('real verifier CLI fails closed without a native broker; matrix output stays explicitly separate',async()=>{
 const env={PATH:process.env.PATH,WORKLOAD_BOUNDARY_ACCOUNT_ID:contract.accountId,WORKLOAD_BOUNDARY_APPLICATION_REGION:contract.applicationRegion,WORKLOAD_BOUNDARY_PARTITION:'aws',WORKLOAD_BOUNDARY_POLICY_REVISION:'r1',WORKLOAD_BOUNDARY_GATEWAY_POLICY_VERSION:'v1'};
 const run=(mode,input='')=>new Promise((resolve,reject)=>{const child=execFile(process.execPath,['scripts/verify-workload-permissions-boundary.mjs',mode],{env,timeout:3000},(error,stdout,stderr)=>error?reject(error):resolve({stdout,stderr}));child.stdin.end(input);});
 const result=await run('--gateway-simulation-probes');expect(JSON.parse(result.stdout)).toEqual(gatewayBoundaryVerificationPlan(contract).simulation);
 await expect(run('--gateway-runtime',JSON.stringify(expectedGatewayBoundaryPolicyDocument(contract)))).rejects.toMatchObject({code:1});
 const body=await readFile(new URL('./deploy-workload-permissions-boundary.sh',import.meta.url),'utf8');
  expect(body).toContain('--gateway-runtime');expect(body).toContain('--gateway-simulation-probes');expect(body.indexOf('Missing or invalid runtime evidence')).toBeLessThan(body.indexOf('aws cloudformation update-stack'));
  expect(body).toContain('[[ "$verify_only" != "true" ]] && ! WORKLOAD_BOUNDARY_ACCOUNT_ID=');
  expect(body).toContain('Read-only boundary documents and IAM simulations verified; runtime source conditions require guarded owner verification.');
});
it('gate-only source changes use the existing code-only preparation classification',()=>{
 expect(classifyChangedPaths(['scripts/lib/gateway-runtime-source-gate.mjs','scripts/lib/gateway-workload-boundary.mjs','scripts/verify-workload-permissions-boundary.mjs','scripts/deploy-workload-permissions-boundary.sh'])).toEqual({workloadChanged:false,applicationInfrastructureChanged:false,awsMutationRequired:false});
});
it('both real CI preflights retain their read-only invocation',async()=>{
 const workflow=await readFile(new URL('../.github/workflows/infra-ci.yml',import.meta.url),'utf8');
 expect([...workflow.matchAll(/deploy-workload-permissions-boundary\.sh --verify-only/g)]).toHaveLength(2);
});
it.each(['valid','denied','wrong-policy','old-request','partial'])('local broker framing: %s (synthetic transport, no native-origin claim)',async kind=>{
 const f=await fixture(),directory=await mkdtemp(join(tmpdir(),'gateway-gate-')),path=join(directory,'gate.sock');
 const server=net.createServer(socket=>{let chunks=[];socket.on('data',chunk=>{chunks.push(chunk);const bytes=Buffer.concat(chunks);if(bytes.length<4||bytes.length<bytes.readUInt32BE(0)+4)return;
  const request=JSON.parse(bytes.subarray(4));expect(request.argv.slice(0,2)).toEqual(['gateway-runtime','verify-source']);expect(request.argv).not.toContain('simulate-custom-policy');
  const receipt=verifyGatewayRuntimeSourceMaterial(f.material,f.options);const body=Buffer.from(JSON.stringify({version:1,id:kind==='old-request'?'0'.repeat(32):request.id,status:kind==='denied'?77:0,stdout:Buffer.from(JSON.stringify(kind==='wrong-policy'?{...receipt,policyHash:'0'.repeat(64)}:receipt)).toString('base64'),stderr:''}));
  const frame=Buffer.alloc(body.length+4);frame.writeUInt32BE(body.length);body.copy(frame,4);socket.end(kind==='partial'?frame.subarray(0,7):frame);
 });});
 await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(path,resolve);});await chmod(path,0o600);
 try{const promise=requestGatewayRuntimeSourceGate({...f.options,socketPath:path});if(kind==='valid')expect((await promise).kind).toBe('gateway-source-condition-verified');else await expect(promise).rejects.toThrow(/GatewayRuntimeSource/);}
 finally{await new Promise(resolve=>server.close(resolve));await rm(directory,{recursive:true,force:true});}
});
