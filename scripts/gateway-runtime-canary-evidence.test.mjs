import {it,expect} from 'vitest';
import {createHash} from 'node:crypto';
import {evidenceFixture,codeZip,handlerSource} from './gateway-runtime-canary.fixture.mjs';
import {validateGatewayRuntimeCanaryEvidence as verify,verifyGatewayCanaryCode,verifyGatewayCanaryPhase,gatewayCanaryPhaseDiagnostic,gatewayCanaryInternalReason} from './lib/gateway-runtime-canary-evidence.mjs';

const diagnosticInput={verificationId:'abcdef012345',templateHash:'a'.repeat(64),phase:'B',stage:'response-validation',observation:'response',startedMs:1000,completedMs:2000};
it('diagnostic payload hashing is bounded and labels partial hashing explicitly',()=>{
 const raw=Buffer.alloc(20000,65),value=gatewayCanaryPhaseDiagnostic({...diagnosticInput,response:{Payload:raw}});
 expect(value.payloadBytes).toBe(20000);expect(value.payloadHashedBytes).toBe(16384);expect(value.payloadFormat).toBe('oversized');
 expect(value.payloadHash).toBe(createHash('sha256').update(raw.subarray(0,16384)).digest('hex'));
 expect(Buffer.byteLength(JSON.stringify(value))).toBeLessThanOrEqual(4096);
});
it.each(['GatewayCanaryInput','GatewayCanaryIdentity','GatewayCanaryCredentials','GatewayCanaryDeadline','GatewayCanarySdk'])('retains fixed handler reason %s with no stack or message field',reason=>{
 const secret='do-not-log-plaintext-key-or-url',value=gatewayCanaryPhaseDiagnostic({...diagnosticInput,response:{FunctionError:'Unhandled',Payload:Buffer.from(JSON.stringify({errorType:'Error',errorMessage:reason,stackTrace:[secret],secret}))}});
 expect(value.handlerReason).toBe(reason);expect(value.functionErrorType).toBe('Error');
 expect(JSON.stringify(value)).not.toContain(secret);expect(value).not.toHaveProperty('errorMessage');expect(value).not.toHaveProperty('stackTrace');
});
it('diagnostics hash unknown handler errors and ignore hostile unknown fields and accessors',()=>{
 const secret='secret-value',raw=Buffer.from(JSON.stringify({errorType:secret,errorMessage:secret,results:[{service:secret,action:secret,outcome:secret,errorCode:secret,requestId:secret}],unknown:{credentials:secret,url:secret,plaintext:secret}}));
 const response={Payload:raw,FunctionError:'Unhandled',$metadata:{requestId:secret,httpStatusCode:200}};
 Object.defineProperty(response,'errorMessage',{get(){throw Error('accessor must not run');}});
 const value=gatewayCanaryPhaseDiagnostic({...diagnosticInput,response});
 expect(value.functionErrorType).toBe('unrecognized');expect(value.handlerReason).toBe('unrecognized');
 expect(value.handlerReasonHash).toBe(createHash('sha256').update(secret).digest('hex'));
 expect(value.services[0].outcome).toBe('unrecognized');expect(value.requestId).toBe(null);
 expect(JSON.stringify(value)).not.toContain(secret);expect(value.payloadHash).toBe(createHash('sha256').update(raw).digest('hex'));
 const error=Object.defineProperty({},'message',{get(){throw Error('must not read getter');}});
 expect(gatewayCanaryInternalReason(error)).toBe('GatewayRuntimeCanaryOperationFailed');
});
it.each([undefined,'invalid',{},Buffer.from('not-json'),Buffer.from('[]')])('classifies malformed diagnostic payload without promoting it to evidence',Payload=>{
 const value=gatewayCanaryPhaseDiagnostic({...diagnosticInput,response:{Payload}});
 expect(['missing','invalid-type','malformed-json','non-object']).toContain(value.payloadFormat);
 expect(value).not.toHaveProperty('authority');expect(value).not.toHaveProperty('securityPass');
});
it('verifies raw handler observations, full stable readbacks and actual ZIP for A→B→A',async()=>{const f=await evidenceFixture(),v=verify(f.evidence,f.expected);expect(v.authority).toBe(false);expect(v.coverage).toEqual(['kms-source-condition','ec2-source-condition']);expect(v).not.toHaveProperty('EvalDecision');expect(Object.isFrozen(v)).toBe(true);});
it.each(['missing-pin','changed-pin','manual-pass','order','missing-A2','role-id','code','layers','identity','key-policy','key-grant','boundary-version','boundary','context','request-id','invoke-error','wrong-key','runtime','time','strict-allowed','ec2-wrong-error'])('rejects %s even with a consistent envelope checksum',async defect=>{
 const f=await evidenceFixture(),e=structuredClone(f.evidence),x=structuredClone(f.expected),b=e.rounds[1];
 if(defect==='missing-pin')delete x.evidenceHash;if(defect==='changed-pin')x.evidenceHash='f'.repeat(64);if(defect==='manual-pass')e.pass=true;if(defect==='order')e.rounds.reverse();if(defect==='missing-A2')e.rounds.pop();
 if(defect==='layers')for(const round of e.rounds)for(const point of ['before','after'])round[point].function.Layers=[{Arn:'arn:aws:lambda:ap-northeast-1:'+e.scope.accountId+':layer:unapproved-sdk:1'}];
 if(defect==='role-id')b.before.role.RoleId='AROAREPLACED000001';if(defect==='code')b.before.function.CodeSha256=Buffer.alloc(32).toString('base64');if(defect==='identity')b.before.identityPolicy.Statement[0].Resource='*';if(defect==='key-policy')b.before.keyPolicy.Statement[0].Principal.AWS='*';if(defect==='key-grant')b.before.keyGrants=[{GrantId:'unexpected'}];if(defect==='boundary-version')e.rounds[2].before.boundary.versionId='v2';if(defect==='boundary')b.before.boundary.document=e.rounds[0].before.boundary.document;if(defect==='invoke-error')b.invoke.response.FunctionError='Unhandled';if(defect==='wrong-key')b.before.key.Arn+='wrong';if(defect==='time')b.after.startedMs=b.invoke.startedMs-1;
 if(['context','request-id','runtime','strict-allowed','ec2-wrong-error'].includes(defect)){const v=JSON.parse(Buffer.from(b.invoke.response.Payload,'base64'));if(defect==='context')v.ciphertextHash='f'.repeat(64);if(defect==='request-id')v.results[0].requestId='';if(defect==='runtime')v.runtime.sdk.kms='3.9999.0';if(defect==='strict-allowed')v.results[0].outcome='success';if(defect==='ec2-wrong-error')v.results[1].errorCode='DryRunOperation';b.invoke.response.Payload=Buffer.from(JSON.stringify(v)).toString('base64');}
 if(!['missing-pin','changed-pin'].includes(defect))x.evidenceHash=f.hash(e);expect(()=>verify(e,x)).toThrow();
});
it.each(['bytes','different-source','filename','trailing','two-files'])('ZIP validation rejects %s',defect=>{let zip=codeZip(),source=handlerSource;if(defect==='bytes'){zip=Buffer.from(zip);zip[35]^=1;}if(defect==='different-source')source+='\n';if(defect==='filename')zip=codeZip(source,'other.js');if(defect==='trailing')zip=Buffer.concat([zip,Buffer.from('trailing')]);if(defect==='two-files'){zip=Buffer.from(zip);zip.writeUInt16LE(2,zip.length-12);}const codeSha=createHash('sha256').update(zip).digest('base64');expect(()=>verifyGatewayCanaryCode(zip,source,codeSha)).toThrow();});
it('lifecycle phase callback binds native state hashes and original raw Invoke payload',async()=>{const f=await evidenceFixture(),round=f.evidence.rounds[0],state={keyArn:f.evidence.keyArn,boundaryArn:f.scope.comparisonArn,handlerHash:f.plan.handlerHash,originalPolicyHash:f.plan.comparison.originalHash,comparisonPolicyHash:f.plan.comparison.comparisonHash},packet={version:1,kind:'gateway-runtime-canary-phase',request:f.evidence.request,invoke:round.invoke},context={phase:'A1',scope:f.scope,reference:state,before:state,after:state,plan:f.plan};expect(verifyGatewayCanaryPhase(packet,context).authority).toBe(false);expect(()=>verifyGatewayCanaryPhase(packet,{...context,after:{...state,handlerHash:'f'.repeat(64)}})).toThrow();});
