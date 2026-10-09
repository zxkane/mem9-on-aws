import {it,expect} from 'vitest';
import {harness,handlerSource} from './gateway-runtime-canary.fixture.mjs';
import {validateGatewayCanaryResult} from './lib/gateway-runtime-canary-evidence.mjs';

it.each(['A1','B','A2'])('fixed handler returns actual SDK-shaped service observations for %s',async phase=>{
 const h=harness({phase}),value=await h.run();validateGatewayCanaryResult(value,{scope:h.scope,keyArn:h.keyArn,request:h.event,phase});
 expect(h.calls).toHaveLength(2);expect(h.calls[0].input.KeyId).toBe(h.keyArn);expect(h.calls[0].input.EncryptionContext).toEqual({'aws:lambda:FunctionArn':h.scope.functionArn});expect(h.calls[1].input).toEqual({DryRun:true,Filters:[{Name:'vpc-id',Values:[h.scope.vpcId]}]});
 expect(h.calls.every(c=>c.client.maxAttempts===1&&c.client.credentials.accessKeyId==='ASIA'+'A'.repeat(16))).toBe(true);expect(h.closed).toEqual(['kms','ec2']);
 const serialized=JSON.stringify(value);expect(serialized).not.toMatch(/synthetic-secret|synthetic-token|explicitDeny|boundaryAllowed|Plaintext/);if(phase!=='B')expect(h.plaintext.every(v=>v===0)).toBe(true);
});
it.each(['network','missing-id','plaintext','wrong-error','ec2-success'])('never turns %s into authorization proof',async defect=>{const h=harness({defect}),value=await h.run();expect(()=>validateGatewayCanaryResult(value,{scope:h.scope,keyArn:h.keyArn,request:h.event,phase:'A1'})).toThrow();expect(h.closed).toEqual(['kms','ec2']);if(defect==='network'||defect==='missing-id')expect(h.calls).toHaveLength(1);});
it.each(['extra','bad-base64','oversize','nonce','role-key','wrong-function','architecture','credentials'])('rejects %s before service calls',async defect=>{
 const h=harness(),e=structuredClone(h.event);if(defect==='extra')e.url='https://example.com';if(defect==='bad-base64')e.ciphertextBase64+='\n';if(defect==='oversize')e.ciphertextBase64='a'.repeat(9000);if(defect==='nonce')e.nonce='bad';if(defect==='role-key')h.sandbox.process.env.CANARY_KEY_ARN=h.keyArn.replace(h.scope.accountId,'1'.repeat(12));if(defect==='wrong-function')h.context.invokedFunctionArn+=':alias';if(defect==='architecture')h.sandbox.process.arch='x64';if(defect==='credentials')h.sandbox.process.env.AWS_ACCESS_KEY_ID='AKIA'+'A'.repeat(16);
 await expect(h.sandbox.exports.handler(e,h.context)).rejects.toThrow();expect(h.calls).toEqual([]);
});
it('ambient endpoint/profile settings cannot reroute fixed service calls',async()=>{const h=harness({environment:{AWS_ENDPOINT_URL:'https://example.com',AWS_PROFILE:'other'}});await h.run();expect(h.calls.map(c=>c.client.endpoint)).toEqual(['https://kms.ap-northeast-1.amazonaws.com','https://ec2.ap-northeast-1.amazonaws.com']);expect(Buffer.byteLength(handlerSource)).toBeLessThanOrEqual(24000);});
