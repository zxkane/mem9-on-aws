import {describe,it,expect,vi} from 'vitest';
import {createRuntimeSecretReader,RUNTIME_SECRET_CACHE_MS} from './runtime-secrets.mjs';
const region='ap-northeast-1',account='123456789012',stage='pr-7';
const ssmArn=`arn:aws:ssm:${region}:${account}:parameter/mem9-on-aws/${stage}/oauth/state-hmac-key`;
const secretArn=`arn:aws:secretsmanager:${region}:${account}:secret:mem9-on-aws-${stage}-identity-signing-keys-resource-AbCd12`;
const env=()=>({STAGE:stage,AWS_REGION:region,MEM9_SECRET_ACCOUNT_ID:account,OAUTH_STATE_HMAC_KEY_PARAMETER_ARN:ssmArn,MEM9_IDENTITY_SIGNING_KEYS_SECRET_ARN:secretArn});
const parameter=(Value='private-value')=>({Parameters:[{ARN:ssmArn,Name:`/mem9-on-aws/${stage}/oauth/state-hmac-key`,Type:'SecureString',Value}],InvalidParameters:[]});
describe('fixed runtime secret references',()=>{
 it('decrypts only the full scoped ARN, preserves bytes and shares concurrent/cached reads',async()=>{
  let now=1,finish;const ssm={send:vi.fn(()=>new Promise(resolve=>{finish=resolve;}))},read=createRuntimeSecretReader({env:env(),ssm,now:()=>now});
  const a=read('oauth'),b=read('oauth');expect(ssm.send).toHaveBeenCalledTimes(1);expect(ssm.send.mock.calls[0][0].input).toEqual({Names:[ssmArn],WithDecryption:true});
  finish(parameter(' exact key bytes '));expect(await a).toBe(' exact key bytes ');expect(await b).toBe(' exact key bytes ');expect(await read('oauth')).toBe(' exact key bytes ');
  now+=RUNTIME_SECRET_CACHE_MS;ssm.send.mockResolvedValue(parameter('same-secret-next-version'));expect(await read('oauth')).toBe('same-secret-next-version');expect(ssm.send).toHaveBeenCalledTimes(2);
 });
 it('reads only AWSCURRENT from the existing named secret',async()=>{
  const secretsManager={send:vi.fn().mockResolvedValue({ARN:secretArn,VersionStages:['AWSCURRENT'],SecretString:'original-keys'})};
  expect(await createRuntimeSecretReader({env:env(),secretsManager})('identity')).toBe('original-keys');
  expect(secretsManager.send.mock.calls[0][0].input).toEqual({SecretId:secretArn,VersionStage:'AWSCURRENT'});
 });
 it.each(['missing','stage','account','region','path','plaintext'])('rejects %s before any request',async fault=>{
  const e=env(),ssm={send:vi.fn()};
  if(fault==='missing')delete e.OAUTH_STATE_HMAC_KEY_PARAMETER_ARN;
  if(fault==='stage')e.STAGE='prod';if(fault==='account')e.MEM9_SECRET_ACCOUNT_ID='1'.repeat(12);if(fault==='region')e.AWS_REGION='us-east-1';
  if(fault==='path')e.OAUTH_STATE_HMAC_KEY_PARAMETER_ARN=ssmArn+'/other';if(fault==='plaintext')e.OAUTH_STATE_HMAC_KEY='never-use-this';
  await expect(createRuntimeSecretReader({env:e,ssm})('oauth')).rejects.toThrow('RuntimeSecretReferenceInvalid');expect(ssm.send).not.toHaveBeenCalled();
 });
 it.each(['wrong-arn','wrong-name','unencrypted','missing','duplicate','invalid','empty','oversize'])('rejects %s response without returning secret bytes',async fault=>{
  const response=parameter();if(fault==='wrong-arn')response.Parameters[0].ARN+='other';if(fault==='wrong-name')response.Parameters[0].Name+='/other';if(fault==='unencrypted')response.Parameters[0].Type='String';if(fault==='missing')response.Parameters=[];if(fault==='duplicate')response.Parameters.push(response.Parameters[0]);if(fault==='invalid')response.InvalidParameters=[ssmArn];if(fault==='empty')response.Parameters[0].Value='';if(fault==='oversize')response.Parameters[0].Value='x'.repeat(4097);
  await expect(createRuntimeSecretReader({env:env(),ssm:{send:vi.fn().mockResolvedValue(response)}})('oauth')).rejects.toThrow('RuntimeSecretUnavailable');
 });
 it('never serves stale secrets on failure and can recover on the next call without cached errors',async()=>{
  let now=1;const ssm={send:vi.fn().mockResolvedValue(parameter())},read=createRuntimeSecretReader({env:env(),ssm,now:()=>now});await read('oauth');now+=RUNTIME_SECRET_CACHE_MS;
  ssm.send.mockRejectedValueOnce(new Error('LEAK-private-secret'));const failure=read('oauth');await expect(failure).rejects.toThrow('RuntimeSecretUnavailable');await failure.catch(e=>{expect(String(e)).not.toContain('LEAK');expect(e.cause).toBeUndefined();});
  expect(await read('oauth')).toBe('private-value');expect(ssm.send).toHaveBeenCalledTimes(3);
 });
 it.each([{VersionStages:['AWSPREVIOUS']},{ARN:secretArn+'wrong'},{SecretString:undefined,SecretBinary:new Uint8Array([1])}])('rejects an unrelated secret version or binary response',async delta=>{
  await expect(createRuntimeSecretReader({env:env(),secretsManager:{send:vi.fn().mockResolvedValue({ARN:secretArn,VersionStages:['AWSCURRENT'],SecretString:'private',...delta})}})('identity')).rejects.toThrow('RuntimeSecretUnavailable');
 });
});
