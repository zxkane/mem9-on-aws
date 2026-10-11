import {afterEach, beforeEach, expect, it, vi} from 'vitest';
import {runtimeSecretsManagerPermissions} from './runtime-secret-permissions';

const region='ap-northeast-1',account='123456789012';
const secret=`arn:aws:secretsmanager:${region}:${account}:secret:mem9-on-aws-prod-identity-signing-keys-fixture`;
const key=`arn:aws:kms:${region}:${account}:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee`;
const output=(value:unknown):any=>({value,apply:(fn:(value:any)=>unknown)=>output(fn(value))});
const unwrap=(value:any):any=>value&&typeof value==='object'
  ? 'value' in value?unwrap(value.value):Array.isArray(value)?value.map(unwrap):Object.fromEntries(Object.entries(value).map(([k,v])=>[k,unwrap(v)])):value;
let lookup:ReturnType<typeof vi.fn>;
beforeEach(()=>{
  lookup=vi.fn(()=>({arn:output(key)}));
  vi.stubGlobal('aws',{kms:{getKeyOutput:lookup}});
  vi.stubGlobal('$jsonStringify',(value:unknown)=>output(JSON.stringify(unwrap(value))));
  vi.stubGlobal('$interpolate',(strings:TemplateStringsArray,...values:unknown[])=>output(strings.reduce((text,s,i)=>text+s+(i<values.length?unwrap(values[i]):''),'')));
});
afterEach(()=>vi.unstubAllGlobals());

it('uses the existing CMK and exact secret context with Secrets Manager mediation',()=>{
  const permissions=unwrap(runtimeSecretsManagerPermissions([{arn:secret,kmsKeyId:key}],region,account));
  expect(lookup).toHaveBeenCalledExactlyOnceWith({keyId:key,region});
  expect(permissions).toEqual([
    {actions:['secretsmanager:GetSecretValue'],resources:[secret]},
    {actions:['kms:Decrypt'],resources:[key],conditions:[
      {test:'StringEquals',variable:'kms:ViaService',values:[`secretsmanager.${region}.amazonaws.com`]},
      {test:'ArnEquals',variable:'kms:EncryptionContext:SecretARN',values:[secret]},
    ]},
  ]);
});
it('retains separate exact secret contexts for proxy identity and tenant reads',()=>{
  const tenant=secret.replace('identity-signing-keys','tenant-api-key');
  const permissions=unwrap(runtimeSecretsManagerPermissions([{arn:secret,kmsKeyId:key},{arn:tenant}],region,account));
  expect(lookup.mock.calls).toEqual([[{keyId:key,region}],[{keyId:'alias/aws/secretsmanager',region}]]);
  expect(permissions[1].conditions[1].values).toEqual([secret]);
  expect(permissions[2].conditions[1].values).toEqual([tenant]);
});
it.each([key.replace(account,'0'.repeat(12)),key.replace(region,'us-west-2'),key.replace(':key/',':alias/')])('rejects a key outside the owned key scope: %s',arn=>{
  lookup.mockReturnValue({arn:output(arn)});
  expect(()=>runtimeSecretsManagerPermissions([{arn:secret,kmsKeyId:key}],region,account)).toThrow('RuntimeSecretKeyScope');
});
