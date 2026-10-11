import {describe,it,expect,vi,beforeEach} from 'vitest';
import {runtimeSecretEndpoint} from './secret-endpoint.mjs';
import {createRuntimeSecretReader} from './runtime-secrets.mjs';
const clients=vi.hoisted(()=>({ssm:vi.fn(),secretsmanager:vi.fn()}));
vi.mock('@aws-sdk/client-ssm',async original=>({...await original(),SSMClient:class{
 constructor(config){clients.ssm(config);}
 async send(command){const arn=command.input.Names[0];return {Parameters:[{ARN:arn,Name:arn.slice(arn.indexOf(':parameter')+10),Type:'SecureString',Value:'synthetic-transport'}]};}
}}));
vi.mock('@aws-sdk/client-secrets-manager',async original=>({...await original(),SecretsManagerClient:class{
 constructor(config){clients.secretsmanager(config);}
 async send(command){return {ARN:command.input.SecretId,VersionStages:['AWSCURRENT'],SecretString:'synthetic-identity'};}
}}));
const region='ap-northeast-1';
const fixture=()=>({MEM9_SECRET_ENDPOINT_MODE:'private',MEM9_SECRET_SSM_VPCE_ID:'vpce-abcd',MEM9_SECRET_SSM_ENDPOINT_DNS:`vpce-abcd-synthetic.ssm.${region}.vpce.amazonaws.com`,MEM9_SECRET_SECRETSMANAGER_VPCE_ID:'vpce-abce',MEM9_SECRET_SECRETSMANAGER_ENDPOINT_DNS:`vpce-abce-synthetic.secretsmanager.${region}.vpce.amazonaws.com`});
describe('fixed runtime endpoint bindings',()=>{
 beforeEach(()=>{clients.ssm.mockClear();clients.secretsmanager.mockClear();});
 it('uses the exact AWS service endpoint with TLS, and leaves non-VPC Lambdas on the regional endpoint',()=>{
  expect(runtimeSecretEndpoint(fixture(),'ssm',region)).toBe('https://'+fixture().MEM9_SECRET_SSM_ENDPOINT_DNS);
  expect(runtimeSecretEndpoint(fixture(),'secretsmanager',region)).toBe('https://'+fixture().MEM9_SECRET_SECRETSMANAGER_ENDPOINT_DNS);
  expect(runtimeSecretEndpoint({},'ssm',region)).toBeUndefined();
 });
 for(const [name,mutate]of Object.entries({
  missing:e=>delete e.MEM9_SECRET_SSM_VPCE_ID, partial:e=>delete e.MEM9_SECRET_SECRETSMANAGER_ENDPOINT_DNS,
  mode:e=>e.MEM9_SECRET_ENDPOINT_MODE='public', ownerless:e=>delete e.MEM9_SECRET_ENDPOINT_MODE,
  endpoint:e=>e.MEM9_SECRET_SSM_ENDPOINT_DNS=e.MEM9_SECRET_SSM_ENDPOINT_DNS.replace('vpce-abcd','vpce-1234'),
  service:e=>e.MEM9_SECRET_SSM_ENDPOINT_DNS=e.MEM9_SECRET_SSM_ENDPOINT_DNS.replace('.ssm.','.s3.'),
  region:e=>e.MEM9_SECRET_SSM_ENDPOINT_DNS=e.MEM9_SECRET_SSM_ENDPOINT_DNS.replace(region,'us-west-2'),
  domain:e=>e.MEM9_SECRET_SSM_ENDPOINT_DNS+='.example.com', path:e=>e.MEM9_SECRET_SSM_ENDPOINT_DNS+='/evil',
  credentials:e=>e.MEM9_SECRET_SSM_ENDPOINT_DNS='user@'+e.MEM9_SECRET_SSM_ENDPOINT_DNS,
  url:e=>e.MEM9_SECRET_SSM_ENDPOINT_DNS='http://'+e.MEM9_SECRET_SSM_ENDPOINT_DNS,
  metadata:e=>e.MEM9_SECRET_SSM_ENDPOINT_DNS='169.254.169.254',
 }))it('rejects '+name+' without a public fallback',()=>{const e=fixture();mutate(e);expect(()=>runtimeSecretEndpoint(e,'ssm',region)).toThrow('RuntimeSecretEndpointInvalid');});
 it('wires both native clients to fixed HTTPS endpoints and ignores ambient endpoint overrides',async()=>{
  const account='123456789012',env={...fixture(),STAGE:'prod',AWS_REGION:region,MEM9_SECRET_ACCOUNT_ID:account,
   AWS_ENDPOINT_URL:'https://untrusted.example.com',
   MEM9_IDENTITY_SIGNING_KEYS_SECRET_ARN:`arn:aws:secretsmanager:${region}:${account}:secret:mem9-on-aws-prod-identity-signing-keys-synthetic-AbCd12`,
   MEM9_TRANSPORT_SIGNING_KEYS_PARAMETER_ARN:`arn:aws:ssm:${region}:${account}:parameter/mem9-on-aws/prod/namespace/transport-signing-keys`};
  const read=createRuntimeSecretReader({env});
  expect(await read('identity')).toBe('synthetic-identity');expect(await read('transport')).toBe('synthetic-transport');
  for(const service of ['ssm','secretsmanager'])expect(clients[service]).toHaveBeenCalledExactlyOnceWith({region,maxAttempts:2,ignoreConfiguredEndpointUrls:true,endpoint:runtimeSecretEndpoint(env,service,region)});
  delete env.MEM9_SECRET_SSM_ENDPOINT_DNS;
  await expect(read('identity')).rejects.toThrow('RuntimeSecretEndpointInvalid');
  expect(clients.secretsmanager).toHaveBeenCalledTimes(1);
 });
});
