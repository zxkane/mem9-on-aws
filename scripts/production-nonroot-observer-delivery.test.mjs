import {test} from 'vitest';
import assert from 'node:assert/strict';
import {gzipSync} from 'node:zlib';
import {inspectObserverControlDelivery,encodeObserverControlDelivery,decodeObserverControlDelivery,bindObserverControlOverrides,assertObserverControlOverrides,OBSERVER_RUNTIME_SLOTS,observerZeroCounter,observerBytesHash as sha,observerDataHash as hash} from './lib/production-nonroot-observer-delivery.mjs';
import {describeObserverProviderFinalization} from './lib/production-nonroot-observer-runtime-provider.mjs';

/** Complete prospective delivery, with all roles/refs/21 work slots and
 * distinct full-length hashes. Synthetic DATA, never a runtime capability. */
export function completeDelivery(){
 const account='123456789012',region='ap-northeast-1',stage='pr-273',owner=sha('owner').slice(0,32),operation=sha('operation').slice(0,32),caseName='post-liveness-regression';
 const registry=JSON.stringify({issuer:'https://identity.example.com/issuer',audience:'original-read-audience',human:Array.from({length:16},(_,i)=>sha('registered-human-'+i)),m2m:Array.from({length:16},(_,i)=>sha('registered-read-machine-'+i))});
 const credentialBindings=Object.fromEntries(['clientId','clientSecret','tenantKey','identitySigningKeys','transportSigningKeys'].map(name=>{
  const store=['tenantKey','identitySigningKeys'].includes(name)?'secretsmanager':'ssm';
  return [name,{store,arn:`arn:aws:${store}:${region}:${account}:`+(store==='ssm'?`parameter/mem9-on-aws/${stage}/original-observer-registered-client/${name}`:`secret:mem9-on-aws-${stage}-${name}-original-protected-runtime-secret-AbCd12`),region,version:store==='ssm'?127:sha(name).slice(0,32),sha256:sha('original-value-commitment-'+name),bytesLength:name==='clientId'?48:4096,endpoint:`https://${store}.${region}.amazonaws.com`}];
 }));
 for(const [name,b]of Object.entries(credentialBindings)){b.valueType=b.store==='ssm'?(name==='clientId'?'String':'SecureString'):'SecretString';b.kms=b.valueType==='String'?null:{keyArn:'arn:aws:kms:'+region+':'+account+':key/00000000-0000-4000-8000-000000000001',viaService:b.store+'.'+region+'.amazonaws.com',contextKey:b.store==='ssm'?'PARAMETER_ARN':'SecretARN',contextValue:b.arn};}
 const slots=OBSERVER_RUNTIME_SLOTS.map(id=>{const kind=['source/registry','credential-adapter','context','output','runtime-finalization'].includes(id)?'local':'http',requestBytes=kind==='http'?65536:0,responseBytes=kind==='http'?1048576:0;return {id,kind,requestBytes,responseBytes,counter:{...observerZeroCounter(),logicalBytes:16777216,httpBodyBytes:requestBytes+responseBytes}};});
 slots.find(s=>s.id==='runtime-finalization').counter.logicalBytes=describeObserverProviderFinalization({allocation:{slots}}).logicalBytes;
 const charge=observerZeroCounter();for(const s of slots)for(const k of Object.keys(charge))charge[k]+=s.counter[k];
 return {version:1,kind:'fixed-observer-control-delivery',owner,operation,stage,caseName,sampleIndex:1023,captureId:sha('capture').slice(0,32),sourceTree:sha('source').slice(0,40),manifestSha256:sha('guard-manifest'),inputHash:sha('bound-input'),account,region,clusterArn:`arn:aws:ecs:${region}:${account}:cluster/mem9-on-aws-${stage}-Cluster-original-bound-network-LongId01`,taskDefinitionArn:`arn:aws:ecs:${region}:${account}:task-definition/mem9-on-aws-${stage}-fixed-original-control-route-purpose:127`,taskDefinitionHash:sha('definition'),taskRoleArn:`arn:aws:iam::${account}:role/mem9-on-aws/${stage}/original-observer-control-registered-read-runtime`,containerName:'consolidation-worker',controlImage:{rootDigest:'sha256:'+sha('root'),arm64Digest:'sha256:'+sha('arm'),configDigest:'sha256:'+sha('config')},startedMs:1900000000000,deadlineMs:1900000100000,allocation:{id:caseName+'/control-runtime/1023',quoteHash:sha('quote'),charge,slots},route:{privateOrigin:`http://mnemo.mem9-${stage}.local:8080`,gatewayUrl:'https://original-bound-gateway.gateway.example.com/mcp',jobId:'00000000-0000-4000-8000-000000000001',identityHash:sha('principal'),issuer:'https://identity.example.com/issuer',audience:'original-read-audience',transportIssuer:'gateway-target',tokenEndpoint:'https://identity.example.com/oauth2/token',jwksUri:'https://identity.example.com/issuer/.well-known/jwks.json',registryHash:sha(registry)},credentialBindings,registry};
}
const originalOverrides=()=>({cpu:'1024',memory:'2048',taskRoleArn:'arn:aws:iam::123456789012:role/mem9-on-aws/pr-273/original-observer-control-registered-read-runtime',executionRoleArn:'arn:aws:iam::123456789012:role/original-bound-execution-role',containerOverrides:[{name:'consolidation-worker',command:[],environment:[{name:'STAGE',value:'pr-273'},{name:'NODE_EXTRA_CA_CERTS',value:'/bootstrap/global-bundle.pem'}]},{name:'original-extra-container',environment:[{name:'UNCHANGED_ORIGINAL_CONFIG',value:'source-bound-value'}]}]});
test('complete real-sized delivery exceeds raw override limit and fits whole gzip delivery without omissions',()=>{
 const value=completeDelivery(),raw=JSON.stringify(value);assert.ok(raw.length>8192);assert.equal(value.allocation.slots.length,21);
 const encoded=encodeObserverControlDelivery(value),base=originalOverrides(),before=structuredClone(base),overrides=bindObserverControlOverrides(base,value.containerName,encoded),checked=assertObserverControlOverrides(overrides,value.containerName,encoded.wireSha256);
 assert.deepEqual(base,before);assert.deepEqual(checked.delivery,value);assert.deepEqual(overrides.containerOverrides[1],before.containerOverrides[1]);assert.equal(overrides.cpu,before.cpu);assert.equal(overrides.taskRoleArn,before.taskRoleArn);assert.ok(checked.characters<=8192);assert.equal(hash(checked.delivery),hash(value));
});
test('all existing override fields count; 8192 accepts and 8193 rejects',()=>{
 const value=completeDelivery(),encoded=encodeObserverControlDelivery(value),o=bindObserverControlOverrides(originalOverrides(),value.containerName,encoded);o.containerOverrides[1].environment.push({name:'BOUNDARY',value:''});
 const remaining=8192-JSON.stringify(o).length;assert.ok(remaining>0);o.containerOverrides[1].environment.at(-1).value='x'.repeat(remaining);
 assert.equal(assertObserverControlOverrides(o,value.containerName,encoded.wireSha256).characters,8192);o.containerOverrides[1].environment.at(-1).value+='x';assert.throws(()=>assertObserverControlOverrides(o,value.containerName,encoded.wireSha256),/CompleteOverridesBound/);
});
test('small env value does not permit oversized sibling container overrides',()=>{
 const v=completeDelivery(),e=encodeObserverControlDelivery(v),o=originalOverrides();o.containerOverrides[1].environment[0].value='x'.repeat(8192);assert.ok(e.wire.length<8192);assert.throws(()=>bindObserverControlOverrides(o,v.containerName,e),/CompleteOverridesBound/);
});
for(const [name,change]of [
 ['missing counter slot',v=>v.allocation.slots.pop()],['wrong task region',v=>v.taskDefinitionArn=v.taskDefinitionArn.replace('ap-northeast-1','us-west-2')],['borrowed secret account',v=>v.credentialBindings.clientSecret.arn=v.credentialBindings.clientSecret.arn.replace('123456789012','9'.repeat(12))],['same identity and transport key',v=>v.credentialBindings.identitySigningKeys={...v.credentialBindings.transportSigningKeys}],['registry changed',v=>v.registry+=' '],['metadata URL used as ingress',v=>v.route.gatewayUrl='https://169.254.170.2/'],['underfunded complete allocation',v=>v.allocation.charge.logicalBytes--],
])test('reject '+name,()=>{const v=completeDelivery();change(v);assert.throws(()=>encodeObserverControlDelivery(v));});
for(const [name,change]of [['raw length',e=>e.rawBytes--],['raw hash',e=>e.rawSha256=sha('wrong')],['compressed length',e=>e.gzipBytes++],['noncanonical base64',e=>e.data+='\n'],['truncated gzip',e=>{e.data=e.data.slice(0,-4);e.gzipBytes=Buffer.from(e.data,'base64').length;}]])test('reject changed '+name,()=>{const e=JSON.parse(encodeObserverControlDelivery(completeDelivery()).wire);change(e);assert.throws(()=>decodeObserverControlDelivery(JSON.stringify(e)));});
test('bounded decompression rejects expansion beyond declared and absolute size',()=>{
 const raw=Buffer.alloc(262145,32),gzip=gzipSync(raw);const e={version:1,encoding:'gzip+base64',rawBytes:262144,rawSha256:sha(raw),gzipBytes:gzip.length,data:gzip.toString('base64')};assert.throws(()=>decodeObserverControlDelivery(JSON.stringify(e)));
});
test('duplicate delivery override cannot replace original binding',()=>{
 const v=completeDelivery(),e=encodeObserverControlDelivery(v),o=bindObserverControlOverrides(originalOverrides(),v.containerName,e);assert.throws(()=>bindObserverControlOverrides(o,v.containerName,e),/Repeated/);
});
test('payload changed after encoding rejects before dispatch',()=>{const v=completeDelivery(),e=encodeObserverControlDelivery(v),o=bindObserverControlOverrides(originalOverrides(),v.containerName,e);o.containerOverrides[0].environment.at(-1).value+=' ';assert.throws(()=>assertObserverControlOverrides(o,v.containerName,e.wireSha256),/Changed/);});
