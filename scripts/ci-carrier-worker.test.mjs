import {describe,it,expect} from 'vitest';
import {readFile,readdir,writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {Readable} from 'node:stream';
import {runCarrierBeforeCopy} from './lib/ci-carrier-worker.mjs';
import {carrierWorkerFixture} from './ci-carrier-worker.fixture.mjs';
import {inspectCarrierBuildResult} from './lib/ci-carrier-result.mjs';
import {carrierCheckpointSelection,carrierHash,measureCarrierBeforeCopyBudget} from './lib/ci-carrier-before-copy.mjs';
import {sha} from './ci-carrier.fixture.mjs';
import {carrierSqlFixtureBudget} from './lib/ci-carrier-before-copy.mjs';
const native=process.platform==='linux'&&process.arch==='arm64',nativeIt=native?it:it.skip;

for(const entry of ['source','bundled'])for(const [platform,arch]of [['linux','x64'],['darwin','arm64']])it(entry+' requires native linux/arm64 before reading configuration or calling a host: '+platform+'/'+arch,async()=>{
 const run=entry==='source'?runCarrierBeforeCopy:(await import('../.github/actions/ci-carrier-before-copy/dist/index.mjs')).runCarrierBeforeCopy;
 const saved={platform:Object.getOwnPropertyDescriptor(process,'platform'),arch:Object.getOwnPropertyDescriptor(process,'arch')};let reads=0;
 try{
  Object.defineProperty(process,'platform',{...saved.platform,value:platform});Object.defineProperty(process,'arch',{...saved.arch,value:arch});
  const env=new Proxy({}, {get(){reads++;throw Error('UnexpectedConfigurationRead');}}),seams=new Proxy({}, {ownKeys(){reads++;throw Error('UnexpectedHostRead');}});
  await expect(run(env,seams)).rejects.toThrow('CarrierWorkerNativeArm64');expect(reads).toBe(0);
 }finally{Object.defineProperty(process,'platform',saved.platform);Object.defineProperty(process,'arch',saved.arch);}
});

nativeIt('a losing successful artifact upload reaches zero HTTP acquisitions',()=>carrierWorkerFixture(async f=>{
 await expect(runCarrierBeforeCopy(f.env,f.seams)).rejects.toThrow('CarrierStartupNotWinner');expect(f.calls).toHaveLength(0);
},{loser:true}));
nativeIt('dispatch/config mismatch fails before GitHub or AWS',()=>carrierWorkerFixture(async f=>{
 f.env.INPUT_GRANT_COMMITMENT='f'.repeat(64);await expect(runCarrierBeforeCopy(f.env,f.seams)).rejects.toThrow('CarrierDispatchCommitments');expect(f.calls).toHaveLength(0);expect(f.ghCalls()).toBe(0);
}));
nativeIt('insufficient declared PG LOCAL work fails before startup or any AWS request',()=>carrierWorkerFixture(async f=>{
 const c=structuredClone(f.config);c.plan.template.fundedLocal.ci.logicalBytes=1;c.templateHash=c.plan.templateHash=carrierHash(c.plan.template);c.plan.budget=measureCarrierBeforeCopyBudget(c.plan.template).fundedRemaining;f.env.MEM9_CARRIER_WORKER_CONFIG=JSON.stringify(c);
 await expect(runCarrierBeforeCopy(f.env,f.seams)).rejects.toThrow('CarrierWorkerPgLocalBudget');expect(f.calls).toHaveLength(0);expect(f.ghCalls()).toBe(0);
}));
nativeIt('package-only LOCAL funding cannot omit fixed SQL runtime costs before startup',()=>carrierWorkerFixture(async f=>{
 const c=structuredClone(f.config);c.plan.template.fundedLocal.ci=carrierSqlFixtureBudget(c.plan.template).packageAndImportLocal.ci;c.templateHash=c.plan.templateHash=carrierHash(c.plan.template);c.plan.budget=measureCarrierBeforeCopyBudget(c.plan.template).fundedRemaining;f.env.MEM9_CARRIER_WORKER_CONFIG=JSON.stringify(c);
 await expect(runCarrierBeforeCopy(f.env,f.seams)).rejects.toThrow('CarrierWorkerSqlRuntimeBudget');expect(f.calls).toHaveLength(0);expect(f.ghCalls()).toBe(0);
}));
nativeIt('unknown initial HTTP outcome burns the one request and stops without retry',()=>carrierWorkerFixture(async f=>{
 await expect(runCarrierBeforeCopy(f.env,f.seams)).rejects.toThrow('CarrierTransportHeld');expect(f.calls).toHaveLength(1);
 const dir=(await readdir(f.tempRoot)).find(n=>n.startsWith('mem9-carrier-consumer-')),text=await readFile(join(f.tempRoot,dir,'journal.jsonl'),'utf8');expect(text).toContain('"unknown"');expect(text).not.toContain('synthetic-oidc');
},{mutateHttp:()=>{throw Error('synthetic-network-unknown');}}));
nativeIt('rejects an unauthenticated grant before fetching the context or base',()=>carrierWorkerFixture(async f=>{
 await expect(runCarrierBeforeCopy(f.env,f.seams)).rejects.toThrow();expect(f.calls.map(c=>c.action)).toEqual(['OIDC','AssumeRoleWithWebIdentity','GetCallerIdentity','GET']);
},{mutateHttp:c=>{if(c.action==='GET'){const body=Buffer.from('{}');return {response:{statusCode:200,headers:{'content-length':'2','x-amz-server-side-encryption':'aws:kms','x-amz-server-side-encryption-aws-kms-key-id':'arn:aws:kms:ap-northeast-1:123456789012:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee','x-amz-server-side-encryption-bucket-key-enabled':'true'},body:Readable.from([body])}};}}}));
nativeIt('rejects a non-starport URL without following it or uploading anything',()=>carrierWorkerFixture(async f=>{
 await expect(runCarrierBeforeCopy(f.env,f.seams)).rejects.toThrow('CarrierBlobEndpoint');expect(f.calls.at(-1).action).toBe('GetDownloadUrlForLayer');expect(f.calls.some(c=>['S3BlobGet','InitiateLayerUpload','PUT'].includes(c.action))).toBe(false);
},{mutateHttp:c=>{if(c.action==='GetDownloadUrlForLayer'){const q=JSON.parse(c.request.body),body=Buffer.from(JSON.stringify({layerDigest:q.layerDigest,downloadUrl:'https://example.com/not-a-layer'}));return {response:{statusCode:200,headers:{'content-length':String(body.length)},body:Readable.from([body])}};}}}));
nativeIt('enforces the authenticated descriptor size and records the aggregate debit before a failing blob read',()=>carrierWorkerFixture(async f=>{
 await expect(runCarrierBeforeCopy(f.env,f.seams)).rejects.toThrow('CarrierTransportHeld');expect(f.calls.at(-1).action).toBe('S3BlobGet');
 const dir=(await readdir(f.tempRoot)).find(n=>n.startsWith('mem9-carrier-consumer-')),events=(await readFile(join(f.tempRoot,dir,'journal.jsonl'),'utf8')).trim().split('\n').map(JSON.parse),request=events.find(e=>e.type==='request'&&e.data.purpose==='baseBlob');
 expect(request.data.caps.responseBytes).toBe(request.data.blobDebit.descriptor.size);expect(request.data.caps.responseBytes).toBeLessThan(f.f.template.profiles.baseBlob.maxObjectBytes);expect(events.at(-1).type).toBe('unknown');
},{mutateHttp:c=>{if(c.action==='S3BlobGet'){const body=Buffer.alloc(1048576,1);return {response:{statusCode:200,headers:{'content-length':String(body.length)},body:Readable.from([body])}};}}}));
describe.skipIf(!native||process.env.MEM9_CARRIER_NATIVE_TEST!=='1')('complete native carrier worker with real SDK serialization and mocked HTTP',()=>{
 for(const defect of ['short','denied'])it('fixture '+defect+' stops its single GET before SQL or registry publication',async()=>{
  const material=JSON.parse(await readFile(process.env.MEM9_CARRIER_ORIGINAL_MATERIAL,'utf8'));
  return carrierWorkerFixture(async f=>{
   await expect(runCarrierBeforeCopy(f.env,f.seams)).rejects.toThrow('CarrierTransportHeld');expect(f.calls.filter(c=>c.request.path.endsWith('/fixture.oci.tar'))).toHaveLength(1);expect(f.calls.at(-1).request.path).toMatch(/fixture[.]oci[.]tar$/);expect(f.result()).toBeUndefined();expect(f.destination.size).toBe(0);
  },{sourceOnly:true,nativeBase:true,material,mutateHttp:c=>{if(c.request.path.endsWith('/fixture.oci.tar'))return {response:{statusCode:defect==='denied'?403:200,headers:{'content-length':'1'},body:Readable.from([Buffer.from('x')])}};}});
 },120000);
 for(const entry of ['source','bundled'])it(entry+' publishes BUILD and actual SQL evidence after separate fixture GET, without any scan call',async()=>{const material=JSON.parse(await readFile(process.env.MEM9_CARRIER_ORIGINAL_MATERIAL,'utf8'));return carrierWorkerFixture(async f=>{
  const run=entry==='source'?runCarrierBeforeCopy:(await import('../.github/actions/ci-carrier-before-copy/dist/index.mjs')).runCarrierBeforeCopy;
  const result=await run(f.env,f.seams);
  const raw=f.result(),body=JSON.parse(raw);
  expect(result).toMatchObject({kind:'carrier-build-published',resultHash:sha(raw)});
  expect(body.kind).toBe('carrier-ci-build-result');expect(body.bindingHash).toBe(result.bindingHash);expect(body.buildEvidence.processStopped).toBe(true);
  expect(body.version).toBe(3);expect(body.sqlAcceptance.record.cases.map(c=>c.exitCode)).toEqual([0,1,1,1,1,1,1,1]);expect(body.consumerPrefix.used.fixtureGet).toBe(1);expect(body.sqlAcceptance.record.fixture.package.archive).toEqual(f.config.plan.template.sqlFixture.archive);
  if(process.env.MEM9_CARRIER_SQL_NOJIT_TEST==='1')expect(body.sqlAcceptance.record.fixture.jit).toEqual({setting:'off',source:'command line'});
  if(process.env.MEM9_CARRIER_SQL_DESCRIPTOR){const descriptor=await readFile(process.env.MEM9_CARRIER_SQL_DESCRIPTOR);expect(sha(descriptor)).toBe(process.env.MEM9_CARRIER_SQL_DESCRIPTOR_SHA256);expect(JSON.parse(descriptor)).toEqual(f.config.plan.template.sqlFixture);}
  expect(body.consumerPrefix.local.logicalBytes).toBeLessThanOrEqual(f.config.plan.template.fundedLocal.ci.logicalBytes);
  console.log(JSON.stringify({kind:'synthetic-only-carrier-local-usage',entry,local:body.consumerPrefix.local,wire:body.consumerPrefix.wire}));
  const startup=body.consumerPrefix.events[0].data.startup,claim=carrierCheckpointSelection(f.config.plan,f.binding,Object.fromEntries(['nonce','scopeHash','artifactId','artifactDigest'].map(k=>[k,startup[k]]))).claim;
  expect(inspectCarrierBuildResult(body,{plan:f.config.plan,binding:f.binding,claim})).toEqual(body);
  expect(body.derivedMaterial.kind).toBe('carrier-derived-runtime-material');expect(body.derivedMaterial.contextHash).toBe(f.config.plan.context.sha256);
  expect(body).not.toHaveProperty('derivedRecord');
  for(const key of ['derivedMaterial','consumerPrefix','logBase64']){const missing={...body};delete missing[key];expect(()=>inspectCarrierBuildResult(missing,{plan:f.config.plan,binding:f.binding,claim})).toThrow('CarrierResultFields');}
  expect(()=>inspectCarrierBuildResult({...body,derivedRecord:body.derivedMaterial},{plan:f.config.plan,binding:f.binding,claim})).toThrow('CarrierResultFields');
  expect(f.destination.has(body.image.rootDigest)).toBe(true);expect(sha(Buffer.from(body.logBase64,'base64'))).toBe(body.buildEvidence.logHash);expect(sha(body.metadata)).toBe(body.buildEvidence.metadataHash);
  expect(f.calls.some(c=>['DescribeImageScanFindings','StartImageScan'].includes(c.action))).toBe(false);
  expect(f.calls.filter(c=>c.action==='AssumeRoleWithWebIdentity')).toHaveLength(1);
  expect(f.calls.filter(c=>c.action==='PUT')).toHaveLength(1);
  expect(body).not.toHaveProperty('artifactSecurity');expect(body).not.toHaveProperty('completedJob');
  expect(raw.toString()).not.toContain('synthetic-session');expect(raw.toString()).not.toContain('downloadUrl');
  const leftovers=await readdir(f.tempRoot);expect(leftovers.every(n=>n.startsWith('mem9-carrier-consumer-'))).toBe(true);
  if(process.env.MEM9_CARRIER_SQL_EVIDENCE_DIRECTORY)await writeFile(join(process.env.MEM9_CARRIER_SQL_EVIDENCE_DIRECTORY,entry+'-worker-result.local.json'),raw,{flag:'wx',mode:0o600});
 },{sourceOnly:true,nativeBase:true,material,nojitPg:process.env.MEM9_CARRIER_SQL_NOJIT_TEST==='1'});},240000);
});
