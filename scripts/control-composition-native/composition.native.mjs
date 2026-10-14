import test from 'node:test';
import assert from 'node:assert/strict';
import {readdir,readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {fixture,admission} from './fixture.mjs';
import {describeProductionControlComposition,describeProductionControlCompositionFunding,inspectProductionControlComposition,compositionUstarPath} from '../lib/production-control-composition.mjs';
import {composeProductionControl,inspectProductionControlCompositionOutput,closeProductionControlCompositionOutput,captureProductionControlComposition} from '../lib/production-control-composition-producer.mjs';
import {verifyProductionControlCompositionStatement,completeProductionControlCompositionCapture} from '../lib/production-control-composition-provenance.mjs';
import {productionControlCompositionSnapshot,reserveProductionControlComposition} from '../lib/production-control-composition-lifetime.mjs';
import {inspectImageFilesystemEntries,inspectImageFilesystem,inspectImageFilesystemEvidence} from '../lib/production-image-filesystem.mjs';
import {createImageBudget,readControlImageGraph} from '../lib/production-image-graph.mjs';

test('closed calculator prices exact canonical tar and rejects rehashed omissions',async()=>{
 const f=await fixture();try{
  assert.equal(f.plan.tarBytes,2560);assert.equal(f.plan.tarEntries,2);
  assert.equal(inspectProductionControlComposition(f.plan).planHash,f.plan.planHash);
  const bad=structuredClone(f.input);bad.copyManifest.shift();assert.throws(()=>describeProductionControlComposition(bad),/Parent/);
  assert.throws(()=>compositionUstarPath('../escape'),/Path/);
  assert.throws(()=>compositionUstarPath('x'.repeat(101)),/UstarPath/);
  const tampered=structuredClone(f.plan);tampered.bounds.graphBytes--;assert.throws(()=>inspectProductionControlComposition(tampered),/PlanChanged/);
 }finally{await f.remove();}
});
test('genuine startup and original debit fund the native producer and complete graph verification',async()=>{
 const f=await fixture();let a,out;try{
  a=await admission(f);const before=JSON.stringify(a.originalGrant);out=await composeProductionControl(a);
  const result=inspectProductionControlCompositionOutput(out);
  assert.equal(result.record.tarBytes,2560);assert.equal(result.record.tarEntries,2);
  assert.notEqual(result.record.image.rootDigest,f.plan.input.base.image.rootDigest);
  assert.equal(result.record.builder,'mem9-native-control-composition/v1');
  assert.equal(result.graph.inventory.attestations.length,1);
  const members=inspectImageFilesystemEntries(result.filesystem);
  assert.equal(members.find(r=>r.path==='app/a.mjs').content.sha256,f.plan.input.copyManifest[1].sha256);
  const layer=await readFile(join(result.directory,'blobs',result.record.layer.digest.slice(7)));
  assert.equal(layer.length,f.plan.tarBytes);assert.equal(layer.toString('ascii',257,263),'ustar\0');
  assert.equal(JSON.stringify(a.originalGrant),before);
  assert.ok(productionControlCompositionSnapshot(a.allocation).spent.logicalBytes>0);
  await closeProductionControlCompositionOutput(out);out=null;
  assert.deepEqual(await readdir(join(f.directory,'mem9-control-composition-'+productionControlCompositionSnapshot(a.allocation).allocationId)),['journal.jsonl']);
 }finally{if(out)await closeProductionControlCompositionOutput(out);await a?.close();await f.remove();}
});
test('JSON allocation and modified original debit cannot start the producer',async()=>{
 const f=await fixture();try{
  await assert.rejects(composeProductionControl({plan:f.plan,allocation:{kind:'native-control-composition-allocation'}}),/NativeAllocation/);
  await assert.rejects(admission(f,{mutateResponse:r=>r.grantSet.debit.events[0].data.charge.logicalBytes--}));
 }finally{await f.remove();}
});
test('inherited ONBUILD holds before producing metadata and cleans owned output',async()=>{
 const f=await fixture({onBuild:true});let a;try{
  a=await admission(f);await assert.rejects(composeProductionControl(a),/InheritedTrigger/);
  assert.equal(productionControlCompositionSnapshot(a.allocation).held,true);
  const path=join(f.directory,'mem9-control-composition-'+productionControlCompositionSnapshot(a.allocation).allocationId);
  assert.deepEqual(await readdir(path),['journal.jsonl']);
 }finally{await a?.close();await f.remove();}
});
test('LOCAL admission failure preserves counters and permits owned cleanup',async()=>{
 const f=await fixture();let a;try{
  a=await admission(f);const before=productionControlCompositionSnapshot(a.allocation);
  assert.throws(()=>reserveProductionControlComposition(a.allocation,{ecrRequests:0,httpBodyBytes:0,logicalBytes:before.quota.logicalBytes,uncompressedBytes:0,processedEntries:0}),/Capacity/);
  assert.deepEqual(productionControlCompositionSnapshot(a.allocation).spent,before.spent);
 }finally{await a?.close();await f.remove();}
});
for(const field of ['mode','uid','gid','sha256','bytesLength'])test('full native source recheck rejects funded COPY substitution: '+field,async()=>{
 const f=await fixture();let a;try{
  const input=structuredClone(f.input),row=input.copyManifest.find(r=>r.type==='file');
  row[field]=field==='sha256'?'f'.repeat(64):row[field]+1;
  f.plan=describeProductionControlComposition(input);f.funding=describeProductionControlCompositionFunding({plan:f.plan,catalog:f.funding.catalog,
   cleanup:{owner:f.funding.parts.ownerCleanup,ci:f.funding.parts.ciCleanup},recordCounts:f.funding.recordCounts});
  a=await admission(f);await assert.rejects(composeProductionControl(a),/CopyChanged|SourceEquivalent/);
  assert.deepEqual(await readdir(join(f.directory,'mem9-control-composition-'+productionControlCompositionSnapshot(a.allocation).allocationId)),['journal.jsonl']);
 }finally{await a?.close();await f.remove();}
});
test('actual native provenance and in-progress capture require later genuine successful completion',async()=>{
 const f=await fixture();let a,out;try{
  a=await admission(f);out=await composeProductionControl(a);const {record:r}=inspectProductionControlCompositionOutput(out);
  const expected={plan:f.plan,actualMain:a.actualMain,arm64Digest:r.image.arm64Digest,startedMs:r.startedMs,completedMs:r.serializedMs};
  assert.deepEqual(verifyProductionControlCompositionStatement(r.statement,expected),r.statement);
  const wrong=structuredClone(r.statement);wrong.predicate.runDetails.builder.id='buildkit';
  assert.throws(()=>verifyProductionControlCompositionStatement(wrong,expected),/ProvenanceChanged/);
  assert.throws(()=>{r.image.rootDigest='sha256:'+'0'.repeat(64);},TypeError);
  const run={id:77,run_attempt:1,event:'push',head_sha:a.actualMain.mainRevision,head_branch:'main',path:'.github/workflows/infra-ci.yml',
   repository:{full_name:f.source.repository},status:'in_progress',conclusion:null};
  const start=new Date(r.startedMs-10).toISOString(),end=new Date(r.completedMs+10).toISOString();
  const job={id:22,run_id:77,run_attempt:1,head_sha:a.actualMain.mainRevision,name:'Build image transition control',status:'in_progress',conclusion:null,
   started_at:start,completed_at:null,steps:[{name:'Build & push image transition bootstrap (arm64)',status:'in_progress',conclusion:null,started_at:start,completed_at:null}]};
  const capture=captureProductionControlComposition(out,{run,job});
  assert.throws(()=>completeProductionControlCompositionCapture(capture,{run,job,now:r.completedMs+100}),/CompletionJob/);
  job.status='completed';job.conclusion='success';job.completed_at=end;Object.assign(job.steps[0],{status:'completed',conclusion:'success',completed_at:end});
  assert.equal(completeProductionControlCompositionCapture(capture,{run,job,now:r.completedMs+100}).completedMs,r.completedMs+10);
  for(const field of ['run_id','run_attempt','head_sha']){
   const bad=structuredClone(job);bad[field]=field==='head_sha'?'f'.repeat(40):999;
   assert.throws(()=>completeProductionControlCompositionCapture(capture,{run,job:bad,now:r.completedMs+100}),/CompletionJob/);
  }
  job.conclusion='failure';assert.throws(()=>completeProductionControlCompositionCapture(capture,{run,job,now:r.completedMs+100}),/CompletionJob/);
 }finally{if(out)await closeProductionControlCompositionOutput(out);await a?.close();await f.remove();}
});
test('abort after real admission leaves no output and cannot recreate allocation from a snapshot',async()=>{
 const f=await fixture();let a;try{
  a=await admission(f);const abort=new AbortController();abort.abort();
  await assert.rejects(composeProductionControl({...a,signal:abort.signal}));
  const snapshot=productionControlCompositionSnapshot(a.allocation);
  assert.equal(snapshot.held,true);
  await assert.rejects(composeProductionControl({...a,allocation:snapshot}),/NativeAllocation/);
 }finally{await a?.close();await f.remove();}
});
test('raw repository replay preserves the complete producer graph and filesystem hashes',async()=>{
 const f=await fixture();let a,out;try{
  a=await admission(f);out=await composeProductionControl(a);const value=inspectProductionControlCompositionOutput(out),r=value.record;
  assert.deepEqual(Object.keys(r.rootDescriptor).sort(),['digest','mediaType','size']);
  const objects=new Map();for(const d of value.graph.inventory.nodes)objects.set(d.digest,await readFile(join(value.directory,'blobs',d.digest.slice(7))));
  const cache=new Map(),store={async put(d,stream){const chunks=[];for await(const b of stream)chunks.push(b);cache.set(d.digest,Buffer.concat(chunks));},async *open(d){yield cache.get(d.digest);}};
  const requests=[],source={async manifest(repositoryName,d){
   const body=Buffer.from(JSON.stringify({images:[{registryId:r.image.account,repositoryName,imageId:{imageDigest:d.digest},imageManifest:objects.get(d.digest).toString('utf8'),imageManifestMediaType:d.mediaType}],failures:[]}));
   const parsed=JSON.parse(body);requests.push({registryId:r.image.account,repositoryName,imageIds:[{imageDigest:d.digest}]});
   assert.equal(parsed.images[0].repositoryName,r.image.repositoryName);assert.equal(parsed.images[0].imageId.imageDigest,d.digest);
   return Buffer.from(parsed.images[0].imageManifest);
  },async blob(repositoryName,d){assert.equal(repositoryName,r.image.repositoryName);return (async function*(){yield objects.get(d.digest);})();}};
  const budget=createImageBudget({credentialExpiresMs:Date.now()+3600000});
  const graph=await readControlImageGraph({account:r.image.account,region:r.image.region,repositoryName:r.image.repositoryName,
   root:r.rootDescriptor,arm64Digest:r.image.arm64Digest,configDigest:r.image.configDigest},{source,store,budget});
  const fs=await inspectImageFilesystem(graph,{component:'bootstrap',budget});
  assert.equal(graph.graphHash,value.graph.graphHash);assert.deepEqual(graph.inventory,value.graph.inventory);
  assert.deepEqual(inspectImageFilesystemEvidence(fs),inspectImageFilesystemEvidence(value.filesystem));
  assert.deepEqual(inspectImageFilesystemEntries(fs),inspectImageFilesystemEntries(value.filesystem));assert.equal(requests.length,3);
 }finally{if(out)await closeProductionControlCompositionOutput(out);await a?.close();await f.remove();}
});
