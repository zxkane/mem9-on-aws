/** Archive-only CI replay. No host, credential or command adapter. */
import {createHash} from 'node:crypto';
import {nonrootHash as hash} from './production-nonroot-contracts.mjs';
import {parseCiSmokeJson,inspectCiSmokeRecord} from './ci-smoke-evidence.mjs';
import {CI_SMOKE_ARCHIVE_LIMITS} from './ci-smoke-private-archive.mjs';
import {verifyArchivedCiSmoke} from './ci-smoke-isolation.mjs';
import {expectedCiSmokeCommandCatalog} from './ci-smoke-command-catalog.mjs';
import {assertNonrootControlCurrent} from './production-nonroot-control-current.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');
const need=(v,c)=>{if(!v)throw Error(c);};
const exact=(v,keys)=>need(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===keys.slice().sort().join(),'CiSmokeFields');
const parse=raw=>parseCiSmokeJson(Buffer.from(raw).toString('utf8'));
const identityKeys=['repository','runId','runAttempt','workflowPath','sourceRevision','sourceTree','buildJobId','smokeJobId','stepId','outputDigest','qualifiedImage','arm64Digest','configDigest'];
class Objects{
 constructor(){this.objects=new Map();this.total=0;}
 bytes(value){const raw=Buffer.from(value),key=sha(raw);need(raw.length<=8388608,'CiSmokeObjectLimit');if(!this.objects.has(key)){this.total+=raw.length;need(this.total<=33554432&&this.objects.size<4096,'CiSmokeArchiveLimit');this.objects.set(key,raw);}return {sha256:key,bytesLength:raw.length};}
 json(value){const raw=Buffer.from(JSON.stringify(value)),b=this.bytes(raw);return {bytesHash:b.sha256,bytesLength:b.bytesLength,canonicalHash:hash(value)};}
 get(key){need(this.objects.has(key),'CiSmokeObjectMissing');return this.objects.get(key);}
 rows(){return [...this.objects].map(([sha256,bytes])=>({sha256,bytes}));}
}
function producedExpected(result,observations,commandBindings,catalog){
 const identity=Object.fromEntries(identityKeys.map(k=>[k,result[k]]));
 need(hash(observations.images)===hash(commandBindings.images)&&observations.invocationId===commandBindings.invocationId,'CiSmokeProducerBindings');
 return {...observations,identity,isolationHash:result.isolationHash,commandCatalog:expectedCiSmokeCommandCatalog({catalog,bindings:commandBindings})};
}
function assertProducerClosure(observations,isolation){
 const sorted=files=>[...files].sort((a,b)=>a.path<b.path?-1:a.path>b.path?1:0);
 need(hash(sorted(observations.sourceFiles))===hash(sorted(isolation.smoke.closure)),'CiSmokeProducerClosureIncomplete');
}
export async function verifyImageMetadataRefs(refs,images,readBytes,options={}){
 const resume=value=>{assertNonrootControlCurrent(options);return value;};resume();
 exact(refs,['server','database']);
 for(const role of ['server','database']){
  const r=refs[role],image=images[role];exact(r,['root','manifest','config']);
  need(r.manifest.sha256===image.arm64Digest.slice(7)&&r.config.sha256===image.configDigest.slice(7),'CiSmokeImageMetadataDigest');
  const manifest=parse(resume(await readBytes(r.manifest))),config=parse(resume(await readBytes(r.config)));
  need(manifest.schemaVersion===2&&manifest.config?.digest===image.configDigest&&config.os==='linux'&&config.architecture==='arm64','CiSmokeImageMetadataBinding');
  if(r.root!==null){
   inspectCiSmokeRecord('ByteRef',r.root);
   need(r.root.sha256===image.rootDigest.slice(7),'CiSmokeImageMetadataDigest');const root=parse(resume(await readBytes(r.root)));
   need(image.rootDigest===image.arm64Digest||root.manifests?.some(m=>m.digest===image.arm64Digest&&m.platform?.os==='linux'&&m.platform.architecture==='arm64'),'CiSmokeImageMetadataBinding');
  }
 }
}
function completedExpected(produced,provenance){
 const job=raw=>({id:raw.id,runId:raw.run_id,runAttempt:raw.run_attempt,sourceRevision:provenance.sourceRevision,status:raw.status,conclusion:raw.conclusion,startedMs:Date.parse(raw.started_at),completedMs:Date.parse(raw.completed_at)});
 return {...produced,buildJob:job(provenance.buildJob),smokeJob:job(provenance.smokeJob)};
}
export async function verifyDecoded(decoded,provenance,now,options={}){
 assertNonrootControlCurrent(options);
 const {result,source,isolation,observations,commandBindings,commandCatalog}=decoded.records;
 assertProducerClosure(observations,isolation);
 exact(source,['version','kind','originRecipe','candidateRecipe','material','imageMetadata']);need(source.version===1&&source.kind==='ci-smoke-source-capture','CiSmokeEnvelopeSource');
 await verifyImageMetadataRefs(source.imageMetadata,observations.images,decoded.readBytes,options);assertNonrootControlCurrent(options);
 const expected=completedExpected(producedExpected(result,observations,commandBindings,commandCatalog),provenance),extra=new Objects();
 // Completion metadata is collected after the producer job ends. It is a new
 // record; the original envelope and its honest in-progress capture stay intact.
 const material={...source.material,provenance:extra.json(provenance),expected:extra.json(expected)};
 const checked=await verifyArchivedCiSmoke(isolation,result,{material,originRecipe:source.originRecipe,candidateRecipe:source.candidateRecipe,
  resolveJson:async ref=>{assertNonrootControlCurrent(options);return extra.objects.get(ref.bytesHash)??decoded.readJson(ref);},readBytes:async ref=>{assertNonrootControlCurrent(options);return extra.objects.get(ref.sha256)??decoded.readBytes(ref);},now,processing:options.processing,assertCurrent:options.assertCurrent});
 assertNonrootControlCurrent(options);
 // These are the two original byte objects consumed above, not rebuilt JSON
 // or predicted job completion. This data remains non-authorizing; consumers
 // replay it with the immutable envelope and authenticated archive bindings.
 need(extra.objects.size===2,'CiSmokeCompletionInventory');
 const refs=[material.provenance,material.expected];
 const estimated=Buffer.byteLength(JSON.stringify(material))+2048+refs.reduce((n,ref)=>n+4*Math.ceil(ref.bytesLength/3),0);
 need(estimated<=CI_SMOKE_ARCHIVE_LIMITS.objectBytes,'CiSmokeCompletionLimit');
 const completion=parseCiSmokeJson(JSON.stringify({version:1,kind:'ci-smoke-completion-material',envelopeSha256:decoded.commitment.envelopeSha256,resultHash:decoded.commitment.resultHash,material,
  objects:refs.map(ref=>({ref,base64:extra.get(ref.bytesHash).toString('base64')}))}));
 need(Buffer.byteLength(JSON.stringify(completion))<=CI_SMOKE_ARCHIVE_LIMITS.objectBytes,'CiSmokeCompletionLimit');
 return Object.freeze({...checked,completion});
}
