/** The actual R15 case sequence. Fixture observations are evidence, never a
 * production CA binding, registry authorization or restored startup capability. */
import {randomBytes} from 'node:crypto';
import {inspectCarrierOfflineBuild} from './production-nonroot-carrier-build.mjs';
import {assertCarrierConsumer} from './ci-carrier-consumer.mjs';
import {controlImageGraphBinding,imageGraphState} from './production-image-graph.mjs';
import {inspectImageFilesystemFile,assertImageFilesystemUncompressedLimit,assertImageFilesystemEntryLimit} from './production-image-filesystem.mjs';
import {loadNonrootControlImage} from './production-nonroot-control-docker.mjs';
import {carrierCheckpointSelection} from './ci-carrier-before-copy.mjs';
import {prepareCarrierSqlAcceptanceFixture,executeCarrierSqlCase,closeCarrierSqlAcceptanceFixture,closeCarrierSqlFixture} from './ci-carrier-sql-fixture.mjs';
import {CARRIER_SQL_CASES,inspectCarrierSqlAcceptance} from './ci-carrier-sql-acceptance-format.mjs';
import {hash,sha,need,freeze} from './ci-smoke-acquisition-format.mjs';
import {CARRIER_SQL_FIXTURE_LIMITS as L,carrierSqlRuntimeBudget} from './ci-carrier-sql-runtime-budget.mjs';

const completed=new WeakMap(),attempted=new WeakSet();
/** Only genuine completed build handles provide these actual image sizes.
 * Planning uses independently authenticated maxima via the pure helper. */
export function inspectCarrierSqlRuntimeBudget(built){
 const b=inspectCarrierOfflineBuild(built),usage=imageGraphState(b.graph).budget.usage();
 const inputs={runtimeFilesBytes:b.runtimeManifest.files.reduce((n,f)=>n+f.bytes,0),originalSourceBytes:b.runtimeManifest.files.filter(f=>f.path.startsWith('/bootstrap/operator/')&&!f.path.startsWith('/bootstrap/operator/node_modules/')&&/\.(?:mjs|js)$/.test(f.path)).reduce((n,f)=>n+f.bytes,0),nodeBytes:inspectImageFilesystemFile(b.filesystem,'/usr/local/bin/node').size,setprivBytes:inspectImageFilesystemFile(b.filesystem,'/bin/setpriv').size,carrierGraphBytes:b.graph.inventory.nodes.reduce((n,d)=>n+d.size,0),carrierGraphNodes:b.graph.inventory.nodes.length,carrierUncompressedBytes:usage.uncompressedBytes,carrierEntries:usage.fsEntries};
 return freeze({inputs,budget:carrierSqlRuntimeBudget(inputs)});
}
export async function runCarrierSqlAcceptance({built,context,derived,consumer,sourceContext,fixture,oldSource,signal}){
 assertCarrierConsumer(consumer);const admission=consumer.admission,plan=admission.config.plan,b=inspectCarrierOfflineBuild(built);
 need(!attempted.has(built)&&b.record.templateHash===plan.templateHash&&b.record.contextHash===plan.context.sha256&&sourceContext===admission.source.sourceContext,'CarrierSqlAcceptanceInputs');
 need(context&&derived&&fixture&&oldSource,'CarrierSqlAcceptanceDependencies');
 assertImageFilesystemUncompressedLimit(b.filesystem,plan.template.bounds.uncompressedBytes);assertImageFilesystemEntryLimit(b.filesystem,plan.template.bounds.processedEntries);
 attempted.add(built);consumer.check();const startedMs=Date.now(),{graphHash,...image}=controlImageGraphBinding(b.graph);
 const upload=Object.fromEntries(['nonce','scopeHash','artifactId','artifactDigest'].map(k=>[k,admission.receipt[k]])),claim=carrierCheckpointSelection(plan,admission.binding,upload).claim;
 const objects=new Map(),put=bytes=>{bytes=Buffer.from(bytes);const ref={sha256:sha(bytes),bytesLength:bytes.length},key=hash(ref);if(!objects.has(key))objects.set(key,{ref,bytesBase64:bytes.toString('base64')});return ref;};
 const runtime=inspectCarrierSqlRuntimeBudget(built);let loadCalls=0;
 let prepared,loaded,closedFixture=false,closedSeed=false;
 try{
  prepared=await prepareCarrierSqlAcceptanceFixture(fixture,{built,sourceContext,oldSource});
  // The loader charges its actual cache/tar bytes. Charge its separate fixed
  // command/cleanup output and cold-daemon materialization before execution.
  consumer.reserveLocal(runtime.budget.parts.carrierLoadControl);consumer.reserveLocal(runtime.budget.parts.carrierColdImport);
  consumer.reserveLocal({ecrRequests:0,logicalBytes:0,httpBodyBytes:0,uncompressedBytes:0,processedEntries:2});
  loaded=await loadNonrootControlImage({graph:b.graph,cacheDirectory:b.cacheDirectory,metadataReads:consumer,tempRoot:consumer.directory,signal},{beforeCommand({args}){need(++loadCalls<=L.maxCarrierLoadCalls&&Buffer.byteLength(JSON.stringify(args))<=L.maxDockerArgumentBytes,'CarrierSqlLoadCommandBudget');}});
  need(loaded.io.logicalBytes<=runtime.budget.parts.carrierLoadFiles.logicalBytes,'CarrierSqlLoadByteBudget');
  const cases=[];
  for(const name of CARRIER_SQL_CASES){signal?.throwIfAborted();consumer.check();const out=await executeCarrierSqlCase(fixture,name);
   cases.push({...out.row,inputBytes:put(out.inputBytes),stdout:put(out.stdout),stderr:put(out.stderr),...(out.tlsLog?{tlsFailure:{...out.row.tlsFailure,log:put(out.tlsLog)}}:{})});
  }
  await closeCarrierSqlAcceptanceFixture(fixture);closedSeed=true;
  const release=loaded;loaded=undefined;await release.close();
  await closeCarrierSqlFixture(fixture);closedFixture=true;
  const record={version:2,kind:'carrier-original-closure-tests',templateHash:plan.templateHash,grantHash:admission.config.grantHash,contextHash:plan.context.sha256,bindingHash:hash(admission.binding),claimHash:hash(claim),sourceRevision:plan.template.source.candidateRevision,sourceTree:plan.template.source.candidateTree,image,
   originalManifestHash:sha(prepared.original),testManifestHash:sha(prepared.test),originalManifest:put(prepared.original),testManifest:put(prepared.test),fixtureCa:put(prepared.ca),fixture:prepared.fixture,
   startedMs,completedMs:Date.now(),deadlineMs:plan.deadlineMs,cases,cleanup:{fixtureStopped:true,networkRemoved:true,imageReleased:true}};
  const value={record,objects:[...objects.values()]};inspectCarrierSqlAcceptance(value,{plan,binding:admission.binding,claim,image,oldSource,originalManifest:prepared.original});
  const handle=Object.freeze({kind:'carrier-sql-acceptance',id:randomBytes(16).toString('hex')});completed.set(handle,{built,consumer,value:freeze(value)});return handle;
 }finally{
  let failed=false;try{if(prepared&&!closedSeed)await closeCarrierSqlAcceptanceFixture(fixture);}catch{failed=true;}
  try{if(loaded)await loaded.close();}catch{failed=true;}
  try{if(!closedFixture)await closeCarrierSqlFixture(fixture);}catch{failed=true;}
  if(failed)throw Object.assign(Error('CarrierSqlAcceptanceCleanup'),{code:'ECLEANUP'});
 }
}
export function inspectCompletedCarrierSqlAcceptance(handle,{built,consumer}){
 const s=completed.get(handle);need(s&&s.built===built&&s.consumer===consumer,'CarrierSqlAcceptanceHandle');assertCarrierConsumer(consumer);return s.value;
}
