import {normalizeImageDigestResponse,imageResponseFromSdk} from './production-image-response.mjs';
import {createCopyScanPoolReplay,applyCopyScanPoolEvent,describeScanSequenceTemplate} from './production-nonroot-scan-pool.mjs';
import {verifyRootOwnerReservations} from './production-nonroot-root-owner-accounting.mjs';
import {createRootOwnerPoolReplay,applyRootOwnerPoolEvent} from './production-nonroot-root-pool.mjs';
import {createHash} from 'node:crypto';
import {NONROOT_LIMITS,NONROOT_DATA_COMPONENTS as COMPONENTS,copyNonrootJson,parseNonrootJson,inspectNonrootRecord,nonrootHash as hash} from './production-nonroot-contracts.mjs';
import {readImageGraph,imageGraphState,assertImageBudget,IMAGE_MEDIA} from './production-image-graph.mjs';
import {inspectImageFilesystem,inspectImageFilesystemEvidence} from './production-image-filesystem.mjs';
import {IMAGE_TRANSITION_LIMITS as IMAGE_LIMITS,IMAGE_TRANSITION_LIMITS_HASH} from './production-image-transition.mjs';
import {inspectFutureFundingPlan} from './ci-smoke-grants.mjs';
import {verifyNonrootBeforeCopyAccounting} from './production-nonroot-before-copy-accounting.mjs';
import {nonrootAccountingPolicy} from './production-nonroot-budget-revision.mjs';
import {verifyNonrootFinalizationPlan} from './production-nonroot-finalization-accounting.mjs';
import {verifyNonrootCopyReplayStart} from './production-nonroot-copy-replay.mjs';

const contexts=new WeakMap(),consumed=new WeakSet(),combinedPasses=new WeakMap();
const need=(ok,code='NonrootCacheInvalid')=>{if(!ok)throw Error(code);};
const exact=(v,keys)=>need(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===keys.slice().sort().join(),'NonrootCacheFields');
const same=(a,b,code='NonrootCacheBinding')=>need(hash(a)===hash(b),code);
const sha=b=>createHash('sha256').update(b).digest('hex');
const digest=b=>'sha256:'+sha(b);
const manifests=new Set([IMAGE_MEDIA.index,IMAGE_MEDIA.dockerIndex,IMAGE_MEDIA.manifest,IMAGE_MEDIA.dockerManifest]);
const freeze=v=>{if(v&&typeof v==='object'){Object.values(v).forEach(freeze);Object.freeze(v);}return v;};
const positive=v=>Number.isSafeInteger(v)&&v>0;

function imageResponse(value,root,descriptor,account){
 exact(value,['request','response']);
 same(value.request,{registryId:account,repositoryName:root.destinationRepository,imageIds:[{imageDigest:descriptor.digest}]},'NonrootCacheDigestRequest');
 const {image}=normalizeImageDigestResponse(imageResponseFromSdk(value.response),{registryId:account,repositoryName:root.destinationRepository,imageDigest:descriptor.digest});
 need(image.registryId===account&&image.repositoryName===root.destinationRepository&&image.imageId?.imageDigest===descriptor.digest&&typeof image.imageManifest==='string'&&Buffer.byteLength(image.imageManifest)===descriptor.size&&digest(image.imageManifest)===descriptor.digest&&(image.imageManifestMediaType===undefined||image.imageManifestMediaType===descriptor.mediaType),'NonrootCacheManifestChanged');
 const document=parseNonrootJson(image.imageManifest);need(document.mediaType===descriptor.mediaType,'NonrootCacheManifestMediaType');return document;
}

function receipt(value,expected){
 exact(value,['version','kind','owner','planHash','publication','publicationHash','summary','graphHash','inventory','destinationReadback','filesystems','finalRootReadbacks',...(value.version===3?['combinedPass']:[])]);
 need([2,3].includes(value.version)&&value.kind==='digest-only-image-copy','NonrootCacheCopyV2Required');
 const {summary:s,inventory:i,publication:p}=value;
 need(/^[a-f0-9]{32}$/.test(value.owner)&&/^[a-f0-9]{64}$/.test(value.planHash)&&value.graphHash===hash(s),'NonrootCacheCopyBinding');
 need(i.version===1&&i.limitsHash===IMAGE_TRANSITION_LIMITS_HASH&&Array.isArray(i.roots)&&i.roots.length===3,'NonrootCacheInventory');
 same(i.roots.map(r=>r.component).sort(),COMPONENTS);
 for(const r of i.roots)need(r.sourceRepository==='mem9-on-aws/preview/'+r.component&&r.destinationRepository==='mem9-on-aws/'+r.component,'NonrootCacheRepository');
 exact(p,['version','mode','inventoryHash','roots','sourceTags']);
 need(p.version===1&&p.mode==='digest-only'&&p.inventoryHash===hash(i)&&value.publicationHash===hash(p),'NonrootCachePublication');
 same(p.roots,Object.fromEntries(i.roots.map(r=>[r.component,{repositoryName:r.destinationRepository,rootDigest:r.root.digest,arm64Digest:r.arm64Digest}])));
 exact(p.sourceTags,COMPONENTS);for(const tag of Object.values(p.sourceTags))need(typeof tag==='string'&&/^pr-[a-z0-9-]+$/.test(tag),'NonrootCacheSourceTag');
 need(s.version===1&&s.account===expected.account&&s.region===expected.region&&s.limitsHash===IMAGE_TRANSITION_LIMITS_HASH&&s.inventoryHash===hash(i)&&s.contentHash===hash(i.nodes)&&s.destinationContentHash===s.contentHash&&s.destinationReadbackHash===hash(value.destinationReadback),'NonrootCacheCopySummary');
 same(s.images,expected.images);same(s.images,Object.fromEntries(i.roots.map(r=>[r.component,{rootDigest:r.root.digest,arm64Digest:r.arm64Digest}])));
 same(value.destinationReadback.inventory,i);need(Array.isArray(value.filesystems)&&value.filesystems.length===3,'NonrootCacheFilesystems');same(value.filesystems.map(f=>f.component).sort(),COMPONENTS);
 need(positive(s.startedMs)&&positive(s.completedMs)&&s.startedMs<=s.completedMs&&Array.isArray(value.finalRootReadbacks)&&value.finalRootReadbacks.length===3,'NonrootCacheCopyTime');
 return value;
}

export function inspectNonrootDigestOnlyCopy(value,expected){return copyNonrootJson(receipt(copyNonrootJson(value),expected));}

export function verifyNonrootCacheDestinationMetadata(value,{copyReceipt,now}){
 const m=copyNonrootJson(value),c=copyReceipt;
 exact(m,['version','kind','account','region','startedMs','completedMs','repositories']);
 need(m.version===1&&m.kind==='nonroot-destination-metadata'&&m.account===c.summary.account&&m.region===c.summary.region,'NonrootCacheMetadataScope');
 need(positive(m.startedMs)&&positive(m.completedMs)&&m.startedMs<=m.completedMs&&m.completedMs<=now&&now-m.startedMs<=NONROOT_LIMITS.maxArtifactObservationAgeMs,'NonrootCacheMetadataExpired');
 need(Array.isArray(m.repositories)&&m.repositories.length===3,'NonrootCacheMetadataCoverage');
 const seen=new Set();
 for(const row of m.repositories){
  exact(row,['component','repositoryName','root','arm64','config','availability','retention']);
  const root=c.inventory.roots.find(r=>r.component===row.component);need(root&&!seen.has(row.component)&&row.repositoryName===root.destinationRepository,'NonrootCacheMetadataRepository');seen.add(row.component);
  imageResponse(row.root,root,root.root,m.account);
  const descriptor=c.inventory.nodes.find(n=>n.digest===root.arm64Digest);need(descriptor,'NonrootCacheArm64');
  const arm=imageResponse(row.arm64,root,descriptor,m.account);
  exact(row.config,['digest','bytesBase64']);
  need(row.config.digest===arm.config.digest&&typeof row.config.bytesBase64==='string'&&row.config.bytesBase64.length<=Math.ceil(8388608/3)*4&&Buffer.byteLength(row.config.bytesBase64,'base64')<=8388608,'NonrootCacheConfig');
  const raw=Buffer.from(row.config.bytesBase64,'base64');need(raw.toString('base64')===row.config.bytesBase64&&raw.length===arm.config.size&&digest(raw)===arm.config.digest,'NonrootCacheConfig');
  const config=parseNonrootJson(raw.toString('utf8'));need(config.os==='linux'&&config.architecture==='arm64','NonrootCacheConfig');
  const blobs=new Map(c.destinationReadback.reads.filter(d=>d.repositoryName===root.destinationRepository&&!manifests.has(d.mediaType)).map(d=>[d.digest,d]));
  need(Array.isArray(row.availability)&&row.availability.length>0&&row.availability.length<=10,'NonrootCacheAvailability');
  const available=new Set();
  for(const batch of row.availability){
   exact(batch,['request','response']);exact(batch.request,['registryId','repositoryName','layerDigests']);
   need(batch.request.registryId===m.account&&batch.request.repositoryName===row.repositoryName&&Array.isArray(batch.request.layerDigests)&&batch.request.layerDigests.length>0&&batch.request.layerDigests.length<=100&&new Set(batch.request.layerDigests).size===batch.request.layerDigests.length,'NonrootCacheAvailability');
   const r=batch.response;need(Array.isArray(r.failures)&&r.failures.length===0&&Array.isArray(r.layers)&&r.layers.length===batch.request.layerDigests.length,'NonrootCacheAvailability');
   const pending=new Set(batch.request.layerDigests);
   for(const layer of r.layers){const d=blobs.get(layer.layerDigest);need(d&&pending.delete(layer.layerDigest)&&!available.has(layer.layerDigest)&&layer.layerAvailability==='AVAILABLE'&&layer.layerSize===d.size&&(layer.mediaType===undefined||layer.mediaType===d.mediaType),'NonrootCacheAvailability');available.add(layer.layerDigest);}
   need(pending.size===0,'NonrootCacheAvailability');
  }
  need(available.size===blobs.size,'NonrootCacheAvailabilityCoverage');
  exact(row.retention,['repository','policy']);const repository=row.retention.repository,policy=row.retention.policy;
  need(repository.registryId===m.account&&repository.repositoryName===row.repositoryName&&repository.repositoryArn===`arn:aws:ecr:${m.region}:${m.account}:repository/${row.repositoryName}`,'NonrootCacheRetention');
  need(policy.operation==='GetLifecyclePolicy'&&policy.registryId===m.account&&policy.repositoryName===row.repositoryName&&policy.errorCode==='LifecyclePolicyNotFoundException'&&typeof policy.requestId==='string'&&policy.requestId.length>0,'NonrootCacheRetention');
 }
 return m;
}

/** Material verification only. The private completed-copy verifier authenticates
 * config/outcome/ledger custody before entering its bounded cache callback.
 * expected pins must come from that verified handle and independent fresh
 * observations, never from caller JSON. No copy/publication authority is minted.
 * The private reader retains cumulative reservations across process boundaries;
 * the graph budget below additionally enforces the unchanged parser limits. */
export async function verifyNonrootArtifactCache(value,{expected,cache,budget,readCopyRecord,measureFilesystem,now=Date.now}={}){
 const input=copyNonrootJson(value),pins=copyNonrootJson(expected);
 exact(input,['copyReceipt','cacheCustody','verifierClosure','freshDestinationMetadata','requirements']);
 exact(pins,['account','region','images','copyReceiptHash','cacheCustodyHash','verifierClosureHash','freshDestinationMetadataHash','requirementsHash']);
 need(/^\d{12}$/.test(pins.account)&&/^[a-z]{2}(?:-[a-z]+)+-\d+$/.test(pins.region),'NonrootCacheScope');
 for(const [key,item]of Object.entries(input))need(/^[a-f0-9]{64}$/.test(pins[key+'Hash'])&&pins[key+'Hash']===hash(item),'NonrootCacheIndependentBinding');
 need(cache&&typeof cache==='object'&&!consumed.has(cache),'NonrootCacheAlreadyConsumed');
 exact(input.cacheCustody,['origin','owner','executionId','copyReceiptRef','checkpointRef']);
 need(input.cacheCustody.origin==='authenticated-completed-destination-cache'&&input.cacheCustody.owner===input.copyReceipt.owner&&/^[a-f0-9]{32}$/.test(input.cacheCustody.executionId),'NonrootCacheCustody');
 for(const ref of [input.cacheCustody.copyReceiptRef,input.cacheCustody.checkpointRef]){
  exact(ref,['path','sha256']);need(typeof ref.path==='string'&&ref.path.startsWith('/')&&ref.path.length<=4096&&/^[a-f0-9]{64}$/.test(ref.sha256),'NonrootCacheCustodyReference');
 }
 same(cache.cacheCustody,input.cacheCustody);same(cache.roots,input.copyReceipt.inventory.roots);
 need(cache.inventoryHash===hash(input.copyReceipt.inventory)&&cache.contentHash===input.copyReceipt.summary.contentHash,'NonrootCacheReaderBinding');
 inspectNonrootRecord('SourceClosureV1',input.verifierClosure);
 exact(input.requirements,COMPONENTS);
 need(input.copyReceipt.version===3||typeof measureFilesystem==='function','NonrootCacheAccountingRequired');
 const c=receipt(input.copyReceipt,pins),startedMs=now();need(c.summary.completedMs<=startedMs,'NonrootCacheCopyFuture');
 verifyNonrootCacheDestinationMetadata(input.freshDestinationMetadata,{copyReceipt:c,now:startedMs});
 need(typeof readCopyRecord==='function','NonrootCacheCopyReader');
 const pinnedRecord=async ref=>{
  const bytes=await readCopyRecord(ref);need(bytes instanceof Uint8Array&&bytes.byteLength<=8388608&&sha(bytes)===ref.sha256,'NonrootCacheCopyRecordPin');
  return parseNonrootJson(Buffer.from(bytes).toString('utf8'));
 };
 same(await pinnedRecord(input.cacheCustody.copyReceiptRef),c,'NonrootCacheCopyReceiptPin');
 if(c.version===3)await verifyNonrootCombinedCustody(c,{readCopyRecord});
 const copyCheckpoint=await pinnedRecord(input.cacheCustody.checkpointRef);
 need(copyCheckpoint.binding?.owner===c.owner&&copyCheckpoint.binding.executionId===input.cacheCustody.executionId&&copyCheckpoint.binding.planHash===c.planHash&&copyCheckpoint.binding.publicationHash===c.publicationHash&&copyCheckpoint.sealed===true&&copyCheckpoint.active===0,'NonrootCacheCheckpoint');
 const finalReads=[],seen=new Set();
 for(const ref of c.finalRootReadbacks){
  exact(ref,['path','sha256']);need(typeof ref.path==='string'&&/^[a-f0-9]{64}$/.test(ref.sha256),'NonrootCacheFinalRootRef');
  const bytes=await readCopyRecord(ref);need(bytes instanceof Uint8Array&&bytes.byteLength<=8388608&&sha(bytes)===ref.sha256,'NonrootCacheFinalRootPin');
  const row=parseNonrootJson(Buffer.from(bytes).toString('utf8'));
  const root=c.inventory.roots.find(r=>r.component===row.component);need(root&&!seen.has(row.component)&&row.phase==='final-root'&&row.observedMs>=c.summary.startedMs&&row.observedMs<=c.summary.completedMs,'NonrootCacheFinalRoot');seen.add(row.component);
  imageResponse({request:row.request,response:row.response},root,root.root,pins.account);finalReads.push(row);
 }
 consumed.add(cache);let material,observedStart=startedMs,observedEnd;
 if(c.version===3){
  const prior=combinedPasses.get(cache.combinedPass);need(prior&&!prior.adopted,'NonrootCombinedContextRequired');
  same(prior.input.binding,copyCheckpoint.binding,'NonrootCombinedBinding');same(prior.input.inventory,c.inventory);same(prior.input.sourceClosure,input.verifierClosure,'NonrootCombinedSource');same(prior.input.requirements,input.requirements);
  same(prior.data.readUsage,c.combinedPass.readUsage);need(prior.data.startedMs===c.combinedPass.startedMs&&prior.data.completedMs===c.combinedPass.completedMs&&prior.data.settledReadbackHash===c.combinedPass.settledReadbackHash,'NonrootCombinedBinding');
  need(c.combinedPass.verifierClosureHash===hash(input.verifierClosure)&&c.summary.completedMs===prior.data.completedMs,'NonrootCombinedBinding');
  same(prior.data.destinationReadback,c.destinationReadback);same(prior.data.filesystem, Object.fromEntries(c.filesystems.map(f=>[f.component,f])));
  prior.adopted=true;material=prior.material;observedStart=prior.data.startedMs;observedEnd=prior.data.completedMs;
 }else{
  need(cache.combinedPass===undefined,'NonrootCombinedLegacy');
  material=await readArtifactCacheCore({inventory:c.inventory,readbacks:c.destinationReadback.reads,filesystems:c.filesystems,requirements:input.requirements},{cache,budget,measureFilesystem});
 }
 const {graph,filesystem,filesystemContexts,readUsage}=material;
 const completedMs=now();need(completedMs>=startedMs,'NonrootCacheClock');
 verifyNonrootCacheDestinationMetadata(input.freshDestinationMetadata,{copyReceipt:c,now:completedMs});
 const context=Object.freeze({kind:'nonroot-cache-reverification'});
 const data=freeze({kind:'nonroot-cache-reverification',authority:false,...pins,inventory:c.inventory,historicalDestinationReadback:c.destinationReadback,copyCheckpoint,finalRootReadbacks:finalReads,filesystem,startedMs:observedStart,completedMs:observedEnd??completedMs,readUsage});
 contexts.set(context,{data,input,graph,filesystemContexts});return context;
}

/** Execute the shared parser exactly once before copy COMPLETE. The caller
 * supplies the authenticated stopped-readback boundary and original ledger.
 * This handle contains actual graph/FS evidence, never deployment authority. */
export async function verifyNonrootCombinedDataPass(value,{expected,cache,budget,measureFilesystem,now=Date.now}={}){
 const input=copyNonrootJson(value);exact(input,['binding','inventory','sourceFilesystems','requirements','sourceClosure','readbacks']);
 exact(expected,['inputHash','settledReadbackHash']);need(expected.inputHash===hash(input)&&cache?.settledReadbackHash===expected.settledReadbackHash,'NonrootCombinedBinding');
 inspectNonrootRecord('SourceClosureV1',input.sourceClosure);exact(input.requirements,COMPONENTS);
 need(!consumed.has(cache),'NonrootCacheAlreadyConsumed');consumed.add(cache);const startedMs=now();
 const material=await readArtifactCacheCore({inventory:input.inventory,readbacks:input.readbacks,filesystems:input.sourceFilesystems,requirements:input.requirements},{cache,budget,measureFilesystem});
 const completedMs=now();need(completedMs>=startedMs,'NonrootCacheClock');
 const data=freeze({kind:'combined-data-pass-material',authority:false,settledReadbackHash:expected.settledReadbackHash,startedMs,completedMs,inventory:input.inventory,destinationReadback:{inventory:input.inventory,reads:imageGraphState(material.graph).readbacks},filesystem:material.filesystem,readUsage:material.readUsage});
 const handle=Object.freeze({kind:'combined-data-pass-context'});combinedPasses.set(handle,{input,data,material,adopted:false});return handle;
}
export function inspectNonrootCombinedDataPass(handle){const state=combinedPasses.get(handle);need(state,'NonrootCombinedContextRequired');return copyNonrootJson(state.data);}
async function readArtifactCacheCore({inventory,readbacks,filesystems,requirements},{cache,budget,measureFilesystem}){
 assertImageBudget(budget);const before=budget.usage();
 const graph=await readImageGraph(cache.roots,{readManifest:cache.readManifest,readBlob:cache.readBlob,store:cache.store,budget,side:'destination'});
 same(graph.inventory,inventory,'NonrootCacheGraphChanged');const state=imageGraphState(graph);
 // Preserve the historical receipt/hash while comparing complete object sets;
 // a new parser's traversal order is not historical readback chronology.
 const ordered=rows=>{need(Array.isArray(rows),'NonrootCacheReadbackChanged');const keys=rows.map(r=>r.repositoryName+'\0'+r.digest);need(new Set(keys).size===keys.length,'NonrootCacheReadbackDuplicate');return rows.slice().sort((a,b)=>{const x=a.repositoryName+'\0'+a.digest,y=b.repositoryName+'\0'+b.digest;return x<y?-1:x>y?1:0;});};
 same(ordered(state.readbacks),ordered(readbacks),'NonrootCacheReadbackChanged');
 const filesystem={},filesystemContexts={};
 for(const component of COMPONENTS){
  // The private ledger measures the actual parser's unpacked/entry counters.
  // Its callback cannot substitute a manufactured filesystem context.
  let actual,started=false;
  const context=await measureFilesystem(component,()=>budget.usage(),async()=>{
   need(!started,'NonrootCacheSecondFilesystemPass');started=true;
   actual=await inspectImageFilesystem(graph,{component,requirements:requirements[component]});return actual;
  });
  need(actual&&context===actual,'NonrootCacheFilesystemMeasurement');filesystemContexts[component]=context;
  filesystem[component]=inspectImageFilesystemEvidence(context);
  const previous=filesystems.find(f=>f.component===component);need(previous&&previous.graphHash===graph.graphHash,'NonrootCacheFilesystem');
  for(const key of ['version','graphHash','limitsHash','component','rootDigest','arm64Digest','entriesHash','entryCount'])same(filesystem[component][key],previous[key],'NonrootCacheFilesystemChanged');
 }
 const after=budget.usage();return {graph,filesystem,filesystemContexts,readUsage:{graphPasses:1,logicalBytes:after.transferredBytes-before.transferredBytes,localGraphReads:after.calls-before.calls,uncompressedBytes:after.uncompressedBytes-before.uncompressedBytes,processedEntries:after.fsEntries-before.fsEntries}};
}

export function inspectNonrootArtifactCacheVerification(context){const s=contexts.get(context);need(s,'NonrootCacheContextRequired');return copyNonrootJson(s.data);}

/** Only same-process proof construction can reach verified byte contexts.
 * Published archives reconstruct commitments separately; they never enter here. */
export function nonrootArtifactCacheMaterial(context){const s=contexts.get(context);need(s,'NonrootCacheContextRequired');return {binding:inspectNonrootArtifactCacheVerification(context),graph:s.graph,filesystem:{...s.filesystemContexts}};}

const CAPS=Object.freeze({ecrRequests:IMAGE_LIMITS.maxEcrCalls,logicalBytes:IMAGE_LIMITS.maxTransferredBytes,httpBodyBytes:IMAGE_LIMITS.maxTransferredBytes,uncompressedBytes:IMAGE_LIMITS.maxUncompressedBytes,processedEntries:IMAGE_LIMITS.maxFsEntries});
const zero=()=>Object.fromEntries(Object.keys(CAPS).map(k=>[k,0]));
const counter=v=>{exact(v,Object.keys(CAPS));for(const [k,max]of Object.entries(CAPS))need(Number.isSafeInteger(v[k])&&v[k]>=0&&v[k]<=max,'NonrootCacheCounter');return v;};

function fundingPlans(record,copyCheckpoint,copyReceipt,expected){
 need(typeof record.startRaw==='string'&&record.startRaw.length>0&&record.startRaw.length<=32768,'NonrootCacheStartRaw');
 const raw=Buffer.from(record.startRaw,'base64'),text=raw.toString('utf8');
 need(raw.toString('base64')===record.startRaw&&Buffer.from(text).equals(raw),'NonrootCacheStartRaw');
 same(parseNonrootJson(text,{maxBytes:24576}),record.start,'NonrootCacheStartRaw');
 need(Array.isArray(record.fundingPlans)&&record.fundingPlans.length>0&&record.fundingPlans.length<=20000,'NonrootCacheFundingPlans');
 const e=copyNonrootJson(expected);
 exact(e,['source','predecessorParameterHash','rootBindingHash','authorizationId','nextParameterVersion']);
 const {source,...anchors}=e,plans=new Map(),scopes=new Set();
 for(const value of record.fundingPlans){
  const checked=inspectFutureFundingPlan(value),{plan,planHash,scopeHash}=checked;
  need(!plans.has(planHash)&&!scopes.has(scopeHash),'NonrootCacheFundingDuplicate');
  need(plan.ledgerStartHash===sha(raw),'NonrootCacheFundingStart');
  const catalog=parseNonrootJson(Buffer.from(plan.catalogRaw,'base64').toString('utf8'),{maxBytes:1048576});
  same(catalog.ledgerBinding,record.start.binding,'NonrootCacheFundingLedger');
  same(plan.source,source,'NonrootCacheFundingSource');
  same(plan.anchors,{...anchors,copyCheckpointHash:hash(copyCheckpoint)},'NonrootCacheFundingAnchors');
  need(plan.issuedMs>=copyReceipt.summary.completedMs&&plan.issuedMs<record.start.deadlineMs,'NonrootCacheFundingTime');
  plans.set(planHash,checked);scopes.add(scopeHash);
 }
 return plans;
}

/** Verify the actual stopped-worker/source/cleanup record joins. These JSON
 * records authenticate archived facts only and never restore process handles. */
export async function verifyNonrootCombinedCustody(copyReceipt,{readCopyRecord}){
 const c=copyReceipt,p=c.combinedPass;need(c.version===3&&p&&typeof readCopyRecord==='function','NonrootCombinedReceipt');
 exact(p.custody,['physicalStopRef','originalHandleCleanupRef','sourcePreflightRef']);
 const read=async ref=>{exact(ref,['path','sha256']);need(typeof ref.path==='string'&&ref.path.startsWith('/')&&/^[a-f0-9]{64}$/.test(ref.sha256),'NonrootCombinedCustodyRef');const raw=await readCopyRecord(ref);need(raw instanceof Uint8Array&&raw.length<=8388608&&sha(raw)===ref.sha256,'NonrootCombinedCustodyPin');return parseNonrootJson(new TextDecoder('utf-8',{fatal:true}).decode(raw));};
 const stop=await read(p.custody.physicalStopRef),cleanup=await read(p.custody.originalHandleCleanupRef),source=await read(p.custody.sourcePreflightRef);
 for(const value of [stop,cleanup,source])need(value.owner===c.owner&&value.executionId===p.binding.executionId&&value.planHash===c.planHash,'NonrootCombinedCustodyBinding');
 need(stop.completed===true&&stop.cleanupComplete===true&&stop.hold===false&&stop.error===null&&stop.terminal?.kind==='subreaper-echild'&&stop.terminal.cleanupComplete===true&&stop.terminal.status===0&&stop.terminal.signal===null&&stop.terminal.reason===null&&positive(stop.terminal.reaped),'NonrootCombinedPhysicalStop');
 need(cleanup.version===1&&cleanup.kind==='original-copy-handle-cleanup'&&cleanup.released===true&&cleanup.filesAbsent===true&&positive(stop.stoppedMs)&&cleanup.releasedMs>=stop.stoppedMs&&p.startedMs>=cleanup.releasedMs,'NonrootCombinedCleanup');same(cleanup.physicalStopRef,p.custody.physicalStopRef);
 same(source.inventory,c.inventory);same(source.filesystems,c.filesystems);need(source.publicationHash===c.publicationHash,'NonrootCombinedSource');
}

/** Reconcile the one pre-seal DATA pass with its original acquisition debits.
 * Copy checkpoint is independently pinned; this never restores a live handle. */
export function verifyNonrootCombinedCopyAccounting(value,{copyCheckpoint,copyReceipt,expectedFunding,expectedBudgetRevision,expectedBudgetCeiling,expectedFenceAcquisition,expectedCopyReplay,requireSettledCopyReplay=false}){
 const record=copyNonrootJson(value),c=copyReceipt,p=c.combinedPass;exact(record,['startRaw','events',...(Object.hasOwn(record,'payments')?['payments']:[]),...(Object.hasOwn(record,'copyReplay')?['copyReplay']:[])]);
 if(Object.hasOwn(record,'copyReplay')){if(expectedCopyReplay!==undefined)same(record.copyReplay,expectedCopyReplay,'NonrootCopyReplayContextConflict');expectedCopyReplay=record.copyReplay;}
 need(c.version===3&&p,'NonrootCombinedReceipt');
 exact(p,['version','kind','binding','custody','settledReadbackHash','verifierClosureHash','ledgerStartHash','firstSequence','lastSequence','lastEventHash','startedMs','completedMs','filesystemHash','readUsage']);
 exact(p.custody,['physicalStopRef','originalHandleCleanupRef','sourcePreflightRef']);
 need(p.version===1&&p.kind==='combined-data-pass'&&[p.settledReadbackHash,p.verifierClosureHash,p.ledgerStartHash,p.lastEventHash,p.filesystemHash].every(v=>/^[a-f0-9]{64}$/.test(v)),'NonrootCombinedReceipt');
 need(typeof record.startRaw==='string'&&record.startRaw.length<=32768,'NonrootCacheStartRaw');const raw=Buffer.from(record.startRaw,'base64');need(raw.toString('base64')===record.startRaw&&sha(raw)===p.ledgerStartHash,'NonrootCacheStartRaw');
 const start=parseNonrootJson(new TextDecoder('utf-8',{fatal:true}).decode(raw));exact(start,['version','kind','binding','startingCounters','reserve','deadlineMs','mode',...(Object.hasOwn(start,'budgetRevision')?['budgetRevision']:[]),...(Object.hasOwn(start,'copyReplay')?['copyReplay']:[])]);
 const policy=nonrootAccountingPolicy(start.budgetRevision,expectedBudgetRevision,expectedBudgetCeiling),{caps:CAPS,counter}=policy,revision=policy.budgetRevision?{budgetRevision:policy.budgetRevision}:{};
 need(start.version===policy.version&&start.kind==='custody-ledger-start'&&start.mode==='copy'&&start.deadlineMs===c.summary.startedMs+IMAGE_LIMITS.maxStageMs,'NonrootCombinedStart');
 if(policy.version===2)same(copyCheckpoint.budgetRevision,policy.budgetRevision,'NonrootBudgetRevisionMismatch');
 const binding={owner:c.owner,executionId:copyCheckpoint.binding.executionId,planHash:c.planHash,publicationHash:c.publicationHash};same(start.binding,binding);same(p.binding,binding);same(copyCheckpoint.binding,binding);
 verifyNonrootCopyReplayStart(start,{startRaw:record.startRaw,copyCheckpoint,copyReceipt:c,policy,expectedCopyReplay,requireSettled:requireSettledCopyReplay});
 need(positive(p.startedMs)&&p.startedMs>=c.summary.startedMs&&p.completedMs>=p.startedMs&&p.completedMs===c.summary.completedMs&&p.completedMs<start.deadlineMs,'NonrootCombinedTime');
 const objects=new Map(c.destinationReadback.reads.map(d=>[d.repositoryName+'\0'+d.digest,d])),charged=new Map(),begun=new Set(),completed=new Set(),fs=new Set(),source=new Map(),ids=new Set(),active=new Map();
 let previous=null,opened=false,finished=false,sealed=false,logical=0,uncompressed=0,entries=0;
 const spent={...counter(start.startingCounters)},remaining={...counter(start.reserve)},scan=createCopyScanPoolReplay(),scanTemplate=describeScanSequenceTemplate({inventory:c.inventory,scope:{account:c.summary.account,region:c.summary.region}}).template;
 const add=(k,n)=>{need(Number.isSafeInteger(n)&&n>=0,'NonrootCacheCounter');spent[k]+=n;};
 const debit=d=>{counter(d);for(const k of Object.keys(CAPS)){need(d[k]<=remaining[k],'NonrootCacheReserveDebit');remaining[k]-=d[k];}};
 const check=()=>{const exposure=[...active.values()].reduce((n,r)=>n+r.bound,0)+scan.active.size*8388608;for(const k of Object.keys(CAPS))need(spent[k]+remaining[k]+(k==='httpBodyBytes'?exposure:0)<=CAPS[k],'NonrootCacheCumulativeLimit');};
 need(Array.isArray(record.events)&&record.events.length>0&&record.events.length<=20000,'NonrootCacheAccountingEvents');check();
 const rootReservations=verifyRootOwnerReservations(record.events),rootPool=createRootOwnerPoolReplay();
 const beforeCopy=Object.hasOwn(record,'payments')?verifyNonrootBeforeCopyAccounting(record.payments,{startRaw:record.startRaw,events:record.events,copyReceipt:c,expectedFunding,expectedBudgetRevision,expectedBudgetCeiling,expectedFenceAcquisition}):{prepayments:new Map(),legacyReservations:new Set(),legacyFilesystemSequences:new Set()};
 need(!expectedFenceAcquisition||Object.hasOwn(record,'payments'),'NonrootFencePaymentRequired');
 for(const [i,e]of record.events.entries()){
  exact(e,['version','sequence','owner','executionId','planHash','publicationHash','previousHash','type','data','spent','remaining',...Object.keys(revision)]);need(!sealed&&e.version===policy.version&&e.sequence===i+1&&e.previousHash===previous,'NonrootCacheEventChain');if(policy.version===2)same(e.budgetRevision,policy.budgetRevision,'NonrootBudgetRevisionMismatch');for(const k of Object.keys(binding))need(e[k]===binding[k],'NonrootCacheEventOwner');const d=e.data;
  need(e.type.startsWith('root-pool-')||!rootPool.plan||rootPool.closed,'NonrootRootPoolExclusive');
  if(e.type==='prepayment'){
   const charge=beforeCopy.prepayments.get(e.sequence);need(charge&&!opened&&active.size===0&&!scan.plan&&source.size===0,'NonrootCacheBeforeCopyPayment');
   for(const [k,n]of Object.entries(charge))add(k,n);
  }else if(e.type.startsWith('root-pool-')){
   need(!opened&&!scan.plan&&active.size===0&&source.size===0&&!['root-pool-activation','root-pool-unknown','root-pool-hold'].includes(e.type),'NonrootCacheUncertainAccounting');
   if(e.type==='root-pool-prepayment'&&expectedFunding){need(d.plan.template.rootBindingHash===expectedFunding.rootBindingHash&&d.plan.template.sourceHash===hash(expectedFunding.source),'NonrootRootPoolProofBinding');}
   const delta=applyRootOwnerPoolEvent(rootPool,e.type,d,{ledgerBinding:binding,ledgerStartHash:p.ledgerStartHash,deadlineMs:start.deadlineMs});for(const [k,n]of Object.entries(delta))add(k,n);
  }else if(e.type.startsWith('scan-pool-')){
   need(!opened&&active.size===0&&!['scan-pool-unknown','scan-pool-rejected'].includes(e.type),'NonrootCacheUncertainAccounting');
   if(e.type==='scan-pool-prepayment')need(d.plan.startedMs>=c.summary.startedMs&&d.plan.startedMs<=p.startedMs&&charged.size===objects.size&&[...source.values()].every(q=>q.complete),'NonrootScanPoolEarly');
   const delta=applyCopyScanPoolEvent(scan,e.type,d,{binding,ledgerStartHash:p.ledgerStartHash,settledReadbackHash:p.settledReadbackHash,template:scanTemplate,deadlineMs:start.deadlineMs});for(const [k,n]of Object.entries(delta))add(k,n);
  }else if(e.type==='logical'){
   exact(d,['purpose','bytes','reserveDebit',...(d.destinationObject?['destinationObject']:[])]);need(['upload','manifest','metadata','archive','destination'].includes(d.purpose),'NonrootCombinedLogical');add('logicalBytes',d.bytes);
   if(d.destinationObject){exact(d.destinationObject,['key','descriptor']);const {key,descriptor}=d.destinationObject,n=objects.get(key);need(!opened&&d.purpose==='destination'&&n&&!charged.has(key)&&d.bytes===n.size,'NonrootCombinedDebit');same(descriptor,{digest:n.digest,size:n.size,mediaType:n.mediaType});same(d.reserveDebit,{...zero(),logicalBytes:n.size});charged.set(key,e.sequence);}
  }else if(e.type==='cache-begin'){
   exact(d,['key','descriptor','origin','reserveDebit']);need(!opened&&d.origin==='source-cache'&&!source.has(d.key),'NonrootCombinedSource');source.set(d.key,{descriptor:d.descriptor,complete:false});add('logicalBytes',d.descriptor.size);
  }else if(e.type==='cache-complete'){
   exact(d,['key','digest','physicalBytes']);const q=source.get(d.key);need(q&&!q.complete&&q.descriptor.digest===d.digest&&q.descriptor.size===d.physicalBytes,'NonrootCombinedSource');q.complete=true;
  }else if(e.type==='reservation'){
   exact(d,['id','action','requestHash','bound','ecr','reserveDebit']);need(!opened&&(!scan.plan||scan.closed)&&positive(d.id)&&!ids.has(d.id)&&active.size<2&&Number.isSafeInteger(d.bound)&&d.bound>=0&&typeof d.ecr==='boolean'&&/^[a-f0-9]{64}$/.test(d.requestHash),'NonrootCacheReadReservation');
   need(rootReservations.has(d.id)||beforeCopy.legacyReservations.has(d.id)||['BatchGetImage','GetDownloadUrlForLayer','BatchCheckLayerAvailability','GetLifecyclePolicy','DescribeRepositories','S3BlobGet','InitiateLayerUpload','UploadLayerPart','CompleteLayerUpload','PutImage','CiSmokePublishedPut','CiSmokeGetObject'].includes(d.action)&&d.ecr===!['S3BlobGet','CiSmokePublishedPut','CiSmokeGetObject'].includes(d.action),'NonrootCacheReadReservation');ids.add(d.id);active.set(d.id,d);add('ecrRequests',d.ecr?1:0);
  }else if(e.type==='completed'){
   exact(d,['id','charged','responseHash']);const q=active.get(d.id);need(q&&Number.isSafeInteger(d.charged)&&d.charged>=0&&d.charged<=q.bound&&/^[a-f0-9]{64}$/.test(d.responseHash),'NonrootCacheReadSettlement');add('httpBodyBytes',d.charged);active.delete(d.id);
  }else if(e.type==='availability'){exact(d,['reservationId','request','response']);need(ids.has(d.reservationId)&&!active.has(d.reservationId),'NonrootCacheAvailabilityReservation');
  }else if(e.type==='combined-pass-start'){
   exact(d,['settledReadbackHash','verifierClosureHash','ledgerStartHash','custody','startedMs']);need(scan.closed&&!opened&&e.sequence===p.firstSequence&&active.size===0&&charged.size===objects.size&&[...source.values()].every(q=>q.complete)&&d.startedMs<=p.startedMs,'NonrootCombinedStart');
   for(const k of ['settledReadbackHash','verifierClosureHash','ledgerStartHash','custody'])same(d[k],p[k]);opened=true;
  }else if(e.type==='combined-cache-begin'){
   exact(d,['key','descriptor','logicalSequence']);const n=objects.get(d.key);need(opened&&!finished&&n&&!begun.has(d.key)&&charged.get(d.key)===d.logicalSequence,'NonrootCombinedDebit');same(d.descriptor,{digest:n.digest,size:n.size,mediaType:n.mediaType});begun.add(d.key);logical+=n.size;
  }else if(e.type==='combined-cache-complete'){
   exact(d,['key','digest','physicalBytes']);const n=objects.get(d.key);need(opened&&!finished&&n&&begun.has(d.key)&&!completed.has(d.key)&&d.digest===n.digest&&d.physicalBytes===n.size,'NonrootCombinedCompletion');completed.add(d.key);
  }else if(e.type==='filesystem'){
   exact(d,['component','phase','uncompressedBytes','processedEntries','reserveDebit']);
   if(beforeCopy.legacyFilesystemSequences.has(e.sequence))need(!opened&&source.size===0,'NonrootCombinedFilesystem');
   else{
    need(COMPONENTS.includes(d.component)&&['source','combined'].includes(d.phase)&&!fs.has(d.phase+'\0'+d.component),'NonrootCombinedFilesystem');
    need(d.phase==='source'?!opened:opened&&!finished,'NonrootCombinedFilesystem');fs.add(d.phase+'\0'+d.component);
    if(d.phase==='combined'){same(d.reserveDebit,{...zero(),uncompressedBytes:d.uncompressedBytes,processedEntries:d.processedEntries});uncompressed+=d.uncompressedBytes;entries+=d.processedEntries;}
   }
   add('uncompressedBytes',d.uncompressedBytes);add('processedEntries',d.processedEntries);
  }else if(e.type==='combined-pass-complete'){
   const {lastSequence,lastEventHash,...expected}=p;need(opened&&!finished&&e.sequence===lastSequence&&hash(e)===lastEventHash,'NonrootCombinedCompletion');same(d,expected);finished=true;
  }else if(e.type==='sealed'){exact(d,['reason']);need(d.reason==='completed'&&finished&&active.size===0,'NonrootCacheAccountingIncomplete');sealed=true;
  }else need(false,'NonrootCacheUncertainAccounting');
  if(d.reserveDebit)debit(d.reserveDebit);check();same(e.spent,spent,'NonrootCacheSpentMismatch');same(e.remaining,remaining,'NonrootCacheRemainingMismatch');previous=hash(e);
 }
 need((!rootPool.plan||rootPool.closed&&!rootPool.normal.held&&!rootPool.cleanup.held)&&scan.closed&&sealed&&completed.size===objects.size&&begun.size===objects.size&&fs.size===6,'NonrootCombinedIncomplete');
 const usage={graphPasses:1,logicalBytes:logical,localGraphReads:objects.size,uncompressedBytes:uncompressed,processedEntries:entries};same(p.readUsage,usage,'NonrootCacheUsageMismatch');same(p.filesystemHash,hash(Object.fromEntries(c.filesystems.map(f=>[f.component,f]))),'NonrootCombinedFilesystem');
 same(copyCheckpoint,{binding,startingCounters:start.startingCounters,counters:spent,remainingReservation:remaining,eventCount:record.events.length,lastEventHash:previous,active:0,sealed:true,...revision},'NonrootCacheCheckpointMismatch');return usage;
}

/** Reconcile actual adoption events with the independently authenticated copy
 * checkpoint and the byte verifier's measured work. Residual reservations are
 * carried forward. V2 prepaid charges require independently bound static plans;
 * they never count as actual graph/FS measurements or execution authority. */
export function verifyNonrootCacheReadAccounting(value,{copyCheckpoint,copyReceipt,readUsage,expectedFunding,expectedBudgetRevision,expectedBudgetCeiling,expectedFinalization,expectedFenceAcquisition,expectedCopyReplay}){
 const record=copyNonrootJson(value),hasFinalization=Object.hasOwn(record,'finalizationPlan');exact(record,['version','kind','start','events','checkpoint',...([2,3].includes(record.version)?['startRaw','fundingPlans']:[]),...(record.version===3?['combinedCopy']:[]),...(hasFinalization?['finalizationPlan']:[])]);
 need(hasFinalization===(expectedFinalization!==undefined),'NonrootFinalizationExpected');
 need([1,2,3].includes(record.version)&&record.kind==='nonroot-cache-read-accounting','NonrootCacheAccounting');
 const {start,events,checkpoint}=record;
 exact(start,['version','kind','binding','startingCounters','reserve','deadlineMs','mode',...(Object.hasOwn(start,'budgetRevision')?['budgetRevision']:[])]);
 const policy=nonrootAccountingPolicy(start.budgetRevision,expectedBudgetRevision,expectedBudgetCeiling),{caps:CAPS,counter}=policy,revision=policy.budgetRevision?{budgetRevision:policy.budgetRevision}:{};
 const binding={owner:copyReceipt.owner,executionId:copyCheckpoint.binding.executionId,planHash:copyReceipt.planHash,publicationHash:copyReceipt.publicationHash};
 need(start.version===policy.version&&start.kind==='custody-ledger-start'&&start.mode==='adoption'&&positive(start.deadlineMs),'NonrootCacheAccountingStart');
 if(policy.version===2)same(copyCheckpoint.budgetRevision,policy.budgetRevision,'NonrootBudgetRevisionMismatch');
 same(start.binding,binding);same(copyCheckpoint.binding,binding);
 need(copyCheckpoint.sealed===true&&copyCheckpoint.active===0,'NonrootCacheAccountingPrior');
 same(start.startingCounters,copyCheckpoint.counters,'NonrootCacheCounterReset');same(start.reserve,copyCheckpoint.remainingReservation,'NonrootCacheReservationReset');
 need((record.version===3)===(copyReceipt.version===3),'NonrootCombinedAccountingVersion');
 need(!expectedFenceAcquisition||record.version===3,'NonrootFenceAccountingVersion');
 need(record.version===3||expectedCopyReplay===undefined,'NonrootCopyReplayExpectedJoin');
 const combinedUsage=record.version===3?verifyNonrootCombinedCopyAccounting(record.combinedCopy,{copyCheckpoint,copyReceipt,expectedFunding,expectedBudgetRevision,expectedBudgetCeiling,expectedFenceAcquisition,expectedCopyReplay,requireSettledCopyReplay:true}):null;
 if(record.version===3){need(Array.isArray(record.fundingPlans)&&typeof record.startRaw==='string'&&record.startRaw.length<=32768,'NonrootCacheFundingPlans');const raw=Buffer.from(record.startRaw,'base64');need(raw.toString('base64')===record.startRaw,'NonrootCacheStartRaw');same(parseNonrootJson(new TextDecoder('utf-8',{fatal:true}).decode(raw)),record.start,'NonrootCacheStartRaw');}
 const plans=(record.version===2||record.version===3&&record.fundingPlans.length)&&!(hasFinalization&&Array.isArray(record.fundingPlans)&&record.fundingPlans.length===0)?fundingPlans(record,copyCheckpoint,copyReceipt,expectedFunding):new Map(),paid=new Set();
 let finalization=null,finalizationPaid=false;
 if(hasFinalization){
  need([2,3].includes(record.version)&&policy.version===2,'NonrootFinalizationVersion');
  exact(expectedFinalization,['budget','archiveManifestHash']);
  need(typeof record.startRaw==='string'&&record.startRaw.length<=32768,'NonrootCacheStartRaw');
  const raw=Buffer.from(record.startRaw,'base64');need(raw.toString('base64')===record.startRaw,'NonrootCacheStartRaw');same(parseNonrootJson(new TextDecoder('utf-8',{fatal:true}).decode(raw)),start,'NonrootCacheStartRaw');
  finalization=verifyNonrootFinalizationPlan(record.finalizationPlan,{...expectedFinalization,ledgerBinding:binding,ledgerStartHash:sha(raw),copyCheckpointHash:hash(copyCheckpoint),budgetRevision:policy.budgetRevision,deadlineMs:start.deadlineMs});
  need(!plans.has(finalization.planHash),'NonrootFinalizationPlanCollision');
 }
 const spent={...counter(start.startingCounters)},remaining={...counter(start.reserve)};
 const active=new Map(),ids=new Set(),objects=new Map(copyReceipt.destinationReadback.reads.map(d=>[d.repositoryName+'\0'+d.digest,d])),begun=new Set(),completed=new Set(),fs=new Set();
 let previous=null,sealed=false,logical=0,uncompressed=0,entries=0;
 const check=()=>{const exposed=[...active.values()].reduce((n,r)=>n+r.bound,0);for(const k of Object.keys(CAPS))need(spent[k]+remaining[k]+(k==='httpBodyBytes'?exposed:0)<=CAPS[k],'NonrootCacheCumulativeLimit');};
 const add=(key,n)=>{need(Number.isSafeInteger(n)&&n>=0&&Number.isSafeInteger(spent[key]+n),'NonrootCacheCounter');spent[key]+=n;};
 const debit=d=>{counter(d);for(const key of Object.keys(CAPS)){need(d[key]<=remaining[key],'NonrootCacheReserveDebit');remaining[key]-=d[key];}};
 need(Array.isArray(events)&&events.length>0&&events.length<=20000,'NonrootCacheAccountingEvents');check();
 for(const [index,event]of events.entries()){
  exact(event,['version','sequence','owner','executionId','planHash','publicationHash','previousHash','type','data','spent','remaining',...Object.keys(revision)]);
  need(!sealed&&event.version===policy.version&&event.sequence===index+1&&event.previousHash===previous,'NonrootCacheEventChain');if(policy.version===2)same(event.budgetRevision,policy.budgetRevision,'NonrootBudgetRevisionMismatch');for(const key of Object.keys(binding))need(event[key]===binding[key],'NonrootCacheEventOwner');
  const d=event.data;
  if(event.type==='cache-begin'){
   exact(d,['key','descriptor','origin','reserveDebit']);const expected=objects.get(d.key);
   need(!combinedUsage&&expected&&!begun.has(d.key)&&d.origin==='completed-destination-cache','NonrootCacheGraphPass');
   same(d.descriptor,{digest:expected.digest,size:expected.size,mediaType:expected.mediaType});same(d.reserveDebit,{...zero(),logicalBytes:expected.size});
   debit(d.reserveDebit);add('logicalBytes',expected.size);logical+=expected.size;begun.add(d.key);
  }else if(event.type==='cache-complete'){
   exact(d,['key','digest','physicalBytes']);const expected=objects.get(d.key);
   need(expected&&begun.has(d.key)&&!completed.has(d.key)&&d.digest===expected.digest&&d.physicalBytes===expected.size,'NonrootCacheGraphCompletion');completed.add(d.key);
  }else if(event.type==='filesystem'){
   exact(d,['component','phase','uncompressedBytes','processedEntries','reserveDebit']);need(!combinedUsage&&COMPONENTS.includes(d.component)&&d.phase==='adoption'&&!fs.has(d.component),'NonrootCacheFilesystemPass');
   same(d.reserveDebit,{...zero(),uncompressedBytes:d.uncompressedBytes,processedEntries:d.processedEntries});debit(d.reserveDebit);add('uncompressedBytes',d.uncompressedBytes);add('processedEntries',d.processedEntries);uncompressed+=d.uncompressedBytes;entries+=d.processedEntries;fs.add(d.component);
  }else if(event.type==='reservation'){
   exact(d,['id','action','requestHash','bound','ecr','reserveDebit']);
   need(positive(d.id)&&!ids.has(d.id)&&/^[a-f0-9]{64}$/.test(d.requestHash)&&Number.isSafeInteger(d.bound)&&d.bound>=0&&typeof d.ecr==='boolean'&&['BatchGetImage','GetDownloadUrlForLayer','BatchCheckLayerAvailability','GetLifecyclePolicy','DescribeRepositories','DescribeImageScanFindings','S3BlobGet'].includes(d.action),'NonrootCacheReadReservation');
   need(d.ecr===(d.action!=='S3BlobGet')&&active.size<2,'NonrootCacheReadReservation');ids.add(d.id);debit(d.reserveDebit);add('ecrRequests',d.ecr?1:0);active.set(d.id,d);
  }else if(event.type==='completed'){
   exact(d,['id','charged','responseHash']);const reserved=active.get(d.id);
   need(reserved&&/^[a-f0-9]{64}$/.test(d.responseHash)&&Number.isSafeInteger(d.charged)&&d.charged>=0&&d.charged<=reserved.bound,'NonrootCacheReadSettlement');add('httpBodyBytes',d.charged);active.delete(d.id);
  }else if(event.type==='logical'){
   exact(d,['purpose','bytes','reserveDebit']);need(['metadata','archive'].includes(d.purpose),'NonrootCacheReadOnly');same(d.reserveDebit,{...zero(),logicalBytes:d.bytes});debit(d.reserveDebit);add('logicalBytes',d.bytes);
  }else if(event.type==='availability'){
   exact(d,['reservationId','request','response']);need(ids.has(d.reservationId)&&!active.has(d.reservationId),'NonrootCacheAvailabilityReservation');
  }else if(event.type==='prepayment'&&[2,3].includes(record.version)){
   if(finalization&&d?.planHash===finalization.planHash){
    need(!finalizationPaid&&active.size===0&&begun.size===completed.size,'NonrootFinalizationPrepaymentOnce');
    const {allocationId,planHash,scopeHash,charge,reserveDebit}=finalization;
    same(d,{allocationId,planHash,scopeHash,charge,reserveDebit},'NonrootFinalizationDebit');
    debit(reserveDebit);for(const key of Object.keys(CAPS))add(key,charge[key]);finalizationPaid=true;
   }else{
    const plan=plans.get(d?.planHash);need(plan&&!paid.has(plan.planHash)&&active.size===0&&begun.size===completed.size,'NonrootCacheFundingEvent');
    same(d,{allocationId:plan.planHash,planHash:plan.planHash,scopeHash:plan.scopeHash,charge:plan.budget,reserveDebit:plan.budget},'NonrootCacheFundingDebit');
    debit(d.reserveDebit);for(const key of Object.keys(CAPS))add(key,plan.budget[key]);paid.add(plan.planHash);
   }
  }else if(event.type==='sealed'){
   exact(d,['reason']);need(d.reason==='completed'&&active.size===0,'NonrootCacheAccountingIncomplete');sealed=true;
  }else need(false,'NonrootCacheUncertainAccounting');
  check();same(event.spent,spent,'NonrootCacheSpentMismatch');same(event.remaining,remaining,'NonrootCacheRemainingMismatch');previous=hash(event);
 }
 need(sealed&&(combinedUsage?completed.size===0&&begun.size===0&&fs.size===0:completed.size===objects.size&&begun.size===objects.size&&fs.size===3),'NonrootCacheAccountingIncomplete');
 need(paid.size===plans.size,'NonrootCacheFundingMissing');
 need(!finalization||finalizationPaid,'NonrootFinalizationPaymentMissing');
 const measuredUsage=combinedUsage??{graphPasses:1,logicalBytes:logical,localGraphReads:objects.size,uncompressedBytes:uncompressed,processedEntries:entries};
 if(readUsage!==undefined)same(readUsage,measuredUsage,'NonrootCacheUsageMismatch');
 exact(checkpoint,['binding','startingCounters','counters','remainingReservation','eventCount','lastEventHash','active','sealed',...Object.keys(revision)]);
 same(checkpoint,{binding,startingCounters:start.startingCounters,counters:spent,remainingReservation:remaining,eventCount:events.length,lastEventHash:previous,active:0,sealed:true,...revision},'NonrootCacheCheckpointMismatch');
 return freeze({counters:spent,remainingReservation:remaining,checkpointHash:hash(checkpoint),readUsage:measuredUsage,...(paid.size?{fundingPlanHashes:[...paid].sort()}:{}),...(finalization?{finalizationPlanHash:finalization.planHash}:{})});
}
