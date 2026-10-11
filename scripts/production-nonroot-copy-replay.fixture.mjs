// Closed public accounting DATA. Graph/filesystem and scan replay use their
// real validators. This fixture does not issue C/R12/COPY handles, perform
// provider operations, or claim a successful native production chain.
import {createHash} from 'node:crypto';
import {graphFixture} from './production-image.fixture.mjs';
import {readImageGraph,verifyImageGraphCopies,inspectImageCopyVerification} from './lib/production-image-graph.mjs';
import {inspectImageFilesystem,inspectImageFilesystemEvidence} from './lib/production-image-filesystem.mjs';
import {nonrootHash as hash} from './lib/production-nonroot-contracts.mjs';
import {NONROOT_REMAINING_WORK_LIMITS_HASH_V2,NONROOT_REMAINING_WORK_CAPS_V2,inspectCommittedNonrootBudgetEnvelope} from './lib/production-nonroot-budget-revision.mjs';
import {IMAGE_TRANSITION_LIMITS_HASH} from './lib/production-image-transition.mjs';
import {describeScanSequenceTemplate,createCopyScanPoolReplay,applyCopyScanPoolEvent,copyScanPoolSummary} from './lib/production-nonroot-scan-pool.mjs';
export const keys=['ecrRequests','logicalBytes','httpBodyBytes','uncompressedBytes','processedEntries'];
export const zero=()=>Object.fromEntries(keys.map(k=>[k,0]));
export const plus=(...rs)=>Object.fromEntries(keys.map(k=>[k,rs.reduce((s,r)=>s+r[k],0)]));
const minus=(a,b)=>Object.fromEntries(keys.map(k=>[k,a[k]-b[k]]));
export const sha=v=>createHash('sha256').update(v).digest('hex');
export const raw=v=>Buffer.from(JSON.stringify(v)+'\n');
const local=n=>({...zero(),logicalBytes:n}),R=name=>({path:'/synthetic/'+name+'.json',sha256:hash(name)});

function envelope(owner,historyCounters,remaining){
 const bindings=Object.fromEntries(['source','sourceReview','policy','scopes','inventory','rootBinding','carrierTemplate','operationSet'].map(k=>[k,R(k)]));
 const history={owner,headHash:hash('synthetic-history8'),counters:historyCounters},bindingValues=Object.fromEntries(Object.entries(bindings).filter(([k])=>k!=='sourceReview'));
 const ids=['remainingMetadata','originalIssuers','legacy','carrier','ciEnvelope','copy','futureNonroot','finalization','root:before-copy',...['9','17','19','21','23'].map(n=>'root:deploy-prod/'+n)];
 // A synthetic committed-envelope codec fixture, not producer completeness.
 // The public inspector's contract explicitly leaves producer authentication
 // to its original validating caller; no native payer is created here.
 const parts=ids.map(id=>({id,complete:true,charge:id==='copy'?remaining:zero(),completionReserve:zero()}));
 const common={version:2,limitsHash:NONROOT_REMAINING_WORK_LIMITS_HASH_V2,perOperationLimitsHash:IMAGE_TRANSITION_LIMITS_HASH,
  inputBindingHash:hash({limitsHash:NONROOT_REMAINING_WORK_LIMITS_HASH_V2,history,bindings:bindingValues}),history,bindings:bindingValues,components:{},parts,
  rootCatalogHash:hash('synthetic-root-catalog'),rootMaximumCalls:1,knownRemaining:remaining,completionReserve:zero(),projected:plus(historyCounters,remaining)};
 const proposal={...common,kind:'remaining-work-budget-proposal'},body={...common,kind:'remaining-work-budget-envelope',bindings,authority:false,executionReady:false,
  designRefs:[],proposalHash:hash(proposal),caps:NONROOT_REMAINING_WORK_CAPS_V2,headroom:minus(NONROOT_REMAINING_WORK_CAPS_V2,common.projected),complete:true,status:'BUDGET_FITS',fits:true,overCap:[],unresolved:[]};
 const value={...body,envelopeHash:hash(body),budgetRevision:{version:2,limitsHash:NONROOT_REMAINING_WORK_LIMITS_HASH_V2,envelopeHash:hash(body),historyHeadHash:history.headHash}};
 inspectCommittedNonrootBudgetEnvelope(value,{budgetRevision:value.budgetRevision,owner});return value;
}
function copyBudget(T){
 const pricing={bounds:{synthetic:128},decoderBytes:4096,planningInputLocalBytes:4096,uncompressedBytes:2048,processedEntries:4};
 const perInvocation={...zero(),logicalBytes:2687488,uncompressedBytes:2048,processedEntries:4};
 const q={version:2,kind:'control-capture-replay-budget',invocations:13,catalogHash:hash('synthetic-read-catalog'),readBytes:128,reads:3,perInvocation,
  charge:Object.fromEntries(keys.map(k=>[k,13*perInvocation[k]])),pricing};
 const family={preclaim:local(12496896),completion:local(19685376),cleanup:local(528384)},nonC={preclaim:local(1000000),completion:local(2000000)};
 const preclaimNormal=plus(q.charge,nonC.preclaim,family.preclaim),P=plus(preclaimNormal,family.cleanup),completion=plus(q.charge,nonC.completion,family.completion);
 const body={version:1,kind:'copy-replay-budget',policyHash:hash('synthetic-policy'),sourceManifestHash:hash('synthetic-source'),replayPricing:pricing,nonC,family,
  preclaimReplay:q,completionReplay:q,preclaimNormal,cleanup:family.cleanup,P,completion,T:plus(P,completion,T)};
 return {...body,budgetHash:hash(body)};
}
export async function copyReplayAccountingFixture({settled=true,legacy}={}){
 const g=graphFixture();for(const r of g.roots){r.sourceRepository='mem9-on-aws/preview/'+r.component;r.destinationRepository='mem9-on-aws/'+r.component;r.targetTag='mem9-example';}
 const source=await readImageGraph(g.roots,g),destination=await readImageGraph(g.roots,{...g,side:'destination'}),scope={account:'123456789012',region:'us-west-2'};
 const copied=inspectImageCopyVerification(verifyImageGraphCopies(source,destination,scope));
 const fs=[],usage={source:{},combined:{}};
 for(const [phase,graph]of [['source',source],['combined',destination]])for(const r of g.roots){
  const before=g.budget.usage(),observed=inspectImageFilesystemEvidence(await inspectImageFilesystem(graph,{component:r.component})),after=g.budget.usage();
  usage[phase][r.component]={uncompressedBytes:after.uncompressedBytes-before.uncompressedBytes,processedEntries:after.fsEntries-before.fsEntries};
  if(phase==='combined')fs.push(observed);
 }
 const objects=copied.destinationReadback.reads,graphBytes=objects.reduce((n,r)=>n+r.size,0),fsUse=Object.fromEntries(['uncompressedBytes','processedEntries'].map(k=>[k,Object.values(usage.combined).reduce((n,row)=>n+row[k],0)]));
 const providerReserve={ecrRequests:600,logicalBytes:2*graphBytes+100000,httpBodyBytes:134217728+16777216+100000,uncompressedBytes:2*fsUse.uncompressedBytes+10000,processedEntries:2*fsUse.processedEntries+100};
 const b=copyBudget(providerReserve),history={ecrRequests:10,logicalBytes:1000,httpBodyBytes:2000,uncompressedBytes:3000,processedEntries:4},paid={...zero(),ecrRequests:12,logicalBytes:4096,httpBodyBytes:1000};
 const baseline=plus(history,paid),owner='a'.repeat(32),executionId='b'.repeat(32),predecessor='c'.repeat(32),e=envelope(owner,history,plus(paid,b.T));
 const c={version:9,kind:'image-cache-custody-successor',owner,executionId,predecessorExecutionId:predecessor,directory:'/synthetic/owners/'+owner+'/'+predecessor+'/'+executionId,
  startingCounters:baseline,budgetRevision:e.budgetRevision,publication:{version:1,mode:'digest-only',inventoryHash:hash(copied.inventory)},inventory:copied.inventory,scope};
 const startMs=copied.summary.startedMs,at=copied.summary.completedMs,deadlineMs=startMs+2700000,binding={owner,executionId,planHash:hash(c),publicationHash:hash(c.publication)};
 const values={},refs={},put=(key,path,value)=>{values[key]=value;refs[key]={path,sha256:sha(raw(value))};return refs[key];};
 const parent=c.directory.slice(0,c.directory.lastIndexOf('/')),input={configRef:{path:'/synthetic/config.json',sha256:sha(raw(c))},ownerAuthorizationRef:R('owner-authorization')},inputHash=hash(input);
 put('Cp',parent+'/claim.json',{version:2,kind:'copy-validation-claim',owner,executionId,predecessorExecutionId:predecessor,input,configHash:hash(c),policyHash:b.policyHash,sourceManifestHash:b.sourceManifestHash,budgetHash:b.budgetHash,
  witnessHash:hash('synthetic-data-only-witness-hash'),historyHeadHash:e.history.headHash,counters:baseline,protectedReservation:zero(),P:b.P,T:b.T,completion:b.completion,startedMs:startMs,deadlineMs});
 const payment={claimRef:refs.Cp,budgetHash:b.budgetHash,policyHash:b.policyHash,sourceManifestHash:b.sourceManifestHash,P:b.P,T:b.T,completion:b.completion,counters:baseline,prefixCounters:plus(baseline,b.P),historyHeadHash:e.history.headHash,startedMs:startMs,deadlineMs};
 put('N','/synthetic/admissions/'+owner+'/admission-0009.json',{version:3,kind:'remaining-work-copy-admission',sequence:9,previousHash:e.history.headHash,baseHistoryHash:hash('synthetic-base'),owner,predecessorExecutionId:predecessor,purpose:'production-copy',operationId:hash({version:1,owner,purpose:'production-copy'}),event:'admit',
  data:{inputRef:input.configRef,configHash:hash(c),executionId,budgetRevision:e.budgetRevision,preclaimHeadHash:e.history.headHash,envelopeRef:R('envelope'),envelopeInputRef:R('envelope-input'),charge:e.knownRemaining,projected:e.projected,startedMs:null,deadlineMs:null,copyReplay:payment}});
 const start={version:2,kind:'custody-ledger-start',budgetRevision:e.budgetRevision,binding,startingCounters:plus(baseline,b.P,b.completion),reserve:minus(b.T,plus(b.P,b.completion)),deadlineMs,mode:'copy',
  copyReplay:{version:1,claimRef:refs.Cp,budgetHash:b.budgetHash,policyHash:b.policyHash,sourceManifestHash:b.sourceManifestHash,nodeRef:refs.N,baselineCounters:baseline,P:b.P,completion:b.completion,T:b.T}};
 if(legacy){delete start.copyReplay;if(legacy===1){start.version=1;delete start.budgetRevision;}}
 put('L',c.directory+'/records/ledger-start.json',start);
 for(const ordinal of [1,2])put('K'+ordinal,parent+'/copy-validation-'+ordinal+'.json',{version:1,kind:'copy-validation-checkpoint',ordinal,claimRef:refs.Cp,...(ordinal===2?{previousRef:refs.K1}:{}),inputHash,budgetHash:b.budgetHash,configHash:hash(c),historyHeadHash:e.history.headHash,envelopeHash:e.envelopeHash,...(ordinal===2?{nodeHash:hash(values.N)}:{})});
 put('J',parent+'/copy-upgrade.json',{version:1,kind:'copy-validation-upgrade',claimRef:refs.Cp,checks:[refs.K1,refs.K2],inputHash,budgetHash:b.budgetHash,policyHash:b.policyHash,P:b.P,delta:minus(b.T,b.P),T:b.T,completion:b.completion,startedMs:startMs,deadlineMs,N:{ref:refs.N,bytesLength:raw(values.N).length},L:{ref:refs.L,bytesLength:raw(start).length}});
 if(settled){const receipt=q=>({authority:false,funding:'caller-counter',budget:q,prepaid:q.charge,used:zero(),replays:13,closed:true,held:false,refund:zero()});
  put('S',parent+'/copy-validation-settlement.json',{version:1,kind:'copy-validation-settlement',claimRef:refs.Cp,refs:Object.fromEntries(['Cp','K1','K2','J'].map(k=>[k,refs[k]])),status:'COMPLETE',liability:b.T,budgetHash:b.budgetHash,startedMs:startMs,deadlineMs,used:{normal:0,completion:0,cleanup:528384},replayReceipts:{preclaim:receipt(b.preclaimReplay),completion:receipt(b.completionReplay)},refund:zero()});}
 const events=[],spent={...start.startingCounters},remaining={...start.reserve};let last=null;
 const emit=(type,data,charge=zero())=>{for(const k of keys){spent[k]+=charge[k];remaining[k]-=data.reserveDebit?.[k]??0;}const row={version:legacy===1?1:2,...(legacy===1?{}:{budgetRevision:e.budgetRevision}),sequence:events.length+1,...binding,previousHash:last,type,data:structuredClone(data),spent:{...spent},remaining:{...remaining}};last=hash(row);events.push(row);return row;};
 emit('reservation',{id:1,action:'BatchGetImage',requestHash:hash('synthetic-request'),bound:4352+8388608,ecr:true,reserveDebit:{...zero(),ecrRequests:1,httpBodyBytes:4352+16777216}},{...zero(),ecrRequests:1});
 emit('completed',{id:1,charged:100,responseHash:hash('synthetic-response')},{...zero(),httpBodyBytes:100});
 for(const d of objects){const key=d.repositoryName+'\0'+d.digest,descriptor={digest:d.digest,size:d.size,mediaType:d.mediaType};emit('cache-begin',{key,descriptor,origin:'source-cache',reserveDebit:local(d.size)},local(d.size));emit('cache-complete',{key,digest:d.digest,physicalBytes:d.size});}
 for(const f of fs){const u=usage.source[f.component];emit('filesystem',{component:f.component,phase:'source',...u,reserveDebit:{...zero(),...u}},{...zero(),...u});}
 const charged=new Map();for(const d of objects){const key=d.repositoryName+'\0'+d.digest;const row=emit('logical',{purpose:'destination',bytes:d.size,reserveDebit:local(d.size),destinationObject:{key,descriptor:{digest:d.digest,size:d.size,mediaType:d.mediaType}}},local(d.size));charged.set(key,row.sequence);}
 const template=describeScanSequenceTemplate({inventory:copied.inventory,scope}).template,scan=createCopyScanPoolReplay(),settledReadbackHash=hash('synthetic-settled'),plan={version:1,kind:'copy-scan-pool-plan',template,templateHash:hash(template),binding,ledgerStartHash:refs.L.sha256,settledReadbackHash,startedMs:at,deadlineMs:at+60000},poolId=hash(plan);
 const scanEmit=(type,data)=>emit(type,data,applyCopyScanPoolEvent(scan,type,data,{binding,ledgerStartHash:refs.L.sha256,settledReadbackHash,template,deadlineMs}));
 const quota={...zero(),ecrRequests:570,httpBodyBytes:134217728};scanEmit('scan-pool-prepayment',{poolId,plan,charge:quota,reserveDebit:quota});
 for(const [i,r]of template.images.entries()){
  const request={repositoryName:r.repositoryName,imageId:{imageDigest:r.imageDigest},maxResults:1000};scanEmit('scan-pool-reservation',{poolId,ordinal:i+1,action:'DescribeImageScanFindings',component:r.component,request,requestHash:hash(request),requestBytes:1024,responseBytes:4096,reservedMs:at,preconditionOrdinal:null});
  const response={registryId:scope.account,repositoryName:r.repositoryName,imageId:request.imageId,imageScanStatus:{status:'COMPLETE'},imageScanFindings:{imageScanCompletedAt:new Date(at).toISOString(),findings:[],findingSeverityCounts:{}}};
  scanEmit('scan-pool-completed',{poolId,ordinal:i+1,completedMs:at,wire:{requestBytes:raw(request).length,responseBytes:raw(response).length,requestSha256:sha(raw(request)),responseSha256:sha(raw(response)),statusCode:200,requestId:'synthetic-'+i,dispatched:true,complete:true},response,responseHash:hash(response),conservativeBytes:0,sharedUnknownBytes:0});
 }
 scanEmit('scan-pool-close',{poolId,completedMs:at,summary:copyScanPoolSummary(scan)});
 const custody={physicalStopRef:R('stop'),originalHandleCleanupRef:R('cleanup'),sourcePreflightRef:R('source')},verifierClosureHash=hash('synthetic-verifier');
 const firstSequence=events.length+1;emit('combined-pass-start',{settledReadbackHash,verifierClosureHash,ledgerStartHash:refs.L.sha256,custody,startedMs:at});
 for(const d of objects){const key=d.repositoryName+'\0'+d.digest;emit('combined-cache-begin',{key,descriptor:{digest:d.digest,size:d.size,mediaType:d.mediaType},logicalSequence:charged.get(key)});emit('combined-cache-complete',{key,digest:d.digest,physicalBytes:d.size});}
 for(const f of fs){const u=usage.combined[f.component];emit('filesystem',{component:f.component,phase:'combined',...u,reserveDebit:{...zero(),...u}},{...zero(),...u});}
 const readUsage={graphPasses:1,logicalBytes:graphBytes,localGraphReads:objects.length,...fsUse},pass={version:1,kind:'combined-data-pass',binding,custody,settledReadbackHash,verifierClosureHash,ledgerStartHash:refs.L.sha256,firstSequence,startedMs:at,completedMs:at,filesystemHash:hash(Object.fromEntries(fs.map(f=>[f.component,f]))),readUsage};
 const final=emit('combined-pass-complete',pass);const combinedPass={...pass,lastSequence:final.sequence,lastEventHash:hash(final)};emit('sealed',{reason:'completed'});
 const copyReceipt={version:3,owner,planHash:hash(c),publicationHash:binding.publicationHash,summary:copied.summary,inventory:copied.inventory,destinationReadback:copied.destinationReadback,filesystems:fs,combinedPass};
 const copyCheckpoint={...(legacy===1?{}:{budgetRevision:e.budgetRevision}),binding,startingCounters:start.startingCounters,counters:{...spent},remainingReservation:{...remaining},eventCount:events.length,lastEventHash:last,active:0,sealed:true};
 const context={refs,values,budget:b,inputHash,group:'verifyCompletedCopyV2',config:c,envelope:e};
 return {record:{startRaw:raw(start).toString('base64'),events},options:{copyCheckpoint,copyReceipt,...(legacy===1?{}:{expectedBudgetRevision:e.budgetRevision,expectedBudgetCeiling:e.projected}),...(legacy?{}:{expectedCopyReplay:context})},context,start,readUsage};
}
