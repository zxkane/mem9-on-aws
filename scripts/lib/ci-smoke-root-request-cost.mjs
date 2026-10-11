/** Prospective arithmetic only. No provider, journal writer, native handle,
 * policy replacement, reservation or permission to execute is created here.
 * The acquisition must debit this complete catalog ONCE before selection and
 * own the counters in its original closure. Checkpoints cannot mint credits. */
import {CI_ROOT_REQUEST_POLICY as P} from './ci-smoke-root-request.mjs';
import {NONROOT_LIMITS,copyNonrootJson,nonrootHash as hash} from './production-nonroot-contracts.mjs';
import {NONROOT_REMAINING_WORK_CAPS_V2 as GLOBAL} from './production-nonroot-budget-revision.mjs';

const KiB=1024,MiB=1024*KiB;
const need=(ok,code='CiRootCostInput')=>{if(!ok)throw Error(code);};
const nat=n=>Number.isSafeInteger(n)&&n>=0;
const freeze=v=>{if(v&&typeof v==='object'){Object.values(v).forEach(freeze);Object.freeze(v);}return v;};
const sum=values=>values.reduce((n,v)=>{need(nat(v)&&Number.isSafeInteger(n+v));return n+v;},0);
// All keys and shapes below are code-owned. No input is serialized to price it.
const ascii=n=>n+2,escaped=n=>6*n+2,number=16;
const object=fields=>2+Math.max(0,Object.keys(fields).length-1)+sum(Object.entries(fields).map(([key,n])=>key.length+3+n));
const array=(n,size)=>2+Math.max(0,n-1)+n*size;
const stages=['selection','request','transport','records','replay','cleanup'];
export const CI_ROOT_CHECKPOINTS=freeze(['deploy-prod/9','deploy-prod/17','deploy-prod/19','deploy-prod/21','deploy-prod/23']);
export const CI_ROOT_REPLAY_CHECKPOINTS=freeze(['deploy-prod/17','deploy-prod/19']);
export const CI_ROOT_LOCAL_JOURNAL_MAX_ROWS=200000;

export const CI_ROOT_COST_MODEL=freeze({
 version:2,kind:'prospective-root-local-cost-catalog',authority:false,
 // Linux native pathname limit, including conservative JSON escaping. This is
 // NOT a new restriction on valid repository paths or on request body bytes.
 referencePathBytes:4096,runBindingBytes:16*KiB,
 countingNodes:100000,checkpointCount:8,
 journalRows:1,
 // Row: text + buffer + write + terminal read/hash (same retained buffer),
 // then 16 raw/text/split/strict-parse/counter-check byte passes per replay.
 journalInitialPasses:4,journalPassesPerReplay:16,
});

/** Upper bound for the existing bounded counter, including a rejecting visit.
 * Nodes and edges cost <=96 bytes per node; total string code units <= the
 * encoded cap before rejection. The alternative 32*cap bound is exact for
 * dense arrays of one-digit numbers; 128 covers the rejecting boundary. */
export function ciRootCountingCostBound(encodedCap){
 need(nat(encodedCap)&&encodedCap>0&&encodedCap<=NONROOT_LIMITS.maxProofBytes);
 return Math.min(32*encodedCap,96*(CI_ROOT_COST_MODEL.countingNodes+1)+2*encodedCap)+128;
}

function recordBounds(){
 const ref=object({path:escaped(CI_ROOT_COST_MODEL.referencePathBytes),sha256:ascii(64)});
 const localRef=object({path:ascii('root-ready-128-complete.json'.length),sha256:ascii(64)});
 const keyBytes='decisions/prod/ci-grants/'.length+64+1+64+'/root-request.json'.length;
 const statusPathBytes='/repos/'.length+201+'/commits/'.length+40+'/statuses?per_page=100&page=3'.length;
 const putIntent=object({version:number,requestRef:localRef,key:ascii(keyBytes),requestBytes:number,responseCap:number,openedMs:number});
 const putDispatch=object({intentRef:localRef,requestHash:ascii(64),requestBytes:number,dispatchedMs:number});
 const putComplete=object({intentRef:localRef,status:number,responseHash:ascii(64),requestBytes:number,responseBytes:number,observedWireBytes:number,completedMs:number});
 const readyIntent=object({path:ascii(statusPathBytes),responseCap:number,requestedMs:number});
 const readyComplete=object({intentRef:localRef,responseRef:localRef,status:number,responseHash:ascii(64),responseBytes:number,completedMs:number});
 const held=object({requestRef:localRef,dispatched:5,observedWireBytes:number,refund:number});
 const exchangeRows=4+3*P.readyCalls;
 const exchangeEntry=object({name:ascii('root-ready-128-complete'.length),ref:localRef});
 const exchange=object({version:number,archiveHash:ascii(64),requestRef:localRef,observedWireBytes:number,records:array(exchangeRows,exchangeEntry),localAccountingRef:localRef});
 // Proposed fixed checkpoints bind the existing claim and scope hash. They
 // carry numbers/hashes only, never payloads, credentials or portable credits.
 const checkpoint=object({version:number,claimRef:ref,scopeHash:ascii(64),catalogHash:ascii(64),requestHash:ascii(64),sequence:number,stage:ascii(9),used:object(Object.fromEntries(stages.map(k=>[k,number]))),previousHash:ascii(64),held:5});
 const accounting=object({version:number,claimRef:ref,scopeHash:ascii(64),catalogHash:ascii(64),debitSequence:number,journalPrefixHash:ascii(64),debit:object(Object.fromEntries(Object.keys(GLOBAL).map(k=>[k,number]))),checkpoints:array(CI_ROOT_COST_MODEL.checkpointCount,checkpoint)});
 need(Math.max(putIntent,putDispatch,putComplete,readyIntent,readyComplete,held,checkpoint)<=P.requestBytes);
 need(exchange<=32*MiB);
 const ordinary=sum([putIntent,putDispatch,putComplete,P.readyCalls*(readyIntent+readyComplete),exchange,accounting]);
 return {ref,localRef,putIntent,putDispatch,putComplete,readyIntent,readyComplete,held,exchangeRows,exchange,checkpoint,accounting,ordinary};
}

/** Complete quote, not observed usage. The successful and rejecting preparation
 * bounds are both included: malformed inputs can consume selection work before
 * the complete request fails its 1 MiB check. No success-only graph coupling. */
export function calculateCiRootRequestCost(options={}){
 need(options&&Object.keys(options).every(k=>k==='checkpoint'));
 const checkpoint=options.checkpoint??'deploy-prod/23';
 need(CI_ROOT_CHECKPOINTS.includes(checkpoint));
 const final=checkpoint==='deploy-prod/23',localReplay=CI_ROOT_REPLAY_CHECKPOINTS.includes(checkpoint);
 const R=P.requestBytes,W=P.readyWireBytes,O=P.responseBytes,U=P.unknownBytes;
 const M=NONROOT_LIMITS.maxProofBytes,A=Math.floor(3*R/4),B=CI_ROOT_COST_MODEL.runBindingBytes;
 const C=ciRootCountingCostBound,record=recordBounds();
 const selectionCount=final?2*C(R)+C(3*R):0;
 const requestCount=2*C(R)+2*C(B);
 const selectionWork=final?8*(2*R+3*R)+2*M+10*A+4096:0;
 const requestWork=12*R+12*B;
 // No speculative streaming discount: copy/concat, text/parse and one durable
 // retained body remain charged. One terminal unknown prefix is disjoint from
 // the completed ready bytes and is charged once, without parsing it.
 const transportWork=6*W+8*O+U;
 // UTF-8/JSON snapshot, serialization/buffer and durable record work. Bodies
 // are outside these metadata rows and are not serialized a second time.
 const recordWork=6*record.ordinary;
 const archiveBytes=R+W+record.ordinary;
 const decoderWork=4*R+C(R)+C(B)+8*(R+B);
 // Only /17 and /19 enter local replay, once each. Entry parses and verifies
 // retained bytes. Finish reads/hash-checks them again, without re-parsing.
 // No root-file reads occur on intermediate reserveLocal calls.
 const replayFiles=record.exchangeRows+2;
 const replayEntryBytes=localReplay?8*(archiveBytes+replayFiles)+decoderWork:0;
 const replayFinishBytes=localReplay?archiveBytes+replayFiles:0;
 const replayWork=replayEntryBytes+replayFinishBytes;
 const cleanupWork=6*record.held;
 // The numeric width bounds the row even after its own overhead is included:
 // no recursive charge -> journal -> charge. Other four counters are zero.
 const journalRowBytes=object({ecrRequests:1,logicalBytes:number,httpBodyBytes:1,uncompressedBytes:1,processedEntries:1})+1;
 const journalBytes=CI_ROOT_COST_MODEL.journalRows*journalRowBytes;
 // The creation journal stays among the OTHER guarded refs. Its added row
 // is still rehashed on every reservation; price the existing journal bound.
 const journalReplayPasses=localReplay?1:0;
 const journalGuardReads=localReplay?CI_ROOT_LOCAL_JOURNAL_MAX_ROWS+2:0;
 const journalWork=journalBytes*(CI_ROOT_COST_MODEL.journalInitialPasses+journalReplayPasses*CI_ROOT_COST_MODEL.journalPassesPerReplay+journalGuardReads);
 const creationJournalWork=journalBytes*CI_ROOT_COST_MODEL.journalInitialPasses;
 const work={selection:selectionCount+selectionWork,request:requestCount+requestWork,transport:transportWork,records:recordWork,replay:replayWork+journalWork-creationJournalWork,cleanup:cleanupWork+creationJournalWork};
 const logicalBytes=sum(Object.values(work)),roundedLocalBytes=Math.ceil(logicalBytes/MiB)*MiB;
 need(roundedLocalBytes<=GLOBAL.logicalBytes);
 return freeze({version:2,kind:CI_ROOT_COST_MODEL.kind,authority:false,executionReady:false,checkpoint,final,
  bounds:{requestBytes:R,readyWireBytes:W,readyCalls:P.readyCalls,readyResponseBytes:P.readyResponseBytes,putResponseBytes:O,unknownBytes:U,manifestBytes:M,originalBytes:A,bindingBytes:B},
  counting:{batches:final?5:3,selectionBytes:selectionCount,requestBytes:requestCount,durableRows:1},
  records:record,journal:{rows:1,rowBytes:journalRowBytes,bytes:journalBytes,localBytes:journalWork,replayPasses:journalReplayPasses,guardReads:journalGuardReads},
  replay:{entries:localReplay?1:0,contentScans:localReplay?2:0,intermediateRootReads:0,files:localReplay?replayFiles:0,entryLocalBytes:replayEntryBytes,finishLocalBytes:replayFinishBytes,decoderLocalBytes:localReplay?decoderWork:0},work,
  logicalBytes,roundedLocalBytes,roundingBytes:roundedLocalBytes-logicalBytes,currentLocalBytes:P.localBytes,fitsCurrentLocal:logicalBytes<=P.localBytes,
  requires:['original acquisition/scope prepayment before selection','native rootStarted latch and non-exported counters','bounded original-byte evidence and fixed checkpoints','independent replay against original debit, never checkpoint-created credits','prospective policy review and full original-cap whole-fit'],
 });
}

/** Five existing, still-prospective root exchanges: four v1 requests and the
 * final seven-originals v2 request. This does not amend any issued token. */
export function calculateCiRootRequestPlanCost(){
 const slots=CI_ROOT_CHECKPOINTS.map(checkpoint=>calculateCiRootRequestCost({checkpoint}));
 const prior=5*P.localBytes,next=sum(slots.map(q=>q.roundedLocalBytes));
 return freeze({authority:false,executionReady:false,slots,priorLocalBytes:prior,prospectiveLocalBytes:next,additionalLocalBytes:next-prior,globalLogicalCap:GLOBAL.logicalBytes});
}

/** A new policy for new grants only; the original v1 policy stays unchanged. */
export function createProspectiveCiRootRequestPolicy(checkpoint){
 const q=calculateCiRootRequestCost({checkpoint});
 return freeze({...P,version:2,checkpoint,referenceEncoding:'owned-basename-v1',localBytes:q.roundedLocalBytes,catalogHash:hash(q)});
}
export function verifyProspectiveCiRootRequestPolicy(policy,scope){
 const phase={'deploy-prod/9':'preupdate','deploy-prod/17':'preconfigure','deploy-prod/19':'presst','deploy-prod/21':'preupdate','deploy-prod/23':'prereadiness'}[scope?.checkpoint];
 need(scope&&Object.keys(scope).sort().join()==='checkpoint,jobKey,kind,phase,route'&&phase&&scope.kind==='target'&&scope.jobKey==='deploy-prod'&&scope.route==='deploy-prod'&&scope.phase===phase,'CiRootCostScope');
 need(hash(policy)===hash(createProspectiveCiRootRequestPolicy(scope.checkpoint)),'CiRootCostPolicy');
 return calculateCiRootRequestCost({checkpoint:scope.checkpoint});
}

/** Arithmetic check only; caller must supply the independently verified COMPLETE
 * projection that still contains the five old root-local prices exactly once. */
export function projectCiRootRequestCost(projected){
 need(projected&&Object.keys(projected).sort().join()===Object.keys(GLOBAL).sort().join());
 for(const key of Object.keys(GLOBAL))need(nat(projected[key]));
 const quote=calculateCiRootRequestPlanCost();
 need(projected.logicalBytes>=quote.priorLocalBytes);
 const next={...projected,logicalBytes:projected.logicalBytes+quote.additionalLocalBytes};
 need(Number.isSafeInteger(next.logicalBytes));
 return freeze({authority:false,executionReady:false,projected:next,additionalLocalBytes:quote.additionalLocalBytes,fitsOriginalCaps:Object.keys(GLOBAL).every(k=>next[k]<=GLOBAL[k])});
}

/** Independent arithmetic replay only. The real caller must obtain expected
 * from its ORIGINAL authenticated acquisition/debit, not these checkpoint rows.
 * Returning this inert result never opens an acquisition or supplies credits. */
export function verifyCiRootCostCheckpoints(rows,expected,{checkpoint='deploy-prod/23'}={}){
 const q=calculateCiRootRequestCost({checkpoint}),input=copyNonrootJson(rows),e=copyNonrootJson(expected);
 const exact=(v,keys)=>need(v&&Object.keys(v).sort().join()===keys.slice().sort().join(),'CiRootCostFields');
 const hex=v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
 exact(e,['claimRef','scopeHash','requestHash','debit']);exact(e.claimRef,['path','sha256']);
 need(typeof e.claimRef.path==='string'&&Buffer.byteLength(e.claimRef.path)<=CI_ROOT_COST_MODEL.referencePathBytes&&hex(e.claimRef.sha256)&&hex(e.scopeHash)&&(e.requestHash===null||hex(e.requestHash)));
 exact(e.debit,Object.keys(GLOBAL));need(Object.keys(e.debit).every(k=>e.debit[k]===(k==='logicalBytes'?q.roundedLocalBytes:0)),'CiRootCostOriginalDebit');
 need(Array.isArray(input)&&input.length>0&&input.length<=CI_ROOT_COST_MODEL.checkpointCount,'CiRootCostCheckpointCount');
 let previous=null,priorStage=-1,terminal=false,boundRequest=false,used=Object.fromEntries(stages.map(k=>[k,0]));
 for(const [i,row] of input.entries()){
  exact(row,['version','claimRef','scopeHash','catalogHash','requestHash','sequence','stage','used','previousHash','held']);
  need(!terminal&&row.version===1&&row.sequence===i+1&&row.previousHash===previous&&typeof row.held==='boolean','CiRootCostCheckpointOrder');
  need(hash(row.claimRef)===hash(e.claimRef)&&row.scopeHash===e.scopeHash&&row.catalogHash===hash(q),'CiRootCostCheckpointBinding');
  const stage=stages.indexOf(row.stage);need(stage>=priorStage&&stage>=0,'CiRootCostCheckpointStage');
  need(row.requestHash===null?!boundRequest:hex(row.requestHash)&&row.requestHash===e.requestHash,'CiRootCostRequestBinding');
  need(row.held||stage===0||row.requestHash!==null,'CiRootCostRequestBinding');
  boundRequest||=row.requestHash!==null;
  exact(row.used,stages);
  for(const key of stages){need(nat(row.used[key])&&row.used[key]>=used[key]&&row.used[key]<=q.work[key],'CiRootCostConsumption');}
  used=row.used;previous=hash(row);priorStage=stage;terminal=row.held||row.stage==='cleanup';
 }
 need(terminal&&(input.at(-1).held||boundRequest),'CiRootCostTerminal');
 need(used.replay===0,'CiRootCostReplayNotCreation');
 const reservedForReplay=input.at(-1).held?0:q.work.replay;
 return freeze({authority:false,executionReady:false,held:input.at(-1).held,debit:e.debit,used,reservedForReplay,unusedForfeited:q.roundedLocalBytes-sum(Object.values(used))-reservedForReplay,lastHash:previous});
}
