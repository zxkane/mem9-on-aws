/** Closed accounting for an original validation prefix. The caller supplies
 * authenticated checkpoint/receipt and the already-owned original records.
 * This codec performs no I/O and creates no spending or execution authority. */
import {createHash} from 'node:crypto';
import {posix} from 'node:path';
import {copyNonrootJson,nonrootHash as hash} from './production-nonroot-contracts.mjs';
import {inspectCommittedNonrootBudgetEnvelope,nonrootAccountingPolicy,NONROOT_REMAINING_WORK_CAPS_V2} from './production-nonroot-budget-revision.mjs';

const fields=['ecrRequests','logicalBytes','httpBodyBytes','uncompressedBytes','processedEntries'];
const B=65536,W=8*B+4096,D=4*B+4096;
const need=(v,c)=>{if(!v)throw Error('NonrootCopyReplay'+c);};
const exact=(v,keys)=>need(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===keys.toSorted().join(),'Fields');
const same=(a,b,c)=>need(hash(a)===hash(b),c);
const hex=(v,n=64)=>typeof v==='string'&&new RegExp('^[a-f0-9]{'+n+'}$').test(v);
const nat=n=>Number.isSafeInteger(n)&&n>=0;
const sha=v=>createHash('sha256').update(v).digest('hex');
const zero=()=>Object.fromEntries(fields.map(k=>[k,0]));
const local=n=>({...zero(),logicalBytes:n});
const add=(...rows)=>Object.fromEntries(fields.map(k=>{const n=rows.reduce((s,r)=>s+r[k],0);need(nat(n),'Counter');return [k,n];}));
function ref(r){exact(r,['path','sha256']);need(typeof r.path==='string'&&r.path.length<=4096&&r.path.startsWith('/')&&posix.normalize(r.path)===r.path&&!/[\\\x00-\x1f]/.test(r.path)&&hex(r.sha256),'Reference');}
function original(value,r){
 ref(r);const text=JSON.stringify(value)+'\n';need(Buffer.byteLength(text)<=B,'RecordBound');need(sha(text)===r.sha256,'OriginalBytes');return text;
}
function replayBudget(q,b,counter){
 exact(q,['version','kind','invocations','catalogHash','readBytes','reads','perInvocation','charge','pricing']);
 need(q.version===2&&q.kind==='control-capture-replay-budget'&&q.invocations===13&&hex(q.catalogHash)&&nat(q.readBytes)&&nat(q.reads),'ReplayBudget');
 same(q.pricing,b.replayPricing,'ReplayPrice');counter(q.perInvocation);counter(q.charge);
 const p=q.pricing;exact(p,['bounds','decoderBytes','uncompressedBytes','processedEntries','planningInputLocalBytes']);
 need(p.bounds&&typeof p.bounds==='object'&&!Array.isArray(p.bounds)&&Object.keys(p.bounds).length>0&&Object.keys(p.bounds).length<=256&&Object.entries(p.bounds).every(([k,v])=>/^[A-Za-z][A-Za-z0-9:-]{0,127}$/.test(k)&&nat(v)&&v<=33554432),'ReplayPrice');
 for(const key of ['decoderBytes','uncompressedBytes','processedEntries','planningInputLocalBytes'])need(nat(p[key]),'ReplayPrice');need(p.planningInputLocalBytes>0,'ReplayPrice');
 need(q.perInvocation.ecrRequests===0&&q.perInvocation.httpBodyBytes===0,'ReplayLocalOnly');
 same(q.perInvocation,{...zero(),logicalBytes:4*q.readBytes+4096*q.reads+p.decoderBytes+p.planningInputLocalBytes+10*D+4096,uncompressedBytes:p.uncompressedBytes,processedEntries:p.processedEntries},'ReplayCharge');
 same(q.charge,Object.fromEntries(fields.map(k=>[k,13*q.perInvocation[k]])),'ReplayCharge');
}
function budget(value,counter){
 const b=value;
 exact(b,['version','kind','policyHash','sourceManifestHash','replayPricing','nonC','family','preclaimReplay','completionReplay','preclaimNormal','cleanup','P','completion','T','budgetHash']);
 need(b.version===1&&b.kind==='copy-replay-budget'&&[b.policyHash,b.sourceManifestHash,b.budgetHash].every(v=>hex(v)),'Budget');
 const {budgetHash,...body}=b;same(hash(body),budgetHash,'BudgetHash');
 exact(b.nonC,['preclaim','completion']);for(const r of Object.values(b.nonC)){counter(r);need(r.ecrRequests===0&&r.httpBodyBytes===0,'LocalOnly');}
 replayBudget(b.preclaimReplay,b,counter);replayBudget(b.completionReplay,b,counter);same(b.preclaimReplay,b.completionReplay,'ReplayPrice');
 same(b.family,{preclaim:local(4*W+3*D+36*D),completion:local(4*W+12*D+54*D),cleanup:local(W)},'FamilyPrice');
 for(const k of ['preclaimNormal','cleanup','P','completion','T'])counter(b[k]);
 same(b.preclaimNormal,add(b.preclaimReplay.charge,b.nonC.preclaim,b.family.preclaim),'PrefixPrice');
 same(b.cleanup,b.family.cleanup,'CleanupPrice');same(b.P,add(b.preclaimNormal,b.cleanup),'PrefixPrice');
 same(b.completion,add(b.completionReplay.charge,b.nonC.completion,b.family.completion),'CompletionPrice');
 for(const k of fields)need(b.T[k]>=b.P[k]+b.completion[k],'Partition');return b;
}

/** Absence preserves the original formats. Presence requires the complete
 * original join, not a Boolean or a projected ledger-start object. `config`
 * is the original already-read config, bound by receipt.planHash; its start
 * counters prevent a self-consistent redistribution of P and the baseline. */
export function verifyNonrootCopyReplayStart(start,{startRaw,copyCheckpoint,copyReceipt,policy,expectedCopyReplay,requireSettled=false}={}){
 const present=Object.hasOwn(start,'copyReplay');
 need(present===(expectedCopyReplay!==undefined),'ExpectedJoin');if(!present)return undefined;
 exact(start,['version','kind','budgetRevision','binding','startingCounters','reserve','deadlineMs','mode','copyReplay']);
 need(start.version===2&&start.mode==='copy'&&policy?.version===2,'Version');
 need(start.kind==='custody-ledger-start','Kind');policy=nonrootAccountingPolicy(start.budgetRevision,policy.budgetRevision,policy.caps);
 const x=copyNonrootJson(expectedCopyReplay);exact(x,['refs','values','budget','inputHash','group','config','envelope']);
 need(['finishCopyRecords','verifyCompletedCopyV2'].includes(x.group)&&hex(x.inputHash),'Context');
 const settled=Object.hasOwn(x.refs,'S'),members=['Cp','K1','K2','J','N','L',...(settled?['S']:[])];exact(x.refs,members);exact(x.values,members);
 need(!requireSettled||settled,'SettlementRequired');
 const raw={};for(const k of members)raw[k]=original(x.values[k],x.refs[k]);
 need(typeof startRaw==='string'&&startRaw.length<=32768,'StartBound');
 need(Buffer.from(startRaw,'base64').toString('base64')===startRaw&&Buffer.from(startRaw,'base64').equals(Buffer.from(raw.L)),'StartBytes');
 same(start,x.values.L,'StartBytes');need(sha(raw.L)===copyReceipt.combinedPass.ledgerStartHash,'StartHash');
 const {Cp:cp,K1:k1,K2:k2,J:j,N:n}=x.values,r=start.copyReplay,c=x.config,b=budget(x.budget,policy.counter);
 exact(r,['version','claimRef','budgetHash','policyHash','sourceManifestHash','nodeRef','baselineCounters','P','completion','T']);
 need(r.version===1,'Version');ref(r.claimRef);ref(r.nodeRef);for(const k of ['budgetHash','policyHash','sourceManifestHash'])need(hex(r[k]),'Hash');
 for(const k of ['baselineCounters','P','completion','T'])policy.counter(r[k]);
 same(hash(c),copyReceipt.planHash,'Config');need(c.version===9&&c.kind==='image-cache-custody-successor'&&c.owner===copyReceipt.owner&&c.executionId===copyCheckpoint.binding.executionId&&[c.owner,c.executionId,c.predecessorExecutionId].every(v=>hex(v,32)),'Config');
 need(typeof c.directory==='string'&&c.directory.endsWith('/'+c.owner+'/'+c.predecessorExecutionId+'/'+c.executionId),'Config');
 same(c.scope,{account:copyReceipt.summary.account,region:copyReceipt.summary.region},'Scope');same(c.inventory,copyReceipt.inventory,'Inventory');
 same(c.budgetRevision,policy.budgetRevision,'Revision');same(c.startingCounters,r.baselineCounters,'Baseline');
 const committed=inspectCommittedNonrootBudgetEnvelope(x.envelope,{budgetRevision:policy.budgetRevision,owner:c.owner});same(committed.compiledCeiling,policy.caps,'EnvelopeCeiling');
 same(start.binding,copyCheckpoint.binding,'Binding');same(start.binding,{owner:c.owner,executionId:c.executionId,planHash:hash(c),publicationHash:hash(c.publication)},'Binding');
 same(start.startingCounters,copyCheckpoint.startingCounters,'CheckpointStart');
 same(start.startingCounters,add(r.baselineCounters,r.P,r.completion),'StartingCounters');
 policy.counter(start.reserve);for(const k of fields)need(r.T[k]>=r.P[k]+r.completion[k]&&start.reserve[k]===r.T[k]-r.P[k]-r.completion[k],'Reserve');
 same(add(start.startingCounters,start.reserve),policy.caps,'Ceiling');same(add(r.baselineCounters,r.T),policy.caps,'Ceiling');
 for(const k of ['P','completion','T','budgetHash','policyHash','sourceManifestHash'])same(r[k],b[k],'BudgetBinding');
 same(r.claimRef,x.refs.Cp,'ClaimRef');same(r.nodeRef,x.refs.N,'NodeRef');
 need(x.refs.L.path===c.directory+'/records/ledger-start.json'&&x.refs.Cp.path===posix.dirname(c.directory)+'/claim.json'&&x.refs.N.path.endsWith('/'+c.owner+'/admission-0009.json'),'Paths');
 for(const [key,name]of [['K1','copy-validation-1.json'],['K2','copy-validation-2.json'],['J','copy-upgrade.json'],...(settled?[['S','copy-validation-settlement.json']]:[])])need(x.refs[key].path===posix.dirname(x.refs.Cp.path)+'/'+name,'Paths');
 exact(cp,['version','kind','owner','executionId','predecessorExecutionId','input','configHash','policyHash','sourceManifestHash','budgetHash','witnessHash','historyHeadHash','counters','protectedReservation','P','T','completion','startedMs','deadlineMs']);
 need(cp.version===2&&cp.kind==='copy-validation-claim'&&cp.owner===c.owner&&cp.executionId===c.executionId&&cp.predecessorExecutionId===c.predecessorExecutionId&&cp.configHash===hash(c)&&hex(cp.witnessHash),'Claim');
 exact(cp.input,['configRef','ownerAuthorizationRef']);ref(cp.input.configRef);ref(cp.input.ownerAuthorizationRef);same(hash(cp.input),x.inputHash,'Input');
 same(cp.counters,r.baselineCounters,'Baseline');exact(cp.protectedReservation,fields);
 const prefixTotal=add(cp.counters,cp.P,cp.protectedReservation);
 for(const key of fields)need(nat(cp.protectedReservation[key])&&prefixTotal[key]<=NONROOT_REMAINING_WORK_CAPS_V2[key],'ProtectedReservation');
 for(const k of ['P','T','completion','budgetHash','policyHash','sourceManifestHash'])same(cp[k],r[k],'ClaimPrice');
 need(nat(cp.startedMs)&&cp.startedMs>0&&cp.startedMs===copyReceipt.summary.startedMs&&cp.deadlineMs===cp.startedMs+2700000&&start.deadlineMs===cp.deadlineMs,'Clock');
 for(const [k,ordinal]of [[k1,1],[k2,2]]){
  exact(k,['version','kind','ordinal','claimRef',...(ordinal===2?['previousRef']:[]),'inputHash','budgetHash','configHash','historyHeadHash','envelopeHash',...(ordinal===2?['nodeHash']:[])]);
  need(k.version===1&&k.kind==='copy-validation-checkpoint'&&k.ordinal===ordinal&&k.inputHash===x.inputHash&&k.budgetHash===r.budgetHash&&k.configHash===hash(c)&&k.historyHeadHash===cp.historyHeadHash&&k.envelopeHash===policy.budgetRevision.envelopeHash,'Checkpoint');same(k.claimRef,x.refs.Cp,'CheckpointClaim');
 }
 same(k2.previousRef,x.refs.K1,'CheckpointOrder');
 exact(n,['version','kind','sequence','previousHash','baseHistoryHash','owner','predecessorExecutionId','purpose','operationId','event','data']);
 need(n.version===3&&n.kind==='remaining-work-copy-admission'&&n.sequence===9&&n.owner===c.owner&&n.predecessorExecutionId===c.predecessorExecutionId&&n.event==='admit'&&n.purpose==='production-copy'&&n.operationId===hash({version:1,owner:c.owner,purpose:'production-copy'})&&hex(n.baseHistoryHash),'Node');
 need(n.previousHash===cp.historyHeadHash&&n.previousHash===policy.budgetRevision.historyHeadHash&&k2.nodeHash===hash(n),'NodeHash');
 const a=n.data;exact(a,['inputRef','configHash','executionId','budgetRevision','preclaimHeadHash','envelopeRef','envelopeInputRef','charge','projected','startedMs','deadlineMs','copyReplay']);
 same(a.inputRef,cp.input.configRef,'NodeInput');ref(a.envelopeRef);ref(a.envelopeInputRef);same(a.budgetRevision,policy.budgetRevision,'NodeRevision');
 need(a.configHash===hash(c)&&a.executionId===c.executionId&&a.preclaimHeadHash===cp.historyHeadHash&&a.startedMs===null&&a.deadlineMs===null,'NodeInput');
 policy.counter(a.charge);same(a.projected,policy.caps,'NodeCeiling');same(a.charge,x.envelope.knownRemaining,'NodeOccupancy');same(add(x.envelope.history.counters,a.charge),a.projected,'NodeOccupancy');
 for(const k of fields)need(a.charge[k]>=r.T[k]&&x.envelope.history.counters[k]<=r.baselineCounters[k],'NodeOccupancy');
 same(a.copyReplay,{claimRef:x.refs.Cp,budgetHash:r.budgetHash,policyHash:r.policyHash,sourceManifestHash:r.sourceManifestHash,P:r.P,T:r.T,completion:r.completion,counters:r.baselineCounters,prefixCounters:add(r.baselineCounters,r.P),historyHeadHash:cp.historyHeadHash,startedMs:cp.startedMs,deadlineMs:cp.deadlineMs},'NodePrefix');
 exact(j,['version','kind','claimRef','checks','inputHash','budgetHash','policyHash','P','delta','T','completion','startedMs','deadlineMs','N','L']);
 need(j.version===1&&j.kind==='copy-validation-upgrade'&&j.inputHash===x.inputHash&&j.startedMs===cp.startedMs&&j.deadlineMs===cp.deadlineMs,'Upgrade');
 same(j.claimRef,x.refs.Cp,'UpgradeClaim');same(j.checks,[x.refs.K1,x.refs.K2],'UpgradeChecks');
 for(const k of ['P','T','completion','budgetHash','policyHash'])same(j[k],r[k],'UpgradePrice');policy.counter(j.delta);same(add(j.P,j.delta),j.T,'UpgradeDelta');
 for(const key of ['N','L']){exact(j[key],['ref','bytesLength']);same(j[key].ref,x.refs[key],'UpgradeRef');need(j[key].bytesLength===Buffer.byteLength(raw[key]),'UpgradeLength');}
 if(settled){
  const s=x.values.S;exact(s,['version','kind','claimRef','refs','status','liability','budgetHash','startedMs','deadlineMs','used','replayReceipts','refund']);
  need(s.version===1&&s.kind==='copy-validation-settlement'&&s.status==='COMPLETE'&&s.budgetHash===r.budgetHash&&s.startedMs===cp.startedMs&&s.deadlineMs===cp.deadlineMs,'Settlement');
  same(s.claimRef,x.refs.Cp,'SettlementClaim');same(s.refs,Object.fromEntries(['Cp','K1','K2','J'].map(k=>[k,x.refs[k]])),'SettlementRefs');same(s.liability,r.T,'SettlementLiability');same(s.refund,zero(),'Refund');
  exact(s.used,['normal','completion','cleanup']);need(nat(s.used.normal)&&s.used.normal<=b.preclaimNormal.logicalBytes&&nat(s.used.completion)&&s.used.completion<=b.completion.logicalBytes&&s.used.cleanup===W,'SettlementUsage');
  exact(s.replayReceipts,['preclaim','completion']);for(const phase of ['preclaim','completion']){
   const q=s.replayReceipts[phase];exact(q,['authority','funding','budget','prepaid','used','replays','closed','held','refund']);
   need(q.authority===false&&q.funding==='caller-counter'&&q.replays===13&&q.closed===true&&q.held===false,'SettlementReplay');same(q.budget,b[phase+'Replay'],'SettlementReplay');same(q.prepaid,q.budget.charge,'SettlementReplay');same(q.refund,zero(),'Refund');policy.counter(q.used);for(const k of fields)need(q.used[k]<=q.prepaid[k],'SettlementReplay');
  }
 }
 return Object.freeze({authority:false,claimHash:x.refs.Cp.sha256,nodeHash:x.refs.N.sha256,ledgerStartHash:x.refs.L.sha256,budgetHash:b.budgetHash,settled});
}
