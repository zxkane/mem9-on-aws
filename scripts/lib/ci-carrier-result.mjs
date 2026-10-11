import {inspectCarrierLocalEvidence} from './ci-carrier-local-policy.mjs';
/** Immutable CI build facts. Completion and security are added by the owner
 * after the real job finishes; neither is claimed by this build result. */
import {copyNonrootJson,inspectNonrootRecord,nonrootHash as hash} from './production-nonroot-contracts.mjs';
import {inspectCarrierFundingPlan,carrierCheckpointSelection,carrierRunAnnouncement,carrierBlobDebit,CARRIER_PROFILE_ACTIONS} from './ci-carrier-before-copy.mjs';
import {COUNTERS,counter,zero,addCounters,parseAcquisitionJson} from './ci-smoke-acquisition-format.mjs';
import {createHash} from 'node:crypto';
import {inspectCarrierDerivedMaterial} from './ci-carrier-derived-format.mjs';
const need=(v,c='CarrierBuildResult')=>{if(!v)throw Error(c);};
const exact=(v,keys)=>need(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===keys.slice().sort().join(),'CarrierResultFields');
const sha=v=>createHash('sha256').update(v).digest('hex');
const hex=v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
const digest=v=>typeof v==='string'&&/^sha256:[a-f0-9]{64}$/.test(v);
const same=(a,b)=>need(hash(a)===hash(b),'CarrierResultBinding');

// This checks the original consumer's prefix; it cannot admit/resume a process,
// reimburse a slot, or reconstruct a mutable budget. The result's own PUT and
// subsequent cleanup are outside this prefix and remain prepaid in full.
function consumerPrefix(value,{plan,binding,claim,buildEvidence,sqlAcceptance}){
 const t=plan.template,v=value;exact(v,['events','lastHash','local','wire','used','blobUsage',...(t.ciLocalPolicy?['ciLocal']:[])]);
 if(t.ciLocalPolicy){const local=inspectCarrierLocalEvidence(v.ciLocal,{plan,binding});same(local.spent,v.local);}
 counter(v.local);counter(v.wire);
 for(const k of COUNTERS)need(v.local[k]<=t.fundedLocal.ci[k],'CarrierResultLocalBudget');
 need(v.local.ecrRequests===0&&v.local.httpBodyBytes===0,'CarrierResultLocalBudget');
 const purposes=Object.keys(CARRIER_PROFILE_ACTIONS).filter(k=>CARRIER_PROFILE_ACTIONS[k][0]==='ci'&&k!=='resultPut');
 const maximum=purposes.reduce((n,k)=>n+(t.profiles[k].count??t.profiles[k].maxRequests),0);
 need(Array.isArray(v.events)&&v.events.length>=11&&v.events.length<=maximum*2+(sqlAcceptance?4:3),'CarrierResultJournalBound');
 const used={},wire=zero();let previous=null,active,granted=false,built=false,sqlAccepted=false,lastMs=plan.issuedMs,journalBytes=0,blobUsage={requests:0,responseBytes:0,digests:[]};
 const time=at=>{need(Number.isSafeInteger(at)&&at>=lastMs&&at<plan.deadlineMs,'CarrierResultJournalTime');lastMs=at;};
 for(const [index,e]of v.events.entries()){
  exact(e,['version','sequence','planHash','previousHash','type','data']);need(e.version===1&&e.sequence===index+1&&e.planHash===hash(plan)&&e.previousHash===previous,'CarrierResultJournalChain');
  previous=hash(e);journalBytes+=Buffer.byteLength(JSON.stringify(e)+'\n');const d=e.data;
  if(index===0){
   need(e.type==='start','CarrierResultJournalStart');exact(d,['grantHash','ledgerStartHash','binding','startup','allocation']);
   need(d.grantHash===binding.grantHash&&d.ledgerStartHash===plan.ledgerStartHash,'CarrierResultJournalStart');same(d.binding,binding);same(d.allocation,plan.budget.ci);
   same(d.startup,{nonce:claim.nonce,scopeHash:claim.scopeHash,artifactId:claim.artifactId,artifactDigest:claim.artifactDigest,claimHash:hash(claim),notAfter:plan.deadlineMs});continue;
  }
  if(e.type==='request'){
   need(!active&&purposes.includes(d.purpose),'CarrierResultJournalRequest');const p=t.profiles[d.purpose],blob=d.purpose==='baseBlob';
   exact(d,['purpose','action','requestHash','caps','attempt',...(blob?['blobDebit']:[]),'atMs']);time(d.atMs);
   need(d.action===CARRIER_PROFILE_ACTIONS[d.purpose][1]&&hex(d.requestHash)&&d.attempt===(used[d.purpose]??0)+1&&d.attempt<=(p.count??p.maxRequests),'CarrierResultJournalProfile');
   if(!granted){const expected=!used.assume?'assume':!used.ciIdentity?'ciIdentity':!used.grantGet?'grantGet':null;need(d.purpose===expected,'CarrierResultJournalOrder');}
   else if(!used.contextGet)need(d.purpose==='contextGet','CarrierResultJournalOrder');
   else need(built?['availability','initiate','part','complete','manifestPut'].includes(d.purpose):['baseManifest','baseUrl','baseBlob','fixtureGet'].includes(d.purpose),'CarrierResultJournalOrder');
   if(blob){
    exact(d.blobDebit,['descriptorSource','descriptor','requests','responseBytes']);const debit=carrierBlobDebit(plan,'ci',blobUsage,d.blobDebit.descriptor);
    same(d.blobDebit,{descriptorSource:debit.descriptorSource,descriptor:debit.descriptor,requests:debit.usage.requests,responseBytes:debit.usage.responseBytes});same(d.caps,debit.caps);blobUsage=debit.usage;
   }else same(d.caps,{requestBytes:p.requestBytes,responseBytes:p.responseBytes,overshootBytes:8388608});
   used[d.purpose]=d.attempt;active=e;continue;
  }
  if(e.type==='complete'){
   exact(d,['request','responseHash','chargedBytes','atMs']);time(d.atMs);
   need(active&&d.request===active.sequence&&hex(d.responseHash)&&Number.isSafeInteger(d.chargedBytes)&&d.chargedBytes>=0&&d.chargedBytes<=active.data.caps.requestBytes+active.data.caps.responseBytes,'CarrierResultJournalComplete');
   if(active.data.purpose==='baseBlob')need(d.chargedBytes===active.data.blobDebit.descriptor.size&&d.responseHash===active.data.blobDebit.descriptor.digest.slice(7),'CarrierResultJournalBlob');
   if(active.data.purpose==='fixtureGet')need(d.chargedBytes===t.sqlFixture.archive.bytesLength&&d.responseHash===t.sqlFixture.archive.sha256,'CarrierResultJournalFixture');
   const ecr=!['S3BlobGet','AssumeRoleWithWebIdentity','GetCallerIdentity','GetObject','PutObject'].includes(active.data.action);
   Object.assign(wire,addCounters(wire,{...zero(),ecrRequests:ecr?1:0,httpBodyBytes:d.chargedBytes,logicalBytes:d.chargedBytes}));active=undefined;continue;
  }
  if(e.type==='grant-verified'){exact(d,['grantHash']);need(!active&&!granted&&used.grantGet===1&&d.grantHash===binding.grantHash,'CarrierResultJournalGrant');granted=true;continue;}
  if(e.type==='sql-accepted'){exact(d,['acceptanceHash','atMs']);time(d.atMs);need(sqlAcceptance&&granted&&!active&&!built&&!sqlAccepted&&used.contextGet===1&&used.fixtureGet===1&&d.acceptanceHash===hash(sqlAcceptance)&&sqlAcceptance.record.completedMs<=d.atMs,'CarrierResultJournalSql');sqlAccepted=true;continue;}
  if(e.type==='built'){exact(d,['record']);need(granted&&!active&&!built&&used.contextGet===1&&used.baseManifest>=2&&used.baseBlob>=1&&used.baseUrl===used.baseBlob,'CarrierResultJournalBuilt');same(d.record,buildEvidence);built=true;continue;}
  need(false,'CarrierResultJournalTerminal');
 }
 need(!active&&granted&&built&&used.availability>=1&&used.manifestPut>=2&&v.lastHash===previous&&journalBytes<=v.local.logicalBytes,'CarrierResultJournalIncomplete');
 need(sqlAccepted===Boolean(sqlAcceptance),'CarrierResultJournalSql');
 same(v.used,used);same(v.wire,wire);same(v.blobUsage,blobUsage);
 for(const k of COUNTERS)need(wire[k]+v.local[k]<=plan.budget.ci[k],'CarrierResultConsumerBudget');
 return v;
}

export function inspectCarrierBuildResult(value,{plan:input,binding,claim}){
 const plan=inspectCarrierFundingPlan(input),t=plan.template,r=copyNonrootJson(value);
 carrierRunAnnouncement(plan,binding);
 same(carrierCheckpointSelection(plan,binding,{nonce:claim.nonce,scopeHash:claim.scopeHash,artifactId:claim.artifactId,artifactDigest:claim.artifactDigest}).claim,claim);
 exact(r,['version','kind','templateHash','grantHash','contextHash','bindingHash','claimHash','image','metadata','buildEvidence','derivedMaterial','consumerPrefix','logBase64',...(r.version===3?['sqlAcceptance']:[])]);
 need([2,3].includes(r.version)&&r.kind==='carrier-ci-build-result'&&r.templateHash===plan.templateHash&&r.grantHash===binding.grantHash&&r.contextHash===plan.context.sha256&&r.bindingHash===hash(binding)&&r.claimHash===hash(claim),'CarrierResultBinding');
 const image=inspectNonrootRecord('ControlImageBindingV1',r.image);
 need(['account','region','repositoryName'].every(k=>image[k]===t.scope[k]),'CarrierResultImage');
 const b=r.buildEvidence;
 exact(b,['version','kind','authority','templateHash','contextHash','derivedRecordHash','rootDigest','arm64Digest','configDigest','graphHash','filesystemHash','sourcePolicyHash','metadataHash','logHash','logBytes','archiveHash','archiveBytes','nativeBuildLogicalReservation','processStopped','termination']);
 need(b.version===2&&b.kind==='carrier-offline-build-evidence'&&b.authority===false&&b.processStopped===true&&b.templateHash===plan.templateHash&&b.contextHash===plan.context.sha256&&b.derivedRecordHash===hash(r.derivedMaterial),'CarrierResultBuild');
 for(const k of ['rootDigest','arm64Digest','configDigest'])need(digest(b[k])&&b[k]===image[k],'CarrierResultImage');
 for(const k of ['graphHash','filesystemHash','sourcePolicyHash','metadataHash','logHash','archiveHash'])need(hex(b[k]),'CarrierResultBuild');
 for(const k of ['logBytes','archiveBytes','nativeBuildLogicalReservation'])need(Number.isSafeInteger(b[k])&&b[k]>=0,'CarrierResultBuild');
 const end=b.termination;
 exact(end,['version','kind','cleanupComplete','supervisorPid','leaderPid','leaderEnded','reaped','killedDescendants','reason','status','signal']);
 need(end.version===1&&end.kind==='carrier-offline-build-subreaper-echild'&&end.cleanupComplete===true&&end.leaderEnded===true&&end.reason===null&&end.status===0&&end.signal===null&&Number.isSafeInteger(end.supervisorPid)&&end.supervisorPid>1&&Number.isSafeInteger(end.leaderPid)&&end.leaderPid>1&&Number.isSafeInteger(end.reaped)&&end.reaped>=1&&Number.isSafeInteger(end.killedDescendants)&&end.killedDescendants>=0&&end.killedDescendants<end.reaped,'CarrierResultTermination');
 need(typeof r.metadata==='string'&&Buffer.byteLength(r.metadata)<=1048576&&sha(r.metadata)===b.metadataHash,'CarrierResultMetadata');
 // BuildKit includes fractional resource observations. Keep the original raw
 // metadata and its byte hash; only the selected digest fields are authority.
 const m=parseAcquisitionJson(Buffer.from(r.metadata),1048576);
 need(m['containerimage.digest']===image.rootDigest&&(m['containerimage.config.digest']===undefined||m['containerimage.config.digest']===image.configDigest)&&m['containerimage.descriptor']?.digest===image.rootDigest,'CarrierResultMetadata');
 inspectCarrierDerivedMaterial(r.derivedMaterial,{plan,grantHash:binding.grantHash});
 need(typeof r.logBase64==='string'&&r.logBase64.length<=1398104,'CarrierResultLog');const log=Buffer.from(r.logBase64,'base64');
 need(log.toString('base64')===r.logBase64&&log.length<=1048576&&log.length===b.logBytes&&sha(log)===b.logHash,'CarrierResultLog');
 if(r.version===3){
  exact(r.sqlAcceptance,['record','objects']);const q=r.sqlAcceptance.record;
  need(q.version===2&&q.kind==='carrier-original-closure-tests'&&q.templateHash===r.templateHash&&q.grantHash===r.grantHash&&q.contextHash===r.contextHash&&q.bindingHash===r.bindingHash&&q.claimHash===r.claimHash,'CarrierResultSqlBinding');same(q.image,r.image);
  need(q.fixture?.package&&hash(q.fixture.package.archive)===hash(t.sqlFixture.archive),'CarrierResultSqlPackage');
  // Full overlay/case verification requires independently read original image
  // bytes and old-source provenance and is performed by the owner inspector.
 }
 consumerPrefix(r.consumerPrefix,{plan,binding,claim,buildEvidence:b,sqlAcceptance:r.sqlAcceptance});
 need(Buffer.byteLength(JSON.stringify(r))<=t.bounds.resultBytes,'CarrierResultSize');return r;
}
export function makeCarrierBuildResult(plan,binding,claim,{metadata,buildEvidence,derivedMaterial,consumerPrefix,logBase64,sqlAcceptance}){
 return inspectCarrierBuildResult({version:sqlAcceptance?3:2,kind:'carrier-ci-build-result',templateHash:plan.templateHash,grantHash:binding.grantHash,contextHash:plan.context.sha256,bindingHash:hash(binding),claimHash:hash(claim),
  image:{account:plan.template.scope.account,region:plan.template.scope.region,repositoryName:plan.template.scope.repositoryName,rootDigest:buildEvidence.rootDigest,arm64Digest:buildEvidence.arm64Digest,configDigest:buildEvidence.configDigest},metadata,buildEvidence,derivedMaterial,consumerPrefix,logBase64,...(sqlAcceptance?{sqlAcceptance}:{})},{plan,binding,claim});
}
