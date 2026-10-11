/** Prospective aggregate accounting only. A policy is not a payment or authority. */
import {nonrootHash as hash,copyNonrootJson} from './production-nonroot-contracts.mjs';
import {COUNTERS,zero} from './ci-smoke-acquisition-format.mjs';
const need=(v,c='CarrierLocalPolicy')=>{if(!v)throw Error(c);};
const POLICY=Object.freeze({version:1,kind:'carrier-aggregate-local-policy',logicalBytes:12884901888,cleanupMs:30000,recordBytes:4096,recordChargeBytes:16384,maxRecords:4096,captureBytes:16777216,commandArgumentBytes:16384});
export function describeCarrierLocalPolicy(){return {...POLICY};}
export function inspectCarrierLocalPolicy(value){need(hash(value)===hash(POLICY));return describeCarrierLocalPolicy();}
export function carrierCleanupReservation(template){
 // Final full context/derived verification and terminal accounting records.
 // SQL/probe/build cleanup already has its own pre-dispatch payment and fixed
 // cleanup-only command credits. Do not reserve or charge those fees twice.
 // This capacity stays inside the original quota, not another ledger debit.
 return template.bounds.contextBytes+2*1048576+4*POLICY.recordChargeBytes;
}
export function inspectCarrierLocalEvidence(value,{plan,binding}){
 const policy=inspectCarrierLocalPolicy(plan.template.ciLocalPolicy),v=copyNonrootJson(value);
 need(v.version===1&&v.kind==='carrier-local-evidence'&&v.planHash===hash(plan)&&v.grantHash===binding.grantHash&&v.policyHash===hash(policy),'CarrierLocalEvidenceBinding');
 need(v.cleanupReserved===carrierCleanupReservation(plan.template)&&Number.isSafeInteger(v.cleanupUsed)&&v.cleanupUsed>=0&&v.cleanupUsed<=v.cleanupReserved,'CarrierLocalCleanup');
 need(Array.isArray(v.records)&&v.records.length>=3&&v.records.length<=policy.maxRecords,'CarrierLocalRecords');
 let previous=null,transferred=false,started=false,last=zero();
 for(const [i,r]of v.records.entries()){
  need(r.sequence===i+1&&r.previousHash===previous&&r.planHash===v.planHash&&['claim','capture','captured','capture-failed','startup','transfer','build','sql','checkpoint','cleanup','closed'].includes(r.type),'CarrierLocalRecord');
  need(Buffer.byteLength(JSON.stringify(r)+'\n')<=policy.recordBytes,'CarrierLocalRecordSize');
  for(const k of COUNTERS)need(Number.isSafeInteger(r.spent[k])&&r.spent[k]>=last[k]&&r.spent[k]<=plan.template.fundedLocal.ci[k],'CarrierLocalRecordCounter');
  need(r.spent.ecrRequests===0&&r.spent.httpBodyBytes===0,'CarrierLocalRecordCounter');
  if(i===0)need(r.type==='claim'&&r.data.grantHash===binding.grantHash&&r.data.runId===binding.runId&&r.data.runAttempt===binding.runAttempt,'CarrierLocalClaim');
  if(r.type==='startup'){need(!started&&hash(r.data)===hash(binding),'CarrierLocalBinding');started=true;}
  if(r.type==='transfer'){need(started&&!transferred&&hash(r.data)===hash(binding),'CarrierLocalBinding');transferred=true;}
  previous=hash(r);last=r.spent;
 }
 need(started&&transferred&&previous===v.lastHash&&hash(last)===hash(v.spent),'CarrierLocalEvidenceTotals');
 need(v.spent.logicalBytes>=v.records.length*policy.recordChargeBytes,'CarrierLocalRecordCoverage');return v;
}
