import {canaryEvidenceHash as hash} from './production-canary-verification.mjs';
import {inspectCanaryTransitionCertificate} from './production-canary-transition.mjs';
import {inspectImageTransitionCertificate} from './production-image-transition.mjs';

const fail=()=>{throw Error('CanaryContinuationEvidenceInvalid');};
const integer=(n,min=0)=>Number.isSafeInteger(n)&&n>=min;
const hex=(value,n=64)=>typeof value==='string'&&new RegExp('^[a-f0-9]{'+n+'}$').test(value);
const key=action=>action.namespace+'/'+action.id;
const stable=['generation','validationId','targets','plannerOid','executorOid','protectedBaselineHash','protectedRows'];

export function inspectContinuationReceiptSet(value){
  const proof=value?.verification,actions=value?.replayActions,times=value?.receiptWindow?.committedMs;
  if(!proof||!Array.isArray(actions)||!actions.length||actions.length>10||!Array.isArray(times)||times.length!==actions.length||
    !Array.isArray(proof.targets)||!proof.targets.length||proof.targets.length>32||new Set(proof.targets).size!==proof.targets.length||
    proof.targets.some(v=>typeof v!=='string'||!v)||!hex(proof.generation)||!hex(proof.validationId,32)||
    !/^mem9-[a-f0-9]{7}$/.test(proof.sourceTag??'')||typeof proof.workerImage!=='string'||!/@sha256:[a-f0-9]{64}$/.test(proof.workerImage)||
    !['backendBindingHash','releaseHash','protectedBaselineHash','conservationHash','replayResultHash'].every(k=>hex(proof[k]))||
    !integer(proof.plannerOid,1)||!integer(proof.executorOid,1)||!integer(proof.protectedRows)||
    new Set(actions.map(key)).size!==actions.length)fail();
  let changedRows=0;
  for(const [index,action]of actions.entries()){
    if(!proof.targets.includes(action.namespace)||!hex(action.id)||action.result?.action_id!==action.id||action.result.status!=='applied'||
      !integer(action.result.changed_rows,2)||action.result.changed_rows>20||!integer(times[index],1)||index>0&&times[index]<=times[index-1])fail();
    changedRows+=action.result.changed_rows;
  }
  if(changedRows>20||changedRows!==proof.changedRows||actions.length!==proof.receipts||proof.sourceRows!==changedRows-actions.length||
    value.receiptWindow.firstCommittedMs!==times[0]||value.receiptWindow.lastCommittedMs!==times.at(-1)||
    hash(actions.map(a=>[a.namespace,a.id,a.result]))!==proof.replayResultHash)fail();
  return {proof,actions,times};
}

// This is a content-free lineage check, not an authorization issuer. The
// canonical database begin operation validates the protected witness and full
// material certificate before any new execution is admitted.
export function verifyContinuationReceiptSet(original,current,{attemptId,compatibility,allowNew=true}){
  if(compatibility?.version===4)inspectImageTransitionCertificate(compatibility);
  else if(compatibility?.version===3||compatibility?.transition!==undefined)inspectCanaryTransitionCertificate(compatibility);
  const old=inspectContinuationReceiptSet(original),next=inspectContinuationReceiptSet(current);
  if(!hex(attemptId,32)||next.proof.attemptId!==attemptId||next.proof.parentProofHash!==hash(old.proof)||
    compatibility?.parentProofHash!==hash(old.proof)||compatibility.generation!==old.proof.generation||
    compatibility.targetsHash!==hash([...old.proof.targets].sort())||
    compatibility.previous?.backendBindingHash!==old.proof.backendBindingHash||hash(compatibility.previous?.release)!==old.proof.releaseHash||
    hash(compatibility.current?.release)!==next.proof.releaseHash||hash(compatibility.current?.backendBinding)!==next.proof.backendBindingHash||
    compatibility.current.release.sourceTag!==next.proof.sourceTag||compatibility.current.release.workerImage!==next.proof.workerImage)fail();
  for(const field of stable)if(hash(old.proof[field])!==hash(next.proof[field]))fail();
  const positions=new Map(next.actions.map((a,i)=>[key(a),i]));
  for(const [index,action]of old.actions.entries()){
    const at=positions.get(key(action));
    if(at===undefined||hash(next.actions[at])!==hash(action)||next.times[at]!==old.times[index])fail();
  }
  const oldKeys=new Set(old.actions.map(key)),newActions=[],newTimes=[];
  next.actions.forEach((action,index)=>{if(!oldKeys.has(key(action))){newActions.push(action);newTimes.push(next.times[index]);}});
  if(!allowNew&&newActions.length)fail();
  return {newActions,newTimes,changedRows:next.proof.changedRows,receipts:next.proof.receipts};
}

export function verifyContinuationCommitWindow(original,current,loaded,context){
  const extension=verifyContinuationReceiptSet(original,current,context);
  if(!extension.newTimes.length||!Array.isArray(loaded?.samples))fail();
  for(const kind of ['read','write_ack']){
    const samples=loaded.samples.filter(s=>s.kind===kind),first=samples[0]?.startedMs,last=samples.at(-1)?.finishedMs;
    if(!integer(first,1)||!integer(last,first)||samples.some(s=>!integer(s.startedMs,first)||!integer(s.finishedMs,s.startedMs))||
      extension.newTimes.some(time=>time<first||time>last))fail();
  }
  return extension;
}
