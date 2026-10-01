import {createHash} from 'node:crypto';

const fail=()=>{throw Error('InvalidCancellationEvidence');};
const object=value=>value&&typeof value==='object'&&!Array.isArray(value);
const exact=(value,keys)=>object(value)&&Object.keys(value).sort().join()===keys.slice().sort().join();
const integer=value=>Number.isSafeInteger(value)&&value>0;
const hex=(value,length)=>typeof value==='string'&&new RegExp(`^[a-f0-9]{${length}}$`).test(value);
const canonical=value=>Array.isArray(value)?value.map(canonical):object(value)?Object.fromEntries(Object.keys(value).sort().map(key=>[key,canonical(value[key])])):value;
export const cancellationHash=value=>createHash('sha256').update(JSON.stringify(canonical(value))).digest('hex');

export function validateCancellationIntent(intent,state,{now=Date.now()}={}){
  const keys=['version','stage','nonce','sourceRunId','sourceAttempt','sourceSha','sourceTree','operatorDigest','schemaDigest','coordinatorDigest','identityHash','preservationHash','createdAt'];
  if(!exact(intent,keys)||intent.version!==1||!/^pr-[1-9][0-9]*$/.test(intent.stage??'')||
    !hex(intent.nonce,32)||typeof intent.sourceRunId!=='string'||!/^[1-9][0-9]*$/.test(intent.sourceRunId)||!integer(intent.sourceAttempt)||
    !['sourceSha','sourceTree'].every(key=>hex(intent[key],40))||
    !['operatorDigest','schemaDigest','coordinatorDigest','identityHash','preservationHash'].every(key=>hex(intent[key],64))||
    !integer(intent.createdAt)||intent.createdAt>now+30000||now-intent.createdAt>24*3600000||
    state?.identity?.stage!==intent.stage||state.operation_nonce!==intent.nonce||cancellationHash(state.identity)!==intent.identityHash)fail();
  return intent;
}

export function cancellationCheckpoint(intent,state,now=Date.now()){
  validateCancellationIntent(intent,state,{now});
  if(state.phase!=='password_fenced'||state.status!=='running'||!integer(state.epoch)||!integer(state.sequence)||!hex(state.last_hash,64)||
    !integer(state.started_ms)||state.deadline_ms!==state.started_ms+7200000||now<state.started_ms||
    now+70*60000>=state.deadline_ms||now+10*60000>=state.started_ms+45*60000)fail();
  return {version:1,status:'awaiting_cancellation',intentHash:cancellationHash(intent),nonce:state.operation_nonce,
    epoch:state.epoch,sequence:state.sequence,eventHash:state.last_hash,phase:state.phase,startedMs:state.started_ms,deadlineMs:state.deadline_ms,atMs:now};
}

export function validateCancellationCheckpoint(checkpoint,intent){
  if(!exact(checkpoint,['version','status','intentHash','nonce','epoch','sequence','eventHash','phase','startedMs','deadlineMs','atMs'])||
    checkpoint.version!==1||checkpoint.status!=='awaiting_cancellation'||checkpoint.intentHash!==cancellationHash(intent)||
    checkpoint.nonce!==intent.nonce||checkpoint.phase!=='password_fenced'||!integer(checkpoint.epoch)||!integer(checkpoint.sequence)||
    !hex(checkpoint.eventHash,64)||!integer(checkpoint.startedMs)||checkpoint.deadlineMs!==checkpoint.startedMs+7200000||
    !integer(checkpoint.atMs)||checkpoint.atMs<checkpoint.startedMs||checkpoint.atMs>=checkpoint.deadlineMs)fail();
  return checkpoint;
}

export function validateRecoveryEvent(event,intent,repository){
  const source=event?.workflow_run;
  // The public webhook may add unrelated fields. Only this typed projection is
  // consumed; none of its values is executable text or an unchecked API path.
  if(typeof repository!=='string'||!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository)||
    event?.repository?.full_name!==repository||source?.head_repository?.full_name!==repository||
    !integer(source?.id)||String(source.id)!==intent.sourceRunId||!integer(source.run_attempt)||source.run_attempt!==intent.sourceAttempt||
    !hex(source.head_sha,40)||source.head_sha!==intent.sourceSha||source.event!=='workflow_dispatch'||
    source.path!=='.github/workflows/infra-ci.yml'||source.conclusion!=='cancelled')fail();
  return {runId:String(source.id),attempt:source.run_attempt,sha:source.head_sha};
}

export function verifyCancellationTakeover(intent,checkpoint,before,after){
  validateCancellationIntent(intent,before);validateCancellationIntent(intent,after);validateCancellationCheckpoint(checkpoint,intent);
  if(before.last_hash!==checkpoint.eventHash||before.sequence!==checkpoint.sequence||before.epoch!==checkpoint.epoch||
    before.phase!==checkpoint.phase||before.status!=='running'||before.started_ms!==checkpoint.startedMs||before.deadline_ms!==checkpoint.deadlineMs||
    after.phase!==checkpoint.phase||after.status!=='restored'||after.epoch<checkpoint.epoch+2||!integer(after.sequence)||
    after.sequence<=checkpoint.sequence||!hex(after.last_hash,64)||after.started_ms!==checkpoint.startedMs||after.deadline_ms!==checkpoint.deadlineMs||
    after.rehearsal_preservation?.count!==3||after.rehearsal_preservation.hash!==intent.preservationHash)fail();
  const history=after.cancellation_history;
  if(!Array.isArray(history)||history.length<3||history.length>128||new Set(history.map(event=>event.sequence)).size!==history.length||
    history.some(event=>!exact(event,['sequence','epoch','phase','status','hash','kind'])||!integer(event.sequence)||!integer(event.epoch)||
      !hex(event.hash,64)||event.phase!==checkpoint.phase||!['running','recovering','restored'].includes(event.status)||!['phase','operation','recovery'].includes(event.kind)))fail();
  const start=history.find(event=>event.sequence===checkpoint.sequence),end=history.find(event=>event.sequence===after.sequence);
  if(start?.hash!==checkpoint.eventHash||start.epoch!==checkpoint.epoch||start.status!=='running'||
    !history.some(event=>event.kind==='recovery'&&event.status==='recovering'&&event.epoch>checkpoint.epoch&&event.epoch<after.epoch&&
      event.sequence>checkpoint.sequence&&event.sequence<after.sequence)||
    end?.kind!=='recovery'||end.status!=='restored'||end.hash!==after.last_hash||end.epoch!==after.epoch)fail();
  return {epoch:after.epoch,sequence:after.sequence,eventHash:after.last_hash,preservationHash:after.rehearsal_preservation.hash};
}

export function assertCancellationSourceSteps(job,intent){
  if(job?.name!==`Preview runtime credential rehearsal (${intent.stage})`||job.head_sha!==intent.sourceSha||job.status!=='completed'||
    job.conclusion!=='cancelled'||!Array.isArray(job.steps)||job.steps.length>100)fail();
  for(const [name,conclusion] of [['Arm preview cancellation rehearsal','success'],['Restore interrupted preview runtime','skipped'],['Remove disposable rehearsal','skipped']]){
    const steps=job.steps.filter(step=>step.name===name);
    if(steps.length!==1||steps[0].status!=='completed'||steps[0].conclusion!==conclusion)fail();
  }
}
