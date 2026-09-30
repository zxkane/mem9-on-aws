import {readFile,appendFile} from 'node:fs/promises';
import {setTimeout as delay} from 'node:timers/promises';
import {cancellationHash,validateCancellationIntent,cancellationCheckpoint,validateCancellationCheckpoint,
  validateRecoveryEvent,verifyCancellationTakeover,assertCancellationSourceSteps} from './production-runtime-cancellation.mjs';

const fail=()=>{throw Error('CancellationRehearsalIncomplete');};
const hex=(value,length)=>typeof value==='string'&&new RegExp(`^[a-f0-9]{${length}}$`).test(value);
const runId=value=>typeof value==='string'&&/^[1-9][0-9]*$/.test(value);
const attempt=value=>Number.isSafeInteger(value)&&value>0;
const exact=(value,keys)=>value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join()===keys.slice().sort().join();

/** Uses the existing coordinator's stage-scoped routing and trusted task path. */
export function cancellationRehearsal({env,stage,getPlan,readRecord,writeRecord,release,readState,invoke,execute,claimSource,
  now=Date.now,sleep=delay,progress=()=>{},readEvent=async()=>JSON.parse(await readFile(env.GITHUB_EVENT_PATH,'utf8')),
  armedOutput=async()=>appendFile(env.GITHUB_OUTPUT,'armed=true\n')}){
  const ensurePreview=()=>{if(!/^pr-[1-9][0-9]*$/.test(stage??''))fail();};
  const actor=()=>{
    const id=env.GITHUB_RUN_ID,n=Number(env.GITHUB_RUN_ATTEMPT);
    if(!runId(id)||!attempt(n))fail();return {runId:id,attempt:n};
  };
  const read=key=>readRecord('cancellation-'+key);
  const write=async(key,value)=>{
    const prior=await read(key);
    if(prior&&cancellationHash(prior)!==cancellationHash(value))fail();
    if(!prior)await writeRecord('cancellation-'+key,value);
    if(cancellationHash(await read(key))!==cancellationHash(value))fail();
  };
  const checkRelease=async intent=>{
    const current=await release();
    for(const key of ['sourceSha','sourceTree','operatorDigest','schemaDigest','coordinatorDigest'])if(intent[key]!==current[key])fail();
  };
  const intentFor=async state=>{
    const intent=validateCancellationIntent(await read('intent'),state,{now:now()});await checkRelease(intent);return intent;
  };
  const github=async path=>{
    const repo=env.GITHUB_REPOSITORY;
    if(!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repo??''))fail();
    const result=await execute('gh',['api',`repos/${repo}/${path}`],{env,timeout:30000,maxBuffer:2*1024*1024});
    return JSON.parse(result.stdout);
  };
  const validateReceipt=(receipt,intent,checkpoint)=>{
    if(!exact(receipt,['version','intentHash','checkpointHash','receiver','epoch','sequence','eventHash','preservationHash','foregroundHash','createdAt'])||
      receipt.version!==1||receipt.intentHash!==cancellationHash(intent)||receipt.checkpointHash!==cancellationHash(checkpoint)||
      !attempt(receipt.epoch)||receipt.epoch<checkpoint.epoch+2||!attempt(receipt.sequence)||receipt.sequence<=checkpoint.sequence||
      !hex(receipt.eventHash,64)||receipt.preservationHash!==intent.preservationHash||!hex(receipt.foregroundHash,64)||
      !Number.isSafeInteger(receipt.createdAt)||receipt.createdAt<checkpoint.atMs||receipt.createdAt>now()+30000)fail();
    const receiver=receipt.receiver;
    if(!exact(receiver,['runId','attempt','workflowRef','workflowSha'])||!runId(receiver.runId)||receiver.runId===intent.sourceRunId||
      !attempt(receiver.attempt)||!hex(receiver.workflowSha,40)||
      receiver.workflowRef!==`${env.GITHUB_REPOSITORY}/.github/workflows/runtime-recovery.yml@refs/heads/main`)fail();
    return receipt;
  };
  return {
    async arm(){
      ensurePreview();const source=actor(),plan=getPlan();
      if(plan?.sourceRunId!==source.runId||plan.sourceRunAttempt!==source.attempt)fail();
      const state=await readState();if(state.phase!=='prepared'||state.status!=='running')fail();
      const checked=await invoke('rehearsal-preservation',state);
      if(checked.rehearsal_preservation?.count!==3)fail();
      const current=await release();if(current.sourceSha!==env.GITHUB_SHA)fail();
      const intent={version:1,stage,nonce:state.operation_nonce,sourceRunId:source.runId,sourceAttempt:source.attempt,...current,
        identityHash:cancellationHash(state.identity),preservationHash:checked.rehearsal_preservation.hash,createdAt:now()};
      validateCancellationIntent(intent,state,{now:now()});await write('intent',intent);await armedOutput();
      progress({phase:'cancellation-armed'});return intent;
    },
    async beforeFence(state){
      if(env.MEM9_RUNTIME_CANCELLATION_DRILL!=='1')return;
      ensurePreview();const intent=await intentFor(state),source=actor();
      if(intent.sourceRunId!==source.runId||intent.sourceAttempt!==source.attempt||state.phase!=='runtime_prepared')fail();
      if(now()+70*60000>=state.deadline_ms||now()+10*60000>=state.started_ms+45*60000)fail();
    },
    async afterFence(state){
      if(env.MEM9_RUNTIME_CANCELLATION_DRILL!=='1')return;
      ensurePreview();const intent=await intentFor(state),checkpoint=cancellationCheckpoint(intent,state,now());
      await write('checkpoint',checkpoint);progress({phase:'awaiting-cancellation',epoch:state.epoch});
      const until=now()+10*60000;
      while(now()<until)await sleep(Math.min(5000,until-now()));
      throw Error('CancellationCheckpointTimeout');
    },
    async afterRestoration(before,restored,foreground){
      if(!env.MEM9_RUNTIME_RECOVERY_RUN_ID||!await read('intent'))return;
      ensurePreview();const intent=await intentFor(before),checkpoint=validateCancellationCheckpoint(await read('checkpoint'),intent);
      if(env.GITHUB_EVENT_NAME!=='workflow_run')fail();
      validateRecoveryEvent(await readEvent(),intent,env.GITHUB_REPOSITORY);
      const receiver={...actor(),workflowRef:env.GITHUB_WORKFLOW_REF,workflowSha:env.GITHUB_WORKFLOW_SHA};
      const checked=await invoke('rehearsal-preservation',restored,{checkpoint_sequence:checkpoint.sequence});
      const result=verifyCancellationTakeover(intent,checkpoint,before,checked);
      const receipt={version:1,intentHash:cancellationHash(intent),checkpointHash:cancellationHash(checkpoint),receiver,...result,
        foregroundHash:foreground?.verification_hash,createdAt:now()};
      validateReceipt(receipt,intent,checkpoint);await write('receipt',receipt);
      progress({phase:'cancellation-recovery-recorded',epoch:restored.epoch});
    },
    async resume(){
      ensurePreview();const source=actor(),state=await readState(),intent=await intentFor(state);
      const checkpoint=validateCancellationCheckpoint(await read('checkpoint'),intent),receipt=validateReceipt(await read('receipt'),intent,checkpoint);
      if(state.phase!==checkpoint.phase||state.status!=='restored'||state.epoch!==receipt.epoch||state.sequence!==receipt.sequence||state.last_hash!==receipt.eventHash||
        state.started_ms!==checkpoint.startedMs||state.deadline_ms!==checkpoint.deadlineMs||now()>=state.started_ms+45*60000||now()>=state.deadline_ms)fail();
      const original=await github(`actions/runs/${intent.sourceRunId}/attempts/${intent.sourceAttempt}`);
      validateRecoveryEvent({repository:{full_name:env.GITHUB_REPOSITORY},workflow_run:original},intent,env.GITHUB_REPOSITORY);
      const jobs=await github(`actions/runs/${intent.sourceRunId}/attempts/${intent.sourceAttempt}/jobs?per_page=100`);
      if(!Number.isInteger(jobs.total_count)||jobs.total_count>100||jobs.jobs?.length!==jobs.total_count)fail();
      const cutovers=jobs.jobs.filter(job=>job.name===`Preview runtime credential rehearsal (${stage})`);
      if(cutovers.length!==1)fail();assertCancellationSourceSteps(cutovers[0],intent);
      const receiver=receipt.receiver,completed=await github(`actions/runs/${receiver.runId}/attempts/${receiver.attempt}`);
      if(String(completed.id)!==receiver.runId||completed.run_attempt!==receiver.attempt||completed.event!=='workflow_run'||
        completed.path!=='.github/workflows/runtime-recovery.yml'||completed.head_branch!=='main'||completed.head_sha!==receiver.workflowSha||
        completed.status!=='completed'||completed.conclusion!=='success')fail();
      await claimSource();
      const resumed=await invoke('resume',state,{expected_hash:receipt.eventHash});
      if(resumed.epoch!==receipt.epoch+1||resumed.status!=='running'||resumed.phase!==checkpoint.phase||resumed.deadline_ms!==checkpoint.deadlineMs)fail();
      await write('accepted',{version:1,receiptHash:cancellationHash(receipt),resumeRunId:source.runId,resumeAttempt:source.attempt,resumeEpoch:resumed.epoch,resumeHash:resumed.last_hash});
      return resumed;
    },
    async evidence(state){
      if(!await read('intent'))return null;
      ensurePreview();const intent=await intentFor(state),checkpoint=validateCancellationCheckpoint(await read('checkpoint'),intent);
      const receipt=validateReceipt(await read('receipt'),intent,checkpoint),accepted=await read('accepted'),source=actor();
      if(!exact(accepted,['version','receiptHash','resumeRunId','resumeAttempt','resumeEpoch','resumeHash'])||accepted.version!==1||
        accepted.receiptHash!==cancellationHash(receipt)||accepted.resumeRunId!==source.runId||accepted.resumeAttempt!==source.attempt||
        accepted.resumeEpoch!==receipt.epoch+1||state.epoch!==accepted.resumeEpoch||!hex(accepted.resumeHash,64)||
        state.phase!=='complete'||state.status!=='running'||state.deadline_ms!==checkpoint.deadlineMs)fail();
      return {sourceRunId:intent.sourceRunId,sourceAttempt:intent.sourceAttempt,receiver:receipt.receiver,
        checkpointHash:cancellationHash(checkpoint),restoredHash:receipt.eventHash,resumeHash:accepted.resumeHash,preservationHash:receipt.preservationHash};
    },
  };
}
