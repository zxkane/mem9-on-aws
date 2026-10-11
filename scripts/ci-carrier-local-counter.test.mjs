import {it,expect} from 'vitest';
import {mkdtemp,rm,readFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {carrierFixture,zero} from './ci-carrier.fixture.mjs';
import {carrierHash as hash,measureCarrierBeforeCopyBudget} from './lib/ci-carrier-before-copy.mjs';
import {NONROOT_REMAINING_WORK_LIMITS_HASH_V2,NONROOT_REMAINING_WORK_CAPS_V2} from './lib/production-nonroot-budget-revision.mjs';
import {describeCarrierLocalPolicy,carrierCleanupReservation,inspectCarrierLocalEvidence} from './lib/ci-carrier-local-policy.mjs';
import {openCarrierLocalCounter,bindCarrierLocalStartup,consumeCarrierLocalCounter,carrierLocalState,beginCarrierLocalCleanup,closeCarrierLocalCounter,drainCarrierLocalCounter,carrierLocalHost} from './lib/ci-carrier-local-counter.mjs';

async function fixture(use){
 const directory=await mkdtemp(join(tmpdir(),'carrier-local-'));
 try{
  const f=carrierFixture(),t=f.template,p=f.plan;t.cumulativeLimitsHash=NONROOT_REMAINING_WORK_LIMITS_HASH_V2;t.ciLocalPolicy=describeCarrierLocalPolicy();t.fundedLocal.ci.logicalBytes=t.ciLocalPolicy.logicalBytes;
  p.version=2;p.budgetRevision={version:2,limitsHash:NONROOT_REMAINING_WORK_LIMITS_HASH_V2,envelopeHash:hash('envelope'),historyHeadHash:hash('history')};p.compiledCeiling=NONROOT_REMAINING_WORK_CAPS_V2;p.templateHash=hash(t);p.budget=measureCarrierBeforeCopyBudget(t).fundedRemaining;
  const config={version:2,kind:'carrier-worker-config',plan:p,grantHash:hash('grant'),templateHash:p.templateHash,configHash:p.configHash,ledgerStartHash:p.ledgerStartHash,budgetRevision:p.budgetRevision,compiledCeiling:p.compiledCeiling};
  const env={...f.sourceInput.env,RUNNER_TEMP:directory,INPUT_GRANT_COMMITMENT:config.grantHash,INPUT_CONTEXT_COMMITMENT:p.context.sha256};
  let now=p.issuedMs+1;const options={config,env,now:()=>now};
  await use({f,config,env,options,setNow:n=>now=n,directory});
 }finally{await rm(directory,{recursive:true,force:true});}
}
it('claims the original slot before capture and never resets it after failure',()=>fixture(async x=>{
 const h=openCarrierLocalCounter(x.options),s=carrierLocalState(h);s.reserveLocal({...zero(),logicalBytes:321});
 closeCarrierLocalCounter(h,{complete:false});
 expect(()=>openCarrierLocalCounter(x.options)).toThrow(/CarrierLocalClaim/);
 expect((await readFile(join(s.directory,'claim.json'),'utf8'))).toContain(x.config.grantHash);
}));
it('transfers the same counter once and preserves startup spending',()=>fixture(async x=>{
 const h=openCarrierLocalCounter(x.options),s=carrierLocalState(h);s.reserveLocal({...zero(),logicalBytes:12345});
 const binding={grantHash:x.config.grantHash,templateHash:x.config.templateHash,runId:71,runAttempt:1,jobId:73};
 bindCarrierLocalStartup(h,{config:x.config,binding});const before=s.snapshot();
 expect(consumeCarrierLocalCounter(h,{config:x.config,binding})).toBe(s);
 expect(s.snapshot().spent.logicalBytes).toBeGreaterThanOrEqual(before.spent.logicalBytes);
 expect(()=>consumeCarrierLocalCounter(h,{config:x.config,binding})).toThrow(/CarrierLocalTransfer/);
 expect(()=>carrierLocalState({...h})).toThrow(/CarrierLocalOriginal/);
}));
it('rejects another job/plan without transferring ownership',()=>fixture(async x=>{
 const h=openCarrierLocalCounter(x.options),binding={grantHash:x.config.grantHash,templateHash:x.config.templateHash,runId:71,runAttempt:1,jobId:73};bindCarrierLocalStartup(h,{config:x.config,binding});
 expect(()=>consumeCarrierLocalCounter(h,{config:x.config,binding:{...binding,jobId:74}})).toThrow(/CarrierLocalBinding/);
 expect(()=>consumeCarrierLocalCounter(h,{config:{...x.config,grantHash:hash('other')},binding})).toThrow(/CarrierLocalBinding/);
 consumeCarrierLocalCounter(h,{config:x.config,binding});
}));
it('holds before capture when normal quota cannot fund the bounded command',()=>fixture(async x=>{
 const h=openCarrierLocalCounter(x.options),s=carrierLocalState(h);let calls=0;const host=carrierLocalHost(h,{env:x.env,run:async()=>{calls++;return 'ok';}});
 s.reserveLocal({...zero(),logicalBytes:s.snapshot().normalRemaining-1});
 await expect(host.run('git',['status','--porcelain'])).rejects.toThrow(/CarrierLocalLimit/);expect(calls).toBe(0);
}));
it('rejects oversized raw returns and retains the prepaid capture charge',()=>fixture(async x=>{
 const h=openCarrierLocalCounter(x.options),s=carrierLocalState(h),host=carrierLocalHost(h,{env:x.env,run:async()=>Buffer.alloc(17)}),before=s.snapshot().spent.logicalBytes;
 await expect(host.run('git',['cat-file','blob','a'.repeat(40)],{maxBytes:16,encoding:'buffer'})).rejects.toThrow(/CarrierLocalCapture/);
 expect(s.snapshot().spent.logicalBytes).toBeGreaterThan(before);
}));
it('protects cleanup after a normal hold, without an additional global payment',()=>fixture(async x=>{
 const h=openCarrierLocalCounter(x.options),s=carrierLocalState(h),before=s.snapshot();
 expect(()=>s.reserveLocal({...zero(),logicalBytes:before.normalRemaining+1})).toThrow(/CarrierLocalLimit/);
 beginCarrierLocalCleanup(h);s.reserveLocal({...zero(),logicalBytes:1024});
 expect(s.snapshot().cleanupUsed).toBeGreaterThanOrEqual(1024);
 expect(s.snapshot().cleanupReserved).toBe(carrierCleanupReservation(x.config.plan.template));
 expect(()=>s.checkNormal()).toThrow();closeCarrierLocalCounter(h,{complete:false});
}));
it('normal cutoff preserves the original cleanup deadline and cannot extend it',()=>fixture(async x=>{
 const h=openCarrierLocalCounter(x.options),s=carrierLocalState(h);x.setNow(x.config.plan.deadlineMs-30000);
 expect(()=>s.checkNormal()).toThrow();beginCarrierLocalCleanup(h);s.reserveLocal({...zero(),logicalBytes:1});x.setNow(x.config.plan.deadlineMs);
 expect(()=>s.reserveLocal({...zero(),logicalBytes:1})).toThrow(/CarrierLocalDeadline/);
}));
it('replay binds startup, totals and the original quota and rejects missing evidence',()=>fixture(async x=>{
 const h=openCarrierLocalCounter(x.options),s=carrierLocalState(h),binding={grantHash:x.config.grantHash,templateHash:x.config.templateHash,runId:71,runAttempt:1,jobId:73};bindCarrierLocalStartup(h,{config:x.config,binding});consumeCarrierLocalCounter(h,{config:x.config,binding});
 const v=s.evidence();expect(inspectCarrierLocalEvidence(v,{plan:x.config.plan,binding}).spent).toEqual(v.spent);
 expect(()=>inspectCarrierLocalEvidence({...v,records:v.records.slice(1)},{plan:x.config.plan,binding})).toThrow();
 expect(()=>inspectCarrierLocalEvidence({...v,spent:{...v.spent,logicalBytes:0}},{plan:x.config.plan,binding})).toThrow();
}));
it('cleanup aborts and joins only the counter-owned capture',()=>fixture(async x=>{
 const h=openCarrierLocalCounter(x.options);let started,stopped=false;const ready=new Promise(resolve=>started=resolve);
 const host=carrierLocalHost(h,{env:x.env,run:async()=>{throw Error('UnboundedRun');},runBounded:async(_p,_a,{signal})=>new Promise((_,reject)=>{signal.addEventListener('abort',()=>{stopped=true;reject(Error('SyntheticAborted'));},{once:true});started();})});
 const call=host.run('git',['status','--porcelain']);const settled=call.catch(e=>e);await ready;beginCarrierLocalCleanup(h);await drainCarrierLocalCounter(h);await settled;expect(stopped).toBe(true);closeCarrierLocalCounter(h,{complete:false});
}));
it('native policy and plan cannot be mutated through the original counter',()=>fixture(async x=>{
 const h=openCarrierLocalCounter(x.options),s=carrierLocalState(h);
 expect(()=>{s.policy.logicalBytes++;}).toThrow();expect(()=>{s.plan.template.fundedLocal.ci.logicalBytes++;}).toThrow();expect(()=>{s.reserveLocal=()=>{};}).toThrow();closeCarrierLocalCounter(h,{complete:false});
}));
