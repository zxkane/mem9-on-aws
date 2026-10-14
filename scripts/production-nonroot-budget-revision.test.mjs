import {it,expect} from 'vitest';
import {nonrootAccountingPolicy,NONROOT_REMAINING_WORK_LIMITS_HASH_V2,NONROOT_REMAINING_WORK_CAPS_V2} from './lib/production-nonroot-budget-revision.mjs';
import {createImageBudget,createRemainingWorkImageBudget,IMAGE_MEDIA} from './lib/production-image-graph.mjs';

const revision=()=>({version:2,limitsHash:NONROOT_REMAINING_WORK_LIMITS_HASH_V2,envelopeHash:'a'.repeat(64),historyHeadHash:'b'.repeat(64)});
const counters=()=>({ecrRequests:0,logicalBytes:0,httpBodyBytes:0,uncompressedBytes:0,processedEntries:0});

it('preserves legacy cumulative limits without an independently selected revision',()=>{
 const policy=nonrootAccountingPolicy();expect(policy.version).toBe(1);
 expect(()=>policy.counter({...counters(),logicalBytes:12*1024**3+1})).toThrow('NonrootBudgetCounter');
 expect(()=>nonrootAccountingPolicy(undefined,revision())).toThrow('NonrootBudgetRevisionMissing');
});
it('requires an independent matching commitment and rejects altered or extra revision fields',()=>{
 const expected=revision();expect(()=>nonrootAccountingPolicy(expected)).toThrow();
 for(const field of ['limitsHash','envelopeHash','historyHeadHash'])expect(()=>nonrootAccountingPolicy({...expected,[field]:'c'.repeat(64)},expected)).toThrow();
 for(const changed of [{...expected,version:1},{...expected,allow:true},{...expected,limitsHash:'latest'}])expect(()=>nonrootAccountingPolicy(changed,expected)).toThrow();
 const policy=nonrootAccountingPolicy(expected,expected,NONROOT_REMAINING_WORK_CAPS_V2);expected.envelopeHash='d'.repeat(64);
 expect(policy.budgetRevision.envelopeHash).toBe('a'.repeat(64));expect(Object.isFrozen(policy.caps)).toBe(true);
});
it('enforces each new absolute cap and rejects invalid counters',()=>{
 const expected=revision(),policy=nonrootAccountingPolicy(expected,expected,NONROOT_REMAINING_WORK_CAPS_V2);
 expect(policy.counter({...counters(),logicalBytes:12*1024**3+1}).logicalBytes).toBe(12*1024**3+1);
 for(const [key,max]of Object.entries(NONROOT_REMAINING_WORK_CAPS_V2)){
  expect(policy.counter({...counters(),[key]:max})[key]).toBe(max);
  for(const value of [max+1,-1,0.5,Infinity,NaN])expect(()=>policy.counter({...counters(),[key]:value})).toThrow();
 }
 expect(()=>policy.counter({...counters(),extra:0})).toThrow();
});
it('requires and enforces the compiled ceiling below the absolute technical cap',()=>{
 const expected=revision(),ceiling={...NONROOT_REMAINING_WORK_CAPS_V2,logicalBytes:13*1024**3};
 expect(()=>nonrootAccountingPolicy(expected,expected)).toThrow();
 const policy=nonrootAccountingPolicy(expected,expected,ceiling);
 expect(policy.counter({...counters(),logicalBytes:ceiling.logicalBytes}).logicalBytes).toBe(ceiling.logicalBytes);
 expect(()=>policy.counter({...counters(),logicalBytes:ceiling.logicalBytes+1})).toThrow('NonrootBudgetCounter');
 expect(()=>nonrootAccountingPolicy(expected,expected,{...ceiling,httpBodyBytes:NONROOT_REMAINING_WORK_CAPS_V2.httpBodyBytes+1})).toThrow('NonrootBudgetCeiling');
});
it('uses a distinct cache budget without relaxing graph size or legacy cumulative limits',()=>{
 const now=1000000000000,clock={now:()=>now,startedMs:now,credentialExpiresMs:now+3600000};
 const old=createImageBudget(clock);expect(()=>old.transfer(13*1024**3)).toThrow('ImageTransferLimit');
 const expected=revision(),ceiling={...NONROOT_REMAINING_WORK_CAPS_V2,logicalBytes:20*1024**3};
 const budget=createRemainingWorkImageBudget({...clock,budgetRevision:expected,expectedBudgetRevision:expected,expectedBudgetCeiling:ceiling});
 budget.transfer(ceiling.logicalBytes);expect(budget.usage().transferredBytes).toBe(ceiling.logicalBytes);
 expect(()=>budget.transfer(1)).toThrow('ImageTransferLimit');expect(budget.cumulativeCaps).toEqual(ceiling);
 const blob=(n,size)=>({digest:'sha256:'+String(n).repeat(64),mediaType:IMAGE_MEDIA.gzip,size});
 budget.blob(blob(1,2*1024**3));budget.blob(blob(2,2*1024**3));
 expect(()=>budget.blob(blob(3,1))).toThrow('ImageGraphByteLimit');
 expect(()=>createImageBudget({...clock,budgetRevision:expected})).toThrow('ImageLimitsOverride');
 expect(()=>createRemainingWorkImageBudget({...clock,budgetRevision:expected,expectedBudgetRevision:expected})).toThrow();
});
