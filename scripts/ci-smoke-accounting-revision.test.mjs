import {describe,it,expect} from 'vitest';
import {replayAccounting,hash,zero,counter} from './lib/ci-smoke-acquisition-format.mjs';
import {NONROOT_REMAINING_WORK_LIMITS_HASH_V2} from './lib/production-nonroot-budget-revision.mjs';

const GiB=1024**3;
function fixture(){
 const binding={owner:'a'.repeat(32),executionId:'b'.repeat(32),planHash:'c'.repeat(64),publicationHash:'d'.repeat(64)};
 const budgetRevision={version:2,limitsHash:NONROOT_REMAINING_WORK_LIMITS_HASH_V2,envelopeHash:hash('envelope'),historyHeadHash:hash('history')};
 const startingCounters={...zero(),logicalBytes:13*GiB,httpBodyBytes:13*GiB},reserve={...zero(),logicalBytes:100,httpBodyBytes:100},compiledCeiling={...startingCounters,logicalBytes:13*GiB+100,httpBodyBytes:13*GiB+100};
 const events=[{version:2,budgetRevision,sequence:1,...binding,previousHash:null,type:'prepayment',data:{allocationId:hash('allocation'),planHash:hash('allocation'),scopeHash:hash('scope'),charge:reserve,reserveDebit:reserve},spent:compiledCeiling,remaining:zero()}];
 return {events,options:{binding,startingCounters,reserve,budgetRevision,expectedBudgetRevision:budgetRevision,compiledCeiling}};
}
describe('independently selected CI accounting revision',()=>{
 it('retains legacy limits and does not infer authority from a v2 journal',()=>{
  const f=fixture();expect(()=>counter(f.options.startingCounters)).toThrow();
  expect(()=>replayAccounting(f.events,{binding:f.options.binding,startingCounters:f.options.startingCounters,reserve:f.options.reserve})).toThrow();
 });
 it('replays above the legacy cap only within the independent compiled ceiling',()=>{
  const f=fixture(),r=replayAccounting(f.events,f.options);expect(r.spent).toEqual(f.options.compiledCeiling);expect(r.remaining).toEqual(zero());
 });
 it.each(['missing-expected','wrong-envelope','wrong-history','too-low','mixed-version','event-revision'])('rejects %s',fault=>{
  const f=fixture();if(fault==='missing-expected')delete f.options.expectedBudgetRevision;
  if(fault==='wrong-envelope')f.options.expectedBudgetRevision={...f.options.budgetRevision,envelopeHash:hash('other')};
  if(fault==='wrong-history')f.options.expectedBudgetRevision={...f.options.budgetRevision,historyHeadHash:hash('other')};
  if(fault==='too-low')f.options.compiledCeiling.logicalBytes--;
  if(fault==='mixed-version'){f.events[0].version=1;delete f.events[0].budgetRevision;}
  if(fault==='event-revision')f.events[0].budgetRevision={...f.options.budgetRevision,envelopeHash:hash('other')};
  expect(()=>replayAccounting(f.events,f.options)).toThrow();
 });
});
