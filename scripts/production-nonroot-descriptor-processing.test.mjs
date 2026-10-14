import {it,expect} from 'vitest';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {carrierFixture,zero} from './ci-carrier.fixture.mjs';
import {carrierHash as hash,measureCarrierBeforeCopyBudget,inspectCarrierBeforeCopyTemplate,carrierSqlFixtureComponentBudget,carrierBlobDebit} from './lib/ci-carrier-before-copy.mjs';
import {NONROOT_REMAINING_WORK_LIMITS_HASH_V2,NONROOT_REMAINING_WORK_CAPS_V2} from './lib/production-nonroot-budget-revision.mjs';
import {describeCarrierLocalPolicy} from './lib/ci-carrier-local-policy.mjs';
import {openCarrierLocalCounter,carrierLocalState,closeCarrierLocalCounter} from './lib/ci-carrier-local-counter.mjs';
import {createDescriptorProcessing,descriptorProcessingRow,descriptorOperations,descriptorCertificate,descriptorJoin,descriptorGuard,descriptorBufferFrom,descriptorBufferString,descriptorPathFilter,descriptorSplit} from './lib/production-nonroot-descriptor-processing.mjs';
import {createNonrootEvidenceArchive,forkNonrootArchive,nonrootArchiveResolvers} from './lib/production-nonroot-archive.mjs';
import {parseNonrootJson,nonrootHash} from './lib/production-nonroot-contracts.mjs';
import {sha} from './lib/ci-smoke-acquisition-format.mjs';
const deferred=()=>{let resolve;const promise=new Promise(r=>resolve=r);return {promise,resolve};};

// Synthetic config and originals, with the real journal/slot/normal counter.
// This is component payment coverage, not a production proof or CI completion.
async function original(use){
 const directory=await mkdtemp(join(tmpdir(),'descriptor-payment-'));let handle;
 try{
  const f=carrierFixture(),t=f.template,p=f.plan;t.cumulativeLimitsHash=NONROOT_REMAINING_WORK_LIMITS_HASH_V2;t.ciLocalPolicy=describeCarrierLocalPolicy();t.fundedLocal.ci.logicalBytes=t.ciLocalPolicy.logicalBytes;
  p.version=2;p.budgetRevision={version:2,limitsHash:NONROOT_REMAINING_WORK_LIMITS_HASH_V2,envelopeHash:hash('envelope'),historyHeadHash:hash('history')};p.compiledCeiling=NONROOT_REMAINING_WORK_CAPS_V2;p.templateHash=hash(t);p.budget=measureCarrierBeforeCopyBudget(t).fundedRemaining;
  const config={version:2,kind:'carrier-worker-config',plan:p,grantHash:hash(directory),templateHash:p.templateHash,configHash:p.configHash,ledgerStartHash:p.ledgerStartHash,budgetRevision:p.budgetRevision,compiledCeiling:p.compiledCeiling};
  const env={...f.sourceInput.env,RUNNER_TEMP:directory,INPUT_GRANT_COMMITMENT:config.grantHash,INPUT_CONTEXT_COMMITMENT:p.context.sha256};
  handle=openCarrierLocalCounter({config,env,now:()=>p.issuedMs+1});const state=carrierLocalState(handle),rows=[];
  const work=createDescriptorProcessing({check:state.checkNormal,charge(input){const row=descriptorProcessingRow(input);state.reserveLocal({...zero(),logicalBytes:row.logicalBytes});rows.push(row);}});
  await use({work,state,rows,template:t,plan:p});
 }finally{if(handle)closeCarrierLocalCounter(handle,{complete:false});await rm(directory,{recursive:true,force:true});}
}
it('charges the real original counter before complete template and package validation without altering output',()=>original(x=>{
 const before=x.state.snapshot().spent.logicalBytes;
 expect(inspectCarrierBeforeCopyTemplate(x.template,{descriptorWork:x.work})).toEqual(inspectCarrierBeforeCopyTemplate(x.template));
 expect(carrierSqlFixtureComponentBudget(x.template.sqlFixture,{putResponseBytes:16384,descriptorWork:x.work})).toEqual(carrierSqlFixtureComponentBudget(x.template.sqlFixture,{putResponseBytes:16384}));
 expect(x.state.snapshot().spent.logicalBytes-before).toBe(x.rows.reduce((n,r)=>n+r.logicalBytes,0));expect(x.rows.some(r=>r.kind==='descriptor-guard')).toBe(true);
 const bad=structuredClone(x.template);bad.source.jobKey='changed';expect(()=>inspectCarrierBeforeCopyTemplate(bad,{descriptorWork:x.work})).toThrow('CarrierFixedJob');
}));
it('stops at an exhausted original counter before reading validator input',()=>original(x=>{
 x.state.reserveLocal({...zero(),logicalBytes:x.state.snapshot().normalRemaining});let reads=0;
 expect(()=>inspectCarrierBeforeCopyTemplate({get version(){reads++;throw Error('unpaid-input');}},{descriptorWork:x.work})).toThrow('CarrierLocalLimit');expect(reads).toBe(0);
}));
it('held original owner rejects decoder and certificate before either can consume invalid input',()=>original(x=>{
 x.state.hold();expect(()=>descriptorOperations(x.work,{parseNonrootJson})).toThrow('CarrierLocalHeld');expect(()=>descriptorCertificate(x.work,Buffer.from('invalid'))).toThrow('CarrierLocalHeld');
}));
it('cannot copy a processing brand or accept asynchronous check or charge callbacks',()=>{
 const work=createDescriptorProcessing({check(){},charge(){}});
 expect(()=>descriptorGuard({...work},{})).toThrow('DescriptorOriginalProcessing');
 expect(()=>descriptorGuard(createDescriptorProcessing({check:async()=>{},charge(){}}),{})).toThrow('DescriptorSynchronousProcessing');
 expect(()=>descriptorGuard(createDescriptorProcessing({check(){},charge:async()=>{}}),{})).toThrow('DescriptorSynchronousProcessing');
});
it('sizes Unicode and escaping before hash and rejects accessors without invoking them',()=>original(x=>{
 const v={text:'\u0000"\\é🙂\ud800',nested:[null,true,1.5,-0]};const before=x.rows.length;descriptorGuard(x.work,v);
 const row=x.rows.slice(before).find(r=>r.kind==='descriptor-guard');expect(row.bytesLength).toBe(Buffer.byteLength(JSON.stringify(v)));expect(row.nodes).toBe(7);
 let called=0;expect(()=>descriptorGuard(x.work,{get field(){called++;return 1;}})).toThrow('DescriptorJsonValue');expect(called).toBe(0);
}));
it('keeps late JSON node rejection fully prepaid and preserves the real strict decoder',()=>original(x=>{
 const text='['+Array(100001).fill('0').join(',')+']',ops=descriptorOperations(x.work,{parseNonrootJson});
 expect(()=>ops.parseNonrootJson(text)).toThrow();const row=x.rows.find(r=>r.kind==='descriptor-json');expect(row.nodeLimit).toBe(33554432);expect(row.logicalBytes).toBe(40*Buffer.byteLength(text));
}));
it('charges both base64 encodings, all path rows, and every possible split line before work',()=>original(x=>{
 const raw=descriptorBufferFrom(x.work,'YQ==','base64');expect(descriptorBufferString(x.work,raw,'base64')).toBe('YQ==');
 expect(descriptorPathFilter(x.work,[{path:'a'},{path:'b'},{path:'a'}],'a')).toHaveLength(2);
 expect(descriptorSplit(x.work,'\n'.repeat(20),'\n')).toHaveLength(21);
 expect(x.rows.filter(r=>r.kind==='descriptor-bytes').map(r=>r.logicalBytes)).toEqual([12,16]);
 expect(x.rows.find(r=>r.kind==='descriptor-path-scan').logicalBytes).toBe(120);expect(x.rows.find(r=>r.kind==='descriptor-split').logicalBytes).toBe(832);
}));
it('joins every original read after the first failure and cannot resume failed work',async()=>{
 const x=createDescriptorProcessing({check(){},charge(){}}),release=deferred(),error=Error('original-read'),started=[],ended=[];let done=false;
 const result=descriptorJoin(x,[1,2,3],async i=>{started.push(i);if(i===1)throw error;await release.promise;ended.push(i);}).catch(e=>{done=true;return e;});
 await Promise.resolve();expect(started).toEqual([1,2,3]);expect(done).toBe(false);release.resolve();expect(await result).toBe(error);expect(ended).toEqual([2,3]);expect(()=>x.check()).toThrow('DescriptorProcessingHeld');
});
it('archive checks the same original owner after read await before copying/hash/JSON decode',()=>original(async x=>{
 const raw=Buffer.from('{"x":1}'),ref={bytesLength:raw.length,bytesHash:sha(raw),canonicalHash:nonrootHash({x:1})},manifest={version:2,kind:'nonroot-proof-archive',owner:'a'.repeat(32),files:[{name:'proof.json',purpose:'protocol',encoding:'json',ref}]};
 const started=deferred(),release=deferred();let touched=0;const value=new Proxy(raw,{get(target,k){if(k==='then')return undefined;touched++;return Reflect.get(target,k,target);}});
 const base=createNonrootEvidenceArchive(JSON.stringify(manifest),{expectedManifestHash:nonrootHash(manifest),readObject:async()=>{started.resolve();await release.promise;return value;}});
 const archive=forkNonrootArchive(base,{assertCurrent:x.work.check}),result=nonrootArchiveResolvers(archive).resolveJson(ref).catch(e=>e);await started.promise;x.state.hold();release.resolve();expect((await result).message).toBe('CarrierLocalHeld');expect(touched).toBe(0);
 expect(()=>forkNonrootArchive(archive,{assertCurrent(){}})).toThrow('NonrootArchiveProcessingChanged');
}));
it('prices all growing original blob prefixes instead of assuming one constant-size replay',()=>original(x=>{
 let usage={requests:0,responseBytes:0,digests:[]},prefixNodes=0;const K=6;
 for(let k=0;k<K;k++){
  const before=x.rows.length;usage=carrierBlobDebit(x.plan,'ci',usage,{digest:'sha256:'+String(k+1).repeat(64),size:1},{descriptorWork:x.work}).usage;
  // Entry H(plan), H(usage), H(descriptor), then the unchanged full plan
  // checks and result copy. The prior usage tree contains 4+k JSON nodes.
  const guards=x.rows.slice(before).filter(r=>r.kind==='descriptor-guard');expect(guards[1].nodes).toBe(4+k);prefixNodes+=guards[1].nodes;
 }
 expect(prefixNodes).toBe(4*K+K*(K-1)/2);expect(usage.digests).toHaveLength(K);
}),30000);
it('join preserves the first observed failure even when a lower-index read fails later',async()=>{
 const work=createDescriptorProcessing({check(){},charge(){}}),slow=deferred(),error=Error('first-observed');
 const result=descriptorJoin(work,[0,1],async i=>{if(i===1)throw error;await slow.promise;throw Error('later-low-index');}).catch(e=>e);
 await Promise.resolve();await Promise.resolve();slow.resolve();expect(await result).toBe(error);
});
