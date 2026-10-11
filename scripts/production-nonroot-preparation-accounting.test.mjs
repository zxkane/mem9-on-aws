import {test,expect} from 'vitest';
import {sourceFixture} from './production-nonroot-preparation-accounting.fixture.mjs';
import {reserveNonrootControlPreparation,verifyNonrootControlSource,verifyNonrootDeployedControlBuild} from './lib/production-nonroot-provenance.mjs';
import {collectNonrootControlScan} from './lib/production-nonroot-control-scan.mjs';
import {describeCompositionRegionLoaderWork} from './lib/production-control-composition-region-loader.mjs';
import {nonrootDeploymentFixture} from './production-nonroot-provenance.fixture.mjs';
import {nonrootHash as hash} from './lib/production-nonroot-contracts.mjs';

// These tests observe the caller interface and ordering. The callback below
// is not a native funding capability or evidence of a completed owner run.
test('native preparation forwards exactly the pinned-bundle charge once',async()=>{
 const x=await sourceFixture(),charges=[];
 reserveNonrootControlPreparation(x.contract,{reserveLocal:charge=>charges.push(charge)});
 expect(charges).toEqual([describeCompositionRegionLoaderWork(x.contract.recipe.invocation.bundle.bytes)]);
 expect(x.reads()).toBe(0);
});

test('scan propagates the caller denial before source inspection or provider dispatch',async()=>{
 const x=await sourceFixture(),denied=Error('OriginalCallerDenied'),charges=[];let requests=0;
 const budgetedReads={reserveLocal(charge){charges.push(charge);if(charge.logicalBytes)throw denied;},readJson(){requests++;throw Error('UnexpectedProviderCall');}};
 await expect(collectNonrootControlScan({contract:x.contract,sourceContext:x.context,graph:x.d.controlVerification.graph,
  archive:x.d.a.archive(),budgetedReads,maximumExpiresMs:x.d.now+120000},{clock:()=>x.d.now})).rejects.toBe(denied);
 expect(charges.filter(c=>c.logicalBytes>0)).toEqual([describeCompositionRegionLoaderWork(x.contract.recipe.invocation.bundle.bytes)]);
 expect(x.reads()).toBe(0);expect(requests).toBe(0);
});

test('deployed-build verification propagates the caller denial before source inspection',async()=>{
 const x=await sourceFixture(),denied=Error('OriginalCallerHeld');let debits=0;
 await expect(verifyNonrootDeployedControlBuild(x.build,{...x.options(),metadataReads:{reserveLocal(){debits++;throw denied;}}})).rejects.toBe(denied);
 expect(debits).toBe(1);expect(x.reads()).toBe(0);
});

test('missing, async and thenable-returning payers cannot enter source inspection',async()=>{
 const x=await sourceFixture();let asyncCalls=0,thenableCalls=0;
 expect(()=>reserveNonrootControlPreparation(x.contract)).toThrow('NonrootControlPreparationBudget');
 expect(()=>reserveNonrootControlPreparation(x.contract,{reserveLocal:async()=>{asyncCalls++;}})).toThrow('NonrootControlPreparationSynchronousBudget');
 expect(()=>reserveNonrootControlPreparation(x.contract,{reserveLocal:()=>{thenableCalls++;return Promise.resolve();}})).toThrow('NonrootControlPreparationSynchronousBudget');
 expect(asyncCalls).toBe(0);expect(thenableCalls).toBe(1);expect(x.reads()).toBe(0);
});

test('a smaller declared bundle cannot select a cheaper inspection of larger bytes',async()=>{
 const x=await sourceFixture(),bad=structuredClone(x.contract),bundle=bad.recipe.invocation.bundle;
 bundle.bytes--;bundle.blob.bytesLength--;
 Object.assign(bad.recipe.preparation.files.find(f=>f.path===bundle.path),bundle);
 bad.recipe.preparation.closureHash=hash(bad.recipe.preparation.files);
 await expect(verifyNonrootControlSource(bad,{...x.options(),expected:{...x.options().expected,contract:bad}})).rejects.toThrow('ControlCompositionPreparationBundleBinding');
});

test('legacy source verification does not acquire the new native preparation charge',async()=>{
 const d=await nonrootDeploymentFixture();let calls=0;
 reserveNonrootControlPreparation(d.contract,{reserveLocal(){calls++;throw Error('UnexpectedLegacyCharge');}});
 await verifyNonrootControlSource(d.contract,d.options());expect(calls).toBe(0);
});
