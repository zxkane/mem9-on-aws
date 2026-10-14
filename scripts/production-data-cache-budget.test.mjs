import {expect, it, vi} from 'vitest';
import {
  assertImageBudget, createImageBudget, createPrepaidDataCacheBudget,
  readImageGraph, readControlImageGraph, IMAGE_MEDIA,
} from './lib/production-image-graph.mjs';
import {IMAGE_TRANSITION_LIMITS as L} from './lib/production-image-transition.mjs';
import {graphFixture} from './production-image.fixture.mjs';

const zero=()=>({ecrRequests:0,logicalBytes:0,httpBodyBytes:0,uncompressedBytes:0,processedEntries:0});
function payer({deny=()=>false}={}) {
  let now=10_000, expired=false;
  const spent={ecrRequests:7,logicalBytes:101,httpBodyBytes:203,uncompressedBytes:307,processedEntries:11};
  const charges=[];
  const metadataReads={reserveLocal(charge) {
    if(expired)throw Error('OriginalOwnerExpired');
    expect(Object.keys(charge).sort()).toEqual(Object.keys(zero()).sort());
    expect(charge.ecrRequests).toBe(0);expect(charge.httpBodyBytes).toBe(0);
    for(const n of Object.values(charge))expect(Number.isSafeInteger(n)&&n>=0).toBe(true);
    if(deny(charge))throw Error('OriginalLocalQuota');
    charges.push({...charge});
    for(const key of Object.keys(spent))spent[key]+=charge[key];
    return {...spent};
  }};
  return {spent,charges,metadataReads,now:()=>now,advance:n=>{now+=n;},expire:()=>{expired=true;}};
}

it('uses existing DATA prepayment without credentials or resetting its five counters',()=>{
  const p=payer(),before={...p.spent};
  const budget=createPrepaidDataCacheBudget({metadataReads:p.metadataReads,now:p.now,deadlineMs:p.now()+120_000});
  expect(Object.isFrozen(budget)).toBe(true);expect(assertImageBudget(budget)).toBe(budget);
  expect(p.spent).toEqual(before);
  budget.uncompressed(23);budget.entry();
  expect(p.spent).toEqual({...before,uncompressedBytes:before.uncompressedBytes+23,processedEntries:before.processedEntries+1});
  expect(budget.usage()).toMatchObject({calls:0,transferredBytes:0,uncompressedBytes:23,fsEntries:1});
  expect(Object.hasOwn(budget,'credentialExpiresMs')).toBe(false);
  expect(()=>createImageBudget({now:p.now,credentialExpiresMs:p.now()+120_000})).toThrow('ImageCredentialLifetime');
});

it.each([
  ['uncompressed',23,'uncompressedBytes'],
  ['entry',undefined,'fsEntries'],
])('debits %s before advancing the original pass counters',(method,amount,counter)=>{
  const p=payer({deny:c=>c.uncompressedBytes>0||c.processedEntries>0});
  const budget=createPrepaidDataCacheBudget({metadataReads:p.metadataReads,now:p.now}),before={...p.spent};
  expect(()=>budget[method](amount)).toThrow('OriginalLocalQuota');
  expect(budget.usage()[counter]).toBe(0);expect(p.spent).toEqual(before);
  expect(()=>budget.check()).toThrow('DataCacheBudgetHeld');
});

it('keeps original owner expiry authoritative even when the local watchdog has time left',()=>{
  const p=payer(),budget=createPrepaidDataCacheBudget({metadataReads:p.metadataReads,now:p.now});
  budget.check();expect(p.charges.length).toBeGreaterThan(0);
  expect(p.charges.every(c=>Object.values(c).every(n=>n===0))).toBe(true);
  p.expire();expect(()=>budget.check()).toThrow('OriginalOwnerExpired');
  expect(()=>budget.uncompressed(1)).toThrow('DataCacheBudgetHeld');
});

it('rejects a replaced payer method before invoking it',()=>{
  const p=payer(),budget=createPrepaidDataCacheBudget({metadataReads:p.metadataReads,now:p.now});
  const replacement=vi.fn();p.metadataReads.reserveLocal=replacement;
  expect(()=>budget.check()).toThrow('DataCache');expect(replacement).not.toHaveBeenCalled();
  expect(()=>budget.check()).toThrow('DataCacheBudgetHeld');
});

it.each([()=>Promise.resolve(),()=>Promise.reject(Error('AsyncDenial'))])('rejects asynchronous payer results',result=>{
  expect(()=>createPrepaidDataCacheBudget({metadataReads:{reserveLocal:result}})).toThrow('DataCacheSynchronousReservationRequired');
});

it('seals an existing budget when a later debit returns a thenable',()=>{
  let asynchronous=false;
  const metadataReads={reserveLocal(){if(asynchronous)return Promise.resolve();}};
  const budget=createPrepaidDataCacheBudget({metadataReads});asynchronous=true;
  expect(()=>budget.entry()).toThrow('DataCacheSynchronousReservationRequired');
  expect(budget.usage().fsEntries).toBe(0);
  expect(()=>budget.check()).toThrow('DataCacheBudgetHeld');
});

it('honors cancellation and the original cleanup margin without renewing a deadline',()=>{
  const p=payer(),abort=new AbortController();
  const budget=createPrepaidDataCacheBudget({metadataReads:p.metadataReads,now:p.now,signal:abort.signal});
  abort.abort(Error('CancelledByOwner'));
  expect(()=>budget.check()).toThrow('CancelledByOwner');
  expect(()=>budget.check()).toThrow('DataCacheBudgetHeld');
  const q=payer(),timed=createPrepaidDataCacheBudget({metadataReads:q.metadataReads,now:q.now,deadlineMs:q.now()+L.cleanupReserveMs+1});
  q.advance(1);expect(()=>timed.check()).toThrow('DataCacheDeadline');
  expect(()=>createPrepaidDataCacheBudget({metadataReads:q.metadataReads,now:q.now,deadlineMs:q.now()+L.maxBlobTransferMs+1})).toThrow('DataCacheDeadline');
});

it.each(['credentialExpiresMs','startedMs','caps','controlCapacity','uncompressedBytesLimit','processedEntriesLimit'])('rejects the undeclared %s option',key=>{
  const reserveLocal=vi.fn();
  expect(()=>createPrepaidDataCacheBudget({metadataReads:{reserveLocal},[key]:1})).toThrow('DataCacheBudgetOptions');
  expect(reserveLocal).not.toHaveBeenCalled();
});

it('retains original descriptor and cumulative decompression limits',()=>{
  const p=payer(),budget=createPrepaidDataCacheBudget({metadataReads:p.metadataReads,now:p.now});
  expect(()=>budget.blob({digest:'sha256:'+'a'.repeat(64),mediaType:IMAGE_MEDIA.tar,size:L.maxBlobBytes+1})).toThrow('ImageBlobLimit');
  const q=payer(),other=createPrepaidDataCacheBudget({metadataReads:q.metadataReads,now:q.now}),before={...q.spent};
  expect(()=>other.uncompressed(L.maxUncompressedBytes+1)).toThrow('ImageUncompressedLimit');
  expect(other.usage().uncompressedBytes).toBe(0);expect(q.spent).toEqual(before);
});

it('does not create a network reader, transfer allowance, or serializable budget authority',async()=>{
  const p=payer(),budget=createPrepaidDataCacheBudget({metadataReads:p.metadataReads,now:p.now}),f=graphFixture();
  const source={manifest:vi.fn(),blob:vi.fn()};
  await expect(readImageGraph(f.roots,{source,store:f.store,budget})).rejects.toThrow('DataCacheNetworkForbidden');
  const root=f.roots[0],config=JSON.parse(f.data.get(root.arm64Digest)).config;
  await expect(readControlImageGraph({account:'123456789012',region:'ap-northeast-1',repositoryName:'mem9-on-aws/bootstrap',root:root.root,arm64Digest:root.arm64Digest,configDigest:config.digest},{source,store:f.store,budget})).rejects.toThrow('DataCache');
  expect(source.manifest).not.toHaveBeenCalled();expect(source.blob).not.toHaveBeenCalled();
  for(const run of [()=>budget.call(),()=>budget.transfer(1),()=>budget.projected({transferBytes:1,ecrCalls:1})])expect(run).toThrow('DataCache');
  expect(()=>assertImageBudget(JSON.parse(JSON.stringify(budget)))).toThrow('ImageBudgetRequired');
  expect(p.spent.ecrRequests).toBe(7);expect(p.spent.httpBodyBytes).toBe(203);
});
