import {it,expect} from 'vitest';
import {createImageBudget,createPrepaidControlCacheBudget,assertImageBudget,readImageGraph,readControlImageGraph} from './lib/production-image-graph.mjs';
import {IMAGE_TRANSITION_LIMITS as L} from './lib/production-image-transition.mjs';
import {graphFixture} from './production-image.fixture.mjs';

function acquisition({limit=Infinity}={}){
 const charges=[],spent={ecrRequests:7,logicalBytes:1000,httpBodyBytes:2000,uncompressedBytes:3000,processedEntries:4};
 let now=10000,expiresMs=now+120000;
 const metadataReads={reserveLocal(charge){
  if(now>=expiresMs)throw Error('OwnerSourceExpired');
  expect(charge.ecrRequests).toBe(0);expect(charge.httpBodyBytes).toBe(0);charges.push({...charge});
  if(Object.values(charge).some(n=>n>limit))throw Error('PrepaidLocalQuota');
  for(const key of Object.keys(spent))spent[key]+=charge[key];return {...spent};
 }};
 return {metadataReads,charges,spent,now:()=>now,expire(){now=expiresMs;},advance(n){now+=n;}};
}
it('uses original prepayment with a short owner lifetime and no fabricated credential expiration',()=>{
 const a=acquisition(),before={...a.spent},budget=createPrepaidControlCacheBudget({metadataReads:a.metadataReads,now:a.now});
 expect(assertImageBudget(budget)).toBe(budget);expect(a.spent).toEqual(before);
 budget.cacheRead(12);budget.uncompressed(34);budget.entry();
 expect(a.spent).toEqual({...before,logicalBytes:1012,uncompressedBytes:3034,processedEntries:5});
 expect(budget.usage()).toMatchObject({calls:0,transferredBytes:0,logicalBytes:12,localReads:1,uncompressedBytes:34,fsEntries:1});
 expect(()=>createImageBudget({now:a.now,credentialExpiresMs:a.now()+120000})).toThrow('ImageCredentialLifetime');
});
it.each([['cacheRead',1,'logicalBytes'],['uncompressed',1,'uncompressedBytes'],['entry',undefined,'fsEntries']])('reserves %s quota before changing parser counters', (method,value,counter)=>{
 const a=acquisition({limit:0}),budget=createPrepaidControlCacheBudget({metadataReads:a.metadataReads,now:a.now}),before={...a.spent};
 expect(()=>budget[method](value)).toThrow('PrepaidLocalQuota');expect(budget.usage()[counter]).toBe(0);expect(a.spent).toEqual(before);
 expect(()=>budget.check()).toThrow('ControlCacheBudgetHeld');
});
it('checks the original owner/source expiry through zero reservations throughout replay',()=>{
 const a=acquisition(),budget=createPrepaidControlCacheBudget({metadataReads:a.metadataReads,now:a.now});
 budget.check();expect(a.charges.length).toBeGreaterThan(0);expect(a.charges.every(c=>Object.values(c).every(n=>n===0))).toBe(true);
 a.expire();expect(()=>budget.check()).toThrow('OwnerSourceExpired');expect(()=>budget.cacheRead(1)).toThrow('ControlCacheBudgetHeld');
});
it('enforces the existing local time and concurrency limits without extending owner validity',()=>{
 const a=acquisition(),budget=createPrepaidControlCacheBudget({metadataReads:a.metadataReads,now:a.now,deadlineMs:a.now()+L.cleanupReserveMs+100});
 const release1=budget.enter(),release2=budget.enter();expect(()=>budget.enter()).toThrow('ImageConcurrencyLimit');release1();release2();expect(budget.usage().active).toBe(0);
 a.advance(100);expect(()=>budget.check()).toThrow('ControlCacheDeadline');
 expect(()=>createPrepaidControlCacheBudget({metadataReads:a.metadataReads,now:a.now,deadlineMs:a.now()+L.maxBlobTransferMs+1})).toThrow('ControlCacheDeadline');
});
it('retains descriptor, graph byte and local transfer limits',()=>{
 const a=acquisition(),budget=createPrepaidControlCacheBudget({metadataReads:a.metadataReads,now:a.now});
 expect(()=>budget.blob({mediaType:'application/vnd.oci.image.layer.v1.tar',digest:'sha256:'+'a'.repeat(64),size:L.maxBlobBytes+1})).toThrow('ImageBlobLimit');
 expect(()=>budget.cacheRead(L.maxTransferredBytes+1)).toThrow('ImageTransferLimit');
 expect(a.spent.logicalBytes).toBe(1000);
});
it('cannot debit network traffic, admit DATA/network CONTROL graphs, or be restored from JSON',async()=>{
 const a=acquisition(),budget=createPrepaidControlCacheBudget({metadataReads:a.metadataReads,now:a.now}),f=graphFixture();let called=0;
 const source={manifest(){called++;throw Error('NetworkForbidden');},blob(){called++;throw Error('NetworkForbidden');}};
 await expect(readImageGraph(f.roots,{source,store:f.store,budget})).rejects.toThrow('ControlCacheNetworkForbidden');
 const root=f.roots[0],config=JSON.parse(f.data.get(root.arm64Digest)).config;
 await expect(readControlImageGraph({account:'123456789012',region:'ap-northeast-1',repositoryName:'mem9-on-aws/bootstrap',root:root.root,arm64Digest:root.arm64Digest,configDigest:config.digest},{source,store:f.store,budget})).rejects.toThrow('ControlCacheNetworkForbidden');
 for(const call of [()=>budget.call(),()=>budget.transfer(1),()=>budget.projected({transferBytes:1,ecrCalls:0})])expect(call).toThrow('ControlCacheNetworkForbidden');
 expect(()=>assertImageBudget(JSON.parse(JSON.stringify(budget)))).toThrow('ImageBudgetRequired');expect(called).toBe(0);
 expect(a.spent.ecrRequests).toBe(7);expect(a.spent.httpBodyBytes).toBe(2000);
});
