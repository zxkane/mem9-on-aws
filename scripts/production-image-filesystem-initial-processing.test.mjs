import {it,expect} from 'vitest';
import {readImageGraph} from './lib/production-image-graph.mjs';
import {inspectImageFilesystem} from './lib/production-image-filesystem.mjs';
import {graphFixture} from './production-image.fixture.mjs';

async function setup(){
 const fixture=graphFixture(),graph=await readImageGraph(fixture.roots,{...fixture});
 return {graph,options:{component:'llm-proxy',budget:fixture.budget}};
}
const frozen=value=>!value||typeof value!=='object'||Object.isFrozen(value)&&Object.values(value).every(frozen);

it('TC-CONS-IMAGE-125 prepays initial freezing with numeric inputs and preserves the complete evidence',async()=>{
 const {graph,options}=await setup(),baseline=await inspectImageFilesystem(graph,options);
 const amounts=[];let exposed=0;const current=()=>{};
 const result=await inspectImageFilesystem(graph,{...options,
  beforeFreeze:async(...args)=>{expect(args).toHaveLength(1);expect(Number.isSafeInteger(args[0])).toBe(true);expect(args[0]).toBeGreaterThan(0);amounts.push(args[0]);return current;},
  beforeRead:async entries=>{
   exposed++;expect(amounts.length).toBeGreaterThan(0);expect(frozen(entries)).toBe(true);
   expect(()=>{entries[0].path='changed';}).toThrow();return current;
  },
 });
 expect(exposed).toBe(1);expect(amounts.length).toBeGreaterThan(1);expect(result.evidence).toEqual(baseline.evidence);
});

it('TC-CONS-IMAGE-125 denied initial payment prevents entry exposure and evidence creation',async()=>{
 const {graph,options}=await setup(),failure=Error('SyntheticProcessingDenied');let exposed=false;
 await expect(inspectImageFilesystem(graph,{...options,beforeFreeze:async()=>{throw failure;},beforeRead:async()=>{exposed=true;return()=>{};}})).rejects.toThrow(failure);
 expect(exposed).toBe(false);
});

for(const phase of ['freeze','hash'])it('TC-CONS-IMAGE-125 checks the original guard after awaited '+phase+' payment',async()=>{
 const {graph,options}=await setup();let closed=false;
 const current=()=>{if(closed)throw Error('SyntheticProcessingClosed');};
 const closeAfterFulfillment=()=>{const pending=Promise.resolve(current);pending.then(()=>{closed=true;});return pending;};
 await expect(inspectImageFilesystem(graph,{...options,
  beforeFreeze:phase==='freeze'?closeAfterFulfillment:async()=>current,
  beforeRead:phase==='hash'?closeAfterFulfillment:async()=>current,
 })).rejects.toThrow('SyntheticProcessingClosed');
});

it('TC-CONS-IMAGE-125 requires both initial processing callbacks',async()=>{
 const {graph,options}=await setup();
 for(const hooks of [{beforeRead:async()=>()=>{}},{beforeFreeze:async()=>()=>{}}])
  await expect(inspectImageFilesystem(graph,{...options,...hooks})).rejects.toThrow('ImageFilesystemProcessingRequired');
});

it('TC-CONS-IMAGE-125 rejects absent and asynchronous initial continuation guards',async()=>{
 for(const guard of [undefined,async()=>{}]){
  const {graph,options}=await setup();
  await expect(inspectImageFilesystem(graph,{...options,beforeFreeze:async()=>guard,beforeRead:async()=>()=>{}})).rejects.toThrow('ImageFilesystemSynchronousPayment');
 }
});
