import {it,expect,beforeAll} from 'vitest';
import {mkdtempSync,writeFileSync,readFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
import {CI_ROOT_COST_MODEL as M,ciRootCountingCostBound,calculateCiRootRequestCost,calculateCiRootRequestPlanCost,projectCiRootRequestCost,verifyCiRootCostCheckpoints} from './lib/ci-smoke-root-request-cost.mjs';
import {nonrootHash as hash} from './lib/production-nonroot-contracts.mjs';
import {CI_ROOT_REQUEST_POLICY as P,selectCiRootControlOriginals,createCiRootRequest,encodeCiRootRequest} from './lib/ci-smoke-root-request.mjs';
import {NONROOT_REMAINING_WORK_CAPS_V2 as CAPS} from './lib/production-nonroot-budget-revision.mjs';
import {NONROOT_FINALIZATION_LIMITS} from './lib/production-nonroot-finalization-accounting.mjs';
import {parseAcquisitionJson} from './lib/ci-smoke-acquisition-format.mjs';
import {rootOriginalsFixture} from './ci-smoke-root-originals.fixture.mjs';
const MiB=1048576,sha=b=>createHash('sha256').update(b).digest('hex');
const zero=()=>({ecrRequests:0,logicalBytes:0,httpBodyBytes:0,uncompressedBytes:0,processedEntries:0});
let fixture,originals;
beforeAll(async()=>{fixture=await rootOriginalsFixture();originals=await selectCiRootControlOriginals({archive:fixture.archive,...fixture.input,chargeLocal:()=>{}});});

it('quotes one prepayment and unchanged maximum request, ready wire, calls and error caps',()=>{
 const q=calculateCiRootRequestCost();
 expect(q.bounds).toMatchObject({requestBytes:MiB,readyWireBytes:8*MiB,readyCalls:128,readyResponseBytes:MiB,putResponseBytes:16384,unknownBytes:8*MiB});
 expect(q.journal.rows).toBe(1);expect(q.counting.batches).toBe(5);
 expect(q.work.transport).toBe(6*8*MiB+8*16384+8*MiB);
 expect(q.logicalBytes).toBe(Object.values(q.work).reduce((a,b)=>a+b,0));
 expect(q.roundedLocalBytes).toBe(Math.ceil(q.logicalBytes/MiB)*MiB);expect(q.roundingBytes).toBeLessThan(MiB);
 expect(q.fitsCurrentLocal).toBe(false);expect(q.executionReady).toBe(false);expect(q.authority).toBe(false);
 expect(Object.isFrozen(q.work)).toBe(true);expect(P.localBytes).toBe(32*MiB);
 expect(NONROOT_FINALIZATION_LIMITS.localBytes).toBe(1024*MiB);expect(NONROOT_FINALIZATION_LIMITS.cleanupLocalBytes).toBe(16*MiB);
});

it('covers all 128 metadata pairs and the complete exchange index including body references',()=>{
 const r=calculateCiRootRequestCost().records;
 expect(r.exchangeRows).toBe(388);
 expect(r.ordinary).toBe(r.putIntent+r.putDispatch+r.putComplete+128*(r.readyIntent+r.readyComplete)+r.exchange+r.accounting);
 expect(Math.max(r.putIntent,r.putDispatch,r.putComplete,r.readyIntent,r.readyComplete,r.checkpoint)).toBeLessThanOrEqual(MiB);
 expect(r.exchange).toBeLessThanOrEqual(32*MiB);
});

it('metadata bound covers worst escaping, longest closed names and safe-integer widths',()=>{
 const q=calculateCiRootRequestCost(),n=Number.MAX_SAFE_INTEGER,ref={path:'\x01'.repeat(M.referencePathBytes),sha256:'f'.repeat(64)};
 const localRef={path:'root-ready-128-complete.json',sha256:'f'.repeat(64)};expect(Buffer.byteLength(JSON.stringify(ref))).toBe(q.records.ref);
 const complete={intentRef:localRef,responseRef:localRef,status:n,responseHash:'f'.repeat(64),responseBytes:n,completedMs:n};
 expect(Buffer.byteLength(JSON.stringify(complete))).toBe(q.records.readyComplete);
 const exchange={version:n,archiveHash:'f'.repeat(64),requestRef:localRef,observedWireBytes:n,records:Array.from({length:q.records.exchangeRows},()=>({name:'root-ready-128-complete',ref:localRef})),localAccountingRef:localRef};
 expect(Buffer.byteLength(JSON.stringify(exchange))).toBe(q.records.exchange);
});

it('bounds journal serialization, terminal read and one replay and bounded intermediate journal hash guards without recursive rows',()=>{
 const q=calculateCiRootRequestCost({checkpoint:'deploy-prod/17'}),dir=mkdtempSync(join(tmpdir(),'root-cost-'));
 try{
  const path=join(dir,'local.ndjson'),value={...zero(),logicalBytes:q.roundedLocalBytes};
  // Same five-counter record as the existing localJournal. This is an offline
  // accounting fixture, not a funded acquisition, source proof or native token.
  const bytes=Buffer.from(JSON.stringify(value)+'\n');expect(bytes.length).toBeLessThanOrEqual(q.journal.rowBytes);
  expect(Buffer.byteLength(JSON.stringify({...zero(),logicalBytes:Number.MAX_SAFE_INTEGER})+'\n')).toBe(q.journal.rowBytes);
  writeFileSync(path,bytes,{mode:0o600,flag:'wx'});
  const terminal=readFileSync(path),pin=sha(terminal);expect(terminal.toString().split('\n').filter(Boolean)).toHaveLength(1);
  for(let i=0;i<q.journal.replayPasses;i++){
   const immutable=readFileSync(path);expect(sha(immutable)).toBe(pin);
   const replay=readFileSync(path,'utf8').slice(0,-1).split('\n').map(line=>parseAcquisitionJson(Buffer.from(line)));
   expect(replay).toEqual([value]);
  }
  expect(q.journal.localBytes).toBe(q.journal.rowBytes*(4+16+200002));
 }finally{rmSync(dir,{recursive:true,force:true});}
});

it('one prepaid row covers actual maximum-size preparation and full readiness without per-node or per-chunk journal writes',async()=>{
 const q=calculateCiRootRequestCost(),rows=[],used=Object.fromEntries(Object.keys(q.work).map(k=>[k,0]));
 rows.push({...zero(),logicalBytes:q.roundedLocalBytes});
 let callbackCount=0;const consume=stage=>n=>{callbackCount++;used[stage]+=n;expect(used[stage]).toBeLessThanOrEqual(q.work[stage]);};
 const controlOriginals=await selectCiRootControlOriginals({archive:fixture.archive,...fixture.input,chargeLocal:consume('selection')});
 const base=createCiRootRequest({...fixture.input,controlOriginals}),targetObservation={...base.targetObservation,padding:''};
 targetObservation.padding='x'.repeat(MiB-Buffer.byteLength(JSON.stringify({...base,targetObservation})));
 const value=createCiRootRequest({...fixture.input,controlOriginals,targetObservation},{chargeLocal:consume('request')});
 const raw=encodeCiRootRequest(value,{chargeLocal:consume('request')});expect(raw.length).toBe(MiB);consume('request')(2*raw.length);
 // 128 calls, total 8 MiB, arbitrarily split chunks. No per-call maximum is
 // multiplied into the aggregate wire price; incomplete terminal data is not parsed.
 for(let call=0;call<128;call++){
  const bytes=64*1024;for(let offset=0;offset<bytes;offset+=113)consume('transport')(Math.min(113,bytes-offset));
  consume('transport')(5*bytes);
 }
 consume('transport')(8*P.responseBytes);consume('transport')(P.unknownBytes);
 expect(used.transport).toBe(q.work.transport);expect(callbackCount).toBeGreaterThan(13000);expect(rows).toHaveLength(1);
 expect(Object.values(used).reduce((a,b)=>a+b,0)).toBeLessThan(q.roundedLocalBytes);
});

it.each(['dense','escaped','node-rejection','oversize-rejection'])('preparation envelope covers %s without success-only coupling',defect=>{
 const targetObservation={...fixture.input.targetObservation};
 if(defect==='dense')targetObservation.padding=Array(90000).fill(0);
 if(defect==='escaped')targetObservation.padding='\x01'.repeat(100000);
 if(defect==='node-rejection')targetObservation.padding=Array(100001).fill(0);
 if(defect==='oversize-rejection')targetObservation.padding='x'.repeat(MiB);
 const q=calculateCiRootRequestCost();let used=0;
 const run=()=>createCiRootRequest({...fixture.input,controlOriginals:originals,targetObservation},{chargeLocal:n=>{used+=n;expect(used).toBeLessThanOrEqual(q.work.request);}});
 if(defect.endsWith('rejection'))expect(run).toThrow();else expect(run().version).toBe(2);
 expect(used).toBeGreaterThan(0);
});

it.each([0,-1,NaN,Infinity,1.5,Number.MAX_SAFE_INTEGER])('rejects invalid counting cap %s',n=>{
 expect(()=>ciRootCountingCostBound(n)).toThrow('CiRootCostInput');
});

it('prices all five new root slots once, without changing old policies or granting authority',()=>{
 const q=calculateCiRootRequestPlanCost();expect(q.slots.map(s=>s.checkpoint)).toEqual(['deploy-prod/9','deploy-prod/17','deploy-prod/19','deploy-prod/21','deploy-prod/23']);
 expect(q.slots[0].work.selection).toBe(0);expect(q.slots[4].work.selection).toBeGreaterThan(0);expect(q.slots.map(s=>s.replay.entries)).toEqual([0,1,1,0,0]);expect(q.slots.map(s=>s.replay.contentScans)).toEqual([0,2,2,0,0]);expect(q.slots.every(s=>s.replay.intermediateRootReads===0)).toBe(true);
 expect(q.prospectiveLocalBytes).toBe(q.slots.reduce((n,s)=>n+s.roundedLocalBytes,0));
 expect(q.additionalLocalBytes).toBe(q.prospectiveLocalBytes-5*32*MiB);
 expect(q.globalLogicalCap).toBe(64*1024*MiB);expect(q.executionReady).toBe(false);
});

it('checks the exact original global-cap boundary; a one-byte excess fails and no other counter gets credit',()=>{
 const q=calculateCiRootRequestPlanCost(),base={...zero(),logicalBytes:CAPS.logicalBytes-q.additionalLocalBytes};
 const result=projectCiRootRequestCost(base);expect(result.fitsOriginalCaps).toBe(true);expect(result.projected.logicalBytes).toBe(CAPS.logicalBytes);
 expect(projectCiRootRequestCost({...base,logicalBytes:base.logicalBytes+1}).fitsOriginalCaps).toBe(false);
 expect(projectCiRootRequestCost({...base,ecrRequests:CAPS.ecrRequests+1}).fitsOriginalCaps).toBe(false);
 for(const key of Object.keys(base).filter(k=>k!=='logicalBytes'))expect(result.projected[key]).toBe(base[key]);
 expect(result.authority).toBe(false);expect(result.executionReady).toBe(false);
});

it('does not accept missing, malformed or absent-old-price projections',()=>{
 expect(()=>projectCiRootRequestCost(zero())).toThrow();
 expect(()=>projectCiRootRequestCost({logicalBytes:CAPS.logicalBytes})).toThrow();
 expect(()=>projectCiRootRequestCost({...zero(),logicalBytes:NaN})).toThrow();
});

function checkpoints(){
 const q=calculateCiRootRequestCost(),claimRef={path:'/fixture/original-claim.json',sha256:'a'.repeat(64)},scopeHash='b'.repeat(64),requestHash='c'.repeat(64),used=Object.fromEntries(Object.keys(q.work).map(k=>[k,0]));
 const expected={claimRef,scopeHash,requestHash,debit:{...zero(),logicalBytes:q.roundedLocalBytes}},rows=[];let previousHash=null;
 for(const [i,stage] of Object.keys(q.work).entries()){
  used[stage]=q.work[stage];const row={version:1,claimRef,scopeHash,catalogHash:hash(q),requestHash:i?requestHash:null,sequence:i+1,stage,used:{...used},previousHash,held:false};rows.push(row);previousHash=hash(row);
 }
 return {q,expected,rows};
}
function rechain(rows){for(let i=0;i<rows.length;i++)rows[i].previousHash=i?hash(rows[i-1]):null;}

it('replays bounded checkpoints against the original full debit, never treating unused credit as a refund',()=>{
 const {q,expected,rows}=checkpoints(),r=verifyCiRootCostCheckpoints(rows,expected);
 expect(r.held).toBe(false);expect(r.used).toEqual(q.work);expect(r.unusedForfeited).toBe(q.roundingBytes);
 expect(r.debit).toEqual(expected.debit);expect(r.authority).toBe(false);expect(r.executionReady).toBe(false);
});

it('early held selection retains the complete charge; later checkpoint cannot reopen it',()=>{
 const {expected,rows}=checkpoints();expected.requestHash=null;rows[0].held=true;
 const result=verifyCiRootCostCheckpoints(rows.slice(0,1),expected);expect(result.held).toBe(true);expect(result.debit).toEqual(expected.debit);
 rows[1].requestHash=null;rows[1].held=true;rechain(rows);
 expect(()=>verifyCiRootCostCheckpoints(rows.slice(0,2),expected)).toThrow('CiRootCostCheckpointOrder');
});

it.each(['claim','scope','catalog','request','discounted-debit','decreasing-use','overdraw','extra-bucket','missing-terminal','extra-checkpoints'])('rejects checkpoint %s tampering',defect=>{
 const {q,expected,rows}=checkpoints();
 if(defect==='claim')rows[0].claimRef={...rows[0].claimRef,sha256:'d'.repeat(64)};
 if(defect==='scope')rows[0].scopeHash='d'.repeat(64);
 if(defect==='catalog')rows[0].catalogHash='d'.repeat(64);
 if(defect==='request')rows[2].requestHash='d'.repeat(64);
 if(defect==='discounted-debit')expected.debit.logicalBytes--;
 if(defect==='decreasing-use')rows[1].used.selection--;
 if(defect==='overdraw')rows[1].used.request=q.work.request+1;
 if(defect==='extra-bucket')rows[1].used.borrowed=1;
 if(defect==='missing-terminal')rows.pop();
 if(defect==='extra-checkpoints')while(rows.length<=M.checkpointCount)rows.push(structuredClone(rows.at(-1)));
 rechain(rows);expect(()=>verifyCiRootCostCheckpoints(rows,expected)).toThrow();
});
