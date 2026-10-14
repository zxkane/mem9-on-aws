import {it as test,onTestFinished} from 'vitest';
import assert from 'node:assert/strict';
import {createServer,request as localRequest} from 'node:http';
import {mkdtemp,rm,readFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {randomBytes,createHash} from 'node:crypto';
import {EventEmitter} from 'node:events';
import {Readable} from 'node:stream';
import {carrierFixture,zero} from './ci-carrier.fixture.mjs';
import {measureCarrierBeforeCopyBudget,carrierHash as hash} from './lib/ci-carrier-before-copy.mjs';
import {NONROOT_REMAINING_WORK_CAPS_V2 as CAPS,NONROOT_REMAINING_WORK_LIMITS_HASH_V2 as LIMITS} from './lib/production-nonroot-budget-revision.mjs';
import {describeCarrierLocalPolicy} from './lib/ci-carrier-local-policy.mjs';
import {openCarrierLocalCounter,carrierLocalState,closeCarrierLocalCounter,beginCarrierLocalCleanup} from './lib/ci-carrier-local-counter.mjs';
import {describeCarrierHttpPolicy,carrierHttpAdditionalBudget,carrierHttpLocalAdmission,carrierHttpCatalog,replayCarrierHttpEvents,inspectCarrierHttpEvidence} from './lib/ci-carrier-http-policy.mjs';
import {createCarrierRawHttp} from './lib/ci-carrier-http-transport.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');
async function fixture(t,handler,overrideRequest){
 const root=await mkdtemp(join(tmpdir(),'carrier-http-test-')),f=carrierFixture(),p=f.plan,v=f.template;
 v.cumulativeLimitsHash=LIMITS;v.ciLocalPolicy=describeCarrierLocalPolicy();v.fundedLocal.ci.logicalBytes=v.ciLocalPolicy.logicalBytes;v.httpPolicy=describeCarrierHttpPolicy();p.version=2;p.templateHash=hash(v);p.budget=measureCarrierBeforeCopyBudget(v).fundedRemaining;p.budgetRevision={version:2,limitsHash:LIMITS,envelopeHash:hash('test'),historyHeadHash:hash('test-history')};p.compiledCeiling=CAPS;
 const config={plan:p,grantHash:hash(randomBytes(32).toString('hex')),templateHash:p.templateHash,configHash:p.configHash,ledgerStartHash:p.ledgerStartHash},env={...f.sourceInput.env,RUNNER_TEMP:root,INPUT_GRANT_COMMITMENT:config.grantHash,INPUT_CONTEXT_COMMITMENT:p.context.sha256};
 const h=openCarrierLocalCounter({config,env}),s=carrierLocalState(h);let dispatches=0;
 const server=createServer((req,res)=>{dispatches++;handler(req,res);});server.listen(0,'127.0.0.1');await new Promise(r=>server.once('listening',r));
 const io=createCarrierRawHttp({account:s.http,deadlineMs:p.deadlineMs,request:overrideRequest??function(options,callback){assert.equal(options.protocol,'https:');assert.equal(options.hostname,'api.github.com');return localRequest({...options,protocol:'http:',hostname:'127.0.0.1',port:server.address().port,agent:false},callback);}});
 onTestFinished(async()=>{await io.close().catch(()=>{});if(!s.snapshot().closed){try{beginCarrierLocalCleanup(h);}catch{}closeCarrierLocalCounter(h,{complete:false});}server.closeAllConnections();await new Promise(r=>server.close(r));await rm(root,{recursive:true,force:true});});
 return {f,p,v,h,s,io,dispatches:()=>dispatches};
}
test('actual socket body hashes/counts and extra original parent prepayment are distinct from stdout',async t=>{
 const raw=Buffer.from(' { "ok" : true, "extra" : [1,2,3] } '),x=await fixture(t,(_req,res)=>{res.writeHead(200,{'content-length':raw.length});res.end(raw);});
 const extra=carrierHttpAdditionalBudget(x.v);assert(extra.ci.httpBodyBytes>0);const before=x.s.snapshot().spent.logicalBytes;
 const r=await x.io.request('github',{url:'https://api.github.com/repos/example/project/actions/runs/71'});assert(r.bytes.equals(raw));assert.equal(x.dispatches(),1);assert(x.s.snapshot().spent.logicalBytes>before);
 const e=x.s.http.evidence().rows.find(r=>r.id==='github');assert.equal(e.responseBytes,raw.length);assert.equal(e.requestBytes,0);
 const journal=(await readFile(join(x.s.directory,'journal.jsonl'),'utf8')).trim().split('\n').map(JSON.parse),done=journal.find(r=>r.data.http?.outcome==='complete');assert.equal(done.data.http.responseHash,sha(raw));assert.equal(done.data.http.observedResponseBytes,raw.length);
});
test('oversized raw response holds after cap+1 before decoding, although hypothetical CLI stdout could be tiny',async t=>{
 const x=await fixture(t,(_req,res)=>res.end(Buffer.alloc(65537,32)));
 await assert.rejects(x.io.request('artifact-create',{url:'https://api.github.com/twirp/test',method:'POST',body:Buffer.from('{}')}),/CarrierHttpResponseLimit/);
 assert.equal(x.dispatches(),1);const r=x.s.http.evidence().rows.find(r=>r.id==='artifact-create');assert.equal(r.responseBytes,65537);assert.equal(r.unknown,1);
 await assert.rejects(x.io.request('artifact-finalize',{url:'https://api.github.com/twirp/test',method:'POST',body:Buffer.from('{}')}));assert.equal(x.dispatches(),1);
 assert.equal((await x.io.close()).cleanupConfirmed,true);
});
test('HTTP redirect is measured then held; it cannot cause an implicit second dispatch',async t=>{
 const x=await fixture(t,(_req,res)=>{res.writeHead(302,{location:'https://unpriced.example/next'});res.end('redirect-body');});
 await assert.rejects(x.io.request('github',{url:'https://api.github.com/repos/example/project/actions/runs/71'}),/CarrierHttpStatus/);
 assert.equal(x.dispatches(),1);assert.equal(x.s.http.evidence().rows.find(r=>r.id==='github').responseBytes,13);
});
test('server retry hint and500 do not trigger retry or another slot',async t=>{
 const x=await fixture(t,(_req,res)=>{res.writeHead(500,{'retry-after':'0'});res.end('uncertain');});
 await assert.rejects(x.io.request('github',{url:'https://api.github.com/repos/example/project/actions/runs/71'}),/CarrierHttpStatus/);
 assert.equal(x.dispatches(),1);assert.equal(x.s.http.evidence().rows.find(r=>r.id==='github').unknown,1);
});
test('failed original LOCAL admission performs zero HTTP and still permits local cleanup',async t=>{
 const x=await fixture(t,(_req,res)=>res.end('{}'));x.s.reserveLocal({...zero(),logicalBytes:x.s.snapshot().normalRemaining-1});
 await assert.rejects(x.io.request('github',{url:'https://api.github.com/repos/example/project/actions/runs/71'}),/CarrierLocalLimit/);assert.equal(x.dispatches(),0);
 assert.equal((await x.io.close()).cleanupConfirmed,true);beginCarrierLocalCleanup(x.h);closeCarrierLocalCounter(x.h,{complete:false});assert(x.s.snapshot().closed);
});
test('close during pending real socket aborts/joins and records unknown once',async t=>{
 let started;const ready=new Promise(r=>started=r),x=await fixture(t,()=>started());
 const p=x.io.request('github',{url:'https://api.github.com/repos/example/project/actions/runs/71'}),settled=p.catch(e=>e);await ready;
 assert.equal((await x.io.close()).cleanupConfirmed,true);await settled;assert.equal(x.io.pending,0);assert.equal(x.s.http.evidence().rows.find(r=>r.id==='github').unknown,1);
});
test('request raw bytes are counted before send and body is snapshotted across intent await',async t=>{
 let actual;const x=await fixture(t,(req,res)=>{const chunks=[];req.on('data',b=>chunks.push(b));req.on('end',()=>{actual=Buffer.concat(chunks);res.end('{}');});});
 const body=Buffer.from('{"name":"original"}'),expected=Buffer.from(body),p=x.io.request('artifact-create',{url:'https://api.github.com/twirp/test',method:'POST',body});body.fill(0);await p;
 assert(actual.equals(expected));assert.equal(x.s.http.evidence().rows.find(r=>r.id==='artifact-create').requestBytes,expected.length);
});
test('wire replay recomputes both actor counters and rejects missing, duplicated and tampered results',async t=>{
 const x=await fixture(t,(_req,res)=>res.end('{"ok":true}'));await x.io.request('github',{url:'https://api.github.com/repos/example/project/actions/runs/71'});
 const records=(await readFile(join(x.s.directory,'journal.jsonl'),'utf8')).trim().split('\n').map(JSON.parse),events=records.filter(r=>r.data.http).map(r=>r.data.http),e=x.s.http.evidence();
 assert.deepEqual(replayCarrierHttpEvents(events,x.v,'ci').rows,e.rows);inspectCarrierHttpEvidence(e,x.v,'ci',events);
 assert.throws(()=>replayCarrierHttpEvents(events.slice(0,-1),x.v,'ci'),/CarrierHttpReplayIncomplete/);
 assert.throws(()=>replayCarrierHttpEvents([...events,events.at(-1)],x.v,'ci'),/CarrierHttpReplayPair/);
 const bad=structuredClone(e);bad.rows[0].responseBytes++;assert.throws(()=>inspectCarrierHttpEvidence(bad,x.v,'ci',events),/CarrierHttpReplayTotals/);
 const other={...e.binding,grantHash:'f'.repeat(64)};assert.throws(()=>inspectCarrierHttpEvidence(e,x.v,'ci',events,other),/CarrierHttpEvidenceBinding/);
 assert.throws(()=>replayCarrierHttpEvents(events,x.v,'ci',other),/CarrierHttpReplayBinding/);
 const versioned=structuredClone(events);versioned[0].version=2;assert.throws(()=>replayCarrierHttpEvents(versioned,x.v,'ci'),/CarrierHttpReplayBinding/);
});
test('an unknown cleanup result is latched across repeated close calls without a renewed wait',async t=>{
 let finishDestroy,ready;const started=new Promise(r=>ready=r);let response;
 const x=await fixture(t,()=>{},(_options,callback)=>{
  const req=new EventEmitter();req.closed=false;req.destroy=()=>{if(!req.closed){req.closed=true;queueMicrotask(()=>req.emit('close'));}};
  req.end=()=>queueMicrotask(()=>{response=new Readable({read(){},destroy(_e,done){finishDestroy=done;}});response.statusCode=200;response.headers={};callback(response);response.push(Buffer.from('partial'));setImmediate(ready);});return req;
 });
 const operation=x.io.request('github',{url:'https://api.github.com/repos/example/project/actions/runs/71'}),settled=operation.catch(e=>e);await started;
 const first=x.io.close(),second=x.io.close();assert.equal(first,second);await assert.rejects(first,e=>e.code==='ECLEANUP'&&e.cleanupConfirmed===false);await assert.rejects(second,/CarrierHttpCleanupUnknown/);
 finishDestroy(Error('synthetic late close'));await settled;assert.equal(x.io.pending,0);assert.equal(x.io.close(),first);await assert.rejects(x.io.close(),/CarrierHttpCleanupUnknown/);
 assert.equal(x.s.http.evidence().rows.find(r=>r.id==='github').unknown,1);
});
test('response processing exhaustion can still settle unknown using the same prepaid record pair',async t=>{
 const x=await fixture(t,(_req,res)=>res.end('{"ok":true}')),row=carrierHttpCatalog(x.v,'ci').find(r=>r.id==='artifact-create'),keep=carrierHttpLocalAdmission(row,2)+32768+8;
 x.s.reserveLocal({...zero(),logicalBytes:x.s.snapshot().normalRemaining-keep});
 await assert.rejects(x.io.request('artifact-create',{url:'https://api.github.com/twirp/test',method:'POST',body:Buffer.from('{}')}),/CarrierLocalLimit/);
 const records=(await readFile(join(x.s.directory,'journal.jsonl'),'utf8')).trim().split('\n').map(JSON.parse),events=records.filter(r=>r.data.http).map(r=>r.data.http);
 assert.equal(events.at(-1).outcome,'unknown');assert.equal(events.at(-1).hashedResponseBytes,11);inspectCarrierHttpEvidence(x.s.http.evidence(),x.v,'ci',events);
 assert.equal((await x.io.close()).cleanupConfirmed,true);assert.equal(x.dispatches(),1);
});
test('close before dispatch retains the paid intent and produces no HTTP or retry',async t=>{
 const x=await fixture(t,(_req,res)=>res.end('{}')),p=x.io.request('github',{url:'https://api.github.com/repos/example/project/actions/runs/71'}),settled=p.catch(e=>e);
 await x.io.close();await settled;assert.equal(x.dispatches(),0);const records=(await readFile(join(x.s.directory,'journal.jsonl'),'utf8')).trim().split('\n').map(JSON.parse),events=records.filter(r=>r.data.http).map(r=>r.data.http);
 assert.equal(events.at(-1).outcome,'not-dispatched');assert.equal(events.at(-1).chargedUnknownBytes,0);inspectCarrierHttpEvidence(x.s.http.evidence(),x.v,'ci',events);
});
test('the prospective normal wire addition is prepaid once while legacy budgets and unknown margin remain unchanged',()=>{
 const v=carrierFixture().template;v.cumulativeLimitsHash=LIMITS;v.ciLocalPolicy=describeCarrierLocalPolicy();v.fundedLocal.ci.logicalBytes=v.ciLocalPolicy.logicalBytes;
 const historical=JSON.stringify(v),old=measureCarrierBeforeCopyBudget(v);v.httpPolicy=describeCarrierHttpPolicy();const next=measureCarrierBeforeCopyBudget(v),extra=carrierHttpAdditionalBudget(v);
 for(const actor of ['owner','ci'])for(const k of Object.keys(zero()))assert.equal(next.fundedRemaining[actor][k]-old.fundedRemaining[actor][k],extra[actor][k]);
 assert.deepEqual(next.preFundingPreparation,old.preFundingPreparation);assert.equal(next.fundedRemaining.total.ecrRequests,old.fundedRemaining.total.ecrRequests);assert.equal(extra.owner.httpBodyBytes,137609216);
 delete v.httpPolicy;assert.equal(JSON.stringify(v),historical);assert.deepEqual(measureCarrierBeforeCopyBudget(v),old);
});
test('per-call metadata and owner plan hashing are separate from raw-body and prepaid record charges',()=>{
 const policy=describeCarrierHttpPolicy(),v=carrierFixture().template;v.httpPolicy=policy;const row=carrierHttpCatalog(v,'owner')[0];
 const common=2*policy.argumentBytes+2*row.responseBytes+8*row.requestBytes+2*(policy.requestMetadataBytes+policy.responseMetadataBytes)+(64+4*Math.ceil((row.responseBytes+1)/65536))*4096;
 assert.equal(carrierHttpLocalAdmission(row,row.requestBytes),common);assert.equal(carrierHttpLocalAdmission(row,row.requestBytes,'owner'),common+3*4*49152);
 assert.equal(policy.unknownBytes,8388608);assert.equal(policy.ownerEvidenceBytes,3*1048576);
});
