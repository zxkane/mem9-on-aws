import {test} from 'vitest';
import assert from 'node:assert/strict';
import {compileOriginalIssuersBudget,originalIssuerSlot,inspectOriginalIssuerPlan,verifyOriginalIssuerJournal} from './lib/production-nonroot-original-issuer-accounting.mjs';
import {hash,sha} from './lib/ci-smoke-acquisition-format.mjs';

// Synthetic portable replay data only. No credentials, payment or live issuer.
function fixture(){
 const account='123456789012',owner='a'.repeat(32),region='us-east-1';
 const source={profile:'default',provider:'static-temporary',configFile:'/synthetic/config',credentialsFile:'/synthetic/credentials',configHash:hash('config'),credentialsHash:hash('credentials')};
 const binding={owner,executionId:'b'.repeat(32),planHash:hash('copy-config'),publicationHash:hash('publication')};
 const sourceTags={usage:'codex-mem9-on-aws',User:'synthetic-user',Host:'synthetic-host',Project:'mem9-on-aws'};
 const identities={sourceRoleArn:`arn:aws:iam::${account}:role/SyntheticSource`,targetRoleArn:`arn:aws:iam::${account}:role/SyntheticTarget`};
 const plan={version:1,kind:'original-issuer-plan',slot:originalIssuerSlot('copy',source.provider),source,binding,ledgerStartHash:hash('original-start'),scope:{account,personalAccount:'0'.repeat(12),owner,region},identities,stsRegion:region,sourceTags,deadlineMs:10000};
 const planHash=inspectOriginalIssuerPlan(plan).planHash,debitEventHash=hash('synthetic-debit'),records=[];
 const add=(kind,data)=>{const row={version:1,sequence:records.length+1,previousHash:records.length?hash(records.at(-1)):null,planHash,kind,data};records.push(row);return row;};
 let requestBytes=0,responseBytes=0,ordinal=0;
 const invoke=(key,request,snapshotHash)=>{
  const op=plan.slot.operations[ordinal++],wire=JSON.stringify(request),wireRequestHash=sha(wire);
  const row=add('request',{key,ordinal,action:op.action,requestHash:hash(request),snapshotHash,request,wireRequestHash,caps:{requestBytes:op.requestBytes,responseBytes:op.responseBytes},atMs:ordinal*100});
  const n=Buffer.byteLength(wire);requestBytes+=n;responseBytes+=100;
  add('response',{requestSequence:row.sequence,key,requestBytes:n,responseBytes:100,requestHash:wireRequestHash,responseHash:hash('synthetic-response-'+ordinal),statusCode:200,dispatched:true,complete:true,atMs:ordinal*100+1});
 };
 const read=['ecr:BatchGetImage','ecr:GetDownloadUrlForLayer'];
 const destination=[...read,'ecr:BatchCheckLayerAvailability','ecr:InitiateLayerUpload','ecr:UploadLayerPart','ecr:CompleteLayerUpload','ecr:PutImage','ecr:DescribeImageScanFindings','ecr:StartImageScan'];
 const prefix=`arn:aws:ecr:${region}:${account}:repository/mem9-on-aws/`,components=['llm-proxy','mnemo-server','qwen3-embed'];
 const dest=components.map(c=>prefix+c),src=components.map(c=>prefix+'preview/'+c),actions=[...destination,'sts:GetCallerIdentity'];
 const Policy=JSON.stringify({Version:'2012-10-17',Statement:[{Effect:'Allow',Action:actions,Resource:'*'},{Effect:'Deny',NotAction:actions,Resource:'*'},{Effect:'Deny',Action:'ecr:*',NotResource:[...src,...dest]},{Effect:'Deny',Action:destination.slice(2),Resource:src}]});
 const sourceHash=hash('source-snapshot'),targetHash=hash('target-snapshot'),name='codex-mem9-on-aws-image-staging-synthetic';
 const targetArn=`arn:aws:sts::${account}:assumed-role/SyntheticTarget/${name}`;
 add('opened',{planHash,debitEventHash});
 add('source-snapshot',{configHash:hash('source-config'),credentialsHash:sourceHash});
 invoke('source-identity',{},sourceHash);
 add('identity',{profile:'default',account,arn:`arn:aws:sts::${account}:assumed-role/SyntheticSource/synthetic`});
 invoke('assume',{RoleArn:identities.targetRoleArn,RoleSessionName:name,DurationSeconds:3600,Tags:Object.entries(sourceTags).map(([Key,Value])=>({Key,Value})),TransitiveTagKeys:Object.keys(sourceTags),Policy},sourceHash);
 add('target-snapshot',{configHash:hash('target-config'),credentialsHash:targetHash,expiresMs:5000,arn:targetArn});
 invoke('target-identity',{},targetHash);
 add('identity',{profile:'cc-tracked',account,arn:targetArn});
 const rawBytes=requestBytes+responseBytes,normalBytes=rawBytes*8+2*records.reduce((sum,r)=>sum+Buffer.byteLength(JSON.stringify(r)+'\n'),0)+4096;
 add('released',{cleanupComplete:true,usageBeforeTerminal:{normalBytes,cleanupBytes:1024,fileNormal:8,fileCleanup:2,normalRecords:records.length,cleanupRecords:0,rawBytes,observed:{requestBytes,responseBytes},unknownBytes:0,held:false,next:3}});
 return {evidence:{plan,records},expected:{binding,sourceHash:hash(source),deadlineMs:plan.deadlineMs,debitEventHash}};
}
function rechain(e){let previous=null;for(const [i,row]of e.records.entries()){row.sequence=i+1;row.previousHash=previous;previous=hash(row);}}

test('original issuer compiler preserves metadata/static fixed SUM and independent LOCAL cleanup',()=>{
 const {evidence:{plan}}=fixture();
 for(const provider of ['instance-metadata','static-temporary']){
  const b=compileOriginalIssuersBudget({source:{...plan.source,provider}});
  assert.equal(b.charge.httpBodyBytes,provider==='instance-metadata'?17604608:17465344);
  assert.equal(b.charge.logicalBytes,33554432);assert.equal(b.charge.ecrRequests,0);
  assert.deepEqual(b.slots.map(s=>s.durationSeconds),[900,3600]);
  assert(b.slots.every(s=>s.limits.cleanupLocalBytes===2097152&&s.limits.localBytes===16777216));
  assert(Object.isFrozen(b)&&Object.isFrozen(b.slots));
 }
});
test('portable successful journal uses plan-bound synthetic roles and reports usage separately from prepayment',()=>{
 const {evidence,expected}=fixture(),r=verifyOriginalIssuerJournal(evidence,expected);
 assert.equal(r.authority,false);assert.equal(r.planHash,hash(evidence.plan));assert.equal(r.debitEventHash,expected.debitEventHash);
 assert(r.requestBytes+r.responseBytes<r.charge.httpBodyBytes);assert.equal(r.journalHash,hash(evidence.records.at(-1)));
});
test('independent original binding, source, deadline and debit mismatches all fail',()=>{
 const {evidence,expected}=fixture();
 for(const changed of [{...expected,binding:{...expected.binding,executionId:'c'.repeat(32)}},{...expected,sourceHash:hash('other-source')},{...expected,deadlineMs:9999},{...expected,debitEventHash:hash('other-debit')}])assert.throws(()=>verifyOriginalIssuerJournal(evidence,changed));
});
test('rehashed missing, duplicated or reordered original issuance events fail',()=>{
 for(const mutate of [r=>r.shift(),r=>r.pop(),r=>r.splice(3,0,structuredClone(r[3])),r=>{[r[5],r[6]]=[r[6],r[5]];}]){
  const {evidence,expected}=fixture();mutate(evidence.records);rechain(evidence);assert.throws(()=>verifyOriginalIssuerJournal(evidence,expected));
 }
});
test('closed rows reject extra authority fields even after recomputing the chain',()=>{
 for(const kind of ['opened','source-snapshot','request','response','identity','target-snapshot','released']){
  const {evidence,expected}=fixture();evidence.records.find(r=>r.kind===kind).data.authority=true;rechain(evidence);assert.throws(()=>verifyOriginalIssuerJournal(evidence,expected));
 }
 const {evidence,expected}=fixture();evidence.authority=true;assert.throws(()=>verifyOriginalIssuerJournal(evidence,expected));
});
test('LOCAL summary cannot hide negative bytes, missing raw work, record counts or terminal cleanup',()=>{
 for(const mutate of [u=>u.normalBytes=-1,u=>u.cleanupBytes=-1,u=>u.normalBytes=0,u=>u.rawBytes--,u=>u.normalRecords--,u=>u.cleanupRecords++,u=>u.fileCleanup=5,u=>u.cleanupBytes=2097152,u=>u.unknownBytes=8388608,u=>u.held=true,u=>u.observed.responseBytes--]){
  const {evidence,expected}=fixture();mutate(evidence.records.at(-1).data.usageBeforeTerminal);rechain(evidence);assert.throws(()=>verifyOriginalIssuerJournal(evidence,expected));
 }
});
test('fixed source/source/target sequence rejects snapshot, policy, status, expiry and request substitution',()=>{
 for(const mutate of [
  r=>r.find(x=>x.kind==='request'&&x.data.key==='target-identity').data.snapshotHash=hash('source-snapshot'),
  r=>r.find(x=>x.kind==='request'&&x.data.key==='assume').data.request.Policy='{}',
  r=>r.find(x=>x.kind==='request').data.caps.responseBytes++,
  r=>r.find(x=>x.kind==='response').data.statusCode=403,
  r=>r.find(x=>x.kind==='response').data.complete=false,
  r=>r.find(x=>x.kind==='target-snapshot').data.expiresMs=250,
  r=>r.find(x=>x.kind==='request').data.atMs=10000,
  r=>r.at(-1).data.cleanupComplete=false,
 ]){const {evidence,expected}=fixture();mutate(evidence.records);rechain(evidence);assert.throws(()=>verifyOriginalIssuerJournal(evidence,expected));}
});
test('plan cannot extend fixed budget or cross the original account with a role field',()=>{
 for(const mutate of [p=>p.slot.operations[0].count++,p=>p.slot.limits.localBytes++,p=>p.identities.targetRoleArn='arn:aws:iam::'+('0'.repeat(12))+':role/SyntheticTarget',p=>p.identities.authority=true]){
  const {evidence}=fixture(),p=structuredClone(evidence.plan);mutate(p);assert.throws(()=>inspectOriginalIssuerPlan(p));
 }
});
