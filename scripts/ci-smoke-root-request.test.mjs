import {it,expect} from 'vitest';
import {Readable} from 'node:stream';
import {createHash} from 'node:crypto';
import {nonrootDeploymentFixture} from './production-nonroot-provenance.fixture.mjs';
import {futureRootScope} from './lib/ci-smoke-owner-delivery.mjs';
import {ciRootReadyStatus,verifyCiRootExchange,CI_ROOT_REQUEST_POLICY as P} from './lib/ci-smoke-root-request.mjs';
import {submitCiRootRequest} from './lib/ci-smoke-root-request-io.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');

async function fixture({fault,pages=false}={}){
 const d=await nonrootDeploymentFixture({now:Date.now()}),now=Date.now(),scope=futureRootScope('deploy-prod/17'),deploymentSource=d.record;
 const source={repository:'example/project',run:{id:77,attempt:1},checkout:{sha:'a'.repeat(40),tree:'b'.repeat(40)}},binding={source:{repository:source.repository,runId:77,runAttempt:1,mainRevision:source.checkout.sha,mainTree:source.checkout.tree}};
 const config={account:'123456789012',region:'us-west-2',ownerRoot:{runtimeNonce:'c'.repeat(32),authorizationId:'d'.repeat(32)},storage:{bucket:'example-artifacts',kmsKeyArn:'arn:aws:kms:us-west-2:123456789012:key/00000000-0000-0000-0000-'+'0'.repeat(12),bucketKeyEnabled:true},target:{parameterVersion:2},startup:{grantSetId:'e'.repeat(64),proofHash:deploymentSource.proofHash,descriptorHash:deploymentSource.descriptorHash,notAfter:now+300000,ownerGithubActorId:42}};
 const startupReceipt={nonce:'f'.repeat(64),artifactId:78},input={parameter:{Version:2},source,deploymentSource,targetObservation:{serviceObservation:{descriptorHash:deploymentSource.descriptorHash,parameterVersion:2}}},records=[],calls=[];let local=0,count=0;
 const save=async(name,value)=>{const bytes=value instanceof Uint8Array?Buffer.from(value):Buffer.from(JSON.stringify(value));const ref={path:'/fixture/'+name+'.json',sha256:sha(bytes)};records.push({name,ref,bytes});return ref;};
 const requestHandler={async handle(q){calls.push(q);expect(q.headers.authorization).toContain('ASIA'+'A'.repeat(16));expect(records.some(r=>r.name==='root-put-dispatch')).toBe(true);if(fault==='unknown-put')throw Error('synthetic unknown');
  const body=Buffer.alloc(fault==='put-overflow'?P.responseBytes+1:0,32);return {response:{statusCode:200,headers:{'content-length':String(body.length),'x-amz-server-side-encryption':'aws:kms','x-amz-server-side-encryption-aws-kms-key-id':config.storage.kmsKeyArn,'x-amz-server-side-encryption-bucket-key-enabled':'true'},body:Readable.from([body])}};
 },destroy(){}};
 const githubRequest=async q=>{count++;const expected=ciRootReadyStatus(config,scope,'0'.repeat(64)),rows=pages&&count===1?Array.from({length:100},(_,i)=>({context:'unrelated-'+i})): [{...expected,creator:{id:fault==='wrong-owner'?43:42}}];
  expect(q.path.endsWith('page='+count)).toBe(true);const raw=Buffer.from('  '+JSON.stringify(rows)+' \n'),response=Readable.from([raw]);response.statusCode=200;response.headers={'content-length':String(raw.length)};return response;};
 const options={env:{AWS_ACCESS_KEY_ID:'ASIA'+'A'.repeat(16),AWS_SECRET_ACCESS_KEY:'B'.repeat(40),AWS_SESSION_TOKEN:'synthetic-session',GH_TOKEN:'synthetic-github'},config,scope,binding,startupReceipt,check(){},chargeLocal:n=>{local+=n;expect(local).toBeLessThanOrEqual(P.localBytes);},save,deadlineMs:now+240000,requestHandler,githubRequest,sleep:async()=>{throw Error('unexpected poll');}};
 const run=async()=>{const result=await submitCiRootRequest(input,options);return {version:1,...result,records:records.map(({name,ref})=>({name,ref}))};};
 const expected=()=>({config,scope,binding,startupReceipt,openedMs:now,completedMs:Date.now(),deadlineMs:options.deadlineMs,deploymentSource});
 return {run,records,calls,expected,get local(){return local;}};
}

it('actual signed PUT and all ready pages replay exact padded raw bytes with one original CI session',async()=>{
 const f=await fixture({pages:true}),exchange=await f.run(),r=verifyCiRootExchange(exchange,f.records,f.expected());
 expect(r.readyCalls).toBe(2);expect(r.observedWireBytes).toBe(exchange.observedWireBytes);expect(f.calls).toHaveLength(1);expect(f.local).toBeGreaterThan(0);
 const wire=f.records.filter(r=>r.name==='root-request'||/root-ready-\d+-response/.test(r.name)).reduce((n,r)=>n+r.bytes.length,0);expect(exchange.observedWireBytes).toBe(wire);
 expect(JSON.stringify(f.records.map(r=>r.bytes.toString()))).not.toContain('synthetic-session');
});
it.each(['unknown-put','put-overflow','wrong-owner'])('%s cannot yield successful exchange or retry the PUT',async fault=>{
 const f=await fixture({fault});await expect(f.run()).rejects.toThrow();expect(f.calls).toHaveLength(1);expect(f.records.at(-1).name).toBe('root-request-held');
});
it('closed replay rejects changed bytes, missing/duplicate dispatch, wrong cap and modified charge even after rehash',async()=>{
 const f=await fixture(),exchange=await f.run(),expected=f.expected();
 for(const mutate of [
  rows=>{rows[0].bytes=Buffer.from('{}');},
  rows=>{rows.splice(2,1);},
  rows=>{rows[2]=structuredClone(rows[1]);},
  rows=>{const row=rows[1],v=JSON.parse(row.bytes);v.responseCap++;row.bytes=Buffer.from(JSON.stringify(v));row.ref.sha256=sha(row.bytes);},
  rows=>{const row=rows[3],v=JSON.parse(row.bytes);v.observedWireBytes--;row.bytes=Buffer.from(JSON.stringify(v));row.ref.sha256=sha(row.bytes);},
 ]){const rows=f.records.map(r=>({...r,ref:{...r.ref},bytes:Buffer.from(r.bytes)}));mutate(rows);const changed={...exchange,records:rows.map(({name,ref})=>({name,ref}))};expect(()=>verifyCiRootExchange(changed,rows,expected)).toThrow();}
});
