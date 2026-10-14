import {it,expect,beforeAll,vi} from 'vitest';
import {rootOriginalsFixture} from './ci-smoke-root-originals.fixture.mjs';
import {nonrootHash as hash} from './lib/production-nonroot-contracts.mjs';
import {createNonrootEvidenceArchive} from './lib/production-nonroot-archive.mjs';
import {futureRootScope} from './lib/ci-smoke-owner-delivery.mjs';
import {createCiRootRequest,encodeCiRootRequest,decodeCiRootRequest,verifyCiRootRequest,selectCiRootControlOriginals,inspectCiRootControlOriginals,CI_ROOT_REQUEST_BYTES,CI_ROOT_REQUEST_POLICY} from './lib/ci-smoke-root-request.mjs';
import {submitCiRootRequest} from './lib/ci-smoke-root-request-io.mjs';
import {ciRootReadyStatus,verifyCiRootExchange} from './lib/ci-smoke-root-request.mjs';
import {Readable} from 'node:stream';
import {createHash} from 'node:crypto';
let f,rows,request;
beforeAll(async()=>{f=await rootOriginalsFixture();rows=await selectCiRootControlOriginals({archive:f.archive,...f.input,chargeLocal:()=>{}});request=createCiRootRequest({...f.input,controlOriginals:rows});});

it('final v2 selects all seven original inventory objects including reused records and preserves newlines',async()=>{
 let local=0;const selected=await selectCiRootControlOriginals({archive:f.archive,...f.input,chargeLocal:n=>{local+=n;}});
 expect(selected).toEqual(rows);expect(selected).toHaveLength(7);expect(f.reads.length).toBe(14);
 const encoded=Buffer.from(JSON.stringify(request));expect(encoded.length).toBeLessThanOrEqual(CI_ROOT_REQUEST_BYTES);
 const decoded=decodeCiRootRequest(encoded,{...f.expected,chargeLocal:n=>{local+=n;}});
 expect(decoded.version).toBe(2);const originals=inspectCiRootControlOriginals(decoded.controlOriginals,{...decoded,chargeLocal:n=>{local+=n;}});
 for(const row of originals){expect(row.bytes.at(-1)).toBe(10);expect(row.bytes).toEqual(f.rows.find(x=>hash(x.ref)===hash(row.ref)).bytes);}
 expect(local).toBeGreaterThan(0);expect(CI_ROOT_REQUEST_POLICY.version).toBe(1);
});

it.each(['deploy-prod/9','deploy-prod/17','deploy-prod/19','deploy-prod/21'])('%s preserves exact v1 encoding',checkpoint=>{
 const scope=futureRootScope(checkpoint),input={...f.input,scope};let charged=0;
 const value=createCiRootRequest(input,{chargeLocal:()=>{charged++;}});
 const expected={version:1,kind:'ci-prepaid-root-audit-request',bindingHash:hash(input.binding),scope,nonce:input.startupReceipt.nonce,artifactId:input.startupReceipt.artifactId,proofHash:input.config.startup.proofHash,descriptorHash:input.config.startup.descriptorHash,parameterVersion:2,source:input.source,deploymentSource:input.deploymentSource,targetObservation:input.targetObservation,requestedMs:input.requestedMs};
 expect(JSON.stringify(value)).toBe(JSON.stringify(expected));expect(charged).toBe(0);
 expect(()=>createCiRootRequest({...input,controlOriginals:rows})).toThrow('CiRootOriginalScope');
});

const defects={missing:v=>v.controlOriginals.pop(),extra:v=>v.controlOriginals.push(v.controlOriginals[0]),duplicate:v=>{v.controlOriginals[2]=v.controlOriginals[3];},purpose:v=>{v.controlOriginals[2].purpose='source';},ref:v=>{v.controlOriginals[0].ref.bytesHash='f'.repeat(64);},hash:v=>{v.controlOriginals[0].base64=Buffer.alloc(v.controlOriginals[0].ref.bytesLength,32).toString('base64');},base64:v=>{v.controlOriginals[0].base64='!'+v.controlOriginals[0].base64.slice(1);},downgrade:v=>{v.version=1;delete v.controlOriginals;},'extra-row-field':v=>{v.controlOriginals[0].path='/not-an-input';},canonical:v=>{v.controlOriginals[0].ref.canonicalHash='f'.repeat(64);}};
it.each(Object.keys(defects))('%s cannot cross the final request decoder',name=>{
 const value=structuredClone(request);defects[name](value);expect(()=>decodeCiRootRequest(Buffer.from(JSON.stringify(value)),f.expected)).toThrow();
});

it('manifest purpose comes from the authenticated archive and wrong purposes fail',async()=>{
 const manifest=structuredClone(f.manifest),first=manifest.files.find(r=>hash(r.ref)===hash(rows[2].ref));first.purpose='source';
 const archive=createNonrootEvidenceArchive(JSON.stringify(manifest),{expectedManifestHash:hash(manifest),readObject:async name=>f.objects.get(name)});
 await expect(selectCiRootControlOriginals({archive,...f.input,chargeLocal:()=>{}})).rejects.toThrow('CiRootOriginalReference');
});

it('selection refuses exhausted LOCAL before any object body read',async()=>{
 const before=f.reads.length;let calls=0;
 await expect(selectCiRootControlOriginals({archive:f.archive,...f.input,chargeLocal:()=>{calls++;throw Error('NoLocal');}})).rejects.toThrow('NoLocal');
 expect(calls).toBe(1);expect(f.reads.length).toBe(before);
});

it.each([2,3])('selection stage %i precharge fails before any archive object read',async stop=>{
 const before=f.reads.length;let calls=0;
 await expect(selectCiRootControlOriginals({archive:f.archive,...f.input,chargeLocal:()=>{if(++calls===stop)throw Error('NoLocal');}})).rejects.toThrow('NoLocal');
 expect(calls).toBe(stop);expect(f.reads.length).toBe(before);
});

it('an asynchronous charge cannot defer prepayment until after selection',async()=>{
 const before=f.reads.length;await expect(selectCiRootControlOriginals({archive:f.archive,...f.input,chargeLocal:async()=>{}})).rejects.toThrow('CiRootSynchronousBudget');expect(f.reads.length).toBe(before);
});

it('decoder refuses exhausted LOCAL before decoding payload data',()=>{
 for(const raw of [Buffer.from(JSON.stringify(request)),Buffer.from('invalid JSON')])expect(()=>decodeCiRootRequest(raw,{...f.expected,chargeLocal:()=>{throw Error('NoLocal');}})).toThrow('NoLocal');
});

it('serialization counts UTF-8 and escapes without stringify and pays before allocating output',()=>{
 const value=structuredClone(request);value.targetObservation.padding='é中😀\n\t\r\b\f\u0000"\\';
 const expected=Buffer.from(JSON.stringify(value)),charges=[];
 const stringify=vi.spyOn(JSON,'stringify');
 try{
  expect(()=>encodeCiRootRequest(value,{chargeLocal:n=>{charges.push(n);if(n===2*expected.length)throw Error('EncodingUnpaid');}})).toThrow('EncodingUnpaid');
  expect(stringify).not.toHaveBeenCalled();expect(charges.at(-1)).toBe(2*expected.length);
 }finally{stringify.mockRestore();}
 expect(encodeCiRootRequest(value,{chargeLocal:()=>{}})).toEqual(expected);
});

it('selection pays for counting before any serialization or archive body acquisition',async()=>{
 const stringify=vi.spyOn(JSON,'stringify'),before=f.reads.length;let calls=0;
 try{
  await expect(selectCiRootControlOriginals({archive:f.archive,...f.input,chargeLocal:()=>{if(++calls===30)throw Error('CountingUnpaid');}})).rejects.toThrow('CountingUnpaid');
  expect(stringify).not.toHaveBeenCalled();expect(f.reads.length).toBe(before);
 }finally{stringify.mockRestore();}
});

it('declared original-byte acquisition is prepaid before the first archive body read',async()=>{
 const before=f.reads.length,total=f.rows.reduce((n,r)=>n+r.ref.bytesLength,0);
 const acquisition=2*Buffer.byteLength(JSON.stringify(f.manifest))+10*total+2048;let blocked=false;
 await expect(selectCiRootControlOriginals({archive:f.archive,...f.input,chargeLocal:n=>{if(n===acquisition){blocked=true;throw Error('AcquisitionUnpaid');}}})).rejects.toThrow('AcquisitionUnpaid');
 expect(blocked).toBe(true);expect(f.reads.length).toBe(before);
});

it('complete counted request accepts the byte boundary and rejects one more byte',()=>{
 const value=structuredClone(request);value.targetObservation.padding='';
 const room=CI_ROOT_REQUEST_BYTES-Buffer.byteLength(JSON.stringify(value));value.targetObservation.padding='x'.repeat(room);
 let local=0;const chargeLocal=n=>{local+=n;expect(local).toBeLessThanOrEqual(CI_ROOT_REQUEST_POLICY.localBytes);};
 const verified=verifyCiRootRequest(value,{...f.expected,chargeLocal}),raw=encodeCiRootRequest(verified,{chargeLocal});
 expect(raw.length).toBe(CI_ROOT_REQUEST_BYTES);value.targetObservation.padding+='x';
 expect(()=>verifyCiRootRequest(value,{...f.expected,chargeLocal})).toThrow('CiRootRequestBound');
});

it.each(['getter','cycle','deep','proxy','sparse','number'])('bounded counting rejects %s without invoking input code',defect=>{
 const value=structuredClone(request);let invoked=0;
 if(defect==='getter')Object.defineProperty(value.targetObservation,'padding',{enumerable:true,get(){invoked++;throw Error('Invoked');}});
 if(defect==='cycle')value.targetObservation.padding=value;
 if(defect==='deep'){let x=value.targetObservation;for(let i=0;i<100;i++)x=x.padding={};}
 if(defect==='proxy')value.targetObservation=new Proxy({}, {ownKeys(){invoked++;throw Error('Invoked');}});
 if(defect==='sparse')value.targetObservation.padding=new Array(1000000);
 if(defect==='number')value.targetObservation.padding=NaN;
 expect(()=>verifyCiRootRequest(value,{...f.expected,chargeLocal:()=>{}})).toThrow('CiRootRequestJson');expect(invoked).toBe(0);
});

it('full encoded request limit includes all payload and target fields',()=>{
 const value=structuredClone(request);value.targetObservation.padding='x'.repeat(CI_ROOT_REQUEST_BYTES);
 expect(()=>verifyCiRootRequest(value,f.expected)).toThrow('CiRootRequestBound');
 expect(()=>decodeCiRootRequest(Buffer.from(JSON.stringify(value)),f.expected)).toThrow('CiRootRequestBound');
});

it('budget failure and oversized requests stop submission before save or dispatch',async()=>{
 let saves=0,providers=0;
 const options={...f.expected,check(){},save:async()=>{saves++;},env:{},deadlineMs:f.expected.now+60000,requestHandler:{handle:async()=>{providers++;}},chargeLocal:()=>{throw Error('NoLocal');}};
 await expect(submitCiRootRequest({...f.input,controlOriginals:rows},options)).rejects.toThrow('NoLocal');
 await expect(submitCiRootRequest({...f.input,controlOriginals:rows,targetObservation:{...f.input.targetObservation,padding:'x'.repeat(CI_ROOT_REQUEST_BYTES)}},{...options,chargeLocal:()=>{}})).rejects.toThrow('CiRootRequestBound');
 expect(saves).toBe(0);expect(providers).toBe(0);
});

it.each([false,true])('full v2 selection, signed request and three large ready pages (decode budget held: %s)',async held=>{
 const g=await rootOriginalsFixture(),records=[],calls=[],sha=raw=>createHash('sha256').update(raw).digest('hex');let local=0;
 const chargeLocal=n=>{if(held&&n===4*1007401)throw Error('ReadyDecodeUnpaid');local+=n;expect(local).toBeLessThanOrEqual(CI_ROOT_REQUEST_POLICY.localBytes);};
 const controlOriginals=await selectCiRootControlOriginals({archive:g.archive,...g.input,chargeLocal});
 const save=async(name,value)=>{const bytes=value instanceof Uint8Array?Buffer.from(value):Buffer.from(JSON.stringify(value));chargeLocal(bytes.length);const ref={path:'/fixture/'+name+'.json',sha256:sha(bytes)};records.push({name,ref,bytes});return ref;};
 const requestHandler={async handle(q){calls.push(q);return {response:{statusCode:200,headers:{'content-length':'0','x-amz-server-side-encryption':'aws:kms','x-amz-server-side-encryption-aws-kms-key-id':g.input.config.storage.kmsKeyArn,'x-amz-server-side-encryption-bucket-key-enabled':'true'},body:Readable.from([],{objectMode:false})}};},destroy(){}};
 const sizes=[1007401,1007401,997535];let page=0;
 const githubRequest=async()=>{const index=page++,statuses=Array.from({length:100},()=>({context:'unrelated',padding:''}));
  if(index===2)statuses[99]={...ciRootReadyStatus(g.input.config,g.input.scope,'0'.repeat(64)),creator:{id:42}};
  statuses[0].padding='x'.repeat(sizes[index]-Buffer.byteLength(JSON.stringify(statuses)));
  const raw=Buffer.from(JSON.stringify(statuses));expect(raw.length).toBe(sizes[index]);
  const body=Readable.from([raw],{objectMode:false});body.statusCode=200;body.headers={'content-length':String(raw.length)};return body;};
 const openedMs=Date.now(),deadlineMs=openedMs+60000;
 const run=()=>submitCiRootRequest({...g.input,controlOriginals},{...g.expected,env:{AWS_ACCESS_KEY_ID:'ASIA'+'A'.repeat(16),AWS_SECRET_ACCESS_KEY:'B'.repeat(40),AWS_SESSION_TOKEN:'synthetic-session',GH_TOKEN:'synthetic-github'},check(){},chargeLocal,save,deadlineMs,requestHandler,githubRequest});
 if(held){
  const parse=vi.spyOn(JSON,'parse');
  try{
   await expect(run()).rejects.toThrow('ReadyDecodeUnpaid');
   expect(parse.mock.calls.every(([text])=>typeof text!=='string'||Buffer.byteLength(text)<1007401)).toBe(true);
  }finally{parse.mockRestore();}
  expect(calls).toHaveLength(1);expect(page).toBe(1);expect(records.some(r=>r.name==='root-ready-1-response')).toBe(false);expect(records.at(-1).name).toBe('root-request-held');return;
 }
 const result=await run();
 const exchange={version:1,...result,records:records.map(({name,ref})=>({name,ref}))};
 const replay=verifyCiRootExchange(exchange,records,{...g.expected,openedMs,completedMs:Date.now(),deadlineMs,deploymentSource:g.input.deploymentSource});
 console.info('seven-originals CI accounting',JSON.stringify({requestBytes:records[0].bytes.length,readyBytes:sizes.reduce((a,b)=>a+b,0),localBytes:local,cap:CI_ROOT_REQUEST_POLICY.localBytes}));
 expect(replay.request.version).toBe(2);expect(exchange.version).toBe(1);expect(CI_ROOT_REQUEST_POLICY.version).toBe(1);expect(calls).toHaveLength(1);expect(replay.request.controlOriginals).toEqual(controlOriginals);expect(replay.readyCalls).toBe(3);expect(sizes.reduce((a,b)=>a+b,0)).toBe(3012337);expect(local).toBeLessThan(CI_ROOT_REQUEST_POLICY.localBytes);
});
