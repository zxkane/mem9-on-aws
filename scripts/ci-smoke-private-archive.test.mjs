import {it,expect} from 'vitest';
import {createHash} from 'node:crypto';
import {Readable} from 'node:stream';
import {ciSmokeEvidenceFixture} from './ci-smoke-evidence.fixture.mjs';
import {canaryEvidenceHash as hash} from './lib/production-canary-verification.mjs';
import {validateCiSmokeEvidence} from './lib/ci-smoke-evidence.mjs';
import {
 encodeCiSmokeEnvelope,decodeCiSmokeEnvelope,inspectCiSmokeCommitment,
 ciSmokeArchiveKey,buildCiSmokeReadPolicy,
 putCiSmokeEnvelope,getCiSmokeEnvelope,
} from './lib/ci-smoke-private-archive.mjs';

const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const json=value=>Buffer.from(JSON.stringify(value));
const account='123456789012',region='us-east-1',bucket='example-smoke-evidence';
function fixture(){
 const f=ciSmokeEvidenceFixture();
 const roots={result:f.json(f.result),source:f.json({identity:f.expected.identity}),isolation:f.json({isolationHash:f.expected.isolationHash}),observations:f.json(f.expected),commandBindings:f.json({invocationId:f.expected.invocationId}),commandCatalog:f.json(f.expected.commandCatalog)};
 // The synthetic archive starts with the actual referenced objects. A changed
 // hash or missing byte object is tested independently below.
 const selected=new Map(),walk=value=>{
  if(!value||typeof value!=='object')return;
  if(value.bytesHash&&value.canonicalHash){const raw=f.objects.get(value.bytesHash);if(selected.has(value.bytesHash))return;selected.set(value.bytesHash,raw);walk(JSON.parse(raw));return;}
  if(value.sha256&&Number.isInteger(value.bytesLength)){selected.set(value.sha256,f.objects.get(value.sha256));return;}
  if(value.gitMode&&value.sha256&&value.bytes){selected.set(value.sha256,f.objects.get(value.sha256));return;}
  for(const v of Object.values(value))walk(v);
 };walk(roots);
 const input={records:roots,objects:[...selected].map(([sha256,bytes])=>({sha256,bytes}))};
 const encoded=encodeCiSmokeEnvelope(input);
 const config={stage:'pr-7',account,region,bucket,bucketArn:'arn:aws:s3:::'+bucket,roleArn:'arn:aws:iam::'+account+':role/ExamplePreviewRole',objectArn:'arn:aws:s3:::'+bucket+'/'+ciSmokeArchiveKey('pr-7',encoded.commitment),encryption:{algorithm:'aws:kms',keyArn:'arn:aws:kms:'+region+':'+account+':key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',bucketKeyEnabled:true}};
 return {f,input,encoded,config};
}
const now=1700000020000;
const credentials=()=>({accessKeyId:'ASIA'+'A'.repeat(16),secretAccessKey:'synthetic-secret-not-issued',sessionToken:'synthetic-session-not-issued',expiration:new Date(now+900000)});
function transport(response){
 const calls=[],handler={handle:async(request,options)=>{calls.push({request,options});return {response:await response(request)};},destroy(){handler.destroyed=true;}};
 return {handler,calls};
}
function headers(config,body){return {'content-type':'application/json','content-length':String(body.length),'x-amz-server-side-encryption':'aws:kms','x-amz-server-side-encryption-aws-kms-key-id':config.encryption.keyArn,'x-amz-server-side-encryption-bucket-key-enabled':'true','x-amz-checksum-sha256':Buffer.from(sha(body),'hex').toString('base64'),etag:'"synthetic-etag"'};}
const producedExpected=f=>Object.fromEntries(Object.entries(f.expected).filter(([k])=>!['buildJob','smokeJob'].includes(k)));
const options=(x,t)=>({config:x.config,credentials:credentials(),now:()=>now,deadlineMs:now+30000,requestHandler:t.handler});

it('round-trips every original byte and all fourteen checks without promoting transport into authority',async()=>{
 const x=fixture(),d=decodeCiSmokeEnvelope(x.encoded.bytes,x.encoded.commitment);
 expect(d.envelopeBytes).toEqual(x.encoded.bytes);expect(d.envelopeBytes).not.toBe(x.encoded.bytes);d.envelopeBytes.fill(0);
 for(const {sha256,bytes}of x.input.objects)expect(d.readBytes({sha256,bytesLength:bytes.length})).toEqual(bytes);
 expect(d.readJson(x.input.records.result)).toEqual(x.f.objects.get(x.input.records.result.bytesHash));
 await expect(validateCiSmokeEvidence(d.records.result,{readJson:d.readJson,readBytes:d.readBytes,expected:x.f.expected,now})).resolves.toHaveProperty('cleanupHash');
 expect(d).not.toHaveProperty('authorized');
});
it('uses the existing lifecycle prefix with exact stage/run/attempt/hash and no path selectors',()=>{
 const x=fixture();expect(ciSmokeArchiveKey('pr-7',x.encoded.commitment)).toBe('decisions/pr-7/ci-smoke/100/1/'+x.encoded.commitment.envelopeSha256+'.json');
 for(const stage of ['preview','pr-07','pr-7/../prod','prod/*','prod%2f'])expect(()=>ciSmokeArchiveKey(stage,x.encoded.commitment)).toThrow();
});
it('emits only the approved public-safe commitment fields',()=>{
 const {encoded}=fixture(),c=encoded.commitment;expect(inspectCiSmokeCommitment(c)).toEqual(c);
 expect(Object.keys(c).sort()).toEqual(['version','kind','runId','runAttempt','sourceRevision','sourceTree','buildJobId','smokeJobId','outputDigest','arm64Digest','configDigest','resultHash','envelopeSha256','bytesLength'].sort());
 expect(JSON.stringify(c)).not.toMatch(/123456789012|arn:|amazonaws|qualifiedImage|bucket|credentials/i);
 expect(()=>inspectCiSmokeCommitment({...c,bucket})).toThrow();
});
for(const name of ['missing','extra','duplicate','changed','canonical'])it('rejects '+name+' envelope objects or references',()=>{
 const x=fixture();
 if(name==='missing')x.input.objects.pop();
 if(name==='extra'){const bytes=Buffer.from('unreferenced');x.input.objects.push({sha256:sha(bytes),bytes});}
 if(name==='duplicate')x.input.objects.push(x.input.objects[0]);
 if(name==='changed')x.input.objects[0]={...x.input.objects[0],bytes:Buffer.from('changed')};
 if(name==='canonical')x.input.records.result={...x.input.records.result,canonicalHash:'f'.repeat(64)};
 expect(()=>encodeCiSmokeEnvelope(x.input)).toThrow();
});
it('rejects invalid UTF8, duplicate decoded JSON keys, unknown fields and noncanonical base64',()=>{
 const x=fixture(),e=JSON.parse(x.encoded.bytes);
 for(const bytes of [Buffer.from([0xff]),Buffer.from('{"version":1,"version":1}'),json({...e,approved:true}),json({...e,objects:e.objects.map((o,i)=>i?o:{...o,base64:o.base64+'\n'})})]){
  const commitment={...x.encoded.commitment,envelopeSha256:sha(bytes),bytesLength:bytes.length};expect(()=>decodeCiSmokeEnvelope(bytes,commitment)).toThrow();
 }
});
it('rejects over-limit bodies and a mismatched public commitment before reads',()=>{
 const x=fixture();expect(()=>decodeCiSmokeEnvelope(Buffer.alloc(33554433),x.encoded.commitment)).toThrow();
 for(const patch of [{runAttempt:2},{resultHash:'f'.repeat(64)},{envelopeSha256:'f'.repeat(64)},{bytesLength:x.encoded.bytes.length+1}])expect(()=>decodeCiSmokeEnvelope(x.encoded.bytes,{...x.encoded.commitment,...patch})).toThrow();
});
it('provides independent reader copies and does not let ByteRef caching bypass JsonRef verification',()=>{
 const x=fixture(),d=decodeCiSmokeEnvelope(x.encoded.bytes,x.encoded.commitment),ref=x.input.records.result;
 d.readBytes({sha256:ref.bytesHash,bytesLength:ref.bytesLength}).fill(0);
 expect(d.readJson(ref)).toEqual(x.f.objects.get(ref.bytesHash));
 expect(()=>d.readJson({...ref,canonicalHash:'f'.repeat(64)})).toThrow();
});

// Limited evaluator for the generated exact-action policy. It explicitly
// models an external Allow to exercise the explicit-Deny boundary, not IAM's
// complete evaluator or a live policy simulation.
function evaluate(policy,action,resource,context={},externalAllow=false){
 const includes=(values,value)=>[values].flat().some(v=>v==='*'||v===value);
 const conditions=condition=>Object.entries(condition??{}).every(([op,entries])=>Object.entries(entries).every(([key,want])=>op==='StringEquals'?context[key]===want:op==='StringNotEquals'?context[key]!==want:false));
 const matching=policy.Statement.filter(s=>(s.NotAction?!includes(s.NotAction,action):includes(s.Action,action))&&(s.NotResource?!includes(s.NotResource,resource):includes(s.Resource,resource))&&conditions(s.Condition));
 return matching.some(s=>s.Effect==='Deny')?'explicitDeny':externalAllow||matching.some(s=>s.Effect==='Allow')?'allowed':'implicitDeny';
}
it('builds a complete <=2048-character policy with explicit denies even against direct session grants',()=>{
 const x=fixture(),out=buildCiSmokeReadPolicy(x.config,x.encoded.commitment),p=JSON.parse(out.Policy),obj=x.config.objectArn,key=x.config.encryption.keyArn;
 expect(out.DurationSeconds).toBe(900);expect(out.Policy.length).toBeLessThanOrEqual(2048);
 const s3={'s3:ResourceAccount':account},kms={'kms:ViaService':'s3.'+region+'.amazonaws.com','kms:CallerAccount':account,'kms:EncryptionContext:aws:s3:arn':x.config.bucketArn};
 expect(evaluate(p,'s3:GetObject',obj,s3)).toBe('allowed');expect(evaluate(p,'kms:Decrypt',key,kms)).toBe('allowed');expect(evaluate(p,'sts:GetCallerIdentity','*')).toBe('allowed');
 for(const [a,r,c]of [['s3:GetObject',obj+'-other',s3],['s3:GetObject',obj,{}],['s3:GetObjectVersion',obj,s3],['s3:PutObject',obj,s3],['s3:ListBucket',x.config.bucketArn,s3],['kms:Decrypt',key+'-other',kms],...Object.keys(kms).flatMap(k=>[['kms:Decrypt',key,{...kms,[k]:'wrong'}],['kms:Decrypt',key,Object.fromEntries(Object.entries(kms).filter(([n])=>n!==k))]]),...['ecs:RunTask','ssm:GetParameter','iam:PassRole','sts:AssumeRole','ecr:BatchGetImage'].map(a=>[a,'*',{}])])expect(evaluate(p,a,r,c,true)).toBe('explicitDeny');
});
it('binds the KMS encryption context to the explicit existing bucket-key mode',()=>{
 const x=fixture();x.config.encryption.bucketKeyEnabled=false;const p=JSON.parse(buildCiSmokeReadPolicy(x.config,x.encoded.commitment).Policy);
 const c={'kms:ViaService':'s3.'+region+'.amazonaws.com','kms:CallerAccount':account,'kms:EncryptionContext:aws:s3:arn':x.config.objectArn};
 expect(evaluate(p,'kms:Decrypt',x.config.encryption.keyArn,c)).toBe('allowed');c['kms:EncryptionContext:aws:s3:arn']=x.config.bucketArn;expect(evaluate(p,'kms:Decrypt',x.config.encryption.keyArn,c,true)).toBe('explicitDeny');
});
it('adds no KMS permission for an explicitly configured SSE-S3 object',()=>{
 const x=fixture();x.config.encryption={algorithm:'AES256',keyArn:null,bucketKeyEnabled:false};const p=JSON.parse(buildCiSmokeReadPolicy(x.config,x.encoded.commitment).Policy);
 expect(evaluate(p,'kms:Decrypt','*',{},true)).toBe('explicitDeny');
});
for(const key of ['account','region','bucket','bucketArn','objectArn','roleArn'])it('rejects missing or inconsistent protected '+key,()=>{
 const x=fixture();delete x.config[key];expect(()=>buildCiSmokeReadPolicy(x.config,x.encoded.commitment)).toThrow();
});
it('rejects guessed aliases, another account/key/region and wildcard object scope',()=>{
 for(const mutate of [c=>{c.encryption.keyArn='alias/aws/s3';},c=>{c.encryption.keyArn=c.encryption.keyArn.replace(region,'us-west-2');},c=>{c.roleArn=c.roleArn.replace(account,'0'.repeat(12));},c=>{c.objectArn+='*';},c=>{c.objectArn=c.objectArn.replace('/pr-7/','/prod/');}]){const x=fixture();mutate(x.config);expect(()=>buildCiSmokeReadPolicy(x.config,x.encoded.commitment)).toThrow();}
});

it('uses real SDK serialization for exactly one conditional private PUT after full replay',async()=>{
 const x=fixture(),t=transport(async req=>({statusCode:200,headers:headers(x.config,Buffer.from(req.body)),body:Readable.from([])}));
 const result=await putCiSmokeEnvelope(x.encoded,{...options(x,t),expected:producedExpected(x.f)});
 expect(t.calls).toHaveLength(1);const {request}=t.calls[0];expect(request.method).toBe('PUT');expect(request.hostname).toBe('s3.'+region+'.amazonaws.com');expect(request.headers['if-none-match']).toBe('*');expect(request.headers['x-amz-expected-bucket-owner']).toBe(account);expect(request.headers['x-amz-acl']).toBeUndefined();expect(request.headers['x-amz-tagging']).toBeUndefined();expect(Buffer.from(request.body)).toEqual(x.encoded.bytes);expect(t.handler.destroyed).toBe(true);expect(result.commitment).toEqual(x.encoded.commitment);
});
it('rejects a failed full replay with zero SDK writes',async()=>{
 const x=fixture(),t=transport(()=>{throw Error('unexpected');});x.f.expected.identity.runAttempt++;
 await expect(putCiSmokeEnvelope(x.encoded,{...options(x,t),expected:producedExpected(x.f)})).rejects.toThrow();expect(t.calls).toHaveLength(0);
});
it('does not retry lost/failed PUT responses and never exposes service error payloads',async()=>{
 const x=fixture(),t=transport(()=>{throw Error('synthetic-sensitive-response');});
 await expect(putCiSmokeEnvelope(x.encoded,{...options(x,t),expected:producedExpected(x.f)})).rejects.toThrow(/^CiSmokePrivatePutHeld$/);expect(t.calls).toHaveLength(1);expect(t.handler.destroyed).toBe(true);
});
it('reads a single capped object through the SDK and replays original bytes',async()=>{
 const x=fixture(),t=transport(()=>({statusCode:200,headers:headers(x.config,x.encoded.bytes),body:Readable.from([x.encoded.bytes.subarray(0,30),x.encoded.bytes.subarray(30)])}));
 const out=await getCiSmokeEnvelope(x.encoded.commitment,options(x,t));expect(t.calls).toHaveLength(1);expect(t.calls[0].request.method).toBe('GET');expect(t.calls[0].request.headers['x-amz-expected-bucket-owner']).toBe(account);expect(t.calls[0].request.headers['x-amz-server-side-encryption']).toBeUndefined();expect(t.calls[0].request.query.versionId).toBeUndefined();expect(out.records.result).toEqual(x.f.result);expect(t.handler.destroyed).toBe(true);
});
for(const fault of ['length','hash','encryption','key','bucket-key','overflow','stream'])it('holds and destroys the body/client on GET '+fault+' failure',async()=>{
 const x=fixture();let body=Readable.from([x.encoded.bytes]),h=headers(x.config,x.encoded.bytes);
 if(fault==='length')h['content-length']='1';if(fault==='hash')body=Readable.from([Buffer.alloc(x.encoded.bytes.length)]);if(fault==='encryption')h['x-amz-server-side-encryption']='AES256';if(fault==='key')h['x-amz-server-side-encryption-aws-kms-key-id']+='wrong';if(fault==='bucket-key')h['x-amz-server-side-encryption-bucket-key-enabled']='false';if(fault==='overflow')body=Readable.from([x.encoded.bytes,Buffer.from('extra')]);if(fault==='stream')body=Readable.from((async function*(){yield x.encoded.bytes.subarray(0,20);throw Error('synthetic-sensitive-body');})());
 const t=transport(()=>({statusCode:200,headers:h,body}));await expect(getCiSmokeEnvelope(x.encoded.commitment,options(x,t))).rejects.toThrow(/^CiSmokePrivateGetHeld$/);expect(t.calls).toHaveLength(1);expect(body.destroyed).toBe(true);expect(t.handler.destroyed).toBe(true);
});
it('never sends after deadline/abort and rejects missing session credentials',async()=>{
 const x=fixture(),t=transport(()=>{throw Error('unexpected');});
 for(const patch of [{deadlineMs:now},{signal:AbortSignal.abort()},{credentials:undefined}])await expect(getCiSmokeEnvelope(x.encoded.commitment,{...options(x,t),...patch})).rejects.toThrow();expect(t.calls).toHaveLength(0);
});
it('preserves the actual merge checkout identity separately from the candidate head in the private source record',()=>{
 const x=fixture(),candidateHead='e'.repeat(40),source={...x.f.get(x.input.records.source),candidateHead};
 const old=x.input.records.source;x.input.records.source=x.f.json(source);x.input.objects=x.input.objects.filter(o=>o.sha256!==old.bytesHash);x.input.objects.push({sha256:x.input.records.source.bytesHash,bytes:x.f.objects.get(x.input.records.source.bytesHash)});
 const encoded=encodeCiSmokeEnvelope(x.input),decoded=decodeCiSmokeEnvelope(encoded.bytes,encoded.commitment);
 expect(encoded.commitment.sourceRevision).toBe(x.f.result.sourceRevision);expect(encoded.commitment.sourceRevision).not.toBe(candidateHead);expect(decoded.records.source.candidateHead).toBe(candidateHead);expect(encoded.commitment).not.toHaveProperty('candidateHead');
});
it('does not invoke input accessors or accept parser/transport options in the closed configuration',()=>{
 const x=fixture();let invoked=0;const row={...x.input.objects[0]};Object.defineProperty(row,'bytes',{enumerable:true,get(){invoked++;throw Error('should not run');}});x.input.objects[0]=row;
 expect(()=>encodeCiSmokeEnvelope(x.input)).toThrow();expect(invoked).toBe(0);
 expect(()=>buildCiSmokeReadPolicy({...x.config,endpoint:'https://example.com'},x.encoded.commitment)).toThrow();
});
it('rechecks the absolute deadline after asynchronous preparation with zero HTTP dispatch',async()=>{
 const x=fixture(),t=transport(()=>{throw Error('unexpected');});let clock=now;
 const pending=getCiSmokeEnvelope(x.encoded.commitment,{...options(x,t),now:()=>clock});queueMicrotask(()=>{clock=now+30000;});
 await expect(pending).rejects.toThrow('CiSmokePrivateGetHeld');expect(t.calls).toHaveLength(0);
});
it('preserves sticky cleanup failure even when the operation itself succeeds',async()=>{
 const x=fixture(),t=transport(()=>({statusCode:200,headers:headers(x.config,x.encoded.bytes),body:Readable.from([x.encoded.bytes])}));t.handler.destroy=()=>{throw Error('synthetic destroy failure');};
 await expect(getCiSmokeEnvelope(x.encoded.commitment,options(x,t))).rejects.toMatchObject({code:'ECLEANUP',message:'CiSmokeArchiveCleanupHeld'});
});
it('never copies secret-bearing external error text even if it uses the cleanup error code',async()=>{
 const x=fixture(),t=transport(()=>{throw Object.assign(Error('synthetic-sensitive-response'),{code:'ECLEANUP'});});
 await expect(getCiSmokeEnvelope(x.encoded.commitment,options(x,t))).rejects.toMatchObject({code:'ECLEANUP',message:'CiSmokeArchiveCleanupHeld'});
});
it('holds when body termination cannot be positively observed',async()=>{
 const x=fixture(),body=new Readable({read(){},destroy(){}}),t=transport(()=>({statusCode:200,headers:{...headers(x.config,x.encoded.bytes),'content-length':'1'},body}));
 await expect(getCiSmokeEnvelope(x.encoded.commitment,{...options(x,t),deadlineMs:now+20})).rejects.toMatchObject({code:'ECLEANUP'});expect(body.destroyed).toBe(true);expect(t.handler.destroyed).toBe(true);
});
it('cancels a stalled body and proves close before returning a hold',async()=>{
 const x=fixture(),controller=new AbortController(),body=new Readable({read(){queueMicrotask(()=>controller.abort());}}),t=transport(()=>({statusCode:200,headers:headers(x.config,x.encoded.bytes),body}));
 await expect(getCiSmokeEnvelope(x.encoded.commitment,{...options(x,t),signal:controller.signal})).rejects.toThrow('CiSmokePrivateGetHeld');expect(body.closed).toBe(true);expect(t.handler.destroyed).toBe(true);
});
it('validates the returned PUT checksum and encryption rather than treating HTTP 200 as proof',async()=>{
 const x=fixture(),t=transport(()=>({statusCode:200,headers:{...headers(x.config,x.encoded.bytes),'x-amz-checksum-sha256':Buffer.alloc(32).toString('base64')},body:Readable.from([])}));
 await expect(putCiSmokeEnvelope(x.encoded,{...options(x,t),expected:producedExpected(x.f)})).rejects.toThrow('CiSmokePrivatePutHeld');expect(t.calls).toHaveLength(1);
});
