import {it,expect} from 'vitest';
import {Readable} from 'node:stream';
import {parseConfiguredAwsExpiration,withCiSmokeReadSession} from './lib/ci-smoke-session.mjs';
import {buildCiSmokeReadPolicy,ciSmokeArchiveKey,encodeCiSmokeEnvelope,getCiSmokeEnvelope} from './lib/ci-smoke-private-archive.mjs';
import {ciSmokeEvidenceFixture} from './ci-smoke-evidence.fixture.mjs';

const NOW=1700000000000,account='123456789012',region='us-east-1',bucket='example-session-evidence';
const requestUrl='https://pipelines.actions.githubusercontent.com/synthetic_scope/_apis/distributedtask/hubs/build/plans/00000000-0000-4000-8000-000000000001/jobs/00000000-0000-4000-8000-000000000002/idtoken?api-version=2.0';
function fixture(){
 const commitment={version:1,kind:'ci-smoke-private-commitment',runId:100,runAttempt:1,sourceRevision:'a'.repeat(40),sourceTree:'b'.repeat(40),buildJobId:101,smokeJobId:102,outputDigest:'sha256:'+'a'.repeat(64),arm64Digest:'sha256:'+'b'.repeat(64),configDigest:'sha256:'+'c'.repeat(64),resultHash:'d'.repeat(64),envelopeSha256:'e'.repeat(64),bytesLength:1};
 const config={stage:'pr-7',account,region,bucket,bucketArn:'arn:aws:s3:::'+bucket,roleArn:'arn:aws:iam::'+account+':role/preview/ExampleReader',objectArn:'arn:aws:s3:::'+bucket+'/'+ciSmokeArchiveKey('pr-7',commitment),encryption:{algorithm:'aws:kms',keyArn:'arn:aws:kms:'+region+':'+account+':key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',bucketKeyEnabled:true}};
 const env={GITHUB_ACTIONS:'true',GITHUB_SERVER_URL:'https://github.com',GITHUB_REPOSITORY:'example/control-plane',GITHUB_RUN_ID:'200',GITHUB_RUN_ATTEMPT:'2',GITHUB_SHA:'c'.repeat(40),AWS_REGION:region,ACTIONS_ID_TOKEN_REQUEST_URL:requestUrl,ACTIONS_ID_TOKEN_REQUEST_TOKEN:'synthetic-request-token-not-issued'};
 return {config,commitment,env,deadlineMs:NOW+30000};
}
function mockHttp(mutate=()=>{}){
 const calls=[],bodies=[],events=[];let sessionName,assumedArn;
 const issued={accessKeyId:'ASIA'+'A'.repeat(16),secretAccessKey:'synthetic-secret-not-issued',sessionToken:'synthetic-session-not-issued',expiration:new Date(NOW+900000).toISOString()};
 const handler={async handle(request,options){
  const row={request,options,authorization:request.headers.authorization,token:request.headers['x-amz-security-token'],params:new URLSearchParams(typeof request.body==='string'?request.body:'')};calls.push(row);
  let stage,statusCode=200,headers={'content-type':'text/xml'},text;
  if(request.hostname.endsWith('.actions.githubusercontent.com')){stage='oidc';headers={'content-type':'application/json'};text=JSON.stringify({count:1,value:'synthetic.header.signature'});}
  else if(row.params.get('Action')==='AssumeRoleWithWebIdentity'){
   stage='assume';sessionName=row.params.get('RoleSessionName');assumedArn='arn:aws:sts::'+account+':assumed-role/ExampleReader/'+sessionName;
   text='<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>'+issued.accessKeyId+'</AccessKeyId><SecretAccessKey>'+issued.secretAccessKey+'</SecretAccessKey><SessionToken>'+issued.sessionToken+'</SessionToken><Expiration>'+issued.expiration+'</Expiration></Credentials><AssumedRoleUser><Arn>'+assumedArn+'</Arn><AssumedRoleId>AROASYNTHETICREADER:'+sessionName+'</AssumedRoleId></AssumedRoleUser></AssumeRoleWithWebIdentityResult><ResponseMetadata><RequestId>synthetic-request</RequestId></ResponseMetadata></AssumeRoleWithWebIdentityResponse>';
  }else{
   stage='identity';text='<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Arn>'+assumedArn+'</Arn><UserId>AROASYNTHETICREADER:'+sessionName+'</UserId><Account>'+account+'</Account></GetCallerIdentityResult><ResponseMetadata><RequestId>synthetic-request</RequestId></ResponseMetadata></GetCallerIdentityResponse>';
  }
  events.push(stage);const response={statusCode,headers,body:Readable.from([Buffer.from(text)])};bodies.push(response.body);await mutate({stage,response,row,issued,sessionName,assumedArn});return {response};
 },destroy(){events.push('destroy');handler.destroyed=true;}};
 return {handler,calls,bodies,events,issued,seams:{now:()=>NOW,requestHandler:handler}};
}

for(const value of ['2023-11-14T22:15:00Z','2023-11-14T22:15:00.000Z','"2023-11-14T22:15:00.000Z"'])it('accepts actual plain/quoted ISO expiry '+value,()=>{
 expect(parseConfiguredAwsExpiration(value,NOW).toISOString()).toBe('2023-11-14T22:15:00.000Z');
});
for(const value of [undefined,null,'',' ',0,{},'null','{}','12345','2023-11-14','2023-11-14T22:15:00','2023-11-14T22:15:00Z\n',' 2023-11-14T22:15:00Z','2024-02-30T22:15:00Z','2023-11-14T24:00:00Z','2023-11-14T22:13:20.000Z','2023-11-14T22:13:19.999Z','"not-an-iso"','"2023-11-14T22:15:00.000Z" trailing'])it('rejects missing/noncanonical/expired expiration '+JSON.stringify(value),()=>{
 expect(()=>parseConfiguredAwsExpiration(value,NOW)).toThrow(/^CiSmokeAwsExpiration$/);
});
it('performs one OIDC + exact 900s web identity STS + signed identity check, then erases credentials',async()=>{
 const f=fixture(),m=mockHttp(),before={...f.env};let held,signal;
 const value=await withCiSmokeReadSession(f,async context=>{m.events.push('use');held=context.credentials;signal=context.signal;expect(held.expiration.toISOString()).toBe(m.issued.expiration);expect(context.config).toEqual(f.config);expect(Object.isFrozen(context.config)).toBe(true);expect(context.config.region).toBe('us-east-1');return 'checked';},m.seams);
 expect(value).toBe('checked');expect(m.events).toEqual(['oidc','assume','identity','use','destroy']);expect(m.calls).toHaveLength(3);
 const [oidc,assume,identity]=m.calls;expect(oidc.request.method).toBe('GET');expect(oidc.request.query.audience).toBe('sts.amazonaws.com');expect(oidc.authorization).toBe('Bearer '+before.ACTIONS_ID_TOKEN_REQUEST_TOKEN);
 expect(assume.request.hostname).toBe('sts.us-west-2.amazonaws.com');expect(assume.params.get('RoleArn')).toBe(f.config.roleArn);expect(assume.params.get('DurationSeconds')).toBe('900');expect(assume.params.get('Policy')).toBe(buildCiSmokeReadPolicy(f.config,f.commitment).Policy);expect(assume.authorization).toBeUndefined();
 expect(identity.authorization).toContain(m.issued.accessKeyId);expect(identity.authorization).toContain('/us-west-2/sts/aws4_request');expect(identity.token).toBe(m.issued.sessionToken);
 expect(f.env).toEqual(before);expect(held.accessKeyId).toBe('');expect(held.secretAccessKey).toBe('');expect(held.sessionToken).toBe('');expect(held.expiration.getTime()).toBe(0);expect(signal.aborted).toBe(true);expect(m.bodies.every(b=>b.closed)).toBe(true);
});
// Synthetic service routes exercise the platform-URL contract, not a claim
// about GitHub's current internal endpoint path or API version.
for(const value of [
 'https://pipelines.actions.githubusercontent.com/synthetic/token?api-version=3.0&scope=fixture',
 'https://pipelines.actions.githubusercontent.com/opaque/provider/route?context=fixture',
 requestUrl.replace('api-version=2.0','api-version=2.1'),
])it('preserves a platform-provided opaque route/query on the existing service origin: '+value,async()=>{
 const f=fixture(),m=mockHttp();f.env.ACTIONS_ID_TOKEN_REQUEST_URL=value;
 await expect(withCiSmokeReadSession(f,()=>true,m.seams)).resolves.toBe(true);
 const supplied=new URL(value),request=m.calls[0].request;
 expect(request.hostname).toBe(supplied.hostname);expect(request.path).toBe(supplied.pathname);
 expect(request.query).toEqual({...Object.fromEntries(supplied.searchParams),audience:'sts.amazonaws.com'});
 expect(m.calls).toHaveLength(3);expect(f.env.ACTIONS_ID_TOKEN_REQUEST_URL).toBe(value);
});
for(const value of [requestUrl.replace('https:','http:'),requestUrl.replace('pipelines.actions.githubusercontent.com','example.com'),requestUrl.replace('pipelines.actions.githubusercontent.com','pipelines.actions.githubusercontent.com.example.com'),requestUrl.replace('https://','https:'+'//user:password@'),requestUrl.replace('.com/','.com:8443/'),requestUrl+'#fragment',requestUrl+'&audience=example.com',requestUrl+'&audience=sts.amazonaws.com&audience=sts.amazonaws.com',requestUrl+'&api-version=3.0'])it('rejects an unapproved OIDC URL before network: '+value,async()=>{
 const f=fixture(),m=mockHttp();f.env.ACTIONS_ID_TOKEN_REQUEST_URL=value;
 await expect(withCiSmokeReadSession(f,()=>{throw Error('unexpected use');},m.seams)).rejects.toThrow();expect(m.calls).toHaveLength(0);
});
for(const name of ['AWS_ACCESS_KEY_ID','AWS_SECRET_ACCESS_KEY','AWS_SESSION_TOKEN','AWS_PROFILE','AWS_CONFIG_FILE','AWS_SHARED_CREDENTIALS_FILE','AWS_WEB_IDENTITY_TOKEN_FILE','AWS_CONTAINER_CREDENTIALS_FULL_URI','AWS_ENDPOINT_URL','AWS_ENDPOINT_URL_STS','NODE_TLS_REJECT_UNAUTHORIZED'])it('rejects ambient override '+name,async()=>{
 const f=fixture(),m=mockHttp();f.env[name]='synthetic';await expect(withCiSmokeReadSession(f,()=>{},m.seams)).rejects.toThrow();expect(m.calls).toHaveLength(0);
});
it('rejects missing GitHub credentials/identity and extra endpoint/provider options with zero calls',async()=>{
 for(const change of [f=>{delete f.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;},f=>{f.env.GITHUB_ACTIONS='false';},f=>{f.env.GITHUB_RUN_ID='0';},f=>{f.endpoint='https://example.com';},f=>{f.credentials=()=>({});}]){const f=fixture(),m=mockHttp();change(f);await expect(withCiSmokeReadSession(f,()=>{},m.seams)).rejects.toThrow();expect(m.calls).toHaveLength(0);}
});
it('reports only owned static reasons and never copies an external callback error',async()=>{
 const f=fixture(),m=mockHttp();f.env.ACTIONS_ID_TOKEN_REQUEST_URL='https://example.com/';
 await expect(withCiSmokeReadSession(f,()=>{},m.seams)).rejects.toMatchObject({phase:'precheck',reason:'CiSmokeOidcOrigin'});
 const good=fixture(),http=mockHttp();await expect(withCiSmokeReadSession(good,()=>{throw Error('synthetic-sensitive-callback');},http.seams)).rejects.toMatchObject({phase:'use',reason:'CiSmokeReadSessionFailure'});
});
for(const stage of ['oidc','assume','identity'])it('holds on '+stage+' HTTP failure without retry, use or raw error text',async()=>{
 const f=fixture(),m=mockHttp(({stage:actual,response})=>{if(actual===stage){response.statusCode=503;response.body=Readable.from([Buffer.from('synthetic-sensitive-error')]);}});let used=false;
 await expect(withCiSmokeReadSession(f,()=>{used=true;},m.seams)).rejects.toThrow(/^CiSmokeReadSessionHeld$/);expect(used).toBe(false);expect(m.calls.length).toBe(['oidc','assume','identity'].indexOf(stage)+1);expect(m.handler.destroyed).toBe(true);
});
it('does not follow redirects or forward the OIDC bearer to another host',async()=>{
 const f=fixture(),m=mockHttp(({response})=>{response.statusCode=302;response.headers.location='https://example.com/steal';});
 f.env.ACTIONS_ID_TOKEN_REQUEST_URL=requestUrl+'&redirect=https://example.com';
 await expect(withCiSmokeReadSession(f,()=>{},m.seams)).rejects.toThrow();expect(m.calls).toHaveLength(1);expect(m.calls[0].request.hostname).toBe('pipelines.actions.githubusercontent.com');expect(m.handler.destroyed).toBe(true);
});
for(const fault of ['account','role','session','user-id','expired','oversized-session'])it('rejects actual STS '+fault+' mismatch before use',async()=>{
 const f=fixture(),m=mockHttp(async({stage,response})=>{
  if((['expired','oversized-session'].includes(fault)?stage==='assume':stage==='identity')){
   const chunks=[];for await(const chunk of response.body)chunks.push(chunk);let text=Buffer.concat(chunks).toString();
   if(fault==='account')text=text.replace('<Account>'+account,'<Account>'+'0'.repeat(12));if(fault==='role')text=text.replace('/ExampleReader/','/OtherRole/');if(fault==='session')text=text.replace('/ci-smoke-read-','/other-');if(fault==='user-id')text=text.replace('AROASYNTHETICREADER','AROADIFFERENT');if(fault==='expired')text=text.replace(new Date(NOW+900000).toISOString(),new Date(NOW).toISOString());if(fault==='oversized-session')text=text.replace(new Date(NOW+900000).toISOString(),new Date(NOW+3600000).toISOString());response.body=Readable.from([Buffer.from(text)]);
  }
 });let used=false;await expect(withCiSmokeReadSession(f,()=>{used=true;},m.seams)).rejects.toThrow();expect(used).toBe(false);expect(m.handler.destroyed).toBe(true);
});
it('bounds token/STS bodies and rejects duplicate OIDC fields',async()=>{
 for(const raw of [Buffer.alloc(131073),Buffer.from('{"value":"synthetic.header.signature","value":"other.header.signature"}'),Buffer.from('{"value":"synthetic.header.signature","extra":true}')]){const f=fixture(),m=mockHttp(({stage,response})=>{if(stage==='oidc')response.body=Readable.from([raw]);});await expect(withCiSmokeReadSession(f,()=>{},m.seams)).rejects.toThrow();expect(m.calls).toHaveLength(1);expect(m.handler.destroyed).toBe(true);}
});
it('erases credentials and closes clients after callback failure',async()=>{
 const f=fixture(),m=mockHttp();let held;
 await expect(withCiSmokeReadSession(f,({credentials})=>{held=credentials;throw Error('synthetic-sensitive-callback');},m.seams)).rejects.toThrow(/^CiSmokeReadSessionHeld$/);expect(held.sessionToken).toBe('');expect(m.handler.destroyed).toBe(true);
});
it('preserves sticky cleanup failure instead of returning callback success',async()=>{
 const f=fixture(),m=mockHttp();m.handler.destroy=()=>{throw Error('synthetic-sensitive-cleanup');};let held;
 await expect(withCiSmokeReadSession(f,({credentials})=>{held=credentials;return 'success';},m.seams)).rejects.toMatchObject({code:'ECLEANUP',message:'CiSmokeReadSessionCleanupHeld'});expect(held.sessionToken).toBe('');
});
it('does no HTTP for an already elapsed deadline or cancellation',async()=>{
 for(const patch of [{deadlineMs:NOW},{signal:AbortSignal.abort()}]){const f={...fixture(),...patch},m=mockHttp();await expect(withCiSmokeReadSession(f,()=>{},m.seams)).rejects.toThrow();expect(m.calls).toHaveLength(0);}
});
it('rejects clock expiry between asynchronous preparation and HTTP dispatch',async()=>{
 const f=fixture(),m=mockHttp();let clock=NOW;const pending=withCiSmokeReadSession(f,()=>{}, {...m.seams,now:()=>clock});queueMicrotask(()=>{clock=f.deadlineMs;});await expect(pending).rejects.toThrow();expect(m.calls).toHaveLength(0);
});
it('propagates cancellation to use and waits for callback cleanup before erasing its credentials',async()=>{
 const f=fixture(),m=mockHttp(),controller=new AbortController();let held,cleaned=false;
 await expect(withCiSmokeReadSession({...f,signal:controller.signal},async({credentials,signal})=>{
  held=credentials;const cancelled=new Promise(resolve=>signal.addEventListener('abort',resolve,{once:true}));controller.abort();await cancelled;expect(credentials.sessionToken).not.toBe('');cleaned=true;throw Error('cancelled');
 },m.seams)).rejects.toThrow();expect(cleaned).toBe(true);expect(held.sessionToken).toBe('');expect(m.handler.destroyed).toBe(true);
});
it('marks an unresponsive callback cleanup as unknown instead of admitting the next credentials',async()=>{
 const f=fixture(),m=mockHttp(),controller=new AbortController();let held;
 await expect(withCiSmokeReadSession({...f,signal:controller.signal},({credentials})=>{held=credentials;controller.abort();return new Promise(()=>{});},m.seams)).rejects.toMatchObject({code:'ECLEANUP'});expect(held.sessionToken).toBe('');expect(m.handler.destroyed).toBe(true);
});
it('closes a response arriving after expiry without starting the next STS operation',async()=>{
 const f=fixture();let clock=NOW;const m=mockHttp(()=>{clock=f.deadlineMs;});
 await expect(withCiSmokeReadSession(f,()=>{}, {...m.seams,now:()=>clock})).rejects.toThrow();expect(m.calls).toHaveLength(1);expect(m.bodies.every(b=>b.closed)).toBe(true);expect(m.handler.destroyed).toBe(true);
});
it('holds an unclosed HTTP body and leaves no fake fixture behind',async()=>{
 const f=fixture();let release;const body=new Readable({read(){},destroy(error,callback){release=()=>callback(error);}}),m=mockHttp(({response})=>{response.body=body;});
 try{await expect(withCiSmokeReadSession({...f,deadlineMs:NOW+20},()=>{},m.seams)).rejects.toMatchObject({code:'ECLEANUP'});expect(m.calls).toHaveLength(1);expect(m.handler.destroyed).toBe(true);}
 finally{release?.();await new Promise(resolve=>setImmediate(resolve));}
 expect(body.closed).toBe(true);
});
it('composes the actual SDK session and archive reader with one S3 GET and byte-exact private output',async()=>{
 const captures=ciSmokeEvidenceFixture(),records={result:captures.json(captures.result),source:captures.json({identity:captures.expected.identity}),isolation:captures.json({isolationHash:captures.expected.isolationHash}),observations:captures.json(captures.expected),commandBindings:captures.json({invocationId:captures.expected.invocationId}),commandCatalog:captures.json(captures.expected.commandCatalog)};
 const objects=new Map(),visit=v=>{if(!v||typeof v!=='object')return;if(v.bytesHash&&v.canonicalHash){if(objects.has(v.bytesHash))return;const bytes=captures.objects.get(v.bytesHash);objects.set(v.bytesHash,bytes);visit(JSON.parse(bytes));return;}if(v.sha256&&(v.bytesLength!==undefined||v.gitMode)){objects.set(v.sha256,captures.objects.get(v.sha256));return;}Object.values(v).forEach(visit);};visit(records);
 const encoded=encodeCiSmokeEnvelope({records,objects:[...objects].map(([sha256,bytes])=>({sha256,bytes}))}),f=fixture();f.commitment=encoded.commitment;f.config.objectArn=f.config.bucketArn+'/'+ciSmokeArchiveKey(f.config.stage,f.commitment);
 const m=mockHttp(),calls=[];let s3Closed=false,held,saved;
 const requestHandler={async handle(request){calls.push({host:request.hostname,authorization:request.headers.authorization,token:request.headers['x-amz-security-token']});return {response:{statusCode:200,headers:{'content-length':String(encoded.bytes.length),'content-type':'application/json','x-amz-server-side-encryption':'aws:kms','x-amz-server-side-encryption-aws-kms-key-id':f.config.encryption.keyArn,'x-amz-server-side-encryption-bucket-key-enabled':'true'},body:Readable.from([encoded.bytes])}};},destroy(){s3Closed=true;}};
 const result=await withCiSmokeReadSession(f,async({credentials,config,signal})=>{
  held=credentials;const read=await getCiSmokeEnvelope(f.commitment,{credentials,config,signal,deadlineMs:f.deadlineMs,now:()=>NOW,requestHandler});saved=Buffer.from(read.envelopeBytes);expect(s3Closed).toBe(true);expect(credentials.sessionToken).not.toBe('');return read.commitment.envelopeSha256;
 },m.seams);
 expect(calls).toHaveLength(1);expect(calls[0].host).toBe('s3.us-east-1.amazonaws.com');expect(calls[0].authorization).toContain(m.issued.accessKeyId);expect(calls[0].token).toBe(m.issued.sessionToken);expect(result).toBe(f.commitment.envelopeSha256);expect(saved).toEqual(encoded.bytes);expect(held.sessionToken).toBe('');expect(m.handler.destroyed).toBe(true);
});
