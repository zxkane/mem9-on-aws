/** In-memory, fixed-purpose CI evidence reader session. The caller must finish
 * its pure GitHub source precheck first. This module never writes env/files,
 * emits outputs, loads ambient credentials or grants deployment admission. */
import {randomBytes} from 'node:crypto';
import {Agent} from 'node:https';
import {types} from 'node:util';
import {parseCiSmokeJson} from './ci-smoke-evidence.mjs';
import {ciSmokeArchiveLocation,buildCiSmokeReadPolicy} from './ci-smoke-private-archive.mjs';
import {sourceAllowanceLocation} from './ci-smoke-source-allowance.mjs';
import {inspectCompositionStsXml} from './production-control-composition-xml.mjs';

const STS_REGION='us-west-2',STS_HOST='sts.us-west-2.amazonaws.com',AUDIENCE='sts.amazonaws.com';
const MAX_BODY=131072,MAX_TOKEN=65536,CLEANUP_MS=1000;
const need=(ok,code='CiSmokeReadSessionInput')=>{if(!ok)throw Error(code);};
const cleanupError=()=>Object.assign(Error('CiSmokeReadSessionCleanupHeld'),{code:'ECLEANUP'});
const reasons=new Set(['CiSmokeAwsExpiration','CiSmokeReadSessionInput','CiSmokeReadSessionEnvironment','CiSmokeOidcEndpoint','CiSmokeOidcOrigin','CiSmokeOidcQuery','CiSmokeReadSessionDeadline','CiSmokeReadSessionAborted','CiSmokeReadSessionEndpoint','CiSmokeReadSessionBody','CiSmokeReadSessionBodyLimit','CiSmokeReadSessionHttp','CiSmokeReadSessionToken','CiSmokeReadSessionNoAmbientCredentials','CiSmokeReadSessionCredentials','CiSmokeReadSessionExpiration','CiSmokeReadSessionIdentity']);
const integer=(n,min=1)=>need(Number.isSafeInteger(n)&&n>=min);
function fields(value,required,optional=[]){
 need(value&&typeof value==='object'&&!Array.isArray(value)&&!types.isProxy(value)&&[Object.prototype,null].includes(Object.getPrototypeOf(value)));
 const ds=Object.getOwnPropertyDescriptors(value),keys=Reflect.ownKeys(ds);
 need(keys.every(k=>typeof k==='string'&&[...required,...optional].includes(k)&&ds[k].enumerable&&Object.hasOwn(ds[k],'value'))&&required.every(k=>Object.hasOwn(ds,k)));
}
export function parseConfiguredAwsExpiration(raw,now=Date.now()){
 try{
  need(typeof raw==='string'&&raw.length>0&&raw.length<=64&&Number.isSafeInteger(now)&&now>0);
  let iso=raw;if(raw.startsWith('"')){iso=JSON.parse(raw);need(typeof iso==='string'&&JSON.stringify(iso)===raw);}
  need(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(iso));const value=new Date(iso);
  need(Number.isSafeInteger(value.getTime())&&value.getTime()>now&&value.toISOString()===(iso.includes('.')?iso:iso.replace('Z','.000Z')));return value;
 }catch{throw Error('CiSmokeAwsExpiration');}
}
function environment(env){
 need(env&&typeof env==='object'&&!Array.isArray(env)&&!types.isProxy(env),'CiSmokeReadSessionEnvironment');
 const ds=Object.getOwnPropertyDescriptors(env),get=key=>{const d=ds[key];need(d&&Object.hasOwn(d,'value')&&typeof d.value==='string'&&d.value.length>0,'CiSmokeReadSessionEnvironment');return d.value;};
 const blocked=/^(?:AWS_(?:ACCESS_KEY_ID|SECRET_ACCESS_KEY|SESSION_TOKEN|SECURITY_TOKEN|PROFILE|DEFAULT_PROFILE|CONFIG_FILE|SHARED_CREDENTIALS_FILE|ROLE_ARN|ROLE_SESSION_NAME|WEB_IDENTITY_TOKEN_FILE|CONTAINER_CREDENTIALS_.*|ENDPOINT_URL(?:_.*)?|CA_BUNDLE|USE_FIPS_ENDPOINT|USE_DUALSTACK_ENDPOINT|STS_REGIONAL_ENDPOINTS)|NODE_(?:TLS_REJECT_UNAUTHORIZED|USE_ENV_PROXY|OPTIONS)|HTTPS?_PROXY|ALL_PROXY)$/;
 for(const key of Object.keys(ds))if(blocked.test(key))need(Object.hasOwn(ds[key],'value')&&!ds[key].value,'CiSmokeReadSessionEnvironment');
 need(get('GITHUB_ACTIONS')==='true'&&get('GITHUB_SERVER_URL')==='https://github.com','CiSmokeReadSessionEnvironment');
 const repository=get('GITHUB_REPOSITORY'),run=get('GITHUB_RUN_ID'),attempt=get('GITHUB_RUN_ATTEMPT');
 need(repository.length<=256&&/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository)&&/^[a-f0-9]{40}$/.test(get('GITHUB_SHA')),'CiSmokeReadSessionEnvironment');
 for(const n of [run,attempt]){need(/^[1-9][0-9]*$/.test(n),'CiSmokeReadSessionEnvironment');integer(Number(n));}
 const token=get('ACTIONS_ID_TOKEN_REQUEST_TOKEN');need(token.length<=MAX_TOKEN&&!/[\r\n\0]/.test(token),'CiSmokeReadSessionEnvironment');
 return {run,attempt,token,url:get('ACTIONS_ID_TOKEN_REQUEST_URL')};
}
function oidcUrl(raw){
 need(typeof raw==='string'&&raw.length<=4096&&!/[\s\\]/.test(raw),'CiSmokeOidcEndpoint');let url;try{url=new URL(raw);}catch{throw Error('CiSmokeOidcEndpoint');}
 // The Node action handler injects GenerateIdTokenUrl from the job's service
 // connection. Its internal path/version is not a public API contract. Keep
 // the existing service-origin policy and pin this exact URL for the request;
 // callers cannot supply an endpoint input and HTTP redirects remain denied.
 const host=/^[a-z0-9]+(?:-[a-z0-9]+)*\.actions\.githubusercontent\.com$/;
 need(url.protocol==='https:'&&!url.username&&!url.password&&!url.port&&!url.hash&&url.href===raw&&host.test(url.hostname),'CiSmokeOidcOrigin');
 const keys=[...url.searchParams.keys()];need(new Set(keys).size===keys.length,'CiSmokeOidcQuery');
 need(!url.searchParams.has('audience')||url.searchParams.get('audience')===AUDIENCE,'CiSmokeOidcQuery');url.searchParams.set('audience',AUDIENCE);return url;
}

/** use({credentials,config,signal}) must pass signal and the same deadline to
 * its bounded S3 reader. The third argument is a code-only clock/HTTP test
 * seam, never loaded from the protected configuration or workflow inputs. */
export async function withCiSmokeReadSession(input,use,seams={}){
 return withReadSession('smoke',input,use,seams);
}
/** Second closed purpose. The object is derived from the protected v2 config
 * and exact funded source checkpoint; no generic policy/key override exists. */
export async function withCiSmokeAllowanceReadSession(input,use,seams={}){
 return withReadSession('allowance',input,use,seams);
}
export async function withCiSmokeCompositionReadSession(input,use,seams={}){return withReadSession('smoke',input,use,seams,true);}
export async function withCiSmokeCompositionAllowanceReadSession(input,use,seams={}){return withReadSession('allowance',input,use,seams,true);}
export function buildCiSmokeAllowanceReadPolicy(input){
 const c=sourceAllowanceLocation(input),actions=['sts:GetCallerIdentity','s3:GetObject','kms:Decrypt'];
 // Keep both the action and resource exclusions: a direct resource-policy
 // grant must not turn this reader session into a broader S3/KMS principal.
 const Statement=[
  {Effect:'Deny',NotAction:actions,Resource:'*'},
  {Effect:'Allow',Action:'sts:GetCallerIdentity',Resource:'*'},
  {Effect:'Allow',Action:'s3:GetObject',Resource:c.objectArn,Condition:{StringEquals:{'s3:ResourceAccount':c.account}}},
  {Effect:'Deny',Action:'s3:GetObject',NotResource:c.objectArn},
  {Effect:'Deny',Action:'s3:GetObject',Resource:'*',Condition:{StringNotEquals:{'s3:ResourceAccount':c.account}}},
 ];
 const conditions={'kms:ViaService':`s3.${c.region}.amazonaws.com`,'kms:CallerAccount':c.account,'kms:EncryptionContext:aws:s3:arn':c.bucketArn};
 Statement.push({Effect:'Allow',Action:'kms:Decrypt',Resource:c.encryption.keyArn,Condition:{StringEquals:conditions}},{Effect:'Deny',Action:'kms:Decrypt',NotResource:c.encryption.keyArn});
 for(const [key,value]of Object.entries(conditions))Statement.push({Effect:'Deny',Action:'kms:Decrypt',Resource:'*',Condition:{StringNotEquals:{[key]:value}}});
 const Policy=JSON.stringify({Version:'2012-10-17',Statement});need(Buffer.byteLength(Policy)<=2048,'CiSmokeReadSessionInput');return Object.freeze({Policy,DurationSeconds:900});
}
async function withReadSession(purpose,input,use,seams,fixedSdk=false){
 let phase='precheck',client,transport,agent,controller,timer,envInfo,credential,assumeOutput,assumeCommand,jwt,identityOutput;
 let cleanupFailed=false,destroyed=false,removeOuter=()=>{},removeAbort=()=>{};
 const bodies=new Set(),buffers=new Set(),requests=new Set(),pending=new Set();let now=Date.now,expires=Infinity;
 const track=value=>{let p;p=Promise.resolve(value).finally(()=>pending.delete(p));pending.add(p);p.catch(()=>{});return p;};
 const destroy=()=>{if(!destroyed){destroyed=true;transport?.destroy();}};
 const closeBody=body=>{try{if(body&&!body.destroyed){need(typeof body.destroy==='function');body.destroy();}}catch{cleanupFailed=true;}};
 let result,error;
 try{
  fields(input,purpose==='smoke'?['config','commitment','env','deadlineMs']:['config','scope','roleArn','env','deadlineMs'],['signal']);fields(seams,[],['now','requestHandler','assertCurrent']);need(typeof use==='function'&&(seams.assertCurrent===undefined||typeof seams.assertCurrent==='function'));now=seams.now??Date.now;need(typeof now==='function');
  const started=now();integer(started);integer(input.deadlineMs);need(input.deadlineMs>started&&input.deadlineMs<=started+900000,'CiSmokeReadSessionDeadline');
  const selector={config:input.config,scope:input.scope,roleArn:input.roleArn};
  const location=purpose==='smoke'?ciSmokeArchiveLocation(input.config,input.commitment):sourceAllowanceLocation(selector),{key,expectedBucketOwner,...config}=location;Object.freeze(config);
  const policy=purpose==='smoke'?buildCiSmokeReadPolicy(config,input.commitment):buildCiSmokeAllowanceReadPolicy(selector);envInfo=environment(input.env);const url=oidcUrl(envInfo.url);
  controller=new AbortController();const abort=()=>{controller.abort();for(const body of bodies)closeBody(body);};
  if(input.signal){need(input.signal instanceof AbortSignal);if(input.signal.aborted)abort();else{input.signal.addEventListener('abort',abort,{once:true});removeOuter=()=>input.signal.removeEventListener('abort',abort);}}
  const check=()=>{seams.assertCurrent?.();const t=now();integer(t);need(!controller.signal.aborted&&t<input.deadlineMs&&t<expires,'CiSmokeReadSessionDeadline');};check();
  let rejectAbort;const aborted=new Promise((_,reject)=>{rejectAbort=()=>reject(Error('CiSmokeReadSessionAborted'));});aborted.catch(()=>{});controller.signal.addEventListener('abort',rejectAbort,{once:true});removeAbort=()=>controller.signal.removeEventListener('abort',rejectAbort);
  const wait=p=>Promise.race([track(p),aborted]);timer=setTimeout(abort,Math.max(1,input.deadlineMs-started));
  const [{STSClient,AssumeRoleWithWebIdentityCommand,GetCallerIdentityCommand},{NodeHttpHandler}]=await wait(Promise.all([import('@aws-sdk/client-sts'),import('@smithy/node-http-handler')]));check();
  if(seams.requestHandler)transport=seams.requestHandler;else{agent=new Agent({keepAlive:false,maxSockets:1,rejectUnauthorized:true});transport=new NodeHttpHandler({httpsAgent:agent,connectionTimeout:5000,requestTimeout:Math.min(30000,input.deadlineMs-now())});}
  need(typeof transport.handle==='function'&&typeof transport.destroy==='function');
  async function collect(body){
   need(body&&typeof body[Symbol.asyncIterator]==='function'&&typeof body.destroy==='function','CiSmokeReadSessionBody');bodies.add(body);const chunks=[];let size=0;
   try{for await(const chunk of body){check();need(chunk instanceof Uint8Array);size+=chunk.byteLength;need(size<=MAX_BODY,'CiSmokeReadSessionBodyLimit');chunks.push(Buffer.from(chunk));}check();const bytes=Buffer.concat(chunks,size);buffers.add(bytes);return bytes;}
   finally{closeBody(body);for(const chunk of chunks)chunk.fill(0);}
  }
  const handler={handle(request,options){
   check();need(request.protocol==='https:'&&request.hostname===(phase==='oidc'?url.hostname:STS_HOST),'CiSmokeReadSessionEndpoint');
   need(phase==='oidc'?request.method==='GET'&&request.path===url.pathname:request.method==='POST'&&request.path==='/','CiSmokeReadSessionEndpoint');requests.add(request);
   need(request.body===undefined||typeof request.body==='string'||request.body instanceof Uint8Array,'CiSmokeReadSessionBody');
   need(Buffer.byteLength(request.body??'')<=(phase==='identity'?1024:MAX_BODY)&&Buffer.byteLength(JSON.stringify(request.headers??{}))<=MAX_BODY,'CiSmokeReadSessionBodyLimit');
   return track((async()=>{let body;try{const out=await transport.handle(request,options);body=out.response?.body;if(body)bodies.add(body);check();const bytes=await collect(body);need(out.response.statusCode===200,'CiSmokeReadSessionHttp');if(fixedSdk&&phase!=='oidc')inspectCompositionStsXml(bytes,phase==='assume'?'AssumeRoleWithWebIdentity':'GetCallerIdentity');return {response:{...out.response,body:bytes}};}finally{closeBody(body);}})());
  },destroy};
  phase='oidc';const tokenResponse=await wait(handler.handle({protocol:'https:',hostname:url.hostname,method:'GET',path:url.pathname,query:Object.fromEntries(url.searchParams),headers:{authorization:'Bearer '+envInfo.token,accept:'application/json'},body:undefined},{abortSignal:controller.signal}));check();
  let tokenPayload;try{tokenPayload=parseCiSmokeJson(new TextDecoder('utf-8',{fatal:true}).decode(tokenResponse.response.body),{maxBytes:MAX_BODY});}catch{throw Error('CiSmokeReadSessionToken');}
  fields(tokenPayload,['value'],['count']);need(tokenPayload.count===undefined||tokenPayload.count===1,'CiSmokeReadSessionToken');jwt=tokenPayload.value;tokenPayload=undefined;
  need(typeof jwt==='string'&&jwt.length>0&&jwt.length<=MAX_TOKEN&&/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(jwt),'CiSmokeReadSessionToken');envInfo.token='';
  const sessionName=`ci-smoke-read-${envInfo.run}-${envInfo.attempt}-${randomBytes(8).toString('hex')}`;need(sessionName.length<=64);
  client=new STSClient({region:STS_REGION,endpoint:'https://'+STS_HOST,ignoreConfiguredEndpointUrls:true,maxAttempts:1,...(fixedSdk?{defaultsMode:'legacy',retryMode:'standard',useFipsEndpoint:false,useDualstackEndpoint:false}:{}),requestHandler:handler,credentials:async()=>{check();need(phase==='identity'&&credential,'CiSmokeReadSessionNoAmbientCredentials');return credential;}});
  phase='assume';assumeCommand=new AssumeRoleWithWebIdentityCommand({RoleArn:config.roleArn,RoleSessionName:sessionName,WebIdentityToken:jwt,...policy});check();
  assumeOutput=await wait(client.send(assumeCommand,{abortSignal:controller.signal}));check();assumeCommand.input.WebIdentityToken='';jwt=undefined;
  const issued=assumeOutput.Credentials;need(issued&&['AccessKeyId','SecretAccessKey','SessionToken'].every(k=>typeof issued[k]==='string'&&issued[k].length>0&&issued[k].length<=MAX_TOKEN)&&issued.Expiration instanceof Date,'CiSmokeReadSessionCredentials');
  const expiration=parseConfiguredAwsExpiration(issued.Expiration.toISOString(),now());expires=expiration.getTime();need(expires<=now()+900000&&input.deadlineMs<=expires,'CiSmokeReadSessionExpiration');
  const roleName=config.roleArn.split('/').at(-1),expectedArn=`arn:aws:sts::${config.account}:assumed-role/${roleName}/${sessionName}`,assumed=assumeOutput.AssumedRoleUser;
  need(assumed?.Arn===expectedArn&&typeof assumed.AssumedRoleId==='string'&&assumed.AssumedRoleId.endsWith(':'+sessionName),'CiSmokeReadSessionIdentity');
  credential={accessKeyId:issued.AccessKeyId,secretAccessKey:issued.SecretAccessKey,sessionToken:issued.SessionToken,expiration};
  phase='identity';identityOutput=await wait(client.send(new GetCallerIdentityCommand({}),{abortSignal:controller.signal}));check();
  need(identityOutput.Account===config.account&&identityOutput.Arn===expectedArn&&identityOutput.UserId===assumed.AssumedRoleId,'CiSmokeReadSessionIdentity');
  phase='use';result=await wait(Promise.resolve().then(()=>{check();return use({credentials:credential,config,signal:controller.signal});}));check();
 }catch(cause){error=cause?.code==='ECLEANUP'?cleanupError():Object.assign(Error('CiSmokeReadSessionHeld'),{phase,reason:reasons.has(cause?.message)?cause.message:'CiSmokeReadSessionFailure'});}
 finally{
  clearTimeout(timer);controller?.abort();removeOuter();for(const body of bodies)closeBody(body);
  try{if(client)client.destroy();else destroy();}catch{cleanupFailed=true;}try{agent?.destroy();}catch{cleanupFailed=true;}
  // Cleanup is a finite physical drain, never a renewed authorization clock.
  const drain=async()=>{
   await Promise.allSettled([...pending]);
   await Promise.all([...bodies].filter(b=>!b.closed).map(body=>new Promise(resolve=>{body.once('close',resolve);})));
  };
  if(pending.size||[...bodies].some(b=>!b.closed)){
   let timeout;const done=await Promise.race([drain().then(()=>true),new Promise(resolve=>{timeout=setTimeout(()=>resolve(false),CLEANUP_MS);})]);clearTimeout(timeout);if(!done)cleanupFailed=true;
  }
  removeAbort();
  try{if(credential){credential.accessKeyId='';credential.secretAccessKey='';credential.sessionToken='';credential.expiration.setTime(0);}}catch{cleanupFailed=true;}
  try{if(assumeOutput?.Credentials){for(const k of ['AccessKeyId','SecretAccessKey','SessionToken'])assumeOutput.Credentials[k]='';if(assumeOutput.Credentials.Expiration instanceof Date)assumeOutput.Credentials.Expiration.setTime(0);else assumeOutput.Credentials.Expiration=undefined;}}catch{cleanupFailed=true;}
  try{if(assumeCommand)assumeCommand.input.WebIdentityToken='';}catch{cleanupFailed=true;}
  for(const request of requests)try{if(request.headers){delete request.headers.authorization;delete request.headers.Authorization;delete request.headers['x-amz-security-token'];}request.body=undefined;}catch{cleanupFailed=true;}
  for(const bytes of buffers)bytes.fill(0);if(envInfo)envInfo.token='';jwt=undefined;credential=undefined;assumeOutput=undefined;assumeCommand=undefined;identityOutput=undefined;
  if(cleanupFailed)error=cleanupError();
 }
 if(error)throw error;return result;
}
