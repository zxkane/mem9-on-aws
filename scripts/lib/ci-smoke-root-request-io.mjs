import {S3Client,PutObjectCommand} from '@aws-sdk/client-s3';
import {NodeHttpHandler} from '@smithy/node-http-handler';
import {request as httpsRequest} from 'node:https';
import {Readable} from 'node:stream';
import {createHash} from 'node:crypto';
import {createCiRootRequest,ciRootRequestKey,ciRootReadyStatus,encodeCiRootRequest,CI_ROOT_REQUEST_POLICY as P} from './ci-smoke-root-request.mjs';
const need=(v,c)=>{if(!v)throw Error(c);},sha=b=>createHash('sha256').update(b).digest('hex');

/** Only the actual acquisition closure calls this fixed request/ready pair.
 * The existing CI session is reused; no additional credential provider, grant
 * or business authorization is created. */
export async function submitCiRootRequest(input,{env,config,scope,binding,startupReceipt,check,chargeLocal,chargeWork,save,deadlineMs,requestHandler,githubRequest,sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms))}){
 const local=(stage,n)=>chargeWork?chargeWork(stage,n):chargeLocal(n);
 check();const value=createCiRootRequest({...input,config,scope,binding,startupReceipt,requestedMs:Date.now()},{chargeLocal:n=>local('request',n),bounded:Boolean(chargeWork)});
 const bytes=encodeCiRootRequest(value,{chargeLocal:n=>local('request',n),bounded:Boolean(chargeWork)}),key=ciRootRequestKey(config,scope),storage=config.storage,requestRef=await save('root-request',bytes);
 check();let wire=0,githubWire=0,reads=0,s3,http,dispatched=false,cleanupFailed=false;
 const streams=new Set(),pending=new Set(),sockets=new Set(),controller=new AbortController();
 const close=r=>{try{r?.destroy?.();}catch{cleanupFailed=true;}};
 const track=p=>{const q=Promise.resolve(p).then(r=>{if(r.response?.body){streams.add(r.response.body);if(controller.signal.aborted)close(r.response.body);}return r;}).finally(()=>pending.delete(q));pending.add(q);q.catch(()=>{});return q;};
 const deadline=setTimeout(()=>{controller.abort();for(const r of sockets)close(r);for(const r of streams)close(r);},Math.max(1,deadlineMs-Date.now()));
 const charge=(n,stage='transport')=>{need(Number.isSafeInteger(n)&&n>=0,'CiRootWire');wire+=n;need(wire<=P.requestBytes+P.responseBytes+P.readyWireBytes+P.unknownBytes,'CiRootWireCap');local(stage,n);};
 try{
  http=requestHandler??new NodeHttpHandler({connectionTimeout:5000,requestTimeout:15000});const intentRef=await save('root-put-intent',{version:1,requestRef,key,requestBytes:bytes.length,responseCap:P.responseBytes,openedMs:Date.now()});
  let status,raw;
  const handler={async handle(q,options){
   check();need(!dispatched&&q.protocol==='https:'&&q.hostname===`s3.${config.region}.amazonaws.com`&&!q.port&&q.method==='PUT'&&q.path==='/'+storage.bucket+'/'+key,'CiRootRequestScope');
   need(Buffer.from(q.body??'').equals(bytes)&&q.headers['if-none-match']==='*'&&q.headers['x-amz-expected-bucket-owner']===config.account&&q.headers['x-amz-server-side-encryption']==='aws:kms'&&q.headers['x-amz-server-side-encryption-aws-kms-key-id']===storage.kmsKeyArn&&q.headers['x-amz-server-side-encryption-bucket-key-enabled']==='true','CiRootRequestProtection');
   await save('root-put-dispatch',{intentRef,requestHash:sha(bytes),requestBytes:bytes.length,dispatchedMs:Date.now()});check();dispatched=true;charge(bytes.length,'request');
   const r=(await track(http.handle(q,options))).response;status=r.statusCode;need(r.body instanceof Readable,'CiRootResponseStream');let n=0;const chunks=[];
   try{for await(const b of r.body){check();need(b instanceof Uint8Array,'CiRootResponseBytes');charge(b.length);n+=b.length;need(n<=P.responseBytes,'CiRootResponseCap');chunks.push(Buffer.from(b));}}finally{r.body.destroy();}
   local('transport',2*n);raw=Buffer.concat(chunks,n);need(r.headers['content-length']===undefined||Number(r.headers['content-length'])===raw.length,'CiRootResponseLength');return {response:{...r,body:Readable.from([raw])}};
  },destroy(){}};
  need(['AWS_ACCESS_KEY_ID','AWS_SECRET_ACCESS_KEY','AWS_SESSION_TOKEN'].every(k=>typeof env[k]==='string'&&env[k].length>0&&env[k].length<=65536),'CiRootCredentials');
  const credentials={accessKeyId:env.AWS_ACCESS_KEY_ID,secretAccessKey:env.AWS_SECRET_ACCESS_KEY,sessionToken:env.AWS_SESSION_TOKEN};
  s3=new S3Client({region:config.region,endpoint:`https://s3.${config.region}.amazonaws.com`,credentials,maxAttempts:1,ignoreConfiguredEndpointUrls:true,forcePathStyle:true,followRegionRedirects:false,requestChecksumCalculation:'WHEN_REQUIRED',responseChecksumValidation:'WHEN_REQUIRED',requestHandler:handler});
  const result=await s3.send(new PutObjectCommand({Bucket:storage.bucket,Key:key,ExpectedBucketOwner:config.account,Body:bytes,ContentLength:bytes.length,ContentType:'application/json',IfNoneMatch:'*',ServerSideEncryption:'aws:kms',SSEKMSKeyId:storage.kmsKeyArn,BucketKeyEnabled:true,ChecksumSHA256:Buffer.from(sha(bytes),'hex').toString('base64')}),{abortSignal:AbortSignal.timeout(Math.max(1,Math.min(15000,deadlineMs-Date.now())))});
  need(status===200&&result.ServerSideEncryption==='aws:kms'&&result.SSEKMSKeyId===storage.kmsKeyArn&&result.BucketKeyEnabled===true,'CiRootPutFailed');await save('root-put-complete',{intentRef,status,responseHash:sha(raw),requestBytes:bytes.length,responseBytes:raw.length,observedWireBytes:wire,completedMs:Date.now()});
  s3.destroy();http.destroy?.();s3=null;http=null;
  const token=env.GH_TOKEN??env.GITHUB_TOKEN;need(typeof token==='string'&&token.length>0,'CiRootGithubCredentials');
  const expectedContext=ciRootReadyStatus(config,scope,'0'.repeat(64)).context;
  for(let poll=0;reads<P.readyCalls;poll++){
   for(let page=1;page<=3;page++){
    check();need(++reads<=P.readyCalls&&githubWire+P.readyResponseBytes<=P.readyWireBytes&&Date.now()<deadlineMs,'CiRootReadyBudget');
    const path=`/repos/${binding.source.repository}/commits/${binding.source.mainRevision}/statuses?per_page=100&page=${page}`,ref=await save('root-ready-'+reads+'-intent',{path,responseCap:P.readyResponseBytes,requestedMs:Date.now()});
    const response=await track((githubRequest??(q=>new Promise((resolve,reject)=>{const req=httpsRequest({hostname:'api.github.com',port:443,path:q.path,method:'GET',headers:{Authorization:'Bearer '+token,Accept:'application/vnd.github+json','Accept-Encoding':'identity','User-Agent':'mem9-root-reader'},signal:controller.signal},resolve);sockets.add(req);req.once('error',reject);req.end();})))({path}));streams.add(response);
    const chunks=[];let n=0;try{for await(const chunk of response){check();need(chunk instanceof Uint8Array,'CiRootReadyBytes');charge(chunk.length);githubWire+=chunk.length;n+=chunk.length;need(n<=P.readyResponseBytes&&githubWire<=P.readyWireBytes,'CiRootReadyResponseCap');chunks.push(Buffer.from(chunk));}}finally{response.destroy?.();}
    // Concatenation, UTF-8 text and parsed ready records are paid before work.
    local('transport',4*n);const raw=Buffer.concat(chunks,n);need(response.statusCode===200&&(response.headers?.['content-encoding']===undefined||response.headers['content-encoding']==='identity'),'CiRootReadyStatus');need(response.headers?.['content-length']===undefined||Number(response.headers['content-length'])===n,'CiRootReadyLength');const statuses=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw));need(Array.isArray(statuses)&&statuses.length<=100,'CiRootReadyRows');
    const responseRef=await save('root-ready-'+reads+'-response',raw);await save('root-ready-'+reads+'-complete',{intentRef:ref,responseRef,status:200,responseHash:sha(raw),responseBytes:n,completedMs:Date.now()});
    const rows=statuses.filter(v=>v.context===expectedContext);if(rows.length){need(rows.every(v=>v.creator?.id===config.startup.ownerGithubActorId&&v.state==='success'&&/^[a-f0-9]{64}$/.test(v.description))&&new Set(rows.map(v=>v.description)).size===1,'CiRootReadyOwner');return {archiveHash:rows[0].description,requestRef,observedWireBytes:wire};}
    if(statuses.length<100)break;
   }
   need(Date.now()+5000<deadlineMs,'CiRootReadyExpired');await sleep(5000);
  }throw Error('CiRootReadyExhausted');
 }catch(error){await save('root-request-held',{requestRef,dispatched,observedWireBytes:wire,refund:0});throw error;}
 finally{
  clearTimeout(deadline);controller.abort();close(s3);close(http);for(const r of sockets)close(r);for(const r of streams)close(r);
  const drain=async p=>{let timer;try{await Promise.race([p,new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('CiRootCleanupTimeout')),1000);})]);}catch{cleanupFailed=true;}finally{clearTimeout(timer);}};
  await drain(Promise.allSettled([...pending]));
  await drain(Promise.all([...streams,...sockets].filter(r=>!r.closed).map(r=>new Promise(resolve=>r.once('close',resolve)))));
  if(cleanupFailed)throw Object.assign(Error('CiRootCleanupHeld'),{code:'ECLEANUP',cleanupComplete:false});
 }
}
