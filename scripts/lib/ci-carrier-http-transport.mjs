/** Fixed native HTTPS: every dispatch is prepaid, no implicit retry/redirect/decompression. */
import {request as requestHttps,Agent} from 'node:https';
import {Readable} from 'node:stream';
import {createHash} from 'node:crypto';
const need=(v,c)=>{if(!v)throw Error(c);},sha=b=>createHash('sha256').update(b).digest('hex');
async function* chunks(stream,cap,{alive,observe,frameBytes}){
 need(stream instanceof Readable&&!stream.readableObjectMode&&stream.readableEncoding===null,'CarrierHttpRawStream');let n=0,used=0,frame=Buffer.alloc(Math.min(frameBytes,cap+1));
 while(n<=cap){
  alive();const b=stream.readableLength>0?stream.read(Math.min(frame.length-used,stream.readableLength,cap-n+1)):null;
  if(b!==null){need(b instanceof Uint8Array,'CarrierHttpRawBytes');observe(b);n+=b.length;b.copy(frame,used);used+=b.length;if(used===frame.length){yield frame;used=0;frame=Buffer.alloc(Math.min(frameBytes,cap-n+1));}continue;}
  if(stream.readableEnded){if(used)yield frame.subarray(0,used);return;}if(stream.destroyed)throw Error('CarrierHttpTruncated');
  await new Promise((resolve,reject)=>{const done=()=>{clear();resolve();},fail=()=>{clear();reject(Error('CarrierHttpClosed'));},clear=()=>{stream.off('readable',done);stream.off('end',done);stream.off('close',fail);stream.off('error',fail);};stream.once('readable',done);stream.once('end',done);stream.once('close',fail);stream.once('error',fail);});
 }
}
export function createCarrierRawHttp({account,deadlineMs,now=Date.now,track=p=>p,request=requestHttps}){
 const agent=request===requestHttps?new Agent({keepAlive:false,maxSockets:1,rejectUnauthorized:true}):undefined,requests=new Set(),streams=new Set(),pending=new Set();let closed=false,closing;
 const check=()=>{need(!closed&&now()<deadlineMs,'CarrierHttpDeadline');account.check();};
 async function execute(id,{url,method='GET',headers={},body=Buffer.alloc(0),statuses=[200]}){
  check();const u=new URL(url);need(u.protocol==='https:'&&!u.username&&!u.password&&!u.port&&!u.hash,'CarrierHttpUrl');need(['GET','POST','PUT'].includes(method)&&body instanceof Uint8Array,'CarrierHttpMethod');
  const slot=account.before(id,{method,urlHash:sha(u.href),requestBytes:body.length}),bytes=Buffer.from(body),requestHeaders={...headers};let req,response,timer,dispatched=false,hashedBytes=0;const responseHash=createHash('sha256');
  try{
   await slot.ready;need(Buffer.byteLength(JSON.stringify({method,url:u.href,headers:requestHeaders}))<=account.policy.requestMetadataBytes,'CarrierHttpMetadata');check();slot.finalGuard();dispatched=true;
   const result=new Promise((resolve,reject)=>{
    req=request({protocol:'https:',hostname:u.hostname,path:u.pathname+u.search,method,headers:{...requestHeaders,'accept-encoding':'identity','content-length':String(bytes.length)},agent,rejectUnauthorized:true,maxHeaderSize:account.policy.responseMetadataBytes},resolve);req.maxHeadersCount=0;requests.add(req);req.once('close',()=>requests.delete(req));req.once('error',()=>reject(Error('CarrierHttpNetwork')));
    timer=setTimeout(()=>{req.destroy();response?.destroy();reject(Error('CarrierHttpTimeout'));},Math.max(1,Math.min(account.policy.requestMs,deadlineMs-now())));
    slot.sent(bytes);req.end(bytes);
   });
   response=await track(result);streams.add(response);response.once('close',()=>streams.delete(response));need(Buffer.byteLength(JSON.stringify(response.rawHeaders??response.headers??{}))<=account.policy.responseMetadataBytes,'CarrierHttpMetadata');
   const parts=[];let count=0;
   for await(const b of chunks(response,slot.caps.responseBytes,{alive:()=>need(!closed&&now()<deadlineMs,'CarrierHttpDeadline'),observe:b=>{slot.observe(b);responseHash.update(b);hashedBytes+=b.length;},frameBytes:account.policy.streamFrameBytes})){check();slot.received(b);count+=b.length;parts.push(b);}
   slot.finishBody();const raw=Buffer.concat(parts,count),h=response.headers??{},status=response.statusCode;
   need(!h['content-encoding']||h['content-encoding']==='identity','CarrierHttpEncoding');
   need(h['content-length']===undefined||/^(0|[1-9][0-9]*)$/.test(String(h['content-length']))&&Number(h['content-length'])===count,'CarrierHttpLength');
   need(statuses.includes(status),'CarrierHttpStatus');await slot.complete({status,responseHash:responseHash.copy().digest('hex')});return {status,headers:{...h},bytes:raw};
  }catch(error){if(dispatched)await slot.unknown({responseHash:responseHash.copy().digest('hex'),hashedResponseBytes:hashedBytes});else await slot.abandon();const safe=Error(/^Carrier[A-Za-z]+$/.test(error.message??'')?error.message:'CarrierHttpNetwork');if(error.code==='ECLEANUP'){safe.code='ECLEANUP';safe.cleanupConfirmed=false;}throw safe;}
  finally{clearTimeout(timer);req?.destroy();response?.destroy();bytes.fill(0);for(const key of Object.keys(requestHeaders))delete requestHeaders[key];}
 }
 return Object.freeze({abort(){for(const r of requests)r.destroy();for(const s of streams)s.destroy();},request(id,input){const p=execute(id,input);pending.add(p);p.then(()=>pending.delete(p),()=>pending.delete(p));return p;},close(){return closing??=(async()=>{closed=true;for(const r of requests)r.destroy();for(const s of streams)s.destroy();agent?.destroy();let timer;
  const drained=await Promise.race([Promise.allSettled([...pending]).then(async()=>{await Promise.all([...requests,...streams].filter(v=>!v.closed).map(v=>new Promise(resolve=>v.once('close',resolve))));return true;}),new Promise(resolve=>{timer=setTimeout(()=>resolve(false),account.policy.drainMs);})]);clearTimeout(timer);if(!drained){await account.hold();throw Object.assign(Error('CarrierHttpCleanupUnknown'),{code:'ECLEANUP',cleanupConfirmed:false});}account.close();return {cleanupConfirmed:true};})();},get pending(){return pending.size;}});
}
