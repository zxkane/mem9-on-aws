import {getExpiration} from '../../node_modules/@actions/artifact/lib/internal/upload/retention.js';
import {open,lstat,realpath} from 'node:fs/promises';
import {constants} from 'node:fs';
import {resolve,join} from 'node:path';
import {crc32} from 'node:zlib';
import {createHash} from 'node:crypto';
import {BlockBlobClient} from '@azure/storage-blob';
import {createHttpHeaders} from '@azure/core-rest-pipeline';
import {toHttpHeadersLike} from '@azure/core-http-compat';
import {ArtifactServiceClientJSON,StringValue} from '../../node_modules/@actions/artifact/lib/generated/index.js';
import {parseCarrierStartupArtifact} from './ci-carrier-artifact.mjs';
import {parseCiSmokeJson} from './ci-smoke-evidence.mjs';
import {carrierArtifactLocation} from './ci-carrier-github-raw.mjs';
const need=(v,c)=>{if(!v)throw Error(c);},sha=b=>createHash('sha256').update(b).digest('hex');
const fields=['dev','ino','size','mtimeNs','ctimeNs','mode','uid','nlink'];
function zipClaim(raw){
 need(raw.length<=1024,'CarrierArtifactClaimSize');const name=Buffer.from('claim.json'),header=Buffer.alloc(40),central=Buffer.alloc(56),end=Buffer.alloc(22),crc=crc32(raw);
 header.writeUInt32LE(0x04034b50);header.writeUInt16LE(20,4);header.writeUInt32LE(crc,14);header.writeUInt32LE(raw.length,18);header.writeUInt32LE(raw.length,22);header.writeUInt16LE(name.length,26);name.copy(header,30);
 central.writeUInt32LE(0x02014b50);central.writeUInt16LE(20,4);central.writeUInt16LE(20,6);central.writeUInt32LE(crc,16);central.writeUInt32LE(raw.length,20);central.writeUInt32LE(raw.length,24);central.writeUInt16LE(name.length,28);name.copy(central,46);
 end.writeUInt32LE(0x06054b50);end.writeUInt16LE(1,8);end.writeUInt16LE(1,10);end.writeUInt32LE(central.length,12);end.writeUInt32LE(header.length+raw.length,16);return Buffer.concat([header,raw,central,end]);
}
export async function uploadCarrierStartupArtifact({http,env,name,file,directory,check,local}){
 check();need(name.startsWith('mem9-carrier-start-')&&/^[a-f0-9]{64}$/.test(name.slice('mem9-carrier-start-'.length)),'CarrierArtifactName');
 need(resolve(directory)===directory&&file===join(directory,'claim.json')&&await realpath(directory)===directory,'CarrierArtifactDirectory');
 // Existing claim preparation tariff; the caller places it before creating its file.
 const token=env.ACTIONS_RUNTIME_TOKEN,endpoint=env.ACTIONS_RESULTS_URL;need(token===process.env.ACTIONS_RUNTIME_TOKEN&&endpoint===process.env.ACTIONS_RESULTS_URL&&typeof token==='string'&&token.length<=65536,'CarrierArtifactRuntime');
 const base=new URL(endpoint);need(base.protocol==='https:'&&!base.username&&!base.password&&!base.port&&!base.hash&&base.hostname.endsWith('.actions.githubusercontent.com'),'CarrierArtifactEndpoint');
 const payload=parseCiSmokeJson(Buffer.from(token.split('.')[1]??'','base64url').toString('utf8')),scopes=String(payload.scp??'').split(' ').filter(x=>x.startsWith('Actions.Results:'));
 need(scopes.length===1,'CarrierArtifactBackend');const ids=scopes[0].split(':');need(ids.length===3&&ids.slice(1).every(v=>/^[a-f0-9-]{36}$/i.test(v)),'CarrierArtifactBackend');
 let raw,zip;
 try{
 const before=await lstat(file,{bigint:true});need(before.isFile()&&!before.isSymbolicLink()&&before.uid===BigInt(process.getuid())&&(before.mode&511n)===384n&&before.nlink===1n&&before.size>0n&&before.size<=1024n,'CarrierArtifactFile');
 const fd=await open(file,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
 try{const opened=await fd.stat({bigint:true});need(fields.every(k=>before[k]===opened[k]),'CarrierArtifactFile');raw=Buffer.alloc(Number(before.size)+1);let n=0;while(n<raw.length){const {bytesRead}=await fd.read(raw,n,raw.length-n,n);if(!bytesRead)break;n+=bytesRead;}need(n===Number(before.size),'CarrierArtifactChanged');raw=raw.subarray(0,n);const after=await fd.stat({bigint:true}),named=await lstat(file,{bigint:true});need(fields.every(k=>before[k]===after[k]&&before[k]===named[k]),'CarrierArtifactChanged');}finally{await fd.close();}
 zip=zipClaim(raw);parseCarrierStartupArtifact(zip);need(zip.length<=65536,'CarrierArtifactZip');
 const rpc=new ArtifactServiceClientJSON({async request(service,method,contentType,data){
  need(service==='github.actions.results.api.v1.ArtifactService'&&['CreateArtifact','FinalizeArtifact'].includes(method)&&contentType==='application/json','CarrierArtifactRpc');check();need(env.ACTIONS_RUNTIME_TOKEN===token&&env.ACTIONS_RESULTS_URL===endpoint,'CarrierArtifactRuntimeChanged');
  const r=await http.request(method==='CreateArtifact'?'artifact-create':'artifact-finalize',{url:new URL('/twirp/'+service+'/'+method,base).href,method:'POST',headers:{authorization:'Bearer '+token,'content-type':contentType,'user-agent':'mem9-carrier'},body:Buffer.from(JSON.stringify(data))});try{return parseCiSmokeJson(new TextDecoder('utf-8',{fatal:true}).decode(r.bytes));}finally{r.bytes.fill(0);}
 }});
 const request={workflowRunBackendId:ids[1],workflowJobRunBackendId:ids[2],name,mimeType:StringValue.create({value:'application/zip'}),version:7,expiresAt:getExpiration(2)};
 const created=await rpc.CreateArtifact(request);need(created.ok===true,'CarrierArtifactCreate');const url=carrierArtifactLocation(created.signedUploadUrl),blockId=Buffer.from('carrier-startup-block-0001').toString('base64');let phase=0;
 const client=new BlockBlobClient(url.href,undefined,{retryOptions:{maxTries:1},keepAliveOptions:{enable:false},httpClient:{async sendRequest(r){
  const u=new URL(r.url);need(u.origin===url.origin&&u.pathname===url.pathname&&r.method==='PUT','CarrierArtifactBlobScope');for(const [k,v]of url.searchParams)need(u.searchParams.get(k)===v,'CarrierArtifactSasChanged');
  need([...u.searchParams.keys()].every(k=>url.searchParams.has(k)||['comp','blockid'].includes(k)),'CarrierArtifactBlobQuery');const wanted=phase===0?'block':'blocklist';need(phase<2&&u.searchParams.get('comp')===wanted&&(phase!==0||u.searchParams.get('blockid')===blockId),'CarrierArtifactBlobOrder');
  const v=typeof r.body==='function'?r.body():r.body,body=Buffer.from(v??'');if(phase===0)need(body.equals(zip),'CarrierArtifactBlobBytes');const id=phase++===0?'artifact-block':'artifact-commit';
  try{const result=await http.request(id,{url:u.href,method:'PUT',headers:r.headers.rawHeaders(),body,statuses:[201]});try{return {request:r,status:result.status,headers:toHttpHeadersLike(createHttpHeaders(result.headers)),bodyAsText:result.bytes.toString('utf8')};}finally{result.bytes.fill(0);}}finally{body.fill(0);}
 }} });
 await client.stageBlock(blockId,zip,zip.length);await client.commitBlockList([blockId],{blobHTTPHeaders:{blobContentType:'application/zip'}});check();
  const done=await rpc.FinalizeArtifact({workflowRunBackendId:ids[1],workflowJobRunBackendId:ids[2],name,size:String(zip.length),hash:StringValue.create({value:'sha256:'+sha(zip)})});need(done.ok===true&&/^[1-9][0-9]*$/.test(done.artifactId)&&Number.isSafeInteger(Number(done.artifactId)),'CarrierArtifactFinalize');return {id:Number(done.artifactId),size:zip.length,digest:sha(zip)};
 }catch(error){const safe=Error(/^Carrier[A-Za-z]+$/.test(error.message??'')?error.message:'CarrierArtifactSdkHeld');if(error.code==='ECLEANUP'){safe.code='ECLEANUP';safe.cleanupConfirmed=false;}throw safe;}finally{raw?.fill(0);zip?.fill(0);}
}
