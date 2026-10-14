import {createHash} from 'node:crypto';
import {createImageBudget,IMAGE_MEDIA} from './lib/production-image-graph.mjs';
const digest=b=>'sha256:'+createHash('sha256').update(b).digest('hex');
export function graphFixture({packageDatabaseText}={}){
 const data=new Map(),manifestCalls=[],blobCalls=[];
 const put=(value,mediaType)=>{const bytes=Buffer.isBuffer(value)?value:Buffer.from(JSON.stringify(value)),d={digest:digest(bytes),size:bytes.length,mediaType};data.set(d.digest,bytes);return d;};
 const roots=['llm-proxy','mnemo-server','qwen3-embed'].map(component=>{
  const layer=put(tar([{path:'app/'+component,body:'synthetic layer '+component},...(component==='mnemo-server'&&packageDatabaseText!==undefined?[{path:'lib/apk/db/installed',body:packageDatabaseText}]:[])]),IMAGE_MEDIA.tar);
  const config=put({architecture:'arm64',os:'linux',rootfs:{type:'layers',diff_ids:[layer.digest]}},IMAGE_MEDIA.config);
  const arm=put({schemaVersion:2,mediaType:IMAGE_MEDIA.manifest,config,layers:[layer]},IMAGE_MEDIA.manifest);
  const payload=put({_type:'https://in-toto.io/Statement/v0.1',subject:[{name:component,digest:{sha256:arm.digest.slice(7)}}],predicateType:'https://slsa.dev/provenance/v0.2',predicate:{complete:true}},IMAGE_MEDIA.attestation);
  const empty=put({},IMAGE_MEDIA.config),attest=put({schemaVersion:2,mediaType:IMAGE_MEDIA.manifest,config:empty,layers:[payload]},IMAGE_MEDIA.manifest);
  const root=put({schemaVersion:2,mediaType:IMAGE_MEDIA.index,manifests:[{...arm,platform:{os:'linux',architecture:'arm64'}},{...attest,platform:{os:'unknown',architecture:'unknown'},annotations:{'vnd.docker.reference.type':'attestation-manifest','vnd.docker.reference.digest':arm.digest}}]},IMAGE_MEDIA.index);
  return {component,sourceRepository:'example/preview/'+component,destinationRepository:'example/'+component,targetTag:'candidate-test',root,arm64Digest:arm.digest};
 });
 const cache=new Map();
 const store={async put(d,stream){const chunks=[];for await(const b of stream)chunks.push(b);cache.set(d.digest,Buffer.concat(chunks));},async *open(d){if(!cache.has(d.digest))throw Error('missing cache');yield cache.get(d.digest);}};
 const source={async manifest(repository,d){manifestCalls.push({repository,d});return data.get(d.digest);},async blob(repository,d){blobCalls.push({repository,d});return (async function*(){yield data.get(d.digest);})();}};
 const budget=createImageBudget({credentialExpiresMs:Date.now()+3600000});
 return {roots,data,put,store,source,budget,manifestCalls,blobCalls};
}

export function tar(entries){
 const blocks=[];for(const e of entries){const body=Buffer.from(e.body??''),h=Buffer.alloc(512);h.write(e.path,0,100);h.write('0000644\0',100);h.write('0000000\0',108);h.write('0000000\0',116);h.write(body.length.toString(8).padStart(11,'0')+'\0',124);h.write('00000000000\0',136);h.fill(32,148,156);h.write(e.type??'0',156);h.write(e.link??'',157,100);h.write('ustar\0',257);h.write('00',263);let sum=0;for(const b of h)sum+=b;h.write(sum.toString(8).padStart(6,'0')+'\0 ',148);blocks.push(h,body,Buffer.alloc((512-body.length%512)%512));}blocks.push(Buffer.alloc(1024));return Buffer.concat(blocks);
}
