// Synthetic R13 base built from an already cached local Node image. Docker
// inspect/save cannot pull; no registry traffic or CI provenance is invented.
import {execFileSync} from 'node:child_process';
import {openSync,readSync,closeSync,unlinkSync} from 'node:fs';
import {rootCertificates} from 'node:tls';
import {join} from 'node:path';
import {sha} from './ci-carrier.fixture.mjs';
import {IMAGE_MEDIA} from './lib/production-image-graph.mjs';

function tar(rows){const blocks=[];for(const r of rows){const b=Buffer.from(r.body??''),h=Buffer.alloc(512),oct=(v,at,n)=>h.write(v.toString(8).padStart(n-1,'0')+'\0',at,n);h.write(r.path);oct(r.mode??0o644,100,8);oct(0,108,8);oct(0,116,8);oct(b.length,124,12);oct(0,136,12);h.fill(32,148,156);h[156]=(r.type??'0').charCodeAt(0);h.write('ustar\0',257);h.write('00',263);h.write([...h].reduce((n,b)=>n+b,0).toString(8).padStart(6,'0')+'\0 ',148);blocks.push(h,b,Buffer.alloc((512-b.length%512)%512));}return Buffer.concat([...blocks,Buffer.alloc(1024)]);}
export function cachedCarrierNativeBase(directory,{variant='valid'}={}){
 if(!['valid','missing-ca','invalid-ca','missing-primitive','unsafe-home'].includes(variant))throw Error('SyntheticBaseVariant');
 const run=args=>execFileSync('/usr/bin/docker',['--host','unix:///var/run/docker.sock','--config',directory,...args],{env:{PATH:'/usr/bin:/bin',HOME:directory,DOCKER_CONFIG:directory},encoding:'utf8',timeout:30000,maxBuffer:1048576,stdio:'pipe'});
 const inspection=JSON.parse(run(['image','inspect','node:24-alpine']));if(inspection.length!==1||inspection[0].Architecture!=='arm64'||inspection[0].Os!=='linux')throw Error('SyntheticNativeBaseMissing');
 const archive=join(directory,'cached-node.tar');run(['image','save','--output',archive,'node:24-alpine']);
 const fd=openSync(archive,'r'),members=new Map();let at=0;
 try{
  while(true){const h=Buffer.alloc(512);if(readSync(fd,h,0,512,at)!==512)throw Error('SyntheticTarShort');if(h.every(b=>b===0))break;const str=b=>b.subarray(0,b.indexOf(0)<0?b.length:b.indexOf(0)).toString(),prefix=str(h.subarray(345,500)),name=(prefix?prefix+'/':'')+str(h.subarray(0,100)),size=parseInt(str(h.subarray(124,136)).trim()||'0',8);if(!Number.isSafeInteger(size)||size<0||size>268435456||members.has(name)||members.size>=4096)throw Error('SyntheticTarMember');members.set(name,{at:at+512,size});at+=512+Math.ceil(size/512)*512;}
  const bytes=name=>{const m=members.get(name);if(!m)throw Error('SyntheticTarMissing');const b=Buffer.alloc(m.size);if(readSync(fd,b,0,b.length,m.at)!==b.length)throw Error('SyntheticTarShort');return b;};
  const docs=new Map();for(const [name,m]of members)if(/^blobs\/sha256\/[a-f0-9]{64}$/.test(name)&&m.size<=1048576){try{docs.set('sha256:'+name.slice(13),JSON.parse(bytes(name)));}catch{}}
  const selected=[...docs].filter(([,v])=>v.schemaVersion===2&&Array.isArray(v.layers)&&docs.get(v.config?.digest)?.architecture==='arm64');if(selected.length!==1)throw Error('SyntheticNativeBaseAmbiguous');
  const old=selected[0][1],config=structuredClone(docs.get(old.config.digest)),data=new Map();
  for(const d of old.layers){const b=bytes('blobs/sha256/'+d.digest.slice(7));if(b.length!==d.size||'sha256:'+sha(b)!==d.digest)throw Error('SyntheticNativeBaseDigest');data.set(d.digest,b);}
  const put=(value,mediaType)=>{const b=Buffer.isBuffer(value)?value:Buffer.from(JSON.stringify(value)),d={digest:'sha256:'+sha(b),size:b.length,mediaType};data.set(d.digest,b);return d;};
  const ca=Buffer.from(variant==='invalid-ca'?'invalid certificate':rootCertificates[0]),rows=[{path:'bootstrap',type:'5',mode:0o755}];
  if(variant!=='missing-ca')rows.push({path:'bootstrap/global-bundle.pem',body:ca,mode:0o644});
  if(variant==='missing-primitive')rows.push({path:'bin/.wh.setpriv',body:'',mode:0o644});
  const layer=put(tar(rows),IMAGE_MEDIA.tar);config.rootfs.diff_ids.push(layer.digest);config.config.Env=(config.config.Env??[]).filter(e=>!e.startsWith('NODE_EXTRA_CA_CERTS='));if(variant!=='missing-ca')config.config.Env.push('NODE_EXTRA_CA_CERTS=/bootstrap/global-bundle.pem');
  if(variant==='unsafe-home')config.config.Env.push('HOME=/root');
  const cfg=put(config,IMAGE_MEDIA.config),arm=put({schemaVersion:2,mediaType:IMAGE_MEDIA.manifest,config:cfg,layers:[...old.layers,layer]},IMAGE_MEDIA.manifest),root=put({schemaVersion:2,mediaType:IMAGE_MEDIA.index,manifests:[{...arm,platform:{os:'linux',architecture:'arm64'}}]},IMAGE_MEDIA.index);
  return {data,root,arm,cfg,ca};
 }finally{closeSync(fd);unlinkSync(archive);}
}
