// Offline synthetic Docker evidence. No AWS/registry operation or host image
// extraction: graph/FS parsers stream only the Docker archive's blob members.
import {execFileSync} from 'node:child_process';
import {mkdtempSync,mkdirSync,writeFileSync,readFileSync,rmSync,openSync,readSync,closeSync,createReadStream} from 'node:fs';
import {join,dirname} from 'node:path';
import {tmpdir} from 'node:os';
import {randomBytes} from 'node:crypto';
import {createImageBudget,readControlImageGraph,controlImageGraphBinding} from './lib/production-image-graph.mjs';
import {inspectImageFilesystem} from './lib/production-image-filesystem.mjs';

function tarMembers(path){
 const fd=openSync(path,'r'),members=new Map();let offset=0;
 try{while(true){const header=Buffer.alloc(512);if(readSync(fd,header,0,512,offset)!==512)throw Error('FixtureTarTruncated');if(header.every(b=>b===0))break;
  const text=buffer=>buffer.subarray(0,buffer.indexOf(0)<0?buffer.length:buffer.indexOf(0)).toString(),name=text(header.subarray(0,100)),prefix=text(header.subarray(345,500)),member=(prefix?prefix+'/':'')+name,size=parseInt(text(header.subarray(124,136)).trim()||'0',8);
  if(!Number.isSafeInteger(size)||size<0||members.has(member)||members.size>4096)throw Error('FixtureTarMember');
  members.set(member,{offset:offset+512,size});offset+=512+Math.ceil(size/512)*512;
 }}finally{closeSync(fd);}
 return members;
}

export function dockerArtifactFixture(){
 const directories=[],images=[],containers=new Set(),heldDirectories=new Set(),cache=new Map();
 const root=mkdtempSync(join(tmpdir(),'nonroot-docker-fixture-'));directories.push(root);
 const run=args=>execFileSync('/usr/bin/docker',['--host','unix:///var/run/docker.sock','--config',root,...args],{env:{PATH:'/usr/bin:/bin',HOME:root,DOCKER_CONFIG:root},encoding:'utf8',stdio:['pipe','pipe','pipe'],maxBuffer:4194304,timeout:120000});
 const factory=({variant='valid'}={})=>async({scope,bodies,archiveBytes})=>{
  let artifact=cache.get(variant);
  if(!artifact){
   const directory=mkdtempSync(join(root,'build-')),tag='mem9-path-observer-test:'+randomBytes(12).toString('hex');images.push(tag);
   for(const [path,body]of bodies){if(['/usr/local/bin/node','/bin/busybox','/lib/native-loader.so'].includes(path))continue;const file=join(directory,'files',path.slice(1));mkdirSync(dirname(file),{recursive:true});writeFileSync(file,body);}
   const additions={valid:'',rootOwner:'RUN chown 1000:1000 /\n',rootWritable:'RUN chmod 0777 /\n',poison:'ENV NODE_OPTIONS=--require=/unreviewed\n',preload:'RUN touch /etc/ld.so.preload\n',symlink:'RUN mkdir /real-bootstrap && cp -a /bootstrap/. /real-bootstrap/ && rm -rf /bootstrap && ln -s /real-bootstrap /bootstrap\n'};
   if(!Object.hasOwn(additions,variant))throw Error('FixtureVariant');
   writeFileSync(join(directory,'Dockerfile'),'FROM node:24-alpine\nCOPY --chmod=0644 files/ /\nRUN chmod -R a+rX,go-w /bootstrap\n'+additions[variant]);
   run(['build','--network=none','--pull=false','--platform=linux/arm64','-t',tag,directory]);
   const archive=join(directory,'image.tar');run(['image','save','--output',archive,tag]);const members=tarMembers(archive);
   const read=name=>{const m=members.get(name);if(!m||m.size>8388608)throw Error('FixtureMemberMissing');const fd=openSync(archive,'r');try{const bytes=Buffer.alloc(m.size);if(readSync(fd,bytes,0,m.size,m.offset)!==m.size)throw Error('FixtureMemberShort');return bytes;}finally{closeSync(fd);}};
   const top=JSON.parse(read('index.json')),rootDescriptor=top.manifests[0],rootBytes=read('blobs/sha256/'+rootDescriptor.digest.slice(7)),index=JSON.parse(rootBytes);
   const arm=index.manifests.filter(m=>m.platform?.os==='linux'&&m.platform.architecture==='arm64');if(arm.length!==1)throw Error('FixtureArm64');
   const child=JSON.parse(read('blobs/sha256/'+arm[0].digest.slice(7))),configBytes=read('blobs/sha256/'+child.config.digest.slice(7));
   const stream=descriptor=>{const m=members.get('blobs/sha256/'+descriptor.digest.slice(7));if(!m||m.size!==descriptor.size)throw Error('FixtureBlobMissing');return createReadStream(archive,{start:m.offset,end:m.offset+m.size-1,highWaterMark:65536});};
   artifact={tag,archive,members,read,stream,root:rootDescriptor,arm:arm[0],child,config:JSON.parse(configBytes)};cache.set(variant,artifact);
  }
  const {read,stream,root:descriptor,arm,child,config}=artifact,known=new Set();
  const graph=await readControlImageGraph({...scope,root:{mediaType:descriptor.mediaType,digest:descriptor.digest,size:descriptor.size},arm64Digest:arm.digest,configDigest:child.config.digest},{source:{async manifest(_repository,d){return read('blobs/sha256/'+d.digest.slice(7));},blob(_repository,d){return stream(d);}},store:{async put(d,input){for await(const _ of input){}known.add(d.digest);},open(d){if(!known.has(d.digest))throw Error('FixtureCacheMissing');return stream(d);}},budget:createImageBudget({credentialExpiresMs:Date.now()+3600000})});
  const filesystem=await inspectImageFilesystem(graph,{component:'bootstrap'}),{graphHash,...image}=controlImageGraphBinding(graph);
  const refs={rootManifest:archiveBytes(read('blobs/sha256/'+descriptor.digest.slice(7)),'image-graph'),arm64Manifest:archiveBytes(read('blobs/sha256/'+arm.digest.slice(7)),'image-graph'),config:archiveBytes(read('blobs/sha256/'+child.config.digest.slice(7)),'image-graph')};
  return {graph,filesystem,image,refs,config,nativePaths:['/lib/ld-musl-aarch64.so.1','/usr/lib/libstdc++.so.6','/usr/lib/libgcc_s.so.1']};
 };
 return {factory,containers,heldDirectories,run,async close(){for(const id of containers){try{run(['container','rm','--force','--volumes',id]);}catch{}}for(const image of images)run(['image','rm',image]);for(const dir of [...directories,...heldDirectories])rmSync(dir,{recursive:true,force:true});}};
}
