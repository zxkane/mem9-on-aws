import {it,expect} from 'vitest';
import {nonrootDeploymentFixture} from './production-nonroot-provenance.fixture.mjs';
import {graphFixture,tar} from './production-image.fixture.mjs';
import {readControlImageGraph,controlImageGraphBinding,IMAGE_MEDIA} from './lib/production-image-graph.mjs';
import {inspectImageFilesystem,inspectImageFilesystemFile} from './lib/production-image-filesystem.mjs';
import {verifyNonrootControlArtifactFiles,inspectNonrootControlArtifactBinding} from './lib/production-nonroot-artifact.mjs';
import {bytesHash} from './production-nonroot-runtime.fixture.mjs';

function metadataTar(entries){
 const bytes=tar(entries);let offset=0;
 for(const e of entries){const header=bytes.subarray(offset,offset+512);header.write((e.mode??(e.type==='5'?0o755:e.type==='2'?0o777:0o644)).toString(8).padStart(7,'0')+'\0',100);header.write((e.uid??0).toString(8).padStart(7,'0')+'\0',108);header.fill(32,148,156);let sum=0;for(const byte of header)sum+=byte;header.write(sum.toString(8).padStart(6,'0')+'\0 ',148);offset+=512+Math.ceil(Buffer.byteLength(e.body??'')/512)*512;}
 return bytes;
}
async function fixture({implicit=false,nodeMode=0o755,nodeUid=0,parentMode=0o755,libraryMode=0o644}={}){
 const f=await nonrootDeploymentFixture(),b=structuredClone(f.build),native=graphFixture();
 const directories=['usr','usr/local','usr/local/bin','bin','lib','bootstrap','bootstrap/operator','bootstrap/operator/scripts'];
 const entries=implicit?[]:directories.map(path=>({path,type:'5',mode:parentMode}));
 const bodies=new Map([['/usr/local/bin/node','synthetic node bytes'],['/bin/busybox','synthetic setpriv bytes'],['/lib/native-loader.so','synthetic native library']]);
 for(const source of b.guardSource.files)bodies.set('/bootstrap/'+source.path.slice('docker/bootstrap/'.length),Buffer.from(await f.options().resolveBytes(source.blob)));
 for(const l of b.resolvedLaunches)if(l.originalModule.present)bodies.set(l.originalModule.value,'synthetic application '+l.originalModule.value);
 for(const [path,body]of bodies)entries.push({path:path.slice(1),body,mode:path==='/usr/local/bin/node'?nodeMode:path==='/bin/busybox'?0o755:path==='/lib/native-loader.so'?libraryMode:0o644,uid:path==='/usr/local/bin/node'?nodeUid:0});
 entries.push({path:'bin/setpriv',type:'2',link:'busybox'});
 const layer=native.put(metadataTar(entries),IMAGE_MEDIA.tar),config=native.put({architecture:'arm64',os:'linux',rootfs:{type:'layers',diff_ids:[layer.digest]},config:{Env:[]}},IMAGE_MEDIA.config),child=native.put({schemaVersion:2,mediaType:IMAGE_MEDIA.manifest,config,layers:[layer]},IMAGE_MEDIA.manifest),root=native.put({schemaVersion:2,mediaType:IMAGE_MEDIA.index,manifests:[{...child,platform:{os:'linux',architecture:'arm64'}}]},IMAGE_MEDIA.index);
 const graph=await readControlImageGraph({account:b.image.account,region:b.image.region,repositoryName:'mem9-on-aws/bootstrap',root,arm64Digest:child.digest,configDigest:config.digest},{source:native.source,store:native.store,budget:native.budget});
 const filesystem=await inspectImageFilesystem(graph,{component:'bootstrap'}),{graphHash,...image}=controlImageGraphBinding(graph),only={rootDigest:image.rootDigest,arm64Digest:image.arm64Digest,configDigest:image.configDigest};
 b.image=image;b.scan.image=image;b.guardImports.nodeRuntime.image=only;b.guardImports.nodeRuntime.executableSha256=bytesHash(bodies.get('/usr/local/bin/node'));
 const libraries=f.json({files:[{path:'/lib/native-loader.so',sha256:bytesHash(bodies.get('/lib/native-loader.so'))}]});b.guardImports.nodeRuntime.loaderAndNativeLibraries=libraries;
 for(const l of b.resolvedLaunches){l.image=image;l.guardImports=b.guardImports;l.environment.image=only;
  const p=structuredClone(f.a.value(l.primitiveEvidence)),fact=inspectImageFilesystemFile(filesystem,'/bin/setpriv');p.image=only;p.fileSha256=fact.sha256;p.resolvedPath=fact.resolvedPath;p.symlinkChain=f.json(fact.symlinkChain);p.loaderAndLibraries=libraries;l.primitiveEvidence=f.json(p);
  if(l.originalModule.present)l.originalModuleSha256.value=bytesHash(bodies.get(l.originalModule.value));
 }
 return {f,b,graph,filesystem,options:()=>({...f.options(),controlVerification:{graph,filesystem}})};
}
it('binds Node/primitive/guard/application/library hashes to actual CONTROL layer bytes without inventing root permissions',async()=>{
 const x=await fixture(),r=await verifyNonrootControlArtifactFiles(x.b,x.options());expect(r.unknownRuntimePaths).toEqual(['/']);
 expect(r.files.find(f=>f.path==='/usr/local/bin/node').sha256).toBe(x.b.guardImports.nodeRuntime.executableSha256);
 expect(r.files.find(f=>f.path==='/bin/setpriv').resolvedPath).toBe('/bin/busybox');expect(r).not.toHaveProperty('authorized');
});
for(const changed of ['node','primitive','library','application','guard'])it('rejects consistently rehashed '+changed+' claims against unchanged actual image bytes',async()=>{
 const x=await fixture(),b=x.b;
 if(changed==='node')b.guardImports.nodeRuntime.executableSha256='e'.repeat(64);
 if(changed==='primitive'){const l=b.resolvedLaunches[0],p=structuredClone(x.f.a.value(l.primitiveEvidence));p.fileSha256='e'.repeat(64);l.primitiveEvidence=x.f.json(p);}
 if(changed==='library')b.guardImports.nodeRuntime.loaderAndNativeLibraries=x.f.json({files:[{path:'/lib/native-loader.so',sha256:'e'.repeat(64)}]});
 if(changed==='application')b.resolvedLaunches.find(l=>l.originalModule.present).originalModuleSha256.value='e'.repeat(64);
 if(changed==='guard'){b.guardSource.files[0].sha256='e'.repeat(64);b.guardSource.files[0].blob.sha256='e'.repeat(64);const {nonrootHash}=await import('./lib/production-nonroot-contracts.mjs');b.guardSource.closureHash=nonrootHash(b.guardSource.files);b.recipe.context.closureHash=nonrootHash(b.recipe.context.files);}
 await expect(verifyNonrootControlArtifactFiles(b,x.options())).rejects.toThrow('NonrootControlFileHash');
});
it('cannot deserialize Graph/FS brands or substitute a filesystem from another graph',async()=>{
 const a=await fixture(),b=await fixture({nodeMode:0o644});
 expect(()=>inspectNonrootControlArtifactBinding(a.b,{controlVerification:{graph:structuredClone(a.graph),filesystem:a.filesystem}})).toThrow();
 expect(()=>inspectNonrootControlArtifactBinding(a.b,{controlVerification:{graph:a.graph,filesystem:structuredClone(a.filesystem)}})).toThrow();
 expect(()=>inspectNonrootControlArtifactBinding(a.b,{controlVerification:{graph:a.graph,filesystem:b.filesystem}})).toThrow('NonrootControlFilesystemBinding');
});
it('keeps implicit directory ownership unknown instead of treating it as root-owned',async()=>{
 const x=await fixture({implicit:true}),r=await verifyNonrootControlArtifactFiles(x.b,x.options());expect(r.unknownRuntimePaths).toContain('/');expect(r.unknownRuntimePaths).toContain('/usr');expect(r.unknownRuntimePaths).toContain('/usr/local/bin');
});
for(const options of [{nodeMode:0o4755},{nodeMode:0o777},{nodeUid:1000}])it('rejects privileged, writable or non-root-owned actual executable metadata',async()=>{
 const x=await fixture(options);await expect(verifyNonrootControlArtifactFiles(x.b,x.options())).rejects.toThrow();
});
for(const options of [{parentMode:0o750},{libraryMode:0o400}])it('rejects actual paths/libraries inaccessible to the fixed nonroot identity',async()=>{
 const x=await fixture(options);await expect(verifyNonrootControlArtifactFiles(x.b,x.options())).rejects.toThrow();
});
