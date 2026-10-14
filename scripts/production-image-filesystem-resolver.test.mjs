import {expect,it} from 'vitest';
import {createHash} from 'node:crypto';
import {graphFixture,tar} from './production-image.fixture.mjs';
import {readImageGraph,IMAGE_MEDIA} from './lib/production-image-graph.mjs';
import {inspectImageFilesystem,inspectImageFilesystemFile,inspectImageFilesystemFileProjection} from './lib/production-image-filesystem.mjs';
import {resolveImageFilesystemFile} from './lib/production-image-filesystem-resolver.mjs';

async function nativeFilesystem(){
 const graph=graphFixture(),root=graph.roots.find(r=>r.component==='llm-proxy');
 const layer=graph.put(tar([
  {path:'payload',type:'5'},{path:'payload/tool',body:'synthetic executable'},
  {path:'bin',type:'5'},{path:'bin/tool',type:'2',link:'../payload/tool'},
  {path:'usr',type:'5'},{path:'usr/bin',type:'2',link:'/bin'},
 ]),IMAGE_MEDIA.tar);
 const config=graph.put({architecture:'arm64',os:'linux',rootfs:{type:'layers',diff_ids:[layer.digest]}},IMAGE_MEDIA.config);
 const arm=graph.put({schemaVersion:2,mediaType:IMAGE_MEDIA.manifest,config,layers:[layer]},IMAGE_MEDIA.manifest);
 root.root=graph.put({schemaVersion:2,mediaType:IMAGE_MEDIA.index,manifests:[{...arm,platform:{os:'linux',architecture:'arm64'}}]},IMAGE_MEDIA.index);root.arm64Digest=arm.digest;
 const verified=await readImageGraph(graph.roots,graph);
 return inspectImageFilesystem(verified,{component:'llm-proxy',budget:graph.budget});
}
it('retains every symlink, target and ancestor needed to replay a native file lookup',async()=>{
 const fs=await nativeFilesystem(),path='/usr/bin/tool',projection=inspectImageFilesystemFileProjection(fs,path,{beforeRead(){}});
 expect(projection.fact).toEqual(inspectImageFilesystemFile(fs,path));
 expect(projection.fact).toMatchObject({path,resolvedPath:'/payload/tool',sha256:createHash('sha256').update('synthetic executable').digest('hex'),size:Buffer.byteLength('synthetic executable')});
 expect(projection.fact.symlinkChain.map(row=>row.path)).toEqual(['/usr/bin','/bin/tool']);
 expect(projection.rows.map(row=>row.path).sort()).toEqual(['bin','bin/tool','payload','payload/tool','usr','usr/bin']);
 expect(resolveImageFilesystemFile(projection.rows,path)).toEqual(projection.fact);
 expect(()=>inspectImageFilesystemFile(projection.rows,path)).toThrow('ImageFilesystemContextRequired');
});
it('fails on an incomplete projected target rather than returning a partial fact',async()=>{
 const fs=await nativeFilesystem(),projection=inspectImageFilesystemFileProjection(fs,'/usr/bin/tool',{beforeRead(){}});
 expect(()=>resolveImageFilesystemFile(projection.rows.filter(row=>row.path!=='payload/tool'),'/usr/bin/tool')).toThrow('ImageVirtualLinkMissing');
});
it.each(['/usr/../bin/tool','/usr/bin/tool/','usr/bin/tool','/','/../escape'])('rejects noncanonical runtime path %s',path=>{
 expect(()=>resolveImageFilesystemFile([],path)).toThrow('ImageRuntimeFilePath');
});
it('preserves effective PAX owners and capability metadata as DATA',()=>{
 const rows=[{path:'app',type:'directory',mode:0o755,uid:0,gid:0},{path:'app/tool',type:'file',mode:0o755,uid:0,gid:0,pax:{uid:'1001',gid:'1002','SCHILY.xattr.security.capability':'synthetic'},content:{sha256:'a'.repeat(64),size:7,layerDigest:'sha256:'+'b'.repeat(64)}}];
 const fact=resolveImageFilesystemFile(rows,'/app/tool');
 expect(fact).toMatchObject({uid:1001,gid:1002,privilegeAttributes:['SCHILY.xattr.security.capability'],parents:[{path:'/app',mode:0o755,uid:0,gid:0}]});
 rows[1].pax.uid='01';expect(()=>resolveImageFilesystemFile(rows,'/app/tool')).toThrow('ImageRuntimeFileOwner');
});
it('refuses a projected symlink cycle within the original hop bound',()=>{
 const rows=[{path:'a',type:'symlink',link:'b'},{path:'b',type:'symlink',link:'a'}];
 expect(()=>resolveImageFilesystemFile(rows,'/a')).toThrow('ImageVirtualLinkLoop');
});
