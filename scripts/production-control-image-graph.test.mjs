import {it,expect} from 'vitest';
import {graphFixture,tar} from './production-image.fixture.mjs';
import {readImageGraph,readControlImageGraph,controlImageGraphBinding,imageGraphState,verifyImageGraphCopies,IMAGE_MEDIA} from './lib/production-image-graph.mjs';
import {inspectImageFilesystem,inspectImageFilesystemEntries,assertImageFilesystemSource,inspectImageFilesystemFile,readImageFilesystemFile} from './lib/production-image-filesystem.mjs';
import {canaryEvidenceHash} from './lib/production-canary-verification.mjs';

function fixture(){
 const f=graphFixture(),root=f.roots.find(row=>row.component==='mnemo-server'),child=JSON.parse(f.data.get(root.arm64Digest));
 return {...f,binding:{account:'123456789012',region:'ap-northeast-1',repositoryName:'mem9-on-aws/bootstrap',root:root.root,arm64Digest:root.arm64Digest,configDigest:child.config.digest}};
}
it('validates the complete single CONTROL graph and filesystem without pretending it is DATA',async()=>{
 const f=fixture(),graph=await readControlImageGraph(f.binding,f.options??{source:f.source,store:f.store,budget:f.budget});
 expect(controlImageGraphBinding(graph)).toMatchObject({repositoryName:f.binding.repositoryName,rootDigest:f.binding.root.digest,configDigest:f.binding.configDigest});
 expect(graph.inventory.kind).toBe('readonly-control-image-graph');expect(graph.inventory.roots).toHaveLength(1);
 const state=imageGraphState(graph);expect(state.side).toBe('control');expect(state.images.has('bootstrap')).toBe(true);
 const fs=await inspectImageFilesystem(graph,{component:'bootstrap'});expect(inspectImageFilesystemEntries(fs).length).toBeGreaterThan(0);
 expect(()=>assertImageFilesystemSource(fs,graph,{requirementsHash:canaryEvidenceHash([])})).toThrow('ImageFilesystemSourceRequired');
 expect(()=>verifyImageGraphCopies(graph,graph,{account:f.binding.account,region:f.binding.region})).toThrow('ImageDestinationGraphChanged');
 expect(()=>controlImageGraphBinding(JSON.parse(JSON.stringify(graph)))).toThrow('ControlImageContextRequired');
});
it('preserves strict legacy DATA root count and prevents side/config/repository substitution',async()=>{
 const f=fixture();await expect(readImageGraph([f.roots[0]],f)).rejects.toThrow('ImageRoots');
 for(const patch of [{repositoryName:'foreign/bootstrap'},{configDigest:'sha256:'+'f'.repeat(64)},{extra:true}]){
  const x=fixture();await expect(readControlImageGraph({...x.binding,...patch},{source:x.source,store:x.store,budget:x.budget})).rejects.toThrow();
 }
 await expect(readControlImageGraph(f.binding,{source:f.source,store:f.store,budget:f.budget,side:'source'})).rejects.toThrow('ControlImageOptions');
 const data=await readImageGraph(f.roots,f);expect(()=>controlImageGraphBinding(data)).toThrow('ControlImageContextRequired');
});
it('rejects changed layer bytes and config bytes under the same manifest identity',async()=>{
 for(const part of ['config','layer']){
  const f=fixture(),child=JSON.parse(f.data.get(f.binding.arm64Digest)),key=part==='config'?child.config.digest:child.layers[0].digest;
  const original=f.data.get(key);f.data.set(key,Buffer.alloc(original.length,1));
  await expect(readControlImageGraph(f.binding,{source:f.source,store:f.store,budget:f.budget})).rejects.toThrow();
 }
});

async function fileContext(entries){
 const f=fixture(),layer=f.put(tar(entries),IMAGE_MEDIA.tar),config=f.put({architecture:'arm64',os:'linux',rootfs:{type:'layers',diff_ids:[layer.digest]}},IMAGE_MEDIA.config),
  child=f.put({schemaVersion:2,mediaType:IMAGE_MEDIA.manifest,config,layers:[layer]},IMAGE_MEDIA.manifest),
  root=f.put({schemaVersion:2,mediaType:IMAGE_MEDIA.index,manifests:[{...child,platform:{os:'linux',architecture:'arm64'}}]},IMAGE_MEDIA.index);
 const graph=await readControlImageGraph({...f.binding,root,arm64Digest:child.digest,configDigest:config.digest},{source:f.source,store:f.store,budget:f.budget});
 return inspectImageFilesystem(graph,{component:'bootstrap'});
}
it('binds small file bytes and symlink/parent facts to the actual verified final filesystem',async()=>{
 const fs=await fileContext([{path:'target',type:'5'},{path:'target/program',body:'verified program'},
  {path:'original',type:'5'},{path:'original/node',type:'2',link:'/target/program'}]);
 const fact=inspectImageFilesystemFile(fs,'/original/node');
 expect(fact).toMatchObject({path:'/original/node',resolvedPath:'/target/program',uid:0,gid:0,size:16,rootMetadata:'not-recorded'});
 expect(fact.parents.map(row=>row.path)).toEqual(['/original','/target']);expect(fact.symlinkChain[0].path).toBe('/original/node');
 expect((await readImageFilesystemFile(fs,'/original/node')).toString()).toBe('verified program');
 await expect(readImageFilesystemFile(fs,'/original/node',{maxBytes:1})).rejects.toThrow('ImageRuntimeFileLimit');
 expect(()=>inspectImageFilesystemFile(structuredClone(fs),'/original/node')).toThrow('ImageFilesystemContextRequired');
});
it('preserves effective PAX ownership and refuses hardlink metadata ambiguity for runtime files',async()=>{
 const payload='uid=1000\n';let length=payload.length+3;while(String(length).length+1+payload.length!==length)length=String(length).length+1+payload.length;
 const fs=await fileContext([{path:'pax',type:'x',body:length+' '+payload},{path:'app/program',body:'test'},
  {path:'app/hard',type:'1',link:'app/program'}]);
 expect(inspectImageFilesystemFile(fs,'/app/program').uid).toBe(1000);
 expect(()=>inspectImageFilesystemFile(fs,'/app/hard')).toThrow('ImageRuntimeFileRequired');
 expect(()=>inspectImageFilesystemFile(fs,'/app/../app/program')).toThrow('ImageRuntimeFilePath');
});
