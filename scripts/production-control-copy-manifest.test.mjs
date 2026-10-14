import {test,expect} from 'vitest';
import {sourceContext,tar,sha} from './control-composition-native/fixture.mjs';
import {IMAGE_MEDIA as M,createImageBudget,readControlImageGraph} from './lib/production-image-graph.mjs';
import {inspectImageFilesystem,inspectImageFilesystemEntries,inspectImageFilesystemEvidence} from './lib/production-image-filesystem.mjs';
import {describeProductionControlCopyManifest} from './lib/production-control-composition-source.mjs';
import {nonrootHash} from './lib/production-nonroot-contracts.mjs';

test('COPY verification accepts a complete filesystem larger than the proof JSON domain',async()=>{
 const files={'docker/bootstrap/Dockerfile':'FROM example.invalid/base\nCOPY scripts/a.mjs /app/a.mjs\n','scripts/a.mjs':'export const value=1;\n'};
 const source=sourceContext(files),data=new Map();
 const put=(value,mediaType)=>{
  const raw=Buffer.isBuffer(value)?value:Buffer.from(JSON.stringify(value));
  const descriptor={mediaType,size:raw.length,digest:'sha256:'+sha(raw)};
  data.set(descriptor.digest,raw);return descriptor;
 };
 const layer=put(tar([{path:'app',type:'5',mode:0o755},{path:'app/a.mjs',body:files['scripts/a.mjs']},
  ...Array.from({length:12000},(_,i)=>({path:'inherited-'+i,type:'5',mode:0o755}))]),M.tar);
 const config=put({architecture:'arm64',os:'linux',config:{User:'node'},rootfs:{type:'layers',diff_ids:[layer.digest]}},M.config);
 const manifest=put({schemaVersion:2,mediaType:M.manifest,config,layers:[layer]},M.manifest);
 const root=put({schemaVersion:2,mediaType:M.index,manifests:[{...manifest,platform:{os:'linux',architecture:'arm64'}}]},M.index);
 const binding={account:'123456789012',region:'us-east-1',repositoryName:'mem9-on-aws/preview/bootstrap',root,arm64Digest:manifest.digest,configDigest:config.digest};
 const cache=new Map(),store={async put(d,stream){const chunks=[];for await(const b of stream)chunks.push(b);cache.set(d.digest,Buffer.concat(chunks));},async *open(d){yield cache.get(d.digest);}};
 const budget=createImageBudget({credentialExpiresMs:Date.now()+3600000});
 const graph=await readControlImageGraph(binding,{budget,store,source:{async manifest(_,d){return data.get(d.digest);},async *blob(_,d){yield data.get(d.digest);}}});
 const filesystem=await inspectImageFilesystem(graph,{component:'bootstrap',budget});
 const entries=inspectImageFilesystemEntries(filesystem),evidence=inspectImageFilesystemEvidence(filesystem);
 expect(entries).toHaveLength(12002);
 expect(()=>nonrootHash(entries)).toThrow('NonrootContractInvalid');
 const copy=await describeProductionControlCopyManifest({sourceContext:source.context,baseFilesystem:filesystem});
 expect(copy.rows.map(row=>row.path)).toEqual(['app','app/a.mjs']);
 expect(copy.rows.find(row=>row.type==='file').sha256).toBe(sha(files['scripts/a.mjs']));
 expect(inspectImageFilesystemEvidence(filesystem)).toEqual(evidence);
 const changed=sourceContext({...files,'scripts/a.mjs':'export const value=2;\n'});
 await expect(describeProductionControlCopyManifest({sourceContext:changed.context,baseFilesystem:filesystem})).rejects.toThrow('ControlCompositionSourceEquivalent');
 await expect(describeProductionControlCopyManifest({sourceContext:source.context,baseFilesystem:{...filesystem}})).rejects.toThrow('ImageFilesystemContextRequired');
},20000);
