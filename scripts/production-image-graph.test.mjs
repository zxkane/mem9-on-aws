import {it,expect} from 'vitest';
import {createHash} from 'node:crypto';
import {createImageBudget,readImageGraph,imageGraphState,validateImageDescriptor,IMAGE_MEDIA} from './lib/production-image-graph.mjs';
import {IMAGE_TRANSITION_LIMITS_HASH} from './lib/production-image-transition.mjs';

const digest=b=>'sha256:'+createHash('sha256').update(b).digest('hex');
import {graphFixture} from './production-image.fixture.mjs';

it('reads full ALL3 graph including config and in-toto subjects without mutation authority',async()=>{
 const f=graphFixture(),g=await readImageGraph(f.roots,{source:f.source,store:f.store,budget:f.budget});
 expect(g.inventory.limitsHash).toBe(IMAGE_TRANSITION_LIMITS_HASH);expect(g.inventory.roots).toHaveLength(3);expect(g.inventory.attestations).toHaveLength(3);
 expect(f.blobCalls.length).toBe(12);expect(imageGraphState(g).manifests.size).toBe(9);expect(()=>imageGraphState(JSON.parse(JSON.stringify(g)))).toThrow();
});
it('rejects over-limit declared blobs before body reads and forbids limit overrides',async()=>{
 const f=graphFixture();expect(()=>f.budget.blob({digest:'sha256:'+'a'.repeat(64),size:2147483649,mediaType:IMAGE_MEDIA.tar})).toThrow();expect(f.blobCalls).toHaveLength(0);
 expect(()=>createImageBudget({credentialExpiresMs:Date.now()+3600000,limits:{maxBlobBytes:1}})).toThrow();
});
it('rejects manifest hash mismatch and external descriptor URLs',async()=>{
 const f=graphFixture();f.data.set(f.roots[0].root.digest,Buffer.from('{}'));await expect(readImageGraph(f.roots,{...f})).rejects.toThrow();
 const z=graphFixture(),root=z.roots[0];root.root={...root.root,urls:['https://example.com/blob']};await expect(readImageGraph(z.roots,{...z})).rejects.toThrow();
});
it('rejects incomplete streams even when the adapter resolves normally',async()=>{
 const f=graphFixture();f.source.blob=async()=>({async *[Symbol.asyncIterator](){yield Buffer.from('short');}});await expect(readImageGraph(f.roots,{...f})).rejects.toThrow();
});

function embeddedConfigFixture(){
 const f=graphFixture();
 for(const root of f.roots){
  const index=JSON.parse(f.data.get(root.root.digest)),attestation=JSON.parse(f.data.get(index.manifests[1].digest));
  const config=f.put({},IMAGE_MEDIA.emptyConfig);
  attestation.config={...config,data:Buffer.from('{}').toString('base64')};
  index.manifests[1]={...index.manifests[1],...f.put(attestation,IMAGE_MEDIA.manifest)};
  root.root=f.put(index,IMAGE_MEDIA.index);
 }
 return f;
}
it('verifies embedded empty configs and still reads every referenced blob from its repository',async()=>{
 const f=embeddedConfigFixture(),g=await readImageGraph(f.roots,{...f});
 expect(g.inventory.attestations).toHaveLength(3);
 const reads=f.blobCalls.filter(({d})=>d.mediaType===IMAGE_MEDIA.emptyConfig);
 expect(reads).toHaveLength(3);expect(new Set(reads.map(r=>r.repository)).size).toBe(3);
 expect(reads.every(({d})=>d.data==='e30='&&d.size===2&&d.digest===digest('{}'))).toBe(true);
 const state=imageGraphState(g);
 for(const r of reads)expect(state.blobs.get(r.d.digest)).toEqual({digest:digest('{}'),size:2,mediaType:IMAGE_MEDIA.emptyConfig});
});
it('rejects malformed, noncanonical, oversized or mismatched embedded descriptor data',()=>{
 const valid={mediaType:IMAGE_MEDIA.emptyConfig,digest:digest('{}'),size:2,data:'e30='};
 expect(validateImageDescriptor(valid,'blob')).toBe(valid);
 for(const change of [{data:null},{data:'e30'},{data:'e30=\n'},{data:'e30*'},{data:'e31='},{data:'e30_'},{data:'bnVsbA=='},{size:3},{digest:digest('[]')},{data:'A'.repeat(11184816)}]){
  expect(()=>validateImageDescriptor({...valid,...change},'blob')).toThrow();
 }
 expect(()=>validateImageDescriptor({...valid,size:8388608,data:'A'.repeat(11184812)},'blob')).toThrow('ImageEmbeddedDataLimit');
});
it('does not let valid embedded data hide missing or changed registry bytes',async()=>{
 for(const replacement of [undefined,Buffer.from('[]')]){
  const f=embeddedConfigFixture();f.data.set(digest('{}'),replacement);
  await expect(readImageGraph(f.roots,{...f})).rejects.toThrow();
 }
});
