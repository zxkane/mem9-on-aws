import {it,expect} from 'vitest';
import {createHash} from 'node:crypto';
import {createImageBudget,readImageGraph,imageGraphState,IMAGE_MEDIA} from './lib/production-image-graph.mjs';
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
