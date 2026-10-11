import {it,expect} from 'vitest';
import {gzipSync,zstdCompressSync} from 'node:zlib';
import {createHash} from 'node:crypto';
import {readImageGraph,IMAGE_MEDIA} from './lib/production-image-graph.mjs';
import {inspectImageFilesystem,inspectImageFilesystemEvidence,inspectImageFilesystemEntries,inspectImageFilesystemFile} from './lib/production-image-filesystem.mjs';
import {canaryEvidenceHash as hash} from './lib/production-canary-verification.mjs';
import {graphFixture,tar} from './production-image.fixture.mjs';
import {IMAGE_TRANSITION_LIMITS as L} from './lib/production-image-transition.mjs';
const digest=b=>'sha256:'+createHash('sha256').update(b).digest('hex');

async function filesystem(layers,{compression='tar',requirements=[{path:'/lib/apk/db/installed',manager:'apk',name:'fixture-library',version:'2.0-r1'}]}={}){
 const f=graphFixture(),t=f.roots.find(r=>r.component==='mnemo-server'),layerDescriptors=layers.map(raw=>f.put(compression==='gzip'?gzipSync(raw):compression==='zstd'?zstdCompressSync(raw):raw,IMAGE_MEDIA[compression]));
 const config=f.put({architecture:'arm64',os:'linux',rootfs:{type:'layers',diff_ids:layers.map(digest)}},IMAGE_MEDIA.config);
 const arm=f.put({schemaVersion:2,mediaType:IMAGE_MEDIA.manifest,config,layers:layerDescriptors},IMAGE_MEDIA.manifest);
 t.root=f.put({schemaVersion:2,mediaType:IMAGE_MEDIA.index,manifests:[{...arm,platform:{os:'linux',architecture:'arm64'}}]},IMAGE_MEDIA.index);t.arm64Digest=arm.digest;
 const graph=await readImageGraph(f.roots,{...f});return inspectImageFilesystem(graph,{component:'mnemo-server',requirements,budget:f.budget});
}
for(const compression of ['tar','gzip','zstd'])it('uses final virtual APK database across '+compression+' layers without image execution',async()=>{
 const before=tar([{path:'lib/apk/db/installed',body:'P:fixture-library\nV:2.0-r0\n\n'}]),after=tar([{path:'lib/apk/db/installed',body:'P:fixture-library\nV:2.0-r1\n\n'}]);
 const result=await filesystem([before,after],{compression});expect(result.evidence.packages[0].version).toBe('2.0-r1');expect(inspectImageFilesystemEvidence(result)).toEqual(result.evidence);
 expect(()=>inspectImageFilesystemEvidence(JSON.parse(JSON.stringify(result)))).toThrow();
});
it('applies opaque and ordinary whiteouts only to lower-layer entries',async()=>{
 const old=tar([{path:'lib/apk/db/old',body:'old'},{path:'lib/apk/db/installed',body:'P:fixture-library\nV:2.0-r0\n\n'}]);
 const next=tar([{path:'lib/apk/db/installed',body:'P:fixture-library\nV:2.0-r1\n\n'},{path:'lib/apk/db/.wh..wh..opq'},{path:'lib/apk/db/.wh.old'}]);
 const result=await filesystem([old,next]);expect(result.evidence.packages[0].version).toBe('2.0-r1');
});
it('exposes detached live path metadata committed by the existing entries hash',async()=>{
 const before=tar([{path:'app/old',body:'old'},{path:'app/program',body:'old program'}]);
 const after=tar([{path:'app/.wh.old'},{path:'app/program',body:'new program'},{path:'app/link',type:'2',link:'program'}]);
 const result=await filesystem([before,after],{requirements:[]}),entries=inspectImageFilesystemEntries(result);
 expect(hash(entries)).toBe(result.evidence.entriesHash);expect(entries.some(e=>e.path==='app/old')).toBe(false);
 const program=entries.find(e=>e.path==='app/program');expect(program.content.sha256).toBe(digest(Buffer.from('new program')).slice(7));
 program.mode=0;expect(hash(inspectImageFilesystemEntries(result))).toBe(result.evidence.entriesHash);
 expect(()=>inspectImageFilesystemEntries(structuredClone(result))).toThrow();
});
it('resolves virtual symlink and hardlink semantics for a package database',async()=>{
 const layer=tar([{path:'payload/installed',body:'P:fixture-library\nV:2.0-r1\n\n'},{path:'payload/hard',type:'1',link:'payload/installed'},{path:'lib/apk/db/installed',type:'2',link:'/payload/hard'}]);
 expect((await filesystem([layer])).evidence.packages[0].version).toBe('2.0-r1');
});
for(const entry of [{path:'../../escape'},{path:'/absolute'},{path:'x',type:'2',link:'../../escape'},{path:'x',type:'1',link:'missing'},{path:'x',type:'3'}])it('rejects unsafe or unsupported virtual entry '+JSON.stringify(entry),async()=>{
 await expect(filesystem([tar([entry])],{requirements:[]})).rejects.toThrow();
});
it('rejects duplicate package records, overwritten versions and link cycles',async()=>{
 for(const entries of [[{path:'lib/apk/db/installed',body:'P:fixture-library\nV:2.0-r1\n\nP:fixture-library\nV:2.0-r1\n\n'}],[{path:'lib/apk/db/installed',body:'P:fixture-library\nV:2.0-r0\n\n'}],[{path:'a',type:'2',link:'b'},{path:'b',type:'2',link:'a'}]])await expect(filesystem([tar(entries)])).rejects.toThrow();
});
it('implicit parent directories consume the shared filesystem-entry budget',async()=>{
 const f=graphFixture(),graph=await readImageGraph(f.roots,{...f});
 for(let i=0;i<L.maxFsEntries-1;i++)f.budget.entry();
 await expect(inspectImageFilesystem(graph,{component:'llm-proxy',budget:f.budget})).rejects.toThrow('ImageFilesystemEntryLimit');
});


it('TC-CONS-IMAGE-125 pays before live entries and file metadata work without changing either result',async()=>{
 const fs=await filesystem([tar([{path:'app/program',body:'synthetic program'}])],{requirements:[]});
 const original=inspectImageFilesystemEntries(fs),originalHash=hash(original),file=inspectImageFilesystemFile(fs,'/app/program'),seen=[];
 const options={beforeRead(entries,evidence){expect(Object.isFrozen(entries)).toBe(true);expect(evidence.entriesHash).toBe(originalHash);seen.push(entries);}};
 expect(inspectImageFilesystemEntries(fs,options)).toEqual(original);
 expect(inspectImageFilesystemFile(fs,'/app/program',options)).toEqual(file);
 expect(seen).toHaveLength(2);expect(seen[0]).toBe(seen[1]);
 original[0].path='changed-test-copy';expect(inspectImageFilesystemEntries(fs,options)).not.toEqual(original);
});
it('TC-CONS-IMAGE-125 exhausted or asynchronous payment stops the full accessor',async()=>{
 const fs=await filesystem([tar([{path:'app/program',body:'synthetic program'}])],{requirements:[]});
 let remaining=1;const error=Error('SyntheticProcessingBudget');
 const options={beforeRead(){if(remaining===0)throw error;remaining--;}};
 inspectImageFilesystemEntries(fs,options);expect(remaining).toBe(0);
 expect(()=>inspectImageFilesystemFile(fs,'/app/program',options)).toThrow(error);expect(remaining).toBe(0);
 expect(()=>inspectImageFilesystemEntries(fs,{beforeRead:async()=>{}})).toThrow('ImageFilesystemSynchronousPayment');
 expect(()=>inspectImageFilesystemEntries(fs,{})).toThrow('ImageFilesystemProcessingRequired');
});
it('TC-CONS-IMAGE-128 payment preserves original filesystem identity and path guards',async()=>{
 const fs=await filesystem([tar([{path:'app/program',body:'synthetic program'}])],{requirements:[]});let paid=0;
 const options={beforeRead(){paid++;}};
 expect(()=>inspectImageFilesystemEntries(structuredClone(fs),options)).toThrow('ImageFilesystemContextRequired');
 expect(()=>inspectImageFilesystemFile(fs,'/../escape',options)).toThrow('ImageRuntimeFilePath');expect(paid).toBe(0);
 expect(()=>inspectImageFilesystemFile(fs,'/missing',options)).toThrow();expect(paid).toBe(1);
 expect(inspectImageFilesystemFile(fs,'/app/program').sha256).toBe(digest(Buffer.from('synthetic program')).slice(7));
});
