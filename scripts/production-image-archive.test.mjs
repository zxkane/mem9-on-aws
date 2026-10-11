import {it,expect} from 'vitest';
import {Readable} from 'node:stream';
import {imageTransitionFixture,imageTransitionServingFixture} from './production-image-transition.fixture.mjs';
import {buildImageTransitionProof} from './lib/production-image-transition-proof.mjs';
import {imageTransitionArchiveLocation,readImageTransitionArchive,loadImageTransitionAuthority} from './lib/production-image-archive.mjs';
import {assertImageTransitionDataRelease} from './lib/production-image-transition-proof.mjs';
import {canaryEvidenceHash as hash} from './lib/production-canary-verification.mjs';
async function fixture(){
 const f=await imageTransitionFixture(),built=await buildImageTransitionProof(f.input,f),s=imageTransitionServingFixture(f,built),data=s.data;
 const records={'operation.json':{version:1,kind:'image-security-transition',operation:{owner:data.authorizationId},authorization:{data,hash:hash(data),review:s.review},expected:{transitionProofHash:built.proofHash},predecessor:{Type:'SecureString',Version:1,Value:f.input.predecessorText}},
  'image-transition-proof.json':built.proof,
  'image-graph-evidence.json':{version:1,graphHash:hash(built.proof.graph),summary:built.proof.graph,inventory:built.proof.graphInventory,destinationReadback:built.proof.destinationReadback},
  'image-filesystem-evidence.json':{version:1,filesystemHash:hash(built.proof.filesystem),evidence:built.proof.filesystemEvidence,filesystem:built.proof.filesystem}};
 const calls=[],bodies=[],clients={s3:{send:async command=>{calls.push(command.input);const name=command.input.Key.split('/').at(-1),bytes=Buffer.from(JSON.stringify(records[name])),Body=Readable.from([bytes]);bodies.push(Body);return {Body,ContentLength:bytes.length,ServerSideEncryption:'aws:kms',SSEKMSKeyId:`arn:aws:kms:${data.region}:${data.account}:key/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa`,ETag:'fixture-etag'};}}};
 const options={raw:data,expected:{stage:'prod',account:data.account,region:data.region,controlSourceTree:data.controlSourceTree},now:f.now};
 return {f,built,s,data,records,calls,bodies,clients,options};
}
it('reads only fixed owner keys and verifies protected descriptor commitments without granting authority',async()=>{
 const f=await fixture(),r=await readImageTransitionArchive(f.clients,f.options);expect(r.authority).toBe(false);expect(r.selected.hash).toBe(hash(f.data));expect(f.calls).toHaveLength(4);
 for(const c of f.calls){expect(c.ExpectedBucketOwner).toBe(f.data.account);expect(c.Bucket).toBe('mem9-audit-'+f.data.account);expect(c.Key.startsWith(`data-authorizations/${f.data.runtimeNonce}/${f.data.authorizationId}/`)).toBe(true);}
 expect(f.bodies.every(b=>b.destroyed)).toBe(true);
});
it.each(['proof','review','owner','predecessor'])('rejects changed archived %s commitments',async kind=>{
 const f=await fixture(),o=f.records['operation.json'];
 if(kind==='proof')f.records['image-transition-proof.json']={...f.built.proof,unknown:true};if(kind==='review')o.authorization.review={...o.authorization.review,decision:'other'};
 if(kind==='owner')o.operation.owner='0'.repeat(32);if(kind==='predecessor')o.predecessor.Value=JSON.stringify({...f.f.predecessor,authorizationId:'0'.repeat(32)});
 await expect(readImageTransitionArchive(f.clients,f.options)).rejects.toThrow();expect(f.bodies.every(b=>b.destroyed)).toBe(true);
});
it('destroys a rejected response body when encryption metadata is wrong',async()=>{
 const f=await fixture(),send=f.clients.s3.send;f.clients.s3.send=async command=>({...await send(command),ServerSideEncryption:'AES256'});
 await expect(readImageTransitionArchive(f.clients,f.options)).rejects.toThrow('ImageArchiveProtectionInvalid');expect(f.bodies.every(b=>b.destroyed)).toBe(true);
});
it('never accepts caller-selected archive paths or invalid bucket overrides',()=>{
 expect(()=>imageTransitionArchiveLocation({version:2,account:'123456789012',region:'ap-northeast-1',runtimeNonce:'../bad',authorizationId:'a'.repeat(32)})).toThrow();
});
it('hydrates verified archive custody and requires fresh exact target manifests for admission',async()=>{
 const f=await fixture(),calls=[];
 const readEcr=async(operation,input)=>{calls.push({operation,input});const name=input.repositoryName.split('/').at(-1),key=input.imageDigest===f.data.images[name].rootDigest?'root':'child';return JSON.parse(f.f.input.artifacts[name][key]);};
 const result=await loadImageTransitionAuthority(f.clients,{...f.options,clock:()=>f.f.now,readEcr});
 expect(calls).toHaveLength(6);expect(()=>assertImageTransitionDataRelease(result.context,{current:f.data,controlSourceTree:f.data.controlSourceTree,now:f.f.now})).not.toThrow();
});
it('fails admission when committed inventory is unavailable or a fresh manifest is wrong',async()=>{
 const f=await fixture();f.records['image-graph-evidence.json'].inventory={...f.built.proof.graphInventory,nodes:[]};
 await expect(loadImageTransitionAuthority(f.clients,{...f.options,clock:()=>f.f.now,readEcr:async()=>({images:[],failures:[]})})).rejects.toThrow();
 const g=await fixture();await expect(loadImageTransitionAuthority(g.clients,{...g.options,clock:()=>g.f.now,readEcr:async()=>({images:[],failures:[]})})).rejects.toThrow();
});
