import {test} from 'vitest';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {createNonrootEvidenceArchive,exportNonrootArchive,importNonrootArchive,nonrootArchiveBindings,forkNonrootArchive} from './lib/production-nonroot-archive.mjs';
import {nonrootHash} from './lib/production-nonroot-contracts.mjs';
import {parseAcquisitionJson,parseNonrootArchiveJson} from './lib/ci-smoke-acquisition-format.mjs';
import {NONROOT_ARCHIVE_CAPACITY_V2 as CAPACITY} from './lib/production-nonroot-archive-capacity.mjs';
const MiB=1048576,sha=b=>createHash('sha256').update(b).digest('hex');
function fixture(bytes,wireVersion=1){
 const ref={sha256:sha(bytes),bytesLength:bytes.length},name=`sha256-${ref.sha256}.bin`;
 const manifest={version:2,kind:'nonroot-proof-archive',owner:'a'.repeat(32),files:[{name,purpose:'source',encoding:'bytes',ref}]};
 return createNonrootEvidenceArchive(JSON.stringify(manifest),{expectedManifestHash:nonrootHash(manifest),wireVersion,readObject:async()=>bytes});
}
test('aggregate capacity v2 preserves a complete archive above the legacy raw limit',async()=>{
 const archive=fixture(Buffer.alloc(33*MiB,7),2),wire=await exportNonrootArchive(archive),expectedManifestHash=nonrootArchiveBindings(archive).manifestHash;
 assert.equal(wire.version,2);assert.throws(()=>importNonrootArchive({...wire,version:1},{expectedManifestHash}),/WireLimit/);
 assert.deepEqual(await exportNonrootArchive(importNonrootArchive(wire,{expectedManifestHash})),wire);
});
test('v2 oversized binary member rejects before decoding its body',()=>{
 const base64='A'.repeat(4*Math.ceil((64*MiB+1)/3));
 assert.throws(()=>importNonrootArchive({version:2,kind:'nonroot-evidence-bytes',manifest:'{}',objects:[{name:'proof.json',base64}]},{expectedManifestHash:'a'.repeat(64)}),/WireLimit/);
});
test('archive document capacity does not change the legacy parser, duplicate-key or depth checks',()=>{
 const raw=Buffer.from('"'+'x'.repeat(33*MiB)+'"');assert.throws(()=>parseAcquisitionJson(raw),/JsonSize/);assert.equal(parseNonrootArchiveJson(raw).length,33*MiB);
 assert.throws(()=>parseNonrootArchiveJson(raw,CAPACITY.documentBytes+1),/JsonSize/);
 assert.throws(()=>parseNonrootArchiveJson(Buffer.from('{"x":1,"x":2}')),/DuplicateKey/);
 assert.throws(()=>parseNonrootArchiveJson(Buffer.from('['.repeat(65)+'0'+']'.repeat(65))),/Depth/);
});
test('archive wire input beyond its bounded document capacity rejects',()=>{
 const raw=new Uint8Array(new ArrayBuffer(CAPACITY.documentBytes+1));assert.throws(()=>parseNonrootArchiveJson(raw),/JsonSize/);
});
test('failed original payment prevents archive body acquisition',async()=>{
 let calls=0;const archive=forkNonrootArchive(fixture(Buffer.from('synthetic'),2),{beforeRead(){calls++;throw Error('PaymentDenied');}});
 await assert.rejects(exportNonrootArchive(archive),/PaymentDenied/);assert.equal(calls,1);
});
