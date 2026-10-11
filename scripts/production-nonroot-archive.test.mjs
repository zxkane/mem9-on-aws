import {describe,it,expect} from 'vitest';
import {createHash} from 'node:crypto';
import {canaryEvidenceHash as hash} from './lib/production-canary-verification.mjs';
import {createNonrootEvidenceArchive,readNonrootArchiveRef,resolveNonrootArchiveCommitment,resolveNonrootArchiveRawJson,nonrootArchiveBindings,nonrootArchiveResolvers,forkNonrootArchive,assertNonrootArchiveConsumed,exportNonrootArchive,importNonrootArchive} from './lib/production-nonroot-archive.mjs';

const sha=b=>createHash('sha256').update(b).digest('hex');
function fixture(){
 const objects=new Map(),value={version:1,kind:'synthetic-evidence',value:'fixture'},raw=Buffer.from(JSON.stringify(value,null,2)+'\n');
 const ref={bytesHash:sha(raw),canonicalHash:hash(value),bytesLength:raw.length};
 const manifest={version:2,kind:'nonroot-proof-archive',owner:'a'.repeat(32),files:[{name:'source-evidence.json',purpose:'protocol',ref,encoding:'json'}]};
 objects.set('source-evidence.json',raw);
 const make=()=>createNonrootEvidenceArchive(Buffer.from(JSON.stringify(manifest)),{expectedManifestHash:hash(manifest),readObject:async name=>objects.get(name)});
 return {objects,value,raw,ref,manifest,make};
}

describe('nonroot archive integrity without authority',()=>{
 it('verifies raw bytes separately from canonical JSON and returns no admission authority',async()=>{
  const f=fixture(),ctx=f.make();expect(f.ref.bytesHash).not.toBe(f.ref.canonicalHash);
  expect(await readNonrootArchiveRef(ctx,f.ref,{purpose:'protocol',kind:'synthetic-evidence'})).toEqual(f.value);
  expect(await resolveNonrootArchiveCommitment(ctx,f.ref.canonicalHash,{purpose:'protocol',kind:'synthetic-evidence'})).toEqual(f.value);
  expect(nonrootArchiveBindings(ctx)).toMatchObject({kind:'evidence-integrity',authority:false,manifestHash:hash(f.manifest)});
 });
 it('requires an independently supplied manifest pin',()=>{
  const f=fixture();expect(()=>createNonrootEvidenceArchive(JSON.stringify(f.manifest),{readObject:async()=>f.raw})).toThrow();
  expect(()=>createNonrootEvidenceArchive(JSON.stringify(f.manifest),{expectedManifestHash:'0'.repeat(64),readObject:async()=>f.raw})).toThrow();
 });
 it.each(['name','purpose','encoding','extra','duplicate-name','duplicate-authority'])('rejects manifest %s drift',kind=>{
  const f=fixture(),row=f.manifest.files[0];
  if(kind==='name')row.name='../source-evidence.json';if(kind==='purpose')row.purpose='unreviewed';if(kind==='encoding')row.encoding='javascript';if(kind==='extra')row.approved=true;
  if(kind==='duplicate-name')f.manifest.files.push(structuredClone(row));
  if(kind==='duplicate-authority')f.manifest.files.push({...structuredClone(row),name:'proof.json'});
  expect(()=>f.make()).toThrow();
 });
 it.each(['missing','bytes','size','canonical','kind','purpose','reference','copied-context'])('rejects %s on resolution',async kind=>{
  const f=fixture();if(kind==='canonical')f.ref.canonicalHash='0'.repeat(64);
  const ctx=f.make();let ref=f.ref,options={purpose:'protocol',kind:'synthetic-evidence'};
  if(kind==='missing')f.objects.clear();if(kind==='bytes')f.objects.set('source-evidence.json',Buffer.from(f.raw.toString().replace('fixture','changed')));
  if(kind==='size')f.objects.set('source-evidence.json',Buffer.concat([f.raw,Buffer.from(' ')]));
  if(kind==='kind')options.kind='different';if(kind==='purpose')options.purpose='root-audit';if(kind==='reference')ref={...f.ref,bytesHash:'0'.repeat(64)};
  await expect(readNonrootArchiveRef(kind==='copied-context'?structuredClone(ctx):ctx,ref,options)).rejects.toThrow();
 });
 it.each(['{"kind":"a","kind":"b"}','{"kind":"a","\\u006bind":"b"}','{"x":9007199254740993}','{"x":1e309}','{"x":"\\ud800"}'])('rejects malformed canonical JSON %s even when its bytes are pinned',async text=>{
  const f=fixture(),raw=Buffer.from(text),parsed=JSON.parse(text);Object.assign(f.ref,{bytesHash:sha(raw),canonicalHash:hash(parsed),bytesLength:raw.length});f.objects.set('source-evidence.json',raw);
  await expect(readNonrootArchiveRef(f.make(),f.ref,{purpose:'protocol'})).rejects.toThrow();
 });
 it('rejects malformed UTF-8 before JSON parsing',async()=>{
  const f=fixture(),raw=Buffer.from([0x22,0xc0,0xaf,0x22]);Object.assign(f.ref,{bytesHash:sha(raw),canonicalHash:hash('replacement'),bytesLength:raw.length});f.objects.set('source-evidence.json',raw);
  await expect(readNonrootArchiveRef(f.make(),f.ref,{purpose:'protocol'})).rejects.toThrow();
 });
 it('rejects the operation and manifest from their own file inventory',()=>{
  for(const name of ['operation.json','manifest.json']){const f=fixture();f.manifest.files[0].name=name;expect(()=>f.make()).toThrow();}
 });
 it('keeps verified records detached from caller mutation',async()=>{
  const f=fixture(),ctx=f.make(),first=await readNonrootArchiveRef(ctx,f.ref,{purpose:'protocol'});
  expect(Object.isFrozen(first)).toBe(true);f.manifest.owner='b'.repeat(32);
  expect(nonrootArchiveBindings(ctx).owner).toBe('a'.repeat(32));
 });
 it('supplies exact raw bytes to shared verifiers and rejects wrong reference types',async()=>{
  const f=fixture(),resolver=nonrootArchiveResolvers(f.make());
  expect(await resolver.resolveJson(f.ref)).toEqual(f.raw);
  await expect(resolver.resolveBytes(f.ref)).rejects.toThrow();
 });
 it('resolves original receipt bytes by their raw digest without accepting a path or canonical hash',async()=>{
  const f=fixture(),archive=f.make();
  expect(await resolveNonrootArchiveRawJson(archive,f.ref.bytesHash)).toEqual(f.raw);
  await expect(resolveNonrootArchiveRawJson(archive,f.ref.canonicalHash)).rejects.toThrow('NonrootArchiveRawCommitmentMissing');
  await expect(resolveNonrootArchiveRawJson(archive,'/untrusted/receipt.json')).rejects.toThrow('NonrootArchiveRawCommitment');
 });
 it('starts an independent consumption scope for each proof verification',async()=>{
  const f=fixture(),ctx=f.make();await readNonrootArchiveRef(ctx,f.ref,{purpose:'protocol'});
  expect(()=>assertNonrootArchiveConsumed(ctx)).not.toThrow();
  const separate=forkNonrootArchive(ctx);expect(()=>assertNonrootArchiveConsumed(separate)).toThrow('NonrootArchiveUnreferencedAuthority');
  await readNonrootArchiveRef(separate,f.ref,{purpose:'protocol'});expect(()=>assertNonrootArchiveConsumed(separate)).not.toThrow();
 });
 it('preserves original manifest whitespace and object bytes through a wire round trip',async()=>{
  const f=fixture(),text=JSON.stringify(f.manifest,null,2)+'\n\n',ctx=createNonrootEvidenceArchive(text,{expectedManifestHash:hash(f.manifest),readObject:async name=>f.objects.get(name)});
  const wire=await exportNonrootArchive(ctx);expect(wire.manifest).toBe(text);
  const restored=importNonrootArchive(wire,{expectedManifestHash:hash(f.manifest)});expect(nonrootArchiveBindings(restored).manifestRef).toEqual(nonrootArchiveBindings(ctx).manifestRef);
  expect(await nonrootArchiveResolvers(restored).resolveJson(f.ref)).toEqual(f.raw);
 });
 it.each([4,16])('imports a valid %i MiB source object without a regular-expression stack overflow',async mib=>{
  const raw=Buffer.alloc(mib*1024*1024,97),ref={sha256:sha(raw),bytesLength:raw.length},name='sha256-'+ref.sha256+'.bin';
  const manifest={version:2,kind:'nonroot-proof-archive',owner:'a'.repeat(32),files:[{name,purpose:'source',ref,encoding:'bytes'}]};
  const wire={version:1,kind:'nonroot-evidence-bytes',manifest:JSON.stringify(manifest),objects:[{name,base64:raw.toString('base64')}]};
  const restored=importNonrootArchive(wire,{expectedManifestHash:hash(manifest)});
  expect((await nonrootArchiveResolvers(restored).resolveBytes(ref)).equals(raw)).toBe(true);
 });
 it.each(['YQ','YR==','YQ===','YQ==\n','____','Y Q='])('rejects noncanonical base64 %j',async base64=>{
  const f=fixture(),wire=await exportNonrootArchive(f.make());wire.objects[0].base64=base64;
  expect(()=>importNonrootArchive(wire,{expectedManifestHash:hash(f.manifest)})).toThrow();
 });
 it('rejects an encoded object over the existing aggregate limit before decoding it',async()=>{
  const f=fixture(),wire=await exportNonrootArchive(f.make());wire.objects[0].base64='A'.repeat(Math.ceil((32*1024*1024+1)/3)*4);
  expect(()=>importNonrootArchive(wire,{expectedManifestHash:hash(f.manifest)})).toThrow('NonrootArchiveWireLimit');
 });
 it.each(['extra-object','missing-object','alias-name','noncanonical-base64'])('rejects wire %s without a parsed-object fallback',async defect=>{
  const f=fixture(),wire=await exportNonrootArchive(f.make());
  if(defect==='extra-object')wire.objects.push({name:'unexpected',base64:'e30='});if(defect==='missing-object')wire.objects=[];
  if(defect==='alias-name')wire.objects[0].name='../source-evidence.json';if(defect==='noncanonical-base64')wire.objects[0].base64+='\n';
  expect(()=>importNonrootArchive(wire,{expectedManifestHash:hash(f.manifest)})).toThrow();
 });
});
