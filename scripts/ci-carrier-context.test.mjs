import {it,expect} from 'vitest';
import {mkdtemp,rm,readFile,writeFile,readdir,chmod} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {materializeCarrierBuildContext,inspectMaterializedCarrierContext,verifyMaterializedCarrierContext,consumeCarrierBuildContext,closeCarrierBuildContext} from './lib/ci-carrier-context.mjs';
import {carrierContextFixture,carrierSourceContextFixture,sha,zero} from './ci-carrier.fixture.mjs';

async function fixture(use){const tempRoot=await mkdtemp(join(tmpdir(),'carrier-context-test-')),spent=zero(),metadataReads={reserveLocal(charge){for(const key of Object.keys(spent))spent[key]+=charge[key];}};try{await use({tempRoot,metadataReads,spent});}finally{await rm(tempRoot,{recursive:true,force:true});}}
const materialize=(f,x,stream=f.stream())=>materializeCarrierBuildContext({stream,plan:f.plan,baseEvidence:f.baseEvidence,...x});
it('extracts the exact framed bytes, requires a real runtime manifest and binds a single-use handle',()=>fixture(async x=>{
 const f=carrierContextFixture(),h=await materialize(f,x),v=inspectMaterializedCarrierContext(h);
 expect(await readFile(join(v.directory,'rootfs/carrier/manifest.json'))).toEqual(f.members.get('rootfs/carrier/manifest.json'));
 expect(x.spent.logicalBytes).toBe(f.bytes.length+f.manifest.files.reduce((n,r)=>n+r.bytesLength,0));
 expect(x.spent.processedEntries).toBe(f.manifest.files.length);
 expect(()=>inspectMaterializedCarrierContext(structuredClone(h))).toThrow('CarrierContextHandle');
 await consumeCarrierBuildContext(h);await expect(consumeCarrierBuildContext(h)).rejects.toThrow('CarrierContextAlreadyConsumed');
 await closeCarrierBuildContext(h);expect(await readdir(x.tempRoot)).toEqual([]);
}));
it.each(['runtime','host','required-import'])('rejects missing %s rather than producing a runnable-looking context',name=>fixture(async x=>{
 const path={runtime:'rootfs/carrier/manifest.json',host:'rootfs/carrier/legacy-audit.mjs','required-import':'rootfs/bootstrap/operator/infra/gateway/service-auth.mjs'}[name];
 const f=carrierContextFixture({mutateFiles:files=>files.splice(files.findIndex(r=>r.path===path),1)});
 await expect(materialize(f,x)).rejects.toThrow('CarrierContextMissingClosure');expect(await readdir(x.tempRoot)).toEqual([]);
}));
it.each(['hash','truncated','trailing'])('fails closed on %s wire bytes',mode=>fixture(async x=>{
 const f=carrierContextFixture();let bytes=Buffer.from(f.bytes);if(mode==='hash')bytes[bytes.length-1]^=1;else if(mode==='truncated')bytes=bytes.subarray(0,-1);else bytes=Buffer.concat([bytes,Buffer.from('X')]);
 await expect(materialize(f,x,(async function*(){yield bytes;})())).rejects.toThrow();expect(await readdir(x.tempRoot)).toEqual([]);
}));
it.each(['../escape','rootfs/bootstrap/operator/.env','rootfs/bootstrap/operator/unreviewed.mjs','rootfs/carrier/other.mjs'])('rejects unknown or escaping member %s',path=>fixture(async x=>{
 const f=carrierContextFixture({mutateFiles:(files,members)=>{const b=Buffer.from('bad');members.set(path,b);files.push({path,type:'file',mode:0o444,sha256:sha(b),bytesLength:b.length});}});
 await expect(materialize(f,x)).rejects.toThrow('CarrierContextPath');
}));
it('rejects a context that changes the runtime inventory or native base pins',()=>fixture(async x=>{
 for(const mutateRuntime of [r=>r.files.pop(),r=>r.runtime={...r.runtime,nodeSha256:'f'.repeat(64)}]){
  const f=carrierContextFixture({mutateRuntime});await expect(materialize(f,x)).rejects.toThrow();
 }
}));
it('requires the exact cleaning recipe even when the altered bytes have matching template hashes',()=>fixture(async x=>{
 const f=carrierContextFixture({mutateDockerfile:d=>d.replace('RUN rm -rf /bootstrap/operator /carrier\n','')});
 await expect(materialize(f,x)).rejects.toThrow('CarrierCleanRecipeRequired');
}));
it('rejects symlink escape before materialization',()=>fixture(async x=>{
 const f=carrierContextFixture({mutateFiles:files=>files.push({path:'rootfs/bootstrap/operator/node_modules/escape',type:'symlink',mode:0o777,target:'../../../../../../etc/passwd',sha256:sha('../../../../../../etc/passwd'),bytesLength:31})});
 await expect(materialize(f,x)).rejects.toThrow();expect(await readdir(x.tempRoot)).toEqual([]);
}));
it('rehashes before use and retains tampered/unknown local state on cleanup',()=>fixture(async x=>{
 const f=carrierContextFixture(),h=await materialize(f,x),v=inspectMaterializedCarrierContext(h),path=join(v.directory,'rootfs/carrier/legacy-audit.mjs');
 await chmod(path,0o600);await writeFile(path,'changed');await chmod(path,0o444);
 await expect(verifyMaterializedCarrierContext(h)).rejects.toThrow('CarrierContextChanged');await expect(closeCarrierBuildContext(h)).rejects.toThrow('CarrierContextChanged');
 expect(await readdir(x.tempRoot)).toHaveLength(1);
}));
it('fails before consuming the stream when the inherited budget is unavailable',()=>fixture(async x=>{
 const f=carrierContextFixture();let consumed=false;const stream=(async function*(){consumed=true;yield f.bytes;})();
 await expect(materialize(f,{...x,metadataReads:{reserveLocal(){throw Error('BUDGET');}}},stream)).rejects.toThrow('BUDGET');expect(consumed).toBe(false);
}));
it('R13 materializes immutable supplied source without any native/CA facts or runtime manifest',()=>fixture(async x=>{
 const f=carrierSourceContextFixture(),originalHash=f.plan.context.sha256,h=await materialize(f,x),v=inspectMaterializedCarrierContext(h);
 expect(v.manifest.version).toBe(2);expect(v.runtimeManifest).toBeNull();expect(v).not.toHaveProperty('nativePins');expect(v.runtimeSource).toEqual(f.manifest.runtimeSource);
 expect(v.plan.context.sha256).toBe(originalHash);expect(sha(f.bytes)).toBe(originalHash);
 await expect(readFile(join(v.directory,'rootfs/carrier/manifest.json'))).rejects.toMatchObject({code:'ENOENT'});
 await expect(readFile(join(v.directory,'rootfs/bootstrap/global-bundle.pem'))).rejects.toMatchObject({code:'ENOENT'});
 await verifyMaterializedCarrierContext(h);await closeCarrierBuildContext(h);
}));
it.each(['rootfs/carrier/manifest.json','rootfs/bootstrap/global-bundle.pem'])('R13 refuses a supplied/generated collision at %s',path=>fixture(async x=>{
 const f=carrierSourceContextFixture({mutateFiles:(files,members)=>{const bytes=Buffer.from('not-derived');members.set(path,bytes);files.push({path,type:'file',mode:0o444,sha256:sha(bytes),bytesLength:bytes.length});}});
 await expect(materialize(f,x)).rejects.toThrow('CarrierSuppliedDerivedCollision');expect(await readdir(x.tempRoot)).toEqual([]);
}));
it('R13 forbids native fields in the authenticated source seed',()=>fixture(async x=>{
 const f=carrierSourceContextFixture({mutateHeader:h=>{h.runtimeSource.native={nodeSha256:sha('invented')};}});
 await expect(materialize(f,x)).rejects.toThrow('CarrierContextFields');
}));
it('R13 rejects changed supplied bytes even with the correct source-only header',()=>fixture(async x=>{
 const f=carrierSourceContextFixture(),bytes=Buffer.from(f.bytes);bytes[bytes.length-1]^=1;
 await expect(materialize(f,x,(async function*(){yield bytes;})())).rejects.toThrow('CarrierContextFileHash');
}));
