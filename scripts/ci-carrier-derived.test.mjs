import {describe,it,expect} from 'vitest';
import {readFile,lstat,chmod,writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {carrierWorkerFixture} from './ci-carrier-worker.fixture.mjs';
import {openCarrierStartup} from './lib/ci-carrier-startup.mjs';
import {openCarrierConsumer} from './lib/ci-carrier-consumer.mjs';
import {createCarrierTransport} from './lib/ci-carrier-transport.mjs';
import {collectCarrierBase} from './lib/ci-carrier-worker.mjs';
import {materializeCarrierBuildContext,inspectMaterializedCarrierContext,closeCarrierBuildContext} from './lib/ci-carrier-context.mjs';
import {deriveCarrierRuntimeMaterial,inspectCarrierRuntimeMaterial,closeCarrierRuntimeMaterial} from './lib/ci-carrier-derived.mjs';
import {buildCarrierOffline,inspectCarrierOfflineBuild,closeCarrierOfflineBuild} from './lib/production-nonroot-carrier-build.mjs';
import {inspectImageFilesystemFile} from './lib/production-image-filesystem.mjs';
import {getNonrootNativeProbeSource,collectCarrierImagePrerequisites,inspectNonrootControlPrerequisites} from './lib/production-nonroot-control-prerequisites.mjs';
import {readControlSourceFile} from './lib/production-control-source.mjs';
import {controlImageGraphBinding} from './lib/production-image-graph.mjs';
import {inspectCarrierDerivedMaterial} from './lib/ci-carrier-derived-format.mjs';
import {sha,hash} from './lib/ci-smoke-acquisition-format.mjs';

async function setup(f,use){let consumer,transport,context,base;
 try{
  const startup=await openCarrierStartup({config:f.config,env:f.env,host:f.seams.host},f.seams.startup);consumer=openCarrierConsumer({startup,config:f.config,env:f.env});transport=createCarrierTransport({consumer,env:f.env},f.seams.transport);
  await transport.assume();await transport.identity();consumer.confirmGrant(await transport.getGrant());
  context=await transport.getContext(stream=>materializeCarrierBuildContext({stream,plan:f.config.plan,tempRoot:f.tempRoot,metadataReads:consumer}));base=await collectCarrierBase({consumer,transport,tempRoot:f.tempRoot});
  await use({context,base,consumer,transport,bindings:{context,baseGraph:base.graph,baseFilesystem:base.filesystem,metadataReads:consumer},args:{context,baseGraph:base.graph,baseFilesystem:base.filesystem,baseCacheDirectory:base.cacheDirectory,sourceContext:consumer.admission.source.sourceContext,metadataReads:consumer,tempRoot:f.tempRoot}});
 }finally{await transport?.close();await base?.close();await consumer?.close();}
}
it('does not accept a JSON-derived handle',async()=>{
 await expect(inspectCarrierRuntimeMaterial({kind:'carrier-derived-runtime-context'},{})).rejects.toThrow('CarrierDerivedHandle');
});
it('requires the final probe local reservation before reading even its source or image inputs',async()=>{
 let reserves=0;const native=process.platform==='linux'&&process.arch==='arm64';
 await expect(collectCarrierImagePrerequisites({}, {metadataReads:{reserveLocal(charge){reserves++;expect(charge.logicalBytes).toBeGreaterThan(16777216);throw Error('SyntheticNoLocalBudget');}},tempRoot:'/tmp',cacheDirectory:'/tmp/synthetic-unopened'})).rejects.toThrow(native?'SyntheticNoLocalBudget':'CarrierPrerequisitesNativeArm64');
 expect(reserves).toBe(native?1:0);
 await expect(collectCarrierImagePrerequisites({}, {home:'/arbitrary'})).rejects.toThrow('NonrootPrerequisitesFields');
});
describe.skipIf(process.env.MEM9_CARRIER_NATIVE_TEST!=='1')('R13 actual native base derivation',()=>{
 it('derives real native/CA facts after SDK base acquisition and builds both contexts without changing supplied bytes',()=>carrierWorkerFixture(f=>setup(f,async s=>{
  const source=inspectMaterializedCarrierContext(s.context),beforeHash=f.config.plan.context.sha256;expect(source.runtimeManifest).toBeNull();expect(source).not.toHaveProperty('nativePins');
  let derived,built;
  try{
   derived=await deriveCarrierRuntimeMaterial(s.args);const d=await inspectCarrierRuntimeMaterial(derived,s.bindings);
   expect(d.record.contextHash).toBe(beforeHash);expect(hash(source.manifest)).toBe(f.config.plan.context.manifestHash);expect(d.record.nativeEvidence.record.probeCodeHash).toBe(getNonrootNativeProbeSource().sha256);
   expect(d.record.nativeEvidence.record.probe.native).toEqual([1,1000,1000,1000,1000,-22,1,-1,-1,1000,1000,1000,1000,1]);
   expect(inspectCarrierDerivedMaterial(d.record,{plan:f.config.plan,grantHash:f.config.grantHash,contextManifest:source.manifest})).toEqual(d.record);
   expect(d.nativePins.nodeSha256).toBe(inspectImageFilesystemFile(s.base.filesystem,'/usr/local/bin/node').sha256);
   expect(sha(await readFile(join(d.materialDirectory,'rootfs/bootstrap/global-bundle.pem')))).toBe(sha(f.native.ca));
   expect(d.record.baseMetadata.map(m=>m.descriptor.digest)).toContain(f.config.plan.template.base.rootDigest);
   const configMetadata=d.record.baseMetadata.find(m=>m.descriptor.digest===f.config.plan.template.base.configDigest);
   expect('sha256:'+sha(Buffer.from(configMetadata.bytesBase64,'base64'))).toBe(f.config.plan.template.base.configDigest);
   await expect(lstat(join(source.directory,'rootfs/carrier/manifest.json'))).rejects.toMatchObject({code:'ENOENT'});
   expect(inspectMaterializedCarrierContext(s.context).plan.context.sha256).toBe(beforeHash);
   built=await buildCarrierOffline({...s.args,derived});const b=inspectCarrierOfflineBuild(built);
   expect(b.record.version).toBe(2);expect(b.record.derivedRecordHash).toBe(hash(d.record));expect(b.record.contextHash).toBe(beforeHash);
   expect(inspectImageFilesystemFile(b.filesystem,'/carrier/manifest.json').sha256).toBe(d.record.files.find(f=>f.path==='rootfs/carrier/manifest.json').sha256);
   expect(inspectImageFilesystemFile(b.filesystem,'/bootstrap/global-bundle.pem').sha256).toBe(sha(f.native.ca));
   const sourceContext=s.args.sourceContext,own=await readControlSourceFile(sourceContext,'scripts/lib/production-nonroot-control-prerequisites.mjs'),files=[own.file];
   const sourceClosure={version:1,kind:'git-file-closure',tree:sourceContext.tree,files,closureHash:hash(files)},finalOptions={controlVerification:{graph:b.graph,filesystem:b.filesystem},sourceContext,expected:{candidateTree:sourceContext.tree},metadataReads:s.consumer,tempRoot:f.tempRoot,cacheDirectory:b.cacheDirectory,deadlineMs:f.config.plan.deadlineMs};
   const {graphHash,...image}=controlImageGraphBinding(b.graph),finalHandle=await collectCarrierImagePrerequisites({image,sourceClosure},finalOptions),finalNative=inspectNonrootControlPrerequisites(finalHandle,finalOptions);
   expect(finalNative.record.image).toEqual(image);expect(finalNative.record.graphHash).toBe(graphHash);expect(finalNative.record.image.rootDigest).not.toBe(d.record.baseImage.rootDigest);
   expect(finalNative.record.cleanupConfirmed).toBe(true);expect(finalNative.environment.imageEnvironment).toContain('HOME=/tmp');expect(finalNative.record.probe.native).toEqual(d.record.nativeEvidence.record.probe.native);
   expect(()=>inspectNonrootControlPrerequisites(finalHandle,{...finalOptions,controlVerification:{graph:s.base.graph,filesystem:s.base.filesystem}})).toThrow('NonrootPrerequisitesContextBinding');
   await expect(collectCarrierImagePrerequisites({image:d.record.baseImage,sourceClosure},{...finalOptions,controlVerification:{graph:s.base.graph,filesystem:s.base.filesystem},cacheDirectory:s.base.cacheDirectory})).rejects.toThrow('CarrierPrerequisitesRecipe');
   expect(f.calls.some(c=>c.action==='DescribeImageScanFindings')).toBe(false);
  }finally{if(built)await closeCarrierOfflineBuild(built);if(derived)await closeCarrierRuntimeMaterial(derived,s.bindings);await closeCarrierBuildContext(s.context);}
 }),{sourceOnly:true,nativeBase:true}),180000);
 for(const variant of ['missing-ca','invalid-ca','missing-primitive','unsafe-home'])it('holds on '+variant+' without manufacturing derived material',()=>carrierWorkerFixture(f=>setup(f,async s=>{
  await expect(deriveCarrierRuntimeMaterial(s.args)).rejects.toThrow(variant==='missing-ca'?'CarrierDerivationNative':variant==='invalid-ca'?'CarrierDerivationPublicCa':variant==='unsafe-home'?'NonrootPrerequisitesEnvironment':'ImageVirtualLinkMissing');
  const source=inspectMaterializedCarrierContext(s.context);expect(source.runtimeManifest).toBeNull();
  await expect(lstat(join(source.directory,'rootfs/carrier/manifest.json'))).rejects.toMatchObject({code:'ENOENT'});
  expect(f.calls.some(c=>c.action==='InitiateLayerUpload')).toBe(false);
 }),{sourceOnly:true,nativeBase:true,nativeVariant:variant}),180000);
});
