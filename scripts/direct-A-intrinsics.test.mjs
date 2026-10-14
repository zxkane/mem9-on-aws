import {it,expect} from 'vitest';
import {createHash} from 'node:crypto';
import {fixture} from './direct-A-artifact.fixture.mjs';
import {verifyNonrootControlArtifactFiles,verifyNonrootControlIntrinsicFiles} from './lib/production-nonroot-artifact.mjs';
import {inspectProductionDeployedControlBuild} from './lib/production-control-composition-recipe.mjs';
import {verifyNonrootControlRuntimeObservation,verifyNonrootRehearsalRuntimeObservation} from './lib/production-nonroot-observation.mjs';
import {inspectNonrootControlGuardTests,inspectNonrootRehearsalGuardTests} from './lib/production-nonroot-control-guard.mjs';
import {readNonrootEvidence} from './lib/production-nonroot-runtime.mjs';
import {nonrootHash} from './lib/production-nonroot-contracts.mjs';
import {normalizeNonrootControlScanPages,normalizeNonrootRehearsalScanPages} from './lib/production-nonroot-control-scan-policy.mjs';
import {assertNonrootControlCurrent} from './lib/production-nonroot-control-current.mjs';

const projection=b=>({image:b.image,guardImports:b.guardImports,guardSource:b.guardSource,resolvedLaunches:b.resolvedLaunches});
it('shares full intrinsic file predicates with preview A, without fabricating ActualMain',async()=>{
 const x=await fixture({repositoryName:'mem9-on-aws/preview/bootstrap'}),input=projection(x.b);
 const result=await verifyNonrootControlIntrinsicFiles(input,{...x.options(),assertCurrent(){}});
 expect(result.image.repositoryName).toBe('mem9-on-aws/preview/bootstrap');
 expect(result.files.some(f=>f.path==='/usr/local/bin/node')).toBe(true);
 expect(result.files.some(f=>f.path==='/bin/setpriv')).toBe(true);
 expect(result.unknownRuntimePaths).toEqual(['/']);
 const a={...input,version:1,kind:'authenticated-A-rehearsal-control-v1'};
 expect(()=>inspectProductionDeployedControlBuild(a)).toThrow();
 await expect(verifyNonrootControlArtifactFiles(a,x.options())).rejects.toThrow();
});
it('keeps forged native runtime and guard contexts rejected in both phases',()=>{
 for(const read of [verifyNonrootControlRuntimeObservation,verifyNonrootRehearsalRuntimeObservation])expect(()=>read({}, {}, {})).toThrow('NonrootRuntimeObservationRequired');
 for(const read of [inspectNonrootControlGuardTests,inspectNonrootRehearsalGuardTests])expect(()=>read({},{})).toThrow('NonrootGuardCaptureContextRequired');
});
for(const field of ['node','library','primitive','guard','application'])it('A intrinsic wrapper rejects actual '+field+' mismatch',async()=>{
 const x=await fixture({repositoryName:'mem9-on-aws/preview/bootstrap'}),b=x.b;
 if(field==='node')b.guardImports.nodeRuntime.executableSha256='e'.repeat(64);
 if(field==='library')b.guardImports.nodeRuntime.loaderAndNativeLibraries=x.f.json({files:[{path:'/lib/native-loader.so',sha256:'e'.repeat(64)}]});
 if(field==='primitive'){const l=b.resolvedLaunches[0],p=structuredClone(x.f.a.value(l.primitiveEvidence));p.fileSha256='e'.repeat(64);l.primitiveEvidence=x.f.json(p);}
 if(field==='guard'){b.guardSource.files[0].sha256='e'.repeat(64);b.guardSource.files[0].blob.sha256='e'.repeat(64);b.guardSource.closureHash=nonrootHash(b.guardSource.files);}
 if(field==='application')b.resolvedLaunches.find(l=>l.originalModule.present).originalModuleSha256.value='e'.repeat(64);
 await expect(verifyNonrootControlIntrinsicFiles(projection(b),x.options())).rejects.toThrow('NonrootControlFileHash');
});
it('stops the evidence reader before cloning/hash/decode when owner closes in the resolver continuation',async()=>{
 let open=true;const bytes=Buffer.from('{}'),ref={bytesHash:createHash('sha256').update(bytes).digest('hex'),canonicalHash:nonrootHash({}),bytesLength:2};
 await expect(readNonrootEvidence(ref,{assertCurrent(){if(!open)throw Error('OriginalOwnerClosed');},resolveJson:async()=>{queueMicrotask(()=>{open=false;});return bytes;}})).rejects.toThrow('OriginalOwnerClosed');
});
it('does not let a returned reference be parsed after closure inside an intrinsic dependency',async()=>{
 const x=await fixture(),options=x.options();let open=true;
 await expect(verifyNonrootControlIntrinsicFiles(projection(x.b),{...options,assertCurrent(){if(!open)throw Error('OriginalPermitClosed');},resolveJson:async ref=>{const raw=await options.resolveJson(ref);queueMicrotask(()=>{open=false;});return raw;}})).rejects.toThrow('OriginalPermitClosed');
});
for(const check of [async()=>{},()=>true,()=>Promise.resolve()])it('rejects non-synchronous or success-flag currentness hooks',()=>{
 expect(()=>assertNonrootControlCurrent({assertCurrent:check})).toThrow('NonrootControlSynchronousCurrent');
});
const now=2000000000000,image={account:'123456789012',region:'ap-northeast-1',repositoryName:'mem9-on-aws/preview/bootstrap',rootDigest:'sha256:'+'1'.repeat(64),arm64Digest:'sha256:'+'2'.repeat(64),configDigest:'sha256:'+'3'.repeat(64)};
const page=()=>({registryId:image.account,repositoryName:image.repositoryName,imageId:{imageDigest:image.arm64Digest},imageScanStatus:{status:'COMPLETE'},imageScanFindings:{imageScanCompletedAt:now/1000,findingSeverityCounts:{},findings:[]}});
it('applies the same zero-findings rule in a fixed preview-only scan lane',()=>{
 expect(normalizeNonrootRehearsalScanPages([JSON.stringify(page())],image,{observedMs:now,now}).findings).toEqual([]);
 expect(()=>normalizeNonrootControlScanPages([JSON.stringify(page())],image,{observedMs:now,now})).toThrow('NonrootControlScanObservation');
});
for(const change of ['observation','completion','digest','repository','findings','pagination'])it('rejects A scan '+change+' failures',()=>{
 const p=page();let observedMs=now;
 if(change==='observation')observedMs-=300001;
 if(change==='completion')p.imageScanFindings.imageScanCompletedAt-=86401;
 if(change==='digest')p.imageId.imageDigest=image.rootDigest;
 if(change==='repository')p.repositoryName='mem9-on-aws/bootstrap';
 if(change==='findings'){p.imageScanFindings.findings=[{name:'test',severity:'HIGH',attributes:[]}];p.imageScanFindings.findingSeverityCounts={HIGH:1};}
 if(change==='pagination')p.nextToken='unread-page';
 expect(()=>normalizeNonrootRehearsalScanPages([JSON.stringify(p)],image,{observedMs,now})).toThrow();
});
