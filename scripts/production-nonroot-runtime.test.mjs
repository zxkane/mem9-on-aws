import {describe,it,expect} from 'vitest';
import {canaryEvidenceHash as hash} from './lib/production-canary-verification.mjs';
import {nonrootRuntimeFixture,h} from './production-nonroot-runtime.fixture.mjs';
import {inspectNonrootRuntimeIdentity,verifyNonrootTargetAuditJoin} from './lib/production-nonroot-runtime.mjs';
import {readFile} from 'node:fs/promises';

describe('nonroot runtime identity and same-target audit joins',()=>{
  it('keeps the regular runtime import closure pure and free of host graph/parser packages',async()=>{
    const seen=new Set();
    async function visit(url){
      if(seen.has(url.href))return;seen.add(url.href);const text=await readFile(url,'utf8');expect(text).not.toMatch(/\bimport\s*\(/);
      for(const m of text.matchAll(/\bfrom\s*['"]([^'"]+)['"]/g)){
        const spec=m[1];if(spec.startsWith('node:'))continue;
        expect(spec).toMatch(/^\.\//);expect(spec).not.toMatch(/artifact|provenance|image-graph|image-filesystem|control-source/);await visit(new URL(spec,url));
      }
    }
    await visit(new URL('./lib/production-nonroot-runtime.mjs',import.meta.url));expect(seen.size).toBe(2);
  });
  it('accepts a complete synthetic pre/audit/post join with fresh independent health processes',async()=>{
    const f=nonrootRuntimeFixture();const result=await verifyNonrootTargetAuditJoin(f.audit,f);
    expect(result.targetBindingHash).toBe(hash(f.target));expect(result.preTargetHash).toBe(hash(f.pre));expect(result.postTargetHash).toBe(hash(f.post));
  });
  for(const field of ['uid','gid'])for(const position of [0,1,2,3])it('rejects root '+field+' position '+position,()=>{
    const f=nonrootRuntimeFixture(),r=f.pre.identity[0];r.application[0][field][position]=0;expect(()=>inspectNonrootRuntimeIdentity(r,{now:f.now})).toThrow();
  });
  for(const field of ['capInh','capPrm','capEff','capBnd','capAmb'])it('rejects nonzero '+field,()=>{
    const f=nonrootRuntimeFixture(),r=f.pre.identity[0];r.application[0][field]='0000000000000001';expect(()=>inspectNonrootRuntimeIdentity(r,{now:f.now})).toThrow();
  });
  for(const defect of ['nnp','extra-group','future','sparse','accessor','duplicate-pid','wrong-artifact'])it('rejects identity '+defect,()=>{
    const f=nonrootRuntimeFixture(),r=f.pre.identity[0];
    if(defect==='nnp')r.application[1].noNewPrivs=0;if(defect==='extra-group')r.application[0].groups=[1000,0];if(defect==='future')r.completedMs=f.now+1;
    if(defect==='sparse')delete r.application[0];if(defect==='accessor')Object.defineProperty(r,'kind',{get(){throw Error('getter must not execute');},enumerable:true});
    if(defect==='duplicate-pid'){r.application[1].pid=r.application[0].pid;r.application[1].startTimeTicks=r.application[0].startTimeTicks;}if(defect==='wrong-artifact')r.artifactBinding.kind='artifact-test';
    expect(()=>inspectNonrootRuntimeIdentity(r,{now:f.now})).toThrow();
  });
  for(const defect of ['missing-container','duplicate-container','changed-pid','changed-start','changed-executable','wrong-registration','wrong-runtime','missing-health','wrong-health-command','old-health-sample','out-of-window','wrong-target','wrong-descriptor','raw-ref-tamper'])it('rejects join '+defect,async()=>{
    const f=nonrootRuntimeFixture(),post=f.post.identityRecheck;
    if(defect==='missing-container')post.identities.pop();if(defect==='duplicate-container')post.identities[1]=post.identities[0];
    if(defect==='changed-pid')post.mainProcesses[0].postMain.pid++;if(defect==='changed-start')post.mainProcesses[0].postMain.startTimeTicks++;
    if(defect==='changed-executable')post.mainProcesses[0].postMain.executableDigest='sha256:'+h(333);
    if(defect==='wrong-registration')post.registrationHash=h(334);if(defect==='wrong-runtime')post.identities[0].runtimeId='foreign-runtime';
    if(defect==='missing-health')post.healthCoverage[0].processes=[];if(defect==='wrong-health-command')post.healthCoverage[0].healthCommandHash=h(335);
    if(defect==='old-health-sample')post.healthCoverage[0].startedMs=f.pre.startedMs;if(defect==='out-of-window')f.pre.startedMs=f.post.completedMs-300001;
    if(defect==='wrong-target')f.post.target={...f.target,taskArn:f.target.taskArn.replace('a'.repeat(32),'b'.repeat(32))};
    if(defect==='wrong-descriptor')f.pre.descriptorHash=h(336);if(defect==='raw-ref-tamper')f.records.set(f.pre.rawObservations.bytesHash,Buffer.from('{}'));
    // Rehashing the pre-record must not hide altered actual target evidence.
    f.post.preTargetHash=post.preTargetHash=hash(f.pre);
    await expect(verifyNonrootTargetAuditJoin(f.audit,f)).rejects.toThrow();
  });
  it('does not accept a generic true-flag identity recheck',async()=>{
    const f=nonrootRuntimeFixture();f.post.identityRecheck={result:'pass'};await expect(verifyNonrootTargetAuditJoin(f.audit,f)).rejects.toThrow();
  });
  it('requires retrieving raw evidence rather than approving self-hashed labels',async()=>{
    const f=nonrootRuntimeFixture();await expect(verifyNonrootTargetAuditJoin(f.audit,{...f,resolveJson:undefined})).rejects.toThrow();
  });
});
