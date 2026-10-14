import {beforeAll,it,expect} from 'vitest';
import {nonrootDeploymentFixture} from './production-nonroot-provenance.fixture.mjs';
import {nonrootHash as hash} from './lib/production-nonroot-contracts.mjs';
import {captureNonrootControlBuildAction,completeNonrootControlBuildAction,captureNonrootControlArtifact} from './lib/production-nonroot-control-build.mjs';
import {verifyNonrootControlBuildLog} from './lib/production-nonroot-provenance.mjs';

let f;
beforeAll(async()=>{f=await nonrootDeploymentFixture();});
function input(){
 const startedMs=f.now-10000,finishedMs=f.now-2000;
 const job={...structuredClone(f.rawJob),status:'in_progress',conclusion:null,started_at:new Date(startedMs).toISOString(),completed_at:null,
  steps:[{number:1,name:f.job.steps[0].name,status:'completed',conclusion:'success',started_at:new Date(startedMs+1000).toISOString(),completed_at:new Date(finishedMs).toISOString()}]};
 return {contract:f.contract,source:f.source,run:{...f.rawRun,status:'in_progress',conclusion:null},job,
  metadata:JSON.stringify({'containerimage.digest':f.build.image.rootDigest,'containerimage.config.digest':f.build.image.configDigest}),
  outputDigest:f.build.image.rootDigest,observedMs:f.now};
}
it('captures an actual successful action without inventing completion of its running job',async()=>{
 const raw=input(),c=await captureNonrootControlBuildAction(raw,f.options());
 expect(c.kind).toBe('nonroot-control-build-action-capture');
 expect(c.job.status).toBe('in_progress');expect(c.job.completed_at).toBeNull();
 expect(c.metadata).toBe(raw.metadata);expect(c.observedMs).toBe(f.now);
 expect(c).not.toHaveProperty('reviewedMs');expect(c).not.toHaveProperty('expiresMs');
 expect(c).not.toHaveProperty('resolvedLaunches');expect(c).not.toHaveProperty('taskDefinitionArn');
});
it.each(['failed-action','pending-action','future-action','wrong-run','duplicate-step','wrong-output','wrong-source'])('rejects %s',async defect=>{
 const raw=input();
 if(defect==='failed-action')raw.job.steps[0].conclusion='failure';
 if(defect==='pending-action')raw.job.steps[0].status='in_progress';
 if(defect==='future-action')raw.job.steps[0].completed_at=new Date(f.now+1).toISOString();
 if(defect==='wrong-run')raw.job.run_id++;
 if(defect==='duplicate-step')raw.job.steps.push({...raw.job.steps[0]});
 if(defect==='wrong-output')raw.outputDigest='sha256:'+'f'.repeat(64);
 if(defect==='wrong-source')raw.source={...raw.source,checkout:{...raw.source.checkout,sha:'f'.repeat(40)}};
 await expect(captureNonrootControlBuildAction(raw,f.options())).rejects.toThrow();
});
it('appends actual final job/log evidence while preserving the original capture and time',async()=>{
 const c=await captureNonrootControlBuildAction(input(),f.options()),original=JSON.stringify(c);
 const job={...c.job,status:'completed',conclusion:'success',completed_at:new Date(f.now+1000).toISOString()};
 const log=Buffer.from(`#7 exporting manifest list ${f.build.image.rootDigest}\n#7 exporting config ${f.build.image.configDigest}\n#7 DONE 1.0s\n`);
 const completed=completeNonrootControlBuildAction(c,{contract:f.contract,run:c.run,job,buildLog:log,now:f.now+2000});
 expect(JSON.stringify(c)).toBe(original);expect(completed.captureHash).toBe(hash(c));
 expect(completed.completedMs).toBe(f.now+1000);expect(completed.observedMs).toBe(f.now+2000);
 expect(completed.job.steps).toEqual(c.job.steps);expect(completed.buildLog.sha256).toMatch(/^[a-f0-9]{64}$/);
});
it.each(['attempt','step-time','failed','still-running','truncated-log'])('rejects final %s',async defect=>{
 const c=await captureNonrootControlBuildAction(input(),f.options());
 const job=structuredClone({...c.job,status:'completed',conclusion:'success',completed_at:new Date(f.now+1000).toISOString()});
 let log=Buffer.from(`#7 exporting manifest list ${f.build.image.rootDigest}\n#7 exporting config ${f.build.image.configDigest}\n#7 DONE 1.0s\n`);
 if(defect==='attempt')job.run_attempt++;
 if(defect==='step-time')job.steps[0].completed_at=new Date(f.now-1000).toISOString();
 if(defect==='failed')job.conclusion='failure';
 if(defect==='still-running')job.status='in_progress';
 if(defect==='truncated-log')log=Buffer.from('unrelated log');
 expect(()=>completeNonrootControlBuildAction(c,{contract:f.contract,run:c.run,job,buildLog:log,now:f.now+2000})).toThrow();
});
it('captures complete inventory and real filesystem facts, never image layers in JSON',async()=>{
 const c=await captureNonrootControlBuildAction(input(),f.options());
 const snapshot=await captureNonrootControlArtifact(c,f.controlVerification);
 expect(snapshot.image).toEqual(f.build.image);
 expect(snapshot.inventory).toEqual(f.controlVerification.graph.inventory);
 expect(snapshot.filesystem.component).toBe('bootstrap');
 expect(snapshot.objects).toHaveLength(3);
 expect(snapshot.objects.every(row=>!row.mediaType.includes('layer'))).toBe(true);
 await expect(captureNonrootControlArtifact(c,{graph:JSON.parse(JSON.stringify(f.controlVerification.graph)),filesystem:f.controlVerification.filesystem})).rejects.toThrow();
});
it('accepts the observed BuildKit start/completion pair for one export vertex',()=>{
 const image=f.build.image;
 const log=Buffer.from(`#64 exporting manifest ${image.arm64Digest}\n#64 exporting manifest ${image.arm64Digest} 0.0s done\n#64 exporting config ${image.configDigest} 0.0s done\n#64 exporting manifest list ${image.rootDigest}\n#64 exporting manifest list ${image.rootDigest} 0.0s done\n#64 DONE 1.2s\n`);
 expect(verifyNonrootControlBuildLog(log,image)).toEqual({vertex:'64'});
});
it.each(['conflict','repeated-start','two-vertices','missing-done','cached'])('rejects %s in build export events',defect=>{
 const image=f.build.image,rows=[`#64 exporting manifest ${image.arm64Digest}`,`#64 exporting config ${image.configDigest} 0.0s done`,`#64 exporting manifest list ${image.rootDigest}`,`#64 exporting manifest list ${image.rootDigest} 0.0s done`,'#64 DONE 1.2s'];
 if(defect==='conflict')rows.splice(3,0,'#64 exporting manifest list sha256:'+'f'.repeat(64));
 if(defect==='repeated-start')rows[3]=rows[2];
 if(defect==='two-vertices')rows[1]=rows[1].replace('#64','#65');
 if(defect==='missing-done')rows.pop();
 if(defect==='cached')rows.splice(0,0,'#64 CACHED');
 expect(()=>verifyNonrootControlBuildLog(Buffer.from(rows.join('\n')),image)).toThrow('NonrootControlBuildLog');
});

function resumedExportRows(image){
 return [
  '#12 DONE 0.1s',
  '#64 exporting to image',
  `#64 exporting manifest ${image.arm64Digest} 0.0s done`,
  `#64 exporting config ${image.configDigest} 0.0s done`,
  `#64 exporting manifest list ${image.rootDigest} 0.0s done`,
  '#64 DONE 1.1s',
  '#65 [auth] sharing credentials for registry.example.com',
  '#65 DONE 0.0s',
  '#64 exporting to image',
  '#64 pushing layers',
  '#64 pushing layers 2.0s done',
  `#64 pushing manifest for registry.example.com/bootstrap:example@${image.rootDigest}`,
  `#64 pushing manifest for registry.example.com/bootstrap:example@${image.rootDigest} 0.2s done`,
  '#64 DONE 3.3s',
  '#66 resolving provenance for metadata file',
  '#66 DONE 0.0s',
 ];
}
it('accepts complete resumed export progress and preserves the full original log bytes',()=>{
 const log=Buffer.from(resumedExportRows(f.build.image).map(row=>'2026-01-01T00:00:00.000Z '+row).join('\n')+'\n'),before=Buffer.from(log);
 expect(verifyNonrootControlBuildLog(log,f.build.image)).toEqual({vertex:'64'});
 expect(log.equals(before)).toBe(true);
});
it('binds the complete resumed push log in the original action completion',async()=>{
 const capture=await captureNonrootControlBuildAction(input(),f.options()),before=JSON.stringify(capture);
 const job={...capture.job,status:'completed',conclusion:'success',completed_at:new Date(f.now+1000).toISOString()};
 const log=Buffer.from(resumedExportRows(f.build.image).join('\n')+'\n');
 const completed=completeNonrootControlBuildAction(capture,{contract:f.contract,run:capture.run,job,buildLog:log,now:f.now+2000});
 expect(completed.buildLog.bytesLength).toBe(log.length);
 expect(completed.buildLog.sha256).toBe(f.bytes(log).sha256);
 expect(JSON.stringify(capture)).toBe(before);
});
it.each(['unfinished-push','unfinished-resume','foreign-final-done','error-after-first-done','cached-after-first-done','conflicting-root','conflicting-config','later-unfinished-progress','done-before-export'])('rejects %s after an earlier export completion',defect=>{
 const image=f.build.image,rows=resumedExportRows(image);
 if(defect==='unfinished-push')rows.splice(rows.indexOf('#64 DONE 3.3s'),1);
 if(defect==='unfinished-resume')rows.splice(rows.indexOf('#64 pushing layers'),6);
 if(defect==='foreign-final-done')rows[rows.indexOf('#64 DONE 3.3s')]='#640 DONE 3.3s';
 if(defect==='error-after-first-done')rows.splice(9,0,'#64 ERROR: failed to push');
 if(defect==='cached-after-first-done')rows.splice(9,0,'#64 CACHED');
 if(defect==='conflicting-root')rows.splice(9,0,'#64 exporting manifest list sha256:'+'f'.repeat(64)+' done');
 if(defect==='conflicting-config')rows.splice(9,0,'#64 exporting config sha256:'+'f'.repeat(64)+' done');
 if(defect==='later-unfinished-progress')rows.push('#64 pushing manifest for registry.example.com/bootstrap:other');
 if(defect==='done-before-export'){rows.splice(rows.indexOf('#64 DONE 3.3s'),1);rows.splice(rows.indexOf('#64 DONE 1.1s'),1);rows.unshift('#64 DONE 0.1s');}
 expect(()=>verifyNonrootControlBuildLog(Buffer.from(rows.join('\n')),image)).toThrow('NonrootControlBuildLog');
});
