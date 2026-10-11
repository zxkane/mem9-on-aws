import {it,expect} from 'vitest';
import {extractMnemoBuildDigest,captureCiSmokeGithub} from './lib/ci-smoke-github.mjs';
const revision='a'.repeat(40),head='b'.repeat(40),tree='c'.repeat(40),digest='sha256:'+'d'.repeat(64);
const log=`#12 pushing manifest for example.com/mem9-on-aws/preview/mnemo-server:pr-${revision.slice(0,7)}@${digest} 0.1s done\n`;
function fixture(){
 const success={status:'completed',conclusion:'success'},run={id:1,run_attempt:1,path:'.github/workflows/infra-ci.yml',event:'pull_request',head_sha:head,head_repository:{full_name:'example/project'}};
 const common={...success,run_id:1,run_attempt:1,head_sha:head};
 const build={...common,id:2,name:'Build & push workload images',steps:[{...success,name:'Build & push mnemo-server (arm64)'}]};
 const smoke={...common,id:3,name:'Mnemo nonroot smoke',steps:[{...success,name:'Verify and preserve private smoke evidence'},{...success,name:'Remove owned smoke evidence'}]};
 const commit={sha:revision,commit:{tree:{sha:tree}},parents:[{sha:'e'.repeat(40)},{sha:head}]},jobs={total_count:2,jobs:[build,smoke]},calls=[];
 const api=async path=>{calls.push(path);if(path==='commits/'+head)return {sha:head,commit:{tree:{sha:tree}}};if(path.startsWith('commits/'))return commit;return path.includes('/jobs?')?jobs:run;};
 return {run,build,smoke,commit,jobs,calls,io:{api,readLog:async id=>{expect(id).toBe(2);return log;}},input:{repository:'example/project',runId:1,runAttempt:1,sourceRevision:revision}};
}
it('binds the actual PR merge source separately from the run and job head',async()=>{
 const f=fixture(),value=await captureCiSmokeGithub(f.io,f.input);expect(value.sourceRevision).toBe(revision);expect(value.run.head_sha).toBe(head);expect(value.sourceTree).toBe(tree);expect(value.buildDigest).toBe(digest);
});
it.each(['wrong-head','wrong-parent','wrong-tree-source','wrong-attempt','duplicate-job','missing-page','failed-publish','skipped-cleanup','in-progress-smoke'])('rejects %s before consuming evidence',async defect=>{
 const f=fixture();
 if(defect==='wrong-head')f.build.head_sha='f'.repeat(40);
 if(defect==='wrong-parent')f.commit.parents[1].sha='f'.repeat(40);
 if(defect==='wrong-tree-source')f.commit.sha='f'.repeat(40);
 if(defect==='wrong-attempt')f.smoke.run_attempt=2;
 if(defect==='duplicate-job'){f.jobs.jobs.push({...f.smoke});f.jobs.total_count++;}
 if(defect==='missing-page')f.jobs.total_count++;
 if(defect==='failed-publish')f.smoke.steps[0].conclusion='failure';
 if(defect==='skipped-cleanup')f.smoke.steps[1].conclusion='skipped';
 if(defect==='in-progress-smoke')f.smoke.status='in_progress';
 await expect(captureCiSmokeGithub(f.io,f.input)).rejects.toThrow();
});
it('allows the current producer only in explicit prepare mode',async()=>{
 const f=fixture();f.smoke.status='in_progress';f.smoke.conclusion=null;f.smoke.steps=[];
 expect((await captureCiSmokeGithub(f.io,{...f.input,purpose:'prepare'})).smokeJob.id).toBe(3);
 await expect(captureCiSmokeGithub(f.io,f.input)).rejects.toThrow('CiSmokeGithubSmokeFailed');
});
it('requires one exact successful published digest and rejects a mutable-tag substitute',()=>{
 expect(extractMnemoBuildDigest(log,{event:'pull_request',revision})).toBe(digest);
 for(const value of [log.replace(' done',''),log.replace('pr-aaaaaaa','latest'),log.replace(digest,'sha256:invalid'),log+log.replace(digest,'sha256:'+'e'.repeat(64))])expect(()=>extractMnemoBuildDigest(value,{event:'pull_request',revision})).toThrow();
});

function gitDatabaseFixture(){
 const f=fixture(),restApi=f.io.api;
 f.commit.tree=f.commit.commit.tree;delete f.commit.commit;
 f.candidateCommit={sha:head,tree:{sha:tree}};
 f.io.api=async path=>{
  if(path.startsWith('commits/'))throw Error('Unexpected REST commit request');
  if(path.startsWith('git/commits/')){
   f.calls.push(path);
   if(path==='git/commits/'+revision)return f.commit;
   if(path==='git/commits/'+head)return f.candidateCommit;
   throw Error('Unexpected Git Database commit request');
  }
  return restApi(path);
 };
 f.input.commitApi='git-database';return f;
}
it('retains Git Database records and their explicit request paths without a REST wrapper',async()=>{
 const f=gitDatabaseFixture(),before=JSON.stringify([f.commit,f.candidateCommit]),value=await captureCiSmokeGithub(f.io,f.input);
 expect(value.commit).toBe(f.commit);expect(value.candidateCommit).toBe(f.candidateCommit);
 expect(JSON.stringify([value.commit,value.candidateCommit])).toBe(before);
 expect(value.commitSource).toEqual({api:'git-database',sourcePath:'git/commits/'+revision,candidatePath:'git/commits/'+head});
 expect(f.calls).toEqual(['actions/runs/1/attempts/1','actions/runs/1/attempts/1/jobs?per_page=100','git/commits/'+revision,'git/commits/'+head]);
 expect(value.buildDigest).toBe(digest);
});
it('rejects unknown commit APIs before making a request and keeps default REST output unchanged',async()=>{
 const f=fixture();await expect(captureCiSmokeGithub(f.io,{...f.input,commitApi:'automatic'})).rejects.toThrow();expect(f.calls).toEqual([]);
 const value=await captureCiSmokeGithub(f.io,f.input);expect(value).not.toHaveProperty('commitSource');
});
it.each(['rest-body','hybrid-source','hybrid-candidate','wrong-parent','wrong-candidate-tree'])('rejects Git Database %s',async defect=>{
 const f=gitDatabaseFixture();
 if(defect==='rest-body'){f.commit.commit={tree:f.commit.tree};delete f.commit.tree;}
 if(defect==='hybrid-source')f.commit.commit={tree:f.commit.tree};
 if(defect==='hybrid-candidate')f.candidateCommit.commit={tree:f.candidateCommit.tree};
 if(defect==='wrong-parent')f.commit.parents[1].sha='f'.repeat(40);
 if(defect==='wrong-candidate-tree')f.candidateCommit.tree.sha='f'.repeat(40);
 await expect(captureCiSmokeGithub(f.io,f.input)).rejects.toThrow();
});
