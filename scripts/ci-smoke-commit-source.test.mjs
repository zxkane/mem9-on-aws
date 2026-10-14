import {it,expect} from 'vitest';
import {ciSmokeEvidenceFixture} from './ci-smoke-evidence.fixture.mjs';
import {verifyCiSmokeSourceResult} from './lib/ci-smoke-isolation.mjs';
import {nonrootHash as hash} from './lib/production-nonroot-contracts.mjs';

function fixture(api='git-database'){
 const f=ciSmokeEvidenceFixture(),r=f.result,head='f'.repeat(40);
 const isolation={candidate:{revision:head,tree:r.sourceTree}};
 r.isolationHash=hash(isolation);f.expected.isolationHash=r.isolationHash;
 const success={status:'completed',conclusion:'success'},common={...success,run_id:r.runId,run_attempt:r.runAttempt,head_sha:head};
 const job=(expected,name)=>({...common,id:expected.id,name,started_at:new Date(expected.startedMs).toISOString(),completed_at:new Date(expected.completedMs).toISOString()});
 const commit={sha:r.sourceRevision,parents:[{sha:'e'.repeat(40)},{sha:head}]},candidateCommit={sha:head};
 for(const value of [commit,candidateCommit]){
  if(api==='rest')value.commit={tree:{sha:r.sourceTree}};
  else value.tree={sha:r.sourceTree};
 }
 const provenance={run:{id:r.runId,run_attempt:r.runAttempt,path:r.workflowPath,head_repository:{full_name:r.repository},head_sha:head,event:'pull_request'},
  buildJob:{...job(f.expected.buildJob,'Build & push workload images'),steps:[{...success,name:'Build & push mnemo-server (arm64)'}]},
  smokeJob:job(f.expected.smokeJob,'Mnemo nonroot smoke'),buildDigest:r.outputDigest,sourceRevision:r.sourceRevision,sourceTree:r.sourceTree,commit,candidateCommit,
  ...(api==='git-database'?{commitSource:{api,sourcePath:'git/commits/'+r.sourceRevision,candidatePath:'git/commits/'+head}}:{})};
 return {...f,isolation,provenance,verify:()=>verifyCiSmokeSourceResult(isolation,r,{...f.options(),provenance})};
}

it.each(['rest','git-database'])('verifies complete smoke evidence with %s commit provenance after JSON replay',async api=>{
 const f=fixture(api),ref=f.json(f.provenance),provenance=f.get(ref);
 await expect(verifyCiSmokeSourceResult(f.isolation,f.result,{...f.options(),provenance})).resolves.toBeDefined();
});
it.each(['missing-family','unknown-family','wrong-route','extra-selector','rest-body','hybrid','wrong-tree','wrong-parent','wrong-head','wrong-attempt','wrong-digest'])('rejects invalid Git Database provenance: %s',async defect=>{
 const f=fixture(),p=f.provenance;
 if(defect==='missing-family')delete p.commitSource;
 if(defect==='unknown-family')p.commitSource.api='automatic';
 if(defect==='wrong-route')p.commitSource.sourcePath='commits/'+p.sourceRevision;
 if(defect==='extra-selector')p.commitSource.allow=true;
 if(defect==='rest-body'){p.commit.commit={tree:p.commit.tree};delete p.commit.tree;}
 if(defect==='hybrid')p.candidateCommit.commit={tree:p.candidateCommit.tree};
 if(defect==='wrong-tree')p.commit.tree.sha='d'.repeat(40);
 if(defect==='wrong-parent')p.commit.parents[1].sha='d'.repeat(40);
 if(defect==='wrong-head')p.candidateCommit.sha='d'.repeat(40);
 if(defect==='wrong-attempt')p.run.run_attempt++;
 if(defect==='wrong-digest')p.buildDigest='sha256:'+'d'.repeat(64);
 await expect(f.verify()).rejects.toThrow();
});
it('continues to enforce the original smoke checks after admitting Git Database metadata',async()=>{
 const f=fixture();f.rewriteCheck('tls-required',value=>{value.payload.tlsEnabled=false;});
 await expect(f.verify()).rejects.toThrow();
});
