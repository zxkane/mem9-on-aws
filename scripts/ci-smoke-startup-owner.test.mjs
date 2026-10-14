import {it,expect} from 'vitest';
import {captureCiOwnerRunBinding,finalizeCiStartupConfig} from './lib/ci-smoke-startup-owner.mjs';
import {nonrootDeploymentWrapperFixture} from './production-nonroot-deployment.fixture.mjs';

function fixture(defect){
 const h=n=>n.repeat(64),g=n=>n.repeat(40),repository='example/project',calls=[];
 const config={version:1,kind:'owner-prepaid-startup-config',grantSetId:h('1'),grantHash:h('2'),ledgerStartHash:h('3'),catalogHash:h('4'),descriptorHash:h('5'),proofHash:h('6'),
  source:{repository,prNumber:7,candidateRevision:g('a'),candidateTree:g('b'),baseRevision:g('c')},
  consumers:[{kind:'target',jobKey:'deploy-prod',route:'deploy-prod',phase:'preconfigure',checkpoint:'deploy-prod/17'}],ownerGithubActorId:11,notAfter:Date.now()+600000};
 const run={id:12,run_attempt:1,event:'push',head_branch:'main',head_sha:g('d'),path:'.github/workflows/infra-ci.yml',status:'in_progress',repository:{full_name:repository},head_repository:{full_name:repository}};
 const commit={sha:g('d'),tree:{sha:g('b')},parents:[{sha:g('c')},{sha:g('a')}]};
 const pullRequest={number:7,state:'closed',merged:true,head:{sha:g('a'),repo:{full_name:repository}},base:{ref:'main'},merge_commit_sha:g('d')};
 const mainRef={ref:'refs/heads/main',object:{type:'commit',sha:g('d')}};
 if(defect==='wrong-run')run.id++;
 if(defect==='completed')run.status='completed';
 if(defect==='wrong-tree')commit.tree.sha=g('e');
 if(defect==='unmerged')pullRequest.merged=false;
 if(defect==='wrong-base')commit.parents[0].sha=g('e');
 if(defect==='squash')commit.parents=commit.parents.slice(0,1);
 let mainReads=0;
 const api=async path=>{
  calls.push(path);
  if(path==='actions/runs/12/attempts/1')return structuredClone(run);
  if(path==='git/commits/'+g('d'))return structuredClone(commit);
  if(path==='pulls/7')return structuredClone(pullRequest);
  if(path==='git/ref/heads/main'){mainReads++;const value=structuredClone(mainRef);if(defect==='main-moved'&&mainReads>1)value.object.sha=g('e');return value;}
  throw Error('UnexpectedGithubRead');
 };
 return {config,api,calls};
}
it.each([undefined,'squash'])('collects actual GitHub run/commit/PR/ref facts without manufacturing a runner checkout (%s)',async kind=>{
 const f=fixture(kind),value=await captureCiOwnerRunBinding({config:f.config,runId:12,runAttempt:1},{api:f.api});
 expect(value.binding.source.runId).toBe(12);expect(value.binding.source.parents).toHaveLength(kind==='squash'?1:2);
 expect(value.observations).not.toHaveProperty('checkout');expect(JSON.stringify(value)).not.toContain('"clean"');
 expect(f.calls).toHaveLength(5);
});
it.each(['wrong-run','completed','wrong-tree','unmerged','wrong-base','main-moved'])('holds invalid owner run observations: %s',async kind=>{
 const f=fixture(kind);await expect(captureCiOwnerRunBinding({config:f.config,runId:12,runAttempt:1},{api:f.api})).rejects.toThrow();
});
it('rejects an expired grant before making a GitHub request',async()=>{
 const f=fixture();f.config.notAfter=Date.now()-1;
 await expect(captureCiOwnerRunBinding({config:f.config,runId:12,runAttempt:1},{api:f.api})).rejects.toThrow();expect(f.calls).toHaveLength(0);
});
it('cannot finalize a funded startup from JSON posing as an authorization handle',()=>{
 expect(()=>finalizeCiStartupConfig({context:{kind:'nonroot-authorization-context',fundingPlanHashes:['a'.repeat(64)]},grantSet:{},expected:{},descriptor:{},parameter:{},proof:{}})).toThrow('NonrootProofContextRequired');
});
it('requires the real proof to authenticate a prepaid plan, including for an otherwise valid authorization',async()=>{
 const f=await nonrootDeploymentWrapperFixture();
 expect(()=>finalizeCiStartupConfig({context:f.authorization,grantSet:{},expected:{},descriptor:f.current,parameter:f.parameter,proof:f.f.input},{now:f.f.now})).toThrow('CiOwnerFundingNotInProof');
},60000);
