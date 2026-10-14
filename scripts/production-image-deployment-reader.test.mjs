import {it,expect} from 'vitest';
import {imageTransitionFixture,imageTransitionServingFixture} from './production-image-transition.fixture.mjs';
import {buildImageTransitionProof,imageTransitionContextBindings} from './lib/production-image-transition-proof.mjs';
import {captureImageDeploymentSource} from './lib/production-image-deployment-reader.mjs';
async function fixture(){
 const f=await imageTransitionFixture(),proof=await buildImageTransitionProof(f.input,f),s=imageTransitionServingFixture(f,proof),b=imageTransitionContextBindings(s.authorizationContext),sha='8'.repeat(40),parents=[b.control.baseRevision,b.control.revision];
 const env={GITHUB_REPOSITORY:b.control.repository,GITHUB_EVENT_NAME:'push',GITHUB_REF:'refs/heads/main',GITHUB_SHA:sha,GITHUB_WORKFLOW_SHA:sha,GITHUB_RUN_ID:'123',GITHUB_RUN_ATTEMPT:'1'},calls=[];
 const api=async path=>{calls.push(path);if(path==='commits/main'||path==='commits/'+sha)return {sha,commit:{tree:{sha:b.control.sourceTree}},parents:parents.map(sha=>({sha}))};if(path.startsWith('pulls/'))return {number:b.control.prNumber,state:'closed',merged:true,head:{sha:b.control.revision,repo:{full_name:b.control.repository}},base:{ref:'main'},merge_commit_sha:sha};return {id:123,run_attempt:1,event:'push',head_sha:sha,head_repository:{full_name:b.control.repository},path:'.github/workflows/infra-ci.yml'};};
 const git=async args=>args[0]==='show'?sha+'\n'+b.control.sourceTree+'\n'+parents.join(' '):'';
 return {env,api,git,context:s.authorizationContext,calls};
}
it('reads exact Git, main, PR and push-attempt facts',async()=>{const f=await fixture(),r=await captureImageDeploymentSource(f,f.env,f.context);expect(r.checkout.clean).toBe(true);expect(r.run.id).toBe(123);expect(f.calls).toHaveLength(4);});
it.each(['event','repository','checkout','attempt'])('rejects mismatched %s before it becomes deployment evidence',async kind=>{const f=await fixture();if(kind==='event')f.env.GITHUB_EVENT_NAME='workflow_dispatch';if(kind==='repository')f.env.GITHUB_REPOSITORY='other/repo';if(kind==='checkout')f.env.GITHUB_SHA='0'.repeat(40);if(kind==='attempt')f.env.GITHUB_RUN_ATTEMPT='0';await expect(captureImageDeploymentSource(f,f.env,f.context)).rejects.toThrow();});
