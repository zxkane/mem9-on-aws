import {it,expect} from 'vitest';
import {imageTransitionFixture,imageTransitionServingFixture} from './production-image-transition.fixture.mjs';
import {buildImageTransitionProof,imageTransitionContextBindings} from './lib/production-image-transition-proof.mjs';
import {verifyImageDeploymentSource} from './lib/production-image-deployment.mjs';
import {canaryEvidenceHash as hash} from './lib/production-canary-verification.mjs';
async function fixture(){
 const f=await imageTransitionFixture(),built=await buildImageTransitionProof(f.input,f),s=imageTransitionServingFixture(f,built),b=imageTransitionContextBindings(s.authorizationContext),sha='8'.repeat(40);
 const parameter={Name:'/mem9-on-aws/prod/consolidation-runtime/data-release',Type:'SecureString',Version:2,ARN:`arn:aws:ssm:${s.data.region}:${s.data.account}:parameter/mem9-on-aws/prod/consolidation-runtime/data-release`,Value:JSON.stringify(s.data)};
 const source={repository:b.control.repository,event:'push',ref:'refs/heads/main',checkout:{sha,tree:b.control.sourceTree,parents:[b.control.baseRevision,b.control.revision],clean:true},main:{sha,tree:b.control.sourceTree},
  run:{id:123,attempt:1,event:'push',headSha:sha,repository:b.control.repository,path:'.github/workflows/infra-ci.yml',workflowSha:sha},
  pullRequest:{number:b.control.prNumber,state:'closed',merged:true,headSha:b.control.revision,headRepository:b.control.repository,baseRef:'main',mergeCommitSha:sha}};
 const operation={version:1,kind:'image-security-transition',operation:{owner:s.data.authorizationId},authorization:{data:s.data,hash:hash(s.data),review:s.review},expected:{transitionProofHash:built.proofHash},predecessor:{Type:'SecureString',Version:1,Value:f.input.predecessorText}};
 return {f,b,s,parameter,source,operation,imageTransition:s.authorizationContext};
}
it('binds a real merge identity to the reviewed control tree, not the data-build revision',async()=>{
 const x=await fixture(),r=verifyImageDeploymentSource(x,{now:x.f.now});expect(r.actualMainRevision).toBe('8'.repeat(40));expect(r.reviewedControlTree).toBe(x.b.control.sourceTree);expect(r.actualMainRevision).not.toBe(x.b.dataOrigin.revision);
 x.source.checkout.parents=[x.b.control.baseRevision];expect(verifyImageDeploymentSource(x,{now:x.f.now}).actualMainTree).toBe(x.b.control.sourceTree);
});
it.each([1,3,99])('rejects same-byte protected version %i outside the archived successor',async version=>{
 const x=await fixture();x.parameter.Version=version;expect(()=>verifyImageDeploymentSource(x,{now:x.f.now})).toThrow('ImageDeploymentSourceInvalid');
});
it.each(['tree','dirty','main','event','workflow','parent','pr','hash','unbound'])('rejects %s before any deployment writes',async kind=>{
 const x=await fixture();if(kind==='tree')x.source.checkout.tree='a'.repeat(40);if(kind==='dirty')x.source.checkout.clean=false;if(kind==='main')x.source.main.sha='a'.repeat(40);
 if(kind==='event')x.source.event='workflow_dispatch';if(kind==='workflow')x.source.run.workflowSha='a'.repeat(40);if(kind==='parent')x.source.checkout.parents=['a'.repeat(40)];
 if(kind==='pr')x.source.pullRequest.headSha='a'.repeat(40);if(kind==='hash'){const d=JSON.parse(x.parameter.Value);d.transition.proofHash='a'.repeat(64);x.parameter.Value=JSON.stringify(d);}
 if(kind==='unbound')x.imageTransition={...x.imageTransition};expect(()=>verifyImageDeploymentSource(x,{now:x.f.now})).toThrow();
});
