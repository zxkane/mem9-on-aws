import {describe,it,expect} from 'vitest';
import {evidenceFixture} from './production-nonroot-runtime.fixture.mjs';
import {verifyNonrootActualMain,verifyNonrootDeployedControlBuild,verifyNonrootDeploymentSource,verifyNonrootControlSource} from './lib/production-nonroot-provenance.mjs';
import {verifyNonrootControlArtifactFiles} from './lib/production-nonroot-artifact.mjs';
import {nonrootDeploymentFixture} from './production-nonroot-provenance.fixture.mjs';
import {nonrootHash as hash} from './lib/production-nonroot-contracts.mjs';

function fixture(squash=false){
  const archive=evidenceFixture(),expected={repository:'example/control-plane',candidateRevision:'a'.repeat(40),candidateTree:'b'.repeat(40),baseRevision:'c'.repeat(40),prNumber:7};
  const main={version:1,kind:'actual-hardening-main',...expected,mainRevision:'d'.repeat(40),mainTree:expected.candidateTree,parents:squash?[expected.baseRevision]:[expected.baseRevision,expected.candidateRevision],workflowRun:100,workflowAttempt:1,workflowPath:'.github/workflows/infra-ci.yml',workflowSha:'d'.repeat(40)};
  const source={repository:main.repository,event:'push',ref:'refs/heads/main',checkout:{sha:main.mainRevision,tree:main.mainTree,parents:main.parents,clean:true},main:{sha:main.mainRevision,tree:main.mainTree},run:{id:main.workflowRun,attempt:main.workflowAttempt,event:'push',headSha:main.mainRevision,repository:main.repository,path:main.workflowPath,workflowSha:main.workflowSha},pullRequest:{number:main.prNumber,state:'closed',merged:true,headSha:main.candidateRevision,headRepository:main.repository,baseRef:'main',mergeCommitSha:main.mainRevision}};
  main.authenticatedSource=archive.json(source);return {...archive,expected,main,source};
}
describe('actual-main provenance',()=>{
  for(const squash of [false,true])it('accepts an authenticated tree-identical '+(squash?'squash':'merge')+' relation',async()=>{
    const f=fixture(squash),r=await verifyNonrootActualMain(f.main,f);expect(r.mainRevision).toBe(f.main.mainRevision);expect(r).not.toHaveProperty('authorized');
  });
  for(const field of ['repository','candidateRevision','candidateTree','baseRevision','prNumber'])it('rejects changed expected '+field,async()=>{
    const f=fixture();f.expected[field]=field==='prNumber'?8:'f'.repeat(40);await expect(verifyNonrootActualMain(f.main,f)).rejects.toThrow();
  });
  for(const defect of ['dirty','wrong-tree','extra-parent','rebase-parent','unmerged','wrong-pr','wrong-job-run','wrong-workflow-sha','wrong-event','wrong-ref','wrong-repository','wrong-merge-commit','extra-field','missing-evidence'])it('rejects '+defect+' despite self-consistent reference hashes',async()=>{
    const f=fixture();
    if(defect==='dirty')f.source.checkout.clean=false;if(defect==='wrong-tree')f.source.checkout.tree='e'.repeat(40);
    if(defect==='extra-parent')f.source.checkout.parents=[...f.main.parents,'e'.repeat(40)];if(defect==='rebase-parent')f.source.checkout.parents=['e'.repeat(40)];
    if(defect==='unmerged')f.source.pullRequest.merged=false;if(defect==='wrong-pr')f.source.pullRequest.number++;
    if(defect==='wrong-job-run')f.source.run.id++;if(defect==='wrong-workflow-sha')f.source.run.workflowSha='e'.repeat(40);
    if(defect==='wrong-event')f.source.run.event='workflow_dispatch';if(defect==='wrong-ref')f.source.ref='refs/heads/other';
    if(defect==='wrong-repository')f.source.run.repository='example/other';if(defect==='wrong-merge-commit')f.source.pullRequest.mergeCommitSha='e'.repeat(40);
    if(defect==='extra-field')f.source.approved=true;
    f.main.authenticatedSource=f.json(f.source);if(defect==='missing-evidence')f.records.clear();
    await expect(verifyNonrootActualMain(f.main,f)).rejects.toThrow();
  });
});

describe('deployed CONTROL build and resolved task-plan provenance',()=>{
 it('uses real CONTROL bytes and Git membership and requires actual runtime path observation',async()=>{
  const f=await nonrootDeploymentFixture(),options=f.options();
  expect(f.checkoutFingerprint).toEqual({tree:f.contract.candidate.tree,copyClosureHash:hash(f.contract.recipe.context),dockerfileHash:f.contract.recipe.dockerfile.sha256,ignoreHash:f.a.value(f.contract.recipe.ignoreFiles).find(file=>file.path==='docker/bootstrap/Dockerfile.dockerignore').sha256});
  await expect(verifyNonrootControlSource(f.contract,options)).resolves.toMatchObject({tree:f.contract.candidate.tree});
  await expect(verifyNonrootControlArtifactFiles(f.build,options)).resolves.toMatchObject({unknownRuntimePaths:['/']});
  await expect(verifyNonrootDeployedControlBuild(f.build,options)).rejects.toThrow('NonrootRuntimeObservationRequired');
 });
 it('does not expose registration bindings from graph/FS/Git evidence without a completed runtime observer',async()=>{
  const f=await nonrootDeploymentFixture();
  await expect(verifyNonrootDeployedControlBuild(f.build,f.options())).rejects.toThrow('NonrootRuntimeObservationRequired');
  await expect(verifyNonrootDeploymentSource(f.record,f.options())).rejects.toThrow('NonrootRuntimeObservationRequired');
 });
 for(const defect of ['foreign-job','foreign-run','wrong-source','wrong-image','carrier-repository','wrong-contract','wrong-recipe','wrong-action','wrong-tag','wrong-node','missing-launch','wrong-guard','wrong-scan','missing-blob'])it('rejects CONTROL '+defect,async()=>{
  const f=await nonrootDeploymentFixture(),b=structuredClone(f.build);
  if(defect==='foreign-job'){const job={...f.rawJob,id:f.rawJob.id+1};b.workflow.authenticatedJob=f.json(job);}
  if(defect==='foreign-run')b.workflow.authenticatedRun=f.json({...f.rawRun,run_attempt:2});
  if(defect==='wrong-source')b.source.revision='e'.repeat(40);if(defect==='wrong-image')b.image.configDigest='sha256:'+'e'.repeat(64);if(defect==='carrier-repository')b.image.repositoryName='mem9-on-aws/preview/bootstrap';
  if(defect==='wrong-contract')b.contractHash='e'.repeat(64);if(defect==='wrong-recipe')b.recipe.invocation.noCacheFilters=[];
  if(defect==='wrong-action')b.actualInvocation=f.json({...f.actualInvocation,buildActionSha:'e'.repeat(40)});
  if(defect==='wrong-tag')b.actualInvocation=f.json({...f.actualInvocation,tags:['example.com/foreign:latest']});
  if(defect==='wrong-node')b.guardImports.nodeRuntime.executableSha256='e'.repeat(64);if(defect==='missing-launch')b.resolvedLaunches.pop();
  if(defect==='wrong-guard')b.guardSource.files[0].sha256='e'.repeat(64);if(defect==='wrong-scan')b.scan.policyHash='e'.repeat(64);
  if(defect==='missing-blob'){const row=f.a.files.find(row=>row.ref.sha256===b.buildLog.sha256);f.a.objects.delete(row.name);}
  await expect(verifyNonrootDeployedControlBuild(b,f.options())).rejects.toThrow();
 });
 for(const defect of ['missing-update','duplicate-update','fallback-update','preaudit-update','wrong-plan','wrong-build','wrong-control-launches','changed-data','changed-role','extra-field','unknown-slot','wrong-slot-owner','wrong-version','wrong-descriptor'])it('rejects resolved task '+defect,async()=>{
  const f=await nonrootDeploymentFixture(),r=structuredClone(f.record),p=structuredClone(f.resolved),options=f.options();
  if(defect==='missing-update')p.tasks.pop();if(defect==='duplicate-update')p.tasks[1]=p.tasks[0];if(defect==='fallback-update')p.tasks[0].taskKey='fallback';if(defect==='preaudit-update')p.tasks[0].taskKey='preaudit';
  if(defect==='wrong-plan')p.taskPlanHash='e'.repeat(64);if(defect==='wrong-build')p.deployedControlBuildHash='e'.repeat(64);if(defect==='wrong-control-launches')p.controlLaunches=[];
  if(['changed-data','changed-role','extra-field'].includes(defect)){
   const key=defect==='changed-data'?'planner':'control',body=structuredClone(key==='control'?f.controlBodies.get(key):f.preBodies.get(key));
   if(defect==='changed-data')body.cpu='1024';if(defect==='changed-role')body.taskRoleArn=body.executionRoleArn;if(defect==='extra-field')body.unreviewed=true;
   p.tasks.find(t=>t.taskKey===key).registrationBody=f.json(body,'task-definition');
  }
  if(['unknown-slot','wrong-slot-owner'].includes(defect)){
   const body=structuredClone(f.preBodies.get('control'));body.containerDefinitions[0].image=defect==='unknown-slot'?'ANY_FUTURE_IMAGE':{version:1,kind:'deployed-control-image',buildContractKey:'other'};
   options.expected.taskPlan=structuredClone(options.expected.taskPlan);options.expected.taskPlan.tasks.find(t=>t.taskKey==='control').targetRegistration=f.json(body,'task-definition');p.taskPlanHash=hash(options.expected.taskPlan);
  }
  if(defect==='wrong-version')r.parameterVersion=3;if(defect==='wrong-descriptor')r.descriptorHash='e'.repeat(64);
  r.resolvedTaskPlan=f.json(p);const resolvers=f.options();options.resolveJson=resolvers.resolveJson;options.resolveBytes=resolvers.resolveBytes;
  await expect(verifyNonrootDeploymentSource(r,options)).rejects.toThrow();
 });
 for(const defect of ['generic-review','wrong-review-image','wrong-review-source','expired-review','generic-guard-tests','denied-application-ran','wrong-test-contract','missing-build-log','cached-export','split-export-steps'])it('rejects incomplete CONTROL material evidence '+defect,async()=>{
  const f=await nonrootDeploymentFixture(),b=structuredClone(f.build);
  if(defect.includes('review')){
   const review=structuredClone(f.a.value(b.scan.artifactReview));
   if(defect==='generic-review'){b.scan.artifactReview=f.json({result:'pass'});}
   else{if(defect==='wrong-review-image')review.image.rootDigest='sha256:'+'e'.repeat(64);if(defect==='wrong-review-source')review.sourceTree='e'.repeat(40);if(defect==='expired-review')review.expiresMs=f.now;b.scan.artifactReview=f.json(review);}
  }else if(['generic-guard-tests','denied-application-ran','wrong-test-contract'].includes(defect)){
   const tests=structuredClone(f.a.value(b.guardTests));
   if(defect==='generic-guard-tests')b.guardTests=f.json({result:'pass'});
   else{if(defect==='denied-application-ran')tests.launches.find(l=>l.taskKey==='provision').applicationReached=true;if(defect==='wrong-test-contract')tests.testContractHash='e'.repeat(64);b.guardTests=f.json(tests);}
  }else{
   const row=f.a.files.find(r=>r.ref.sha256===b.buildLog.sha256);let text=f.a.objects.get(row.name).toString();
   if(defect==='missing-build-log')text='';if(defect==='cached-export')text=text.replace('DONE','CACHED');if(defect==='split-export-steps')text=text.replace('#9 exporting config','#8 exporting config');b.buildLog=f.bytes(text,'build');
  }
  await expect(verifyNonrootDeployedControlBuild(b,f.options())).rejects.toThrow();
 });
 for(const defect of ['node-bytes','primitive-bytes','invented-git-file','omitted-copy-member'])it('rejects consistently rehashed '+defect+' against independently verified image/source bytes',async()=>{
  const f=await nonrootDeploymentFixture(),b=structuredClone(f.build),contract=structuredClone(f.contract);
  if(defect==='node-bytes'){
   b.guardImports.nodeRuntime.executableSha256='e'.repeat(64);
   b.guardImports.nodeRuntime.inventory=f.json({image:b.guardImports.nodeRuntime.image,executablePath:'/usr/local/bin/node',executableSha256:'e'.repeat(64)});
   for(const l of b.resolvedLaunches)l.guardImports=b.guardImports;
  }
  if(defect==='primitive-bytes'){
   const l=b.resolvedLaunches[0],primitive=structuredClone(f.a.value(l.primitiveEvidence));primitive.fileSha256='e'.repeat(64);l.primitiveEvidence=f.json(primitive);
  }
  if(defect==='invented-git-file'){
   const blob=f.bytes('export const unreviewed=true;');
   const files=[{path:'scripts/not-in-the-authenticated-tree.mjs',gitMode:'100644',sha256:blob.sha256,bytes:blob.bytesLength,blob}];
   contract.recipe.preparation={version:1,kind:'git-file-closure',tree:contract.candidate.tree,files,closureHash:hash(files)};
  }
  if(defect==='omitted-copy-member')contract.recipe.context={version:1,kind:'git-file-closure',tree:contract.candidate.tree,files:[],closureHash:hash([])};
  b.recipe=contract.recipe;b.contractHash=hash(contract);for(const l of b.resolvedLaunches)l.contractHash=b.contractHash;
  const tests=structuredClone(f.a.value(b.guardTests));tests.contractHash=b.contractHash;
  for(const row of tests.launches)row.launchHash=hash(b.resolvedLaunches.find(l=>l.taskKey===row.taskKey));b.guardTests=f.json(tests);
  const options=f.options();options.expected.contract=contract;
  const reason=['node-bytes','primitive-bytes'].includes(defect)?'NonrootControlFileHash':defect==='invented-git-file'?'NonrootProvenanceBinding':'ControlSourceUnverified';
  await expect(verifyNonrootDeployedControlBuild(b,options)).rejects.toThrow(reason);
 });
});
