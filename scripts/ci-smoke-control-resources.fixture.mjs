// Synthetic ownership setup only. This supplies no deployment authorization.
import {mkdir,writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {nonrootHash as hash} from './lib/production-nonroot-contracts.mjs';
import {sha} from './lib/ci-smoke-acquisition-format.mjs';
import {allocateCiSmokeControlResources,sealControlResources,linkControlResourceCompletion} from './lib/ci-smoke-control-resources.mjs';

export async function controlResourceFixture(root,{rootDigest,configDigest},seams={}){
 const env={RUNNER_TEMP:root,GITHUB_ACTIONS:'true',GITHUB_REPOSITORY:'example/project',GITHUB_RUN_ID:'77',GITHUB_RUN_ATTEMPT:'1',GITHUB_JOB:'deploy-prod',GITHUB_SHA:'a'.repeat(40),MEM9_CI_ACQUISITION_CONFIG:'{"synthetic":true}'};
 const scope={kind:'target',jobKey:'deploy-prod',route:'deploy-prod',phase:'preconfigure',checkpoint:'deploy-prod/19'},binding={source:{repository:env.GITHUB_REPOSITORY,runId:77,runAttempt:1,mainRevision:env.GITHUB_SHA}},bindingHash=hash(binding);
 const sourceReceiptRef={path:join(root,'resource-source.json'),sha256:sha('{}')};await writeFile(sourceReceiptRef.path,'{}',{mode:0o600,flag:'wx'});
 const directory=join(root,'mem9-ci-future-acquisitions');await mkdir(directory,{mode:0o700});
 const claim={version:1,kind:'ci-future-acquisition-claim',scope,binding,sourceReceiptRef,configHash:sha(env.MEM9_CI_ACQUISITION_CONFIG),openedMs:Date.now(),expiresMs:Date.now()+300000,ownerRefund:0};
 const claimRef={path:join(directory,'target-'+hash({bindingHash,scope})+'-claim.json'),sha256:sha(JSON.stringify(claim))};await writeFile(claimRef.path,JSON.stringify(claim),{mode:0o600,flag:'wx'});
 const expected={claimRef,scope,bindingHash,sourceReceiptRef,configHash:claim.configHash,run:{repository:env.GITHUB_REPOSITORY,runId:77,runAttempt:1,jobKey:'deploy-prod',revision:env.GITHUB_SHA},rootDigest,configDigest};
 const allocation=await allocateCiSmokeControlResources({env,expected},seams);
 return {env,expected,allocation,async complete(controlCache){
  const bundle={controlCache},bundleRef={path:join(root,'resource-bundle.json'),sha256:sha(JSON.stringify(bundle))};await writeFile(bundleRef.path,JSON.stringify(bundle),{mode:0o600,flag:'wx'});
  const resourceReceiptRef=await sealControlResources(allocation.handle,{bundleRef});
  const completion={version:2,kind:'ci-future-acquisition-complete',claimRef,bundleRef,resourceReceiptRef,completedMs:Date.now(),ownerRefund:0},completionRef={path:claimRef.path.replace('-claim.json','-complete.json'),sha256:sha(JSON.stringify(completion))};await writeFile(completionRef.path,JSON.stringify(completion),{mode:0o600,flag:'wx'});
  await linkControlResourceCompletion({env,resourceReceiptRef,completionRef});return {bundleRef,resourceReceiptRef,completionRef};
 }};
}
