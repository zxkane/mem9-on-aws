import {it,expect,beforeAll} from 'vitest';
import {inspectFutureAcquisitionConfig,futureAcquisitionScope,futureGrantExpectations} from './lib/ci-smoke-future-config.mjs';
import {nonrootDeploymentWrapperFixture} from './production-nonroot-deployment.fixture.mjs';
import {nonrootHash as hash} from './lib/production-nonroot-contracts.mjs';

import {NONROOT_REMAINING_WORK_LIMITS_HASH_V2,NONROOT_REMAINING_WORK_CAPS_V2} from './lib/production-nonroot-budget-revision.mjs';
let config,scope;
beforeAll(async()=>{
 const f=await nonrootDeploymentWrapperFixture(),d=f.current,c=f.f.deploymentControl;
 scope={kind:'target',jobKey:'deploy-prod',route:'deploy-prod',phase:'preconfigure',checkpoint:'deploy-prod/17'};
 const startup={version:1,kind:'owner-prepaid-startup-config',grantSetId:'1'.repeat(64),grantHash:'2'.repeat(64),ledgerStartHash:'3'.repeat(64),catalogHash:'4'.repeat(64),descriptorHash:hash(d),proofHash:d.transition.proofHash,
  source:{repository:f.d.contract.repository,prNumber:f.d.contract.prNumber,candidateRevision:c.revision,candidateTree:c.tree,baseRevision:c.baseRevision},consumers:[scope],ownerGithubActorId:42,notAfter:Math.min(d.expiresMs,f.f.now+600000)};
 config={version:2,kind:'owner-ci-acquisition-config',startup,target:{kind:'production-data-release',descriptor:d,parameterVersion:f.parameter.Version},account:d.account,region:d.region,
  ownerRoot:{runtimeNonce:d.runtimeNonce,authorizationId:d.authorizationId},storage:{bucket:'example-owned-artifacts',kmsKeyArn:`arn:aws:kms:${d.region}:${d.account}:key/00000000-0000-4000-8000-000000000000`,bucketKeyEnabled:true},bootstrap:[{checkpoint:scope.checkpoint,responseBytes:65536}]};
},60000);
it('binds exact protected descriptor, source and independently supplied bootstrap limits',()=>{
 expect(inspectFutureAcquisitionConfig(config)).toEqual(config);
 const selected=futureAcquisitionScope(config,scope),base=`data-authorizations/${config.ownerRoot.runtimeNonce}/${config.ownerRoot.authorizationId}/ci-grants/${config.startup.grantSetId}`;
 expect(selected.bindingKey).toBe(base+'/run-binding.json');
 expect(selected.responseKey).toBe(base+'/'+hash(scope.checkpoint)+'/response.json');
 expect(selected.requestKey).toBe('decisions/prod/ci-grants/'+config.startup.grantSetId+'/'+hash(scope.checkpoint)+'/request.json');
 expect(selected.responseBytes).toBe(65536);expect(selected.expectedBucketOwner).toBe(config.account);
});
it.each(['descriptor','proof','source','account','owner','kms','missing-cap','extra-cap','oversize','duplicate-cap','extra-field','extended-window'])('rejects mismatched bootstrap configuration: %s',defect=>{
 const c=structuredClone(config);
 if(defect==='descriptor')c.startup.descriptorHash='0'.repeat(64);
 if(defect==='proof')c.startup.proofHash='0'.repeat(64);
 if(defect==='source')c.startup.source.candidateTree='0'.repeat(40);
 if(defect==='account')c.account='0'.repeat(12);
 if(defect==='owner')c.ownerRoot.runtimeNonce='0'.repeat(32);
 if(defect==='kms')c.storage.kmsKeyArn=c.storage.kmsKeyArn.replace(c.account,'0'.repeat(12));
 if(defect==='missing-cap')c.bootstrap=[];
 if(defect==='extra-cap')c.bootstrap.push({checkpoint:'deploy-prod/999',responseBytes:1});
 if(defect==='oversize')c.bootstrap[0].responseBytes=1048577;
 if(defect==='duplicate-cap')c.bootstrap.push(c.bootstrap[0]);
 if(defect==='extra-field')c.allocationUrl='https://example.com/untrusted';
 if(defect==='extended-window')c.startup.notAfter=c.target.descriptor.expiresMs+1;
 expect(()=>inspectFutureAcquisitionConfig(c)).toThrow();
});
it('cannot select a different checkpoint or redefine its phase',()=>{
 expect(()=>futureAcquisitionScope(config,{...scope,checkpoint:'deploy-prod/19'})).toThrow();
 expect(()=>futureAcquisitionScope(config,{...scope,phase:'presst'})).toThrow();
});

it('v3 protected config keeps the independent revision/ceiling alongside the unchanged startup receipt',()=>{
 const c={...structuredClone(config),version:3,budgetRevision:{version:2,limitsHash:NONROOT_REMAINING_WORK_LIMITS_HASH_V2,envelopeHash:hash('envelope'),historyHeadHash:hash('history')},compiledCeiling:{...NONROOT_REMAINING_WORK_CAPS_V2,logicalBytes:20*1024**3}};
 expect(inspectFutureAcquisitionConfig(c)).toEqual(c);const roots=futureGrantExpectations(c);expect(roots.budgetRevision).toEqual(c.budgetRevision);expect(roots.compiledCeiling).toEqual(c.compiledCeiling);expect(roots.grantHash).toBe(c.startup.grantHash);
 for(const key of ['budgetRevision','compiledCeiling']){const missing=structuredClone(c);delete missing[key];expect(()=>inspectFutureAcquisitionConfig(missing)).toThrow();}
 expect(()=>inspectFutureAcquisitionConfig({...c,version:2})).toThrow();
 c.compiledCeiling.httpBodyBytes++;expect(()=>inspectFutureAcquisitionConfig(c)).toThrow();
});
