import {beforeAll,it,expect} from 'vitest';
import {nonrootDeploymentWrapperFixture} from './production-nonroot-deployment.fixture.mjs';
import {nonrootBundleRecords} from './production-nonroot-bundle.fixture.mjs';
import {authenticateNonrootArchive} from './lib/production-nonroot-archive.mjs';
import {nonrootHash as hash} from './lib/production-nonroot-contracts.mjs';
import {verifyNonrootImageTransitionProof,nonrootProofExpected,bindNonrootTransitionAuthorization,getNonrootWorkerRegistration,getNonrootTargetRegistration} from './lib/production-nonroot-proof.mjs';
import {loadWorkerDataRelease} from './lib/production-data-release-loader.mjs';
let f,records,archive,context;
beforeAll(async()=>{
 f=await nonrootDeploymentWrapperFixture();records=await nonrootBundleRecords(f);
 archive=await authenticateNonrootArchive(records.proofArchive,{parameter:f.parameter,operation:records.operation},{expectedProofHash:f.built.proofHash,expectedDataHash:hash(f.current),expectedReviewHash:hash(f.review),expectedParameterVersion:f.parameter.Version,expectedScope:{account:f.current.account,region:f.current.region,runtimeNonce:f.current.runtimeNonce,authorizationId:f.current.authorizationId}});
 context=bindNonrootTransitionAuthorization(await verifyNonrootImageTransitionProof(f.built.proof,{proofHash:f.built.proofHash,expected:nonrootProofExpected(f.built.proof,{proofHash:f.built.proofHash}),evidence:{archive},now:f.f.now}),{review:f.review,now:f.f.now});
});
function target(){
 const data=f.current,revision=f.d.main.mainRevision;
 return {meta:{version:3,stage:'prod',account:data.account,region:data.region,generation:data.generation,sourceTag:data.dataSourceTag,controlSourceTag:'mem9-'+revision.slice(0,7),workerImage:`${data.account}.dkr.ecr.${data.region}.amazonaws.com/mem9-on-aws/llm-proxy@${data.images['llm-proxy'].rootDigest}`,dataReleaseParameter:f.parameter.Name,dataReleaseHash:hash(data),dataReleaseParameterVersion:f.parameter.Version},options:{controlRevision:revision,controlSourceTree:data.controlSourceTree,mode:'admission',imageTransition:context,now:f.f.now}};
}
it('restores published DATA-worker authority without creating a CONTROL or deployment capability',async()=>{
 for(const key of ['planner','executor'])expect(getNonrootWorkerRegistration(context,key,{now:f.f.now})).toEqual(f.f.target[key]);
 expect(()=>getNonrootTargetRegistration(context,'control')).toThrow();expect(()=>getNonrootTargetRegistration(context,'backend')).toThrow();
 const {meta,options}=target();let reads=0;
 const clients={ssm:{send:async command=>{reads++;expect(command.input).toEqual({Names:[f.parameter.Name],WithDecryption:true});return {Parameters:[f.parameter],InvalidParameters:[]};}}};
 const result=await loadWorkerDataRelease(clients,meta,options);expect(result.hash).toBe(hash(f.current));expect(result.parameterVersion).toBe(f.parameter.Version);expect(reads).toBe(1);
});
it.each(['control','backend','bootstrap','promotion','provision','transition','fallback','preaudit'])('does not expose %s through the worker-only lookup',key=>{
 expect(()=>getNonrootWorkerRegistration(context,key,{now:f.f.now})).toThrow('NonrootWorkerRequired');
});
it('rejects copied handles, unpublished authorization and expired authorization',()=>{
 expect(()=>getNonrootWorkerRegistration(structuredClone(context),'executor',{now:f.f.now})).toThrow();
 expect(()=>getNonrootWorkerRegistration(f.authorization,'executor',{now:f.f.now})).toThrow('NonrootPublishedAuthorizationRequired');
 expect(()=>getNonrootWorkerRegistration(context,'executor',{now:f.review.expiresMs})).toThrow();
});
it('inspection restoration cannot become admission',async()=>{
 const inspected=bindNonrootTransitionAuthorization(await verifyNonrootImageTransitionProof(f.built.proof,{proofHash:f.built.proofHash,expected:nonrootProofExpected(f.built.proof,{proofHash:f.built.proofHash}),evidence:{archive},now:f.f.now,mode:'inspection'}),{review:f.review,now:f.f.now,mode:'inspection'});
 expect(()=>getNonrootWorkerRegistration(inspected,'executor',{now:f.f.now})).toThrow();
});
it.each(['version','descriptor','main-head','expired'])('retains live %s rejection in the worker loader',async defect=>{
 const {meta,options}=target(),parameter=structuredClone(f.parameter);
 if(defect==='version')parameter.Version++;if(defect==='descriptor')meta.dataReleaseHash='0'.repeat(64);if(defect==='main-head')options.controlRevision=f.f.deploymentControl.revision;if(defect==='expired')options.now=f.current.expiresMs;
 await expect(loadWorkerDataRelease({ssm:{send:async()=>({Parameters:[parameter],InvalidParameters:[]})}},meta,options)).rejects.toThrow();
});
