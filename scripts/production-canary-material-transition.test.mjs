import {describe,it,expect} from 'vitest';
import {transitionFixture,sha,semantic} from './production-canary-transition.fixture.mjs';
import {buildCanaryMaterialTransition,verifyCanaryMaterialTransition,verifyCanaryTransitionObservation,buildCanaryCompatibilityV3} from './lib/production-canary-material-transition.mjs';
import {buildCanaryCompatibility} from './lib/production-canary-producer.mjs';
import {canaryEvidenceHash as hash} from './lib/production-canary-verification.mjs';
import {inspectCanaryCompatibility,validateCanaryCompatibility} from './lib/production-canary-compatibility.mjs';

describe('authenticated, exact material transition',()=>{
 it('keeps raw self hashes and V1/V2 strict while V3 carries truthful authority hashes',()=>{
  const f=transitionFixture(),before=JSON.stringify(f.previous),after=JSON.stringify(f.current);
  expect(()=>buildCanaryCompatibility(f.previous,f.current,f.parent,{now:f.now})).toThrow();
  const built=buildCanaryMaterialTransition(f.input(),{expectedBootstrap:f.expectedBootstrap}),context=verifyCanaryMaterialTransition(built.proof,{proofHash:built.proofHash,expectedBootstrap:f.expectedBootstrap});
  const certificate=buildCanaryCompatibilityV3(f.previous,f.current,f.parent,{transition:context,selection:f.selection(),now:f.now});
  expect(certificate.version).toBe(3);expect(certificate.material.authority).toEqual({previous:f.previous.material.authority,current:f.current.material.authority});expect(certificate.material.authority.previous).not.toBe(certificate.material.authority.current);
  expect(certificate.transition.proofHash).toBe(built.proofHash);expect(Buffer.byteLength(JSON.stringify(certificate))).toBeLessThanOrEqual(6000);
  expect(JSON.stringify(f.previous)).toBe(before);expect(JSON.stringify(f.current)).toBe(after);expect(built.proof.anchors.previousSnapshotHash).toBe(sha(before));
 });
 it.each(['raw-hash','unknown-execution','cpu','credentials','role-id','trust','allow','deny-removed','resource-exception','new-deny','fake-chain','template','bootstrap-pin'])('rejects %s even when untrusted material is internally rehashed',kind=>{
  const f=transitionFixture();
  if(kind==='raw-hash')f.current.material.backend='0'.repeat(64);
  if(kind==='unknown-execution')f.current.definitions.backend.unknownExecutionSetting=true;
  if(kind==='cpu')f.current.definitions.backend.cpu='1024';
  if(kind==='credentials')f.current.definitions.executor.containerDefinitions[0].secrets=[{name:'DB',valueFrom:'arn:aws:ssm:ap-northeast-1:123456789012:parameter/mem9-on-aws/prod/fixture'}];
  if(kind==='role-id')f.current.authority[0].roleId='ChangedRole';
  if(kind==='trust')f.current.authority[0].trust.Statement.push({Effect:'Allow',Action:'sts:AssumeRole',Principal:{AWS:'*'}});
  for(const role of f.current.authority){const s=role.boundary.document.Statement;if(kind==='allow')s.push({Effect:'Allow',Action:'iam:*',Resource:'*'});if(kind==='deny-removed')s.splice(s.findIndex(v=>v.Effect==='Deny'&&!v.NotResource),1);if(kind==='resource-exception')s.find(v=>Array.isArray(v.NotResource)).NotResource.push('*');if(kind==='new-deny')s.find(v=>v.Action?.includes?.('iam:PassRole')).Resource.push('arn:aws:s3:::other-123456789012/*');}
  if(kind==='fake-chain')f.bootstrap.controlChain.at(-1).record.phase='HELD';if(kind==='template')f.bootstrap.boundaryTemplate+='changed';if(kind==='bootstrap-pin')f.expectedBootstrap.operationHash='0'.repeat(64);
  if(kind!=='raw-hash')f.refresh(f.current);
  expect(()=>buildCanaryMaterialTransition(f.input(),{expectedBootstrap:f.expectedBootstrap})).toThrow();
 });
 it('accepts only configured metadata permutations for fresh observations, with distinct raw hashes',()=>{
  const f=transitionFixture(),built=buildCanaryMaterialTransition(f.input(),{expectedBootstrap:f.expectedBootstrap});
  const old=verifyCanaryTransitionObservation(f.current,built.context,{selection:f.selection(),now:f.now}),changed=structuredClone(f.current);
  changed.observedAt=new Date(f.now+1).toISOString();changed.definitions.backend.compatibilities.reverse();changed.definitions.backend.requiresAttributes.reverse();f.refresh(changed);
  const current=verifyCanaryTransitionObservation(changed,built.context,{selection:f.selection(),now:f.now+1});expect(current.stableMaterialHash).toBe(old.stableMaterialHash);expect(current.cloudObservationHash).not.toBe(old.cloudObservationHash);
  changed.definitions.backend.futureField=true;f.refresh(changed);expect(()=>verifyCanaryTransitionObservation(changed,built.context,{selection:f.selection(),now:f.now+1})).toThrow();
 });
 it('certificate material pairs remain explicitly proof-anchored across fresh metadata order and selected control release changes',()=>{
  const f=transitionFixture(),built=buildCanaryMaterialTransition(f.input(),{expectedBootstrap:f.expectedBootstrap}),fresh=structuredClone(f.current);
  fresh.definitions.backend.compatibilities.reverse();fresh.definitions.backend.requiresAttributes.reverse();fresh.observedAt=new Date(f.now+1).toISOString();
  fresh.revision='e'.repeat(40);fresh.sourceTree='f'.repeat(40);fresh.coordinatorDigest='a'.repeat(64);fresh.controlSourceTag='mem9-eeeeeee';fresh.dataRelease.data.controlSourceTree=fresh.sourceTree;fresh.dataRelease.hash=hash(fresh.dataRelease.data);fresh.dataRelease.parameterVersion=3;f.refresh(fresh);
  const selection={revision:fresh.revision,sourceTree:fresh.sourceTree,coordinatorDigest:fresh.coordinatorDigest,dataReleaseHash:fresh.dataRelease.hash,parameterVersion:3};
  const observation=verifyCanaryTransitionObservation(fresh,built.context,{selection,now:f.now+1});
  const certificate=buildCanaryCompatibilityV3(f.previous,fresh,f.parent,{transition:built.context,selection,now:f.now+1});
  expect(fresh.material.backend).not.toBe(f.current.material.backend);expect(certificate.material.backend.current).toBe(f.current.material.backend);expect(certificate.material.backend.current).not.toBe(fresh.material.backend);
  expect(certificate.material.authority.current).toBe(fresh.material.authority);expect(certificate.transition.proofHash).toBe(built.proofHash);expect(certificate.current.release.sourceTree).toBe(selection.sourceTree);expect(certificate.dataReleaseHash).toBe(selection.dataReleaseHash);
  expect(observation.cloudObservationHash).not.toBe(built.proof.anchors.currentSnapshotHash);expect(observation.stableMaterialHash).toBe(built.stableMaterialHash);
 });
 it('rejects forged contexts, replaced proof anchors, missing commitments and source/parameter selection changes',()=>{
  const f=transitionFixture(),built=buildCanaryMaterialTransition(f.input(),{expectedBootstrap:f.expectedBootstrap});
  expect(()=>verifyCanaryTransitionObservation(f.current,{}, {selection:f.selection(),now:f.now})).toThrow();
  const proof=structuredClone(built.proof);proof.anchors.previousSnapshotHash='0'.repeat(64);expect(()=>verifyCanaryMaterialTransition(proof,{proofHash:hash(proof),expectedBootstrap:f.expectedBootstrap})).toThrow();
  expect(()=>verifyCanaryMaterialTransition(built.proof,{proofHash:'0'.repeat(64),expectedBootstrap:f.expectedBootstrap})).toThrow();
  expect(()=>verifyCanaryTransitionObservation(f.current,built.context,{selection:{...f.selection(),parameterVersion:3},now:f.now})).toThrow();
  expect(()=>verifyCanaryTransitionObservation(f.current,built.context,{selection:f.selection(),now:f.now+300001})).toThrow();
 });
 it.each(['extra-deny','changed-allow','scope-condition','scope-exception','archive-resource'])('rejects nonapproved %s even with matching proposed policy digest',kind=>{
  const f=transitionFixture();for(const role of f.current.authority){const s=role.boundary.document.Statement;
   if(kind==='extra-deny')s.push({Effect:'Deny',Action:'kms:Decrypt',Resource:'*'});
   if(kind==='changed-allow')s.find(v=>v.Effect==='Allow').Action='s3:GetObject';
   if(kind==='scope-condition')s.find(v=>Array.isArray(v.NotResource)).Condition={StringEquals:{'aws:RequestedRegion':'us-west-2'}};
   if(kind==='scope-exception')s.find(v=>Array.isArray(v.NotResource)).NotResource.push('arn:aws:s3:::another-project-123456789012/*');
   if(kind==='archive-resource')s.find(v=>v.Action?.includes?.('iam:PassRole')).Resource.push('arn:aws:s3:::another-project-123456789012/*');
  }
  f.refresh(f.current);f.expectedBootstrap.currentPolicyHash=hash(semantic(f.current.authority[0].boundary.document));
  expect(()=>buildCanaryMaterialTransition(f.input(),{expectedBootstrap:f.expectedBootstrap})).toThrow();
 });
 it.each(['command','role','cpu','unknown'])('rejects hidden task execution override %s',kind=>{
  const f=transitionFixture();f.current.backendTask.overrides=kind==='command'?{containerOverrides:[{name:'llm-proxy',command:['unexpected']}]}:kind==='role'?{taskRoleArn:'arn:aws:iam::123456789012:role/other'}:kind==='cpu'?{cpu:'1024'}:{futureOverride:true};
  expect(()=>buildCanaryMaterialTransition(f.input(),{expectedBootstrap:f.expectedBootstrap})).toThrow();
 });
 it('keeps historical inspection separate from publication expiry and observation freshness',()=>{
  const f=transitionFixture(),built=buildCanaryMaterialTransition(f.input(),{expectedBootstrap:f.expectedBootstrap});
  const fresh=structuredClone(f.current),now=f.current.dataRelease.data.expiresMs;
  fresh.observedAt=new Date(now).toISOString();
  const options={selection:f.selection(),now};
  expect(()=>verifyCanaryTransitionObservation(fresh,built.context,options)).toThrow('DataReleaseAuthorizationExpired');
  expect(()=>buildCanaryCompatibilityV3(f.previous,fresh,f.parent,{transition:built.context,...options})).toThrow('DataReleaseAuthorizationExpired');
  const historical=buildCanaryCompatibilityV3(f.previous,fresh,f.parent,{transition:built.context,...options,mode:'inspection'});
  expect(historical.dataReleaseHash).toBe(f.current.dataRelease.hash);
  expect(historical.transition.proofHash).toBe(built.proofHash);
  expect(()=>verifyCanaryTransitionObservation(fresh,built.context,{...options,mode:'inspection',now:now+300001})).toThrow();
  expect(()=>verifyCanaryTransitionObservation(fresh,built.context,{...options,mode:'inspection',now:now-1})).toThrow();
 });
 it('passes the actual builder certificate through the root consumer and still requires its exact protected witness',()=>{
  const f=transitionFixture(),built=buildCanaryMaterialTransition(f.input(),{expectedBootstrap:f.expectedBootstrap});
  const context=verifyCanaryMaterialTransition(built.proof,{proofHash:built.proofHash,expectedBootstrap:f.expectedBootstrap});
  const certificate=buildCanaryCompatibilityV3(f.previous,f.current,f.parent,{transition:context,selection:f.selection(),now:f.now});
  const config={generation:f.parent.generation,targets:f.parent.targets,sourceTag:f.current.sourceTag,workerImage:f.current.workerImage,
   dataRelease:f.current.dataRelease,acceptance:{sourceTree:f.current.sourceTree,coordinatorDigest:f.current.coordinatorDigest,dataReleaseHash:f.current.dataRelease.hash}};
  const state={operation_nonce:f.current.runtime.runtimeNonce,identity:{schemaDigest:f.current.runtime.schemaDigest,operatorDigest:f.current.runtime.operatorDigest,clusterArn:f.current.network.cluster}};
  expect(inspectCanaryCompatibility(certificate,f.parent,config,state).certificateHash).toBe(hash(certificate));
  expect(()=>validateCanaryCompatibility(certificate,f.parent,config,state)).toThrow('CanaryCompatibilityInvalid');
  config.acceptance.continuation={version:1,parentProofHash:hash(f.parent),certificateHash:hash(certificate),sourceTree:f.current.sourceTree,fixture:{hash:'9'.repeat(64),runId:'12345',runAttempt:1}};
  expect(validateCanaryCompatibility(certificate,f.parent,config,state).backendBinding).toEqual(f.current.backendBinding);
  const changed=structuredClone(certificate);changed.transition.proofHash='8'.repeat(64);
  expect(()=>validateCanaryCompatibility(changed,f.parent,config,state)).toThrow('CanaryCompatibilityInvalid');
 });
 it('rejects duplicate JSON keys, unknown proof fields and executable metadata',()=>{
  const f=transitionFixture(),input=f.input();input.previousText=input.previousText.replace('{','{"version":2,');expect(()=>buildCanaryMaterialTransition(input,{expectedBootstrap:f.expectedBootstrap})).toThrow();
  const built=buildCanaryMaterialTransition(f.input(),{expectedBootstrap:f.expectedBootstrap});const changed={...built.proof,compatible:true};expect(()=>verifyCanaryMaterialTransition(changed,{proofHash:hash(changed),expectedBootstrap:f.expectedBootstrap})).toThrow();
  const invalid=f.input();invalid.bootstrap.operation.extra=()=>true;expect(()=>buildCanaryMaterialTransition(invalid,{expectedBootstrap:f.expectedBootstrap})).toThrow();
 });
});
