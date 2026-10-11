import {describe,it,expect,vi} from 'vitest';
import {nonrootHash as hash} from './lib/production-nonroot-contracts.mjs';
import {replayOwnerTargetWindow} from './lib/production-nonroot-target-identity.mjs';
import {nonrootRuntimeFixture,digest,COMPONENTS} from './production-nonroot-runtime.fixture.mjs';

function fixture(){
 const f=nonrootRuntimeFixture(),join=structuredClone(f.audit.targetJoin);
 join.targetEvidence.target=structuredClone(f.target);
 join.postAuditObservation.target=structuredClone(f.target);
 const images=Object.fromEntries(f.target.containers.map(c=>[c.name,structuredClone(c.image)]));
 const proof={root:f.audit.root,dataOrigin:{images}},deploymentSource={sourceTree:'a'.repeat(40)};
 const parameter={Version:2,Value:JSON.stringify({images:Object.fromEntries(Object.entries(images).map(([name,image])=>[name,{rootDigest:image.rootDigest,arm64Digest:image.arm64Digest}]))})};
 const receipt={version:1,kind:'future-target-window-receipt',scope:{checkpoint:'deploy-prod/23'},proofHash:hash(proof),rootBindingHash:hash(proof.root),descriptorHash:hash(JSON.parse(parameter.Value)),parameterVersion:parameter.Version,deploymentSourceHash:hash(deploymentSource),targetJoinHash:hash(join),accounting:{}};
 const json=vi.fn(()=>{throw Error('UnexpectedReplayRead');}),put=vi.fn(()=>{throw Error('UnexpectedReplayWrite');});
 return {input:{receipt,join,proof,deploymentSource,parameter,json,put},json,put};
}

describe('owner target image binding before funded replay',()=>{
 for(const window of ['targetEvidence','postAuditObservation'])for(const component of COMPONENTS)for(const field of ['rootDigest','arm64Digest','configDigest']){
  it(`rejects rehashed ${window} ${component} ${field} substitution`,async()=>{
   const f=fixture(),{input}=f;
   input.join[window].target.containers.find(c=>c.name===component).image[field]=digest(999);
   input.receipt.targetJoinHash=hash(input.join);
   await expect(replayOwnerTargetWindow(input)).rejects.toThrow('TargetWindowReceiptImage');
   expect(f.json).not.toHaveBeenCalled();expect(f.put).not.toHaveBeenCalled();
  });
 }
 it('requires original funding after all complete images match',async()=>{
  const f=fixture();
  await expect(replayOwnerTargetWindow(f.input)).rejects.toThrow('TargetWindowFundingRequired');
  expect(f.json).not.toHaveBeenCalled();expect(f.put).not.toHaveBeenCalled();
 });
 for(const defect of ['missing-config','duplicate-container','missing-container'])it(`rejects ${defect} in the typed target`,async()=>{
  const f=fixture(),target=f.input.join.postAuditObservation.target;
  if(defect==='missing-config')delete target.containers[0].image.configDigest;
  if(defect==='duplicate-container')target.containers[1]=structuredClone(target.containers[0]);
  if(defect==='missing-container')target.containers.pop();
  f.input.receipt.targetJoinHash=hash(f.input.join);
  await expect(replayOwnerTargetWindow(f.input)).rejects.toThrow('NonrootContractInvalid');
  expect(f.json).not.toHaveBeenCalled();expect(f.put).not.toHaveBeenCalled();
 });
});
