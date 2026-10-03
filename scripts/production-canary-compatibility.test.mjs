import {describe,it,expect} from 'vitest';
import {canaryEvidenceHash as hash} from './lib/production-canary-verification.mjs';
import {validateCanaryCompatibility,inspectCanaryCompatibility} from './lib/production-canary-compatibility.mjs';

const hex=n=>n.toString(16).padStart(64,'0');
function fixture(){
  const runtime={schemaDigest:hex(1),operatorDigest:hex(2),runtimeNonce:'a'.repeat(32)};
  const oldRelease={...runtime,sourceTree:'a'.repeat(40),coordinatorDigest:hex(3),sourceTag:'mem9-aaaaaaa',workerImage:'example/worker@sha256:'+hex(4)};
  const nextRelease={...runtime,sourceTree:'b'.repeat(40),coordinatorDigest:hex(5),sourceTag:'mem9-bbbbbbb',workerImage:'example/worker@sha256:'+hex(6)};
  const cluster='arn:aws:ecs:ap-northeast-1:123456789012:cluster/mem9-on-aws-prod-Fixture';
  const backend={taskArn:cluster.replace(':cluster/',':task/')+'/'+'b'.repeat(32),taskDefinitionArn:'arn:aws:ecs:ap-northeast-1:123456789012:task-definition/mem9-on-aws-prod-Fixture-Mem9RuntimeServer:2',
    containers:['llm-proxy','mnemo-server','qwen3-embed'].map(name=>({name,imageDigest:'sha256:'+hex(9)}))};
  const parent={generation:hex(7),validationId:'c'.repeat(32),targets:['namespace-a'],sourceTag:oldRelease.sourceTag,workerImage:oldRelease.workerImage,
    releaseHash:hash(oldRelease),backendBindingHash:hex(8),protectedBaselineHash:hex(10)};
  const certificate={version:1,parentProofHash:hash(parent),generation:parent.generation,targetsHash:hash(parent.targets),
    previous:{release:oldRelease,backendBindingHash:parent.backendBindingHash},current:{release:nextRelease,backendBinding:backend},
    images:Object.fromEntries(['worker','mnemo-server','qwen3-embed','llm-proxy'].map(name=>[name,{previousRoot:'sha256:'+hex(name==='worker'?4:9),currentRoot:'sha256:'+hex(name==='worker'?6:9),previousChild:'sha256:'+hex(11),currentChild:'sha256:'+hex(11)}])),
    material:Object.fromEntries(['planner','executor','backend','network','authority','credentials'].map(name=>[name,{previous:hex(12),current:hex(12)}]))};
  const config={generation:parent.generation,targets:parent.targets,sourceTag:nextRelease.sourceTag,workerImage:nextRelease.workerImage,
    acceptance:{sourceTree:nextRelease.sourceTree,coordinatorDigest:nextRelease.coordinatorDigest,
      continuation:{version:1,parentProofHash:hash(parent),certificateHash:hash(certificate),sourceTree:nextRelease.sourceTree,
        fixture:{hash:hex(33),runId:'12345',runAttempt:1}}}};
  const state={operation_nonce:runtime.runtimeNonce,identity:{schemaDigest:runtime.schemaDigest,operatorDigest:runtime.operatorDigest,clusterArn:cluster}};
  return {certificate,parent,config,state};
}
describe('canary continuation compatibility certificate',()=>{
  it('binds the separately authorized retained selection without changing historical release fields',()=>{
    const f=fixture();f.certificate.version=2;f.certificate.dataReleaseHash=hex(44);
    f.config.dataRelease={hash:hex(44),expiresMs:1800000000000};f.config.acceptance.dataReleaseHash=hex(44);
    f.config.acceptance.continuation.certificateHash=hash(f.certificate);
    expect(validateCanaryCompatibility(f.certificate,f.parent,f.config,f.state).certificateHash).toBe(hash(f.certificate));
    delete f.config.acceptance.dataReleaseHash;expect(()=>validateCanaryCompatibility(f.certificate,f.parent,f.config,f.state)).toThrow();
    f.config.acceptance.dataReleaseHash=hex(44);f.config.dataRelease.hash=hex(45);
    expect(()=>validateCanaryCompatibility(f.certificate,f.parent,f.config,f.state)).toThrow();
  });
  it('allows non-authorizing structural inspection while mutation still requires the published witness',()=>{
    const f=fixture();delete f.config.acceptance.continuation;
    expect(inspectCanaryCompatibility(f.certificate,f.parent,f.config,f.state).certificateHash).toBe(hash(f.certificate));
    expect(()=>validateCanaryCompatibility(f.certificate,f.parent,f.config,f.state)).toThrow('CanaryCompatibilityInvalid');
  });
  it('binds both releases, unchanged runtime identity, images and material configuration',()=>{
    const f=fixture();expect(validateCanaryCompatibility(f.certificate,f.parent,f.config,f.state).backendBinding).toEqual(f.certificate.current.backendBinding);
  });
  it('rejects a missing or mismatched source-bound witness',()=>{
    for(const change of [f=>{delete f.config.acceptance.continuation;},f=>{f.config.acceptance.continuation.certificateHash=hex(88);},f=>{f.config.acceptance.continuation.parentProofHash=hex(88);},f=>{f.config.acceptance.continuation.version=2;},
      f=>{delete f.config.acceptance.continuation.fixture;},f=>{f.config.acceptance.continuation.fixture.runAttempt=0;}]){
      const f=fixture();change(f);expect(()=>validateCanaryCompatibility(f.certificate,f.parent,f.config,f.state)).toThrow();
    }
  });
  it('rejects differences even when a caller recomputes the certificate digest',()=>{
    for(const change of [f=>{f.certificate.images.worker.currentChild=hex(88);},f=>{f.certificate.material.authority.current=hex(88);},
      f=>{f.certificate.generation=hex(88);},f=>{f.certificate.current.release.schemaDigest=hex(88);},f=>{f.certificate.previous.release.sourceTree='c'.repeat(40);},
      f=>{f.certificate.current.backendBinding.taskArn=f.certificate.current.backendBinding.taskArn.replace('prod-Fixture','other-Fixture');},
      f=>{f.certificate.current.release.workerImage='example/worker@sha256:'+hex(99);},f=>{f.certificate.extra=true;}]){
      const f=fixture();change(f);f.config.acceptance.continuation.certificateHash=hash(f.certificate);
      expect(()=>validateCanaryCompatibility(f.certificate,f.parent,f.config,f.state)).toThrow();
    }
  });
});
