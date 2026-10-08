import {describe,it,expect} from 'vitest';
import {canaryEvidenceHash as hash} from './lib/production-canary-verification.mjs';
import {validateCanaryCompatibility,inspectCanaryCompatibility} from './lib/production-canary-compatibility.mjs';
import {readFile} from 'node:fs/promises';
import {IMAGE_TRANSITION_LIMITS_HASH} from './lib/production-image-transition.mjs';

const hex=n=>n.toString(16).padStart(64,'0');
it('the control image and coordinator closure include the V3/V4 consumer and host modules',async()=>{
 const docker=await readFile(new URL('../docker/bootstrap/Dockerfile',import.meta.url),'utf8');
 expect(docker).toContain('COPY scripts/lib/production-canary-transition.mjs /bootstrap/operator/scripts/lib/production-canary-transition.mjs');
 expect(docker).toContain('COPY scripts/lib/production-image-transition.mjs /bootstrap/operator/scripts/lib/production-image-transition.mjs');
 const host=await readFile(new URL('./run-production-runtime.mjs',import.meta.url),'utf8');
 const digest=host.slice(host.indexOf('export async function productionCoordinatorDigest()'),host.indexOf('export async function retainedDeploymentEnvironment'));
 for(const name of ['production-canary-transition','production-canary-material-transition','production-canary-material-integrity','production-maintenance-admission'])expect(digest).toContain("'scripts/lib/"+name+".mjs'");
});
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

function transitionFixture(){
 const f=fixture(),c=f.certificate,worker='123456789012.dkr.ecr.ap-northeast-1.amazonaws.com/mem9-on-aws/llm-proxy@sha256:'+hex(4);
 c.version=3;c.dataReleaseHash=hex(44);c.previous.release.workerImage=worker;c.current.release.workerImage=worker;c.images.worker.currentRoot=c.images.worker.previousRoot;
 f.parent.workerImage=worker;f.parent.releaseHash=hash(c.previous.release);c.parentProofHash=hash(f.parent);f.config.workerImage=worker;
 c.material.authority.current=hex(45);c.material.backend.current=hex(46);c.transition={version:1,kind:'bootstrap-boundary-tightening',proofHash:hex(47),backendProjectionHash:hex(48)};
 f.config.dataRelease={hash:c.dataReleaseHash};f.config.acceptance.dataReleaseHash=c.dataReleaseHash;f.config.acceptance.continuation.parentProofHash=c.parentProofHash;f.config.acceptance.continuation.certificateHash=hash(c);return f;
}
it('V3 binds real material differences and the entire certificate to the protected witness',()=>{
 const f=transitionFixture(),before=structuredClone(f.certificate);expect(validateCanaryCompatibility(f.certificate,f.parent,f.config,f.state).certificateHash).toBe(hash(before));expect(f.certificate).toEqual(before);
 delete f.config.acceptance.continuation;expect(inspectCanaryCompatibility(f.certificate,f.parent,f.config,f.state).certificateHash).toBe(hash(before));expect(()=>validateCanaryCompatibility(f.certificate,f.parent,f.config,f.state)).toThrow();
});
for(const defect of ['proof','witness','root','authority-equal','planner','legacy-downgrade','unsupported'])it('V3 consumer rejects '+defect,()=>{
 const f=transitionFixture();if(defect==='proof')f.certificate.transition.proofHash='bad';if(defect==='witness')f.config.acceptance.continuation.certificateHash=hex(99);if(defect==='root')f.config.generation=hex(99);
 if(defect==='authority-equal')f.certificate.material.authority.current=f.certificate.material.authority.previous;if(defect==='planner')f.certificate.material.planner.current=hex(99);if(defect==='legacy-downgrade')f.certificate.version=2;if(defect==='unsupported')f.certificate.version=4;
 expect(()=>validateCanaryCompatibility(f.certificate,f.parent,f.config,f.state)).toThrow();
});

function imageTransitionFixture(){
 const f=transitionFixture(),c=f.certificate;c.version=4;
 c.transition={version:1,kind:'image-security-upgrade',proofHash:hex(50),predecessorHash:hex(51),limitsHash:IMAGE_TRANSITION_LIMITS_HASH,projectionHash:hex(52)};
 for(const [i,name]of ['worker','llm-proxy','mnemo-server','qwen3-embed'].entries()){
  const root=name==='worker'||name==='llm-proxy'?6:20+i;
  c.images[name]={previousRoot:'sha256:'+hex(name==='worker'||name==='llm-proxy'?4:9),previousChild:'sha256:'+hex(11),currentRoot:'sha256:'+hex(root),currentChild:'sha256:'+hex(root+20)};
 }
 c.current.release.workerImage=c.current.release.workerImage.replace('@'+c.images.worker.previousRoot,'@'+c.images.worker.currentRoot);f.config.workerImage=c.current.release.workerImage;
 for(const name of ['planner','executor'])c.material[name].current=hex(70);
 for(const container of c.current.backendBinding.containers)container.imageDigest=c.images[container.name].currentRoot;
 const {projectionHash:ignored,...transition}=c.transition;f.config.dataRelease={data:{version:2,transition},hash:hex(44)};
 f.config.acceptance.continuation.certificateHash=hash(c);return f;
}
it('V4 binds typed descriptor commitments and the new images to the original parent and protected witness',()=>{
 const f=imageTransitionFixture(),before=structuredClone(f.certificate);
 expect(validateCanaryCompatibility(f.certificate,f.parent,f.config,f.state).certificateHash).toBe(hash(before));expect(f.certificate).toEqual(before);
 delete f.config.acceptance.continuation;expect(inspectCanaryCompatibility(f.certificate,f.parent,f.config,f.state).certificateHash).toBe(hash(before));
 expect(()=>validateCanaryCompatibility(f.certificate,f.parent,f.config,f.state)).toThrow();
});
for(const version of [1,2,3])it('a typed descriptor V2 cannot fall through certificate V'+version+' even with unchanged images',()=>{
 const f=version===3?transitionFixture():fixture();f.certificate.version=version;
 if(version===2){f.certificate.dataReleaseHash=hex(44);f.config.acceptance.dataReleaseHash=hex(44);}
 f.config.dataRelease={hash:hex(44),data:{version:2,transition:{version:1,kind:'image-security-upgrade',proofHash:hex(50),predecessorHash:hex(51),limitsHash:IMAGE_TRANSITION_LIMITS_HASH}}};
 f.config.acceptance.continuation.certificateHash=hash(f.certificate);
 expect(()=>inspectCanaryCompatibility(f.certificate,f.parent,f.config,f.state)).toThrow();
});
for(const defect of ['legacy-descriptor','missing-data','proofHash','predecessorHash','limitsHash','witness','unknown-kind'])it('V4 rejects '+defect,()=>{
 const f=imageTransitionFixture();
 if(defect==='legacy-descriptor')f.config.dataRelease.data.version=1;else if(defect==='missing-data')delete f.config.dataRelease.data;
 else if(defect==='witness')delete f.config.acceptance.dataReleaseHash;else if(defect==='unknown-kind')f.certificate.transition.kind='other';else f.config.dataRelease.data.transition[defect]=hex(99);
 expect(()=>validateCanaryCompatibility(f.certificate,f.parent,f.config,f.state)).toThrow();
});
