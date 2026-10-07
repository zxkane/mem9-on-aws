import {describe,it,expect} from 'vitest';
import {inspectCanaryTransitionCertificate} from './lib/production-canary-transition.mjs';

const h=c=>c.repeat(64),d=c=>'sha256:'+h(c);
function fixture(){
 const image={previousRoot:d('a'),currentRoot:d('a'),previousChild:d('b'),currentChild:d('b')};
 const release={sourceTree:'a'.repeat(40),coordinatorDigest:h('b'),sourceTag:'mem9-aaaaaaa',workerImage:'123456789012.dkr.ecr.ap-northeast-1.amazonaws.com/mem9-on-aws/llm-proxy@'+d('a'),schemaDigest:h('c'),operatorDigest:h('d'),runtimeNonce:'e'.repeat(32)};
 const current={release:{...release},backendBinding:{taskArn:'arn:aws:ecs:ap-northeast-1:123456789012:task/mem9-on-aws-prod-example/'+'a'.repeat(32),taskDefinitionArn:'arn:aws:ecs:ap-northeast-1:123456789012:task-definition/mem9-on-aws-prod-example-Mem9RuntimeServer:1',containers:['llm-proxy','mnemo-server','qwen3-embed'].map(name=>({name,imageDigest:d('b')}))}};
 return {version:3,dataReleaseHash:h('f'),parentProofHash:h('1'),generation:h('2'),targetsHash:h('3'),previous:{release,backendBindingHash:h('4')},current,images:Object.fromEntries(['worker','llm-proxy','mnemo-server','qwen3-embed'].map(n=>[n,{...image}])),material:Object.fromEntries(['planner','executor','backend','network','authority','credentials'].map(n=>[n,{previous:h('5'),current:h(n==='backend'?'6':n==='authority'?'7':'5')}])),transition:{version:1,kind:'bootstrap-boundary-tightening',proofHash:h('8'),backendProjectionHash:h('9')}};
}
describe('pure V3 transition certificate schema',()=>{
 it('retains actual unequal authority hashes and a typed proof commitment',()=>{const c=fixture();expect(inspectCanaryTransitionCertificate(c)).toEqual({proofHash:h('8'),backendProjectionHash:h('9')});expect(c.material.authority.previous).not.toBe(c.material.authority.current);});
 it.each(['legacy','unknown','kind','proof','authority-equal','planner','image','release','size'])('rejects %s instead of lowering old or new requirements',kind=>{
  const c=fixture();if(kind==='legacy')c.version=2;if(kind==='unknown')c.transition.compatible=true;if(kind==='kind')c.transition.kind='arbitrary-tightening';if(kind==='proof')c.transition.proofHash='invalid';if(kind==='authority-equal')c.material.authority.current=c.material.authority.previous;if(kind==='planner')c.material.planner.current=h('a');if(kind==='image')c.images.worker.currentChild=d('c');if(kind==='release')c.current.release.runtimeNonce='bad';if(kind==='size')c.current.backendBinding.taskArn+='x'.repeat(6000);
  expect(()=>inspectCanaryTransitionCertificate(c)).toThrow('CanaryTransitionCertificateInvalid');
 });
});
