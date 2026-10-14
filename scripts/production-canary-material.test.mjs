import {describe,it,expect} from 'vitest';
import {createHash} from 'node:crypto';
import {verifyCanaryImageIndex,normalizeCanaryTask,projectConfiguredCanaryBackend,CANARY_BACKEND_ADDITIONAL_ATTRIBUTE} from './lib/production-canary-material.mjs';
import {canaryEvidenceHash as hash} from './lib/production-canary-verification.mjs';

const account='123456789012',region='ap-northeast-1',registry=account+'.dkr.ecr.'+region+'.amazonaws.com';
const digest=n=>'sha256:'+n.repeat(64),oldRef=registry+'/mem9-on-aws/llm-proxy@'+digest('a'),newRef=registry+'/mem9-on-aws/llm-proxy@'+digest('b');
function fixture(){
  const image=(root)=>({rootDigest:root,arm64Digest:digest('c'),registryId:account,repositoryName:'mem9-on-aws/llm-proxy'});
  const context={account,region,images:new Map([[oldRef,image(digest('a'))],[newRef,image(digest('b'))]])};
  const definition={taskDefinitionArn:`arn:aws:ecs:${region}:${account}:task-definition/mem9-on-aws-prod-Worker:1`,family:'mem9-on-aws-prod-Worker',revision:1,status:'ACTIVE',registeredAt:'2026-01-01T00:00:00Z',registeredBy:'old-registration',
    taskRoleArn:`arn:aws:iam::${account}:role/mem9-on-aws-prod-WorkerTaskRole`,executionRoleArn:`arn:aws:iam::${account}:role/mem9-on-aws-prod-WorkerExecutionRole`,
    networkMode:'awsvpc',cpu:'512',memory:'1024',runtimePlatform:{cpuArchitecture:'ARM64',operatingSystemFamily:'LINUX'},requiresCompatibilities:['FARGATE'],volumes:[],placementConstraints:[],
    containerDefinitions:[{name:'worker',image:oldRef,essential:true,entryPoint:['node'],command:['/app/scripts/consolidation-worker.mjs'],
      environment:[{name:'B',value:'2'},{name:'A',value:'1'}],secrets:[{name:'DB',valueFrom:`arn:aws:ssm:${region}:${account}:parameter/mem9-on-aws/prod/runtime/database-credential`}],
      mountPoints:[],linuxParameters:{initProcessEnabled:true},logConfiguration:{logDriver:'awslogs',options:{'awslogs-group':'example'}}}]};
  const current=structuredClone(definition);current.taskDefinitionArn=current.taskDefinitionArn.replace(/:1$/,':2');current.revision=2;current.registeredAt='2026-01-02T00:00:00Z';current.registeredBy='new-registration';current.containerDefinitions[0].image=newRef;
  return {context,definition,current};
}
describe('actual canary image and material comparison',()=>{
  it('accepts a cryptographically bound unique Linux ARM64 child',()=>{
    const manifest=JSON.stringify({schemaVersion:2,mediaType:'application/vnd.oci.image.index.v1+json',manifests:[{digest:digest('c'),mediaType:'application/vnd.oci.image.manifest.v1+json',platform:{os:'linux',architecture:'arm64'}}]});
    const rootDigest='sha256:'+createHash('sha256').update(manifest).digest('hex');
    const response={images:[{registryId:account,repositoryName:'mem9-on-aws/llm-proxy',imageId:{imageDigest:rootDigest},imageManifest:manifest}]};
    expect(verifyCanaryImageIndex(response,{account,repositoryName:'mem9-on-aws/llm-proxy',rootDigest}).arm64Digest).toBe(digest('c'));
    for(const mutate of [r=>{r.images[0].registryId='0'.repeat(12);},r=>{r.images[0].imageManifest+=' ';},r=>{r.failures=[{failureCode:'ImageNotFound'}];}]){
      const changed=structuredClone(response);mutate(changed);expect(()=>verifyCanaryImageIndex(changed,{account,repositoryName:'mem9-on-aws/llm-proxy',rootDigest})).toThrow();
    }
  });
  it('does not choose one of multiple ARM64 descriptors',()=>{
    const manifest=JSON.stringify({schemaVersion:2,mediaType:'application/vnd.oci.image.index.v1+json',manifests:[0,1].map(()=>({digest:digest('c'),mediaType:'application/vnd.oci.image.manifest.v1+json',platform:{os:'linux',architecture:'arm64'}}))});
    const rootDigest='sha256:'+createHash('sha256').update(manifest).digest('hex');
    expect(()=>verifyCanaryImageIndex({images:[{registryId:account,repositoryName:'mem9-on-aws/llm-proxy',imageId:{imageDigest:rootDigest},imageManifest:manifest}]},{account,repositoryName:'mem9-on-aws/llm-proxy',rootDigest})).toThrow();
  });
  it('normalizes only registration identity and verified image references',()=>{
    const f=fixture();f.current.containerDefinitions[0].environment.reverse();
    expect(normalizeCanaryTask(f.current,f.context)).toEqual(normalizeCanaryTask(f.definition,f.context));
    expect(f.definition.containerDefinitions[0].image).toBe(oldRef);
  });
  it.each(['cpu','memory','role','network','command','environment','secret','privileged','health','unknown'])('keeps material %s changes visible',kind=>{
    const f=fixture(),c=f.current.containerDefinitions[0];
    if(kind==='cpu')f.current.cpu='1024';if(kind==='memory')f.current.memory='2048';
    if(kind==='role')f.current.taskRoleArn+='Other';if(kind==='network')f.current.volumes=[{name:'different'}];
    if(kind==='command')c.command=['different'];if(kind==='environment')c.environment[0].value='different';if(kind==='secret')c.secrets[0].valueFrom+='-other';
    if(kind==='privileged')c.privileged=true;if(kind==='health')c.healthCheck={command:['CMD','false']};if(kind==='unknown')f.current.futureSemanticSetting=true;
    expect(hash(normalizeCanaryTask(f.current,f.context))).not.toBe(hash(normalizeCanaryTask(f.definition,f.context)));
  });
  it('rejects duplicate environment names, unverified images and foreign image scope',()=>{
    for(const change of [f=>{f.current.containerDefinitions[0].environment.push({name:'A',value:'shadow'});},
      f=>{f.context.images.delete(newRef);},f=>{f.current.containerDefinitions[0].image='https://example.com/unverified';},
      f=>{f.context.images.get(newRef).registryId='0'.repeat(12);}]){
      const f=fixture();change(f);expect(()=>normalizeCanaryTask(f.current,f.context)).toThrow();
    }
  });
});

describe('configured backend projection keeps service metadata separate',()=>{
 it('retains every execution field while sorting compatibility metadata and exposing the complete attribute set',()=>{
  const f=fixture();for(const d of [f.definition,f.current])Object.assign(d,{compatibilities:['MANAGED_INSTANCES','EC2','FARGATE'],requiresAttributes:[{name:'ecs.capability.task-eni'}]});
  f.current.requiresAttributes.push({name:CANARY_BACKEND_ADDITIONAL_ATTRIBUTE});
  const before=structuredClone(f.definition),a=projectConfiguredCanaryBackend(f.definition,f.context),b=projectConfiguredCanaryBackend(f.current,f.context);
  expect(a.configuration).toEqual(b.configuration);expect(a.metadata.attributeNames).not.toEqual(b.metadata.attributeNames);expect(f.definition).toEqual(before);
  f.current.futureExecutionField=true;expect(projectConfiguredCanaryBackend(f.current,f.context).configuration).not.toEqual(a.configuration);
 });
 it.each(['duplicate-compatibility','missing-compatibility','different-platform','duplicate-attribute','attribute-extra-field','requires-compatibility'])('rejects %s',kind=>{
  const f=fixture(),d=f.definition;Object.assign(d,{compatibilities:['EC2','FARGATE','MANAGED_INSTANCES'],requiresAttributes:[{name:'ecs.capability.task-eni'}]});
  if(kind==='duplicate-compatibility')d.compatibilities[2]='EC2';if(kind==='missing-compatibility')d.compatibilities.pop();if(kind==='different-platform')d.runtimePlatform.cpuArchitecture='X86_64';if(kind==='duplicate-attribute')d.requiresAttributes.push(d.requiresAttributes[0]);if(kind==='attribute-extra-field')d.requiresAttributes[0].value='unrecognized';if(kind==='requires-compatibility')d.requiresCompatibilities.push('EC2');
  expect(()=>projectConfiguredCanaryBackend(d,f.context)).toThrow();
 });
});
