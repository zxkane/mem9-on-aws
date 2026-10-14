import {describe,it,expect} from 'vitest';
import {createHash} from 'node:crypto';
import {frozenServiceRegistration,registrationInput} from './lib/service-nonroot.mjs';
import {taggedServiceDefinition} from './test-fixtures/service-nonroot-images.mjs';

describe('actual running image bindings',()=>{
  it('pins the served platform digests without rewriting the raw baseline or unrelated settings',()=>{
    const d=taggedServiceDefinition(),before=structuredClone(d),r=frozenServiceRegistration(d);
    expect(d).toEqual(before);
    for(const c of r.containerDefinitions)expect(c.image).toBe(d.imageBindings.images[c.name].image.replace(/:[^/:]+$/,'@'+d.imageBindings.images[c.name].imageDigest));
    expect({...r,containerDefinitions:d.taskDefinition.containerDefinitions}).toEqual(registrationInput(d));
  });
  it('retains an already pinned baseline without requiring mutable-tag proof',()=>{
    const d=taggedServiceDefinition();d.taskDefinition.containerDefinitions=frozenServiceRegistration(d).containerDefinitions;delete d.imageBindings;
    expect(frozenServiceRegistration(d)).toEqual(registrationInput(d));
  });
  it('preserves a served index digest while verifying its ARM64 content',()=>{
    const d=taggedServiceDefinition();
    for(const c of d.imageBindings.tasks[0].containers){const e=d.imageBindings.images[c.name];c.imageDigest=e.imageDigest=e.registryDigest;}
    const r=frozenServiceRegistration(d);
    for(const c of r.containerDefinitions)expect(c.image).toBe(d.imageBindings.images[c.name].image.replace(/:[^/:]+$/,'@'+d.imageBindings.images[c.name].registryDigest));
  });
  it('accepts a single image manifest only when its digest is the served digest',()=>{
    const d=taggedServiceDefinition(),e=d.imageBindings.images['mnemo-server'];
    e.imageManifest=JSON.stringify({schemaVersion:2,mediaType:'application/vnd.oci.image.manifest.v1+json',config:{digest:'sha256:'+'a'.repeat(64)},layers:[]});e.leafManifest=e.imageManifest;
    e.registryDigest=e.imageDigest='sha256:'+createHash('sha256').update(e.imageManifest).digest('hex');d.imageBindings.tasks[0].containers[0].imageDigest=e.imageDigest;
    expect(frozenServiceRegistration(d).containerDefinitions[0].image).toContain('@'+e.imageDigest);
  });
  it.each(['nested-index','ambiguous-platform','ambiguous-shape','unsupported-type'])('rejects a hash-consistent %s manifest',kind=>{
    const d=taggedServiceDefinition(),e=d.imageBindings.images['mnemo-server'],m=JSON.parse(e.imageManifest);
    if(kind==='nested-index')m.manifests[0].mediaType='application/vnd.oci.image.index.v1+json';
    if(kind==='ambiguous-platform')m.manifests.push(structuredClone(m.manifests[0]));
    if(kind==='ambiguous-shape')m.config={digest:'sha256:'+'f'.repeat(64)};
    if(kind==='unsupported-type')m.mediaType='application/octet-stream';
    e.imageManifest=JSON.stringify(m);e.registryDigest='sha256:'+createHash('sha256').update(e.imageManifest).digest('hex');
    expect(()=>frozenServiceRegistration(d)).toThrow();
  });
  it.each(['missing-proof','manifest-hash','leaf','leaf-manifest','tag','registry','repository','task-digest','task-definition','task-cluster','task-health','draining','container-health','missing-task','duplicate-task','missing-container','duplicate-container','platform','service-definition'])('rejects %s without producing a candidate',kind=>{
    const d=taggedServiceDefinition(),b=d.imageBindings,e=b.images['mnemo-server'],t=b.tasks[0];
    if(kind==='missing-proof')delete d.imageBindings;
    if(kind==='manifest-hash')e.imageManifest+=' ';
    if(kind==='leaf')e.imageDigest='sha256:'+'f'.repeat(64);
    if(kind==='leaf-manifest')e.leafManifest+=' ';
    if(kind==='tag')e.image=e.image.replace('abcdef1','abcdef2');
    if(kind==='registry')d.taskDefinition.containerDefinitions[0].image=d.taskDefinition.containerDefinitions[0].image.replace('123456789012','0'.repeat(12));
    if(kind==='repository')d.taskDefinition.containerDefinitions[0].image=d.taskDefinition.containerDefinitions[0].image.replace('/mnemo-server:', '/other:');
    if(kind==='task-digest')t.containers[0].imageDigest='sha256:'+'e'.repeat(64);
    if(kind==='task-definition')t.taskDefinitionArn=t.taskDefinitionArn.replace(':7',':8');
    if(kind==='task-cluster')t.clusterArn+='-other';
    if(kind==='task-health')t.healthStatus='UNHEALTHY';
    if(kind==='draining')t.desiredStatus='STOPPED';
    if(kind==='container-health')t.containers[0].healthStatus='UNKNOWN';
    if(kind==='missing-task')b.tasks=[];
    if(kind==='duplicate-task')b.tasks.push(structuredClone(t));
    if(kind==='missing-container')t.containers.pop();
    if(kind==='duplicate-container')t.containers[2]=t.containers[0];
    if(kind==='platform')d.taskDefinition.runtimePlatform.cpuArchitecture='X86_64';
    if(kind==='service-definition')b.service.taskDefinition=b.service.taskDefinition.replace(':7',':8');
    expect(()=>frozenServiceRegistration(d)).toThrow();
  });
});
