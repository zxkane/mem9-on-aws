import {createHash} from 'node:crypto';
import {canaryEvidenceHash as hash} from './lib/production-canary-verification.mjs';
import {NONROOT_LIMITS_HASH} from './lib/production-nonroot-contracts.mjs';

export const h=n=>n.toString(16).padStart(64,'0');
export const digest=n=>'sha256:'+h(n);
export const bytesHash=bytes=>createHash('sha256').update(bytes).digest('hex');
export const COMPONENTS=['llm-proxy','mnemo-server','qwen3-embed'];
export function asNonrootCertificate(value){
  const c=structuredClone(value);c.version=5;
  c.transition={...c.transition,version:2,kind:'image-security-nonroot-upgrade',limitsHash:NONROOT_LIMITS_HASH,runtimeEvidenceHash:h(801),operatorEvidenceHash:h(802),deploymentSourceHash:h(803)};
  return c;
}
export function evidenceFixture(){
  const records=new Map();
  const json=value=>{const bytes=Buffer.from(JSON.stringify(value));const ref={bytesHash:bytesHash(bytes),canonicalHash:hash(value),bytesLength:bytes.length};records.set(ref.bytesHash,bytes);return ref;};
  const bytes=value=>{const raw=Buffer.from(value),ref={sha256:bytesHash(raw),bytesLength:raw.length};records.set(ref.sha256,raw);return ref;};
  const resolveJson=async ref=>records.get(ref.bytesHash),resolveBytes=async ref=>records.get(ref.sha256);
  return {records,json,bytes,resolveJson,resolveBytes};
}

/** All task, process, source and timing records are synthetic test inputs. */
export function nonrootRuntimeFixture(){
  const archive=evidenceFixture(),now=1800000000000,account='123456789012',region='us-west-2';
  const clusterArn=`arn:aws:ecs:${region}:${account}:cluster/mem9-on-aws-prod-Fixture`;
  const taskArn=clusterArn.replace(':cluster/',':task/')+'/'+'a'.repeat(32);
  const taskDefinitionArn=`arn:aws:ecs:${region}:${account}:task-definition/mem9-on-aws-prod-Fixture-Backend:2`;
  const descriptorHash=h(1),proofHash=h(2),deploymentSourceHash=h(3),sourceBindingHash=h(4),registrationHash=h(5);
  const image=i=>({rootDigest:digest(100+i),arm64Digest:digest(200+i),configDigest:digest(300+i)});
  const process=(pid,kind='node')=>({pid,ppid:1,startTimeTicks:pid*100,executablePath:'/usr/local/bin/'+kind,executableDigest:digest(pid),entrypointIdentityHash:h(pid+500),uid:[1000,1000,1000,1000],gid:[1000,1000,1000,1000],groups:[1000],capInh:'0000000000000000',capPrm:'0000000000000000',capEff:'0000000000000000',capBnd:'0000000000000000',capAmb:'0000000000000000',noNewPrivs:1});
  const target={account,region,clusterArn,serviceName:'Mem9Server',serviceDeploymentId:'ecs-svc/fixture',taskArn,taskDefinitionArn,registrationHash,
    containers:COMPONENTS.map((name,i)=>({name,runtimeId:'runtime-'+name,image:image(i),launchContractHash:h(20+i)}))};
  const identity=(i,after=false)=>{
    const c=target.containers[i],startedMs=now-(after?3000:10000),completedMs=startedMs+1000;
    const application=[process(10+i),process((after?40:30)+i)];
    return {version:2,kind:'application-process-identity',phase:'target',taskKey:'backend',account,region,taskArn,taskDefinitionArn,containerName:c.name,runtimeId:c.runtimeId,image:c.image,
      registrationHash,launchContractHash:c.launchContractHash,sourceBindingHash,
      artifactBinding:{kind:'data',descriptorHash,launchContractHash:c.launchContractHash},collectorCodeHash:h(40),
      sessionBinding:archive.json({taskArn,runtimeId:c.runtimeId}),startedMs,completedMs,application,trustedLaunch:[],managed:[],
      samples:archive.json(application),coverage:archive.json({main:application[0],health:application.slice(1)}),result:'pass'};
  };
  const routing=(startedMs,completedMs)=>({version:1,kind:'target-private-routing',targetBindingHash:hash(target),probeSource:archive.json({source:h(55)}),routeObservations:archive.json({target:taskArn}),targetAttribution:archive.json(target),dependencyChecks:archive.json({target:taskArn}),startedMs,completedMs,result:'pass'});
  const identities=COMPONENTS.map((_,i)=>identity(i));
  const pre={version:1,kind:'target-before-root-audit',descriptorHash,parameterVersion:2,deploymentSourceHash,target,identity:identities,routing:routing(now-9000,now-8000),
    platform:{version:1,kind:'actual-runtime-platform',taskArn,taskDefinitionArn,launchType:'FARGATE',platformVersion:'1.4.0',platformFamily:'Linux',cpuArchitecture:'ARM64',operatingSystemFamily:'LINUX',rawTask:archive.json({taskArn,taskDefinitionArn,platformVersion:'1.4.0',platformFamily:'Linux'}),rawDefinition:archive.json({taskDefinitionArn,runtimePlatform:{cpuArchitecture:'ARM64',operatingSystemFamily:'LINUX'}}),independentHealthProbe:archive.json({taskArn}),observedMs:now-8000},
    rawObservations:archive.json(target),startedMs:now-11000,completedMs:now-7000};
  const postIdentities=COMPONENTS.map((_,i)=>identity(i,true));
  const recheck={version:1,kind:'typed-post-audit-target-identities',preTargetHash:hash(pre),targetBindingHash:hash(target),registrationHash,identities:postIdentities,
    mainProcesses:COMPONENTS.map((containerName,i)=>({containerName,preMain:identities[i].application[0],postMain:postIdentities[i].application[0]})),
    healthCoverage:COMPONENTS.map((containerName,i)=>({containerName,runtimeId:target.containers[i].runtimeId,image:target.containers[i].image,registrationHash,launchContractHash:target.containers[i].launchContractHash,healthCommandHash:h(60+i),processes:postIdentities[i].application.slice(1),startedMs:now-3000,completedMs:now-2000})),startedMs:now-3000,completedMs:now-2000};
  const post={version:1,kind:'same-target-after-root-audit',preTargetHash:hash(pre),target,identityRecheck:recheck,routingRecheck:routing(now-3000,now-2000),rawObservations:archive.json(target),startedMs:now-3500,completedMs:now-1000};
  const audit={version:2,kind:'old-root-readonly-audit',phase:'postdeployment-preservation',root:{identity:h(90)},predecessorParameter:archive.json({Version:1}),oldMaterial:archive.json({hash:h(91)}),oldCertificate:archive.json({hash:h(92)}),carrierBuild:archive.json({hash:h(93)}),preauditPermit:archive.json({hash:h(94)}),taskObservation:archive.json({taskArn:'carrier-fixture'}),carrierIdentity:archive.json({hash:h(95)}),targetJoin:{kind:'same-target-window',targetEvidence:pre,postAuditObservation:post},runtimeState:archive.json({paused:true}),extensionMaintenance:archive.json({hash:h(96)}),schedulerState:archive.json({paused:true}),credentialBindings:archive.json({hash:h(97)}),writerCensus:archive.json({hash:h(98)}),ownershipFence:archive.json({hash:h(99)}),startedMs:now-6000,databaseObservedMs:now-5500,cloudObservedMs:now-5000,completedMs:now-4000,cleanupComplete:true};
  const expected={descriptorHash,parameterVersion:2,proofHash,deploymentSourceHash,sourceBindingHash,target,
    mainProcesses:Object.fromEntries(identities.map(r=>[r.containerName,{executableDigest:r.application[0].executableDigest,entrypointIdentityHash:r.application[0].entrypointIdentityHash}])),
    healthCommandHashes:Object.fromEntries(COMPONENTS.map((name,i)=>[name,h(60+i)]))};
  return {...archive,now,account,region,target,pre,post,audit,expected,process};
}
