import {createHash} from 'node:crypto';
import {
  NONROOT_LIMITS, NONROOT_LIMITS_HASH, parseNonrootJson,
  inspectNonrootRecord, inspectRuntimeIdentity, nonrootHash as hash,
} from './production-nonroot-contracts.mjs';

const need=(ok,code='NonrootRuntimeInvalid')=>{if(!ok)throw Error(code);};
const same=(a,b,code)=>need(hash(a)===hash(b),code);
const positive=v=>Number.isSafeInteger(v)&&v>0;
const hex=v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
const COMPONENTS=Object.freeze(['llm-proxy','mnemo-server','qwen3-embed']);
const TIME_WINDOW=300000;
const MAX_BUFFERED_ARTIFACT_BYTES=67108864;
const digest=b=>createHash('sha256').update(b).digest('hex');
const interval=(value,now)=>need(positive(now)&&positive(value.startedMs)&&positive(value.completedMs)&&value.startedMs<=value.completedMs&&value.completedMs<=now,'NonrootObservationTime');
const within=(value,outer)=>need(value.startedMs>=outer.startedMs&&value.completedMs<=outer.completedMs,'NonrootObservationWindow');

/** Resolvers are supplied by the authenticated archive/collector adapter.
 * They return raw bytes, never a parsed object or a boolean approval. This
 * module checks byte/canonical commitments but does not authenticate a cloud
 * caller or manufacture a permission from self-hashed records. */
export async function readNonrootEvidence(reference,{resolveJson,resolveBytes},json=true){
  const ref=inspectNonrootRecord(json?'JsonRef':'ByteRef',reference);
  const resolver=json?resolveJson:resolveBytes;need(typeof resolver==='function','NonrootEvidenceResolverRequired');
  const returned=await resolver(ref);need(returned instanceof Uint8Array&&returned.byteLength===ref.bytesLength&&returned.byteLength<=(json?NONROOT_LIMITS.maxProofBytes:MAX_BUFFERED_ARTIFACT_BYTES),'NonrootEvidenceBytes');
  const bytes=Buffer.from(returned);
  need(digest(bytes)===(json?ref.bytesHash:ref.sha256),'NonrootEvidenceHash');
  if(!json)return Buffer.from(bytes);
  const value=parseNonrootJson(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
  need(hash(value)===ref.canonicalHash,'NonrootEvidenceCanonicalHash');return value;
}

export async function verifyNonrootEvidenceReferences(value,options){
  hash(value);const copied=parseNonrootJson(JSON.stringify(value));
  const seen=new Set();
  async function visit(v){
    if(v===null||typeof v!=='object')return;
    const keys=Object.keys(v).sort().join();
    if(keys==='bytesHash,bytesLength,canonicalHash'||keys==='bytesLength,sha256'){
      const key=hash(v);if(seen.has(key))return;need(seen.size<1000,'NonrootEvidenceCount');seen.add(key);
      await readNonrootEvidence(v,options,keys==='bytesHash,bytesLength,canonicalHash');return;
    }
    for(const child of Object.values(v))await visit(child);
  }
  await visit(copied);
}

/** Closed schema plus optional independently selected task/image bindings.
 * A returned identity is evidence data, not an execution or signing handle. */
export function inspectNonrootRuntimeIdentity(value,{expected,now=Date.now()}={}){
  const r=inspectRuntimeIdentity(value);interval(r,now);
  need(r.completedMs-r.startedMs<=TIME_WINDOW,'NonrootObservationWindow');
  if(expected){
    for(const k of ['phase','taskKey','account','region','taskArn','taskDefinitionArn','containerName','runtimeId','image','registrationHash','launchContractHash','sourceBindingHash']){
      if(Object.hasOwn(expected,k))same(r[k],expected[k],'NonrootIdentityBinding');
    }
    if(expected.descriptorHash!==undefined)need(r.artifactBinding.kind==='data'&&r.artifactBinding.descriptorHash===expected.descriptorHash,'NonrootIdentityArtifact');
    if(expected.artifactBinding!==undefined)same(r.artifactBinding,expected.artifactBinding,'NonrootIdentityArtifact');
    // NNP=0 ancestors and managed agents require an independent classification
    // binding. A process cannot become trusted by changing its display name.
    for(const p of r.trustedLaunch){
      const permitted=expected.trustedLaunch??[];
      need(permitted.some(x=>x.kind===p.kind&&x.pid===p.pid&&x.ppid===p.ppid&&x.startTimeTicks===p.startTimeTicks&&x.executablePath===p.executablePath&&x.executableDigest===p.executableDigest&&hash(x.evidence)===hash(p.evidence)),'NonrootTrustedLaunchBinding');
    }
    for(const p of r.managed){
      const permitted=expected.managed??[];
      need(permitted.some(x=>x.managedAgentName===p.managedAgentName&&x.pid===p.pid&&x.ppid===p.ppid&&x.startTimeTicks===p.startTimeTicks&&x.executablePath===p.executablePath&&x.executableDigest===p.executableDigest&&x.sessionIdHash===p.sessionIdHash&&hash(x.classificationEvidence)===hash(p.classificationEvidence)),'NonrootManagedProcessBinding');
    }
  }
  return r;
}

function targetIdentity(record,container,target,expected,now){
  return inspectNonrootRuntimeIdentity(record,{now,expected:{phase:'target',taskKey:'backend',account:target.account,region:target.region,
    taskArn:target.taskArn,taskDefinitionArn:target.taskDefinitionArn,containerName:container.name,runtimeId:container.runtimeId,image:container.image,
    registrationHash:target.registrationHash,launchContractHash:container.launchContractHash,sourceBindingHash:expected.sourceBindingHash,
    descriptorHash:expected.descriptorHash,trustedLaunch:expected.processClassifications?.[container.name]?.trustedLaunch,
    managed:expected.processClassifications?.[container.name]?.managed}});
}
function named(values,names,name='containerName'){
  need(Array.isArray(values)&&values.length===names.length&&new Set(values.map(v=>v[name])).size===names.length&&values.every(v=>names.includes(v[name])),'NonrootContainerCoverage');
  return new Map(values.map(v=>[v[name],v]));
}
function mainProcess(identity,selector){
  need(selector&&hex(selector.entrypointIdentityHash)&&/^sha256:[a-f0-9]{64}$/.test(selector.executableDigest),'NonrootMainSelectorRequired');
  const rows=identity.application.filter(p=>p.executableDigest===selector.executableDigest&&p.entrypointIdentityHash===selector.entrypointIdentityHash);
  need(rows.length===1,'NonrootMainIdentity');return rows[0];
}

/** Verify only the typed target/time join of an already authenticated root
 * audit. The proof adapter separately validates the complete carrier/root/
 * permit record. This function does not certify a carrier or old SQL root. */
export async function verifyNonrootTargetAuditJoin(audit,options){
  let {expected,now=Date.now()}=options??{};
  hash(audit);audit=parseNonrootJson(JSON.stringify(audit));
  hash(expected);expected=parseNonrootJson(JSON.stringify(expected));
  need(expected&&hex(expected.descriptorHash)&&positive(expected.parameterVersion)&&hex(expected.deploymentSourceHash)&&hex(expected.sourceBindingHash),'NonrootExpectedBindingRequired');
  need(audit?.version===2&&audit.kind==='old-root-readonly-audit'&&audit.phase==='postdeployment-preservation'&&audit.cleanupComplete===true&&audit.targetJoin?.kind==='same-target-window','NonrootTargetJoinRequired');
  interval(audit,now);need(positive(audit.databaseObservedMs)&&positive(audit.cloudObservedMs)&&audit.databaseObservedMs>=audit.startedMs&&audit.databaseObservedMs<=audit.completedMs&&audit.cloudObservedMs>=audit.startedMs&&audit.cloudObservedMs<=audit.completedMs,'NonrootAuditTime');
  const pre=inspectNonrootRecord('TargetPreReadinessV1',audit.targetJoin.targetEvidence);
  const post=inspectNonrootRecord('TargetPostAuditV1',audit.targetJoin.postAuditObservation);
  interval(pre,now);interval(post,now);
  const target=pre.target;
  same(target,expected.target,'NonrootTargetBinding');same(post.target,target,'NonrootTargetChanged');
  need(pre.descriptorHash===expected.descriptorHash&&pre.parameterVersion===expected.parameterVersion&&pre.deploymentSourceHash===expected.deploymentSourceHash,'NonrootTargetAuthorityBinding');
  need(pre.completedMs<=audit.startedMs&&audit.completedMs<=post.startedMs&&post.completedMs-pre.startedMs<=TIME_WINDOW,'NonrootTargetAuditWindow');
  need(post.preTargetHash===hash(pre),'NonrootPreTargetHash');
  const names=target.containers.map(c=>c.name);need(hash([...names].sort())===hash(COMPONENTS),'NonrootContainerCoverage');
  const before=named(pre.identity,names),after=named(post.identityRecheck.identities,names),mains=named(post.identityRecheck.mainProcesses,names),health=named(post.identityRecheck.healthCoverage,names);
  const recheck=post.identityRecheck;
  interval(recheck,now);within(recheck,post);
  need(recheck.preTargetHash===hash(pre)&&recheck.targetBindingHash===hash(target)&&recheck.registrationHash===target.registrationHash,'NonrootIdentityRecheckBinding');
  for(const container of target.containers){
    const first=targetIdentity(before.get(container.name),container,target,expected,now),last=targetIdentity(after.get(container.name),container,target,expected,now);
    within(first,pre);within(last,post);need(last.startedMs>=audit.completedMs,'NonrootPostAuditIdentityTime');
    const selected=mainProcess(first,expected.mainProcesses?.[container.name]),current=mainProcess(last,expected.mainProcesses?.[container.name]),pair=mains.get(container.name);
    same(pair.preMain,selected,'NonrootMainSelection');same(pair.postMain,current,'NonrootMainSelection');
    for(const k of ['pid','startTimeTicks','executableDigest','entrypointIdentityHash'])need(selected[k]===current[k],'NonrootMainRestarted');
    const checked=health.get(container.name);interval(checked,now);within(checked,post);
    need(checked.startedMs>=audit.completedMs&&checked.runtimeId===container.runtimeId&&checked.registrationHash===target.registrationHash&&checked.launchContractHash===container.launchContractHash,'NonrootHealthBinding');
    same(checked.image,container.image,'NonrootHealthBinding');
    need(hex(expected.healthCommandHashes?.[container.name])&&checked.healthCommandHash===expected.healthCommandHashes[container.name],'NonrootHealthCommand');
    need(checked.processes.length>0,'NonrootHealthCoverage');
    for(const process of checked.processes){inspectNonrootRecord('ProcessIdentityV2',process);need(process.pid!==current.pid&&last.application.some(p=>hash(p)===hash(process)),'NonrootHealthCoverage');}
  }
  for(const [route,outer]of [[pre.routing,pre],[post.routingRecheck,post]]){interval(route,now);within(route,outer);need(route.targetBindingHash===hash(target),'NonrootRoutingTarget');}
  const platform=pre.platform;need(platform.taskArn===target.taskArn&&platform.taskDefinitionArn===target.taskDefinitionArn&&platform.observedMs>=pre.startedMs&&platform.observedMs<=pre.completedMs,'NonrootPlatformBinding');
  if(expected.platformVersion!==undefined)need(platform.platformVersion===expected.platformVersion,'NonrootPlatformBinding');
  const rawTask=await readNonrootEvidence(platform.rawTask,options),rawDefinition=await readNonrootEvidence(platform.rawDefinition,options);
  for(const k of ['taskArn','taskDefinitionArn','platformVersion','platformFamily'])need(rawTask[k]===platform[k],'NonrootPlatformReadback');
  need(rawDefinition.taskDefinitionArn===platform.taskDefinitionArn&&rawDefinition.runtimePlatform?.cpuArchitecture===platform.cpuArchitecture&&rawDefinition.runtimePlatform?.operatingSystemFamily===platform.operatingSystemFamily,'NonrootPlatformReadback');
  await verifyNonrootEvidenceReferences(pre,options);await verifyNonrootEvidenceReferences(post,options);
  return Object.freeze({targetBindingHash:hash(target),preTargetHash:hash(pre),postTargetHash:hash(post),startedMs:pre.startedMs,completedMs:post.completedMs});
}

export function inspectNonrootCompatibilityCertificate(value){
  const c=inspectNonrootRecord('CompatibilityCertificateV5',value),t=c.transition;
  need(c.version===5&&t.version===2&&t.kind==='image-security-nonroot-upgrade'&&t.limitsHash===NONROOT_LIMITS_HASH,'NonrootCertificateVersion');
  need(Buffer.byteLength(JSON.stringify(c))<=6000,'NonrootCertificateSize');
  for(const k of ['schemaDigest','operatorDigest','runtimeNonce'])need(c.previous.release[k]===c.current.release[k],'NonrootCertificateRootChanged');
  for(const k of ['network','credentials'])need(c.material[k].previous===c.material[k].current,'NonrootCertificateMaterialChanged');
  for(const k of ['planner','executor','backend','authority'])need(c.material[k].previous!==c.material[k].current,'NonrootCertificateMaterialChanged');
  let scope;
  for(const [side,release]of [['previous',c.previous.release],['current',c.current.release]]){
    const image=/^(\d{12})\.dkr\.ecr\.([a-z0-9-]+)\.amazonaws\.com\/mem9-on-aws\/llm-proxy@(sha256:[a-f0-9]{64})$/.exec(release.workerImage);
    need(image,'NonrootCertificateWorkerImage');const selected=image[1]+'/'+image[2];need(scope===undefined||scope===selected,'NonrootCertificateScope');scope=selected;
    need(image[3]===c.images.worker[side+'Root'],'NonrootCertificateWorkerImage');
  }
  for(const image of Object.values(c.images))need(image.previousRoot!==image.previousChild&&image.currentRoot!==image.currentChild&&image.previousRoot!==image.currentRoot&&image.previousChild!==image.currentChild,'NonrootCertificateImages');
  for(const key of ['previousRoot','currentRoot','previousChild','currentChild'])need(c.images.worker[key]===c.images['llm-proxy'][key],'NonrootCertificateWorkerImage');
  const [account,region]=scope.split('/'),backend=c.current.backendBinding,prefix='arn:aws:ecs:'+region+':'+account+':';
  need(backend.taskArn.startsWith(prefix+'task/')&&backend.taskDefinitionArn.startsWith(prefix+'task-definition/'),'NonrootCertificateScope');
  for(const container of backend.containers)need([c.images[container.name].currentRoot,c.images[container.name].currentChild].includes(container.imageDigest),'NonrootCertificateBackendImage');
  return Object.freeze({...t,dataReleaseHash:c.dataReleaseHash,parentProofHash:c.parentProofHash});
}

export function inspectNonrootContinuationWitness(value,{certificate,parentProofHash,sourceTree}={}){
  const w=inspectNonrootRecord('ContinuationWitnessV2',value);
  need(w.version===2,'NonrootWitnessVersion');
  if(certificate){const c=inspectNonrootCompatibilityCertificate(certificate);need(w.certificateHash===hash(certificate)&&w.descriptorHash===c.dataReleaseHash&&w.readinessHash===c.runtimeEvidenceHash&&w.parentProofHash===c.parentProofHash,'NonrootWitnessBinding');}
  if(parentProofHash!==undefined)need(w.parentProofHash===parentProofHash,'NonrootWitnessBinding');
  if(sourceTree!==undefined)need(w.sourceTree===sourceTree,'NonrootWitnessBinding');return w;
}

export async function verifyNonrootRuntimeReadiness(value,options){
  const r=inspectNonrootRecord('RuntimeReadinessV2',value),{expected,now=Date.now()}=options??{};
  need(expected,'NonrootExpectedBindingRequired');interval(r,now);
  for(const k of ['descriptorHash','proofHash','deploymentSourceHash','resolvedTaskPlanHash'])need(hex(expected[k])&&r[k]===expected[k],'NonrootReadinessBinding');
  const joined=await verifyNonrootTargetAuditJoin(r.postdeployRootAudit,options);
  need(r.startedMs<=joined.startedMs&&r.completedMs>=joined.completedMs&&r.completedMs-r.startedMs<=TIME_WINDOW,'NonrootReadinessWindow');
  same(r.dependencyAndRoutingChecks,r.postdeployRootAudit.targetJoin.postAuditObservation.routingRecheck,'NonrootReadinessRouting');
  await verifyNonrootEvidenceReferences(r,options);
  return Object.freeze({...joined,runtimeEvidenceHash:hash(r),operatorEvidenceHash:r.operators.canonicalHash,descriptorHash:r.descriptorHash,deploymentSourceHash:r.deploymentSourceHash});
}
