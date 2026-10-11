/** Pure-data full proof composition. No network/filesystem/issuer callbacks.
 * expected pins MUST come from independently authenticated source, graph,
 * destination/virtual-filesystem and policy evidence. A serialized graph claim
 * is never made authoritative merely by hashing its own fields here.
 */
import {createHash} from 'node:crypto';
import {canaryEvidenceHash as hash} from './production-canary-verification.mjs';
import {captureDataReleaseScans,verifyDataReleaseArtifact} from './production-data-evidence.mjs';
import {inspectDataRelease,requireActiveDataRelease} from './production-data-release.mjs';
import {verifyCanaryMaterialTransition} from './production-canary-material-transition.mjs';
import {normalizeCanaryAuthority,verifyLegacyCanaryMaterial} from './production-canary-material-integrity.mjs';
import {normalizeCanaryTask,projectConfiguredCanaryBackend} from './production-canary-material.mjs';
import {inspectImageCopyVerification} from './production-image-graph.mjs';
import {imageFilesystemProof,inspectImageFilesystemEvidence,imageFilesystemVerificationKind,imageFilesystemVerificationBinding} from './production-image-filesystem.mjs';
import {IMAGE_TRANSITION_KIND,IMAGE_TRANSITION_COMPONENTS as COMPONENTS,IMAGE_TRANSITION_MATERIALS as MATERIALS,IMAGE_TRANSITION_LIMITS as LIMITS,IMAGE_TRANSITION_LIMITS_HASH as LIMITS_HASH,inspectImageTransitionDescriptorCommitment,inspectImageTransitionCertificate} from './production-image-transition.mjs';

const fail=()=>{throw Error('ImageTransitionProofInvalid');},need=v=>{if(!v)fail();};
const sha=text=>createHash('sha256').update(text).digest('hex');
const hex=(v,n=64)=>typeof v==='string'&&new RegExp('^[a-f0-9]{'+n+'}$').test(v);
const record=v=>v!==null&&typeof v==='object'&&!Array.isArray(v)&&[Object.prototype,null].includes(Object.getPrototypeOf(v))&&Reflect.ownKeys(v).every(k=>typeof k==='string'&&Object.hasOwn(Object.getOwnPropertyDescriptor(v,k),'value')&&Object.getOwnPropertyDescriptor(v,k).enumerable);
const exact=(v,keys)=>record(v)&&Reflect.ownKeys(v).length===keys.length&&keys.every(k=>Object.hasOwn(v,k));
const same=(a,b)=>hash(a)===hash(b),freeze=v=>{if(v&&typeof v==='object'){Object.freeze(v);Object.values(v).forEach(freeze);}return v;};
const contexts=new WeakMap(),authorizations=new WeakMap();
const inputKeys=['version','kind','limits','predecessorText','bootstrapProof','dataOrigin','control','dataInputs','images','artifacts','graph','filesystem','scans','policy','vendors','buildEvidence'];
const expectedKeys=['predecessorHash','parentProofHash','bootstrapProofHash','expectedBootstrap','dataOriginSourceEvidenceHash','buildCommitHash','controlSourceEvidenceHash','dataInputsHash','graphHash','filesystemHash','policyHash','buildEvidenceHash'];
const proofKeys=[...inputKeys,'bootstrapPins','graphInventory','destinationReadback','filesystemEvidence','observedMs','projectionHash','targetBuildInputsHash','targetSecurityEvidenceHash'];
export const IMAGE_TRANSITION_REVIEW_KEYS=Object.freeze(['version','kind','decision','controlSourceTree','sourceEvidenceHash','dataOriginSourceEvidenceHash','parentProofHash','buildInputsHash','securityEvidenceHash','freshBuildSecurityHash','policySourcesHash','artifactPolicyHash','imageTransitionProofHash','reviewedMs','expiresMs']);
function json(v,depth=0,seen=new Set()){
 need(depth<=LIMITS.maxJsonDepth);
 if(v===null||typeof v==='boolean'||typeof v==='string')return;
 if(typeof v==='number'){need(Number.isFinite(v));return;}
 need(!seen.has(v));seen.add(v);
 if(Array.isArray(v)){need(Reflect.ownKeys(v).length===v.length+1);for(let i=0;i<v.length;i++){need(Object.hasOwn(Object.getOwnPropertyDescriptor(v,String(i))??{},'value'));json(v[i],depth+1,seen);}}
 else{need(record(v));for(const x of Object.values(v))json(x,depth+1,seen);}seen.delete(v);
}
/** Duplicate decoded keys are rejected before JSON.parse can erase them. */
export function parseImageTransitionJson(text){
 need(typeof text==='string'&&text.isWellFormed());let i=0;
 const ws=()=>{while(/[\x20\t\r\n]/.test(text[i]??'!'))i++;};
 const str=()=>{const start=i;need(text[i++]==='"');let escaped=false;while(i<text.length){const c=text[i++];if(!escaped&&c==='"')return JSON.parse(text.slice(start,i));if(escaped)escaped=false;else if(c==='\\')escaped=true;}fail();};
 const value=depth=>{need(depth<=LIMITS.maxJsonDepth);ws();const c=text[i];
  if(c==='{'){i++;ws();const keys=new Set();if(text[i]==='}'){i++;return;}while(true){ws();const k=str();need(!keys.has(k));keys.add(k);ws();need(text[i++]===':');value(depth+1);ws();if(text[i]==='}'){i++;return;}need(text[i++]===',');}}
  if(c==='['){i++;ws();if(text[i]===']'){i++;return;}while(true){value(depth+1);ws();if(text[i]===']'){i++;return;}need(text[i++]===',');}}
  if(c==='"'){str();return;}const m=/^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(text.slice(i));need(m);i+=m[0].length;
 };value(0);ws();need(i===text.length);const result=JSON.parse(text);json(result);return result;
}
const rootFields=['stage','account','region','runtimeNonce','generation','targetsHash','parentProofHash','backendBindingHash','schemaDigest','operatorDigest'];
const release=s=>({sourceTree:s.sourceTree,coordinatorDigest:s.coordinatorDigest,sourceTag:s.sourceTag,workerImage:s.workerImage,...s.runtime});
function snapshot(value){
 if(typeof value!=='string')json(value);const text=typeof value==='string'?value:JSON.stringify(value),s=parseImageTransitionJson(text);
 need(Buffer.byteLength(text)<=LIMITS.maxManifestBytes&&s.version===2&&hex(s.revision,40)&&hex(s.sourceTree,40)&&hex(s.coordinatorDigest)&&hex(s.generation));
 need(exact(s,['version','observedAt','account','region','revision','sourceTree','coordinatorDigest','generation','sourceTag','workerImage','runtime','components','definitions','backendBinding','backendTask','authority','scheduler','credentials','network','material',...(Object.hasOwn(s,'dataRelease')?['dataRelease']:[]),...(Object.hasOwn(s,'controlSourceTag')?['controlSourceTag']:[])]));
 need(exact(s.components,['worker',...COMPONENTS])&&exact(s.definitions,['planner','executor','backend'])&&exact(s.runtime,['schemaDigest','operatorDigest','runtimeNonce'])&&exact(s.material,MATERIALS)&&exact(s.scheduler,['roleArn','groupName']));
 for(const c of Object.values(s.components))need(exact(c,['registryId','repositoryName','rootDigest','arm64Digest']));
 if(s.dataRelease)need(exact(s.dataRelease,['data','hash','parameterVersion']));
 need(typeof s.observedAt==='string'&&new Date(s.observedAt).toISOString()===s.observedAt);
 const material=verifyLegacyCanaryMaterial(s),task=s.backendTask,d=s.definitions.backend;
 need(task.launchType==='FARGATE'&&task.healthStatus==='HEALTHY'&&task.cpu===d.cpu&&task.memory===d.memory&&task.containers.every(c=>c.healthStatus==='HEALTHY')&&task.attributes?.filter(a=>a.name==='ecs.cpu-architecture').length===1&&task.attributes.find(a=>a.name==='ecs.cpu-architecture').value==='arm64');
 if(task.overrides!==undefined){const o=task.overrides;need(record(o)&&Object.keys(o).every(k=>['containerOverrides','taskRoleArn','executionRoleArn','cpu','memory','inferenceAcceleratorOverrides','ephemeralStorage'].includes(k)));
  for(const k of ['taskRoleArn','executionRoleArn','cpu','memory'])if(o[k]!==undefined)need(String(o[k])===String(d[k]));
  if(o.ephemeralStorage!==undefined)need(same(o.ephemeralStorage,d.ephemeralStorage));
  need(o.inferenceAcceleratorOverrides===undefined||Array.isArray(o.inferenceAcceleratorOverrides)&&o.inferenceAcceleratorOverrides.length===0);
  if(o.containerOverrides!==undefined)need(Array.isArray(o.containerOverrides)&&o.containerOverrides.every(c=>exact(c,['name'])&&d.containerDefinitions.some(v=>v.name===c.name))&&new Set(o.containerOverrides.map(c=>c.name)).size===o.containerOverrides.length);
 }
 return {s,material,text};
}
function neutral(s){
 const catalog=new Map([[s.workerImage,s.components.worker]]);for(const c of s.definitions.backend.containerDefinitions)catalog.set(c.image,s.components[c.name]);
 const result={};for(const kind of ['planner','executor','backend']){
  const normalized=kind==='backend'?projectConfiguredCanaryBackend(s.definitions[kind],{account:s.account,region:s.region,images:catalog}):{configuration:normalizeCanaryTask(s.definitions[kind],{account:s.account,region:s.region,images:catalog})};
  for(const c of normalized.configuration.containerDefinitions){const component=kind==='backend'?c.name:'llm-proxy';need(COMPONENTS.includes(component)&&c.image===s.components[component].arm64Digest);c.image='image-component:'+component;}
  result[kind]=normalized;
 }
 return result;
}
function checkedTime(at,now,max=86400000){need(Number.isSafeInteger(now)&&now>0&&Number.isSafeInteger(at)&&at>0&&at<=now&&now-at<=max);}
function targetPresence(value,state,now){
 json(value);need(exact(value,['observedMs','artifacts'])&&exact(value.artifacts,COMPONENTS));checkedTime(value.observedMs,now,300000);
 for(const name of COMPONENTS){
  const responses=value.artifacts[name];need(exact(responses,['root','child']));
  const parse=v=>typeof v==='string'?parseImageTransitionJson(v):v;
  verifyDataReleaseArtifact(parse(responses.root),parse(responses.child),{account:state.predecessor.account,repositoryName:'mem9-on-aws/'+name,...state.proof.images[name]});
 }
 return freeze(structuredClone(value));
}

/** Reuses the frozen normalizer with a read-only structural scan context.
 * This local context is never returned/issued as a data authorization. */
async function scans(input,predecessor,phase,now){
 const pages=input.scans[phase];need(exact(pages,COMPONENTS));const positions=new Map(),seen=new Set();
 const data={...predecessor,stage:phase==='preview'?'pr-1':'prod',images:phase==='old'?predecessor.images:input.images};
 data.dataSourceTag=(data.stage==='prod'?'mem9-':'pr-')+data.dataRevision.slice(0,7);
 const result=await captureDataReleaseScans({data,now,readEcr:async(operation,request)=>{
  need(operation==='describe-image-scan-findings');const component=request.repositoryName.split('/').at(-1),list=pages[component],index=positions.get(component)??0;
  need(Array.isArray(list)&&list.length>0&&list.length<=LIMITS.maxScanPagesPerObservation&&index<list.length);const raw=list[index];need(typeof raw==='string'&&Buffer.byteLength(raw)<=LIMITS.maxBufferPerStreamBytes);
  const response=parseImageTransitionJson(raw);need(!seen.has(component+'\0'+sha(raw)));seen.add(component+'\0'+sha(raw));positions.set(component,index+1);return response;
 }});
 for(const name of COMPONENTS){need(positions.get(name)===pages[name].length);const f=result.scans[name].findings;need(new Set(f.map(x=>hash(x))).size===f.length);for(const finding of f)need(new Set(finding.attributes.map(a=>a.key)).size===finding.attributes.length);}
 return result;
}
function policyEvidence(input,normalized,now){
 const p=input.policy;need(exact(p,['version','kind','schema','policySources','requiredControls','rules','fixed','open'])&&p.version===1&&p.kind==='image-security-policy'&&p.schema==='ecr-basic-full-findings-v1');
 need(Array.isArray(p.policySources)&&p.policySources.length>0&&Array.isArray(p.requiredControls)&&p.requiredControls.length>0&&exact(p.rules,COMPONENTS));
 const policyHashes=new Set();for(const s of p.policySources){need(exact(s,['path','text'])&&typeof s.path==='string'&&typeof s.text==='string');policyHashes.add(sha(s.text));}
 need(new Set(p.policySources.map(s=>s.path)).size===p.policySources.length);
 for(const c of p.requiredControls)need(exact(c,['clause','policySourceHash','evidenceHash'])&&typeof c.clause==='string'&&c.clause.length>0&&policyHashes.has(c.policySourceHash)&&hex(c.evidenceHash));
 need(new Set(p.requiredControls.map(c=>c.policySourceHash+'\0'+c.clause)).size===p.requiredControls.length);
 need(same(input.buildEvidence.controls,p.requiredControls));
 const vendors=new Map();need(Array.isArray(input.vendors));
 for(const v of input.vendors){need(exact(v,['version','cve','package','suite','packageVersion','status','observedMs','source','rawText','rawHash'])&&v.version===1&&/^CVE-[0-9]{4}-[0-9]{4,}$/.test(v.cve)&&['fixed','unfixed'].includes(v.status)&&typeof v.source==='string'&&v.source.startsWith('https://')&&typeof v.rawText==='string'&&sha(v.rawText)===v.rawHash);checkedTime(v.observedMs,now);need(!vendors.has(hash(v)));vendors.set(hash(v),v);}
 for(const name of COMPONENTS){const rule=p.rules[name];need(exact(rule,['oldHash','targetHash'])&&hex(rule.oldHash)&&hex(rule.targetHash));need(hash(normalized.old.scans[name].findings)===rule.oldHash&&hash(normalized.preview.scans[name].findings)===rule.targetHash&&hash(normalized.destination.scans[name].findings)===rule.targetHash);}
 const fixed=p.fixed;need(exact(fixed,['component','findingHash','package','oldVersion','targetVersion','cve','vendorHash'])&&fixed.component==='mnemo-server'&&fixed.package==='zlib');
 const old=normalized.old.scans[fixed.component].findings,target=normalized.destination.scans[fixed.component].findings;
 need(old.length===1&&target.length===0&&hash(old[0])===fixed.findingHash&&old[0].name===fixed.cve&&old[0].severity==='HIGH');
 const attrs=Object.fromEntries(old[0].attributes.map(a=>[a.key,a.value]));need(attrs.package_name===fixed.package&&attrs.package_version===fixed.oldVersion);
 const vendor=vendors.get(fixed.vendorHash);need(vendor&&vendor.status==='fixed'&&vendor.suite==='alpine'&&vendor.cve===fixed.cve&&vendor.package===fixed.package&&vendor.packageVersion===fixed.targetVersion);
 const fs=input.filesystem;need(exact(fs,['version','kind','imageDigest','graphHash','path','databaseText','databaseHash'])&&fs.version===1&&fs.kind==='effective-apk-database'&&fs.imageDigest===input.images['mnemo-server'].arm64Digest&&fs.graphHash===hash(input.graph)&&fs.path==='/lib/apk/db/installed'&&typeof fs.databaseText==='string'&&Buffer.byteLength(fs.databaseText)<=LIMITS.maxPackageDatabaseBytes&&sha(fs.databaseText)===fs.databaseHash);
 const packages=fs.databaseText.trim().split(/\n\s*\n/).map(block=>block.split('\n')),zlib=packages.filter(lines=>lines.includes('P:zlib'));need(zlib.length===1&&zlib[0].filter(l=>l.startsWith('P:')).length===1&&zlib[0].filter(l=>l.startsWith('V:')).length===1&&zlib[0].includes('V:'+fixed.targetVersion));
 need(Array.isArray(p.open)&&p.open.length===4&&p.rules['llm-proxy'].targetHash===p.rules['qwen3-embed'].targetHash);const remaining=new Map();for(const name of COMPONENTS.filter(n=>n!=='mnemo-server')){need(p.rules[name].oldHash===p.rules[name].targetHash&&normalized.destination.scans[name].findings.length===2);for(const f of normalized.destination.scans[name].findings)remaining.set(name+'\0'+hash(f),f);}
 need(p.open.length===remaining.size);for(const d of p.open){need(exact(d,['component','findingHash','package','packageVersion','cve','vendorHash','disposition','controls'])&&d.disposition==='OPEN_UNCHANGED_REQUIRED_CONTROLS_SATISFIED'&&same(d.controls,p.requiredControls));const key=d.component+'\0'+d.findingHash,f=remaining.get(key),v=vendors.get(d.vendorHash);need(f&&f.name===d.cve&&f.severity==='HIGH'&&v&&v.status==='unfixed'&&v.suite==='trixie'&&v.cve===d.cve&&v.package===d.package&&v.packageVersion===d.packageVersion);const a=Object.fromEntries(f.attributes.map(x=>[x.key,x.value]));need(a.package_name===d.package&&a.package_version===d.packageVersion);remaining.delete(key);}
 need(remaining.size===0);
}
function buildEvidence(input){
 const b=input.buildEvidence;need(exact(b,['version','logText','logHash','controls'])&&b.version===1&&typeof b.logText==='string'&&sha(b.logText)===b.logHash);
 const lines=b.logText.split('\n').map(l=>l.replace(/^\d{4}-\d\d-\d\dT\S+Z /,''));
 const starts=lines.flatMap((line,index)=>/^\[command\]\S+\/docker buildx build /.test(line)?[index]:[]);
 const sections=starts.map((start,i)=>lines.slice(start,starts[i+1]??lines.length)),option=(tokens,key)=>tokens.flatMap((t,i)=>t===key?[tokens[i+1]]:[]);
 for(const component of COMPONENTS){
  const selected=sections.filter(rows=>option(rows[0].split(/\s+/),'--file').includes('docker/'+component+'/Dockerfile'));need(selected.length===1);
  const rows=selected[0],tokens=rows[0].split(/\s+/),tag='mem9-on-aws/preview/'+component+':pr-'+input.dataOrigin.revision.slice(0,7);
  need(tokens.filter(t=>t==='--pull').length===1&&tokens.filter(t=>t==='--push').length===1&&same(option(tokens,'--platform'),['linux/arm64'])&&option(tokens,'--tag').some(t=>t.endsWith('/'+tag)));
  need(same(option(tokens,'--no-cache-filter').flatMap(v=>v.split(',')).sort(),component==='mnemo-server'?['builder','runtime']:['runtime']));
  for(const stage of component==='mnemo-server'?['builder','runtime']:['runtime']){
   const ids=new Set(rows.flatMap(row=>{const m=/^#([0-9]+) \[([^\]]+)\] RUN (.*)$/.exec(row);return m&&/(?:apk upgrade|apt-get dist-upgrade)/.test(m[3])&&(m[2].startsWith(stage+' ')||stage==='runtime'&&/^\d+\/\d+$/.test(m[2].trim()))?[m[1]]:[];}));need(ids.size===1);
   const id=[...ids][0],terminal=rows.filter(row=>new RegExp('^#'+id+' (?:DONE|CACHED|ERROR)(?: |$)').test(row));need(terminal.length===1&&new RegExp('^#'+id+' DONE(?: |$)').test(terminal[0]));
  }
  const image=input.images[component];need(rows.some(row=>row.includes('pushing manifest for ')&&row.includes('/'+tag+'@'+image.rootDigest)&&row.endsWith(' done'))&&rows.some(row=>row.trim()==='"containerimage.digest": "'+image.rootDigest+'",')&&rows.some(row=>row.includes(' exporting manifest '+image.arm64Digest+' ')&&!row.includes('attestation')));
 }
}

/** Shared strict artifact predicates for the explicit nonroot route. This is
 * evidence verification only: it creates no proof or authorization context. */
export async function verifyImageTransitionArtifactSecurity(input,{predecessor,now}){
 json(input);json(predecessor);need(exact(input,['images','artifacts','dataOrigin','scans','policy','vendors','buildEvidence','graph','filesystem']));
 need(exact(input.images,COMPONENTS)&&exact(input.artifacts,COMPONENTS)&&exact(input.scans,['old','preview','destination']));
 const artifacts={};
 for(const name of COMPONENTS){
  const a=input.artifacts[name];need(exact(a,['root','child']));
  artifacts[name]=verifyDataReleaseArtifact(parseImageTransitionJson(a.root),parseImageTransitionJson(a.child),{account:predecessor.account,repositoryName:'mem9-on-aws/'+name,...input.images[name]});
 }
 buildEvidence(input);const normalized={};
 for(const phase of ['old','preview','destination'])normalized[phase]=await scans(input,predecessor,phase,now);
 policyEvidence(input,normalized,now);
 return freeze({artifacts,normalized,artifactPolicyHash:hash(input.policy),policySourcesHash:hash(input.policy.policySources.map(s=>({path:s.path,hash:sha(s.text)}))),buildEvidenceHash:hash(input.buildEvidence)});
}

async function derive(input,expected,now,{graphVerification,filesystemVerification,allowArchive=false}){
 json(input);json(expected);need(exact(input,inputKeys)&&exact(expected,expectedKeys));for(const k of expectedKeys.filter(k=>k!=='expectedBootstrap'))need(hex(expected[k]));
 input=structuredClone(input);expected=structuredClone(expected);
 need(input.version===1&&input.kind==='image-security-upgrade-proof'&&same(input.limits,LIMITS));
 const predecessor=parseImageTransitionJson(input.predecessorText);need(hash(predecessor)===expected.predecessorHash&&predecessor.version===1);
 inspectDataRelease(predecessor,{stage:'prod',account:predecessor.account,region:predecessor.region,controlSourceTree:predecessor.controlSourceTree});
 await verifyCanaryMaterialTransition(input.bootstrapProof,{proofHash:expected.bootstrapProofHash,expectedBootstrap:expected.expectedBootstrap});
 const original=snapshot(input.bootstrapProof.previousText),serving=snapshot(input.bootstrapProof.currentText),parent=input.bootstrapProof.parent;
 need(Number.isSafeInteger(parent.changedRows)&&parent.changedRows>=0&&parent.changedRows<20&&Number.isSafeInteger(parent.receipts)&&parent.receipts>=0&&hex(parent.validationId,32)&&hex(parent.conservationHash));
 need(hash(parent)===expected.parentProofHash&&predecessor.parentProofHash===expected.parentProofHash&&predecessor.backendBindingHash===parent.backendBindingHash&&same(serving.s.dataRelease.data,predecessor));
 const origin=input.dataOrigin,control=input.control;
 need(exact(origin,['revision','sourceTree','sourceHead','sourceEvidence','buildCommit'])&&[origin.revision,origin.sourceTree,origin.sourceHead].every(v=>hex(v,40))&&hash(origin.sourceEvidence)===expected.dataOriginSourceEvidenceHash);
 const commit=origin.buildCommit;need(exact(commit,['sha','tree','parents'])&&hash(commit)===expected.buildCommitHash&&commit.sha===origin.revision&&commit.tree===origin.sourceTree&&Array.isArray(commit.parents)&&commit.parents.length>0&&commit.parents.length<=16&&commit.parents.every(p=>hex(p,40))&&new Set(commit.parents).size===commit.parents.length&&commit.parents.includes(origin.sourceHead));
 need(origin.sourceEvidence.controlRevision===origin.sourceHead&&origin.sourceEvidence.controlTree===origin.sourceTree&&origin.sourceEvidence.build.revision===origin.revision&&origin.sourceEvidence.build.tree===origin.sourceTree&&origin.sourceEvidence.build.tag==='pr-'+origin.revision.slice(0,7));
 need(exact(control,['revision','sourceTree','baseRevision','sourceEvidence'])&&[control.revision,control.sourceTree,control.baseRevision].every(v=>hex(v,40))&&hash(control.sourceEvidence)===expected.controlSourceEvidenceHash&&control.sourceEvidence.controlRevision===control.revision&&control.sourceEvidence.controlTree===control.sourceTree&&control.sourceEvidence.baseRevision===control.baseRevision);
 const {repository,prNumber}=control.sourceEvidence;
 need(typeof repository==='string'&&!/\s/.test(repository)&&/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?\/[A-Za-z0-9_.-]{1,100}$/.test(repository)&&!['.','..'].includes(repository.split('/')[1])&&Number.isSafeInteger(prNumber)&&prNumber>0);
 const inputs=input.dataInputs;need(exact(inputs,['version','recipe','controlRecipe','protectedInputs','controlProtectedInputs'])&&inputs.version===1&&hash(inputs)===expected.dataInputsHash&&same(inputs.recipe,inputs.controlRecipe)&&same(inputs.protectedInputs,inputs.controlProtectedInputs)&&Array.isArray(inputs.protectedInputs)&&inputs.protectedInputs.length>0);
 for(const f of inputs.protectedInputs)need(exact(f,['path','sha256'])&&typeof f.path==='string'&&!f.path.startsWith('/')&&!f.path.split('/').includes('..')&&hex(f.sha256));need(new Set(inputs.protectedInputs.map(f=>f.path)).size===inputs.protectedInputs.length);
 need(exact(input.images,COMPONENTS)&&exact(input.artifacts,COMPONENTS));const artifacts={};
 for(const name of COMPONENTS){const image=input.images[name],a=input.artifacts[name];need(exact(image,['rootDigest','arm64Digest'])&&exact(a,['root','child'])&&origin.sourceEvidence.build.images[name]===image.rootDigest);need(image.rootDigest!==predecessor.images[name].rootDigest&&image.arm64Digest!==predecessor.images[name].arm64Digest);artifacts[name]=verifyDataReleaseArtifact(parseImageTransitionJson(a.root),parseImageTransitionJson(a.child),{account:predecessor.account,repositoryName:'mem9-on-aws/'+name,...image});}
 const graph=input.graph;need(exact(graph,['version','limitsHash','account','region','images','contentHash','destinationContentHash','inventoryHash','destinationReadbackHash','startedMs','completedMs'])&&graph.version===1&&graph.limitsHash===LIMITS_HASH&&graph.account===predecessor.account&&graph.region===predecessor.region&&same(graph.images,input.images)&&graph.contentHash===graph.destinationContentHash&&['contentHash','inventoryHash','destinationReadbackHash'].every(k=>hex(graph[k]))&&hash(graph)===expected.graphHash);
 const copy=inspectImageCopyVerification(graphVerification),filesystem=inspectImageFilesystemEvidence(filesystemVerification);
 need(copy.kind==='live-copy-evidence'||allowArchive&&copy.kind==='archived-copy-evidence');
 const verificationOrigin=copy.kind==='live-copy-evidence'?'live':'archive',archiveBinding=verificationOrigin==='archive'?structuredClone(copy.archiveBinding):undefined;
 need(imageFilesystemVerificationKind(filesystemVerification)===(verificationOrigin==='live'?'live-filesystem-evidence':'archived-filesystem-evidence'));
 const filesystemBinding=imageFilesystemVerificationBinding(filesystemVerification);
 if(archiveBinding){
  need(exact(archiveBinding,['proofHash','dataHash','reviewHash','scope'])&&['proofHash','dataHash','reviewHash'].every(k=>hex(archiveBinding[k]))&&exact(archiveBinding.scope,['account','region','runtimeNonce','authorizationId'])&&archiveBinding.scope.account===predecessor.account&&archiveBinding.scope.region===predecessor.region&&archiveBinding.scope.runtimeNonce===predecessor.runtimeNonce&&hex(archiveBinding.scope.authorizationId,32));
  need(exact(filesystemBinding,['proofHash','dataHash','reviewHash'])&&['proofHash','dataHash','reviewHash'].every(k=>filesystemBinding[k]===archiveBinding[k]));
 }else need(verificationOrigin==='live'&&filesystemBinding===null);
 need(copy.graphHash===expected.graphHash&&same(copy.summary,graph)&&hash(copy.inventory)===graph.inventoryHash&&hash(copy.destinationReadback)===graph.destinationReadbackHash);
 for(const r of copy.inventory.roots)need(r.sourceRepository==='mem9-on-aws/preview/'+r.component&&r.destinationRepository==='mem9-on-aws/'+r.component&&r.targetTag==='mem9-'+origin.revision.slice(0,7)&&r.root.digest===input.images[r.component].rootDigest&&r.arm64Digest===input.images[r.component].arm64Digest);
 need(filesystem.component==='mnemo-server'&&filesystem.graphHash===graph.inventoryHash&&filesystem.arm64Digest===input.images['mnemo-server'].arm64Digest&&filesystem.rootDigest===input.images['mnemo-server'].rootDigest&&filesystem.limitsHash===LIMITS_HASH);
 need(same(imageFilesystemProof(filesystemVerification,graphVerification,{path:'/lib/apk/db/installed'}),input.filesystem));
 need(filesystem.packages.length===1&&filesystem.packages[0].path==='/lib/apk/db/installed'&&filesystem.packages[0].manager==='apk'&&filesystem.packages[0].name==='zlib'&&filesystem.packages[0].version===input.policy.fixed.targetVersion);
 need(Number.isSafeInteger(graph.startedMs)&&graph.startedMs>0&&Number.isSafeInteger(graph.completedMs)&&graph.completedMs>=graph.startedMs&&graph.completedMs-graph.startedMs<=LIMITS.maxStageMs&&graph.completedMs<=now);
 need(hash(input.filesystem)===expected.filesystemHash&&hash(input.policy)===expected.policyHash&&hash(input.buildEvidence)===expected.buildEvidenceHash);buildEvidence(input);
 need(exact(input.scans,['old','preview','destination']));const normalized={};for(const phase of ['old','preview','destination'])normalized[phase]=await scans(input,predecessor,phase,now);policyEvidence(input,normalized,now);
 const projection={version:1,kind:'image-security-execution-projection',execution:neutral(serving.s),originalImages:predecessor.images,targetImages:input.images,runtime:serving.s.runtime,networkHash:serving.material.network,credentialsHash:serving.material.credentials,authorityHash:serving.material.authority};
 const targetBuildInputsHash=hash({version:1,recipeHash:hash(inputs.recipe),artifacts}),targetSecurityEvidenceHash=normalized.destination.securityEvidenceHash;
 const scanCompletedMs=Object.values(input.scans).flatMap(group=>Object.values(group).flatMap(pages=>pages.map(raw=>Date.parse(parseImageTransitionJson(raw).imageScanFindings.imageScanCompletedAt))));
 const proof=freeze({...structuredClone(input),bootstrapPins:structuredClone(expected.expectedBootstrap),graphInventory:copy.inventory,destinationReadback:copy.destinationReadback,filesystemEvidence:filesystem,observedMs:now,projectionHash:hash(projection),targetBuildInputsHash,targetSecurityEvidenceHash});
 return {proof,predecessor,original,serving,parent,projection,normalized,scanCompletedMs,expected:structuredClone(expected),verificationOrigin,archiveBinding};
}
function proofContext(state,mode){
 need(['inspection','admission'].includes(mode));state.verificationMode=mode;
 const proofHash=hash(state.proof),context=freeze({version:1,verificationMode:mode,verificationOrigin:state.verificationOrigin,proofHash,predecessorHash:state.expected.predecessorHash,limitsHash:LIMITS_HASH,projectionHash:state.proof.projectionHash});contexts.set(context,state);return context;
}
export async function buildImageTransitionProof(input,{expected,now=Date.now(),mode='admission',graphVerification,filesystemVerification}){
 const state=await derive(input,expected,now,{graphVerification,filesystemVerification}),context=proofContext(state,mode),proofHash=context.proofHash;
 return {proof:state.proof,proofHash,context};
}
/** Reconstruction inputs only, never an authorization context. proofHash MUST
 * come from the authenticated protected descriptor or immutable owned operation.
 * Initial publication still supplies independent pins and live graph/FS brands.
 * Retaining the validated bootstrap pins avoids local files and a second policy
 * normalizer in CI; the unchanged V3 verifier checks those pins again below. */
export function imageTransitionProofExpected(proof,{proofHash}={}){
 json(proof);need(hex(proofHash)&&hash(proof)===proofHash&&exact(proof,proofKeys)&&proof.version===1&&proof.kind==='image-security-upgrade-proof'&&same(proof.limits,LIMITS));
 const expected={predecessorHash:hash(parseImageTransitionJson(proof.predecessorText)),parentProofHash:hash(proof.bootstrapProof.parent),bootstrapProofHash:hash(proof.bootstrapProof),expectedBootstrap:structuredClone(proof.bootstrapPins),
  dataOriginSourceEvidenceHash:hash(proof.dataOrigin.sourceEvidence),buildCommitHash:hash(proof.dataOrigin.buildCommit),controlSourceEvidenceHash:hash(proof.control.sourceEvidence),dataInputsHash:hash(proof.dataInputs),graphHash:hash(proof.graph),filesystemHash:hash(proof.filesystem),policyHash:hash(proof.policy),buildEvidenceHash:hash(proof.buildEvidence)};
 json(expected);need(exact(expected,expectedKeys));return freeze(expected);
}
export async function verifyImageTransitionProof(proof,{proofHash,expected,now=Date.now(),mode='admission',graphVerification,filesystemVerification,targetObservation,current,review}){
 json(proof);need(exact(proof,proofKeys)&&hex(proofHash)&&hash(proof)===proofHash&&['inspection','admission'].includes(mode));
 proof=structuredClone(proof);
 need(Number.isSafeInteger(now)&&now>0&&Number.isSafeInteger(proof.observedMs)&&proof.observedMs>0&&proof.observedMs<=now);
 const input=Object.fromEntries(inputKeys.map(k=>[k,proof[k]])),state=await derive(input,expected,mode==='inspection'?proof.observedMs:now,{graphVerification,filesystemVerification,allowArchive:true});
 state.proof=freeze({...state.proof,observedMs:proof.observedMs});need(same(state.proof,proof));
 if(state.archiveBinding){
  need(state.archiveBinding.proofHash===proofHash);
  if(current!==undefined){json(current);need(hash(current)===state.archiveBinding.dataHash);}
  if(review!==undefined){json(review);need(hash(review)===state.archiveBinding.reviewHash);}
 }
 if(targetObservation!==undefined)state.targetObservation=targetPresence(targetObservation,state,now);
 const context=proofContext(state,mode);
 if(state.archiveBinding&&current!==undefined&&review!==undefined)assertImageTransitionDataRelease(context,{current,controlSourceTree:state.proof.control.sourceTree,now,mode,review});
 return context;
}
export function imageTransitionContextBindings(context){
 const s=contexts.get(context);need(s);return freeze({verificationMode:s.verificationMode,verificationOrigin:s.verificationOrigin,evidenceKind:s.verificationOrigin==='live'?'live-copy-evidence':'archived-copy-evidence',...(s.archiveBinding?{archiveBinding:structuredClone(s.archiveBinding)}:{}),observedMs:s.proof.observedMs,proofHash:context.proofHash,predecessorHash:context.predecessorHash,limitsHash:LIMITS_HASH,projectionHash:context.projectionHash,
  control:{revision:s.proof.control.revision,sourceTree:s.proof.control.sourceTree,baseRevision:s.proof.control.baseRevision,sourceEvidenceHash:s.expected.controlSourceEvidenceHash,repository:s.proof.control.sourceEvidence.repository,prNumber:s.proof.control.sourceEvidence.prNumber},
  dataOrigin:{revision:s.proof.dataOrigin.revision,sourceTree:s.proof.dataOrigin.sourceTree,sourceHead:s.proof.dataOrigin.sourceHead,sourceEvidenceHash:s.expected.dataOriginSourceEvidenceHash},
  images:structuredClone(s.proof.images),buildInputsHash:s.proof.targetBuildInputsHash,securityEvidenceHash:s.proof.targetSecurityEvidenceHash,freshBuildSecurityHash:s.normalized.preview.securityEvidenceHash,artifactPolicyHash:s.expected.policyHash,
  previousSelection:{dataSourceTag:s.predecessor.dataSourceTag,images:Object.fromEntries(COMPONENTS.map(name=>[name,`${s.predecessor.account}.dkr.ecr.${s.predecessor.region}.amazonaws.com/mem9-on-aws/${name}@${s.predecessor.images[name].rootDigest}`])),arm64Digests:Object.fromEntries(COMPONENTS.map(name=>[name,s.predecessor.images[name].arm64Digest])),dataReleaseHash:s.expected.predecessorHash},
  previousControlTag:s.serving.s.controlSourceTag??'mem9-'+s.serving.s.revision.slice(0,7),
  sourceEvidenceHash:s.expected.controlSourceEvidenceHash,dataOriginSourceEvidenceHash:s.expected.dataOriginSourceEvidenceHash,policySourcesHash:hash(s.proof.policy.policySources.map(p=>({path:p.path,hash:sha(p.text)}))),
  root:Object.fromEntries(rootFields.map(k=>[k,s.predecessor[k]])),rootState:{generation:s.parent.generation,validationId:s.parent.validationId,receipts:s.parent.receipts,changedRows:s.parent.changedRows,conservationHash:s.parent.conservationHash,cap:20}});
}
/** Caller authenticates this record from the same immutable operation archive.
 * Parent protocol separately matches its root and material-joint evidence to real
 * fresh inspection. This function never generates a stamp or substitutes a
 * static artifact-policy hash for the final owner-review hash. */
function finalReview(context,value,{now,mode}){
 const s=contexts.get(context);need(s&&['inspection','admission'].includes(mode)&&(mode==='inspection'||s.verificationMode==='admission'));
 const review=typeof value==='string'?parseImageTransitionJson(value):value;json(review);
 if(s.archiveBinding)need(hash(review)===s.archiveBinding.reviewHash);
 need(exact(review,IMAGE_TRANSITION_REVIEW_KEYS)&&review.version===1&&review.kind==='image-security-policy-review'&&review.decision==='within-existing-policy');
 const b=imageTransitionContextBindings(context);
 for(const key of ['artifactPolicyHash','sourceEvidenceHash','dataOriginSourceEvidenceHash','buildInputsHash','securityEvidenceHash','freshBuildSecurityHash','policySourcesHash'])need(review[key]===b[key]);
 need(review.imageTransitionProofHash===b.proofHash&&review.controlSourceTree===b.control.sourceTree&&review.parentProofHash===b.root.parentProofHash);
 need(Number.isSafeInteger(now)&&now>0&&Number.isSafeInteger(review.reviewedMs)&&review.reviewedMs>=s.proof.observedMs&&review.reviewedMs<=now&&Number.isSafeInteger(review.expiresMs)&&review.expiresMs>review.reviewedMs&&review.expiresMs-review.reviewedMs<=86400000);
 if(mode==='admission'){need(now<review.expiresMs);if(s.targetObservation)checkedTime(s.targetObservation.observedMs,now,300000);}
 return review;
}
export function bindImageTransitionAuthorization(context,{review,now=Date.now(),mode='admission'}){
 const s=contexts.get(context);need(s);const checked=finalReview(context,review,{now,mode});
 const bound=authorizations.get(context);if(bound)need(same(bound.review,checked));
 const result=freeze({...context,verificationMode:mode,reviewHash:hash(checked)});contexts.set(result,{...s,verificationMode:mode});authorizations.set(result,{review:freeze(structuredClone(checked))});return result;
}
/** Existing validity cutoff for a bounded operation, not an admission check.
 * Descriptor admission requires expiresMs to equal the bound review expiry.
 * Review expiry is exclusive; the existing 24h evidence boundaries are inclusive.
 * Target observations retain their separate freshness check and are excluded. */
export function imageTransitionAdmissionDeadline(context){
 const state=contexts.get(context),bound=authorizations.get(context);
 need(state&&bound&&state.verificationMode==='admission');
 let deadline=bound.review.expiresMs;
 for(const at of [...state.scanCompletedMs,...state.proof.vendors.map(v=>v.observedMs)]){
  const cutoff=at+86400000;need(Number.isSafeInteger(cutoff));deadline=Math.min(deadline,cutoff);
 }
 return deadline;
}
export function assertImageTransitionDataRelease(context,{previous,current,controlSourceTree,now=Date.now(),mode='admission',review}){
 const state=contexts.get(context);need(state&&['inspection','admission'].includes(mode)&&(mode==='inspection'||state.verificationMode==='admission')&&Number.isSafeInteger(now)&&now>0);json(current);
 if(state.archiveBinding)need(hash(current)===state.archiveBinding.dataHash&&current.policyHash===state.archiveBinding.reviewHash&&current.authorizationId===state.archiveBinding.scope.authorizationId);
 if(previous!==undefined){json(previous);need(same(previous,state.predecessor)&&hash(previous)===context.predecessorHash);}previous=state.predecessor;
 need(current.version===2&&current.controlSourceTree===controlSourceTree&&controlSourceTree===state.proof.control.sourceTree);
 const t=inspectImageTransitionDescriptorCommitment(current.transition);need(t.proofHash===context.proofHash&&t.predecessorHash===context.predecessorHash&&t.limitsHash===LIMITS_HASH);
 for(const k of rootFields)need(current[k]===previous[k]);
 need(current.dataRevision===state.proof.dataOrigin.revision&&current.dataSourceTree===state.proof.dataOrigin.sourceTree&&current.dataSourceTag==='mem9-'+current.dataRevision.slice(0,7)&&same(current.images,state.proof.images)&&current.buildInputsHash===state.proof.targetBuildInputsHash&&current.securityEvidenceHash===state.proof.targetSecurityEvidenceHash&&current.authorizationId!==previous.authorizationId);
 const bound=authorizations.get(context);if(bound&&review!==undefined)need(same(bound.review,typeof review==='string'?parseImageTransitionJson(review):review));review??=bound?.review;
 if(mode==='admission'||review!==undefined||state.archiveBinding){need(review!==undefined);const checked=finalReview(context,review,{now,mode});need(hash(checked)===current.policyHash&&current.issuedMs===checked.reviewedMs&&current.expiresMs===checked.expiresMs);}
 (mode==='admission'?requireActiveDataRelease:inspectDataRelease)(current,{stage:'prod',account:previous.account,region:previous.region,controlSourceTree},{now});
 if(mode==='admission'){for(const at of state.scanCompletedMs)checkedTime(at,now);policyEvidence(state.proof,state.normalized,now);if(state.archiveBinding)need(state.targetObservation);if(state.targetObservation)checkedTime(state.targetObservation.observedMs,now,300000);}
 return Object.freeze({proofHash:context.proofHash,predecessorHash:context.predecessorHash,limitsHash:LIMITS_HASH,projectionHash:context.projectionHash});
}
export function verifyImageTransitionObservation(value,context,{selection,now=Date.now(),mode='admission',phase='target-serving',review}={}){
 const state=contexts.get(context);need(state&&exact(selection,['revision','sourceTree','coordinatorDigest','dataReleaseHash','parameterVersion'])&&['predeployment','target-serving'].includes(phase));
 const observed=snapshot(value),s=observed.s;checkedTime(Date.parse(s.observedAt),now,300000);
 need(s.revision===selection.revision&&s.sourceTree===selection.sourceTree&&s.coordinatorDigest===selection.coordinatorDigest&&s.dataRelease?.hash===selection.dataReleaseHash&&s.dataRelease.parameterVersion===selection.parameterVersion&&Number.isSafeInteger(selection.parameterVersion)&&selection.parameterVersion>0&&hash(s.dataRelease.data)===s.dataRelease.hash);
 if(phase==='predeployment'){
  need(mode==='inspection');const old=state.serving.s;
  need(s.account===old.account&&s.region===old.region&&s.generation===old.generation&&same(release(s),release(old))&&s.revision===old.revision&&s.controlSourceTag===old.controlSourceTag&&same(s.components,old.components));
  need(same(neutral(s),state.projection.execution)&&observed.material.authority===state.projection.authorityHash&&observed.material.network===state.projection.networkHash&&observed.material.credentials===state.projection.credentialsHash);
  if(s.dataRelease.data.version===1)need(same(s.dataRelease,old.dataRelease));
  else{
   need(s.dataRelease.parameterVersion===old.dataRelease.parameterVersion+1);
   assertImageTransitionDataRelease(context,{current:s.dataRelease.data,controlSourceTree:state.proof.control.sourceTree,now,mode:'inspection',review});
  }
  return Object.freeze({phase,cloudObservationHash:sha(observed.text),projectionHash:context.projectionHash,authorityHash:observed.material.authority});
 }
 assertImageTransitionDataRelease(context,{previous:state.predecessor,current:s.dataRelease.data,controlSourceTree:s.sourceTree,now,mode,review});
 need(s.account===state.predecessor.account&&s.region===state.predecessor.region&&s.generation===state.predecessor.generation&&same(s.runtime,state.serving.s.runtime)&&s.sourceTag===s.dataRelease.data.dataSourceTag&&s.controlSourceTag==='mem9-'+s.revision.slice(0,7));
 for(const name of [...COMPONENTS,'worker']){const target=state.proof.images[name==='worker'?'llm-proxy':name],c=s.components[name];need(c.rootDigest===target.rootDigest&&c.arm64Digest===target.arm64Digest);}
 need(s.workerImage===`${s.account}.dkr.ecr.${s.region}.amazonaws.com/mem9-on-aws/llm-proxy@${state.proof.images['llm-proxy'].rootDigest}`&&same(neutral(s),state.projection.execution)&&observed.material.authority===state.projection.authorityHash&&observed.material.network===state.projection.networkHash&&observed.material.credentials===state.projection.credentialsHash);
 return Object.freeze({phase,cloudObservationHash:sha(observed.text),projectionHash:context.projectionHash,authorityHash:observed.material.authority});
}
export function buildCanaryCompatibilityV4(previous,current,parent,{transition,selection,now=Date.now(),mode='admission',review}={}){
 const state=contexts.get(transition);need(state&&same(previous,state.original.s)&&same(parent,state.parent));verifyImageTransitionObservation(current,transition,{selection,now,mode,review});
 const material=verifyLegacyCanaryMaterial(current),certificate={version:4,dataReleaseHash:current.dataRelease.hash,parentProofHash:hash(parent),generation:parent.generation,targetsHash:hash([...parent.targets].sort()),previous:{release:release(previous),backendBindingHash:parent.backendBindingHash},current:{release:release(current),backendBinding:structuredClone(current.backendBinding)},images:Object.fromEntries(['worker',...COMPONENTS].map(n=>[n,{previousRoot:previous.components[n].rootDigest,currentRoot:current.components[n].rootDigest,previousChild:previous.components[n].arm64Digest,currentChild:current.components[n].arm64Digest}])),material:Object.fromEntries(MATERIALS.map(n=>[n,{previous:state.original.material[n],current:material[n]}])),transition:{version:1,kind:IMAGE_TRANSITION_KIND,proofHash:transition.proofHash,predecessorHash:transition.predecessorHash,limitsHash:LIMITS_HASH,projectionHash:transition.projectionHash}};
 inspectImageTransitionCertificate(certificate);return certificate;
}
