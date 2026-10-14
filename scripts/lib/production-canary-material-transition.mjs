import {createHash} from 'node:crypto';
import {canaryEvidenceHash as hash} from './production-canary-verification.mjs';
import {inspectDataRelease,requireActiveDataRelease} from './production-data-release.mjs';
import {verifyLegacyCanaryMaterial,normalizeCanaryAuthority} from './production-canary-material-integrity.mjs';
import {projectConfiguredCanaryBackend,CANARY_BACKEND_ADDITIONAL_ATTRIBUTE} from './production-canary-material.mjs';
import {inspectCanaryTransitionCertificate,CANARY_TRANSITION_MATERIALS,CANARY_TRANSITION_KIND} from './production-canary-transition.mjs';

const fail=()=>{throw Error('CanaryMaterialTransitionInvalid');};
const requireValue=v=>{if(!v)fail();};
const hex=(v,n=64)=>typeof v==='string'&&new RegExp('^[a-f0-9]{'+n+'}$').test(v);
const record=v=>v&&typeof v==='object'&&!Array.isArray(v)&&[Object.prototype,null].includes(Object.getPrototypeOf(v))&&Reflect.ownKeys(v).every(k=>typeof k==='string'&&Object.getOwnPropertyDescriptor(v,k).enumerable&&Object.hasOwn(Object.getOwnPropertyDescriptor(v,k),'value'));
const exact=(v,keys)=>record(v)&&Object.keys(v).sort().join()===keys.slice().sort().join();
const same=(a,b)=>hash(a)===hash(b);
const sha=text=>createHash('sha256').update(text).digest('hex');
const canonical=v=>Array.isArray(v)?v.map(canonical):record(v)?Object.fromEntries(Object.keys(v).sort().map(k=>[k,canonical(v[k])])):v;
const semantic=v=>Array.isArray(v)?v.map(semantic).sort((a,b)=>JSON.stringify(a).localeCompare(JSON.stringify(b))):record(v)?Object.fromEntries(Object.keys(v).filter(k=>k!=='Sid').sort().map(k=>[k,semantic(v[k])])):v;
const freeze=v=>{if(v&&typeof v==='object'){Object.freeze(v);Object.values(v).forEach(freeze);}return v;};
const contexts=new WeakMap(),scopeActions=['bedrock-mantle:CreateInference','bedrock-mantle:GetProject','bedrock-mantle:ListProjects','bedrock-mantle:ListTagsForResource','ecr:BatchCheckLayerAvailability','ecr:BatchGetImage','ecr:GetDownloadUrlForLayer','lambda:InvokeFunction','logs:CreateLogGroup','logs:CreateLogStream','logs:PutLogEvents','s3:GetObject','s3:PutObject','secretsmanager:GetSecretValue','sns:Publish','sqs:SendMessage','ssm:GetParameters','ssm:PutParameter'];
const scopeFamilies=['bedrock-mantle:CreateInference','bedrock-mantle:GetProject','bedrock-mantle:ListProjects','bedrock-mantle:ListTagsForResource','ecr:Batch*','ecr:GetDownloadUrlForLayer','lambda:*','logs:*','secretsmanager:*','sns:*','sqs:*','ssm:*','s3:*'];
const pinKeys=['attempt','operationHash','terminalHash','sourceCommit','sourceTree','boundaryTemplateHash','parametersHash','previousPolicyHash','currentPolicyHash'];
function jsonValue(value,depth=0,budget={nodes:0}){
 requireValue(depth<=64&&++budget.nodes<=500000);
 if(value===null||typeof value==='string'||typeof value==='boolean')return;
 if(typeof value==='number'){requireValue(Number.isFinite(value));return;}
 if(Array.isArray(value)){requireValue(Object.keys(value).length===value.length);for(let i=0;i<value.length;i++){requireValue(Object.hasOwn(Object.getOwnPropertyDescriptor(value,String(i))??{},'value'));jsonValue(value[i],depth+1,budget);}return;}
 requireValue(record(value));for(const v of Object.values(value))jsonValue(v,depth+1,budget);
}

// The snapshot texts are archived byte anchors. Detect duplicate keys before
// JSON.parse can erase one; no URLs, module paths or executable input is loaded.
function parseSnapshot(text){
 requireValue(typeof text==='string'&&text.isWellFormed()&&Buffer.byteLength(text)<=4*1024*1024);let i=0,nodes=0;
 const ws=()=>{while(/[\x20\t\r\n]/.test(text[i]??'!'))i++;};
 const string=()=>{const start=i;requireValue(text[i++]==='"');let escaped=false;while(i<text.length){const c=text[i++];if(!escaped&&c==='"')return JSON.parse(text.slice(start,i));if(escaped)escaped=false;else if(c==='\\')escaped=true;}fail();};
 const value=depth=>{requireValue(depth<64&&++nodes<250000);ws();const c=text[i];
  if(c==='{'){i++;ws();const keys=new Set();if(text[i]==='}'){i++;return;}while(true){ws();const k=string();requireValue(!keys.has(k));keys.add(k);ws();requireValue(text[i++]===':');value(depth+1);ws();if(text[i]==='}'){i++;return;}requireValue(text[i++]===',');}}
  if(c==='['){i++;ws();if(text[i]===']'){i++;return;}while(true){value(depth+1);ws();if(text[i]===']'){i++;return;}requireValue(text[i++]===',');}}
  if(c==='"'){string();return;}const m=/^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(text.slice(i));requireValue(m);i+=m[0].length;
 };value(0);ws();requireValue(i===text.length);const parsed=JSON.parse(text);jsonValue(parsed);return parsed;
}
function rawSnapshot(text){
 const s=parseSnapshot(text);
 requireValue(exact(s,['version','observedAt','account','region','revision','sourceTree','coordinatorDigest','generation','sourceTag','workerImage','runtime','components','definitions','backendBinding','backendTask','authority','scheduler','credentials','network','material',...(Object.hasOwn(s,'dataRelease')?['dataRelease']:[]),...(Object.hasOwn(s,'controlSourceTag')?['controlSourceTag']:[])]));
 requireValue(s?.version===2&&/^\d{12}$/.test(s.account??'')&&/^[a-z]{2}(?:-[a-z]+)+-\d$/.test(s.region??'')&&hex(s.revision,40)&&hex(s.sourceTree,40)&&hex(s.coordinatorDigest)&&hex(s.generation)&&hex(s.runtime?.runtimeNonce,32));
 if(s.controlSourceTag!==undefined||s.dataRelease)requireValue(s.controlSourceTag==='mem9-'+s.revision.slice(0,7));
 requireValue(typeof s.observedAt==='string'&&Number.isSafeInteger(Date.parse(s.observedAt))&&new Date(s.observedAt).toISOString()===s.observedAt);
 requireValue(exact(s.definitions,['planner','executor','backend'])&&exact(s.components,['worker','mnemo-server','qwen3-embed','llm-proxy'])&&exact(s.material,CANARY_TRANSITION_MATERIALS));
 const material=verifyLegacyCanaryMaterial(s),task=s.backendTask,definition=s.definitions.backend;
 requireValue(task.launchType==='FARGATE'&&task.healthStatus==='HEALTHY'&&task.cpu===definition.cpu&&task.memory===definition.memory&&task.containers.every(c=>c.healthStatus==='HEALTHY')&&task.attributes?.filter(a=>a.name==='ecs.cpu-architecture').length===1&&task.attributes.find(a=>a.name==='ecs.cpu-architecture').value==='arm64');
 if(task.overrides!==undefined){
  const o=task.overrides;requireValue(record(o)&&Object.keys(o).every(k=>['containerOverrides','taskRoleArn','executionRoleArn','cpu','memory','inferenceAcceleratorOverrides','ephemeralStorage'].includes(k)));
  for(const k of ['taskRoleArn','executionRoleArn','cpu','memory'])if(o[k]!==undefined)requireValue(String(o[k])===String(definition[k]));
  if(o.ephemeralStorage!==undefined)requireValue(same(o.ephemeralStorage,definition.ephemeralStorage));
  requireValue(o.inferenceAcceleratorOverrides===undefined||Array.isArray(o.inferenceAcceleratorOverrides)&&o.inferenceAcceleratorOverrides.length===0);
  if(o.containerOverrides!==undefined)requireValue(Array.isArray(o.containerOverrides)&&o.containerOverrides.every(c=>exact(c,['name'])&&definition.containerDefinitions.some(d=>d.name===c.name))&&new Set(o.containerOverrides.map(c=>c.name)).size===o.containerOverrides.length);
 }
 const images=new Map([[s.workerImage,s.components.worker]]);for(const c of definition.containerDefinitions)images.set(c.image,s.components[c.name]);
 return {snapshot:s,material,projection:projectConfiguredCanaryBackend(definition,{account:s.account,region:s.region,images}),byteHash:sha(text)};
}
const release=s=>({sourceTree:s.sourceTree,coordinatorDigest:s.coordinatorDigest,sourceTag:s.sourceTag,workerImage:s.workerImage,...s.runtime});
function selectedData(previous,current,parent,{mode='inspection',now=Date.now()}={}){
 requireValue(['inspection','publication'].includes(mode)&&Number.isSafeInteger(now)&&now>0);
 requireValue(current.dataRelease&&same(previous.runtime,current.runtime)&&previous.account===current.account&&previous.region===current.region&&previous.generation===current.generation&&previous.generation===parent.generation&&previous.workerImage===parent.workerImage&&previous.sourceTag===parent.sourceTag&&hash(previous.backendBinding)===parent.backendBindingHash&&hash(release(previous))===parent.releaseHash);
 requireValue(hex(parent.validationId,32)&&Number.isSafeInteger(parent.changedRows)&&parent.changedRows>=2&&parent.changedRows<20&&Number.isSafeInteger(parent.receipts)&&parent.receipts>0&&hex(parent.conservationHash));
 if(previous.dataRelease)requireValue(inspectDataRelease(previous.dataRelease.data,{stage:'prod',account:previous.account,region:previous.region,controlSourceTree:previous.sourceTree}).hash===previous.dataRelease.hash);
 const expected={stage:'prod',account:current.account,region:current.region,controlSourceTree:current.sourceTree,bindings:{parentProofHash:hash(parent),backendBindingHash:parent.backendBindingHash,generation:parent.generation,targetsHash:hash([...parent.targets].sort()),runtimeNonce:current.runtime.runtimeNonce,schemaDigest:current.runtime.schemaDigest,operatorDigest:current.runtime.operatorDigest}};
 const selected=(mode==='publication'?requireActiveDataRelease:inspectDataRelease)(current.dataRelease.data,expected,{now});
 requireValue(selected.hash===current.dataRelease.hash&&selected.data.dataSourceTag===current.sourceTag&&selected.images['llm-proxy']===current.workerImage&&selected.data.dataRevision===(previous.dataRelease?.data.dataRevision??previous.revision)&&selected.data.dataSourceTree===(previous.dataRelease?.data.dataSourceTree??previous.sourceTree));
 for(const name of ['worker','mnemo-server','qwen3-embed','llm-proxy']){
  const a=previous.components[name],b=current.components[name];requireValue(a&&b&&same(a,b));
  if(name!=='worker')requireValue(selected.data.images[name].rootDigest===b.rootDigest&&selected.data.images[name].arm64Digest===b.arm64Digest);
 }
 return selected;
}
function bootstrapProof(evidence,pins,old,current){
 requireValue(exact(pins,pinKeys)&&hex(pins.attempt,32)&&hex(pins.sourceCommit,40)&&hex(pins.sourceTree,40)&&pinKeys.filter(k=>!['attempt','sourceCommit','sourceTree'].includes(k)).every(k=>hex(pins[k])));
 requireValue(exact(evidence,['operation','controlChain','boundaryTemplate'])&&record(evidence.operation)&&Array.isArray(evidence.controlChain)&&evidence.controlChain.length>=3&&evidence.controlChain.length<=1000&&typeof evidence.boundaryTemplate==='string'&&evidence.boundaryTemplate.length<=262144);
 const op=evidence.operation,parameters=op.bindings?.stacks?.boundary?.parameters;
 requireValue(op.version===1&&op.attempt===pins.attempt&&hex(op.bindingHash)&&hash(op)===pins.operationHash&&op.source?.commit===pins.sourceCommit&&op.source?.tree===pins.sourceTree&&op.bindings.accountId===old.account&&op.bindings.applicationRegion===old.region);
 requireValue(record(parameters)&&parameters.ApplicationRegion===old.region&&hash(parameters)===pins.parametersHash&&sha(evidence.boundaryTemplate)===pins.boundaryTemplateHash&&op.templateHashes?.boundary?.source===pins.boundaryTemplateHash&&op.templateHashes.boundary.wire===pins.boundaryTemplateHash);
 let previous='0'.repeat(64);
 for(const [index,row]of evidence.controlChain.entries()){
  requireValue(exact(row,['version','previousHash','hash','record'])&&row.version===1&&row.previousHash===previous&&hex(row.hash)&&record(row.record));const r=row.record;
  requireValue(r.version===1&&r.attempt===op.attempt&&r.bindingHash===op.bindingHash&&r.sequence===index+1&&row.hash===sha(previous+'\n'+JSON.stringify(canonical(r)))&&r.phase!=='CLOSED'&&r.phase!=='DRAINING'&&(r.event!=='succeeded'||index===evidence.controlChain.length-1));previous=row.hash;
 }
 requireValue(previous===pins.terminalHash&&evidence.controlChain.at(-1).record.event==='succeeded'&&evidence.controlChain.at(-1).record.phase==='SUCCEEDED');
 const a=normalizeCanaryAuthority(old),b=normalizeCanaryAuthority(current);
 requireValue(a.length===7&&b.length===7&&new Set(a.map(r=>r.roleId)).size===7&&a.every(r=>typeof r.roleId==='string'&&r.roleId.length>0));
 const arn=`arn:aws:iam::${old.account}:policy/mem9-on-aws-workload-boundary`,before=a[0].boundary.document,after=b[0].boundary.document;
 for(const role of a){const next=b.find(r=>r.arn===role.arn);requireValue(next&&role.boundary.arn===arn&&next.boundary.arn===arn&&same({...role,boundary:{arn}},{...next,boundary:{arn}})&&same(role.boundary.document,before)&&same(next.boundary.document,after));}
 requireValue(hash(semantic(before))===pins.previousPolicyHash&&hash(semantic(after))===pins.currentPolicyHash&&pins.previousPolicyHash!==pins.currentPolicyHash);
 requireValue(exact(before,['Version','Statement'])&&exact(after,['Version','Statement'])&&before.Version==='2012-10-17'&&after.Version===before.Version&&before.Statement.length===15&&after.Statement.length===16);
 const oldStatements=before.Statement.map(semantic),newStatements=after.Statement.map(semantic),oldHashes=new Set(oldStatements.map(hash)),newHashes=new Set(newStatements.map(hash));
 requireValue(oldHashes.size===15&&newHashes.size===16&&oldStatements.filter(s=>newHashes.has(hash(s))).length===14);
 const removed=oldStatements.filter(s=>!newHashes.has(hash(s))),added=newStatements.filter(s=>!oldHashes.has(hash(s)));
 const oldScope=removed[0],newScope=added.find(s=>s.NotResource),newDeny=added.find(s=>!s.NotResource);
 requireValue(removed.length===1&&added.length===2&&oldScope?.Effect==='Deny'&&newScope?.Effect==='Deny'&&same(oldScope.Action,semantic(scopeActions))&&same(newScope.Action,semantic(scopeFamilies))&&same({...oldScope,Action:semantic(scopeFamilies)},newScope));
 const bucket=parameters.DecisionArtifactBucketName;requireValue(typeof bucket==='string'&&/^[a-z0-9][a-z0-9-]{1,31}[a-z0-9]$/.test(bucket));
 requireValue(same(newDeny,semantic({Effect:'Deny',Action:['s3:PutObject','iam:PassRole'],Resource:[`arn:aws:s3:::${bucket}/data-authorizations/*`,`arn:aws:iam::${old.account}:role/mem9-on-aws-namespace-operator`,`arn:aws:iam::${old.account}:role/mem9-on-aws-preview-human-acceptance`]})));
 return {previousAuthorityHash:hash(a),currentAuthorityHash:hash(b)};
}
function stableMaterial(value,projectionHash){
 const s=value.snapshot;return hash({version:1,domain:'canary-transition-material-v1',account:s.account,region:s.region,generation:s.generation,runtime:s.runtime,sourceTag:s.sourceTag,workerImage:s.workerImage,components:s.components,material:{...value.material,backend:projectionHash}});
}
function derive({previousText,currentText,parent,bootstrap},expectedBootstrap){
 const old=rawSnapshot(previousText),current=rawSnapshot(currentText);selectedData(old.snapshot,current.snapshot,parent);
 const a=old.projection,b=current.projection;requireValue(same(a.configuration,b.configuration)&&!a.metadata.attributeNames.includes(CANARY_BACKEND_ADDITIONAL_ATTRIBUTE)&&same(b.metadata.attributeNames,[...a.metadata.attributeNames,CANARY_BACKEND_ADDITIONAL_ATTRIBUTE].sort()));
 const oldDefinition=old.snapshot.definitions.backend,nextDefinition=current.snapshot.definitions.backend,cluster=old.snapshot.network.cluster;
 requireValue(cluster===current.snapshot.network.cluster&&oldDefinition.family===cluster.split('/').at(-1)+'-Mem9RuntimeServer'&&nextDefinition.family===oldDefinition.family&&oldDefinition.taskDefinitionArn!==nextDefinition.taskDefinitionArn&&old.snapshot.backendTask.taskArn!==current.snapshot.backendTask.taskArn);
 for(const name of ['planner','executor','network','credentials'])requireValue(old.material[name]===current.material[name]);
 const authority=bootstrapProof(bootstrap,expectedBootstrap,old.snapshot,current.snapshot),backendProjectionHash=hash(a.configuration),stableMaterialHash=stableMaterial(current,backendProjectionHash);
 const proof={version:1,kind:'canary-material-transition',previousText,currentText,parent:structuredClone(parent),anchors:{previousSnapshotHash:old.byteHash,currentSnapshotHash:current.byteHash,parentProofHash:hash(parent)},bootstrap:structuredClone(bootstrap),backendProjectionHash,...authority,stableMaterialHash};
 return {proof,old,current,parent:structuredClone(parent),expectedBootstrap:structuredClone(expectedBootstrap)};
}
/** Independent bootstrap pins must come from the authenticated, reviewed
 * operation configuration, not from a claimed compatible boolean in proof. */
export function buildCanaryMaterialTransition(input,{expectedBootstrap}){
 requireValue(exact(input,['previousText','currentText','parent','bootstrap']));jsonValue(input);jsonValue(expectedBootstrap);requireValue(Buffer.byteLength(JSON.stringify(input))<=16*1024*1024);const result=derive(input,expectedBootstrap),proof=freeze(result.proof),proofHash=hash(proof);
 const context=freeze({version:1,proofHash,stableMaterialHash:proof.stableMaterialHash});contexts.set(context,result);
 return {proof,proofHash,context,stableMaterialHash:proof.stableMaterialHash};
}
export function verifyCanaryMaterialTransition(proof,{proofHash,expectedBootstrap}){
 jsonValue(proof);
 requireValue(exact(proof,['version','kind','previousText','currentText','parent','anchors','bootstrap','backendProjectionHash','previousAuthorityHash','currentAuthorityHash','stableMaterialHash'])&&proof.version===1&&proof.kind==='canary-material-transition'&&hex(proofHash)&&hash(proof)===proofHash);
 const built=buildCanaryMaterialTransition({previousText:proof.previousText,currentText:proof.currentText,parent:proof.parent,bootstrap:proof.bootstrap},{expectedBootstrap});requireValue(same(built.proof,proof));return built.context;
}
export function verifyCanaryTransitionObservation(snapshot,context,{selection,mode='publication',now=Date.now()}={}){
 const state=contexts.get(context);requireValue(state&&exact(selection,['revision','sourceTree','coordinatorDigest','dataReleaseHash','parameterVersion'])&&hex(selection.revision,40)&&hex(selection.sourceTree,40)&&hex(selection.coordinatorDigest)&&hex(selection.dataReleaseHash)&&Number.isSafeInteger(selection.parameterVersion)&&selection.parameterVersion>0);
 if(typeof snapshot!=='string')jsonValue(snapshot);
 const raw=typeof snapshot==='string'?snapshot:JSON.stringify(snapshot),value=rawSnapshot(raw),s=value.snapshot;
 requireValue(s.revision===selection.revision&&s.sourceTree===selection.sourceTree&&s.coordinatorDigest===selection.coordinatorDigest&&s.dataRelease?.hash===selection.dataReleaseHash&&s.dataRelease.parameterVersion===selection.parameterVersion&&Number.isSafeInteger(now)&&Date.parse(s.observedAt)<=now&&now-Date.parse(s.observedAt)<=300000);
 selectedData(state.old.snapshot,s,state.parent,{mode,now});
 requireValue(same(value.projection.configuration,state.current.projection.configuration)&&same(value.projection.metadata,state.current.projection.metadata)&&value.material.authority===state.proof.currentAuthorityHash&&stableMaterial(value,state.proof.backendProjectionHash)===state.proof.stableMaterialHash);
 return {cloudObservationHash:value.byteHash,stableMaterialHash:state.proof.stableMaterialHash,authorityHash:value.material.authority};
}
export function buildCanaryCompatibilityV3(previous,current,parent,{transition,selection,mode='publication',now=Date.now()}={}){
 const state=contexts.get(transition);requireValue(state&&same(previous,state.old.snapshot)&&same(parent,state.parent));verifyCanaryTransitionObservation(current,transition,{selection,mode,now});
 const images=Object.fromEntries(['worker','mnemo-server','qwen3-embed','llm-proxy'].map(name=>[name,{previousRoot:previous.components[name].rootDigest,currentRoot:current.components[name].rootDigest,previousChild:previous.components[name].arm64Digest,currentChild:current.components[name].arm64Digest}]));
 // The pair is anchored raw evidence. Fresh response metadata has its own
 // cloudObservationHash; it is never mislabeled as this initial raw anchor.
 const material=Object.fromEntries(CANARY_TRANSITION_MATERIALS.map(name=>[name,{previous:state.old.material[name],current:state.current.material[name]}]));
 const certificate={version:3,dataReleaseHash:current.dataRelease.hash,parentProofHash:hash(parent),generation:parent.generation,targetsHash:hash([...parent.targets].sort()),previous:{release:release(previous),backendBindingHash:parent.backendBindingHash},current:{release:release(current),backendBinding:current.backendBinding},images,material,transition:{version:1,kind:CANARY_TRANSITION_KIND,proofHash:transition.proofHash,backendProjectionHash:state.proof.backendProjectionHash}};
 const commitments=inspectCanaryTransitionCertificate(certificate);
 requireValue(commitments.proofHash===hash(state.proof)&&certificate.material.authority.previous===state.proof.previousAuthorityHash&&certificate.material.authority.current===state.proof.currentAuthorityHash&&certificate.material.authority.current===current.material.authority);
 return certificate;
}
