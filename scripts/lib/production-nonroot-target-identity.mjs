import {need,same,exact,sha} from './ci-smoke-acquisition-format.mjs';
import {nonrootHash as hash,inspectNonrootRecord} from './production-nonroot-contracts.mjs';
import {targetCmdlineHash,targetHealthArgv,createTargetProbe,TARGET_PROBE_HASH,decodeTargetProbeSample,targetProbeRuntime} from './production-nonroot-target-probe.mjs';
import {verifyFutureOwnerDeliveryJournal} from './ci-smoke-owner-delivery.mjs';
const rowKey=p=>p.pid+':'+p.startTimeTicks;
/** Actual proc records are checked against authenticated image filesystem
 * hashes. Root Exec agents are identified by protected file AND process tree,
 * never by a display-name allowlist alone. */
export function assembleTargetIdentity(sample,{target,launch,paths,descriptorHash,deploymentSourceHash,definition,put}){
 need(sample.program.collectorCodeHash===TARGET_PROBE_HASH&&sample.program.healthCommandHash===hash(launch.healthLaunch.after),'TargetWindowCollectorSource');same(sample.program.healthArgv,targetHealthArgv(launch),'TargetWindowHealthSource');
 const raw=decodeTargetProbeSample(sample.raw,launch),rows=new Map();exact(raw,['version','kind','nonce','probePid','startedMs','completedMs','initial','final','health','healthObservedMs','readBytes']);
 const resolution=targetProbeRuntime(launch)==='busybox'?1000:1;
 need(raw.version===1&&raw.kind==='native-target-proc-sample'&&Number.isSafeInteger(raw.readBytes)&&raw.readBytes>=0&&raw.readBytes<=256*1048576&&raw.startedMs+resolution>sample.startedMs&&raw.completedMs<=sample.completedMs&&raw.startedMs<=raw.healthObservedMs&&raw.healthObservedMs<=raw.completedMs,'TargetWindowSampleTimes');
 need(Array.isArray(raw.initial)&&Array.isArray(raw.final)&&raw.initial.length>0&&raw.initial.length<=128&&raw.final.length>0&&raw.final.length<=128,'TargetWindowProcessCoverage');
 for(const set of [raw.initial,raw.final])need(new Set(set.map(p=>p.pid)).size===set.length&&set.some(p=>p.pid===1)&&set.some(p=>p.pid===raw.probePid),'TargetWindowProcessCoverage');
 const stable=new Map(raw.initial.map(p=>[rowKey(p),p]));for(const p of raw.final){const before=stable.get(rowKey(p));if(before)same(before,p,'TargetWindowProcessChanged');rows.set(rowKey(p),p);}for(const p of raw.initial)rows.set(rowKey(p),p);rows.set(rowKey(raw.health),raw.health);need(rows.size<=256,'TargetWindowProcessCoverage');
 const byPid=new Map(raw.final.map(p=>[p.pid,p])),ancestors=new Set();let cursor=byPid.get(raw.probePid);
 let agentFound=false;for(let n=0;cursor&&n<128;n++){need(!ancestors.has(cursor.pid),'TargetWindowProcessCycle');ancestors.add(cursor.pid);if(cursor.executablePath==='/managed-agents/execute-command/amazon-ssm-agent'){agentFound=true;break;}cursor=byPid.get(cursor.ppid);}
 need(agentFound&&ancestors.size>1&&!ancestors.has(1),'TargetWindowProbeAncestry');const files=new Map(paths.map(p=>['/'+p.path.replace(/^\//,''),p])),container=target.containers.find(c=>c.name===sample.component),app=[],trusted=[],managed=[];
 const evidence=put({sample},'runtime-identity');
 for(const p of rows.values()){
  exact(p,['pid','ppid','startTimeTicks','executablePath','executableDigest','file','cmdlineHash','uid','gid','groups','noNewPrivs','capInh','capPrm','capEff','capBnd','capAmb']);exact(p.file,['mode','uid','gid']);need(p.uid.length===4&&p.gid.length===4&&[...p.uid,...p.gid,...p.groups].every(v=>Number.isSafeInteger(v)&&v>=0),'TargetWindowProcessIds');
  need(Number.isSafeInteger(p.pid)&&p.pid>0&&Number.isSafeInteger(p.ppid)&&p.ppid>=0&&Number.isSafeInteger(p.startTimeTicks)&&p.startTimeTicks>0&&/^sha256:[a-f0-9]{64}$/.test(p.executableDigest)&&/^[a-f0-9]{64}$/.test(p.cmdlineHash),'TargetWindowProcessFields');
  const file=files.get(p.executablePath),imageFile=file?.type==='file'&&'sha256:'+file.content.sha256===p.executableDigest&&file.mode===p.file.mode&&file.uid===p.file.uid&&file.gid===p.file.gid;
  const base={pid:p.pid,ppid:p.ppid,startTimeTicks:p.startTimeTicks,executablePath:p.executablePath,executableDigest:p.executableDigest,uid:p.uid,gid:p.gid,groups:p.groups,noNewPrivs:p.noNewPrivs,...Object.fromEntries(['Inh','Prm','Eff','Bnd','Amb'].map(k=>['cap'+k,p['cap'+k]]))};
  if(p.uid.every(n=>n===1000)&&p.noNewPrivs===1){need(imageFile,'TargetWindowExecutableNotInImage');app.push(inspectNonrootRecord('ProcessIdentityV2',{...base,entrypointIdentityHash:p.cmdlineHash}));continue;}
  const taskContainer=definition.containerDefinitions.find(c=>c.name===sample.component);
  if(p.pid===1&&taskContainer.linuxParameters?.initProcessEnabled===true&&p.executablePath==='/dev/init'&&p.uid.every(n=>n===1000)&&p.file.uid===0&&(p.file.mode&0o022)===0){trusted.push(inspectNonrootRecord('TrustedLaunchV1',{kind:'init',...base,evidence}));continue;}
  if(imageFile&&p.executablePath===launch.prefix[0]&&p.uid.every(n=>n===1000)){trusted.push(inspectNonrootRecord('TrustedLaunchV1',{kind:'fixed-nnp-prefix',...base,evidence}));continue;}
  const agent=/^\/managed-agents\/execute-command\/(?:amazon-ssm-agent|ssm-agent-worker|ssm-session-worker)$/.test(p.executablePath);
  const sampler=ancestors.has(p.pid)&&imageFile&&['/usr/local/bin/node','/usr/bin/env','/bin/sh','/bin/busybox','/usr/bin/dash'].includes(p.executablePath);
  need((agent||sampler)&&p.uid.every(n=>n===0)&&p.file.uid===0&&(p.file.mode&0o022)===0&&ancestors.has(p.pid),'TargetWindowUnclassifiedProcess');
  managed.push(inspectNonrootRecord('ManagedProcessV1',{pid:p.pid,ppid:p.ppid,startTimeTicks:p.startTimeTicks,executablePath:p.executablePath,executableDigest:p.executableDigest,managedAgentName:'ExecuteCommandAgent',sessionIdHash:sample.session.sessionIdHash,classificationEvidence:evidence}));
 }
 const mainCandidates=app.filter(p=>(p.pid===1||p.ppid===1)&&p.pid!==raw.health.pid),main=mainCandidates[0];need(mainCandidates.length===1&&stable.has(rowKey(main))&&byPid.get(main.pid)?.startTimeTicks===main.startTimeTicks,'TargetWindowMainProcess');
 const health=app.find(p=>rowKey(p)===rowKey(raw.health));need(health&&sample.program.healthArgv.some(argv=>targetCmdlineHash(argv)===health.entrypointIdentityHash),'TargetWindowHealthProcess');
 const identity=inspectNonrootRecord('RuntimeIdentityV2',{version:2,kind:'application-process-identity',phase:'target',taskKey:'backend',account:target.account,region:target.region,taskArn:target.taskArn,taskDefinitionArn:target.taskDefinitionArn,containerName:sample.component,runtimeId:container.runtimeId,image:container.image,registrationHash:target.registrationHash,launchContractHash:container.launchContractHash,sourceBindingHash:deploymentSourceHash,artifactBinding:{kind:'data',descriptorHash,launchContractHash:container.launchContractHash},collectorCodeHash:sample.program.collectorCodeHash,sessionBinding:evidence,startedMs:sample.startedMs,completedMs:sample.completedMs,application:app,trustedLaunch:trusted,managed,samples:evidence,coverage:put({initial:raw.initial.map(rowKey),final:raw.final.map(rowKey),health:rowKey(raw.health),main:rowKey(main),readBytes:raw.readBytes,remoteLocalCharge:256*1048576},'runtime-identity'),result:'pass'});
 return {identity,main,health,classification:{trustedLaunch:trusted,managed}};
}

/** Replay only an owner artifact acquired from the original protected prefix.
 * The allowance supplies the expected funding independently of the journal. */
export async function replayOwnerTargetWindow({receipt,join,proof,deploymentSource,parameter,funding,json,put}){
 exact(receipt,['version','kind','scope','proofHash','rootBindingHash','descriptorHash','parameterVersion','deploymentSourceHash','targetJoinHash','accounting']);
 need(receipt.version===1&&receipt.kind==='future-target-window-receipt'&&receipt.proofHash===hash(proof)&&receipt.rootBindingHash===hash(proof.root)&&receipt.descriptorHash===hash(JSON.parse(parameter.Value))&&receipt.parameterVersion===parameter.Version&&receipt.deploymentSourceHash===hash(deploymentSource)&&receipt.targetJoinHash===hash(join),'TargetWindowReceiptBinding');
 // The descriptor intentionally carries only root/arm64 digests. Bind the
 // complete target image, including its config, to the authenticated proof.
 for(const target of [join.targetEvidence?.target,join.postAuditObservation?.target]){
  inspectNonrootRecord('TargetBindingV1',target);
  for(const container of target.containers)same(container.image,proof.dataOrigin.images[container.name],'TargetWindowReceiptImage');
 }
 need(funding&&receipt.scope.checkpoint==='deploy-prod/23','TargetWindowFundingRequired');const {issuedMs,notAfter,...expected}=funding;
 const journal=receipt.accounting;verifyFutureOwnerDeliveryJournal(journal,expected);need(journal.events.at(-1).data.outcome==='complete'&&journal.plan.startedMs>=issuedMs&&journal.plan.deadlineMs<=notAfter,'TargetWindowAccountingIncomplete');same(journal.plan.scope,receipt.scope,'TargetWindowAccountingScope');
 const paths=await json(proof.artifactReverification.pathPermissions),before=join.targetEvidence,after=join.postAuditObservation,definition=await json(before.platform.rawDefinition),groups=[];
 const calls=journal.events.filter(e=>e.type==='intent'),completions=journal.events.filter(e=>e.type==='complete'),seen=new Set();
 for(const [phase,identities]of [['pre',before.identity],['post',after.identityRecheck.identities]]){
  const values=[];
  for(const identity of identities){
   const material=await json(identity.sessionBinding);exact(material,['sample']);const sample=material.sample,launch=proof.taskPlan.dataLaunches.find(l=>l.taskKey==='backend'&&l.containerName===identity.containerName);need(launch&&sample.phase===phase&&sample.component===identity.containerName,'TargetWindowReceiptSample');
   need(sample.raw.nonce===hash({allocationId:journal.plan.allocationId,phase,component:sample.component})&&sample.startedMs>=journal.plan.startedMs&&sample.completedMs<=journal.plan.deadlineMs,'TargetWindowReceiptSample');
   const program=createTargetProbe({launch,paths:paths[sample.component],nonce:sample.raw.nonce,deadlineMs:sample.program.deadlineMs});need(program.commandHash===sample.program.commandHash,'TargetWindowReceiptCommand');
   const index=journal.plan.slot.calls.findIndex(c=>c.key===phase+'-'+sample.component+'-execute'),call=calls.filter(e=>e.data.index===index);
   need(index>=0&&call.length===1&&!seen.has(index),'TargetWindowReceiptCall');seen.add(index);
   need(call[0].data.requestHash===hash({cluster:before.target.clusterArn,task:before.target.taskArn,container:sample.component,interactive:true,command:program.command}),'TargetWindowReceiptCall');
   const channel=journal.plan.slot.calls.findIndex(c=>c.key===phase+'-'+sample.component+'-channel'),completion=completions.filter(e=>e.data.index===channel);need(completion.length===1&&completion[0].data.responseHash===sample.wire.responseHash&&completion[0].data.requestHash===sample.wire.requestHash&&completion[0].data.requestBytes===sample.wire.requestBytes&&completion[0].data.responseBytes===sample.wire.responseBytes,'TargetWindowReceiptWire');
   const v=assembleTargetIdentity(sample,{target:before.target,launch,paths:paths[sample.component],descriptorHash:receipt.descriptorHash,deploymentSourceHash:receipt.deploymentSourceHash,definition,put});same(v.identity,identity,'TargetWindowReceiptIdentity');values.push(v);
  }groups.push(values);
 }
 need(seen.size===6,'TargetWindowReceiptCoverage');const [pre,post]=groups;
 return {mainProcesses:Object.fromEntries(pre.map(i=>[i.identity.containerName,{executableDigest:i.main.executableDigest,entrypointIdentityHash:i.main.entrypointIdentityHash}])),healthCommandHashes:Object.fromEntries(pre.map(i=>[i.identity.containerName,hash(proof.taskPlan.dataLaunches.find(l=>l.taskKey==='backend'&&l.containerName===i.identity.containerName).healthLaunch.after)])),processClassifications:Object.fromEntries(pre.map(i=>{const later=post.find(v=>v.identity.containerName===i.identity.containerName);return [i.identity.containerName,{trustedLaunch:[...i.classification.trustedLaunch,...later.classification.trustedLaunch],managed:[...i.classification.managed,...later.classification.managed]}];})),platformVersion:before.platform.platformVersion};
}
