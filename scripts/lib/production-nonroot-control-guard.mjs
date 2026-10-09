/** Fixed, credential-free guard rehearsal against the real CONTROL image.
 * Allowed branches must enter the ORIGINAL application and reject missing
 * configuration locally. No loader hook, replacement module, or business
 * success is used. The credential-order proof combines exact reviewed guard
 * sources with the real event sequence; it is not a fabricated access trace. */
import {readFileSync} from 'node:fs';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash,randomBytes} from 'node:crypto';
import {copyNonrootJson,parseNonrootJson,inspectNonrootRecord,nonrootHash as hash} from './production-nonroot-contracts.mjs';
import {inspectNonrootControlPrerequisites,runNonrootControlDockerCommand} from './production-nonroot-control-prerequisites.mjs';
import {controlImageGraphBinding,imageGraphState,readImageJson} from './production-image-graph.mjs';
import {inspectImageFilesystemEntries,inspectImageFilesystemFile,readImageFilesystemFile} from './production-image-filesystem.mjs';
import {readControlSourceFile,verifyControlSourceClosure} from './production-control-source.mjs';
import {verifyNonrootActualMain} from './production-nonroot-provenance.mjs';
import {inspectGuardManifest} from '../../docker/bootstrap/nonroot-files.mjs';

const states=new WeakMap(),sha=b=>createHash('sha256').update(b).digest('hex');
const need=(v,code='NonrootGuardCaptureInvalid')=>{if(!v)throw Object.assign(Error(code),{code,hold:true});};
const same=(a,b,code='NonrootGuardCaptureBinding')=>need(hash(a)===hash(b),code);
const exact=(v,keys)=>need(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===keys.slice().sort().join(),'NonrootGuardCaptureFields');
const sourcePath='scripts/lib/production-nonroot-control-guard.mjs',collectorBytes=readFileSync(new URL(import.meta.url)),collectorCodeHash=sha(collectorBytes);
const guardPaths=['docker/bootstrap/nonroot-dispatch.mjs','docker/bootstrap/nonroot-files.mjs','docker/bootstrap/nonroot-identity.mjs'];
const appPaths=['scripts/runtime-bootstrap.mjs','scripts/production-consolidation-operator.mjs','scripts/lib/runtime-credentials.mjs'];
const trusted=new Map([...guardPaths,...appPaths].map(path=>[path,readFileSync(new URL('../../'+path,import.meta.url))]));
const purposes={bootstrap:'bootstrap-runtime-verify',control:'consolidation-control',promotion:'consolidation-promote',provision:'denied-provision',transition:'denied-transition'};
const cleanupError=()=>Object.assign(Error('ECLEANUP'),{code:'ECLEANUP',hold:true,cleanupConfirmed:false});

async function prepare(value,options){
 const v=copyNonrootJson(value);exact(v,['contract','actualMain','resolvedLaunches']);
 const expected=copyNonrootJson(options.expected);exact(expected,['contractHash','actualMainHash','resolvedLaunchesHash']);
 same(hash(v.contract),expected.contractHash);same(hash(v.actualMain),expected.actualMainHash);same(hash(v.resolvedLaunches),expected.resolvedLaunchesHash);
 const contract=inspectNonrootRecord('ControlBuildContractV1',v.contract),main=inspectNonrootRecord('ActualMainV1',v.actualMain);
 const prerequisites=inspectNonrootControlPrerequisites(options.prerequisites,{controlVerification:options.controlVerification,sourceContext:options.sourceContext});
 const {graph,filesystem}=options.controlVerification,binding=controlImageGraphBinding(graph),{graphHash,...image}=binding;
 same(prerequisites.record.image,image);same(prerequisites.record.sourceClosureHash,hash(contract.guardSource));
 same(contract.output,{account:image.account,region:image.region,repositoryName:image.repositoryName});
 await verifyNonrootActualMain(main,{...options,expected:{repository:contract.repository,prNumber:contract.prNumber,candidateRevision:contract.candidate.revision,candidateTree:contract.candidate.tree,baseRevision:contract.candidate.baseRevision}});
 need(main.mainTree===options.sourceContext?.tree,'NonrootGuardCaptureSource');await verifyControlSourceClosure(options.sourceContext,contract.guardSource);
 const self=await readControlSourceFile(options.sourceContext,sourcePath);need(self.file.sha256===collectorCodeHash&&self.bytes.equals(collectorBytes),'NonrootGuardCaptureCollectorSource');
 const matched=[];
 for(const [path,raw]of trusted){
  const source=await readControlSourceFile(options.sourceContext,path),imagePath=path.startsWith('docker/bootstrap/')?'/bootstrap/'+path.slice('docker/bootstrap/'.length):'/bootstrap/operator/'+path;
  need(source.bytes.equals(raw),'NonrootGuardCaptureReviewedSource');const file=inspectImageFilesystemFile(filesystem,imagePath);
  need(file.sha256===sha(raw)&&file.size===raw.length&&file.uid===0&&file.gid===0&&(file.mode&0o6022)===0,'NonrootGuardCaptureOriginalModule');
  if(guardPaths.includes(path))need(contract.guardSource.files.some(f=>f.path===path&&f.sha256===file.sha256),'NonrootGuardCaptureClosure');
  matched.push({path,imagePath,sha256:file.sha256});
 }
 const manifestBytes=await readImageFilesystemFile(filesystem,'/bootstrap/nonroot-manifest.json',{maxBytes:8388608}),manifest=inspectGuardManifest(manifestBytes.toString('utf8'));
 const wanted=inspectImageFilesystemEntries(filesystem).filter(e=>e.path.startsWith('bootstrap/')&&e.path!=='bootstrap/nonroot-manifest.json'&&e.type!=='directory').map(e=>'/'+e.path).sort();
 same(manifest.files.map(f=>f.path).sort(),wanted,'NonrootGuardCaptureManifestCoverage');
 for(const file of matched){const row=manifest.files.find(r=>r.path===file.imagePath);need(row?.sha256===file.sha256,'NonrootGuardCaptureManifestBinding');}
 const node=inspectImageFilesystemFile(filesystem,'/usr/local/bin/node');need(manifest.node.sha256===node.sha256&&manifest.node.size===node.size,'NonrootGuardCaptureManifestBinding');
 const state=imageGraphState(graph),descriptor=state.images.get('bootstrap').config,config=await readImageJson(state.store.open(descriptor),{maxBytes:8388608,budget:state.budget});
 same(config.config?.Env??[],prerequisites.environment.imageEnvironment);need(!Object.keys(config.config?.Volumes??{}).length,'NonrootGuardCaptureVolumes');
 need(Array.isArray(v.resolvedLaunches)&&v.resolvedLaunches.length===5,'NonrootGuardCaptureLaunches');const seen=new Set();
 for(const raw of v.resolvedLaunches){const l=inspectNonrootRecord('ResolvedControlLaunchV1',raw),purpose=purposes[l.taskKey];
  need(purpose&&!seen.has(l.taskKey),'NonrootGuardCaptureLaunches');seen.add(l.taskKey);same(l.image,image);need(l.contractHash===hash(contract),'NonrootGuardCaptureContract');
  const template=contract.launchTemplates.find(t=>t.taskKey===l.taskKey);need(template&&template.purpose===purpose&&l.templateHash===hash(template),'NonrootGuardCaptureTemplate');
  same(l.entryPoint,['/bin/setpriv','--no-new-privs','--','/usr/local/bin/node','/bootstrap/nonroot-dispatch.mjs',purpose]);same(l.command,[]);same(l.entryPoint,template.entryPoint);same(l.command,template.command);
  need(l.guardClosureHash===hash(contract.guardSource),'NonrootGuardCaptureClosure');
  if(!purpose.startsWith('denied')){const path=l.taskKey==='bootstrap'?'/bootstrap/operator/scripts/runtime-bootstrap.mjs':'/bootstrap/operator/scripts/production-consolidation-operator.mjs';need(l.originalModule.present&&l.originalModule.value===path&&l.originalModuleSha256.present&&l.originalModuleSha256.value===inspectImageFilesystemFile(filesystem,path).sha256,'NonrootGuardCaptureOriginalModule');}
 }
 return {v,contract,main,graph,filesystem,image,config,manifestHash:sha(manifestBytes),matched,sourceContext:options.sourceContext};
}

function testEnvironment(taskKey,deadlineMs){
 const env={MEM9_STAGE:'prod'};
 if(taskKey==='bootstrap')Object.assign(env,{MEM9_BOOTSTRAP_OPERATION:'runtime-verify',MEM9_RUNTIME_BOOTSTRAP_VERSION:'1'});
 else if(taskKey==='control'||taskKey==='promotion')Object.assign(env,{MEM9_PRODUCTION_WORKER_OPERATOR:taskKey==='control'?'control':'promotion',MEM9_PRODUCTION_CONSOLIDATION_REQUEST:JSON.stringify({operation:taskKey==='control'?'status':'promote',invocation:randomBytes(16).toString('hex'),deadline:deadlineMs})});
 return env;
}
function checkImage(raw,p){
 need(Array.isArray(raw)&&raw.length===1,'NonrootGuardCaptureImage');const image=raw[0];need(image.Os==='linux'&&image.Architecture==='arm64','NonrootGuardCaptureImage');
 if(image.Descriptor)need(image.Descriptor.digest===p.image.rootDigest&&image.Id===p.image.rootDigest,'NonrootGuardCaptureImage');else need(image.Id===p.image.configDigest&&image.RepoDigests?.some(d=>d.endsWith('@'+p.image.rootDigest)),'NonrootGuardCaptureImage');
 same(image.Config,p.config.config);same(image.RootFS,{Type:'layers',Layers:p.config.rootfs.diff_ids});return image;
}
function checkContainer(raw,p,c,exited){
 need(Array.isArray(raw)&&raw.length===1,'NonrootGuardCaptureContainer');const v=raw[0],h=v.HostConfig,config=v.Config;
 need(v.Id===c.id&&v.Name==='/'+c.name&&config.Image===p.image.rootDigest&&config.User==='1000:1000'&&config.Labels?.['mem9-guard-test']===c.name,'NonrootGuardCaptureContainerBinding');
 need([p.image.configDigest,p.image.rootDigest,p.image.arm64Digest].includes(v.Image),'NonrootGuardCaptureContainerBinding');
 if(v.ImageManifestDescriptor)need(v.ImageManifestDescriptor.digest===p.image.arm64Digest,'NonrootGuardCaptureContainerBinding');else need(v.Image===p.image.configDigest,'NonrootGuardCaptureContainerBinding');
 same(config.Entrypoint,['/bin/setpriv']);same(config.Cmd,c.args);
 need(Array.isArray(config.Env)&&new Set(config.Env.map(v=>v.slice(0,v.indexOf('=')))).size===config.Env.length,'NonrootGuardCaptureEnvironment');
 same([...config.Env].sort(),[...c.environment].sort(),'NonrootGuardCaptureEnvironment');
 need(h.NetworkMode==='none'&&h.ReadonlyRootfs===true&&h.Privileged===false&&h.PublishAllPorts===false&&h.PidMode!=='host'&&h.IpcMode!=='host'&&h.UTSMode!=='host'&&!h.UsernsMode,'NonrootGuardCaptureIsolation');
 same(h.CapDrop,['ALL']);need(!h.CapAdd?.length&&h.SecurityOpt?.length===1&&['no-new-privileges','no-new-privileges:true'].includes(h.SecurityOpt[0]),'NonrootGuardCaptureIsolation');
 need(h.PidsLimit===32&&h.Memory===268435456&&h.NanoCpus===1000000000&&h.RestartPolicy?.Name==='no'&&config.Healthcheck?.Test?.[0]==='NONE','NonrootGuardCaptureIsolation');
 for(const key of ['Binds','Devices','DeviceRequests','VolumesFrom'])need(!h[key]?.length,'NonrootGuardCaptureMounts');need(!Object.keys(h.Tmpfs??{}).length&&!v.Mounts?.length,'NonrootGuardCaptureMounts');
 need(v.State?.Running===false&&v.State.Status===(exited?'exited':'created'),'NonrootGuardCaptureState');
 if(exited)need(v.State.Pid===0&&v.State.ExitCode===1&&v.State.OOMKilled===false&&!v.State.Error,'NonrootGuardCaptureExit');return v;
}
function checkEvents(text,p,launch){
 need(Buffer.byteLength(text)<=65536,'NonrootGuardCaptureOutput');const events=text.trim().split('\n').map(line=>parseNonrootJson(line,{maxBytes:16384})),purpose=purposes[launch.taskKey],denied=purpose.startsWith('denied');
 if(denied){same(events,[{event:'nonroot_guard',outcome:'failed',errorClass:'NonrootGuardRejected'}],'NonrootGuardCaptureDenied');return {events,applicationReached:false};}
 need(events.length===2,'NonrootGuardCaptureEvents');const first=events[0];exact(first,['event','outcome','purpose','pid','noNewPrivs','manifestSha256']);
 need(first.event==='nonroot_guard'&&first.outcome==='passed'&&first.purpose===purpose&&Number.isSafeInteger(first.pid)&&first.pid>0&&first.noNewPrivs===1&&first.manifestSha256===p.manifestHash,'NonrootGuardCapturePassed');
 if(launch.taskKey==='bootstrap')same(events[1],{event:'runtime_bootstrap_failed',phase:'configuration',errorClass:'InvalidRuntimeConfiguration'},'NonrootGuardCaptureApplication');
 else same(events[1],{event:'production_consolidation_operator',outcome:'failed',errorClass:'ProductionConsolidationFailed'},'NonrootGuardCaptureApplication');
 return {events,applicationReached:true};
}

export async function collectNonrootControlGuardTests(value,options){
 need(options&&typeof options==='object'&&!Array.isArray(options)&&Object.keys(options).every(key=>['expected','controlVerification','sourceContext','prerequisites','resolveJson','resolveBytes','deadlineMs','signal','beforeDocker'].includes(key)),'NonrootGuardCaptureFields');
 need(options.beforeDocker===undefined||typeof options.beforeDocker==='function','NonrootGuardCaptureFields');
 const startedMs=Date.now(),deadlineMs=Math.min(options.deadlineMs??startedMs+180000,startedMs+180000),p=await prepare(value,options),cases=[];
 need(Number.isSafeInteger(deadlineMs)&&Date.now()<deadlineMs&&!options.signal?.aborted,'NonrootGuardCaptureExpired');
 const directory=await mkdtemp(join(tmpdir(),'mem9-control-guard-'));let held=false;
 try{for(const launch of p.v.resolvedLaunches){
  const name='mem9-guard-test-'+randomBytes(16).toString('hex');let id,attempted=false,sticky=false,primary,record;
  const run=async(stage,args,cleanup=false)=>{
   if(options.beforeDocker){await options.beforeDocker(Object.freeze({stage,taskKey:launch.taskKey,containerId:id,args:Object.freeze([...args])}));}
   if(!cleanup){controlImageGraphBinding(p.graph);need(Date.now()<deadlineMs&&!options.signal?.aborted,'NonrootGuardCaptureExpired');}if(stage==='create')attempted=true;
   try{return await runNonrootControlDockerCommand(args,{directory,timeoutMs:cleanup?10000:Math.min(30000,deadlineMs-Date.now()),signal:cleanup?undefined:options.signal});}catch(e){if(e.code==='ECLEANUP')sticky=true;throw e;}
  };
  const checked=async(stage,args,cleanup=false)=>{const r=await run(stage,args,cleanup);need(r.status===0,'NonrootGuardCaptureDockerCommand');return r;};
  const inspect=async(stage,args)=>parseNonrootJson((await checked(stage,args)).stdout,{maxBytes:1048576});
  try{
   const root=checkImage(await inspect('inspect-image',['image','inspect',p.image.rootDigest]),p),route=testEnvironment(launch.taskKey,Math.min(deadlineMs,Date.now()+60000));
   const args=launch.entryPoint.slice(1),environment=[...(p.config.config?.Env??[]),...Object.entries(route).map(([k,v])=>k+'='+v)],envArgs=Object.entries(route).flatMap(([k,v])=>['--env',k+'='+v]);
   const result=await checked('create',['container','create','--pull=never','--platform=linux/arm64','--network=none','--read-only','--user=1000:1000','--cap-drop=ALL','--security-opt=no-new-privileges:true','--pids-limit=32','--memory=256m','--cpus=1','--restart=no','--no-healthcheck','--label','mem9-guard-test='+name,'--name',name,'--entrypoint','/bin/setpriv',...envArgs,p.image.rootDigest,...args]);
   need(/^[a-f0-9]{64}$/.test(result.stdout.trim()),'NonrootGuardCaptureContainerId');id=result.stdout.trim();const container={id,name,args,environment};
   const before=checkContainer(await inspect('inspect-created',['container','inspect',id]),p,container,false),started=Date.now();
   const out=await run('start',['container','start','--attach',id]);need(out.status===1&&out.stderr==='', 'NonrootGuardCaptureExpectedRejection');
   const after=checkContainer(await inspect('inspect-exited',['container','inspect',id]),p,container,true),checkedEvents=checkEvents(out.stdout,p,launch);
   // The fixed, source-authenticated guard imports only its reviewed helpers
   // before this first event. These helpers read identity, routing and image
   // bytes, never credential values. No credential env/file is supplied here.
   const credentialAccessBeforeGuard=checkedEvents.events.findIndex(e=>e.event==='nonroot_guard')!==0;
   need(!credentialAccessBeforeGuard,'NonrootGuardCaptureOrder');
   record={taskKey:launch.taskKey,launchHash:hash(launch),purpose:purposes[launch.taskKey],environment:route,imageInspectHash:hash(root),createdInspectHash:hash(before),exitedInspectHash:hash(after),stdout:out.stdout,stdoutHash:sha(out.stdout),exitCode:after.State.ExitCode,events:checkedEvents.events,applicationReached:checkedEvents.applicationReached,credentialAccessBeforeGuard,startedMs:started,completedMs:Date.now()};
  }catch(e){primary=e;}
  try{
   if(id){await checked('remove',['container','rm','--force','--volumes',id],true);const absent=await run('inspect-removed',['container','inspect',id],true);need(absent.status===1&&new RegExp('(?:No such container|No such object): '+id+'(?:\\s|$)').test(absent.stderr),'ECLEANUP');if(record)record.cleanup={containerId:id,confirmed:true,absenceHash:sha(absent.stderr)};}
   else if(attempted)sticky=true;need(!sticky,'ECLEANUP');
  }catch{held=true;throw Object.assign(cleanupError(),{containerId:id,containerName:name,operationDirectory:directory});}
  if(primary){primary.cleanupConfirmed=true;throw primary;}cases.push(record);
 }}finally{if(!held)await rm(directory,{recursive:true,force:true});}
 need(Date.now()<deadlineMs&&!options.signal?.aborted,'NonrootGuardCaptureExpired');
 const completedMs=Date.now(),guardTests=copyNonrootJson({version:1,kind:'control-guard-test-evidence',image:p.image,sourceRevision:p.main.mainRevision,sourceTree:p.main.mainTree,guardSourceHash:hash(p.contract.guardSource),contractHash:hash(p.contract),testContractHash:p.contract.guardTestContract.canonicalHash,
  launches:cases.map(c=>({taskKey:c.taskKey,launchHash:c.launchHash,purpose:c.purpose,result:'pass',applicationReached:c.applicationReached,credentialAccessBeforeGuard:c.credentialAccessBeforeGuard})),completedMs});
 const record=copyNonrootJson({version:1,kind:'isolated-original-control-guard-tests',collectorCodeHash,contractHash:hash(p.contract),actualMainHash:hash(p.main),resolvedLaunchesHash:hash(p.v.resolvedLaunches),credentialOrderingBasis:{kind:'fixed-guard-source-and-event-order',matchedSources:p.matched},startedMs,completedMs,cases});
 const handle=Object.freeze({kind:'control-guard-tests-context'});states.set(handle,{p,guardTests,record});return handle;
}

export function inspectNonrootControlGuardTests(handle,{controlVerification,sourceContext,now=Date.now()}={}){
 const state=states.get(handle);need(state,'NonrootGuardCaptureContextRequired');
 need(state.p.graph===controlVerification?.graph&&state.p.filesystem===controlVerification?.filesystem&&state.p.sourceContext===sourceContext,'NonrootGuardCaptureContextBinding');controlImageGraphBinding(state.p.graph);
 need(now>=state.record.completedMs&&now-state.record.completedMs<=300000,'NonrootGuardCaptureStale');
 const objects=[state.guardTests,state.record].map(value=>{const bytes=Buffer.from(JSON.stringify(value)+'\n');return {ref:{bytesHash:sha(bytes),canonicalHash:hash(value),bytesLength:bytes.length},bytes};});
 return {guardTests:copyNonrootJson(state.guardTests),record:copyNonrootJson(state.record),guardTestsRef:objects[0].ref,recordRef:objects[1].ref,objects};
}
