import {nonrootProofFixture} from './production-nonroot.fixture.mjs';
import {nonrootArchiveResolvers} from './lib/production-nonroot-archive.mjs';
import {NONROOT_HARDENING_POLICY,NONROOT_GUARD_BUILTINS,inspectNonrootRecord,nonrootHash as hash} from './lib/production-nonroot-contracts.mjs';
import {controlLaunchPolicy,dataLaunchPolicy,NONROOT_FORBIDDEN_ENVIRONMENT} from './lib/production-nonroot-launch.mjs';
import {createHash} from 'node:crypto';
import {mkdtempSync,rmSync,mkdirSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,dirname} from 'node:path';
import {execFileSync} from 'node:child_process';
import {tar} from './production-image.fixture.mjs';
import {createImageBudget,IMAGE_MEDIA,readControlImageGraph,controlImageGraphBinding} from './lib/production-image-graph.mjs';
import {inspectImageFilesystem,inspectImageFilesystemFile} from './lib/production-image-filesystem.mjs';
import {createControlSourceContext,readControlSourceFile,describeControlCopyClosure,verifyControlBuildCheckout} from './lib/production-control-source.mjs';

async function sourceFixture(files,archiveBytes){
 const directory=mkdtempSync(join(tmpdir(),'nonroot-provenance-git-'));
 try{
  const git=(args,input)=>execFileSync('git',args,{cwd:directory,input,encoding:'utf8',stdio:['pipe','pipe','pipe']}).trim();
  git(['init','--quiet']);const entries=[],blobs=new Map();
  for(const [path,body]of files){const raw=Buffer.from(body),oid=git(['hash-object','-w','--stdin'],raw);entries.push({path,mode:'100644',type:'blob',oid});blobs.set(oid,raw);archiveBytes(raw);mkdirSync(dirname(join(directory,path)),{recursive:true});writeFileSync(join(directory,path),raw,{mode:0o644});git(['update-index','--add','--cacheinfo','100644',oid,path]);}
  const context=createControlSourceContext({tree:git(['write-tree']),entries},async oid=>blobs.get(oid));
  return {context,fingerprint:await verifyControlBuildCheckout(context,directory)};
 }finally{rmSync(directory,{recursive:true,force:true});}
}

async function controlFixture(scope,bodies,archiveBytes){
 const directories=new Set();
 for(const path of bodies.keys()){const parts=path.slice(1).split('/');parts.pop();while(parts.length){directories.add(parts.join('/'));parts.pop();}}
 const entries=[...[...directories].sort().map(path=>({path,type:'5',mode:0o755})),...[...bodies].map(([path,body])=>({path:path.slice(1),body,mode:['/usr/local/bin/node','/bin/busybox'].includes(path)?0o755:0o644})),{path:'bin/setpriv',type:'2',link:'busybox',mode:0o777}];
 const layerBytes=tar(entries);let offset=0;
 for(const entry of entries){const header=layerBytes.subarray(offset,offset+512);header.write(entry.mode.toString(8).padStart(7,'0')+'\0',100);header.fill(32,148,156);let checksum=0;for(const byte of header)checksum+=byte;header.write(checksum.toString(8).padStart(6,'0')+'\0 ',148);offset+=512+Math.ceil(Buffer.byteLength(entry.body??'')/512)*512;}
 const blobs=new Map(),cache=new Map();
 const put=(value,mediaType)=>{const raw=Buffer.isBuffer(value)?value:Buffer.from(JSON.stringify(value)),digest='sha256:'+createHash('sha256').update(raw).digest('hex');blobs.set(digest,raw);return {mediaType,digest,size:raw.length};};
 const layer=put(layerBytes,IMAGE_MEDIA.tar),config=put({architecture:'arm64',os:'linux',rootfs:{type:'layers',diff_ids:[layer.digest]},config:{Env:[]}},IMAGE_MEDIA.config);
 const child=put({schemaVersion:2,mediaType:IMAGE_MEDIA.manifest,config,layers:[layer]},IMAGE_MEDIA.manifest),root=put({schemaVersion:2,mediaType:IMAGE_MEDIA.index,manifests:[{...child,platform:{os:'linux',architecture:'arm64'}}]},IMAGE_MEDIA.index);
 const source={async manifest(_repository,descriptor){return blobs.get(descriptor.digest);},async *blob(_repository,descriptor){yield blobs.get(descriptor.digest);}};
 const store={async put(descriptor,stream){const chunks=[];for await(const chunk of stream)chunks.push(chunk);cache.set(descriptor.digest,Buffer.concat(chunks));},async *open(descriptor){yield cache.get(descriptor.digest);}};
 const graph=await readControlImageGraph({...scope,root,arm64Digest:child.digest,configDigest:config.digest},{source,store,budget:createImageBudget({credentialExpiresMs:Date.now()+3600000})});
 const filesystem=await inspectImageFilesystem(graph,{component:'bootstrap'}),{graphHash,...image}=controlImageGraphBinding(graph);
 const refs=Object.fromEntries([['rootManifest',root],['arm64Manifest',child],['config',config]].map(([name,descriptor])=>[name,archiveBytes(blobs.get(descriptor.digest),'image-graph')]));
 return {graph,filesystem,image,refs};
}

/** Synthetic source/service evidence. No build, deployment, or cloud call. */
export async function nonrootDeploymentFixture({controlArtifactFactory,now:observedNow,baseFixture,sourceOverrides}={}){
 const f=baseFixture??await nonrootProofFixture(),{a,json,bytes,h,g,account,region}=f,now=observedNow??f.now;
 const file=(path,text)=>({path,gitMode:'100644',sha256:f.sha(text),bytes:Buffer.byteLength(text),blob:bytes(text)});
 const job={name:'Build image transition control',steps:[{id:'bootstrap',name:'Build CONTROL image',uses:'docker/build-push-action@'+'a'.repeat(40),with:{context:'.',file:'docker/bootstrap/Dockerfile',platforms:'linux/arm64',pull:true,'no-cache-filters':'runtime',push:true,tags:'reviewed-main-tag','cache-from':'type=gha,scope=control','cache-to':'type=gha,scope=control,mode=max'}}]};
 const sourceFiles=new Map([
  ['.github/workflows/infra-ci.yml',JSON.stringify({jobs:{'build-image-transition-control':job}})],
  ['docker/bootstrap/Dockerfile','FROM synthetic-control\nCOPY docker/bootstrap/nonroot-dispatch.mjs /bootstrap/\nCOPY scripts/ /bootstrap/operator/scripts/\n'],
  ['docker/bootstrap/Dockerfile.dockerignore',['**','!docker/','!docker/bootstrap/','!docker/bootstrap/**','!scripts/','!scripts/*.mjs','!scripts/lib/','!scripts/lib/*.mjs','!infra/','!infra/gateway/','!infra/gateway/service-auth.mjs','!package.json','!package-lock.json','**/*.local.*','**/CLAUDE.local.md','**/.env','**/.env.*','**/.git','**/node_modules','**/.ssh',''].join('\n')],
  ['docker/bootstrap/nonroot-dispatch.mjs','export const testGuard=true;'],
  ['scripts/runtime-bootstrap.mjs','export const syntheticBootstrap=true;'],
  ['scripts/production-consolidation-operator.mjs','export const syntheticOperator=true;'],
  ['README.md','Synthetic complete Git tree, including a non-COPY member.'],
 ]);
 for(const [path,body] of sourceOverrides??[])sourceFiles.set(path,body);
 const {context:sourceContext,fingerprint:checkoutFingerprint}=await sourceFixture(sourceFiles,bytes),deploymentControl={...f.deploymentControl,tree:sourceContext.tree};
 const closure=files=>({version:1,kind:'git-file-closure',tree:sourceContext.tree,files,closureHash:hash(files)});
 const bodies=new Map([['/usr/local/bin/node','synthetic node bytes'],['/bin/busybox','synthetic setpriv bytes'],['/lib/native-loader.so','synthetic native library']]);
 bodies.set('/bootstrap/nonroot-dispatch.mjs',sourceFiles.get('docker/bootstrap/nonroot-dispatch.mjs'));
 for(const path of ['scripts/runtime-bootstrap.mjs','scripts/production-consolidation-operator.mjs'])bodies.set('/bootstrap/operator/'+path,sourceFiles.get(path));
 const scope={account,region,repositoryName:'mem9-on-aws/bootstrap'};
 const controlVerification=controlArtifactFactory?await controlArtifactFactory({scope,bodies,sourceFiles,archiveBytes:bytes}):await controlFixture(scope,bodies,bytes),{image}=controlVerification;
 const imageOnly=({rootDigest,arm64Digest,configDigest})=>({rootDigest,arm64Digest,configDigest});
 const imageUri=`${account}.dkr.ecr.${region}.amazonaws.com/mem9-on-aws/bootstrap@${image.rootDigest}`;
 const expectedMain={repository:f.carrierBuild.source.repository,candidateRevision:deploymentControl.revision,candidateTree:deploymentControl.tree,baseRevision:deploymentControl.baseRevision,prNumber:f.carrierBuild.source.prNumber};
 const main={version:1,kind:'actual-hardening-main',...expectedMain,mainRevision:g('merged-main'),mainTree:expectedMain.candidateTree,parents:[expectedMain.baseRevision,expectedMain.candidateRevision],workflowRun:201,workflowAttempt:1,workflowPath:'.github/workflows/infra-ci.yml',workflowSha:g('merged-main')};
 const source={repository:main.repository,event:'push',ref:'refs/heads/main',checkout:{sha:main.mainRevision,tree:main.mainTree,parents:main.parents,clean:true},main:{sha:main.mainRevision,tree:main.mainTree},run:{id:201,attempt:1,event:'push',headSha:main.mainRevision,repository:main.repository,path:main.workflowPath,workflowSha:main.workflowSha},pullRequest:{number:main.prNumber,state:'closed',merged:true,headSha:main.candidateRevision,headRepository:main.repository,baseRef:'main',mergeCommitSha:main.mainRevision}};
 main.authenticatedSource=json(source);
 const workflow=file('.github/workflows/infra-ci.yml',sourceFiles.get('.github/workflows/infra-ci.yml'));
 const guardSource=closure([file('docker/bootstrap/nonroot-dispatch.mjs',sourceFiles.get('docker/bootstrap/nonroot-dispatch.mjs'))]);
 const guardPolicy={version:1,kind:'guard-source-import-policy',allowedBuiltins:NONROOT_GUARD_BUILTINS,guardSource,sourceImportAudit:json({entryModule:guardSource.files[0].path,allowedBuiltins:NONROOT_GUARD_BUILTINS})};
 const invocation={context:'.',file:'docker/bootstrap/Dockerfile',platforms:['linux/arm64'],pull:true,noCacheFilters:['runtime'],buildArgs:[],buildContexts:[],secretMounts:[],ssh:[],target:null,cacheFrom:['type=gha,scope=control'],cacheTo:['type=gha,scope=control,mode=max'],buildActionSha:'a'.repeat(40),tagRule:'mem9-actual-main-sha7',provenanceRule:'authenticated-workflow-run-attempt'};
 const recipe={dockerfilePath:'docker/bootstrap/Dockerfile',dockerfile:(await readControlSourceFile(sourceContext,'docker/bootstrap/Dockerfile')).file,context:await describeControlCopyClosure(sourceContext),ignoreFiles:json([{path:'.dockerignore',absent:true},(await readControlSourceFile(sourceContext,'docker/bootstrap/Dockerfile.dockerignore')).file]),preparation:closure([]),invocation};
 const purposes={bootstrap:'bootstrap-runtime-verify',control:'consolidation-control',promotion:'consolidation-promote',provision:'denied-provision',transition:'denied-transition'};
 const containerNames={bootstrap:'Mem9Bootstrap',control:'ControlMem9Bootstrap',promotion:'PromoteMem9Bootstrap',provision:'ProdMem9Bootstrap',transition:'TransitionMem9Bootstrap'};
 const templates=Object.entries(purposes).map(([taskKey,purpose])=>({version:1,kind:'guard-first-control-launch',taskKey,containerName:containerNames[taskKey],purpose,entryPoint:controlLaunchPolicy(purpose).entryPoint,command:[],dispatcherPath:'/bootstrap/nonroot-dispatch.mjs',dispatcherSha256:guardSource.files[0].sha256,guardClosure:json(guardSource),originalModule:{present:!purpose.startsWith('denied'),...(!purpose.startsWith('denied')?{value:'/bootstrap/operator/scripts/'+(taskKey==='bootstrap'?'runtime-bootstrap.mjs':'production-consolidation-operator.mjs')}:{})},originalModuleSha256:{present:!purpose.startsWith('denied'),...(!purpose.startsWith('denied')?{value:f.sha(bodies.get('/bootstrap/operator/scripts/'+(taskKey==='bootstrap'?'runtime-bootstrap.mjs':'production-consolidation-operator.mjs')))}:{})},originalArgv:purpose.startsWith('denied')?[]:['node','original-module.mjs'],permittedOperations:purpose.startsWith('denied')?[]:['runtime-verify'],primitiveContract:f.leaf('control-primitive-contract'),buildContractKey:'deployed-bootstrap'}));
 const contract={version:1,kind:'reviewed-deployed-control-build-contract',key:'deployed-bootstrap',repository:main.repository,candidate:deploymentControl,prNumber:main.prNumber,workflow:{path:main.workflowPath,sourceFile:workflow,jobKey:'build-image-transition-control',buildStepId:'bootstrap',jobSource:bytes(JSON.stringify(job))},recipe,guardSource,guardImportPolicy:guardPolicy,launchTemplates:templates,output:{account,region,repositoryName:'mem9-on-aws/bootstrap'},artifactPolicyHash:h('control-policy'),guardTestContract:f.leaf('control-guard-tests'),sourceReview:f.leaf('control-source-review')};
 const libraries=json({files:(controlVerification.nativePaths??['/lib/native-loader.so']).map(path=>({path,sha256:inspectImageFilesystemFile(controlVerification.filesystem,path).sha256}))}),nodeSha=inspectImageFilesystemFile(controlVerification.filesystem,'/usr/local/bin/node').sha256;
 const nodeRuntime={...f.guardImports.nodeRuntime,image:imageOnly(image),executableSha256:nodeSha,loaderAndNativeLibraries:libraries,inventory:json({image:imageOnly(image),executablePath:'/usr/local/bin/node',executableSha256:nodeSha})};
 const guardImports={...f.guardImports,entryModule:guardSource.files[0].blob,localGuardFiles:guardSource,policyHash:hash(guardPolicy),nodeRuntime};
 const controlBodies=new Map(),preBodies=new Map();
 const slot={version:1,kind:'deployed-control-image',buildContractKey:'deployed-bootstrap'};
 const definition=(key,containers)=>{
  if(baseFixture?.target?.[key]){const body=structuredClone(baseFixture.target[key]);for(const c of body.containerDefinitions)c.image=containers.find(row=>row.name===c.name).image;return body;}
  return {family:'mem9-on-aws-prod-example-'+key,networkMode:'awsvpc',requiresCompatibilities:['FARGATE'],runtimePlatform:{cpuArchitecture:'ARM64',operatingSystemFamily:'LINUX'},cpu:'256',memory:'512',taskRoleArn:`arn:aws:iam::${account}:role/example-task`,executionRoleArn:`arn:aws:iam::${account}:role/example-execution`,containerDefinitions:containers};
 };
 const launches=templates.map(t=>{
  const body=definition(t.taskKey,[{...controlLaunchPolicy(t.purpose,{name:t.containerName,environment:[],secrets:[]}),image:imageUri}]);
  controlBodies.set(t.taskKey,body);const before=structuredClone(body);before.containerDefinitions[0].image=slot;preBodies.set(t.taskKey,before);
  const environment={version:1,kind:'prelaunch-environment-gate',image:imageOnly(image),registrationBodyHash:hash(body),overrideHash:hash({}),imageEnvironment:json(controlVerification.config?.config?.Env??[]),taskEnvironment:json([]),secretNamesAndReferences:json([]),overrideEnvironment:json({}),caBindings:[],forbiddenNamesHash:hash({names:NONROOT_FORBIDDEN_ENVIRONMENT,prefix:'LD_'}),loaderFileEvidence:json([]),checkedMs:now-1000,result:'pass'};
  const primitiveFact=inspectImageFilesystemFile(controlVerification.filesystem,'/bin/setpriv');
  const primitive={version:1,kind:'verified-nnp-primitive',image:imageOnly(image),invokedPath:'/bin/setpriv',resolvedPath:'/bin/busybox',fileSha256:primitiveFact.sha256,mode:primitiveFact.mode,uid:primitiveFact.uid,gid:primitiveFact.gid,symlinkChain:json(primitiveFact.symlinkChain),loaderAndLibraries:libraries,privilegeMetadata:f.leaf('primitive-metadata'),featureProbe:f.leaf('primitive-probe'),inheritanceAndNegativeProbes:f.leaf('primitive-negative')};
  return {version:1,kind:'resolved-control-launch',taskKey:t.taskKey,containerName:t.containerName,templateHash:hash(t),contractHash:hash(contract),image,entryPoint:t.entryPoint,command:[],dispatcherSha256:t.dispatcherSha256,guardClosureHash:hash(guardSource),originalModule:t.originalModule,originalModuleSha256:t.originalModuleSha256,originalArgv:t.originalArgv,primitiveEvidence:json(primitive),guardImports,environment,registrationBody:json(body,'task-definition'),registrationBodyHash:hash(body)};
 });
 const actualInvocation={...invocation,tags:[`${account}.dkr.ecr.${region}.amazonaws.com/mem9-on-aws/bootstrap:mem9-${main.mainRevision.slice(0,7)}`],provenance:{repository:main.repository,revision:main.mainRevision,runId:201,attempt:1,jobId:202}};delete actualInvocation.tagRule;delete actualInvocation.provenanceRule;
 const rawRun={id:201,run_attempt:1,event:'push',head_sha:main.mainRevision,head_branch:'main',path:main.workflowPath,repository:{full_name:main.repository}};
 const rawJob={id:202,run_id:201,run_attempt:1,head_sha:main.mainRevision,name:job.name,status:'completed',conclusion:'success',steps:[{name:job.steps[0].name,status:'completed',conclusion:'success'}]};
 const graph=json(controlVerification.refs,'image-graph');
 const scanPages={registryId:account,repositoryName:'mem9-on-aws/bootstrap',imageId:{imageDigest:image.arm64Digest},imageScanStatus:{status:'COMPLETE'},imageScanFindings:{imageScanCompletedAt:new Date(now-1000).toISOString(),findings:[],findingSeverityCounts:{}}};
 const scan={version:1,kind:'deployed-control-scan-evidence',image,rawPages:json([scanPages]),normalizedFindings:json([]),policyHash:contract.artifactPolicyHash,artifactReview:json({version:1,kind:'control-artifact-policy-review',decision:'within-existing-policy',image,policyHash:contract.artifactPolicyHash,findingsHash:hash([]),sourceTree:main.mainTree,reviewedMs:now-750,expiresMs:now+600000}),observedMs:now-1000,result:'pass'};
 const guardTests=json({version:1,kind:'control-guard-test-evidence',image,sourceRevision:main.mainRevision,sourceTree:main.mainTree,guardSourceHash:hash(guardSource),contractHash:hash(contract),testContractHash:contract.guardTestContract.canonicalHash,
  launches:launches.map(l=>({taskKey:l.taskKey,launchHash:hash(l),purpose:purposes[l.taskKey],result:'pass',applicationReached:!purposes[l.taskKey].startsWith('denied'),credentialAccessBeforeGuard:false})),completedMs:now-700});
 const build={version:1,kind:'actual-main-deployed-control-build',contractHash:hash(contract),actualMain:main,source:{repository:main.repository,revision:main.mainRevision,tree:main.mainTree,checkout:json(source.checkout),sourceEvidence:main.authenticatedSource},workflow:{path:main.workflowPath,workflowSha:main.workflowSha,runId:201,attempt:1,jobId:202,jobKey:'build-image-transition-control',buildStepId:'bootstrap',jobName:job.name,authenticatedRun:json(rawRun),authenticatedJob:json(rawJob)},recipe,actualInvocation:json(actualInvocation),buildLog:bytes(`#9 exporting to image\n#9 exporting manifest list ${image.rootDigest}\n#9 exporting manifest ${image.arm64Digest}\n#9 exporting config ${image.configDigest}\n#9 DONE 1.0s\n`,'build'),image,imageGraph:graph,guardSource,guardImports,scan,guardTests,resolvedLaunches:launches,startedMs:now-10000,completedMs:now-500};
 const dataLaunches=['llm-proxy','mnemo-server','qwen3-embed','planner','executor'].map((key,i)=>{const worker=['planner','executor'].includes(key),name=worker?'Mem9Consolidation'+(key==='planner'?'Planner':'Executor'):key,imageBinding=f.images[worker?'llm-proxy':key],container=dataLaunchPolicy(key,{name});return {version:1,kind:'fixed-data-nnp-launch',taskKey:worker?key:'backend',containerName:name,image:imageBinding,originalEntryPoint:container.entryPoint.slice(3),originalCommand:container.command??[],prefix:container.entryPoint.slice(0,3),targetEntryPoint:container.entryPoint,targetCommand:container.command??[],workingDirectory:{present:false},pathEvidence:f.leaf('data-path-'+i),primitiveEvidence:f.leaf('data-primitive-'+i),healthLaunch:{kind:'absent'}};});
 for(const key of ['backend','planner','executor']){const rows=dataLaunches.filter(l=>l.taskKey===key).map(l=>({...dataLaunchPolicy(key==='backend'?l.containerName:key,{name:l.containerName}),image:`${account}.dkr.ecr.${region}.amazonaws.com/mem9-on-aws/${key==='backend'?l.containerName:'llm-proxy'}@${l.image.rootDigest}`}));preBodies.set(key,definition(key,rows));}
 const tasks=[...preBodies].map(([taskKey,body])=>({taskKey,disposition:'update',containerNames:body.containerDefinitions.map(c=>c.name),phase:['planner','executor'].includes(taskKey)?'continuation':['provision','transition'].includes(taskKey)?'registration-only':'deploy',invocation:{backend:'service',planner:'worker-planner',executor:'worker-executor',bootstrap:'runtime-verify',control:'control',promotion:'promote',provision:'deny',transition:'deny'}[taskKey],beforeDefinition:json(body),targetRegistration:json(body,'task-definition'),imageBindings:f.leaf('image-bindings-'+taskKey),baselineEvidence:f.leaf('baseline-'+taskKey)}));
 tasks.push({taskKey:'fallback',disposition:'retain',containerNames:['mnemo-server','qwen3-embed','llm-proxy'],phase:'retained',invocation:'deny',beforeDefinition:json({family:'retained-fallback'}),unchangedBindingHash:hash({family:'retained-fallback'})});
 tasks.push({taskKey:'preaudit',disposition:'carrier',containerNames:['ControlMem9Bootstrap'],phase:'preaudit',invocation:'readonly-root',beforeDefinition:f.plan.registrationBody,targetRegistration:f.plan.registrationBody,carrierBuildHash:hash(f.carrierBuild),baselineEvidence:f.leaf('preaudit-baseline')});
 const cases=['successful-handover','prefix-start-failure','sidecar-readiness-failure','post-liveness-regression','nonterminal-timeout'].map(name=>({name,startedMs:now-20000,completedMs:now-19000,maximumObservedOutageMs:0,oldTaskPreserved:true,deploymentState:'COMPLETED',privateApiPassed:true,rootRelaunchCount:0,evidence:f.leaf(name)}));
 const overlap={version:1,kind:'rolling-healthy-overlap',serviceName:'Mem9Server',strategy:'ROLLING',controller:'ECS',desiredCount:1,minimumHealthyPercent:100,maximumPercent:200,bakeTimeInMinutes:0,circuitBreaker:{enable:true,beforeRollback:true,afterRollback:false},baseline:{observedMs:now-20000,service:f.leaf('service'),task:f.leaf('old-task'),taskArn:f.predeploymentAudit.carrierIdentity.taskArn,taskDefinitionArn:f.predeploymentAudit.carrierIdentity.taskDefinitionArn,containerBindings:f.leaf('containers'),privateApiEvidence:f.leaf('route')},cloudMap:f.leaf('cloudmap'),ordinaryWorkflow:f.leaf('workflow'),rehearsal:{version:1,kind:'bounded-overlap-rehearsal',sourceTree:main.candidateTree,dataImages:f.images,controlBuild:f.leaf('preview-control-build'),configurationHash:h('configuration'),cases,outcome:'overlap-sufficient',evidence:f.leaf('overlap'),completedMs:now-19000},maxPlannedOutageMs:7200000};
 const taskPlan={version:2,kind:'exact-nnp-task-plan',policy:NONROOT_HARDENING_POLICY,tasks,fieldChanges:[],dataLaunches,controlLaunches:templates,previewLaunches:{version:1,kind:'preview-guard-launch-inventory',sourceTree:main.candidateTree,entries:f.leaf('preview-entries'),tests:f.leaf('preview-tests')},carrierBuild:f.carrierBuild,permissions:f.permissions,overlap,beforeProjection:f.leaf('before'),targetProjection:f.leaf('target'),deployedControlBuildContract:contract,previewEvidence:f.leaf('preview-evidence')};
 const resolved={version:1,kind:'resolved-nonroot-task-plan',taskPlanHash:hash(taskPlan),deployedControlBuildHash:hash(build),tasks:tasks.filter(t=>t.disposition==='update').map(t=>({taskKey:t.taskKey,registrationBody:json(controlBodies.get(t.taskKey)??preBodies.get(t.taskKey),'task-definition')})),controlLaunches:launches};
 const record={version:2,kind:'nonroot-deployment-source',descriptorHash:h('descriptor'),parameterVersion:2,proofHash:h('proof'),actualMain:main,deployedControlBuild:build,resolvedTaskPlan:json(resolved),checkedMs:now};
 for(const [type,value]of [['ControlBuildContractV1',contract],['DeployedControlBuildV1',build],['TaskPlanV2',taskPlan],['ResolvedTaskPlanV1',resolved],['DeploymentSourceRecordV2',record]])inspectNonrootRecord(type,value);
 const options=()=>({expected:{contract,taskPlan,descriptorHash:record.descriptorHash,parameterVersion:record.parameterVersion,proofHash:record.proofHash,actualMainExpected:expectedMain,sourceContext},controlVerification:{graph:controlVerification.graph,filesystem:controlVerification.filesystem},...nonrootArchiveResolvers(a.archive()),now});
 return {f,a,json,bytes,now,expectedMain,main,source,job,rawRun,rawJob,actualInvocation,contract,build,taskPlan,resolved,record,preBodies,controlBodies,sourceContext,checkoutFingerprint,controlVerification,options};
}
