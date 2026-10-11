import {createHash} from 'node:crypto';
import {transitionFixture} from './production-canary-transition.fixture.mjs';
import {buildCanaryMaterialTransition} from './lib/production-canary-material-transition.mjs';
import {canaryEvidenceHash as hash} from './lib/production-canary-verification.mjs';
import {IMAGE_TRANSITION_LIMITS,IMAGE_TRANSITION_LIMITS_HASH} from './lib/production-image-transition.mjs';
import {imageTransitionContextBindings,bindImageTransitionAuthorization} from './lib/production-image-transition-proof.mjs';
import {normalizeCanaryTask} from './lib/production-canary-material.mjs';
import {normalizeCanaryAuthority} from './lib/production-canary-material-integrity.mjs';
import {graphFixture,tar} from './production-image.fixture.mjs';
import {IMAGE_MEDIA,createImageBudget,readImageGraph,verifyImageGraphCopies,inspectImageCopyVerification} from './lib/production-image-graph.mjs';
import {inspectImageFilesystem,imageFilesystemProof} from './lib/production-image-filesystem.mjs';

const sha=text=>createHash('sha256').update(text).digest('hex');
export async function imageTransitionFixture({rootCounters,observationNow,layerBytes={},imageConfigurations={},workerContainerNames}={}){
 const legacy=transitionFixture();
 if(workerContainerNames)for(const snapshot of [legacy.previous,legacy.current]){
  for(const kind of ['planner','executor'])Object.assign(snapshot.definitions[kind].containerDefinitions[0],{name:workerContainerNames[kind],entryPoint:['node'],command:['/app/scripts/consolidation-worker.mjs']});
  for(const c of snapshot.definitions.backend.containerDefinitions)if(imageConfigurations[c.name])Object.assign(c,{entryPoint:imageConfigurations[c.name].Entrypoint,command:imageConfigurations[c.name].Cmd});
  legacy.refresh(snapshot);
 }
 if(rootCounters){
  legacy.parent.changedRows=rootCounters.changedRows;legacy.parent.receipts=rootCounters.receipts;
  legacy.current.dataRelease.data.parentProofHash=hash(legacy.parent);
  legacy.current.dataRelease.hash=hash(legacy.current.dataRelease.data);
 }
 const bootstrap=buildCanaryMaterialTransition(legacy.input(),{expectedBootstrap:legacy.expectedBootstrap});
 const {account,region}=legacy.current,now=observationNow??legacy.now,components=['llm-proxy','mnemo-server','qwen3-embed'];
 const images={},artifacts={},native=graphFixture(),roots=[];
 const databaseText='P:zlib\nV:1.3.2-r1\nA:aarch64\n\n';
 for(const name of components){
  const layer=native.put(layerBytes[name]??tar([{path:name==='mnemo-server'?'lib/apk/db/installed':'app/'+name,body:name==='mnemo-server'?databaseText:'synthetic '+name}]),IMAGE_MEDIA.tar);
  const config=native.put({architecture:'arm64',os:'linux',rootfs:{type:'layers',diff_ids:[layer.digest]},...(imageConfigurations[name]?{config:imageConfigurations[name]}:{})},IMAGE_MEDIA.config);
  const childDescriptor=native.put({schemaVersion:2,mediaType:IMAGE_MEDIA.manifest,config,layers:[layer]},IMAGE_MEDIA.manifest),arm64Digest=childDescriptor.digest;
  const payload=native.put({_type:'https://in-toto.io/Statement/v0.1',subject:[{name,digest:{sha256:arm64Digest.slice(7)}}],predicateType:'https://slsa.dev/provenance/v0.2',predicate:{synthetic:true}},IMAGE_MEDIA.attestation);
  const empty=native.put({},IMAGE_MEDIA.config),attestation=native.put({schemaVersion:2,mediaType:IMAGE_MEDIA.manifest,config:empty,layers:[payload]},IMAGE_MEDIA.manifest);
  const rootDescriptor=native.put({schemaVersion:2,mediaType:IMAGE_MEDIA.index,manifests:[{...childDescriptor,platform:{os:'linux',architecture:'arm64'}},{...attestation,platform:{os:'unknown',architecture:'unknown'},annotations:{'vnd.docker.reference.type':'attestation-manifest','vnd.docker.reference.digest':arm64Digest}}]},IMAGE_MEDIA.index);
  const rootDigest=rootDescriptor.digest,root=native.data.get(rootDigest).toString(),child=native.data.get(arm64Digest).toString();images[name]={rootDigest,arm64Digest};
  roots.push({component:name,sourceRepository:'mem9-on-aws/preview/'+name,destinationRepository:'mem9-on-aws/'+name,targetTag:'mem9-fffffff',root:rootDescriptor,arm64Digest});
  const response=(digest,text)=>JSON.stringify({failures:[],images:[{registryId:account,repositoryName:'mem9-on-aws/'+name,imageId:{imageDigest:digest},imageManifest:text}]});
  artifacts[name]={root:response(rootDigest,root),child:response(arm64Digest,child)};
 }
 const predecessor=structuredClone(legacy.current.dataRelease.data),recipe={version:1,synthetic:true},protectedInputs=[{path:'scripts/consolidation-worker.mjs',sha256:sha('unchanged worker')}];
 const sourceEvidence={controlRevision:'4'.repeat(40),controlTree:'e'.repeat(40),build:{revision:'f'.repeat(40),tree:'e'.repeat(40),tag:'pr-fffffff',images:Object.fromEntries(components.map(n=>[n,images[n].rootDigest]))}};
 const controlEvidence={controlRevision:'5'.repeat(40),controlTree:'6'.repeat(40),baseRevision:'7'.repeat(40),repository:'example/memory-service',prNumber:17};
 const dataInputs={version:1,recipe,controlRecipe:structuredClone(recipe),protectedInputs,controlProtectedInputs:structuredClone(protectedInputs)};
 const budget=createImageBudget({now:()=>now-1000,startedMs:now-2000,credentialExpiresMs:now+3600000});
 const sourceGraph=await readImageGraph(roots,{source:native.source,store:native.store,budget});
 const destinationGraph=await readImageGraph(roots,{source:native.source,store:native.store,budget,side:'destination'});
 const graphVerification=verifyImageGraphCopies(sourceGraph,destinationGraph,{account,region}),graph=inspectImageCopyVerification(graphVerification).summary;
 const filesystemVerification=await inspectImageFilesystem(destinationGraph,{component:'mnemo-server',requirements:[{path:'/lib/apk/db/installed',manager:'apk',name:'zlib',version:'1.3.2-r1'}]});
 const filesystem=imageFilesystemProof(filesystemVerification,graphVerification,{path:'/lib/apk/db/installed'});
 const finding=(name,version,cve)=>({name:cve,severity:'HIGH',description:'Synthetic advisory',attributes:[{key:'package_name',value:name},{key:'package_version',value:version}]});
 const fixed=finding('zlib','1.3.2-r0','CVE-2099-1001'),open=finding('gcc-14','14.0-fixture','CVE-2099-1002'),openZlib=finding('zlib','1.3-fixture','CVE-2099-1001');
 const scans={old:{},preview:{},destination:{}};
 const normalized=fs=>fs.map(f=>({...f,attributes:[...f.attributes].sort((a,b)=>hash(a).localeCompare(hash(b)))})).sort((a,b)=>hash(a).localeCompare(hash(b)));
 const rules={};
 for(const name of components){
  const before=name==='mnemo-server'?[fixed]:[open,openZlib],after=name==='mnemo-server'?[]:[open,openZlib];rules[name]={oldHash:hash(normalized(before)),targetHash:hash(normalized(after))};
  for(const phase of Object.keys(scans)){
   const fs=phase==='old'?before:after,repositoryName=(phase==='preview'?'mem9-on-aws/preview/':'mem9-on-aws/')+name;
   const digest=phase==='old'?predecessor.images[name].arm64Digest:images[name].arm64Digest;
   scans[phase][name]=[JSON.stringify({registryId:account,repositoryName,imageId:{imageDigest:digest},imageScanStatus:{status:'COMPLETE'},imageScanFindings:{imageScanCompletedAt:new Date(now-1000).toISOString(),findingSeverityCounts:fs.length?{HIGH:fs.length}:{},findings:fs}})];
  }
 }
 const policySources=[{path:'/synthetic/policy.txt',text:'Apply available security updates; verify isolation and review complete findings.'}];
 const controls=[{clause:'UPDATE-1',policySourceHash:sha(policySources[0].text),evidenceHash:sha('workload controls passed')}];
 const vendor=(cve,pkg,version,status)=>({version:1,cve,package:pkg,suite:status==='fixed'?'alpine':'trixie',packageVersion:version,status,observedMs:now-1000,source:'https://example.com/vendor/'+cve,rawText:JSON.stringify({cve,package:pkg,packageVersion:version,status}),rawHash:sha(JSON.stringify({cve,package:pkg,packageVersion:version,status}))});
 const fixedVendor=vendor(fixed.name,'zlib','1.3.2-r1','fixed'),openVendor=vendor(open.name,'gcc-14','14.0-fixture','unfixed'),openZlibVendor=vendor(openZlib.name,'zlib','1.3-fixture','unfixed');
 const policy={version:1,kind:'image-security-policy',schema:'ecr-basic-full-findings-v1',policySources,requiredControls:controls,rules,fixed:{component:'mnemo-server',findingHash:hash(normalized([fixed])[0]),package:'zlib',oldVersion:'1.3.2-r0',targetVersion:'1.3.2-r1',cve:fixed.name,vendorHash:hash(fixedVendor)},open:components.filter(n=>n!=='mnemo-server').flatMap(component=>[[open,openVendor],[openZlib,openZlibVendor]].map(([f,v])=>({component,findingHash:hash(normalized([f])[0]),package:v.package,packageVersion:v.packageVersion,cve:f.name,vendorHash:hash(v),disposition:'OPEN_UNCHANGED_REQUIRED_CONTROLS_SATISFIED',controls:structuredClone(controls)})))};
 const buildLog=components.map(name=>`[command]/usr/bin/docker buildx build --file docker/${name}/Dockerfile --pull --push --no-cache-filter runtime ${name==='mnemo-server'?'--no-cache-filter builder ':''}--platform linux/arm64 --tag registry/mem9-on-aws/preview/${name}:pr-fffffff .
#1 [runtime 2/4] RUN ${name==='mnemo-server'?'apk upgrade --no-cache':'apt-get dist-upgrade -y'}
#1 DONE 1s
${name==='mnemo-server'?'#2 [builder 2/4] RUN apk upgrade --no-cache\n#2 DONE 1s\n':''}#8 exporting manifest ${images[name].arm64Digest} done
#8 pushing manifest for registry/mem9-on-aws/preview/${name}:pr-fffffff@${images[name].rootDigest} 1s done
  "containerimage.digest": "${images[name].rootDigest}",
`).join('\n');
 const input={version:1,kind:'image-security-upgrade-proof',limits:IMAGE_TRANSITION_LIMITS,predecessorText:JSON.stringify(predecessor),bootstrapProof:bootstrap.proof,dataOrigin:{revision:'f'.repeat(40),sourceTree:'e'.repeat(40),sourceHead:'4'.repeat(40),sourceEvidence,buildCommit:{sha:'f'.repeat(40),tree:'e'.repeat(40),parents:['4'.repeat(40)]}},control:{revision:'5'.repeat(40),sourceTree:'6'.repeat(40),baseRevision:'7'.repeat(40),sourceEvidence:controlEvidence},dataInputs,images,artifacts,graph,filesystem,scans,policy,vendors:[fixedVendor,openVendor,openZlibVendor],buildEvidence:{version:1,logText:buildLog,logHash:sha(buildLog),controls}};
 const expected={predecessorHash:hash(predecessor),parentProofHash:hash(legacy.parent),bootstrapProofHash:bootstrap.proofHash,expectedBootstrap:legacy.expectedBootstrap,dataOriginSourceEvidenceHash:hash(sourceEvidence),buildCommitHash:hash(input.dataOrigin.buildCommit),controlSourceEvidenceHash:hash(controlEvidence),dataInputsHash:hash(dataInputs),graphHash:hash(graph),filesystemHash:hash(filesystem),policyHash:hash(policy),buildEvidenceHash:hash(input.buildEvidence)};
 return {input,expected,now,legacy,predecessor,images,hash,sha,graphVerification,filesystemVerification,native:{...native,roots,sourceGraph,destinationGraph,budget}};
}

export function imageTransitionServingFixture(f,built){
 const bindings=imageTransitionContextBindings(built.context);
 const review={version:1,kind:'image-security-policy-review',decision:'within-existing-policy',artifactPolicyHash:bindings.artifactPolicyHash,imageTransitionProofHash:built.proofHash,controlSourceTree:f.input.control.sourceTree,sourceEvidenceHash:bindings.control.sourceEvidenceHash,dataOriginSourceEvidenceHash:bindings.dataOrigin.sourceEvidenceHash,parentProofHash:f.expected.parentProofHash,buildInputsHash:built.proof.targetBuildInputsHash,securityEvidenceHash:built.proof.targetSecurityEvidenceHash,freshBuildSecurityHash:bindings.freshBuildSecurityHash,policySourcesHash:bindings.policySourcesHash,reviewedMs:f.now,expiresMs:f.now+600000};
 const data={...structuredClone(f.predecessor),version:2,controlSourceTree:f.input.control.sourceTree,dataRevision:f.input.dataOrigin.revision,dataSourceTree:f.input.dataOrigin.sourceTree,dataSourceTag:'mem9-'+f.input.dataOrigin.revision.slice(0,7),images:structuredClone(f.images),buildInputsHash:built.proof.targetBuildInputsHash,securityEvidenceHash:built.proof.targetSecurityEvidenceHash,policyHash:hash(review),authorizationId:'9'.repeat(32),issuedMs:f.now,expiresMs:f.now+600000,
  transition:{version:1,kind:'image-security-upgrade',proofHash:built.proofHash,predecessorHash:f.expected.predecessorHash,limitsHash:IMAGE_TRANSITION_LIMITS_HASH}};
 const current=structuredClone(f.legacy.current);current.revision='8'.repeat(40);current.sourceTree=f.input.control.sourceTree;current.coordinatorDigest='9'.repeat(64);current.sourceTag=data.dataSourceTag;current.controlSourceTag='mem9-'+current.revision.slice(0,7);current.dataRelease={data,hash:hash(data),parameterVersion:2};
 for(const name of ['worker',...Object.keys(f.images)]){const component=name==='worker'?'llm-proxy':name;current.components[name]={registryId:current.account,repositoryName:'mem9-on-aws/'+component,...f.images[component]};}
 const ref=name=>`${current.account}.dkr.ecr.${current.region}.amazonaws.com/mem9-on-aws/${name}@${f.images[name].rootDigest}`;current.workerImage=ref('llm-proxy');
 for(const [kind,definition]of Object.entries(current.definitions))for(const c of definition.containerDefinitions)c.image=ref(kind==='backend'?c.name:'llm-proxy');
 current.definitions.backend.revision=3;current.definitions.backend.taskDefinitionArn=current.definitions.backend.taskDefinitionArn.replace(/:2$/,':3');current.backendBinding.taskDefinitionArn=current.definitions.backend.taskDefinitionArn;current.backendBinding.taskArn=current.backendBinding.taskArn.replace(/b{32}$/,'d'.repeat(32));
 for(const c of current.backendBinding.containers)c.imageDigest=f.images[c.name].arm64Digest;
 current.backendTask.taskArn=current.backendBinding.taskArn;current.backendTask.taskDefinitionArn=current.backendBinding.taskDefinitionArn;
 for(const c of current.backendTask.containers){c.image=ref(c.name);c.imageDigest=f.images[c.name].arm64Digest;}
 const refresh=()=>{const images=new Map([[current.workerImage,current.components.worker]]);for(const c of current.definitions.backend.containerDefinitions)images.set(c.image,current.components[c.name]);for(const name of ['planner','executor','backend'])current.material[name]=hash(normalizeCanaryTask(current.definitions[name],{account:current.account,region:current.region,images}));current.material.network=hash(current.network);current.material.credentials=hash(current.credentials);current.material.authority=hash(normalizeCanaryAuthority(current));};refresh();
 const selection={revision:current.revision,sourceTree:current.sourceTree,coordinatorDigest:current.coordinatorDigest,dataReleaseHash:current.dataRelease.hash,parameterVersion:2};
 return {data,current,selection,refresh,review,authorizationContext:bindImageTransitionAuthorization(built.context,{review,now:f.now})};
}

/** Synthetic protected-descriptor/immutable-archive service fixtures. Anchors
 * are copied before archive tampering tests, never derived from altered bodies. */
export function imageTransitionArchiveFixture(built,served){
 const proof=structuredClone(built.proof),data=structuredClone(served.data),review=structuredClone(served.review);
 const expected={expectedProofHash:served.data.transition.proofHash,expectedReviewHash:served.data.policyHash,expectedDataHash:hash(served.data),expectedScope:{account:served.data.account,region:served.data.region,runtimeNonce:served.data.runtimeNonce,authorizationId:served.data.authorizationId}};
 const input={proof,data,review,
  graphEvidence:{version:1,graphHash:hash(proof.graph),summary:structuredClone(proof.graph),inventory:structuredClone(proof.graphInventory),destinationReadback:structuredClone(proof.destinationReadback)},
  filesystemEvidence:{version:1,filesystemHash:hash(proof.filesystem),evidence:structuredClone(proof.filesystemEvidence),filesystem:structuredClone(proof.filesystem)}};
 return {input,expected};
}
