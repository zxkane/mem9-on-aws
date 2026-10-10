import {describe,it,expect,beforeAll,afterAll,vi} from 'vitest';
import {dockerArtifactFixture} from './production-nonroot-observation.fixture.mjs';
import {nonrootDeploymentWrapperFixture} from './production-nonroot-deployment.fixture.mjs';
import {nonrootBundleRecords} from './production-nonroot-bundle.fixture.mjs';
import {transitionFixture} from './production-canary-transition.fixture.mjs';
import {collectNonrootControlRuntime} from './lib/production-nonroot-observation.mjs';
import {bindNonrootDeploymentContext,getNonrootTargetRegistration} from './lib/production-nonroot-proof.mjs';
import {createNonrootDeploymentBundle,restoreImageDeploymentBundle,createImageDeploymentPhaseReceipt} from './lib/production-image-deployment-bundle.mjs';
import {writeImageDeploymentBundle,removeImageDeploymentBundle} from './lib/production-image-deployment-bundle.mjs';
import {exportNonrootArchive} from './lib/production-nonroot-archive.mjs';
import {nonrootHash as hash} from './lib/production-nonroot-contracts.mjs';
import {nonrootAuthorizationBindings} from './lib/production-nonroot-proof.mjs';
import {verifyImageSecurityDeployment} from './verify-image-security-deployment.mjs';
import {loadDeploymentDataRelease,loadWorkerDataRelease} from './lib/production-data-release-loader.mjs';
import {installImageAuthorization,getImageAuthorization} from './lib/production-image-admission.mjs';
import {Readable} from 'node:stream';
import {mkdtemp,rm,mkdir,writeFile,readFile,open,readdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,dirname} from 'node:path';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {imageGraphState} from './lib/production-image-graph.mjs';
import {controlSourcePaths,readControlSourceFile} from './lib/production-control-source.mjs';
import {openCiSmokeAcquisition,acquisitionOwnerKey} from './lib/ci-smoke-acquisition.mjs';
import {zero,prepaidSlotBudget,sha} from './lib/ci-smoke-acquisition-format.mjs';
import {S3Client} from '@aws-sdk/client-s3';

describe.skipIf(process.env.MEM9_NONROOT_CONTAINER_TEST!=='1')('v3 deployment bundle with real opaque evidence',()=>{
 let docker,f,records,evidence,context,bundle,options;
 beforeAll(async()=>{
  vi.useFakeTimers({toFake:['Date']});vi.setSystemTime(transitionFixture().now+7200000);
  docker=dockerArtifactFixture();f=await nonrootDeploymentWrapperFixture({controlArtifactFactory:docker.factory()});
  const runtimeObservation=await collectNonrootControlRuntime(f.d.build,{...f.d.options(),beforeDocker:({containerId})=>{if(containerId)docker.containers.add(containerId);}});
  evidence={...f.evidence,runtimeObservation};records=await nonrootBundleRecords(f);
  context=await bindNonrootDeploymentContext(f.authorization,{parameter:f.parameter,deploymentSource:f.deploymentSource,phaseEvidence:f.phaseEvidence,evidence,now:f.f.now});
  bundle=await createNonrootDeploymentBundle({...records,context,evidence,deploymentSource:f.deploymentSource,phaseEvidence:f.phaseEvidence,targetObservation:f.targetObservation},f.d.source,f.parameter,{phase:'deployment',sourceReceiptHash:records.sourceReceiptHash,now:f.f.now});
  options={parameter:f.parameter,expected:{stage:'prod',account:f.current.account,region:f.current.region,controlSourceTree:f.current.controlSourceTree},controlRevision:f.d.main.mainRevision,now:f.f.now,nonrootEvidence:evidence};
 },120000);
 afterAll(async()=>{try{await docker?.close();}finally{vi.useRealTimers();}},120000);
 it('round trips evidence bytes and returns a real deployment context',async()=>{
  const restored=await restoreImageDeploymentBundle(JSON.parse(JSON.stringify(bundle)),options);
  expect(getNonrootTargetRegistration(restored,'control')).toEqual(f.d.controlBodies.get('control'));
  expect(bundle.phaseReceipt.phase).toBe('preconfigure');expect(bundle.phaseReceipt.sourceReceiptHash).toBe(records.sourceReceiptHash);
  expect(bundle).not.toHaveProperty('runtimeObservation');expect(bundle).not.toHaveProperty('sourceContext');
 });
 it.each(['preconfigure','presst'])('restores genuine evidence through the actual %s entry in a separate process',async phase=>{
  const root=await mkdtemp(join(tmpdir(),'nonroot-sst-replay-')),cache=join(root,'cache'),repo=join(root,'repo');let owned,send;
  const put=async(name,value)=>{const bytes=Buffer.from(JSON.stringify(value)),path=join(root,name);await writeFile(path,bytes,{mode:0o600});return {path,sha256:sha(bytes)};};
  try{
   await mkdir(cache,{mode:0o700});await mkdir(repo,{mode:0o700});
   const graph=f.d.controlVerification.graph,state=imageGraphState(graph);
   for(const node of graph.inventory.nodes){const fd=await open(join(cache,node.digest.slice(7)),'wx',0o600);try{for await(const chunk of state.store.open(node))await fd.write(chunk);}finally{await fd.close();}}
   for(const path of controlSourcePaths(f.d.sourceContext)){const target=join(repo,path);await mkdir(dirname(target),{recursive:true});await writeFile(target,(await readControlSourceFile(f.d.sourceContext,path)).bytes,{mode:0o644});}
   const git=args=>execFileSync('git',args,{cwd:repo,encoding:'utf8',stdio:['ignore','pipe','pipe']});
   git(['init','--quiet']);git(['add','.']);git(['-c','user.name=Fixture','-c','user.email=user@example.com','commit','-qm','test: synthetic source']);
   await mkdir(join(repo,'infra'),{recursive:true});
   const data=f.current,scope={descriptorHash:hash(data),proofHash:f.built.proofHash,sourceTree:f.d.main.mainTree,repository:f.d.source.repository,
    mainRevision:f.d.main.mainRevision,runId:f.d.source.run.id,runAttempt:f.d.source.run.attempt,jobKey:'deploy-prod',route:'deploy-prod',phase,checkpoint:phase==='presst'?'deploy-prod/19':'deploy-prod/17',account:data.account,region:data.region};
   const source={current:{repository:scope.repository,runId:scope.runId,runAttempt:scope.runAttempt,job:scope.jobKey,revision:scope.mainRevision},checkout:{revision:scope.mainRevision,tree:scope.sourceTree},observedMs:f.f.now-500,expiresMs:f.phaseEvidence.expiresMs};
   const sourceRef=await put('source.json',source),phaseEvidence={...f.phaseEvidence,phase};
   const checked=await bindNonrootDeploymentContext(f.authorization,{parameter:f.parameter,deploymentSource:f.deploymentSource,phaseEvidence,evidence,now:f.f.now});
   const selected=await createNonrootDeploymentBundle({...records,context:checked,evidence:{...evidence,controlCache:{directory:cache,inventory:graph.inventory}},deploymentSource:f.deploymentSource,phaseEvidence,targetObservation:f.targetObservation},f.d.source,f.parameter,{phase:'deployment',sourceReceiptHash:sourceRef.sha256,now:f.f.now});
   owned=await writeImageDeploymentBundle(selected,{environmentFile:join(root,'env')});
   const bundleRef={path:owned.file,sha256:owned.digest},binding={owner:data.authorizationId,executionId:'e'.repeat(32),planHash:'a'.repeat(64),publicationHash:'b'.repeat(64)};
   const storage={bucket:'example-owned-artifacts',requestBytes:4096,responseBytes:33554432,kmsKeyArn:`arn:aws:kms:${data.region}:${data.account}:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee`,bucketKeyEnabled:true};
   const key=acquisitionOwnerKey({descriptor:data,expected:{scope}});
   const calls=[{action:'GetObject',request:{Bucket:storage.bucket,Key:key,ExpectedBucketOwner:data.account},requestBytes:4096,responseBytes:33554432,ecr:false},
    {action:'GetParameters',request:{Names:[f.parameter.Name],WithDecryption:true},requestBytes:4096,responseBytes:65536,ecr:false}];
   const localBudget={...zero(),logicalBytes:1000000000,uncompressedBytes:2000000000,processedEntries:80000},budget=prepaidSlotBudget(calls,localBudget);
   const plan={version:1,kind:'named-prepayment-plan',catalogHash:'c'.repeat(64),ledgerBinding:binding,scope,calls,localBudget,budget},allocationId=hash(plan);
   const start={version:1,kind:'custody-ledger-start',binding,startingCounters:zero(),reserve:budget,deadlineMs:f.f.now+180000,mode:'adoption'},startRaw=Buffer.from(JSON.stringify(start));
   const event={version:1,sequence:1,...binding,previousHash:null,type:'prepayment',data:{allocationId,planHash:hash(plan),scopeHash:hash(scope),charge:budget,reserveDebit:budget},spent:budget,remaining:zero()};
   const allocation={version:2,kind:'owner-prepaid-named-allocation',authority:false,allocationId,plan,runEvidence:{observedMs:f.f.now-1000,
    run:{...f.d.rawRun,status:'in_progress',created_at:new Date(f.f.now-10000).toISOString()},commit:{sha:scope.mainRevision,tree:{sha:scope.sourceTree}}},
    debit:{start,startRaw:startRaw.toString('base64'),events:[event],checkpoint:{binding,startingCounters:zero(),counters:budget,remainingReservation:zero(),eventCount:1,lastEventHash:hash(event),active:0,sealed:false}}};
   const config={version:1,kind:'owner-ci-acquisition-config',account:data.account,region:data.region,ownerRoot:{runtimeNonce:data.runtimeNonce,authorizationId:data.authorizationId},ledgerBinding:binding,ledgerStartHash:sha(startRaw),catalogHash:plan.catalogHash,expiresMs:source.expiresMs,target:{kind:'production-data-release',descriptor:data,parameterVersion:f.parameter.Version},storage};
   const env={PATH:process.env.PATH,HOME:root,LANG:'C.UTF-8',GITHUB_ACTIONS:'true',GITHUB_REPOSITORY:scope.repository,GITHUB_RUN_ID:String(scope.runId),GITHUB_RUN_ATTEMPT:String(scope.runAttempt),GITHUB_JOB:scope.jobKey,GITHUB_SHA:scope.mainRevision,GITHUB_WORKSPACE:repo,AWS_REGION:data.region,STAGE:'prod',RUNNER_TEMP:root,
    AWS_ACCESS_KEY_ID:'synthetic-host-only',AWS_SECRET_ACCESS_KEY:'synthetic-host-only',AWS_SESSION_TOKEN:'synthetic-host-only',MEM9_CI_ACQUISITION_CONFIG:JSON.stringify(config),
    MEM9_CI_SMOKE_SOURCE_RECEIPT:sourceRef.path,MEM9_CI_SMOKE_SOURCE_RECEIPT_HASH:sourceRef.sha256,MEM9_IMAGE_TRANSITION_BUNDLE_FILE:owned.file,MEM9_IMAGE_TRANSITION_BUNDLE_HASH:owned.digest};
   const allocationRaw=Buffer.from(JSON.stringify(allocation));
   send=vi.spyOn(S3Client.prototype,'send').mockImplementation(async command=>{expect(command.input.Key).toBe(key);return {$metadata:{httpStatusCode:200},ContentLength:allocationRaw.length,Body:Readable.from([allocationRaw]),ServerSideEncryption:'aws:kms',SSEKMSKeyId:storage.kmsKeyArn,BucketKeyEnabled:true};});
   const slot=await openCiSmokeAcquisition({env,scope:{route:scope.route,phase:scope.phase,checkpoint:scope.checkpoint},sourceReceipt:source,host:{env,checkout:async()=>source.checkout}});
   const meter=await slot.beforeRead('GetParameters',calls[1].request);meter.finalGuard();await meter.complete({Parameters:[f.parameter],InvalidParameters:[]},sha(JSON.stringify(f.parameter)));
   slot.reserveLocal({...zero(),logicalBytes:1000});const completed=await slot.finish({bundleRef});send.mockRestore();send=undefined;
   env.MEM9_CI_ACQUISITION_COMPLETION_FILE=completed.receiptRef.path;env.MEM9_CI_ACQUISITION_COMPLETION_HASH=completed.receiptRef.sha256;
   const b=nonrootAuthorizationBindings(checked),previous=b.previousSelection,prefix='/mem9-on-aws/prod/';
   const selection={version:1,mode:'retained',controlTag:b.previousControlTag,dataTag:previous.dataSourceTag,images:previous.images,dataReleaseHash:previous.dataReleaseHash,arm64Digests:previous.arm64Digests};
   const operator={version:3,stage:'prod',account:data.account,region:data.region,generation:data.generation,dataReleaseParameter:f.parameter.Name,dataReleaseParameterVersion:f.parameter.Version-1,sourceTag:previous.dataSourceTag,workerImage:previous.images['llm-proxy'],dataReleaseHash:previous.dataReleaseHash};
   const parameter=(Name,value)=>({Name,Type:'String',Version:1,ARN:`arn:aws:ssm:${data.region}:${data.account}:parameter${Name}`,Value:JSON.stringify(value)});
   const input=await put('input.json',{parameter:f.parameter,expected:options.expected,controlRevision:scope.mainRevision,now:f.f.now,
    parameters:[f.parameter,parameter(prefix+'ecs/image-selection',selection),parameter(prefix+'consolidation-runtime/operator-manifest',operator)],
    runtime:{phase:'complete',status:'running',stage:'prod',nonce:data.runtimeNonce,schemaDigest:data.schemaDigest,operatorDigest:data.operatorDigest},buildInputsHash:data.buildInputsHash,dataHash:hash(data)});
   env.MEM9_SYNTHETIC_INPUT=input.path;
   const proofModule=new URL('./lib/production-nonroot-proof.mjs',import.meta.url).href,hashModule=new URL('./lib/production-nonroot-contracts.mjs',import.meta.url).href;
   const shared=`import {readFile} from 'node:fs/promises';import {getNonrootTargetRegistration} from ${JSON.stringify(proofModule)};import {nonrootHash} from ${JSON.stringify(hashModule)};const input=JSON.parse(await readFile(process.env.MEM9_SYNTHETIC_INPUT));Date.now=()=>input.now;let reads=0;`;
   let code;
   if(phase==='preconfigure'){
    const runtimeModule=new URL('./run-production-runtime.mjs',import.meta.url).href,admissionModule=new URL('./lib/production-image-admission.mjs',import.meta.url).href;
    code=shared+`import {retainedDeploymentEnvironment} from ${JSON.stringify(runtimeModule)};import {getImageAuthorization} from ${JSON.stringify(admissionModule)};const clients={ssm:{send:async command=>{if(JSON.stringify(command.input.Names)!==JSON.stringify(input.parameters.map(p=>p.Name)))throw Error('UnexpectedExtraSsmRead');reads++;return {Parameters:input.parameters,InvalidParameters:[]};}}};const exported=await retainedDeploymentEnvironment(clients,{...input.expected,controlRevision:input.controlRevision,runtime:input.runtime});if(exported.MEM9_RETAINED_DATA_RELEASE_HASH!==input.dataHash)throw Error('WrongExport');console.log(JSON.stringify({controlHash:nonrootHash(getNonrootTargetRegistration(getImageAuthorization(clients),'control')),reads}));`;
   }else{
    Object.assign(env,{MEM9_PRODUCTION_RUNTIME_MODE:'active',MEM9_RETAINED_DATA_RELEASE:JSON.stringify(data),MEM9_RETAINED_DATA_RELEASE_HASH:hash(data),MEM9_RETAINED_DATA_RELEASE_VERSION:String(f.parameter.Version)});
    // Cloud/GitHub identities are synthetic. Git tree membership, cache bytes,
    // the actual ecr.ts entry, runtime isolation and final proof replay are real.
    const ecrModule=new URL('../infra/ecr.ts',import.meta.url).href;
    code=shared+`import childProcess from 'node:child_process';import {syncBuiltinESMExports} from 'node:module';const original=childProcess.execFileSync;childProcess.execFileSync=(file,args,opts)=>file==='git'&&args.join(' ')==='rev-parse HEAD'?input.controlRevision+'\\n':original(file,args,opts);syncBuiltinESMExports();const unwrap=async v=>v&&Object.hasOwn(v,'_out')?unwrap(await v._out):v instanceof Promise?unwrap(await v):v;const out=v=>({_out:v,apply:fn=>out(unwrap(v).then(fn))});globalThis.$app={stage:'prod'};globalThis.aws={getCallerIdentityOutput:()=>({accountId:out(input.expected.account)}),getRegionOutput:()=>({name:out(input.expected.region)}),ssm:{getParameterOutput:request=>{if(request.name!==input.parameter.Name)throw Error('WrongParameter');reads++;return out({name:input.parameter.Name,arn:input.parameter.ARN,type:input.parameter.Type,version:input.parameter.Version,value:input.parameter.Value});}}};const {selectedNonrootTaskRegistration}=await import(${JSON.stringify(ecrModule)});console.log(JSON.stringify({controlHash:nonrootHash(await unwrap(selectedNonrootTaskRegistration('control'))),reads}));`;
   }
   const output=execFileSync(process.execPath,['--input-type=module','-e',code],{cwd:join(repo,'infra'),env,encoding:'utf8',timeout:120000,maxBuffer:1048576});
   expect(JSON.parse(output.trim())).toEqual({controlHash:hash(f.d.controlBodies.get('control')),reads:phase==='presst'?1:2});
   const names=await readdir(join(root,'mem9-ci-acquisitions')),suffix=phase==='presst'?'sst':'configure',receipt=JSON.parse(await readFile(join(root,'mem9-ci-acquisitions',names.find(name=>name.endsWith('-local-'+suffix+'-complete.json')))));
   expect(receipt.startingLocalUsed.logicalBytes).toBe(1000);expect(receipt.localUsed.logicalBytes).toBeGreaterThan(1000);
   expect(receipt.localUsed.ecrRequests).toBe(0);expect(receipt.localUsed.httpBodyBytes).toBe(0);
  }finally{send?.mockRestore();if(owned)await removeImageDeploymentBundle({MEM9_IMAGE_TRANSITION_BUNDLE_FILE:owned.file,MEM9_IMAGE_TRANSITION_BUNDLE_HASH:owned.digest});await rm(root,{recursive:true,force:true});}
 },125000);
 it.each(['missing','graph','filesystem','source','runtime'])('rejects %s opaque evidence instead of accepting JSON claims',async defect=>{
  const selected={...evidence};
  const field={graph:'controlGraph',filesystem:'controlFilesystemVerification',source:'sourceContext',runtime:'runtimeObservation'}[defect];
  if(field)selected[field]=structuredClone(selected[field]);
  await expect(restoreImageDeploymentBundle(bundle,{...options,nonrootEvidence:defect==='missing'?undefined:selected})).rejects.toThrow();
 });
 it.each([1,2,4,99])('rejects parameter Version %i with identical descriptor bytes',async Version=>{
  const parameter={...f.parameter,Version};await expect(restoreImageDeploymentBundle({...bundle,parameter},{...options,parameter})).rejects.toThrow();
 });
 it('rejects a publication operation whose predecessor metadata differs from the proof',async()=>{
  const changed=structuredClone(bundle);changed.operation.predecessor.ARN=changed.operation.predecessor.ARN.replace(':'+f.current.region+':',':us-east-2:');
  const commitment=JSON.parse(changed.operation.operation.expected.newValue);commitment.predecessorHash=hash(changed.operation.predecessor);changed.operation.operation.expected.newValue=JSON.stringify(commitment);
  await expect(restoreImageDeploymentBundle(changed,options).then(()=>true)).rejects.toThrow('NonrootArchivePredecessor');
 });
 it('cannot restore a source-only bundle as deployment authority',async()=>{
  const source=await createNonrootDeploymentBundle({...records,context:f.authorization},f.d.source,f.parameter,{phase:'source',sourceReceiptHash:records.sourceReceiptHash,now:f.f.now});
  await expect(restoreImageDeploymentBundle(source,options)).rejects.toThrow('NonrootDeploymentPhaseRequired');
 });
 it('rejects a separately valid source run that is not the deployed CONTROL build run',async()=>{
  const changed=structuredClone(bundle);changed.source.run.id++;
  await expect(restoreImageDeploymentBundle(changed,options)).rejects.toThrow('NonrootDeploymentSourceChanged');
 });
 it.each(['deploymentSource','phaseEvidence','targetObservation'])('refuses to export %s not verified by the deployment context',async field=>{
  const material={...records,context,evidence,deploymentSource:structuredClone(f.deploymentSource),phaseEvidence:structuredClone(f.phaseEvidence),targetObservation:structuredClone(f.targetObservation)};
  if(field==='deploymentSource')material[field].checkedMs--;
  else material[field].observedMs--;
  await expect(createNonrootDeploymentBundle(material,f.d.source,f.parameter,{phase:'deployment',sourceReceiptHash:records.sourceReceiptHash,now:f.f.now}).then(()=>true)).rejects.toThrow('NonrootDeploymentMaterialChanged');
 });
 it('bounds phase receipts by the original registry observation and rechecks getters at that boundary',async()=>{
  const targetObservation={...f.targetObservation,observedMs:f.f.now-290000};
  const checked=await bindNonrootDeploymentContext(f.authorization,{parameter:f.parameter,deploymentSource:f.deploymentSource,phaseEvidence:f.phaseEvidence,evidence:{...evidence,targetObservation},now:f.f.now});
  const receipt=createImageDeploymentPhaseReceipt(checked,{sourceReceiptHash:records.sourceReceiptHash,phase:'preconfigure',now:f.f.now});
  expect(receipt.expiresMs).toBe(targetObservation.observedMs+300000);
  try{
   vi.setSystemTime(receipt.expiresMs);
   expect(()=>getNonrootTargetRegistration(checked,'control')).toThrow('NonrootDeploymentExpired');
  }finally{vi.setSystemTime(f.f.now);}
 });
 it('does not restamp a phase receipt or accept the wrong phase',()=>{
  const receipt=createImageDeploymentPhaseReceipt(context,{sourceReceiptHash:records.sourceReceiptHash,phase:'preconfigure',now:f.f.now+1});
  expect(receipt.observedMs).toBe(f.phaseEvidence.observedMs);expect(receipt.expiresMs).toBeLessThanOrEqual(f.phaseEvidence.expiresMs);
  expect(()=>createImageDeploymentPhaseReceipt(context,{sourceReceiptHash:records.sourceReceiptHash,phase:'presst',now:f.f.now})).toThrow();
  expect(()=>createImageDeploymentPhaseReceipt(context,{sourceReceiptHash:records.sourceReceiptHash,phase:'preconfigure',now:f.phaseEvidence.expiresMs})).toThrow();
 });
 async function cliFixture(){
  const blobs={'operation.json':Buffer.from(JSON.stringify(records.operation)),'nonroot-proof-archive.json':Buffer.from(JSON.stringify(await exportNonrootArchive(records.proofArchive)))},calls=[];
  const clients={sts:{send:async()=>({Account:f.current.account,Arn:`arn:aws:sts::${f.current.account}:assumed-role/deploy/test`})},ssm:{send:async()=>({Parameters:[f.parameter]})},s3:{send:async command=>{
   calls.push(command.input);const bytes=blobs[command.input.Key.split('/').at(-1)];
   return {Body:Readable.from([bytes]),ContentLength:bytes.length,ServerSideEncryption:'aws:kms',SSEKMSKeyId:`arn:aws:kms:${f.current.region}:${f.current.account}:key/synthetic-existing-key`,ETag:'synthetic-etag'};
  }}};
  const source=f.d.source,env={STAGE:'prod',GITHUB_ACTIONS:'true',MEM9_DEPLOY_ROLE_ARN:`arn:aws:iam::${f.current.account}:role/deploy`,GITHUB_REPOSITORY:source.repository,GITHUB_EVENT_NAME:'push',GITHUB_REF:'refs/heads/main',GITHUB_SHA:source.checkout.sha,GITHUB_WORKFLOW_SHA:source.checkout.sha,GITHUB_RUN_ID:String(source.run.id),GITHUB_RUN_ATTEMPT:String(source.run.attempt)};
  const api=async path=>{
   if(path.startsWith('commits/'))return {sha:source.checkout.sha,commit:{tree:{sha:source.checkout.tree}},parents:source.checkout.parents.map(sha=>({sha}))};
   if(path.startsWith('pulls/'))return {number:source.pullRequest.number,state:'closed',merged:true,head:{sha:source.pullRequest.headSha,repo:{full_name:source.repository}},base:{ref:'main'},merge_commit_sha:source.checkout.sha};
   return {id:source.run.id,run_attempt:source.run.attempt,event:'push',head_sha:source.checkout.sha,head_repository:{full_name:source.repository},path:source.run.path};
  };
  return {clients,calls,blobs,deps:{clients,git:async args=>args[0]==='show'?[source.checkout.sha,source.checkout.tree,source.checkout.parents.join(' ')].join('\n'):'',api,clock:()=>f.f.now},options:{env,region:f.current.region,sourceReceiptHash:records.sourceReceiptHash}};
 }
 it('loads the protected private archive through the real CLI source branch without a target claim',async()=>{
  const c=await cliFixture(),result=await verifyImageSecurityDeployment(c.deps,c.options);
  expect(result.phase).toBe('nonroot-security-source-verified');expect(result.bundle.phase).toBe('source');expect(result).not.toHaveProperty('phaseReceipt');
  expect(c.calls.map(x=>x.Key.split('/').at(-1))).toEqual(['operation.json','nonroot-proof-archive.json']);
  for(const call of c.calls)expect(call.ExpectedBucketOwner).toBe(f.current.account);
 });
 it('emits target phase evidence only after real opaque collector evidence reaches the binder',async()=>{
  const c=await cliFixture(),{targetObservation,...handles}=evidence;
  c.deps.loadNonrootEvidence=async()=>({evidence:handles,deploymentSource:f.deploymentSource,phaseEvidence:f.phaseEvidence,targetObservation});
  const result=await verifyImageSecurityDeployment(c.deps,{...c.options,phase:'preconfigure'});
  expect(result.phaseReceipt).toEqual(bundle.phaseReceipt);expect(result.phaseEvidence).toEqual(f.phaseEvidence);
  expect(getNonrootTargetRegistration(result.context,'control')).toEqual(f.d.controlBodies.get('control'));
 });
 it('holds a requested target checkpoint without a real target evidence provider',async()=>{
  const c=await cliFixture();await expect(verifyImageSecurityDeployment(c.deps,{...c.options,phase:'preconfigure'})).rejects.toThrow('NonrootDeploymentEvidenceRequired');
 });
 it.each(['kms','size','utf8','duplicate-key','wrong-owner','archive-bytes'])('rejects private authorization archive %s and closes the read stream',async defect=>{
  const c=await cliFixture(),send=c.clients.s3.send;let body;
  c.clients.s3.send=async command=>{
   const response=await send(command);
   if(command.input.Key.endsWith('/operation.json')){
    if(defect==='kms')response.SSEKMSKeyId=`arn:aws:kms:other-region:${f.current.account}:key/other`;
    if(defect==='size')response.ContentLength++;
    let raw;
    if(defect==='utf8')raw=Buffer.from([0xc0,0xaf]);
    if(defect==='duplicate-key')raw=Buffer.from('{"version":2,"version":2}');
    if(defect==='wrong-owner'){const op=structuredClone(records.operation);op.operation.owner='f'.repeat(32);raw=Buffer.from(JSON.stringify(op));}
    if(raw){response.Body.destroy();response.Body=Readable.from([raw]);response.ContentLength=raw.length;}
   }
   if(defect==='archive-bytes'&&command.input.Key.endsWith('/nonroot-proof-archive.json')){
    const value=JSON.parse(c.blobs['nonroot-proof-archive.json']);value.objects[0].base64=Buffer.from('{}').toString('base64');
    const raw=Buffer.from(JSON.stringify(value));response.Body.destroy();response.Body=Readable.from([raw]);response.ContentLength=raw.length;
   }
   body=response.Body;return response;
  };
  await expect(verifyImageSecurityDeployment(c.deps,c.options).then(()=>true)).rejects.toThrow();
  expect(body.destroyed).toBe(true);
 });
 it('loads v3 from an owned bundle, registers the genuine context and pins its exact version',async()=>{
  const directory=await mkdtemp(join(tmpdir(),'nonroot-bundle-loader-'));let owned;
  try{
   owned=await writeImageDeploymentBundle(bundle,{environmentFile:join(directory,'env')});
   const b=nonrootAuthorizationBindings(context),previous=b.previousSelection,prefix=`/mem9-on-aws/prod/`;
   const selection={version:1,mode:'retained',controlTag:b.previousControlTag,dataTag:previous.dataSourceTag,images:previous.images,dataReleaseHash:previous.dataReleaseHash,arm64Digests:previous.arm64Digests};
   const operator={version:3,stage:'prod',account:f.current.account,region:f.current.region,generation:f.current.generation,dataReleaseParameter:f.parameter.Name,dataReleaseParameterVersion:f.parameter.Version-1,sourceTag:previous.dataSourceTag,workerImage:previous.images['llm-proxy'],dataReleaseHash:previous.dataReleaseHash};
   const parameter=(Name,value)=>({Name,Type:'String',Version:1,ARN:`arn:aws:ssm:${f.current.region}:${f.current.account}:parameter${Name}`,Value:JSON.stringify(value)});
   const clients={ssm:{send:async()=>({Parameters:[f.parameter,parameter(prefix+'ecs/image-selection',selection),parameter(prefix+'consolidation-runtime/operator-manifest',operator)]})}};
   const result=await loadDeploymentDataRelease(clients,{stage:'prod',account:f.current.account,region:f.current.region,controlRevision:f.d.main.mainRevision,controlSourceTree:f.current.controlSourceTree,
    runtime:{phase:'complete',status:'running',stage:'prod',nonce:f.current.runtimeNonce,schemaDigest:f.current.schemaDigest,operatorDigest:f.current.operatorDigest},
    env:{MEM9_IMAGE_TRANSITION_BUNDLE_FILE:owned.file,MEM9_IMAGE_TRANSITION_BUNDLE_HASH:owned.digest},nonrootEvidence:evidence,now:f.f.now});
   expect(result.parameterVersion).toBe(f.parameter.Version);expect(result.nonrootDeploymentContext).toBe(getImageAuthorization(clients));
   expect(getNonrootTargetRegistration(result.nonrootDeploymentContext,'control')).toEqual(f.d.controlBodies.get('control'));
  }finally{if(owned)await removeImageDeploymentBundle({MEM9_IMAGE_TRANSITION_BUNDLE_FILE:owned.file,MEM9_IMAGE_TRANSITION_BUNDLE_HASH:owned.digest});await rm(directory,{recursive:true,force:true});}
 });
 it('worker admission rejects an authorization-only context and a later same-byte version',async()=>{
  const data=f.current,meta={version:3,stage:'prod',account:data.account,region:data.region,generation:data.generation,sourceTag:data.dataSourceTag,controlSourceTag:'mem9-'+f.d.main.mainRevision.slice(0,7),workerImage:`${data.account}.dkr.ecr.${data.region}.amazonaws.com/mem9-on-aws/llm-proxy@${data.images['llm-proxy'].rootDigest}`,dataReleaseHash:f.deploymentSource.descriptorHash,dataReleaseParameter:f.parameter.Name,dataReleaseParameterVersion:f.parameter.Version};
  const clients={ssm:{send:async()=>({Parameters:[f.parameter]})}},input={controlRevision:f.d.main.mainRevision,controlSourceTree:data.controlSourceTree,mode:'admission',now:f.f.now};
  await expect(loadWorkerDataRelease(clients,meta,{...input,imageTransition:f.authorization})).rejects.toThrow('NonrootPublishedAuthorizationRequired');
  installImageAuthorization(clients,context,{data,controlSourceTree:data.controlSourceTree,now:f.f.now});
  expect((await loadWorkerDataRelease(clients,meta,input)).parameterVersion).toBe(f.parameter.Version);
  clients.ssm.send=async()=>({Parameters:[{...f.parameter,Version:99}]});
  await expect(loadWorkerDataRelease(clients,{...meta,dataReleaseParameterVersion:99},input)).rejects.toThrow('ProductionDataReleaseVersionMismatch');
 });
});
