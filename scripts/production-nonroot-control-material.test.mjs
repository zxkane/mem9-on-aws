import {describe,it,expect,beforeAll,afterAll,vi} from 'vitest';
import {readFileSync,mkdtempSync,mkdirSync,writeFileSync,rmSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
import {tmpdir} from 'node:os';
import {join,dirname} from 'node:path';
import {parseDocument} from 'yaml';
import {prepareNonrootControlLaunches,assembleNonrootControlMaterial} from './lib/production-nonroot-control-material.mjs';
import {completeNonrootProofFixture,nonrootAuthorizationValues} from './production-nonroot.fixture.mjs';
import {nonrootDeploymentFixture} from './production-nonroot-provenance.fixture.mjs';
import {dockerArtifactFixture} from './production-nonroot-observation.fixture.mjs';
import {controlSourcePaths,readControlSourceFile} from './lib/production-control-source.mjs';
import {createNonrootEvidenceArchive,exportNonrootArchive,nonrootArchiveResolvers} from './lib/production-nonroot-archive.mjs';
import {buildNonrootImageTransitionProof,nonrootProofExpected,nonrootTransitionContextBindings,bindNonrootTransitionAuthorization} from './lib/production-nonroot-proof.mjs';
import {captureNonrootControlBuildAction,completeNonrootControlBuildAction} from './lib/production-nonroot-control-build.mjs';
import {encodeControlBuildCapture} from './lib/production-control-capture-archive.mjs';
import {collectNonrootControlPrerequisites} from './lib/production-nonroot-control-prerequisites.mjs';
import {verifyNonrootDeploymentSource} from './lib/production-nonroot-provenance.mjs';
import {verifyNonrootControlRuntimeObservation} from './lib/production-nonroot-observation.mjs';
import {readNonrootEvidence} from './lib/production-nonroot-runtime.mjs';
import {nonrootHash as hash} from './lib/production-nonroot-contracts.mjs';

// Only GitHub, policy/guard producer records and production account data below
// are synthetic. Git membership, full proof authorization, image graph/FS,
// native kernel observations and the isolated runtime collector remain real.
// No test fixture is imported by the production assembler.
it('rejects an open or absent material input before any producer is invoked',async()=>{
 await expect(prepareNonrootControlLaunches({passed:true})).rejects.toThrow('NonrootControlMaterialFields');
 await expect(assembleNonrootControlMaterial({})).rejects.toThrow('NonrootControlMaterialFields');
});

function treeFor(files){
 const root=mkdtempSync(join(tmpdir(),'control-material-tree-'));
 try{
  const git=args=>execFileSync('git',['-c','core.hooksPath=/dev/null',...args],{cwd:root,encoding:'utf8',stdio:['pipe','pipe','pipe']}).trim();
  git(['init','--quiet']);
  for(const [path,raw]of files){const file=join(root,path);mkdirSync(dirname(file),{recursive:true});writeFileSync(file,raw);git(['add','--',path]);}
  return git(['write-tree']);
 }finally{rmSync(root,{recursive:true,force:true});}
}

async function actualFixture(docker){
 const nativePath='scripts/lib/production-nonroot-control-prerequisites.mjs';
 const seed=await completeNonrootProofFixture();
 const template=await nonrootDeploymentFixture({sourceOverrides:new Map([[nativePath,readFileSync(new URL('./lib/production-nonroot-control-prerequisites.mjs',import.meta.url),'utf8')]])});
 const files=new Map();for(const path of controlSourcePaths(template.sourceContext))files.set(path,Buffer.from((await readControlSourceFile(template.sourceContext,path)).bytes).toString());
 const raw=ref=>seed.a.objects.get(seed.a.files.find(row=>row.encoding==='bytes'&&row.ref.sha256===ref.sha256).name).toString();
 const data=seed.a.value(seed.input.protectedInputs).dataClosure;
 const oldWorkflow=parseDocument(raw(data.files.find(row=>row.path==='.github/workflows/infra-ci.yml').blob)).toJS();
 const workflow=parseDocument(files.get('.github/workflows/infra-ci.yml')).toJS();workflow.jobs['build-and-push-image']=oldWorkflow.jobs['build-and-push-image'];
 files.set('.github/workflows/infra-ci.yml',JSON.stringify(workflow));
 for(const row of data.files)if(row.path!=='.github/workflows/infra-ci.yml')files.set(row.path,raw(row.blob));
 for(const row of seed.guardSource.files)files.set(row.path,raw(row.blob));
 const tree=treeFor(files),f=await completeNonrootProofFixture({controlSourceTree:tree,controlSourceFiles:files});
 const originalNames=new Set(f.a.files.map(row=>row.name));
 const d=await nonrootDeploymentFixture({baseFixture:f,sourceOverrides:files,controlArtifactFactory:docker.factory(),now:f.now});
 f.input=structuredClone(f.input);f.input.taskPlan.controlLaunches=d.contract.launchTemplates;f.input.taskPlan.deployedControlBuildContract=d.contract;f.a.replaceJson('task-plan.json',f.input.taskPlan);
 const manifest=f.a.manifest();manifest.files=manifest.files.filter(row=>row.purpose!=='task-definition'||originalNames.has(row.name));
 f.evidence.archive=createNonrootEvidenceArchive(JSON.stringify(manifest),{expectedManifestHash:hash(manifest),readObject:async name=>f.a.objects.get(name)});
 const built=await buildNonrootImageTransitionProof(f.input,{expected:nonrootProofExpected(f.input,{proofHash:hash(f.input)}),evidence:f.evidence,now:f.now});
 const {review,current}=nonrootAuthorizationValues(f,built,nonrootTransitionContextBindings(built.context));
 const context=bindNonrootTransitionAuthorization(built.context,{review,now:f.now}),parameter={...f.parameter,Version:f.parameter.Version+1,Value:JSON.stringify(current)};
 const job={...d.rawJob,status:'in_progress',conclusion:null,started_at:new Date(f.now-10000).toISOString(),completed_at:null,
  steps:[{number:1,name:d.job.steps[0].name,status:'completed',conclusion:'success',started_at:new Date(f.now-9000).toISOString(),completed_at:new Date(f.now-2000).toISOString()}]};
 const capture=await captureNonrootControlBuildAction({contract:d.contract,source:d.source,run:d.rawRun,job,metadata:JSON.stringify({'containerimage.digest':d.build.image.rootDigest,'containerimage.config.digest':d.build.image.configDigest}),outputDigest:d.build.image.rootDigest,observedMs:f.now},d.options());
 const buildLog=Buffer.from(`#7 exporting manifest list ${d.build.image.rootDigest}\n#7 exporting manifest ${d.build.image.arm64Digest}\n#7 exporting config ${d.build.image.configDigest}\n#7 DONE 1.0s\n`);
 const completion=completeNonrootControlBuildAction(capture,{contract:d.contract,run:d.rawRun,job:{...job,status:'completed',conclusion:'success',completed_at:new Date(f.now+1).toISOString()},buildLog,now:f.now+2});
 const prepared={version:1,kind:'control-build-prepared',identity:{repository:d.source.repository,revision:d.source.checkout.sha,runId:d.source.run.id,attempt:d.source.run.attempt},bundleHash:'a'.repeat(64),contractHash:hash(d.contract),fingerprint:d.checkoutFingerprint,preparedMs:f.now-11000};
 const {commitment}=encodeControlBuildCapture({prepared,capture});
 const prerequisites=await collectNonrootControlPrerequisites({image:d.build.image,sourceClosure:d.build.guardSource},{controlVerification:d.controlVerification,sourceContext:d.sourceContext,expected:{candidateTree:tree},beforeDocker:({containerId})=>{if(containerId)docker.containers.add(containerId);}});
 const base={context,parameter,proof:f.input,archive:f.a.archive(),completedCapture:{capture,prepared,commitment,completion,buildLog,contract:d.contract,sourceContext:d.sourceContext},controlVerification:{graph:d.controlVerification.graph,filesystem:d.controlVerification.filesystem},sourceContext:d.sourceContext,prerequisites,guardImportAudit:d.build.guardImports.importAudit};
 return {f,d,base};
}

describe.skipIf(process.env.MEM9_NONROOT_CONTAINER_TEST!=='1')('CONTROL material with actual graph/FS and local isolated runtime',()=>{
 let docker,x,clock,prepared;
 const full=()=>{
  const {f,d}=x;
  const tests={version:1,kind:'control-guard-test-evidence',image:d.build.image,sourceRevision:d.main.mainRevision,sourceTree:d.main.mainTree,guardSourceHash:hash(d.contract.guardSource),contractHash:hash(d.contract),testContractHash:d.contract.guardTestContract.canonicalHash,
   launches:prepared.resolvedLaunches.map(l=>({taskKey:l.taskKey,launchHash:hash(l),purpose:d.contract.launchTemplates.find(t=>t.taskKey===l.taskKey).purpose,result:'pass',applicationReached:!d.contract.launchTemplates.find(t=>t.taskKey===l.taskKey).purpose.startsWith('denied'),credentialAccessBeforeGuard:false})),completedMs:Date.now()-1};
  const guardTests=f.json(tests,'build');
  return {...x.base,archive:f.a.archive(),guardTests,scan:d.build.scan};
 };
 beforeAll(async()=>{
  const start=performance.now();clock=vi.spyOn(Date,'now').mockImplementation(()=>1800007200000+Math.floor(performance.now()-start));
  docker=dockerArtifactFixture();x=await actualFixture(docker);prepared=await prepareNonrootControlLaunches(x.base);
 },120000);
 afterAll(async()=>{try{await docker?.close();}finally{clock?.mockRestore();}},120000);
 it('resolves only the typed CONTROL image slots and preserves every other registration property',async()=>{
  for(const task of x.f.input.taskPlan.tasks.filter(t=>t.disposition==='update')){
   const before=x.f.a.value(task.targetRegistration),expected=structuredClone(before),launch=prepared.resolvedLaunches.find(l=>l.taskKey===task.taskKey);
   if(launch)expected.containerDefinitions.find(c=>c.name===launch.containerName).image=`${x.d.build.image.account}.dkr.ecr.${x.d.build.image.region}.amazonaws.com/${x.d.build.image.repositoryName}@${x.d.build.image.rootDigest}`;
   expect(prepared.registrations[task.taskKey]).toEqual(expected);
  }
  expect(prepared.authority).toBe(false);expect(prepared).not.toHaveProperty('context');
  const again=await prepareNonrootControlLaunches(x.base);expect(again.resolvedLaunches).toEqual(prepared.resolvedLaunches);
 },60000);
 it('assembles and verifies actual runtime handles, full raw archive references and immutable capture clocks',async()=>{
  const input=full(),original=JSON.stringify(input.completedCapture.capture),result=await assembleNonrootControlMaterial(input);
  expect(result.authority).toBe(false);expect(result).not.toHaveProperty('context');expect(result).not.toHaveProperty('phaseEvidence');
  expect(JSON.stringify(input.completedCapture.capture)).toBe(original);
  expect(result.build.actualMain).toEqual(input.completedCapture.capture.actualMain);
  expect(result.build.scan).toEqual(input.scan);expect(result.build.guardTests).toEqual(input.guardTests);
  const readers=nonrootArchiveResolvers(result.evidence.archive);
  expect(await readNonrootEvidence(result.build.buildLog,readers,false)).toEqual(input.completedCapture.buildLog);
  expect(await readNonrootEvidence(result.build.actualInvocation,readers)).toEqual(x.d.actualInvocation);
  const options={...readers,...x.d.options(),...readers,now:Date.now(),runtimeObservation:result.evidence.runtimeObservation,
   expected:{...x.d.options().expected,taskPlan:x.f.input.taskPlan,descriptorHash:result.deploymentSource.descriptorHash,proofHash:result.deploymentSource.proofHash,parameterVersion:x.base.parameter.Version}};
  expect((await verifyNonrootDeploymentSource(result.deploymentSource,options)).registrations).toEqual(result.registrations);
  expect(verifyNonrootControlRuntimeObservation(result.evidence.runtimeObservation,result.build,options).cleanupConfirmed).toBe(true);
  expect(result.archiveAdditions.find(row=>row.ref.sha256===result.build.buildLog.sha256)?.purpose).toBe('build');
  const wire=await exportNonrootArchive(result.evidence.archive);expect(JSON.parse(wire.manifest).files.some(row=>row.purpose==='artifact')).toBe(false);
 },120000);
 it.each([
  ['context','NonrootProofContextRequired'],['prerequisites','NonrootPrerequisitesContextRequired'],['source','NonrootControlMaterialSourceContext'],
  ['proof','NonrootControlMaterialProof'],['parameter','NonrootControlMaterialParameter'],['parameter-path','NonrootContractInvalid'],['completion','NonrootControlMaterialCompletion'],
  ['digest','NonrootControlMaterialCommitment'],['graph','NonrootPrerequisitesContextBinding'],
 ])('rejects substituted %s without manufacturing replacement evidence',async(defect,code)=>{
  const input={...x.base,completedCapture:{...x.base.completedCapture}};
  if(defect==='context')input.context=structuredClone(input.context);
  if(defect==='prerequisites')input.prerequisites=structuredClone(input.prerequisites);
  if(defect==='source')input.sourceContext=structuredClone(input.sourceContext);
  if(defect==='proof')input.proof={...input.proof,observedMs:input.proof.observedMs-1};
  if(defect==='parameter')input.parameter={...input.parameter,Version:input.parameter.Version+1};
  if(defect==='parameter-path')input.parameter={...input.parameter,Name:'/unrelated',ARN:input.parameter.ARN.replace(input.parameter.Name,'/unrelated')};
  if(defect==='completion')input.completedCapture.completion={...input.completedCapture.completion,captureHash:'f'.repeat(64)};
  if(defect==='digest')input.completedCapture.commitment={...input.completedCapture.commitment,outputDigest:'sha256:'+'f'.repeat(64)};
  if(defect==='graph')input.controlVerification={...input.controlVerification,graph:structuredClone(input.controlVerification.graph)};
  await expect(prepareNonrootControlLaunches(input)).rejects.toThrow(code);
 },60000);
 it.each([
  ['missing-guard','NonrootArchiveReferenceAmbiguous'],['guard-launch','NonrootControlGuardTests'],['guard-credentials','NonrootControlGuardTests'],['guard-json-pass','NonrootControlMaterialGuardTime'],
  ['missing-policy','NonrootArchiveReferenceAmbiguous'],
  ['scan-count','NonrootProvenanceBinding'],['scan-image','NonrootControlMaterialScanImage'],['review-expired','NonrootControlArtifactReview'],
 ])('rejects corrupt actual producer record: %s',async(defect,code)=>{
  const input=full(),{f}=x;
  if(defect==='missing-guard')input.guardTests={bytesHash:'f'.repeat(64),canonicalHash:'f'.repeat(64),bytesLength:1};
  if(['guard-launch','guard-credentials'].includes(defect)){const v=structuredClone(f.a.value(input.guardTests));if(defect==='guard-launch')v.launches[0].launchHash='f'.repeat(64);else v.launches[0].credentialAccessBeforeGuard=true;input.guardTests=f.json(v,'build');}
  if(defect==='guard-json-pass')input.guardTests=f.json({passed:true},'build');
  if(defect==='missing-policy')input.scan={...input.scan,artifactReview:{bytesHash:'f'.repeat(64),canonicalHash:'f'.repeat(64),bytesLength:1}};
  if(defect==='scan-count'){const pages=structuredClone(f.a.value(input.scan.rawPages));pages[0].imageScanFindings.findingSeverityCounts={HIGH:1};input.scan={...input.scan,rawPages:f.json(pages,'scan')};}
  if(defect==='scan-image')input.scan={...input.scan,image:{...input.scan.image,arm64Digest:'sha256:'+'f'.repeat(64)}};
  if(defect==='review-expired'){const review=structuredClone(f.a.value(input.scan.artifactReview));review.expiresMs=Date.now()-1;input.scan={...input.scan,artifactReview:f.json(review,'policy')};}
  input.archive=f.a.archive();await expect(assembleNonrootControlMaterial(input)).rejects.toThrow(code);
 },120000);
});
