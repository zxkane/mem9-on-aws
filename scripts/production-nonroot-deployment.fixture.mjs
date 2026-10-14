import {mkdtempSync,rmSync,mkdirSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,dirname} from 'node:path';
import {execFileSync} from 'node:child_process';
import {parseDocument} from 'yaml';
import {completeNonrootProofFixture,nonrootAuthorizationValues} from './production-nonroot.fixture.mjs';
import {nonrootDeploymentFixture} from './production-nonroot-provenance.fixture.mjs';
import {controlSourcePaths,readControlSourceFile} from './lib/production-control-source.mjs';
import {nonrootHash as hash} from './lib/production-nonroot-contracts.mjs';
import {createNonrootEvidenceArchive} from './lib/production-nonroot-archive.mjs';
import {buildNonrootImageTransitionProof,nonrootProofExpected,nonrootTransitionContextBindings,bindNonrootTransitionAuthorization} from './lib/production-nonroot-proof.mjs';

function gitTree(files){
 const root=mkdtempSync(join(tmpdir(),'nonroot-wrapper-source-'));
 try{
  const git=args=>execFileSync('git',args,{cwd:root,encoding:'utf8',stdio:['pipe','pipe','pipe']}).trim();
  git(['init','--quiet']);
  for(const [path,body]of files){const file=join(root,path);mkdirSync(dirname(file),{recursive:true});writeFileSync(file,body,{mode:0o644});git(['add','--',path]);}
  return git(['write-tree']);
 }finally{rmSync(root,{recursive:true,force:true});}
}

/** One coherent synthetic source/archive/plan. The CONTROL factory supplies
 * real graph/FS handles; no serialized context or provider success flag can
 * stand in for the separate runtime collector used by the caller. */
export async function nonrootDeploymentWrapperFixture({controlArtifactFactory}={}){
 const seed=await completeNonrootProofFixture(),template=await nonrootDeploymentFixture(),sourceFiles=new Map();
 for(const path of controlSourcePaths(template.sourceContext))sourceFiles.set(path,Buffer.from((await readControlSourceFile(template.sourceContext,path)).bytes).toString('utf8'));
 const data=seed.a.value(seed.input.protectedInputs).dataClosure;
 const raw=ref=>seed.a.objects.get(seed.a.files.find(row=>row.encoding==='bytes'&&row.ref.sha256===ref.sha256).name).toString('utf8');
 const oldWorkflow=parseDocument(raw(data.files.find(file=>file.path==='.github/workflows/infra-ci.yml').blob)).toJS();
 const currentWorkflow=parseDocument(sourceFiles.get('.github/workflows/infra-ci.yml')).toJS();
 currentWorkflow.jobs['build-and-push-image']=oldWorkflow.jobs['build-and-push-image'];
 sourceFiles.set('.github/workflows/infra-ci.yml',JSON.stringify(currentWorkflow));
 for(const file of data.files)if(file.path!=='.github/workflows/infra-ci.yml')sourceFiles.set(file.path,raw(file.blob));
 for(const file of seed.guardSource.files)sourceFiles.set(file.path,raw(file.blob));
 const tree=gitTree(sourceFiles),f=await completeNonrootProofFixture({controlSourceTree:tree,controlSourceFiles:sourceFiles});
 const predeploymentNames=new Set(f.a.files.map(row=>row.name));
 const d=await nonrootDeploymentFixture({baseFixture:f,sourceOverrides:sourceFiles,controlArtifactFactory,now:f.now});
 if(d.sourceContext.tree!==tree)throw Error('FixtureSourceTreeMismatch');
 f.input=structuredClone(f.input);f.input.taskPlan.controlLaunches=d.contract.launchTemplates;f.input.taskPlan.deployedControlBuildContract=d.contract;
 f.taskPlan=f.input.taskPlan;f.a.replaceJson('task-plan.json',f.taskPlan);
 // Actual deployed CONTROL registrations belong to the later deployment
 // archive, never the preauthorization archive containing typed image slots.
 const predeploymentManifest=f.a.manifest();
 predeploymentManifest.files=predeploymentManifest.files.filter(row=>row.purpose!=='task-definition'||predeploymentNames.has(row.name));
 f.evidence.archive=createNonrootEvidenceArchive(JSON.stringify(predeploymentManifest),{expectedManifestHash:hash(predeploymentManifest),readObject:async name=>f.a.objects.get(name)});
 const expected=nonrootProofExpected(f.input,{proofHash:hash(f.input)}),built=await buildNonrootImageTransitionProof(f.input,{expected,evidence:f.evidence,now:f.now});
 const {review,current}=nonrootAuthorizationValues(f,built,nonrootTransitionContextBindings(built.context));
 const authorization=bindNonrootTransitionAuthorization(built.context,{review,now:f.now});
 const parameter={...f.parameter,Version:f.parameter.Version+1,Value:JSON.stringify(current)};
 const resolved={...d.resolved,taskPlanHash:hash(f.taskPlan),tasks:f.taskPlan.tasks.filter(row=>row.disposition==='update').map(row=>({taskKey:row.taskKey,registrationBody:f.json(d.controlBodies.get(row.taskKey)??d.preBodies.get(row.taskKey),'task-definition')}))};
 const deploymentSource={...d.record,descriptorHash:hash(current),proofHash:built.proofHash,parameterVersion:parameter.Version,resolvedTaskPlan:f.json(resolved)};
 const task=structuredClone(f.f.legacy.current.backendTask);
 const serviceObservation={observedMs:f.now,account:f.account,region:f.region,parameterVersion:parameter.Version,descriptorHash:hash(current),
  service:{runningCount:1,pendingCount:0,deployments:[{rolloutState:'COMPLETED'}],taskArn:task.taskArn,taskDefinition:task.taskDefinitionArn},
  task:{...task,lastStatus:'RUNNING'},definition:{...f.before.backend,taskDefinitionArn:task.taskDefinitionArn,status:'ACTIVE'}};
 const phaseEvidence={version:1,kind:'same-binding-admission-refresh',proofHash:built.proofHash,descriptorHash:hash(current),phase:'preconfigure',parameterVersion:parameter.Version,
  rootAudit:f.json(f.predeploymentAudit,'root-audit'),serviceObservation:f.json(serviceObservation),sourceEvidenceHash:f.deploymentControl.sourceEvidence.canonicalHash,permissionBindingsHash:hash(f.taskPlan.permissions),observedMs:f.now,expiresMs:f.now+240000};
 const targetObservation={observedMs:f.now,artifacts:Object.fromEntries(Object.entries(f.f.input.artifacts).map(([name,value])=>[name,value]))};
 return {f,d,built,review,current,authorization,parameter,deploymentSource,phaseEvidence,resolved,serviceObservation,targetObservation,
  evidence:{archive:f.a.archive(),controlGraph:d.controlVerification.graph,controlFilesystemVerification:d.controlVerification.filesystem,sourceContext:d.sourceContext,targetObservation}};
}
