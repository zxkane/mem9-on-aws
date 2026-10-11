import {parseDocument} from 'yaml';
import {posix} from 'node:path';
import {parse as parseJavaScript} from '@babel/parser';
import {copyNonrootJson,parseNonrootJson,nonrootHash as hash} from './production-nonroot-contracts.mjs';
import {createControlSourceContext,readControlSourceFile,controlSourcePaths,controlSourceEntries} from './production-control-source.mjs';
import {describeDataBuildInputs} from './production-data-build-inputs.mjs';
import {CI_SMOKE_POLICY as policy} from './ci-smoke-policy.mjs';
import {ciSmokeJobDefinition,controlBuildCaptureSteps} from './ci-smoke-job.mjs';
import {buildNativeControlCompositionSourceJob,controlCompositionActionDefinition,CONTROL_COMPOSITION_ASSET_PATHS} from './production-control-composition-job.mjs';
import {CI_SMOKE_CHECKS,inspectCiSmokeRecord,inspectCiSmokeResult,validateCiSmokeEvidence} from './ci-smoke-evidence.mjs';

const need=(ok,code='CiSmokeSourceInvalid')=>{if(!ok)throw Error(code);};
const same=(a,b,code)=>need(hash(a)===hash(b),code);
const exact=(v,keys)=>need(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===keys.slice().sort().join(),'CiSmokeSourceFields');
const copy=value=>structuredClone(copyNonrootJson(value));
const workflowPath='.github/workflows/infra-ci.yml';
const actionPath='.github/actions/runtime-cutover/action.yml';
export const CI_SMOKE_GATE_ACTION_PATH='.github/actions/ci-smoke-gate/action.yml';
export const CI_SMOKE_GATE_ENTRY_PATH='.github/actions/ci-smoke-gate/index.mjs';
export const CI_SMOKE_VALIDATOR_ROOTS=Object.freeze(['scripts/verify-ci-smoke-isolation.mjs','scripts/lib/production-nonroot-proof.mjs','scripts/verify-image-security-deployment.mjs',CI_SMOKE_GATE_ENTRY_PATH]);
const gateUses='./.github/actions/ci-smoke-gate';
const legacySmoke='Smoke test mnemo-server EMF framing (non-TTY)';
const buildName='Build & push mnemo-server (arm64)';
const originalCondition="steps.gate.outputs.skip != 'true'";
const guardCommand='node scripts/verify-ci-smoke-isolation.mjs guard --route "$MEM9_CI_SMOKE_ROUTE" --step "$MEM9_CI_SMOKE_STEP" --phase "$MEM9_CI_SMOKE_PHASE"';
const text=bytes=>new TextDecoder('utf-8',{fatal:true}).decode(bytes);
const identity=s=>s.name??s.uses??s.run;
const unique=(rows,key)=>need(new Set(rows.map(key)).size===rows.length,'CiSmokeSourceDuplicate');
const selected=(steps,name)=>{const matches=steps.filter(s=>s.name===name);need(matches.length===1,'CiSmokeStepIdentity');return matches[0];};

export const CI_SMOKE_ROUTES=Object.freeze(policy.routes.map(r=>r.route));
export const CI_SMOKE_JOB='mnemo-nonroot-smoke';
export const CI_SMOKE_JOB_NAME='Mnemo nonroot smoke';
export const CI_SMOKE_JOB_CONDITION="!cancelled() && needs.application-region.result == 'success' && needs.build-and-push-image.result == 'success' && needs.build-and-push-image.outputs.mnemo_digest != '' && (github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository)";

/** Keep both actual recipe hashes. Disabled legacy scripts remain in the
 * historical closure; no other preparation or DATA source delta is allowed. */
export function isolateDataRecipe(origin){
 const candidate=copy(origin),steps=candidate.preparation?.steps;need(Array.isArray(steps),'CiSmokeRecipeShape');
 const smoke=selected(steps,legacySmoke),build=selected(steps,buildName);
 need(smoke.if===originalCondition&&!Object.hasOwn(build,'id')&&!steps.some(s=>s.id==='mnemo'),'CiSmokeRecipePriorState');
 unique(steps.filter(s=>s.id),s=>s.id);smoke.if=false;build.id='mnemo';return candidate;
}
export function verifyIsolatedDataRecipe(origin,candidate,{originHash,candidateHash}){
 need(hash(origin)===originHash&&hash(candidate)===candidateHash&&originHash!==candidateHash,'CiSmokeRecipeHash');
 same(isolateDataRecipe(origin),candidate,'CiSmokeRecipeChanged');return Object.freeze({originHash,candidateHash});
}

export function ciSmokeGateActionDefinition(){
 return {name:'CI smoke gate',description:"Verify the current job's source or target in the action process",
  inputs:{mode:{description:'source or target',required:true},phase:{description:'Required target phase; empty for source',required:false}},
  runs:{using:'node24',main:'index.mjs'}};
}
/** The one reviewed Node action. This checks its definition and invocation;
 * callers still authenticate both files and the complete entry source closure. */
export function verifyCiSmokeGateAction(step,definition){
 need(step?.uses===gateUses,'CiSmokeNodeActionInvocation');
 same(definition,ciSmokeGateActionDefinition(),'CiSmokeNodeActionChanged');
 need(!Object.hasOwn(step,'run')&&!Object.hasOwn(step,'shell'),'CiSmokeNodeActionInvocation');
 const input=step.with;need(input&&['source','target'].includes(input.mode),'CiSmokeNodeActionInvocation');
 exact(input,input.mode==='source'?['mode']:['mode','phase']);
 if(input.mode==='target')need(['preupdate','preconfigure','presst','prereadiness'].includes(input.phase),'CiSmokeNodeActionInvocation');
 return Object.freeze({actionPath:CI_SMOKE_GATE_ACTION_PATH,entryPath:CI_SMOKE_GATE_ENTRY_PATH});
}
function sourceGate(condition,route){
 return {id:'ci_smoke_source',name:'Verify actual CI smoke source evidence (hard)',
  ...(condition?{if:condition}:{}),env:{GH_TOKEN:'${{ github.token }}',
   MEM9_CI_EVIDENCE_ROLE_ARN:route.endsWith('prod')||Object.hasOwn(policy.sourceJobs,route)?'${{ secrets.AWS_PROD_ROLE_ARN }}':'${{ secrets.AWS_PREVIEW_ROLE_ARN }}',
   MEM9_CI_EVIDENCE_KMS_KEY_ARN:'${{ secrets.MEM9_CI_EVIDENCE_KMS_KEY_ARN }}',MEM9_CI_SMOKE_LINEAGE:'${{ secrets.MEM9_CI_SMOKE_LINEAGE }}'},
  uses:gateUses,with:{mode:'source'},'continue-on-error':false};
}
function guarded(step,row){
 const condition=step.if??'true';need(typeof condition==='string','CiSmokeProtectedCondition');
 const gate={id:row.rule.gateId,name:'Verify smoke phase receipt: '+row.name,shell:'bash',if:'success() && ('+condition+')',
  env:{MEM9_CI_SMOKE_ROUTE:row.route,MEM9_CI_SMOKE_STEP:row.callPath,MEM9_CI_SMOKE_PHASE:row.rule.phase},run:guardCommand,'continue-on-error':false};
 const protectedStep={...copy(step),if:row.rule.requiredCondition,'continue-on-error':false};
 if(row.callPath==='deploy-prod/20'){need(typeof protectedStep.run==='string'&&!protectedStep.run.includes('record-nonroot-deployment'),'CiSmokePostApplyStep');protectedStep.run=protectedStep.run.trimEnd()+'\nnode scripts/record-nonroot-deployment.mjs complete\n';}
 return [gate,protectedStep];
}

function targetCheckpoint(route,row,condition,role,stage){
 return {id:'ci_smoke_target_'+row.rule.phase+'_'+row.callPath.split('/').at(-1),name:'Acquire smoke target receipt: '+row.name,if:'success() && ('+(condition??'true')+')',
  env:{GH_TOKEN:'${{ github.token }}',MEM9_DEPLOY_ROLE_ARN:role,STAGE:stage,MEM9_CI_SMOKE_CHECKPOINT:row.callPath},
  uses:gateUses,with:{mode:'target',phase:row.rule.phase},'continue-on-error':false};
}

function previewCredentialRenewal(row){
 const rule=policy.previewCredentialRenewal,recovery=row?.callPath===rule.recoveryAnchor;
 if(!row||!recovery&&!rule.normalAnchors.includes(row.callPath))return [];
 need(row.route==='deploy-preview'&&(recovery?row.rule.kind==='safe-recovery':row.rule.phase==='prereadiness'),'CiSmokeRenewalScope');
 const suffix=row.callPath.split('/').at(-1),checkId='ci_smoke_oidc_check_'+suffix,renewalId='ci_smoke_credentials_'+suffix;
 const condition=recovery?rule.recoveryCondition:rule.normalCondition;
 return [
  {id:checkId,name:'Verify native OIDC context: '+row.callPath,if:condition,...copy(rule.presenceCheck)},
  {id:renewalId,name:'Renew preview credentials: '+row.callPath,if:'('+condition+") && steps."+checkId+".outcome == 'success'",...copy(rule.action)},
 ];
}

/** Pure reconstruction from an independently authenticated baseline. This is
 * also used by the source verifier, so unknown steps and hidden local actions
 * cannot escape classification merely by appearing after credentials. */
export function buildCiSmokePromotionRoutes({workflow,actions}){
 exact(actions,Object.keys(policy.baselineActionHashes));
 for(const [path,expected]of Object.entries(policy.baselineActionHashes))need(hash(actions[path])===expected,'CiSmokeBaselineActionChanged');
 const jobs={},nextActions=copy(actions);
 nextActions[CI_SMOKE_GATE_ACTION_PATH]=ciSmokeGateActionDefinition();
 const shared=nextActions[actionPath];need(shared?.runs?.using==='composite','CiSmokeCompositeRequired');
 const originalShared=copy(shared),childRows=policy.shared.childGates;
 for(const [key,value]of Object.entries(policy.shared.inputAdditions)){need(!Object.hasOwn(shared.inputs,key),'CiSmokeCompositeAlreadyChanged');shared.inputs[key]=copy(value);}
 need(identity(shared.runs.steps[0])==='Validate cutover phase','CiSmokeCompositePriorState');
 shared.runs.steps=originalShared.runs.steps.flatMap((step,index)=>{
  if(index===0)return [copy(policy.shared.precredentialValidation)];
  const rule=childRows.find(r=>r.baselineIndex===index);if(!rule)return [copy(step)];
  need(identity(step)===rule.childName,'CiSmokeCompositePriorState');
  const result=[];
  if([2,5,7,8,10].includes(index)){
   const phase=rule.definition.env.MEM9_CI_SMOKE_PHASE;
   result.push({id:'ci_smoke_child_target_'+index,name:'Acquire smoke target receipt: '+rule.childName,if:rule.definition.if,
    env:{GH_TOKEN:'${{ github.token }}',MEM9_DEPLOY_ROLE_ARN:'${{ inputs.role-arn }}',STAGE:'${{ env.STAGE }}',MEM9_CI_SMOKE_CHECKPOINT:'${{ inputs.ci-smoke-call-path }}/.github/actions/runtime-cutover/action.yml/'+index},
    uses:gateUses,with:{mode:'target',phase},'continue-on-error':false});
  }
  return [...result,copy(rule.definition),{...copy(step),if:rule.protectedCondition,'continue-on-error':false}];
 });
 for(const route of policy.routes){
  const name=route.route,original=workflow.jobs?.[name];need(original&&Array.isArray(original.steps),'CiSmokeRouteMissing');
  need(hash(original)===route.baselineJobHash&&hash({needs:original.needs,if:original.if})===route.baselinePredicateHash,'CiSmokeBaselineJobChanged');
  const rows=policy.rows.filter(r=>r.route===name),top=rows.filter(r=>!r.callPath.includes('/.github/'));
  need(top.length===original.steps.length-route.firstCredentialContainingStep,'CiSmokeRouteCoverage');
  for(const row of top){const index=Number(row.callPath.split('/')[1]);need(identity(original.steps[index])===row.name,'CiSmokeRoutePriorState');}
  // Every local composite and its full leaf sequence has an explicit class.
  for(const row of top.filter(r=>original.steps[Number(r.callPath.split('/')[1])].uses?.startsWith('./'))){
   const step=original.steps[Number(row.callPath.split('/')[1])],path=step.uses.slice(2)+'/action.yml',action=actions[path];
   need(action?.runs?.using==='composite'&&Array.isArray(action.runs.steps),'CiSmokeLocalAction');
   const children=rows.filter(r=>r.callPath.startsWith(row.callPath+'/'+path+'/'));
   need(children.length===action.runs.steps.length,'CiSmokeLocalActionCoverage');
   children.forEach((r,i)=>need(r.callPath===row.callPath+'/'+path+'/'+i&&r.name===identity(action.runs.steps[i]),'CiSmokeLocalActionCoverage'));
   need(!action.runs.steps.some(s=>s.uses?.startsWith('./')),'CiSmokeUnclassifiedNestedAction');
  }
  const job=copy(original),runtime=name.startsWith('runtime-cutover-');
  if(!runtime){
   const prior="(needs.build-and-push-image.result == 'success' || needs.build-and-push-image.result == 'skipped')";
   need(job.if.split(prior).length===2,'CiSmokeImageBuildPriorState');
   job.if=job.if.replace(prior,"needs.build-and-push-image.result == 'success'");
  }
  job.steps=original.steps.flatMap((old,index)=>{
   let step=copy(old);const result=[];
   if(name==='deploy-preview'&&['Deploy PR stage','Deploy PR namespace enforcement'].includes(step.name)){
    need(step.env.MEM9_IMAGE_TAG==="${{ needs.build-and-push-image.outputs.image_tag || 'latest' }}"&&step.env.MEM9_ECR_NAMESPACE==="${{ needs.build-and-push-image.outputs.image_tag != '' && 'mem9-on-aws/preview' || 'mem9-on-aws' }}",'CiSmokePreviewImagePriorState');
    step.env={...step.env,MEM9_IMAGE_TAG:'${{ needs.build-and-push-image.outputs.image_tag }}',MEM9_ECR_NAMESPACE:'mem9-on-aws/preview'};
   }
   if(runtime&&step.name==='Require the verified deployment revision')return [sourceGate(undefined,name)];
   if(!runtime&&index===route.firstCredentialContainingStep)result.push(sourceGate(step.if,name));
   const call=policy.shared.parentCalls.find(c=>c.route===name&&c.baselineIndex===index);
   if(call){need(step.name===call.name&&step.uses==='./.github/actions/runtime-cutover','CiSmokeCompositeCaller');step.with={...step.with,...copy(call.withAdditions)};}
   const row=top.find(r=>r.callPath===name+'/'+index);
   const renewal=previewCredentialRenewal(row);result.push(...renewal);
   if(row?.callPath===policy.previewCredentialRenewal.recoveryAnchor){
    need(renewal.length===2,'CiSmokeRenewalScope');
    step.if='('+step.if+") && steps."+renewal[1].id+".outcome == 'success'";
   }
   const existingPhases={
    'Verify protected image upgrade source':'preupdate',
    'Refresh image upgrade authorization before configure':'preconfigure',
    'Refresh image upgrade authorization before SST':'presst',
   };
   if(name==='deploy-prod'&&Object.hasOwn(existingPhases,step.name)){
    const prior='node scripts/verify-image-security-deployment.mjs'+(step.name==='Verify protected image upgrade source'?'':' --deploy');
    need(step.run.trim()===prior,'CiSmokeAcquisitionPriorState');
    step.env={...step.env,MEM9_CI_SMOKE_CHECKPOINT:name+'/'+index};
    delete step.run;delete step.shell;
    step.uses=gateUses;step.with={mode:'target',phase:existingPhases[step.name]};
   }
   // A preceding hard E2E step can outlast the target receipt. Each protected
   // readiness operation gets its own bounded observation and checkpoint.
   const previewTargets=['Remove conflicting Pulumi installation','Drain preview service and previous bootstrap tasks',
    'Verify preview runtime credentials (hard)','Aurora administrator authority (preview, hard)',
    'Continuous consolidation Scheduler E2E (preview, hard)','Canary continuation fixture (preview, hard)',
    'MCP write-search E2E (preview, hard)','Namespace connection attribution E2E (preview, hard)',
    'Namespace performance E2E (preview, hard)','OAuth façade smoke (preview)',
    'Human namespace OAuth E2E (preview, hard)','Comment deploy status'];
   const prodTargets=['Seed OAuth HMAC key (workflow_dispatch only)','Reconcile prod ECS deployment','MCP write-search E2E (prod, hard)'];
   if(row&&(name==='deploy-preview'&&previewTargets.includes(step.name)||name==='deploy-prod'&&prodTargets.includes(step.name))){
    const role=name==='deploy-prod'?'${{ secrets.AWS_PROD_ROLE_ARN }}':'${{ secrets.AWS_PREVIEW_ROLE_ARN }}';
    const stage=name==='deploy-prod'?'prod':"${{ format('pr-{0}', github.event.pull_request.number) }}";
    result.push(targetCheckpoint(name,row,step.if,role,stage));
   }
   return [...result,...(row?.rule.kind==='protected'?guarded(step,row):[step])];
  });
  need(job.steps.filter(s=>s.id==='ci_smoke_source').length===1,'CiSmokeSourceGateRequired');
  unique(job.steps.filter(s=>s.id),s=>s.id);
  // Runtime maintenance consumes the already completed source CI. Ordinary
  // deployments with a new DATA build must depend on this run's actual smoke.
  if(!runtime){
   need(Array.isArray(job.needs)&&!job.needs.includes(CI_SMOKE_JOB),'CiSmokeNeedsPriorState');job.needs.push(CI_SMOKE_JOB);
   const smoke="needs.mnemo-nonroot-smoke.result == 'success'";
   job.if='('+job.if+') && '+(name==='deploy-prod'?"(needs.verify-production-image-transition.outputs.image_transition == 'true' || "+smoke+')':smoke);
  }
  // GitHub job/artifact verification uses read access only.
  job.permissions={...job.permissions,actions:'read'};
  job.env={...job.env,
   ...(name.endsWith('prod')?{MEM9_CI_ACQUISITION_CONFIG:'${{ secrets.MEM9_CI_PROD_ACQUISITION_CONFIG }}'}:{}),
   MEM9_CI_EVIDENCE_KMS_KEY_ARN:'${{ secrets.MEM9_CI_EVIDENCE_KMS_KEY_ARN }}'};
  jobs[name]=job;
  job.steps.push({name:'Remove owned CI smoke source evidence',if:'always()',run:'node scripts/verify-ci-smoke-isolation.mjs cleanup-source'});
 }
 unique(shared.runs.steps.filter(s=>s.id),s=>s.id);return {jobs,actions:nextActions};
}
export function verifyCiSmokePromotionRoutes(baseline,candidate){
 const expected=buildCiSmokePromotionRoutes(baseline);exact(candidate,['jobs','actions']);same(candidate,expected,'CiSmokePromotionSourceChanged');return expected;
}

/** Ordinary infrastructure changes need a current build for the same-run
 * nonroot smoke. The protected transition predicate remains untouched. */
export function buildCiSmokeImageJob(workflow){
 const job=copy(workflow.jobs['build-and-push-image']),prior="needs.changes.outputs.workload_changed == 'true'";
 need(typeof job?.if==='string'&&job.if.split(prior).length===2,'CiSmokeImageBuildPriorState');
 job.if=job.if.replace(prior,"needs.changes.outputs.aws_mutation_required == 'true'");
 selected(job.steps,legacySmoke).if=false;need(!selected(job.steps,buildName).id);selected(job.steps,buildName).id='mnemo';
 need(!Object.hasOwn(job.outputs,'mnemo_digest'));job.outputs.mnemo_digest='${{ steps.mnemo.outputs.digest }}';return job;
}

export function buildCiSmokeSourceJobs(workflow,{controlComposition=false}={}){
 need(typeof controlComposition==='boolean','CiSmokeSourceJobFormat');
 const result={};
 for(const[name,digest]of Object.entries(policy.sourceJobs)){
  const job=copy(workflow.jobs?.[name]);need(hash(job)===digest,'CiSmokeControlSourceJobChanged');
  job.env={...job.env,MEM9_CI_ACQUISITION_CONFIG:'${{ secrets.MEM9_CI_PROD_ACQUISITION_CONFIG }}'};
  const at=job.steps.findIndex(step=>step.uses?.startsWith('aws-actions/configure-aws-credentials@'));need(at>=0,'CiSmokeControlSourceCredential');
  job.steps.splice(at,0,sourceGate(undefined,name));
  if(name==='build-image-transition-control'){
   const credentials=job.steps[at+1];need(!credentials.id&&!Object.hasOwn(credentials.with,'output-credentials'),'CiSmokeControlCredentialChanged');
   credentials.id='control_credentials';credentials.with['output-credentials']=true;
   const capture=controlBuildCaptureSteps(),build=job.steps.findIndex(step=>step.id==='bootstrap');need(build>=0,'CiSmokeControlBuildMissing');
   job.steps.splice(build,0,capture.prepare);job.steps.splice(build+2,0,capture.capture,capture.publish,capture.cleanup);
   need(!Object.hasOwn(job.outputs,'control_capture'),'CiSmokeControlOutputChanged');job.outputs.control_capture='${{ steps.publish_control_capture.outputs.commitment }}';
  }
  job.steps.push({name:'Remove owned CI smoke source evidence',if:'always()',run:'node scripts/verify-ci-smoke-isolation.mjs cleanup-source'});
  result[name]=controlComposition&&name==='build-image-transition-control'?buildNativeControlCompositionSourceJob(job):job;
 }
 return result;
}

export function describeCiSmokePromotionPins(workflow,actions,filePins){
 return CI_SMOKE_ROUTES.map(jobKey=>{
  const job=workflow.jobs[jobKey],credentials=[],targets=[],protectedSteps=[],localActions=new Map(),seen=new Set();let source;
  const visit=(steps,path,scope)=>{
   need(Array.isArray(steps)&&filePins[path],'CiSmokeStepSource');
   steps.forEach((step,index)=>{
    const row={file:filePins[path],scope,index,name:identity(step),id:step.id??null,stepHash:hash(step)},key=path+':'+scope+':'+index;
    if(!seen.has(key)){
     seen.add(key);
     if(step.id==='ci_smoke_source'){need(!source,'CiSmokeSourceGateDuplicate');source=row;}
     if(step.uses?.startsWith('aws-actions/configure-aws-credentials@'))credentials.push(row);
     if(/^ci_smoke_(?:child_)?(?:guard_|target_)/.test(step.id??''))targets.push(row);
     if(typeof step.if==='string'&&step.if.includes(".outcome == 'success'"))protectedSteps.push(row);
    }
    if(step.uses?.startsWith('./')){
     const child=step.uses.slice(2)+'/action.yml';need(actions[child]&&filePins[child],'CiSmokeUnclassifiedLocalAction');
     if(child===CI_SMOKE_GATE_ACTION_PATH){
      verifyCiSmokeGateAction(step,actions[child]);
      need(filePins[CI_SMOKE_GATE_ENTRY_PATH]?.path===CI_SMOKE_GATE_ENTRY_PATH,'CiSmokeNodeActionSource');
      localActions.set(child,filePins[child]);localActions.set(CI_SMOKE_GATE_ENTRY_PATH,filePins[CI_SMOKE_GATE_ENTRY_PATH]);
     }else{
      need(Object.hasOwn(policy.baselineActionHashes,child)&&actions[child].runs?.using==='composite'&&Array.isArray(actions[child].runs.steps),'CiSmokeUnclassifiedLocalAction');
      if(!localActions.has(child)){localActions.set(child,filePins[child]);visit(actions[child].runs.steps,child,'runs.steps');}
     }
    }
   });
  };
  visit(job.steps,workflowPath,'jobs.'+jobKey+'.steps');need(source&&credentials.length&&targets.length&&protectedSteps.length,'CiSmokeRouteCoverage');
  return {job:jobKey,jobHash:hash(job),predicateHash:hash({needs:job.needs,if:job.if}),sourceGate:source,credentialSteps:credentials,targetGates:targets,protectedSteps,
   localActions:[...localActions.values()].sort((a,b)=>a.path.localeCompare(b.path))};
 });
}

function parseYaml(raw){const doc=parseDocument(text(raw),{uniqueKeys:true});need(!doc.errors.length&&!doc.warnings.length,'CiSmokeYamlInvalid');return doc.toJS({maxAliasCount:0});}
const pin=file=>({path:file.path,gitMode:file.gitMode,sha256:file.sha256,bytes:file.bytes});
async function file(context,path,expected){const result=await readControlSourceFile(context,path);if(expected)same(pin(result.file),expected,'CiSmokeFileChanged');return result;}

/** Derive complete local imports, re-exports and script references. Dynamic
 * module selection cannot be silently omitted from a reviewed code closure. */
export async function ciSmokeSourceClosure(context,roots){
 const maxFiles=20000,maxBytes=33554432;
 const paths=new Set(controlSourcePaths(context)),seen=new Map(),queued=new Set(),pending=[];
 let bytes=0;
 const queue=path=>{
  need(typeof path==='string'&&paths.has(path),'CiSmokeClosureMissing');
  if(!queued.has(path)){need(queued.size<maxFiles,'CiSmokeClosureFileLimit');queued.add(path);pending.push(path);}
 };
 need(Array.isArray(roots)&&roots.length>0&&roots.length<=maxFiles,'CiSmokeClosureFileLimit');roots.forEach(queue);
 const regionLoader='scripts/lib/application-region.mjs';
 // Exact reviewed module shapes, including the default-path construction,
 // serialized $config shim, app-only invocation and URL cache-buster. Location
 // and comment trivia are excluded; every executable AST field remains bound.
 const shapeHash=body=>{
  const ignored=new Set(['start','end','loc','extra','comments','leadingComments','trailingComments','innerComments']);
  const shape=value=>Array.isArray(value)?value.map(shape):value&&typeof value==='object'?
   Object.fromEntries(Object.entries(value).filter(([k,v])=>!ignored.has(k)&&v!==undefined).map(([k,v])=>[k,shape(v)])):value;
  return hash(JSON.parse(JSON.stringify(shape(body))));
 };
 const modulePath=(from,specifier)=>{
  need(typeof specifier==='string','CiSmokeDynamicImport');
  if(!specifier.startsWith('.')){
   // Only Node builtins and ordinary package specifiers are external leaves.
   // Inline/file URLs and package-import aliases can hide executable local
   // source, so they require an explicit resolver instead of being omitted.
   need(specifier.startsWith('node:')?/^node:[a-z_][a-z0-9_/-]*$/.test(specifier):
    !specifier.startsWith('/')&&!specifier.startsWith('#')&&!specifier.includes(':'),'CiSmokeExternalCode');return null;
  }
  const next=posix.normalize(posix.join(posix.dirname(from),specifier));
  need(!next.startsWith('../')&&!next.startsWith('/'),'CiSmokeClosureEscape');
  if(paths.has(next))return next;
  // SST's checked-in TypeScript uses extensionless local imports. Resolve only
  // a unique regular source candidate; never guess between shadowing files.
  const choices=posix.extname(next)?[]:['.ts','.mts','.mjs','.js','.json','/index.ts','/index.mts','/index.mjs','/index.js'].map(suffix=>next+suffix).filter(path=>paths.has(path));
  need(choices.length===1,choices.length?'CiSmokeClosureAmbiguous':'CiSmokeClosureMissing');return choices[0];
 };
 while(pending.length){
  const path=pending.pop();if(seen.has(path))continue;
  const found=await file(context,path);need(found.bytes.byteLength<=maxBytes-bytes,'CiSmokeClosureByteLimit');bytes+=found.bytes.byteLength;
  seen.set(path,pin(found.file));const source=text(found.bytes);
  const enqueue=specifier=>{
   const next=modulePath(path,specifier);if(next)queue(next);return next;
  };
  if(/\.(?:mjs|cjs|js|ts|mts|cts|tsx|jsx)$/.test(path)){
   const ast=parseJavaScript(source,{sourceType:'module',plugins:[...(/\.(?:ts|mts|cts|tsx)$/.test(path)?['typescript']:[]),...(/\.[jt]sx$/.test(path)?['jsx']:[])]});
   const fixedRegionLoader=path===regionLoader&&shapeHash(ast.program.body)==='0f24b8dec9c9f35e9e621792d6dae3e317956866988e37372cfc4d42415ae690';
   if(path===regionLoader)need(fixedRegionLoader,'CiSmokeRegionLoaderShape');
   const fixedRegionCli=path==='scripts/resolve-application-region.mjs'&&shapeHash(ast.program.body)==='5fffdd2b64f1c81dccc55faf6dd87441dfda2e04b85bdfa685f6a9a176cf72d7';
   const resolverNames=new Set(),resolverImports=new Set(),resolverDeclarations=new Set();
   for(const node of ast.program.body)if(node.type==='ImportDeclaration'&&modulePath(path,node.source.value)===regionLoader){
    need(node.specifiers.every(s=>s.type==='ImportSpecifier'&&s.imported.name==='resolveApplicationRegion'),'CiSmokeRegionLoaderInvocation');
    node.specifiers.forEach(s=>resolverNames.add(s.local.name));
   }
   const collectResolverImports=node=>{
    if(!node||typeof node!=='object')return;
    const call=node.type==='VariableDeclarator'&&node.init?.type==='AwaitExpression'?node.init.argument:null;
    if(call?.type==='CallExpression'&&call.callee?.type==='Import'&&call.arguments[0]?.type==='StringLiteral'&&modulePath(path,call.arguments[0].value)===regionLoader){
     need(node.id.type==='ObjectPattern'&&node.id.properties.length===1,'CiSmokeRegionLoaderInvocation');
     const property=node.id.properties[0];need(property.type==='ObjectProperty'&&!property.computed&&property.key?.name==='resolveApplicationRegion'&&property.value?.type==='Identifier','CiSmokeRegionLoaderInvocation');
     resolverNames.add(property.value.name);resolverImports.add(call);resolverDeclarations.add(property.key);resolverDeclarations.add(property.value);
    }
    for(const [key,value]of Object.entries(node))if(!['loc','start','end','extra'].includes(key)){if(Array.isArray(value))value.forEach(collectResolverImports);else if(value&&typeof value==='object')collectResolverImports(value);}
   };collectResolverImports(ast);
   const visit=(node,parent)=>{if(!node||typeof node!=='object')return;
    if(['ImportDeclaration','ExportNamedDeclaration','ExportAllDeclaration'].includes(node.type)&&node.source)enqueue(node.source.value);
    if(node.type==='ImportSpecifier'&&node.imported?.name==='createRequire'||node.type==='MemberExpression'&&node.property?.name==='createRequire')need(false,'CiSmokeUnsupportedModuleLoader');
    if(node.type==='CallExpression'&&node.callee?.type==='Import'){
     if(fixedRegionLoader){
      // This one call is covered by the complete module shape above. Never
      // grant the exception to another file or to any other computed import.
      need(node.arguments.length===1&&node.arguments[0].type==='MemberExpression'&&node.arguments[0].object?.name==='configUrl'&&node.arguments[0].property?.name==='href','CiSmokeDynamicImport');
      queue('sst.config.ts');
     }else{need(node.arguments.length===1&&node.arguments[0].type==='StringLiteral','CiSmokeDynamicImport');const imported=enqueue(node.arguments[0].value);if(imported===regionLoader)need(resolverImports.has(node),'CiSmokeRegionLoaderInvocation');}
    }
    if(node.type==='CallExpression'&&node.callee?.type==='Identifier'&&node.callee.name==='require'){need(node.arguments.length===1&&node.arguments[0].type==='StringLiteral','CiSmokeDynamicImport');need(enqueue(node.arguments[0].value)!==regionLoader,'CiSmokeRegionLoaderInvocation');}
    if(node.type==='TSImportType'){need(node.argument?.type==='StringLiteral','CiSmokeDynamicImport');enqueue(node.argument.value);}
    if(node.type==='Identifier'&&resolverNames.has(node.name)&&parent?.type!=='ImportSpecifier'&&!resolverDeclarations.has(node)&&
      !(parent?.type==='ObjectProperty'&&parent.key===node&&!parent.computed&&!parent.shorthand)){
     const direct=parent?.type==='CallExpression'&&parent.callee===node;
     need(direct&&(parent.arguments.length===0||fixedRegionCli),'CiSmokeRegionLoaderInvocation');
    }
    for(const [key,value]of Object.entries(node))if(!['loc','start','end','extra'].includes(key)){if(Array.isArray(value))value.forEach(child=>visit(child,node));else if(value&&typeof value==='object')visit(value,node);}
   };visit(ast);
  }
  for(const match of source.matchAll(/\bscripts\/[A-Za-z0-9_./-]+\.(?:mjs|cjs|js|sh)\b/g))queue(match[0]);
 }
 return [...seen.values()].sort((a,b)=>Buffer.compare(Buffer.from(a.path),Buffer.from(b.path)));
}

export async function verifyCiSmokeCompositionToolchain(context,assets){
 const toolchain=parseNonrootJson(text(assets.toolchain.bytes)),output=toolchain.output;
 exact(toolchain,['version','kind','nodeMajor','bundler','packageLockHash','inputs','output']);
 exact(output,['path','sha256','bytesLength']);
 exact(toolchain.bundler,['name','version','integrity','builderSourceHash']);
 need(toolchain.version===1&&toolchain.kind==='control-composition-ci-toolchain'&&toolchain.nodeMajor===24&&
  output?.path===CONTROL_COMPOSITION_ASSET_PATHS.bundle&&output.sha256===assets.bundle.file.sha256&&output.bytesLength===assets.bundle.file.bytes,'CiSmokeCompositionToolchain');
 const lockSource=await readControlSourceFile(context,'package-lock.json');
 need(toolchain.packageLockHash===lockSource.file.sha256,'CiSmokeCompositionToolchainLock');
 const lock=parseNonrootJson(text(lockSource.bytes)),bundler=toolchain.bundler;
 need(lock.lockfileVersion===3&&lock.packages&&bundler.name==='rolldown'&&
  typeof bundler.version==='string'&&bundler.version.length>0&&typeof bundler.integrity==='string'&&bundler.integrity.length>0&&
  lock.packages['node_modules/rolldown']?.version===bundler.version&&lock.packages['node_modules/rolldown']?.integrity===bundler.integrity,'CiSmokeCompositionToolchainLock');
 const builder=await readControlSourceFile(context,'scripts/build-control-composition-action.mjs');
 need(builder.file.sha256===bundler.builderSourceHash,'CiSmokeCompositionToolchainBuilder');
 need(Array.isArray(toolchain.inputs)&&toolchain.inputs.length>0&&toolchain.inputs.length<=20000,'CiSmokeCompositionToolchainInputs');
 let previous='';const sourcePaths=new Set();
 for(const input of toolchain.inputs){
  const path=input.path,external=typeof path==='string'&&path.startsWith('node_modules/');
  exact(input,['path','sha256','bytesLength',...(external?['packagePin']:[])]);
  need(typeof path==='string'&&path.length<=4096&&/^[A-Za-z0-9_@./-]+$/.test(path)&&!path.startsWith('/')&&
   path.split('/').every(part=>part&&part!=='.'&&part!=='..')&&path>previous&&
   /^[a-f0-9]{64}$/.test(input.sha256)&&Number.isSafeInteger(input.bytesLength)&&input.bytesLength>=0,'CiSmokeCompositionToolchainInputs');
  previous=path;
  if(external){
   const key=Object.keys(lock.packages).filter(key=>key.startsWith('node_modules/')&&path.startsWith(key+'/')).sort((a,b)=>b.length-a.length)[0];
   need(key&&!path.slice(key.length+1).split('/').includes('node_modules'),'CiSmokeCompositionToolchainPackage');
   const name=key.split('node_modules/').at(-1);
   exact(input.packagePin,['name','version','integrity']);
   const pin=input.packagePin,locked=lock.packages[key];
   need(pin.name===name&&typeof pin.version==='string'&&pin.version.length>0&&typeof pin.integrity==='string'&&pin.integrity.length>0&&
    locked?.version===pin.version&&locked?.integrity===pin.integrity,'CiSmokeCompositionToolchainPackage');
  }else{
   const source=await readControlSourceFile(context,path);
   need(source.file.sha256===input.sha256&&source.file.bytes===input.bytesLength,'CiSmokeCompositionToolchainSource');
   sourcePaths.add(path);
  }
 }
 need(sourcePaths.has(CONTROL_COMPOSITION_ASSET_PATHS.entry),'CiSmokeCompositionToolchainEntry');
 // This verifies the committed manifest's source and lock bindings. The
 // separately required reproducible --check build verifies bundle generation;
 // a manifest cannot itself authenticate untracked package file contents.
 return toolchain;
}

export async function verifyCiSmokeIsolationSource(isolation,{originContext,candidateContext,baselineContext,originRecipe,candidateRecipe}){
 exact(isolation,['version','kind','origin','candidate','recipeEdits','workflow','preservedScripts','smoke','promotion']);
 need([1,2].includes(isolation.version)&&isolation.kind==='ci-smoke-isolation','CiSmokeIsolationKind');
 const composition=isolation.version===2;
 for(const [record,context]of [[isolation.origin,originContext],[isolation.candidate,candidateContext]]){
  exact(record,['revision','tree','recipeHash']);need(/^[a-f0-9]{40}$/.test(record.revision)&&record.tree===context?.tree,'CiSmokeTreeBinding');
 }
 const sourceRecipe=async context=>{
  const entries=controlSourceEntries(context),byOid=new Map(entries.map(e=>[e.oid,e.path]));
  return describeDataBuildInputs(entries,async oid=>(await readControlSourceFile(context,byOid.get(oid))).bytes);
 };
 same(await sourceRecipe(originContext),originRecipe,'CiSmokeOriginRecipeSource');
 same(await sourceRecipe(candidateContext),candidateRecipe,'CiSmokeCandidateRecipeSource');
 verifyIsolatedDataRecipe(originRecipe,candidateRecipe,{originHash:isolation.origin.recipeHash,candidateHash:isolation.candidate.recipeHash});
 same(isolation.recipeEdits,[{stepName:legacySmoke,field:'if',before:originalCondition,after:false},{stepName:buildName,field:'id',beforeAbsent:true,after:'mnemo'}],'CiSmokeRecipeEditShape');
 exact(isolation.workflow,['source','buildJob','digestOutput',...(composition?['composition']:[])]);need(isolation.workflow.buildJob==='build-and-push-image'&&isolation.workflow.source.path===workflowPath);
 same(isolation.workflow.digestOutput,{name:'mnemo_digest',expression:'${{ steps.mnemo.outputs.digest }}'});
 const candidate=parseYaml((await file(candidateContext,workflowPath,isolation.workflow.source)).bytes),baseline=parseYaml((await file(baselineContext,workflowPath)).bytes);
 const actions={},candidateActions={},filePins={[workflowPath]:isolation.workflow.source};for(const path of [actionPath,'.github/actions/runtime-cleanup/action.yml','.github/actions/runtime-recovery/action.yml']){
  actions[path]=parseYaml((await file(baselineContext,path)).bytes);const found=await file(candidateContext,path);candidateActions[path]=parseYaml(found.bytes);filePins[path]=pin(found.file);
 }
 const gate=await file(candidateContext,CI_SMOKE_GATE_ACTION_PATH),entry=await file(candidateContext,CI_SMOKE_GATE_ENTRY_PATH);
 candidateActions[CI_SMOKE_GATE_ACTION_PATH]=parseYaml(gate.bytes);filePins[CI_SMOKE_GATE_ACTION_PATH]=pin(gate.file);filePins[CI_SMOKE_GATE_ENTRY_PATH]=pin(entry.file);
 const routes=verifyCiSmokePromotionRoutes({workflow:baseline,actions},{jobs:Object.fromEntries(CI_SMOKE_ROUTES.map(k=>[k,candidate.jobs[k]])),actions:candidateActions});
 const sourceJobs=Object.keys(policy.sourceJobs);
 if(composition)need(sourceJobs.every(name=>Object.hasOwn(candidate.jobs,name)),'CiSmokeControlSourceJobs');
 if(sourceJobs.some(name=>Object.hasOwn(candidate.jobs,name)))same(Object.fromEntries(sourceJobs.map(name=>[name,candidate.jobs[name]])),buildCiSmokeSourceJobs(baseline,{controlComposition:composition}),'CiSmokeControlSourceJobs');
 if(composition){
  exact(isolation.workflow.composition,Object.keys(CONTROL_COMPOSITION_ASSET_PATHS));
  const assets={};for(const [key,path]of Object.entries(CONTROL_COMPOSITION_ASSET_PATHS)){
   need(isolation.workflow.composition[key].path===path,'CiSmokeCompositionAssetPath');
   assets[key]=await file(candidateContext,path,isolation.workflow.composition[key]);
  }
  same(parseYaml(assets.action.bytes),controlCompositionActionDefinition(),'CiSmokeCompositionAction');
  await verifyCiSmokeCompositionToolchain(candidateContext,assets);
 }
 for(const row of policy.rows.filter(r=>r.rule.kind==='safe-recovery'))for(const source of row.rule.entryFiles)await file(candidateContext,source.path,source);
 const oldBuild=buildCiSmokeImageJob(baseline),newBuild=candidate.jobs['build-and-push-image'];same(newBuild,oldBuild,'CiSmokeBuildJobChanged');
 need(Array.isArray(isolation.preservedScripts)&&isolation.preservedScripts.length===2);
 for(const [index,path]of ['scripts/run-mnemo-emf-smoke.sh','scripts/run-mnemo-health-smoke.sh'].entries()){
  need(isolation.preservedScripts[index].path===path);await file(originContext,path,isolation.preservedScripts[index]);await file(candidateContext,path,isolation.preservedScripts[index]);
 }
 exact(isolation.smoke,['jobKey','jobHash','script','closure','databaseImage','platform','serverUser','databaseUser','capDrop','noNewPrivileges','internalNetwork','timeoutMinutes','requiredChecks']);
 const s=isolation.smoke,j=candidate.jobs[CI_SMOKE_JOB];need(s.jobKey===CI_SMOKE_JOB&&s.jobHash===hash(j)&&j.name===CI_SMOKE_JOB_NAME&&j['timeout-minutes']===15&&j.if===CI_SMOKE_JOB_CONDITION,'CiSmokeJobBinding');
 same(j,ciSmokeJobDefinition(),'CiSmokeJobExecutionChanged');
 const producer=parseJavaScript(text((await file(candidateContext,'scripts/run-mnemo-nonroot-smoke.mjs')).bytes),{sourceType:'module'});
 const databases=producer.program.body.filter(n=>n.type==='ExportNamedDeclaration'&&n.declaration?.type==='VariableDeclaration').flatMap(n=>n.declaration.declarations).filter(n=>n.id.name==='NONROOT_SMOKE_DATABASE_IMAGE');
 need(databases.length===1,'CiSmokeDatabaseSource');const declaration=databases[0].init;
 need(declaration?.type==='CallExpression'&&declaration.callee.type==='MemberExpression'&&declaration.callee.object.name==='Object'&&declaration.callee.property.name==='freeze'&&declaration.arguments.length===1&&declaration.arguments[0].type==='ObjectExpression','CiSmokeDatabaseSource');
 const databaseFields=declaration.arguments[0].properties;need(databaseFields.every(p=>p.type==='ObjectProperty'&&!p.computed&&p.key.type==='Identifier'&&p.value.type==='StringLiteral'),'CiSmokeDatabaseSource');
 const database=Object.fromEntries(databaseFields.map(p=>[p.key.name,p.value.value]));exact(database,['qualifiedImage','rootDigest','arm64Digest','configDigest']);need(databaseFields.length===4&&s.databaseImage===database.qualifiedImage,'CiSmokeDatabaseSource');
 need(j.needs.includes('build-and-push-image')&&j.needs.includes('application-region')&&j['runs-on']===newBuild['runs-on'],'CiSmokeJobDependency');
 need(s.platform==='linux/arm64'&&s.serverUser==='1000:1000'&&s.databaseUser==='999:999'&&s.noNewPrivileges===true&&s.internalNetwork===true&&s.timeoutMinutes===15&&/^pgvector\/pgvector@sha256:[a-f0-9]{64}$/.test(s.databaseImage),'CiSmokeJobIsolation');
 same(s.capDrop,['ALL']);same(s.requiredChecks,CI_SMOKE_CHECKS);need(s.script.path==='scripts/run-mnemo-nonroot-smoke.sh');await file(candidateContext,s.script.path,s.script);
 same(await ciSmokeSourceClosure(candidateContext,[s.script.path]),s.closure,'CiSmokeIncompleteClosure');
 const p=isolation.promotion;exact(p,['requiredJobs','routes','preparationValidators','resultKind','sourceRule','retainedRule','failureRule']);
 same(p.requiredJobs,CI_SMOKE_ROUTES);need(p.routes.length===4&&p.resultKind==='ci-smoke-isolation-result'&&p.sourceRule==='actual-candidate-build-smoke-required'&&p.retainedRule==='original-target-evidence-also-required'&&p.failureRule==='hold-on-missing-skipped-failed-mismatch');
 same(p.routes,describeCiSmokePromotionPins(candidate,candidateActions,filePins),'CiSmokeRoutePinCoverage');
 const validators=await ciSmokeSourceClosure(candidateContext,[...CI_SMOKE_VALIDATOR_ROOTS,...(composition?[CONTROL_COMPOSITION_ASSET_PATHS.entry]:[])]);
 same(validators,p.preparationValidators,'CiSmokeValidatorClosure');
 return Object.freeze({kind:'verified-ci-smoke-source',isolationHash:hash(isolation),sourceRevision:isolation.candidate.revision,sourceTree:isolation.candidate.tree});
}

/** Actual GitHub completion is supplied by the authenticated read-only
 * collector. A skipped main build cannot replace a completed source smoke. */
export async function verifyCiSmokeSourceResult(isolation,result,{provenance,readJson,readBytes,expected,now=Date.now()}){
 const r=inspectCiSmokeResult(result);need(r.isolationHash===hash(isolation)&&r.sourceTree===isolation.candidate.tree,'CiSmokeResultSource');
 const {run,buildJob,smokeJob,buildDigest,sourceRevision,sourceTree,commit,candidateCommit}=provenance;
 need(run.id===r.runId&&run.run_attempt===r.runAttempt&&run.path===r.workflowPath&&run.head_repository?.full_name===r.repository&&sourceRevision===r.sourceRevision&&sourceTree===r.sourceTree,'CiSmokeActualRun');
 need(commit?.sha===r.sourceRevision&&commit.commit?.tree?.sha===r.sourceTree&&Array.isArray(commit.parents)&&commit.parents.length>=1&&commit.parents.length<=2,'CiSmokeActualCommit');
 need(run.event==='pull_request'?commit.parents.length===2&&commit.parents[1].sha===run.head_sha:run.event==='push'&&run.head_sha===r.sourceRevision,'CiSmokeActualSourceRelation');
 need(candidateCommit?.sha===isolation.candidate.revision&&candidateCommit.commit?.tree?.sha===r.sourceTree&&
  (r.sourceRevision===isolation.candidate.revision||run.event==='pull_request'&&commit.parents[1].sha===isolation.candidate.revision),'CiSmokeActualCandidateRelation');
 for(const [job,id,name]of [[buildJob,r.buildJobId,'Build & push workload images'],[smokeJob,r.smokeJobId,CI_SMOKE_JOB_NAME]]){
  need(job.id===id&&job.name===name&&job.run_id===r.runId&&job.run_attempt===r.runAttempt&&job.status==='completed'&&job.conclusion==='success','CiSmokeActualJob');
  need(job.head_sha===run.head_sha,'CiSmokeActualJobSource');
 }
 const build=selected(buildJob.steps,buildName);need(build.status==='completed'&&build.conclusion==='success'&&buildDigest===r.outputDigest,'CiSmokeBuildOutput');
 need(Date.parse(buildJob.completed_at)<=Date.parse(smokeJob.started_at)&&Date.parse(smokeJob.started_at)<=r.startedMs&&r.completedMs<=Date.parse(smokeJob.completed_at)&&r.completedMs<=now,'CiSmokeActualChronology');
 return validateCiSmokeEvidence(r,{readJson,readBytes,expected,now});
}

/** Replay the exact archived source material. The containing policySources
 * hash is independently committed by the parent proof/review; a JSON `passed`
 * field or a subset of Git entries cannot create a verified source context. */
export async function verifyArchivedCiSmoke(isolation,result,{material,resolveJson,readBytes,originRecipe,candidateRecipe,now}){
 exact(material,['version','kind','origin','candidate','baseline','provenance','expected']);
 need(material.version===1&&material.kind==='ci-smoke-source-material','CiSmokeSourceMaterial');
 const readJson=async ref=>parseNonrootJson(text(await resolveJson(ref)));
 const context=async ref=>{
  const source=await readJson(ref);exact(source,['tree','entries','blobs']);
  need(source.blobs&&typeof source.blobs==='object'&&!Array.isArray(source.blobs)&&Object.keys(source.blobs).length<=20000,'CiSmokeSourceBlobs');
  for(const [oid,bytes]of Object.entries(source.blobs)){need(/^[a-f0-9]{40}$/.test(oid),'CiSmokeSourceBlobIdentity');inspectCiSmokeRecord('ByteRef',bytes);}
  return createControlSourceContext({tree:source.tree,entries:source.entries},oid=>{need(source.blobs[oid],'CiSmokeSourceBlobMissing');return readBytes(source.blobs[oid]);});
 };
 const originContext=await context(material.origin),candidateContext=await context(material.candidate),baselineContext=await context(material.baseline);
 const source=await verifyCiSmokeIsolationSource(isolation,{originContext,candidateContext,baselineContext,originRecipe,candidateRecipe});
 const verified=await verifyCiSmokeSourceResult(isolation,result,{provenance:await readJson(material.provenance),expected:await readJson(material.expected),
  readJson:resolveJson,readBytes,now});
 return Object.freeze({source,verified});
}
