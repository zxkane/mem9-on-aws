import {inspectNonrootRecord,copyNonrootJson,parseNonrootJson,nonrootHash as hash} from './production-nonroot-contracts.mjs';
import {readNonrootEvidence,verifyNonrootEvidenceReferences} from './production-nonroot-runtime.mjs';
import {controlLaunchPolicy,validateNonrootEnvironment} from './production-nonroot-launch.mjs';
import {inspectNonrootControlArtifactBinding,verifyNonrootControlArtifactFiles} from './production-nonroot-artifact.mjs';
import {verifyNonrootControlRuntimeObservation} from './production-nonroot-observation.mjs';
import {readControlSourceFile,verifyControlSourceClosure,controlSourcePaths} from './production-control-source.mjs';
import {CI_SMOKE_GATE_ACTION_PATH,ciSmokeSourceClosure,verifyCiSmokeGateAction} from './ci-smoke-isolation.mjs';
import {CONTROL_ZERO_FINDINGS_POLICY_HASH,assertNonrootControlScanPolicy,verifyNonrootControlScan,ecrScanTimestampMs} from './production-nonroot-control-scan-policy.mjs';
import {posix} from 'node:path';
import {parseDocument} from 'yaml';
import {parse as parseSource} from '@babel/parser';
import {inspectProductionControlBuildContract,inspectProductionDeployedControlBuild,inspectProductionControlCompositionRecipe} from './production-control-composition-recipe.mjs';
import {describeProductionControlCompositionPreparation,verifyProductionControlCompositionAction} from './production-control-composition-preparation.mjs';
import {completeProductionControlCompositionBuildCapture,inspectProductionControlCompositionInvocation} from './production-control-composition-capture-reader.mjs';
import {extractProductionControlCompositionCommitment} from './production-control-composition-reader.mjs';

const need=(ok,code='NonrootProvenanceInvalid')=>{if(!ok)throw Error(code);};
const exact=(value,keys)=>need(value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join()===keys.slice().sort().join(),'NonrootProvenanceFields');
const same=(a,b)=>need(hash(a)===hash(b),'NonrootProvenanceBinding');
const git=v=>typeof v==='string'&&/^[a-f0-9]{40}$/.test(v);
const positive=v=>Number.isSafeInteger(v)&&v>0;
const hex=v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
const controlKeys=Object.freeze(['bootstrap','control','promotion','provision','transition']);
const updateKeys=Object.freeze(['backend','bootstrap','control','executor','planner','promotion','provision','transition']);
export const NONROOT_DEPLOYED_CONTROL_IMAGE_SLOT=Object.freeze({version:1,kind:'deployed-control-image',buildContractKey:'deployed-bootstrap'});
const imageOnly=v=>({rootDigest:v.rootDigest,arm64Digest:v.arm64Digest,configDigest:v.configDigest});
const imageUri=v=>`${v.account}.dkr.ecr.${v.region}.amazonaws.com/${v.repositoryName}@${v.rootDigest}`;
const current=(at,now)=>need(positive(now)&&positive(at)&&at<=now&&now-at<=300000,'NonrootProvenanceExpired');
const names=(rows,keys,field='taskKey')=>{need(Array.isArray(rows)&&rows.length===keys.length&&new Set(rows.map(r=>r[field])).size===keys.length,'NonrootProvenanceCoverage');same(rows.map(r=>r[field]).sort(),[...keys].sort());};

/** Uses the existing deployment-source adapter's normalized Git/GitHub facts.
 * The adapter authenticates their origin. This verifies records/commitments;
 * it does not establish authority from a caller-provided approval boolean. */
export async function verifyNonrootActualMain(value,options){
  const main=inspectNonrootRecord('ActualMainV1',value),expected=options?.expected&&copyNonrootJson(options.expected);
  need(expected&&typeof expected.repository==='string'&&positive(expected.prNumber)&&['candidateRevision','candidateTree','baseRevision'].every(k=>git(expected[k])),'NonrootMainExpected');
  for(const k of ['repository','candidateRevision','candidateTree','baseRevision','prNumber'])need(main[k]===expected[k],'NonrootMainExpected');
  const source=await readNonrootEvidence(main.authenticatedSource,options);
  exact(source,['repository','event','ref','checkout','main','run','pullRequest']);
  need(source.repository===main.repository&&source.event==='push'&&source.ref==='refs/heads/main','NonrootMainSource');
  exact(source.checkout,['sha','tree','parents','clean']);exact(source.main,['sha','tree']);
  need(source.checkout.clean===true&&source.checkout.sha===main.mainRevision&&source.checkout.tree===main.mainTree&&source.main.sha===main.mainRevision&&source.main.tree===main.mainTree,'NonrootMainCheckout');
  same(source.checkout.parents,main.parents);
  exact(source.pullRequest,['number','state','merged','headSha','headRepository','baseRef','mergeCommitSha']);
  const pr=source.pullRequest;
  need(pr.number===main.prNumber&&pr.state==='closed'&&pr.merged===true&&pr.headSha===main.candidateRevision&&pr.headRepository===main.repository&&pr.baseRef==='main'&&pr.mergeCommitSha===main.mainRevision,'NonrootMainPullRequest');
  exact(source.run,['id','attempt','event','headSha','repository','path','workflowSha']);
  const run=source.run;
  need(run.id===main.workflowRun&&run.attempt===main.workflowAttempt&&run.event==='push'&&run.headSha===main.mainRevision&&run.workflowSha===main.workflowSha&&run.repository===main.repository&&run.path===main.workflowPath,'NonrootMainRun');
  return Object.freeze({actualMainHash:hash(main),sourceEvidenceHash:main.authenticatedSource.canonicalHash,mainRevision:main.mainRevision,mainTree:main.mainTree,runId:main.workflowRun,runAttempt:main.workflowAttempt});
}

function expectedMain(contract,expected){
 const selected={repository:contract.repository,candidateRevision:contract.candidate.revision,candidateTree:contract.candidate.tree,baseRevision:contract.candidate.baseRevision,prNumber:contract.prNumber};
 need(expected.actualMainExpected,'NonrootMainExpected');same(selected,expected.actualMainExpected);return selected;
}
async function sourceClosure(value,tree,options,sourceContext,copyContext=false){
 const c=await verifyControlSourceClosure(sourceContext,value,{copyContext});need(c.tree===tree,'NonrootBuildSourceTree');
 for(const f of c.files)await readNonrootEvidence(f.blob,options,false);
 return c;
}
async function jsonBytes(ref,options){return parseNonrootJson(new TextDecoder('utf-8',{fatal:true}).decode(await readNonrootEvidence(ref,options,false)));}

async function localSourceClosure(context,roots,{guard=false,allowedBuiltins=[]}={}){
 const seen=new Map();
 async function visit(path){
  if(seen.has(path))return;need(seen.size<1000,'NonrootSourceClosureLimit');
  const {file,bytes}=await readControlSourceFile(context,path);seen.set(path,file);
  const source=new TextDecoder('utf-8',{fatal:true}).decode(bytes);
  need(/\.(?:mjs|js|ts)$/.test(path),'NonrootPreparationLanguageUnsupported');
  const ast=parseSource(source,{sourceType:'unambiguous',createImportExpressions:true,plugins:path.endsWith('.ts')?['typescript']:[]});
  const dependencies=new Set(),requireFactories=new Set();
  for(const node of ast.program.body)if(node.type==='ImportDeclaration'&&node.source.value==='node:module'){
   need(!guard&&node.specifiers.every(s=>s.type==='ImportSpecifier'&&s.imported.name==='createRequire'),'NonrootPreparationLoaderUnsupported');
   for(const s of node.specifiers)requireFactories.add(s.local.name);
  }
  const add=node=>{
   const spec=node?.type==='StringLiteral'?node.value:node?.type==='TemplateLiteral'&&node.expressions.length===0?node.quasis[0].value.cooked:null;
   need(typeof spec==='string','NonrootDynamicPreparationImport');
   if(spec.startsWith('.'))dependencies.add(posix.normalize(posix.join(posix.dirname(path),spec)));
   else{need(!spec.startsWith('/')&&!spec.startsWith('file:'),'NonrootSourceImportScope');if(guard)need(allowedBuiltins.includes(spec),'NonrootGuardSourceImport');}
  };
  const walk=(node,parent)=>{
   if(!node||typeof node!=='object')return;
   if(!guard&&node.type==='Identifier'&&node.name==='require'){
    const direct=parent?.type==='CallExpression'&&parent.callee===node;
    const declaration=parent?.type==='VariableDeclarator'&&parent.id===node&&parent.init?.type==='CallExpression'&&requireFactories.has(parent.init.callee?.name);
    need(direct||declaration,'NonrootIndirectPreparationRequire');
   }
   if(node.type==='CallExpression'||node.type==='NewExpression'){
    need(!['eval','Function'].includes(node.callee?.name),'NonrootPreparationEvalUnsupported');
    need(!['getBuiltinModule','register','registerHooks'].includes(node.callee?.property?.name),'NonrootPreparationLoaderUnsupported');
    if(requireFactories.has(node.callee?.name))need(parent?.type==='VariableDeclarator'&&parent.id?.name==='require','NonrootIndirectPreparationRequire');
   }
   if(['ImportDeclaration','ExportAllDeclaration','ExportNamedDeclaration'].includes(node.type)&&node.source)add(node.source);
   if(!guard&&node.type==='ImportExpression')add(node.source);
   if(!guard&&node.type==='CallExpression'&&(node.callee?.type==='Import'||node.callee?.type==='Identifier'&&node.callee.name==='require')){need(node.arguments.length===1,'NonrootSourceRequire');add(node.arguments[0]);}
   if(!guard&&node.type==='StringLiteral'&&/^(?:scripts\/|\.\.?\/)[A-Za-z0-9_./-]+\.(?:mjs|js|ts|sh)$/.test(node.value))dependencies.add(node.value.startsWith('scripts/')?node.value:posix.normalize(posix.join(posix.dirname(path),node.value)));
   for(const [key,value]of Object.entries(node)){if(['loc','start','end','extra','comments','tokens'].includes(key))continue;if(Array.isArray(value))value.forEach(child=>walk(child,node));else if(value&&typeof value==='object')walk(value,node);}
  };
  walk(ast);for(const dep of [...dependencies].sort())await visit(dep);
 }
 for(const path of [...new Set(roots)].sort())await visit(path);
 const files=[...seen.values()].sort((a,b)=>a.path.localeCompare(b.path));return {version:1,kind:'git-file-closure',tree:context.tree,files,closureHash:hash(files)};
}

/** Keep CONTROL's existing eval/loader/indirect-require checks and literal
 * local script references while using the already reviewed CI resolver for
 * the Node action's transitive imports, including the fixed SST loader. */
function preparationReferences(path,bytes){
 if(!/\.(?:mjs|cjs|js|ts|mts|cts|tsx|jsx)$/.test(path))return [];
 const ast=parseSource(new TextDecoder('utf-8',{fatal:true}).decode(bytes),{sourceType:'unambiguous',createImportExpressions:true,plugins:[...(/\.(?:ts|mts|cts|tsx)$/.test(path)?['typescript']:[]),...(/\.[jt]sx$/.test(path)?['jsx']:[])]}),references=new Set();
 const visit=(node,parent)=>{
  if(!node||typeof node!=='object')return;
  if(node.type==='ImportDeclaration'&&node.source.value==='node:module')need(false,'NonrootPreparationLoaderUnsupported');
  if(node.type==='Identifier'&&node.name==='require')need(parent?.type==='CallExpression'&&parent.callee===node,'NonrootIndirectPreparationRequire');
  if(node.type==='CallExpression'||node.type==='NewExpression'){
   need(!['eval','Function'].includes(node.callee?.name),'NonrootPreparationEvalUnsupported');
   need(!['getBuiltinModule','register','registerHooks'].includes(node.callee?.property?.name),'NonrootPreparationLoaderUnsupported');
  }
  if(node.type==='StringLiteral'&&/^(?:scripts\/|\.\.?\/)[A-Za-z0-9_./-]+\.(?:mjs|js|ts|sh)$/.test(node.value))references.add(node.value.startsWith('scripts/')?node.value:posix.normalize(posix.join(posix.dirname(path),node.value)));
  for(const [key,value]of Object.entries(node)){if(['loc','start','end','extra','comments','tokens'].includes(key))continue;if(Array.isArray(value))value.forEach(child=>visit(child,node));else if(value&&typeof value==='object')visit(value,node);}
 };
 visit(ast);return [...references];
}

/** Source description only. The verifier separately binds job to the complete
 * authenticated workflow; a matching action name alone is never a closure. */
export async function describeNonrootControlPreparation(context,job){
 if(job?.steps?.some(s=>s.uses==='./.github/actions/control-composition'))return describeProductionControlCompositionPreparation(context,job);
 need(job&&Array.isArray(job.steps),'NonrootWorkflowSource');const roots=new Set();let gate=false;
 for(const step of job.steps){
  if(typeof step.uses==='string'&&step.uses.startsWith('./')){
   need(step.uses==='./'+posix.dirname(CI_SMOKE_GATE_ACTION_PATH),'NonrootLocalBuildActionUnsupported');
   const action=await readControlSourceFile(context,CI_SMOKE_GATE_ACTION_PATH),doc=parseDocument(new TextDecoder('utf-8',{fatal:true}).decode(action.bytes),{uniqueKeys:true});
   need(doc.errors.length===0&&doc.warnings.length===0,'NonrootWorkflowSource');
   const paths=verifyCiSmokeGateAction(step,doc.toJS({maxAliasCount:0}));roots.add(paths.actionPath);roots.add(paths.entryPath);gate=true;
  }
  if(typeof step.run==='string')for(const m of step.run.matchAll(/\bscripts\/[A-Za-z0-9_./-]+\.(?:mjs|js|ts|sh)\b/g))roots.add(m[0]);
 }
 if(!gate)return localSourceClosure(context,[...roots]);
 const files=new Map();
 while(true){
  need(roots.size<=1000,'NonrootSourceClosureLimit');const pins=await ciSmokeSourceClosure(context,[...roots]);need(pins.length<=1000,'NonrootSourceClosureLimit');let added=false;
  for(const pin of pins){
   if(files.has(pin.path))continue;const found=await readControlSourceFile(context,pin.path);files.set(pin.path,found.file);
   for(const path of preparationReferences(pin.path,found.bytes))if(!roots.has(path)){roots.add(path);added=true;}
  }
  if(!added)break;
 }
 const source=[...files.values()].sort((a,b)=>a.path.localeCompare(b.path));return {version:1,kind:'git-file-closure',tree:context.tree,files:source,closureHash:hash(source)};
}

/** Git membership and declared COPY/static preparation closure only. The build
 * producer additionally checks its actual working directory for untracked or
 * changed build-context inputs immediately before Docker consumes it. */
export async function verifyNonrootControlSource(value,options){
 const contract=inspectProductionControlBuildContract(value),context=options?.expected?.sourceContext;
 need(context,'NonrootSourceVerificationRequired');const paths=controlSourcePaths(context);
 need(context.tree===contract.candidate.tree,'NonrootBuildSourceTree');
 if(contract.artifactPolicyHash===CONTROL_ZERO_FINDINGS_POLICY_HASH)await assertNonrootControlScanPolicy(contract,context);
 const workflow=await readControlSourceFile(context,contract.workflow.path);same(workflow.file,contract.workflow.sourceFile);
 const doc=parseDocument(new TextDecoder('utf-8',{fatal:true}).decode(workflow.bytes),{uniqueKeys:true});need(doc.errors.length===0,'NonrootWorkflowSource');
 const job=doc.toJS()?.jobs?.[contract.workflow.jobKey];need(job&&Array.isArray(job.steps),'NonrootWorkflowSource');same(job,await jsonBytes(contract.workflow.jobSource,options));
 if(contract.version===2){
  inspectProductionControlCompositionRecipe(contract.recipe);
  const steps=job.steps.filter(s=>s.id===contract.workflow.buildStepId);need(steps.length===1,'NonrootControlBuildStep');
  const action=await readControlSourceFile(context,contract.recipe.invocation.actionPath),yaml=parseDocument(new TextDecoder('utf-8',{fatal:true}).decode(action.bytes),{uniqueKeys:true});
  need(yaml.errors.length===0&&yaml.warnings.length===0,'NonrootWorkflowSource');
  verifyProductionControlCompositionAction(steps[0],yaml.toJS({maxAliasCount:0}));same(action.file,contract.recipe.invocation.actionSource);
 }
 else need(!job.steps.some(s=>s.uses==='./.github/actions/control-composition'),'NonrootControlRecipeVersion');
 const dockerfile=await readControlSourceFile(context,contract.recipe.dockerfilePath);same(dockerfile.file,contract.recipe.dockerfile);
 await sourceClosure(contract.recipe.context,context.tree,options,context,true);
 const ignores=await readNonrootEvidence(contract.recipe.ignoreFiles,options),ignorePaths=['.dockerignore','docker/bootstrap/Dockerfile.dockerignore'];
 need(Array.isArray(ignores)&&ignores.length===2&&new Set(ignores.map(r=>r.path)).size===2,'NonrootControlIgnoreFiles');
 for(const path of ignorePaths){const row=ignores.find(r=>r.path===path);need(row,'NonrootControlIgnoreFiles');if(paths.includes(path))same(row,(await readControlSourceFile(context,path)).file);else{exact(row,['path','absent']);need(row.absent===true,'NonrootControlIgnoreFiles');}}
 const preparation=await describeNonrootControlPreparation(context,job);same(preparation,contract.recipe.preparation);
 const guard=await localSourceClosure(context,['docker/bootstrap/nonroot-dispatch.mjs'],{guard:true,allowedBuiltins:contract.guardImportPolicy.allowedBuiltins});same(guard,contract.guardSource);same(guard,contract.guardImportPolicy.guardSource);
 await sourceClosure(contract.recipe.preparation,context.tree,options,context);await sourceClosure(contract.guardSource,context.tree,options,context);
 return copyNonrootJson({tree:context.tree,contractHash:hash(contract),copyClosureHash:hash(contract.recipe.context),preparationHash:hash(preparation),guardSourceHash:hash(guard),ignoreFilesHash:hash(ignores)});
}

export function verifyNonrootControlBuildLog(bytes,image){
 need(bytes instanceof Uint8Array&&bytes.length>0&&bytes.length<=16777216,'NonrootControlBuildLog');
 const rows=new TextDecoder('utf-8',{fatal:true}).decode(bytes).split('\n');
 const events=rows.flatMap((line,index)=>{
  const m=/(?:^|\s)#([0-9]+) exporting (manifest list|manifest|config) (sha256:[a-f0-9]{64})(.*)$/.exec(line);
  return m?[{vertex:m[1],kind:m[2],digest:m[3],suffix:m[4].trim(),index}]:[];
 });
 const kinds=[['manifest list',image.rootDigest],['config',image.configDigest],...(image.arm64Digest===undefined?[]:[['manifest',image.arm64Digest]])];
 let vertex,last=-1;
 for(const[kind,digest]of kinds){
  need(/^sha256:[a-f0-9]{64}$/.test(digest??''),'NonrootControlBuildLog');
  const matches=events.filter(e=>e.kind===kind&&e.digest===digest);
  need(matches.length>=1&&matches.length<=2,'NonrootControlBuildLog');
  vertex??=matches[0].vertex;
  need(matches.every(e=>e.vertex===vertex&&(e.suffix===''||/^(?:[0-9]+(?:\.[0-9]+)?s )?done$/.test(e.suffix))),'NonrootControlBuildLog');
  // BuildKit may report a start line and a separate completion for the same
  // export. They are one event, not two competing image identities.
  if(matches.length===2)need(matches[0].suffix===''&&matches[1].suffix.endsWith('done'),'NonrootControlBuildLog');
  need(events.filter(e=>e.vertex===vertex&&e.kind===kind).every(e=>e.digest===digest),'NonrootControlBuildLog');
  last=Math.max(last,...matches.map(e=>e.index));
 }
 const done=rows.flatMap((line,index)=>new RegExp('(?:^|\\s)#'+vertex+' DONE(?:\\s|$)').test(line)?[index]:[]);
 need(done.length===1&&done[0]>last&&!rows.some(line=>new RegExp('(?:^|\\s)#'+vertex+' (?:ERROR|CACHED)(?:\\s|$)').test(line)),'NonrootControlBuildLog');
 return {vertex};
}

async function verifyControlImage(value,options){
 const graph=await readNonrootEvidence(value.imageGraph,options);exact(graph,['rootManifest','arm64Manifest','config']);
 for(const [key,field]of [['rootManifest','rootDigest'],['arm64Manifest','arm64Digest'],['config','configDigest']])need('sha256:'+graph[key].sha256===value.image[field],'NonrootControlImageBinding');
 const root=await jsonBytes(graph.rootManifest,options),child=await jsonBytes(graph.arm64Manifest,options),config=await jsonBytes(graph.config,options);
 need(root.schemaVersion===2&&['application/vnd.oci.image.index.v1+json','application/vnd.docker.distribution.manifest.list.v2+json'].includes(root.mediaType)&&Array.isArray(root.manifests),'NonrootControlImageGraph');
 const arm=root.manifests.filter(m=>m.platform?.os==='linux'&&m.platform.architecture==='arm64');
 need(arm.length===1&&arm[0].digest===value.image.arm64Digest&&arm[0].size===graph.arm64Manifest.bytesLength&&arm[0].mediaType===child.mediaType,'NonrootControlImageGraph');
 need(child.schemaVersion===2&&['application/vnd.oci.image.manifest.v1+json','application/vnd.docker.distribution.manifest.v2+json'].includes(child.mediaType)&&Array.isArray(child.layers)&&child.config?.digest===value.image.configDigest&&child.config.size===graph.config.bytesLength&&config.os==='linux'&&config.architecture==='arm64','NonrootControlImageGraph');
 return config;
}

async function verifyControlScan(scan,image,policyHash,sourceTree,options,now){
 same(scan.image,image);need(scan.policyHash===policyHash,'NonrootControlScanPolicy');current(scan.observedMs,now);
 const pages=await readNonrootEvidence(scan.rawPages,options),normalized=await readNonrootEvidence(scan.normalizedFindings,options),review=await readNonrootEvidence(scan.artifactReview,options);
 need(Array.isArray(pages)&&pages.length>0&&pages.length<=100&&Array.isArray(normalized),'NonrootControlScan');
 const findings=[],tokens=new Set();let identity;
 for(const [i,p]of pages.entries()){
  const s=p.imageScanFindings,completedMs=ecrScanTimestampMs(s?.imageScanCompletedAt);
  need(p.registryId===image.account&&p.repositoryName===image.repositoryName&&p.imageId?.imageDigest===image.arm64Digest&&p.imageScanStatus?.status==='COMPLETE'&&positive(completedMs)&&completedMs<=scan.observedMs&&scan.observedMs-completedMs<=86400000&&Array.isArray(s?.findings)&&!s.enhancedFindings?.length&&s.findingSeverityCounts,'NonrootControlScan');
  const currentIdentity={completedMs,counts:s.findingSeverityCounts};if(identity)same(identity,currentIdentity);identity=currentIdentity;
  findings.push(...s.findings);need(findings.length<=10000,'NonrootControlScan');
  if(i<pages.length-1){need(typeof p.nextToken==='string'&&p.nextToken.length>0&&!tokens.has(p.nextToken),'NonrootControlScanPages');tokens.add(p.nextToken);}else need(!p.nextToken,'NonrootControlScanPages');
 }
 const counts={},actual=findings.map(f=>{need(typeof f?.name==='string'&&['INFORMATIONAL','LOW','MEDIUM','HIGH','CRITICAL','UNDEFINED'].includes(f.severity)&&Array.isArray(f.attributes)&&f.attributes.every(a=>typeof a.key==='string'&&typeof a.value==='string'),'NonrootControlFinding');counts[f.severity]=(counts[f.severity]??0)+1;return {...f,attributes:[...f.attributes].sort((a,b)=>hash(a).localeCompare(hash(b)))};}).sort((a,b)=>hash(a).localeCompare(hash(b)));
 need(Object.values(identity.counts).every(n=>Number.isSafeInteger(n)&&n>=0),'NonrootControlFindingCounts');same(counts,Object.fromEntries(Object.entries(identity.counts).filter(([,n])=>n!==0)));same(actual,normalized);
 // The archive adapter authenticates the image-specific review. The hashes
 // here prevent applying that review to different findings or a different image.
 exact(review,['version','kind','decision','image','policyHash','findingsHash','sourceTree','reviewedMs','expiresMs']);
 need(review.version===1&&review.kind==='control-artifact-policy-review'&&review.decision==='within-existing-policy'&&review.policyHash===policyHash&&review.findingsHash===hash(normalized)&&review.sourceTree===sourceTree&&positive(review.reviewedMs)&&positive(review.expiresMs)&&review.reviewedMs>=scan.observedMs&&review.reviewedMs<=now&&review.expiresMs>now&&review.expiresMs-review.reviewedMs<=86400000,'NonrootControlArtifactReview');same(review.image,image);
 return scan.rawPages.canonicalHash;
}

async function verifyControlLaunch(launch,template,build,contract,imageConfig,options,now){
 need(launch.templateHash===hash(template)&&launch.contractHash===hash(contract)&&launch.containerName===template.containerName,'NonrootControlLaunchTemplate');
 for(const key of ['entryPoint','command','dispatcherSha256','originalModule','originalModuleSha256','originalArgv'])same(launch[key],template[key]);
 need(launch.guardClosureHash===hash(build.guardSource)&&launch.guardClosureHash===template.guardClosure.canonicalHash,'NonrootControlGuardClosure');same(launch.guardImports,build.guardImports);
 const body=await readNonrootEvidence(launch.registrationBody,options);need(hash(body)===launch.registrationBodyHash,'NonrootControlRegistrationHash');
 need(body.networkMode==='awsvpc'&&body.runtimePlatform?.cpuArchitecture==='ARM64'&&body.runtimePlatform?.operatingSystemFamily==='LINUX'&&Array.isArray(body.containerDefinitions)&&body.containerDefinitions.length===1,'NonrootControlRegistration');
 const container=body.containerDefinitions[0];need(container.name===launch.containerName&&container.image===imageUri(build.image),'NonrootControlRegistrationImage');
 same(container,controlLaunchPolicy(template.purpose,container));same(container.entryPoint,launch.entryPoint);same(container.command,launch.command);
 const primitive=inspectNonrootRecord('PrimitiveEvidenceV1',await readNonrootEvidence(launch.primitiveEvidence,options));same(primitive.image,imageOnly(build.image));need(primitive.invokedPath===launch.entryPoint[0],'NonrootControlPrimitive');
 const e=launch.environment;current(e.checkedMs,now);same(e.image,imageOnly(build.image));need(e.registrationBodyHash===hash(body),'NonrootControlEnvironment');
 const imageEnvironment=await readNonrootEvidence(e.imageEnvironment,options),taskEnvironment=await readNonrootEvidence(e.taskEnvironment,options),secrets=await readNonrootEvidence(e.secretNamesAndReferences,options),overrides=await readNonrootEvidence(e.overrideEnvironment,options),files=await readNonrootEvidence(e.loaderFileEvidence,options);
 same(imageEnvironment,imageConfig.config?.Env??[]);same(taskEnvironment,container.environment??[]);same(secrets,container.secrets??[]);same(overrides,{});
 const checked=validateNonrootEnvironment({imageEnvironment,taskEnvironment,secrets,overrides,files,expectedCa:e.caBindings.map(c=>({path:c.resolvedPath,sha256:c.file.sha256}))});
 need(checked.overrideHash===e.overrideHash&&checked.forbiddenNamesHash===e.forbiddenNamesHash,'NonrootControlEnvironment');
 return body;
}

/** expected.contract is authenticated and source-validated before this call.
 * workflow.jobSource is its byte-pinned normalized source-job object (the
 * existing source parser owns extraction from the retained full workflow).
 * Provider observations and artifact reviews come through the trusted archive.
 * The result contains verified bindings, never an authorization brand. */
export async function verifyNonrootDeployedControlBuild(value,options){
 const b=inspectProductionDeployedControlBuild(value),{sourceContext,...expectedData}=options?.expected??{},expected=copyNonrootJson(expectedData),now=options?.now??Date.now();
 inspectNonrootControlArtifactBinding(b,options);
 const contract=inspectProductionControlBuildContract(expected.contract);need(b.version===contract.version,'NonrootControlRecipeVersion');
 need(positive(now)&&b.startedMs<=b.completedMs&&b.completedMs<=now&&b.contractHash===hash(contract),'NonrootControlBuildBinding');
 await verifyNonrootControlSource(contract,{...options,expected:{...expected,sourceContext}});
 const main=await verifyNonrootActualMain(b.actualMain,{...options,expected:expectedMain(contract,expected)});
 same(b.recipe,contract.recipe);same(b.guardSource,contract.guardSource);
 need(b.source.repository===contract.repository&&b.source.tree===contract.candidate.tree&&b.source.revision===main.mainRevision,'NonrootControlBuildSource');
 await verifyNonrootActualMain({...b.actualMain,authenticatedSource:b.source.sourceEvidence},{...options,expected:expectedMain(contract,expected)});
 const source=await readNonrootEvidence(b.actualMain.authenticatedSource,options);same(await readNonrootEvidence(b.source.checkout,options),source.checkout);
 for(const key of ['account','region','repositoryName'])need(b.image[key]===contract.output[key],'NonrootControlBuildImage');
 const jobSource=await jsonBytes(contract.workflow.jobSource,options);need(jobSource&&typeof jobSource.name==='string'&&Array.isArray(jobSource.steps),'NonrootControlJobSource');
 const steps=jobSource.steps.filter(s=>s.id===contract.workflow.buildStepId);need(steps.length===1,'NonrootControlBuildStep');const step=steps[0];
 if(contract.version===1){
 need(Object.keys(step).every(k=>['name','id','if','uses','with'].includes(k))&&Object.keys(step.with??{}).every(k=>['context','file','platforms','pull','no-cache-filters','push','tags','cache-from','cache-to'].includes(k)),'NonrootControlBuildStep');
 need(step.uses==='docker/build-push-action@'+contract.recipe.invocation.buildActionSha&&step.with?.context==='.'&&step.with.file===contract.recipe.dockerfilePath&&step.with.pull===true&&step.with.platforms==='linux/arm64'&&step.with['no-cache-filters']==='runtime'&&step.with.push===true,'NonrootControlBuildStep');
 const list=v=>typeof v==='string'?v.split('\n').map(s=>s.trim()).filter(Boolean):[];
 same(list(step.with['cache-from']),contract.recipe.invocation.cacheFrom);same(list(step.with['cache-to']),contract.recipe.invocation.cacheTo);
 }
 const run=await readNonrootEvidence(b.workflow.authenticatedRun,options),job=await readNonrootEvidence(b.workflow.authenticatedJob,options);
 need(run.id===b.workflow.runId&&run.run_attempt===b.workflow.attempt&&run.event==='push'&&run.head_sha===main.mainRevision&&run.head_branch==='main'&&run.path===b.workflow.path&&run.repository?.full_name===b.source.repository,'NonrootControlBuildRun');
 need(job.id===b.workflow.jobId&&job.run_id===b.workflow.runId&&job.run_attempt===b.workflow.attempt&&job.head_sha===main.mainRevision&&job.name===jobSource.name&&job.name===b.workflow.jobName&&job.status==='completed'&&job.conclusion==='success'&&Array.isArray(job.steps),'NonrootControlBuildJob');
 const actualSteps=job.steps.filter(s=>s.name===step.name);need(actualSteps.length===1&&actualSteps[0].status==='completed'&&actualSteps[0].conclusion==='success','NonrootControlBuildStep');
 const invoked=await readNonrootEvidence(b.actualInvocation,options);let nativeCapture;
 if(contract.version===2){
  inspectProductionControlCompositionInvocation(invoked,contract.recipe);
  const bytes=await readNonrootEvidence(invoked.capture,options,false),buildLog=await readNonrootEvidence(b.buildLog,options,false);
  const checked=completeProductionControlCompositionBuildCapture(bytes,{commitment:extractProductionControlCompositionCommitment(buildLog),contract,source,run,job,buildLog,metadataReads:options.metadataReads,now});
  nativeCapture=checked.capture;same(nativeCapture.image,b.image);same(nativeCapture.actualMain,b.actualMain);
  need(b.startedMs<=nativeCapture.startedMs&&nativeCapture.completedMs<=b.completedMs,'NonrootControlBuildBinding');
 }else{
 const {tagRule,provenanceRule,...invocation}=contract.recipe.invocation;
 exact(invoked,[...Object.keys(invocation),'tags','provenance']);for(const key of Object.keys(invocation))same(invoked[key],invocation[key]);
 same(invoked.tags,[`${b.image.account}.dkr.ecr.${b.image.region}.amazonaws.com/${b.image.repositoryName}:mem9-${main.mainRevision.slice(0,7)}`]);
 same(invoked.provenance,{repository:b.source.repository,revision:main.mainRevision,runId:b.workflow.runId,attempt:b.workflow.attempt,jobId:b.workflow.jobId});
 }
 await sourceClosure(b.guardSource,contract.candidate.tree,options,sourceContext);
 await readNonrootEvidence(contract.workflow.sourceFile.blob,options,false);await readNonrootEvidence(contract.recipe.dockerfile.blob,options,false);
 const imageConfig=await verifyControlImage(b,options);
 const fileFacts=await verifyNonrootControlArtifactFiles(b,options);
 if(nativeCapture){
  need(nativeCapture.graphHash===fileFacts.graphHash&&hash(nativeCapture.filesystem)===fileFacts.filesystemHash,'NonrootControlBuildGraph');
 }
 // Missing tar root/parent metadata is supplied only by the actual isolated
 // runtime collector, bound to these same graph/FS handles and build bytes.
 const runtimeObservation=verifyNonrootControlRuntimeObservation(options.runtimeObservation,b,options);
 same(runtimeObservation.filesHash,hash(fileFacts.files));
 same(b.guardImports.nodeRuntime.image,imageOnly(b.image));same(b.guardImports.localGuardFiles,b.guardSource);need(b.guardImports.policyHash===hash(contract.guardImportPolicy),'NonrootGuardImportPolicy');
 same(b.guardImports.allowedBuiltins,contract.guardImportPolicy.allowedBuiltins);
 const dispatchers=b.guardSource.files.filter(f=>f.path==='docker/bootstrap/nonroot-dispatch.mjs');need(dispatchers.length===1,'NonrootControlGuardSource');
 same(b.guardImports.entryModule,dispatchers[0].blob);for(const t of contract.launchTemplates)need(t.dispatcherSha256===dispatchers[0].sha256,'NonrootControlGuardSource');
 const node=await readNonrootEvidence(b.guardImports.nodeRuntime.inventory,options);same(node.image,imageOnly(b.image));need(node.executablePath===b.guardImports.nodeRuntime.executablePath&&node.executableSha256===b.guardImports.nodeRuntime.executableSha256,'NonrootControlNodeBinding');
 if(contract.artifactPolicyHash===CONTROL_ZERO_FINDINGS_POLICY_HASH)await verifyNonrootControlScan(b.scan,{image:b.image,contract,sourceContext,resolveJson:options.resolveJson,resolveBytes:options.resolveBytes,now});
 else await verifyControlScan(b.scan,b.image,contract.artifactPolicyHash,b.source.tree,options,now);
 names(contract.launchTemplates,controlKeys);names(b.resolvedLaunches,controlKeys);
 const registrations={};for(const l of b.resolvedLaunches)registrations[l.taskKey]=await verifyControlLaunch(l,contract.launchTemplates.find(t=>t.taskKey===l.taskKey),b,contract,imageConfig,options,now);
 const tests=await readNonrootEvidence(b.guardTests,options);exact(tests,['version','kind','image','sourceRevision','sourceTree','guardSourceHash','contractHash','testContractHash','launches','completedMs']);
 same(tests.image,b.image);need(tests.version===1&&tests.kind==='control-guard-test-evidence'&&tests.sourceRevision===main.mainRevision&&tests.sourceTree===main.mainTree&&tests.guardSourceHash===hash(b.guardSource)&&tests.contractHash===hash(contract)&&tests.testContractHash===contract.guardTestContract.canonicalHash&&positive(tests.completedMs)&&tests.completedMs>=b.startedMs&&tests.completedMs<=b.completedMs,'NonrootControlGuardTests');names(tests.launches,controlKeys);
 for(const result of tests.launches){exact(result,['taskKey','launchHash','purpose','result','applicationReached','credentialAccessBeforeGuard']);const template=contract.launchTemplates.find(t=>t.taskKey===result.taskKey);
  need(result.launchHash===hash(b.resolvedLaunches.find(l=>l.taskKey===result.taskKey))&&result.purpose===template.purpose&&result.result==='pass'&&result.applicationReached===!template.purpose.startsWith('denied')&&result.credentialAccessBeforeGuard===false,'NonrootControlGuardTests');}
 if(contract.version===1)verifyNonrootControlBuildLog(await readNonrootEvidence(b.buildLog,options,false),b.image);
 await verifyNonrootEvidenceReferences(b,options);await verifyNonrootEvidenceReferences(contract,options);
 return copyNonrootJson({...main,deployedControlBuildHash:hash(b),contractHash:hash(contract),image:b.image,registrations,controlRuntimeObservationHash:hash(runtimeObservation)});
}

/** The only preplan substitution is an exact typed image slot in the one
 * named deployed-CONTROL container. Every other key/value, including unknown
 * provider fields, is compared. No neutral projection strips execution data. */
function resolveBody(before,launch,image){
 const body=structuredClone(copyNonrootJson(before));
 need(Array.isArray(body.containerDefinitions),'NonrootTaskPlanBody');
 const rows=body.containerDefinitions.filter(c=>c.name===launch.containerName);need(rows.length===1,'NonrootTaskPlanContainer');
 same(rows[0].image,NONROOT_DEPLOYED_CONTROL_IMAGE_SLOT);rows[0].image=imageUri(image);return body;
}

export async function verifyNonrootDeploymentSource(value,options){
 const record=inspectNonrootRecord('DeploymentSourceRecordV2',value),{sourceContext,...expectedData}=options?.expected??{},expected=copyNonrootJson(expectedData),now=options?.now??Date.now();
 need(hex(expected.descriptorHash)&&hex(expected.proofHash)&&positive(expected.parameterVersion),'NonrootDeploymentExpected');
 for(const key of ['descriptorHash','parameterVersion','proofHash'])need(record[key]===expected[key],'NonrootDeploymentBinding');current(record.checkedMs,now);
 const taskPlan=inspectNonrootRecord('TaskPlanV2',expected.taskPlan),contract=inspectProductionControlBuildContract(expected.contract);
 same(taskPlan.deployedControlBuildContract,contract);same(taskPlan.controlLaunches,contract.launchTemplates);
 const build=await verifyNonrootDeployedControlBuild(record.deployedControlBuild,{...options,expected:{...expected,sourceContext}});same(record.actualMain,record.deployedControlBuild.actualMain);
 need(record.checkedMs>=record.deployedControlBuild.completedMs,'NonrootDeploymentTime');
 const resolved=inspectNonrootRecord('ResolvedTaskPlanV1',await readNonrootEvidence(record.resolvedTaskPlan,options));
 need(resolved.taskPlanHash===hash(taskPlan)&&resolved.deployedControlBuildHash===build.deployedControlBuildHash,'NonrootResolvedTaskPlanBinding');
 same(resolved.controlLaunches,record.deployedControlBuild.resolvedLaunches);
 const updates=taskPlan.tasks.filter(t=>t.disposition==='update');names(updates,updateKeys);names(resolved.tasks,updateKeys);
 const registrations={};
 for(const task of updates){
  const row=resolved.tasks.find(r=>r.taskKey===task.taskKey),before=await readNonrootEvidence(task.targetRegistration,options),actual=await readNonrootEvidence(row.registrationBody,options);
  const launch=resolved.controlLaunches.find(l=>l.taskKey===task.taskKey);
  if(controlKeys.includes(task.taskKey)){need(launch,'NonrootControlLaunchMissing');same(resolveBody(before,launch,record.deployedControlBuild.image),actual);same(actual,build.registrations[task.taskKey]);}
  else{need(!launch,'NonrootUnexpectedControlLaunch');same(before,actual);}
  same(actual.containerDefinitions.map(c=>c.name).sort(),[...task.containerNames].sort());registrations[task.taskKey]=actual;
 }
 const fallback=taskPlan.tasks.filter(t=>t.taskKey==='fallback');need(fallback.length===1&&fallback[0].disposition==='retain'&&fallback[0].invocation==='deny','NonrootFallbackBinding');
 const retained=await readNonrootEvidence(fallback[0].beforeDefinition,options);need(hash(retained)===fallback[0].unchangedBindingHash,'NonrootFallbackBinding');
 return copyNonrootJson({...build,deploymentSourceHash:hash(record),resolvedTaskPlanHash:hash(resolved),taskPlanHash:hash(taskPlan),descriptorHash:record.descriptorHash,parameterVersion:record.parameterVersion,proofHash:record.proofHash,registrations,retainedFallback:fallback[0]});
}
