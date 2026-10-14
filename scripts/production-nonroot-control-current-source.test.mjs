import {it,expect,afterEach} from 'vitest';
import {execFileSync} from 'node:child_process';
import {mkdtempSync,readFileSync,lstatSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {parseDocument} from 'yaml';
import {nonrootDeploymentFixture} from './production-nonroot-provenance.fixture.mjs';
import {createControlSourceContext,readControlSourceFile,describeControlCopyClosure} from './lib/production-control-source.mjs';
import {verifyNonrootControlSource,describeNonrootControlPreparation} from './lib/production-nonroot-provenance.mjs';
import {PRODUCTION_CONTROL_COMPOSITION_ACTION as ACTION,PRODUCTION_CONTROL_COMPOSITION_ENTRY as ENTRY,PRODUCTION_CONTROL_COMPOSITION_TOOLCHAIN as TOOLCHAIN} from './lib/production-control-composition-recipe.mjs';
import {PRODUCTION_CONTROL_COMPOSITION_BUNDLE_BUILDER as BUILDER} from './lib/production-control-composition-preparation.mjs';
import {COMPOSITION_BUILDER_ID} from './lib/production-control-composition.mjs';
import {nonrootHash as hash} from './lib/production-nonroot-contracts.mjs';
import {CONTROL_ZERO_FINDINGS_POLICY_HASH,CONTROL_ZERO_FINDINGS_POLICY_SOURCE} from './lib/production-nonroot-control-scan-policy.mjs';

const directories=[],repository=new URL('..',import.meta.url),workflowPath='.github/workflows/infra-ci.yml';
afterEach(()=>{for(const directory of directories.splice(0))rmSync(directory,{recursive:true,force:true});});
function checkoutFiles(){
 const names=execFileSync('git',['ls-files','--cached','--others','--exclude-standard','-z'],{cwd:repository,maxBuffer:33554432}).toString().split('\0').filter(Boolean),files=new Map();
 for(const path of new Set(names)){
  if(path.includes('.local.')||path==='.local.json'||path==='.env')continue;
  const name=new URL(path,repository),stat=lstatSync(name);if(stat.isFile())files.set(path,{bytes:readFileSync(name),mode:stat.mode&0o111?'100755':'100644'});
 }
 return files;
}
async function fixture({defect}={}){
 const f=await nonrootDeploymentFixture(),files=checkoutFiles(),directory=mkdtempSync(join(tmpdir(),'control-current-source-'));directories.push(directory);
 if(['unknown-action','aliased-action','extra-input'].includes(defect)){
  const workflow=parseDocument(files.get(workflowPath).bytes.toString()).toJS(),step=workflow.jobs['build-image-transition-control'].steps.find(s=>s.id==='bootstrap');
  if(defect==='unknown-action')step.uses='./.github/actions/unreviewed';
  if(defect==='aliased-action')step.uses='./.github/actions/control-composition/.';
  if(defect==='extra-input')step.with={argv:'unreviewed'};
  files.set(workflowPath,{bytes:Buffer.from(JSON.stringify(workflow)),mode:'100644'});
 }
 if(defect==='action-definition'){
  const action=parseDocument(files.get(ACTION).bytes.toString()).toJS();action.runs.using='node20';
  files.set(ACTION,{bytes:Buffer.from(JSON.stringify(action)),mode:'100644'});
 }
 const sourceEntry='.github/actions/control-composition/index.mjs';
 if(defect==='entry-eval')files.set(sourceEntry,{...files.get(sourceEntry),bytes:Buffer.concat([files.get(sourceEntry).bytes,Buffer.from('\neval(process.env.EXTRA_CODE);\n')])});
 const git=(args,input)=>execFileSync('git',args,{cwd:directory,input,maxBuffer:33554432,stdio:['pipe','pipe','pipe']});git(['init','--quiet']);
 const blobs=new Map(),entries=[],index=[];
 for(const [path,file]of files){const oid=git(['hash-object','-w','--stdin'],file.bytes).toString().trim();blobs.set(oid,file.bytes);entries.push({path,mode:file.mode,type:'blob',oid});index.push(file.mode+' '+oid+'\t'+path+'\n');}
 git(['update-index','--index-info'],index.join(''));const tree=git(['write-tree']).toString().trim();
 const context=createControlSourceContext({tree,entries},async oid=>{const b=blobs.get(oid);f.bytes(b);return b;}),contract=structuredClone(f.contract);
 const job=parseDocument(files.get(workflowPath).bytes.toString()).toJS().jobs['build-image-transition-control'];
 const closure=async paths=>{const rows=await Promise.all([...new Set(paths)].map(async path=>(await readControlSourceFile(context,path)).file));rows.sort((a,b)=>a.path.localeCompare(b.path));return {version:1,kind:'git-file-closure',tree,files:rows,closureHash:hash(rows)};};
 const manifest=JSON.parse(files.get(TOOLCHAIN).bytes);
 const paths=[ACTION,ENTRY,TOOLCHAIN,BUILDER,'package-lock.json',...manifest.inputs.filter(row=>!row.path.startsWith('node_modules/')).map(row=>row.path)];
 contract.version=2;contract.candidate.tree=tree;contract.artifactPolicyHash=CONTROL_ZERO_FINDINGS_POLICY_HASH;contract.workflow.sourceFile=(await readControlSourceFile(context,workflowPath)).file;contract.workflow.jobSource=f.bytes(JSON.stringify(job));
 contract.recipe={version:2,kind:'native-control-composition-recipe',dockerfilePath:'docker/bootstrap/Dockerfile',
  dockerfile:(await readControlSourceFile(context,'docker/bootstrap/Dockerfile')).file,context:await describeControlCopyClosure(context),preparation:await closure(paths),
  invocation:{version:2,kind:'native-control-composition-invocation',builder:COMPOSITION_BUILDER_ID,
   actionPath:ACTION,actionSource:(await readControlSourceFile(context,ACTION)).file,entryPath:ENTRY,
   bundle:(await readControlSourceFile(context,ENTRY)).file,toolchain:(await readControlSourceFile(context,TOOLCHAIN)).file,
   runtime:'node24',format:'ustar',compression:'none',platform:'linux/arm64',tagRule:'mem9-actual-main-sha7',provenanceRule:'authenticated-workflow-run-attempt'},
  // These synthetic anchors exercise source verification only. They are not
  // a funded composition plan, runtime capture or production authorization.
  composition:{planHash:hash('synthetic-source-plan'),copyHash:hash('synthetic-source-copy')},
 };
 contract.recipe.ignoreFiles=f.json(await Promise.all(['.dockerignore','docker/bootstrap/Dockerfile.dockerignore'].map(async path=>files.has(path)?(await readControlSourceFile(context,path)).file:{path,absent:true})));
 contract.guardSource=await closure(['docker/bootstrap/nonroot-dispatch.mjs','docker/bootstrap/nonroot-files.mjs','docker/bootstrap/nonroot-identity.mjs']);contract.guardImportPolicy.guardSource=contract.guardSource;
 return {f,files,context,contract,job,options:()=>({...f.options(),expected:{sourceContext:context}})};
}

it('verifies the complete current CONTROL workflow, real Node24 action and preparation transitives',async()=>{
 const x=await fixture();
 expect(x.job.steps.some(s=>s.uses==='./.github/actions/control-composition')).toBe(true);
 expect(x.job.env.MEM9_CI_ACQUISITION_CONFIG).toBe('${{ secrets.MEM9_CI_PROD_ACQUISITION_CONFIG }}');
 expect(x.files.has(CONTROL_ZERO_FINDINGS_POLICY_SOURCE)).toBe(true);
 const paths=x.contract.recipe.preparation.files.map(f=>f.path);
 const described=await describeNonrootControlPreparation(x.context,x.job);
 expect(described).toEqual(x.contract.recipe.preparation);
 for(const path of [ACTION,ENTRY,TOOLCHAIN,BUILDER,'.github/actions/control-composition/index.mjs','scripts/lib/production-control-composition-main.mjs','scripts/lib/production-control-composition-controller.mjs','scripts/verify-ci-smoke-isolation.mjs','scripts/lib/application-region.mjs'])expect(paths).toContain(path);
 const result=await verifyNonrootControlSource(x.contract,x.options());
 expect(result.tree).toBe(x.context.tree);expect(result.preparationHash).toBe(hash(x.contract.recipe.preparation));
},60000);

it.each([ACTION,ENTRY,'scripts/lib/application-region.mjs'])('rejects omitted current-source evidence %s even after rehashing the declared closure',async path=>{
 const x=await fixture(),c=x.contract.recipe.preparation;c.files=c.files.filter(f=>f.path!==path);c.closureHash=hash(c.files);
 await expect(verifyNonrootControlSource(x.contract,x.options())).rejects.toThrow();
},60000);

it.each([
 ['unknown-action','ControlCompositionActionStep'],['aliased-action','ControlCompositionActionStep'],
 ['action-definition','ControlCompositionActionRuntime'],['extra-input','ControlCompositionActionStep'],['entry-eval','ControlCompositionToolchainSource'],
])('rejects %s in the full current workflow with fresh tree/file/contract hashes',async(defect,code)=>{
 const x=await fixture({defect});await expect(verifyNonrootControlSource(x.contract,x.options())).rejects.toThrow(code);
},60000);
