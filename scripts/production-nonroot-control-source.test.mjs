import {it,expect,afterEach} from 'vitest';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {execFileSync} from 'node:child_process';
import {nonrootDeploymentFixture} from './production-nonroot-provenance.fixture.mjs';
import {createControlSourceContext,readControlSourceFile,describeControlCopyClosure} from './lib/production-control-source.mjs';
import {verifyNonrootControlSource} from './lib/production-nonroot-provenance.mjs';
import {nonrootHash as hash} from './lib/production-nonroot-contracts.mjs';

const directories=[];afterEach(()=>{for(const path of directories.splice(0))rmSync(path,{recursive:true,force:true});});
async function fixture({prepare='import "./prepare-helper.mjs";',omitHelper=false}={}){
 const f=await nonrootDeploymentFixture(),contract=structuredClone(f.contract),directory=mkdtempSync(join(tmpdir(),'nonroot-source-contract-'));directories.push(directory);
 const git=(args,input)=>execFileSync('git',args,{cwd:directory,input,encoding:'utf8',stdio:['pipe','pipe','pipe']}).trim();git(['init','--quiet']);
 const job=structuredClone(f.job);job.steps.unshift({name:'Prepare',run:'node scripts/prepare.mjs'});
 const source=new Map([
  ['.github/workflows/infra-ci.yml',JSON.stringify({jobs:{'build-image-transition-control':job}})],
  ['docker/bootstrap/Dockerfile','FROM node:24-alpine\nCOPY docker/bootstrap/nonroot-*.mjs /bootstrap/\n'],
  ['.dockerignore','node_modules\n'],['docker/bootstrap/Dockerfile.dockerignore','**\n!docker/\n!docker/bootstrap/\n!docker/bootstrap/*.mjs\n'],
  ['docker/bootstrap/nonroot-dispatch.mjs','import "./nonroot-identity.mjs"; export const dispatcher=1;'],
  ['docker/bootstrap/nonroot-identity.mjs','import {createHash} from "node:crypto"; export const identity=1;'],
  ['scripts/prepare.mjs',prepare],['scripts/prepare-helper.mjs','export const helper=1;'],['README.md','unrelated complete-tree entry'],
 ]);
 const blobs=new Map(),entries=[];
 for(const [path,text]of source){const raw=Buffer.from(text),oid=git(['hash-object','-w','--stdin'],raw);blobs.set(oid,raw);entries.push({path,mode:'100644',type:'blob',oid});git(['update-index','--add','--cacheinfo','100644',oid,path]);f.bytes(raw);}
 const tree=git(['write-tree']),sourceContext=createControlSourceContext({tree,entries},async oid=>blobs.get(oid));
 const closure=async paths=>{const files=[];for(const path of paths.sort())files.push((await readControlSourceFile(sourceContext,path)).file);return {version:1,kind:'git-file-closure',tree,files,closureHash:hash(files)};};
 contract.candidate.tree=tree;contract.workflow.sourceFile=(await readControlSourceFile(sourceContext,contract.workflow.path)).file;contract.workflow.jobSource=f.bytes(JSON.stringify(job));
 contract.recipe.dockerfile=(await readControlSourceFile(sourceContext,'docker/bootstrap/Dockerfile')).file;contract.recipe.context=await describeControlCopyClosure(sourceContext);
 contract.recipe.preparation=await closure(omitHelper?['scripts/prepare.mjs']:['scripts/prepare.mjs','scripts/prepare-helper.mjs']);
 contract.recipe.ignoreFiles=f.json(await Promise.all(['.dockerignore','docker/bootstrap/Dockerfile.dockerignore'].map(async p=>(await readControlSourceFile(sourceContext,p)).file)));
 contract.guardSource=await closure(['docker/bootstrap/nonroot-dispatch.mjs','docker/bootstrap/nonroot-identity.mjs']);contract.guardImportPolicy.guardSource=contract.guardSource;
 return {f,contract,sourceContext,options:()=>({...f.options(),expected:{sourceContext}})};
}
it('binds actual Git membership, complete COPY/static preparation/guard closures and both ignore files',async()=>{
 const x=await fixture(),r=await verifyNonrootControlSource(x.contract,x.options());expect(r.tree).toBe(x.sourceContext.tree);expect(r.copyClosureHash).toBe(hash(x.contract.recipe.context));expect(r).not.toHaveProperty('authorized');
});
for(const prepare of ['import {createRequire} from "node:module"; const load=createRequire(import.meta.url); load("./prepare-helper.mjs");','const name="./prepare-helper.mjs"; await import(name);','eval("import(\\"./prepare-helper.mjs\\")");'])it('holds unsupported dynamic/indirect preparation instead of accepting an incomplete closure',async()=>{
 const x=await fixture({prepare,omitHelper:true});await expect(verifyNonrootControlSource(x.contract,x.options())).rejects.toThrow();
});
for(const defect of ['serialized-context','wrong-tree','omitted-copy','invented-file','omitted-preparation','omitted-guard','omitted-ignore','false-ignore-absence','wrong-job-projection'])it('rejects source '+defect+' even with recomputed reference hashes',async()=>{
 const x=await fixture(),c=x.contract;let options=x.options();
 if(defect==='serialized-context')options.expected.sourceContext=structuredClone(x.sourceContext);
 if(defect==='wrong-tree')c.candidate.tree='f'.repeat(40);
 if(defect==='omitted-copy'){c.recipe.context=structuredClone(c.recipe.context);c.recipe.context.files.pop();c.recipe.context.closureHash=hash(c.recipe.context.files);}
 if(defect==='invented-file'){const blob=x.f.bytes('invented');c.recipe.preparation.files.push({path:'scripts/not-in-tree.mjs',gitMode:'100644',sha256:blob.sha256,bytes:blob.bytesLength,blob});c.recipe.preparation.closureHash=hash(c.recipe.preparation.files);}
 if(defect==='omitted-preparation'){c.recipe.preparation.files.pop();c.recipe.preparation.closureHash=hash(c.recipe.preparation.files);}
 if(defect==='omitted-guard'){c.guardSource.files.pop();c.guardSource.closureHash=hash(c.guardSource.files);c.guardImportPolicy.guardSource=c.guardSource;}
 if(defect==='omitted-ignore')c.recipe.ignoreFiles=x.f.json([]);
 if(defect==='false-ignore-absence'){const rows=structuredClone(x.f.a.value(c.recipe.ignoreFiles));rows[1]={path:'docker/bootstrap/Dockerfile.dockerignore',absent:true};c.recipe.ignoreFiles=x.f.json(rows);}
 if(defect==='wrong-job-projection')c.workflow.jobSource=x.f.bytes(JSON.stringify({name:'different',steps:[]}));
 if(defect!=='serialized-context')options=x.options();
 await expect(verifyNonrootControlSource(c,options)).rejects.toThrow();
});
