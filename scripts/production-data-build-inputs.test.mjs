import {it,expect} from 'vitest';
import {createHash} from 'node:crypto';
import {stringify,parse} from 'yaml';
import {dataCopySources,describeDataBuildInputs,compareDataBuildInputs,captureDataBuildInputs} from './lib/production-data-build-inputs.mjs';
import {canaryEvidenceHash as hash} from './lib/production-canary-verification.mjs';
import {execFileSync} from 'node:child_process';
import {readFileSync} from 'node:fs';
import {isolateDataRecipe,verifyIsolatedDataRecipe} from './lib/ci-smoke-isolation.mjs';

function fixture(){
  const files=new Map(),names=['llm-proxy','mnemo-server','qwen3-embed'];
  const steps=[...['setup-buildx-action','setup-qemu-action'].map(name=>({uses:'docker/'+name+'@'+'a'.repeat(40)}))];
  for(const name of names){
    files.set('docker/'+name+'/Dockerfile','FROM node:24 AS runtime\nCOPY docker/'+name+'/package*.json ./\nCOPY scripts/shared/ /app/\n');
    files.set('docker/'+name+'/package.json','{}');files.set('docker/'+name+'/package-lock.json','{"lock":1}');
    steps.push({uses:'docker/build-push-action@'+'b'.repeat(40),with:{context:'.',file:'docker/'+name+'/Dockerfile',platforms:'linux/arm64',pull:true,'no-cache-filters':name==='mnemo-server'?'builder,runtime':'runtime',tags:'same-declared-expression'}});
  }
  files.set('scripts/shared/code.mjs','export const value=1;');files.set('.github/workflows/infra-ci.yml',stringify({jobs:{'build-and-push-image':{steps}}}));
  const describe=async()=>{
    const bodies=new Map(),entries=[...files].map(([path,text])=>{const bytes=Buffer.from(text),oid=createHash('sha1').update(bytes).digest('hex');bodies.set(oid,bytes);return {path,oid,mode:'100644',type:'blob'};});
    const recipe=await describeDataBuildInputs(entries,async oid=>bodies.get(oid));return {recipe,hash:hash(recipe)};
  };
  return {files,describe};
}
it('binds all matching lockfiles, directory members, Dockerfile bytes and ignore rules',async()=>{
  for(const [path,text]of [['docker/llm-proxy/package-lock.json','{"lock":2}'],['scripts/shared/new.mjs','new'],['.dockerignore','scripts/shared'],['docker/mnemo-server/Dockerfile.dockerignore','ignored']]){
    const f=fixture(),before=await f.describe();f.files.set(path,text);expect(()=>compareDataBuildInputs(before,{...before,hash:'f'.repeat(64)})).toThrow();
    const after=await f.describe();expect(()=>compareDataBuildInputs(before,after)).toThrow('DataBuildInputsChanged');
  }
});
it('does not mistake control source edits for data recipe changes',async()=>{
  const f=fixture(),before=await f.describe();f.files.set('scripts/operator.mjs','new control');expect(compareDataBuildInputs(before,await f.describe())).toBe(before.hash);
});
it('preserves the authenticated benchmark recipe while capacity configuration changes outside DATA',async()=>{
  const f=fixture(),path='docker/mnemo-server/patches/0020-namespace-performance-gates.patch';
  const patch=readFileSync(new URL('../'+path,import.meta.url),'utf8');
  f.files.set(path,patch);
  f.files.set('docker/mnemo-server/Dockerfile',f.files.get('docker/mnemo-server/Dockerfile')+'COPY docker/mnemo-server/patches/ /patches/\n');
  const workflow=parse(f.files.get('.github/workflows/infra-ci.yml')),steps=workflow.jobs['build-and-push-image'].steps;
  const build=steps.find(step=>step.with?.file==='docker/mnemo-server/Dockerfile');
  build.name='Build & push mnemo-server (arm64)';
  const smoke={name:'Smoke test mnemo-server EMF framing (non-TTY)',if:"steps.gate.outputs.skip != 'true'",run:'echo synthetic-smoke'};
  steps.push(smoke);f.files.set('.github/workflows/infra-ci.yml',stringify(workflow));
  const origin=(await f.describe()).recipe;
  // This public source pin is the reviewed 25k test fixture, not a runtime cap.
  // Test-only bytes copied into an image remain part of its exact DATA recipe.
  origin.components['mnemo-server'].context.find(row=>row.path===path).sha256='8696f3ca3ecc244bbfbfb785ff17dba65c4c1414760e21b7437c555b0b6f5944';
  smoke.if=false;build.id='mnemo';f.files.set('.github/workflows/infra-ci.yml',stringify(workflow));
  const current=(await f.describe()).recipe,originHash=hash(origin);
  expect(verifyIsolatedDataRecipe(origin,current,{originHash,candidateHash:hash(current)})).toEqual({originHash,candidateHash:hash(current)});
  expect(current).toEqual(isolateDataRecipe(origin));
  f.files.set('infra/ecs.ts',readFileSync(new URL('../infra/ecs.ts',import.meta.url),'utf8'));
  expect((await f.describe()).recipe).toEqual(current);
  const changed=patch.replace('+const namespaceBenchmarkRows = 25000\n','+const namespaceBenchmarkRows = 30000\n');
  expect(changed).not.toBe(patch);f.files.set(path,changed);
  const altered=(await f.describe()).recipe;
  expect(()=>verifyIsolatedDataRecipe(origin,altered,{originHash,candidateHash:hash(altered)})).toThrow('CiSmokeRecipeChanged');
});
it('keeps a separate prerequisite source-verifier job outside the data build recipe',async()=>{
 const f=fixture(),before=await f.describe(),workflow=parse(f.files.get('.github/workflows/infra-ci.yml'));
 workflow.jobs['verify-production-image-transition']={steps:[{run:'node scripts/verify-image-security-deployment.mjs'}]};
 workflow.jobs['build-and-push-image'].needs=['verify-production-image-transition'];
 workflow.jobs['build-and-push-image'].if="needs.verify-production-image-transition.result == 'success'";
 f.files.set('.github/workflows/infra-ci.yml',stringify(workflow));f.files.set('scripts/verify-image-security-deployment.mjs','throw Error("synthetic source hold");');
 expect(compareDataBuildInputs(before,await f.describe())).toBe(before.hash);
});
it('fingerprints context preparation and its transitive local scripts',async()=>{
  const f=fixture(),before=await f.describe(),workflow=parse(f.files.get('.github/workflows/infra-ci.yml'));
  workflow.jobs['build-and-push-image'].steps.unshift({run:'bash scripts/prepare.sh'});
  f.files.set('.github/workflows/infra-ci.yml',stringify(workflow));f.files.set('scripts/prepare.sh','node scripts/prepare.mjs');f.files.set('scripts/prepare.mjs',"import './helper.mjs';");f.files.set('scripts/helper.mjs','export const value=1;');
  const prepared=await f.describe();expect(()=>compareDataBuildInputs(before,prepared)).toThrow('DataBuildInputsChanged');
  f.files.set('scripts/helper.mjs','export const value=2;');
  const changed=await f.describe();expect(()=>compareDataBuildInputs(prepared,changed)).toThrow('DataBuildInputsChanged');
});
it('rejects unsupported COPY/ADD syntax and missing input coverage',async()=>{
  for(const line of ['ADD https://example.com/x /app/','COPY ["a", "b"]','COPY $SOURCE /app/','COPY --link a b','COPY ../outside /app/','COPY . /app/','COPY a \\','RUN --mount=type=bind,source=. true'])expect(()=>dataCopySources(line)).toThrow();
  expect(()=>dataCopySources('FROM node:24\nCOPY a b\nRUN \\\n  --mount=type=bind,source=other true')).toThrow();
  const f=fixture();f.files.delete('scripts/shared/code.mjs');await expect(f.describe()).rejects.toThrow('DataBuildInputsUnverified');
});
it('captures the committed repository data recipes without executing an image',async()=>{
  const revision=execFileSync('git',['rev-parse','HEAD'],{encoding:'utf8'}).trim(),sourceTree=execFileSync('git',['rev-parse','HEAD^{tree}'],{encoding:'utf8'}).trim();
  const selected=await captureDataBuildInputs({revision,sourceTree});expect(selected.recipe.components['llm-proxy'].context.some(f=>f.path==='scripts/consolidation-worker.mjs')).toBe(true);
  expect(selected.recipe.components['mnemo-server'].context.some(f=>f.path.endsWith('0024-runtime-schema-credentials.patch'))).toBe(true);
});
