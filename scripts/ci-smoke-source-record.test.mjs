import {describe,it,expect,beforeAll,afterAll} from 'vitest';
import {execFileSync} from 'node:child_process';
import {mkdtempSync,readFileSync,lstatSync,rmSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {createHash} from 'node:crypto';
import {stringify,parse} from 'yaml';
import {createCiSmokeIsolationRecord} from './lib/ci-smoke-source-record.mjs';
import {createControlSourceContext,controlSourceEntries} from './lib/production-control-source.mjs';
import {CI_SMOKE_POLICY} from './lib/ci-smoke-policy.mjs';
import {ciSmokeJobDefinition} from './lib/ci-smoke-job.mjs';
import {buildCiSmokePromotionRoutes,buildCiSmokeImageJob,buildCiSmokeSourceJobs,verifyCiSmokeIsolationSource,isolateDataRecipe} from './lib/ci-smoke-isolation.mjs';
import {nonrootHash as hash} from './lib/production-nonroot-contracts.mjs';
import {NONROOT_SMOKE_DATABASE_IMAGE} from './run-mnemo-nonroot-smoke.mjs';

const repository=new URL('..',import.meta.url),sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const databaseImage=NONROOT_SMOKE_DATABASE_IMAGE.qualifiedImage;
const workflowPath='.github/workflows/infra-ci.yml';
let directory,origin,candidate,baseline,candidateFiles;
const objectIds=new Map(),blobBytes=new Map();
const fileModes=new Map();
const git=(args,input)=>execFileSync('git',['-c','core.hooksPath=/dev/null',...args],{cwd:directory,input,maxBuffer:32*1024*1024,stdio:['pipe','pipe','pipe']});

// These are real Git objects in an isolated temporary repository. A supplied
// tree label or mocked source-verifier success is never used by the tests.
function snapshot(files){
  git(['read-tree','--empty']);
  const index=[];
  for(const [path,bytes]of files){
    const digest=sha(bytes);let oid=objectIds.get(digest);
    if(!oid){oid=git(['hash-object','-w','--stdin'],bytes).toString().trim();objectIds.set(digest,oid);blobBytes.set(oid,Buffer.from(bytes));}
    index.push((fileModes.get(path)??'100644')+' '+oid+'\t'+path+'\n');
  }
  git(['update-index','--index-info'],index.join(''));
  const tree=git(['write-tree']).toString().trim();
  const revision=git(['-c','user.name=Fixture','-c','user.email=user@example.com','commit-tree',tree,'-m','Synthetic smoke source fixture']).toString().trim();
  const entries=git(['ls-tree','-rz',tree]).toString().split('\0').filter(Boolean).map(row=>{
    const match=/^(\d+) (\w+) ([a-f0-9]{40})\t(.+)$/.exec(row);
    return {mode:match[1],type:match[2],oid:match[3],path:match[4]};
  });
  return {revision,context:createControlSourceContext({tree,entries},async oid=>blobBytes.get(oid))};
}
function variant(change){const files=new Map(candidateFiles);change(files);return snapshot(files);}
const input=selected=>({origin,candidate:selected??candidate,baseline,databaseImage});
const changedWorkflow=(files,change)=>{const workflow=parse(files.get(workflowPath).toString());change(workflow);files.set(workflowPath,Buffer.from(stringify(workflow)));};

beforeAll(()=>{
  directory=mkdtempSync(join(tmpdir(),'mem9-smoke-record-test-'));git(['init','--quiet']);
  const fixed=JSON.parse(readFileSync(new URL('./fixtures/ci-smoke-baseline.json',import.meta.url))),files=new Map();
  // Real checkout implementation bytes, including the actual CLI, proof and
  // SST loader. Only the explicitly synthetic DATA/workflow fixtures below and
  // exact reviewed recovery preimages differ from the checkout snapshot.
  const names=execFileSync('git',['ls-files','--cached','--others','--exclude-standard','-z'],{cwd:repository,maxBuffer:32*1024*1024}).toString().split('\0').filter(Boolean);
  for(const name of new Set(names)){
    if(name.includes('.local.')||name==='.local.json'||name==='.env')continue;
    const path=new URL(name,repository),stat=lstatSync(path);if(!stat.isFile())continue;
    files.set(name,readFileSync(path));fileModes.set(name,stat.mode&0o111?'100755':'100644');
  }
  // Recovery preimages remain exact. During parallel implementation a reviewed
  // pin may still refer to HEAD's immutable bytes; never rewrite policy pins to
  // make the fixture pass. Once reviewed pins advance, checkout bytes are used.
  const recovery=[...new Map(CI_SMOKE_POLICY.rows.filter(row=>row.rule.kind==='safe-recovery').flatMap(row=>row.rule.entryFiles).map(pin=>[pin.path,pin])).values()];
  for(const pin of recovery){
    let bytes=readFileSync(new URL(pin.path,repository));
    if(sha(bytes)!==pin.sha256||bytes.length!==pin.bytes)bytes=execFileSync('git',['show','HEAD:'+pin.path],{cwd:repository,maxBuffer:16*1024*1024});
    if(sha(bytes)!==pin.sha256||bytes.length!==pin.bytes)throw Error('ReviewedRecoveryFixtureBytesMissing:'+pin.path);
    files.set(pin.path,bytes);
  }
  const workflow={jobs:{...fixed.workflow.jobs}},steps=[
    {uses:'docker/setup-qemu-action@'+'a'.repeat(40)},
    {uses:'docker/setup-buildx-action@'+'b'.repeat(40)},
  ];
  for(const name of ['mnemo-server','qwen3-embed','llm-proxy']){
    files.set('docker/'+name+'/Dockerfile',Buffer.from('FROM node:24-alpine AS runtime\nCOPY docker/'+name+'/fixture.mjs /app/fixture.mjs\n'));
    files.set('docker/'+name+'/fixture.mjs',Buffer.from('export const fixture = true;\n'));
    steps.push({name:name==='mnemo-server'?'Build & push mnemo-server (arm64)':'Build '+name,uses:'docker/build-push-action@'+'c'.repeat(40),with:{context:'.',file:'docker/'+name+'/Dockerfile',platforms:'linux/arm64',pull:true,'no-cache-filters':name==='mnemo-server'?'builder,runtime':'runtime'}});
  }
  steps.push({name:'Smoke test mnemo-server EMF framing (non-TTY)',if:"steps.gate.outputs.skip != 'true'",run:'bash scripts/run-mnemo-emf-smoke.sh'});
  workflow.jobs['build-and-push-image']={if:fixed.workflow.jobs['build-and-push-image'].if,'runs-on':ciSmokeJobDefinition()['runs-on'],outputs:{},steps};
  files.set(workflowPath,Buffer.from(stringify(workflow)));
  for(const [path,action]of Object.entries(fixed.actions)){
    // Preserve exact reviewed bytes for unmodified recovery/cleanup actions.
    if(!recovery.some(pin=>pin.path===path))files.set(path,Buffer.from(stringify(action)));
  }
  origin=snapshot(files);baseline=origin;
  const promoted=buildCiSmokePromotionRoutes({workflow,actions:fixed.actions});
  Object.assign(workflow.jobs,promoted.jobs,buildCiSmokeSourceJobs(workflow));workflow.jobs['mnemo-nonroot-smoke']=ciSmokeJobDefinition();
  workflow.jobs['build-and-push-image']=buildCiSmokeImageJob(workflow);
  files.set(workflowPath,Buffer.from(stringify(workflow)));
  files.set('.github/actions/runtime-cutover/action.yml',Buffer.from(stringify(promoted.actions['.github/actions/runtime-cutover/action.yml'])));
  candidateFiles=files;candidate=snapshot(files);
},30000);
afterAll(()=>{if(directory)rmSync(directory,{recursive:true,force:true});});

describe('Git-backed CI smoke source record producer',()=>{
  it('builds a complete record and passes the actual full source verifier',async()=>{
    const result=await createCiSmokeIsolationRecord(input());
    expect(Object.keys(result).sort()).toEqual(['candidateRecipe','isolation','originRecipe']);
    expect(result.candidateRecipe).toEqual(isolateDataRecipe(result.originRecipe));
    expect(result.isolation.candidate).toEqual({revision:candidate.revision,tree:git(['rev-parse',candidate.revision+'^{tree}']).toString().trim(),recipeHash:hash(result.candidateRecipe)});
    expect(result.isolation.promotion.routes.map(route=>route.job)).toEqual(['deploy-preview','deploy-prod','runtime-cutover-prod','runtime-cutover-preview']);
    expect(result.isolation.promotion.preparationValidators.some(pin=>pin.path==='scripts/lib/ci-smoke-source-record.mjs')).toBe(true);
    const entry='.github/actions/ci-smoke-gate/index.mjs';
    expect(result.isolation.promotion.preparationValidators.find(pin=>pin.path===entry)?.sha256).toBe(sha(candidateFiles.get(entry)));
    for(const route of result.isolation.promotion.routes){
      expect(route.localActions.find(pin=>pin.path===entry)?.sha256).toBe(sha(candidateFiles.get(entry)));
      expect(route.localActions.some(pin=>pin.path==='.github/actions/ci-smoke-gate/action.yml')).toBe(true);
    }
    const verified=await verifyCiSmokeIsolationSource(result.isolation,{originContext:origin.context,candidateContext:candidate.context,baselineContext:baseline.context,...result});
    expect(verified.kind).toBe('verified-ci-smoke-source');expect(verified.isolationHash).toBe(hash(result.isolation));
    expect(result).not.toHaveProperty('sourcePassed');
  },30000);
  it('requires authentic opaque contexts and a closed input before reading blobs',async()=>{
    for(const value of [{...input(),sourcePassed:true},{...input(),databaseImage:'pgvector/pgvector:pg17'},
      {...input(),candidate:{revision:candidate.revision,context:{...candidate.context}}},
      {...input(),origin:{...origin,approved:true}}, {...input(),baseline:{...baseline,revision:'main'}}]){
      await expect(createCiSmokeIsolationRecord(value)).rejects.toThrow();
    }
  });
  it('rejects a well-formed database digest that differs from the actual producer source',async()=>{
    await expect(createCiSmokeIsolationRecord({...input(),databaseImage:'pgvector/pgvector@sha256:'+'a'.repeat(64)})).rejects.toThrow('CiSmokeDatabaseSource');
  });
  it.each(['scripts/run-mnemo-nonroot-smoke.sh','scripts/verify-ci-smoke-isolation.mjs','scripts/lib/mnemo-nonroot-smoke-helper.mjs','.github/actions/ci-smoke-gate/action.yml','.github/actions/ci-smoke-gate/index.mjs'])('rejects missing closure file %s',async path=>{
    await expect(createCiSmokeIsolationRecord(input(variant(files=>files.delete(path))))).rejects.toThrow();
  },30000);
  it.each(['docker/llm-proxy/fixture.mjs','scripts/run-mnemo-health-smoke.sh'])('rejects changed DATA/preparation bytes %s',async path=>{
    const context=variant(files=>files.set(path,Buffer.concat([files.get(path),Buffer.from('\n# changed fixture bytes\n')])));
    await expect(createCiSmokeIsolationRecord(input(context))).rejects.toThrow('CiSmokeRecipeChanged');
  },30000);
  it.each(['scripts/lib/production-image-deployment-bundle.mjs','scripts/lib/nonroot-preview-source.mjs'])('rejects recovery-source drift in %s instead of refreshing its reviewed pin',async p=>{
    const context=variant(files=>{files.set(p,Buffer.concat([files.get(p),Buffer.from('\n// changed recovery source\n')]));});
    await expect(createCiSmokeIsolationRecord(input(context))).rejects.toThrow('CiSmokeFileChanged');
  },30000);
  it('rejects a missing route guard and a substituted smoke job',async()=>{
    for(const change of [workflow=>{workflow.jobs['deploy-prod'].steps=workflow.jobs['deploy-prod'].steps.filter(step=>!step.id?.startsWith('ci_smoke_guard_'));},
      workflow=>{workflow.jobs['mnemo-nonroot-smoke'].steps=[{run:'echo synthetic-unreviewed'}];}]){
      const context=variant(files=>changedWorkflow(files,change));
      await expect(createCiSmokeIsolationRecord(input(context))).rejects.toThrow();
    }
  },30000);
  it('rejects blob substitution even when the original tree entries are retained',async()=>{
    const entries=controlSourceEntries(candidate.context);
    const context=createControlSourceContext({tree:candidate.context.tree,entries},async()=>Buffer.from('unrelated bytes'));
    await expect(createCiSmokeIsolationRecord(input({revision:candidate.revision,context}))).rejects.toThrow('ControlSourceUnverified');
  });
  it('rejects computed imports rather than hiding them from the closure',async()=>{
    const context=variant(files=>{const path='scripts/lib/mnemo-nonroot-smoke-helper.mjs';files.set(path,Buffer.concat([files.get(path),Buffer.from('\nconst selected = process.env.UNTRUSTED_MODULE; await import(selected);\n')]));});
    await expect(createCiSmokeIsolationRecord(input(context))).rejects.toThrow('CiSmokeDynamicImport');
  });
  it('pins the actual Node entry and its transitive imports instead of trusting only action YAML',async()=>{
    const entry='.github/actions/ci-smoke-gate/index.mjs',leaf='.github/actions/ci-smoke-gate/synthetic-leaf.mjs';
    const selected=variant(files=>{
      files.set(entry,Buffer.concat([files.get(entry),Buffer.from("\nimport './synthetic-leaf.mjs';\n")]));
      files.set(leaf,Buffer.from('export const synthetic = true;\n'));
    });
    const result=await createCiSmokeIsolationRecord(input(selected));
    expect(result.isolation.promotion.preparationValidators.some(pin=>pin.path===leaf)).toBe(true);
    const changed=variant(files=>files.set(entry,Buffer.concat([files.get(entry),Buffer.from('\n// different actual source\n')])));
    const rebound=structuredClone(result.isolation);rebound.candidate={...rebound.candidate,revision:changed.revision,tree:changed.context.tree};
    await expect(verifyCiSmokeIsolationSource(rebound,{originContext:origin.context,candidateContext:changed.context,baselineContext:baseline.context,...result})).rejects.toThrow('CiSmokeRoutePinCoverage');
  },30000);
  it('rejects dynamic module selection in the new Node entry',async()=>{
    const selected=variant(files=>{const p='.github/actions/ci-smoke-gate/index.mjs';files.set(p,Buffer.concat([files.get(p),Buffer.from('\nawait import(process.env.UNREVIEWED_MODULE);\n')]));});
    await expect(createCiSmokeIsolationRecord(input(selected))).rejects.toThrow('CiSmokeDynamicImport');
  },30000);
});
