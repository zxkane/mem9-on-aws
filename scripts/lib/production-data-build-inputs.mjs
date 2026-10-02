import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {createHash} from 'node:crypto';
import {posix} from 'node:path';
import {parseDocument} from 'yaml';
import {DATA_COMPONENTS} from './production-data-release.mjs';
import {canaryEvidenceHash as hash} from './production-canary-verification.mjs';

const execute=promisify(execFile);
const fail=()=>{throw Error('DataBuildInputsUnverified');};
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const safePath=path=>typeof path==='string'&&/^[A-Za-z0-9_./*-]+$/.test(path)&&!path.startsWith('/')&&!path.split('/').includes('..');

// A deliberately bounded parser for this repository's declared recipes. New
// Docker syntax must be reviewed here before it can authorize retention.
export function dataCopySources(dockerfile){
  const sources=new Set();
  const stages=new Set();
  for(const line of dockerfile.split(/\r?\n/)){
    const text=line.trim();
    if(!text.startsWith('#')&&/--mount(?:=|\s)/.test(text))fail();
    const stage=text.match(/^FROM\s+.+\s+AS\s+([a-z][a-z0-9-]*)$/);if(stage)stages.add(stage[1]);
    if(!/^(?:COPY|ADD)\b/i.test(text))continue;
    const words=text.split(/\s+/);
    if(words.shift()!=='COPY'||words.length<2||/[\\\[\]"'$`]/.test(text))fail();
    if(words[0]?.startsWith('--from=')){
      if(words.length!==3||!/^--from=[a-z][a-z0-9-]*$/.test(words[0])||!stages.has(words[0].slice(7)))fail();
      continue;
    }
    if(words.some(word=>word.startsWith('--')))fail();
    words.pop();
    for(const source of words){if(!safePath(source)||source==='.'||source==='./')fail();sources.add(source);}
  }
  if(!sources.size)fail();return [...sources].sort();
}

/** Declared source recipe only; it does NOT claim reproducible remote resolution. */
export async function describeDataBuildInputs(entries,readBlob){
  if(!Array.isArray(entries)||!entries.length||entries.length>20000||new Set(entries.map(e=>e.path)).size!==entries.length)fail();
  const files=new Map(entries.map(entry=>[entry.path,entry]));
  const file=async(path,optional=false)=>{
    const entry=files.get(path);
    if(!entry){if(optional)return null;fail();}
    if(entry.type!=='blob'||!['100644','100755'].includes(entry.mode)||!/^[a-f0-9]{40}$/.test(entry.oid??''))fail();
    const bytes=await readBlob(entry.oid);if(!Buffer.isBuffer(bytes)||bytes.length>16*1024*1024)fail();
    return {path,mode:entry.mode,sha256:sha(bytes),bytes};
  };
  const workflow=await file('.github/workflows/infra-ci.yml');
  const doc=parseDocument(workflow.bytes.toString('utf8'),{uniqueKeys:true});if(doc.errors.length)fail();
  const document=doc.toJS(),job=document?.jobs?.['build-and-push-image'];
  if(!job||!Array.isArray(job.steps))fail();
  const builderSteps=job.steps.filter(s=>/^docker\/(setup-buildx-action|setup-qemu-action)@/.test(s?.uses??''));
  if(builderSteps.length!==2)fail();
  const builders=builderSteps.map(s=>({uses:s.uses,with:s.with??{}}));
  const identity=({bytes,...value})=>value;
  const independentFiles=['docker/bootstrap/Dockerfile','docker/canary-fixture/runner.Dockerfile','docker/canary-fixture/database.Dockerfile'];
  const preparationSteps=job.steps.filter(step=>{
    if(!independentFiles.includes(step?.with?.file))return true;
    // These reviewed Docker actions only publish independent images. Local
    // outputs, extra environment or arbitrary preparation commands may change
    // the later data build's context and cannot use this exclusion.
    const options=step.with;
    if(!/^docker\/build-push-action@[a-f0-9]{40}$/.test(step.uses??'')||
      Object.keys(step).some(k=>!['name','id','if','uses','with'].includes(k))||
      Object.keys(options).some(k=>!['context','file','pull','no-cache-filters','platforms','push','tags','cache-from','cache-to','build-args'].includes(k))||
      options.context!=='.'||options.pull!==true||options.platforms!=='linux/arm64'||options['no-cache-filters']!=='runtime'||
      options['build-args']!==undefined&&!(options.file==='docker/canary-fixture/runner.Dockerfile'&&
        options['build-args']==='BOOTSTRAP_IMAGE=${{ steps.ecr-login.outputs.registry }}/${{ env.ECR_NS }}/bootstrap@${{ steps.bootstrap.outputs.digest }}'))fail();
    return false;
  });
  const preparationScripts=new Map(),pending=[];
  const discover=(text,origin='.')=>{
    for(const match of text.matchAll(/\bscripts\/[A-Za-z0-9_./-]+\.(?:mjs|js|sh)\b/g))pending.push(match[0]);
    for(const match of text.matchAll(/(?:from\s*|import\s*(?:\(\s*)?)['"](\.[^'"]+)['"]/g))pending.push(posix.normalize(posix.join(posix.dirname(origin),match[1])));
  };
  for(const step of preparationSteps){
    if(step.uses?.startsWith('./'))fail();
    if(typeof step.run==='string')discover(step.run);
  }
  while(pending.length){
    const path=pending.pop();if(preparationScripts.has(path))continue;
    if(!safePath(path)||preparationScripts.size>=100)fail();
    const script=await file(path);preparationScripts.set(path,identity(script));discover(script.bytes.toString('utf8'),path);
  }
  const preparation={workflowEnvironment:document.env??{},jobEnvironment:job.env??{},defaults:job.defaults??{},
    runner:job['runs-on']??null,container:job.container??null,steps:preparationSteps,scripts:[...preparationScripts.values()].sort((a,b)=>a.path.localeCompare(b.path))};
  const components={};
  for(const name of DATA_COMPONENTS){
    const path='docker/'+name+'/Dockerfile',dockerfile=await file(path);
    const steps=job.steps.filter(s=>s?.with?.file===path);
    if(steps.length!==1)fail();const step=steps[0],options=step.with;
    if(!/^docker\/build-push-action@[a-f0-9]{40}$/.test(step.uses??'')||step.env||
      options.context!=='.'||options.platforms!=='linux/arm64'||options.pull!==true||options['no-cache-filters']!==(name==='mnemo-server'?'builder,runtime':'runtime')||
      ['build-args','build-contexts','secrets','secret-envs','secret-files','ssh','target'].some(key=>options[key]!==undefined))fail();
    const paths=new Set();
    for(const source of dataCopySources(dockerfile.bytes.toString('utf8'))){
      const pattern=new RegExp('^'+source.split('*').map(RegExp.escape).join('[^/]*')+'$');
      const matched=entries.filter(e=>source.endsWith('/')?e.path.startsWith(source):pattern.test(e.path));
      if(!matched.length)fail();for(const entry of matched)paths.add(entry.path);
    }
    const context=[];for(const selected of [...paths].sort())context.push(identity(await file(selected)));
    const ignores=[];
    for(const ignore of ['.dockerignore',path+'.dockerignore']){const selected=await file(ignore,true);ignores.push(selected?identity(selected):{path:ignore,absent:true});}
    // Preserve all step inputs, including cache/pull settings. Tags are fixed
    // workflow expressions; no current environment is substituted into a recipe.
    components[name]={dockerfile:identity(dockerfile),context,ignores,build:{uses:step.uses,with:options}};
  }
  return {version:1,kind:'declared-data-build-inputs',platform:'linux/arm64',builders,preparation,components};
}

export async function captureDataBuildInputs({repository=process.cwd(),revision,sourceTree}){
  if(!/^[a-f0-9]{40}$/.test(revision??'')||!/^[a-f0-9]{40}$/.test(sourceTree??''))fail();
  const git=async(args,encoding='utf8')=>(await execute('git',['-C',repository,...args],{encoding,timeout:30000,maxBuffer:32*1024*1024})).stdout;
  if((await git(['rev-parse',revision+'^{tree}'])).trim()!==sourceTree)fail();
  const entries=(await git(['ls-tree','-rz','--full-tree',revision])).split('\0').filter(Boolean).map(line=>{
    const match=line.match(/^([0-9]{6}) (blob|commit) ([a-f0-9]{40})\t(.+)$/);if(!match)fail();
    return {mode:match[1],type:match[2],oid:match[3],path:match[4]};
  });
  const recipe=await describeDataBuildInputs(entries,oid=>git(['cat-file','blob',oid],null));
  return {revision,sourceTree,recipe,hash:hash(recipe)};
}

export function compareDataBuildInputs(previous,current){
  if(!previous?.recipe||!current?.recipe||previous.hash!==hash(previous.recipe)||current.hash!==hash(current.recipe)||previous.hash!==current.hash)throw Error('DataBuildInputsChanged');
  return previous.hash;
}
