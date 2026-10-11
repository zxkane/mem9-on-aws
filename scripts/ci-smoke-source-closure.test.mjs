import {describe,it,expect,afterEach} from 'vitest';
import {execFileSync} from 'node:child_process';
import {mkdtempSync,readFileSync,lstatSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
import {createControlSourceContext} from './lib/production-control-source.mjs';
import {ciSmokeSourceClosure,CI_SMOKE_VALIDATOR_ROOTS,CI_SMOKE_GATE_ENTRY_PATH} from './lib/ci-smoke-isolation.mjs';

const directories=[],repository=new URL('..',import.meta.url);
const loaderPath='scripts/lib/application-region.mjs';
const loader=readFileSync(new URL('./lib/application-region.mjs',import.meta.url),'utf8');
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
afterEach(()=>{for(const path of directories.splice(0))rmSync(path,{recursive:true,force:true});});

function context(files){
  const directory=mkdtempSync(join(tmpdir(),'mem9-source-closure-'));directories.push(directory);
  const git=(args,input)=>execFileSync('git',['-c','core.hooksPath=/dev/null',...args],{cwd:directory,input,maxBuffer:33554432,stdio:['pipe','pipe','pipe']});
  git(['init','--quiet']);const blobs=new Map(),oids=new Map(),index=[];
  for(const [path,value]of Object.entries(files)){
    const bytes=Buffer.from(value.bytes??value),mode=value.mode??'100644',digest=sha(bytes);let oid=oids.get(digest);
    if(!oid){oid=git(['hash-object','-w','--stdin'],bytes).toString().trim();oids.set(digest,oid);blobs.set(oid,bytes);}
    index.push(mode+' '+oid+'\t'+path+'\n');
  }
  git(['update-index','--index-info'],index.join(''));
  const tree=git(['write-tree']).toString().trim();
  const entries=git(['ls-tree','-rz',tree]).toString().split('\0').filter(Boolean).map(line=>{
    const m=/^(\d+) (\w+) ([a-f0-9]{40})\t(.+)$/.exec(line);return {mode:m[1],type:m[2],oid:m[3],path:m[4]};
  });
  return createControlSourceContext({tree,entries},async oid=>blobs.get(oid));
}
function regionFiles(){
  return {[loaderPath]:loader,'sst.config.ts':'export {region} from "./infra/region";\n',
    'infra/region.ts':'export {region} from "./leaf";\n','infra/leaf.ts':'export const region: string = "us-east-1";\n'};
}

describe('fixed SST loader and complete bounded source closure',()=>{
  it('closes the actual checkout CLI, proof and SST source graph without fixture entrypoints',async()=>{
    const paths=execFileSync('git',['ls-files','--cached','--others','--exclude-standard','-z'],{cwd:repository,maxBuffer:33554432}).toString().split('\0').filter(Boolean),files={};
    for(const path of new Set(paths)){
      if(path.includes('.local.')||path==='.local.json'||path==='.env')continue;
      const absolute=new URL(path,repository),stat=lstatSync(absolute);if(!stat.isFile())continue;
      files[path]={bytes:readFileSync(absolute),mode:stat.mode&0o111?'100755':'100644'};
    }
    const closure=await ciSmokeSourceClosure(context(files),CI_SMOKE_VALIDATOR_ROOTS);
    expect(closure.length).toBeGreaterThan(128);
    expect(closure.reduce((total,file)=>total+file.bytes,0)).toBeLessThanOrEqual(33554432);
    for(const path of [CI_SMOKE_GATE_ENTRY_PATH,'scripts/verify-ci-smoke-isolation.mjs','scripts/lib/production-nonroot-proof.mjs',loaderPath,'sst.config.ts','infra/ecs.ts','infra/bootstrap.ts','scripts/workload-permissions-boundary-contract.json']){
      expect(closure.find(file=>file.path===path)?.sha256).toBe(sha(files[path].bytes));
    }
    expect(new Set(closure.map(file=>file.path)).size).toBe(closure.length);
  },30000);
  it('includes the fixed target and all extensionless TypeScript dependencies',async()=>{
    const closure=await ciSmokeSourceClosure(context(regionFiles()),[loaderPath]);
    expect(closure.map(file=>file.path)).toEqual(['infra/leaf.ts','infra/region.ts',loaderPath,'sst.config.ts']);
  });
  it('allows formatting trivia without masking executable loader changes',async()=>{
    const files=regionFiles();files[loaderPath]='// harmless formatting comment\n'+loader;
    expect((await ciSmokeSourceClosure(context(files),[loaderPath])).length).toBe(4);
  });
  it.each([
    value=>value.replace('../../sst.config.ts','../../other.config.ts'),
    value=>value.replace('import(configUrl.href)','import(process.env.MODULE)'),
    value=>value.replace('app({ stage: "application-region-resolution" })','configModule.default.run()'),
    value=>value+'\nawait import(process.env.EXTRA_MODULE);\n',
  ])('rejects a modified default, import argument, execution path or extra loader',async change=>{
    const files=regionFiles();files[loaderPath]=change(loader);
    await expect(ciSmokeSourceClosure(context(files),[loaderPath])).rejects.toThrow('CiSmokeRegionLoaderShape');
  });
  it('does not extend the exception to a copied loader at another path',async()=>{
    await expect(ciSmokeSourceClosure(context({'other.mjs':loader}),['other.mjs'])).rejects.toThrow('CiSmokeDynamicImport');
  });
  it('includes nested CommonJS source and rejects a missing or computed dependency',async()=>{
    const files={'entry.mjs':"import './bridge.cjs';",'bridge.cjs':"module.exports = require('./leaf.cjs');",'leaf.cjs':'module.exports = 1;'};
    expect((await ciSmokeSourceClosure(context(files),['entry.mjs'])).map(file=>file.path)).toEqual(['bridge.cjs','entry.mjs','leaf.cjs']);
    const missing={...files};delete missing['leaf.cjs'];
    await expect(ciSmokeSourceClosure(context(missing),['entry.mjs'])).rejects.toThrow('CiSmokeClosureMissing');
    await expect(ciSmokeSourceClosure(context({...files,'bridge.cjs':'require(process.env.MODULE);'}),['entry.mjs'])).rejects.toThrow('CiSmokeDynamicImport');
    await expect(ciSmokeSourceClosure(context({'entry.sh':'node scripts/missing.cjs\n'}),['entry.sh'])).rejects.toThrow('CiSmokeClosureMissing');
  });
  it.each(['data:text/javascript,export default 1','file:///unreviewed.mjs','https://example.com/unreviewed.mjs','#unresolved-local-code'])('rejects unaccounted executable source %s',async specifier=>{
    await expect(ciSmokeSourceClosure(context({'entry.mjs':'import '+JSON.stringify(specifier)+';'}),['entry.mjs'])).rejects.toThrow('CiSmokeExternalCode');
  });
  it('rejects missing fixed targets/dependencies and ambiguous extensionless files',async()=>{
    for(const path of ['sst.config.ts','infra/leaf.ts']){
      const files=regionFiles();delete files[path];await expect(ciSmokeSourceClosure(context(files),[loaderPath])).rejects.toThrow('CiSmokeClosureMissing');
    }
    const files=regionFiles();files['infra/leaf.mjs']='export const region="fixture";';
    await expect(ciSmokeSourceClosure(context(files),[loaderPath])).rejects.toThrow('CiSmokeClosureAmbiguous');
  });
  it('admits default calls but rejects config overrides and escaping resolver aliases',async()=>{
    for(const source of [
      "import {resolveApplicationRegion as region} from './scripts/lib/application-region.mjs'; await region();",
      "const {resolveApplicationRegion:region}=await import('./scripts/lib/application-region.mjs'); await region();",
    ])expect((await ciSmokeSourceClosure(context({...regionFiles(),'entry.mjs':source}),['entry.mjs'])).length).toBe(5);
    for(const source of [
      "import {resolveApplicationRegion as region} from './scripts/lib/application-region.mjs'; await region({configPath:'/unreviewed.ts'});",
      "import {resolveApplicationRegion as region} from './scripts/lib/application-region.mjs'; const alias=region;",
      "import {resolveApplicationRegion as region} from './scripts/lib/application-region.mjs'; const alias={run:region};",
      "const {resolveApplicationRegion:region}=await import('./scripts/lib/application-region.mjs'); await region({configPath:'/unreviewed.ts'});",
      "const region=await import('./scripts/lib/application-region.mjs'); await region.resolveApplicationRegion();",
    ])await expect(ciSmokeSourceClosure(context({...regionFiles(),'entry.mjs':source}),['entry.mjs'])).rejects.toThrow('CiSmokeRegionLoaderInvocation');
  });
  it('keeps large authenticated inventories and rejects more than 20,000 roots',async()=>{
    // The existing opaque-context JSON node budget is independently stricter
    // at 20,000 five-node entry records. This layer must not bypass that gate.
    const files=Object.fromEntries(Array.from({length:19999},(_,i)=>['files/'+String(i).padStart(5,'0')+'.txt','x']));
    const source=context(files),roots=Object.keys(files),closure=await ciSmokeSourceClosure(source,roots);
    expect(closure).toHaveLength(19999);
    await expect(ciSmokeSourceClosure(source,[...roots,roots[0],roots[0]])).rejects.toThrow('CiSmokeClosureFileLimit');
  },30000);
  it('accepts exactly 32 MiB and rejects one more byte without truncation',async()=>{
    const raw=Buffer.alloc(16777216,32),source=context({'a.txt':raw,'b.txt':raw,'c.txt':'x'});
    expect((await ciSmokeSourceClosure(source,['a.txt','b.txt'])).reduce((total,file)=>total+file.bytes,0)).toBe(33554432);
    await expect(ciSmokeSourceClosure(source,['a.txt','b.txt','c.txt'])).rejects.toThrow('CiSmokeClosureByteLimit');
  },30000);
});
