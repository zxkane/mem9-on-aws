import {describe,it,expect,afterEach} from 'vitest';
import {execFileSync} from 'node:child_process';
import {mkdtempSync,rmSync,readFileSync,writeFileSync,mkdirSync,symlinkSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,dirname} from 'node:path';
import {createControlSourceContext,readControlSourceFile,describeControlCopyClosure,verifyControlSourceClosure,verifyControlBuildCheckout} from './lib/production-control-source.mjs';

const directories=[];afterEach(()=>{for(const directory of directories.splice(0))rmSync(directory,{recursive:true,force:true});});
function fixture(){
 const directory=mkdtempSync(join(tmpdir(),'mem9-control-tree-'));directories.push(directory);
 const git=(args,input)=>execFileSync('git',args,{cwd:directory,input,encoding:'utf8',stdio:['pipe','pipe','pipe']}).trim();git(['init','--quiet']);
 const data=new Map(),rows=[];
 const file=(path,text,mode='100644')=>{const raw=Buffer.from(text),oid=git(['hash-object','-w','--stdin'],raw);data.set(oid,raw);rows.push({path,mode,type:'blob',oid});return oid;};
 const docker=file('docker/bootstrap/Dockerfile','FROM node:24-alpine\nCOPY scripts/main.mjs scripts/helper*.mjs /app/\n');
 const ignore=file('docker/bootstrap/Dockerfile.dockerignore',readFileSync(new URL('../docker/bootstrap/Dockerfile.dockerignore',import.meta.url)));
 const main=file('scripts/main.mjs','export const main = true;\n'),helper=file('scripts/helper.mjs','export const helper = true;\n');
 const readme=file('README.md','synthetic\n'),samePrefix=file('scripts.txt','git tree sorting fixture\n');
 const bootstrap=git(['mktree'],`100644 blob ${docker}\tDockerfile\n100644 blob ${ignore}\tDockerfile.dockerignore\n`),dockerTree=git(['mktree'],`040000 tree ${bootstrap}\tbootstrap\n`);
 const scripts=git(['mktree'],`100644 blob ${helper}\thelper.mjs\n100644 blob ${main}\tmain.mjs\n`);
 const tree=git(['mktree'],`100644 blob ${readme}\tREADME.md\n040000 tree ${dockerTree}\tdocker\n100644 blob ${samePrefix}\tscripts.txt\n040000 tree ${scripts}\tscripts\n`);
 for(const row of rows){const path=join(directory,row.path);mkdirSync(dirname(path),{recursive:true});writeFileSync(path,data.get(row.oid),{mode:0o644});}
 return {directory,tree,entries:rows,data,readBlob:async oid=>data.get(oid)};
}
describe('complete Git membership and CONTROL COPY closure',()=>{
 it('reconstructs the actual Git tree including directory sorting and verifies every copied blob',async()=>{
  const f=fixture(),context=createControlSourceContext({tree:f.tree,entries:f.entries},f.readBlob),closure=await describeControlCopyClosure(context);
  expect(closure.files.map(file=>file.path)).toEqual(['scripts/helper.mjs','scripts/main.mjs']);
  expect(await verifyControlSourceClosure(context,closure,{copyContext:true})).toEqual(closure);
  expect((await readControlSourceFile(context,'README.md')).bytes.toString()).toBe('synthetic\n');
 });
 it('rejects a missing unrelated tree entry, altered mode, duplicate path or foreign tree',()=>{
  for(const change of [f=>f.entries.pop(),f=>{f.entries[0].mode='100755';},f=>f.entries.push(f.entries[0]),f=>{f.tree='f'.repeat(40);}]){
   const f=fixture();change(f);expect(()=>createControlSourceContext({tree:f.tree,entries:f.entries},f.readBlob)).toThrow('ControlSourceUnverified');
  }
 });
 it('rejects substituted bytes even if a caller supplies a valid-looking SHA256 reference',async()=>{
  const f=fixture(),context=createControlSourceContext({tree:f.tree,entries:f.entries},f.readBlob),entry=f.entries.find(row=>row.path==='scripts/main.mjs');f.data.set(entry.oid,Buffer.from('changed'));
  await expect(readControlSourceFile(context,entry.path)).rejects.toThrow('ControlSourceUnverified');
 });
 it('rejects omitted COPY matches and serialized contexts',async()=>{
  const f=fixture(),context=createControlSourceContext({tree:f.tree,entries:f.entries},f.readBlob),closure=await describeControlCopyClosure(context);
  const {nonrootHash}=await import('./lib/production-nonroot-contracts.mjs');const files=closure.files.slice(1);
  await expect(verifyControlSourceClosure(context,{...closure,files,closureHash:nonrootHash(files)},{copyContext:true})).rejects.toThrow('ControlSourceUnverified');
  await expect(readControlSourceFile(JSON.parse(JSON.stringify(context)),'README.md')).rejects.toThrow('ControlSourceUnverified');
 });
 it('checks actual working bytes and ignores machine-local state without reading it',async()=>{
  const f=fixture(),context=createControlSourceContext({tree:f.tree,entries:f.entries},f.readBlob);
  writeFileSync(join(f.directory,'.env'),'synthetic-private',{mode:0o600});writeFileSync(join(f.directory,'scripts/helper.local.mjs'),'synthetic-private',{mode:0o600});
  expect((await verifyControlBuildCheckout(context,f.directory)).tree).toBe(f.tree);
  writeFileSync(join(f.directory,'scripts/main.mjs'),'changed');await expect(verifyControlBuildCheckout(context,f.directory)).rejects.toThrow('ControlSourceUnverified');
 });
 it('rejects untracked COPY matches and symlinked source parents',async()=>{
  const f=fixture(),context=createControlSourceContext({tree:f.tree,entries:f.entries},f.readBlob);
  writeFileSync(join(f.directory,'scripts/helper-extra.mjs'),'unreviewed');await expect(verifyControlBuildCheckout(context,f.directory)).rejects.toThrow('ControlSourceUnverified');
  rmSync(join(f.directory,'scripts'),{recursive:true});mkdirSync(join(f.directory,'other'));symlinkSync('other',join(f.directory,'scripts'));
  await expect(verifyControlBuildCheckout(context,f.directory)).rejects.toThrow('ControlSourceUnverified');
 });
});
