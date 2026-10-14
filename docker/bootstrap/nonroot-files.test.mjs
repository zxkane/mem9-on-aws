import {describe,it,expect} from 'vitest';
import {readFileSync} from 'node:fs';
import {parse} from '@babel/parser';
import {inspectGuardManifest} from './nonroot-files.mjs';

const file=path=>({path,realPath:path,sha256:'a'.repeat(64),size:1});
const manifest=()=>({version:1,kind:'guarded-control-files',files:['nonroot-dispatch.mjs','nonroot-files.mjs','nonroot-identity.mjs'].map(name=>file('/bootstrap/'+name)),node:file('/usr/local/bin/node')});

describe('guard immutable manifest',()=>{
 it('requires exact canonical inventory and the absolute Node binary',()=>{
  expect(inspectGuardManifest(JSON.stringify(manifest())).files).toHaveLength(3);
 });
 it.each([
  value=>{value.files.push({...value.files[0]});},
  value=>{value.files.reverse();},
  value=>{value.files[0].path='/tmp/untrusted.mjs';},
  value=>{value.files[0].realPath='/tmp/untrusted.mjs';},
  value=>{value.node.path='node';},
  value=>{value.files[0].extra=true;},
  value=>{value.files[0].sha256='x'.repeat(64);},
  value=>{value.files[0].size=-1;},
  value=>{value.files[0].size=134217729;},
  value=>{value.files.pop();},
 ])('rejects a changed inventory before file access',mutate=>{
  const value=manifest();mutate(value);expect(()=>inspectGuardManifest(JSON.stringify(value))).toThrow('NonrootArtifact');
 });
});

describe('guard module import boundary',()=>{
 it('has no package, SDK, database or network static import in its entire authored closure',()=>{
  const allowed=new Set(['node:fs','node:crypto','node:buffer','node:path','node:process','./nonroot-identity.mjs','./nonroot-files.mjs']);
  for(const name of ['nonroot-dispatch.mjs','nonroot-files.mjs','nonroot-identity.mjs']){
   const ast=parse(readFileSync(new URL('./'+name,import.meta.url),'utf8'),{sourceType:'module'});
   for(const item of ast.program.body)if(item.type==='ImportDeclaration')expect(allowed.has(item.source.value),name+': '+item.source.value).toBe(true);
  }
 });
});
