import {test,expect} from 'vitest';
import {mkdtemp,writeFile,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {runCompositionNativeTests} from './control-composition-native/gate.mjs';

test('all 76 native composition cases pass with original Node hooks and runtime processes',async()=>{
 const files=['composition','transport','runtime','consumer-contracts','recipe','action-output']
  .map(name=>new URL('./control-composition-native/'+name+'.native.mjs',import.meta.url));
 const result=await runCompositionNativeTests(files,{expectedTests:76});
 expect(result.exitCode).toBe(0);expect(result.passed).toBe(76);
},195000);

test('a native assertion failure rejects the awaited gate after t.after cleanup and later tests',async()=>{
 const directory=await mkdtemp(join(tmpdir(),'composition-node-gate-')),file=join(directory,'failure.native.mjs');
 const cleaned=join(directory,'cleaned'),continued=join(directory,'continued');
 try{
  await writeFile(file,`import test from 'node:test';
import assert from 'node:assert/strict';
import {writeFile} from 'node:fs/promises';
test('intentional gate failure',async t=>{t.after(()=>writeFile(${JSON.stringify(cleaned)},'cleanup',{mode:0o600}));assert.fail('COMPOSITION_NATIVE_GATE_INTENTIONAL_FAILURE');});
test('later native case',()=>writeFile(${JSON.stringify(continued)},'continued',{mode:0o600}));
`,{mode:0o600,flag:'wx'});
  let failure;try{await runCompositionNativeTests([file],{timeoutMs:10000});}catch(error){failure=error;}
  expect(failure?.code).toBe(1);expect(failure?.message).toContain('COMPOSITION_NATIVE_GATE_INTENTIONAL_FAILURE');
  expect(await readFile(cleaned,'utf8')).toBe('cleanup');expect(await readFile(continued,'utf8')).toBe('continued');
 }finally{await rm(directory,{recursive:true,force:true});}
},15000);

test('an empty native file cannot masquerade as the required case inventory',async()=>{
 const directory=await mkdtemp(join(tmpdir(),'composition-node-empty-')),file=join(directory,'empty.native.mjs');
 try{await writeFile(file,'// No native cases.\n',{mode:0o600,flag:'wx'});
  await expect(runCompositionNativeTests([file],{expectedTests:76,timeoutMs:10000})).rejects.toThrow('native case inventory changed');
 }finally{await rm(directory,{recursive:true,force:true});}
},15000);
