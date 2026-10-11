import {test,expect} from 'vitest';
import {mkdtemp,writeFile,readFile,rm,copyFile,chmod,lstat,realpath} from 'node:fs/promises';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {createHash} from 'node:crypto';
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
 const cleaned=join(directory,'cleaned'),continued=join(directory,'continued'),executable=join(directory,'executable');
 try{
  await writeFile(file,`import test from 'node:test';
import assert from 'node:assert/strict';
import {writeFile} from 'node:fs/promises';
await writeFile(${JSON.stringify(executable)},process.execPath,{mode:0o600});
test('intentional gate failure',async t=>{t.after(()=>writeFile(${JSON.stringify(cleaned)},'cleanup',{mode:0o600}));assert.fail('COMPOSITION_NATIVE_GATE_INTENTIONAL_FAILURE');});
test('later native case',()=>writeFile(${JSON.stringify(continued)},'continued',{mode:0o600}));
`,{mode:0o600,flag:'wx'});
  let failure;try{await runCompositionNativeTests([file],{timeoutMs:10000});}catch(error){failure=error;}
  expect(failure?.code).toBe(1);expect(failure?.message).toContain('COMPOSITION_NATIVE_GATE_INTENTIONAL_FAILURE');
  expect(await readFile(cleaned,'utf8')).toBe('cleanup');expect(await readFile(continued,'utf8')).toBe('continued');
  await expect(lstat(await readFile(executable,'utf8'))).rejects.toMatchObject({code:'ENOENT'});
 }finally{await rm(directory,{recursive:true,force:true});}
},15000);

test('an empty native file cannot masquerade as the required case inventory',async()=>{
 const directory=await mkdtemp(join(tmpdir(),'composition-node-empty-')),file=join(directory,'empty.native.mjs');
 try{await writeFile(file,'// No native cases.\n',{mode:0o600,flag:'wx'});
  await expect(runCompositionNativeTests([file],{expectedTests:76,timeoutMs:10000})).rejects.toThrow('native case inventory changed');
 }finally{await rm(directory,{recursive:true,force:true});}
},15000);

const execute=promisify(execFile),sha=b=>createHash('sha256').update(b).digest('hex');
for(const mode of [0o775,0o777])test('native gate owns a byte-identical executable from writable host mode '+mode.toString(8),async()=>{
 const directory=await mkdtemp(join(tmpdir(),'composition-node-host-')),host=join(directory,'node'),file=join(directory,'ownership.native.mjs');
 const observed=join(directory,'observed.json'),launcher=join(directory,'launch.mjs'),gate=new URL('./control-composition-native/gate.mjs',import.meta.url).href;
 const original=await realpath(process.execPath),before=await lstat(original),originalHash=sha(await readFile(original));
 try{
  await copyFile(original,host);await chmod(host,mode);
  await writeFile(file,`import test from 'node:test';
import assert from 'node:assert/strict';
import {lstat,readFile,writeFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
test('real owned executable, never a mode manifest override',async()=>{
 const stat=await lstat(process.execPath),hash=createHash('sha256').update(await readFile(process.execPath)).digest('hex');
 assert.notEqual(process.execPath,${JSON.stringify(host)});assert.equal(stat.mode&0o7777,0o700);assert.equal(stat.nlink,1);assert.equal(stat.uid,process.getuid());
 assert.equal(hash,${JSON.stringify(originalHash)});
 await writeFile(${JSON.stringify(observed)},JSON.stringify({path:process.execPath,hash}),{mode:0o600});
});
`,{mode:0o600,flag:'wx'});
  await writeFile(launcher,`import {runCompositionNativeTests} from ${JSON.stringify(gate)};
const result=await runCompositionNativeTests([${JSON.stringify(file)}],{expectedTests:1,timeoutMs:10000});
if(result.passed!==1)throw Error('missing original child');
`,{mode:0o600,flag:'wx'});
  await execute(host,[launcher],{timeout:15000,maxBuffer:1048576});
  const result=JSON.parse(await readFile(observed,'utf8'));expect(result.hash).toBe(originalHash);
  await expect(lstat(result.path)).rejects.toMatchObject({code:'ENOENT'});
  expect((await lstat(host)).mode&0o7777).toBe(mode);expect(sha(await readFile(host))).toBe(originalHash);
  const after=await lstat(original);for(const key of ['dev','ino','mode','nlink','size','mtimeMs','ctimeMs'])expect(after[key]).toBe(before[key]);
 }finally{await rm(directory,{recursive:true,force:true});}
},20000);

test('native gate timeout rejects and removes the owned executable after child termination',async()=>{
 const directory=await mkdtemp(join(tmpdir(),'composition-node-timeout-')),file=join(directory,'timeout.native.mjs'),observed=join(directory,'observed.json');
 let pid;
 try{
  await writeFile(file,`import test from 'node:test';
import {writeFile} from 'node:fs/promises';
await writeFile(${JSON.stringify(observed)},JSON.stringify({path:process.execPath,pid:process.pid}),{mode:0o600});
test('never completes',async()=>{await new Promise(()=>{setInterval(()=>{},1000);});});
`,{mode:0o600,flag:'wx'});
  let failure;try{await runCompositionNativeTests([file],{expectedTests:1,timeoutMs:1000});}catch(error){failure=error;}
  expect(failure?.signal).toBe('SIGKILL');
  const result=JSON.parse(await readFile(observed,'utf8'));pid=result.pid;
  await expect(lstat(result.path)).rejects.toMatchObject({code:'ENOENT'});
  // An orphan already killed by the group can briefly remain a zombie until
  // the host reaps it. It must not retain a running worker or executable maps.
  let state;
  try{state=(await readFile('/proc/'+pid+'/stat','utf8')).split(') ')[1].split(' ')[0];}catch(error){if(error.code!=='ENOENT')throw error;}
  expect([undefined,'Z','X']).toContain(state);
 }finally{
  if(pid){try{process.kill(pid,'SIGKILL');}catch(error){if(error.code!=='ESRCH')throw error;}}
  await rm(directory,{recursive:true,force:true});
 }
},15000);


test('native gate retains its output ceiling and cleans workers when output exceeds it',async()=>{
 const directory=await mkdtemp(join(tmpdir(),'composition-node-output-')),file=join(directory,'output.native.mjs'),observed=join(directory,'observed.json');
 let pid;
 try{
  await writeFile(file,`import {writeFile} from 'node:fs/promises';
await writeFile(${JSON.stringify(observed)},JSON.stringify({path:process.execPath,pid:process.pid}),{mode:0o600});
process.stderr.write(('x'.repeat(1023)+'\\n').repeat(9*1024));setInterval(()=>{},1000);
`,{mode:0o600,flag:'wx'});
  let failure;try{await runCompositionNativeTests([file],{timeoutMs:10000});}catch(error){failure=error;}
  expect(failure?.code).toBe('ERR_CHILD_PROCESS_STDIO_MAXBUFFER');expect(failure.message.length).toBeLessThan(25000);
  const result=JSON.parse(await readFile(observed,'utf8'));pid=result.pid;
  await expect(lstat(result.path)).rejects.toMatchObject({code:'ENOENT'});
  let state;try{state=(await readFile('/proc/'+pid+'/stat','utf8')).split(') ')[1].split(' ')[0];}catch(error){if(error.code!=='ENOENT')throw error;}
  expect([undefined,'Z','X']).toContain(state);
 }finally{
  if(pid){try{process.kill(pid,'SIGKILL');}catch(error){if(error.code!=='ESRCH')throw error;}}
  await rm(directory,{recursive:true,force:true});
 }
},15000);


test('native fixture names a writable source entry without changing its mode or bypassing pack guards',async()=>{
 const directory=await mkdtemp(join(tmpdir(),'composition-node-entry-')),file=join(directory,'entry.native.mjs');
 const fixture=new URL('./control-composition-native/fixture.mjs',import.meta.url).href;
 try{
  await writeFile(file,`import test from 'node:test';
import assert from 'node:assert/strict';
import {lstat} from 'node:fs/promises';
import {fixture} from ${JSON.stringify(fixture)};
test('real writable source entry rejects before fixture allocation',async()=>{
 assert.equal((await lstat(process.argv[1])).mode&0o7777,0o664);
 await assert.rejects(fixture({transport:true,packed:true,nativeTools:true}),error=>{
  assert.equal(error.message,'ControlCompositionNativeEntryWritable: '+process.argv[1]+' mode=664');return true;
 });
 assert.equal((await lstat(process.argv[1])).mode&0o7777,0o664);
});
`,{mode:0o600,flag:'wx'});
  await chmod(file,0o664);
  const result=await runCompositionNativeTests([file],{expectedTests:1,timeoutMs:10000});expect(result.passed).toBe(1);
  expect((await lstat(file)).mode&0o7777).toBe(0o664);
 }finally{await rm(directory,{recursive:true,force:true});}
},15000);
