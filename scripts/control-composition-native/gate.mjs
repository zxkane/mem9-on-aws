import assert from 'node:assert/strict';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {fileURLToPath} from 'node:url';

const execute=promisify(execFile);

// Native suites retain node:test's mocks, hooks and child-process semantics.
// Vitest must await this process: printed TAP alone is never a passing gate.
export async function runCompositionNativeTests(files,{expectedTests,timeoutMs=180000}={}){
 assert.ok(Array.isArray(files)&&files.length>0);
 const paths=files.map(file=>file instanceof URL?fileURLToPath(file):file);
 assert.ok(paths.every(file=>typeof file==='string'&&file.endsWith('.native.mjs')));
 let stdout,stderr;
 try{
  ({stdout,stderr}=await execute(process.execPath,['--test','--test-concurrency=1','--test-reporter=tap',...paths],{
   encoding:'utf8',timeout:timeoutMs,maxBuffer:8*1024*1024,killSignal:'SIGKILL',
  }));
 }catch(error){
  // Keep the real exit code/signal for the caller and bounded failure evidence.
  const failure=new Error('Composition native test process failed: '+String(error.code??error.signal)+'\n'+String(error.stdout??'').slice(-16384)+'\n'+String(error.stderr??'').slice(-8192),{cause:error});
  failure.code=error.code;failure.signal=error.signal;throw failure;
 }
 const summary=name=>{
  const rows=[...stdout.matchAll(new RegExp('^# '+name+' ([0-9]+)$','gm'))];
  assert.equal(rows.length,1,'missing or ambiguous native '+name+' summary');return Number(rows[0][1]);
 };
 const tests=summary('tests'),passed=summary('pass');
 assert.ok(tests>0,'native test process ran no tests');
 if(expectedTests!==undefined)assert.equal(tests,expectedTests,'native case inventory changed');
 assert.equal(passed,tests);for(const key of ['fail','cancelled','skipped','todo'])assert.equal(summary(key),0,key);
 return {exitCode:0,tests,passed,stdout,stderr};
}
