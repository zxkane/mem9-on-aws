import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {constants,createReadStream} from 'node:fs';
import {mkdtemp,copyFile,chmod,lstat,realpath,rm,readdir,readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {setTimeout as delay} from 'node:timers/promises';

async function executableHash(path,size){
 const hash=createHash('sha256');let bytes=0;
 for await(const chunk of createReadStream(path,{flags:constants.O_RDONLY|constants.O_NOFOLLOW,highWaterMark:1024*1024})){
  bytes+=chunk.length;assert.ok(bytes<=size,'native test executable grew');hash.update(chunk);
 }
 assert.equal(bytes,size,'native test executable truncated');return hash.digest('hex');
}
const identity=s=>[s.dev,s.ino,s.mode,s.uid,s.gid,s.nlink,s.size,s.mtimeNs,s.ctimeNs];
async function ownTestExecutable(directory){
 // Hosted setup-node caches can be writable. Execute an owned byte-identical
 // copy so real runtime/pack guards inspect its real mode, inode and mapped bytes.
 // This is test setup only; production action runtimes retain their own checks.
 const source=await realpath(process.execPath),before=await lstat(source,{bigint:true});
 assert.ok(before.isFile()&&before.nlink===1n&&before.size>0n&&before.size<=256n*1024n*1024n,'native test executable source');
 const expected=await executableHash(source,Number(before.size)),target=join(directory,'node');
 await copyFile(source,target,constants.COPYFILE_EXCL);await chmod(target,0o700);
 const copied=await lstat(target,{bigint:true});
 assert.ok(copied.isFile()&&copied.nlink===1n&&copied.uid===BigInt(process.getuid())&&(copied.mode&0o7777n)===0o700n,'native test executable ownership');
 assert.equal(copied.size,before.size);assert.equal(await executableHash(target,Number(before.size)),expected,'native test executable hash');
 assert.deepEqual(identity(await lstat(source,{bigint:true})),identity(before),'native test executable source changed');
 assert.equal(await realpath(source),source);return target;
}

async function waitForGroupStop(pid){
 const deadline=performance.now()+2000;
 for(;;){
  let running=false;
  for(const entry of await readdir('/proc')){
   if(!/^[0-9]+$/.test(entry))continue;
   let stat;try{stat=await readFile('/proc/'+entry+'/stat','utf8');}catch(error){if(error.code==='ENOENT'||error.code==='ESRCH')continue;throw error;}
   const fields=stat.slice(stat.lastIndexOf(') ')+2).split(' ');
   if(Number(fields[2])===pid&&!['Z','X'].includes(fields[0])){running=true;break;}
  }
  if(!running)return;
  assert.ok(performance.now()<deadline,'native test process group cleanup incomplete');await delay(10);
 }
}

async function executeNative(executable,paths,timeoutMs){
 assert.ok(Number.isInteger(timeoutMs)&&timeoutMs>=0,'native test timeout');
 const child=spawn(executable,['--test','--test-concurrency=1','--test-reporter=tap',...paths],{detached:true,stdio:['ignore','pipe','pipe']});
 const output={stdout:[],stderr:[]},lengths={stdout:0,stderr:0};let failure,cleanupError;
 const stop=()=>{if(child.pid)try{process.kill(-child.pid,'SIGKILL');}catch(error){if(error.code!=='ESRCH')cleanupError=error;}};
 const timer=timeoutMs?setTimeout(stop,timeoutMs):undefined;
 child.once('error',error=>{failure??=error;});child.once('exit',stop);
 for(const name of ['stdout','stderr'])child[name].on('data',chunk=>{
  const remaining=8*1024*1024-lengths[name];
  output[name].push(chunk.subarray(0,remaining));lengths[name]+=Math.min(remaining,chunk.length);
  if(chunk.length>remaining){failure??=Object.assign(new Error('native '+name+' exceeded maxBuffer'),{code:'ERR_CHILD_PROCESS_STDIO_MAXBUFFER'});stop();}
 });
 const closed=await new Promise(resolve=>child.once('close',(code,signal)=>resolve({code,signal})));
 clearTimeout(timer);stop();
 try{if(cleanupError)throw cleanupError;if(child.pid)await waitForGroupStop(child.pid);}
 catch(error){throw Object.assign(new Error('native process group cleanup incomplete',{cause:error}),{cleanupIncomplete:true});}
 const stdout=Buffer.concat(output.stdout).toString('utf8'),stderr=Buffer.concat(output.stderr).toString('utf8');
 if(failure||closed.code!==0)throw Object.assign(failure??new Error('native test process failed'),{code:failure?.code??closed.code,signal:closed.signal,stdout,stderr});
 return {stdout,stderr};
}

// Native suites retain node:test's mocks, hooks and child-process semantics.
// Vitest must await this process: printed TAP alone is never a passing gate.
export async function runCompositionNativeTests(files,{expectedTests,timeoutMs=180000}={}){
 assert.ok(Array.isArray(files)&&files.length>0);
 const paths=files.map(file=>file instanceof URL?fileURLToPath(file):file);
 assert.ok(paths.every(file=>typeof file==='string'&&file.endsWith('.native.mjs')));
 const directory=await mkdtemp(join(tmpdir(),'composition-native-node-'));let cleanupComplete=true;
 try{
 const owned=await lstat(directory);assert.ok(owned.isDirectory()&&owned.uid===process.getuid()&&(owned.mode&0o777)===0o700,'native test executable directory');
 const executable=await ownTestExecutable(directory);
 let stdout,stderr;
 try{
  ({stdout,stderr}=await executeNative(executable,paths,timeoutMs));
 }catch(error){
  if(error.cleanupIncomplete){cleanupComplete=false;throw new Error('Native test cleanup incomplete; retained '+directory,{cause:error});}
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
 }finally{if(cleanupComplete)await rm(directory,{recursive:true,force:true});}
}
