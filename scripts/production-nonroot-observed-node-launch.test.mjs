import {test,expect,vi,beforeEach,afterEach} from 'vitest';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
const raw=vi.hoisted(()=>({files:new Map(),fds:new Map(),next:10,spawns:[],mode:'armed',opens:[],killed:[],execs:[]}));
vi.mock('node:fs',()=>({
 constants:{O_RDONLY:0,O_NONBLOCK:2048},
 openSync(path){if(!raw.files.has(path))throw Object.assign(Error('absent'),{code:'ENOENT'});const fd=raw.next++;raw.fds.set(fd,{row:raw.files.get(path),offset:0});raw.opens.push(path);return fd;},
 closeSync(fd){if(!raw.fds.delete(fd))throw Error('closed');},
 readSync(fd,b){const r=raw.fds.get(fd),n=Math.min(b.length,r.row.bytes.length-r.offset);r.row.bytes.copy(b,0,r.offset,r.offset+n);r.offset+=n;return n;},
 realpathSync(path){return raw.files.get(path)?.resolved??path;},
 fstatSync(fd){const r=raw.fds.get(fd).row;return {dev:1,ino:r.ino??20,size:r.bytes.length,mode:493,uid:0,gid:0,mtimeMs:1,ctimeMs:1,isFile:()=>true};},
 statSync(path){const r=raw.files.get(path);return {dev:1,ino:r.ino??20,size:r.bytes.length,mode:493,uid:0,gid:0,mtimeMs:1,ctimeMs:1,isFile:()=>true};},
}));
vi.mock('node:child_process',async importOriginal=>{
 const original=await importOriginal();const {EventEmitter}=await import('node:events');
 return {...original,spawn(file,args,options){
  const child=new EventEmitter(),pipe=new EventEmitter();let closing=false;
  pipe.destroy=vi.fn(()=>{
   if(closing)return;closing=true;
   if(raw.neverClose)return;
   setTimeout(()=>{if(raw.closeError)pipe.emit('error',Error('synthetic closure error'));pipe.emit('close');},raw.closeDelay);
  });child.pid=49;child.stdio=[null,null,null,pipe];
  child.kill=signal=>{raw.killed.push({pid:49,signal});child.emit('exit',null,signal);return true;};raw.spawns.push({file,args,options,child});
  setTimeout(()=>{
   if(raw.mode!=='unknown'){
    pipe.emit('data',Buffer.from('B|50|400|'+'c'.repeat(32)+'\n'));
    if(raw.mode==='armed')pipe.emit('data',Buffer.from('A|50|400|'+'c'.repeat(32)+'\n'));
   }
   if(raw.invalidTail)pipe.emit('data',Buffer.from('not-an-arm-frame\n'));
   child.emit('exit',0,null);
  },1);
  return child;
 }};
});
import {compileObservedNodeDataLaunch,runObservedNodeDataLaunch} from './lib/production-nonroot-observed-node-launch.mjs';
const hash=b=>createHash('sha256').update(b).digest('hex');
const kernel=['Uid:\t1000 1000 1000 1000','Gid:\t1000 1000 1000 1000','Groups:\t1000',...['Inh','Prm','Eff','Bnd','Amb'].map(k=>'Cap'+k+':\t0000000000000000'),'NoNewPrivs:\t1'].join('\n')+'\n';
const node='/usr/local/bin/node',script='/app/scripts/consolidation-worker.mjs';
const proc=(pid,ticks)=>Buffer.from(pid+' (node) '+['S','1',...Array(17).fill('0'),String(ticks)].join(' ')+'\n');
const input=()=>({
 plan:{version:1,kind:'bounded-data-observation',owner:'a'.repeat(32),operation:'b'.repeat(32),launchNonce:'c'.repeat(32),sourceTree:'d'.repeat(40),role:'planner',
  image:{rootDigest:'sha256:'+'1'.repeat(64),arm64Digest:'sha256:'+'2'.repeat(64),configDigest:'sha256:'+'3'.repeat(64)},
  startedMs:1000,latestArmMs:1100,observationEndMs:1400,deadlineMs:1500,armingLimitMs:25,cleanupReserveMs:100,
  episodes:[{index:0,offsetMs:200,durationMs:100,sampleEveryMs:50}],limits:{readBytes:268435456,rawBytes:1048576,initialProcesses:128,finalProcesses:128,combinedIdentities:256}},
 original:{name:'Mem9ConsolidationPlanner',image:'example.com/worker@sha256:'+'1'.repeat(64),linuxParameters:{initProcessEnabled:true},readonlyRootFilesystem:true,environment:[{name:'SYNTHETIC_APPLICATION_SETTING',value:'retained'}]},
 files:[node,script].map(path=>({path,resolvedPath:path,sha256:hash(raw.files.get(path).bytes),size:raw.files.get(path).bytes.length,mode:493,uid:0,gid:0})),
});
let arch,version,exec,kill,listeners;
beforeEach(()=>{
 raw.files.clear();raw.fds.clear();raw.spawns=[];raw.opens=[];raw.killed=[];raw.execs=[];raw.mode='armed';raw.invalidTail=false;raw.closeError=false;raw.neverClose=false;raw.closeDelay=0;
 raw.files.set(node,{bytes:Buffer.from('synthetic node'),ino:20});raw.files.set(script,{bytes:Buffer.from('synthetic original app'),ino:21});
 raw.files.set('/proc/self/exe',{...raw.files.get(node),resolved:node});raw.files.set('/proc/self/status',{bytes:Buffer.from(kernel)});
 raw.files.set('/proc/self/maps',{bytes:Buffer.from('1000-2000 r-xp 0 00:01 20 '+node+'\n')});
 raw.files.set('/proc/'+process.pid+'/stat',{bytes:proc(process.pid,300)});raw.files.set('/proc/50/stat',{bytes:proc(50,400)});
 arch=Object.getOwnPropertyDescriptor(process,'arch');version=Object.getOwnPropertyDescriptor(process,'version');
 Object.defineProperty(process,'arch',{...arch,value:'arm64'});Object.defineProperty(process,'version',{...version,value:'v24.0.0'});
 exec=vi.spyOn(process,'execve').mockImplementation((file,args,env)=>{raw.execs.push({file,args,env});});
 kill=vi.spyOn(process,'kill').mockImplementation((pid,signal)=>{expect(pid).toBe(50);raw.killed.push({pid,signal});raw.files.delete('/proc/50/stat');return true;});
 listeners=['SIGTERM','SIGINT'].map(s=>process.listenerCount(s));vi.useFakeTimers();vi.setSystemTime(1000);
});
afterEach(()=>{
 expect(raw.fds.size).toBe(0);expect(['SIGTERM','SIGINT'].map(s=>process.listenerCount(s))).toEqual(listeners);
 vi.useRealTimers();exec.mockRestore();kill.mockRestore();Object.defineProperty(process,'arch',arch);Object.defineProperty(process,'version',version);
});
async function run(value=input()){
 const pending=runObservedNodeDataLaunch(value).then(value=>({value}),error=>({error}));await vi.runAllTimersAsync();return pending;
}
test('compiler preserves complete normal DATA/security/environment and includes every initial snapshot',()=>{
 const r=compileObservedNodeDataLaunch(input());expect(r.normal.entryPoint).toEqual(['/usr/bin/setpriv','--no-new-privs','--','node']);
 expect(r.normal.command).toEqual([script]);expect(r.target.environment).toEqual(input().original.environment);expect(r.target.readonlyRootFilesystem).toBe(true);
 expect(r.snapshotCount).toBe(4);expect(r.target.command).toEqual([]);expect(r.sourceHash).toBe(hash(Buffer.from(r.target.entryPoint.at(-1))));
});
test('all four Node roles compile their original application and scheduled health argv',()=>{
 for(const role of ['planner','executor','llm-proxy','qwen3-embed']){
  const v=input();v.plan.role=role;v.original.name=role==='planner'?'Mem9ConsolidationPlanner':role==='executor'?'Mem9ConsolidationExecutor':role;
  if(['llm-proxy','qwen3-embed'].includes(role)){
   v.original.healthCheck={command:['CMD','node','/app/healthcheck.mjs',role==='llm-proxy'?'http://localhost:8082/health':'http://localhost:8081/health'],interval:30};
   v.files.push({...v.files[1],path:'/app/server.mjs',resolvedPath:'/app/server.mjs'},{...v.files[1],path:'/app/healthcheck.mjs',resolvedPath:'/app/healthcheck.mjs'});
  }
  const r=compileObservedNodeDataLaunch(v);expect(r.plan.role).toBe(role);expect(r.target.healthCheck).toEqual(r.normal.healthCheck);
  expect(r.normal.entryPoint.at(-1)).toBe(['planner','executor'].includes(role)?'node':'server.mjs');
 }
});
test('a schedule with no time left to emit fails before any launch or IO',()=>{
 const v=input();v.plan.observationEndMs=1300;
 expect(()=>compileObservedNodeDataLaunch(v)).toThrow('DataObservationEmissionWindow');expect(raw.opens).toEqual([]);expect(raw.spawns).toEqual([]);
});
test('later normal launches execute the unchanged app through the real common gate, without helper spawn',async()=>{
 vi.setSystemTime(1500);const r=await run();expect(r.error.message).toBe('DataObservationExecReturned');expect(raw.spawns).toHaveLength(0);
 expect(raw.execs).toHaveLength(1);expect(raw.execs[0].args).toEqual(['node',script]);expect(raw.execs[0].env).toBe(process.env);expect(raw.opens).toContain('/proc/self/maps');
});
test('prewindow normal selection creates no finite observation helper',async()=>{
 vi.setSystemTime(999);await run();expect(raw.spawns).toHaveLength(0);expect(raw.execs).toHaveLength(1);
});
test('expired window never suppresses a source or kernel security failure',async()=>{
 vi.setSystemTime(2000);raw.files.get('/proc/self/status').bytes=Buffer.from(kernel.replace('NoNewPrivs:\t1','NoNewPrivs:\t0'));
 const r=await run();expect(r.error.message).toBe('DataObservationSecurityGate');expect(raw.execs).toHaveLength(0);expect(raw.spawns).toHaveLength(0);
});
test('original source hashing completes before the single relay start and app handoff',async()=>{
 const r=await run();expect(r.error.message).toBe('DataObservationExecReturned');expect(raw.spawns).toHaveLength(1);expect(raw.execs).toHaveLength(1);
 expect(raw.spawns[0].file).toBe(node);expect(raw.spawns[0].options.env).toEqual({PATH:'/usr/local/bin:/usr/bin:/bin'});
 expect(raw.spawns[0].args.at(-1)).toBe('1025');
 // A returning execve is a raw syscall failure seam, so the actual catch
 // stops the known observer instead of inventing an app completion.
 expect(raw.killed).toContainEqual({pid:50,signal:'SIGTERM'});
});
test('arming expiry joins the known helper before taking the same normal launch path',async()=>{
 raw.mode='expired';const r=await run();expect(r.error.message).toBe('DataObservationExecReturned');expect(raw.killed).toContainEqual({pid:50,signal:'SIGTERM'});
 expect(raw.files.has('/proc/50/stat')).toBe(false);expect(raw.execs).toHaveLength(1);
 expect(raw.opens.filter(p=>p==='/proc/self/maps')).toHaveLength(2);
});
test('missing birth/cleanup evidence cannot take normal fallback',async()=>{
 raw.mode='unknown';const r=await run();expect(r.error.message).toBe('DataObservationCleanupUnknown');expect(raw.execs).toHaveLength(0);
});
test('launch cancellation joins its known observer and never executes the application',async()=>{
 raw.mode='expired';setTimeout(()=>process.emit('SIGTERM'),5);const r=await run();
 expect(r.error.message).toBe('DataObservationLaunchCancelled');expect(raw.execs).toHaveLength(0);expect(raw.killed).toContainEqual({pid:50,signal:'SIGTERM'});
});
test('reused helper PID is rejected without signalling the foreign instance',async()=>{
 raw.files.set('/proc/50/stat',{bytes:proc(50,401)});const r=await run();
 expect(r.error.message).toBe('DataObservationLifecycleReused');expect(raw.execs).toHaveLength(0);expect(raw.killed).toHaveLength(0);
});
test('wrong mapped interpreter rejects before any observer or app starts',async()=>{
 raw.files.get('/proc/self/maps').bytes=Buffer.from('1000-2000 r-xp 0 00:01 99 '+node+'\n');
 const r=await run();expect(r.error.message).toBe('DataObservationSecurityGate');expect(raw.spawns).toHaveLength(0);expect(raw.execs).toHaveLength(0);
});
test('compiler rejects unknown source, missing init, changed image and missing app bytes',()=>{
 for(const mutate of [v=>v.source='success',v=>v.original.linuxParameters.initProcessEnabled=false,v=>v.original.image='example.com/other@sha256:'+'f'.repeat(64),v=>v.files=v.files.slice(0,1)]){
  const v=input();mutate(v);expect(()=>compileObservedNodeDataLaunch(v)).toThrow();
 }
 expect(raw.opens).toEqual([]);expect(raw.spawns).toEqual([]);
});
test('generated coordinator compiles in actual Node after configured test transform',()=>{
 const source=compileObservedNodeDataLaunch(input()).target.entryPoint.at(-1);
 const r=spawnSync(process.execPath,['--input-type=module','--check'],{env:{},input:source,encoding:'utf8',timeout:5000});
 expect(r.error).toBeUndefined();expect(r.status).toBe(0);expect(r.stderr).toBe('');
});
test('native execve retains PID and original argument boundary',()=>{
 const child="process.stdout.write(JSON.stringify({pid:process.pid,arg:process.argv[1]}))";
 const parent="const before=process.pid;process.execve(process.execPath,['node','--input-type=module','-e',"+JSON.stringify(child)+",String(before)],{});";
 const r=spawnSync(process.execPath,['--input-type=module','-e',parent],{env:{},encoding:'utf8',timeout:5000});
 expect(r.error).toBeUndefined();expect(r.status).toBe(0);const observed=JSON.parse(r.stdout);expect(observed.pid).toBe(Number(observed.arg));
});
test('late invalid channel data after valid B/A prevents exec and preserves the original error',async()=>{
 raw.invalidTail=true;const r=await run();expect(raw.execs).toHaveLength(0);expect(r.error.message).toBe('DataObservationArmBinding');
 expect(raw.killed).toContainEqual({pid:50,signal:'SIGTERM'});
});
test('asynchronous channel closure error after readiness prevents observed application exec',async()=>{
 raw.closeError=true;raw.closeDelay=2;const r=await run();expect(raw.execs).toHaveLength(0);expect(r.error.message).toBe('DataObservationArmChannel');
 expect(raw.killed).toContainEqual({pid:50,signal:'SIGTERM'});
});
test('confirmed delayed clean channel closure still permits the original app handoff',async()=>{
 raw.closeDelay=2;const r=await run();expect(r.error.message).toBe('DataObservationExecReturned');expect(raw.execs).toHaveLength(1);
});
test('unconfirmed channel closure cannot become expiry fallback or observed exec',async()=>{
 raw.neverClose=true;const r=await run();expect(raw.execs).toHaveLength(0);expect(r.error.message).toBe('DataObservationHelperCleanup');
});
test('closure failure during expired-arm cleanup prevents normal fallback',async()=>{
 raw.mode='expired';raw.closeError=true;const r=await run();expect(raw.execs).toHaveLength(0);expect(r.error.message).toBe('DataObservationArmChannel');
});
test('frozen wall clock exhausts finite arming polls and still joins its owned helper',async()=>{
 const clock=vi.spyOn(Date,'now').mockReturnValue(1000);
 try{
  raw.mode='expired';raw.closeDelay=3;const r=await run();
  expect(r.error.message).toBe('DataObservationPollBound');expect(raw.execs).toHaveLength(0);
  expect(raw.killed).toContainEqual({pid:50,signal:'SIGTERM'});expect(raw.files.has('/proc/50/stat')).toBe(false);
  expect(raw.spawns[0].child.stdio[3].destroy).toHaveBeenCalledTimes(1);expect(vi.getTimerCount()).toBe(0);
 }finally{clock.mockRestore();}
});
test('frozen clock and missing physical channel close exhaust a separate cleanup budget',async()=>{
 const clock=vi.spyOn(Date,'now').mockReturnValue(1000);
 try{
  raw.neverClose=true;const r=await run();
  expect(r.error.message).toBe('DataObservationCleanupPollBound');expect(raw.execs).toHaveLength(0);
  expect(raw.killed).toContainEqual({pid:50,signal:'SIGTERM'});expect(vi.getTimerCount()).toBe(0);
 }finally{clock.mockRestore();}
});
test('live owned helper cannot keep cleanup polling forever when the wall clock stops',async()=>{
 const clock=vi.spyOn(Date,'now').mockReturnValue(1000);
 try{
  raw.mode='expired';kill.mockImplementation((pid,signal)=>{raw.killed.push({pid,signal});return true;});
  const r=await run();expect(r.error.message).toBe('DataObservationCleanupPollBound');
  expect(raw.files.has('/proc/50/stat')).toBe(true);expect(raw.execs).toHaveLength(0);expect(vi.getTimerCount()).toBe(0);
 }finally{clock.mockRestore();}
});
