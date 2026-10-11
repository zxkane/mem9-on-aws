import {test,expect,vi,beforeEach,afterEach} from 'vitest';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';

// Kernel/filesystem and time seams only; no verifier or native-result mocks.
const model=vi.hoisted(()=>({processes:new Map(),fds:new Map(),opens:[],readBytes:0,next:20,hook:null,children:'',reads:new Map()}));
vi.mock('node:fs',()=>({
 constants:{O_RDONLY:0,O_NONBLOCK:2048},
 readdirSync(path){if(path!=='/proc')throw Error('unexpected directory');return [...model.processes.keys()].map(String);},
 readlinkSync(path){const pid=Number(path.split('/')[2]);const row=model.processes.get(pid);if(!row)throw Object.assign(Error('absent'),{code:'ENOENT'});return row.executable;},
 openSync(path){
  model.opens.push(path);let bytes,row;const pid=Number(path.split('/')[2]),name=path.split('/').at(-1);
  if(path==='/proc/self/task/'+process.pid+'/children')bytes=Buffer.from(model.children);
  else{
   row=model.processes.get(pid);if(!row)throw Object.assign(Error('absent'),{code:'ENOENT'});
   if(name==='stat'){const f=['S',String(row.ppid),...Array(17).fill('0'),String(row.ticks)];bytes=Buffer.from(pid+' (synthetic app) '+f.join(' ')+'\n');}
   else if(name==='status')bytes=Buffer.from(row.status);
   else if(name==='cmdline')bytes=Buffer.from(row.cmdline);
   else if(name==='exe')bytes=row.bytes;
   else throw Error('unexpected raw read');
  }
  const fd=model.next++;model.fds.set(fd,{path,offset:0,bytes,row});return fd;
 },
 closeSync(fd){if(!model.fds.delete(fd))throw Error('unknown descriptor');},
 readSync(fd,buffer){
  const f=model.fds.get(fd),n=Math.min(buffer.length,f.bytes.length-f.offset);f.bytes.copy(buffer,0,f.offset,f.offset+n);f.offset+=n;model.readBytes+=n;
  model.reads.set(f.path,(model.reads.get(f.path)??0)+n);if(model.hook)model.hook(f.path);return n;
 },
 fstatSync(fd){const r=model.fds.get(fd).row;return {dev:1,ino:r.inode,size:r.bytes.length,mode:0o100755,uid:0,gid:0,mtimeMs:1,ctimeMs:1,isFile:()=>true};},
}));
import {collectNodeObservationEpisode,nodeObservationCollectorSource} from './lib/production-nonroot-observation-collector.mjs';
const hash=b=>createHash('sha256').update(b).digest('hex');
const kernel=['Uid:\t1000 1000 1000 1000','Gid:\t1000 1000 1000 1000','Groups:\t1000',...['Inh','Prm','Eff','Bnd','Amb'].map(k=>'Cap'+k+':\t0000000000000000'),'NoNewPrivs:\t1'].join('\n')+'\n';
const row=(extra={})=>({ppid:1,ticks:100,executable:'/usr/local/bin/node',bytes:Buffer.from('synthetic resident node'),inode:40,cmdline:'node\0/app/scripts/consolidation-worker.mjs\0',status:kernel,...extra});
const input=()=>({planHash:'a'.repeat(64),role:'planner',launchNonce:'b'.repeat(32),episodeIndex:0,parentPid:41,parentStartTimeTicks:100,
 mainExecutable:'/usr/local/bin/node',mainCmdlineHashes:[hash(Buffer.from(model.processes.get(41).cmdline))],healthRequired:false,healthCmdlineHashes:[],
 startMs:1020,endMs:1040,sampleEveryMs:10,deadlineMs:1100});
let beforeSignals;
beforeEach(()=>{
 vi.useFakeTimers();vi.setSystemTime(1000);model.processes.clear();model.fds.clear();model.opens=[];model.readBytes=0;model.hook=null;model.children='';model.reads.clear();
 model.processes.set(41,row());model.processes.set(process.pid,row({cmdline:'node\0-e\0fixed observer\0',ticks:200}));
 beforeSignals=['SIGTERM','SIGINT'].map(s=>process.listenerCount(s));
});
afterEach(()=>{expect(model.fds.size).toBe(0);expect(['SIGTERM','SIGINT'].map(s=>process.listenerCount(s))).toEqual(beforeSignals);vi.useRealTimers();});
async function collect(spec=input()){
 const settled=collectNodeObservationEpisode(spec).then(value=>({value}),error=>({error}));
 await vi.runAllTimersAsync();const result=await settled;if(result.error)throw result.error;return result.value;
}
test('healthless original worker collects initial/end/full proc rows and closes actual owned FDs',async()=>{
 const r=await collect();expect(r.snapshots.map(s=>s.startedMs)).toEqual([1020,1030,1040]);expect(r.initial.startedMs).toBe(1000);
 expect(r.health).toEqual([]);expect(r.snapshots.every(s=>s.processes.length===2)).toBe(true);expect(r.collectorResources).toEqual({heldImageFiles:0,childProcesses:0});
 expect(r.initial.processes.find(p=>p.pid===41)).toMatchObject({pid:41,startTimeTicks:100,executableDigest:'sha256:'+hash(row().bytes),uid:[1000,1000,1000,1000],noNewPrivs:1});
 expect(model.opens.every(p=>!p.includes('environ'))).toBe(true);expect(model.opens.filter(p=>p.endsWith('/exe'))).not.toHaveLength(0);
 expect([...model.reads].filter(([p])=>p.endsWith('/exe')).reduce((n,[,v])=>n+v,0)).toBe(row().bytes.length);
});
test('actual matching health process is collected, with original command digest and role binding',async()=>{
 model.processes.set(42,row({cmdline:'node\0/app/healthcheck.mjs\0http://localhost:8082/health\0',ticks:300}));
 const s={...input(),role:'llm-proxy',healthRequired:true,healthCmdlineHashes:[hash(Buffer.from(model.processes.get(42).cmdline))]};
 const r=await collect(s);expect(r.health).toHaveLength(1);expect(r.health[0].process.pid).toBe(42);expect(r.health[0].atMs).toBeGreaterThanOrEqual(s.startMs);
});
test('missing required health observation stays failure',async()=>{
 await expect(collect({...input(),role:'llm-proxy',healthRequired:true,healthCmdlineHashes:['f'.repeat(64)]})).rejects.toThrow('DataObservationHealthMissing');
});
test('health security cannot be bypassed through the scheduled snapshot path',async()=>{
 model.processes.set(42,row({cmdline:'node\0/app/healthcheck.mjs\0',ticks:300,status:kernel.replace('NoNewPrivs:\t1','NoNewPrivs:\t0')}));
 const s={...input(),role:'llm-proxy',healthRequired:true,healthCmdlineHashes:[hash(Buffer.from(model.processes.get(42).cmdline))]};
 await expect(collect(s)).rejects.toThrow('DataObservationHealthSecurity');
});
test('current app must have actually execed the fixed command',async()=>{
 const s=input();model.processes.get(41).cmdline='node\0-e\0still coordinator\0';
 await expect(collect(s)).rejects.toThrow('DataObservationMainNotExecuted');
});
test('PID reuse before or during sampling rejects rather than relabeling the new process',async()=>{
 const s=input();model.processes.get(41).ticks++;
 await expect(collect(s)).rejects.toThrow('DataObservationParentChanged');
});
test('changed executable instance during one proc observation is rejected',async()=>{
 let mutated=false;model.hook=path=>{if(!mutated&&path==='/proc/41/exe'){mutated=true;model.processes.get(41).inode++;}};
 await expect(collect()).rejects.toThrow();
});
test('main process identity and NNP changes cannot pass later snapshots',async()=>{
 let mutated=false;model.hook=()=>{if(!mutated&&Date.now()>=1030){mutated=true;model.processes.get(41).status=kernel.replace('NoNewPrivs:\t1','NoNewPrivs:\t0');}};
 await expect(collect()).rejects.toThrow('DataObservationMainSecurity');
});
test('executable hash cache must not survive in-place mutation after its first hash',async()=>{
 let mutated=false;model.hook=()=>{if(!mutated&&Date.now()>=1030){mutated=true;model.processes.get(41).inode++;}};
 await expect(collect()).rejects.toThrow('DataObservationProcessChanged');
});
test('oversized proc text is bounded and fails without leaking owned descriptors',async()=>{
 model.processes.get(41).status='x'.repeat(65537);await expect(collect()).rejects.toThrow('DataObservationProcBound');
 expect(model.reads.get('/proc/41/status')).toBe(65537);
});
test('a helper still present at close cannot become successful cleanup evidence',async()=>{
 model.children='99 ';await expect(collect()).rejects.toThrow('DataObservationHelperCleanup');
});
test('expired original deadline reads nothing and adds no lingering signal handlers',async()=>{
 const s=input();vi.setSystemTime(s.deadlineMs);await expect(collect(s)).rejects.toThrow('DataObservationCollectionExpired');expect(model.opens).toEqual([]);
});
test('cancellation retains failure and closes all held image files',async()=>{
 let sent=false;model.hook=path=>{if(!sent&&path.endsWith('/exe')){sent=true;process.emit('SIGTERM');}};
 await expect(collect()).rejects.toThrow('DataObservationCollectionExpired');
});
test('all original proc rows must fit the fixed process count',async()=>{
 for(let pid=100;pid<229;pid++)model.processes.set(pid,row({ticks:pid}));
 await expect(collect()).rejects.toThrow('DataObservationProcessCount');
});
test('invalid source/role/health/clock representation performs no IO',()=>{
 for(const mutate of [s=>s.callback='success',s=>s.role='debug',s=>s.mainExecutable='/tmp/node',s=>s.endMs=s.deadlineMs,s=>s.healthRequired=true,s=>s.healthCmdlineHashes=['f'.repeat(64)]]){
  const s=input();mutate(s);expect(()=>collectNodeObservationEpisode(s)).toThrow('DataObservationCollectorInput');
 }
 expect(model.opens).toEqual([]);
});
test('fixed generated collector loads in native Node without transformed closure bindings',()=>{
 const source=nodeObservationCollectorSource();const r=spawnSync(process.execPath,['--input-type=module','-e',source+'\nprocess.stdout.write(typeof collectNodeObservationEpisode)'],{env:{},encoding:'utf8',timeout:5000});
 expect(r.error).toBeUndefined();expect(r.status).toBe(0);expect(r.stdout).toBe('function');expect(r.stderr).toBe('');
});
test('final health binding rejects the exact foreign-executable reviewer reproduction',async()=>{
 const command='node\0/app/healthcheck.mjs\0http://localhost:8082/health\0';
 model.processes.set(42,row({cmdline:command,ticks:300,executable:'/usr/bin/foreign-program',bytes:Buffer.from('different executable'),inode:99}));
 const s={...input(),role:'llm-proxy',healthRequired:true,healthCmdlineHashes:[hash(Buffer.from(command))]};
 await expect(collect(s)).rejects.toThrow('DataObservationHealthBinding');
});
test('final health binding rejects the exact changed-argv reviewer reproduction',async()=>{
 const wanted='node\0/app/healthcheck.mjs\0http://localhost:8082/health\0',other='node\0/app/unrelated.mjs\0';let changed=false;
 setTimeout(()=>model.processes.set(42,row({cmdline:wanted,ticks:300})),21);
 model.hook=path=>{if(!changed&&path==='/proc/42/cmdline'){changed=true;model.processes.get(42).cmdline=other;}};
 const s={...input(),role:'llm-proxy',healthRequired:true,healthCmdlineHashes:[hash(Buffer.from(wanted))]};
 await expect(collect(s)).rejects.toThrow('DataObservationHealthBinding');expect(changed).toBe(true);
});
test('same-path same-content health must still use the original Node file instance',async()=>{
 const command='node\0/app/healthcheck.mjs\0http://localhost:8082/health\0';
 model.processes.set(42,row({cmdline:command,ticks:300,inode:99}));
 await expect(collect({...input(),role:'llm-proxy',healthRequired:true,healthCmdlineHashes:[hash(Buffer.from(command))]})).rejects.toThrow('DataObservationHealthBinding');
});
test('a genuinely matching final Node health row remains accepted through polling',async()=>{
 const command='node\0/app/healthcheck.mjs\0http://localhost:8082/health\0';
 setTimeout(()=>model.processes.set(42,row({cmdline:command,ticks:300})),21);
 const r=await collect({...input(),role:'llm-proxy',healthRequired:true,healthCmdlineHashes:[hash(Buffer.from(command))]});
 expect(r.health[0].atMs).toBe(1021);expect(r.health[0].process.cmdlineHash).toBe(hash(Buffer.from(command)));
});
