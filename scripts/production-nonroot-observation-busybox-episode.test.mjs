import {test,expect} from 'vitest';
import {spawnSync} from 'node:child_process';
import {nonrootHash} from './lib/production-nonroot-contracts.mjs';
import {busyboxObservationEpisodeSource,inspectBusyboxObservationEpisode} from './lib/production-nonroot-observation-busybox-episode.mjs';
import {busyboxObservationCollectorSource} from './lib/production-nonroot-observation-busybox-collector.mjs';
const hex=s=>Buffer.from(s).toString('hex');
const stamp=inode=>'1,'+inode+',100,81ed,0,0,2026-01-01 00:00:00.000000000 +0000,2026-01-01 00:00:00.000000000 +0000';
function row(pid,path,digest,cmdlineHash,inode){
 const stat=pid+' (fixed) '+['S',pid===1?'0':'1',...Array(17).fill('0'),String(pid*100)].join(' ');
 return {pid,stat:hex(stat),statAfter:hex(stat),status:hex(['Name:\tfixed','Pid:\t'+pid,'PPid:\t'+(pid===1?0:1),'Uid:\t1000 1000 1000 1000','Gid:\t1000 1000 1000 1000','Groups:\t1000','NoNewPrivs:\t1',...['Inh','Prm','Eff','Bnd','Amb'].map(k=>'Cap'+k+':\t0000000000000000')].join('\n')+'\n'),cmdlineHash,path:hex(path),stamp:stamp(inode),digest};
}
function fixture(){
 const plan={version:1,kind:'bounded-data-observation',owner:'a'.repeat(32),operation:'b'.repeat(32),launchNonce:'c'.repeat(32),sourceTree:'d'.repeat(40),role:'mnemo-server',image:{rootDigest:'sha256:'+'1'.repeat(64),arm64Digest:'sha256:'+'2'.repeat(64),configDigest:'sha256:'+'3'.repeat(64)},startedMs:1000,latestArmMs:2000,observationEndMs:12000,deadlineMs:13000,armingLimitMs:500,cleanupReserveMs:1000,episodes:[{index:0,offsetMs:3000,durationMs:4000,sampleEveryMs:2000}],limits:{readBytes:268435456,rawBytes:1048576,initialProcesses:128,finalProcesses:128,combinedIdentities:256}};
 const main=row(2,'/usr/local/bin/mnemo-server','a'.repeat(64),'d'.repeat(64),20),observer=row(3,'/bin/busybox','b'.repeat(64),'e'.repeat(64),30),init=row(1,'/dev/init','c'.repeat(64),'f'.repeat(64),10),health=row(4,'/bin/busybox','b'.repeat(64),'1'.repeat(64),30);
 const rows=()=>structuredClone([init,main,observer]);
 const raw={version:1,kind:'data-busybox-observation-episode',planHash:nonrootHash(plan),launchNonce:plan.launchNonce,episodeIndex:0,observerPid:3,parentPid:2,parentStartTimeTicks:200,requestedStartMs:4000,requestedEndMs:8000,initial:{startedSeconds:1,completedSeconds:2,processes:rows()},snapshots:[4,6,8].map(s=>({requestedMs:s*1000,startedSeconds:s,completedSeconds:s,processes:rows()})),health:{observedSeconds:5,process:health},readBytes:10000,movementBytes:80000,helperInvocations:100,collectorChildren:0};
 const options={plan,episodeIndex:0,mainFile:{path:'/usr/local/bin/mnemo-server',sha256:'a'.repeat(64),size:100,mode:493,uid:0,gid:0},healthFile:{path:'/bin/busybox',sha256:'b'.repeat(64),size:100,mode:493,uid:0,gid:0},mainCmdlineHash:'d'.repeat(64),healthCmdlineHashes:['1'.repeat(64)],parentPid:2,parentStartTimeTicks:200,observerPid:3};
 return {raw,options};
}
test('complete timed Go DATA retains all snapshots and final health role without granting authority',()=>{
 const {raw,options}=fixture(),r=inspectBusyboxObservationEpisode(raw,options);expect(r.authority).toBe(false);expect(r.snapshots).toHaveLength(4);expect(r.main.pid).toBe(2);expect(r.health.pid).toBe(4);
});
test.each([
 ['missing snapshot',r=>r.snapshots.pop()],
 ['missing observer',r=>r.snapshots[0].processes.pop()],
 ['foreign health executable',r=>r.health.process.path=hex('/bin/foreign')],
 ['foreign health argv',r=>r.health.process.cmdlineHash='2'.repeat(64)],
 ['late health',r=>r.health.observedSeconds=8],
 ['early initial',r=>r.initial.startedSeconds=0],
 ['wrong owner plan',r=>r.planHash='0'.repeat(64)],
 ['remaining child',r=>r.collectorChildren=1],
 ['raw cap overrun',r=>r.readBytes=268435457],
 ['main inode change',r=>r.snapshots[1].processes[1].stamp=stamp(99)],
 ['main length changed',r=>r.snapshots[1].processes[1].stamp=stamp(20).replace(',100,',',101,')],
 ['same main inode timestamp changed',r=>r.snapshots[1].processes[1].stamp=stamp(20).replace('.000000000','.000000001')],
 ['health same hash foreign inode',r=>r.health.process.stamp=stamp(99)],
 ['health length changed',r=>r.health.process.stamp=stamp(30).replace(',100,',',101,')],
 ['health same inode timestamp changed',r=>r.health.process.stamp=stamp(30).replace('.000000000','.000000001')],
 ['observer reused PID',r=>{const p=r.snapshots[1].processes[2];p.stat=p.stat.replace(hex('300'),hex('301'));p.statAfter=p.stat;}],
 ['observer security changed',r=>{for(const s of [r.initial,...r.snapshots])s.processes[2].status=s.processes[2].status.replace(hex('NoNewPrivs:\t1'),hex('NoNewPrivs:\t0'));}],
 ['observer foreign file',r=>{for(const s of [r.initial,...r.snapshots])s.processes[2].path=hex('/bin/foreign');}],
 ['observer file uid changed',r=>{for(const s of [r.initial,...r.snapshots])s.processes[2].stamp=stamp(30).replace(',0,0,',',1000,0,');}],
 ['backwards snapshot chronology',r=>r.snapshots[0].completedSeconds=7],
 ['main NNP change',r=>r.snapshots[1].processes[1].status=r.snapshots[1].processes[1].status.replace(hex('NoNewPrivs:\t1'),hex('NoNewPrivs:\t0'))],
])('timed episode rejects %s',(_name,change)=>{
 const {raw,options}=fixture();change(raw);expect(()=>inspectBusyboxObservationEpisode(raw,options)).toThrow();
});
test('expected file facts cannot permit writable/root-privileged or foreign-owned binaries',()=>{
 for(const mutate of [f=>f.uid=1000,f=>f.mode=511,f=>f.mode=0o4755,f=>f.sha256='invalid',f=>delete f.size,f=>f.size=101]){
  const {raw,options}=fixture();mutate(options.mainFile);expect(()=>inspectBusyboxObservationEpisode(raw,options)).toThrow();
 }
});
test('separate health row must agree with the same process observed in a full snapshot',()=>{
 const {raw,options}=fixture();raw.snapshots[1].processes.push(structuredClone(raw.health.process));
 expect(inspectBusyboxObservationEpisode(raw,options).health.pid).toBe(4);
 raw.snapshots[1].processes.at(-1).cmdlineHash='2'.repeat(64);
 expect(()=>inspectBusyboxObservationEpisode(raw,options)).toThrow('DataObservationEpisodeProcessChanged');
});
test('caller bindings are closed inert values and malformed identity/hash sets reject',()=>{
 for(const change of [o=>o.parentPid=o.observerPid,o=>o.observerPid=1,o=>o.episodeIndex='0',o=>o.mainCmdlineHash='',o=>o.healthCmdlineHashes=[],o=>o.healthCmdlineHashes.push(o.healthCmdlineHashes[0]),o=>o.extra=true]){
  const {raw,options}=fixture();change(options);expect(()=>inspectBusyboxObservationEpisode(raw,options)).toThrow();
 }
 const {raw,options}=fixture();let called=false;Object.defineProperty(options,'mainFile',{get(){called=true;throw Error('GetterExecuted');},enumerable:true});
 expect(()=>inspectBusyboxObservationEpisode(raw,options)).toThrow();expect(called).toBe(false);
});
test('episode source is fixed and preserves complete raw row/health capture calls',()=>{
 expect(()=>busyboxObservationEpisodeSource('source')).toThrow();const s=busyboxObservationEpisodeSource();expect(s).toContain('obs_collect_proc "$pid"');expect(s).toContain('obs_collect_close || return 1');expect(s).not.toContain('/environ');
});
const tool=process.env.MEM9_TEST_BUSYBOX,loader=process.env.MEM9_TEST_BUSYBOX_LOADER;
test.runIf(!!tool&&!!loader)('timed episode source parses in the retained original BusyBox shell',()=>{
 const r=spawnSync(loader,[tool,'sh','-n'],{input:busyboxObservationEpisodeSource(),env:{},encoding:'utf8',timeout:5000});expect(r.error).toBeUndefined();expect(r.status).toBe(0);expect(r.stderr).toBe('');
});
test.runIf(!!tool&&!!loader)('failed episode closes genuine held files, clears stale payload and preserves spent counters',()=>{
 // Fixed tool-path mapping only. This is a real failed local episode with
 // genuine proc/file reads, not a successful Go task or policy fixture.
 const q=s=>"'"+s.replaceAll("'","'\\''")+"'";
 const source=busyboxObservationCollectorSource()+busyboxObservationEpisodeSource()+`
obs_collect_bb=${q(loader+' '+tool)}
OBS_COLLECT_DEADLINE_MS=${Date.now()+10000}
obs_collect_file /proc/$$/exe || exit 71
[ -r /proc/$$/fd/20 ] || exit 72
spent=$OBS_COLLECT_READ_BYTES
[ "$spent" -gt 0 ] || exit 73
OBS_EPISODE_RESULT='prior-episode'
if obs_busybox_episode 0 2 1 1; then exit 74; fi
[ -z "$OBS_EPISODE_RESULT" ] || exit 75
[ ! -e /proc/$$/fd/20 ] && [ ! -e /proc/$$/fd/4 ] || exit 76
[ "$OBS_COLLECT_READ_BYTES" -eq "$spent" ] || exit 77
[ "$obs_collect_next" -eq 20 ] && [ -z "$obs_collect_cache" ] || exit 78
`;
 const r=spawnSync(loader,[tool,'sh','-s'],{input:source,env:{},encoding:'utf8',timeout:5000});expect(r.error).toBeUndefined();expect(r.status).toBe(0);expect(r.stdout).toBe('');expect(r.stderr).toBe('');
});
