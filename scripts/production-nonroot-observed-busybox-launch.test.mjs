import {test,expect} from 'vitest';
import {gunzipSync} from 'node:zlib';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {compileObservedBusyboxDataLaunch} from './lib/production-nonroot-observed-busybox-launch.mjs';
import {dataLaunchPolicy} from './lib/production-nonroot-launch.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');
function fixture(){
 const image={rootDigest:'sha256:'+'1'.repeat(64),arm64Digest:'sha256:'+'2'.repeat(64),configDigest:'sha256:'+'3'.repeat(64)},startedMs=1800000000000;
 const plan={version:1,kind:'bounded-data-observation',owner:'a'.repeat(32),operation:'b'.repeat(32),launchNonce:'c'.repeat(32),sourceTree:'d'.repeat(40),role:'mnemo-server',image,startedMs,latestArmMs:startedMs+4000,observationEndMs:startedMs+40000,deadlineMs:startedMs+41000,armingLimitMs:2000,cleanupReserveMs:1000,episodes:[{index:0,offsetMs:10000,durationMs:5000,sampleEveryMs:1000}],limits:{readBytes:268435456,rawBytes:1048576,initialProcesses:128,finalProcesses:128,combinedIdentities:256}};
 const files=['/bin/busybox','/bin/sh','/bin/setpriv','/lib/ld-musl-aarch64.so.1','/usr/local/bin/entrypoint.sh','/usr/local/bin/mnemo-server'].map(path=>({path,resolvedPath:path,sha256:sha(Buffer.from(path)),size:100,mode:493,uid:0,gid:0}));
 const original={name:'mnemo-server',image:'example.com/server@'+image.rootDigest,linuxParameters:{initProcessEnabled:true},readonlyRootFilesystem:true,healthCheck:{command:['CMD-SHELL','wget -q -O /dev/null http://localhost:8080/healthz || exit 1'],interval:30},environment:[{name:'UNCHANGED',value:'synthetic'}]};
 return {plan,files,original};
}
function unpack(c){
 const program=c.target.entryPoint.at(-2),m=/^obs_payload='([A-Za-z0-9+/=]+)'/m.exec(program);expect(m).not.toBeNull();
 const compressed=Buffer.from(m[1],'base64'),source=gunzipSync(compressed);return {program,compressed,source,encoded:m[1]};
}
test('compiler preserves original normal definition, health and environment with one closed observed entry',()=>{
 const input=fixture(),before=structuredClone(input),c=compileObservedBusyboxDataLaunch(input);expect(input).toEqual(before);expect(c.normal).toEqual(dataLaunchPolicy('mnemo-server',input.original));
 const recovered={...c.target,entryPoint:c.normal.entryPoint};if(!Object.hasOwn(c.normal,'command'))delete recovered.command;
 expect(recovered).toEqual(c.normal);expect(c.target.command).toEqual([]);expect(c.target.entryPoint.slice(0,6)).toEqual(['/bin/setpriv','--no-new-privs','--','/bin/busybox','sh','-c']);expect(c.target.entryPoint.at(-1)).toBe('coordinator');
 expect(c.delivery.maximumInvocations).toBe(3);expect(c.snapshotCount).toBe(7);expect(c.delivery.cmdlineBytes).toBeLessThanOrEqual(16384);
});
test('delivery commits complete common gate, timed collector, bounded writer and both normal/observed modes',()=>{
 const c=compileObservedBusyboxDataLaunch(fixture()),{compressed,source}=unpack(c),s=source.toString();
 expect(source.length).toBe(c.delivery.sourceBytes);expect(sha(source)).toBe(c.delivery.sourceHash);expect(sha(compressed)).toBe(c.delivery.compressedHash);
 for(const name of ['obs_busybox_common_gate','obs_busybox_episode','obs_emit_busybox','obs_launch_coordinate','obs_launch_cleanup','obs_launch_observe'])expect(s).toContain(name);
 expect(s).toContain('exec /usr/local/bin/entrypoint.sh');expect(s).not.toContain('ExecuteCommand');expect(s).not.toContain('/environ');
});
test.each([
 ['extra source',i=>i.source='exit 0'],['wrong role',i=>i.plan.role='planner'],['wrong image',i=>i.original.image='example.com/server@sha256:'+'4'.repeat(64)],
 ['missing init',i=>i.original.linuxParameters.initProcessEnabled=false],['missing original Go',i=>i.files.pop()],['foreign Go resolution',i=>i.files.at(-1).resolvedPath='/tmp/foreign'],
 ['missing health',i=>delete i.original.healthCheck],['writable file',i=>i.files[0].mode=511],['wrong file owner',i=>i.files[0].uid=1000],
])('closed compiler rejects %s',(_name,mutate)=>{const input=fixture();mutate(input);expect(()=>compileObservedBusyboxDataLaunch(input)).toThrow();});
test('all declared episodes are emitted and uncompressible complete input cannot grow the cmdline cap',()=>{
 const i=fixture();i.plan.episodes.push({index:1,offsetMs:20000,durationMs:5000,sampleEveryMs:1000});const c=compileObservedBusyboxDataLaunch(i),s=unpack(c).source.toString();expect(c.snapshotCount).toBe(14);expect(s).toContain('obs_busybox_episode 0 ');expect(s).toContain('obs_busybox_episode 1 ');
 for(let n=0;n<200;n++){const path='/usr/lib/'+sha(Buffer.from(String(n)))+'.so';i.files.push({path,resolvedPath:path,sha256:sha(Buffer.from('content'+n)),size:100,mode:493,uid:0,gid:0});}
 expect(()=>compileObservedBusyboxDataLaunch(i)).toThrow('DataObservationSourceArgvBound');expect(i.files).toHaveLength(206);
});

const tool=process.env.MEM9_TEST_BUSYBOX,loader=process.env.MEM9_TEST_BUSYBOX_LOADER;
const q=s=>"'"+s.replaceAll("'","'\\''")+"'";
const mapped=s=>s.replace(/(^[a-z_]+=)\/bin\/busybox$/gm,(_,prefix)=>prefix+q(loader+' '+tool)).replaceAll('/bin/busybox',q(loader)+' '+q(tool));
function shell(source,args=[]){return spawnSync(loader,[tool,'sh','-s','--',...args],{input:source,env:{},encoding:'utf8',timeout:5000,maxBuffer:2097152});}
// These tests invoke protocol/cleanup functions directly at top level. The
// complete bootstrap's function-scope restoration is checked separately.
function definitions(){const c=compileObservedBusyboxDataLaunch(fixture());return mapped(unpack(c).source.toString().replace(/^local [^\n]+\n/,'').split('obs_loader_head=')[0]);}
test.runIf(!!tool&&!!loader)('complete original BusyBox source parses with retained shell',()=>{
 const {source}=unpack(compileObservedBusyboxDataLaunch(fixture())),r=spawnSync(loader,[tool,'sh','-n'],{input:source,env:{},encoding:'utf8',timeout:5000});expect(r.error).toBeUndefined();expect(r.status).toBe(0);expect(r.stderr).toBe('');
});
test.runIf(!!tool&&!!loader)('genuine decoder rejects wrong length, hash, CRC and unknown mode before any launch',()=>{
 const c=compileObservedBusyboxDataLaunch(fixture()),u=unpack(c);
 const crc=Buffer.from(u.compressed);crc[crc.length-8]^=1;
 for(const [name,p,status]of [
  ['valid source unknown mode',u.program,82],
  ['length',u.program.replace('obs_program_bytes='+u.source.length,'obs_program_bytes='+(u.source.length-1)),81],
  ['hash',u.program.replace(c.delivery.sourceHash,'0'.repeat(64)),81],
  ['trailer CRC',u.program.replace(u.encoded,crc.toString('base64')),81],
 ]){
  const r=spawnSync(loader,[tool,'sh','-c',mapped(p),'unknown'],{env:{},encoding:'utf8',timeout:5000});expect(r.error,name).toBeUndefined();expect(r.status,name).toBe(status);expect(r.stdout,name).toBe('');
 }
});
test.runIf(!!tool&&!!loader)('actual strict arm parser accepts single B/A pair and rejects trailing, duplicate and reordered bytes',()=>{
 const s=definitions(),nonce='c'.repeat(32);
 for(const [lines,success]of [
  [[`B|123|456|${nonce}`,`A|123|456|${nonce}`],true],
  [[`B|123|456|${nonce}|`],false],[[`A|123|456|${nonce}`],false],
  [[`B|123|456|${nonce}`,`B|123|456|${nonce}`],false],
  [[`B|123|456|${nonce}`,`A|124|456|${nonce}`],false],
  [[`B|123|456|${nonce}`,`E|123|456|${nonce}`],false],
 ]){
  const r=shell(s+'\n'+lines.map(l=>'obs_launch_record '+q(l)+' || exit 91').join('\n')+'\n');expect(r.error).toBeUndefined();expect(r.status).toBe(success?0:91);
 }
});
test.runIf(!!tool&&!!loader)('real original clock distinguishes deadline expiry from cancellation',()=>{
 const s=definitions(),r=shell(s+`
obs_launch_check 1; result=$?
[ "$result" -eq 2 ] || exit 92
obs_launch_cancelled=1
obs_launch_check 1; result=$?
[ "$result" -eq 1 ] || exit 93
`);expect(r.error).toBeUndefined();expect(r.status).toBe(0);
});
test.runIf(!!tool&&!!loader)('actual anonymous arm pipe preserves complete lines and rejects a partial record',()=>{
 const s=definitions(),nonce='c'.repeat(32);
 for(const [wire,status]of [[`B|123|456|${nonce}\n`,0],[`B|123|456|${nonce}`,94]]){
  const r=shell(s+`\nexec 3< <(printf '%s' ${q(wire)})\nobs_launch_read || exit 94\nexec 3<&-\nwait\n`);expect(r.error).toBeUndefined();expect(r.status).toBe(status);
 }
});
test.runIf(!!tool&&!!loader)('actual owned relay is terminated and reaped before cleanup completes',()=>{
 const r=shell(definitions()+`
OBS_DEADLINE=${Date.now()+5000}
obs_launch_polllimit=400
${q(loader)} ${q(tool)} sleep 30 &
child=$!
trap 'kill -TERM "$child" 2>/dev/null; wait "$child" 2>/dev/null' EXIT
obs_launch_relay=$child
obs_launch_identity "$child" || exit 95
obs_launch_relay_ticks=$OBS_LAUNCH_TICKS
obs_launch_birth=1
obs_launch_cleanup || exit 96
[ ! -e /proc/$child/stat ] || exit 97
trap - EXIT
`);expect(r.error).toBeUndefined();expect(r.status).toBe(0);expect(r.stdout).toBe('');
});
test.runIf(!!tool&&!!loader)('missing birth remains unknown cleanup despite reaping the real relay',()=>{
 const r=shell(definitions()+`
OBS_DEADLINE=${Date.now()+5000}
obs_launch_polllimit=400
${q(loader)} ${q(tool)} sleep 30 &
child=$!
trap 'kill -TERM "$child" 2>/dev/null; wait "$child" 2>/dev/null' EXIT
obs_launch_relay=$child
obs_launch_identity "$child" || exit 95
obs_launch_relay_ticks=$OBS_LAUNCH_TICKS
if obs_launch_cleanup; then exit 96; fi
[ ! -e /proc/$child/stat ] || exit 97
trap - EXIT
`);expect(r.error).toBeUndefined();expect(r.status).toBe(0);expect(r.stdout).toBe('');
});
test.runIf(!!tool&&!!loader)('mismatching original child ticks prevent a signal to that PID',()=>{
 const r=shell(definitions()+`
${q(loader)} ${q(tool)} sleep 30 &
child=$!
trap 'kill -TERM "$child" 2>/dev/null; wait "$child" 2>/dev/null' EXIT
obs_launch_identity "$child" || exit 95
wrong=$((OBS_LAUNCH_TICKS+1))
if obs_launch_kill "$child" "$wrong"; then exit 96; fi
kill -0 "$child" || exit 97
kill -TERM "$child"
wait "$child" 2>/dev/null || :
trap - EXIT
`);expect(r.error).toBeUndefined();expect(r.status).toBe(0);expect(r.stdout).toBe('');
});
test.runIf(!!tool&&!!loader)('expired relay join preserves ownership until genuine cleanup has reaped the child',()=>{
 const r=shell(definitions()+`
OBS_DEADLINE=${Date.now()+5000}
OBS_ARM_DEADLINE=1
obs_launch_polllimit=400
${q(loader)} ${q(tool)} sleep 30 &
child=$!
trap 'kill -TERM "$child" 2>/dev/null; wait "$child" 2>/dev/null' EXIT
obs_launch_relay=$child
obs_launch_identity "$child" || exit 95
obs_launch_relay_ticks=$OBS_LAUNCH_TICKS
obs_launch_birth=1
status=0; obs_launch_join_relay || status=$?
[ "$status" -eq 2 ] && [ "$obs_launch_relay" = "$child" ] || exit 96
kill -0 "$child" || exit 97
obs_launch_cleanup || exit 98
[ ! -e /proc/$child/stat ] || exit 99
trap - EXIT
`);expect(r.error).toBeUndefined();expect(r.status).toBe(0);expect(r.stdout).toBe('');
});
test.runIf(!!tool&&!!loader)('original exported variables are restored after the complete fixed observer scope returns',()=>{
 const {program,source}=unpack(compileObservedBusyboxDataLaunch(fixture())),head=/^obs_fixed_launch_main\(\)\{\n local ([^\n]+)\n/.exec(program);
 const sourceNames=/^local ([^\n]+)\n/.exec(source.toString())[1].split(' '),names=[...new Set([...head[1].split(' '),...sourceNames])];
 expect(names.every(n=>/^[A-Za-z_][A-Za-z0-9_]*$/.test(n))).toBe(true);
 const exports=names.map(n=>'export '+n+'=original').join('\n');
 const checks=names.map(n=>'[ "$'+n+'" = original ] || exit 96').join('\n');
 // Scope mechanics and exact fixed initializers only: no gate substitute,
 // no original application invocation, no successful runtime record.
 const r=shell(exports+'\nobs_fixed_launch_main(){\nlocal '+head[1]+'\n'+source.toString().split('obs_loader_head=')[0]+'\nreturn 0\n}\nobs_fixed_launch_main || exit 95\n'+checks+'\n');
 expect(r.error).toBeUndefined();expect(r.status).toBe(0);expect(r.stdout).toBe('');expect(r.stderr).toBe('');
});
test.runIf(!!tool&&!!loader)('relay and observer reconstruct byte-identical complete bootstrap source',()=>{
 const {program,source}=unpack(compileObservedBusyboxDataLaunch(fixture()));
 const prefix=program.slice(0,program.indexOf('obs_program=$('));
 const r=shell(prefix+source.toString().split('case "$0" in')[0]+'\nprintf "%s" "$obs_bootstrap"\n}\nobs_fixed_launch_main\n');
 expect(r.error).toBeUndefined();expect(r.status).toBe(0);expect(r.stderr).toBe('');expect(r.stdout).toBe(program);
});
test.runIf(!!tool&&!!loader)('SIGTERM during actual FD closure prevents normal success after trap restoration',()=>{
 const source=definitions(),close=/obs_launch_close\(\)\{[^\n]*\}/.exec(source)[0].replace('obs_launch_close(){','original_close(){');
 const r=shell(source+'\n'+close+`
obs_launch_close(){ original_close || return 1; kill -TERM "$$"; }
trap obs_launch_signal TERM INT PIPE
status=0; obs_launch_normal || status=$?
[ "$status" -ne 0 ] && [ "$obs_launch_cancelled" -eq 1 ] || exit 95
`);expect(r.error).toBeUndefined();expect(r.status).toBe(0);expect(r.stdout).toBe('');expect(r.stderr).toBe('');
});
test.runIf(!!tool&&!!loader).each(['missing','mismatched'])('expired cleanup retains %s relay identity without blocking wait',kind=>{
 const start=performance.now(),r=shell(definitions()+`
OBS_DEADLINE=1
obs_launch_polllimit=1
${q(loader)} ${q(tool)} sleep 0.6 &
child=$!
trap 'kill -TERM "$child" 2>/dev/null; wait "$child" 2>/dev/null' EXIT
obs_launch_relay=$child
obs_launch_identity "$child" || exit 95
obs_launch_relay_ticks=${kind==='missing'?"''":'$((OBS_LAUNCH_TICKS+1))'}
if obs_launch_cleanup; then exit 96; fi
[ "$obs_launch_relay" = "$child" ] || exit 97
kill -0 "$child" || exit 98
kill -TERM "$child"
wait "$child" 2>/dev/null || :
trap - EXIT
`);expect(r.error).toBeUndefined();expect(r.status).toBe(0);expect(performance.now()-start).toBeLessThan(300);
});
test.runIf(!!tool&&!!loader)('live mismatched helper is not waited on even with cleanup time remaining',()=>{
 const start=performance.now(),r=shell(definitions()+`
OBS_DEADLINE=${Date.now()+5000}
obs_launch_polllimit=400
${q(loader)} ${q(tool)} sleep 0.6 &
child=$!
trap 'kill -TERM "$child" 2>/dev/null; wait "$child" 2>/dev/null' EXIT
obs_launch_relay=$child
obs_launch_identity "$child" || exit 95
obs_launch_relay_ticks=$((OBS_LAUNCH_TICKS+1))
if obs_launch_cleanup; then exit 96; fi
[ "$obs_launch_relay" = "$child" ] || exit 97
kill -0 "$child" || exit 98
kill -TERM "$child"
wait "$child" 2>/dev/null || :
trap - EXIT
`);expect(r.error).toBeUndefined();expect(r.status).toBe(0);expect(performance.now()-start).toBeLessThan(300);
});
test.runIf(!!tool&&!!loader)('final child census respects the original deadline without catch-all wait',()=>{
 const start=performance.now(),r=shell(definitions()+`
obs_launch_polllimit=1
${q(loader)} ${q(tool)} sleep 0.6 &
child=$!
trap 'kill -TERM "$child" 2>/dev/null; wait "$child" 2>/dev/null' EXIT
status=0; obs_launch_no_children 1 || status=$?
[ "$status" -eq 2 ] || exit 95
kill -0 "$child" || exit 96
kill -TERM "$child"
wait "$child" 2>/dev/null || :
trap - EXIT
`);expect(r.error).toBeUndefined();expect(r.status).toBe(0);expect(performance.now()-start).toBeLessThan(300);
});
