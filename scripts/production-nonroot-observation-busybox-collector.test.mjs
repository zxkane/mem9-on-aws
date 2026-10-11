import {test,expect} from 'vitest';
import {spawnSync} from 'node:child_process';
import {readFileSync,statSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {busyboxObservationCollectorSource,decodeBusyboxObservationRows} from './lib/production-nonroot-observation-busybox-collector.mjs';

const sha=b=>createHash('sha256').update(b).digest('hex');
const hex=s=>Buffer.from(s).toString('hex');
const record=()=>({pid:42,stat:hex('42 (synthetic) '+['S','1',...Array(17).fill('0'),'100'].join(' ')),statAfter:hex('42 (synthetic) '+['S','1',...Array(17).fill('0'),'100'].join(' ')),
 status:hex(['Name:\tsynthetic','Pid:\t42','PPid:\t1','Uid:\t1000 1000 1000 1000','Gid:\t1000 1000 1000 1000','Groups:\t1000','NoNewPrivs:\t1',...['Inh','Prm','Eff','Bnd','Amb'].map(k=>'Cap'+k+':\t0000000000000000')].join('\n')+'\n'),
 cmdlineHash:'c'.repeat(64),path:hex('/bin/busybox'),stamp:'1,20,100,81ed,0,0,2026-01-01 00:00:00.000000000 +0000,2026-01-01 00:00:00.000000000 +0000',digest:'d'.repeat(64)});
test('collector row wrapper uses the real strict decoder and retains all observed identity fields',()=>{
 const p=decodeBusyboxObservationRows([record()])[0];expect(p).toMatchObject({pid:42,ppid:1,startTimeTicks:100,file:{device:'1',inode:'20'},cmdlineHash:'c'.repeat(64)});expect(Object.isFrozen(p)).toBe(true);
});
test('missing or duplicate pid rows and oversized outer array reject',()=>{
 for(const rows of [[],Array(129).fill(record()),[record(),record()],[{...record(),statAfter:hex('43 (other) S 1')}]] )expect(()=>decodeBusyboxObservationRows(rows)).toThrow();
});
test('collector row wrapper does not invoke array or row accessors',()=>{
 let touched=false;const r=record();Object.defineProperty(r,'pid',{enumerable:true,get(){touched=true;return 42;}});
 expect(()=>decodeBusyboxObservationRows([r])).toThrow();expect(touched).toBe(false);
 expect(()=>decodeBusyboxObservationRows(new Proxy([record()],{get(){touched=true;return 1;}}))).toThrow();expect(touched).toBe(false);
});
test('producer source is fixed and raw read allowance stays256MiB independently of movement accounting',()=>{
 expect(()=>busyboxObservationCollectorSource('callback')).toThrow();const source=busyboxObservationCollectorSource();
 expect(source).toContain('OBS_COLLECT_READ_BYTES+$1');expect(source).toContain('268435456');expect(source).toContain('OBS_COLLECT_MOVEMENT_BYTES');expect(source).not.toContain('/environ');
});

const tool=process.env.MEM9_TEST_BUSYBOX,loader=process.env.MEM9_TEST_BUSYBOX_LOADER,native=!!tool&&!!loader;
const q=s=>"'"+s.replaceAll("'","'\\''")+"'";
function actual(tail){
 const source='set -o pipefail\nobs_test_busybox(){ '+q(loader)+' '+q(tool)+' "$@"; }\n'+busyboxObservationCollectorSource().replace('obs_collect_bb=/bin/busybox','obs_collect_bb=obs_test_busybox')+
  '\nOBS_COLLECT_DEADLINE_MS='+(Date.now()+10000)+'\n'+tail;
 // Deliver code on the test child's stdin; no large source body enters its
 // cmdline. This is a local raw producer test, not a target launch selection.
 const r=spawnSync(loader,[tool,'sh','-s'],{env:{PATH:'/usr/bin:/bin',LC_ALL:'C'},input:source,encoding:'utf8',timeout:12000,maxBuffer:1048576});
 expect(r.error).toBeUndefined();expect(r.signal).toBeNull();expect(r.stderr).toBe('');return r;
}
test.runIf(native)('retained tool produces a genuine complete proc/file row accepted by active decoder',()=>{
 const r=actual('obs_collect_proc $$ || exit 71\nobs_collect_close || exit 72\nprintf \'{"row":%s,"readBytes":%s,"movementBytes":%s,"helpers":%s}\' "$OBS_COLLECT_ROW" "$OBS_COLLECT_READ_BYTES" "$OBS_COLLECT_MOVEMENT_BYTES" "$OBS_COLLECT_HELPERS"');
 expect(r.status).toBe(0);const v=JSON.parse(r.stdout),p=decodeBusyboxObservationRows([v.row])[0];
 expect(p.executablePath).toBe(loader);expect(p.executableDigest).toBe('sha256:'+sha(readFileSync(loader)));expect(p.file.inode).toBe(statSync(loader,{bigint:true}).ino.toString());
 expect(v.readBytes).toBeGreaterThan(statSync(loader).size);expect(v.readBytes).toBeLessThanOrEqual(268435456);expect(v.movementBytes).toBeGreaterThan(v.readBytes);expect(v.helpers).toBeGreaterThan(0);
 // Native host UID/NNP/caps are merely DATA; this test grants no target policy.
});
test.runIf(native)('retained tool bounds oversized proc input and closes its held files on rejection',()=>{
 const r=actual('if obs_collect_hex /dev/zero 32; then exit 70; fi\nobs_collect_close || exit 72\n[ "$OBS_COLLECT_READ_BYTES" -eq 33 ]');expect(r.status).toBe(0);
});
test.runIf(native)('retained tool refuses a read before exceeding the original raw allowance',()=>{
 const r=actual('OBS_COLLECT_READ_BYTES=268435456\nif obs_collect_hex /dev/zero 1; then exit 70; fi\n[ "$OBS_COLLECT_READ_BYTES" -eq 268435456 ]');expect(r.status).toBe(0);
});
