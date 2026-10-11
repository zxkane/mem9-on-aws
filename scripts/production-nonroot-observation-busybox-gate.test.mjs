import {test,expect} from 'vitest';
import {spawnSync} from 'node:child_process';
import {busyboxObservationGateSource} from './lib/production-nonroot-observation-busybox-gate.mjs';

const file=()=>({path:'/bin/busybox',resolvedPath:'/bin/busybox',sha256:'a'.repeat(64),size:1,mode:493,uid:0,gid:0});
const source=()=>busyboxObservationGateSource([file()]);
test('BusyBox gate compiler embeds only closed immutable file metadata',()=>{
 const s=source();expect(s).toContain('/bin/busybox|/bin/busybox|'+'a'.repeat(64)+'|1|493|0|0');
 expect(s).not.toContain('@@FILES@@');expect(s).toContain('obs_gate_close || result=1');
 for(const mutate of [f=>f.path='/tmp/busybox',f=>f.path='/bin/busybox;id',f=>f.uid=1000,f=>f.mode=511,f=>f.callback='pass']){
  const f=file();mutate(f);expect(()=>busyboxObservationGateSource([f])).toThrow();
 }
});
test('BusyBox gate metadata getters are not executable input',()=>{
 let called=false;const f=file();Object.defineProperty(f,'sha256',{enumerable:true,get(){called=true;return 'a'.repeat(64);}});
 expect(()=>busyboxObservationGateSource([f])).toThrow();expect(called).toBe(false);
});

const tool=process.env.MEM9_TEST_BUSYBOX,loader=process.env.MEM9_TEST_BUSYBOX_LOADER,native=!!tool&&!!loader;
const q=s=>"'"+s.replaceAll("'","'\\''")+"'";
function evaluate(tail,syntax=false){
 const r=spawnSync(loader,[tool,'sh',...(syntax?['-n']:[])],{input:source()+'\n'+tail,env:{LC_ALL:'C'},encoding:'utf8',timeout:5000});
 expect(r.error).toBeUndefined();expect(r.signal).toBeNull();expect(r.stderr).toBe('');return r;
}
const held='10|/bin/busybox|/bin/busybox|1,20,1,81ed,0,0,original-mtime,original-ctime|'+'a'.repeat(64)+'|1|493\n'+
 '11|/lib/ld-musl-aarch64.so.1|/lib/ld-musl-aarch64.so.1|1,21,1,81ed,0,0,original-mtime,original-ctime|'+'b'.repeat(64)+'|1|493';
const maps='1000-2000 r-xp 0 00:01 20 /bin/busybox\n2000-3000 r-xp 0 00:01 21 /lib/ld-musl-aarch64.so.1';
test.runIf(native)('complete generated BusyBox gate parses using the retained shell',()=>expect(evaluate('',true).status).toBe(0));
test.runIf(native).each([
 ['verified mappings',maps],
 ['ordinary anonymous mappings',maps+'\n3000-4000 rw-p 0 00:00 0 [heap]'],
 ['exact io_uring class',maps+'\n3000-4000 rw-s 0 00:11 123 anon_inode:[io_uring]'],
])('native BusyBox maps classifier accepts %s',(_name,raw)=>{
 expect(evaluate('obs_gate_held='+q(held)+'\nobs_gate_maps '+q(raw)+'\nexit $?').status).toBe(0);
});
test.runIf(native).each([
 ['empty',''],
 ['wrong inode',maps.replace('00:01 20','00:01 999')],
 ['wrong device',maps.replace('00:01 20','00:02 20')],
 ['missing interpreter',maps.split('\n')[1]],
 ['non-executable interpreter',maps.replace('r-xp','r--p')],
 ['malformed row','not a maps row'],
 ['leading whitespace',' '+maps],
 ['unknown pseudo file',maps+'\n3000-4000 rw-s 0 00:11 123 anon_inode:[foreign]'],
 ['executable io_uring',maps+'\n3000-4000 rwxs 0 00:11 123 anon_inode:[io_uring]'],
 ['private io_uring',maps+'\n3000-4000 rw-p 0 00:11 123 anon_inode:[io_uring]'],
 ['nonzero io_uring major',maps+'\n3000-4000 rw-s 0 01:11 123 anon_inode:[io_uring]'],
 ['zero io_uring inode',maps+'\n3000-4000 rw-s 0 00:11 0 anon_inode:[io_uring]'],
 ['deleted mapped file',maps.replace('/bin/busybox','/bin/busybox (deleted)')],
])('native BusyBox maps classifier rejects %s',(_name,raw)=>{
 expect(evaluate('obs_gate_held='+q(held)+'\nobs_gate_maps '+q(raw)+'\nexit $?').status).toBe(1);
});
test.runIf(native)('native BusyBox retains full64-bit device and inode identity',()=>{
 const inode=String((1n<<60n)+1n),h=held.replace('1,20,','fedcb123456789ab,'+inode+','),m=maps.replace('00:01 20','fedcb789:123456ab '+inode);
 expect(evaluate('obs_gate_held='+q(h)+'\nobs_gate_maps '+q(m)+'\nexit $?').status).toBe(0);
 expect(evaluate('obs_gate_held='+q(h)+'\nobs_gate_maps '+q(m.replace(inode,String(BigInt(inode)+1n)))+'\nexit $?').status).toBe(1);
});
const status=['Name:\tsh','Uid:\t1000 1000 1000 1000','Gid:\t1000 1000 1000 1000','Groups:\t1000',...['Inh','Prm','Eff','Bnd','Amb'].map(k=>'Cap'+k+':\t0000000000000000'),'NoNewPrivs:\t1'].join('\n');
test.runIf(native)('native BusyBox status parser validates original complete security fields',()=>{
 // This overrides only the raw file-read seam, not the security predicate.
 expect(evaluate('obs_gate_read(){ OBS_GATE_TEXT='+q(status)+'; }\nobs_gate_status\nexit $?').status).toBe(0);
});
test.runIf(native).each([
 ['mixed uid',status.replace('1000 1000 1000 1000','1000 0 1000 1000')],
 ['extra group',status.replace('Groups:\t1000','Groups:\t1000 0')],
 ['missing NNP',status.replace('\nNoNewPrivs:\t1','')],
 ['NNP0',status.replace('NoNewPrivs:\t1','NoNewPrivs:\t0')],
 ['duplicate field',status+'\nNoNewPrivs:\t1'],
 ...['Inh','Prm','Eff','Bnd','Amb'].map(k=>['nonzero '+k,status.replace('Cap'+k+':\t0000000000000000','Cap'+k+':\t0000000000000001')]),
])('native BusyBox status parser rejects %s',(_name,raw)=>{
 expect(evaluate('obs_gate_read(){ OBS_GATE_TEXT='+q(raw)+'; }\nobs_gate_status\nexit $?').status).toBe(1);
});
