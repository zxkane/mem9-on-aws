import {test} from 'vitest';
import assert from 'node:assert/strict';
import {createTargetProbe,decodeTargetProbeSample} from './lib/production-nonroot-target-probe.mjs';
const nonce='a'.repeat(64),deadlineMs=Date.now()+35000;
const paths=path=>[{path:path.slice(1),type:'file',uid:0,gid:0,mode:493,content:{sha256:'b'.repeat(64)}}];
const launch=name=>({containerName:name,prefix:[name==='mnemo-server'?'/bin/setpriv':'/usr/bin/setpriv','--no-new-privs','--'],healthLaunch:{kind:'fixed-health-nnp',before:name==='mnemo-server'?['CMD-SHELL','wget -q -O /dev/null http://localhost:8080/healthz || exit 1']:['CMD','node','/app/healthcheck.mjs'],after:name==='mnemo-server'?['CMD-SHELL','/bin/setpriv --no-new-privs -- /bin/sh -c health']:['CMD','/usr/bin/setpriv','--no-new-privs','--','node','/app/healthcheck.mjs']}});
test('mnemo selects authenticated BusyBox without requiring or invoking Node',()=>{
 const p=createTargetProbe({launch:launch('mnemo-server'),paths:paths('/bin/busybox'),nonce,deadlineMs});
 assert.match(p.command,/^\/bin\/busybox env -i /);assert(!p.command.includes('/usr/local/bin/node'));assert.equal(p.runtime,'busybox');
});
test('both Node sidecars require their real authenticated Node executable',()=>{
 for(const name of ['qwen3-embed','llm-proxy']){
  const p=createTargetProbe({launch:launch(name),paths:[...paths('/usr/local/bin/node'),...paths('/usr/bin/env')],nonce,deadlineMs});assert.equal(p.runtime,'node');
  assert.throws(()=>createTargetProbe({launch:launch(name),paths:paths('/bin/busybox'),nonce,deadlineMs}),/TargetProbeTool/);
 }
});
test('missing, writable or anonymous probe tools fail before any Exec',()=>{
 for(const value of [undefined,[],[{...paths('/bin/busybox')[0],mode:511}],[{...paths('/bin/busybox')[0],uid:1000}]])assert.throws(()=>createTargetProbe({launch:launch('mnemo-server'),paths:value,nonce,deadlineMs}),/TargetProbeTool/);
});
const hex=s=>Buffer.from(s).toString('hex');
function sample(){
 const stat=hex('1 (fixture) S 0 '+Array(17).fill('0').join(' ')+' 100\n');
 const row={pid:1,stat,statAfter:stat,status:hex('Uid:\t1000 1000 1000 1000\nGid:\t1000 1000 1000 1000\nGroups:\t\nNoNewPrivs:\t1\n'+['Inh','Prm','Eff','Bnd','Amb'].map(k=>'Cap'+k+':\t'+'0'.repeat(16)).join('\n')+'\n'),cmdlineHash:'c'.repeat(64),path:hex('/bin/busybox'),stamp:'1,2,1000,81ed,0,0,2026-01-01,2026-01-01',digest:'b'.repeat(64)};
 return {version:2,kind:'native-target-busybox-sample',nonce,probePid:1,startedSeconds:100,completedSeconds:101,initial:[row],final:[structuredClone(row)],health:structuredClone(row),healthObservedSeconds:100,readBytes:1000,chargedBytes:10000};
}
test('BusyBox parser keeps raw second precision and separates observed reads from conservative charge',()=>{
 const raw=sample(),decoded=decodeTargetProbeSample(raw,launch('mnemo-server'));
 assert.equal(decoded.startedMs,100000);assert.equal(decoded.healthObservedMs,100000);assert.equal(decoded.readBytes,1000);assert.equal(decoded.health.executablePath,'/bin/busybox');assert.equal(decoded.health.executableDigest,'sha256:'+'b'.repeat(64));assert.deepEqual(decoded.health.uid,[1000,1000,1000,1000]);assert.equal(raw.chargedBytes,10000);
});
test('BusyBox parser rejects incompatible runtimes, extra fields, changed processes and oversized records',()=>{
 for(const mutate of [r=>r.extra=true,r=>r.chargedBytes=256*1048576+1,r=>r.chargedBytes=999,r=>r.initial[0].statAfter=hex('1 (fixture) S 0 '+Array(17).fill('0').join(' ')+' 101\n'),r=>r.initial[0].status+=hex('Uid:\t0 0 0 0\n'),r=>r.initial[0].status='00'.repeat(65537),r=>r.initial[0].cmdline='secret',r=>r.initial[0].digest='x',r=>r.initial[0].stamp='1,2,1000,41ed,0,0,x,x']){const raw=sample();mutate(raw);assert.throws(()=>decodeTargetProbeSample(raw,launch('mnemo-server')));}
 assert.throws(()=>decodeTargetProbeSample(sample(),launch('qwen3-embed')),/TargetProbeRuntime/);
 assert.throws(()=>decodeTargetProbeSample({version:1,kind:'native-target-proc-sample'},launch('mnemo-server')));
});
