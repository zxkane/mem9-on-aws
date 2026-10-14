import {test} from 'vitest';
import assert from 'node:assert/strict';
import {decodeBusyboxObservationProcess} from './lib/production-nonroot-observation-busybox-records.mjs';

const hex=s=>Buffer.from(s).toString('hex');
const stat=(pid=73,ppid=5,start='101',name='worker ) nested (name')=>`${pid} (${name}) S ${ppid} ${Array(17).fill('0').join(' ')} ${start}\n`;
const caps=['Inh','Prm','Eff','Bnd','Amb'];
const status=()=>['Name:\tworker','Pid:\t73','PPid:\t5','Uid:\t1000 1000 1000 1000','Gid:\t1000 1000 1000 1000','Groups:\t1000','NoNewPrivs:\t1',...caps.map(k=>'Cap'+k+':\t'+'0'.repeat(16))].join('\n')+'\n';
const times=['2026-01-02 03:04:05.123456789 +0000','2026-01-02 03:04:06.987654321 +0000'];
const uint64=((1n<<64n)-1n).toString(),largeInode=((1n<<60n)+1n).toString();
const row=()=>({pid:73,stat:hex(stat()),statAfter:hex(stat()),status:hex(status()),cmdlineHash:'c'.repeat(64),path:hex('/usr/local/bin/mnemo-server'),
 stamp:[uint64,largeInode,'16384','81ed','0','0',...times].join(','),digest:'d'.repeat(64)});
const alterStatus=(r,fn)=>{r.status=hex(fn(Buffer.from(r.status,'hex').toString()));};
const stampField=(r,index,value)=>{const fields=r.stamp.split(',');fields[index]=value;r.stamp=fields.join(',');};

test('exact output preserves kernel identity, last-parenthesis parsing and uint64 file identity',()=>{
 const input=row(),before=structuredClone(input),got=decodeBusyboxObservationProcess(input);
 assert.deepEqual(got,{pid:73,ppid:5,startTimeTicks:101,executablePath:'/usr/local/bin/mnemo-server',executableDigest:'sha256:'+'d'.repeat(64),
  file:{mode:0o755,uid:0,gid:0,device:uint64,inode:largeInode},cmdlineHash:'c'.repeat(64),uid:[1000,1000,1000,1000],gid:[1000,1000,1000,1000],groups:[1000],noNewPrivs:1,
  ...Object.fromEntries(caps.map(k=>['cap'+k,'0'.repeat(16)]))});
 assert(Object.isFrozen(got)&&Object.isFrozen(got.file)&&Object.isFrozen(got.uid));assert.deepEqual(input,before);assert(!Object.hasOwn(got,'authority'));
});
test('root/mixed uint32 IDs, NNP0 and nonzero capabilities remain DATA for the independent policy verifier',()=>{
 const r=row();alterStatus(r,s=>s.replace('Uid:\t1000 1000 1000 1000','Uid:\t0 1 2 4294967295').replace('Gid:\t1000 1000 1000 1000','Gid:\t4294967295 2 1 0').replace('Groups:\t1000','Groups:\t0 4294967295').replace('NoNewPrivs:\t1','NoNewPrivs:\t0').replace('CapEff:\t'+'0'.repeat(16),'CapEff:\t'+'f'.repeat(16)));
 stampField(r,3,'89ed');stampField(r,4,'4294967295');const got=decodeBusyboxObservationProcess(r);
 assert.deepEqual(got.uid,[0,1,2,4294967295]);assert.deepEqual(got.groups,[0,4294967295]);assert.equal(got.noNewPrivs,0);assert.equal(got.capEff,'f'.repeat(16));assert.equal(got.file.mode,0o4755);assert.equal(got.file.uid,4294967295);
});
test('empty supplementary groups and zero device/inode are faithfully represented',()=>{
 const r=row();alterStatus(r,s=>s.replace('Groups:\t1000','Groups:\t'));stampField(r,0,'0');stampField(r,1,'0');const got=decodeBusyboxObservationProcess(r);
 assert.deepEqual(got.groups,[]);assert.equal(got.file.device,'0');assert.equal(got.file.inode,'0');
});
test('PID/PPID/start bindings reject mismatches and missing stat fields',()=>{
 for(const mutate of [r=>r.stat=hex(stat(74)),r=>r.statAfter=hex(stat(74)),r=>r.statAfter=hex(stat(73,6)),r=>r.statAfter=hex(stat(73,5,'102')),
  r=>r.stat=hex('73 (name) S 5 0\n'),r=>r.statAfter=hex('73 (name) S 5\n'),r=>alterStatus(r,s=>s.replace('Pid:\t73','Pid:\t74')),r=>alterStatus(r,s=>s.replace('PPid:\t5','PPid:\t6'))]){
  const r=row();mutate(r);assert.throws(()=>decodeBusyboxObservationProcess(r));
 }
});
test('safe integer maximum survives and unsafe/rounded identity numbers reject',()=>{
 const r=row();r.pid=Number.MAX_SAFE_INTEGER;r.stat=r.statAfter=hex(stat(r.pid,0,String(Number.MAX_SAFE_INTEGER)));alterStatus(r,s=>s.replace('Pid:\t73','Pid:\t'+r.pid).replace('PPid:\t5','PPid:\t0'));
 const got=decodeBusyboxObservationProcess(r);assert.equal(got.pid,r.pid);assert.equal(got.startTimeTicks,Number.MAX_SAFE_INTEGER);
 for(const bad of [0,-1,1.5,NaN,Infinity,Number.MAX_SAFE_INTEGER+1,'73'])assert.throws(()=>decodeBusyboxObservationProcess({...row(),pid:bad}));
 for(const n of ['0','-1','01',(BigInt(Number.MAX_SAFE_INTEGER)+1n).toString()]){const x=row();x.stat=x.statAfter=hex(stat(73,5,n));assert.throws(()=>decodeBusyboxObservationProcess(x));}
 for(const n of ['-1','05',(BigInt(Number.MAX_SAFE_INTEGER)+1n).toString()]){const x=row();x.stat=x.statAfter=hex(stat(73,n));assert.throws(()=>decodeBusyboxObservationProcess(x));}
});
test('statAfter may change non-identity fields without losing the PID/start binding',()=>{
 const r=row();r.statAfter=hex(stat(73,5,'101','renamed ) process'));assert.equal(decodeBusyboxObservationProcess(r).startTimeTicks,101);
});
test('every required status identity/capability field is mandatory and every duplicate rejects',()=>{
 for(const key of ['Pid','PPid','Uid','Gid','Groups','NoNewPrivs',...caps.map(k=>'Cap'+k)]){
  const r=row();alterStatus(r,s=>s.split('\n').filter(line=>!line.startsWith(key+':')).join('\n'));assert.throws(()=>decodeBusyboxObservationProcess(r));
 }
 for(const key of ['Name','Pid','Uid','NoNewPrivs','CapBnd']){const r=row();alterStatus(r,s=>s+s.split('\n').find(line=>line.startsWith(key+':'))+'\n');assert.throws(()=>decodeBusyboxObservationProcess(r));}
});
test('ID cardinality/uint32/lexical bounds and literal NNP reject permissive conversions',()=>{
 for(const value of ['','1000','1000 1000 1000','1000 1000 1000 1000 1000','-1 0 0 0','4294967296 0 0 0','01 0 0 0']){
  const r=row();alterStatus(r,s=>s.replace('Uid:\t1000 1000 1000 1000','Uid:\t'+value));assert.throws(()=>decodeBusyboxObservationProcess(r));
 }
 for(const value of ['-1','4294967296','1.5','+1','01']){const r=row();alterStatus(r,s=>s.replace('Groups:\t1000','Groups:\t'+value));assert.throws(()=>decodeBusyboxObservationProcess(r));}
 for(const value of ['','2','01','true','-0']){const r=row();alterStatus(r,s=>s.replace('NoNewPrivs:\t1','NoNewPrivs:\t'+value));assert.throws(()=>decodeBusyboxObservationProcess(r));}
});
test('large supplementary group set within the original64KiB status bound is retained',()=>{
 const groups=Array(4000).fill('4294967295').join(' '),r=row();alterStatus(r,s=>s.replace('Groups:\t1000','Groups:\t'+groups));
 assert(Buffer.from(r.status,'hex').length<=65536);assert.equal(decodeBusyboxObservationProcess(r).groups.length,4000);
});
test('hex and decoded raw byte bounds apply before decoding',()=>{
 for(const [key,cap] of [['stat',4096],['statAfter',4096],['status',65536],['path',4096]]){
  for(const bad of ['', 'a','GG','AB','00'.repeat(cap+1),Buffer.from('raw')]){const r=row();r[key]=bad;assert.throws(()=>decodeBusyboxObservationProcess(r));}
 }
});
test('exact raw boundaries remain supported without reducing the declared caps',()=>{
 const r=row(),s=stat().trimEnd();r.stat=r.statAfter=hex(s+' '.repeat(4096-s.length));
 const statusText=status(),padding='Z'.repeat(65536-statusText.length-'Padding:\t\n'.length);r.status=hex(statusText+'Padding:\t'+padding+'\n');
 r.path=hex('/'+'a'.repeat(4095));assert.equal(Buffer.from(r.stat,'hex').length,4096);assert.equal(Buffer.from(r.status,'hex').length,65536);assert.equal(Buffer.from(r.path,'hex').length,4096);
 assert.equal(decodeBusyboxObservationProcess(r).executablePath.length,4096);
});
test('malformed UTF8 and BOM prefixes are not repaired into original kernel/path data',()=>{
 for(const key of ['stat','statAfter','status','path']){const r=row();r[key]='ff';assert.throws(()=>decodeBusyboxObservationProcess(r));}
 for(const key of ['stat','path']){const r=row();r[key]='efbbbf'+r[key];assert.throws(()=>decodeBusyboxObservationProcess(r));}
});
test('canonical absolute executable paths preserve valid UTF8 and reject normalization/deleted/control tricks',()=>{
 const r=row();r.path=hex('/app/工具 worker');assert.equal(decodeBusyboxObservationProcess(r).executablePath,'/app/工具 worker');
 for(const path of ['relative','/','/usr//bin/app','/usr/./bin/app','/usr/../app','/app/','/app/x (deleted)','/app/a\\b','/app/a\n','/app/a\0','/app/a\t']){
  const x=row();x.path=hex(path);assert.throws(()=>decodeBusyboxObservationProcess(x));
 }
});
test('uint64 stamp bounds preserve precision and reject leading signs/zeros or overflow',()=>{
 for(const index of [0,1])for(const value of ['-1','+1','01','1.5',((1n<<64n)).toString()]){const r=row();stampField(r,index,value);assert.throws(()=>decodeBusyboxObservationProcess(r));}
 const a=row(),b=row();stampField(b,1,(BigInt(largeInode)+1n).toString());assert.notEqual(decodeBusyboxObservationProcess(a).file.inode,decodeBusyboxObservationProcess(b).file.inode);
});
test('regular file type, full mode width, size and file uid/gid are checked before narrowing',()=>{
 for(const [index,value] of [[2,'0'],[2,'201326593'],[2,((1n<<64n)).toString()],[3,'41ed'],[3,'a1ff'],[3,'100000000000081ed'],[3,'81ED'],[4,'-1'],[5,'4294967296']]){
  const r=row();stampField(r,index,value);assert.throws(()=>decodeBusyboxObservationProcess(r));
 }
 const r=row();stampField(r,2,'201326592');assert.equal(decodeBusyboxObservationProcess(r).file.mode,0o755);
});
test('stamp has exactly8 bounded fields with full time text and no control bytes',()=>{
 for(const mutate of [r=>r.stamp+=',extra',r=>r.stamp=r.stamp.split(',').slice(0,7).join(','),r=>r.stamp='x'.repeat(1025),r=>stampField(r,6,'x'),r=>stampField(r,7,'2026-01-02'),r=>stampField(r,7,times[1]+'\n')]){
  const r=row();mutate(r);assert.throws(()=>decodeBusyboxObservationProcess(r));
 }
});
test('hash and every capability require exact lowercase lengths',()=>{
 for(const key of ['digest','cmdlineHash'])for(const value of ['f'.repeat(63),'f'.repeat(65),'F'.repeat(64)])assert.throws(()=>decodeBusyboxObservationProcess({...row(),[key]:value}));
 for(const key of caps)for(const value of ['0','0'.repeat(17),'F'.repeat(16)]){const r=row();alterStatus(r,s=>s.replace('Cap'+key+':\t'+'0'.repeat(16),'Cap'+key+':\t'+value));assert.throws(()=>decodeBusyboxObservationProcess(r));}
});
test('exact inert input rejects unknown fields, callbacks, accessors and proxy traps without executing them',()=>{
 let calls=0;const r=row();Object.defineProperty(r,'pid',{enumerable:true,get(){calls++;return 73;}});assert.throws(()=>decodeBusyboxObservationProcess(r));assert.equal(calls,0);
 const proxy=new Proxy(row(),{get(){calls++;throw Error('trap');},getPrototypeOf(){calls++;throw Error('trap');},ownKeys(){calls++;throw Error('trap');}});assert.throws(()=>decodeBusyboxObservationProcess(proxy));assert.equal(calls,0);
 const revoked=Proxy.revocable(row(),{});revoked.revoke();assert.throws(()=>decodeBusyboxObservationProcess(revoked.proxy));
 for(const extra of [{authority:true},{readFile:()=>{calls++;}},{toJSON:()=>{calls++;}},{[Symbol('extra')]:1}])assert.throws(()=>decodeBusyboxObservationProcess({...row(),...extra}));
 const boxed=row();boxed.stat={toString(){calls++;return stat();}};assert.throws(()=>decodeBusyboxObservationProcess(boxed));assert.equal(calls,0);
 const nullPrototype=Object.assign(Object.create(null),row());assert.equal(decodeBusyboxObservationProcess(nullPrototype).pid,73);
});
test('malformed input diagnostics are bounded codes without raw fields',()=>{
 const r=row();r.stamp='private-marker';assert.throws(()=>decodeBusyboxObservationProcess(r),e=>/^BusyboxObservation[A-Za-z]+$/.test(e.message)&&!e.message.includes('private-marker'));
});
