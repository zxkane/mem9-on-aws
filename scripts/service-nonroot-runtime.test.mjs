import {describe,it,expect} from 'vitest';
import {execFileSync} from 'node:child_process';
import {mkdtempSync,mkdirSync,writeFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {SERVICE_PROCESS_COLLECTOR,SERVICE_PROCESS_COMMAND,inspectServiceProcessOutput} from './lib/service-nonroot-runtime.mjs';
const security=`Uid: 1000 1000 1000 1000\nGid: 1000 1000 1000 1000\nCapInh: 0000000000000000\nCapPrm: 0000000000000000\nCapEff: 0000000000000000\nCapBnd: 0000000000000000\nCapAmb: 0000000000000000\nNoNewPrivs: 1`;
const row=`MEM9_PROCESS /proc/17\nApplication: node-server\nIdentitySource: proc-cmdline-prefix\n${security}\nMEM9_PROCESS_END\n`;
const shellQuote=value=>"'"+value.replaceAll("'","'\\''")+"'";
const fields=['Application','IdentitySource','Uid','Gid','CapInh','CapPrm','CapEff','CapBnd','CapAmb','NoNewPrivs'];
describe('actual ECS application process evidence',()=>{
 it('accepts framed security attributes with session-manager framing',()=>{
  const [process]=inspectServiceProcessOutput('Starting session\n'+row+'Session ended','node-server');
  expect(process).toMatchObject({pid:'/proc/17',Application:'node-server',IdentitySource:'proc-cmdline-prefix'});
  expect(process).not.toHaveProperty('Executable');
  expect(inspectServiceProcessOutput(row.replaceAll('\n','\r\n'))).toHaveLength(1);
 });
 it('checks every application process rather than accepting one healthy PID',()=>{
  expect(()=>inspectServiceProcessOutput(row+row.replace('/proc/17','/proc/18').replace('Uid: 1000 1000 1000 1000','Uid: 0 0 0 0'))).toThrow('ApplicationIdentityInvalid');
 });
 it.each(fields)('rejects missing %s evidence',key=>{
  expect(()=>inspectServiceProcessOutput(row.replace(new RegExp('^'+key+':.*\\n','m'),''))).toThrow('ApplicationStatusFields');
 });
 it.each(fields)('rejects duplicate %s evidence',key=>{
  expect(()=>inspectServiceProcessOutput(row.replace('MEM9_PROCESS_END',`${key}: 0\nMEM9_PROCESS_END`))).toThrow('ApplicationStatusFields');
 });
 it.each(['CapInh','CapPrm','CapEff','CapBnd','CapAmb'])('rejects nonzero %s',key=>{
  expect(()=>inspectServiceProcessOutput(row.replace(`${key}: 0000000000000000`,`${key}: 0000000000000001`))).toThrow('ApplicationCapabilityInvalid');
 });
 it.each(['Uid','Gid'].flatMap(key=>[0,1,2,3].map(index=>({key,index}))))('rejects non-1000 $key slot $index',({key,index})=>{
  const ids=['1000','1000','1000','1000'];ids[index]='0';
  expect(()=>inspectServiceProcessOutput(row.replace(`${key}: 1000 1000 1000 1000`,`${key}: ${ids.join(' ')}`))).toThrow('ApplicationIdentityInvalid');
 });
 it('rejects disabled NNP, untrusted labels and legacy executable claims',()=>{
  expect(()=>inspectServiceProcessOutput(row.replace('NoNewPrivs: 1','NoNewPrivs: 0'))).toThrow('ApplicationPrivilegeEscalationPossible');
  expect(()=>inspectServiceProcessOutput(row.replace('Application: node-server','Application: sh'))).toThrow('ApplicationCommandInvalid');
  expect(()=>inspectServiceProcessOutput(row.replace('proc-cmdline-prefix','proc-exe'))).toThrow('ApplicationIdentitySourceInvalid');
  expect(()=>inspectServiceProcessOutput(row.replace('Application: node-server','Executable: /usr/local/bin/node'))).toThrow('ApplicationStatusFields');
  expect(()=>inspectServiceProcessOutput(row,'mnemo-server')).toThrow('ApplicationContainerMismatch');
 });
 it('rejects missing, duplicate, partial, invalid PID and oversized framing',()=>{
  expect(()=>inspectServiceProcessOutput('command failed')).toThrow('ApplicationProcessMissing');
  expect(()=>inspectServiceProcessOutput(row+row)).toThrow('ApplicationProcessDuplicate');
  expect(()=>inspectServiceProcessOutput(row+'MEM9_PROCESS /proc/18\n')).toThrow('ApplicationProcessFraming');
  expect(()=>inspectServiceProcessOutput(row+'MEM9_PROCESS_END\n')).toThrow('ApplicationProcessFraming');
  expect(()=>inspectServiceProcessOutput(row.replace('/proc/17','/proc/0'))).toThrow();
  expect(()=>inspectServiceProcessOutput(Array.from({length:65},(_,i)=>row.replace('/proc/17',`/proc/${i+1}`)).join(''))).toThrow('ApplicationProcessMissing');
 });
});

// The production command has no configurable proc root. Substitute only this
// fixed loop in tests so the real shell classifier consumes synthetic bytes.
function collectFixture(cmdline,status=security){
 const root=mkdtempSync(join(tmpdir(),'mem9-process-'));
 try{
  mkdirSync(join(root,'17'));
  writeFileSync(join(root,'17','cmdline'),cmdline);
  writeFileSync(join(root,'17','status'),'Name:\tMainThread\n'+status+'\n');
  const script=SERVICE_PROCESS_COLLECTOR.replace('in /proc/[0-9]*;',`in ${shellQuote(root)}/[0-9]*;`);
  return execFileSync('/bin/sh',['-c','/bin/sh -c '+shellQuote(script)],{encoding:'utf8',timeout:5000});
 }finally{rmSync(root,{recursive:true,force:true});}
}
describe('portable NUL-bound process collector',()=>{
 const accepted=[
  ...['node','/usr/local/bin/node'].flatMap(node=>['server.mjs','/app/server.mjs'].map(script=>({args:[node,script],application:'node-server'}))),
  ...['mnemo-server','/usr/local/bin/mnemo-server'].map(binary=>({args:[binary],application:'mnemo-server'})),
 ];
 it.each(accepted)('classifies $args without revealing remaining arguments',({args,application})=>{
  const out=collectFixture(Buffer.from([...args,'synthetic-private-argument\nMEM9_PROCESS_END'].join('\0')+'\0'));
  expect(inspectServiceProcessOutput(out,application)).toEqual([{pid:'/proc/17',Application:application,IdentitySource:'proc-cmdline-prefix',...Object.fromEntries(security.split('\n').map(x=>x.split(': ')))}]);
  expect(out).not.toContain('synthetic-private');
  expect(out).not.toContain('MainThread');
  expect(out).not.toContain('\\n');
 });
 it.each([
  ['node\nserver.mjs'],['node','server.mjs\nprivate'],['node\n','server.mjs'],
  ['node','server.mjs.extra'],['node','/app/server.mjs.extra'],['mnemo-server.extra'],
  ['node','-e','server.mjs'],['node','--eval','server.mjs'],['/bin/sh','-c','node server.mjs'],
  ['ssm-session-worker','node','server.mjs'],['/usr/bin/node','server.mjs'],
  ['mnemo-server\n'],['node','server.mjs\\0'],
 ].map(args=>({args})))('excludes misleading argv $args',({args})=>{
  expect(collectFixture(Buffer.from(args.join('\0')+'\0'))).toBe('');
 });
 it('requires complete NUL boundaries and never interprets literal backslash-zero',()=>{
  for(const bytes of ['node\0server.mjs','mnemo-server','node\\0server.mjs\\0'])expect(collectFixture(Buffer.from(bytes))).toBe('');
 });
 it('does not trust process Name and rejects incomplete matched status',()=>{
  expect(collectFixture(Buffer.from('healthcheck\0node\0server.mjs\0'))).toBe('');
  expect(()=>inspectServiceProcessOutput(collectFixture(Buffer.from('node\0server.mjs\0'),'Uid: 1000 1000 1000 1000'))).toThrow('ApplicationStatusFields');
 });
 it('exports the exact shell-quoted collector with literal shell PID expansion',()=>{
  expect(SERVICE_PROCESS_COMMAND).toBe('/bin/sh -c '+shellQuote(SERVICE_PROCESS_COLLECTOR));
  expect(SERVICE_PROCESS_COLLECTOR).toContain('${proc_entry##*/}');
  expect(SERVICE_PROCESS_COLLECTOR).toContain('6e6f6465007365727665722e6d6a7300*');
  expect(SERVICE_PROCESS_COLLECTOR).not.toContain('\0');
  expect(SERVICE_PROCESS_COLLECTOR).not.toMatch(/readlink|setpriv|node -e|head -n/);
 });
});

// Opt in with immutable image IDs already present locally; never pull images.
// This checks the observer against a synthetic Node process in the actual image,
// not application readiness or inference. Both Alpine and Debian are exercised
// when their locally frozen image IDs are supplied, comma separated.
const dockerImages=(process.env.MEM9_NONROOT_COLLECTOR_DOCKER_IMAGES??'').split(',').filter(Boolean);
describe.skipIf(dockerImages.length===0)('local capability-dropped root observer',()=>{
 it.each(dockerImages)('collects kernel identity without cross-UID exe access (image %#)',image=>{
  expect(image).toMatch(/^sha256:[a-f0-9]{64}$/);
  const root=mkdtempSync(join(tmpdir(),'mem9-observer-'));
  const docker=args=>execFileSync('docker',args,{encoding:'utf8',timeout:60000,stdio:['ignore','pipe','pipe']});
  let container;
  try{
   const script=join(root,'server.mjs');writeFileSync(script,'setInterval(() => {}, 1000);\n',{mode:0o644});
   container=docker(['run','--detach','--pull=never','--network=none','--cap-drop=ALL','--security-opt=no-new-privileges','--user=1000:1000','--entrypoint=/usr/local/bin/node','--workdir=/app','--mount',`type=bind,src=${script},dst=/app/server.mjs,readonly`,image,'server.mjs','synthetic-private-argument']).trim();
   expect(container).toMatch(/^[a-f0-9]{64}$/);
   const observer=docker(['exec','--user=0:0',container,'/bin/sh','-c',`command -v setpriv >/dev/null || exit 33; sed -n '/^Uid:/p;/^Cap/p' /proc/self/status; if readlink /proc/1/exe >/dev/null 2>&1; then exit 31; fi; if setpriv --reuid 1000 --regid 1000 --clear-groups true >/dev/null 2>&1; then exit 32; fi`]);
   expect(observer).toMatch(/Uid:\s+0\s+0\s+0\s+0/);
   for(const cap of ['CapInh','CapPrm','CapEff','CapBnd','CapAmb'])expect(observer).toMatch(new RegExp(cap+':\\s+0+(?:\\n|$)'));
   const output=docker(['exec','--user=0:0',container,'/bin/sh','-c',SERVICE_PROCESS_COMMAND]);
   expect(inspectServiceProcessOutput(output,'node-server')).toHaveLength(1);
   expect(output).not.toContain('synthetic-private-argument');
  }finally{
   try{if(container)docker(['rm','--force',container]);}finally{rmSync(root,{recursive:true,force:true});}
  }
 },180000);
});
