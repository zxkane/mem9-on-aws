import {it,expect} from 'vitest';
import {spawn} from 'node:child_process';
import {mkdtemp,writeFile,rm,lstat} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {DOCKER_STDIN_SUPERVISOR_SOURCE as SOURCE} from './lib/production-nonroot-control-docker-supervisor.mjs';

async function fixture(use){
 const root=await mkdtemp(join(tmpdir(),'docker-subreaper-test-')),directory=await mkdtemp(join(root,'mem9-control-docker-'));
 try{for(const name of ['index.json','oci-layout'])await writeFile(join(directory,name),'{}',{mode:0o600});await use({root,directory});}
 finally{await rm(root,{recursive:true,force:true});}
}
function execute(source,directory,{extraArgs=[],extraEnv={},cancel=false}={}){
 return new Promise((resolve,reject)=>{
  const child=spawn('/usr/bin/python3',['-I','-B','-c',source,String(process.pid),directory,...extraArgs],{env:{PATH:'/usr/bin:/bin',HOME:directory,...extraEnv},stdio:['pipe','pipe','pipe','pipe','pipe']});
  const output=[],error=[],ack=[];let timeout;
  for(const [stream,chunks]of [[child.stdout,output],[child.stderr,error],[child.stdio[3],ack]])stream.on('data',chunk=>{chunks.push(chunk);if(cancel&&stream===child.stdout){clearTimeout(timeout);child.stdio[4].end('X');}});
  child.stdin.on('error',()=>{});child.stdio[4].on('error',()=>{});child.on('error',reject);
  if(cancel){child.stdin.write('partial');timeout=setTimeout(()=>child.stdio[4].end('X'),2000);}else child.stdin.end('synthetic-stdin');
  child.on('close',(status,signal)=>{clearTimeout(timeout);child.stdio[4].end();try{resolve({status,signal,pid:child.pid,stdout:Buffer.concat(output).toString(),stderr:Buffer.concat(error).toString(),terminal:JSON.parse(Buffer.concat(ack))});}catch(e){reject(e);}});
 });
}
async function fakeDocker(root,body){
 const path=join(root,'fixed-fixture-docker.py');
 await writeFile(path,'#!/usr/bin/python3\nimport os,sys,signal,time,json,errno\n'+body,{mode:0o700});
 // Trusted test-source substitution only. The production helper accepts no
 // executable override in argv, environment, stdin or its control channel.
 expect(SOURCE.split('DOCKER = "/usr/bin/docker"')).toHaveLength(2);
 return SOURCE.replace('DOCKER = "/usr/bin/docker"','DOCKER = '+JSON.stringify(path));
}
it('reaps a leader and two surviving descendants, including a descendant in another session',()=>fixture(async({root,directory})=>{
 const source=await fakeDocker(root,`
sys.stdin.buffer.read()
read_fd, write_fd = os.pipe()
child = os.fork()
if child == 0:
    os.close(read_fd)
    os.setsid()
    grandchild = os.fork()
    if grandchild != 0:
        os.write(write_fd, json.dumps([os.getpid(), grandchild]).encode())
    os.close(write_fd)
    for fd in [0, 1, 2]:
        os.close(fd)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    time.sleep(30)
    os._exit(9)
os.close(write_fd)
descendants = os.read(read_fd, 4096)
os.close(read_fd)
os.write(1, descendants)
os._exit(0)
`);
 const result=await execute(source,directory),t=result.terminal;
 expect(result.status).toBe(0);expect(result.signal).toBeNull();expect(t).toMatchObject({kind:'docker-stdin-subreaper-echild',supervisorPid:result.pid,leaderEnded:true,status:0,signal:null,cleanupComplete:true,reason:'DockerDescendantSurvived',reaped:3,killedDescendants:2});
 for(const pid of JSON.parse(result.stdout))await expect(lstat('/proc/'+pid)).rejects.toMatchObject({code:'ENOENT'});
}),10000);
it('fixed stdin reaches the child but supervisor channels and caller credentials do not',()=>fixture(async({root,directory})=>{
 const source=await fakeDocker(root,`
assert sys.argv[1:] == ["--host", "unix:///var/run/docker.sock", "--config", os.getcwd(), "image", "load"]
for fd in [3, 4]:
    try:
        os.fstat(fd)
        os._exit(70)
    except OSError as error:
        assert error.errno == errno.EBADF
assert set(os.environ).issubset({"PATH", "HOME", "DOCKER_CONFIG", "LANG", "LC_ALL", "LC_CTYPE"})
assert sys.stdin.buffer.read() == b"synthetic-stdin"
os.write(1, b"loaded fixture")
`);
 const r=await execute(source,directory,{extraEnv:{AWS_SECRET_ACCESS_KEY:'synthetic-not-secret',DOCKER_HOST:'tcp://example.com',PYTHONPATH:'/unreviewed'}});
 expect(r.stdout).toBe('loaded fixture');expect(r.stderr).toBe('');expect(r.terminal).toMatchObject({status:0,signal:null,reason:null,cleanupComplete:true,reaped:1,killedDescendants:0});
}),10000);
it('cancellation kills and reaps the original child while stdin remains open',()=>fixture(async({root,directory})=>{
 const source=await fakeDocker(root,'signal.signal(signal.SIGTERM, signal.SIG_IGN)\nos.write(1, b"READY")\nsys.stdin.buffer.read()\ntime.sleep(30)\n');
 const r=await execute(source,directory,{cancel:true});expect(r.terminal).toMatchObject({cleanupComplete:true,reason:'DockerStdinCancelled',leaderEnded:true,signal:'SIGKILL',reaped:1});
 await expect(lstat('/proc/'+r.terminal.leaderPid)).rejects.toMatchObject({code:'ENOENT'});
}),10000);
it('a pidfd for a foreign process is rejected before any signal',async()=>{
 const foreign=spawn('/usr/bin/python3',['-I','-c','import time; time.sleep(30)'],{stdio:'ignore'});
 try{
  const code=`namespace={"__name__":"fixture"}\nexec(${JSON.stringify(SOURCE)},namespace)\ntry:\n namespace["owned_signal"](${foreign.pid})\n raise RuntimeError("ForeignSignalAccepted")\nexcept ChildProcessError:\n print("foreign-rejected")\n`;
  const result=await new Promise((resolve,reject)=>{const child=spawn('/usr/bin/python3',['-I','-B','-c',code],{stdio:['ignore','pipe','pipe']}),out=[];child.stdout.on('data',b=>out.push(b));child.on('error',reject);child.on('close',status=>resolve({status,text:Buffer.concat(out).toString()}));});
  expect(result).toEqual({status:0,text:'foreign-rejected\n'});expect(foreign.exitCode).toBeNull();expect((await lstat('/proc/'+foreign.pid)).isDirectory()).toBe(true);
 }finally{foreign.kill('SIGKILL');await new Promise(resolve=>foreign.on('close',resolve));}
},10000);
it('rejects an executable override before starting any child',()=>fixture(async({directory})=>{
 const r=await execute(SOURCE,directory,{extraArgs:['--exec','/bin/sh']});expect(r.status).toBe(74);expect(r.stdout).toBe('');expect(r.terminal).toMatchObject({kind:'docker-stdin-subreaper-unconfirmed',cleanupComplete:false});
}),10000);
it('missing pidfd support rejects before the fixed child starts',()=>fixture(async({root,directory})=>{
 const source=(await fakeDocker(root,'os.write(1, b"MUST-NOT-START")\n')).replace('cancelled = False','cancelled = False\nos.pidfd_open = None');
 const r=await execute(source,directory);expect(r.status).toBe(74);expect(r.stdout).toBe('');expect(r.terminal).toMatchObject({kind:'docker-stdin-subreaper-unconfirmed',cleanupComplete:false});
}),10000);
