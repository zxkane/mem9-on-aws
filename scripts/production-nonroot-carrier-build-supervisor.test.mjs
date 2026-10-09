import {it,expect} from 'vitest';
import {spawn} from 'node:child_process';
import {mkdtemp,mkdir,writeFile,lstat,rm} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {createHash} from 'node:crypto';
import {CARRIER_BUILD_SUPERVISOR_SOURCE as SOURCE} from './lib/production-nonroot-carrier-build-supervisor.mjs';

const sha=b=>createHash('sha256').update(b).digest('hex');
async function fixture(use){
 const root=await mkdtemp(join(tmpdir(),'carrier-supervisor-test-')),directory=join(root,'mem9-carrier-build-'+'a'.repeat(32)),context=join(root,'mem9-carrier-context-'+'b'.repeat(32));
 await mkdir(directory,{mode:0o700});await mkdir(context,{mode:0o700});for(const name of ['base','docker-config','output'])await mkdir(join(directory,name),{mode:0o700});
 const recipe='FROM synthetic\n',policy='{}',baseRootDigest='sha256:'+'c'.repeat(64);
 const plan={version:1,kind:'fixed-offline-carrier-build',baseRootDigest,baseImage:'123456789012.dkr.ecr.ap-northeast-1.amazonaws.com/mem9-on-aws/bootstrap@'+baseRootDigest,contextDirectory:context,deadlineMs:Date.now()+120000,dockerfileHash:sha(recipe),policyHash:sha(policy)};
 await writeFile(join(context,'Dockerfile'),recipe,{mode:0o444});await writeFile(join(directory,'source-policy.json'),policy,{mode:0o600});const raw=Buffer.from(JSON.stringify(plan));await writeFile(join(directory,'build-input.json'),raw,{mode:0o600});
 try{await use({root,directory,context,plan,inputHash:sha(raw)});}finally{await rm(root,{recursive:true,force:true});}
}
async function fake(x,body){const file=join(x.root,'fixed-fixture-docker.py');await writeFile(file,'#!/usr/bin/python3\nimport os,sys,signal,time,json,errno\n'+body,{mode:0o700});expect(SOURCE.split('DOCKER = "/usr/bin/docker"')).toHaveLength(2);return SOURCE.replace('DOCKER = "/usr/bin/docker"','DOCKER = '+JSON.stringify(file));}
function run(source,x,{cancel=false,extraEnv={},inputHash=x.inputHash}={}){
 return new Promise((resolve,reject)=>{
  const p=spawn('/usr/bin/python3',['-I','-B','-c',source,String(process.pid),x.directory,inputHash],{env:{PATH:'/usr/bin:/bin',...extraEnv},stdio:['ignore','pipe','pipe','pipe','pipe']}),out=[],err=[],ack=[];let timer;
  p.stdout.on('data',b=>{out.push(b);if(cancel)p.stdio[4].end('X');});p.stderr.on('data',b=>err.push(b));p.stdio[3].on('data',b=>ack.push(b));p.stdio[4].on('error',()=>{});p.on('error',reject);
  if(cancel)timer=setTimeout(()=>p.stdio[4].end('X'),1000);
  p.on('close',(status,signal)=>{clearTimeout(timer);p.stdio[4].end();try{resolve({status,signal,stdout:Buffer.concat(out).toString(),stderr:Buffer.concat(err).toString(),terminal:JSON.parse(Buffer.concat(ack))});}catch(e){reject(e);}});
 });
}
it('fixed build receives no credentials, arbitrary flags or supervisor control FDs',()=>fixture(async x=>{
 const source=await fake(x,`
args=sys.argv[1:]
assert args[:6]==["--host","unix:///var/run/docker.sock","--config",os.path.join(os.getcwd(),"docker-config"),"buildx","build"]
assert args[args.index("--network")+1]=="none"
assert args[args.index("--output")+1]=="type=oci,oci-artifact=true,dest=-"
assert args[args.index("--tag")+1]=="mem9-carrier-build:"+"a"*32
assert "--push" not in args and "--load" not in args
assert args[args.index("--build-context")+1].endswith("=oci-layout://"+os.path.join(os.getcwd(),"base")+"@sha256:"+"c"*64)
assert set(os.environ).issubset({"PATH","HOME","LANG","LC_ALL","LC_CTYPE","DOCKER_CONFIG","EXPERIMENTAL_BUILDKIT_SOURCE_POLICY","BUILDX_METADATA_PROVENANCE","BUILDX_NO_DEFAULT_LOAD"})
for fd in [3,4]:
 try:
  os.fstat(fd)
  os._exit(75)
 except OSError as error:
  assert error.errno==errno.EBADF
os.write(1,b"fixed-oci-output")
`);
 const r=await run(source,x,{extraEnv:{AWS_ACCESS_KEY_ID:'synthetic',AWS_SECRET_ACCESS_KEY:'synthetic',ACTIONS_RUNTIME_TOKEN:'synthetic',DOCKER_HOST:'tcp://example.com'}});
 expect(r.stdout).toBe('fixed-oci-output');expect(r.stderr).toBe('');expect(r.terminal).toMatchObject({cleanupComplete:true,reason:null,status:0,reaped:1});
}),10000);
it('reaps a real surviving descendant after the leader exits without relying on a recycled PGID',()=>fixture(async x=>{
 const source=await fake(x,`
ready_r,ready_w=os.pipe()
child=os.fork()
if child==0:
 os.close(ready_r)
 os.setsid()
 signal.signal(signal.SIGTERM,signal.SIG_IGN)
 os.write(ready_w,b"ready")
 os.close(ready_w)
 for fd in [0,1,2]: os.close(fd)
 time.sleep(30)
 os._exit(0)
os.close(ready_w)
os.read(ready_r,5)
os.close(ready_r)
os.write(1,str(child).encode())
os._exit(0)
`);
 const r=await run(source,x);expect(r.terminal).toMatchObject({cleanupComplete:true,reason:'DockerDescendantSurvived',status:0,reaped:2,killedDescendants:1});await expect(lstat('/proc/'+r.stdout)).rejects.toMatchObject({code:'ENOENT'});
}),10000);
it('cancellation waits for confirmed ECHILD',()=>fixture(async x=>{
 const r=await run(await fake(x,'signal.signal(signal.SIGTERM,signal.SIG_IGN)\nos.write(1,b"READY")\ntime.sleep(30)\n'),x,{cancel:true});
 expect(r.terminal).toMatchObject({cleanupComplete:true,reason:'DockerStdinCancelled',signal:'SIGKILL',reaped:1});await expect(lstat('/proc/'+r.terminal.leaderPid)).rejects.toMatchObject({code:'ENOENT'});
}),10000);
it('rejects a changed hashed plan before starting Docker',()=>fixture(async x=>{
 const r=await run(await fake(x,'os.write(1,b"MUST NOT RUN")\n'),x,{inputHash:'f'.repeat(64)});expect(r.stdout).toBe('');expect(r.status).toBe(74);expect(r.terminal.cleanupComplete).toBe(false);
}),10000);
it('an exhausted original deadline cannot become a fresh build window',()=>fixture(async x=>{
 const raw=Buffer.from(JSON.stringify({...x.plan,deadlineMs:Date.now()-1}));await writeFile(join(x.directory,'build-input.json'),raw,{mode:0o600});
 const r=await run(await fake(x,'os.write(1,b"MUST NOT RUN")\n'),x,{inputHash:sha(raw)});expect(r.stdout).toBe('');expect(r.status).toBe(74);
}),10000);
