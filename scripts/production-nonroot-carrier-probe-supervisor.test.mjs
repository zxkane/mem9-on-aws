import {it,expect} from 'vitest';
import {spawn} from 'node:child_process';
import {mkdtemp,writeFile,rm,lstat} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {createHash} from 'node:crypto';
import {CARRIER_PROBE_SUPERVISOR_SOURCE} from './lib/production-nonroot-carrier-probe-supervisor.mjs';
import {getNonrootNativeProbeSource} from './lib/production-nonroot-control-prerequisites.mjs';

async function fixture(use){const directory=await mkdtemp(join(tmpdir(),'mem9-prerequisites-'));try{await use(directory);}finally{await rm(directory,{recursive:true,force:true});}}
async function run(directory,program,args=['image','inspect','sha256:'+'f'.repeat(64)]){
 const file=join(directory,'fake-docker.py');await writeFile(file,'#!/usr/bin/python3\nimport os,sys,time,signal,json,errno\n'+program,{mode:0o700});
 const source=CARRIER_PROBE_SUPERVISOR_SOURCE.replace('__PROBE_HASH__',getNonrootNativeProbeSource().sha256).replace('DOCKER = "/usr/bin/docker"','DOCKER = '+JSON.stringify(file)),raw=Buffer.from(JSON.stringify(args));
 return new Promise((resolve,reject)=>{const child=spawn('/usr/bin/python3',['-I','-B','-c',source,String(process.pid),directory,raw.toString('base64'),createHash('sha256').update(raw).digest('hex'),'5000'],{env:{PATH:'/usr/bin:/bin',AWS_SECRET_ACCESS_KEY:'synthetic-not-a-secret'},stdio:['ignore','pipe','pipe','pipe','pipe']}),out=[],err=[],ack=[];
  child.stdout.on('data',b=>out.push(b));child.stderr.on('data',b=>err.push(b));child.stdio[3].on('data',b=>ack.push(b));child.stdio[4].on('error',()=>{});child.on('error',reject);child.on('close',status=>{child.stdio[4].end();try{resolve({status,out:Buffer.concat(out).toString(),err:Buffer.concat(err).toString(),terminal:JSON.parse(Buffer.concat(ack))});}catch(e){reject(e);}});
 });
}
it('kills and reaps a real descendant after the probe CLI leader has exited',()=>fixture(async directory=>{
 const r=await run(directory,`
read_fd,write_fd=os.pipe()
child=os.fork()
if child==0:
 os.close(read_fd)
 os.setsid()
 signal.signal(signal.SIGTERM,signal.SIG_IGN)
 os.write(write_fd,b"READY")
 os.close(write_fd)
 for fd in [0,1,2]: os.close(fd)
 time.sleep(30)
 os._exit(0)
os.close(write_fd)
os.read(read_fd,5)
os.close(read_fd)
os.write(1,str(child).encode())
os._exit(0)
`);
 expect(r.terminal).toMatchObject({kind:'carrier-native-probe-subreaper-echild',cleanupComplete:true,reaped:2,killedDescendants:1,reason:'DockerDescendantSurvived'});await expect(lstat('/proc/'+r.out)).rejects.toMatchObject({code:'ENOENT'});
}),10000);
it('rejects commands outside the fixed probe grammar before child creation',()=>fixture(async directory=>{
 for(const args of [['run','--privileged','example'],['container','exec','a'.repeat(64),'sh'],['image','pull','example']]){const r=await run(directory,'os.write(1,b"MUST NOT RUN")\n',args);expect(r.out).toBe('');expect(r.status).toBe(74);expect(r.terminal.cleanupComplete).toBe(false);}
}),10000);
it('does not give Docker credentials or supervisor FDs',()=>fixture(async directory=>{
 const r=await run(directory,`
assert "AWS_SECRET_ACCESS_KEY" not in os.environ
assert sys.argv[1:5]==["--host","unix:///var/run/docker.sock","--config",os.getcwd()]
for fd in [3,4]:
 try:
  os.fstat(fd)
  os._exit(75)
 except OSError as error:
  assert error.errno==errno.EBADF
os.write(1,b"bounded-probe")
`);expect(r.out).toBe('bounded-probe');expect(r.err).toBe('');expect(r.terminal).toMatchObject({cleanupComplete:true,reason:null,status:0});
}),10000);
