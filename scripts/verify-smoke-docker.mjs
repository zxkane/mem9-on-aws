import {execFileSync} from 'node:child_process';
import {constants,openSync,readSync,fstatSync,closeSync,mkdirSync,realpathSync,appendFileSync,existsSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {pathToFileURL} from 'node:url';

export const SMOKE_DOCKER_VERSION='29.9.0';
export const SMOKE_DOCKER_CONTEXT='setup-docker-action';
const need=(ok,code)=>{if(!ok)throw Error(code);};
const root=env=>{
 need(env.RUNNER_ENVIRONMENT==='github-hosted'&&typeof env.RUNNER_TEMP==='string'&&!/[\r\n\0]/.test(env.RUNNER_TEMP)&&resolve(env.RUNNER_TEMP)===env.RUNNER_TEMP,'SmokeDockerRunner');
 return join(env.RUNNER_TEMP,'mem9-smoke-docker');
};
export function validateSmokeDockerHostConfig(value){
 need(value&&typeof value==='object'&&!Array.isArray(value),'SmokeDockerHostConfig');
 for(const [key,v]of Object.entries(value)){
  const valid=key==='debug'?typeof v==='boolean':key==='log-level'?['debug','info','warn','error','fatal'].includes(v):
   key==='exec-opts'?Array.isArray(v)&&v.every(x=>['native.cgroupdriver=systemd','native.cgroupdriver=cgroupfs'].includes(x)):
   key==='features'?v&&typeof v==='object'&&!Array.isArray(v)&&Object.entries(v).every(([k,b])=>['buildkit','containerd-snapshotter'].includes(k)&&typeof b==='boolean'):
   ['max-concurrent-downloads','max-concurrent-uploads'].includes(key)&&Number.isSafeInteger(v)&&v>0&&v<=128;
  need(valid,'SmokeDockerSharedConfig');
 }
 return value;
}
function hostConfig(){
 let fd;try{fd=openSync('/etc/docker/daemon.json',constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);}catch(e){if(e.code==='ENOENT')return {};throw e;}
 try{
  const s=fstatSync(fd);need(s.isFile()&&s.uid===0&&s.nlink===1&&(s.mode&0o022)===0&&s.size<=65536,'SmokeDockerHostConfig');
  const bytes=Buffer.alloc(65537);let length=0,n;
  while(length<bytes.length&&(n=readSync(fd,bytes,length,bytes.length-length,null))>0)length+=n;
  const after=fstatSync(fd);need(length===s.size&&['dev','ino','size','mtimeMs','ctimeMs'].every(k=>s[k]===after[k]),'SmokeDockerHostConfig');return validateSmokeDockerHostConfig(JSON.parse(bytes.subarray(0,length).toString('utf8')));
 }finally{closeSync(fd);}
}
export function validateSmokeDockerEnvironment(env){
 const base=root(env),host=env.DOCKER_HOST;
 need(typeof host==='string'&&host.startsWith('unix://'+base+'/run-')&&/^run-[a-f0-9]{8}\/docker\.sock$/.test(host.slice(('unix://'+base+'/').length)),'SmokeDockerSocket');
 need(!env.DOCKER_CONTEXT&&!env.DOCKER_TLS_VERIFY&&!env.DOCKER_CERT_PATH&&!env.DOCKER_API_VERSION&&env.DOCKER_CONFIG===join(base,'client'),'SmokeDockerEnvironment');
 return {base,host};
}
export function validateSmokeDockerRuntime(env,version,info,contexts){
 const {host}=validateSmokeDockerEnvironment(env);
 for(const side of ['Client','Server']){
  const v=version?.[side],api=/^(\d+)\.(\d+)$/.exec(v?.ApiVersion??'');
  need(v?.Version===SMOKE_DOCKER_VERSION&&api&&(Number(api[1])>1||Number(api[1])===1&&Number(api[2])>=49),'SmokeDockerVersion');
 }
 need(info?.DriverStatus?.some(row=>Array.isArray(row)&&row[0]==='driver-type'&&row[1]==='io.containerd.snapshotter.v1'),'SmokeDockerImageStore');
 need(info.DockerRootDir===host.slice('unix://'.length).replace(/\/docker\.sock$/,'/data'),'SmokeDockerDataRoot');
 need(Array.isArray(contexts)&&contexts.length===1&&contexts[0].Name===SMOKE_DOCKER_CONTEXT&&contexts[0].Endpoints?.docker?.Host===host,'SmokeDockerContext');
 return {phase:'smoke-docker-ready',version:SMOKE_DOCKER_VERSION,containerd:true};
}
function main(env){
 const [mode,...rest]=process.argv.slice(2);need(rest.length===0&&['prepare','verify'].includes(mode),'SmokeDockerArguments');
 const base=root(env);
 if(mode==='prepare'){
  need(['DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH','DOCKER_CONFIG','DOCKER_API_VERSION'].every(k=>!env[k]),'SmokeDockerEnvironment');
  need(realpathSync(env.RUNNER_TEMP)===env.RUNNER_TEMP&&typeof env.GITHUB_ENV==='string'&&env.GITHUB_ENV,'SmokeDockerRunner');hostConfig();
  if(existsSync('/var/run/docker.sock'))need(execFileSync('docker',['--host','unix:///var/run/docker.sock','ps','--all','--quiet'],{encoding:'utf8',timeout:30000,maxBuffer:1048576}).trim()==='','SmokeDockerHostWorkloads');
  mkdirSync(base,{mode:0o700});mkdirSync(join(base,'client'),{mode:0o700});
  appendFileSync(env.GITHUB_ENV,'DOCKER_CONFIG='+join(base,'client')+'\n');return {phase:'smoke-docker-prepared'};
 }
 validateSmokeDockerEnvironment(env);
 const read=args=>JSON.parse(execFileSync('docker',args,{encoding:'utf8',timeout:30000,maxBuffer:1048576}));
 return validateSmokeDockerRuntime(env,read(['version','--format','{{json .}}']),read(['info','--format','{{json .}}']),read(['context','inspect',SMOKE_DOCKER_CONTEXT]));
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){try{console.log(JSON.stringify(main(process.env)));}catch(e){console.error(JSON.stringify({phase:'smoke-docker-held',code:/^SmokeDocker[A-Za-z]+$/.test(e.message)?e.message:'SmokeDockerSetupFailed'}));process.exitCode=1;}}
