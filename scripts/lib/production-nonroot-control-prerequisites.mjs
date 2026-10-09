/** Host-only, fixed local Docker probe. Graph/FS/source handles authenticate
 * inputs; JSON records returned here are measurements, not release authority. */
import {spawn} from 'node:child_process';
import {readFileSync} from 'node:fs';
import {mkdtemp,rm,lstat} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,posix} from 'node:path';
import {createHash,randomBytes} from 'node:crypto';
import {copyNonrootJson,parseNonrootJson,inspectNonrootRecord,nonrootHash as hash} from './production-nonroot-contracts.mjs';
import {NONROOT_FORBIDDEN_ENVIRONMENT} from './production-nonroot-launch.mjs';
import {controlImageGraphBinding,imageGraphState,readImageJson} from './production-image-graph.mjs';
import {inspectImageFilesystemEvidence,inspectImageFilesystemEntries,inspectImageFilesystemFile,readImageFilesystemFile,imageFilesystemVerificationKind} from './production-image-filesystem.mjs';
import {verifyControlSourceClosure,readControlSourceFile} from './production-control-source.mjs';

const states=new WeakMap(),sha=b=>createHash('sha256').update(b).digest('hex');
const sourcePath='scripts/lib/production-nonroot-control-prerequisites.mjs',sourceBytes=readFileSync(new URL(import.meta.url)),collectorCodeHash=sha(sourceBytes);
const need=(ok,code='NonrootPrerequisitesInvalid')=>{if(!ok)throw Object.assign(Error(code),{code,hold:true});};
const same=(a,b,code='NonrootPrerequisitesBinding')=>need(hash(a)===hash(b),code);
const exact=(v,keys)=>need(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===keys.slice().sort().join(),'NonrootPrerequisitesFields');
const canonical=p=>typeof p==='string'&&p.length<=4096&&/^\/[A-Za-z0-9_./+-]*$/.test(p)&&posix.normalize(p)===p&&(p==='/'||!p.endsWith('/'));
const imageOnly=({rootDigest,arm64Digest,configDigest})=>({rootDigest,arm64Digest,configDigest});
const capNames=['CapInh','CapPrm','CapEff','CapBnd','CapAmb'];
const loaderPaths=['/etc/ld.so.preload','/etc/ld.so.conf','/etc/ld.so.cache','/etc/ld-musl-aarch64.path'];
const cleanupError=()=>Object.assign(Error('ECLEANUP'),{code:'ECLEANUP',hold:true,cleanupConfirmed:false});

// Fixed AArch64 ELF, no libc/interpreter or external input. The instructions
// invoke PR_GET_NO_NEW_PRIVS, getuid/euid/gid/egid, PR_SET_NO_NEW_PRIVS(0), GET,
// setuid(0), setgid(0), the four identity reads and GET again, then write the
// fourteen signed 64-bit return values. syscall numbers follow asm-generic
// unistd.h (prctl=167, uid=174/175, gid=176/177, setuid=146, setgid=144).
// This measures kernel rejection, rather than mistaking CLI syntax rejection
// for an attempted NNP clear. Executed only in the bounded nosuid/nodev tmpfs.
const nativeCode=Buffer.from('ff0302d1f4030091e00480d2010080d2020080d2030080d2040080d2e81480d2010000d4800200f9000080d2010080d2020080d2030080d2040080d2c81580d2010000d4800600f9000080d2010080d2020080d2030080d2040080d2e81580d2010000d4800a00f9000080d2010080d2020080d2030080d2040080d2081680d2010000d4800e00f9000080d2010080d2020080d2030080d2040080d2281680d2010000d4801200f9c00480d2010080d2020080d2030080d2040080d2e81480d2010000d4801600f9e00480d2010080d2020080d2030080d2040080d2e81480d2010000d4801a00f9000080d2010080d2020080d2030080d2040080d2481280d2010000d4801e00f9000080d2010080d2020080d2030080d2040080d2081280d2010000d4802200f9000080d2010080d2020080d2030080d2040080d2c81580d2010000d4802600f9000080d2010080d2020080d2030080d2040080d2e81580d2010000d4802a00f9000080d2010080d2020080d2030080d2040080d2081680d2010000d4802e00f9000080d2010080d2020080d2030080d2040080d2281680d2010000d4803200f9e00480d2010080d2020080d2030080d2040080d2e81480d2010000d4803600f9200080d2e10314aa020e80d2080880d2010000d41fc001f1e0079f9aa80b80d2010000d4','hex');
function nativeElf(){
 const b=Buffer.alloc(128+nativeCode.length);Buffer.from('7f454c46020101000000000000000000','hex').copy(b);
 b.writeUInt16LE(2,16);b.writeUInt16LE(183,18);b.writeUInt32LE(1,20);b.writeBigUInt64LE(0x400080n,24);b.writeBigUInt64LE(64n,32);
 b.writeUInt16LE(64,52);b.writeUInt16LE(56,54);b.writeUInt16LE(1,56);b.writeUInt32LE(1,64);b.writeUInt32LE(5,68);
 b.writeBigUInt64LE(0x400000n,80);b.writeBigUInt64LE(0x400000n,88);b.writeBigUInt64LE(BigInt(b.length),96);b.writeBigUInt64LE(BigInt(b.length),104);b.writeBigUInt64LE(4096n,112);nativeCode.copy(b,128);return b;
}
const nativeBytes=nativeElf(),nativeProbeHash=sha(nativeBytes);

// Function source and the fixed native bytes are committed by collectorCodeHash.
// Only a bounded list of authenticated file paths crosses the probe interface.
// BEGIN FIXED CONTROL PREREQUISITES PROBE
async function fixedProbe(nativeBase64,paths,phase='parent'){
 const fs=await import('node:fs'),path=await import('node:path'),cp=await import('node:child_process');
 const requireFact=(ok,code)=>{if(!ok)throw Error(code);};
 const canon=p=>typeof p==='string'&&p.length<=4096&&/^\/[A-Za-z0-9_./+-]*$/.test(p)&&path.posix.normalize(p)===p;
 const small=p=>{const fd=fs.openSync(p,'r');try{const chunks=[],buffer=Buffer.alloc(8192);let size=0;for(;;){const n=fs.readSync(fd,buffer,0,buffer.length,null);if(!n)break;size+=n;requireFact(size<=262144,'ProbeReadLimit');chunks.push(Buffer.from(buffer.subarray(0,n)));}return Buffer.concat(chunks,size).toString('utf8');}finally{fs.closeSync(fd);}};
 const identity=()=>{
  const lines=new Map(small('/proc/self/status').split('\n').map(line=>{const i=line.indexOf(':');return [line.slice(0,i),line.slice(i+1).trim()];}));
  const ids=k=>(lines.get(k)??'').split(/\s+/).filter(Boolean).map(Number);
  const value={pid:process.pid,ppid:process.ppid,executablePath:fs.realpathSync('/proc/self/exe'),uid:ids('Uid'),gid:ids('Gid'),groups:ids('Groups'),noNewPrivs:Number(lines.get('NoNewPrivs'))};
  for(const key of ['CapInh','CapPrm','CapEff','CapBnd','CapAmb'])value[key]=lines.get(key);
  requireFact(value.uid.length===4&&value.gid.length===4&&[...value.uid,...value.gid,...value.groups].every(n=>n===1000)&&value.noNewPrivs===1&&['CapInh','CapPrm','CapEff','CapBnd','CapAmb'].every(k=>value[k]==='0000000000000000'),'ProbeIdentity');return value;
 };
 try{
  const initial=identity();requireFact(process.arch==='arm64'&&/^v24\.[0-9]+\.[0-9]+$/.test(process.version)&&initial.executablePath==='/usr/local/bin/node','ProbeNode');
  if(phase==='child'){process.stdout.write(JSON.stringify(initial));return;}
  requireFact(phase==='parent'&&Array.isArray(paths)&&paths.length<=512&&paths.every(canon),'ProbeInput');
  const loaderAbsences=['/etc/ld.so.preload','/etc/ld.so.conf','/etc/ld.so.cache','/etc/ld-musl-aarch64.path'];
  for(const p of loaderAbsences){try{fs.lstatSync(p);throw Error('ProbeLoaderPresent');}catch(e){requireFact(e.code==='ENOENT','ProbeLoaderPresent');}}
  const run=(file,args)=>{const r=cp.spawnSync(file,args,{env:{},encoding:null,stdio:['ignore','pipe','pipe'],timeout:15000,maxBuffer:262144,killSignal:'SIGKILL'});requireFact(!r.error&&r.signal===null&&r.status===0&&r.stderr.length===0,'ProbeChild'+path.posix.basename(file)+(r.error?.code??r.status));return r.stdout;};
  const childCode='('+fixedProbe.toString()+')('+JSON.stringify(nativeBase64)+',[],"child")';
  const child=JSON.parse(run('/usr/local/bin/node',['--input-type=module','-e',childCode]));
  requireFact(child.ppid===initial.pid&&child.pid!==initial.pid,'ProbeInheritance');
  const elfCache=new Map();let totalRead=0;
  const elf=input=>{
   requireFact(canon(input),'ProbeElfPath');const resolvedPath=fs.realpathSync(input);requireFact(canon(resolvedPath),'ProbeElfPath');if(elfCache.has(resolvedPath))return elfCache.get(resolvedPath);
   requireFact(elfCache.size<64,'ProbeElfCount');const fd=fs.openSync(input,'r');
   try{
    const stat=fs.fstatSync(fd);requireFact(stat.isFile()&&stat.size<=268435456,'ProbeElfFile');
    const read=(at,size)=>{requireFact(Number.isSafeInteger(at)&&at>=0&&Number.isSafeInteger(size)&&size>=0&&size<=65536&&at+size<=stat.size&&(totalRead+=size)<=2097152,'ProbeElfBounds');const b=Buffer.alloc(size);requireFact(fs.readSync(fd,b,0,size,at)===size,'ProbeElfShort');return b;};
    const number=(b,off)=>{const n=Number(b.readBigUInt64LE(off));requireFact(Number.isSafeInteger(n),'ProbeElfInteger');return n;};
    const h=read(0,64);requireFact(h.subarray(0,7).toString('hex')==='7f454c46020101'&&h.readUInt16LE(18)===183&&[2,3].includes(h.readUInt16LE(16))&&h.readUInt16LE(54)===56,'ProbeElfFormat');
    const count=h.readUInt16LE(56),phoff=number(h,32);requireFact(count>0&&count<=128,'ProbeElfHeaders');const headers=read(phoff,count*56),segments=[];
    for(let i=0;i<count;i++){const p=headers.subarray(i*56,(i+1)*56);segments.push({type:p.readUInt32LE(0),offset:number(p,8),address:number(p,16),size:number(p,32)});}
    const interps=segments.filter(p=>p.type===3),dynamic=segments.filter(p=>p.type===2);requireFact(interps.length<=1&&dynamic.length<=1,'ProbeElfSegments');
    const cstring=(b)=>{const end=b.indexOf(0);requireFact(end>=0,'ProbeElfString');return b.subarray(0,end).toString('utf8');};
    const interpreter=interps.length?cstring(read(interps[0].offset,interps[0].size)):null;requireFact(interpreter===null||interpreter==='/lib/ld-musl-aarch64.so.1','ProbeUnsupportedInterpreter');
    let needed=[],soname=null;
    if(dynamic.length){const d=read(dynamic[0].offset,dynamic[0].size);requireFact(d.length%16===0,'ProbeElfDynamic');const tags=[];let ended=false;
     for(let i=0;i<d.length;i+=16){const tag=number(d,i),value=number(d,i+8);if(tag===0){ended=true;break;}requireFact(tag!==15&&tag!==29,'ProbeUnsupportedRunpath');tags.push({tag,value});}
     requireFact(ended,'ProbeElfDynamic');const strings=tags.filter(t=>t.tag===5),sizes=tags.filter(t=>t.tag===10);requireFact(strings.length===1&&sizes.length===1,'ProbeElfStrings');
     const load=segments.filter(p=>p.type===1&&strings[0].value>=p.address&&strings[0].value+sizes[0].value<=p.address+p.size);requireFact(load.length===1,'ProbeElfStringRange');
     const text=offset=>{requireFact(offset<sizes[0].value,'ProbeElfStringRange');const value=cstring(read(load[0].offset+strings[0].value-load[0].address+offset,Math.min(512,sizes[0].value-offset)));requireFact(/^[A-Za-z0-9_.+-]+$/.test(value),'ProbeElfName');return value;};
     needed=tags.filter(t=>t.tag===1).map(t=>text(t.value));requireFact(needed.length<=64&&new Set(needed).size===needed.length,'ProbeElfDependencies');
     const names=tags.filter(t=>t.tag===14);requireFact(names.length<=1,'ProbeElfSoname');if(names.length)soname=text(names[0].value);
    }
    const out={path:input,resolvedPath,interpreter,needed,soname};elfCache.set(resolvedPath,out);return out;
   }finally{fs.closeSync(fd);}
  };
  const closure=executable=>{
   const main=elf(executable);requireFact(main.interpreter==='/lib/ld-musl-aarch64.so.1','ProbeDynamicMuslRequired');
   const text=run(main.interpreter,['--list',executable]).toString('utf8'),bindings=[],seen=new Set();
   for(const line of text.trim().split('\n')){const m=/^\s*(?:(\S+) => )?(\/[^\s]+) \([^\n]+\)$/.exec(line);requireFact(m&&canon(m[2]),'ProbeLoaderOutput');bindings.push({name:m[1]??path.posix.basename(m[2]),path:m[2]});seen.add(m[2]);}
   seen.add(main.interpreter);requireFact(seen.size<=64&&bindings.length<=128,'ProbeLoaderCount');const files=[...seen].sort().map(elf),names=new Set(bindings.map(b=>b.name));
   for(const e of [main,...files])for(const name of e.needed)requireFact(names.has(name),'ProbeDependencyUnresolved');
   return {executable:main,files,bindings};
  };
  const node=closure('/usr/local/bin/node'),primitive=closure('/bin/setpriv');
  const mapped=[...new Set(small('/proc/self/maps').split('\n').filter(Boolean).flatMap(line=>{const m=/^\S+\s+\S+\s+\S+\s+\S+\s+\S+(?:\s+(.+))?$/.exec(line.trimEnd());requireFact(m,'ProbeMaps');if(!m[1]||m[1].startsWith('['))return [];requireFact(canon(m[1]),'ProbeMapPath');return [fs.realpathSync(m[1])];}))].sort();
  const allowed=new Set([node.executable.resolvedPath,...node.files.map(f=>f.resolvedPath)]);requireFact(mapped.length>0&&mapped.every(p=>allowed.has(p)),'ProbeUnexpectedMappedFile');
  const nativePath='/tmp/mem9-fixed-native-probe';fs.writeFileSync(nativePath,Buffer.from(nativeBase64,'base64'),{flag:'wx',mode:0o700});
  let native;try{const raw=run(nativePath,[]);requireFact(raw.length===112,'ProbeNativeOutput');native=Array.from({length:14},(_,i)=>Number(raw.readBigInt64LE(i*8)));}finally{fs.unlinkSync(nativePath);}
  const requested=new Set(['/']);
  const add=p=>{requireFact(canon(p),'ProbePath');requested.add(p);while(p!=='/'){p=path.posix.dirname(p);requested.add(p);}};
  for(const p of [...paths,...node.files.map(f=>f.path),...primitive.files.map(f=>f.path),'/usr/local/bin/node','/bin/setpriv']){add(p);add(fs.realpathSync(p));let current='';for(const part of p.split('/').filter(Boolean)){current+='/'+part;add(fs.realpathSync(current));}}
  requireFact(requested.size<=512,'ProbePathCount');const observations=[...requested].sort().map(p=>{const s=fs.lstatSync(p);requireFact(s.isFile()||s.isDirectory()||s.isSymbolicLink(),'ProbePathType');return {path:p,resolvedPath:fs.realpathSync(p),type:s.isSymbolicLink()?'symlink':s.isDirectory()?'directory':'file',mode:s.mode&0o7777,uid:s.uid,gid:s.gid};});
  const out=JSON.stringify({version:1,kind:'control-native-prerequisites',nodeVersion:process.version,architecture:process.arch,identity:initial,child,native,node,primitive,mapped,observations,loaderAbsences,finalIdentity:identity()});requireFact(Buffer.byteLength(out)<=262144,'ProbeOutputLimit');process.stdout.write(out+'\n');
 }catch(error){process.stderr.write('NonrootPrerequisitesProbeRejected:'+String(error.message).replace(/[^A-Za-z0-9]/g,'').slice(0,80)+'\n');process.exitCode=1;}
}
// END FIXED CONTROL PREREQUISITES PROBE
// Read literal reviewed source, not a bundler/test runner's transformed
// Function.toString(). No caller input can select or replace this program.
const probeSource=sourceBytes.toString('utf8').split('// BEGIN FIXED CONTROL PREREQUISITES PROBE\n')[1]?.split('// END FIXED CONTROL PREREQUISITES PROBE\n')[0];
need(probeSource?.startsWith('async function fixedProbe('),'NonrootPrerequisitesProbeSource');
const probeCode='('+probeSource.trim()+')('+JSON.stringify(nativeBytes.toString('base64'))+',JSON.parse(process.argv[1]))';
const probeCodeHash=sha(probeCode);

// Same bounded positive process-group exit discipline as the path observer.
// Internal host transport shared by the two fixed collectors. This function
// creates no evidence/authority; callers must supply their code-owned argv.
export function runNonrootControlDockerCommand(args,{directory,timeoutMs,signal}){
 return new Promise((resolve,reject)=>{
  const child=spawn('/usr/bin/docker',['--host','unix:///var/run/docker.sock','--config',directory,...args],{cwd:directory,env:{PATH:'/usr/bin:/bin',HOME:directory,DOCKER_CONFIG:directory,LANG:'C',LC_ALL:'C'},detached:true,stdio:['ignore','pipe','pipe']});
  const out=[],err=[];let size=0,closed=false,finished=false,problem,status,timer,drainTimer;
  const alive=()=>{if(!child.pid)return false;try{process.kill(-child.pid,0);return true;}catch(e){if(e.code==='ESRCH')return false;throw e;}};
  const kill=()=>{try{if(child.pid)process.kill(-child.pid,'SIGKILL');}catch(e){if(e.code!=='ESRCH')problem=cleanupError();}};
  const finish=()=>{if(finished)return;finished=true;clearTimeout(timer);clearTimeout(drainTimer);signal?.removeEventListener('abort',abort);if(problem)reject(problem);else resolve({status,stdout:Buffer.concat(out).toString('utf8'),stderr:Buffer.concat(err).toString('utf8')});};
  const drain=until=>{if(finished)return;let exists=true;try{exists=alive();}catch{}if(closed&&!exists)return finish();if(Date.now()>=until){problem=cleanupError();return finish();}drainTimer=setTimeout(()=>drain(until),10);};
  const stop=code=>{problem??=Object.assign(Error(code),{code});kill();clearTimeout(drainTimer);drain(Date.now()+1000);};
  const abort=()=>stop('NonrootPrerequisitesAborted'),collect=chunks=>b=>{size+=b.length;if(size>1048576)stop('NonrootPrerequisitesOutputLimit');else chunks.push(b);};
  child.stdout.on('data',collect(out));child.stderr.on('data',collect(err));
  child.on('error',()=>{closed=true;problem??=Error('NonrootPrerequisitesDockerUnavailable');if(child.pid)stop('ECLEANUP');else finish();});
  child.on('close',code=>{closed=true;status=code;try{if(alive())stop('NonrootPrerequisitesDescendant');else finish();}catch{problem=cleanupError();finish();}});
  timer=setTimeout(()=>stop('NonrootPrerequisitesTimeout'),timeoutMs);signal?.addEventListener('abort',abort,{once:true});if(signal?.aborted)abort();
 });
}

async function preflight(value,options){
 const input=copyNonrootJson(value);exact(input,['image','sourceClosure']);const expected=copyNonrootJson(options.expected);exact(expected,['candidateTree']);
 const {graph,filesystem}=options.controlVerification??{},binding=controlImageGraphBinding(graph),fs=inspectImageFilesystemEvidence(filesystem);
 same(input.image,((({graphHash,...image})=>image)(binding)));need(fs.component==='bootstrap'&&fs.graphHash===binding.graphHash&&imageFilesystemVerificationKind(filesystem)==='live-filesystem-evidence','NonrootPrerequisitesFilesystem');
 need(options.sourceContext?.tree===expected.candidateTree&&input.sourceClosure.tree===expected.candidateTree,'NonrootPrerequisitesSource');
 await verifyControlSourceClosure(options.sourceContext,input.sourceClosure);
 need(input.sourceClosure.files.length>0,'NonrootPrerequisitesSource');
 const own=await readControlSourceFile(options.sourceContext,sourcePath);need(own.file.sha256===collectorCodeHash&&own.bytes.equals(sourceBytes),'NonrootPrerequisitesCollectorSource');
 const entries=inspectImageFilesystemEntries(filesystem),nodes=new Map(entries.map(e=>[e.path,e]));
 // Resolve every intermediate symlink before declaring a loader path absent.
 // Preserve '..' until expansion; normalization alone can skip a real hop.
 const exists=path=>{let pending=path.split('/').filter(Boolean),parts=[],links=0,steps=0;while(pending.length){need(++steps<=512,'NonrootPrerequisitesLoaderPath');const part=pending.shift();if(part==='.')continue;if(part==='..'){need(parts.length>0,'NonrootPrerequisitesLoaderPath');parts.pop();continue;}const node=nodes.get([...parts,part].join('/'));if(!node)return false;if(node.type==='symlink'){need(++links<=40,'NonrootPrerequisitesLoaderPath');if(!pending.length)return true;if(node.link.startsWith('/'))parts=[];pending=[...node.link.split('/').filter(Boolean),...pending];}else{parts.push(part);if(pending.length)need(node.type==='directory','NonrootPrerequisitesLoaderPath');}}return true;};
 for(const p of loaderPaths)need(!exists(p),'NonrootPrerequisitesLoaderFile');
 const files=new Map();
 const file=(path,executable=false)=>{const f=inspectImageFilesystemFile(filesystem,path);need(f.uid===0&&f.gid===0&&(f.mode&0o6022)===0&&!f.privilegeAttributes.length&&(executable?f.mode===0o755:(f.mode&0o004)!==0),'NonrootPrerequisitesFilePermissions');files.set(path,f);return f;};
 file('/usr/local/bin/node',true);file('/bin/setpriv',true);file('/lib/ld-musl-aarch64.so.1');
 for(const f of input.sourceClosure.files){if(f.path.startsWith('docker/bootstrap/')){const actual=file('/bootstrap/'+f.path.slice('docker/bootstrap/'.length));need(actual.sha256===f.sha256,'NonrootPrerequisitesSourceFile');}}
 const state=imageGraphState(graph),descriptor=state.images.get('bootstrap').config,config=await readImageJson(state.store.open(descriptor),{maxBytes:8388608,budget:state.budget});
 need(descriptor.digest===binding.configDigest&&config.architecture==='arm64'&&config.os==='linux'&&!Object.keys(config.config?.Volumes??{}).length,'NonrootPrerequisitesImageConfig');
 const env=config.config?.Env??[],seen=new Set();let ca;
 need(Array.isArray(env)&&env.length<=32,'NonrootPrerequisitesEnvironment');
 for(const item of env){need(typeof item==='string'&&item.length<=4096&&item.includes('='),'NonrootPrerequisitesEnvironment');const i=item.indexOf('='),key=item.slice(0,i),v=item.slice(i+1);need(!seen.has(key)&&!key.startsWith('LD_')&&!NONROOT_FORBIDDEN_ENVIRONMENT.includes(key)&&['PATH','HOME','NODE_VERSION','YARN_VERSION','NODE_EXTRA_CA_CERTS'].includes(key),'NonrootPrerequisitesEnvironment');seen.add(key);
  if(key==='PATH')need(v.split(':').every(canonical),'NonrootPrerequisitesEnvironment');else if(key==='HOME')need(v==='/tmp','NonrootPrerequisitesEnvironment');else if(key==='NODE_EXTRA_CA_CERTS'){need(['/bootstrap/global-bundle.pem','/app/global-bundle.pem'].includes(v),'NonrootPrerequisitesCa');ca=file(v);need(ca.resolvedPath===v,'NonrootPrerequisitesCa');}else need(/^\d+\.\d+\.\d+$/.test(v),'NonrootPrerequisitesEnvironment');
 }
 const paths=new Set(['/']);for(const f of files.values())for(const p of [f.path,f.resolvedPath,...f.parents.map(r=>r.path),...f.symlinkChain.map(r=>r.path)])paths.add(p);
 need(paths.size<=512&&[...paths].every(canonical),'NonrootPrerequisitesPaths');
 return {input,graph,filesystem,binding,fs,config,files,file,paths:[...paths].sort(),ca,nodes,sourceContext:options.sourceContext};
}
function checkImage(raw,p,platform=false){
 need(Array.isArray(raw)&&raw.length===1,'NonrootPrerequisitesDockerImage');const v=raw[0],wanted=platform?p.binding.arm64Digest:p.binding.rootDigest;
 need(v.Os==='linux'&&v.Architecture==='arm64','NonrootPrerequisitesDockerImage');
 if(v.Descriptor)need(v.Descriptor.digest===wanted&&v.Id===wanted,'NonrootPrerequisitesDockerImage');else need(v.Id===p.binding.configDigest&&v.RepoDigests?.some(d=>d.endsWith('@'+p.binding.rootDigest)),'NonrootPrerequisitesDockerImage');
 same(v.Config,p.config.config);same(v.RootFS,{Type:'layers',Layers:p.config.rootfs.diff_ids});return v;
}
function checkContainer(raw,p,{id,name,args},exited){
 need(Array.isArray(raw)&&raw.length===1,'NonrootPrerequisitesContainer');const v=raw[0],c=v.Config,h=v.HostConfig;
 need(v.Id===id&&v.Name==='/'+name&&c.Image===p.binding.rootDigest&&c.User==='1000:1000'&&c.Labels?.['mem9-prerequisites-probe']===name,'NonrootPrerequisitesContainerIdentity');
 need([p.binding.configDigest,p.binding.rootDigest,p.binding.arm64Digest].includes(v.Image),'NonrootPrerequisitesContainerImage');
 if(v.ImageManifestDescriptor)need(v.ImageManifestDescriptor.digest===p.binding.arm64Digest,'NonrootPrerequisitesContainerImage');else need(v.Image===p.binding.configDigest,'NonrootPrerequisitesContainerImage');
 same(c.Entrypoint,['/bin/setpriv']);same(c.Cmd,args);same(c.Env,p.config.config?.Env??[]);
 need(h.NetworkMode==='none'&&h.ReadonlyRootfs===true&&h.Privileged===false&&h.PublishAllPorts===false&&h.PidMode!=='host'&&h.IpcMode!=='host'&&h.UTSMode!=='host'&&!h.UsernsMode,'NonrootPrerequisitesIsolation');
 same(h.CapDrop,['ALL']);need(!h.CapAdd?.length&&h.SecurityOpt?.length===1&&['no-new-privileges','no-new-privileges:true'].includes(h.SecurityOpt[0]),'NonrootPrerequisitesIsolation');
 need(h.PidsLimit===32&&h.Memory===268435456&&h.NanoCpus===1000000000&&h.RestartPolicy?.Name==='no'&&c.Healthcheck?.Test?.[0]==='NONE','NonrootPrerequisitesIsolation');
 for(const key of ['Binds','Devices','DeviceRequests','VolumesFrom'])need(!h[key]?.length,'NonrootPrerequisitesMount');
 same(h.Tmpfs,{'/tmp':'rw,nosuid,nodev,exec,size=1048576,uid=1000,gid=1000,mode=0700'});need(v.Mounts?.length===0||v.Mounts?.length===1&&v.Mounts[0].Type==='tmpfs'&&v.Mounts[0].Destination==='/tmp','NonrootPrerequisitesMount');
 need(v.State.Running===false&&v.State.Status===(exited?'exited':'created'),'NonrootPrerequisitesContainerState');
 if(exited)need(v.State.ExitCode===0&&v.State.Pid===0&&v.State.OOMKilled===false&&!v.State.Error,'NonrootPrerequisitesExit');return v;
}
function validate(raw,p){
 const result=parseNonrootJson(raw,{maxBytes:262144});exact(result,['version','kind','nodeVersion','architecture','identity','child','native','node','primitive','mapped','observations','loaderAbsences','finalIdentity']);
 same(result.loaderAbsences,loaderPaths,'NonrootPrerequisitesLoaderFile');
 need(result.version===1&&result.kind==='control-native-prerequisites'&&/^v24\.[0-9]+\.[0-9]+$/.test(result.nodeVersion)&&result.architecture==='arm64','NonrootPrerequisitesProbe');
 const declaredVersion=p.config.config?.Env?.find(e=>e.startsWith('NODE_VERSION='));if(declaredVersion)need(declaredVersion.slice(13)===result.nodeVersion.slice(1),'NonrootPrerequisitesNodeVersion');
 for(const identity of [result.identity,result.child,result.finalIdentity]){
  exact(identity,['pid','ppid','executablePath','uid','gid','groups','noNewPrivs',...capNames]);need(Number.isSafeInteger(identity.pid)&&identity.pid>0&&identity.executablePath==='/usr/local/bin/node'&&identity.uid.length===4&&identity.gid.length===4&&[...identity.uid,...identity.gid,...identity.groups].every(n=>n===1000)&&identity.noNewPrivs===1&&capNames.every(k=>identity[k]==='0000000000000000'),'NonrootPrerequisitesIdentity');
 }
 same(result.finalIdentity,result.identity);need(result.child.ppid===result.identity.pid&&result.child.pid!==result.identity.pid,'NonrootPrerequisitesInheritance');
 same(result.native,[1,1000,1000,1000,1000,-22,1,-1,-1,1000,1000,1000,1000,1],'NonrootPrerequisitesNativeChecks');
 for(const [key,path]of [['node','/usr/local/bin/node'],['primitive','/bin/setpriv']]){
  const c=result[key];exact(c,['executable','files','bindings']);need(c.executable.path===path&&c.executable.interpreter==='/lib/ld-musl-aarch64.so.1'&&c.files.length>0&&c.files.length<=64,'NonrootPrerequisitesDependencies');
  for(const row of [c.executable,...c.files]){exact(row,['path','resolvedPath','interpreter','needed','soname']);const f=p.file(row.path,row===c.executable);need(f.resolvedPath===row.resolvedPath,'NonrootPrerequisitesDependencyBinding');}
 }
 const observations=new Map();need(result.observations.length>0&&result.observations.length<=512,'NonrootPrerequisitesObservations');
 for(const row of result.observations){exact(row,['path','resolvedPath','type','mode','uid','gid']);need(canonical(row.path)&&canonical(row.resolvedPath)&&!observations.has(row.path),'NonrootPrerequisitesPath');observations.set(row.path,row);
  need(row.uid===0&&row.gid===0&&Number.isSafeInteger(row.mode)&&row.mode>=0&&row.mode<=4095&&(row.mode&0o6000)===0&&(row.type==='symlink'||(row.mode&0o022)===0),'NonrootPrerequisitesPathPermissions');
  const node=p.nodes.get(row.path.slice(1))??p.nodes.get(row.resolvedPath.slice(1));
  if(node&&!node.implicit){need(node.type===row.type,'NonrootPrerequisitesPathType');for(const k of ['mode','uid','gid'])need(row[k]===(node.pax?.[k]===undefined?node[k]:Number(node.pax[k])),'NonrootPrerequisitesPathMetadata');}else need(row.type==='directory','NonrootPrerequisitesPathType');
 }
 for(const f of p.files.values())for(const path of [f.path,f.resolvedPath,...f.parents.map(r=>r.path),...f.symlinkChain.map(r=>r.path)])need(observations.has(path),'NonrootPrerequisitesPathCoverage');
 need(observations.get('/')?.type==='directory','NonrootPrerequisitesRoot');
 return result;
}

export async function collectNonrootControlPrerequisites(value,options={}){
 need(options&&typeof options==='object'&&!Array.isArray(options)&&Object.keys(options).every(key=>['controlVerification','sourceContext','expected','signal','deadlineMs','beforeDocker'].includes(key)),'NonrootPrerequisitesFields');
 return collectPrerequisites(value,options,runNonrootControlDockerCommand,tmpdir());
}
/** Carrier reuses the same actual native checks without an ActualMain or
 * deployment contract. Its process driver admits only the fixed probe verbs. */
export async function collectCarrierBasePrerequisites(value,options={}){
 need(options&&typeof options==='object'&&!Array.isArray(options)&&Object.keys(options).every(key=>['controlVerification','sourceContext','expected','signal','deadlineMs','metadataReads','tempRoot','baseCacheDirectory'].includes(key)),'NonrootPrerequisitesFields');
 need(typeof options.metadataReads?.reserveLocal==='function'&&typeof options.tempRoot==='string'&&typeof options.baseCacheDirectory==='string','CarrierPrerequisitesBudget');
 return collectCarrierPrerequisites(value,options,options.baseCacheDirectory);
}
/** Run the same real native checks against the final independently verified
 * carrier. The returned live handle is bound to that graph/FS and cannot be
 * replaced with the base probe's handle or transported as JSON. */
export async function collectCarrierImagePrerequisites(value,options={}){
 need(options&&typeof options==='object'&&!Array.isArray(options)&&Object.keys(options).every(key=>['controlVerification','sourceContext','expected','signal','deadlineMs','metadataReads','tempRoot','cacheDirectory'].includes(key)),'NonrootPrerequisitesFields');
 need(typeof options.metadataReads?.reserveLocal==='function'&&typeof options.tempRoot==='string'&&typeof options.cacheDirectory==='string','CarrierPrerequisitesBudget');
 reserveCarrierProbe(options);
 const prepared=await preflight(value,options),config=prepared.config.config;
 need(config.User==='1000:1000'&&config.Env.includes('HOME=/tmp')&&config.Env.includes('PATH=/usr/local/bin:/usr/bin:/bin')&&config.Env.includes('NODE_EXTRA_CA_CERTS=/bootstrap/global-bundle.pem')&&!config.OnBuild?.length,'CarrierPrerequisitesRecipe');
 same(config.Entrypoint,['/bin/setpriv','--no-new-privs','--','/usr/local/bin/node','/carrier/guard-first.mjs','audit-original-root'],'CarrierPrerequisitesRecipe');same(config.Cmd??[],[],'CarrierPrerequisitesRecipe');
 const usage=imageGraphState(prepared.graph).budget.usage();
 need(Number.isSafeInteger(usage.uncompressedBytes)&&usage.uncompressedBytes>0&&Number.isSafeInteger(usage.fsEntries)&&usage.fsEntries>0,'CarrierPrerequisitesImportBound');
 // Import materialization is prepaid before Docker, independently of the
 // stream loader's actual charged reads. No unused work is refunded.
 options.metadataReads.reserveLocal({ecrRequests:0,httpBodyBytes:0,logicalBytes:2*usage.uncompressedBytes,uncompressedBytes:usage.uncompressedBytes,processedEntries:usage.fsEntries});
 return collectCarrierPrerequisites(value,options,options.cacheDirectory,prepared);
}
function reserveCarrierProbe(options){
 need(process.platform==='linux'&&process.arch==='arm64','CarrierPrerequisitesNativeArm64');
 options.metadataReads.reserveLocal({ecrRequests:0,httpBodyBytes:0,logicalBytes:16777216+2*sourceBytes.length,uncompressedBytes:0,processedEntries:4096});
}
async function collectCarrierPrerequisites(value,options,cacheDirectory,prepared){
 if(!prepared)reserveCarrierProbe(options);
 const {runCarrierProbeDockerCommand}=await import('./production-nonroot-carrier-probe-supervisor.mjs');
 const {loadNonrootControlImage}=await import('./production-nonroot-control-docker.mjs');
 let loaded,primary;
 try{
  loaded=await loadNonrootControlImage({graph:options.controlVerification.graph,cacheDirectory,metadataReads:options.metadataReads,tempRoot:options.tempRoot,signal:options.signal});
  const handle=await collectPrerequisites(value,options,runCarrierProbeDockerCommand,options.tempRoot,prepared);
  await loaded.close();loaded=undefined;return handle;
 }catch(e){primary=e;throw e;}
 finally{if(loaded&&primary?.code!=='ECLEANUP')await loaded.close();}
}
export function getNonrootNativeProbeSource(){return Object.freeze({code:probeCode,sha256:probeCodeHash});}
async function collectPrerequisites(value,options,runDocker,temporaryRoot,prepared){
 const startedMs=Date.now(),deadlineMs=Math.min(options.deadlineMs??startedMs+120000,startedMs+120000);need(Number.isSafeInteger(deadlineMs)&&deadlineMs>startedMs,'NonrootPrerequisitesDeadline');
 const p=prepared??await preflight(value,options);need((await lstat('/var/run/docker.sock')).isSocket(),'NonrootPrerequisitesLocalDocker');
 const directory=await mkdtemp(join(temporaryRoot,'mem9-prerequisites-')),name='mem9-prerequisites-'+randomBytes(16).toString('hex');let id,attempted=false,sticky=false,primary,record;
 const run=async(stage,args,cleanup=false)=>{
  if(options.beforeDocker!==undefined){need(typeof options.beforeDocker==='function');await options.beforeDocker(Object.freeze({stage,containerId:id,args:Object.freeze([...args])}));}
  if(!cleanup){controlImageGraphBinding(p.graph);need(Date.now()<deadlineMs&&!options.signal?.aborted,'NonrootPrerequisitesExpired');}if(stage==='create')attempted=true;
  try{return await runDocker(args,{directory,timeoutMs:cleanup?10000:Math.min(30000,deadlineMs-Date.now()),signal:cleanup?undefined:options.signal});}catch(e){if(e.code==='ECLEANUP')sticky=true;throw e;}
 };
 const checked=async(stage,args,cleanup=false)=>{const r=await run(stage,args,cleanup);const probeFailure=stage==='start'&&/^NonrootPrerequisitesProbeRejected:[A-Za-z0-9]{1,80}\n$/.test(r.stderr)?r.stderr.trim():'NonrootPrerequisitesDockerCommand';need(r.status===0,probeFailure);return r;};
 const inspect=async(stage,args)=>parseNonrootJson((await checked(stage,args)).stdout,{maxBytes:1048576});
 try{
  const root=checkImage(await inspect('inspect-root',['image','inspect',p.binding.rootDigest]),p),platform=checkImage(await inspect('inspect-platform',['image','inspect','--platform','linux/arm64',p.binding.rootDigest]),p,true);
  const args=['--no-new-privs','--','/usr/local/bin/node','--input-type=module','-e',probeCode,'--',JSON.stringify(p.paths)];
  const created=await checked('create',['container','create','--pull=never','--platform=linux/arm64','--network=none','--read-only','--user=1000:1000','--cap-drop=ALL','--security-opt=no-new-privileges:true','--pids-limit=32','--memory=256m','--cpus=1','--restart=no','--no-healthcheck','--tmpfs','/tmp:rw,nosuid,nodev,exec,size=1048576,uid=1000,gid=1000,mode=0700','--label','mem9-prerequisites-probe='+name,'--name',name,'--entrypoint','/bin/setpriv',p.binding.rootDigest,...args]);
  const candidate=created.stdout.trim();need(/^[a-f0-9]{64}$/.test(candidate),'NonrootPrerequisitesContainerId');id=candidate;
  const container={id,name,args},before=checkContainer(await inspect('inspect-created',['container','inspect',id]),p,container,false);
  const output=await checked('start',['container','start','--attach',id]),after=checkContainer(await inspect('inspect-exited',['container','inspect',id]),p,container,true),result=validate(output.stdout,p);
  record={version:1,kind:'measured-control-prerequisites',image:p.input.image,sourceTree:options.expected.candidateTree,sourceClosureHash:hash(p.input.sourceClosure),collectorCodeHash,probeCodeHash,nativeProbeHash,graphHash:p.binding.graphHash,filesystemHash:hash(p.fs),startedMs,
   container:{id,name,rootInspectHash:hash(root),platformInspectHash:hash(platform),createdInspectHash:hash(before),exitedInspectHash:hash(after),exitCode:after.State.ExitCode},probe:result,probeOutput:output.stdout,probeOutputHash:sha(output.stdout)};
 }catch(e){primary=e;}
 try{
  if(id){const removed=await checked('remove',['container','rm','--force','--volumes',id],true),absent=await run('inspect-removed',['container','inspect',id],true);need(absent.status===1&&new RegExp('(?:No such container|No such object): '+id+'(?:\\s|$)').test(absent.stderr),'ECLEANUP');if(record)record.removal={containerId:id,removeExitCode:removed.status,absenceExitCode:absent.status,absenceEvidenceHash:sha(absent.stderr)};}
  else if(attempted)sticky=true;need(!sticky,'ECLEANUP');await rm(directory,{recursive:true,force:true});
 }catch{throw Object.assign(cleanupError(),{containerId:id,containerName:name,operationDirectory:directory});}
 if(primary){primary.cleanupConfirmed=true;throw primary;}
 let caBytes;
 try{controlImageGraphBinding(p.graph);need(Date.now()<deadlineMs&&!options.signal?.aborted,'NonrootPrerequisitesExpired');
  caBytes=p.ca?await readImageFilesystemFile(p.filesystem,p.ca.path,{maxBytes:1048576}):null;
  need(Date.now()<deadlineMs&&!options.signal?.aborted,'NonrootPrerequisitesExpired');
 }catch(e){e.cleanupConfirmed=true;throw e;}
 record.completedMs=Date.now();record.cleanupConfirmed=true;
 const handle=Object.freeze({kind:'control-prerequisites-context'});states.set(handle,{p,record:copyNonrootJson(record),caBytes});return handle;
}

/** Return typed inputs and their exact archive bytes only from a live handle.
 * This does not create guard-test, policy-review or deployment authorization. */
export function inspectNonrootControlPrerequisites(handle,{controlVerification,sourceContext,now=Date.now()}={}){
 const state=states.get(handle);need(state,'NonrootPrerequisitesContextRequired');const {p,record:r}=state;
 need(controlVerification?.graph===p.graph&&controlVerification?.filesystem===p.filesystem&&sourceContext===p.sourceContext,'NonrootPrerequisitesContextBinding');controlImageGraphBinding(p.graph);
 need(now>=r.completedMs&&now-r.completedMs<=300000,'NonrootPrerequisitesStale');
 const objects=[],json=value=>{const raw=Buffer.from(JSON.stringify(value)+'\n'),ref={bytesHash:sha(raw),canonicalHash:hash(value),bytesLength:raw.length};if(!objects.some(o=>o.ref.bytesHash===ref.bytesHash))objects.push({ref,bytes:raw});return ref;};
 const image=imageOnly(r.image),node=p.files.get('/usr/local/bin/node'),primitive=p.files.get('/bin/setpriv');
 const libraries=c=>json({files:[...new Map(c.files.map(f=>{const fact=p.files.get(f.path);return [fact.path,{path:fact.path,sha256:fact.sha256}];})).values()].sort((a,b)=>a.path.localeCompare(b.path))});
 const nodeRuntime=inspectNonrootRecord('NodeRuntimeV1',{version:1,kind:'pinned-node-runtime',versionString:r.probe.nodeVersion,executablePath:node.path,executableSha256:node.sha256,image,loaderAndNativeLibraries:libraries(r.probe.node),inventory:json({image,executablePath:node.path,executableSha256:node.sha256,elf:r.probe.node,mapped:r.probe.mapped,observationHash:hash(r)})});
 const primitiveEvidence=inspectNonrootRecord('PrimitiveEvidenceV1',{version:1,kind:'verified-nnp-primitive',image,invokedPath:primitive.path,resolvedPath:primitive.resolvedPath,fileSha256:primitive.sha256,mode:primitive.mode,uid:primitive.uid,gid:primitive.gid,
  symlinkChain:json(primitive.symlinkChain),loaderAndLibraries:libraries(r.probe.primitive),privilegeMetadata:json({setuid:(primitive.mode&0o4000)!==0,setgid:(primitive.mode&0o2000)!==0,fileCapabilities:primitive.privilegeAttributes.length!==0,actualFile:primitive}),
  featureProbe:json({image,executableSha256:primitive.sha256,noNewPrivs:r.probe.identity.noNewPrivs,exitCode:r.container.exitCode,identity:r.probe.identity,observationHash:hash(r)}),
  inheritanceAndNegativeProbes:json({image,executableSha256:primitive.sha256,parent:r.probe.identity,child:r.probe.child,method:'fixed-aarch64-kernel-syscalls',nativeProbeHash,kernelResults:r.probe.native,setuidBlocked:r.probe.native[7]===-1,setgidBlocked:r.probe.native[8]===-1,clearRejected:r.probe.native[5]===-22&&r.probe.native[6]===1&&r.probe.native[13]===1,observationHash:hash(r)})});
 const metadata=r.probe.observations.filter(o=>o.type==='directory').map(({path,type,mode,uid,gid})=>({path,type,mode,uid,gid}));
 for(const f of p.files.values())metadata.push({path:f.path,type:'file',mode:f.mode,uid:f.uid,gid:f.gid,sha256:f.sha256});
 const caBindings=[];
 if(p.ca){const file={sha256:sha(state.caBytes),bytesLength:state.caBytes.length};objects.push({ref:file,bytes:Buffer.from(state.caBytes)});caBindings.push(inspectNonrootRecord('CaBindingV1',{name:'NODE_EXTRA_CA_CERTS',value:p.ca.path,file,resolvedPath:p.ca.resolvedPath,mode:p.ca.mode,uid:p.ca.uid,gid:p.ca.gid,parentPathEvidence:json({file:p.ca,observations:r.probe.observations})}));}
 const environment=copyNonrootJson({imageEnvironment:p.config.config?.Env??[],files:metadata,expectedCa:caBindings.map(c=>({path:c.value,sha256:c.file.sha256})),caBindings,loaderAbsences:loaderPaths,observedMs:r.completedMs});
 const recordRef=json(r);
 return {record:copyNonrootJson(r),recordRef,nodeRuntime,primitiveEvidence,environment,objects};
}
