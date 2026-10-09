/** Local-only Docker primitives. No registry acquisition or cloud transport. */
import {spawn,spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {readFileSync,lstatSync,readdirSync,rmSync,realpathSync} from 'node:fs';
import {resolve,dirname,join} from 'node:path';
import {pathToFileURL} from 'node:url';
import {parseNonrootJson} from './production-nonroot-contracts.mjs';

export const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
export const fail=code=>{throw Error(code);};
export const need=(ok,code='SmokeInputInvalid')=>{if(!ok)fail(code);};
const MAX_CAPTURE=8*1024*1024;
export function command(file,args,{input,timeoutMs=30000,maxBytes=MAX_CAPTURE,env=process.env,cwd}={}){
 const r=spawnSync(file,args,{input,timeout:timeoutMs,maxBuffer:maxBytes,env,cwd});
 if(r.error||r.signal||r.status===null)fail('SmokeCommandIncomplete');
 return {stdout:r.stdout??Buffer.alloc(0),stderr:r.stderr??Buffer.alloc(0),exitCode:r.status};
}
export function docker(args,options){return command('docker',args,options);}
export function dockerJson(args){const r=docker(args);need(r.exitCode===0,'SmokeDockerReadFailed');return JSON.parse(r.stdout);}
export function privateJson(file){const s=lstatSync(file);need(s.isFile()&&!s.isSymbolicLink()&&(s.mode&0o077)===0&&s.uid===process.getuid()&&s.size<=4*1024*1024,'SmokePrivateFile');return parseNonrootJson(readFileSync(file,'utf8'));}
export function scanBytes(bytes,password=''){
 const text=Buffer.from(bytes).toString('utf8');
 const count=s=>s?text.split(s).length-1:0;
 return {rawPasswordMatches:count(password),encodedPasswordMatches:count(password?encodeURIComponent(password):''),
  cloudCredentialMatches:(text.match(/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|(?:AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN)\s*[=:]\s*[^\s"<]+/g)??[]).length,
  privateKeyMatches:(text.match(/-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/g)??[]).length,
  tokenMatches:(text.match(/\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{24,})\b/g)??[]).length};
}
export function allZero(scan){return Object.values(scan).every(v=>v===0);}
const id=v=>need(typeof v==='string'&&/^[a-f0-9]{64}$/.test(v),'SmokeContainerId');
const uid=v=>need(v==='1000:1000'||v==='999:999','SmokeUser');
const decode=b=>Buffer.from(b,'base64').toString('utf8');
export function processCapture(container,user,pid){
 id(container);uid(user);need(/^[1-9][0-9]*$/.test(String(pid)),'SmokePid');
 const script='p=/proc/'+pid+'; base64 -w 0 "$p/status"; printf "\\n"; base64 -w 0 "$p/stat"; printf "\\n"; readlink "$p/exe"; sha256sum "$p/exe"; base64 -w 0 "$p/stat"; printf "\\n"';
 const r=docker(['exec','--user',user,container,'/bin/sh','-ceu',script]);need(r.exitCode===0,'SmokeProcessRead');
 const lines=r.stdout.toString().trimEnd().split('\n');need(lines.length===5,'SmokeProcessRead');
 const stat=decode(lines[1]),last=decode(lines[4]);
 const ticks=s=>s.match(/^\d+ \(.*\) \S (.*)$/s)?.[1].trim().split(/\s+/)[18];
 need(ticks(stat)===ticks(last),'SmokePidReuse');
 return {status:decode(lines[0]),stat,exe:lines[2],executableSha256:lines[3].split(/\s/)[0]};
}
export function processIds(container,user){
 id(container);uid(user);
 const r=docker(['exec','--user',user,container,'/bin/sh','-ceu','for p in /proc/[0-9]*/stat; do cat "$p" 2>/dev/null || :; done']);
 need(r.exitCode===0,'SmokeProcessInventory');
 const rows=r.stdout.toString().trim().split('\n').map(s=>{const m=s.match(/^(\d+) \(.*\) \S (\d+) /);return m?[Number(m[1]),Number(m[2])]:null;}).filter(Boolean);
 const selected=new Set([1]);let changed=true;while(changed){changed=false;for(const [pid,parent]of rows)if(selected.has(parent)&&!selected.has(pid)){selected.add(pid);changed=true;}}
 return [...selected].sort((a,b)=>a-b);
}

/** Docker 29 image IDs can be index/manifest digests. Obtain actual child and
 * config bytes from the local Docker export instead of guessing from .Id. */
export async function localImageMetadata(qualifiedImage){
 need(typeof qualifiedImage==='string'&&/^[A-Za-z0-9._:/-]+@sha256:[a-f0-9]{64}$/.test(qualifiedImage),'SmokeDigestQualifiedImageRequired');
 const rootDigest=qualifiedImage.split('@')[1],root=dockerJson(['image','inspect',qualifiedImage]);
 const selected=dockerJson(['image','inspect','--platform','linux/arm64',qualifiedImage]);
 need(root.length===1&&selected.length===1&&selected[0].Architecture==='arm64'&&selected[0].Os==='linux','SmokeImagePlatform');
 need(root[0].RepoDigests?.includes(qualifiedImage),'SmokeImageRootBinding');
 const childDigest=selected[0].Descriptor?.digest;
 need(/^sha256:[a-f0-9]{64}$/.test(childDigest??''),'SmokeImageDescriptorRequired');
 const jsons=new Map();
 await new Promise((ok,reject)=>{
  const child=spawn('docker',['image','save','--platform','linux/arm64',qualifiedImage],{stdio:['ignore','pipe','pipe']});
  let pending=Buffer.alloc(0),remaining=0,padding=0,name='',capture=false,parts=[],total=0,settled=false;
  const stop=error=>{if(!settled){settled=true;child.kill('SIGKILL');reject(error);}};
  const timer=setTimeout(()=>stop(Error('SmokeImageExportTimeout')),90000);
  child.on('error',stop);child.stderr.on('data',()=>{});
  child.stdout.on('data',chunk=>{
   try{
    total+=chunk.length;need(total<=3*1024*1024*1024,'SmokeImageExportLimit');pending=Buffer.concat([pending,chunk]);
    while(pending.length){
     if(remaining){const n=Math.min(remaining,pending.length);if(capture)parts.push(Buffer.from(pending.subarray(0,n)));pending=pending.subarray(n);remaining-=n;
      if(!remaining&&capture){const bytes=Buffer.concat(parts);try{const value=JSON.parse(bytes.toString());if(name.startsWith('blobs/sha256/')){need(sha(bytes)===name.slice('blobs/sha256/'.length),'SmokeImageBlobHash');jsons.set('sha256:'+sha(bytes),{bytes,value});}}catch(error){if(error.message==='SmokeImageBlobHash')throw error;}}
      continue;
     }
     if(padding){const n=Math.min(padding,pending.length);pending=pending.subarray(n);padding-=n;continue;}
     if(pending.length<512)break;
     const header=pending.subarray(0,512);pending=pending.subarray(512);if(header.every(v=>v===0))continue;
     name=header.subarray(0,100).toString().replace(/\0.*$/s,'');const size=parseInt(header.subarray(124,136).toString().replace(/\0.*$/s,'').trim()||'0',8);
     need(Number.isSafeInteger(size)&&size>=0&&size<=3*1024*1024*1024,'SmokeImageArchive');remaining=size;padding=(512-size%512)%512;
     capture=name.startsWith('blobs/sha256/')&&size>0&&size<=1024*1024;parts=[];
    }
   }catch(error){stop(error);}
  });
  child.on('close',code=>{clearTimeout(timer);if(!settled){settled=true;if(code!==0||remaining||padding)reject(Error('SmokeImageExportFailed'));else ok();}});
 });
 const manifest=jsons.get(childDigest);need(manifest?.value.config?.digest,'SmokeImageManifestMissing');
 const configDigest=manifest.value.config.digest,config=jsons.get(configDigest);need(config&&config.value.architecture==='arm64'&&config.value.os==='linux','SmokeImageConfigMissing');
 if(jsons.has(rootDigest)&&rootDigest!==childDigest)need(jsons.get(rootDigest).value.manifests?.some(m=>m.digest===childDigest&&m.platform?.architecture==='arm64'&&m.platform?.os==='linux'),'SmokeImageIndexChild');
 return {qualifiedImage,rootDigest,arm64Digest:childDigest,configDigest,config:config.value,manifest:manifest.value,
  bytes:{manifest:manifest.bytes,config:config.bytes,...(jsons.has(rootDigest)?{root:jsons.get(rootDigest).bytes}:{})}};
}

function ownedState(file){
 const state=privateJson(file);need(/^[a-f0-9]{64}$/.test(state.invocationId)&&Array.isArray(state.containers)&&state.containers.length===6&&typeof state.network==='string','SmokeOwnershipState');
 for(const c of state.containers)id(c.id);id(state.network);return state;
}
function assertOwner(inspected,state){need(inspected?.Config?.Labels?.['mem9-ci-smoke-invocation']===state.invocationId,'SmokeOwnership');}
export function cleanupOwned(file){
 const state=ownedState(file),containerIds=[];
 for(const c of state.containers){const found=dockerJson(['inspect',c.id]);need(found.length===1,'SmokeOwnership');assertOwner(found[0],state);
  need(found[0].Name==='/'+c.name,'SmokeOwnership');const r=docker(['rm','--force','--volumes',c.id]);need(r.exitCode===0&&r.stdout.toString().trim()===c.id,'SmokeRemovalFailed');containerIds.push(c.id);}
 const n=dockerJson(['network','inspect',state.network]);need(n.length===1&&n[0].Labels?.['mem9-ci-smoke-invocation']===state.invocationId,'SmokeOwnership');
 const r=docker(['network','rm',state.network]);need(r.exitCode===0,'SmokeRemovalFailed');
 const work=lstatSync(state.workDirectory);need(work.isDirectory()&&!work.isSymbolicLink()&&work.uid===process.getuid()&&realpathSync(state.workDirectory)===state.workDirectory&&state.workDirectory.includes('/mem9-ci-smoke-'),'SmokeWorkOwnership');
 rmSync(state.workDirectory,{recursive:true});return {containerIds,networkIds:[state.network],volumeNames:[]};
}
export function ownedInventory(file){
 const state=ownedState(file),filter='label=mem9-ci-smoke-invocation='+state.invocationId;
 const list=args=>{const r=docker(args);need(r.exitCode===0,'SmokeInventoryFailed');return r.stdout.toString().trim().split('\n').filter(Boolean);};
 const containerIds=list(['ps','--all','--no-trunc','--filter',filter,'--format','{{.ID}}']);
 const networkIds=list(['network','ls','--no-trunc','--filter',filter,'--format','{{.ID}}']);
 const volumeNames=list(['volume','ls','--filter',filter,'--format','{{.Name}}']);
 const remaining=readdirSync(dirname(state.workDirectory)).filter(n=>n===state.workDirectory.split('/').at(-1));
 return {containerIds,networkIds,volumeNames,temporaryEntries:remaining};
}
function forward(result){process.stdout.write(result.stdout);process.stderr.write(result.stderr);process.exitCode=result.exitCode;}
function query(container,kind){
 id(container);
 const sql=kind==='tls-query'?"SELECT json_build_object('backendPid',pg_backend_pid(),'tlsEnabled',(SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()))::text;":
  kind==='relations-query'?"SELECT json_build_object('relations',json_build_array('public.ingest_jobs','public.ingest_job_plans','public.sessions'),'present',json_build_array(to_regclass('public.ingest_jobs') IS NOT NULL,to_regclass('public.ingest_job_plans') IS NOT NULL,to_regclass('public.sessions') IS NOT NULL))::text;":'SELECT 1;';
 const script='export PGPASSWORD="$POSTGRES_PASSWORD"; export PGSSLMODE='+ (kind==='plaintext-query'?'disable':'require')+'; exec psql -X --host 127.0.0.1 --username mnemo --dbname mnemo --tuples-only --no-align --command "$1"';
 return docker(['exec','--user','999:999',container,'/bin/sh','-ceu',script,'query',sql]);
}
async function cli(){
 const [mode,...args]=process.argv.slice(2);
 if(mode==='image-metadata'){
  need(args.length===1,'SmokeHelperOperation');const image=await localImageMetadata(args[0]);
  console.log(JSON.stringify({qualifiedImage:image.qualifiedImage,rootDigest:image.rootDigest,arm64Digest:image.arm64Digest,configDigest:image.configDigest}));return;
 }
 if(mode==='process'){console.log(JSON.stringify(processCapture(...args)));return;}
 if(mode==='pids'){console.log(JSON.stringify(processIds(...args)));return;}
 if(['tls-query','relations-query','plaintext-query'].includes(mode)){forward(query(args[0],mode));return;}
 if(mode==='stat-tls'){
  id(args[0]);const r=docker(['exec','--user','999:999',args[0],'/bin/sh','-ceu','stat -c "%u %g %a" /tls/server.key; sha256sum /tls/server.crt; date -r /tls/server.key +%s%3N']);
  need(r.exitCode===0,'SmokeTlsStat');const lines=r.stdout.toString().trim().split('\n'),[keyUid,keyGid,modeText]=lines[0].split(' ');
  console.log(JSON.stringify({keyPath:'/tls/server.key',certificatePath:'/tls/server.crt',keyUid:Number(keyUid),keyGid:Number(keyGid),keyMode:parseInt(modeText,8),certificateSha256:lines[1].split(' ')[0]}));
  process.stderr.write(JSON.stringify({generatedMs:Number(lines[2])})+'\n');return;
 }
 if(mode==='remove-owned'){console.log(JSON.stringify(cleanupOwned(args[0])));return;}
 if(mode==='inventory-owned'){console.log(JSON.stringify(ownedInventory(args[0])));return;}
 if(mode==='scan-logs'){
  const plan=privateJson(args[0]),secret=readFileSync(plan.secretFile,'utf8');let rawMatches=0,encodedMatches=0,credentialPatternMatches=0;
  for(const ref of plan.logs){const bytes=readFileSync(join(plan.objectsDirectory,ref.bytesHash+'.bin'));need(sha(bytes)===ref.bytesHash&&bytes.length===ref.bytesLength,'SmokeLogScanBinding');const scan=scanBytes(bytes,secret);
   rawMatches+=scan.rawPasswordMatches;encodedMatches+=scan.encodedPasswordMatches;credentialPatternMatches+=scan.cloudCredentialMatches+scan.privateKeyMatches+scan.tokenMatches;}
  console.log(JSON.stringify({logHashes:plan.logHashes,syntheticCredentialFingerprint:sha(secret),rawMatches,encodedMatches,credentialPatternMatches}));
  if(rawMatches||encodedMatches||credentialPatternMatches)process.exitCode=1;return;
 }
 fail('SmokeHelperOperation');
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)cli().catch(error=>{process.stderr.write((/^[A-Za-z]+$/.test(error.message)?error.message:'SmokeHelperFailed')+'\n');process.exitCode=1;});
