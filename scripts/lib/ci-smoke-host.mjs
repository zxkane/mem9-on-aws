import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {createHash} from 'node:crypto';
import {open,lstat,realpath,mkdir,readdir,unlink,rmdir,appendFile} from 'node:fs/promises';
import {constants} from 'node:fs';
import {resolve,join} from 'node:path';
import {parseCiSmokeJson} from './ci-smoke-evidence.mjs';
import {createControlSourceContext} from './production-control-source.mjs';

const execute=promisify(execFile);
export const smokeHash=bytes=>createHash('sha256').update(bytes).digest('hex');
export const smokeNeed=(ok,code='CiSmokeHostInvalid')=>{if(!ok)throw Error(code);};
const need=smokeNeed,git=v=>typeof v==='string'&&/^[a-f0-9]{40}$/.test(v);

export function ciSmokeHost(env,cwd=process.cwd()){
 need(env.GITHUB_ACTIONS==='true'&&/^[-A-Za-z0-9_.]+\/[-A-Za-z0-9_.]+$/.test(env.GITHUB_REPOSITORY??'')&&git(env.GITHUB_SHA),'CiSmokeHostIdentity');
 for(const key of ['GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT'])need(/^[1-9][0-9]*$/.test(env[key]??'')&&Number.isSafeInteger(Number(env[key])),'CiSmokeHostIdentity');
 const run=async(file,args,{maxBytes=16777216,timeoutMs=30000,encoding='utf8',input}={})=>{
  need(['git','gh','docker'].includes(file)&&Array.isArray(args)&&args.every(v=>typeof v==='string'&&!v.includes('\0')),'CiSmokeHostCommand');
  need(timeoutMs>0&&timeoutMs<=180000&&maxBytes>0&&maxBytes<=33554432);
  // The only callers are fixed code-owned operations. No shell interpolation.
  try{return (await execute(file,args,{cwd,env,encoding,timeout:timeoutMs,maxBuffer:maxBytes,killSignal:'SIGKILL',input})).stdout;}
  catch(error){const failure=Error('CiSmokeHostCommandFailed');failure.exitCode=error.code;throw failure;}
 };
 const api=async path=>{
  need(typeof path==='string'&&/^[A-Za-z0-9_./?=&%+-]+$/.test(path)&&!path.includes('..')&&!path.startsWith('/'),'CiSmokeGithubPath');
  return parseCiSmokeJson(await run('gh',['api','--hostname','github.com','repos/'+env.GITHUB_REPOSITORY+'/'+path]));
 };
 const readLog=async id=>{need(Number.isSafeInteger(id)&&id>0);return run('gh',['api','--hostname','github.com','repos/'+env.GITHUB_REPOSITORY+'/actions/jobs/'+id+'/logs'],{maxBytes:8388608});};
 const checkout=async()=>{
  await run('git',['diff','--quiet']);await run('git',['diff','--cached','--quiet']);
  const revision=(await run('git',['rev-parse','HEAD'])).trim(),tree=(await run('git',['rev-parse','HEAD^{tree}'])).trim();
  need(revision===env.GITHUB_SHA&&git(tree),'CiSmokeCheckoutChanged');return {revision,tree};
 };
 return {run,api,readLog,checkout,cwd,env};
}

export async function smokePrivateRead(path,maxBytes=8388608,beforeRead){
 need(typeof path==='string'&&resolve(path)===path&&await realpath(path)===path,'CiSmokePrivatePath');
 const fd=await open(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
 try{
  const before=await fd.stat();need(before.isFile()&&before.uid===process.getuid()&&(before.mode&0o777)===0o600&&before.nlink===1&&before.size<=maxBytes,'CiSmokePrivateFile');
  if(beforeRead){need(typeof beforeRead==='function','CiSmokeReadAccounting');const charged=beforeRead(before.size+1);need(!charged||typeof charged.then!=='function','CiSmokeReadAccounting');}
  const buffer=Buffer.alloc(before.size+1);let length=0;
  while(length<buffer.length){const r=await fd.read(buffer,length,Math.min(65536,buffer.length-length),length);if(!r.bytesRead)break;length+=r.bytesRead;}
  const raw=buffer.subarray(0,length),after=await fd.stat(),named=await lstat(path);
  need(raw.length===before.size&&['dev','ino','uid','mode','nlink','size','mtimeMs','ctimeMs'].every(k=>before[k]===after[k]&&before[k]===named[k]),'CiSmokePrivateFileChanged');return raw;
 }finally{await fd.close();}
}
export async function smokePrivateWrite(path,value){
 const raw=Buffer.isBuffer(value)?value:Buffer.from(JSON.stringify(value));need(raw.length<=33554432,'CiSmokePrivateSize');
 const fd=await open(path,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);
 try{await fd.writeFile(raw);await fd.sync();}finally{await fd.close();}return smokeHash(raw);
}
export async function smokeDirectory(env,name,{create=false}={}){
 need(['mem9-ci-smoke-state','mem9-ci-smoke-source'].includes(name)&&typeof env.RUNNER_TEMP==='string'&&resolve(env.RUNNER_TEMP)===env.RUNNER_TEMP,'CiSmokeTemporaryRoot');
 const root=await realpath(env.RUNNER_TEMP);need(root===env.RUNNER_TEMP,'CiSmokeTemporaryRoot');const path=join(root,name);
 if(create)await mkdir(path,{mode:0o700});
 const s=await lstat(path);need(s.isDirectory()&&!s.isSymbolicLink()&&s.uid===process.getuid()&&(s.mode&0o777)===0o700&&await realpath(path)===path,'CiSmokeOwnedDirectory');return path;
}

/** Only a directory created by this CLI, with its closed file inventory, may
 * be removed. Unknown ownership/state retains evidence instead of broad rm. */
export async function removeSmokeDirectory(env,name){
 let path;try{path=await smokeDirectory(env,name);}catch(error){if(error.code==='ENOENT')return;throw error;}
 const allowed=new Set(name==='mem9-ci-smoke-state'?['precheck.json','source.json','objects','put-intent.json','put-result.json']:['receipt.json','envelope.json']);
 const entries=await readdir(path);need(entries.every(entry=>allowed.has(entry)),'CiSmokeCleanupUnknownEntry');
 const files=[],directories=[];
 for(const entry of entries){
  need(allowed.has(entry),'CiSmokeCleanupUnknownEntry');const child=join(path,entry);
  if(entry==='objects'){
   const d=await lstat(child);need(d.isDirectory()&&!d.isSymbolicLink()&&d.uid===process.getuid()&&(d.mode&0o777)===0o700,'CiSmokeCleanupOwnership');
   const names=await readdir(child);need(names.length<=4096&&names.every(file=>/^[a-f0-9]{64}\.bin$/.test(file)),'CiSmokeCleanupUnknownEntry');
   for(const file of names){await smokePrivateRead(join(child,file));files.push(join(child,file));}
   directories.push(child);
  }else{await smokePrivateRead(child,33554432);files.push(child);}
 }
 // Validate the whole owned inventory before the first deletion.
 for(const file of files)await unlink(file);for(const directory of directories)await rmdir(directory);
 await rmdir(path);
}
export async function smokeEnvironment(env,values){
 need(typeof env.GITHUB_ENV==='string'&&env.GITHUB_ENV,'CiSmokeEnvironmentFile');
 let text='';for(const[key,value]of Object.entries(values)){need(/^MEM9_[A-Z_]+$/.test(key)&&typeof value==='string'&&!/[\r\n\0]/.test(value));text+=key+'='+value+'\n';}
 await appendFile(env.GITHUB_ENV,text);
}

/** Full Git-tree membership is verified by the existing source context.
 * Old unreachable merge commits may be read through the same repository's
 * GitHub Git API; no foreign repository or arbitrary download is admitted. */
export async function captureSmokeTree(host,{revision,tree},store){
 need(git(revision)&&git(tree),'CiSmokeTreeIdentity');let entries,local=false;
 try{
  const actual=(await host.run('git',['show','-s','--format=%T',revision])).trim();need(actual===tree,'CiSmokeTreeChanged');
  entries=(await host.run('git',['ls-tree','-r','-z','--full-tree',revision])).split('\0').filter(Boolean).map(row=>{
   const m=/^(\d+) (\w+) ([a-f0-9]{40})\t(.+)$/.exec(row);need(m,'CiSmokeGitEntry');return {mode:m[1],type:m[2],oid:m[3],path:m[4]};
  });local=true;
 }catch(error){
  if(error.message!=='CiSmokeHostCommandFailed')throw error;
  const commit=await host.api('commits/'+revision);need(commit.sha===revision&&commit.commit?.tree?.sha===tree,'CiSmokeTreeChanged');
  const raw=await host.api('git/trees/'+tree+'?recursive=1');need(raw.sha===tree&&raw.truncated===false&&Array.isArray(raw.tree),'CiSmokeTreeIncomplete');
  entries=raw.tree.filter(r=>r.type!=='tree').map(({mode,type,sha,path})=>({mode,type,oid:sha,path}));
 }
 const blobs={};
 const context=createControlSourceContext({tree,entries},async oid=>{
  if(blobs[oid])return store.get(blobs[oid].sha256);
  let raw;
  if(local)raw=await host.run('git',['cat-file','blob',oid],{encoding:'buffer',maxBytes:8388608});
  else{const value=await host.api('git/blobs/'+oid);need(value.sha===oid&&value.encoding==='base64'&&Number.isSafeInteger(value.size)&&value.size<=8388608,'CiSmokeGithubBlob');raw=Buffer.from(value.content.replace(/\s/g,''),'base64');need(raw.length===value.size,'CiSmokeGithubBlob');}
  blobs[oid]=store.bytes(raw);return Buffer.from(raw);
 });
 return {context,snapshot:()=>({tree,entries,blobs:{...blobs}})};
}
