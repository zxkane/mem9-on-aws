import {createHash} from 'node:crypto';
import {open,lstat,realpath,readdir} from 'node:fs/promises';
import {constants} from 'node:fs';
import {join,resolve,posix} from 'node:path';
import {copyNonrootJson,nonrootHash,inspectNonrootRecord} from './production-nonroot-contracts.mjs';

const contexts=new WeakMap(),fail=()=>{throw Error('ControlSourceUnverified');};
const need=value=>{if(!value)fail();};
const sha=value=>createHash('sha256').update(value).digest('hex');
const gitObject=(type,bytes)=>createHash('sha1').update(type+' '+bytes.length+'\0').update(bytes).digest('hex');
const safePath=path=>typeof path==='string'&&path.length<=4096&&/^[A-Za-z0-9_.\/-]+$/.test(path)&&!path.startsWith('/')&&
 path.split('/').every(part=>part&&part!=='.'&&part!=='..')&&path.split('/').length<=64;

/** Reconstruct the full Git tree from all recursive entries. A declared tree
 * hash beside a subset of COPY files is not membership or closure evidence. */
export function createControlSourceContext(value,readBlob){
 const input=copyNonrootJson(value);need(input&&Object.keys(input).sort().join()==='entries,tree');const {tree,entries}=input;
 need(/^[a-f0-9]{40}$/.test(tree??'')&&typeof readBlob==='function');
 const rows=copyNonrootJson(entries);need(Array.isArray(rows)&&rows.length>0&&rows.length<=20000);
 const root=new Map(),files=new Map();
 for(const row of rows){
  need(row&&Object.keys(row).sort().join()===['path','mode','type','oid'].sort().join()&&safePath(row.path)&&!files.has(row.path)&&/^[a-f0-9]{40}$/.test(row.oid??'')&&
   (['100644','100755','120000'].includes(row.mode)&&row.type==='blob'||row.mode==='160000'&&row.type==='commit'));
  files.set(row.path,row);const parts=row.path.split('/');let node=root;
  for(const part of parts.slice(0,-1)){if(!node.has(part))node.set(part,new Map());need(node.get(part)instanceof Map);node=node.get(part);}
  need(!node.has(parts.at(-1)));node.set(parts.at(-1),row);
 }
 const treeHash=node=>{
  const entries=[...node].sort(([a,av],[b,bv])=>Buffer.compare(Buffer.from(a+(av instanceof Map?'/':'')),Buffer.from(b+(bv instanceof Map?'/':''))));
  const bytes=Buffer.concat(entries.flatMap(([name,value])=>[Buffer.from((value instanceof Map?'40000':value.mode)+' '+name+'\0'),Buffer.from(value instanceof Map?treeHash(value):value.oid,'hex')]));
  return gitObject('tree',bytes);
 };
 need(treeHash(root)===tree);const handle=Object.freeze({kind:'verified-control-source-tree',tree});contexts.set(handle,{tree,files,readBlob});return handle;
}

export async function readControlSourceFile(context,path){
 const state=contexts.get(context);need(state&&safePath(path));const entry=state.files.get(path);
 need(entry?.type==='blob'&&['100644','100755'].includes(entry.mode));
 const bytes=await state.readBlob(entry.oid,path);need(bytes instanceof Uint8Array&&bytes.byteLength<=16777216);
 const raw=Buffer.from(bytes);need(gitObject('blob',raw)===entry.oid);
 return {file:inspectNonrootRecord('SourceFileV1',{path,gitMode:entry.mode,sha256:sha(raw),bytes:raw.length,blob:{sha256:sha(raw),bytesLength:raw.length}}),bytes:raw};
}

function copySources(text){
 const values=[];
 for(const raw of text.split(/\r?\n/)){
  const line=raw.trim();if(!/^(?:COPY|ADD)\b/i.test(line))continue;
  need(line.startsWith('COPY ')&&!/[\\\[\]"'$`]/.test(line));const words=line.split(/\s+/).slice(1);need(words.length>=2&&!words.some(word=>word.startsWith('--')));
  words.pop();for(const source of words){need(/^[A-Za-z0-9_.*\/-]+$/.test(source)&&!source.startsWith('/')&&!source.split('/').some(part=>part==='.'||part==='..'));values.push(source);}
 }
 need(values.length>0);return [...new Set(values)].sort();
}

/** Exact COPY expansion against the authenticated complete tree. This is the
 * declared recipe; the build launcher separately rejects untracked matches. */
export async function describeControlCopyClosure(context){
 const state=contexts.get(context);need(state);const dockerfile=await readControlSourceFile(context,'docker/bootstrap/Dockerfile'),paths=new Set();
 for(const source of copySources(new TextDecoder('utf-8',{fatal:true}).decode(dockerfile.bytes))){
  const pattern=new RegExp('^'+source.split('*').map(RegExp.escape).join('[^/]*')+'$');
  const matches=[...state.files.keys()].filter(path=>source.endsWith('/')?path.startsWith(source):pattern.test(path));need(matches.length>0);
  for(const path of matches)paths.add(path);
 }
 const files=[];for(const path of [...paths].sort())files.push((await readControlSourceFile(context,path)).file);
 return inspectNonrootRecord('SourceClosureV1',{version:1,kind:'git-file-closure',tree:state.tree,files,closureHash:nonrootHash(files)});
}

export async function verifyControlSourceClosure(context,closure,{copyContext=false}={}){
 const state=contexts.get(context);need(state);const checked=inspectNonrootRecord('SourceClosureV1',closure);need(checked.tree===state.tree);
 for(const file of checked.files)need(nonrootHash((await readControlSourceFile(context,file.path)).file)===nonrootHash(file));
 if(copyContext)need(nonrootHash(await describeControlCopyClosure(context))===nonrootHash(checked));
 return checked;
}

export function controlSourcePaths(context){const state=contexts.get(context);need(state);return Object.freeze([...state.files.keys()].sort());}
export function controlSourceEntries(context){const state=contexts.get(context);need(state);return copyNonrootJson([...state.files.values()]);}

const ignorePath='docker/bootstrap/Dockerfile.dockerignore';
const ignorePatterns=['**','!docker/','!docker/bootstrap/','!docker/bootstrap/**','!scripts/','!scripts/*.mjs','!scripts/lib/','!scripts/lib/*.mjs',
 '!infra/','!infra/gateway/','!infra/gateway/service-auth.mjs','!package.json','!package-lock.json','**/*.local.*','**/CLAUDE.local.md','**/.env','**/.env.*','**/.git','**/node_modules','**/.ssh'];
const excluded=path=>path.split('/').some(part=>['.git','node_modules','.ssh','CLAUDE.local.md'].includes(part)||part==='.env'||part.startsWith('.env.')||part.includes('.local.'));

/** Check the actual context immediately before the Docker build. Unknown COPY
 * matches are rejected before their contents are read; machine-local state is
 * excluded by the separately pinned CONTROL-only ignore file. */
export async function verifyControlBuildCheckout(context,repository){
 const state=contexts.get(context);need(state&&typeof repository==='string'&&resolve(repository)===repository&&await realpath(repository)===repository);
 const root=await lstat(repository);need(root.isDirectory()&&!root.isSymbolicLink());
 need(!state.files.has('.dockerignore'));
 try{await lstat(join(repository,'.dockerignore'));fail();}catch(error){if(error.code!=='ENOENT')throw error;}
 const checkedDirectory=async relative=>{
  const parts=relative?relative.split('/'):[];let path=repository;
  for(const part of parts){path=join(path,part);const stat=await lstat(path);need(stat.isDirectory()&&!stat.isSymbolicLink()&&await realpath(path)===path);}
 };
 const checkFile=async file=>{
  need(safePath(file.path));await checkedDirectory(posix.dirname(file.path)==='.'?'':posix.dirname(file.path));
  const path=join(repository,file.path),fd=await open(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
  try{
   const before=await fd.stat();need(before.isFile()&&before.nlink===1&&before.size===file.bytes&&before.size<=16777216&&
    (file.gitMode==='100755'?(before.mode&0o111)!==0:(before.mode&0o111)===0));
   const bytes=await fd.readFile(),after=await fd.stat(),named=await lstat(path);
   need(['dev','ino','size','mtimeMs','ctimeMs','mode'].every(key=>before[key]===after[key]&&before[key]===named[key])&&sha(bytes)===file.sha256);
  }finally{await fd.close();}
 };
 const ignore=await readControlSourceFile(context,ignorePath);await checkFile(ignore.file);
 const patterns=new TextDecoder('utf-8',{fatal:true}).decode(ignore.bytes).split(/\r?\n/).map(line=>line.trim()).filter(line=>line&&!line.startsWith('#'));
 need(nonrootHash(patterns)===nonrootHash(ignorePatterns));
 const recipe=await readControlSourceFile(context,'docker/bootstrap/Dockerfile');await checkFile(recipe.file);
 const expected=await describeControlCopyClosure(context),actual=new Set();let count=0;
 const visit=async relative=>{
  if(excluded(relative))return;need(++count<=20000);await checkedDirectory(posix.dirname(relative)==='.'?'':posix.dirname(relative));
  const path=join(repository,relative),stat=await lstat(path);need(!stat.isSymbolicLink());
  if(stat.isDirectory()){for(const name of await readdir(path))await visit(relative+'/'+name);}
  else{need(stat.isFile());actual.add(relative);}
 };
 for(const source of copySources(new TextDecoder('utf-8',{fatal:true}).decode(recipe.bytes))){
  if(source.endsWith('/'))await visit(source.slice(0,-1));
  else if(source.includes('*')){
   const directory=posix.dirname(source)==='.'?'':posix.dirname(source);need(!directory.includes('*'));await checkedDirectory(directory);
   const pattern=new RegExp('^'+source.split('*').map(RegExp.escape).join('[^/]*')+'$');
   for(const name of await readdir(join(repository,directory))){const path=directory?directory+'/'+name:name;if(pattern.test(path))await visit(path);}
  }else await visit(source);
 }
 const expectedPaths=expected.files.map(file=>file.path);need(expectedPaths.every(path=>!excluded(path))&&nonrootHash([...actual].sort())===nonrootHash(expectedPaths));
 for(const file of expected.files)await checkFile(file);
 return Object.freeze({tree:state.tree,copyClosureHash:nonrootHash(expected),dockerfileHash:recipe.file.sha256,ignoreHash:ignore.file.sha256});
}
