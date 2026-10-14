/** Local, reproducible packaging. CI runs these committed bytes and never
 * installs tools/packages while the original copy deadline is running. */
import {readFile,writeFile,mkdir,lstat,readlink} from 'node:fs/promises';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {builtinModules} from 'node:module';
import {fileURLToPath} from 'node:url';
import {dirname,join,relative,resolve} from 'node:path';
import {rolldown,VERSION as version,RUNTIME_MODULE_ID} from 'rolldown';
import {minifySync} from 'rolldown/utils';
import {parse} from '@babel/parser';
import {createControlSourceContext} from './lib/production-control-source.mjs';
import {ciSmokeSourceClosure} from './lib/ci-smoke-isolation.mjs';

const root=resolve(dirname(fileURLToPath(import.meta.url)),'..'),directory=join(root,'.github/actions/control-composition/dist'),sha=b=>createHash('sha256').update(b).digest('hex');
const need=(v,c)=>{if(!v)throw Error(c);};
async function currentSourceContext(){
 // Include pending source additions without changing the repository index
 // or object database. The original reader independently checks this tree
 // and each blob. This snapshot is local build input, not runtime authority.
 const paths=[...new Set(execFileSync('git',['ls-files','--cached','--others','--exclude-standard','-z'],{cwd:root,maxBuffer:8*1024*1024}).toString().split('\0').filter(Boolean))];
 const entries=[],blobs=new Map(),tree=new Map(),gitHash=(type,bytes)=>createHash('sha1').update(type+' '+bytes.length+'\0').update(bytes).digest('hex');
 for(const path of paths){
  const file=join(root,path),stat=await lstat(file);need(stat.isFile()||stat.isSymbolicLink(),'ControlCompositionSourceEntry');
  const bytes=stat.isSymbolicLink()?Buffer.from(await readlink(file)):await readFile(file),oid=gitHash('blob',bytes);
  const row={path,mode:stat.isSymbolicLink()?'120000':stat.mode&0o111?'100755':'100644',type:'blob',oid};entries.push(row);blobs.set(oid,bytes);
  const parts=path.split('/');let node=tree;
  for(const part of parts.slice(0,-1)){if(!node.has(part))node.set(part,new Map());need(node.get(part)instanceof Map,'ControlCompositionSourceEntry');node=node.get(part);}
  node.set(parts.at(-1),row);
 }
 const treeHash=node=>gitHash('tree',Buffer.concat([...node].sort(([a,av],[b,bv])=>Buffer.compare(Buffer.from(a+(av instanceof Map?'/':'')),Buffer.from(b+(bv instanceof Map?'/':''))))
  .flatMap(([name,value])=>[Buffer.from((value instanceof Map?'40000':value.mode)+' '+name+'\0'),Buffer.from(value instanceof Map?treeHash(value):value.oid,'hex')])));
 return createControlSourceContext({tree:treeHash(tree),entries},async oid=>blobs.get(oid));
}
export function compactControlCompositionCode(code){
 // Keep the exact notices from the generated program, including copyright
 // comments that the minifier does not classify as legal comments. Parsing
 // avoids mistaking comment-like text in strings or regexes for a notice.
 const notices=[...new Set(parse(code,{sourceType:'module'}).comments
  .filter(comment=>/^!|@license|@preserve|\bcopyright\b/i.test(comment.value))
  .map(comment=>code.slice(comment.start,comment.end)))];
 const compact=minifySync('index.mjs',code,{module:true,compress:false,mangle:false,
  codegen:{removeWhitespace:true,asciiOnly:false,legalComments:'none'}});
 need(compact.errors.length===0,'ControlCompositionBundleCodegen');
 // Keep literal import specifiers in the form accepted by the source gate.
 // Codegen may otherwise spell a constant string as a template literal.
 const imports=[],visit=node=>{
  if(!node||typeof node!=='object')return;
  if(node.type==='ImportExpression'&&node.source.type==='TemplateLiteral'&&node.source.expressions.length===0){
   const source=node.source;imports.push([source.start,source.end,JSON.stringify(source.quasis[0].value.cooked)]);
  }
  for(const [key,value]of Object.entries(node))if(!['loc','extra','comments','tokens','leadingComments','innerComments','trailingComments'].includes(key))Array.isArray(value)?value.forEach(visit):visit(value);
 };
 visit(parse(compact.code,{sourceType:'module',createImportExpressions:true}));
 let output=compact.code;for(const[start,end,value]of imports.sort((a,b)=>b[0]-a[0]))output=output.slice(0,start)+value+output.slice(end);
 return output+'\n'+notices.join('\n')+'\n';
}
export async function bundleControlCompositionAction({check=false}={}){
 const lockBytes=await readFile(join(root,'package-lock.json')),lock=JSON.parse(lockBytes);
 need(lock.packages['node_modules/rolldown']?.version===version&&typeof lock.packages['node_modules/rolldown'].integrity==='string','ControlCompositionBundlerLock');
 const entry=join(root,'.github/actions/control-composition/index.mjs');
 const preserveModuleUrls={name:'control-composition-module-identity',transform(code,id){
  if(id===entry||!id.startsWith(root+'/')||!code.includes('import.meta.url')||!/[.]m?js$/.test(id))return;
  const ast=parse(code,{sourceType:'unambiguous',allowReturnOutsideFunction:true}),ranges=[];
  const fixedProbe=ast.program.body.find(node=>node.type==='FunctionDeclaration'&&node.id?.name==='fixedProbe');
  const moduleUrl=node=>node?.type==='MemberExpression'&&!node.computed&&node.object?.type==='MetaProperty'&&node.object.meta.name==='import'&&node.object.property.name==='meta'&&node.property?.name==='url';
  const visit=node=>{if(!node||typeof node!=='object')return;
   if(id.endsWith('/production-nonroot-control-prerequisites.mjs')&&node.type==='CallExpression'){
    if(node.callee?.name==='readFileSync'&&node.arguments.length===1&&node.arguments[0]?.type==='NewExpression'&&node.arguments[0].callee?.name==='URL'&&node.arguments[0].arguments.length===1&&moduleUrl(node.arguments[0].arguments[0])){ranges.push([node.start,node.end,'Buffer.from('+JSON.stringify(Buffer.from(code).toString('base64'))+', "base64")']);return;}
    if(fixedProbe&&node.callee?.type==='MemberExpression'&&node.callee.object?.name==='fixedProbe'&&node.callee.property?.name==='toString'&&node.arguments.length===0){ranges.push([node.start,node.end,JSON.stringify(code.slice(fixedProbe.start,fixedProbe.end))]);return;}
   }
   if(moduleUrl(node)){ranges.push([node.start,node.end]);return;}
   for(const [key,value]of Object.entries(node))if(!['loc','comments','tokens'].includes(key))Array.isArray(value)?value.forEach(visit):visit(value);
  };visit(ast);
  const replacement='new URL('+JSON.stringify(relative(directory,id))+', import.meta.url).href';for(const [start,end,custom]of ranges.sort((a,b)=>b[0]-a[0]))code=code.slice(0,start)+(custom??replacement)+code.slice(end);
  return {code,map:null};
 }};
 const warnings=[],bundle=await rolldown({cwd:root,input:entry,platform:'node',plugins:[preserveModuleUrls],onwarn:w=>warnings.push(w)});
 let result;try{result=await bundle.generate({format:'esm',codeSplitting:false,file:join(directory,'index.mjs'),banner:'import { createRequire as __compositionCreateRequire } from "node:module"; const require = __compositionCreateRequire(import.meta.url);'});}finally{await bundle.close();}
 need(warnings.length===0,'ControlCompositionBundleWarning');need(result.output.length===1&&result.output[0].type==='chunk','ControlCompositionBundleChunks');const chunk=result.output[0];
 const allowed=new Set(builtinModules.flatMap(k=>[k,'node:'+k.replace(/^node:/,'')]));
 for(const path of chunk.imports)need(allowed.has(path),'ControlCompositionBundleExternalDependency');
 for(const path of chunk.dynamicImports)need(allowed.has(path)||path===chunk.fileName,'ControlCompositionBundleExternalDependency');
 const inputs=[];for(const id of Object.keys(chunk.modules).sort()){
  if(id===RUNTIME_MODULE_ID)continue;const path=relative(root,id);
  need(!path.startsWith('/')&&!path.split('/').includes('..'),'ControlCompositionBundleSourcePath');const bytes=await readFile(join(root,path));
  let packagePin=null;if(path.startsWith('node_modules/')){const key=Object.keys(lock.packages).filter(key=>key.startsWith('node_modules/')&&path.startsWith(key+'/')).sort((a,b)=>b.length-a.length)[0],p=lock.packages[key];need(p&&!path.slice(key.length+1).split('/').includes('node_modules')&&typeof p.version==='string'&&typeof p.integrity==='string','ControlCompositionBundlePackageLock');packagePin={name:key.split('node_modules/').at(-1),version:p.version,integrity:p.integrity};}
  inputs.push({path,sha256:sha(bytes),bytesLength:bytes.length,...(packagePin?{packagePin}:{})});
 }
 // The reviewed region resolver and fixed script references also load local
 // source outside the bundle. Bind their full original transitive closure,
 // including SST configuration; keep all bundled dependency inputs as well.
 const known=new Map(inputs.map(row=>[row.path,row])),context=await currentSourceContext();
 for(const source of await ciSmokeSourceClosure(context,['.github/actions/control-composition/index.mjs'])){
  const old=known.get(source.path);
  if(old)need(old.sha256===source.sha256&&old.bytesLength===source.bytes,'ControlCompositionSourceChanged');
  else{const row={path:source.path,sha256:source.sha256,bytesLength:source.bytes};inputs.push(row);known.set(row.path,row);}
 }
 inputs.sort((a,b)=>a.path<b.path?-1:a.path>b.path?1:0);
 // Preserve the original bundling passes, then compact the final program.
 // Disable compression and all name/property mangling; retain legal notices
 // and the original probe/source string values installed by the plugin.
 const output=Buffer.from(compactControlCompositionCode(chunk.code)),manifest=Buffer.from(JSON.stringify({version:1,kind:'control-composition-ci-toolchain',nodeMajor:24,bundler:{name:'rolldown',version,integrity:lock.packages['node_modules/rolldown'].integrity,builderSourceHash:sha(await readFile(fileURLToPath(import.meta.url)))},packageLockHash:sha(lockBytes),inputs,output:{path:'.github/actions/control-composition/dist/index.mjs',sha256:sha(output),bytesLength:output.length}},null,2)+'\n');
 need(output.length<=8*1024*1024&&manifest.length<=8*1024*1024,'ControlCompositionBundleSourceBound');
 if(check){need((await readFile(join(directory,'index.mjs'))).equals(Buffer.from(output))&&(await readFile(join(directory,'toolchain.json'))).equals(manifest),'ControlCompositionBundleStale');}
 else{await mkdir(directory,{recursive:true});await writeFile(join(directory,'index.mjs'),output);await writeFile(join(directory,'toolchain.json'),manifest);}
 return {bundleHash:sha(output),bundleBytes:output.length,manifestHash:sha(manifest),manifestBytes:manifest.length,inputs:inputs.length};
}
if(process.argv[1]===fileURLToPath(import.meta.url)){
 need(process.argv.length<=3&&(process.argv.length===2||process.argv[2]==='--check'),'ControlCompositionBundleArguments');
 console.log(JSON.stringify(await bundleControlCompositionAction({check:process.argv[2]==='--check'})));
}
