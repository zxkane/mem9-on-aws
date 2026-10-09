/** Local, reproducible packaging. CI runs these committed bytes and never
 * installs tools/packages while the original copy deadline is running. */
import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {builtinModules} from 'node:module';
import {fileURLToPath} from 'node:url';
import {dirname,join,relative,resolve} from 'node:path';
import {rolldown,VERSION as version,RUNTIME_MODULE_ID} from 'rolldown';
import {parse} from '@babel/parser';

const root=resolve(dirname(fileURLToPath(import.meta.url)),'..'),directory=join(root,'.github/actions/ci-carrier-before-copy/dist'),sha=b=>createHash('sha256').update(b).digest('hex');
const need=(v,c)=>{if(!v)throw Error(c);};
export async function bundleCarrierAction({check=false}={}){
 const lockBytes=await readFile(join(root,'package-lock.json')),lock=JSON.parse(lockBytes);
 need(lock.packages['node_modules/rolldown']?.version===version&&typeof lock.packages['node_modules/rolldown'].integrity==='string','CarrierBundlerLock');
 const entry=join(root,'.github/actions/ci-carrier-before-copy/index.mjs');
 const preserveModuleUrls={name:'carrier-module-identity',transform(code,id){
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
 let result;try{result=await bundle.generate({format:'esm',codeSplitting:false,file:join(directory,'index.mjs'),banner:'import { createRequire as __carrierCreateRequire } from "node:module"; const require = __carrierCreateRequire(import.meta.url);'});}finally{await bundle.close();}
 need(warnings.length===0,'CarrierBundleWarning');need(result.output.length===1&&result.output[0].type==='chunk','CarrierBundleChunks');const chunk=result.output[0];
 const allowed=new Set(builtinModules.flatMap(k=>[k,'node:'+k.replace(/^node:/,'')]));
 for(const path of chunk.imports)need(allowed.has(path),'CarrierBundleExternalDependency');
 for(const path of chunk.dynamicImports)need(allowed.has(path)||path===chunk.fileName,'CarrierBundleExternalDependency');
 const inputs=[];for(const id of Object.keys(chunk.modules).sort()){
  if(id===RUNTIME_MODULE_ID)continue;const path=relative(root,id);
  need(!path.startsWith('/')&&!path.split('/').includes('..'),'CarrierBundleSourcePath');const bytes=await readFile(join(root,path));
  let packagePin=null;if(path.startsWith('node_modules/')){const parts=path.split('/'),name=parts[1].startsWith('@')?parts.slice(1,3).join('/'):parts[1],key='node_modules/'+name,p=lock.packages[key];need(p&&typeof p.version==='string'&&typeof p.integrity==='string','CarrierBundlePackageLock');packagePin={name,version:p.version,integrity:p.integrity};}
  inputs.push({path,sha256:sha(bytes),bytesLength:bytes.length,...(packagePin?{packagePin}:{})});
 }
 const output=Buffer.from(chunk.code),manifest=Buffer.from(JSON.stringify({version:1,kind:'carrier-ci-toolchain',nodeMajor:24,bundler:{name:'rolldown',version,integrity:lock.packages['node_modules/rolldown'].integrity,builderSourceHash:sha(await readFile(fileURLToPath(import.meta.url)))},packageLockHash:sha(lockBytes),inputs,output:{path:'.github/actions/ci-carrier-before-copy/dist/index.mjs',sha256:sha(output),bytesLength:output.length}},null,2)+'\n');
 if(check){need((await readFile(join(directory,'index.mjs'))).equals(Buffer.from(output))&&(await readFile(join(directory,'toolchain.json'))).equals(manifest),'CarrierBundleStale');}
 else{await mkdir(directory,{recursive:true});await writeFile(join(directory,'index.mjs'),output);await writeFile(join(directory,'toolchain.json'),manifest);}
 return {bundleHash:sha(output),bundleBytes:output.length,manifestHash:sha(manifest),manifestBytes:manifest.length,inputs:inputs.length};
}
if(process.argv[1]===fileURLToPath(import.meta.url)){
 need(process.argv.length<=3&&(process.argv.length===2||process.argv[2]==='--check'),'CarrierBundleArguments');
 console.log(JSON.stringify(await bundleCarrierAction({check:process.argv[2]==='--check'})));
}
