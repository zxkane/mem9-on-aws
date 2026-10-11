/** A separately reviewed native action is one committed bundle. Every
 * repository input remains a Git member; dependency pins bind package-lock.
 * This branch does not alter the legacy preparation/guard import policy. */
import {builtinModules} from 'node:module';
import {parseDocument} from 'yaml';
import {parse as parseSource} from '@babel/parser';
import {createCompositionRegionLoaderInspection} from './production-control-composition-region-loader.mjs';
import {readControlSourceFile} from './production-control-source.mjs';
import {ciSmokeSourceClosure} from './ci-smoke-isolation.mjs';
import {nonrootHash as hash,parseNonrootJson,inspectNonrootRecord} from './production-nonroot-contracts.mjs';
import {compositionNeed as need,compositionExact as exact} from './production-control-composition.mjs';
import {PRODUCTION_CONTROL_COMPOSITION_ACTION as ACTION,PRODUCTION_CONTROL_COMPOSITION_ENTRY as ENTRY,PRODUCTION_CONTROL_COMPOSITION_TOOLCHAIN as TOOLCHAIN} from './production-control-composition-recipe.mjs';

export const PRODUCTION_CONTROL_COMPOSITION_BUNDLE_BUILDER='scripts/build-control-composition-action.mjs';
export function verifyProductionControlCompositionAction(step,action){
 need(step?.uses==='./.github/actions/control-composition'&&step.id==='bootstrap'&&
  !Object.hasOwn(step,'run')&&!Object.hasOwn(step,'with')&&step['continue-on-error']!==true,'ControlCompositionActionStep');
 need(action&&Object.keys(action).every(k=>['name','description','outputs','runs'].includes(k)),'ControlCompositionAction');
 exact(action.runs,['using','main']);need(action.runs.using==='node24'&&action.runs.main==='dist/index.mjs','ControlCompositionActionRuntime');
 need(action.outputs&&Object.keys(action.outputs).sort().join()==='commitment,digest,image_tag','ControlCompositionActionOutputs');
 for(const value of Object.values(action.outputs)){exact(value,['description']);need(typeof value.description==='string'&&value.description.length>0,'ControlCompositionActionOutputs');}
 return Object.freeze({actionPath:ACTION,entryPath:ENTRY,toolchainPath:TOOLCHAIN});
}
export async function describeProductionControlCompositionPreparation(context,job){
 need(job&&Array.isArray(job.steps),'ControlCompositionPreparationJob');
 const local=job.steps.filter(s=>typeof s.uses==='string'&&s.uses.startsWith('./'));
 need(local.length===1,'ControlCompositionPreparationActions');
 const files=new Map(),read=async path=>{const row=await readControlSourceFile(context,path);files.set(path,row.file);return row;};
 const a=await read(ACTION),doc=parseDocument(new TextDecoder('utf-8',{fatal:true}).decode(a.bytes),{uniqueKeys:true});
 need(doc.errors.length===0&&doc.warnings.length===0,'ControlCompositionActionYaml');verifyProductionControlCompositionAction(local[0],doc.toJS({maxAliasCount:0}));
 const bundle=await read(ENTRY),toolchain=await read(TOOLCHAIN),lock=await read('package-lock.json'),builder=await read(PRODUCTION_CONTROL_COMPOSITION_BUNDLE_BUILDER);
 const m=parseNonrootJson(new TextDecoder('utf-8',{fatal:true}).decode(toolchain.bytes)),p=parseNonrootJson(new TextDecoder('utf-8',{fatal:true}).decode(lock.bytes));
 exact(m,['version','kind','nodeMajor','bundler','packageLockHash','inputs','output']);
 exact(m.bundler,['name','version','integrity','builderSourceHash']);exact(m.output,['path','sha256','bytesLength']);
 need(m.version===1&&m.kind==='control-composition-ci-toolchain'&&m.nodeMajor===24&&m.packageLockHash===lock.file.sha256&&m.bundler.name==='rolldown'&&
  m.bundler.builderSourceHash===builder.file.sha256&&p.packages?.['node_modules/rolldown']?.version===m.bundler.version&&p.packages['node_modules/rolldown'].integrity===m.bundler.integrity,'ControlCompositionToolchain');
 need(m.output.path===ENTRY&&m.output.sha256===bundle.file.sha256&&m.output.bytesLength===bundle.bytes.length,'ControlCompositionBundle');
 need(Array.isArray(m.inputs)&&m.inputs.length>0&&m.inputs.length<=8192,'ControlCompositionToolchainInputs');
 const seen=new Set();
 for(const row of m.inputs){
  exact(row,['path','sha256','bytesLength',...(Object.hasOwn(row,'packagePin')?['packagePin']:[])]);
  need(typeof row.path==='string'&&/^[A-Za-z0-9@_./+-]+$/.test(row.path)&&!row.path.startsWith('/')&&!row.path.split('/').some(p=>p==='.'||p==='..'||!p)&&
   !seen.has(row.path)&&/^[a-f0-9]{64}$/.test(row.sha256)&&Number.isSafeInteger(row.bytesLength)&&row.bytesLength>=0,'ControlCompositionToolchainInput');seen.add(row.path);
  if(row.path.startsWith('node_modules/')){
   exact(row.packagePin,['name','version','integrity']);
   const key=Object.keys(p.packages).filter(k=>k.startsWith('node_modules/')&&row.path.startsWith(k+'/')).sort((a,b)=>b.length-a.length)[0],pin=p.packages[key];
   need(key&&pin&&!row.path.slice(key.length+1).split('/').includes('node_modules')&&row.packagePin.name===key.split('node_modules/').at(-1)&&row.packagePin.version===pin.version&&row.packagePin.integrity===pin.integrity,'ControlCompositionPackagePin');
  }else{
   need(!row.packagePin&&row.path!==ENTRY&&row.path!==TOOLCHAIN,'ControlCompositionToolchainInput');
   const actual=await read(row.path);need(actual.file.sha256===row.sha256&&actual.bytes.length===row.bytesLength,'ControlCompositionToolchainSource');
  }
 }
 // The actual entry and implementation must occur in the bundled closure;
 // a manifest containing only unrelated repository files is not coverage.
 for(const required of ['.github/actions/control-composition/index.mjs','scripts/lib/production-control-composition-main.mjs','scripts/lib/production-control-composition-controller.mjs'])
  need(seen.has(required),'ControlCompositionToolchainClosure');
 const closure=await ciSmokeSourceClosure(context,['.github/actions/control-composition/index.mjs']);
 for(const row of closure)need(seen.has(row.path),'ControlCompositionToolchainClosure');
 const ast=parseSource(new TextDecoder('utf-8',{fatal:true}).decode(bundle.bytes),{sourceType:'module',createImportExpressions:true});
 const regionLoader=createCompositionRegionLoaderInspection(ast,{bundleBytes:bundle.bytes.length});
 const allowed=new Set(builtinModules.flatMap(k=>[k,'node:'+k.replace(/^node:/,'')]));
 const visit=(node,parent,key,functionDepth=0)=>{if(!node||typeof node!=='object')return;
  regionLoader.observe(node,parent,key,functionDepth);
  if(['ImportDeclaration','ExportNamedDeclaration','ExportAllDeclaration'].includes(node.type)&&node.source)need(allowed.has(node.source.value),'ControlCompositionBundleExternal');
  if(node.type==='ImportExpression')need(node.source?.type==='StringLiteral'&&(allowed.has(node.source.value)||node.source.value==='./index.mjs')||regionLoader.allowsImport(node),'ControlCompositionBundleExternal');
  const depth=functionDepth+Number(['FunctionDeclaration','FunctionExpression','ArrowFunctionExpression','ObjectMethod','ClassMethod','ClassPrivateMethod'].includes(node.type));
  for(const [k,v]of Object.entries(node))if(!['loc','comments','tokens'].includes(k))Array.isArray(v)?v.forEach(child=>visit(child,node,k,depth)):v&&typeof v==='object'&&visit(v,node,k,depth);
 };visit(ast);regionLoader.finish();
 // Shell commands in this fixed job may perform maintenance checks, but no
 // additional local script becomes an unaccounted preparation entry.
 for(const step of job.steps)if(typeof step.run==='string')need(!/\bscripts\/[A-Za-z0-9_./-]+\.(?:mjs|js|ts|sh)\b/.test(step.run),'ControlCompositionExtraPreparation');
 const ordered=[...files.values()].sort((a,b)=>a.path.localeCompare(b.path));
 return inspectNonrootRecord('SourceClosureV1',{version:1,kind:'git-file-closure',tree:context.tree,files:ordered,closureHash:hash(ordered)});
}
