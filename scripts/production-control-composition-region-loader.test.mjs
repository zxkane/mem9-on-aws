import {beforeAll,test,expect} from 'vitest';
import {readFile} from 'node:fs/promises';
import {builtinModules} from 'node:module';
import {parse} from '@babel/parser';
import {createCompositionRegionLoaderInspection,describeCompositionRegionLoaderWork} from './lib/production-control-composition-region-loader.mjs';

const compositionRegionTestAllowed=new Set(builtinModules.flatMap(name=>[name,'node:'+name.replace(/^node:/,'')]));
let compositionRegionTestBundle,compositionRegionTestAst,compositionRegionTestFixture;
const compositionRegionTestParse=code=>parse(code,{sourceType:'module',createImportExpressions:true});

beforeAll(async()=>{
 compositionRegionTestBundle=await readFile(new URL('../.github/actions/control-composition/dist/index.mjs',import.meta.url),'utf8');
 compositionRegionTestAst=compositionRegionTestParse(compositionRegionTestBundle);
 const fragments=[];
 for(const node of compositionRegionTestAst.program.body){
  if(node.type==='FunctionDeclaration'&&['importWithConfigShim','resolveApplicationRegion'].includes(node.id?.name))fragments.push(compositionRegionTestBundle.slice(node.start,node.end));
  if(node.type==='VariableDeclaration'){
   if(node.declarations.some(d=>d.id?.name==='DEFAULT_CONFIG_PATH'))fragments.push(compositionRegionTestBundle.slice(node.start,node.end));
   for(const declaration of node.declarations)if(['init_application_region','__esmMin'].includes(declaration.id?.name))fragments.push('var '+compositionRegionTestBundle.slice(declaration.start,declaration.end)+';');
  }
 }
 expect(fragments).toHaveLength(5);
 compositionRegionTestFixture='import {resolve} from "node:path";\nimport {fileURLToPath,pathToFileURL} from "node:url";\n'+fragments.join('\n')+'\ninit_application_region();\nawait resolveApplicationRegion();\n';
});

// Exercise the real helper on the same AST and parent identities delivered by
// preparation. This executes no bundle, loader, SST config or provider code.
function compositionRegionTestInspect(code,ast=compositionRegionTestParse(code)){
 const inspection=createCompositionRegionLoaderInspection(ast,{bundleBytes:Buffer.byteLength(code)}),computed=[];
 const visit=(node,parent,key,functionDepth=0)=>{
  if(!node||typeof node!=='object')return;
  inspection.observe(node,parent,key,functionDepth);
  if(node.type==='ImportExpression'){
   const literal=node.source?.type==='StringLiteral'&&(compositionRegionTestAllowed.has(node.source.value)||node.source.value==='./index.mjs');
   if(!literal&&!inspection.allowsImport(node))throw Error('ControlCompositionBundleExternal');
   if(!literal)computed.push(node);
  }
  const depth=functionDepth+Number(['FunctionDeclaration','FunctionExpression','ArrowFunctionExpression','ObjectMethod','ClassMethod','ClassPrivateMethod'].includes(node.type));
  for(const[k,v]of Object.entries(node))if(!['loc','comments','tokens'].includes(k))Array.isArray(v)?v.forEach(child=>visit(child,node,k,depth)):v&&typeof v==='object'&&visit(v,node,k,depth);
 };
 visit(ast);return {computed,work:inspection.finish()};
}

test('actual complete bundle admits only its original computed SST loader import',()=>{
 const result=compositionRegionTestInspect(compositionRegionTestBundle,compositionRegionTestAst);
 expect(result.computed).toHaveLength(1);expect(result.computed[0].source.object.name).toBe('configUrl');
 expect(result.work.regionLoader).toBe(true);expect(result.work.authority).toBe(false);
 expect(result.work.scanWork).toBeLessThanOrEqual(16*Buffer.byteLength(compositionRegionTestBundle));
 expect(result.work.shapeBytes).toBeLessThanOrEqual(65536);
});
test('original StringLiteral-only rule reproduces the actual computed-import rejection',()=>{
 const found=[];const visit=n=>{if(!n||typeof n!=='object')return;if(n.type==='ImportExpression'&&n.source.type!=='StringLiteral')found.push(n);for(const[k,v]of Object.entries(n))if(!['loc','comments','tokens'].includes(k))Array.isArray(v)?v.forEach(visit):v&&typeof v==='object'&&visit(v);};visit(compositionRegionTestAst);
 expect(found).toHaveLength(1);expect(found[0].source.type).toBe('MemberExpression');
});
test('reviewed emitted loader with exact imported bindings and original call counts passes',()=>{
 expect(compositionRegionTestInspect(compositionRegionTestFixture).work.regionLoader).toBe(true);
});

const compositionRegionTestMutations=[
 ['foreign computed import',s=>s+'\nawait import(otherUrl.href);'],
 ['same configUrl spelling in another function',s=>s+'\nasync function foreign(configUrl){return import(configUrl.href)}'],
 ['changed default config path',s=>s.replace('../../sst.config.ts','../../foreign.config.ts')],
 ['explicit resolver arguments',s=>s.replace('await resolveApplicationRegion();','await resolveApplicationRegion({configPath:"/foreign.ts"});')],
 ['escaped resolver binding',s=>s.replace('await resolveApplicationRegion();','const stolen=resolveApplicationRegion;await stolen();')],
 ['object escape',s=>s+'\nconst leaked={resolveApplicationRegion};'],
 ['shadowed resolver binding',s=>s+'\nfunction foreign(resolveApplicationRegion){return resolveApplicationRegion()}'],
 ['extra resolver caller',s=>s+'\nawait resolveApplicationRegion();'],
 ['extra shim caller',s=>s+'\nawait importWithConfigShim(new URL("file:///foreign.ts"));'],
 ['extra initializer caller',s=>s+'\ninit_application_region();'],
 ['unreviewed state write',s=>s+'\nimportSequence=0;'],
 ['altered shim cleanup',s=>s.replace('releaseImport()','void 0')],
 ['altered initializer',s=>s.replace('configImportTail=Promise.resolve()','configImportTail=Promise.reject()')],
 ['altered cache-buster',s=>s.replace('application-region-read','foreign-region-read')],
 ['resource-producing run instead of app',s=>s.replace('.default?.app','.default?.run')],
 ['wrong builtin import',s=>s.replace('from "node:path"','from "node:fs"')],
 ['global constructor shadow',s=>'const Promise={resolve(){return null}};\n'+s],
 ['reassigned generated initializer helper',s=>s+'\n__esmMin=()=>()=>{};'],
 ['computed import options',s=>s.replace('import(configUrl.href)','import(configUrl.href,{})')],
 ['builtin template remains disallowed',s=>s+'\nawait import(`node:fs`);'],
 ['interpolated builtin template',s=>s+'\nawait import(`node:${service}`);'],
];
test.each(compositionRegionTestMutations)('rejects %s',(_name,change)=>{
 const altered=change(compositionRegionTestFixture);expect(altered).not.toBe(compositionRegionTestFixture);
 expect(()=>compositionRegionTestInspect(altered)).toThrow();
});
test('ordinary literal imports need no region exception',()=>{
 const result=compositionRegionTestInspect('await import("node:fs");');expect(result.work.regionLoader).toBe(false);expect(result.computed).toHaveLength(0);
});
test('the added work quote is finite and retains the original 8MiB source cap',()=>{
 expect(describeCompositionRegionLoaderWork(8388608)).toEqual({ecrRequests:0,httpBodyBytes:0,logicalBytes:134483968,uncompressedBytes:0,processedEntries:0});
 for(const bytes of [0,-1,1.5,8388609,Number.MAX_SAFE_INTEGER])expect(()=>describeCompositionRegionLoaderWork(bytes)).toThrow();
});
test('declared processing bound cannot be exceeded by a larger supplied AST',()=>{
 expect(()=>createCompositionRegionLoaderInspection(compositionRegionTestAst,{bundleBytes:1})).toThrow(/Bound/);
});
