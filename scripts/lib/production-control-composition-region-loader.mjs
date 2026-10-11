/** A single reviewed computed SST import in the emitted composition bundle.
 * This inspects the caller's existing Babel AST; it neither parses nor executes
 * code. The returned import identity is valid only after the complete walk and
 * finish check. Original source-closure authentication remains a prerequisite. */
import {createHash as compositionRegionCreateHash} from 'node:crypto';

const compositionRegionMaxBundleBytes=8388608;
const compositionRegionShapeBytes=65536;
const compositionRegionStateBytes=4096;
const compositionRegionNames=new Set(['importWithConfigShim','resolveApplicationRegion','DEFAULT_CONFIG_PATH','AWS_REGION_PATTERN','importSequence','configImportTail','init_application_region']);
const compositionRegionGlobals=new Set(['Promise','URL','String','Error','globalThis']);
const compositionRegionIgnored=new Set(['start','end','loc','extra','comments','leadingComments','trailingComments','innerComments','tokens']);
const compositionRegionShapePins=Object.freeze({
 shim:'f3e8ffb3e71952ed9d3471f641e873ebd25a315a676c1390624efac6190b04fd',resolver:'6f4b7ad080955783772223e198cbc00337a03d9c6262adee5b483f6a348f9e65',state:'07b602063bae602b41e007e4a9a44e1b3d25183a7605c09cadc73995b720d200',initializer:'256cf854f370f1178988a6f5a6f113e2c81be991c7eeab24867cb06f32e5c6e5',esm:'bd0ba4ba4432dff3105c6a2bf83c21dc0be2cdcc4f3e16524260c2d38cdee44b',
});
const compositionRegionNeed=(ok,reason='ControlCompositionRegionLoader')=>{if(!ok)throw Error(reason);};

/** Added work per preparation invocation. The caller must include this once
 * in its original prospective LOCAL payment. This is not a new allocation or
 * provider capability. The scan allowance is enforced during the existing AST
 * walk; shape encoding/hashing is separately bounded across all five roots. */
export function describeCompositionRegionLoaderWork(bundleBytes){
 compositionRegionNeed(Number.isSafeInteger(bundleBytes)&&bundleBytes>0&&bundleBytes<=compositionRegionMaxBundleBytes,'ControlCompositionRegionBundleBound');
 return Object.freeze({ecrRequests:0,httpBodyBytes:0,logicalBytes:16*bundleBytes+4*compositionRegionShapeBytes+compositionRegionStateBytes,uncompressedBytes:0,processedEntries:0});
}

export function createCompositionRegionLoaderInspection(ast,{bundleBytes}){
 const quote=describeCompositionRegionLoaderWork(bundleBytes),scanLimit=16*bundleBytes;
 let scanWork=0,shapeBytes=0,computedImport,computedSeen=0,resolverCalls=0,initializerCalls=0,finished=false;
 const owned=new WeakSet(),roots={},imports=new Map();
 const scan=n=>{compositionRegionNeed(Number.isSafeInteger(n)&&n>=0&&scanWork+n<=scanLimit,'ControlCompositionRegionScanBound');scanWork+=n;};
 const bind=(key,node)=>{compositionRegionNeed(!roots[key],'ControlCompositionRegionDuplicate');roots[key]=node;};
 compositionRegionNeed(ast?.type==='File'&&ast.program?.sourceType==='module'&&Array.isArray(ast.program.body));
 // These declarations must be in the actual program scope. Their complete
 // shapes, including the default SST URL and generated initializer, are bound.
 for(const statement of ast.program.body){
  scan(8);
  if(statement.type==='FunctionDeclaration'){
   if(statement.id?.name==='importWithConfigShim')bind('shim',statement);
   if(statement.id?.name==='resolveApplicationRegion')bind('resolver',statement);
  }
  if(statement.type==='VariableDeclaration')for(const declaration of statement.declarations){
   scan(8+2*(declaration.id?.name?.length??0));
   if(declaration.id?.name==='DEFAULT_CONFIG_PATH')bind('state',statement);
   if(declaration.id?.name==='init_application_region')bind('initializer',declaration);
   if(declaration.id?.name==='__esmMin')bind('esm',declaration);
  }
  if(statement.type==='ImportDeclaration')for(const specifier of statement.specifiers){
   scan(8+2*(specifier.local?.name?.length??0));
   const name=specifier.local?.name;
   if(['resolve','fileURLToPath','pathToFileURL'].includes(name)){
    compositionRegionNeed(!imports.has(name)&&specifier.type==='ImportSpecifier'&&specifier.imported.name===name&&statement.source.value===(name==='resolve'?'node:path':'node:url'),'ControlCompositionRegionBuiltinBinding');
    imports.set(name,specifier);
   }
  }
 }
 const enabled=Boolean(roots.shim||roots.resolver||roots.state||roots.initializer);
 function shape(root){
  compositionRegionNeed(Number.isSafeInteger(root.start)&&Number.isSafeInteger(root.end)&&root.start>=0&&root.end>root.start&&root.end<=bundleBytes&&root.end-root.start<=8192,'ControlCompositionRegionShapeBound');
  const digest=compositionRegionCreateHash('sha256');
  const emit=text=>{const size=Buffer.byteLength(text);compositionRegionNeed(shapeBytes+size<=compositionRegionShapeBytes,'ControlCompositionRegionShapeBound');shapeBytes+=size;digest.update(text);};
  const primitive=value=>{
   // Reserve the worst escaped size before JSON encoding a source string.
   if(typeof value==='string')compositionRegionNeed(shapeBytes+6*value.length+2<=compositionRegionShapeBytes,'ControlCompositionRegionShapeBound');
   emit(JSON.stringify(value));
  };
  function encode(value){
   if(value===null||typeof value!=='object'){primitive(value);return;}
   owned.add(value);
   if(Array.isArray(value)){emit('[');value.forEach((v,i)=>{if(i)emit(',');encode(v);});emit(']');return;}
   // Codegen may quote an unchanged string as an untagged, substitution-free
   // template. This normalization applies to the fixed shape only; ordinary
   // import admission elsewhere remains StringLiteral-only.
   if(value.type==='TemplateLiteral'&&value.expressions.length===0){
    emit('{"type":"StringLiteral","value":');primitive(value.quasis[0].value.cooked);emit('}');return;
   }
   const keys=Object.keys(value).filter(k=>!compositionRegionIgnored.has(k)&&value[k]!==undefined).sort();
   emit('{');keys.forEach((key,i)=>{if(i)emit(',');primitive(key);emit(':');encode(value[key]);});emit('}');
  }
  encode(root);return digest.digest('hex');
 }
 if(enabled){
  compositionRegionNeed(Object.keys(roots).length===5&&imports.size===3,'ControlCompositionRegionIncomplete');
  for(const key of ['shim','resolver','state','initializer','esm'])compositionRegionNeed(shape(roots[key])===compositionRegionShapePins[key],'ControlCompositionRegionShape:'+key);
  // Locate by node identity only inside the authenticated shim. There can be
  // no second computed import in that fixed body or elsewhere in the bundle.
  const seek=value=>{
   if(!value||typeof value!=='object')return;
   if(value.type==='ImportExpression'){compositionRegionNeed(!computedImport);computedImport=value;}
   for(const key of Object.keys(value))if(!compositionRegionIgnored.has(key)){const next=value[key];if(Array.isArray(next))next.forEach(seek);else if(next&&typeof next==='object')seek(next);}
  };seek(roots.shim);
  compositionRegionNeed(computedImport?.source?.type==='MemberExpression'&&computedImport.source.computed===false&&computedImport.source.object?.name==='configUrl'&&computedImport.source.property?.name==='href'&&computedImport.options==null);
 }
 function checkGlobalBinding(pattern){
  if(!pattern||typeof pattern!=='object')return;
  scan(8+2*(pattern.name?.length??0));
  if(pattern.type==='Identifier')compositionRegionNeed(!compositionRegionGlobals.has(pattern.name),'ControlCompositionRegionGlobalShadow');
  else if(pattern.type==='ObjectPattern')pattern.properties.forEach(p=>checkGlobalBinding(p.type==='RestElement'?p.argument:p.value));
  else if(pattern.type==='ArrayPattern')pattern.elements.forEach(checkGlobalBinding);
  else if(pattern.type==='AssignmentPattern')checkGlobalBinding(pattern.left);
  else if(pattern.type==='RestElement')checkGlobalBinding(pattern.argument);
 }
 return Object.freeze({
  observe(node,parent,key,functionDepth){
   compositionRegionNeed(!finished,'ControlCompositionRegionInspectionClosed');
   scan(8+(node.type==='Identifier'?2*node.name.length:0));
   if(!enabled)return;
   if(functionDepth===0){
    if(node.type==='VariableDeclarator')checkGlobalBinding(node.id);
    if(['FunctionDeclaration','ClassDeclaration'].includes(node.type))checkGlobalBinding(node.id);
    if(['ImportSpecifier','ImportDefaultSpecifier','ImportNamespaceSpecifier'].includes(node.type))checkGlobalBinding(node.local);
   }
   if(node===computedImport)computedSeen++;
   if(node.type!=='Identifier'||owned.has(node))return;
   if(node.name==='__esmMin'){
    compositionRegionNeed(parent?.type==='CallExpression'&&parent.callee===node&&parent.arguments.length===1&&!parent.optional,'ControlCompositionRegionInitializerBinding');return;
   }
   if(!compositionRegionNames.has(node.name))return;
   const direct=parent?.type==='CallExpression'&&parent.callee===node&&parent.arguments.length===0&&!parent.optional;
   if(node.name==='resolveApplicationRegion'&&direct){resolverCalls++;return;}
   if(node.name==='init_application_region'&&direct){initializerCalls++;return;}
   compositionRegionNeed(false,'ControlCompositionRegionBindingEscape');
  },
  allowsImport(node){return enabled&&node===computedImport;},
  finish(){
   compositionRegionNeed(!finished,'ControlCompositionRegionInspectionClosed');finished=true;
   if(enabled)compositionRegionNeed(computedSeen===1&&resolverCalls===1&&initializerCalls===1,'ControlCompositionRegionCallInventory');
   return Object.freeze({authority:false,regionLoader:enabled,scanWork,shapeBytes,quote});
  },
 });
}
