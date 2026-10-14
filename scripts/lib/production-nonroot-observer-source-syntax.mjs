/** Source bytes are parsed as DATA, never imported/executed from archive paths. */
import {parse} from '@babel/parser';
import {need} from './production-nonroot-engineering-json.mjs';
const parsedSources=new WeakMap();

export function parseArchivedObserverSource(raw,path,{reader}){
 reader.current();need(raw instanceof Uint8Array,'ObserverHostSourceBytes');reader.paid.debit(observerHostSyntaxLocal(raw.byteLength));
 const source=new TextDecoder('utf-8',{fatal:true}).decode(raw);reader.current();
 if(path.endsWith('.json'))return {source,ast:null,description:describeObserverHostJson(source)};
 const ast=parse(source,{sourceType:'unambiguous',createImportExpressions:true,plugins:/\.[mc]?tsx?$/.test(path)?['typescript']:[]});reader.current();
 const description=describeObserverHostAst(ast,source);parsedSources.set(ast,{reader,bytes:raw.byteLength});
 return {source,ast,description};
}

/** Read only the fixed literal grammar used by original policy/catalog
 * declarations. There is no eval, dynamic import, property call or host IO. */
export function archivedObserverConstant(ast,name){
 const binding=parsedSources.get(ast);need(binding,'ObserverSourceParsedContext');const {reader}=binding;
 reader.current();reader.paid.debit(32*binding.bytes+65536);reader.current();
 const declarations=new Map();
 for(let node of ast.program.body){
  if(node.type==='ExportNamedDeclaration')node=node.declaration;
  if(node?.type==='VariableDeclaration')for(const d of node.declarations)if(d.id.type==='Identifier')declarations.set(d.id.name,d.init);
 }
 need(declarations.has(name),'ObserverSourceConstant');
 // Cost each distinct AST/declaration once, then add costs at every reference
 // occurrence. No output array/object/concatenated string exists yet. The IR
 // also detaches the grammar from AST mutation by a payment callback.
 const capBytes=33554432,capNodes=1000000,capDepth=64,memo=new Map(),active=new Set();let visited=0;
 const add=(a,b)=>{const n=a+b;need(Number.isSafeInteger(n),'ObserverSourceConstantBound');return n;};
 const stringBytes=value=>{
  let n=2;
  for(let i=0;i<value.length;i++){
   const c=value.charCodeAt(i);let bytes;
   if(c===34||c===92||[8,9,10,12,13].includes(c))bytes=2;
   else if(c<32)bytes=6;else if(c<128)bytes=1;else if(c<2048)bytes=2;
   else if(c>=0xd800&&c<=0xdbff){const next=value.charCodeAt(i+1);if(next>=0xdc00&&next<=0xdfff){bytes=4;i++;}else bytes=6;}
   else if(c>=0xdc00&&c<=0xdfff)bytes=6;else bytes=3;
   n=add(n,bytes);need(n<=capBytes,'ObserverSourceConstantBound');
  }
  return n;
 };
 const describe=node=>{
  need(node,'ObserverSourceConstant');
  if(['StringLiteral','NumericLiteral','BooleanLiteral'].includes(node.type))return {kind:'literal',value:node.value,dependencies:[]};
  if(node.type==='NullLiteral')return {kind:'literal',value:null,dependencies:[]};
  if(node.type==='Identifier'){need(declarations.has(node.name),'ObserverSourceConstant');return {kind:'alias',dependencies:[declarations.get(node.name)]};}
  if(node.type==='ArrayExpression'){need(node.elements.every(Boolean),'ObserverSourceConstant');return {kind:'array',dependencies:[...node.elements]};}
  if(node.type==='ObjectExpression'){
   const keys=[],dependencies=[],seen=new Set();
   for(const p of node.properties){need(p.type==='ObjectProperty'&&!p.computed,'ObserverSourceConstant');const key=p.key.name??p.key.value;need(typeof key==='string'&&!seen.has(key),'ObserverSourceConstant');seen.add(key);keys.push(key);dependencies.push(p.value);}
   return {kind:'object',keys,dependencies};
  }
  if(node.type==='BinaryExpression'&&node.operator==='+')return {kind:'concat',dependencies:[node.left,node.right]};
  if(node.type==='CallExpression'&&node.arguments.length===1&&(node.callee.type==='Identifier'&&node.callee.name==='freeze'||node.callee.type==='MemberExpression'&&!node.callee.computed&&node.callee.object.name==='Object'&&node.callee.property.name==='freeze'))return {kind:'alias',dependencies:[node.arguments[0]]};
  if(node.type==='NewExpression'&&node.callee.type==='Identifier'&&node.callee.name==='Map'&&node.arguments.length===1)return {kind:'alias',dependencies:[node.arguments[0]]};
  throw Error('ObserverSourceConstant');
 };
 const root=declarations.get(name),stack=[{node:root}];
 while(stack.length){
  const frame=stack.at(-1);
  if(memo.has(frame.node)){stack.pop();continue;}
  if(!frame.description){
   need(!active.has(frame.node)&&++visited<=capNodes,'ObserverSourceConstantBound');active.add(frame.node);
   frame.description=describe(frame.node);frame.next=0;
  }
  const d=frame.description;
  if(frame.next<d.dependencies.length){const node=d.dependencies[frame.next++];need(!active.has(node),'ObserverSourceConstant');if(!memo.has(node))stack.push({node});continue;}
  const children=d.dependencies.map(n=>memo.get(n));let bytes=0,nodes=1,depth=0,operations=1,type,first,last;
  for(const child of children)operations=add(operations,child.operations);
  if(d.kind==='literal'){
   type=typeof d.value;
   if(type==='string'){bytes=stringBytes(d.value);first=d.value.charCodeAt(0);last=d.value.charCodeAt(d.value.length-1);}
   else{need(d.value===null||type==='boolean'||Number.isSafeInteger(d.value),'ObserverSourceConstant');bytes=JSON.stringify(d.value).length;}
  }else if(d.kind==='alias'){
   ({bytes,nodes,depth,type,first,last}=children[0]);
  }else if(d.kind==='concat'){
   need(children.every(c=>c.type==='string'),'ObserverSourceConstant');const [a,b]=children;
   const joinedSurrogate=a.last>=0xd800&&a.last<=0xdbff&&b.first>=0xdc00&&b.first<=0xdfff;
   bytes=add(a.bytes,b.bytes)-2-(joinedSurrogate?8:0);type='string';first=Number.isNaN(a.first)?b.first:a.first;last=Number.isNaN(b.last)?a.last:b.last;
  }else{
   type=d.kind;bytes=2+Math.max(0,children.length-1);
   for(const [i,child]of children.entries()){bytes=add(bytes,child.bytes);nodes=add(nodes,child.nodes);depth=Math.max(depth,child.depth+1);if(d.kind==='object')bytes=add(bytes,stringBytes(d.keys[i])+1);}
  }
  need(bytes<=capBytes&&nodes<=capNodes&&depth<=capDepth,'ObserverSourceConstantBound');
  memo.set(frame.node,Object.freeze({kind:d.kind,value:d.value,keys:d.keys?Object.freeze([...d.keys]):undefined,children:Object.freeze(children),bytes,nodes,depth,operations,type,first,last}));active.delete(frame.node);stack.pop();
 }
 const recipe=memo.get(root),checks=Math.ceil(recipe.operations/1024)+2;
 const fee=16*recipe.bytes+128*recipe.nodes+128*recipe.operations+131072*checks+65536;
 need(Number.isSafeInteger(fee),'ObserverSourceConstantBound');
 reader.current();reader.paid.debit(fee);reader.current();
 // Construct only after the entire expansion fits and its original payer has
 // accepted the fee. Iteration avoids call-stack growth along alias chains.
 let count=0,result;const frames=[{node:recipe,next:0,values:[]}];
 while(frames.length){
  const frame=frames.at(-1),n=frame.node;
  if(frame.next<n.children.length){frames.push({node:n.children[frame.next++],next:0,values:[]});continue;}
  need(++count<=recipe.operations,'ObserverSourceConstantBound');if(count%1024===0)reader.current();
  let value;
  if(n.kind==='literal')value=n.value;
  else if(n.kind==='alias')value=frame.values[0];
  else if(n.kind==='concat')value=frame.values[0]+frame.values[1];
  else if(n.kind==='array')value=frame.values;
  else{value=Object.create(null);for(let i=0;i<n.keys.length;i++)value[n.keys[i]]=frame.values[i];}
  frames.pop();if(frames.length)frames.at(-1).values.push(value);else result=value;
 }
 reader.current();return result;
}
export const observerHostSyntaxLocal=bytes=>{need(Number.isSafeInteger(bytes)&&bytes>=0&&bytes<=33554432,'ObserverHostSourceBound');return 48*bytes+131072;};
export function describeObserverHostJson(source){JSON.parse(source);return {imports:[],computed:[],constructors:[],requires:[],parserPins:null};}
export function describeObserverHostAst(ast,source){
 const imports=[],computed=[],constructors=[],requires=[],aliases=new Map(),nodes=[],inputBytes=Buffer.byteLength(source);let steps=0,outputBytes=0;
 const stack=[{node:ast,fn:null}];
 while(stack.length){const {node:n,fn:parent}=stack.pop();if(!n||typeof n!=='object')continue;need(++steps<=12*inputBytes+8192,'ObserverHostWalkBound');
  const fn=n.type==='FunctionDeclaration'?n.id?.name??parent:parent;nodes.push({n,fn});
  if(['ImportDeclaration','ExportNamedDeclaration','ExportAllDeclaration'].includes(n.type)&&n.source&&n.importKind!=='type'&&n.exportKind!=='type')imports.push({specifier:n.source.value,kind:'static',start:n.start});
  if(n.type==='ImportExpression'){
   if(n.source.type==='StringLiteral')imports.push({specifier:n.source.value,kind:'deferred',start:n.start,function:fn});
   else{const expression=source.slice(n.start,n.end);outputBytes+=Buffer.byteLength(expression);computed.push({kind:'import',start:n.start,end:n.end,function:fn,expression});}
  }
  if(n.type==='VariableDeclarator'&&n.id.type==='Identifier'&&n.init?.type==='CallExpression'&&n.init.callee?.name==='createRequire'){
   const expression=source.slice(n.init.start,n.init.end),base=n.init.arguments.length===1&&n.init.arguments[0].type==='StringLiteral'?n.init.arguments[0].value:null;
   constructors.push({kind:'createRequire',start:n.init.start,end:n.init.end,alias:n.id.name,base,expression});aliases.set(n.id.name,base);
  }
  for(const[k,v]of Object.entries(n))if(!['loc','start','end','extra','comments','tokens'].includes(k)){if(Array.isArray(v))for(const x of v)stack.push({node:x,fn});else if(v&&typeof v==='object')stack.push({node:v,fn});}
 }
 const constructorStarts=new Set(constructors.map(c=>c.start));
 for(const {n}of nodes)if(n.type==='CallExpression'&&(n.callee?.name==='createRequire'||n.callee?.property?.name==='createRequire'))need(constructorStarts.has(n.start),'ObserverUnclassifiedRequireConstructor');
 for(const {n}of nodes)if(n.type==='CallExpression'&&n.callee?.type==='Identifier'&&(aliases.has(n.callee.name)||n.callee.name==='require')){
  need(aliases.has(n.callee.name)&&n.arguments.length===1&&n.arguments[0].type==='StringLiteral','ObserverUnclassifiedRequire');requires.push({alias:n.callee.name,specifier:n.arguments[0].value,start:n.start});
 }
 const parserNode=nodes.find(({n})=>n.type==='VariableDeclarator'&&n.id?.name==='SOURCE_DEPENDENCY_PARSER')?.n;
 let parserPins=null;
 if(parserNode){const value=parserNode.init?.arguments?.[0];need(value?.type==='ArrayExpression','ObserverParserPinSyntax');parserPins=value.elements.map(n=>{need(n.type==='ObjectExpression','ObserverParserPinSyntax');const row={};for(const p of n.properties){need(p.type==='ObjectProperty'&&!p.computed&&['StringLiteral','NumericLiteral'].includes(p.value.type),'ObserverParserPinSyntax');row[p.key.name??p.key.value]=p.value.value;}return row;});}
 need(outputBytes<=2*inputBytes+4096,'ObserverHostDescriptionBound');
 const order=(a,b)=>a.start-b.start;return {imports:imports.sort(order),computed:computed.sort(order),constructors:constructors.sort(order),requires:requires.sort(order),parserPins};
}

/** Original literal dependency scan; parser loading/IO is absent. */
export function scanArchivedObserverDependencies(raw,{check}){
 check();need(raw instanceof Uint8Array&&raw.byteLength<=33554432,'SourceDependencyInputBound');const bytes=raw.byteLength;
  const ast=parse(new TextDecoder('utf-8',{fatal:true}).decode(raw),{sourceType:'module',createImportExpressions:true});
  const result=[],stack=[ast],limit=8*bytes+4096;let steps=0,outputBytes=0;
  const step=()=>need(++steps<=limit,'SourceDependencyWalkBound');
  while(stack.length){
   const node=stack.pop();if(!node||typeof node!=='object')continue;
   if(node.type==='ImportExpression'&&node.source?.type!=='StringLiteral'){
    let lead=node.source;
    while(lead){
     step();need(lead.type!=='StringLiteral'||!lead.value.startsWith('.')&&!lead.value.startsWith('/'),'SourceDependencyComputedLiteral');
     if(['BinaryExpression','LogicalExpression'].includes(lead.type))lead=lead.left;
     else if(lead.type==='ConditionalExpression')lead=lead.test;
     else if(lead.type==='SequenceExpression')lead=lead.expressions[0];
     else if(['MemberExpression','OptionalMemberExpression'].includes(lead.type))lead=lead.object;
     else if(['CallExpression','OptionalCallExpression'].includes(lead.type))lead=lead.callee;
     else if(lead.type==='TaggedTemplateExpression')lead=lead.tag;
     else if(lead.type==='ParenthesizedExpression')lead=lead.expression;
     else break;
    }
   }
   if(['ImportDeclaration','ExportNamedDeclaration','ExportAllDeclaration','ImportExpression'].includes(node.type)&&node.source?.type==='StringLiteral'){
    outputBytes+=Buffer.byteLength(node.source.value);need(outputBytes<=bytes,'SourceDependencyOutputBound');result.push(node.source.value);
   }
   if(Array.isArray(node)){for(let i=0;i<node.length;i++){step();if(node[i]&&typeof node[i]==='object')stack.push(node[i]);}}
   else for(const key in node){step();if(['loc','start','end','comments','extra','leadingComments','innerComments','trailingComments','tokens'].includes(key))continue;const value=node[key];if(value&&typeof value==='object')stack.push(value);}
  }
  return result;
}
