import {assertObserverAccountingBinding} from './production-nonroot-observer-accounting.mjs';
/** Full archived source-model verification; historical paths are lookup keys
 * only. No archived code, credential source or host file is executed/read. */
import {dirname,join,resolve} from 'node:path';
import {isBuiltin} from 'node:module';
import {need,exact,hash,sha,json,same,canonical,immutable} from './production-nonroot-engineering-json.mjs';
import {parseArchivedObserverSource,archivedObserverConstant} from './production-nonroot-observer-source-syntax.mjs';
import {verifyArchivedObserverSourceOriginals} from './production-nonroot-observer-source-originals.mjs';

const purpose='original-preview-overlap-isolated-owner-v1';
const sdkNames=['@aws-sdk/client-ecs','@aws-sdk/client-ssm','@aws-sdk/client-servicediscovery','@aws-sdk/client-cloudwatch-logs','@aws-sdk/client-sts','@smithy/node-http-handler'];
const parserNames=['index.js','package.json'];
const parserHashes=['6969920ae0610df927b6b3e675d1309372c268e36d391652af8e3e0183cbe8f8','6d6a65b879cd7cd249a4367c0b57cce00e78c728de45056ac2a5ca1d1f528d1a'];
const parserSizes=[513214,1382];
const states=new WeakMap();

export async function replayArchivedObserverSourceModel({plan,input,sourceModelRef},{reader}){
 reader.current();reader.paid.debit(32*67108864);
 ({plan,input,sourceModelRef}=immutable(json(Buffer.from(canonical({plan,input,sourceModelRef})),67108864)));
 assertObserverAccountingBinding(plan,input);
 need(sourceModelRef&&Number.isSafeInteger(sourceModelRef.bytesLength),'ObserverSourceModelRef');
 reader.paid.debit(32*sourceModelRef.bytesLength+65536);
 const model=await reader.json(sourceModelRef,4194304);reader.current();
 exact(model,['version','kind','authority','owner','operation','planHash','sourceHash','scope','ownerInput','inputs','node','hostCatalogue','packageCatalogue','parserPins','sources','originals']);
 need(model.version===1&&model.kind==='original-observer-authenticated-source-model'&&model.authority===false&&model.owner===plan.owner&&model.operation===plan.operation,'ObserverSourceModelOwner');
 need(model.planHash===hash(plan)&&model.sourceHash===hash(plan.source),'ObserverSourceModelPlan');
 same(model.scope,Object.fromEntries(['account','region','stsRegion','baseRoleArn'].map(k=>[k,plan.scope[k]])),'ObserverSourceModelScope');
 const nonsecret=ref=>{need(ref&&ref.path!==plan.scope.sourceCredentialsRef.path&&ref.sha256!==plan.scope.sourceCredentialsRef.sha256,'ObserverCredentialBodyArchiveForbidden');return ref;};
 const material=async row=>{
  exact(row,['original','blob']);const r=nonsecret(row.original);
  need(row.blob.sha256===r.sha256&&row.blob.bytesLength===r.bytesLength,'ObserverSourceModelBlob');
  const raw=await reader.readBytes(row.blob,33554432);reader.current();
  const copy=Buffer.from(raw);need(copy.length===r.bytesLength&&sha(copy)===r.sha256,'ObserverSourceModelBlob');return copy;
 };
 same(model.ownerInput.original,plan.ownerRef,'ObserverSourceModelOwnerRef');
 const ownerRaw=await material(model.ownerInput);reader.current();
 const {ownerRef,...approved}=plan;
 same(json(ownerRaw,65536),{version:1,kind:purpose,owner:plan.owner,operation:plan.operation,planHash:hash(approved)},'ObserverSourceModelApproval');
 same(model.inputs.original,plan.inputsRef,'ObserverSourceModelInputRef');
 const inputRaw=await material(model.inputs);reader.current();same(json(inputRaw,33554432),input,'ObserverSourceModelInput');
 same(model.node.reference,plan.source.node,'ObserverSourceModelNode');
 same(model.node.identity,{authority:false,kind:'original-executing-node-identity',sha256:plan.source.node.sha256,bytesLength:plan.source.node.bytesLength},'ObserverSourceModelNode');
 // This is the original native executing-file receipt. It is not a new
 // execution claim, executable body, or credit against this replay payer.
 need(Array.isArray(model.sources)&&model.sources.length>0&&model.sources.length<=20000,'ObserverSourceModelFiles');
 reader.paid.debit(8192*model.sources.length);
 const files=new Map(),rows=new Map(),sourceBlobs=new Map();
 for(const row of model.sources){
  need(!rows.has(row.original.path),'ObserverSourceModelDuplicate');
  const raw=await material(row);reader.current();files.set(row.original.path,raw);rows.set(row.original.path,row.original);sourceBlobs.set(row.original.path,row.blob);
 }
 const root=plan.source.roots[0],directory=dirname(root);
 need(plan.source.roots.length===1,'ObserverHostEntryBinding');
 const source=(path)=>{reader.current();const raw=files.get(path);need(raw,'ObserverSourceModelMissing');return parseArchivedObserverSource(raw,path,{reader});};
 const packageModule=source(join(directory,'observer-package-catalog.mjs'));
 const packageText=archivedObserverConstant(packageModule.ast,'OBSERVER_PACKAGE_CATALOG_JSON');
 need(typeof packageText==='string'&&Buffer.byteLength(packageText)<=33554432,'ObserverSourceModelPackage');
 const packageRaw=await reader.readBytes(model.packageCatalogue,33554432);reader.current();
 need(packageRaw.equals(Buffer.from(packageText)),'ObserverSourceModelPackageBytes');
 const packages=json(packageRaw,33554432);
 for(const key of ['files','packageRoots','bindings','fileBindings','literalRequires','esmEdges','roots'])need(Array.isArray(packages[key])&&packages[key].length<=200000,'ObserverSourceModelPackageBound');
 const expectedRows=new Map();
 for(const r of [...packages.files,...plan.source.files]){const old=expectedRows.get(r.path);need(!old||old.sha256===r.sha256&&old.bytesLength===r.bytesLength,'ObserverSourceModelConflict');expectedRows.set(r.path,r);}
 need(rows.size===expectedRows.size,'ObserverSourceModelCoverage');
 for(const [path,r]of expectedRows){const actual=rows.get(path);need(actual&&actual.sha256===r.sha256&&actual.bytesLength===r.bytesLength,'ObserverSourceModelCoverage');}
 same(model.hostCatalogue.original,rows.get(join(directory,'host-catalog.local.json')),'ObserverSourceModelHostRef');
 same(model.hostCatalogue.blob,sourceBlobs.get(model.hostCatalogue.original.path),'ObserverSourceModelHostBlob');
 const hostCatalogue=json(files.get(model.hostCatalogue.original.path),33554432);
 need(hostCatalogue.version===1&&hostCatalogue.kind==='original-observer-host-closure'&&hostCatalogue.authority===false&&hostCatalogue.root===root,'ObserverHostCatalogKind');
 const privatePolicy=source(join(directory,'host-closure.mjs'));
 const constant=name=>archivedObserverConstant(privatePolicy.ast,name);
 const policy={root,publicRoot:constant('publicRoot'),parserSibling:constant('parserSibling'),sdk:constant('sdk'),parserExpression:constant('parserExpression'),imageImports:new Map(constant('imageImports'))};
 need(typeof policy.publicRoot==='string'&&resolve(policy.publicRoot)===policy.publicRoot&&typeof policy.parserSibling==='string'&&resolve(policy.parserSibling)===policy.parserSibling,'ObserverSourceModelPolicyPath');
 same([...policy.imageImports],[[policy.publicRoot+'/scripts/lib/production-nonroot-observer-control-context.mjs','openObserverControlContext'],[policy.publicRoot+'/scripts/lib/production-nonroot-observer-runtime-provider.mjs','openObserverRuntimeProvider']],'ObserverSourceModelImageImports');
 same(policy.sdk,plan.version===3?[...sdkNames.slice(0,-1),'@aws-sdk/client-service-quotas','@aws-sdk/client-cloudwatch',sdkNames.at(-1)]:sdkNames,'ObserverSourceModelSdk');
 need(policy.parserExpression==='import(pathToFileURL(SOURCE_DEPENDENCY_PARSER[0].path).href)','ObserverSourceModelParserExpression');
 need(Array.isArray(model.parserPins)&&model.parserPins.length===2,'ObserverSourceModelParser');
 policy.parserPins=model.parserPins.map((r,i)=>{
  exact(r,['original','blob']);
  same(r.original,rows.get(r.original.path),'ObserverSourceModelParser');
  same(r.blob,sourceBlobs.get(r.original.path),'ObserverSourceModelParserBlob');
  need(r.original.path.endsWith('/@babel/parser/'+(i===0?'lib/':'')+parserNames[i])&&r.original.sha256===parserHashes[i]&&r.original.bytesLength===parserSizes[i],'ObserverSourceModelParser');
  return {path:r.original.path,sha256:r.original.sha256,bytes:r.original.bytesLength};
 });
 const packageFiles=new Set(packages.files.map(f=>f.path));
 const locks=new Map(packages.packageRoots.map(r=>{need(files.has(r.lock.path),'ObserverPackageLockBinding');return [r.root,json(files.get(r.lock.path),33554432)];}));
 for(const b of packages.bindings){
  const lock=locks.get(b.base),raw=files.get(b.metadata.path);need(lock&&raw,'ObserverPackageLockBinding');
  const pkg=json(raw,33554432),row=lock.packages[b.key];need(row&&pkg.name===b.name&&pkg.version===b.version&&row.version===b.version&&row.integrity===b.integrity,'ObserverPackageLockBinding');
 }
 const packageBindings=new Map(packages.bindings.map(b=>[b.base+'/'+b.key,b]));
 for(const f of packages.fileBindings)need(packageBindings.has(f.base+'/'+f.key)&&f.path.startsWith(f.base+'/'+f.key+'/')&&!f.path.slice((f.base+'/'+f.key+'/').length).split('/').includes('node_modules'),'ObserverUnlockedNestedPackage');
 for(const edge of [...packages.literalRequires,...packages.esmEdges])need(packageFiles.has(edge.from)&&(edge.builtin||packageFiles.has(edge.target)),'ObserverPackageEdgeMissing');
 for(const r of packages.roots)need(packageFiles.has(r.path),'ObserverPackageRootMissing');
 const hostRows=new Map(hostCatalogue.files.map(r=>[r.path,r])),declared=new Map(plan.source.files.map(r=>[r.path,r]));
 need(hostCatalogue.files.length>0&&hostCatalogue.files.length<=20000,'ObserverHostCatalogBound');
 need(hostRows.size===hostCatalogue.files.length,'ObserverHostDuplicate');
 const pending=[root],visited=new Set();let imageEdges=0;
 while(pending.length){
  reader.current();const path=pending.pop();if(visited.has(path))continue;visited.add(path);
  const row=hostRows.get(path),pin=declared.get(path);need(row&&pin&&row.sha256===pin.sha256&&row.bytesLength===pin.bytesLength,'ObserverHostSourceBinding');
  const parsed=source(path);same(parsed.description,row.description,'ObserverHostDescriptionChanged');
  const links=describeArchivedObserverHostLinks(path,parsed.description,packages.roots,policy);same(links,row.links,'ObserverHostEdgesChanged');
  for(const edge of links){if(edge.builtin)continue;if(edge.image){imageEdges++;continue;}if(edge.package){need(packageFiles.has(edge.target)&&files.has(edge.target),'ObserverHostPackageMissing');continue;}need(hostRows.has(edge.target),'ObserverHostEdgeMissing');pending.push(edge.target);}
 }
 need(visited.size===hostRows.size&&imageEdges===2,'ObserverHostUnreachableOrImageBoundary');
 // Preserve every declared original occurrence. Image blobs and the raw
 // credentials reference are intentionally outside this typed source set.
 verifyArchivedObserverSourceOriginals(input,model.originals);
 const originals=[];
 for(const row of model.originals){
  need(['DATA-prerequisite','CONTROL-source','CONTROL-proof'].includes(row.kind),'ObserverSourceModelOriginalKind');
  const raw=await material({original:row.original,blob:row.blob});reader.current();
  if(row.reference){need((row.reference.bytesHash??row.reference.sha256)===row.blob.sha256&&row.reference.bytesLength===raw.length,'ObserverSourceModelOriginalRef');if(row.reference.canonicalHash!==undefined)need(hash(json(raw,33554432))===row.reference.canonicalHash,'ObserverSourceModelOriginalCanonical');}
  originals.push(row);
 }
 reader.current();
 const value=immutable({model,packageCatalogue:packages,hostCatalogue,policy:{...policy,imageImports:[...policy.imageImports]}});
 const readSource=path=>{reader.current();const raw=files.get(path);need(raw,'ObserverSourceModelMissing');reader.paid.debit(4*raw.length+4096);return Buffer.from(raw);};
 const quoteModel=immutable({hostCatalogPath:model.hostCatalogue.original.path,packageCatalogJson:packageText,parserFiles:policy.parserPins,baseRoleArn:model.scope.baseRoleArn});
 const state={plan,input,value,reader,readSource,quoteModel,originals:immutable(originals),rows:immutable([...rows.values()])};
 states.set(value,state);return value;
}

/** Only a result verified by this module and this original reader qualifies.
 * Returned source bytes are paid copies, not aliases into verified state. */
export function requireArchivedObserverSourceModel(handle,{reader,plan,input}){
 reader.current();const s=states.get(handle);need(s&&s.reader===reader,'ObserverSourceModelRequired');
 reader.paid.debit(16*67108864);same(plan,s.plan,'ObserverSourceModelPlanChanged');same(input,s.input,'ObserverSourceModelInputsChanged');
 return Object.freeze({plan:s.plan,input:s.input,model:s.value.model,policy:s.value.policy,quoteModel:s.quoteModel,originals:s.originals,rows:s.rows,readSource:s.readSource});
}
export function describeArchivedObserverHostLinks(path,description,packageRoots,{root,publicRoot,parserSibling,sdk,parserExpression,imageImports,parserPins}){
 const links=[],dir=dirname(root),packageIndex=new Map();
 for(const row of packageRoots){const key=row.from+'\0'+row.kind+'\0'+row.specifier;const old=packageIndex.get(key);need(!old||old===row.path,'ObserverHostPackageAmbiguous');packageIndex.set(key,row.path);}
 const add=(site,kind=site.kind)=>{
  const specifier=site.specifier;
  need(typeof specifier==='string'&&specifier.length>0,'ObserverHostSpecifier');
  if(isBuiltin(specifier)){links.push({...site,kind,builtin:true});return;}
  if(specifier.startsWith('/bootstrap/')){
   need(specifier==='/bootstrap/nonroot-dispatch.mjs'&&kind==='deferred'&&site.function===imageImports.get(path),'ObserverHostImageImport');
   links.push({...site,kind,image:true});return;
  }
  if(specifier.startsWith('.')||specifier.startsWith('/')){links.push({...site,kind,target:resolve(dirname(path),specifier)});return;}
  const target=packageIndex.get(path+'\0'+kind+'\0'+specifier);
  need(target,'ObserverHostUnboundPackage');links.push({...site,kind,target,package:true});
 };
 for(const site of description.imports)add(site);
 if(description.computed.length){
  need([dir+'/source-dependencies.mjs',parserSibling].includes(path)&&description.computed.length===1,'ObserverHostComputedImport');
  const site=description.computed[0];need(site.kind==='import'&&site.function==='parser'&&site.expression===parserExpression,'ObserverHostComputedImport');
  need(hash(description.parserPins)===hash(parserPins),'ObserverHostParserBinding');
  links.push({kind:'fixed-parser',start:site.start,target:parserPins[0].path,package:true});
 }
 if(description.constructors.length||description.requires.length){
  const c=description.constructors[0];
  need(path===dir+'/provider.mjs'&&description.constructors.length===1&&c.alias==='require'&&c.base===publicRoot+'/package.json'&&c.expression==="createRequire('"+publicRoot+"/package.json')",'ObserverHostRequireConstructor');
  need(description.requires.length===sdk.length&&description.requires.every((r,i)=>r.alias==='require'&&r.specifier===sdk[i]),'ObserverHostRequireBranches');
  for(const site of description.requires)add(site,'require');
 }
 return links;
}
