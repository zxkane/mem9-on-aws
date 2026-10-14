import {describe,it,expect,beforeAll,afterAll} from 'vitest';
import {readFileSync,writeFileSync,mkdirSync,mkdtempSync,rmSync,cpSync,existsSync,openSync,readSync,closeSync,createReadStream} from 'node:fs';
import {dirname,join,resolve,relative} from 'node:path';
import {tmpdir} from 'node:os';
import {fileURLToPath} from 'node:url';
import {createRequire} from 'node:module';
import {execFileSync} from 'node:child_process';
import {randomBytes} from 'node:crypto';
import {parse} from '@babel/parser';
import {nonrootDeploymentFixture} from './production-nonroot-provenance.fixture.mjs';
import {collectNonrootControlPrerequisites} from './lib/production-nonroot-control-prerequisites.mjs';
import {collectNonrootControlGuardTests,inspectNonrootControlGuardTests} from './lib/production-nonroot-control-guard.mjs';
import {nonrootHash as hash} from './lib/production-nonroot-contracts.mjs';
import {createImageBudget,readControlImageGraph,controlImageGraphBinding} from './lib/production-image-graph.mjs';
import {inspectImageFilesystem} from './lib/production-image-filesystem.mjs';
import {readControlSourceFile} from './lib/production-control-source.mjs';
import {nonrootArchiveResolvers} from './lib/production-nonroot-archive.mjs';

it('never adopts JSON guard-test success as a live collector context',()=>{
 expect(()=>inspectNonrootControlGuardTests({kind:'control-guard-tests-context',result:'pass'})).toThrow('NonrootGuardCaptureContextRequired');
});
it('rejects caller-selected scripts before any source or Docker work',async()=>{
 await expect(collectNonrootControlGuardTests({}, {script:'unreviewed'})).rejects.toThrow('NonrootGuardCaptureFields');
});

describe.skipIf(process.env.MEM9_NONROOT_CONTAINER_TEST!=='1')('actual original CONTROL guard branches',()=>{
 const repository=fileURLToPath(new URL('../',import.meta.url)),require=createRequire(import.meta.url),directories=[],images=[],containers=new Set();let root,sourceFiles,packages,fixture;
 const run=args=>execFileSync('/usr/bin/docker',['--host','unix:///var/run/docker.sock','--config',root,...args],{env:{PATH:'/usr/bin:/bin',HOME:root,DOCKER_CONFIG:root},stdio:['pipe','pipe','pipe'],encoding:'utf8',timeout:120000,maxBuffer:4194304});
 beforeAll(async()=>{
  root=mkdtempSync(join(tmpdir(),'actual-control-guard-'));directories.push(root);sourceFiles=new Map();packages=new Set();
  const visit=path=>{
   const file=resolve(repository,path),key=relative(repository,file);if(key.startsWith('..'))throw Error('FixtureSourceEscape');if(sourceFiles.has(key))return;
   const raw=readFileSync(file,'utf8');sourceFiles.set(key,raw);
   if(key.endsWith('.json'))return;
   for(const node of parse(raw,{sourceType:'module'}).program.body){
    if(!['ImportDeclaration','ExportNamedDeclaration','ExportAllDeclaration'].includes(node.type)||!node.source)continue;
    const specifier=node.source.value;if(specifier.startsWith('node:'))continue;
    if(specifier.startsWith('.'))visit(relative(repository,resolve(dirname(file),specifier)));else packages.add(specifier.startsWith('@')?specifier.split('/').slice(0,2).join('/'):specifier.split('/')[0]);
   }
  };
  for(const path of ['docker/bootstrap/nonroot-dispatch.mjs','docker/bootstrap/nonroot-files.mjs','docker/bootstrap/nonroot-identity.mjs','scripts/runtime-bootstrap.mjs','scripts/production-consolidation-operator.mjs'])visit(path);
  const overrides=new Map(sourceFiles);
  for(const path of ['scripts/lib/production-nonroot-control-prerequisites.mjs','scripts/lib/production-nonroot-control-guard.mjs'])overrides.set(path,readFileSync(join(repository,path),'utf8'));
  const artifactFactory=async({scope,archiveBytes})=>{
   const directory=mkdtempSync(join(root,'image-')),tag='mem9-original-guard-test:'+randomBytes(12).toString('hex');images.push(tag);
   for(const [path,raw]of sourceFiles){const target=join(directory,'files',path.startsWith('docker/bootstrap/')?'bootstrap/'+path.slice('docker/bootstrap/'.length):'bootstrap/operator/'+path);mkdirSync(dirname(target),{recursive:true});writeFileSync(target,raw,{mode:0o644});}
   // Copy installed immutable package bytes; do not fetch, install, modify
   // dependencies or substitute a production module with a success fixture.
   const copied=new Set();
   const copyPackage=(name,from)=>{
    if(copied.has(name))return;
    // Some installed SDK packages expose subpaths only, not a root entry.
    // Locate their real package directory through Node's resolution search.
    const packageFile=from.resolve.paths(name).map(base=>join(base,name,'package.json')).find(existsSync);
    if(!packageFile||JSON.parse(readFileSync(packageFile)).name!==name)throw Error('FixturePackage');const path=dirname(packageFile);
    copied.add(name);const pkg=JSON.parse(readFileSync(join(path,'package.json'))),target=join(directory,'files/bootstrap/operator/node_modules',name);
    mkdirSync(dirname(target),{recursive:true});cpSync(path,target,{recursive:true,dereference:true,filter:p=>!p.split('/').some(n=>n==='.git'||n==='.ssh'||n==='.env'||n.startsWith('.env.'))});
    const local=createRequire(join(path,'package.json'));for(const dep of Object.keys(pkg.dependencies??{}))copyPackage(dep,local);
   };
   for(const name of packages)copyPackage(name,require);
   writeFileSync(join(directory,'build-manifest.mjs'),readFileSync(join(repository,'scripts/build-nonroot-manifest.mjs')));
   writeFileSync(join(directory,'Dockerfile'),'FROM node:24-alpine\nCOPY --chmod=0644 files/ /\nCOPY build-manifest.mjs /build-manifest.mjs\nRUN chmod -R a+rX,go-w /bootstrap && node /build-manifest.mjs\n');
   run(['build','--network=none','--pull=false','--platform=linux/arm64','-t',tag,directory]);
   const archive=join(directory,'image.tar');run(['image','save','--output',archive,tag]);const fd=openSync(archive,'r'),members=new Map();let offset=0;
   try{for(;;){const header=Buffer.alloc(512);if(readSync(fd,header,0,512,offset)!==512)throw Error('FixtureTarShort');if(header.every(b=>b===0))break;
    const text=b=>b.subarray(0,b.indexOf(0)<0?b.length:b.indexOf(0)).toString(),prefix=text(header.subarray(345,500)),name=(prefix?prefix+'/':'')+text(header.subarray(0,100)),size=parseInt(text(header.subarray(124,136)).trim()||'0',8);
    if(!Number.isSafeInteger(size)||size<0||members.has(name)||members.size>4096)throw Error('FixtureTar');members.set(name,{offset:offset+512,size});offset+=512+Math.ceil(size/512)*512;
   }}finally{closeSync(fd);}
   const read=name=>{const m=members.get(name);if(!m||m.size>8388608)throw Error('FixtureMember');const fd=openSync(archive,'r');try{const b=Buffer.alloc(m.size);if(readSync(fd,b,0,b.length,m.offset)!==b.length)throw Error('FixtureShort');return b;}finally{closeSync(fd);}};
   const top=JSON.parse(read('index.json')),descriptor=top.manifests[0],rootBytes=read('blobs/sha256/'+descriptor.digest.slice(7)),index=JSON.parse(rootBytes),arms=index.manifests.filter(m=>m.platform?.architecture==='arm64'&&m.platform.os==='linux');if(arms.length!==1)throw Error('FixtureArm');
   const arm=arms[0],childBytes=read('blobs/sha256/'+arm.digest.slice(7)),child=JSON.parse(childBytes),configBytes=read('blobs/sha256/'+child.config.digest.slice(7)),known=new Set();
   const stream=d=>{const m=members.get('blobs/sha256/'+d.digest.slice(7));if(!m||m.size!==d.size)throw Error('FixtureBlob');return createReadStream(archive,{start:m.offset,end:m.offset+m.size-1,highWaterMark:65536});};
   const graph=await readControlImageGraph({...scope,root:{mediaType:descriptor.mediaType,digest:descriptor.digest,size:descriptor.size},arm64Digest:arm.digest,configDigest:child.config.digest},{source:{manifest:async(_r,d)=>read('blobs/sha256/'+d.digest.slice(7)),blob:(_r,d)=>stream(d)},store:{async put(d,s){for await(const _ of s){}known.add(d.digest);},open(d){if(!known.has(d.digest))throw Error('FixtureCache');return stream(d);}},budget:createImageBudget({credentialExpiresMs:Date.now()+3600000})});
   const filesystem=await inspectImageFilesystem(graph,{component:'bootstrap'}),{graphHash,...image}=controlImageGraphBinding(graph);
   return {graph,filesystem,image,config:JSON.parse(configBytes),refs:{rootManifest:archiveBytes(rootBytes,'image-graph'),arm64Manifest:archiveBytes(childBytes,'image-graph'),config:archiveBytes(configBytes,'image-graph')},nativePaths:['/lib/ld-musl-aarch64.so.1','/usr/lib/libstdc++.so.6','/usr/lib/libgcc_s.so.1']};
  };
  const f=await nonrootDeploymentFixture({controlArtifactFactory:artifactFactory,sourceOverrides:overrides,now:Date.now()});
  const guardFiles=await Promise.all(['nonroot-dispatch.mjs','nonroot-files.mjs','nonroot-identity.mjs'].map(async name=>(await readControlSourceFile(f.sourceContext,'docker/bootstrap/'+name)).file));
  const guardSource={version:1,kind:'git-file-closure',tree:f.sourceContext.tree,files:guardFiles,closureHash:hash(guardFiles)},contract=structuredClone(f.contract);
  contract.guardSource=guardSource;contract.guardImportPolicy.guardSource=guardSource;
  const guardRef=f.json(guardSource);for(const template of contract.launchTemplates)template.guardClosure=guardRef;
  const launches=f.build.resolvedLaunches.map(row=>{const l=structuredClone(row),template=contract.launchTemplates.find(t=>t.taskKey===row.taskKey);l.contractHash=hash(contract);l.templateHash=hash(template);l.guardClosureHash=hash(guardSource);l.guardImports.localGuardFiles=guardSource;l.guardImports.policyHash=hash(contract.guardImportPolicy);return l;});
  const controlVerification=f.options().controlVerification,o={controlVerification,sourceContext:f.sourceContext,expected:{candidateTree:f.sourceContext.tree},beforeDocker:({containerId})=>{if(containerId)containers.add(containerId);}};
  const prerequisites=await collectNonrootControlPrerequisites({image:f.build.image,sourceClosure:guardSource},o);
  const value={contract,actualMain:f.main,resolvedLaunches:launches},options={controlVerification,sourceContext:f.sourceContext,prerequisites,...nonrootArchiveResolvers(f.a.archive()),expected:{contractHash:hash(contract),actualMainHash:hash(f.main),resolvedLaunchesHash:hash(launches)},beforeDocker:o.beforeDocker};
  fixture={f,value,options};
 },120000);
 afterAll(()=>{for(const id of containers)try{run(['container','rm','--force','--volumes',id]);}catch{}for(const image of images)try{run(['image','rm',image]);}catch{}for(const directory of directories)rmSync(directory,{recursive:true,force:true});},120000);
 it('executes all five real guard branches and observes genuine application configuration rejection',async()=>{
  const {value,options}=fixture,handle=await collectNonrootControlGuardTests(value,options),result=inspectNonrootControlGuardTests(handle,options);
  expect(result.guardTests.launches.map(row=>[row.taskKey,row.applicationReached])).toEqual(value.resolvedLaunches.map(l=>[l.taskKey,!l.entryPoint.at(-1).startsWith('denied')]));
  for(const row of result.guardTests.launches){expect(row.launchHash).toBe(hash(value.resolvedLaunches.find(l=>l.taskKey===row.taskKey)));expect(row.credentialAccessBeforeGuard).toBe(false);expect(row.result).toBe('pass');}
  for(const c of result.record.cases){expect(c.cleanup.confirmed).toBe(true);expect(c.exitCode).toBe(1);expect(c.events[0].event).toBe('nonroot_guard');expect(Object.keys(c.environment).some(k=>k.includes('SECRET')||k.startsWith('AWS_'))).toBe(false);}
  expect(result.record.cases.find(c=>c.taskKey==='bootstrap').events[1]).toMatchObject({event:'runtime_bootstrap_failed',phase:'configuration'});
  expect(result.record.cases.find(c=>c.taskKey==='control').events[1].event).toBe('production_consolidation_operator');
  expect(()=>inspectNonrootControlGuardTests(structuredClone(handle),options)).toThrow('NonrootGuardCaptureContextRequired');
  process.stdout.write('Original module guard outcomes: '+JSON.stringify(result.record.cases.map(c=>({taskKey:c.taskKey,applicationReached:c.applicationReached,events:c.events.map(e=>e.event),exitCode:c.exitCode})))+'\n');
 },120000);
 it('rejects unrelated launch/source bindings before creating any container',async()=>{
  const {value,options}=fixture,stages=[];
  await expect(collectNonrootControlGuardTests({...value,resolvedLaunches:value.resolvedLaunches.slice(1)},{...options,beforeDocker:e=>stages.push(e)})).rejects.toThrow();
  await expect(collectNonrootControlGuardTests(value,{...options,sourceContext:structuredClone(options.sourceContext),beforeDocker:e=>stages.push(e)})).rejects.toThrow();
  expect(stages).toEqual([]);
 },120000);
 it('does not return guard success when physical cleanup fails',async()=>{
  const {value,options}=fixture;let failure;
  try{await collectNonrootControlGuardTests(value,{...options,beforeDocker:e=>{options.beforeDocker(e);if(e.stage==='remove')throw Error('synthetic cleanup failure');}});}catch(e){failure=e;if(e.operationDirectory)directories.push(e.operationDirectory);}
  expect(failure?.code).toBe('ECLEANUP');expect(failure?.cleanupConfirmed).toBe(false);
 },120000);
});
