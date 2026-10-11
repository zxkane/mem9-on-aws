// Synthetic provenance/network only; graph, filesystem, owned Docker import,
// native prerequisites and original application guard execution stay real.
import {readFileSync,writeFileSync,mkdirSync,mkdtempSync,rmSync,cpSync,existsSync,openSync,readSync,closeSync,createReadStream} from 'node:fs';
import {dirname,join,resolve,relative} from 'node:path';
import {tmpdir} from 'node:os';
import {fileURLToPath} from 'node:url';
import {createRequire} from 'node:module';
import {execFileSync} from 'node:child_process';
import {randomBytes} from 'node:crypto';
import {parse} from '@babel/parser';
import {parseDocument} from 'yaml';
import {nonrootDeploymentFixture} from './production-nonroot-provenance.fixture.mjs';
import {completeNonrootProofFixture,nonrootAuthorizationValues} from './production-nonroot.fixture.mjs';
import {nonrootHash as hash} from './lib/production-nonroot-contracts.mjs';
import {createImageBudget,readControlImageGraph,controlImageGraphBinding} from './lib/production-image-graph.mjs';
import {inspectImageFilesystem} from './lib/production-image-filesystem.mjs';
import {readControlSourceFile,controlSourcePaths} from './lib/production-control-source.mjs';
import {createNonrootEvidenceArchive} from './lib/production-nonroot-archive.mjs';
import {buildNonrootImageTransitionProof,nonrootProofExpected,nonrootTransitionContextBindings,bindNonrootTransitionAuthorization} from './lib/production-nonroot-proof.mjs';
import {captureNonrootControlBuildAction} from './lib/production-nonroot-control-build.mjs';
import {encodeControlBuildCapture} from './lib/production-control-capture-archive.mjs';
import {CONTROL_ZERO_FINDINGS_POLICY_HASH} from './lib/production-nonroot-control-scan-policy.mjs';
function treeFor(files){
 const root=mkdtempSync(join(tmpdir(),'control-prefix-tree-'));
 try{const git=args=>execFileSync('git',['-c','core.hooksPath=/dev/null',...args],{cwd:root,encoding:'utf8'}).trim();git(['init','--quiet']);
 for(const [path,raw]of files){const target=join(root,path);mkdirSync(dirname(target),{recursive:true});writeFileSync(target,raw);git(['add','--',path]);}return git(['write-tree']);
 }finally{rmSync(root,{recursive:true,force:true});}
}
export async function controlPrefixFixture(){
 const repository=fileURLToPath(new URL('../',import.meta.url)),require=createRequire(import.meta.url),images=[];
 const root=mkdtempSync(join(tmpdir(),'control-prefix-')),sourceFiles=new Map(),packages=new Set();
 const run=args=>execFileSync('/usr/bin/docker',['--host','unix:///var/run/docker.sock','--config',root,...args],{env:{PATH:'/usr/bin:/bin',HOME:root,DOCKER_CONFIG:root},stdio:['pipe','pipe','pipe'],encoding:'utf8',timeout:120000,maxBuffer:4194304});
 const close=()=>{for(const tag of images)try{run(['image','rm',tag]);}catch{}rmSync(root,{recursive:true,force:true});};
 try{
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
  for(const path of ['scripts/lib/production-nonroot-control-prerequisites.mjs','scripts/lib/production-nonroot-control-guard.mjs','scripts/lib/production-nonroot-control-scan-policy.json'])overrides.set(path,readFileSync(join(repository,path),'utf8'));
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

 const seed=await completeNonrootProofFixture(),template=await nonrootDeploymentFixture({sourceOverrides:overrides});
 const files=new Map();for(const path of controlSourcePaths(template.sourceContext))files.set(path,Buffer.from((await readControlSourceFile(template.sourceContext,path)).bytes).toString());
 const raw=ref=>seed.a.objects.get(seed.a.files.find(row=>row.encoding==='bytes'&&row.ref.sha256===ref.sha256).name).toString();
 const data=seed.a.value(seed.input.protectedInputs).dataClosure;
 const workflow=parseDocument(files.get('.github/workflows/infra-ci.yml')).toJS();
 workflow.jobs['build-and-push-image']=parseDocument(raw(data.files.find(row=>row.path==='.github/workflows/infra-ci.yml').blob)).toJS().jobs['build-and-push-image'];
 files.set('.github/workflows/infra-ci.yml',JSON.stringify(workflow));for(const row of data.files)if(row.path!=='.github/workflows/infra-ci.yml')files.set(row.path,raw(row.blob));
 const tree=treeFor(files),f=await completeNonrootProofFixture({controlSourceTree:tree,controlSourceFiles:files}),originalNames=new Set(f.a.files.map(row=>row.name));
 const d=await nonrootDeploymentFixture({baseFixture:f,sourceOverrides:files,controlArtifactFactory:artifactFactory,now:f.now});
 const guardFiles=await Promise.all(['nonroot-dispatch.mjs','nonroot-files.mjs','nonroot-identity.mjs'].map(async name=>(await readControlSourceFile(d.sourceContext,'docker/bootstrap/'+name)).file));
 const guardSource={version:1,kind:'git-file-closure',tree,files:guardFiles,closureHash:hash(guardFiles)},contract=structuredClone(d.contract);
 contract.artifactPolicyHash=CONTROL_ZERO_FINDINGS_POLICY_HASH;contract.guardSource=guardSource;contract.guardImportPolicy.guardSource=guardSource;const guardRef=f.json(guardSource);for(const t of contract.launchTemplates)t.guardClosure=guardRef;
 f.input=structuredClone(f.input);f.input.taskPlan.controlLaunches=contract.launchTemplates;f.input.taskPlan.deployedControlBuildContract=contract;f.a.replaceJson('task-plan.json',f.input.taskPlan);
 const manifest=f.a.manifest();manifest.files=manifest.files.filter(row=>row.purpose!=='task-definition'||originalNames.has(row.name));
 f.evidence.archive=createNonrootEvidenceArchive(JSON.stringify(manifest),{expectedManifestHash:hash(manifest),readObject:async name=>f.a.objects.get(name)});
 const built=await buildNonrootImageTransitionProof(f.input,{expected:nonrootProofExpected(f.input,{proofHash:hash(f.input)}),evidence:f.evidence,now:f.now});
 const {review,current}=nonrootAuthorizationValues(f,built,nonrootTransitionContextBindings(built.context));
 const context=bindNonrootTransitionAuthorization(built.context,{review,now:f.now}),parameter={...f.parameter,Version:f.parameter.Version+1,Value:JSON.stringify(current)};
 const job={...d.rawJob,status:'in_progress',conclusion:null,started_at:new Date(f.now-10000).toISOString(),completed_at:null,
 steps:[{number:1,name:d.job.steps[0].name,status:'completed',conclusion:'success',started_at:new Date(f.now-9000).toISOString(),completed_at:new Date(f.now-2000).toISOString()}]};
 const capture=await captureNonrootControlBuildAction({contract,source:d.source,run:d.rawRun,job,metadata:JSON.stringify({'containerimage.digest':d.build.image.rootDigest,'containerimage.config.digest':d.build.image.configDigest}),outputDigest:d.build.image.rootDigest,observedMs:f.now},{...d.options(),expected:{sourceContext:d.sourceContext}});
 const prepared={version:1,kind:'control-build-prepared',identity:{repository:d.source.repository,revision:d.source.checkout.sha,runId:d.source.run.id,attempt:d.source.run.attempt},bundleHash:'a'.repeat(64),contractHash:hash(contract),fingerprint:d.checkoutFingerprint,preparedMs:f.now-11000};
 const encoded=encodeControlBuildCapture({prepared,capture}),completedJob={...job,status:'completed',conclusion:'success',completed_at:new Date(f.now+1).toISOString()};
 const log=`#7 exporting manifest list ${d.build.image.rootDigest}\n#7 exporting manifest ${d.build.image.arm64Digest}\n#7 exporting config ${d.build.image.configDigest}\n#7 DONE 1.0s\nMEM9_CONTROL_BUILD_COMMITMENT ${JSON.stringify(encoded.commitment)}\n`;
 return {root,run,close,f,d,built,review,current,context,parameter,contract,capture,encoded,completedJob,log,records:{proof:built.proof,proofArchive:f.a.archive()},guardImportAudit:d.build.guardImports.importAudit};
 }catch(e){close();throw e;}
}
