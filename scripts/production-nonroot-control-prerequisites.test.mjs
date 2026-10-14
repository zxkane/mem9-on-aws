import {describe,it,expect,beforeAll,afterAll} from 'vitest';
import {readFileSync,mkdtempSync,mkdirSync,writeFileSync,rmSync,openSync,readSync,closeSync,createReadStream} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,dirname} from 'node:path';
import {randomBytes,createHash} from 'node:crypto';
import {rootCertificates} from 'node:tls';
import {dockerArtifactFixture} from './production-nonroot-observation.fixture.mjs';
import {nonrootDeploymentFixture} from './production-nonroot-provenance.fixture.mjs';
import {collectNonrootControlPrerequisites,inspectNonrootControlPrerequisites} from './lib/production-nonroot-control-prerequisites.mjs';
import {inspectNonrootRecord,nonrootHash as hash} from './lib/production-nonroot-contracts.mjs';
import {inspectImageFilesystemFile,inspectImageFilesystem} from './lib/production-image-filesystem.mjs';
import {createImageBudget,readControlImageGraph,controlImageGraphBinding} from './lib/production-image-graph.mjs';
import {validateNonrootEnvironment} from './lib/production-nonroot-launch.mjs';

it('does not accept serialized prerequisite contexts',()=>{
 expect(()=>inspectNonrootControlPrerequisites({kind:'control-prerequisites-context'})).toThrow('NonrootPrerequisitesContextRequired');
});
it('rejects caller-selected probe code before inspecting or launching an image',async()=>{
 await expect(collectNonrootControlPrerequisites({}, {script:'unreviewed'})).rejects.toThrow('NonrootPrerequisitesFields');
});

describe.skipIf(process.env.MEM9_NONROOT_CONTAINER_TEST!=='1')('actual isolated CONTROL native prerequisites',()=>{
 let docker;const caDirectories=[],caImages=[];
 beforeAll(()=>{docker=dockerArtifactFixture();});
 afterAll(async()=>{try{for(const image of caImages)docker.run(['image','rm',image]);}finally{try{await docker?.close();}finally{for(const dir of caDirectories)rmSync(dir,{recursive:true,force:true});}}},120000);
 // CA-enabled variant of the existing offline Docker archive fixture. Only
 // this synthetic image is built, using the cached base and a public Node CA.
 const caFactory=async({scope,bodies,archiveBytes})=>{
  const directory=mkdtempSync(join(tmpdir(),'nonroot-ca-fixture-'));caDirectories.push(directory);
  const tag='mem9-prerequisites-ca-test:'+randomBytes(12).toString('hex');caImages.push(tag);
  const files=new Map(bodies);files.set('/bootstrap/global-bundle.pem',rootCertificates[0]);
  for(const [path,body]of files){if(['/usr/local/bin/node','/bin/busybox','/lib/native-loader.so'].includes(path))continue;const file=join(directory,'files',path.slice(1));mkdirSync(dirname(file),{recursive:true});writeFileSync(file,body);}
  writeFileSync(join(directory,'Dockerfile'),'FROM node:24-alpine\nCOPY --chmod=0644 files/ /\nRUN chmod -R a+rX,go-w /bootstrap\nENV NODE_EXTRA_CA_CERTS=/bootstrap/global-bundle.pem\n');
  docker.run(['build','--network=none','--pull=false','--platform=linux/arm64','-t',tag,directory]);
  const archive=join(directory,'image.tar');docker.run(['image','save','--output',archive,tag]);
  const fd=openSync(archive,'r'),members=new Map();let offset=0;
  try{for(;;){const header=Buffer.alloc(512);if(readSync(fd,header,0,512,offset)!==512)throw Error('FixtureTarTruncated');if(header.every(b=>b===0))break;
   const text=b=>b.subarray(0,b.indexOf(0)<0?b.length:b.indexOf(0)).toString(),prefix=text(header.subarray(345,500)),name=(prefix?prefix+'/':'')+text(header.subarray(0,100)),size=parseInt(text(header.subarray(124,136)).trim()||'0',8);
   if(!Number.isSafeInteger(size)||size<0||members.has(name)||members.size>=4096)throw Error('FixtureTarMember');members.set(name,{offset:offset+512,size});offset+=512+Math.ceil(size/512)*512;
  }}finally{closeSync(fd);}
  const read=name=>{const member=members.get(name);if(!member||member.size>8388608)throw Error('FixtureMember');const fd=openSync(archive,'r');try{const raw=Buffer.alloc(member.size);if(readSync(fd,raw,0,raw.length,member.offset)!==raw.length)throw Error('FixtureShort');return raw;}finally{closeSync(fd);}};
  const top=JSON.parse(read('index.json')),root=top.manifests[0],rootBytes=read('blobs/sha256/'+root.digest.slice(7)),index=JSON.parse(rootBytes),arms=index.manifests.filter(m=>m.platform?.architecture==='arm64'&&m.platform?.os==='linux');
  if(arms.length!==1)throw Error('FixturePlatform');const arm=arms[0],childBytes=read('blobs/sha256/'+arm.digest.slice(7)),child=JSON.parse(childBytes),configBytes=read('blobs/sha256/'+child.config.digest.slice(7));
  const stream=d=>{const m=members.get('blobs/sha256/'+d.digest.slice(7));if(!m||m.size!==d.size)throw Error('FixtureBlob');return createReadStream(archive,{start:m.offset,end:m.offset+m.size-1,highWaterMark:65536});},known=new Set();
  const graph=await readControlImageGraph({...scope,root:{mediaType:root.mediaType,digest:root.digest,size:root.size},arm64Digest:arm.digest,configDigest:child.config.digest},{source:{manifest:async(_r,d)=>read('blobs/sha256/'+d.digest.slice(7)),blob:(_r,d)=>stream(d)},store:{async put(d,input){for await(const _ of input){}known.add(d.digest);},open(d){if(!known.has(d.digest))throw Error('FixtureCacheMissing');return stream(d);}},budget:createImageBudget({credentialExpiresMs:Date.now()+3600000})});
  const filesystem=await inspectImageFilesystem(graph,{component:'bootstrap'}),{graphHash,...image}=controlImageGraphBinding(graph);
  return {graph,filesystem,image,config:JSON.parse(configBytes),refs:{rootManifest:archiveBytes(rootBytes,'image-graph'),arm64Manifest:archiveBytes(childBytes,'image-graph'),config:archiveBytes(configBytes,'image-graph')},nativePaths:['/lib/ld-musl-aarch64.so.1','/usr/lib/libstdc++.so.6','/usr/lib/libgcc_s.so.1']};
 };
 const fixture=variant=>nonrootDeploymentFixture({controlArtifactFactory:docker.factory({variant}),now:Date.now(),sourceOverrides:new Map([
  ['scripts/lib/production-nonroot-control-prerequisites.mjs',readFileSync(new URL('./lib/production-nonroot-control-prerequisites.mjs',import.meta.url),'utf8')],
 ])});
 const input=f=>({image:f.build.image,sourceClosure:f.build.guardSource});
 const options=f=>({controlVerification:f.options().controlVerification,sourceContext:f.sourceContext,expected:{candidateTree:f.contract.candidate.tree},beforeDocker:({containerId})=>{if(containerId)docker.containers.add(containerId);}});
 it('collects the actual configured public CA bytes and parent metadata in isolated Docker',async()=>{
  const f=await nonrootDeploymentFixture({controlArtifactFactory:caFactory,now:Date.now(),sourceOverrides:new Map([['scripts/lib/production-nonroot-control-prerequisites.mjs',readFileSync(new URL('./lib/production-nonroot-control-prerequisites.mjs',import.meta.url),'utf8')]])}),o=options(f);
  const handle=await collectNonrootControlPrerequisites(input(f),o),result=inspectNonrootControlPrerequisites(handle,o),env=result.environment;
  expect(env.imageEnvironment).toContain('NODE_EXTRA_CA_CERTS=/bootstrap/global-bundle.pem');expect(env.caBindings).toHaveLength(1);
  const ca=env.caBindings[0],raw=result.objects.find(row=>row.ref.sha256===ca.file.sha256).bytes;
  expect(raw.equals(Buffer.from(rootCertificates[0]))).toBe(true);
  expect(ca.file.sha256).toBe(createHash('sha256').update(raw).digest('hex'));expect(ca.file.bytesLength).toBe(raw.length);
  expect(ca.file.sha256).toBe(inspectImageFilesystemFile(o.controlVerification.filesystem,ca.value).sha256);
  expect(inspectNonrootRecord('CaBindingV1',ca)).toEqual(ca);
  for(const path of ['/','/bootstrap'])expect(env.files.find(row=>row.path===path)).toMatchObject({type:'directory',uid:0,gid:0,mode:0o755});
  expect(()=>validateNonrootEnvironment({imageEnvironment:env.imageEnvironment,taskEnvironment:[],secrets:[],overrides:{},files:env.files,expectedCa:env.expectedCa})).not.toThrow();
  expect(result.record.cleanupConfirmed).toBe(true);
  process.stdout.write('Actual isolated CA capture: '+JSON.stringify({bytes:raw.length,mode:ca.mode,uid:ca.uid,gid:ca.gid,configured:true})+'\n');
 },120000);
 it('measures actual version, both ELF closures, kernel NNP rejection and child inheritance',async()=>{
  const f=await fixture('valid'),o=options(f),stages=[];
  const handle=await collectNonrootControlPrerequisites(input(f),{...o,beforeDocker:event=>{o.beforeDocker(event);stages.push(event);}});
  const result=inspectNonrootControlPrerequisites(handle,o),{record,nodeRuntime,primitiveEvidence,environment,objects}=result;
  expect(record.cleanupConfirmed).toBe(true);expect(record.container.exitCode).toBe(0);expect(record.removal).toMatchObject({removeExitCode:0,absenceExitCode:1});
  expect(record.probe.native).toEqual([1,1000,1000,1000,1000,-22,1,-1,-1,1000,1000,1000,1000,1]);
  expect(record.probe.child.ppid).toBe(record.probe.identity.pid);expect(record.probe.child.noNewPrivs).toBe(1);
  expect(nodeRuntime.versionString).toMatch(/^v24\./);expect(inspectNonrootRecord('NodeRuntimeV1',nodeRuntime)).toEqual(nodeRuntime);
  expect(inspectNonrootRecord('PrimitiveEvidenceV1',primitiveEvidence)).toEqual(primitiveEvidence);
  expect(nodeRuntime.executableSha256).toBe(inspectImageFilesystemFile(o.controlVerification.filesystem,'/usr/local/bin/node').sha256);
  const json=ref=>JSON.parse(objects.find(o=>hash(o.ref)===hash(ref)).bytes);
  const nodeFiles=json(nodeRuntime.loaderAndNativeLibraries).files,primitiveFiles=json(primitiveEvidence.loaderAndLibraries).files;
  expect(nodeFiles.some(f=>f.path==='/lib/ld-musl-aarch64.so.1')).toBe(true);
  expect(nodeFiles.some(f=>f.path.includes('libstdc++'))).toBe(true);expect(primitiveFiles.length).toBeGreaterThan(0);
  for(const row of [...nodeFiles,...primitiveFiles])expect(row.sha256).toBe(inspectImageFilesystemFile(o.controlVerification.filesystem,row.path).sha256);
  expect(json(primitiveEvidence.inheritanceAndNegativeProbes)).toMatchObject({method:'fixed-aarch64-kernel-syscalls',setuidBlocked:true,setgidBlocked:true,clearRejected:true});
  expect(json(result.recordRef)).toEqual(record);
  expect(environment.files.find(f=>f.path==='/')).toMatchObject({type:'directory',uid:0,gid:0,mode:0o755});
  expect(()=>validateNonrootEnvironment({imageEnvironment:environment.imageEnvironment,taskEnvironment:[],secrets:[],overrides:{},files:environment.files,expectedCa:environment.expectedCa})).not.toThrow();
  const create=stages.find(s=>s.stage==='create').args;
  for(const flag of ['--pull=never','--network=none','--read-only','--user=1000:1000','--cap-drop=ALL','--security-opt=no-new-privileges:true'])expect(create).toContain(flag);
  expect(create).not.toContain('--env');expect(create).not.toContain('--mount');expect(create).not.toContain('--volume');
  expect(()=>inspectNonrootControlPrerequisites(structuredClone(handle),o)).toThrow('NonrootPrerequisitesContextRequired');
  expect(()=>inspectNonrootControlPrerequisites(handle,{...o,now:record.completedMs+300001})).toThrow('NonrootPrerequisitesStale');
  process.stdout.write('Actual cached-node prerequisites: '+JSON.stringify({version:nodeRuntime.versionString,nodeLibraries:nodeFiles.map(f=>f.path),primitiveLibraries:primitiveFiles.map(f=>f.path),kernelResults:record.probe.native,objectCount:objects.length,objectBytes:objects.reduce((n,o)=>n+o.bytes.length,0)})+'\n');
 },120000);
 for(const variant of ['poison','preload'])it('rejects '+variant+' from authenticated bytes before Docker',async()=>{
  const f=await fixture(variant),stages=[];
  await expect(collectNonrootControlPrerequisites(input(f),{...options(f),beforeDocker:e=>stages.push(e)})).rejects.toThrow(variant==='poison'?'NonrootPrerequisitesEnvironment':'NonrootPrerequisitesLoaderFile');
  expect(stages).toEqual([]);
 },120000);
 it('rejects image/source drift before launch',async()=>{
  const f=await fixture('valid'),o=options(f),stages=[];
  await expect(collectNonrootControlPrerequisites({...input(f),image:{...f.build.image,configDigest:'sha256:'+'f'.repeat(64)}},{...o,beforeDocker:e=>stages.push(e)})).rejects.toThrow();
  await expect(collectNonrootControlPrerequisites(input(f),{...o,sourceContext:structuredClone(f.sourceContext),beforeDocker:e=>stages.push(e)})).rejects.toThrow();
  await expect(collectNonrootControlPrerequisites(input(f),{...o,expected:{candidateTree:'f'.repeat(40)},beforeDocker:e=>stages.push(e)})).rejects.toThrow('NonrootPrerequisitesSource');
  expect(stages).toEqual([]);
 },120000);
 it('joins actual symlink parents to graph/FS observations',async()=>{
  const f=await fixture('symlink'),o=options(f),handle=await collectNonrootControlPrerequisites(input(f),o),result=inspectNonrootControlPrerequisites(handle,o);
  expect(result.record.probe.observations.find(row=>row.path==='/bootstrap')).toMatchObject({type:'symlink',resolvedPath:'/real-bootstrap'});
 },120000);
 it('retains cleanup uncertainty and releases no context',async()=>{
  const f=await fixture('valid'),o=options(f);let failure;
  try{await collectNonrootControlPrerequisites(input(f),{...o,beforeDocker:e=>{o.beforeDocker(e);if(e.stage==='remove')throw Error('synthetic cleanup failure');}});}catch(e){failure=e;if(e.operationDirectory)docker.heldDirectories.add(e.operationDirectory);}
  expect(failure?.code).toBe('ECLEANUP');expect(failure?.cleanupConfirmed).toBe(false);expect(failure?.containerId).toMatch(/^[a-f0-9]{64}$/);
 },120000);
 it('removes the created container on abort and returns no usable handle',async()=>{
  const f=await fixture('valid'),o=options(f),controller=new AbortController(),stages=[];let failure;
  try{await collectNonrootControlPrerequisites(input(f),{...o,signal:controller.signal,beforeDocker:e=>{o.beforeDocker(e);stages.push(e.stage);if(e.stage==='inspect-created')controller.abort();}});}catch(e){failure=e;}
  expect(failure?.code).toBe('NonrootPrerequisitesExpired');expect(failure?.cleanupConfirmed).toBe(true);
  expect(stages).not.toContain('start');expect(stages.slice(-2)).toEqual(['remove','inspect-removed']);
 },120000);
});
