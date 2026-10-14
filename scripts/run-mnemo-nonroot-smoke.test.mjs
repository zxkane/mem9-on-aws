import {describe,it,expect,afterEach,vi} from 'vitest';
import {mkdtempSync,writeFileSync,chmodSync,symlinkSync,existsSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {runNonrootSmoke,createCiSmokeProducerInput,NONROOT_SMOKE_DATABASE_IMAGE,expectedCiSmokeCommandCatalog} from './run-mnemo-nonroot-smoke.mjs';
import {scanBytes,allZero,privateJson,localImageMetadata,command} from './lib/mnemo-nonroot-smoke-helper.mjs';

const roots=[];
const temp=()=>{const p=mkdtempSync(join(tmpdir(),'mem9-smoke-unit-'));roots.push(p);return p;};
const roles=['server','database','busybox','invalid-migration','invalid-timeout','no-server-health'];
function ciInput(){
 const d='sha256:'+'a'.repeat(64),image={qualifiedImage:'example.com/server@'+d,rootDigest:d,arm64Digest:'sha256:'+'b'.repeat(64),configDigest:'sha256:'+'c'.repeat(64)};
 return {identity:{repository:'example/fixture',runId:1,runAttempt:1,workflowPath:'.github/workflows/infra-ci.yml',sourceRevision:'a'.repeat(40),sourceTree:'b'.repeat(40),buildJobId:1,smokeJobId:2,stepId:'mnemo',outputDigest:d,qualifiedImage:image.qualifiedImage,arm64Digest:image.arm64Digest,configDigest:image.configDigest},isolationHash:'d'.repeat(64),images:{server:image,database:{...NONROOT_SMOKE_DATABASE_IMAGE}}};
}
function commandFixture(){
 const bindings={invocationId:'a'.repeat(64),rootDirectory:'/work/checkout',nodeExecutable:'/usr/local/bin/node',workDirectory:'/tmp/mem9-ci-smoke-fixture',outputDirectory:'/tmp/evidence',images:ciInput().images,containers:Object.fromEntries(roles.map((r,i)=>[r,String(i+1).repeat(64)])),networkId:'9'.repeat(64)};
 const catalog=[{sequence:0,commandKey:'inspect-container',containerId:bindings.containers.server,argv:['docker','inspect','--format','{{json .HostConfig}}',bindings.containers.server]},
 {sequence:1,commandKey:'inspect-processes',containerId:bindings.containers.database,argv:[bindings.nodeExecutable,bindings.rootDirectory+'/scripts/lib/mnemo-nonroot-smoke-helper.mjs','process',bindings.containers.database,'999:999','1']}];
 return {bindings,catalog};
}
afterEach(()=>{vi.unstubAllEnvs();for(const p of roots.splice(0))rmSync(p,{recursive:true,force:true});});
describe('nonroot smoke producer boundaries',()=>{
 it('rejects mutable image references before any Docker operation',async()=>{
  for(const image of ['pgvector/pgvector:pg17','example.com/server:latest','sha256:'+'a'.repeat(64)])
   await expect(localImageMetadata(image)).rejects.toThrow('SmokeDigestQualifiedImageRequired');
 });
 it('never manufactures a CI result for a local run or accepts extra input fields',async()=>{
  const outputDirectory=join(temp(),'evidence');
  await expect(runNonrootSmoke({local:true,outputDirectory,input:{version:1,kind:'local-smoke-producer-input',images:{server:{},database:{}},identity:{runId:1}}})).rejects.toThrow('SmokeInputFields');
  expect(existsSync(outputDirectory)).toBe(false);
 });
 it('requires actual CI identity before image acquisition or output creation',async()=>{
  vi.stubEnv('GITHUB_ACTIONS','false');
  const outputDirectory=join(temp(),'evidence');
  await expect(runNonrootSmoke({outputDirectory,input:createCiSmokeProducerInput(ciInput())})).rejects.toThrow('SmokeActualCiIdentityRequired');
  expect(existsSync(outputDirectory)).toBe(false);
 });
 it('requires owner-only regular input files and rejects duplicate JSON keys',()=>{
  const root=temp(),file=join(root,'input');writeFileSync(file,'{"version":1}',{mode:0o600});expect(privateJson(file)).toEqual({version:1});
  const link=join(root,'link');symlinkSync(file,link);expect(()=>privateJson(link)).toThrow('SmokePrivateFile');
  chmodSync(file,0o644);expect(()=>privateJson(file)).toThrow('SmokePrivateFile');chmodSync(file,0o600);
  writeFileSync(file,'{"version":1,"version":2}');expect(()=>privateJson(file)).toThrow();
 });
 it('detects raw/encoded fixture passwords and prohibited credential classes before redaction',()=>{
  const password='synthetic:@/?#fixture';
  expect(scanBytes(password,password).rawPasswordMatches).toBe(1);
  expect(scanBytes(encodeURIComponent(password),password).encodedPasswordMatches).toBe(1);
  for(const text of ['AKIA'+'A'.repeat(16),'-----BEGIN '+'PRIVATE KEY-----','ghp_'+'a'.repeat(30)])expect(allZero(scanBytes(text))).toBe(false);
  expect(allZero(scanBytes('migration attempt 1/60 failed: connection refused',password))).toBe(true);
 });
 it('treats a timed-out child as incomplete rather than a successful negative test',()=>{
  expect(()=>command(process.execPath,['-e','setTimeout(()=>{},5000)'],{timeoutMs:20})).toThrow('SmokeCommandIncomplete');
 });
});

describe('CI input and source-pinned command catalog APIs',()=>{
 it('constructs the closed input without acquiring images or fabricating job completion',()=>{
  const source=ciInput(),input=createCiSmokeProducerInput(source);
  expect(input).toEqual({version:1,kind:'ci-smoke-producer-input',...source});
  source.identity.runId=99;expect(input.identity.runId).toBe(1);
 });
 it('rejects unknown input fields and mismatched image provenance before execution',()=>{
  for(const mutate of [v=>{v.identity.authorized=true;},v=>{v.images.database.arm64Digest='sha256:'+'e'.repeat(64);},v=>{v.images.server.configDigest='sha256:'+'e'.repeat(64);},v=>{v.identity.buildJobId=0;},v=>{v.extra=true;}]){
   const source=ciInput();mutate(source);expect(()=>createCiSmokeProducerInput(source)).toThrow();
  }
 });
 it('accepts only complete commands with exact bound paths, roles and IDs',()=>{
  const input=commandFixture(),result=expectedCiSmokeCommandCatalog(input);expect(result).toEqual(input.catalog);
  input.catalog[0].argv[0]='shadow-docker';expect(result[0].argv[0]).toBe('docker');
 });
 it('rejects changed command fields, root probes, shadow Node and PID injection',()=>{
  for(const mutate of [v=>{v.catalog[0].extra=true;},v=>{v.catalog[1].sequence=3;},v=>{v.catalog[0].commandKey='collect-logs';},v=>{v.catalog[0].containerId='8'.repeat(64);},v=>{v.catalog[0].argv[3]='{{json .Config.Env}}';},v=>{v.catalog[1].argv[0]='node';},v=>{v.catalog[1].argv[4]='0:0';},v=>{v.catalog[1].argv[5]='1;id';},v=>{v.bindings.rootDirectory='/work/../untrusted';}]){
   const input=commandFixture();mutate(input);expect(()=>expectedCiSmokeCommandCatalog(input)).toThrow();
  }
 });
});
