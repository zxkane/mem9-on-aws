import {describe,it,expect,beforeAll,afterAll} from 'vitest';
import {execFileSync,spawnSync} from 'node:child_process';
import {mkdtempSync,copyFileSync,writeFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {randomBytes} from 'node:crypto';

// Explicit isolated Docker E2E. No AWS credentials, host mounts or network.
const enabled=process.env.MEM9_NONROOT_CONTAINER_TEST==='1';
describe.skipIf(!enabled)('actual guarded CONTROL entrypoint',()=>{
 const image='mem9-nonroot-test:'+randomBytes(8).toString('hex'),changedImage=image+'-changed',linkImage=image+'-link',linkOwnerImage=image+'-link-owner';let directory;
 beforeAll(()=>{
  directory=mkdtempSync(join(tmpdir(),'mem9-nonroot-'));
  for(const name of ['nonroot-dispatch.mjs','nonroot-files.mjs','nonroot-identity.mjs'])copyFileSync(new URL('../docker/bootstrap/'+name,import.meta.url),join(directory,name));
  copyFileSync(new URL('./build-nonroot-manifest.mjs',import.meta.url),join(directory,'build-manifest.mjs'));
  writeFileSync(join(directory,'runtime-bootstrap.mjs'),`if(process.argv[1]!=='/bootstrap/operator/scripts/runtime-bootstrap.mjs')throw Error('wrong argv');console.log('synthetic_application_executed');\n`);
  writeFileSync(join(directory,'shadow-node'),'#!/bin/sh\necho synthetic_shadow_executed\nexit 99\n');
  writeFileSync(join(directory,'Dockerfile'),`FROM node:24-alpine AS valid
COPY --chmod=0644 nonroot-dispatch.mjs nonroot-files.mjs nonroot-identity.mjs /bootstrap/
COPY --chmod=0644 runtime-bootstrap.mjs /bootstrap/operator/scripts/runtime-bootstrap.mjs
COPY --chmod=0644 build-manifest.mjs /build-manifest.mjs
COPY --chmod=0755 shadow-node /shadow/node
RUN ln -s /bootstrap/operator/scripts/runtime-bootstrap.mjs /bootstrap/linked.mjs && chmod -R a+rX,go-w /bootstrap && node /build-manifest.mjs
USER 1000:1000
ENTRYPOINT ["/bin/setpriv","--no-new-privs","--","/usr/local/bin/node","/bootstrap/nonroot-dispatch.mjs","bootstrap-runtime-verify"]
FROM valid AS changed
USER root
RUN echo "console.log('synthetic_changed_application_executed');" > /bootstrap/operator/scripts/runtime-bootstrap.mjs
USER 1000:1000
FROM valid AS unsafe-link
USER root
RUN mkdir /intermediate && chmod 0777 /intermediate && ln -s /bootstrap/operator/scripts/runtime-bootstrap.mjs /intermediate/hop && ln -sf /intermediate/hop /bootstrap/linked.mjs
USER 1000:1000
FROM valid AS unsafe-link-owner
USER root
RUN mkdir /intermediate && ln -s /bootstrap/operator/scripts/runtime-bootstrap.mjs /intermediate/hop && chown -h 1000:1000 /intermediate/hop && ln -sf /intermediate/hop /bootstrap/linked.mjs
USER 1000:1000
`);
  for(const [target,tag]of [['valid',image],['changed',changedImage],['unsafe-link',linkImage],['unsafe-link-owner',linkOwnerImage]])execFileSync('docker',['build','--network=none','--pull=false','--target',target,'-t',tag,directory],{stdio:'pipe',timeout:120000,maxBuffer:4194304});
 },120000);
 afterAll(()=>{
  // Only this invocation's random tag and private synthetic build directory.
  spawnSync('docker',['image','rm',changedImage,linkImage,linkOwnerImage,image],{stdio:'pipe',timeout:30000});
  if(directory)rmSync(directory,{recursive:true,force:true});
 });
 const run=(extra=[],command=[],selected=image)=>spawnSync('docker',['run','--rm','--network=none','--cap-drop=ALL','--pids-limit=32','--memory=256m','--cpus=1',
  '-e','MEM9_STAGE=prod','-e','MEM9_BOOTSTRAP_OPERATION=runtime-verify','-e','MEM9_RUNTIME_BOOTSTRAP_VERSION=1',...extra,selected,...command],
 {encoding:'utf8',timeout:30000,maxBuffer:1048576});
 it('prefix establishes NNP and executes the original CLI after identity/closure verification',()=>{
  const result=run();expect(result.status,result.stdout+result.stderr).toBe(0);
  expect(result.stdout).toContain('"outcome":"passed"');expect(result.stdout).toContain('synthetic_application_executed');
 });
 it('rejects a foreign numeric identity before importing application code',()=>{
  const result=run(['--user','1001:1001']);expect(result.status).not.toBe(0);expect(result.stdout).not.toContain('synthetic_application_executed');
  expect(result.stdout).toContain('NonrootGuardRejected');
 });
 it('rejects a forbidden loader setting without echoing its value or importing application code',()=>{
  const result=run(['-e','NODE_PATH=/synthetic-untrusted']);expect(result.status).not.toBe(0);
  expect(result.stdout).not.toContain('synthetic_application_executed');expect(result.stdout+result.stderr).not.toContain('/synthetic-untrusted');
  expect(result.stdout).toContain('NonrootGuardRejected');
 });
 it('rejects a direct Node launch that omits the independent NNP prefix',()=>{
  const result=run(['--entrypoint','/usr/local/bin/node'],['/bootstrap/nonroot-dispatch.mjs','bootstrap-runtime-verify']);
  expect(result.status).not.toBe(0);expect(result.stdout).toContain('NonrootGuardRejected');expect(result.stdout).not.toContain('synthetic_application_executed');
 });
 it('selects the pinned absolute Node even when a shadow executable precedes it in PATH',()=>{
  const result=run(['-e','PATH=/shadow:/usr/local/bin:/usr/bin:/bin']);expect(result.status,result.stdout+result.stderr).toBe(0);
  expect(result.stdout).toContain('synthetic_application_executed');expect(result.stdout).not.toContain('synthetic_shadow_executed');
 });
 it('rejects an empty preload setting by presence',()=>{
  const result=run(['-e','NODE_OPTIONS=']);expect(result.status).not.toBe(0);expect(result.stdout).toContain('NonrootGuardRejected');
  expect(result.stdout).not.toContain('synthetic_application_executed');
 });
 it('rejects changed application bytes before their top-level code runs',()=>{
  const result=run([],[],changedImage);expect(result.status).not.toBe(0);expect(result.stdout).toContain('NonrootGuardRejected');
  expect(result.stdout).not.toContain('synthetic_changed_application_executed');
 });
 it.each([['writable intermediate directory',linkImage],['non-root intermediate symlink',linkOwnerImage]])('rejects %s even when the final path and bytes still match',(_name,selected)=>{
  const result=run([],[],selected);expect(result.status).not.toBe(0);
  expect(result.stdout).toContain('NonrootGuardRejected');expect(result.stdout).not.toContain('synthetic_application_executed');
 });
 it.each([['writable intermediate directory',linkImage],['non-root intermediate symlink',linkOwnerImage]])('rejects %s during manifest generation too',(_name,selected)=>{
  // Build-time only: the builder requires root; it must reject the hop before
  // attempting to overwrite the existing manifest. No application is started.
  const result=spawnSync('docker',['build','--network=none','--pull=false','-f','-',directory],{
   input:`FROM ${selected}\nUSER root\nRUN node /build-manifest.mjs\n`,encoding:'utf8',timeout:30000,maxBuffer:1048576});
  expect(result.status).not.toBe(0);expect(result.stdout+result.stderr).toContain('NonrootArtifact');
  expect(result.stdout+result.stderr).not.toContain('EEXIST');
 });
});
