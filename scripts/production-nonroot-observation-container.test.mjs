import {describe,it,expect,beforeAll,afterAll} from 'vitest';
import {dockerArtifactFixture} from './production-nonroot-observation.fixture.mjs';
import {nonrootDeploymentFixture} from './production-nonroot-provenance.fixture.mjs';
import {collectNonrootControlRuntime,verifyNonrootControlRuntimeObservation,inspectNonrootControlRuntimeProbe} from './lib/production-nonroot-observation.mjs';
import {verifyNonrootDeployedControlBuild,verifyNonrootDeploymentSource} from './lib/production-nonroot-provenance.mjs';
import {nonrootHash as hash} from './lib/production-nonroot-contracts.mjs';

describe.skipIf(process.env.MEM9_NONROOT_CONTAINER_TEST!=='1')('actual isolated CONTROL path observer',()=>{
 let docker;
 beforeAll(()=>{docker=dockerArtifactFixture();});afterAll(async()=>{await docker?.close();},120000);
 const fixture=variant=>nonrootDeploymentFixture({controlArtifactFactory:docker.factory({variant}),now:Date.now()});
 const options=f=>({...f.options(),beforeDocker:({containerId})=>{if(containerId)docker.containers.add(containerId);}});
 it('observes root ownership and mode through the actual fixed nonroot probe',async()=>{
  const f=await fixture('valid'),handle=await collectNonrootControlRuntime(f.build,options(f)),record=verifyNonrootControlRuntimeObservation(handle,f.build,{...f.options(),now:Date.now()});
  expect(record.observations.find(p=>p.path==='/')).toMatchObject({type:'directory',uid:0,gid:0,mode:0o755});expect(record.cleanupConfirmed).toBe(true);expect(record.identity.noNewPrivs).toBe(1);expect(record.configDigest).toBe(f.build.image.configDigest);
  expect(record.container).toMatchObject({id:record.containerId,configDigest:f.build.image.configDigest,exitCode:0,pid:0});expect(record.removal).toMatchObject({containerId:record.containerId,removeExitCode:0,absenceExitCode:1});
  expect(()=>verifyNonrootControlRuntimeObservation(handle,f.build,{...f.options(),now:record.completedMs+300000})).not.toThrow();
  expect(()=>verifyNonrootControlRuntimeObservation(handle,f.build,{...f.options(),now:record.completedMs+300001})).toThrow('NonrootRuntimeObservationExpired');
  expect(()=>verifyNonrootControlRuntimeObservation(structuredClone(handle),f.build,f.options())).toThrow('NonrootRuntimeObservationRequired');
  const admitted={...f.options(),now:Date.now(),runtimeObservation:handle},build=await verifyNonrootDeployedControlBuild(f.build,admitted),deployment=await verifyNonrootDeploymentSource(f.record,admitted);
  expect(build.deployedControlBuildHash).toBe(hash(f.build));expect(Object.keys(deployment.registrations).sort()).toEqual(['backend','bootstrap','control','executor','planner','promotion','provision','transition']);
  expect(deployment.retainedFallback.disposition).toBe('retain');expect(deployment.retainedFallback.invocation).toBe('deny');expect(deployment.registrations).not.toHaveProperty('fallback');expect(deployment.registrations).not.toHaveProperty('preaudit');expect(deployment).not.toHaveProperty('authorized');
  for(const [field,value]of [['uid',1000],['gid',1000],['mode',0o777]]){
   const changed=structuredClone({version:1,kind:'control-runtime-path-observation',identity:record.identity,observations:record.observations});changed.observations.find(p=>p.path==='/')[field]=value;
   await expect(inspectNonrootControlRuntimeProbe(JSON.stringify(changed),f.build,f.options())).rejects.toThrow(field==='mode'?'NonrootRuntimePathWritable':'NonrootRuntimePathPrivilege');
  }
  expect(()=>verifyNonrootControlRuntimeObservation(record,f.build,f.options())).toThrow('NonrootRuntimeObservationRequired');
 },120000);
 for(const variant of ['poison','preload'])it('rejects actual '+variant+' before creating a container',async()=>{
  const f=await fixture(variant),stages=[];await expect(collectNonrootControlRuntime(f.build,{...options(f),beforeDocker:({stage})=>stages.push(stage)})).rejects.toThrow(variant==='poison'?'NonrootRuntimeImageEnvironment':'NonrootRuntimeLoaderPreload');expect(stages).toEqual([]);
 },120000);
 for(const variant of ['rootOwner','rootWritable'])it('uses observed root metadata rather than the image build command '+variant,async()=>{
  const f=await fixture(variant),handle=await collectNonrootControlRuntime(f.build,options(f)),r=verifyNonrootControlRuntimeObservation(handle,f.build,{...f.options(),now:Date.now()});
  expect(r.observations.find(row=>row.path==='/')).toMatchObject({type:'directory',uid:0,gid:0,mode:0o755});
 },120000);
 it('joins an actual symlink parent to the same verified filesystem',async()=>{
  const f=await fixture('symlink'),handle=await collectNonrootControlRuntime(f.build,options(f)),r=verifyNonrootControlRuntimeObservation(handle,f.build,{...f.options(),now:Date.now()});expect(r.observations.find(p=>p.path==='/bootstrap')).toMatchObject({type:'symlink',resolvedPath:'/real-bootstrap'});
 },120000);
 it('never releases a usable handle when actual container cleanup fails',async()=>{
  const f=await fixture('valid');let caught;
  try{await collectNonrootControlRuntime(f.build,{...options(f),beforeDocker(event){if(event.containerId)docker.containers.add(event.containerId);if(event.stage==='remove')throw Error('synthetic cleanup failure');}});}catch(error){caught=error;if(error.operationDirectory)docker.heldDirectories.add(error.operationDirectory);}
  expect(caught?.code).toBe('ECLEANUP');expect(caught?.cleanupConfirmed).toBe(false);expect(caught?.containerId).toMatch(/^[a-f0-9]{64}$/);
 },120000);
 it('rejects another actual image with the original graph before Docker dispatch',async()=>{
  const original=await fixture('valid'),changed=await fixture('rootOwner'),stages=[];
  await expect(collectNonrootControlRuntime(changed.build,{...options(changed),controlVerification:original.options().controlVerification,beforeDocker:({stage})=>stages.push(stage)})).rejects.toThrow('NonrootControlArtifactBinding');expect(stages).toEqual([]);
 },120000);
});
