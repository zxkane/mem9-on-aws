import {describe,it,expect} from 'vitest';
import {readFile,writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {sha} from './ci-carrier.fixture.mjs';
import {carrierWorkerFixture} from './ci-carrier-worker.fixture.mjs';
import {openCarrierStartup} from './lib/ci-carrier-startup.mjs';
import {openCarrierConsumer} from './lib/ci-carrier-consumer.mjs';
import {createCarrierTransport} from './lib/ci-carrier-transport.mjs';
import {collectCarrierBase} from './lib/ci-carrier-worker.mjs';
import {materializeCarrierBuildContext,closeCarrierBuildContext} from './lib/ci-carrier-context.mjs';
import {deriveCarrierRuntimeMaterial,closeCarrierRuntimeMaterial} from './lib/ci-carrier-derived.mjs';
import {buildCarrierOffline,closeCarrierOfflineBuild} from './lib/production-nonroot-carrier-build.mjs';
import {openCarrierSqlFixture,closeCarrierSqlFixture,inspectCarrierSqlFixtureUsage} from './lib/ci-carrier-sql-fixture.mjs';
import {materializeCarrierSqlPackage,verifyCarrierSqlPackage,closeCarrierSqlPackage,inspectCarrierSqlPackageIo} from './lib/ci-carrier-sql-package.mjs';
import {carrierSqlPackageReadBounds} from './lib/ci-carrier-before-copy.mjs';
import {runCarrierSqlAcceptance,inspectCompletedCarrierSqlAcceptance,inspectCarrierSqlRuntimeBudget} from './lib/ci-carrier-sql-acceptance.mjs';
import {CARRIER_SQL_FIXTURE_LIMITS as L} from './lib/ci-carrier-sql-runtime-budget.mjs';
import {CARRIER_SQL_CASES,verifyCarrierSqlTlsRejection} from './lib/ci-carrier-sql-acceptance-format.mjs';

it('does not restore completed SQL acceptance from JSON',()=>{
 expect(()=>inspectCompletedCarrierSqlAcceptance({kind:'carrier-sql-acceptance'},{})).toThrow('CarrierSqlAcceptanceHandle');
});
it('rejects EOF, generic TLS errors and ambiguous server connections as proof of certificate rejection',()=>{
 const prefix='mem9_fixture|2026-01-01 00:00:00|a.1|123|127.0.0.1(1234)|';
 for(const failure of ['EOF detected','unexpected eof while reading','connection reset by peer'])expect(()=>verifyCarrierSqlTlsRejection(prefix+'connection received: host=127.0.0.1 port=1234\n'+prefix+'could not accept SSL connection: '+failure)).toThrow('CarrierSqlTlsCertificateRejection');
 const ok=prefix+'connection received: host=127.0.0.1 port=1234\n'+prefix+'could not accept SSL connection: tlsv1 alert unknown ca';
 expect(verifyCarrierSqlTlsRejection(ok)).toMatchObject({sessionId:'a.1',peer:'127.0.0.1(1234)'});
 expect(()=>verifyCarrierSqlTlsRejection(ok+'\n'+prefix+'connection received: host=127.0.0.1 port=1234')).toThrow('CarrierSqlTlsConnections');
});
it('joins a safe client certificate diagnostic to exactly one failed fixture peer, never EOF alone',()=>{
 const prefix='mem9_fixture|2026-01-01 00:00:00|a.1|123|127.0.0.1(1234)|';
 const raw=prefix+'connection received: host=127.0.0.1 port=1234\n'+prefix+'could not accept SSL connection: EOF detected';
 const failure={event:'carrier_guard_rejected',stage:'legacy',code:'CarrierRejected',tlsErrorCode:'DEPTH_ZERO_SELF_SIGNED_CERT'};
 expect(verifyCarrierSqlTlsRejection(raw,{sessionId:'a.1',peer:'127.0.0.1(1234)'},failure)).toMatchObject({sessionId:'a.1'});
 for(const delta of [{stage:'guard'},{code:'CarrierIdentity'},{tlsErrorCode:'ECONNRESET'},{tlsErrorCode:'CERT_HAS_EXPIRED'},{message:'untrusted detail'}])expect(()=>verifyCarrierSqlTlsRejection(raw,undefined,{...failure,...delta})).toThrow();
 expect(()=>verifyCarrierSqlTlsRejection(raw,{sessionId:'b.2',peer:'127.0.0.1(1234)'},failure)).toThrow('CarrierSqlTlsConnections');
 expect(()=>verifyCarrierSqlTlsRejection(raw.replace('a.1|123|127.0.0.1(1234)|could','b.2|123|127.0.0.1(1234)|could'),undefined,failure)).toThrow('CarrierSqlTlsConnections');
 expect(()=>verifyCarrierSqlTlsRejection(raw.replace('EOF detected','connection reset by peer'),undefined,failure)).toThrow('CarrierSqlTlsCertificateRejection');
});

// Owner-local material supplies the actual frozen program/module bytes. This
// test never fetches packages/images or claims production image provenance.
describe.skipIf(!process.env.MEM9_CARRIER_ORIGINAL_MATERIAL||process.env.MEM9_CARRIER_SQL_TEST!=='1')('actual original-module SQL cases on one image',()=>{
 it('completes the fixed positive/negative sequence with exact test-only overlays',async()=>{
  const materialBytes=await readFile(process.env.MEM9_CARRIER_ORIGINAL_MATERIAL),material=JSON.parse(materialBytes);let evidence;
  await carrierWorkerFixture(async f=>{
   let descriptorRef;
   if(process.env.MEM9_CARRIER_SQL_DESCRIPTOR){
    const bytes=await readFile(process.env.MEM9_CARRIER_SQL_DESCRIPTOR);expect(sha(bytes)).toBe(process.env.MEM9_CARRIER_SQL_DESCRIPTOR_SHA256);expect(JSON.parse(bytes)).toEqual(f.config.plan.template.sqlFixture);
    descriptorRef={path:process.env.MEM9_CARRIER_SQL_DESCRIPTOR,sha256:sha(bytes)};
   }
   let consumer,transport,context,base,derived,built,fixture,databasePackage;
   try{
    const startup=await openCarrierStartup({config:f.config,env:f.env,host:f.seams.host},f.seams.startup);consumer=openCarrierConsumer({startup,config:f.config,env:f.env});transport=createCarrierTransport({consumer,env:f.env},f.seams.transport);
    await transport.assume();await transport.identity();consumer.confirmGrant(await transport.getGrant());
    context=await transport.getContext(stream=>materializeCarrierBuildContext({stream,plan:f.config.plan,tempRoot:f.tempRoot,metadataReads:consumer}));base=await collectCarrierBase({consumer,transport,tempRoot:f.tempRoot});
    const options={context,baseGraph:base.graph,baseFilesystem:base.filesystem,baseCacheDirectory:base.cacheDirectory,sourceContext:consumer.admission.source.sourceContext,metadataReads:consumer,tempRoot:f.tempRoot};
    derived=await deriveCarrierRuntimeMaterial(options);built=await buildCarrierOffline({...options,derived}).catch(async error=>{if(error.operationDirectory){try{const log=await readFile(error.operationDirectory+'/build.log','utf8');console.error(JSON.stringify({kind:'synthetic-build-failure',stage:error.stage,termination:error.termination,log:log.slice(-3000)}));}catch{}}throw error;});
    databasePackage=await transport.getFixture(stream=>materializeCarrierSqlPackage({stream,consumer,tempRoot:f.tempRoot}));const beforeVerification=consumer.inspect().local;await verifyCarrierSqlPackage(databasePackage,{consumer});
    const afterVerification=consumer.inspect().local,io=inspectCarrierSqlPackageIo(databasePackage,{consumer}),bounds=carrierSqlPackageReadBounds(f.config.plan.template.sqlFixture);
    expect(io.archiveWriteBytes).toBe(f.config.plan.template.sqlFixture.archive.bytesLength);expect(io.verificationReadBytes).toBe(bounds.compressedLayerBytes+bounds.metadataReadBytes);
    expect(afterVerification.logicalBytes-beforeVerification.logicalBytes).toBe(io.verificationReadBytes);expect(afterVerification.uncompressedBytes-beforeVerification.uncompressedBytes).toBe(io.decodedBytes);
    const runtimeBudget=inspectCarrierSqlRuntimeBudget(built);
    fixture=await openCarrierSqlFixture({databasePackage,tempRoot:f.tempRoot,metadataReads:consumer,deadlineMs:f.config.plan.deadlineMs});
    const fixtureHandle=fixture,storageSamples=[];let samplePending,sampleTimer,handle;
    // Local test diagnostics only, outside the consumer. Sample only the
    // container ID obtained from this test's genuine fixture handle.
    const sample=()=>samplePending??=(async()=>{
     try{const {stdout}=await promisify(execFile)('/usr/bin/docker',['--host','unix:///var/run/docker.sock','--config',f.tempRoot,'exec',inspectCarrierSqlFixtureUsage(fixtureHandle).containerId,'df','-B1','--output=target,used,size','/tmp','/var/run/postgresql'],{env:{PATH:'/usr/bin:/bin',HOME:f.tempRoot},timeout:3000,maxBuffer:4096});
      storageSamples.push({observedMs:Date.now(),mounts:stdout.trim().split('\n').slice(1).map(line=>{const [mount,used,size]=line.trim().split(/\s+/);return {mount,usedBytes:Number(used),sizeBytes:Number(size)};})});
     }catch{}finally{samplePending=undefined;}
    })();
    if(process.env.MEM9_CARRIER_SQL_EVIDENCE_DIRECTORY){await sample();sampleTimer=setInterval(sample,250);}
    try{handle=await runCarrierSqlAcceptance({built,context,derived,consumer,sourceContext:options.sourceContext,fixture,oldSource:material.oldSource}).catch(error=>{if(error.observed)console.error(JSON.stringify({kind:'fixture-file-metadata',...error.observed}));throw error;});fixture=undefined;}
    finally{clearInterval(sampleTimer);await samplePending;}
    const result=inspectCompletedCarrierSqlAcceptance(handle,{built,consumer});expect(result.record.cases.map(c=>c.name)).toEqual(CARRIER_SQL_CASES);expect(result.record.cases.map(c=>c.exitCode)).toEqual([0,1,1,1,1,1,1,1]);
    expect(result.record.originalManifestHash).not.toBe(result.record.testManifestHash);expect(result.record.cases[6].mounts).toEqual([]);expect(result.record.cases[6].tlsFailure.kind).toBe('fixture-certificate-rejection');
    if(process.env.MEM9_CARRIER_SQL_NOJIT_TEST==='1')expect(result.record.fixture.jit).toEqual({setting:'off',source:'command line'});
    const raw=ref=>Buffer.from(result.objects.find(o=>o.ref.sha256===ref.sha256).bytesBase64,'base64').toString('utf8');
    const positive=raw(result.record.cases[0].stdout).trimEnd().split('\n').map(JSON.parse),supplement=positive[2];
    expect(supplement.extensionMaintenance.updatePaths).toHaveLength(1640);expect(Buffer.byteLength(JSON.stringify(supplement))).toBeLessThanOrEqual(1048576);
    const tls=result.record.cases[6],failure=JSON.parse(raw(tls.stderr)),log=raw(tls.tlsFailure.log);
    expect(failure).toEqual({event:'carrier_guard_rejected',stage:'legacy',code:'CarrierLegacyFailed',tlsErrorCode:'DEPTH_ZERO_SELF_SIGNED_CERT'});
    expect(verifyCarrierSqlTlsRejection(log,tls.tlsFailure,failure)).toMatchObject({sessionId:tls.tlsFailure.sessionId,peer:tls.tlsFailure.peer});
    const missingCode={...failure};delete missingCode.tlsErrorCode;expect(()=>verifyCarrierSqlTlsRejection(log,tls.tlsFailure,missingCode)).toThrow('CarrierSqlTlsCertificateRejection');
    await consumer.bindSqlAcceptance(handle,built);expect(consumer.inspect().events.at(-1).type).toBe('sql-accepted');
    const runtimeUsage=inspectCarrierSqlFixtureUsage(fixtureHandle);expect(runtimeUsage.relayBytes).toBeLessThanOrEqual(L.maxRelayBytes);
    for(const command of runtimeUsage.journal)expect(command.bytes).toBeLessThanOrEqual(command.outputLimit);
    if(process.env.MEM9_CARRIER_SQL_EVIDENCE_DIRECTORY){expect(storageSamples.length).toBeGreaterThan(0);for(const sample of storageSamples)for(const mount of sample.mounts){expect(mount.sizeBytes).toBe(mount.mount==='/tmp'?L.tmpDataBytes:L.tmpSocketBytes);expect(mount.usedBytes).toBeLessThanOrEqual(mount.sizeBytes);}}
    evidence={version:1,kind:'carrier-sql-native-local-test',authority:false,platform:process.platform,arch:process.arch,node:process.version,descriptorRef,materialRef:{path:process.env.MEM9_CARRIER_ORIGINAL_MATERIAL,sha256:sha(materialBytes)},packageOrigin:material.packageOrigin,sqlFixture:f.config.plan.template.sqlFixture,io,runtimeBudget,runtimeUsage,storageSamples,plan:f.config.plan,binding:f.binding,acceptance:result};
   }finally{if(fixture)await closeCarrierSqlFixture(fixture);await transport?.close();await base?.close();if(built)await closeCarrierOfflineBuild(built);if(derived)await closeCarrierRuntimeMaterial(derived,{context,baseGraph:base.graph,baseFilesystem:base.filesystem,metadataReads:consumer});if(context)await closeCarrierBuildContext(context);if(databasePackage)await closeCarrierSqlPackage(databasePackage,{consumer});await consumer?.close();}
  },{sourceOnly:true,nativeBase:true,material,derivedPg:process.env.MEM9_CARRIER_SQL_DERIVED_TEST==='1',nojitPg:process.env.MEM9_CARRIER_SQL_NOJIT_TEST==='1'});
  if(process.env.MEM9_CARRIER_SQL_EVIDENCE_DIRECTORY)await writeFile(join(process.env.MEM9_CARRIER_SQL_EVIDENCE_DIRECTORY,'acceptance.local.json'),JSON.stringify(evidence)+'\n',{flag:'wx',mode:0o600});
 },240000);
});
