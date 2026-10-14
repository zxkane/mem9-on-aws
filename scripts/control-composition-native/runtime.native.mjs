import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,writeFile,readFile,rm,chmod} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {fixture,admission,sha} from './fixture.mjs';
import {holdProductionControlComposition,closeProductionControlCompositionAllocation,productionControlCompositionSnapshot,beginProductionControlCompositionRequest} from '../lib/production-control-composition-lifetime.mjs';
import {completeProductionControlCompositionBuildCapture} from '../lib/production-control-composition-capture-reader.mjs';
import {describeProductionControlComposition,inspectProductionControlComposition,inspectProductionControlCompositionFunding} from '../lib/production-control-composition.mjs';
import {PRODUCTION_CONTROL_COMPOSITION_RUNTIME_POLICY_HASH as policyHash} from '../lib/production-control-composition-runtime-policy.mjs';
import {compositionRuntimeStat,inspectCompositionRuntimeStat,sameCompositionRuntimeStat,parseCompositionRuntimeMaps,compositionRuntimeDevice} from '../lib/production-control-composition-runtime-evidence.mjs';
import {inspectProductionControlCompositionRuntimeLengths} from '../lib/production-control-composition-runtime.mjs';
import {COMPOSITION_OWNER_SOURCE_LIMITS,describeCompositionOwnerWork} from '../lib/production-control-composition-owner.mjs';

const run=promisify(execFile),root=fileURLToPath(new URL('../',import.meta.url));
const pin=(path,b)=>({path,gitMode:'100644',sha256:sha(b),bytes:b.length,blob:{sha256:sha(b),bytesLength:b.length}});
const definition={version:1,kind:'github-main-runtime-observation',policyHash,
 entry:pin('.github/actions/control-composition/dist/index.mjs',Buffer.from('entry')),toolchain:pin('.github/actions/control-composition/dist/toolchain.json',Buffer.from('tools'))};
test('V2 runtime/source-only plan and funding reconstruct strictly, with original runtime and private-directory fees once',async()=>{
 const f=await fixture({transport:true,packed:true,runtime:definition});try{
  assert.equal(f.plan.version,2);assert.equal(f.funding.version,2);assert.deepEqual(inspectProductionControlComposition(f.plan),f.plan);assert.deepEqual(inspectProductionControlCompositionFunding(f.funding,f.plan),f.funding);
  assert.equal(f.plan.parts.runtime.logicalBytes,4617105520);assert.equal(f.plan.runtime.physicalCleanupCharge.logicalBytes,2490368);assert.equal(f.funding.recordCounts.ci,34);
  assert.equal(f.plan.parts.allocationFilesystem.logicalBytes,32768);assert.equal(f.plan.parts.source.logicalBytes,42*f.input.sourceBytes+196608*f.input.sourceFiles);
  assert.ok(!f.funding.catalog.owner.some(r=>r.id.startsWith('tools-')));assert.ok(!f.funding.catalog.ci.some(r=>r.id==='tools-get'));
  const owner=describeCompositionOwnerWork({sourcePack:f.input.packs.source,inputBytes:COMPOSITION_OWNER_SOURCE_LIMITS.inputBytes,runtimeObservationVersion:1});
  assert.deepEqual(f.funding.parts.packingOwner,owner.work);assert.deepEqual(f.funding.parts.ownerCleanup,owner.rows.cleanup);assert.deepEqual(f.funding.ownerCharge,owner.ownerCharge);
  assert.equal(f.funding.ownerCharge.logicalBytes,25*f.input.packs.source.ref.bytesLength+12*16777216+606367856);
  for(const I of [1,16777216]){const actual=describeCompositionOwnerWork({sourcePack:f.input.packs.source,inputBytes:I,runtimeObservationVersion:1});for(const k of Object.keys(actual.ownerCharge))assert.ok(f.funding.ownerCharge[k]>=actual.ownerCharge[k]);}
  for(const mutate of [p=>{p.version=1;},p=>{p.input.version=1;},p=>{p.input.packs.tools=p.input.packs.source;},p=>{p.input.runtime.policyHash='f'.repeat(64);},p=>{p.runtime.normalCharge.logicalBytes--;}]){
   const p=structuredClone(f.plan);mutate(p);assert.throws(()=>inspectProductionControlComposition(p));
  }
 }finally{await f.remove();}
});
test('runtime metadata and complete maps preserve uint64 identity and single-nanosecond changes without suffix filtering',()=>{
 const raw={dev:18446744073709551615n,ino:9007199254740993n,mode:33188n,uid:0n,gid:0n,nlink:1n,size:20n,ctimeNs:-1n,mtimeNs:1770000000000000001n};
 const s=compositionRuntimeStat(raw);assert.deepEqual(inspectCompositionRuntimeStat(s),s);assert.equal(s.ino,'9007199254740993');assert.equal(s.ctimeNs,'-1');
 assert.equal(sameCompositionRuntimeStat(raw,{...raw,mtimeNs:raw.mtimeNs+1n}),false);
 for(const bad of ['09','+1','-0','1e10',9007199254740992])assert.throws(()=>inspectCompositionRuntimeStat({...s,ino:bad}));
 const maps=Buffer.from('1000-2000 r--p 00000000 1ff:100 9007199254740993 /opt/runtime/extensionless\n2000-3000 r-xp 00000000 1ff:100 9007199254740993 /opt/runtime/extensionless\n3000-4000 rw-p 00000000 00:00 0 [heap]\n');
 assert.deepEqual(parseCompositionRuntimeMaps(maps),[{path:'/opt/runtime/extensionless',major:'511',minor:'256',ino:'9007199254740993',executable:true}]);
 assert.throws(()=>parseCompositionRuntimeMaps(Buffer.from(maps.toString().replace('extensionless','extensionless (deleted)'))));
 assert.throws(()=>parseCompositionRuntimeMaps(Buffer.alloc(65537)));
 const d=compositionRuntimeDevice(0x123456789abcdef0n);assert.equal(typeof d.major,'bigint');assert.equal(typeof d.minor,'bigint');
 const major=0x12345678n,minor=0x9abcdef0n,encoded=((major&0xfffn)<<8n)|((major&0xfffff000n)<<32n)|(minor&255n)|((minor&0xffffff00n)<<12n);
 assert.deepEqual(compositionRuntimeDevice(encoded),{major,minor});
 assert.equal(inspectProductionControlCompositionRuntimeLengths([{size:268435456n}]),268435456);assert.throws(()=>inspectProductionControlCompositionRuntimeLengths([{size:268435457n}]));
 assert.throws(()=>inspectProductionControlCompositionRuntimeLengths(Array.from({length:131},()=>({size:0n}))));
});
test('V2 decoder charges original LOCAL before malformed capture decoding and retains failed admission charge',()=>{
 const used=[];assert.throws(()=>completeProductionControlCompositionBuildCapture(Buffer.from('invalid'),{commitment:{version:2},metadataReads:{reserveLocal:c=>{used.push(c);throw Error('OriginalLocalExhausted');}}}),/OriginalLocalExhausted/);
 assert.deepEqual(used,[{ecrRequests:0,logicalBytes:15925360,httpBodyBytes:0,uncompressedBytes:0,processedEntries:0}]);
 assert.throws(()=>completeProductionControlCompositionBuildCapture(Buffer.from('invalid'),{commitment:{version:2}}),/RuntimeValidationBudget/);
});
test('only the exact non-executable kernel io_uring pseudo-file is classified outside ordinary files',()=>{
 const ring='1000-2000 rw-s 00000000 00:11 123 anon_inode:[io_uring]\n',raw=Buffer.from(ring),original=Buffer.from(raw);
 assert.deepEqual(parseCompositionRuntimeMaps(raw),[]);assert.deepEqual(raw,original);
 for(const altered of [ring.replace('rw-s','r-xs'),ring.replace('rw-s','rw-p'),ring.replace('00:11','01:11'),ring.replace(' 123 ',' 0 '),
  ring.replace('[io_uring]','[unknown]'),ring.replace('[io_uring]','[io_uring] (deleted)'),ring.replace('anon_inode:[io_uring]','/memfd:test (deleted)')])
  assert.throws(()=>parseCompositionRuntimeMaps(Buffer.from(altered)));
 const ordinary=ring.replace('anon_inode:[io_uring]','/opt/runtime/extensionless');assert.equal(parseCompositionRuntimeMaps(Buffer.from(ordinary)).length,1);
});
test('V2 allocation owns and cleans a private child under 0755 parent and rejects 0775 before child creation',async()=>{
 for(const mode of [0o755,0o775]){
  const f=await fixture({transport:true,packed:true,runtime:definition});let a;
  try{await chmod(f.directory,mode);
   if(mode===0o775)await assert.rejects(admission(f),/ControlCompositionDirectory/);
   else{
    a=await admission(f);assert.throws(()=>beginProductionControlCompositionRequest(a.allocation,'oidc',{service:'github',action:'OidcToken',requestHash:'a'.repeat(64)}),/RuntimeRequired/);
    holdProductionControlComposition(a.allocation,'TestTerminal');const closed=closeProductionControlCompositionAllocation(a.allocation,{cleanupComplete:true});
    assert.equal(closed.closed,true);assert.equal(closed.held,true);assert.ok(closed.spent.logicalBytes>=65536);
   }
   const {lstat,readdir}=await import('node:fs/promises');assert.equal((await lstat(f.directory)).mode&511,mode);
   assert.ok(!(await readdir(f.directory)).some(n=>n.startsWith('mem9-control-composition-')));
  }finally{if(a&&!productionControlCompositionSnapshot(a.allocation).closed){holdProductionControlComposition(a.allocation,'TestTerminal');closeProductionControlCompositionAllocation(a.allocation,{cleanupComplete:true});}await a?.close();await f.remove();}
 }
});

async function nativeCase(mode){
 const workspace=await mkdtemp(join(tmpdir(),'composition-runtime-native-')),dist=join(workspace,'.github/actions/control-composition/dist');await mkdir(dist,{recursive:true,mode:0o700});
 const entry=join(dist,'index.mjs'),toolchain=join(dist,'toolchain.json');await writeFile(toolchain,'{"synthetic":true}',{mode:0o600});
 const script=`import {readFile,chmod,writeFile,lstat} from 'node:fs/promises';
import {fixture,admission,sha} from ${JSON.stringify(root+'control-composition-native/fixture.mjs')};
import {captureProductionControlCompositionRuntime,verifyProductionControlCompositionRuntime,closeProductionControlCompositionRuntime,productionControlCompositionRuntimeCapture,productionControlCompositionRuntimeTerminal,requireProductionControlCompositionRuntime} from ${JSON.stringify(root+'lib/production-control-composition-runtime.mjs')};
import {PRODUCTION_CONTROL_COMPOSITION_RUNTIME_POLICY_HASH as policyHash} from ${JSON.stringify(root+'lib/production-control-composition-runtime-policy.mjs')};
import {holdProductionControlComposition,closeProductionControlCompositionAllocation,productionControlCompositionSnapshot} from ${JSON.stringify(root+'lib/production-control-composition-lifetime.mjs')};
import {runProductionControlComposition} from ${JSON.stringify(root+'lib/production-control-composition-controller.mjs')};
import {productionControlCompositionCommitment,completeProductionControlCompositionEnvelope} from ${JSON.stringify(root+'lib/production-control-composition-reader.mjs')};
import {registry,captureService,packService,baseService,env as serviceEnv} from ${JSON.stringify(root+'control-composition-native/runtime-controller-services.fixture.mjs')};
import assert from 'node:assert/strict';
const workspace=${JSON.stringify(workspace)},mode=${JSON.stringify(mode)},pin=(path,b)=>({path,gitMode:'100644',sha256:sha(b),bytes:b.length,blob:{sha256:sha(b),bytesLength:b.length}});
const e='.github/actions/control-composition/dist/index.mjs',t='.github/actions/control-composition/dist/toolchain.json';
const runtime={version:1,kind:'github-main-runtime-observation',policyHash,entry:pin(e,await readFile(workspace+'/'+e)),toolchain:pin(t,await readFile(workspace+'/'+t))};
const f=await fixture({transport:true,packed:true,runtime});let a,h,result;
try{
 await chmod(f.directory,0o755);a=await admission(f,{preloadBase:!mode.startsWith('controller')});a.env.GITHUB_WORKSPACE=workspace;
 const parent=(await lstat(f.directory)).mode&511;
 if(mode==='bad-pin')await writeFile(workspace+'/'+t,'changed');
 try{h=await captureProductionControlCompositionRuntime({allocation:a.allocation,actualMain:a.actualMain,env:a.env});}
 catch(e){if(mode!=='bad-pin')throw e;assert.equal(e.message,'ControlCompositionRuntimeSource');assert.equal(e.cleanupComplete,true);result={held:true,error:e.message,cleanup:true};}
 if(h){
  const initial=requireProductionControlCompositionRuntime(h,a.allocation);assert.ok(initial.files.length>2);assert.ok(initial.files.some(f=>f.roles.includes('node')));assert.equal(typeof initial.files[0].stat.ino,'string');
  assert.throws(()=>requireProductionControlCompositionRuntime({...h},a.allocation));
  if(mode.startsWith('controller')){
   const original=registry(a),raw=captureService(a,baseService(a,f,packService(a,f,original))),send=raw.handle.bind(raw);
   raw.handle=async request=>{const response=await send(request);
    if(request.method==='GET'&&request.path.endsWith('/capture.json')){
     if(mode==='controller-final-change')await writeFile(workspace+'/'+t,'changed');
     if(mode==='controller-lost-capture')throw Error('SyntheticUnknownCaptureRead');
    }
    return response;
   };
   let done;
   try{done=await runProductionControlComposition({...a,runtimeHandle:h,env:{...serviceEnv(a),GITHUB_TOKEN:'synthetic-github'}},{requestHandler:raw});}
   catch(e){if(mode==='controller')throw e;assert.ok(raw.stored);assert.equal(productionControlCompositionSnapshot(a.allocation).held,true);result={held:true,closed:productionControlCompositionSnapshot(a.allocation).closed,capturePreserved:true,error:e.operationError?.message??e.message};}
   h=null;
   if(done){
    assert.equal(done.version,2);assert.equal(done.capture.version,2);assert.equal(done.accounting.closed,true);assert.equal(done.accounting.held,false);
    assert.equal(done.runtimeTerminal.cleanupComplete,true);assert.deepEqual(done.runtimeTerminal.passes.map(r=>r.phase),['packs','source','base','composed','published','captured']);
    const commitment=productionControlCompositionCommitment({grantSetId:a.config.startup.grantSetId,ref:done.capture.ref,capture:done.capture.capture,runtimeTerminal:done.runtimeTerminal});assert.equal(commitment.version,2);
    const envelope=JSON.parse(raw.stored),run=envelope.observations.run,observed=JSON.parse(Buffer.from(run.bytesBase64,'base64'));
    const jobs=JSON.parse(Buffer.from(envelope.observations.jobs.bytesBase64,'base64')),job=structuredClone(jobs.jobs[0]),now=Date.now();
    Object.assign(job,{status:'completed',conclusion:'success',started_at:job.steps[0].started_at,completed_at:new Date(now).toISOString()});
    Object.assign(job.steps[0],{status:'completed',conclusion:'success',completed_at:job.completed_at});
    const expected={ref:done.capture.ref,plan:f.plan,actualMain:a.actualMain},completion={run:observed,job,now,runtimeTerminal:done.runtimeTerminal};
    assert.equal(completeProductionControlCompositionEnvelope(raw.stored,expected,completion).authority,false);
    for(const mutate of [t=>{t.cleanupComplete=false;},t=>{t.passes.pop();},t=>{t.passes[5].identitySetHash='f'.repeat(64);},t=>{t.passes[5].checkedMs=1;}]){const changed=structuredClone(done.runtimeTerminal);mutate(changed);assert.throws(()=>completeProductionControlCompositionEnvelope(raw.stored,expected,{...completion,runtimeTerminal:changed}));}
    assert.ok(Buffer.byteLength(JSON.stringify(commitment))<=16384);assert.equal(raw.calls.filter(c=>c.method==='PUT').length,1);assert.equal(raw.calls.filter(c=>c.method==='GET').length,3);
    for(const [k,n]of Object.entries(done.accounting.spent))assert.ok(n<=done.accounting.quota[k],k);
    result={closed:true,held:false,files:initial.files.length,local:done.accounting.spent.logicalBytes,entries:done.accounting.spent.processedEntries,terminal:true,version:done.version};
   }
  }else{
  for(const phase of ['packs','source','base','composed','published','captured']){
   if(mode==='mutate'&&phase==='base')await writeFile(workspace+'/'+t,'changed');
   try{await verifyProductionControlCompositionRuntime(h,a.allocation,phase);}catch(e){if(mode!=='mutate')throw e;result={held:true,error:e.message};break;}
   if(phase==='published'){const c=productionControlCompositionRuntimeCapture(a.allocation);assert.equal(c.checks.length,5);}
  }
  await closeProductionControlCompositionRuntime(h,a.allocation);h=null;
  if(mode==='normal'){const snapshot=closeProductionControlCompositionAllocation(a.allocation,{cleanupComplete:true});result={closed:snapshot.closed,held:snapshot.held,files:initial.files.length,local:snapshot.spent.logicalBytes,entries:snapshot.spent.processedEntries};}
  }
 }
 assert.equal((await lstat(f.directory)).mode&511,parent);
}finally{if(h)await closeProductionControlCompositionRuntime(h,a.allocation);if(a&&!productionControlCompositionSnapshot(a.allocation).closed){holdProductionControlComposition(a.allocation,'TestTerminal');closeProductionControlCompositionAllocation(a.allocation,{cleanupComplete:true});}await a?.close();await f.remove();}
console.log(JSON.stringify(result));
`;
 await writeFile(entry,script,{mode:0o600});
 try{const result=await run(process.execPath,[entry],{cwd:workspace,timeout:30000,maxBuffer:1048576});return JSON.parse(result.stdout.trim());}
 finally{await rm(workspace,{recursive:true,force:true});}
}
for(const mode of ['normal','mutate','bad-pin'])test('actual original allocation runtime '+mode+' uses same-process Node/full maps, 0755 parent and owned cleanup',async()=>{
 const r=await nativeCase(mode);if(mode==='normal'){assert.equal(r.closed,true);assert.equal(r.held,false);assert.ok(r.files>2);assert.ok(r.local>1000000);}else assert.equal(r.held,true);
});
for(const mode of ['controller','controller-final-change','controller-lost-capture'])test('actual runtime '+mode+' preserves full raw SDK acquisition/publication/capture and terminal cleanup rules',async t=>{
 const r=await nativeCase(mode);assert.equal(r.closed,true);if(mode==='controller'){assert.equal(r.held,false);assert.equal(r.terminal,true);assert.equal(r.version,2);t.diagnostic(JSON.stringify({fixtureOnly:true,files:r.files,local:r.local,entries:r.entries}));}
 else{assert.equal(r.held,true);assert.equal(r.capturePreserved,true);assert.equal(r.error,mode==='controller-final-change'?'ControlCompositionRuntimeChanged':'SyntheticUnknownCaptureRead');}
});
