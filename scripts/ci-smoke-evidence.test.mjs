import {it,expect} from 'vitest';
import {inspectCiSmokeRecord,CI_SMOKE_CHECKS,ciSmokeBindingHash,validateCiSmokeEvidence,validateCiSmokeProducedEvidence,validateLocalCiSmokeEvidence,parseCiSmokeJson} from './lib/ci-smoke-evidence.mjs';
import {ciSmokeEvidenceFixture} from './ci-smoke-evidence.fixture.mjs';
const hex='a'.repeat(64),ref={sha256:hex,bytesLength:0};
const command=()=>({version:1,kind:'ci-smoke-command',bindingHash:hex,invocationId:hex,sequence:0,commandKey:'busybox-wget',containerId:'synthetic-busybox',argv:['docker','start','--attach','synthetic-busybox'],startedMs:1700000000000,completedMs:1700000000001,exitCode:0,signal:null,timedOut:false,stdout:ref,stderr:ref});
it('inspects closed R2 command records without creating authority',()=>{
 const c=inspectCiSmokeRecord('CommandV1',command());expect(c).toEqual(command());expect(Object.isFrozen(c)).toBe(true);expect(c).not.toHaveProperty('authorized');
 for(const patch of [{approved:true},{signal:'SIGTERM'},{timedOut:true},{sequence:-1},{argv:['x'.repeat(4097)]}])expect(()=>inspectCiSmokeRecord('CommandV1',{...command(),...patch})).toThrow();
});
it('fixes all fourteen check names and rejects unknown record types',()=>{
 expect(CI_SMOKE_CHECKS).toHaveLength(14);expect(new Set(CI_SMOKE_CHECKS).size).toBe(14);expect(()=>inspectCiSmokeRecord('Approved',{})).toThrow();
});
it('does not admit missing expected source or fabricated result booleans',async()=>{
 await expect(validateCiSmokeEvidence({passed:true},{readJson:async()=>Buffer.from('{}'),readBytes:async()=>Buffer.alloc(0),now:1700000000000})).rejects.toThrow();
 expect(()=>ciSmokeBindingHash({approved:true})).toThrow();
});
it('verifies all fourteen checks through actual raw-byte/canonical-reference parsing in a synthetic complete graph',async()=>{
 const f=ciSmokeEvidenceFixture(),r=await validateCiSmokeEvidence(f.result,f.options());
 expect(r.bindingHash).toBe(ciSmokeBindingHash(f.result));expect(r.completedMs).toBe(f.result.completedMs);expect(r).not.toHaveProperty('authorized');
});
for(const name of CI_SMOKE_CHECKS){
 it(name+' rejects an extra field and does not turn passed:true into evidence',async()=>{
  const f=ciSmokeEvidenceFixture();f.rewriteCheck(name,c=>{c.payload.passed=true;});await expect(validateCiSmokeEvidence(f.result,f.options())).rejects.toThrow('CiSmokeFields');
 });
 it(name+' rejects a missing required payload field',async()=>{
  const f=ciSmokeEvidenceFixture();f.rewriteCheck(name,c=>{delete c.payload[Object.keys(c.payload)[0]];});await expect(validateCiSmokeEvidence(f.result,f.options())).rejects.toThrow('CiSmokeFields');
 });
 it(name+' rejects another valid check kind in its slot',async()=>{
  const f=ciSmokeEvidenceFixture(),other=CI_SMOKE_CHECKS.find(n=>n!==name);f.result.checks[name]=f.result.checks[other];if(name==='owned-resource-cleanup')f.result.cleanupRef=f.result.checks[name];await expect(validateCiSmokeEvidence(f.result,f.options())).rejects.toThrow('CiSmokeCheckKind');
 });
 it(name+' rejects cross-invocation and future observation data',async()=>{
  for(const patch of [{invocationId:'e'.repeat(64)},{completedMs:1700000020001}]){const f=ciSmokeEvidenceFixture();f.rewriteCheck(name,c=>Object.assign(c,patch));await expect(validateCiSmokeEvidence(f.result,f.options())).rejects.toThrow(Object.hasOwn(patch,'invocationId')?'CiSmokeInvocationBinding':'CiSmokeTime');}
 });
}
for(const [name,mutate,reason]of [
 ['different source',f=>{f.expected.identity.sourceTree='c'.repeat(40);},'CiSmokeSourceIdentity'],
 ['different run',f=>{f.result.runAttempt++;},'CiSmokeSourceIdentity'],
 ['different image',f=>{f.result.outputDigest='sha256:'+'c'.repeat(64);},'CiSmokeSourceIdentity'],
 ['skipped job',f=>{f.expected.smokeJob.conclusion='skipped';},'CiSmokeLiteral'],
 ['future result',f=>{f.result.completedMs=f.options().now+1;},'CiSmokeTime'],
 ['reversed result',f=>{f.result.startedMs=f.result.completedMs+1;},'CiSmokeTime'],
 ['command drift',f=>{f.expected.commandCatalog[0].argv=['unreviewed'];},'CiSmokeCommandArguments'],
 ['canonical ref drift',f=>{f.result.runtimeEvidence={...f.result.runtimeEvidence,canonicalHash:'f'.repeat(64)};},'CiSmokeReferenceCanonicalHash'],
 ['missing helper',f=>f.rewriteRuntime(r=>r.containers.pop()),'CiSmokeArray'],
 ['root process',f=>f.rewriteRuntime(r=>{r.containers[0].processes[0].uid[0]=0;}),'CiSmokeProcessIdentity'],
 ['nonzero caps',f=>f.rewriteRuntime(r=>{r.containers[0].processes[0].capBnd='0000000000000001';}),'CiSmokeLiteral'],
 ['NNP absent',f=>f.rewriteRuntime(r=>{r.containers[0].processes[0].noNewPrivs=0;}),'CiSmokeLiteral'],
 ['foreign executable',f=>f.rewriteRuntime(r=>{r.containers[0].processes[0].executableSha256='f'.repeat(64);}),'CiSmokeProcessExecutable'],
 ['PID reuse',f=>f.rewriteRuntime(r=>{const p=structuredClone(r.containers[0].processes[0]);p.startTimeTicks++;r.containers[0].processes.push(p);}),'CiSmokePidReuse'],
 ['external network',f=>f.rewriteRuntime(r=>{r.network.internal=false;}),'CiSmokeLiteral'],
 ['extra network member',f=>f.rewriteRuntime(r=>{r.network.attachedContainerIds[1]='unknown';}),'CiSmokeNetworkMembers'],
 ['TLS key mode',f=>f.rewriteRuntime(r=>{r.databaseTls.keyMode=420;}),'CiSmokeLiteral'],
 ['raw host bind',f=>f.rewriteInspect('server',r=>{r.HostConfig.Binds=['/var/run/docker.sock:/socket'];}),'CiSmokeInspectHostBinding'],
 ['raw wrong user',f=>f.rewriteInspect('server',r=>{r.Config.User='0:0';}),'CiSmokeInspectIsolation'],
 ['raw no NNP',f=>f.rewriteInspect('server',r=>{r.HostConfig.SecurityOpt=[];}),'CiSmokeInspectIsolation'],
 ['unreviewed security option',f=>f.rewriteInspect('server',r=>{r.HostConfig.SecurityOpt.push('seccomp:unconfined');}),'CiSmokeInspectIsolation'],
 ['raw wrong image',f=>f.rewriteInspect('server',r=>{r.Config.Image='mutable:latest';}),'CiSmokeInspectIdentity'],
 ['raw extra network',f=>f.rewriteInspect('server',r=>{r.NetworkSettings.Networks.external={NetworkID:'external'};}),'CiSmokeInspectNetwork'],
 ['raw wrong tmpfs',f=>f.rewriteInspect('database',r=>{r.HostConfig.Tmpfs['/tls']=r.HostConfig.Tmpfs['/tls'].replace('uid=999','uid=0');}),'CiSmokeInspectMounts'],
 ['raw created-time drift',f=>f.rewriteInspect('server',r=>{r.Created=new Date(Date.parse(r.Created)+1).toISOString();}),'CiSmokeInspectCreatedTime'],
 ['raw started-time drift',f=>f.rewriteInspect('server',r=>{r.State.StartedAt=new Date(Date.parse(r.State.StartedAt)+1).toISOString();}),'CiSmokeInspectStartedTime'],
 ['stopped server before migration',f=>f.rewriteInspect('server',r=>{r.State.Running=false;r.State.Status='exited';}),'CiSmokeServerNotRunning'],
 ['host PID namespace',f=>f.rewriteInspect('server',r=>{r.HostConfig.PidMode='host';}),'CiSmokeInspectNamespace'],
 ['foreign IPC namespace',f=>f.rewriteInspect('server',r=>{r.HostConfig.IpcMode='container:foreign';}),'CiSmokeInspectNamespace'],
 ['unbounded memory',f=>f.rewriteInspect('database',r=>{r.HostConfig.Memory=0;}),'CiSmokeInspectResourceLimit'],
 ['unbounded PIDs',f=>f.rewriteInspect('server',r=>{r.HostConfig.PidsLimit=0;}),'CiSmokeInspectResourceLimit'],
 ['unbounded CPU',f=>f.rewriteInspect('server',r=>{r.HostConfig.NanoCpus=0;}),'CiSmokeInspectResourceLimit'],
 ['missing dependency',f=>f.rewriteCheck('owned-resource-cleanup',c=>{c.dependencies.push('f'.repeat(64));}),'CiSmokeDependencyOrder'],
 ['truncated log',f=>f.rewriteCheck('migration-retry',c=>{c.payload.log.complete=false;}),'CiSmokeLiteral'],
 ['redacted application password',f=>f.rewriteCheck('password-absent-from-logs',c=>{c.payload.serverLogs[0].scan.rawPasswordMatches=1;}),'CiSmokeCredentialLeak'],
 ['forged EMF frame',f=>f.rewriteCheck('non-tty-emf-framing',c=>{c.payload.frames[0].sha256='f'.repeat(64);}),'CiSmokeEmfFrames'],
 ['wrong TLS PID',f=>f.rewriteCheck('tls-required',c=>{c.payload.backendPid++;}),'CiSmokeSqlResult'],
 ['remaining volume',f=>f.rewriteCheck('owned-resource-cleanup',c=>{c.payload.remainingVolumeNames=['left'];}),'CiSmokeLiteral'],
])it('rejects '+name+' with a concrete reason',async()=>{
 const f=ciSmokeEvidenceFixture();mutate(f);await expect(validateCiSmokeEvidence(f.result,f.options())).rejects.toThrow(reason);
});
it('rejects changed raw bytes and readers returning parsed JSON',async()=>{
 const f=ciSmokeEvidenceFixture(),ref=f.get(f.result.checks['tls-required']).payload.queryResult,changed=Buffer.from(f.objects.get(ref.sha256));changed[0]^=1;f.objects.set(ref.sha256,changed);
 await expect(validateCiSmokeEvidence(f.result,f.options())).rejects.toThrow('CiSmokeReferenceHash');
 const good=ciSmokeEvidenceFixture();await expect(validateCiSmokeEvidence(good.result,{...good.options(),readJson:async ref=>good.get(ref)})).rejects.toThrow('CiSmokeReferenceSize');
});
it('rejects duplicate decoded JSON keys and permits the approved capture size above the unrelated nonroot-proof cap',()=>{
 for(const text of ['{"x":1,"x":2}','{"x":1,"\\u0078":2}'])expect(()=>parseCiSmokeJson(text)).toThrow('CiSmokeDuplicateJsonKey');
 const value='x'.repeat(4194305);expect(parseCiSmokeJson(JSON.stringify({value})).value.length).toBe(value.length);
});
it('object key order is not authority and shared raw references are charged once',async()=>{
 const f=ciSmokeEvidenceFixture(),seen=new Map(),options=f.options();
 const read=(base,key)=>async ref=>{const bytes=await base(ref);seen.set(ref[key],bytes.length);return bytes;};
 const result=await validateCiSmokeEvidence(Object.fromEntries(Object.entries(f.result).reverse()),{...options,readJson:read(options.readJson,'bytesHash'),readBytes:read(options.readBytes,'sha256')});
 expect(result.archiveBytes).toBe([...seen.values()].reduce((a,b)=>a+b,0));
});
it('rejects a self-consistent process capture that has no actual process-observation command',async()=>{
 const f=ciSmokeEvidenceFixture();f.rewriteRuntime(r=>{const c=r.containers[0],p=structuredClone(c.processes[0]),raw=f.get(p.statusCapture);p.pid=99;raw.status=raw.status.replace('Pid:\t17','Pid:\t99');raw.stat=raw.stat.replace(/^17 /,'99 ');p.statusCapture=f.bytes(JSON.stringify(raw));c.processes.push(p);});
 await expect(validateCiSmokeEvidence(f.result,f.options())).rejects.toThrow('CiSmokeProcessCommandBinding');
});
it('rejects a self-consistent network capture that has no actual network-inspection command',async()=>{
 const f=ciSmokeEvidenceFixture();f.rewriteRuntime(r=>{const raw=f.get(r.network.inspectCapture);r.network.inspectCapture=f.bytes(JSON.stringify(raw,null,2));});
 await expect(validateCiSmokeEvidence(f.result,f.options())).rejects.toThrow('CiSmokeNetworkCommandBinding');
});
it('enforces the cumulative 32 MiB archive limit without increasing any protected proof limit',async()=>{
 const f=ciSmokeEvidenceFixture();for(let n=0;n<6;n++){const ref=f.bytes(String(n)+'x'.repeat(6*1024*1024-1));f.expected.sourceFiles.push({path:'scripts/synthetic-large-'+n+'.mjs',gitMode:'100644',sha256:ref.sha256,bytes:ref.bytesLength});}
 await expect(validateCiSmokeEvidence(f.result,f.options())).rejects.toThrow('CiSmokeArchiveLimit');
});
it('accepts scoped inspect redaction without persisting a synthetic credential or hiding runtime fields',async()=>{
 const f=ciSmokeEvidenceFixture({inspectSecret:true});const checked=await validateCiSmokeEvidence(f.result,f.options());expect(checked.runtimeHash).toBe(f.get(f.result.checks['owned-resource-cleanup']).payload.runtimeHash);
 expect([...f.objects.values()].some(bytes=>bytes.includes(Buffer.from('synthetic-only-not-a-real-password')))).toBe(false);
 f.rewriteRuntime(r=>{const c=r.containers.find(c=>c.role==='database'),capture=f.get(c.inspectCapture);capture.redactedFields[0].pointer='/0/HostConfig/Privileged';c.inspectCapture=f.json(capture);});
 await expect(validateCiSmokeEvidence(f.result,f.options())).rejects.toThrow('CiSmokeRedactionPointer');
});
it('includes a negative container removed earlier without requiring its recreation or deletion twice',async()=>{
 const f=ciSmokeEvidenceFixture({earlyCleanup:true});await expect(validateCiSmokeEvidence(f.result,f.options())).resolves.toHaveProperty('cleanupHash');
});
it('does not promote an authorized ByteRef into a denied JsonRef through the shared-byte cache',async()=>{
 const f=ciSmokeEvidenceFixture(),ref=f.result.runtimeEvidence,options=f.options();f.expected.sourceFiles.push({path:'scripts/synthetic-runtime.json',gitMode:'100644',sha256:ref.bytesHash,bytes:ref.bytesLength});
 await expect(validateCiSmokeEvidence(f.result,{...options,readJson:async request=>{if(request.bytesHash===ref.bytesHash)throw Error('synthetic manifest reference denied');return options.readJson(request);}})).rejects.toThrow('CiSmokeReferenceRead');
});
it('does not echo malformed payload bytes or reader exception content',async()=>{
 expect(()=>parseCiSmokeJson('synthetic-sensitive-marker-not-json')).toThrow(/^CiSmokeJson$/);
 const f=ciSmokeEvidenceFixture();await expect(validateCiSmokeEvidence(f.result,{...f.options(),readBytes:async()=>{throw Error('synthetic-sensitive-marker');}})).rejects.toThrow(/^CiSmokeReferenceRead$/);
});
it('replays the same fourteen local captures without fabricating completed CI jobs',async()=>{
 const f=ciSmokeEvidenceFixture({local:true}),checked=await validateLocalCiSmokeEvidence(f.result,f.options());
 expect(checked.kind).toBe('verified-local-ci-smoke-captures');expect(checked).not.toHaveProperty('runId');expect(checked).not.toHaveProperty('sourceRevision');expect(checked).not.toHaveProperty('authorized');
 let reads=0;await expect(validateCiSmokeEvidence(f.result,{...f.options(),readJson:async()=>{reads++;throw Error('unexpected read');}})).rejects.toThrow('CiSmokeFields');expect(reads).toBe(0);
});
it('accepts only true Docker NNP spellings and keeps migration recovery on actual stdout',async()=>{
 const f=ciSmokeEvidenceFixture();f.rewriteCheck('healthy-after-migration',c=>{c.payload.recoveryLog.stream='stderr';});await expect(validateCiSmokeEvidence(f.result,f.options())).rejects.toThrow('CiSmokeRecoveryLog');
 const record=inspectCiSmokeRecord('CommandV1',{...command(),commandKey:'start-container'});expect(record.commandKey).toBe('start-container');
});
for(const local of [false,true])it('joins native pre-start inspect, HostConfig, State and stop captures in '+(local?'local':'CI')+' evidence',async()=>{
 const f=ciSmokeEvidenceFixture({local,prestartInspect:true,supplementalHostConfig:true,nativeStop:true,latestLogScan:true});
 expect(f.rawInspects.get('server').raw[0].State.Status).toBe('created');
 expect(f.get(f.result.checks['password-absent-from-logs']).payload.serverLogs).toHaveLength(2);
 await expect((local?validateLocalCiSmokeEvidence:validateCiSmokeEvidence)(f.result,f.options())).resolves.toHaveProperty('cleanupHash');
});
it('does not mistake supplementary HostConfig for a running-state readback',async()=>{
 const f=ciSmokeEvidenceFixture({prestartInspect:true,supplementalHostConfig:true});
 f.rewriteAuxiliaryCommand(f.stateReads.get('server-running'),c=>{c.argv=['docker','inspect','--format','{{json .HostConfig}}',c.containerId];c.stdout=f.bytes(JSON.stringify(f.rawInspects.get('server').raw[0].HostConfig));});
 await expect(validateCiSmokeEvidence(f.result,f.options())).rejects.toThrow('CiSmokeServerNotRunning');
});
it('requires an independent stopped-state readback after native stop stdout',async()=>{
 const f=ciSmokeEvidenceFixture({nativeStop:true});
 f.rewriteAuxiliaryCommand(f.stateReads.get('server-stopped'),c=>{c.argv=['docker','inspect','--format={{json .HostConfig}}',c.containerId];c.stdout=f.bytes('{}');});
 await expect(validateCiSmokeEvidence(f.result,f.options())).rejects.toThrow('CiSmokeStoppedReadback');
});
for(const phase of ['running','stopped'])it('rejects a '+phase+' state from a different server start',async()=>{
 const f=ciSmokeEvidenceFixture({prestartInspect:true,nativeStop:true});
 f.rewriteAuxiliaryCommand(f.stateReads.get('server-'+phase),c=>{const state=f.get(c.stdout);state.StartedAt=new Date(Date.parse(state.StartedAt)+1).toISOString();c.stdout=f.bytes(JSON.stringify(state));});
 await expect(validateCiSmokeEvidence(f.result,f.options())).rejects.toThrow(phase==='running'?'CiSmokeServerNotRunning':'CiSmokeStoppedReadback');
});
it('rejects unknown inspect formats even when stdout resembles valid state',async()=>{
 const f=ciSmokeEvidenceFixture({prestartInspect:true});
 f.rewriteAuxiliaryCommand(f.stateReads.get('server-running'),c=>{c.argv=['docker','inspect','--format','{{json .Config}}',c.containerId];});
 await expect(validateCiSmokeEvidence(f.result,f.options())).rejects.toThrow('CiSmokeInspectFormat');
});
it('requires later complete log snapshots to retain every earlier byte on the same stream',async()=>{
 const f=ciSmokeEvidenceFixture({latestLogScan:true,retryExtraLine:'synthetic earlier diagnostic removed by rotation\n'});
 await expect(validateCiSmokeEvidence(f.result,f.options())).rejects.toThrow('CiSmokePasswordScanCoverage');
});
it('replays producer captures before job completion without fabricating completed jobs or weakening downstream CI checks',async()=>{
 const f=ciSmokeEvidenceFixture(),expected=Object.fromEntries(Object.entries(f.expected).filter(([k])=>!['buildJob','smokeJob'].includes(k)));
 const result=await validateCiSmokeProducedEvidence(f.result,{...f.options(),expected});expect(result.kind).toBe('verified-ci-smoke-producer-captures');expect(result).not.toHaveProperty('authorized');
 f.expected.smokeJob.status='in_progress';await expect(validateCiSmokeEvidence(f.result,f.options())).rejects.toThrow('CiSmokeLiteral');
 await expect(validateCiSmokeProducedEvidence(f.result,f.options())).rejects.toThrow('CiSmokeFields');
});
it('still rejects invalid runtime captures in the producer pre-completion entry',async()=>{
 const f=ciSmokeEvidenceFixture(),expected=Object.fromEntries(Object.entries(f.expected).filter(([k])=>!['buildJob','smokeJob'].includes(k)));
 f.rewriteInspect('server',r=>{r.Config.User='0:0';});await expect(validateCiSmokeProducedEvidence(f.result,{...f.options(),expected})).rejects.toThrow('CiSmokeInspectIsolation');
});
