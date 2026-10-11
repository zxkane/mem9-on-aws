/** R15 evidence data only. The runner retains its live image/process handles;
 * this verifier cannot restore a capability or authorize production mounts. */
import {X509Certificate} from 'node:crypto';
import {inspectCarrierFundingPlan,carrierCheckpointSelection,carrierHash as hash} from './ci-carrier-before-copy.mjs';
import {copyNonrootJson} from './production-nonroot-contracts.mjs';
import {parseAcquisitionJson,sha,need,exact} from './ci-smoke-acquisition-format.mjs';

export const CARRIER_SQL_CASES=Object.freeze(['original-readonly-completion','root-uid','missing-nnp','changed-input-hash','wrong-encoding','wrong-database-role','untrusted-fixture-ca','changed-root-counters']);
export const CARRIER_SQL_MOUNTS=Object.freeze(['/bootstrap/global-bundle.pem','/carrier/manifest.json']);
export {CARRIER_SQL_DATABASE_ROOT,CARRIER_SQL_DERIVED_FIXTURE,CARRIER_SQL_NOJIT_FIXTURE,carrierSqlDerivedProfile,assertCarrierSqlDatabasePin} from './ci-carrier-before-copy.mjs';
import {CARRIER_SQL_DATABASE_ROOT,CARRIER_SQL_NOJIT_FIXTURE,carrierSqlDerivedProfile} from './ci-carrier-before-copy.mjs';
const same=(a,b)=>need(hash(a)===hash(b),'CarrierSqlAcceptanceBinding');
const hex=v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
const bytesRef=bytes=>({sha256:sha(bytes),bytesLength:bytes.length});

/** The production manifest is never changed. Return the exact two test files;
 * only the existing CA row's hash and byte count may differ. */
export function deriveCarrierSqlTestManifest(originalBytes,fixtureCa){
 need(originalBytes instanceof Uint8Array&&fixtureCa instanceof Uint8Array&&fixtureCa.length>0&&fixtureCa.length<=16384,'CarrierSqlOverlayBytes');
 const original=parseAcquisitionJson(originalBytes,1048576),certificate=new X509Certificate(fixtureCa);
 need(Buffer.from(originalBytes).equals(Buffer.from(JSON.stringify(original))),'CarrierSqlOriginalManifestEncoding');
 need(certificate.checkIssued(certificate)&&certificate.verify(certificate.publicKey)&&/^CN=mem9-carrier-db-[a-f0-9]{32}$/.test(certificate.subject),'CarrierSqlOverlayCertificate');
 need(Buffer.from(fixtureCa).toString('utf8').trim()===certificate.toString().trim(),'CarrierSqlOverlayCertificate');
 exact(original,['version','legacyCodeHash','expandedSourceHash','minifiedSourceHash','dependencyHash','operatorInventoryHash','runtime','files','caPath']);
 need(original.version===1&&original.caPath===CARRIER_SQL_MOUNTS[0]&&Array.isArray(original.files),'CarrierSqlOverlayManifest');
 const test=structuredClone(original),rows=test.files.filter(f=>f.path===CARRIER_SQL_MOUNTS[0]);
 need(rows.length===1&&rows[0].type==='file'&&rows[0].mode===0o444,'CarrierSqlOverlayCa');
 rows[0].sha256=sha(fixtureCa);rows[0].bytes=fixtureCa.length;
 return Buffer.from(JSON.stringify(test));
}

export function inspectCarrierSqlAcceptance(value,{plan:input,binding,claim,image,oldSource,originalManifest,now=Date.now()}={}){
 const plan=inspectCarrierFundingPlan(input),v=copyNonrootJson(value),r=v.record;
 exact(v,['record','objects']);
 exact(r,['version','kind','templateHash','grantHash','contextHash','bindingHash','claimHash','sourceRevision','sourceTree','image','originalManifestHash','testManifestHash','originalManifest','testManifest','fixtureCa','fixture','startedMs','completedMs','deadlineMs','cases','cleanup']);
 need(r.version===2&&r.kind==='carrier-original-closure-tests'&&r.templateHash===plan.templateHash&&r.grantHash===binding.grantHash&&r.contextHash===plan.context.sha256&&r.bindingHash===hash(binding),'CarrierSqlAcceptanceBinding');
 same(carrierCheckpointSelection(plan,binding,Object.fromEntries(['nonce','scopeHash','artifactId','artifactDigest'].map(k=>[k,claim[k]]))).claim,claim);
 need(r.claimHash===hash(claim)&&r.sourceRevision===plan.template.source.candidateRevision&&r.sourceTree===plan.template.source.candidateTree,'CarrierSqlAcceptanceSource');
 same(r.image,image);need(['account','region','repositoryName'].every(k=>r.image[k]===plan.template.scope[k]),'CarrierSqlAcceptanceImageScope');exact(oldSource,['revision','tree']);need([oldSource.revision,oldSource.tree].every(s=>typeof s==='string'&&/^[a-f0-9]{40}$/.test(s)),'CarrierSqlAcceptanceOldSource');
 need(Number.isSafeInteger(r.startedMs)&&Number.isSafeInteger(r.completedMs)&&r.startedMs>=plan.issuedMs&&r.completedMs>=r.startedMs&&r.completedMs<=now&&r.completedMs<plan.deadlineMs&&r.deadlineMs===plan.deadlineMs,'CarrierSqlAcceptanceTime');
 need(Array.isArray(v.objects)&&v.objects.length<=64,'CarrierSqlAcceptanceObjects');
 const objects=new Map();let total=0;
 for(const row of v.objects){exact(row,['ref','bytesBase64']);exact(row.ref,['sha256','bytesLength']);
  need(hex(row.ref.sha256)&&Number.isSafeInteger(row.ref.bytesLength)&&row.ref.bytesLength>=0&&row.ref.bytesLength<=2097152&&typeof row.bytesBase64==='string'&&row.bytesBase64.length<=4*Math.ceil(row.ref.bytesLength/3),'CarrierSqlAcceptanceObject');
  const bytes=Buffer.from(row.bytesBase64,'base64');same(bytesRef(bytes),row.ref);need(bytes.toString('base64')===row.bytesBase64&&!objects.has(hash(row.ref)),'CarrierSqlAcceptanceObject');total+=bytes.length;need(total<=plan.template.bounds.resultBytes,'CarrierSqlAcceptanceBytes');objects.set(hash(row.ref),{ref:row.ref,bytes});
 }
 const used=new Set(),read=ref=>{const key=hash(ref),row=objects.get(key);need(row,'CarrierSqlAcceptanceMissingObject');used.add(key);return row.bytes;};
 const original=read(r.originalManifest),test=read(r.testManifest),ca=read(r.fixtureCa);
 need(originalManifest instanceof Uint8Array&&original.equals(originalManifest)&&sha(original)===r.originalManifestHash&&sha(test)===r.testManifestHash,'CarrierSqlAcceptanceManifest');
 need(deriveCarrierSqlTestManifest(original,ca).equals(test),'CarrierSqlAcceptanceDelta');
 const manifest=parseAcquisitionJson(original,1048576),certificate=new X509Certificate(ca),f=r.fixture;
 exact(f,['imageDigest','containerId','networkId','hostAlias','certificateHash','seederSourceHash','rootIdentity',...(f.package?['package']:[]),...(f.imageDigest===CARRIER_SQL_NOJIT_FIXTURE.rootDigest?['jit']:[])]);
 if(f.imageDigest===CARRIER_SQL_NOJIT_FIXTURE.rootDigest){exact(f.jit,['setting','source']);need(f.jit.setting==='off'&&f.jit.source==='command line','CarrierSqlJitSetting');}
 if(f.package){const p=f.package,t=plan.template.sqlFixture;exact(p,['archive','rootDigest','arm64Digest','configDigest','attestationDigest','uncompressedBytes','processedEntries']);same(p.archive,t.archive);for(const k of ['rootDigest','arm64Digest','configDigest','attestationDigest','uncompressedBytes'])need(p[k]===t[k],'CarrierSqlPackageBinding');need(Number.isSafeInteger(p.processedEntries)&&p.processedEntries>0&&p.processedEntries<=t.processedEntries,'CarrierSqlPackageBinding');same(oldSource,t.oldSource);}
 need((f.imageDigest===CARRIER_SQL_DATABASE_ROOT||carrierSqlDerivedProfile(f.imageDigest))&&f.imageDigest===(f.package?.rootDigest??CARRIER_SQL_DATABASE_ROOT)&&id(f.containerId)&&id(f.networkId)&&hex(f.seederSourceHash)&&hex(f.rootIdentity)&&f.certificateHash===sha(certificate.raw)&&certificate.checkHost(f.hostAlias)===f.hostAlias&&certificate.checkIP('127.0.0.1')==='127.0.0.1','CarrierSqlAcceptanceFixture');
 need(Array.isArray(r.cases)&&r.cases.length===CARRIER_SQL_CASES.length,'CarrierSqlAcceptanceCases');
 let last=r.startedMs;const ids=new Set();
 for(const [i,c]of r.cases.entries()){
  exact(c,['name','image','containerId','networkAddress','startedMs','completedMs','inputBytes','manifestHash','mounts','stdout','stderr','exitCode','state','commandHash','cleanup',...(c.name==='untrusted-fixture-ca'?['tlsFailure']:[])]);
  need(c.name===CARRIER_SQL_CASES[i]&&id(c.containerId)&&!ids.has(c.containerId)&&hex(c.commandHash),'CarrierSqlAcceptanceCase');ids.add(c.containerId);same(c.image,r.image);
  need(Number.isSafeInteger(c.startedMs)&&Number.isSafeInteger(c.completedMs)&&c.startedMs>=last&&c.completedMs>=c.startedMs&&c.completedMs-c.startedMs<=170000&&c.completedMs<=r.completedMs,'CarrierSqlAcceptanceCaseTime');last=c.completedMs;
  const inputBytes=read(c.inputBytes),stdout=read(c.stdout).toString('utf8'),stderr=read(c.stderr).toString('utf8');need(inputBytes.length<=32768,'CarrierSqlAcceptanceInput');
  exact(c.state,['Running','Pid','ExitCode','OOMKilled','Status']);need(c.state.Running===false&&c.state.Pid===0&&c.state.OOMKilled===false&&c.state.Status==='exited'&&c.state.ExitCode===c.exitCode,'CarrierSqlAcceptanceStopped');
  exact(c.cleanup,['removed','absenceStatus','absenceHash']);need(c.cleanup.removed===true&&c.cleanup.absenceStatus===1&&hex(c.cleanup.absenceHash),'CarrierSqlAcceptanceCleanup');
  const tls=c.name==='untrusted-fixture-ca';need(c.manifestHash===(tls?r.originalManifestHash:r.testManifestHash),'CarrierSqlAcceptanceCaseManifest');
  need(Array.isArray(c.mounts)&&c.mounts.length===(tls?0:2),'CarrierSqlAcceptanceMounts');
  for(const [j,m]of c.mounts.entries()){
   exact(m,['destination','readOnly','source']);need(m.destination===CARRIER_SQL_MOUNTS[j]&&m.readOnly===true,'CarrierSqlAcceptanceMounts');
   const s=m.source;exact(s,['path','dev','ino','uid','gid','mode','nlink','size','mtimeNs','ctimeNs','sha256']);
   need(typeof s.path==='string'&&/^\/[^\0]+\/mem9-carrier-sql-[A-Za-z0-9_-]+\/material\/(?:ca.pem|manifest.json)$/.test(s.path)&&['dev','ino','mtimeNs','ctimeNs'].every(k=>typeof s[k]==='string'&&/^[0-9]+$/.test(s[k]))&&s.uid===0&&s.gid===0&&s.mode===0o444&&s.nlink===1,'CarrierSqlAcceptanceMountSource');
   const expected=j===0?ca:test;need(s.sha256===sha(expected)&&s.size===expected.length,'CarrierSqlAcceptanceMountSource');
  }
  if(i===0){
   need(c.exitCode===0,'CarrierSqlAcceptancePositive');const lines=stdout.trimEnd().split('\n').map(line=>parseAcquisitionJson(Buffer.from(line),1048576));need(lines.length===4,'CarrierSqlAcceptancePositive');
   const [before,legacy,supplement,after]=lines,input=parseAcquisitionJson(inputBytes,32768);
   same(input.deployed,{revision:oldSource.revision,sourceTree:oldSource.tree});
   for(const p of [before,after]){const who=p.identity;need(p.event==='carrier_process_identity'&&p.manifestHash===r.testManifestHash&&p.inputHash===sha(inputBytes)&&p.invocation===input.invocation&&p.legacyCodeHash===manifest.legacyCodeHash&&who?.noNewPrivs===1&&who.executableDigest===manifest.runtime.nodeSha256&&who.pid===1&&who.ppid===0&&who.uid?.length===4&&who.gid?.length===4&&[...who.uid,...who.gid,...who.groups].every(n=>n===1000)&&['CapInh','CapPrm','CapEff','CapBnd','CapAmb'].every(k=>who[k]==='0000000000000000'),'CarrierSqlAcceptancePositive');}
   need(before.phase==='before'&&after.phase==='after'&&after.identity.startTimeTicks===before.identity.startTimeTicks&&legacy.event==='supersession_root_audit'&&legacy.cleanupComplete===true&&legacy.codeHash===manifest.legacyCodeHash&&legacy.dependencyHash===manifest.dependencyHash&&legacy.inputHash===sha(inputBytes)&&legacy.rootHash===f.rootIdentity&&supplement.event==='carrier_supplemental_audit'&&supplement.cleanupComplete===true,'CarrierSqlAcceptancePositive');
  }else{
   need(c.exitCode===1&&!stdout.includes('"event":"supersession_root_audit"'),'CarrierSqlAcceptanceNegative');
   const failure=parseAcquisitionJson(Buffer.from(stderr.trim()),1048576),guardCodes={'root-uid':'CarrierIdentity','missing-nnp':'CarrierPrivileges','changed-input-hash':'CarrierInputHash','wrong-encoding':'CarrierInputEncoding'};
   need(failure.event==='carrier_guard_rejected','CarrierSqlAcceptanceNegative');
   if(guardCodes[c.name])need(failure.stage==='guard'&&failure.code===guardCodes[c.name],'CarrierSqlAcceptanceNegative');
   else{const lines=stdout.trimEnd().split('\n');need(lines.length===1&&failure.stage==='legacy','CarrierSqlAcceptanceNegative');const before=parseAcquisitionJson(Buffer.from(lines[0]),1048576);need(before.event==='carrier_process_identity'&&before.phase==='before'&&before.inputHash===sha(inputBytes)&&before.manifestHash===c.manifestHash,'CarrierSqlAcceptanceNegative');}
  }
  if(tls){
   const lines=stdout.trimEnd().split('\n');need(lines.length===1,'CarrierSqlTlsGuard');const before=parseAcquisitionJson(Buffer.from(lines[0]),1048576),failure=parseAcquisitionJson(Buffer.from(stderr.trim()),1048576);
   need(before.event==='carrier_process_identity'&&before.phase==='before'&&before.manifestHash===r.originalManifestHash&&before.inputHash===sha(inputBytes)&&failure.event==='carrier_guard_rejected'&&failure.stage==='legacy','CarrierSqlTlsGuard');
   const t=c.tlsFailure;exact(t,['kind','fixtureContainerId','sessionId','peer','log']);need(t.kind==='fixture-certificate-rejection'&&t.fixtureContainerId===f.containerId&&typeof t.sessionId==='string'&&typeof t.peer==='string','CarrierSqlTlsEvidence');
   need(typeof c.networkAddress==='string'&&/^\d+\.\d+\.\d+\.\d+$/.test(c.networkAddress)&&t.peer.startsWith(c.networkAddress+'('),'CarrierSqlTlsPeer');
   verifyCarrierSqlTlsRejection(read(t.log).toString('utf8'),{sessionId:t.sessionId,peer:t.peer},failure);
  }
 }
 exact(r.cleanup,['fixtureStopped','networkRemoved','imageReleased']);need(Object.values(r.cleanup).every(v=>v===true),'CarrierSqlAcceptanceCleanup');
 need(used.size===objects.size&&Buffer.byteLength(JSON.stringify(v))<=plan.template.bounds.resultBytes,'CarrierSqlAcceptanceBytes');
 return {record:r,objects:[...objects.values()]};
}
function id(value){return typeof value==='string'&&/^[a-f0-9]{64}$/.test(value);}

/** One completed case, one new server-side connection. EOF alone is never
 * evidence. Node may close after certificate rejection without sending an
 * alert, so bind its exact allowlisted diagnostic to the same failed peer. */
export function verifyCarrierSqlTlsRejection(raw,expected,clientFailure){
 need(typeof raw==='string'&&Buffer.byteLength(raw)<=1048576,'CarrierSqlTlsLog');
 const rows=raw.trim().split('\n').map(line=>/^mem9_fixture\|[^|]+\|([^|]+)\|[0-9]+\|([^|]+)\|(.*)$/.exec(line));
 need(rows.every(Boolean),'CarrierSqlTlsLog');
 const connections=rows.filter(r=>r[3].includes('connection received:'));
 need(connections.length===1,'CarrierSqlTlsConnections');const selected=connections[0];
 need(rows.length===2&&rows[0]===selected&&rows.every(r=>r[1]===selected[1]&&r[2]===selected[2]),'CarrierSqlTlsConnections');
 let clientRejected=false;
 if(clientFailure!==undefined){
  exact(clientFailure,['event','stage','code',...(Object.hasOwn(clientFailure,'tlsErrorCode')?['tlsErrorCode']:[])]);
  need(clientFailure.event==='carrier_guard_rejected'&&clientFailure.stage==='legacy'&&['CarrierRejected','CarrierLegacyFailed'].includes(clientFailure.code),'CarrierSqlTlsClient');
  if(Object.hasOwn(clientFailure,'tlsErrorCode')){need(clientFailure.tlsErrorCode==='DEPTH_ZERO_SELF_SIGNED_CERT','CarrierSqlTlsClient');clientRejected=true;}
 }
 const rejection=rows.filter(r=>/could not accept SSL connection:.*(?:alert unknown ca|alert bad certificate|alert certificate unknown)/i.test(r[3])||(clientRejected&&/could not accept SSL connection: EOF detected$/.test(r[3])));
 need(rejection.length===1,'CarrierSqlTlsCertificateRejection');
 if(expected)need(expected.sessionId===selected[1]&&expected.peer===selected[2],'CarrierSqlTlsConnections');
 return {kind:'fixture-certificate-rejection',sessionId:selected[1],peer:selected[2]};
}
