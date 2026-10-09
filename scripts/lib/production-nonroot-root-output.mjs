/** Original four-event carrier output validator, shared by owner and CI. */
import {need,exact,sha,hex} from './ci-smoke-acquisition-format.mjs';
export function inspectRootCarrierOutput({stdout,exitCode},expected){
 exact(expected,['invocation','inputHash','legacyCodeHash','manifestHash','nodeSha256','supplementalSha256']);
 need(typeof stdout==='string'&&Buffer.byteLength(stdout)<=2097152&&exitCode===0,'CarrierObservedExit');
 const lines=stdout.trimEnd().split('\n');need(lines.length===4,'CarrierOutputCount');
 const [before,result,supplemental,after]=lines.map(line=>JSON.parse(line));
 for(const row of [before,after]){
  need(row.event==='carrier_process_identity'&&row.invocation===expected.invocation&&row.inputHash===expected.inputHash&&row.legacyCodeHash===expected.legacyCodeHash&&row.manifestHash===expected.manifestHash,'CarrierOutputBinding');
  const p=row.identity;need(p&&Number.isSafeInteger(p.pid)&&p.pid>0&&Number.isSafeInteger(p.startTimeTicks)&&p.startTimeTicks>0&&p.executablePath==='/usr/local/bin/node'&&p.executableDigest===expected.nodeSha256,'CarrierOutputIdentity');
  need(p.uid?.length===4&&p.gid?.length===4&&[...p.uid,...p.gid,...p.groups].every(id=>id===1000)&&p.noNewPrivs===1&&['CapInh','CapPrm','CapEff','CapBnd','CapAmb'].every(k=>p[k]==='0000000000000000'),'CarrierOutputIdentity');
 }
 need(before.phase==='before'&&after.phase==='after'&&before.identity.pid===after.identity.pid&&before.identity.startTimeTicks===after.identity.startTimeTicks,'CarrierOutputProcess');
 need(Number.isSafeInteger(before.observedMs)&&Number.isSafeInteger(after.observedMs)&&before.observedMs<=after.observedMs&&after.observedMs-before.observedMs<=140000,'CarrierOutputTime');
 need(result.event==='supersession_root_audit'&&result.invocation===expected.invocation&&result.inputHash===expected.inputHash&&result.codeHash===expected.legacyCodeHash&&result.cleanupComplete===true&&hex(result.rootHash)&&after.legacyOutputSha256===sha(lines[1]),'CarrierOutputRoot');
 need(supplemental.event==='carrier_supplemental_audit'&&supplemental.authority===false&&supplemental.sourceHash===expected.supplementalSha256&&supplemental.cleanupComplete===true&&after.supplementalOutputSha256===sha(lines[2]),'CarrierOutputSupplement');
 for(const key of ['invocation','inputHash','legacyCodeHash','manifestHash'])need(supplemental[key]===expected[key],'CarrierOutputSupplement');
 need(supplemental.legacyOutputSha256===sha(lines[1])&&supplemental.startedMs>=result.observedMs&&supplemental.databaseObservedMs>=supplemental.startedMs&&supplemental.completedMs>=supplemental.databaseObservedMs&&supplemental.completedMs<=after.observedMs,'CarrierOutputSupplement');
 return {authority:false,before,legacyResult:result,supplemental,after,stdoutSha256:sha(stdout)};
}
