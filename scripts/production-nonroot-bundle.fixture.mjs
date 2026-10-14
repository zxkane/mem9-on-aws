import {createHash} from 'node:crypto';
import {nonrootArchiveBindings,createNonrootEvidenceArchive,exportNonrootArchive} from './lib/production-nonroot-archive.mjs';
import {nonrootHash as hash} from './lib/production-nonroot-contracts.mjs';

/** Synthetic publication records, with a real contiguous historical chain.
 * No writer, cloud client or authorization brand is created by this helper. */
export async function nonrootBundleRecords(f){
 const a=f.f.a,previous=JSON.parse(f.f.parameter.Value);
 const history=Array.from({length:f.f.parameter.Version},(_,i)=>({...structuredClone(previous),authorizationId:i===f.f.parameter.Version-1?previous.authorizationId:String(i+1).repeat(32)}));
 const lineage=history.map((authorization,i)=>({parameterVersion:i+1,predecessorHash:i?hash(history[i-1]):null,authorization,authorizationHash:hash(authorization)}));
 const lineageRef=a.json(lineage,'lineage');
 a.json(f.built.proof,'protocol','proof.json');a.json(f.review,'protocol','review.json');
 const manifest=a.manifest();
 // Prepublication proof custody excludes later actual CONTROL registrations
 // and phase records. Keep the original proof archive's exact inventory.
 const original=JSON.parse((await exportNonrootArchive(f.f.evidence.archive)).manifest);
 const selected=new Set([...original.files.map(r=>r.name),'proof.json','review.json',a.files.find(r=>r.ref.canonicalHash===lineageRef.canonicalHash).name]);
 manifest.files=manifest.files.filter(row=>selected.has(row.name));
 const proofArchive=createNonrootEvidenceArchive(JSON.stringify(manifest),{expectedManifestHash:hash(manifest),readObject:async name=>a.objects.get(name)});
 const p=f.built.proof,commitment={version:2,kind:'image-security-nonroot-transition',predecessorHash:hash(f.f.parameter),predecessorVersion:f.f.parameter.Version,authorizationHash:hash(f.current),authorizationId:f.current.authorizationId,nextVersion:f.parameter.Version};
 const operation={version:2,kind:'image-security-nonroot-transition',operation:{owner:f.current.authorizationId,expected:{revision:p.deploymentControl.revision,newValue:JSON.stringify(commitment)},prior:{value:f.f.parameter.Value}},predecessor:f.f.parameter,
  authorization:{data:f.current,hash:hash(f.current),review:f.review},expected:{account:f.current.account,region:f.current.region,controlRevision:p.deploymentControl.revision,controlSourceTree:p.deploymentControl.tree,
   sourceEvidenceHash:p.deploymentControl.sourceEvidence.canonicalHash,proofHash:f.built.proofHash,taskPlanHash:hash(p.taskPlan),carrierBuildHash:hash(p.taskPlan.carrierBuild),permissionsHash:hash(p.taskPlan.permissions),availabilityRehearsalHash:hash(p.taskPlan.overlap.rehearsal),rootBindingHash:hash(p.root),oldRootAuditHash:hash(p.predeploymentAudit),artifactReverificationHash:hash(p.artifactReverification),artifactSecurityHash:p.artifactSecurity.canonicalHash,writerBoundaryHash:hash({synthetic:true}),lineageHash:hash(lineage),parameterProtection:{KeyId:'synthetic-existing-key',Tier:'Standard',DataType:'text'}},lineage:lineageRef,evidenceManifest:nonrootArchiveBindings(proofArchive).manifestRef};
 return {proof:f.built.proof,operation,proofArchive,sourceReceiptHash:createHash('sha256').update('synthetic-authenticated-source-receipt').digest('hex')};
}
