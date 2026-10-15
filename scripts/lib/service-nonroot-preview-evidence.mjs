import assert from 'node:assert/strict';
import {open,realpath} from 'node:fs/promises';
import {constants} from 'node:fs';
import {dirname,join,basename} from 'node:path';
import {createHash} from 'node:crypto';
import {PutObjectCommand,HeadObjectCommand} from '@aws-sdk/client-s3';
const sha=b=>createHash('sha256').update(b).digest('hex');

/** Binds the complete producer journal, not a checksum freshly invented by
 * the uploader. A fallback diagnostic can be transported but never permits
 * deletion of its preview stage. */
export async function collectPreviewEvidence(report){
 assert(typeof report.evidence==='string'&&/^[a-f0-9]{64}$/.test(report.evidenceHash),'ProducerEvidenceHashMissing');
 const complete=Array.isArray(report.evidenceFiles),rows=complete?report.evidenceFiles:[{name:basename(report.evidence),sha256:report.evidenceHash}];
 assert(rows.length>0&&rows.length<=64&&new Set(rows.map(r=>r.name)).size===rows.length,'EvidenceSetInvalid');
 const files=[];let total=0,record;
 for(const row of rows){
  assert(/^[a-z][a-z0-9.-]{0,127}\.json$/.test(row.name)&&/^[a-f0-9]{64}$/.test(row.sha256),'EvidenceNameInvalid');
  const path=join(dirname(report.evidence),row.name);assert.equal(await realpath(path),path,'EvidenceSymlink');
  const fd=await open(path,constants.O_RDONLY|constants.O_NOFOLLOW);
  let body;
  try{const stat=await fd.stat();assert(stat.isFile()&&stat.uid===process.getuid()&&(stat.mode&0o777)===0o600&&stat.size<=2*1024*1024);body=await fd.readFile();}finally{await fd.close();}
  assert.equal(sha(body),row.sha256,'ProducerEvidenceChanged');if(complete)assert.equal(body.length,row.bytes,'ProducerEvidenceSizeChanged');
  total+=body.length;assert(total<=16*1024*1024,'EvidenceSetTooLarge');files.push({name:row.name,body,sha256:row.sha256});
  if(path===report.evidence){assert.equal(row.sha256,report.evidenceHash,'ReportHashChanged');record=JSON.parse(body);}
 }
 assert(record,'ReportMissingFromEvidence');
 const cleanupAuthorized=complete&&record.cleanup?.verified===true&&record.cleanup.complete===true&&Array.isArray(record.cleanup.failures)&&record.cleanup.failures.length===0&&Array.isArray(record.cleanup.remainingCandidateTasks)&&record.cleanup.remainingCandidateTasks.length===0;
 return {files,complete,cleanupAuthorized,outcome:record.outcome,manifest:{version:1,complete,report:basename(report.evidence),files:files.map(f=>({name:f.name,sha256:f.sha256,bytes:f.body.length}))}};
}

export async function uploadPreviewEvidence({bundle,client,bucket,account,prefix}){
 assert(/^\d{12}$/.test(account)&&/^runtime-service-hardening\/previews\/pr-[1-9][0-9]*\/[a-f0-9]{40}\/[1-9][0-9]*-[1-9][0-9]*\/$/.test(prefix));
 const manifest=Buffer.from(JSON.stringify(bundle.manifest)+'\n');
 for(const file of [...bundle.files,{name:'manifest.json',body:manifest}]){
  const checksum=createHash('sha256').update(file.body).digest('base64'),input={Bucket:bucket,ExpectedBucketOwner:account,Key:prefix+file.name};
  await client.send(new PutObjectCommand({...input,Body:file.body,IfNoneMatch:'*',ContentType:'application/json',ChecksumSHA256:checksum,ServerSideEncryption:'aws:kms',BucketKeyEnabled:true}),{abortSignal:AbortSignal.timeout(30000)});
  const head=await client.send(new HeadObjectCommand({...input,ChecksumMode:'ENABLED'}),{abortSignal:AbortSignal.timeout(30000)});
  assert(head.ContentLength===file.body.length&&head.ChecksumSHA256===checksum,'EvidenceUploadUnverified');
 }
 return {evidenceUploaded:bundle.complete,cleanupAuthorized:bundle.cleanupAuthorized,outcome:bundle.outcome,evidenceKey:prefix+'manifest.json',evidenceSha256:sha(manifest)};
}
