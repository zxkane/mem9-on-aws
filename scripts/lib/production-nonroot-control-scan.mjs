import {inspectProductionControlBuildContract} from './production-control-composition-recipe.mjs';
/** Scan-only producer over the caller's existing paid reader. No credentials,
 * new counter, scan-start operation, review service or cross-job transport. */
import {createHash} from 'node:crypto';
import {controlImageGraphBinding} from './production-image-graph.mjs';
import {copyNonrootJson,inspectNonrootRecord,parseNonrootJson,nonrootHash as hash} from './production-nonroot-contracts.mjs';
import {exportNonrootArchive,createNonrootEvidenceArchive,nonrootArchiveResolvers,nonrootArchiveBindings} from './production-nonroot-archive.mjs';
import {verifyNonrootControlSource,reserveNonrootControlPreparation} from './production-nonroot-provenance.mjs';
import {CONTROL_ZERO_FINDINGS_POLICY as P,CONTROL_ZERO_FINDINGS_POLICY_HASH,assertNonrootControlScanPolicy,normalizeNonrootControlScanPages,verifyNonrootControlScan} from './production-nonroot-control-scan-policy.mjs';
export {CONTROL_ZERO_FINDINGS_POLICY,CONTROL_ZERO_FINDINGS_POLICY_HASH,CONTROL_ZERO_FINDINGS_POLICY_SOURCE,verifyNonrootControlScan} from './production-nonroot-control-scan-policy.mjs';

const need=(ok,code='NonrootControlScanProducer')=>{if(!ok)throw Error(code);};
const exact=(value,keys)=>need(value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join()===keys.slice().sort().join(),'NonrootControlScanProducerFields');
const positive=value=>Number.isSafeInteger(value)&&value>0;
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const zero=()=>({ecrRequests:0,httpBodyBytes:0,logicalBytes:0,uncompressedBytes:0,processedEntries:0});

export async function collectNonrootControlScan(input,{clock=Date.now,signal}={}){
 exact(input,['contract','sourceContext','graph','archive','budgetedReads','maximumExpiresMs']);
 const {sourceContext,archive,budgetedReads}=input,contract=inspectProductionControlBuildContract(input.contract),{graphHash,...image}=controlImageGraphBinding(input.graph);
 need(typeof clock==='function'&&typeof budgetedReads?.readJson==='function'&&typeof budgetedReads?.reserveLocal==='function','NonrootControlScanReader');
 need(['account','region','repositoryName'].every(key=>image[key]===contract.output[key]),'NonrootControlScanScope');
 nonrootArchiveBindings(archive);const startedMs=clock();need(positive(startedMs)&&positive(input.maximumExpiresMs),'NonrootControlScanWindow');
 const deadlineMs=Math.min(input.maximumExpiresMs,startedMs+P.maxObservationAgeMs);
 const reserve=charge=>{const result=budgetedReads.reserveLocal(charge);if(result&&typeof result.then==='function'){Promise.resolve(result).catch(()=>{});throw Error('NonrootControlScanSynchronousBudget');}};
 const check=()=>{signal?.throwIfAborted();const at=clock();need(positive(at)&&at>=startedMs&&at<deadlineMs,'NonrootControlScanExpired');reserve(zero());};check();
 reserveNonrootControlPreparation(contract,budgetedReads);
 await assertNonrootControlScanPolicy(contract,sourceContext);
 await verifyNonrootControlSource(contract,{...nonrootArchiveResolvers(archive),expected:{sourceContext}});check();
 // The current authenticated CONTROL profile adds only imageId. It has no
 // maxResults or nextToken field, and its bridge refuses a nonterminal page.
 // Never broaden that profile or return a truncated scan as complete.
 const page=await budgetedReads.readJson('ecr','DescribeImageScanFindings',{registryId:image.account,repositoryName:image.repositoryName,imageId:{imageDigest:image.arm64Digest}});check();
 need(page?.nextToken===undefined||page.nextToken===null||page.nextToken==='','NonrootControlScanPaginationUnfunded');
 const observedMs=clock(),actual=normalizeNonrootControlScanPages([JSON.stringify(page)],image,{observedMs,now:observedMs});check();
 const reviewedMs=clock(),expiresMs=Math.min(deadlineMs,actual.scanCompletedMs+P.maxScanAgeMs);need(reviewedMs<expiresMs,'NonrootControlScanExpired');
 const decision={version:1,kind:'control-artifact-policy-review',decision:'within-existing-policy',image,policyHash:CONTROL_ZERO_FINDINGS_POLICY_HASH,findingsHash:hash(actual.findings),sourceTree:contract.candidate.tree,reviewedMs,expiresMs};
 const wire=await exportNonrootArchive(archive),manifest=structuredClone(parseNonrootJson(wire.manifest)),objects=new Map(wire.objects.map(item=>[item.name,Buffer.from(item.base64,'base64')])),archiveAdditions=[];
 let total=[...objects.values()].reduce((n,b)=>n+b.length,0);need(total<=P.maxEvidenceBytes,'NonrootControlScanArchiveLimit');
 const add=(value,purpose)=>{
  check();const canonicalHash=hash(value),canonical=manifest.files.filter(row=>row.encoding==='json'&&row.purpose===purpose&&row.ref.canonicalHash===canonicalHash);
  need(canonical.length<=1,'NonrootControlScanArchiveAmbiguous');if(canonical.length)return canonical[0].ref;
  const bytes=Buffer.from(JSON.stringify(value)),ref={bytesHash:sha(bytes),canonicalHash,bytesLength:bytes.length},existing=manifest.files.filter(row=>row.encoding==='json'&&hash(row.ref)===hash(ref));
  need(existing.length<=1,'NonrootControlScanArchiveAmbiguous');if(existing.length)return existing[0].ref;
  need(total+bytes.length<=P.maxEvidenceBytes&&manifest.files.length<20000,'NonrootControlScanArchiveLimit');reserve({...zero(),logicalBytes:bytes.length});
  const name='sha256-'+ref.bytesHash+'.json';need(!objects.has(name),'NonrootControlScanArchiveCollision');const row={name,purpose,encoding:'json',ref};
  total+=bytes.length;objects.set(name,bytes);manifest.files.push(row);archiveAdditions.push({...copyNonrootJson(row),bytes:Buffer.from(bytes)});return ref;
 };
 const scan=inspectNonrootRecord('ControlScanEvidenceV1',{version:1,kind:'deployed-control-scan-evidence',image,rawPages:add(actual.rawPages,'scan'),normalizedFindings:add(actual.findings,'scan'),artifactReview:add(decision,'policy'),policyHash:CONTROL_ZERO_FINDINGS_POLICY_HASH,observedMs,result:'pass'});
 const nextArchive=createNonrootEvidenceArchive(JSON.stringify(manifest),{expectedManifestHash:hash(manifest),readObject:async name=>objects.get(name)});
 await verifyNonrootControlScan(scan,{image,contract,sourceContext,...nonrootArchiveResolvers(nextArchive),now:clock()});check();
 return Object.freeze({scan,archive:nextArchive,archiveAdditions});
}
