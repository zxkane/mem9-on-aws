/** The fixed CONTROL scan rule. It grants no exception and creates no human
 * approval. Source membership, raw scan bytes and all other gates remain
 * independently required. Numeric ECR timestamps are seconds, never ms. */
import policy from './production-nonroot-control-scan-policy.json' with {type:'json'};
import {copyNonrootJson,inspectNonrootRecord,parseNonrootJson,nonrootHash as hash} from './production-nonroot-contracts.mjs';
import {readControlSourceFile} from './production-control-source.mjs';
import {readNonrootEvidence} from './production-nonroot-runtime.mjs';
import {parseImageTransitionJson} from './production-image-transition-proof.mjs';

export const CONTROL_ZERO_FINDINGS_POLICY=copyNonrootJson(policy);
export const CONTROL_ZERO_FINDINGS_POLICY_HASH=hash(CONTROL_ZERO_FINDINGS_POLICY);
export const CONTROL_ZERO_FINDINGS_POLICY_SOURCE='scripts/lib/production-nonroot-control-scan-policy.json';
const P=CONTROL_ZERO_FINDINGS_POLICY;
const need=(ok,code='NonrootControlScanInvalid')=>{if(!ok)throw Error(code);};
const exact=(v,keys)=>need(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===keys.slice().sort().join(),'NonrootControlScanFields');
const positive=n=>Number.isSafeInteger(n)&&n>0;
const same=(a,b,code='NonrootControlScanBinding')=>need(hash(a)===hash(b),code);
const severities=new Set(['INFORMATIONAL','LOW','MEDIUM','HIGH','CRITICAL','UNDEFINED']);

export function ecrScanTimestampMs(value){
 let ms;
 if(typeof value==='number'){
  need(Number.isFinite(value)&&value>0,'NonrootControlScanTimestamp');ms=Math.round(value*1000);
 }else{
  need(typeof value==='string'&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(value),'NonrootControlScanTimestamp');ms=Date.parse(value);
 }
 need(positive(ms)&&ms<=8640000000000000,'NonrootControlScanTimestamp');return ms;
}

export async function assertNonrootControlScanPolicy(contract,sourceContext){
 const c=inspectNonrootRecord('ControlBuildContractV1',contract);
 need(c.artifactPolicyHash===CONTROL_ZERO_FINDINGS_POLICY_HASH&&c.output.repositoryName===P.repositoryName,'NonrootControlScanPolicy');
 need(sourceContext?.tree===c.candidate.tree,'NonrootControlScanPolicySource');
 const source=await readControlSourceFile(sourceContext,CONTROL_ZERO_FINDINGS_POLICY_SOURCE);
 same(parseNonrootJson(new TextDecoder('utf-8',{fatal:true}).decode(source.bytes)),P,'NonrootControlScanPolicySource');
 return source.file;
}

/** Full decoded response pages are archived as JSON text, preserving numeric
 * fractional seconds without widening the integer-only proof-record codec.
 * The transport separately records the hash of the original HTTP body. */
export function normalizeNonrootControlScanPages(input,image,{observedMs,now}={}){
 const rawPages=copyNonrootJson(input),binding=inspectNonrootRecord('ControlImageBindingV1',image);
 need(binding.repositoryName===P.repositoryName&&positive(now)&&positive(observedMs)&&observedMs<=now&&now-observedMs<=P.maxObservationAgeMs,'NonrootControlScanObservation');
 need(Array.isArray(rawPages)&&rawPages.length>0&&rawPages.length<=P.maxPages,'NonrootControlScanPages');
 let bytes=0,identity;const findings=[],tokens=new Set();
 for(const [index,raw]of rawPages.entries()){
  need(typeof raw==='string','NonrootControlScanPageEncoding');
  const length=Buffer.byteLength(raw);bytes+=length;need(length<=P.maxPageBytes&&bytes<=P.maxEvidenceBytes,'NonrootControlScanSize');
  const page=parseImageTransitionJson(raw);
  need(page.registryId===binding.account&&page.repositoryName===binding.repositoryName&&page.imageId?.imageDigest===binding.arm64Digest&&page.imageScanStatus?.status==='COMPLETE','NonrootControlScanScope');
  const scan=page.imageScanFindings,completedMs=ecrScanTimestampMs(scan?.imageScanCompletedAt),counts=scan?.findingSeverityCounts;
  need(completedMs<=observedMs&&observedMs-completedMs<=P.maxScanAgeMs&&Array.isArray(scan.findings)&&(!Object.hasOwn(scan,'enhancedFindings')||Array.isArray(scan.enhancedFindings)&&scan.enhancedFindings.length===0),'NonrootControlScanStatus');
  need(counts&&typeof counts==='object'&&!Array.isArray(counts)&&Object.entries(counts).every(([key,value])=>severities.has(key)&&Number.isSafeInteger(value)&&value>=0),'NonrootControlScanCounts');
  const sourceUpdatedMs=Object.hasOwn(scan,'vulnerabilitySourceUpdatedAt')?ecrScanTimestampMs(scan.vulnerabilitySourceUpdatedAt):null;
  need(sourceUpdatedMs===null||sourceUpdatedMs<=observedMs,'NonrootControlScanTimestamp');
  const current={completedMs,sourceUpdatedMs,counts};if(identity)same(current,identity,'NonrootControlScanChanged');else identity=current;
  findings.push(...scan.findings);need(findings.length<=P.maxFindings,'NonrootControlScanFindingLimit');
  if(index<rawPages.length-1){need(typeof page.nextToken==='string'&&page.nextToken.length>0&&Buffer.byteLength(page.nextToken)<=P.maxTokenBytes&&!tokens.has(page.nextToken),'NonrootControlScanPagination');tokens.add(page.nextToken);}
  else need(page.nextToken===undefined||page.nextToken===null||page.nextToken==='','NonrootControlScanPagination');
 }
 const counts={},normalized=findings.map(f=>{
  need(typeof f?.name==='string'&&f.name.length>0&&severities.has(f.severity)&&Array.isArray(f.attributes)&&f.attributes.every(a=>typeof a.key==='string'&&typeof a.value==='string'),'NonrootControlScanFinding');
  counts[f.severity]=(counts[f.severity]??0)+1;return {...f,attributes:[...f.attributes].sort((a,b)=>hash(a).localeCompare(hash(b)))};
 }).sort((a,b)=>hash(a).localeCompare(hash(b)));
 same(counts,Object.fromEntries(Object.entries(identity.counts).filter(([,value])=>value!==0)),'NonrootControlScanCounts');
 need(normalized.length===P.allowedFindings,'NonrootControlScanFindingsPresent');
 return copyNonrootJson({rawPages,findings:normalized,scanCompletedMs:identity.completedMs});
}

/** Recompute the rule from real archived pages; the review's decision string
 * or its content hash alone never establishes the zero-findings result. */
export async function verifyNonrootControlScan(value,{image,contract,sourceContext,resolveJson,resolveBytes,now=Date.now()}={}){
 const scan=inspectNonrootRecord('ControlScanEvidenceV1',value),options={resolveJson,resolveBytes};
 await assertNonrootControlScanPolicy(contract,sourceContext);
 need(['account','region','repositoryName'].every(key=>image?.[key]===contract.output[key]),'NonrootControlScanScope');
 same(scan.image,image);need(scan.policyHash===CONTROL_ZERO_FINDINGS_POLICY_HASH,'NonrootControlScanPolicy');
 const pages=await readNonrootEvidence(scan.rawPages,options),findings=await readNonrootEvidence(scan.normalizedFindings,options),review=await readNonrootEvidence(scan.artifactReview,options);
 const actual=normalizeNonrootControlScanPages(pages,image,{observedMs:scan.observedMs,now});same(findings,actual.findings);
 exact(review,['version','kind','decision','image','policyHash','findingsHash','sourceTree','reviewedMs','expiresMs']);
 need(review.version===1&&review.kind==='control-artifact-policy-review'&&review.decision==='within-existing-policy'&&review.policyHash===CONTROL_ZERO_FINDINGS_POLICY_HASH&&review.findingsHash===hash(actual.findings)&&review.sourceTree===contract.candidate.tree,'NonrootControlScanDecision');same(review.image,image);
 need(positive(review.reviewedMs)&&review.reviewedMs>=scan.observedMs&&review.reviewedMs<=now&&positive(review.expiresMs)&&review.expiresMs>now&&review.expiresMs<=Math.min(scan.observedMs+P.maxObservationAgeMs,actual.scanCompletedMs+P.maxScanAgeMs),'NonrootControlScanExpired');
 return Object.freeze({policyHash:scan.policyHash,rawPagesHash:scan.rawPages.canonicalHash,findingsHash:hash(actual.findings),expiresMs:review.expiresMs});
}
