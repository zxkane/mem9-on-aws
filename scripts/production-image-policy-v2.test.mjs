import {describe,it,expect} from 'vitest';
import {imageTransitionFixture,imageTransitionServingFixture} from './production-image-transition.fixture.mjs';
import {captureDataReleaseScans} from './lib/production-data-evidence.mjs';
import {buildImageTransitionProof,verifyImageTransitionProof,verifyImageTransitionArtifactSecurity,buildFullFindingsArtifactPolicy,imageTransitionFullFindingReviewScope,assertImageTransitionDataRelease,bindImageTransitionAuthorization} from './lib/production-image-transition-proof.mjs';

async function fullFixture(){
 const f=await imageTransitionFixture(),priorPolicy=structuredClone(f.input.policy),priorPolicyHash=f.hash(priorPolicy);
 const original=JSON.parse(f.input.scans.old['llm-proxy'][0]).imageScanFindings.findings;
 const retained=original.filter(x=>x.attributes.some(a=>a.key==='package_name'&&a.value==='zlib'));
 const additions=['HIGH','MEDIUM','LOW'].map((severity,i)=>({name:'CVE-2099-'+(2001+i),severity,description:'Synthetic additional full-catalogue finding',attributes:[{key:'package_name',value:'glibc'},{key:'package_version',value:'9.0-synthetic'}]}));
 for(const phase of ['old','preview','destination'])for(const c of ['llm-proxy','qwen3-embed']){
  const raw=JSON.parse(f.input.scans[phase][c][0]);raw.imageScanFindings.findings=[...retained,...additions];raw.imageScanFindings.findingSeverityCounts={HIGH:2,MEDIUM:1,LOW:1};f.input.scans[phase][c][0]=JSON.stringify(raw);
 }
 for(const finding of additions){
  const rawText=JSON.stringify({synthetic:true,cve:finding.name,package:'glibc',packageVersion:'9.0-synthetic',status:'unfixed'});
  f.input.vendors.push({version:1,cve:finding.name,package:'glibc',suite:'trixie',packageVersion:'9.0-synthetic',status:'unfixed',observedMs:f.now-1000,source:'https://example.com/vendor/'+finding.name,rawText,rawHash:f.sha(rawText)});
 }
 const normalized={};for(const phase of ['old','preview']){
  const data={...f.predecessor,stage:phase==='old'?'prod':'pr-1',images:phase==='old'?f.predecessor.images:f.input.images};data.dataSourceTag=(phase==='old'?'mem9-':'pr-')+data.dataRevision.slice(0,7);
  normalized[phase]=await captureDataReleaseScans({data,now:f.now,readEcr:async(operation,r)=>{expect(operation).toBe('describe-image-scan-findings');return JSON.parse(f.input.scans[phase][r.repositoryName.split('/').at(-1)][0]);}});
 }
 const basis={...normalized,vendors:f.input.vendors,priorPolicy,priorPolicyHash},baseControls=structuredClone(priorPolicy.requiredControls);
 const scope=imageTransitionFullFindingReviewScope({...basis,baseControls});
 const control={clause:'CATALOGUE-1: synthetic reviewed complete findings',policySourceHash:f.sha(priorPolicy.policySources[0].text),evidenceHash:f.hash(scope)};
 const controls={authority:false,policySources:structuredClone(priorPolicy.policySources),requiredControls:[...baseControls,control]};
 const construction={...basis,controls,applicability:{control,scope},now:f.now};
 f.input.policy=buildFullFindingsArtifactPolicy(construction);f.input.buildEvidence.controls=structuredClone(controls.requiredControls);
 f.expected.policyHash=f.hash(f.input.policy);f.expected.buildEvidenceHash=f.hash(f.input.buildEvidence);
 return {...f,construction,normalized,priorPolicy};
}
function mutable(f){f.input.policy=structuredClone(f.input.policy);return f;}
function repin(f){f.expected.policyHash=f.hash(f.input.policy);f.expected.buildEvidenceHash=f.hash(f.input.buildEvidence);}

describe('versioned full-finding artifact policy',()=>{
 it('preserves exact original v1 policy/proof goldens and limits',async()=>{
  const f=await imageTransitionFixture(),b=await buildImageTransitionProof(f.input,f);
  expect(f.hash(f.input.policy)).toBe('a3dbdfe931f62b2e9446a6c667eeb508b69a0bd8c52876b5087ed813f7d7e8a5');
  expect(b.proofHash).toBe('dd13922c564f7f1390a057a19530ae3da5c170dea69d900c1f2babe34431018b');
  expect(f.hash(f.input.limits)).toBe('59a5bf6d08f4e1a787d1f016a320c625fd43bb973bb924d6999427dfcfe71ced');
 });
 it('constructs and verifies v2 through the actual full proof and nonroot artifact entry points',async()=>{
  const f=await fullFixture(),b=await buildImageTransitionProof(f.input,f);
  expect(b.proof.policy.version).toBe(2);expect(b.proof.policy.open).toHaveLength(8);
  expect(new Set(b.proof.policy.open.map(x=>x.severity))).toEqual(new Set(['HIGH','MEDIUM','LOW']));
  expect(b.proof.policy.history.policy).toEqual(f.priorPolicy);
  expect(b.proof.policy.history.entries.filter(x=>x.currentFindingHash===null)).toHaveLength(2);
  expect(b.proof.policy.history.entries.every(x=>x.disposition==='OPEN_UNRESOLVED')).toBe(true);
  await expect(verifyImageTransitionProof(b.proof,{...f,proofHash:b.proofHash})).resolves.toBeDefined();
  const keys=['images','artifacts','dataOrigin','scans','policy','vendors','buildEvidence','graph','filesystem'];
  const checked=await verifyImageTransitionArtifactSecurity(Object.fromEntries(keys.map(k=>[k,f.input[k]])),{predecessor:f.predecessor,now:f.now});
  expect(checked.artifactPolicyHash).toBe(f.hash(f.input.policy));
  const s=imageTransitionServingFixture(f,b),context=bindImageTransitionAuthorization(b.context,{review:s.review,now:f.now});
  expect(()=>assertImageTransitionDataRelease(context,{current:s.data,controlSourceTree:s.data.controlSourceTree,now:f.now})).not.toThrow();
  expect(()=>bindImageTransitionAuthorization(b.context,{review:{...s.review,artifactPolicyHash:'0'.repeat(64)},now:f.now})).toThrow();
 });
 it('does not mutate caller inputs while producing a detached immutable policy',async()=>{
  const f=await fullFixture(),before=JSON.stringify(f.construction),p=buildFullFindingsArtifactPolicy(f.construction);
  expect(JSON.stringify(f.construction)).toBe(before);expect(Object.isFrozen(f.construction.controls)).toBe(false);expect(Object.isFrozen(p.history.policy)).toBe(true);
  f.construction.priorPolicy.open.pop();expect(p.history.policy.open).toHaveLength(4);
 });
 it.each(['missing-scope','previous-controls','wrong-scope','missing-vendor','unknown-vendor','expired-vendor','different-prior-pin','baseline-removed'])('rejects construction with %s',async mode=>{
  const f=await fullFixture(),c=structuredClone(f.construction);
  if(mode==='missing-scope')c.applicability=null;
  if(mode==='previous-controls')c.controls.requiredControls.pop();
  if(mode==='wrong-scope')c.applicability.scope.findings.pop();
  if(mode==='missing-vendor')c.vendors.pop();
  if(mode==='unknown-vendor')c.vendors.at(-1).status='unknown';
  if(mode==='expired-vendor')c.vendors.at(-1).observedMs=f.now-86400001;
  if(mode==='different-prior-pin')c.priorPolicyHash='0'.repeat(64);
  if(mode==='baseline-removed')c.controls.policySources=[];
  expect(()=>buildFullFindingsArtifactPolicy(c)).toThrow();
 });
 it.each(['drop-low','duplicate-row','change-severity','close-history','drop-history','change-history','generic-approval','unknown-version','legacy-relabel'])('rejects repinned policy %s in the original verifier',async mode=>{
  const f=mutable(await fullFixture()),p=f.input.policy;
  if(mode==='drop-low')p.open=p.open.filter(x=>x.severity!=='LOW');
  if(mode==='duplicate-row')p.open[0]=p.open[1];
  if(mode==='change-severity')p.open[0].severity='CRITICAL';
  if(mode==='close-history')p.history.entries[0].disposition='CLOSED';
  if(mode==='drop-history')p.history.entries.pop();
  if(mode==='change-history')p.history.policy.open.pop();
  if(mode==='generic-approval')p.applicability={approved:true};
  if(mode==='unknown-version')p.version=3;
  if(mode==='legacy-relabel'){p.version=1;p.schema='ecr-basic-full-findings-v1';delete p.history;delete p.applicability;}
  repin(f);await expect(buildImageTransitionProof(f.input,f)).rejects.toThrow();
 });
 it.each(['destination','copy','filesystem','expired-scan','build-controls'])('keeps original %s checks mandatory for v2',async mode=>{
  const f=await fullFixture();
  if(mode==='destination'){const r=JSON.parse(f.input.scans.destination['llm-proxy'][0]);r.imageScanFindings.findings.pop();f.input.scans.destination['llm-proxy'][0]=JSON.stringify(r);}
  if(mode==='copy')f.graphVerification={};
  if(mode==='filesystem'){f.input.filesystem.databaseText='P:zlib\nV:older-synthetic\n';f.input.filesystem.databaseHash=f.sha(f.input.filesystem.databaseText);f.expected.filesystemHash=f.hash(f.input.filesystem);}
  if(mode==='expired-scan'){const r=JSON.parse(f.input.scans.old['llm-proxy'][0]);r.imageScanFindings.imageScanCompletedAt=new Date(f.now-86400001).toISOString();f.input.scans.old['llm-proxy'][0]=JSON.stringify(r);}
  if(mode==='build-controls'){f.input.buildEvidence.controls.pop();repin(f);}
  await expect(buildImageTransitionProof(f.input,f)).rejects.toThrow();
 });
});
