import {it,expect} from 'vitest';
import {readImageGraph,verifyImageGraphCopies,inspectImageCopyVerification,imageDigest} from './lib/production-image-graph.mjs';
import {inspectImageFilesystem} from './lib/production-image-filesystem.mjs';
import {restoreImageVerificationEvidence} from './lib/production-image-restoration.mjs';
import {imageTransitionFixture,imageTransitionServingFixture,imageTransitionArchiveFixture} from './production-image-transition.fixture.mjs';
import {buildImageTransitionProof} from './lib/production-image-transition-proof.mjs';
import {copyImageGraph,observeImageScans} from './lib/production-image-copy.mjs';
import {graphFixture} from './production-image.fixture.mjs';
import {captureDataReleaseScans} from './lib/production-data-evidence.mjs';
import {canaryEvidenceHash as hash} from './lib/production-canary-verification.mjs';

async function fixture(){
 const f=graphFixture({packageDatabaseText:'P:fixture-library\nV:2.0-r1\n\n'});
 for(const r of f.roots){r.sourceRepository='mem9-on-aws/preview/'+r.component;r.destinationRepository='mem9-on-aws/'+r.component;}
 const source=await readImageGraph(f.roots,{...f});
 const filesystemRequirements={'llm-proxy':[],'mnemo-server':[{path:'/lib/apk/db/installed',manager:'apk',name:'fixture-library',version:'2.0-r1'}],'qwen3-embed':[]};
 const filesystems=await Promise.all(f.roots.map(r=>inspectImageFilesystem(source,{component:r.component,budget:f.budget,requirements:filesystemRequirements[r.component]})));
 const records=new Map(),events=[],stored=new Map(),tags=new Map(),uploads=new Map();let count=0;
 const journal={async read(name){return records.get(name)??null;},async once(name,value){if(records.has(name))throw Error('exists');records.set(name,structuredClone(value));}};
 const api={
  async readTag({repositoryName,imageTag}){return tags.get(repositoryName+'@'+imageTag)??null;},
  async readManifest({repositoryName,descriptor}){return stored.get(repositoryName+'@'+descriptor.digest)??null;},
  async BatchCheckLayerAvailability({repositoryName,layerDigests}){return {repositoryName,layers:layerDigests.map(d=>({layerDigest:d,layerAvailability:stored.has(repositoryName+'@'+d)?'AVAILABLE':'UNAVAILABLE'})),failures:[]};},
  async InitiateLayerUpload({repositoryName}){const uploadId='upload-'+(++count);uploads.set(uploadId,{repositoryName,parts:[]});events.push('init');return {repositoryName,uploadId,partSize:5242880};},
  async UploadLayerPart({repositoryName,uploadId,partFirstByte,partLastByte,layerPartBlob}){const u=uploads.get(uploadId);expect(u.repositoryName).toBe(repositoryName);expect(partFirstByte).toBe(u.parts.reduce((n,b)=>n+b.length,0));expect(partLastByte).toBe(partFirstByte+layerPartBlob.length-1);u.parts.push(Buffer.from(layerPartBlob));events.push('part');return {repositoryName,uploadId,lastByteReceived:partLastByte};},
  async CompleteLayerUpload({repositoryName,uploadId,layerDigests}){const bytes=Buffer.concat(uploads.get(uploadId).parts);expect(imageDigest(bytes)).toBe(layerDigests[0]);stored.set(repositoryName+'@'+layerDigests[0],bytes);events.push('complete');return {repositoryName,uploadId,layerDigest:layerDigests[0]};},
  async PutImage({repositoryName,imageDigest:d,imageManifest,imageTag}){const bytes=Buffer.from(imageManifest);expect(imageDigest(bytes)).toBe(d);stored.set(repositoryName+'@'+d,bytes);if(imageTag)tags.set(repositoryName+'@'+imageTag,bytes);events.push('manifest');return {image:{registryId:'123456789012',repositoryName,imageId:{imageDigest:d},imageManifest}};},
 };
 const destination={readManifest:async({repositoryName,descriptor})=>stored.get(repositoryName+'@'+descriptor.digest),readBlob:async({repositoryName,descriptor})=>(async function*(){const b=stored.get(repositoryName+'@'+descriptor.digest);if(!b)throw Error('missing');yield b;})()};
 const options={api,destination,store:f.store,budget:f.budget,filesystems,filesystemRequirements,journal,scope:{account:'123456789012',region:'us-west-2'},operation:{owner:'a'.repeat(32),planHash:'b'.repeat(64)},authorize:async()=>{},assertCurrent:()=>{}};
 return {...f,source,filesystems,records,events,stored,tags,uploads,journal,api,destination,options};
}
it('copies full graph with immutable intents and independent destination byte verification',async()=>{
 const f=await fixture(),result=await copyImageGraph(f.source,f.options);expect(result.phase).toBe('copied');expect(inspectImageCopyVerification(result.verification).summary.inventoryHash).toBe(f.source.inventoryHash);
 expect(f.events.filter(x=>x==='manifest')).toHaveLength(9);expect(f.tags.size).toBe(3);expect([...f.records.keys()].some(k=>k.startsWith('intent-'))).toBe(true);
});
it('all destination tag conflicts and authority checks precede every upload',async()=>{
 const f=await fixture();f.tags.set(f.roots[2].destinationRepository+'@'+f.roots[2].targetTag,Buffer.from('conflict'));
 await expect(copyImageGraph(f.source,f.options)).rejects.toThrow();expect(f.events).toHaveLength(0);
 const g=await fixture();g.options.authorize=async()=>{throw Error('not current');};await expect(copyImageGraph(g.source,g.options)).rejects.toThrow();expect(g.events).toHaveLength(0);
});
it('unknown mutation leaves its intent and never retries or starts later writes',async()=>{
 const f=await fixture();f.api.UploadLayerPart=async()=>{f.events.push('unknown');throw Error('lost response');};await expect(copyImageGraph(f.source,f.options)).rejects.toThrow();
 expect(f.events.filter(x=>x==='unknown')).toHaveLength(1);const previous=f.events.length;await expect(copyImageGraph(f.source,f.options)).rejects.toThrow();expect(f.events.length).toBe(previous);
 await expect(copyImageGraph(f.source,{...f.options,mode:'observe'})).rejects.toThrow();expect(f.events.length).toBe(previous);
});
it('rejects omitted/forged filesystem contexts and destination byte corruption',async()=>{
 const f=await fixture();await expect(copyImageGraph(f.source,{...f.options,filesystems:f.filesystems.slice(1)})).rejects.toThrow();expect(f.events).toHaveLength(0);
 const g=await fixture();g.destination.readBlob=async()=>({async *[Symbol.asyncIterator](){yield Buffer.from('corrupt');}});await expect(copyImageGraph(g.source,g.options)).rejects.toThrow();
});
it('source/destination graph contexts cannot be replaced by serialized flags',async()=>{
 const f=await fixture();expect(()=>verifyImageGraphCopies(f.source,JSON.parse(JSON.stringify(f.source)))).toThrow();
 expect(()=>inspectImageCopyVerification({graphHash:f.source.graphHash,verified:true})).toThrow();
});

it('requires all live source FS handles and independent nonempty package requirements before any write',async()=>{
 for(const override of [o=>({filesystems:undefined}),o=>({filesystems:[]}),o=>({filesystemRequirements:undefined}),o=>({filesystemRequirements:{...o.filesystemRequirements,'mnemo-server':[]}}),o=>({filesystemRequirements:{...o.filesystemRequirements,'mnemo-server':[{...o.filesystemRequirements['mnemo-server'][0],version:'wrong'}]}})]){
  const f=await fixture();await expect(copyImageGraph(f.source,{...f.options,...override(f.options)})).rejects.toThrow();expect(f.events).toHaveLength(0);expect(f.records.size).toBe(0);
 }
});
it('rejects real destination and another source graph FS handles before any write',async()=>{
 for(const side of ['source','destination']){
  const f=await fixture(),other=await readImageGraph(f.roots,{...f,source:undefined,readManifest:async({descriptor})=>f.data.get(descriptor.digest),readBlob:async({descriptor})=>(async function*(){yield f.data.get(descriptor.digest);})(),side}),filesystems=await Promise.all(f.roots.map(r=>inspectImageFilesystem(other,{component:r.component,requirements:f.options.filesystemRequirements[r.component]})));
  await expect(copyImageGraph(f.source,{...f.options,filesystems})).rejects.toThrow();expect(f.events).toHaveLength(0);expect(f.records.size).toBe(0);
 }
});
it('rejects an actual restored archived FS handle before any copy write',async()=>{
 const origin=await imageTransitionFixture(),built=await buildImageTransitionProof(origin.input,origin),served=imageTransitionServingFixture(origin,built),archive=imageTransitionArchiveFixture(built,served);
 const restored=restoreImageVerificationEvidence(archive.input,archive.expected),f=await fixture();
 const filesystems=f.filesystems.map(c=>c.evidence.component==='mnemo-server'?restored.filesystemVerification:c);
 await expect(copyImageGraph(f.source,{...f.options,filesystems})).rejects.toThrow('ImageFilesystemSourceRequired');expect(f.events).toHaveLength(0);expect(f.records.size).toBe(0);
});

async function scansFixture(){
 const f=await fixture(),copied=await copyImageGraph(f.source,f.options),scanTime=f.budget.now(),clock=()=>scanTime,starts=[];let scenario='complete';const requested=new Set();
 f.api.DescribeImageScanFindings=async({repositoryName,imageId,nextToken})=>{
  const component=repositoryName.split('/').at(-1);
  if(scenario==='missing'&&!requested.has(component))throw Object.assign(Error('missing'),{name:'ScanNotFoundException',$metadata:{httpStatusCode:400,requestId:'fixture'}});
  if(scenario==='denied')throw Object.assign(Error('denied'),{name:'AccessDeniedException',$metadata:{httpStatusCode:400,requestId:'fixture'}});
  const status=scenario==='pending'?'PENDING':'COMPLETE',age=scenario==='stale'&&!requested.has(component)?86400001:1000;
  return {registryId:'123456789012',repositoryName,imageId,imageScanStatus:{status},imageScanFindings:{imageScanCompletedAt:new Date(clock()-age).toISOString(),findingSeverityCounts:{HIGH:1},findings:nextToken?[{name:'TEST-ADVISORY',severity:'HIGH',attributes:[{key:'package_name',value:'fixture'}]}]:[]},...(!nextToken?{nextToken:'next-page'}:{})};
 };
 f.api.StartImageScan=async({repositoryName,imageId})=>{const component=repositoryName.split('/').at(-1);starts.push(component);requested.add(component);if(scenario==='unknown')throw Error('lost response');if(scenario==='cleanup')throw Object.assign(Error('unconfirmed'),{code:'ECLEANUP',cleanupComplete:false});return {registryId:'123456789012',repositoryName,imageId,imageScanStatus:{status:'PENDING'}};};
 const normalize=async({summary,scans,observedMs})=>{
  const data={version:1,stage:'prod',account:summary.account,region:summary.region,controlSourceTree:'a'.repeat(40),dataRevision:'b'.repeat(40),dataSourceTree:'c'.repeat(40),dataSourceTag:'mem9-bbbbbbb',images:summary.images,runtimeNonce:'a'.repeat(32),authorizationId:'b'.repeat(32),issuedMs:observedMs-1000,expiresMs:observedMs+1000,...Object.fromEntries(['parentProofHash','backendBindingHash','generation','targetsHash','schemaDigest','operatorDigest','buildInputsHash','securityEvidenceHash','policyHash'].map(k=>[k,'d'.repeat(64)]))};
  return captureDataReleaseScans({data,now:observedMs,readEcr:async(_operation,input)=>structuredClone(scans[input.repositoryName.split('/').at(-1)].pages[input.nextToken?1:0])});
 };
 const options={...f.options,normalize,pause:async()=>{},operation:f.options.operation};
 return {...f,copied,starts,requested,options,setScenario:v=>scenario=v};
}
it('normalizes every complete page with the unchanged full finding normalizer',async()=>{
 const f=await scansFixture(),r=await observeImageScans(f.copied.verification,f.options);expect(f.starts).toHaveLength(0);
 for(const s of Object.values(r.scans)){expect(s.pages).toHaveLength(2);expect(s.findings).toHaveLength(1);expect(s.findingsHash).toBe(hash(s.findings));}
});
for(const scenario of ['missing','stale'])it('starts one eligible '+scenario+' scan and accepts pending before observing COMPLETE',async()=>{
 const f=await scansFixture();f.setScenario(scenario);const r=await observeImageScans(f.copied.verification,f.options);expect(f.starts).toHaveLength(3);expect(Object.values(r.scans).every(s=>s.requestOutcome==='accepted')).toBe(true);
});
it('does not treat access denial as scan absence',async()=>{
 const f=await scansFixture();f.setScenario('denied');await expect(observeImageScans(f.copied.verification,f.options)).rejects.toThrow();expect(f.starts).toHaveLength(0);
});
it('unknown existing scan intent is observation-only even when copy mode is requested again',async()=>{
 const f=await scansFixture();f.records.set('scan-llm-proxy-intent.json',{version:1,owner:f.options.operation.owner});const r=await observeImageScans(f.copied.verification,f.options);expect(f.starts).toHaveLength(0);expect(r.scans['llm-proxy'].requestOutcome).toBe('unknown');
});
