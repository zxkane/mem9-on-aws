import {beforeAll,it,expect} from 'vitest';
import {Readable} from 'node:stream';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {parseEpochTimestamp} from '@smithy/core/serde';
import {nonrootDeploymentFixture} from './production-nonroot-provenance.fixture.mjs';
import {createNonrootBudgetedReads} from './lib/production-nonroot-budget-transport.mjs';
import {nonrootArchiveResolvers,nonrootArchiveBindings} from './lib/production-nonroot-archive.mjs';
import {readNonrootEvidence} from './lib/production-nonroot-runtime.mjs';
import {nonrootHash as hash} from './lib/production-nonroot-contracts.mjs';
import {verifyNonrootControlSource,verifyNonrootDeployedControlBuild} from './lib/production-nonroot-provenance.mjs';
import {collectNonrootControlRuntime} from './lib/production-nonroot-observation.mjs';
import {dockerArtifactFixture} from './production-nonroot-observation.fixture.mjs';
import {collectNonrootControlScan,verifyNonrootControlScan,CONTROL_ZERO_FINDINGS_POLICY as P,CONTROL_ZERO_FINDINGS_POLICY_HASH as policyHash,CONTROL_ZERO_FINDINGS_POLICY_SOURCE as policyPath} from './lib/production-nonroot-control-scan.mjs';
import {ecrScanTimestampMs,normalizeNonrootControlScanPages,assertNonrootControlScanPolicy} from './lib/production-nonroot-control-scan-policy.mjs';

const policyBytes=readFileSync(new URL('./lib/production-nonroot-control-scan-policy.json',import.meta.url));
const env={AWS_ACCESS_KEY_ID:'synthetic-access',AWS_SECRET_ACCESS_KEY:'synthetic-secret',AWS_SESSION_TOKEN:'synthetic-session'};
const encode=pages=>pages.map(page=>JSON.stringify(page));
let base;
beforeAll(async()=>{base=await nonrootDeploymentFixture({sourceOverrides:new Map([[policyPath,policyBytes]])});});
function fixture({deployment=base,mutate,deny=false,localDeny=false,responseLimit=8192,networkError=false,status=200,afterHttp}={}){
 const f=deployment,events=[],contract={...f.contract,artifactPolicyHash:policyHash},image=f.build.image,now=f.now;
 const page={registryId:image.account,repositoryName:image.repositoryName,imageId:{imageDigest:image.arm64Digest},imageScanStatus:{status:'COMPLETE',description:'Synthetic completed scan'},
  imageScanFindings:{imageScanCompletedAt:(now-1000)/1000+0.0001,vulnerabilitySourceUpdatedAt:(now-2000)/1000,findings:[],findingSeverityCounts:{}}};
 mutate?.(page);const raw=Buffer.from(JSON.stringify(page));
 const acquisition={async beforeRead(action,request){
  events.push(['reserve',action,request]);if(deny)throw Error('SyntheticBudgetExhausted');
  return {caps:{requestBytes:4096,responseBytes:responseLimit},finalGuard(){events.push(['guard']);},charge(n){events.push(['charge',n]);},async complete(response,responseHash){events.push(['complete',response,responseHash]);},async unknown(){events.push(['unknown']);}};
 },reserveLocal(charge){events.push(['local',charge]);if(localDeny)throw Error('SyntheticLocalExhausted');},finish(){throw Error('CallerOwnsFinish');}};
 const handler={async handle(request){events.push(['http',request]);if(networkError)throw Error('synthetic network interruption');afterHttp?.();return {response:{statusCode:status,headers:{'content-type':'application/x-amz-json-1.1'},body:Readable.from([raw.subarray(0,10),raw.subarray(10)])}};},destroy(){}};
 const reader=createNonrootBudgetedReads({region:image.region,env,metadataReads:acquisition,requestHandler:handler});
 const input={contract,sourceContext:f.sourceContext,graph:f.controlVerification.graph,archive:f.a.archive(),budgetedReads:reader,maximumExpiresMs:now+120000};
 return {f,contract,image,now,page,raw,events,reader,input,collect:options=>collectNonrootControlScan(input,{clock:()=>now,...options})};
}
function archived(page,{findings=[],reviewChange={},scanChange={}}={}){
 const x=fixture(),a=x.f,review={version:1,kind:'control-artifact-policy-review',decision:'within-existing-policy',image:x.image,policyHash,findingsHash:hash(findings),sourceTree:x.contract.candidate.tree,reviewedMs:x.now,expiresMs:x.now+120000,...reviewChange};
 x.reader.close();
 const scan={version:1,kind:'deployed-control-scan-evidence',image:x.image,rawPages:a.json(encode(page??[x.page]),'scan'),normalizedFindings:a.json(findings,'scan'),artifactReview:a.json(review,'policy'),policyHash,observedMs:x.now,result:'pass',...scanChange};
 return {x,scan,options:{image:x.image,contract:x.contract,sourceContext:a.sourceContext,...nonrootArchiveResolvers(a.a.archive()),now:x.now}};
}

it('collects a terminal CONTROL scan through real signed transport with prepaid mocked HTTP and preserves raw seconds',async()=>{
 const x=fixture();try{
  const original=nonrootArchiveBindings(x.input.archive),r=await x.collect(),options={image:x.image,contract:x.contract,sourceContext:x.f.sourceContext,...nonrootArchiveResolvers(r.archive),now:x.now};
  const pages=await readNonrootEvidence(r.scan.rawPages,options),review=await readNonrootEvidence(r.scan.artifactReview,options);
  expect(pages).toEqual(encode([x.page]));expect(JSON.parse(pages[0]).imageScanFindings.imageScanCompletedAt).toBe(x.page.imageScanFindings.imageScanCompletedAt);
  expect(ecrScanTimestampMs(JSON.parse(pages[0]).imageScanFindings.imageScanCompletedAt)).toBe(x.now-1000);
  expect(review).toMatchObject({policyHash,findingsHash:hash([]),expiresMs:x.input.maximumExpiresMs});
  await expect(verifyNonrootControlScan(r.scan,options)).resolves.toMatchObject({policyHash,expiresMs:x.input.maximumExpiresMs});
  const request=x.events.find(e=>e[0]==='http')[1];
  expect(JSON.parse(request.body)).toEqual({registryId:x.image.account,repositoryName:x.image.repositoryName,imageId:{imageDigest:x.image.arm64Digest}});
  expect(request.headers['x-amz-target']).toBe('AmazonEC2ContainerRegistry_V20150921.DescribeImageScanFindings');
  expect(request.headers.authorization).toMatch(/^AWS4-HMAC-SHA256 /);
  expect(x.events.filter(e=>e[0]==='reserve')).toHaveLength(1);
  expect(x.events.findIndex(e=>e[0]==='reserve')).toBeLessThan(x.events.findIndex(e=>e[0]==='http'));
  expect(x.events.find(e=>e[0]==='complete')).toEqual(['complete',x.page,createHash('sha256').update(x.raw).digest('hex')]);
  expect(x.events.filter(e=>e[0]==='charge').reduce((n,e)=>n+e[1],0)).toBe(x.raw.length+Buffer.byteLength(request.body));
  expect(x.events.filter(e=>e[0]==='local').every(e=>e[1].ecrRequests===0&&e[1].httpBodyBytes===0)).toBe(true);
  expect(x.events.filter(e=>e[0]==='local').some(e=>e[1].logicalBytes>0)).toBe(true);
  expect(nonrootArchiveBindings(x.input.archive)).toEqual(original);expect(r.archiveAdditions.length).toBeGreaterThan(0);
 }finally{x.reader.close();}
});

it('binds the fixed policy to the authenticated source tree and the contract',async()=>{
 const x=fixture();try{await expect(verifyNonrootControlSource(x.contract,{...x.f.options(),expected:{sourceContext:x.f.sourceContext}})).resolves.toMatchObject({contractHash:hash(x.contract)});
  expect(policyHash).toBe(hash(JSON.parse(policyBytes)));expect(Object.isFrozen(P)).toBe(true);expect(Object.isFrozen(P.exceptions)).toBe(true);
 }finally{x.reader.close();}
});
it.each(['policy','source','graph','expiry','missing-reader','budget','local'])('rejects %s before HTTP',async defect=>{
 const x=fixture({deny:defect==='budget',localDeny:defect==='local'});try{
  if(defect==='policy')x.input.contract={...x.contract,artifactPolicyHash:'f'.repeat(64)};
  if(defect==='source')x.input.sourceContext={tree:x.contract.candidate.tree};
  if(defect==='graph')x.input.graph=structuredClone(x.input.graph);
  if(defect==='expiry')x.input.maximumExpiresMs=x.now;
  if(defect==='missing-reader')x.input.budgetedReads={};
  await expect(x.collect()).rejects.toThrow();expect(x.events.some(e=>e[0]==='http')).toBe(false);
 }finally{x.reader.close();}
});
it('rejects modified policy bytes even when their membership belongs to a real tree',async()=>{
 const changed={...P,allowedFindings:1},f=await nonrootDeploymentFixture({sourceOverrides:new Map([[policyPath,JSON.stringify(changed)]])}),contract={...f.contract,artifactPolicyHash:policyHash};
 await expect(assertNonrootControlScanPolicy(contract,f.sourceContext)).rejects.toThrow('NonrootControlScanPolicySource');
 await expect(verifyNonrootControlSource(contract,f.options())).rejects.toThrow('NonrootControlScanPolicySource');
});
it.each(['token','foreign-image','incomplete-scan','nonzero','count','enhanced'])('holds %s after a single physical scan request',async defect=>{
 const x=fixture({mutate:p=>{
  if(defect==='token')p.nextToken='synthetic-next';if(defect==='foreign-image')p.imageId.imageDigest='sha256:'+'f'.repeat(64);
  if(defect==='incomplete-scan')p.imageScanStatus.status='IN_PROGRESS';
  if(defect==='nonzero'){p.imageScanFindings.findings=[{name:'SYNTHETIC-1',severity:'LOW',attributes:[]}];p.imageScanFindings.findingSeverityCounts={LOW:1};}
  if(defect==='count')p.imageScanFindings.findingSeverityCounts={CRITICAL:1};if(defect==='enhanced')p.imageScanFindings.enhancedFindings=[{severity:'LOW'}];
 }});try{
  await expect(x.collect()).rejects.toThrow(defect==='token'?'NonrootControlScanPaginationUnfunded':undefined);
  expect(x.events.filter(e=>e[0]==='http')).toHaveLength(1);
 }finally{x.reader.close();}
});
it.each(['denied','overflow','unknown'])('retains transport HOLD for %s without retry',async defect=>{
 const x=fixture({status:defect==='denied'?403:200,responseLimit:defect==='overflow'?10:8192,networkError:defect==='unknown'});try{
  await expect(x.collect()).rejects.toThrow();expect(x.events.filter(e=>e[0]==='http')).toHaveLength(1);expect(x.events.filter(e=>e[0]==='unknown')).toHaveLength(1);
  await expect(x.collect()).rejects.toThrow('NonrootAcquisitionHeld');expect(x.events.filter(e=>e[0]==='http')).toHaveLength(1);
 }finally{x.reader.close();}
});
it('does not renew expiry when the read finishes after the original deadline',async()=>{
 let elapsed=0;const x=fixture({afterHttp(){elapsed=120000;}});try{
  await expect(x.collect({clock:()=>x.now+elapsed})).rejects.toThrow('NonrootControlScanExpired');expect(x.events.filter(e=>e[0]==='http')).toHaveLength(1);
 }finally{x.reader.close();}
});
it('rejects an already aborted collection before any reads',async()=>{
 const x=fixture();try{await expect(x.collect({signal:AbortSignal.abort()})).rejects.toThrow();expect(x.events).toEqual([]);}finally{x.reader.close();}
});
it('accepts complete archived pagination but rejects missing, repeated and excess pages',()=>{
 const x=fixture();x.reader.close();const options={observedMs:x.now,now:x.now},first={...x.page,nextToken:'synthetic-next'};
 expect(normalizeNonrootControlScanPages(encode([first,x.page]),x.image,options).findings).toEqual([]);
 for(const pages of [[first],[x.page,x.page],[first,first,x.page],Array.from({length:101},()=>x.page)])expect(()=>normalizeNonrootControlScanPages(encode(pages),x.image,options)).toThrow();
});
it.each(['stale','future','milliseconds','unknown-severity','changed-page-time','future-feed','oversized-token'])('rejects %s in complete raw evidence',defect=>{
 const x=fixture();x.reader.close();const page=structuredClone(x.page),options={observedMs:x.now,now:x.now};let pages=[page];
 if(defect==='stale')page.imageScanFindings.imageScanCompletedAt=(x.now-P.maxScanAgeMs-1)/1000;
 if(defect==='future')page.imageScanFindings.imageScanCompletedAt=(x.now+1)/1000;
 if(defect==='milliseconds')page.imageScanFindings.imageScanCompletedAt=x.now;
 if(defect==='unknown-severity')page.imageScanFindings.findingSeverityCounts={unexpected:0};
 if(defect==='future-feed')page.imageScanFindings.vulnerabilitySourceUpdatedAt=(x.now+1)/1000;
 if(defect==='changed-page-time'){pages=[{...x.page,nextToken:'synthetic-next'},page];page.imageScanFindings.imageScanCompletedAt-=1;}
 if(defect==='oversized-token')pages=[{...page,nextToken:'x'.repeat(P.maxTokenBytes+1)},page];
 expect(()=>normalizeNonrootControlScanPages(encode(pages),x.image,options)).toThrow();
});
it.each(['decision','expiry','review-time','normalized','policy','extra'])('recomputes a rehashed archive and rejects forged %s evidence',async defect=>{
 const {x,scan,options}=archived();
 if(defect==='policy')scan.policyHash='f'.repeat(64);
 else if(defect==='normalized')scan.normalizedFindings=x.f.json([{name:'fabricated'}],'scan');
 else{const review=structuredClone(x.f.a.value(scan.artifactReview));
  if(defect==='decision')review.decision='approved';if(defect==='expiry')review.expiresMs=x.now+P.maxObservationAgeMs+1;
  if(defect==='review-time')review.reviewedMs=x.now+1;if(defect==='extra')review.authorized=true;scan.artifactReview=x.f.json(review,'policy');}
 await expect(verifyNonrootControlScan(scan,{...options,...nonrootArchiveResolvers(x.f.a.archive())})).rejects.toThrow();
});
it.each(['INFORMATIONAL','LOW','MEDIUM','HIGH','CRITICAL','UNDEFINED'])('never accepts a self-consistent positive review for %s findings',async severity=>{
 const x=fixture();x.reader.close();const findings=[{name:'SYNTHETIC-1',severity,attributes:[]}];x.page.imageScanFindings.findings=findings;x.page.imageScanFindings.findingSeverityCounts={[severity]:1};
 const a=archived([x.page],{findings});await expect(verifyNonrootControlScan(a.scan,a.options)).rejects.toThrow('NonrootControlScanFindingsPresent');
});
it('rejects expired observed evidence even with a rehashed future review',async()=>{
 const {scan,options}=archived();await expect(verifyNonrootControlScan(scan,{...options,now:options.now+P.maxObservationAgeMs+1})).rejects.toThrow('NonrootControlScanObservation');
});
it('rejects a self-consistent image outside the contract output account',async()=>{
 const {scan,options}=archived(),image={...scan.image,account:'0'.repeat(12)};
 await expect(verifyNonrootControlScan({...scan,image},{...options,image})).rejects.toThrow('NonrootControlScanScope');
});
it('rejects duplicate decoded keys in archived response text before JSON can discard them',()=>{
 const x=fixture();x.reader.close();
 const raw=JSON.stringify(x.page).replace('"findings":[]','"findings":[],"findings":[]');
 expect(()=>normalizeNonrootControlScanPages([raw],x.image,{observedMs:x.now,now:x.now})).toThrow();
});
it('converts raw epoch seconds and archived ISO timestamps without interpreting numbers as milliseconds',()=>{
 expect(ecrScanTimestampMs(1579839105)).toBe(1579839105000);
 expect(ecrScanTimestampMs(1579839105.125)).toBe(1579839105125);
 for(const seconds of [1579839105.001,1579839105.999,1579839105.9999])expect(ecrScanTimestampMs(seconds)).toBe(parseEpochTimestamp(seconds).getTime());
 expect(ecrScanTimestampMs('2020-01-24T03:45:05.125Z')).toBe(1579837505125);
 for(const value of [0,-1,NaN,Infinity,'1579839105',{},null])expect(()=>ecrScanTimestampMs(value)).toThrow();
});

it.skipIf(process.env.MEM9_NONROOT_CONTAINER_TEST!=='1')('verifies produced scan evidence through full deployed provenance with real Docker graph, filesystem and runtime handles',async()=>{
 const docker=dockerArtifactFixture();let x;
 try{
  const f=await nonrootDeploymentFixture({now:Date.now(),sourceOverrides:new Map([[policyPath,policyBytes]]),controlArtifactFactory:docker.factory()});
  f.contract.artifactPolicyHash=policyHash;x=fixture({deployment:f});const collected=await x.collect();
  for(const addition of collected.archiveAdditions){const {bytes,...row}=addition;f.a.files.push(row);f.a.objects.set(row.name,bytes);}
  f.build.scan=collected.scan;f.build.contractHash=hash(f.contract);f.build.completedMs=Math.max(f.build.completedMs,collected.scan.observedMs);
  f.build.resolvedLaunches=f.build.resolvedLaunches.map(launch=>({...launch,contractHash:hash(f.contract)}));
  const tests=structuredClone(f.a.value(f.build.guardTests));tests.contractHash=hash(f.contract);
  for(const test of tests.launches)test.launchHash=hash(f.build.resolvedLaunches.find(launch=>launch.taskKey===test.taskKey));
  f.build.guardTests=f.json(tests);
  const options={...f.options(),beforeDocker:({containerId})=>{if(containerId)docker.containers.add(containerId);}};
  const runtimeObservation=await collectNonrootControlRuntime(f.build,options);
  await expect(verifyNonrootDeployedControlBuild(f.build,{...f.options(),now:Date.now(),runtimeObservation})).resolves.toMatchObject({deployedControlBuildHash:hash(f.build),contractHash:hash(f.contract)});
  expect(x.events.filter(e=>e[0]==='http')).toHaveLength(1);
 }finally{x?.reader.close();await docker.close();}
},120000);
