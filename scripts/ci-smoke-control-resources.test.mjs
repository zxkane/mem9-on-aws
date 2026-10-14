import {it,expect,vi,afterEach} from 'vitest';
import {mkdtemp,mkdir,writeFile,readFile,readdir,rm,symlink,lstat} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {graphFixture} from './production-image.fixture.mjs';
import {readControlImageGraph} from './lib/production-image-graph.mjs';
import {nonrootHash as hash} from './lib/production-nonroot-contracts.mjs';
import {sha} from './lib/ci-smoke-acquisition-format.mjs';
import {allocateCiSmokeControlResources,registerControlCache,beginControlImageLoad,recordControlImageLoad,sealControlResources,verifyControlResources,linkControlResourceCompletion,cleanupCiSmokeControlResources} from './lib/ci-smoke-control-resources.mjs';
const roots=[];afterEach(async()=>{vi.restoreAllMocks();for(const p of roots.splice(0))await rm(p,{recursive:true,force:true});});
async function fixture({checkpoint='deploy-prod/19',runId=77,existingRoot,streaming=false}={}){
 const root=existingRoot??await mkdtemp(join(tmpdir(),'ci-control-owned-'));if(!existingRoot)roots.push(root);const env={RUNNER_TEMP:root,GITHUB_ACTIONS:'true',GITHUB_REPOSITORY:'example/project',GITHUB_RUN_ID:String(runId),GITHUB_RUN_ATTEMPT:'1',GITHUB_JOB:'deploy-prod',GITHUB_SHA:'a'.repeat(40),MEM9_CI_ACQUISITION_CONFIG:'{"synthetic":"config"}'},scope={kind:'target',jobKey:'deploy-prod',route:'deploy-prod',phase:'presst',checkpoint};
 const f=graphFixture(),r=f.roots[0],configDigest=JSON.parse(f.data.get(r.arm64Digest)).config.digest;
 const graph=await readControlImageGraph({account:'123456789012',region:'us-east-1',repositoryName:'mem9-on-aws/bootstrap',root:r.root,arm64Digest:r.arm64Digest,configDigest},{source:f.source,store:f.store,budget:f.budget});
 const binding={source:{repository:env.GITHUB_REPOSITORY,runId,runAttempt:1,mainRevision:env.GITHUB_SHA}},bindingHash=hash(binding),sourceRef={path:join(root,'source.json'),sha256:sha('{}')};await writeFile(sourceRef.path,'{}',{mode:0o600});
 const claim={version:1,kind:'ci-future-acquisition-claim',scope,binding,sourceReceiptRef:sourceRef,configHash:sha(env.MEM9_CI_ACQUISITION_CONFIG),openedMs:Date.now(),expiresMs:Date.now()+60000,ownerRefund:0};
 const dir=join(root,'mem9-ci-future-acquisitions');await mkdir(dir,{mode:0o700,recursive:true});const claimRef={path:join(dir,'target-'+hash({bindingHash,scope})+'-claim.json'),sha256:sha(JSON.stringify(claim))};await writeFile(claimRef.path,JSON.stringify(claim),{mode:0o600});
 const expected={claimRef,scope,bindingHash,sourceReceiptRef:sourceRef,configHash:claim.configHash,run:{repository:env.GITHUB_REPOSITORY,runId,runAttempt:1,jobKey:env.GITHUB_JOB,revision:env.GITHUB_SHA},rootDigest:r.root.digest,configDigest};
 let image=null;const docker=vi.fn(async args=>{
  if(args[0]==='image'&&args[1]==='inspect')return image?{status:0,stdout:JSON.stringify([image]),stderr:''}:{status:1,stdout:'',stderr:'No such image: '+args[2]};
  expect(args.slice(0,2)).toEqual(['image','rm']);image=null;return {status:0,stdout:'Untagged\n',stderr:''};
 });
 const allocated=await allocateCiSmokeControlResources({env,expected},{docker});
 const download=await mkdtemp(join(allocated.tempRoot,'mem9-control-download-')),cacheDirectory=join(download,'blobs');await mkdir(cacheDirectory,{mode:0o700});
 for(const d of graph.inventory.nodes)await writeFile(join(cacheDirectory,d.digest.slice(7)),f.data.get(d.digest),{mode:0o600});
 const startedMs=Date.now();await registerControlCache(allocated.handle,{graph,cacheDirectory,startedMs,completedMs:Date.now()});
 const loaderDirectory=await mkdtemp(join(allocated.tempRoot,'mem9-control-docker-'));
 const loaderNames=streaming?['index.json','oci-layout']:['index.json','oci-layout','image.tar'];
 for(const name of loaderNames)await writeFile(join(loaderDirectory,name),name,{mode:0o600});
 const transport=streaming?{kind:'oci-tar-stdin',blobBytes:graph.inventory.nodes.reduce((n,d)=>n+d.size,0),archiveBytes:[...graph.inventory.nodes.map(d=>d.size),...loaderNames.map(n=>Buffer.byteLength(n))].reduce((n,size)=>n+512+Math.ceil(size/512)*512,1024)}:undefined;
 const bundle={controlCache:{directory:cacheDirectory,inventory:graph.inventory}},bundleRef={path:join(root,'bundle.json'),sha256:sha(JSON.stringify(bundle))};await writeFile(bundleRef.path,JSON.stringify(bundle),{mode:0o600});
 return {root,env,expected,allocated,graph,cacheDirectory,loaderDirectory,transport,bundle,bundleRef,docker,setImage(v){image=v;},async loaded(){await beginControlImageLoad(allocated.handle,{loaderDirectory,...(transport?{transport}:{})});image={Id:expected.rootDigest,Descriptor:{digest:expected.rootDigest},RepoTags:[allocated.tag],Os:'linux',Architecture:'arm64'};await recordControlImageLoad(allocated.handle,{outcome:'loaded',completedMs:Date.now()});},async seal(){const resourceReceiptRef=await sealControlResources(allocated.handle,{bundleRef});const completion={version:2,kind:'ci-future-acquisition-complete',claimRef,bundleRef,resourceReceiptRef,completedMs:Date.now(),ownerRefund:0},completionRef={path:claimRef.path.replace('-claim.json','-complete.json'),sha256:sha(JSON.stringify(completion))};await writeFile(completionRef.path,JSON.stringify(completion),{mode:0o600});await linkControlResourceCompletion({env,resourceReceiptRef,completionRef});return {resourceReceiptRef,completionRef};}};
}
it.each(['archiveBytes','blobBytes','kind'])('rejects changed stdin transport %s before invoking Docker',async field=>{
 const f=await fixture({streaming:true}),transport={...f.transport,[field]:field==='kind'?'file':f.transport[field]+1};
 await expect(beginControlImageLoad(f.allocated.handle,{loaderDirectory:f.loaderDirectory,transport})).rejects.toThrow('CiControlResourceTransport');expect(f.docker).not.toHaveBeenCalled();
});
it('does not downgrade a streaming receipt to the historical file layout',async()=>{
 const f=await fixture({streaming:true});await f.loaded();const {resourceReceiptRef}=await f.seal(),record=JSON.parse(await readFile(resourceReceiptRef.path,'utf8'));
 record.version=1;delete record.docker.transport;const raw=JSON.stringify(record);await writeFile(resourceReceiptRef.path,raw);
 await expect(verifyControlResources({env:f.env,resourceReceiptRef:{...resourceReceiptRef,sha256:sha(raw)}})).rejects.toThrow();
});
it('retains the cache/tag through sealing and validates only the exact run/source/bundle binding',async()=>{
 const f=await fixture();await f.loaded();const {resourceReceiptRef}=await f.seal();
 const record=await verifyControlResources({env:f.env,resourceReceiptRef,expected:{...f.expected,bundleRef:f.bundleRef,controlCache:f.bundle.controlCache}});
 expect(record.cache.directory).toBe(f.cacheDirectory);expect(record.docker.tag).toBe(f.allocated.tag);expect((await readdir(f.cacheDirectory)).length).toBe(f.graph.inventory.nodes.length);expect(f.docker.mock.calls.some(([a])=>a[1]==='rm')).toBe(false);
});
it('explicit final cleanup removes only the owned random tag and exact files, retaining audit records',async()=>{
 const f=await fixture();await f.loaded();await f.seal();await cleanupCiSmokeControlResources({env:f.env},{docker:f.docker});
 await expect(lstat(f.cacheDirectory)).rejects.toMatchObject({code:'ENOENT'});expect(f.docker.mock.calls.filter(([a])=>a[1]==='rm')).toEqual([[[ 'image','rm',f.allocated.tag],expect.anything()]]);
 expect(await readdir(f.allocated.root)).toContain('cleanup-complete.json');await cleanupCiSmokeControlResources({env:f.env},{docker:f.docker});expect(f.docker.mock.calls.filter(([a])=>a[1]==='rm')).toHaveLength(1);
});
it('unknown load outcome is sticky and never automatically removed',async()=>{
 const f=await fixture();await beginControlImageLoad(f.allocated.handle,{loaderDirectory:f.loaderDirectory});await recordControlImageLoad(f.allocated.handle,{outcome:'unknown',completedMs:Date.now()});
 await expect(recordControlImageLoad(f.allocated.handle,{outcome:'loaded',completedMs:Date.now()})).rejects.toThrow();await expect(cleanupCiSmokeControlResources({env:f.env},{docker:f.docker})).rejects.toThrow();expect(f.docker.mock.calls.some(([a])=>a[1]==='rm')).toBe(false);expect((await readdir(f.cacheDirectory)).length).toBeGreaterThan(0);
});
it.each(['extra','symlink','changed-file','foreign-tag','wrong-source'])('never deletes unknown or changed ownership: %s',async fault=>{
 const f=await fixture();await f.loaded();const {resourceReceiptRef}=await f.seal();
 if(fault==='extra')await writeFile(join(f.cacheDirectory,'unowned'),'keep',{mode:0o600});
 if(fault==='symlink'){await rm(join(f.loaderDirectory,'oci-layout'));await symlink('/etc/hosts',join(f.loaderDirectory,'oci-layout'));}
 if(fault==='changed-file')await writeFile(join(f.loaderDirectory,'image.tar'),'changed',{mode:0o600});
 if(fault==='foreign-tag')f.setImage({Id:'sha256:'+'0'.repeat(64),RepoTags:[f.allocated.tag],Os:'linux',Architecture:'arm64'});
 if(fault==='wrong-source')f.env.GITHUB_SHA='b'.repeat(40);
 if(fault==='wrong-source')await expect(verifyControlResources({env:f.env,resourceReceiptRef,expected:{...f.expected,bundleRef:f.bundleRef,controlCache:f.bundle.controlCache}})).rejects.toThrow();
 else await expect(cleanupCiSmokeControlResources({env:f.env},{docker:f.docker})).rejects.toThrow();
 expect(f.docker.mock.calls.some(([a])=>a[1]==='rm')).toBe(false);expect((await readdir(f.cacheDirectory)).length).toBeGreaterThan(0);
});
it('does not accept a serialized allocation handle',async()=>{const f=await fixture();await expect(beginControlImageLoad({...f.allocated.handle},{loaderDirectory:f.loaderDirectory})).rejects.toThrow();});
it('final cleanup covers every completed phase of this job after bundle replacement, but preserves another run',async()=>{
 const a=await fixture({checkpoint:'deploy-prod/17'});await a.loaded();await a.seal();
 const b=await fixture({existingRoot:a.root,checkpoint:'deploy-prod/19'});await b.loaded();await b.seal();
 const other=await fixture({existingRoot:a.root,runId:88});await other.loaded();await other.seal();
 // Ordinary bundle replacement can remove the prior bytes. Ownership stays
 // authenticated by the phase completion and immutable resource record.
 await rm(a.bundleRef.path);const byTag=new Map([a,b,other].map(f=>[f.allocated.tag,f]));
 const docker=(args,options)=>byTag.get(args[2]).docker(args,options);
 const result=await cleanupCiSmokeControlResources({env:a.env},{docker});expect(result.cleaned).toHaveLength(2);
 expect(other.docker.mock.calls.some(([args])=>args[1]==='rm')).toBe(false);expect((await readdir(other.cacheDirectory)).length).toBeGreaterThan(0);
});
it('expired admission never renews authority and does not block exact owned-resource cleanup',async()=>{
 const f=await fixture();await f.loaded();await f.seal();vi.spyOn(Date,'now').mockReturnValue(Date.now()+86400000);
 await cleanupCiSmokeControlResources({env:f.env},{docker:f.docker});expect(f.docker.mock.calls.some(([args])=>args[1]==='rm')).toBe(true);
});
it('an uncertain Docker deletion is not retried and leaves all files for reconciliation',async()=>{
 const f=await fixture();await f.loaded();await f.seal();const docker=vi.fn(async(args,opts)=>{if(args[1]==='rm')throw Error('synthetic lost terminal');return f.docker(args,opts);});
 await expect(cleanupCiSmokeControlResources({env:f.env},{docker})).rejects.toThrow();expect((await readdir(f.cacheDirectory)).length).toBeGreaterThan(0);
 await expect(cleanupCiSmokeControlResources({env:f.env},{docker})).rejects.toThrow();expect(docker.mock.calls.filter(([args])=>args[1]==='rm')).toHaveLength(1);
});
it.each(['malformed','foreign-ref','missing-intent'])('does not report completed cleanup from an invalid terminal record: %s',async fault=>{
 const f=await fixture();await f.loaded();await f.seal();await cleanupCiSmokeControlResources({env:f.env},{docker:f.docker});
 const path=join(f.allocated.root,'cleanup-complete.json'),record=JSON.parse(await readFile(path,'utf8'));
 if(fault==='malformed')await writeFile(path,'{}');
 if(fault==='foreign-ref'){record.resourceReceiptRef.sha256='0'.repeat(64);await writeFile(path,JSON.stringify(record));}
 if(fault==='missing-intent')await rm(join(f.allocated.root,'cleanup-intent.json'));
 f.docker.mockClear();await expect(cleanupCiSmokeControlResources({env:f.env},{docker:f.docker})).rejects.toThrow('CiControlResourceCleanupHeld');expect(f.docker).not.toHaveBeenCalled();
});
it('authenticates already completed cleanup after ordinary source and bundle disposal without recreating resources',async()=>{
 const f=await fixture();await f.loaded();await f.seal();await cleanupCiSmokeControlResources({env:f.env},{docker:f.docker});
 await rm(f.expected.sourceReceiptRef.path);await rm(f.bundleRef.path);f.docker.mockClear();
 expect(await cleanupCiSmokeControlResources({env:f.env},{docker:f.docker})).toEqual({phase:'ci-control-resources-cleaned',cleaned:[]});expect(f.docker).not.toHaveBeenCalled();
});
