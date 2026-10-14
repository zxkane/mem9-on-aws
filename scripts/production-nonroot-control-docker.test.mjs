import {describe,it,expect} from 'vitest';
import {mkdtemp,mkdir,open,rm,readdir,writeFile,lstat,readFile,copyFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {dockerArtifactFixture} from './production-nonroot-observation.fixture.mjs';
import {imageGraphState} from './lib/production-image-graph.mjs';
import {loadNonrootControlImage} from './lib/production-nonroot-control-docker.mjs';
import {controlResourceFixture} from './ci-smoke-control-resources.fixture.mjs';
import {registerControlCache,verifyControlResources,cleanupCiSmokeControlResources} from './lib/ci-smoke-control-resources.mjs';

describe.skipIf(process.env.MEM9_NONROOT_CONTAINER_TEST!=='1')('offline CONTROL Docker materialization',()=>{
 async function fixture(use){
  const docker=dockerArtifactFixture(),directory=await mkdtemp(join(tmpdir(),'control-load-test-')),cache=join(directory,'cache');await mkdir(cache,{mode:0o700});
  try{
   const result=await docker.factory()({scope:{account:'123456789012',region:'ap-northeast-1',repositoryName:'mem9-on-aws/bootstrap'},bodies:new Map([['/bootstrap/nonroot-dispatch.mjs','export const synthetic=true;']]),archiveBytes:()=>({})});
   const state=imageGraphState(result.graph);
   for(const d of result.graph.inventory.nodes){const file=await open(join(cache,d.digest.slice(7)),'wx',0o600);try{for await(const bytes of state.store.open(d))await file.writeFile(bytes);}finally{await file.close();}}
   const charges=[],metadataReads={reserveLocal(value){expect(value.ecrRequests).toBe(0);expect(value.httpBodyBytes).toBe(0);charges.push(value);}};
   await use({graph:result.graph,cacheDirectory:cache,metadataReads,tempRoot:directory,docker,charges});
  }finally{await docker.close();await rm(directory,{recursive:true,force:true});}
 }
 it('loads verified OCI bytes without registry credentials and removes only its own random tag',()=>fixture(async input=>{
  const before=JSON.parse(input.docker.run(['image','inspect',input.graph.inventory.roots[0].root.digest]));
  const loaded=await loadNonrootControlImage(input);
  const tag=loaded.tag;
  try{
   expect(loaded.rootDigest).toBe(input.graph.inventory.roots[0].root.digest);expect(JSON.parse(input.docker.run(['image','inspect',tag]))[0].Descriptor.digest).toBe(loaded.rootDigest);
   expect((await readdir(loaded.loaderDirectory)).sort()).toEqual(['index.json','oci-layout']);
   const graphBytes=input.graph.inventory.nodes.reduce((n,d)=>n+d.size,0),metadataBytes=(await lstat(join(loaded.loaderDirectory,'index.json'))).size+(await lstat(join(loaded.loaderDirectory,'oci-layout'))).size;
   expect(loaded.io).toEqual({cacheVerificationBytes:graphBytes,cacheStreamingBytes:graphBytes,metadataWriteBytes:metadataBytes,tarFramingBytes:loaded.archiveBytes-graphBytes,logicalBytes:graphBytes+loaded.archiveBytes+metadataBytes});
   expect(input.charges.reduce((n,c)=>n+c.logicalBytes,0)).toBe(loaded.io.logicalBytes);expect(loaded.io.logicalBytes).toBeLessThan(2*graphBytes+loaded.archiveBytes);
   process.stdout.write(JSON.stringify({kind:'synthetic-control-tar-io',graphBytes,streamBytes:loaded.archiveBytes,metadataWriteBytes:metadataBytes,newLogicalBytes:loaded.io.logicalBytes,oldLogicalLowerBound:2*graphBytes+loaded.archiveBytes,minimumLogicalSaved:graphBytes-metadataBytes})+'\n');
  }
  finally{await loaded.close();}
  const after=JSON.parse(input.docker.run(['image','inspect',input.graph.inventory.roots[0].root.digest]));
  expect(after[0].RepoTags).toEqual(before[0].RepoTags);expect(await readdir(input.tempRoot)).toEqual(['cache']);
 }),120000);
 it('rejects changed cache bytes before invoking Docker load',()=>fixture(async input=>{
  const node=input.graph.inventory.nodes[0];await writeFile(join(input.cacheDirectory,node.digest.slice(7)),Buffer.alloc(node.size,1));
  await expect(loadNonrootControlImage(input)).rejects.toThrow('NonrootControlDockerCache');expect(await readdir(input.tempRoot)).toEqual(['cache']);
 }),120000);
 it('rechecks all cache identities after the final asynchronous hook and before Docker starts',()=>fixture(async input=>{
  let loadHook=0;
  await expect(loadNonrootControlImage(input,{beforeCommand:async command=>{
   if(command.args.includes('load')){loadHook++;const node=input.graph.inventory.nodes[0];await writeFile(join(input.cacheDirectory,node.digest.slice(7)),Buffer.alloc(node.size,1));}
  }})).rejects.toThrow('NonrootControlDockerCache');
  expect(loadHook).toBe(1);expect(await readdir(input.tempRoot)).toEqual(['cache']);
 }),120000);
 it('rejects insufficient stream prepayment before invoking Docker load',()=>fixture(async input=>{
  const reserve=input.metadataReads.reserveLocal;let loadHook=0;
  const graphBytes=input.graph.inventory.nodes.reduce((n,d)=>n+d.size,0);
  input.metadataReads.reserveLocal=charge=>{if(charge.logicalBytes>graphBytes)throw Error('SyntheticStreamBudget');return reserve(charge);};
  await expect(loadNonrootControlImage(input,{beforeCommand:command=>{if(command.args.includes('load'))loadHook++;}})).rejects.toThrow('SyntheticStreamBudget');
  expect(loadHook).toBe(0);expect(await readdir(input.tempRoot)).toEqual(['cache']);
 }),120000);
 it('retains the operation when Node reports CLI output overflow and the daemon outcome arrives later',()=>fixture(async input=>{
  const commands=[];let loaded,error,late;
  try{
   try{loaded=await loadNonrootControlImage(input,{beforeCommand:async command=>{
    commands.push(command);
    if(command.program==='/usr/bin/docker'&&command.args.includes('load')){
     try{await promisify(execFile)(process.execPath,['-e','process.stdout.write("x".repeat(2097152))'],{maxBuffer:1024,env:{PATH:'/usr/bin:/bin'}});}
     catch(e){expect(e.code).toBe('ERR_CHILD_PROCESS_STDIO_MAXBUFFER');expect(e.killed).toBeUndefined();expect(e.signal).toBeUndefined();
      late=new Promise((resolve,reject)=>setTimeout(()=>writeFile(join(input.tempRoot,'late-daemon-outcome'),'synthetic completed import',{mode:0o600}).then(resolve,reject),50));throw e;
     }
    }
   }});}catch(e){error=e;}
   expect(error).toMatchObject({code:'ECLEANUP'});await late;
   expect((await lstat(error.operationDirectory)).isDirectory()).toBe(true);
   expect(commands.at(-1).args).toContain('load');expect(commands.some(c=>c.cleanupOnly)).toBe(false);
  }finally{await loaded?.close();if(error?.operationDirectory)await rm(error.operationDirectory,{recursive:true,force:true});}
 }),120000);
 it('never interprets a hook exception as successful Docker output',()=>fixture(async input=>{
  let reachedLoad=false,loaded,error;
  try{
   try{loaded=await loadNonrootControlImage(input,{beforeCommand:command=>{
    if(command.cleanupOnly)return;
    if(command.args.includes('load')){reachedLoad=true;throw {code:0,stdout:'synthetic fake load'};}
    if(reachedLoad&&command.args.includes('inspect')){
     const tag=command.args.at(-1),root=input.graph.inventory.roots[0].root.digest;
     throw {code:0,stdout:JSON.stringify([{Id:root,Descriptor:{digest:root},Os:'linux',Architecture:'arm64',RepoTags:[tag]}])};
    }
   }});}catch(e){error=e;}
   expect(reachedLoad).toBe(true);expect(loaded).toBeUndefined();expect(error).toMatchObject({message:'NonrootControlDockerHook'});
  }finally{try{await loaded?.close();}catch{/* Synthetic spoofing must not prevent fixture cleanup. */}}
 }),120000);
 it('uses the allocated tag, retains it across close, and removes it through exact final resource cleanup',()=>fixture(async input=>{
  const state=imageGraphState(input.graph),binding=state.controlBinding??{rootDigest:input.graph.inventory.roots[0].root.digest,configDigest:state.images.get('bootstrap').config.digest};
  const resource=await controlResourceFixture(input.tempRoot,binding);
  const download=await mkdtemp(join(resource.allocation.tempRoot,'mem9-control-download-')),cacheDirectory=join(download,'blobs');await mkdir(cacheDirectory,{mode:0o700});
  for(const node of input.graph.inventory.nodes){const {copyFile}=await import('node:fs/promises');await copyFile(join(input.cacheDirectory,node.digest.slice(7)),join(cacheDirectory,node.digest.slice(7)));}
  const now=Date.now();await registerControlCache(resource.allocation.handle,{graph:input.graph,cacheDirectory,startedMs:now,completedMs:now});
  const loaded=await loadNonrootControlImage({...input,cacheDirectory,tempRoot:resource.allocation.tempRoot,resourceHandle:resource.allocation.handle});
  await loaded.close();expect(loaded.tag).toBe(resource.allocation.tag);expect(JSON.parse(input.docker.run(['image','inspect',loaded.tag]))[0].RepoTags).toContain(loaded.tag);
  const controlCache={directory:cacheDirectory,inventory:input.graph.inventory},refs=await resource.complete(controlCache);
  try{
   const checked=await verifyControlResources({env:resource.env,...refs,expected:{...resource.expected,bundleRef:refs.bundleRef,controlCache}});expect(checked.docker.tag).toBe(loaded.tag);
   expect(checked.version).toBe(2);expect(checked.docker.transport).toEqual({kind:'oci-tar-stdin',archiveBytes:loaded.archiveBytes,blobBytes:input.graph.inventory.nodes.reduce((n,d)=>n+d.size,0)});
  }finally{await cleanupCiSmokeControlResources({env:resource.env});}
  await expect(lstat(cacheDirectory)).rejects.toMatchObject({code:'ENOENT'});expect(await readdir(resource.allocation.root)).toContain('cleanup-complete.json');
 }),120000);
 it('a partial stdin abort stops the original child, charges the full stream and retains the unknown owned load',()=>fixture(async input=>{
  const state=imageGraphState(input.graph),resource=await controlResourceFixture(input.tempRoot,{rootDigest:input.graph.inventory.roots[0].root.digest,configDigest:state.images.get('bootstrap').config.digest});
  const download=await mkdtemp(join(resource.allocation.tempRoot,'mem9-control-download-')),cacheDirectory=join(download,'blobs');await mkdir(cacheDirectory,{mode:0o700});
  for(const node of input.graph.inventory.nodes)await copyFile(join(input.cacheDirectory,node.digest.slice(7)),join(cacheDirectory,node.digest.slice(7)));
  const now=Date.now();await registerControlCache(resource.allocation.handle,{graph:input.graph,cacheDirectory,startedMs:now,completedMs:now});
  const controller=new AbortController(),reserve=input.metadataReads.reserveLocal;let streaming=false,checks=0,error,loads=0;
  input.metadataReads.reserveLocal=charge=>{reserve(charge);if(streaming&&++checks===12)controller.abort();};
  try{await loadNonrootControlImage({...input,cacheDirectory,tempRoot:resource.allocation.tempRoot,resourceHandle:resource.allocation.handle,signal:controller.signal},{beforeCommand:command=>{if(command.args.includes('load')){streaming=true;loads++;}}});}catch(e){error=e;}
  expect(error).toMatchObject({code:'ECLEANUP',processStopped:true,termination:{kind:'docker-stdin-subreaper-echild',cleanupComplete:true}});expect(error.producedBytes).toBeGreaterThan(0);expect(error.cacheReadBytes).toBeGreaterThan(0);expect(loads).toBe(1);
  const intent=JSON.parse(await readFile(join(resource.allocation.root,'load-intent.json'),'utf8')),outcome=JSON.parse(await readFile(join(resource.allocation.root,'load-outcome.json'),'utf8'));
  expect(intent.version).toBe(2);expect(outcome.outcome).toBe('unknown');expect(input.charges.some(c=>c.logicalBytes===intent.transport.archiveBytes)).toBe(true);
  expect((await readdir(error.operationDirectory)).sort()).toEqual(['index.json','oci-layout']);expect((await readdir(cacheDirectory)).length).toBe(input.graph.inventory.nodes.length);
  await expect(cleanupCiSmokeControlResources({env:resource.env})).rejects.toThrow('CiControlResourceCleanupHeld');
 }),120000);
});
