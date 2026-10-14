import {it,expect} from 'vitest';
import {readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {carrierWorkerFixture} from './ci-carrier-worker.fixture.mjs';
import {openCarrierStartup} from './lib/ci-carrier-startup.mjs';
import {openCarrierConsumer} from './lib/ci-carrier-consumer.mjs';
import {createCarrierTransport} from './lib/ci-carrier-transport.mjs';
import {collectCarrierBase} from './lib/ci-carrier-worker.mjs';
import {materializeCarrierBuildContext} from './lib/ci-carrier-context.mjs';
import {IMAGE_MEDIA,imageDescriptorDataLocalBytes,decodeImageDescriptorData} from './lib/production-image-graph.mjs';
import {carrierObjectKeys} from './lib/ci-carrier-before-copy.mjs';

async function collect(f,use){
 const startup=await openCarrierStartup({config:f.config,env:f.env,host:f.seams.host},f.seams.startup),consumer=openCarrierConsumer({startup,config:f.config,env:f.env});
 const transport=createCarrierTransport({consumer,env:f.env},f.seams.transport);let base;
 try{
  await transport.assume();await transport.identity();consumer.confirmGrant(await transport.getGrant());
  await transport.getContext(stream=>materializeCarrierBuildContext({stream,plan:f.config.plan,tempRoot:f.tempRoot,metadataReads:consumer}));
  base=await collectCarrierBase({consumer,transport,tempRoot:f.tempRoot});await use({base,consumer,transport});
 }finally{await base?.close();await transport.close();await consumer.close();}
}
it('real startup/SDK consumer reaches complete base graph with inline config and no registry copy',()=>carrierWorkerFixture(f=>collect(f,async({base,consumer})=>{
 const d=base.graph.inventory.nodes.find(d=>d.mediaType===IMAGE_MEDIA.emptyConfig);expect(d).toBeDefined();expect(base.graph.inventory.attestations).toHaveLength(1);
 expect(await readFile(join(base.cacheDirectory,d.digest.slice(7)),'utf8')).toBe('{}');
 expect(f.calls.filter(c=>c.action==='GetDownloadUrlForLayer').every(c=>JSON.parse(c.request.body).layerDigest!==d.digest)).toBe(true);
 expect(f.calls.filter(c=>c.action==='S3BlobGet')).toHaveLength(3);
 expect(consumer.inspect().blobUsage.requests).toBe(3);
 const t=f.config.plan.template;
 await expect(consumer.beforeRequest('baseUrl','GetDownloadUrlForLayer',{registryId:t.scope.account,repositoryName:t.base.repositoryName,layerDigest:d.digest})).rejects.toThrow('CarrierConsumerBaseBlob');
 // Admission of the next fixed request proves inline coverage reached the
 // consumer's own state; no caller-completed blob receipt is introduced.
 const reservation=await consumer.beforeRequest('fixtureGet','GetObject',{Bucket:t.scope.bucket,Key:carrierObjectKeys(t).fixture,ExpectedBucketOwner:t.scope.account});await reservation.unknown();
}),{inlineConfig:'valid'}));
it.each(['e30','e30=\n','e31=','W10='])('actual consumer rejects inline %s before any attempt to fetch its digest',inlineConfig=>carrierWorkerFixture(async f=>{
 await expect(collect(f,()=>{throw Error('UnexpectedBaseSuccess');})).rejects.toThrow('CarrierTransportHeld');
 expect(f.calls.filter(c=>c.action==='GetDownloadUrlForLayer')).toHaveLength(2);
},{inlineConfig}));
it('descriptor decoder returns authenticated bytes and exact bounded LOCAL decode/hash charge',()=>{
 const d={mediaType:IMAGE_MEDIA.emptyConfig,digest:'sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a',size:2,data:'e30='};
 expect(imageDescriptorDataLocalBytes(d)).toBe(8);expect(decodeImageDescriptorData(d,'blob').toString()).toBe('{}');
 expect(imageDescriptorDataLocalBytes({...d,data:'e30=\n'})).toBe(11);expect(()=>decodeImageDescriptorData({...d,data:'e30=\n'},'blob')).toThrow('ImageEmbeddedDataInvalid');
 expect(()=>imageDescriptorDataLocalBytes({...d,data:'A'.repeat(11184816)})).toThrow('ImageEmbeddedDataLimit');
 const {data,...ordinary}=d;expect(imageDescriptorDataLocalBytes(ordinary)).toBe(0);expect(decodeImageDescriptorData(ordinary,'blob')).toBeUndefined();
});
it('actual SDK/consumer completes a full base graph from multiple exact-digest aliases including inline config',()=>carrierWorkerFixture(f=>collect(f,async({base,consumer})=>{
 expect(base.graph.inventory.attestations).toHaveLength(1);expect(consumer.inspect().used.baseManifest).toBe(3);
 expect(f.calls.filter(c=>c.action==='BatchGetImage')).toHaveLength(3);
}),{inlineConfig:'valid',manifestAliases:true}));
it.each(['top','image','id','bytes','scope','media'])('actual SDK/consumer holds alias %s without another attempt',aliasDefect=>carrierWorkerFixture(async f=>{
 await expect(collect(f,()=>{throw Error('unexpected success');})).rejects.toThrow('CarrierTransportHeld');
 expect(f.calls.filter(c=>c.action==='BatchGetImage')).toHaveLength(1);
},{manifestAliases:true,aliasDefect}));
