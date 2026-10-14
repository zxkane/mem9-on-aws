import {it,expect} from 'vitest';
import {createHash} from 'node:crypto';
import {normalizeImageDigestResponse as normalize,normalizeImageDigestResponseAsync as normalizeAsync,imageResponseFromSdk,imageResponseFromLegacyEvidence} from './lib/production-image-response.mjs';
import {digestAliases} from './production-image-response.fixture.mjs';
const media='application/vnd.oci.image.index.v1+json',raw=JSON.stringify({schemaVersion:2,mediaType:media,manifests:[]}),imageDigest='sha256:'+createHash('sha256').update(raw).digest('hex');
const expected={registryId:'123456789012',repositoryName:'mem9-on-aws/bootstrap',imageDigest};
const response=()=>({images:[{registryId:expected.registryId,repositoryName:expected.repositoryName,imageId:{imageDigest},imageManifest:raw,imageManifestMediaType:media}],failures:[]});
it('validates every alias, meters every original buffer/hash and does not mutate the captured response',()=>{
 const r=digestAliases(response()),before=structuredClone(r),debits=[],v=normalize(r,expected,n=>debits.push(n));
 expect(debits).toEqual([2*Buffer.byteLength(raw),2*Buffer.byteLength(raw)]);expect(v.raw.toString()).toBe(raw);expect(v.image.imageId).toEqual({imageDigest});expect(r).toEqual(before);
});
it.each(['top','image','id','bytes','scope','media'])('rejects %s in any alias without silently filtering it',defect=>expect(()=>normalize(digestAliases(response(),defect),expected)).toThrow());
it.each(['empty','failures','missing-failures','extra-expected','size','missing-media','too-many','body-limit'])('rejects %s',fault=>{
 const r=digestAliases(response()),e={...expected};let cap;
 if(fault==='empty')r.images=[];if(fault==='failures')r.failures=[{failureCode:'ImageNotFound'}];if(fault==='missing-failures')delete r.failures;
 if(fault==='extra-expected')e.imageTag='not-a-selector';if(fault==='size')r.images[1].imageManifestSize=1;if(fault==='missing-media')delete r.images[1].imageManifestMediaType;if(fault==='too-many'){r.images=Array(101).fill(r.images[0]);cap=100*Buffer.byteLength(raw);}if(fault==='body-limit')cap=1;
 expect(()=>normalize(r,e,()=>{},cap)).toThrow();
});
it('bounds aliases by actual bytes and rejects a uniformly false wire media type',()=>{
 const r=response();r.images=Array(101).fill(r.images[0]);expect(normalize(r,expected).raw.toString()).toBe(raw);
 const bad=digestAliases(response());for(const image of bad.images)image.imageManifestMediaType='application/vnd.oci.image.manifest.v1+json';expect(()=>normalize(bad,expected)).toThrow();
 const missing=digestAliases(response());for(const image of missing.images)delete image.imageManifestMediaType;expect(normalize(missing,expected).image.imageManifestMediaType).toBe(media);
});
it('awaits the original durable LOCAL debit before each hash; rejection produces no successful result',async()=>{
 const order=[];await normalizeAsync(digestAliases(response()),expected,async n=>{await Promise.resolve();order.push(n);});expect(order).toHaveLength(2);
 await expect(normalizeAsync(response(),expected,async()=>{throw Error('funds-exhausted');})).rejects.toThrow('funds-exhausted');
});
it('accepts SDK metadata only through its explicit closed adapter and preserves application extras for rejection',()=>{
 const r={...response(),$metadata:{httpStatusCode:200,requestId:'synthetic',attempts:1,totalRetryDelay:0}};
 expect(()=>normalize(r,expected)).toThrow();expect(normalize(imageResponseFromSdk(r),expected).raw.toString()).toBe(raw);expect(r.$metadata).toBeDefined();
 for(const change of [{$metadata:{httpStatusCode:403}},{$metadata:{httpStatusCode:200,unreviewed:true}},{unreviewed:true}])expect(()=>imageResponseFromSdk({...r,...change})).toThrow();
});
it('preserves old singleton evidence without allowing missing fields to reconcile aliases',()=>{
 const r=response();delete r.images[0].imageManifestMediaType;delete r.failures;
 expect(normalize(imageResponseFromLegacyEvidence(r),expected).raw.toString()).toBe(raw);expect(r.failures).toBeUndefined();
 expect(()=>imageResponseFromLegacyEvidence({...r,unreviewed:true})).toThrow();expect(()=>normalize(imageResponseFromLegacyEvidence(digestAliases(r)),expected)).toThrow();
});
it('recognizes only the fixed reader raw-hash metadata pair without inventing an HTTP status',()=>{
 const r={...response(),$metadata:{rawRequestHash:'a'.repeat(64),rawResponseHash:'b'.repeat(64)}};
 expect(normalize(imageResponseFromSdk(r),expected).raw.toString()).toBe(raw);expect(r.$metadata.httpStatusCode).toBeUndefined();
 for(const m of [{rawResponseHash:'b'.repeat(64)},{...r.$metadata,httpStatusCode:403},{...r.$metadata,unknown:true},{...r.$metadata,rawRequestHash:'invalid'}])expect(()=>imageResponseFromSdk({...r,$metadata:m})).toThrow();
});
