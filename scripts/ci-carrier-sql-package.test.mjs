import {it,expect} from 'vitest';
import {carrierFixture} from './ci-carrier.fixture.mjs';
import {carrierObjectKeys,carrierSqlFixtureBudget,carrierSqlFixtureComponentBudget,carrierSqlPackageReadBounds,inspectCarrierBeforeCopyTemplate,measureCarrierBeforeCopyBudget} from './lib/ci-carrier-before-copy.mjs';
import {carrierSessionPolicy} from './lib/ci-carrier-transport.mjs';
import {verifyCarrierSqlPackage,consumeCarrierSqlPackage} from './lib/ci-carrier-sql-package.mjs';
import {assertCarrierSqlDatabasePin,CARRIER_SQL_DERIVED_FIXTURE,CARRIER_SQL_NOJIT_FIXTURE} from './lib/ci-carrier-sql-acceptance-format.mjs';

// Component planning needs only the fixed package descriptor, no pretend
// carrier template, funding plan, source CI, or ledger.
const nojitFixture=()=>({version:1,kind:'carrier-sql-fixture',...structuredClone(Object.fromEntries(['archive','rootDigest','arm64Digest','configDigest','attestationDigest','uncompressedBytes','processedEntries'].map(k=>[k,CARRIER_SQL_NOJIT_FIXTURE[k]]))),oldSource:{revision:'d'.repeat(40),tree:'e'.repeat(40)}});
it('computes the complete pinned fixture component without a carrier template or another unknown lane',()=>{
 const f=nojitFixture(),before=structuredClone(f),b=carrierSqlFixtureComponentBudget(f,{putResponseBytes:16384});
 expect(f).toEqual(before);expect(b.transfers.total.logicalBytes).toBe(134795264);expect(b.transfers.total.httpBodyBytes).toBe(134795264);
 expect(b.packageAndImportLocal.owner.logicalBytes).toBe(67440640);expect(b.packageAndImportLocal.ci.logicalBytes).toBe(497894000);
 expect(b.transfers.total.logicalBytes+b.packageAndImportLocal.owner.logicalBytes+b.packageAndImportLocal.ci.logicalBytes).toBe(700129904);
 expect(b.packageAndImportLocal.ci.uncompressedBytes).toBe(426254336);expect(b.packageAndImportLocal.ci.processedEntries).toBe(100000);
 expect(b.ioBounds.ciVerificationFileReadBytes).toBe(67377776);expect(b.additionalUnknownBytes).toBe(0);expect(b.sharedUnknownBytesPerActor).toBe(8388608);
 expect(()=>{b.profiles.fixturePut.requestBytes=0;}).toThrow(TypeError);expect(carrierSqlFixtureComponentBudget(f,{putResponseBytes:16384}).profiles.fixturePut.requestBytes).toBe(67389440);
});
it('delegates from the fully checked template without adding transfers or local charges twice',()=>{
 const {template:t}=carrierFixture();t.sqlFixture=nojitFixture();t.profiles.fixturePut={count:1,requestBytes:t.sqlFixture.archive.bytesLength,responseBytes:32768};t.profiles.fixtureGet={count:1,requestBytes:0,responseBytes:t.sqlFixture.archive.bytesLength};
 const b=carrierSqlFixtureComponentBudget(t.sqlFixture,{putResponseBytes:32768});expect(carrierSqlFixtureBudget(t)).toEqual(b);
 expect(b.transfers.total.httpBodyBytes).toBe(134795264+16384);expect(b.packageAndImportLocal.owner.logicalBytes).toBe(67440640);
 t.source.jobKey='another-job';expect(()=>carrierSqlFixtureBudget(t)).toThrow('CarrierFixedJob');
});
it.each(['archive-hash','archive-size','rootDigest','arm64Digest','configDigest','attestationDigest','uncompressedBytes','processedEntries'])('rejects unauthenticated or understated component bounds: %s',field=>{
 const f=nojitFixture();if(field==='archive-hash')f.archive.sha256='a'.repeat(64);else if(field==='archive-size')f.archive.bytesLength--;else if(field.endsWith('Digest'))f[field]='sha256:'+'a'.repeat(64);else f[field]--;
 expect(()=>carrierSqlFixtureComponentBudget(f,{putResponseBytes:16384})).toThrow(/CarrierPg(?:FixedImage|DerivedPin|FixturePin)/);
});
it.each([undefined,{},null,{putResponseBytes:0},{putResponseBytes:16383},{putResponseBytes:16384.5},{putResponseBytes:Number.MAX_SAFE_INTEGER},{putResponseBytes:16384,count:2}])('rejects missing, invalid or open-ended PUT response caps: %j',options=>{
 expect(()=>carrierSqlFixtureComponentBudget(nojitFixture(),options)).toThrow(/CarrierFields|CarrierSqlPutResponseBytes/);
});
it('rejects extra descriptor authority/provenance fields and malformed original source binding',()=>{
 const f=nojitFixture();expect(()=>carrierSqlFixtureComponentBudget({...f,provenanceHash:'a'.repeat(64)},{putResponseBytes:16384})).toThrow('CarrierFields');
 f.oldSource.tree='unknown';expect(()=>carrierSqlFixtureComponentBudget(f,{putResponseBytes:16384})).toThrow('CarrierSqlFixtureContract');
});
it('checks original-package sizes too instead of trusting only its known root digest',()=>{
 const {template:t}=carrierFixture();expect(carrierSqlFixtureComponentBudget(t.sqlFixture,{putResponseBytes:16384})).toEqual(carrierSqlFixtureBudget(t));
 t.sqlFixture.archive.bytesLength--;expect(()=>carrierSqlFixtureComponentBudget(t.sqlFixture,{putResponseBytes:16384})).toThrow('CarrierPgFixturePin');
});

it('prepays exactly one independent owner PUT and CI GET without another unknown lane',()=>{
 const {template:t}=carrierFixture(),b=carrierSqlFixtureBudget(t),F=t.sqlFixture.archive.bytesLength;
 expect(b.transfers.total.httpBodyBytes).toBe(2*F+16384);expect(b.additionalUnknownBytes).toBe(0);expect(b.sharedUnknownBytesPerActor).toBe(8388608);
 expect(b.ioBounds.ownerFileReadBytes).toBe(F);expect(b.packageAndImportLocal.owner.logicalBytes).toBe(F+51200);const reads=carrierSqlPackageReadBounds(t.sqlFixture);
 expect(b.ioBounds.ciVerificationFileReadBytes).toBe(reads.compressedLayerBytes+reads.metadataReadBytes);expect(b.packageAndImportLocal.ci.logicalBytes).toBe(3*F+reads.compressedLayerBytes+reads.metadataReadBytes+t.sqlFixture.uncompressedBytes+7*(2097152+32768+32768+16384));
 const before=measureCarrierBeforeCopyBudget(t);t.sqlFixture.archive.bytesLength++;t.profiles.fixturePut.requestBytes++;t.profiles.fixtureGet.responseBytes++;
 expect(measureCarrierBeforeCopyBudget(t).fundedRemaining.total.httpBodyBytes-before.fundedRemaining.total.httpBodyBytes).toBe(2);
});
it.each(['fixturePut','fixtureGet'])('rejects extra attempts or a mismatching descriptor cap for %s',key=>{
 const {template:t}=carrierFixture();t.profiles[key].count=2;expect(()=>inspectCarrierBeforeCopyTemplate(t)).toThrow('CarrierSingleAttempt');t.profiles[key].count=1;
 t.profiles[key][key==='fixturePut'?'requestBytes':'responseBytes']++;expect(()=>inspectCarrierBeforeCopyTemplate(t)).toThrow('CarrierSqlFixtureBudget');
});
it('puts only the derived fixture key into the CI temporary session read scope',()=>{
 const {template:t,plan}=carrierFixture(),key=carrierObjectKeys(t).fixture,policy=JSON.parse(carrierSessionPolicy(plan));
 expect(key).toBe(t.scope.prefix+'/'+t.executionId+'/'+t.slotNonce+'/fixture.oci.tar');
 const get=policy.Statement.find(s=>s.Effect==='Allow'&&s.Action==='s3:GetObject');expect(get.Resource).toContain('arn:aws:s3:::'+t.scope.bucket+'/'+key);
 const put=policy.Statement.find(s=>s.Effect==='Allow'&&s.Action==='s3:PutObject');expect(put.Resource).not.toContain('fixture.oci.tar');expect(JSON.stringify(policy).length).toBeLessThanOrEqual(2048);
});
it('does not recover a verified package or Docker import from serialized evidence',async()=>{
 const fake={kind:'carrier-sql-package'};await expect(verifyCarrierSqlPackage(fake,{consumer:{}})).rejects.toThrow('CarrierPgHandle');await expect(consumeCarrierSqlPackage(fake,{consumer:{}})).rejects.toThrow('CarrierPgHandle');
});
it('binds the one derived recipe and archive without accepting arbitrary roots or mistaking observed entries for the ceiling',()=>{
 const f=structuredClone(CARRIER_SQL_DERIVED_FIXTURE);assertCarrierSqlDatabasePin(f);
 expect(()=>assertCarrierSqlDatabasePin({...f,rootDigest:'sha256:'+'a'.repeat(64)})).toThrow('CarrierPgFixedImage');
 expect(()=>assertCarrierSqlDatabasePin({...f,archive:{...f.archive,sha256:'a'.repeat(64)}})).toThrow('CarrierPgDerivedPin');
 expect(()=>assertCarrierSqlDatabasePin({...f,processedEntries:f.observedEntries})).toThrow('CarrierPgDerivedPin');
 expect(()=>assertCarrierSqlDatabasePin({...f,configDigest:'sha256:'+'b'.repeat(64)})).toThrow('CarrierPgDerivedPin');
});
