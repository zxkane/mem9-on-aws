import {it,expect} from 'vitest';
import {carrierFixture} from './ci-carrier.fixture.mjs';
import {carrierNativeBuildAdmissionBytes,carrierPublicationAdmissionBytes,carrierSqlStageAdmissionBytes} from './lib/ci-carrier-stage-admission.mjs';
import {carrierSqlRuntimeBudget} from './lib/ci-carrier-sql-runtime-budget.mjs';
import {describeCarrierLocalPolicy,inspectCarrierLocalPolicy} from './lib/ci-carrier-local-policy.mjs';
import {inspectCarrierBeforeCopyTemplate,measureCarrierBeforeCopyBudget} from './lib/ci-carrier-before-copy.mjs';
it('preserves the complete native build precharge and immediate rechecks',()=>{
 expect(carrierNativeBuildAdmissionBytes({nativeBound:2149580800,contextBytes:111,derivedBytes:222})).toBe(2149581133);
 expect(()=>carrierNativeBuildAdmissionBytes({nativeBound:Number.MAX_SAFE_INTEGER,contextBytes:1,derivedBytes:1})).toThrow();
});
it('prices all missing output blobs and every manifest, not only one upload',()=>{
 const t=carrierFixture().template;for(const p of Object.values(t.profiles))if(p.count)p.count=100;
 const rows=[{mediaType:'application/vnd.oci.image.layer.v1.tar',size:5242881},{mediaType:'application/vnd.oci.image.manifest.v1+json',size:300}];
 const value=carrierPublicationAdmissionBytes(t,rows);expect(value).toBeGreaterThan(carrierPublicationAdmissionBytes(t,[{...rows[0],size:5242880},rows[1]]));
 t.profiles.part.count=1;expect(()=>carrierPublicationAdmissionBytes(t,rows)).toThrow(/CarrierStagePublicationProfile/);
});
it('SQL admission includes every case plus package, source capture, publication and cleanup',()=>{
 const runtime=carrierSqlRuntimeBudget({runtimeFilesBytes:2000,originalSourceBytes:1000,nodeBytes:12345,setprivBytes:2345,carrierGraphBytes:45678,carrierGraphNodes:5,carrierUncompressedBytes:345678,carrierEntries:20});
 const quote=carrierSqlStageAdmissionBytes({runtime,packageLocal:{logicalBytes:777},publicationBytes:888,sourceReads:3,fixtureCaptureBytes:999});
 expect(quote).toBeGreaterThan(runtime.total.logicalBytes+777+888);expect(runtime.parts.caseSecurityReads.logicalBytes).toBe(8*(2*(2000+12345+2345)+1000));
 expect(()=>carrierSqlStageAdmissionBytes({runtime:{...runtime,caseSecurityReadPasses:14},packageLocal:{logicalBytes:777},publicationBytes:888})).toThrow(/CarrierStageSqlCases/);
});
it('legacy reconstruction adds no policy and retains its original measured payment',()=>{
 const t=carrierFixture().template,raw=JSON.stringify(t),before=measureCarrierBeforeCopyBudget(t);expect(inspectCarrierBeforeCopyTemplate(t)).toEqual(t);expect(JSON.stringify(t)).toBe(raw);expect(t.ciLocalPolicy).toBeUndefined();expect(measureCarrierBeforeCopyBudget(JSON.parse(raw))).toEqual(before);
});
it('the first prospective policy keeps 12 GiB and rejects unsupported repricing',()=>{
 const p=describeCarrierLocalPolicy();expect(p.logicalBytes).toBe(12*1024**3);expect(()=>inspectCarrierLocalPolicy({...p,logicalBytes:p.logicalBytes-1})).toThrow(/CarrierLocalPolicy/);expect(()=>inspectCarrierLocalPolicy({...p,version:2})).toThrow();
});
