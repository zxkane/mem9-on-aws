import {IMAGE_TRANSITION_LIMITS as IMAGE} from './production-image-transition.mjs';
/** Forecasts inside the original CI quota. These functions never debit a
 * ledger, create a native handle or replace any individual operation guard. */
import {CARRIER_SQL_FIXTURE_LIMITS as SQL} from './ci-carrier-sql-runtime-budget.mjs';
const need=(v,c)=>{if(!v)throw Error(c);};
const checked=n=>{need(Number.isSafeInteger(n)&&n>=0,'CarrierStageCost');return n;};
export function carrierNativeBuildAdmissionBytes({nativeBound,contextBytes,derivedBytes}){
 // The complete existing native precharge plus its immediate full-content
 // checks. Output collection remains bounded and charged by the same meter.
 return checked(nativeBound+contextBytes+derivedBytes);
}
export function carrierPublicationAdmissionBytes(template,nodes){
 need(Array.isArray(nodes)&&nodes.length>0,'CarrierStageGraph');
 const manifest=d=>d.mediaType.includes('manifest')||d.mediaType.includes('image.index'),blobs=nodes.filter(d=>!manifest(d)),manifests=nodes.filter(manifest);
 let bytes=0,parts=0;for(const d of nodes){checked(d.size);bytes+=d.size;}for(const d of blobs)parts+=Math.ceil(d.size/IMAGE.uploadPartBytes);
 const counts={availability:Math.ceil(blobs.length/100),initiate:blobs.length,part:parts,complete:blobs.length,manifestPut:manifests.length,resultPut:1};
 let cost=2*bytes+8*template.bounds.resultBytes;
 for(const [purpose,count]of Object.entries(counts)){
  const p=template.profiles[purpose];need(p&&count<=p.count,'CarrierStagePublicationProfile');
  // Matches the prospective consumer's pre-dispatch copy/parser reservation
  // and both bounded consumer journal records. Wire stays separately paid.
  cost+=count*(8*(p.requestBytes+p.responseBytes)+2*65536);
 }
 return checked(cost);
}
export function carrierSqlStageAdmissionBytes({runtime,packageLocal,publicationBytes,sourceReads=0,fixtureCaptureBytes=0,counterRecordBytes=0}){
 // runtime.total includes all eight cases, setup/relay, loader and their
 // original cleanup prepayments. No unused-case credit is taken.
 need(runtime?.caseSecurityReadPasses===undefined||runtime.caseSecurityReadPasses===2*SQL.cases,'CarrierStageSqlCases');
 checked(sourceReads);checked(fixtureCaptureBytes);checked(counterRecordBytes);return checked(4*(counterRecordBytes+(2*sourceReads+1)*4096)+runtime.total.logicalBytes+packageLocal.logicalBytes+publicationBytes+sourceReads*(6*8388608+2*16384+2*16384)+8*fixtureCaptureBytes+4*65536+16384);
}
