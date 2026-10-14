/** Original typed archive selection, with occurrence order preserved. Image
 * bodies and credential bodies are never selected by a recursive ref walk. */
import {need,ref,same} from './production-nonroot-engineering-json.mjs';

export function archivedObserverSourceOriginals(input){
 const rows=[];
 const add=(kind,original,reference)=>{
  const selected={path:original.path,sha256:original.sha256,bytesLength:original.bytesLength??reference?.bytesLength};ref(selected);
  need(selected.bytesLength<=33554432,'ObserverSourceArchiveInputBound');
  if(reference)need((reference.bytesHash??reference.sha256)===selected.sha256&&reference.bytesLength===selected.bytesLength,'ObserverSourceArchiveInputBinding');
  rows.push({kind,original:selected,...(reference?{reference}:{})});
 };
 need(Array.isArray(input.prerequisiteObjects),'ObserverSourceArchivePrerequisites');
 for(const r of input.prerequisiteObjects)add('DATA-prerequisite',r.raw,r.ref);
 need(input.control&&Array.isArray(input.control.sourceObjects)&&Array.isArray(input.control.proofObjects),'ObserverSourceArchiveControl');
 for(const r of input.control.sourceObjects)add('CONTROL-source',r.ref);
 for(const r of input.control.proofObjects)add('CONTROL-proof',r);
 return rows;
}

export function verifyArchivedObserverSourceOriginals(input,rows){
 need(Array.isArray(rows),'ObserverSourceModelOriginals');
 same(rows.map(({blob,...r})=>r),archivedObserverSourceOriginals(input),'ObserverSourceModelOriginalCoverage');
}
