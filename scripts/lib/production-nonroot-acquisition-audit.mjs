/** Original A journal/counter/raw predicates, replayed from authenticated
 * archive entries. Historical paths and inode records are evidence only;
 * local D separately performs the original physical claim authentication. */
import {need,exact,same,sha,hash,json,ref,immutable,COUNTERS,add} from './production-nonroot-engineering-json.mjs';
import {LIMITS as L,quoteOriginalObserverAcquisition,observerAcquisitionClaimKey,observerAcquisitionOperationHash} from './production-nonroot-acquisition-math.mjs';

export function inspectArchivedAcquisitionReference(a){
 exact(a,['headerRef','terminalRef','manifestRef','recordCount','recordBytes','rawCount','rawBytes']);
 for(const k of ['headerRef','terminalRef','manifestRef'])ref(a[k]);
 need(a.headerRef.bytesLength>0&&a.headerRef.bytesLength<=L.headerBytes&&a.terminalRef.bytesLength>0&&a.terminalRef.bytesLength<=L.recordBytes&&a.manifestRef.bytesLength>0&&a.manifestRef.bytesLength<=L.manifestBytes,'AcquisitionReferenceBound');
 for(const k of ['recordCount','recordBytes','rawCount','rawBytes'])need(Number.isSafeInteger(a[k])&&a[k]>=0,'AcquisitionReferenceBound');
 need(a.recordCount>0&&a.recordCount<=L.recordCount+L.cleanupRecords&&a.recordBytes<=a.recordCount*L.recordBytes&&a.rawCount>0&&a.rawCount<=L.materialFiles+L.maxNodes+512&&a.rawBytes<=L.graphBytes+L.inputBytes+8*33554432+L.metadataBytes,'AcquisitionReferenceBound');return a;
}
export async function replayArchivedAcquisitionChain(a,{reader,expectedSource,image}){
 reader.current();inspectArchivedAcquisitionReference(a);
 const load=async(r,cap)=>{const raw=await reader.readBytes(r,cap);reader.current();return {raw,value:json(raw,cap)};};
 const {value:header}=await load(a.headerRef,L.headerBytes);reader.current();
 const {value:m}=await load(a.manifestRef,L.manifestBytes);reader.current();
 exact(m,['version','kind','authority','input3Ready','owner','claimKey','operationHash','headerRef','configRef','selection','sourceManifestHash','toolEnvironmentHash','inputs','envelopeRef','completionRef','measurementRef','baseRef','graph','raws','rawBytes']);
 need(m.version===1&&m.kind==='engineering-acquisition-manifest'&&m.authority===false&&m.input3Ready===false,'AcquisitionManifest');
 const {value:c}=await load(m.configRef,L.configBytes);reader.current();
 const q=quoteOriginalObserverAcquisition(c),key=observerAcquisitionClaimKey(c),suffix='/'+c.owner+'/'+key+'/reservation.json';
 need(a.headerRef.path.endsWith(suffix),'AcquisitionClaimPath');const directory=a.headerRef.path.slice(0,-'/reservation.json'.length);
 need(a.manifestRef.path===directory+'/acquisition-manifest.json'&&a.terminalRef.path===directory+'/j-'+String(a.recordCount).padStart(6,'0')+'.json','AcquisitionClaimPath');
 need(header.version===2&&header.phase==='acquire'&&header.kind==='engineering-open-reservation'&&header.owner===c.owner&&header.claimKey===key,'AcquisitionHeader');
 need(m.owner===c.owner&&m.claimKey===key&&m.operationHash===header.operationHash,'AcquisitionManifest');
 same(m.headerRef,a.headerRef,'AcquisitionHeaderRef');same(m.selection,c.selection,'AcquisitionSelection');same(header.ownerRecord,c.ownerRecord,'AcquisitionOwner');
 same(c.provenance.source,expectedSource,'AcquisitionSourceExpected');same(c.selection.bootstrap,image,'AcquisitionImageExpected');
 need(c.selection.repository===expectedSource.repository&&c.selection.head===expectedSource.candidateRevision&&c.selection.tree===expectedSource.candidateTree,'AcquisitionSourceExpected');
 same(header.quote,q,'AcquisitionQuote');same(header.capacity,c.capacity,'AcquisitionCapacity');same(header.reserved,q.total,'AcquisitionReservation');
 need(header.configHash===hash(c)&&header.operationHash===observerAcquisitionOperationHash(c,q)&&header.selectionHash===hash(c.selection)&&header.sourceManifestHash===hash(c.sourceManifest)&&header.toolEnvironmentHash===hash(c.toolEnvironment)&&header.calculatorManifestHash===hash(c.calculatorManifest)&&header.catalogHash===q.catalogHash&&header.quoteHash===q.quoteHash,'AcquisitionSourceBinding');
 need(m.sourceManifestHash===header.sourceManifestHash&&m.toolEnvironmentHash===header.toolEnvironmentHash,'AcquisitionSourceBinding');
 need(header.deadlineMs===header.startedMs+L.maximumMs,'AcquisitionClock');
 need(m.raws.length===a.rawCount&&m.rawBytes===a.rawBytes,'AcquisitionRawBound');
 const byPath=new Map();let rawBytes=0;
 for(const r of m.raws){ref(r);need(r.path.startsWith(directory+'/')&&!byPath.has(r.path),'AcquisitionRawPath');byPath.set(r.path,r);rawBytes+=r.bytesLength;}
 need(rawBytes===a.rawBytes,'AcquisitionRawBound');
 for(const r of [m.configRef,m.envelopeRef,m.completionRef,m.measurementRef,m.baseRef])same(byPath.get(r.path),r,'AcquisitionRequiredRaw');
 need(m.envelopeRef.sha256===c.selection.dataRoot&&m.envelopeRef.sha256===c.ci.commitment.envelopeSha256&&m.envelopeRef.bytesLength===c.ci.commitment.bytesLength,'AcquisitionEnvelopeCommitment');
 same(m.inputs.map(r=>r.original),c.inputs,'AcquisitionInputInventory');
 for(const row of m.inputs){same(byPath.get(row.retained.path),row.retained,'AcquisitionInputRetention');need(row.retained.sha256===row.original.sha256&&row.retained.bytesLength===row.original.bytesLength,'AcquisitionInputBytes');}
 let nextHash=a.terminalRef.sha256,totalBytes=0,lastTime=header.deadlineMs,terminal,cleanup=null,dataComplete=null,dataSequence=0,lastRequestSequence=0,firstReleaseSequence=a.recordCount,childJoined=0,childCreated=0,childIntent=0;
 const removals=new Map(),resources=new Map(),retained=new Map(),results=new Map(),calls={},wireByRow={},released=new Set(),journal=[];
 for(let i=a.recordCount;i>0;i--){
  const path=directory+'/j-'+String(i).padStart(6,'0')+'.json',raw=await reader.readBytes({sha256:nextHash},L.recordBytes);reader.current();
  const r={path,sha256:nextHash,bytesLength:raw.length},item=json(raw,L.recordBytes);totalBytes+=raw.length;need(totalBytes<=a.recordBytes,'AcquisitionJournalBytes');
  need(item.version===1&&item.sequence===i&&item.claimKey===key&&item.operationHash===header.operationHash&&item.atMs>=header.startedMs&&item.atMs<=lastTime&&item.atMs<header.deadlineMs,'AcquisitionJournalBinding');lastTime=item.atMs;nextHash=item.previousHash;journal.push(r);
  const d=item.data;
  if(i===a.recordCount){
   same(r,a.terminalRef,'AcquisitionTerminalRef');need(item.kind==='terminal','AcquisitionTerminal');terminal=d;
   need(d.status==='COMPLETE'&&d.phase==='acquire'&&d.input3Ready===false&&d.cleanupComplete===true,'AcquisitionNotComplete');same(d.outputs,a.manifestRef,'AcquisitionOutput');same(d.retainedReservation,q.total,'AcquisitionReservation');
   need(!d.accounting.held&&!d.accounting.unknown&&!d.accounting.active,'AcquisitionAccounting');same(d.accounting.reserved,q.total,'AcquisitionReservation');same(add(...Object.values(d.accounting.rows)),d.accounting.consumed,'AcquisitionConservation');same(Object.keys(d.accounting.rows).sort(),q.rows.map(r=>r.id).sort(),'AcquisitionCounterRows');
   for(const row of q.rows){const used=d.accounting.rows[row.id];need(COUNTERS.every(k=>used[k]>=0&&Number.isSafeInteger(used[k])&&used[k]+(row.id==='protected-cleanup'&&k==='logicalBytes'?8*raw.length+4096:0)<=row.charge[k]),'AcquisitionConservation');}
   need(COUNTERS.every(k=>q.total[k]<=c.capacity[k]&&header.initialCounters[k]<=q.prelude[k]&&d.accounting.rows.prelude[k]===header.initialCounters[k]),'AcquisitionConservation');
  }else need(item.kind!=='terminal'&&item.kind!=='request-unknown'&&item.kind!=='issuance-held','AcquisitionUnsettled');
  if(item.kind==='acquisition-cleanup'){need(cleanup===null&&i===a.recordCount-1,'AcquisitionCleanupOrder');cleanup=d;}
  if(item.kind==='acquisition-data-complete'){need(dataComplete===null,'AcquisitionDataDuplicate');dataComplete=d;dataSequence=i;}
  if(item.kind==='resource-removed'){need(!removals.has(d.path),'AcquisitionRemovalDuplicate');removals.set(d.path,d.identity);}
  if(item.kind==='resource-created'){need(!resources.has(d.path)&&d.identity,'AcquisitionResourceDuplicate');resources.set(d.path,d);}
  if(item.kind==='data-retained'){need(!retained.has(d.ref.path),'AcquisitionRetainedDuplicate');retained.set(d.ref.path,d.ref);}
  if(item.kind==='request-result'){need(!d.unknown&&d.statusCode>=200&&d.statusCode<300&&!results.has(d.intent.path),'AcquisitionRequestResult');results.set(d.intent.path,d);lastRequestSequence=Math.max(i,lastRequestSequence);}
  if(item.kind==='request-intent'){
   const result=results.get(path);need(result&&result.intent.sha256===sha(raw)&&result.intent.bytesLength===raw.length,'AcquisitionRequestUnsettled');results.delete(path);
   const op=q.catalog.find(v=>v.purpose===d.purpose&&v.action===d.action);need(op&&d.requestHash===hash(d.request)&&d.caps.requestBytes===op.requestBytes&&d.caps.responseBytes<=op.responseBytes&&result.requestBytes>=0&&result.responseBytes>=0&&result.requestBytes<=d.caps.requestBytes&&result.responseBytes<=d.caps.responseBytes,'AcquisitionRequestScope');
   const ck=d.purpose+':'+d.action;calls[ck]=(calls[ck]??0)+1;need(calls[ck]<=op.count,'AcquisitionRequestCount');
   if(d.action==='GetObject')need(result.responseHash===m.envelopeRef.sha256&&result.responseBytes===m.envelopeRef.bytesLength,'AcquisitionEnvelopeResponse');
   const lane=d.purpose==='CI_OBJECT_READER'?(d.action==='GetObject'?'ci-reader':'ci-issuer'):'census-including-issuer-worker';const wire=wireByRow[lane]??={ecrRequests:0,httpBodyBytes:0};wire.httpBodyBytes+=result.requestBytes+result.responseBytes;if(['BatchGetImage','GetDownloadUrlForLayer'].includes(d.action))wire.ecrRequests++;
  }
  if(item.kind==='issuer-released'){need(!released.has(d.purpose),'AcquisitionIssuerCleanup');released.add(d.purpose);firstReleaseSequence=Math.min(i,firstReleaseSequence);}
  if(item.kind==='child-intent')childIntent++;
  if(item.kind==='child-created')childCreated++;
  if(item.kind==='child-joined'){need(d.status===0,'AcquisitionChildStatus');childJoined++;}
 }
 need(nextHash===a.headerRef.sha256&&totalBytes===a.recordBytes&&results.size===0,'AcquisitionJournalRoot');same(calls,terminal.accounting.calls,'AcquisitionRequestAccounting');
 for(const op of q.catalog.filter(r=>['ImdsV2Token','ImdsV2Credentials','GetCallerIdentity','AssumeRole','GetObject'].includes(r.action)))need(calls[op.purpose+':'+op.action]===op.count,'AcquisitionRequiredRequests');
 need(calls['PREVIEW_BOOTSTRAP_READER:BatchGetImage']>0,'AcquisitionRequiredRequests');
 for(const [lane,wire]of Object.entries(wireByRow))for(const k of ['ecrRequests','httpBodyBytes'])need(terminal.accounting.rows[lane][k]===wire[k],'AcquisitionWireAccounting');
 need(childJoined===1&&childCreated===1&&childIntent===1,'AcquisitionChildJoin');
 need(released.size===2&&released.has('CI_OBJECT_READER')&&released.has('PREVIEW_BOOTSTRAP_READER'),'AcquisitionIssuerCleanup');
 need(cleanup?.cleanupComplete===true&&cleanup.pendingIo===0&&cleanup.children===0&&cleanup.active===false&&cleanup.temporaryFiles?.length===0,'AcquisitionCleanupMissing');
 same(dataComplete,{manifestRef:a.manifestRef,rawCount:a.rawCount,rawBytes:a.rawBytes,input3Ready:false},'AcquisitionDataComplete');
 need(lastRequestSequence<dataSequence&&dataSequence<firstReleaseSequence,'AcquisitionCleanupOrder');
 for(const [path,r]of resources){need(path.startsWith(directory+'/'),'AcquisitionResourcePath');if(r.temporary&&r.kind==='file')same(removals.get(path),r.identity,'AcquisitionCleanupMissing');}
 same(retained.get(a.manifestRef.path),a.manifestRef,'AcquisitionManifestRetention');
 for(const r of m.raws){
  const resource=resources.get(r.path);need(resource?.kind==='file'&&!resource.temporary&&!removals.has(r.path),'AcquisitionRawOwnership');
  const id=resource.identity,mode=Number(id.mode);need(id.uid===header.claimIdentity.uid&&id.nlink==='1'&&Number.isSafeInteger(mode)&&(mode&0o777)===0o600,'AcquisitionRecordedRawIdentity');
  if(r.path.startsWith(directory+'/cache/')){const n=m.graph.nodes.find(n=>n.digest==='sha256:'+r.sha256);need(n&&n.size===r.bytesLength&&r.path===directory+'/cache/'+r.sha256,'AcquisitionGraphRaw');}else same(retained.get(r.path),r,'AcquisitionRetainedRaw');
  if(r.path!==m.configRef.path){await reader.readBytes(r,Math.min(L.graphBytes,67108864));reader.current();}
 }
 for(const n of m.graph.nodes)same(byPath.get(directory+'/cache/'+n.digest.slice(7)),{path:directory+'/cache/'+n.digest.slice(7),sha256:n.digest.slice(7),bytesLength:n.size},'AcquisitionGraphComplete');
 reader.current();return immutable({authority:false,physicalOwnershipObserved:false,config:c,manifest:m,header,terminal,journal:journal.reverse(),directory,quote:q});
}
