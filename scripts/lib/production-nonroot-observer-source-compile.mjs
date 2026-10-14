import {observerCaseVersion} from './production-nonroot-observer-accounting.mjs';
/** Original per-case compiler checks over file facts. This pure step does
 * not authenticate a facts provider or create an owner/source capability. */
import {need,hash} from './production-nonroot-engineering-json.mjs';
import {observerCaseRoles,observerContractKey,inspectObserverCaseSchedule} from './production-nonroot-observer-case-bindings.mjs';
import {compileObservedNodeDataLaunch} from './production-nonroot-observed-node-launch.mjs';
import {compileObservedBusyboxDataLaunch} from './production-nonroot-observed-busybox-launch.mjs';

export function compileArchivedObserverRoles({plan,input,images},{reader,file}){
 reader.current();need(typeof file==='function','ObserverSourceFactsRequired');
 const contracts=new Map(),nonces=new Set(),requiredPaths=new Map();
 if(observerCaseVersion(plan)){
  need(input.roles.length===5&&new Set(input.roles.map(r=>r.role)).size===5&&input.cohorts.length===5&&new Set(input.cohorts.map(c=>c.name)).size===5,'ObserverCompleteCaseInputs');
  for(const c of plan.cases){
   const row=input.cohorts.find(x=>x.name===c.name),wanted=observerCaseRoles(c);
   need(row&&Array.isArray(row.observations)&&row.observations.length===wanted.length&&new Set(row.observations.map(r=>r.role)).size===wanted.length&&wanted.every(role=>row.observations.some(r=>r.role===role)),'ObserverCompleteCaseObservations');
  }
 }
 for(const quoted of plan.geometry.roles){
  reader.current();
  // The old owner prepaid the complete compile row before entering this
  // block. The current replay payer must likewise cover generation/hash/
  // compression before calling the original compiler; errors retain it.
  reader.paid.debit(8*quoted.inputBytes+8*quoted.compiledBytes+8*quoted.expandedBytes+4*quoted.compressedBytes);
  const role=quoted.role,caseName=observerCaseVersion(plan)?quoted.caseName:null,c=caseName?plan.cases.find(c=>c.name===caseName):null;
  const r=input.roles.find(r=>r.role===role);need(r,'ObserverFiveRoles');
  const observation=c?input.cohorts.find(x=>x.name===caseName)?.observations?.find(x=>x.role===role):r;
  need(observation,'ObserverCaseObservationMissing');
  const component=['planner','executor'].includes(role)?'llm-proxy':role,g=input.filesystems[component];
  if(c){
   need(quoted.filesystemLookupLocal===r.filePaths.length*(4*g.entriesBytes+32*g.entryNodes),'ObserverFilesystemLookupQuote');
   inspectObserverCaseSchedule(plan,c,role,observation,quoted,input.control.source.tree,images[component]);
   need(!nonces.has(observation.plan.launchNonce),'ObserverCaseNonceReused');nonces.add(observation.plan.launchNonce);
   if(c.runtimeRoles.includes(role))need(observation.plan.deadlineMs<=c.logPollTimes[0],'ObserverLogBeforeObservationClosed');
  }
  if(!requiredPaths.has(component))requiredPaths.set(component,new Set());
  const files=r.filePaths.map(path=>{
   reader.paid.debit(4*g.entriesBytes+32*g.entryNodes);
   const fact=file(component,path);reader.current();requiredPaths.get(component).add(path);return fact;
  }).map(f=>({path:f.path,resolvedPath:f.resolvedPath,sha256:f.sha256,size:f.size,mode:f.mode,uid:f.uid,gid:f.gid}));
  need(hash(observation.plan.image)===hash(images[component])&&observation.plan.owner===plan.owner&&observation.plan.operation===plan.operation,'ObserverCompiledOwner');
  const args={plan:observation.plan,original:r.original,files};
  if(c)need(Buffer.byteLength(JSON.stringify(args))<=quoted.inputBytes&&files.length===quoted.files&&files.reduce((n,f)=>n+f.size,0)===quoted.fileBytes,'ObserverCompleteCompileInputGeometry');
  const compiled=(role==='mnemo-server'?compileObservedBusyboxDataLaunch:compileObservedNodeDataLaunch)(args);reader.current();
  need(hash(compiled)===observation.compiledHash,'ObserverFinalSourceOrScheduleChanged');
  need(compiled.delivery.sourceBytes===quoted.expandedBytes&&compiled.delivery.compressedBytes===quoted.compressedBytes&&compiled.delivery.bootstrapBytes===quoted.bootstrapBytes&&compiled.snapshotCount===quoted.snapshots,'ObserverFinalGeometryChanged');
  const compiledBytes=Buffer.byteLength(JSON.stringify(compiled));
  if(c)need(compiledBytes===quoted.compiledBytes&&Buffer.byteLength(JSON.stringify(compiled.target))===quoted.targetContainerBytes,'ObserverFinalCompiledBytes');
  const key=c?observerContractKey(caseName,role):role;need(!contracts.has(key),'ObserverDuplicateContract');contracts.set(key,compiled);
 }
 reader.current();return {contracts,requiredPaths};
}
