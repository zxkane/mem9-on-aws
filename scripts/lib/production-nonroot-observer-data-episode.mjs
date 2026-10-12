/** Original Node episode predicates only; no runtime authority is created. */
import {createHash} from 'node:crypto';
import {need,exact,hash} from './production-nonroot-engineering-json.mjs';
import {describeDataObservationSchedule,inspectWorkerExecAnchor,resolveWorkerObservationSchedule} from './production-nonroot-data-observer.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex'),command=argv=>sha(Buffer.from(argv.join('\0')+'\0'));
const rowKeys=['pid','ppid','startTimeTicks','executablePath','executableDigest','file','cmdlineHash','uid','gid','groups','noNewPrivs','capInh','capPrm','capEff','capBnd','capAmb'];
export function inspectArchivedObserverProcess(p){
 exact(p,rowKeys);exact(p.file,['mode','uid','gid','device','inode']);
 need([p.pid,p.startTimeTicks].every(n=>Number.isSafeInteger(n)&&n>0)&&Number.isSafeInteger(p.ppid)&&p.ppid>=0&&typeof p.executablePath==='string'&&p.executablePath.startsWith('/')&&/^sha256:[a-f0-9]{64}$/.test(p.executableDigest)&&/^[a-f0-9]{64}$/.test(p.cmdlineHash),'ObserverProcessFields');
 need([p.uid,p.gid].every(v=>Array.isArray(v)&&v.length===4&&v.every(n=>n===1000))&&Array.isArray(p.groups)&&(p.groups.length===0||p.groups.length===1&&p.groups[0]===1000),'ObserverProcessIdentity');
 need(['Inh','Prm','Eff','Bnd','Amb'].every(k=>p['cap'+k]==='0000000000000000')&&[0,1].includes(p.noNewPrivs),'ObserverProcessPrivilege');
 need(p.file.uid===0&&p.file.gid===0&&Number.isSafeInteger(p.file.mode)&&p.file.mode>=0&&p.file.mode<=4095&&(p.file.mode&0o6022)===0&&['device','inode'].every(k=>typeof p.file[k]==='string'&&/^(0|[1-9][0-9]*)$/.test(p.file[k])),'ObserverProcessFile');return p;
}
export function inspectArchivedNodeObserverEpisode(raw,contract,index){
 const p=contract.plan,relative=p.version===2;
 exact(raw,['version','kind','planHash','role','launchNonce','episodeIndex','observerPid','parentPid','parentStartTimeTicks','requestedStartMs','requestedEndMs','startedMs','completedMs','initial','final','snapshots','health','readBytes','collectorResources','launch',...(relative?['execAnchor']:[])]);
 const anchor=relative?inspectWorkerExecAnchor(raw.execAnchor,p):null,e=(relative?resolveWorkerObservationSchedule(p,anchor):describeDataObservationSchedule(p)).episodes[index];
 need(e&&raw.version===(relative?2:1)&&raw.kind==='data-observation-episode'&&raw.planHash===hash(p)&&raw.role===p.role&&raw.launchNonce===p.launchNonce&&raw.episodeIndex===index,'ObserverEpisodeBinding');
 need(raw.requestedStartMs===e.startedMs&&raw.requestedEndMs===e.completedMs&&raw.startedMs>=p.startedMs&&raw.completedMs< p.observationEndMs&&raw.startedMs<=raw.completedMs,'ObserverEpisodeClock');
 exact(raw.collectorResources,['heldImageFiles','childProcesses']);need(raw.collectorResources.heldImageFiles===0&&raw.collectorResources.childProcesses===0&&Number.isSafeInteger(raw.readBytes)&&raw.readBytes>=0&&raw.readBytes<=268435456,'ObserverCollectionClosure');
 exact(raw.launch,['observerStartTimeTicks','armingDeadlineMs']);need(Number.isSafeInteger(raw.launch.observerStartTimeTicks)&&raw.launch.observerStartTimeTicks>0&&Number.isSafeInteger(raw.launch.armingDeadlineMs)&&raw.launch.armingDeadlineMs>=p.startedMs&&raw.launch.armingDeadlineMs<=p.latestArmMs+p.armingLimitMs,'ObserverArmingBinding');
 if(relative)need(anchor.observerPid===raw.observerPid&&anchor.observerStartTimeTicks===raw.launch.observerStartTimeTicks&&anchor.parentPid===raw.parentPid&&anchor.parentStartTimeTicks===raw.parentStartTimeTicks&&anchor.observedMs<=raw.initial.startedMs,'ObserverExecAnchorBinding');
 need(Array.isArray(raw.snapshots)&&raw.snapshots.length===e.samples&&hash(raw.final)===hash(raw.snapshots.at(-1))&&raw.startedMs===raw.initial.startedMs&&raw.completedMs===raw.final.completedMs,'ObserverSnapshotCoverage');
 need(raw.initial.completedMs<=e.startedMs,'ObserverInitialWindow');const snapshots=[raw.initial,...raw.snapshots];
 let previous=raw.startedMs;
 for(const [i,s]of snapshots.entries()){
  exact(s,['startedMs','completedMs','processes']);need(Number.isSafeInteger(s.startedMs)&&Number.isSafeInteger(s.completedMs)&&s.startedMs>=previous&&s.completedMs>=s.startedMs&&s.completedMs<p.observationEndMs,'ObserverSnapshotClock');
  if(i)need(s.startedMs>=Math.min(e.completedMs,e.startedMs+(i-1)*e.sampleEveryMs),'ObserverSnapshotSchedule');previous=s.completedMs;
  need(Array.isArray(s.processes)&&s.processes.length>0&&s.processes.length<=128&&new Set(s.processes.map(r=>r.pid)).size===s.processes.length,'ObserverProcessCoverage');s.processes.forEach(inspectArchivedObserverProcess);
  need(s.processes.some(r=>r.pid===1)&&s.processes.some(r=>r.pid===raw.observerPid)&&s.processes.some(r=>r.pid===raw.parentPid&&r.startTimeTicks===raw.parentStartTimeTicks),'ObserverRequiredProcess');
 }
 const mainHash=command([...contract.normal.entryPoint.slice(3),...(contract.normal.command??[])]),healthHash=contract.normal.healthCheck?command(contract.normal.healthCheck.command.slice(4)):null;
 for(const s of snapshots){const main=s.processes.find(r=>r.pid===raw.parentPid);need(main.noNewPrivs===1&&main.executablePath==='/usr/local/bin/node'&&main.cmdlineHash===mainHash,'ObserverOriginalMain');
  if(relative)need(hash(main)===hash(anchor.main),'ObserverExecAnchorProcess');
  const observer=s.processes.find(r=>r.pid===raw.observerPid);need(observer.noNewPrivs===1&&observer.ppid===1&&observer.startTimeTicks===raw.launch.observerStartTimeTicks&&observer.executablePath==='/usr/local/bin/node'&&observer.cmdlineHash===command([...contract.target.entryPoint.slice(3),'observer',String(raw.parentPid),String(raw.parentStartTimeTicks),String(raw.launch.armingDeadlineMs)]),'ObserverOriginalProgram');
 }
 need(Array.isArray(raw.health)&&raw.health.length===(healthHash?1:0),'ObserverHealthCoverage');
 for(const h of raw.health){exact(h,['atMs','process']);inspectArchivedObserverProcess(h.process);need(h.atMs>=e.startedMs&&h.atMs<=e.completedMs&&h.process.noNewPrivs===1&&h.process.executablePath==='/usr/local/bin/node'&&h.process.cmdlineHash===healthHash,'ObserverOriginalHealth');}
 return {snapshots,main:snapshots[0].processes.find(r=>r.pid===raw.parentPid),health:raw.health[0]?.process??null,observer:snapshots[0].processes.find(r=>r.pid===raw.observerPid),startedMs:raw.startedMs,completedMs:raw.completedMs,observerTicks:raw.launch.observerStartTimeTicks,...(relative?{execAnchor:anchor,anchorHash:hash(anchor),requiredStartMs:e.startedMs,requiredEndMs:e.completedMs}: {})};
}
