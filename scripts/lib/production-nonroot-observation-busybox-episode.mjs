/** Timed Go observation DATA. The original caller authenticates the actual
 * task/source/filesystem and prepays collection/replay before using it. */
import {copyNonrootJson,nonrootHash} from './production-nonroot-contracts.mjs';
import {inspectDataObservationPlan,describeDataObservationSchedule} from './production-nonroot-data-observer.mjs';
import {decodeBusyboxObservationProcess} from './production-nonroot-observation-busybox-records.mjs';
import {decodeBusyboxObservationRows} from './production-nonroot-observation-busybox-collector.mjs';

const SOURCE=String.raw`
obs_episode_identity(){
 local pid=$1 text rest
 obs_collect_hex /proc/$pid/stat 4096 || return 1
 OBS_COLLECT_HELPERS=$((OBS_COLLECT_HELPERS+1))
 text=$(printf '%s' "$OBS_COLLECT_HEX" | $obs_collect_bb xxd -r -p 2>/dev/null) || return 1
 OBS_COLLECT_MOVEMENT_BYTES=$((OBS_COLLECT_MOVEMENT_BYTES+\${#text}*4))
 case "$text" in "$pid ("*') '*) ;; *) return 1;; esac
 rest=\${text##*) }; set -- $rest; [ "$#" -ge 20 ] || return 1
 OBS_EPISODE_PPID=$2; shift 19; OBS_EPISODE_TICKS=$1
 case "$OBS_EPISODE_TICKS" in ''|*[!0-9]*) return 1;; esac
}
obs_episode_parent(){
 obs_episode_identity "$OBS_PARENT_PID" || return 1
 [ "$OBS_EPISODE_TICKS" = "$OBS_PARENT_TICKS" ]
}
obs_episode_role(){
 local wanted=$1 stamp=$2 command=$3
 [ "$OBS_COLLECT_ROW_PATH" = "$wanted" ] && [ "$OBS_COLLECT_FILE_STAMP" = "$stamp" ] && [ "$OBS_COLLECT_ROW_CMDLINE" = "$command" ]
}
obs_episode_prepare(){
 # These names/digests are emitted by the compiler from original verified
 # image files. Held inode stamps are obtained now, not from archived JSON.
 obs_collect_file /usr/local/bin/mnemo-server || return 1
 [ "$OBS_COLLECT_FILE_DIGEST" = "$OBS_MAIN_DIGEST" ] || return 1; OBS_MAIN_STAMP=$OBS_COLLECT_FILE_STAMP
 obs_collect_file /bin/busybox || return 1
 [ "$OBS_COLLECT_FILE_DIGEST" = "$OBS_HEALTH_DIGEST" ] || return 1; OBS_HEALTH_STAMP=$OBS_COLLECT_FILE_STAMP
 obs_episode_parent
}
obs_episode_health(){
 local path pid before command count=0
 [ -z "$OBS_EPISODE_HEALTH" ] || return 0
 obs_collect_clock || return 1
 [ $((OBS_COLLECT_SECONDS*1000)) -ge "$OBS_EPISODE_START" ] && [ $(((OBS_COLLECT_SECONDS+1)*1000)) -le "$OBS_EPISODE_END" ] || return 0
 for path in /proc/[0-9]*; do
  count=$((count+1)); [ "$count" -le 128 ] || return 1
  pid=\${path##*/}; [ "$pid" != "$$" ] || continue
  obs_collect_hex /proc/$pid/cmdline 16384 || return 1; before=$OBS_COLLECT_HEX
  OBS_COLLECT_HELPERS=$((OBS_COLLECT_HELPERS+2))
  command=$(printf '%s' "$before" | $obs_collect_bb xxd -r -p 2>/dev/null | $obs_collect_bb sha256sum 2>/dev/null) || return 1; command=\${command%% *}
  case " $OBS_HEALTH_ARGV_HASHES " in *" $command "*) ;; *) continue;; esac
  obs_collect_proc "$pid" || return 1
  obs_episode_role /bin/busybox "$OBS_HEALTH_STAMP" "$command" || return 1
  [ "$OBS_COLLECT_ROW_DIGEST" = "$OBS_HEALTH_DIGEST" ] || return 1
  obs_collect_clock || return 1
  [ $(((OBS_COLLECT_SECONDS+1)*1000)) -le "$OBS_EPISODE_END" ] || return 1
  OBS_EPISODE_HEALTH=$OBS_COLLECT_ROW; OBS_EPISODE_HEALTH_SECONDS=$OBS_COLLECT_SECONDS
  return 0
 done
}
obs_episode_snapshot(){
 local pid path ids='' count=0 separator='' mainSeen=0
 obs_collect_clock || return 1; OBS_SNAPSHOT_STARTED=$OBS_COLLECT_SECONDS
 for path in /proc/[0-9]*; do count=$((count+1)); [ "$count" -le 128 ] || return 1; ids="$ids \${path##*/}"; done
 OBS_COLLECT_READ_BYTES=$((OBS_COLLECT_READ_BYTES+\${#ids})); OBS_EPISODE_SNAPSHOT=''
 for pid in $ids; do
  obs_collect_proc "$pid" || return 1
  if [ "$pid" = "$OBS_PARENT_PID" ]; then
   obs_episode_role /usr/local/bin/mnemo-server "$OBS_MAIN_STAMP" "$OBS_MAIN_ARGV_HASH" || return 1
   [ "$OBS_COLLECT_ROW_DIGEST" = "$OBS_MAIN_DIGEST" ] || return 1; mainSeen=1
  fi
  OBS_EPISODE_SNAPSHOT="$OBS_EPISODE_SNAPSHOT$separator$OBS_COLLECT_ROW"; separator=,
  [ \${#OBS_EPISODE_SNAPSHOT} -le 1048576 ] || return 1
 done
 [ "$mainSeen" -eq 1 ] || return 1; obs_episode_parent || return 1
 obs_collect_clock || return 1; OBS_SNAPSHOT_COMPLETED=$OBS_COLLECT_SECONDS
}
obs_busybox_episode_body(){
 local index=$1 start=$2 end=$3 step=$4 next now initial initialStarted initialCompleted snapshots='' separator='' childlist childRead polls=0 pollLimit
 case "$index:$start:$end:$step" in *[!0-9:]*|:*|*::*|*:) return 1;; esac
 [ "$end" -gt "$start" ] && [ "$step" -gt 0 ] && [ "$step" -le $((end-start)) ] && [ "$end" -lt "$OBS_COLLECT_DEADLINE_MS" ] || return 1
 OBS_EPISODE_HEALTH=''; OBS_EPISODE_HEALTH_SECONDS=0
 OBS_EPISODE_START=$start; OBS_EPISODE_END=$end
 obs_collect_clock || return 1; [ $(((OBS_COLLECT_SECONDS+1)*1000)) -le "$start" ] || return 1
 # Every wait consumes one invocation. A backwards/frozen wall clock cannot
 # manufacture unlimited helper work from the original finite deadline.
 pollLimit=$(((OBS_COLLECT_DEADLINE_MS-OBS_COLLECT_SECONDS*1000+9)/10))
 obs_episode_snapshot || return 1
 initial=$OBS_EPISODE_SNAPSHOT; initialStarted=$OBS_SNAPSHOT_STARTED; initialCompleted=$OBS_SNAPSHOT_COMPLETED
 [ $(((initialCompleted+1)*1000)) -le "$start" ] || return 1
 next=$start
 while :; do
  obs_collect_clock || return 1; now=$((OBS_COLLECT_SECONDS*1000))
  while [ "$now" -lt "$next" ]; do
   polls=$((polls+1)); [ "$polls" -le "$pollLimit" ] || return 1
   obs_episode_parent || return 1
   if [ "$now" -ge "$start" ] && [ "$now" -le "$end" ]; then obs_episode_health || return 1; fi
   OBS_COLLECT_HELPERS=$((OBS_COLLECT_HELPERS+1)); $obs_collect_bb sleep 0.01 2>/dev/null || return 1
   obs_collect_clock || return 1; now=$((OBS_COLLECT_SECONDS*1000))
  done
  obs_episode_snapshot || return 1
  snapshots="$snapshots$separator{\"requestedMs\":$next,\"startedSeconds\":$OBS_SNAPSHOT_STARTED,\"completedSeconds\":$OBS_SNAPSHOT_COMPLETED,\"processes\":[$OBS_EPISODE_SNAPSHOT]}"; separator=,
  [ $((\${#snapshots}+\${#initial}+\${#OBS_EPISODE_HEALTH}+2048)) -le 1048576 ] || return 1
  obs_episode_health || return 1
  [ "$next" -ne "$end" ] || break
  next=$((next+step)); [ "$next" -le "$end" ] || next=$end
 done
 [ -n "$OBS_EPISODE_HEALTH" ] || return 1
 obs_collect_close || return 1
 # Open failure is not an empty child list. The builtin read creates no
 # subprocess that could contaminate this final self-children observation.
 exec 19</proc/$$/task/$$/children || return 1
 childlist=''; childRead=0; IFS= read -r -n 4097 childlist <&19 || childRead=$?
 exec 19<&- || return 1
 [ "$childRead" -eq 1 ] && [ -z "$childlist" ] || return 1
 OBS_COLLECT_MOVEMENT_BYTES=$((OBS_COLLECT_MOVEMENT_BYTES+\${#childlist}))
 OBS_EPISODE_RESULT=$(printf '{"version":1,"kind":"data-busybox-observation-episode","planHash":"%s","launchNonce":"%s","episodeIndex":%s,"observerPid":%s,"parentPid":%s,"parentStartTimeTicks":%s,"requestedStartMs":%s,"requestedEndMs":%s,"initial":{"startedSeconds":%s,"completedSeconds":%s,"processes":[%s]},"snapshots":[%s],"health":{"observedSeconds":%s,"process":%s},"readBytes":%s,"movementBytes":%s,"helperInvocations":%s,"collectorChildren":0}' "$OBS_PLAN_HASH" "$OBS_LAUNCH_NONCE" "$index" "$$" "$OBS_PARENT_PID" "$OBS_PARENT_TICKS" "$start" "$end" "$initialStarted" "$initialCompleted" "$initial" "$snapshots" "$OBS_EPISODE_HEALTH_SECONDS" "$OBS_EPISODE_HEALTH" "$OBS_COLLECT_READ_BYTES" "$OBS_COLLECT_MOVEMENT_BYTES" "$OBS_COLLECT_HELPERS")
 [ \${#OBS_EPISODE_RESULT} -le 1048576 ]
}
obs_busybox_episode(){
 OBS_EPISODE_RESULT=''
 if obs_busybox_episode_body "$@"; then return 0; fi
 # A failed later episode cannot expose the previous successful payload.
 # Closing failures remain failures; counters are never reset or refunded.
 OBS_EPISODE_RESULT=''
 obs_collect_close || return 1
 return 1
}
`.replaceAll('\\${','${');

export function busyboxObservationEpisodeSource(){
 if(arguments.length)throw Error('DataObservationBusyboxEpisodeSource');return SOURCE;
}

/** Closed episode DATA and role binding. expected file facts must come from
 * the original independently verified filesystem. This does not authenticate
 * a task/log stream, confer payment, or create a runtime-acceptance handle. */
export function inspectBusyboxObservationEpisode(input,options){
 const checked=copyNonrootJson(options),r=copyNonrootJson(input),need=(v,c)=>{if(!v)throw Error(c);};
 const exact=(v,keys)=>need(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join()===keys.split(' ').sort().join(),'DataObservationEpisodeFields');
 exact(checked,'plan episodeIndex mainFile healthFile mainCmdlineHash healthCmdlineHashes parentPid parentStartTimeTicks observerPid');
 const {plan:inputPlan,episodeIndex,mainFile,healthFile,mainCmdlineHash,healthCmdlineHashes,parentPid,parentStartTimeTicks,observerPid}=checked;
 const plan=inspectDataObservationPlan(inputPlan),schedule=describeDataObservationSchedule(plan);
 need(Number.isSafeInteger(episodeIndex)&&episodeIndex>=0&&[parentPid,parentStartTimeTicks,observerPid].every(n=>Number.isSafeInteger(n)&&n>0)&&parentPid!==observerPid&&parentPid!==1&&observerPid!==1,'DataObservationEpisodeInput');
 const digest=h=>typeof h==='string'&&/^[a-f0-9]{64}$/.test(h);
 need(digest(mainCmdlineHash)&&Array.isArray(healthCmdlineHashes)&&healthCmdlineHashes.length>0&&new Set(healthCmdlineHashes).size===healthCmdlineHashes.length&&healthCmdlineHashes.every(digest),'DataObservationEpisodeInput');
 exact(r,'version kind planHash launchNonce episodeIndex observerPid parentPid parentStartTimeTicks requestedStartMs requestedEndMs initial snapshots health readBytes movementBytes helperInvocations collectorChildren');
 const e=schedule.episodes[episodeIndex];need(plan.role==='mnemo-server'&&e&&r.version===1&&r.kind==='data-busybox-observation-episode','DataObservationEpisodeKind');
 need(r.planHash===nonrootHash(plan)&&r.launchNonce===plan.launchNonce&&r.episodeIndex===episodeIndex&&r.parentPid===parentPid&&r.parentStartTimeTicks===parentStartTimeTicks&&r.observerPid===observerPid,'DataObservationEpisodeBinding');
 need(r.requestedStartMs===e.startedMs&&r.requestedEndMs===e.completedMs,'DataObservationEpisodeWindow');
 for(const k of ['readBytes','movementBytes','helperInvocations'])need(Number.isSafeInteger(r[k])&&r[k]>=0,'DataObservationEpisodeCounter');
 need(r.readBytes<=268435456&&r.collectorChildren===0,'DataObservationEpisodeCounter');
 need(Buffer.byteLength(JSON.stringify(r))<=1048576,'DataObservationEpisodeOutput');
 const time=n=>need(Number.isSafeInteger(n)&&n>0&&Number.isSafeInteger((n+1)*1000),'DataObservationEpisodeTime');
 const secure=p=>need([...p.uid,...p.gid,...p.groups].every(v=>v===1000)&&p.noNewPrivs===1&&['Inh','Prm','Eff','Bnd','Amb'].every(k=>p['cap'+k]==='0000000000000000'),'DataObservationEpisodeSecurity');
 const role=(p,file,commands)=>{
  secure(p);need(p.executablePath===file.path&&p.executableDigest==='sha256:'+file.sha256&&p.file.mode===file.mode&&p.file.uid===file.uid&&p.file.gid===file.gid&&commands.includes(p.cmdlineHash),'DataObservationEpisodeRole');
 };
 need(mainFile.path==='/usr/local/bin/mnemo-server'&&healthFile.path==='/bin/busybox','DataObservationEpisodeFiles');
 for(const f of [mainFile,healthFile])need(digest(f.sha256)&&f.uid===0&&f.gid===0&&Number.isSafeInteger(f.size)&&f.size>0&&f.size<=201326592&&Number.isSafeInteger(f.mode)&&f.mode>=0&&f.mode<=4095&&(f.mode&0o6022)===0,'DataObservationEpisodeFiles');
 const fileSize=(raw,file)=>need(raw.stamp.split(',')[2]===String(file.size),'DataObservationEpisodeFileSize');
 exact(r.initial,'startedSeconds completedSeconds processes');time(r.initial.startedSeconds);time(r.initial.completedSeconds);
 need(r.initial.startedSeconds*1000>=plan.startedMs&&r.initial.startedSeconds<=r.initial.completedSeconds&&(r.initial.completedSeconds+1)*1000<=e.startedMs,'DataObservationEpisodeInitial');
 need(Array.isArray(r.snapshots)&&r.snapshots.length===e.samples,'DataObservationEpisodeCoverage');
 const decoded=[{...r.initial,processes:decodeBusyboxObservationRows(r.initial.processes)}];let requested=e.startedMs,completed=r.initial.completedSeconds;
 for(const s of r.snapshots){
  exact(s,'requestedMs startedSeconds completedSeconds processes');time(s.startedSeconds);time(s.completedSeconds);
  need(s.requestedMs===requested&&s.startedSeconds*1000>=requested&&s.startedSeconds>=completed&&s.startedSeconds<=s.completedSeconds&&(s.completedSeconds+1)*1000<plan.observationEndMs,'DataObservationEpisodeTime');
  decoded.push({...s,processes:decodeBusyboxObservationRows(s.processes)});requested=Math.min(e.completedMs,requested+e.sampleEveryMs);completed=s.completedSeconds;
 }
 const identities=new Map(),stamps=new Map();let originalMain,originalObserver;
 for(const [index,s]of decoded.entries()){
  const rawSnapshot=index===0?r.initial:r.snapshots[index-1];
  need(s.processes.some(p=>p.pid===1)&&s.processes.some(p=>p.pid===observerPid),'DataObservationEpisodeCoverage');
  const main=s.processes.filter(p=>p.pid===parentPid&&p.startTimeTicks===parentStartTimeTicks);need(main.length===1,'DataObservationEpisodeMain');role(main[0],mainFile,[mainCmdlineHash]);
  fileSize(rawSnapshot.processes.find(p=>p.pid===parentPid),mainFile);
  const observer=s.processes.find(p=>p.pid===observerPid);secure(observer);need(observer.ppid===1&&observer.executablePath===healthFile.path&&observer.executableDigest==='sha256:'+healthFile.sha256&&observer.file.mode===healthFile.mode&&observer.file.uid===healthFile.uid&&observer.file.gid===healthFile.gid,'DataObservationEpisodeObserver');
  fileSize(rawSnapshot.processes.find(p=>p.pid===observerPid),healthFile);
  if(originalObserver)need(observer.startTimeTicks===originalObserver.startTimeTicks&&nonrootHash(observer)===nonrootHash(originalObserver),'DataObservationEpisodeObserver');else originalObserver=observer;
  if(originalMain)need(main[0].file.device===originalMain.file.device&&main[0].file.inode===originalMain.file.inode,'DataObservationEpisodeInstance');else originalMain=main[0];
  for(const p of s.processes){const key=p.pid+':'+p.startTimeTicks,prior=identities.get(key),stamp=rawSnapshot.processes.find(row=>row.pid===p.pid).stamp;if(prior)need(nonrootHash(p)===nonrootHash(prior)&&stamps.get(key)===stamp,'DataObservationEpisodeProcessChanged');identities.set(key,p);stamps.set(key,stamp);}
 }
 exact(r.health,'observedSeconds process');time(r.health.observedSeconds);need(r.health.observedSeconds*1000>=e.startedMs&&(r.health.observedSeconds+1)*1000<=e.completedMs,'DataObservationEpisodeHealthTime');
 const health=decodeBusyboxObservationProcess(r.health.process);role(health,healthFile,healthCmdlineHashes);fileSize(r.health.process,healthFile);
 need(health.pid!==1&&health.pid!==parentPid&&health.pid!==observerPid&&health.file.device===originalObserver.file.device&&health.file.inode===originalObserver.file.inode,'DataObservationEpisodeHealth');
 need(r.health.process.stamp===r.initial.processes.find(p=>p.pid===observerPid).stamp,'DataObservationEpisodeHealth');
 const healthKey=health.pid+':'+health.startTimeTicks,priorHealth=identities.get(healthKey);
 if(priorHealth)need(nonrootHash(priorHealth)===nonrootHash(health)&&stamps.get(healthKey)===r.health.process.stamp,'DataObservationEpisodeProcessChanged');
 identities.set(healthKey,health);
 need(identities.size<=256,'DataObservationEpisodeCoverage');
 return copyNonrootJson({authority:false,planHash:r.planHash,episodeIndex,snapshots:decoded,main:originalMain,health,readBytes:r.readBytes,movementBytes:r.movementBytes,helperInvocations:r.helperInvocations});
}
