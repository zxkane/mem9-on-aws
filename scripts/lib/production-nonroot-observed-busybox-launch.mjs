/** Fixed BusyBox launch DATA. Only the original owner adapter may bind this
 * source to authenticated image files, task identity and prepaid execution. */
import {createHash} from 'node:crypto';
import {gzipSync} from 'node:zlib';
import {copyNonrootJson,nonrootHash} from './production-nonroot-contracts.mjs';
import {dataLaunchPolicy} from './production-nonroot-launch.mjs';
import {inspectDataObservationPlan,describeDataObservationSchedule} from './production-nonroot-data-observer.mjs';
import {inspectObservationGateFiles} from './production-nonroot-observation-gate.mjs';
import {busyboxObservationGateSource} from './production-nonroot-observation-busybox-gate.mjs';
import {busyboxObservationCollectorSource} from './production-nonroot-observation-busybox-collector.mjs';
import {busyboxObservationEpisodeSource} from './production-nonroot-observation-busybox-episode.mjs';
import {busyboxObservationOutputSource} from './production-nonroot-observation-busybox-output.mjs';
import {targetHealthArgv,targetCmdlineHash} from './production-nonroot-target-probe.mjs';

const sha=b=>createHash('sha256').update(b).digest('hex');
const need=(v,c)=>{if(!v)throw Error(c);};
const quote=s=>"'"+s.replaceAll("'","'\\''")+"'";

// BusyBox sh pipefail is used in a subshell, so no application shell option
// changes. Failed gzip trailers remain failures even if full bytes arrived.
// The bounded head and exact length/hash checks precede all source evaluation.
const BOOT=String.raw`
obs_program=$(set -o pipefail; printf '%s' "$obs_payload" | /bin/busybox base64 -d 2>/dev/null | /bin/busybox gzip -dc 2>/dev/null | /bin/busybox head -c $((obs_program_bytes+1))) || exit 81
[ \${#obs_program} -eq "$obs_program_bytes" ] || exit 81
obs_actual_hash=$(printf '%s' "$obs_program" | /bin/busybox sha256sum 2>/dev/null) || exit 81
[ "\${obs_actual_hash%% *}" = "$obs_program_hash" ] || exit 81
eval "$obs_program"
`.replaceAll('\\${','${').trim();
const BOOT_END=`\n}\nif obs_fixed_launch_main "$@"; then\n exec /usr/local/bin/entrypoint.sh\n exit 83\nelse\n exit $?\nfi`;
function bootstrap(d,head){return `${head}obs_payload=${quote(d.base64)}\nobs_program_bytes=${d.bytes}\nobs_program_hash=${quote(d.sha256)}\n${BOOT}${BOOT_END}`;}

const LIFECYCLE=String.raw`
obs_launch_cancelled=0
obs_launch_relay=''
obs_launch_relay_ticks=''
obs_launch_observer=''
obs_launch_observer_ticks=''
obs_launch_birth=0
obs_launch_armed=0
obs_launch_wire_bytes=0
obs_launch_poll_count=0
obs_launch_polllimit=0
obs_launch_failure=0
obs_launch_now(){
 local seconds
 seconds=$(/bin/busybox date +%s 2>/dev/null) || return 1
 case "$seconds" in ''|*[!0-9]*) return 1;; esac
 [ \${#seconds} -le 13 ] || return 1
 OBS_NOW_LOWER=$((seconds*1000)); OBS_NOW_UPPER=$(((seconds+1)*1000))
}
obs_launch_check(){
 [ "$obs_launch_cancelled" -eq 0 ] || return 1
 obs_launch_now || return 1
 [ "$OBS_NOW_UPPER" -lt "$1" ] || return 2
}
obs_launch_pause(){
 obs_launch_poll_count=$((obs_launch_poll_count+1))
 [ "$obs_launch_poll_count" -le "$obs_launch_polllimit" ] || return 1
 /bin/busybox sleep 0.01 2>/dev/null
}
obs_launch_identity(){
 local pid=$1 text rest
 case "$pid" in ''|*[!0-9]*) return 1;; esac
 text=$(/bin/busybox head -c 4097 /proc/$pid/stat 2>/dev/null) || return 1
 [ \${#text} -le 4096 ] || return 1
 case "$text" in "$pid ("*') '*) ;; *) return 1;; esac
 rest=\${text##*) }; set -- $rest; [ "$#" -ge 20 ] || return 1
 OBS_LAUNCH_STATE=$1; OBS_LAUNCH_PPID=$2; shift 19; OBS_LAUNCH_TICKS=$1
 case "$OBS_LAUNCH_PPID:$OBS_LAUNCH_TICKS" in *[!0-9:]*|:*|*:) return 1;; esac
 [ "$OBS_LAUNCH_TICKS" -gt 0 ]
}
obs_launch_parent(){
 obs_launch_identity "$OBS_PARENT_PID" && [ "$OBS_LAUNCH_TICKS" = "$OBS_PARENT_TICKS" ]
}
obs_launch_signal(){ obs_launch_cancelled=1; }
obs_launch_close(){ exec 3<&- 4>&- 5<&- 6>&-; }
obs_launch_kill(){
 local pid=$1 ticks=$2
 [ -n "$pid" ] || return 0
 if obs_launch_identity "$pid"; then
  [ "$OBS_LAUNCH_TICKS" = "$ticks" ] || return 1
  case "$OBS_LAUNCH_STATE" in Z|X) return 0;; esac
  kill -TERM "$pid" 2>/dev/null || return 1
 elif [ -e /proc/$pid/stat ]; then return 1
 fi
}
obs_launch_wait_absent(){
 local pid=$1 ticks=$2
 [ -n "$pid" ] || return 0
 while [ -e /proc/$pid/stat ]; do
  obs_launch_identity "$pid" && [ "$OBS_LAUNCH_TICKS" = "$ticks" ] || return 1
  obs_launch_now && [ "$OBS_NOW_UPPER" -lt "$OBS_DEADLINE" ] || return 1
  obs_launch_pause || return 1
 done
}
obs_launch_relay_exited(){
 local deadline=$1 cleanup=$2
 case "$obs_launch_relay_ticks" in ''|*[!0-9]*) return 1;; esac
 [ "$obs_launch_relay_ticks" -gt 0 ] || return 1
 while :; do
  [ "$cleanup" -eq 1 ] || [ "$obs_launch_cancelled" -eq 0 ] || return 1
  obs_launch_now || return 1
  [ "$OBS_NOW_UPPER" -lt "$deadline" ] || return 2
  if obs_launch_identity "$obs_launch_relay"; then
   [ "$OBS_LAUNCH_TICKS" = "$obs_launch_relay_ticks" ] && [ "$OBS_LAUNCH_PPID" = "$$" ] || return 1
   case "$OBS_LAUNCH_STATE" in Z|X) return 0;; esac
  else
   # A read failure for a live process is unknown, never permission to wait.
   # For the previously identified owned child, disappearance from proc and
   # the PID namespace permits the already-terminal shell wait status read.
   [ ! -e /proc/$obs_launch_relay/stat ] && ! kill -0 "$obs_launch_relay" 2>/dev/null || return 1
   return 0
  fi
  obs_launch_pause || return 1
 done
}
obs_launch_no_children(){
 local deadline=$1 children status
 while :; do
  obs_launch_now || return 1
  [ "$OBS_NOW_UPPER" -lt "$deadline" ] || return 2
  exec 19</proc/$$/task/$$/children || return 1
  children=''; status=0; IFS= read -r -n 4097 children <&19 || status=$?
  exec 19<&- || return 1
  [ \${#children} -le 4096 ] || return 1
  [ "$status" -eq 1 ] && [ -z "$children" ] && return 0
  case "$children" in *[!0-9\ ]*) return 1;; esac
  # Process-substitution creators are reaped by the shell. An unexpected
  # live/stopped child cannot turn this into an unbounded catch-all wait.
  obs_launch_pause || return 1
 done
}
obs_launch_join_relay(){
 local status=0
 [ -n "$obs_launch_relay" ] || return 0
 obs_launch_relay_exited "$OBS_ARM_DEADLINE" 0 || return $?
 wait "$obs_launch_relay" || status=$?
 obs_launch_relay=''; obs_launch_relay_ticks=''
 [ "$status" -eq 0 ]
}
obs_launch_cleanup(){
 local failure=0
 obs_launch_close || failure=1
 obs_launch_now && [ "$OBS_NOW_UPPER" -lt "$OBS_DEADLINE" ] || return 1
 obs_launch_kill "$obs_launch_relay" "$obs_launch_relay_ticks" || failure=1
 obs_launch_kill "$obs_launch_observer" "$obs_launch_observer_ticks" || failure=1
 # A killed relay is still explicitly reaped; its nonzero exit cannot make
 # arming successful but does not erase confirmation of physical cleanup.
 if [ -n "$obs_launch_relay" ]; then
  if obs_launch_relay_exited "$OBS_DEADLINE" 1; then
   wait "$obs_launch_relay" 2>/dev/null || :
   obs_launch_relay=''; obs_launch_relay_ticks=''
  else failure=1
  fi
 fi
 obs_launch_wait_absent "$obs_launch_observer" "$obs_launch_observer_ticks" || failure=1
 [ -z "$obs_launch_relay" ] || return 1
 obs_launch_no_children "$OBS_DEADLINE" || failure=1
 [ "$obs_launch_birth" -eq 1 ] || failure=1
 [ "$failure" -eq 0 ]
}
obs_launch_record(){
 local line=$1 kind pid ticks nonce extra
 obs_launch_wire_bytes=$((obs_launch_wire_bytes+\${#line}+1))
 [ "$obs_launch_wire_bytes" -le 1024 ] || return 1
 IFS='|' read -r kind pid ticks nonce extra <<OBS_ARM_RECORD
$line
OBS_ARM_RECORD
 [ -z "$extra" ] && [ "$nonce" = "$OBS_LAUNCH_NONCE" ] || return 1
 [ "$line" = "$kind|$pid|$ticks|$nonce" ] || return 1
 case "$pid:$ticks" in *[!0-9:]*|:*|*:) return 1;; esac
 [ "$pid" -gt 0 ] && [ "$ticks" -gt 0 ] && [ \${#pid} -le 16 ] && [ \${#ticks} -le 16 ] || return 1
 case "$kind" in
  B) [ "$obs_launch_birth" -eq 0 ] && [ "$obs_launch_armed" -eq 0 ] || return 1
     obs_launch_observer=$pid; obs_launch_observer_ticks=$ticks; obs_launch_birth=1;;
  A) [ "$obs_launch_birth" -eq 1 ] && [ "$obs_launch_armed" -eq 0 ] && [ "$pid:$ticks" = "$obs_launch_observer:$obs_launch_observer_ticks" ] || return 1
     obs_launch_armed=1;;
  *) return 1;;
 esac
}
obs_launch_read(){
 local line='' result=0
 IFS= read -r -n 1025 -t 0.01 line <&3 || result=$?
 [ \${#line} -le 1024 ] || return 1
 if [ "$result" -eq 0 ]; then obs_launch_record "$line" || return 1
 elif [ -n "$line" ]; then return 1
 fi
}
obs_launch_normal(){
 [ "$obs_launch_cancelled" -eq 0 ] || return 1
 obs_launch_close || return 1
 trap - TERM INT PIPE
 # The outer bootstrap execs only after the function scope has restored all
 # inherited application environment variables, including colliding names.
 [ "$obs_launch_cancelled" -eq 0 ]
}
obs_launch_coordinate(){
 local result=0 childlist line status
 trap obs_launch_signal TERM INT PIPE
 obs_busybox_common_gate || return 1
 obs_launch_now || return 1
 if [ "$OBS_NOW_LOWER" -lt "$OBS_STARTED" ] || [ "$OBS_NOW_UPPER" -ge "$OBS_LATEST_ARM" ]; then obs_launch_normal; return $?; fi
 OBS_ARM_DEADLINE=$((OBS_NOW_LOWER+OBS_ARM_LIMIT))
 [ "$OBS_ARM_DEADLINE" -le $((OBS_LATEST_ARM+OBS_ARM_LIMIT)) ] || return 1
 obs_launch_polllimit=$(((OBS_DEADLINE-OBS_STARTED+9)/10))
 OBS_PARENT_PID=$$
 obs_launch_identity "$$" || return 1; OBS_PARENT_TICKS=$OBS_LAUNCH_TICKS
 # Two private anonymous FIFOs. No log stream is used as a handshake and no
 # inherited application descriptor/open-file flags are changed.
 exec 3< <(:)
 exec 4>/proc/$$/fd/3
 exec 5< <(:)
 exec 6>/proc/$$/fd/5
 /bin/busybox env -i PATH=/bin:/usr/bin /bin/busybox sh -c "$obs_bootstrap" relay "$OBS_PARENT_PID" "$OBS_PARENT_TICKS" "$OBS_ARM_DEADLINE" 3<&- 6>&- &
 obs_launch_relay=$!
 if obs_launch_identity "$obs_launch_relay"; then obs_launch_relay_ticks=$OBS_LAUNCH_TICKS; else obs_launch_failure=1; fi
 exec 4>&- 5<&-
 while [ "$obs_launch_birth" -eq 0 ] && [ "$obs_launch_failure" -eq 0 ]; do
  status=0; obs_launch_check "$OBS_ARM_DEADLINE" || status=$?
  if [ "$status" -ne 0 ]; then if [ "$status" -eq 2 ]; then result=2; else obs_launch_failure=1; fi; break; fi
  obs_launch_read && obs_launch_pause || { obs_launch_failure=1; break; }
 done
 if [ "$result" -eq 0 ] && [ "$obs_launch_failure" -eq 0 ]; then
  status=0; obs_launch_join_relay || status=$?
  if [ "$status" -eq 2 ]; then result=2; elif [ "$status" -ne 0 ]; then obs_launch_failure=1; fi
  if [ "$result" -eq 0 ] && [ "$obs_launch_failure" -eq 0 ]; then
   obs_launch_identity "$obs_launch_observer" && [ "$OBS_LAUNCH_TICKS:$OBS_LAUNCH_PPID" = "$obs_launch_observer_ticks:1" ] || obs_launch_failure=1
  fi
  if [ "$result" -eq 0 ] && [ "$obs_launch_failure" -eq 0 ]; then
   printf '%s\n' "$OBS_LAUNCH_NONCE" >&6 || obs_launch_failure=1
  fi
  exec 6>&-
 fi
 while [ "$result" -eq 0 ] && [ "$obs_launch_failure" -eq 0 ] && [ "$obs_launch_armed" -eq 0 ]; do
  status=0; obs_launch_check "$OBS_ARM_DEADLINE" || status=$?
  if [ "$status" -ne 0 ]; then if [ "$status" -eq 2 ]; then result=2; else obs_launch_failure=1; fi; break; fi
  obs_launch_read && obs_launch_pause || { obs_launch_failure=1; break; }
 done
 if [ "$result" -eq 0 ] && [ "$obs_launch_failure" -eq 0 ]; then
  obs_launch_identity "$obs_launch_observer" && [ "$OBS_LAUNCH_TICKS:$OBS_LAUNCH_PPID" = "$obs_launch_observer_ticks:1" ] || obs_launch_failure=1
  while [ -e /proc/$obs_launch_observer/fd/4 ]; do
   status=0; obs_launch_check "$OBS_ARM_DEADLINE" || status=$?
   if [ "$status" -ne 0 ]; then if [ "$status" -eq 2 ]; then result=2; else obs_launch_failure=1; fi; break; fi
   obs_launch_read && obs_launch_pause || { obs_launch_failure=1; break; }
  done
  # Relay reaped; parent writer closed; observer writer physically closed.
  # A final read must be empty EOF, never a trailing/unknown arm record.
  if [ "$result" -eq 0 ] && [ "$obs_launch_failure" -eq 0 ]; then
   line=''; status=0; IFS= read -r -n 1025 -t 0.01 line <&3 || status=$?
   [ "$status" -eq 1 ] && [ -z "$line" ] || obs_launch_failure=1
   status=0; obs_launch_check "$OBS_ARM_DEADLINE" || status=$?
   if [ "$status" -eq 2 ]; then result=2; elif [ "$status" -ne 0 ]; then obs_launch_failure=1; fi
  fi
 fi
 if [ "$result" -eq 0 ] && [ "$obs_launch_failure" -eq 0 ]; then
  obs_launch_close || return 1
  status=0; obs_launch_no_children "$OBS_ARM_DEADLINE" || status=$?
  if [ "$status" -eq 0 ]; then obs_launch_normal; return $?; fi
  if [ "$status" -eq 2 ]; then result=2; else obs_launch_failure=1; fi
 fi
 obs_launch_cleanup || return 1
 [ "$result" -eq 2 ] && [ "$obs_launch_failure" -eq 0 ] && [ "$obs_launch_cancelled" -eq 0 ] || return 1
 obs_busybox_common_gate || return 1
 obs_launch_normal
}
obs_launch_relay_entry(){
 local child ticks
 trap obs_launch_signal TERM INT PIPE
 /bin/busybox env -i PATH=/bin:/usr/bin /bin/busybox sh -c "$obs_bootstrap" observer "$OBS_PARENT_PID" "$OBS_PARENT_TICKS" "$OBS_ARM_DEADLINE" 5<&5 4>&4 &
 child=$!
 obs_launch_identity "$child" || return 1; ticks=$OBS_LAUNCH_TICKS
 printf 'B|%s|%s|%s\n' "$child" "$ticks" "$OBS_LAUNCH_NONCE" >&4 || { kill -TERM "$child" 2>/dev/null; wait "$child" 2>/dev/null; return 1; }
 # Explicit exit (not a waiting shell) leaves the observer under the task's
 # real init. It cannot begin collection until the original parent sends GO.
 exec 4>&- 5<&-
 return 0
}
obs_launch_observe(){
 local token='' result=0 ticks exe command capture
 trap obs_launch_signal TERM INT PIPE
 obs_launch_now || return 1
 obs_launch_polllimit=$(((OBS_DEADLINE-OBS_STARTED+9)/10))
 while :; do
  obs_launch_check "$OBS_ARM_DEADLINE" && obs_launch_parent || return 1
  obs_launch_identity "$$" || return 1
  [ "$OBS_LAUNCH_PPID" -ne 1 ] || break
  obs_launch_pause || return 1
 done
 ticks=$OBS_LAUNCH_TICKS
 while [ -z "$token" ]; do
  obs_launch_check "$OBS_ARM_DEADLINE" && obs_launch_parent || return 1
  result=0; IFS= read -r -n 129 -t 0.01 token <&5 || result=$?
  if [ "$result" -ne 0 ]; then [ -z "$token" ] || return 1; obs_launch_pause || return 1; fi
 done
 [ "$result" -eq 0 ] && [ "$token" = "$OBS_LAUNCH_NONCE" ] || return 1
 exec 5<&-
 obs_busybox_common_gate && obs_launch_check "$OBS_ARM_DEADLINE" && obs_launch_parent || return 1
 printf 'A|%s|%s|%s\n' "$$" "$ticks" "$OBS_LAUNCH_NONCE" >&4 || return 1
 exec 4>&-
 while :; do
  obs_launch_check "$OBS_FIRST_SAMPLE" && obs_launch_parent || return 1
  exe=$(/bin/busybox readlink /proc/$OBS_PARENT_PID/exe 2>/dev/null) || return 1
  if [ "$exe" = /usr/local/bin/mnemo-server ]; then
   command=$(/bin/busybox head -c 16385 /proc/$OBS_PARENT_PID/cmdline | /bin/busybox sha256sum) || return 1
   [ "\${command%% *}" = "$OBS_MAIN_ARGV_HASH" ] || return 1
   break
  fi
  obs_launch_pause || return 1
 done
 obs_episode_prepare || { obs_collect_close || :; return 1; }
 @@EPISODES@@
 obs_collect_close || return 1
 trap - TERM INT PIPE
 return 0
}
`.replaceAll('\\${','${');

export function compileObservedBusyboxDataLaunch(input){
 const v=copyNonrootJson(input);need(v&&Object.keys(v).sort().join()==='files,original,plan','DataObservationLaunchInput');
 const plan=inspectDataObservationPlan(v.plan);need(plan.role==='mnemo-server','DataObservationBusyboxRole');
 const files=inspectObservationGateFiles(v.files),normal=dataLaunchPolicy(plan.role,v.original),schedule=describeDataObservationSchedule(plan);
 need(normal.image.endsWith('@'+plan.image.rootDigest)&&normal.linuxParameters?.initProcessEnabled===true,'DataObservationLaunchImage');
 need(normal.entryPoint.slice(3).join()==='/usr/local/bin/entrypoint.sh'&&(normal.command??[]).length===0,'DataObservationLaunchArgv');
 for(const p of ['/bin/busybox','/bin/sh','/bin/setpriv','/lib/ld-musl-aarch64.so.1','/usr/local/bin/entrypoint.sh','/usr/local/bin/mnemo-server'])need(files.some(f=>f.path===p),'DataObservationLaunchFiles');
 need(schedule.episodes.at(-1).completedMs<plan.observationEndMs,'DataObservationEmissionWindow');
 const main=files.find(f=>f.path==='/usr/local/bin/mnemo-server'),busybox=files.find(f=>f.path==='/bin/busybox');
 need(main.resolvedPath===main.path&&busybox.resolvedPath===busybox.path,'DataObservationLaunchFiles');
 const healthArgv=targetHealthArgv({prefix:normal.entryPoint.slice(0,3),healthLaunch:{kind:'fixed-health-nnp',before:v.original.healthCheck.command,after:normal.healthCheck.command}});
 const binding=nonrootHash({planHash:schedule.planHash,normal,files}),mainHash=targetCmdlineHash(['/usr/local/bin/mnemo-server']),healthHashes=healthArgv.map(targetCmdlineHash);
 const globals={OBS_STARTED:plan.startedMs,OBS_LATEST_ARM:plan.latestArmMs,OBS_ARM_LIMIT:plan.armingLimitMs,OBS_DEADLINE:plan.deadlineMs,OBS_FIRST_SAMPLE:schedule.episodes[0].startedMs,
  OBS_COLLECT_DEADLINE_MS:plan.observationEndMs,OBS_MAIN_DIGEST:main.sha256,OBS_HEALTH_DIGEST:busybox.sha256,OBS_MAIN_ARGV_HASH:mainHash,OBS_HEALTH_ARGV_HASHES:healthHashes.join(' '),OBS_PLAN_HASH:schedule.planHash,OBS_LAUNCH_NONCE:plan.launchNonce,OBS_BINDING:binding};
 const episodes=schedule.episodes.map(e=>`obs_busybox_episode ${e.index} ${e.startedMs} ${e.completedMs} ${e.sampleEveryMs} || return 1
capture=$(printf '%s|%s|%s|%s' "$OBS_LAUNCH_NONCE" "$$" "$ticks" ${e.index} | /bin/busybox sha256sum) || return 1
capture=\${capture%% *}; capture=\${capture:0:32}
obs_emit_busybox "$OBS_EPISODE_RESULT" "$OBS_BINDING" "$capture" ${plan.observationEndMs} || return 1
trap obs_launch_signal TERM INT PIPE`).join('\n');
 let source=[busyboxObservationGateSource(files),busyboxObservationCollectorSource(),busyboxObservationEpisodeSource(),busyboxObservationOutputSource(),
  Object.entries(globals).map(([k,x])=>k+'='+quote(String(x))).join('\n'),LIFECYCLE.replace('@@EPISODES@@',episodes),
  `obs_loader_head=@@BOOT_HEAD@@
obs_loader_source=${quote(BOOT)}
obs_loader_end=${quote(BOOT_END)}
obs_bootstrap="$obs_loader_head""obs_payload='$obs_payload'
obs_program_bytes=$obs_program_bytes
obs_program_hash='$obs_program_hash'
$obs_loader_source$obs_loader_end"
case "$0" in
 coordinator) [ "$#" -eq 0 ] || exit 82; obs_launch_coordinate; return $?;;
 relay|observer)
  [ "$#" -eq 3 ] || exit 82
  case "$1:$2:$3" in *[!0-9:]*|:*|*::*|*:) exit 82;; esac
  OBS_PARENT_PID=$1; OBS_PARENT_TICKS=$2; OBS_ARM_DEADLINE=$3
  [ "$1" -gt 0 ] && [ "$2" -gt 0 ] && [ "$3" -gt 0 ] && [ "$3" -le $((OBS_LATEST_ARM+OBS_ARM_LIMIT)) ] || exit 82
  if [ "$0" = relay ]; then obs_launch_relay_entry; exit $?; fi
  obs_launch_observe; result=$?
  obs_collect_close || result=84
  obs_launch_close || result=84
  exit "$result";;
 *) exit 82;;
esac
# fixed-source-end`].join('\n');
 // Scope every fixed observer variable so an existing exported variable
 // with the same name is restored before the original application exec.
 // This inspects our own fixed source, never application environment values.
 const names=new Set(['obs_payload','obs_program_bytes','obs_program_hash','obs_program','obs_actual_hash','obs_loader_head','obs_loader_source','obs_loader_end','obs_bootstrap','result','LC_ALL']);
 for(const m of source.matchAll(/\b((?:OBS_|obs_)[A-Za-z0-9_]+)=/g))names.add(m[1]);
 const bootstrapNames=['obs_payload','obs_program_bytes','obs_program_hash','obs_program','obs_actual_hash'];
 const head='obs_fixed_launch_main(){\n local '+bootstrapNames.join(' ')+'\n';
 // The full local declarations belong to the same hashed/compressed source;
 // none is omitted to fit argv. Only loader variables precede source decode.
 source='local '+[...names].filter(n=>!bootstrapNames.includes(n)).sort().join(' ')+'\n'+source.replace('@@BOOT_HEAD@@',quote(head));
 need(Buffer.from(source).every(b=>b<128),'DataObservationSourceAscii');
 const compressed=gzipSync(Buffer.from(source),{level:9}),descriptor={bytes:Buffer.byteLength(source),sha256:sha(Buffer.from(source)),base64:compressed.toString('base64')},program=bootstrap(descriptor,head);
 const cmdlineBytes=Buffer.byteLength(['/bin/busybox','sh','-c',program,'coordinator'].join('\0')+'\0')+3*17;
 need(cmdlineBytes<=16384,'DataObservationSourceArgvBound');
 return copyNonrootJson({version:2,kind:'observed-busybox-data-launch',plan,normal,target:{...normal,entryPoint:[...normal.entryPoint.slice(0,3),'/bin/busybox','sh','-c',program,'coordinator'],command:[]},binding,
  sourceHash:sha(Buffer.from(program)),sourceBytes:Buffer.byteLength(program),delivery:{kind:'fixed-busybox-gzip-source-v1',sourceHash:descriptor.sha256,sourceBytes:descriptor.bytes,compressedHash:sha(compressed),compressedBytes:compressed.length,bootstrapHash:sha(Buffer.from(program)),bootstrapBytes:Buffer.byteLength(program),cmdlineBytes,processes:['coordinator','relay','observer'],maximumInvocations:3},
  snapshotCount:schedule.snapshotCount+schedule.episodes.length,healthCmdlineHashes:healthHashes,mainCmdlineHash:mainHash});
}
