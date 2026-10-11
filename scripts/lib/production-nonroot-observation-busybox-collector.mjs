/** Source-bound BusyBox proc collector. Raw records use the shared strict
 * decoder; they confer no source, image, policy or funding authority. */
import {copyNonrootJson} from './production-nonroot-contracts.mjs';
import {decodeBusyboxObservationProcess} from './production-nonroot-observation-busybox-records.mjs';
import {types} from 'node:util';

const SOURCE=String.raw`
obs_collect_bb=/bin/busybox
OBS_COLLECT_READ_BYTES=0
OBS_COLLECT_MOVEMENT_BYTES=0
OBS_COLLECT_HELPERS=0
obs_collect_next=20
obs_collect_cache=''
obs_collect_clock(){
 OBS_COLLECT_HELPERS=$((OBS_COLLECT_HELPERS+1))
 OBS_COLLECT_SECONDS=$($obs_collect_bb date +%s 2>/dev/null) || return 1
 case "$OBS_COLLECT_SECONDS:$OBS_COLLECT_DEADLINE_MS" in *[!0-9:]*|:*|*:) return 1;; esac
 [ $(((OBS_COLLECT_SECONDS+1)*1000)) -lt "$OBS_COLLECT_DEADLINE_MS" ]
}
obs_collect_allow(){
 obs_collect_clock || return 1
 [ $((OBS_COLLECT_READ_BYTES+$1)) -le 268435456 ]
}
obs_collect_hex(){
 local path=$1 cap=$2 result bytes
 obs_collect_allow $((cap+1)) || return 1
 OBS_COLLECT_HELPERS=$((OBS_COLLECT_HELPERS+3))
 result=$($obs_collect_bb head -c $((cap+1)) "$path" 2>/dev/null | $obs_collect_bb od -An -v -tx1 2>/dev/null | $obs_collect_bb tr -d ' \n' 2>/dev/null) || return 1
 bytes=$((\${#result}/2)); OBS_COLLECT_READ_BYTES=$((OBS_COLLECT_READ_BYTES+bytes)); OBS_COLLECT_MOVEMENT_BYTES=$((OBS_COLLECT_MOVEMENT_BYTES+bytes*16))
 [ "$bytes" -le "$cap" ] || return 1
 OBS_COLLECT_HEX=$result
}
obs_collect_stamp(){
 OBS_COLLECT_HELPERS=$((OBS_COLLECT_HELPERS+1))
 OBS_COLLECT_STAMP=$($obs_collect_bb stat -Lc '%d,%i,%s,%f,%u,%g,%y,%z' "$1" 2>/dev/null) || return 1
 [ \${#OBS_COLLECT_STAMP} -le 1024 ] || return 1
 OBS_COLLECT_MOVEMENT_BYTES=$((OBS_COLLECT_MOVEMENT_BYTES+\${#OBS_COLLECT_STAMP}))
}
obs_collect_file(){
 local path=$1 before rest size mode entry cachedfd value='' output n line fd
 exec 4<"$path" || return 1
 obs_collect_stamp /proc/$$/fd/4 || return 1; before=$OBS_COLLECT_STAMP
 rest=\${before#*,}; rest=\${rest#*,}; size=\${rest%%,*}; rest=\${rest#*,}; mode=\${rest%%,*}
 case "$size:$mode" in *[!0-9a-f:]*) return 1;; esac
 [ "$size" -gt 0 ] && [ "$size" -le 201326592 ] && [ $((0x$mode&61440)) -eq 32768 ] || return 1
 while IFS='|' read -r entry cachedfd line; do
  [ "$entry" = "$before" ] || continue
  obs_collect_stamp /proc/$$/fd/$cachedfd || return 1
  [ "$entry" = "$OBS_COLLECT_STAMP" ] || return 1; value=$line
 done <<OBS_CACHE
$obs_collect_cache
OBS_CACHE
 if [ -z "$value" ]; then
  obs_collect_allow $((size+1)) || return 1
  OBS_COLLECT_HELPERS=$((OBS_COLLECT_HELPERS+4))
  output=$( { { $obs_collect_bb head -c $((size+1)) <&4 2>/dev/null | $obs_collect_bb tee /proc/self/fd/5 2>/dev/null | $obs_collect_bb sha256sum 2>/dev/null >&6; } 5>&1 | $obs_collect_bb wc -c 2>/dev/null; } 6>&1 ) || return 1
  n=''
  while IFS= read -r line; do case "$line" in *'  -') value=\${line%% *};; *) n=$line;; esac; done <<OBS_HASH
$output
OBS_HASH
  [ "$n" = "$size" ] && [ \${#value} -eq 64 ] || return 1
  OBS_COLLECT_READ_BYTES=$((OBS_COLLECT_READ_BYTES+n)); OBS_COLLECT_MOVEMENT_BYTES=$((OBS_COLLECT_MOVEMENT_BYTES+5*n))
  [ "$obs_collect_next" -le 275 ] || return 1
  fd=$obs_collect_next; obs_collect_next=$((obs_collect_next+1)); eval "exec $fd<&4" || return 1
  obs_collect_cache="$obs_collect_cache$before|$fd|$value
"
 fi
 obs_collect_stamp /proc/$$/fd/4 || return 1; [ "$before" = "$OBS_COLLECT_STAMP" ] || return 1
 exec 4<&-
 OBS_COLLECT_FILE_STAMP=$before; OBS_COLLECT_FILE_DIGEST=$value
}
obs_collect_proc(){
 local pid=$1 first status command after path pathhex stamp digest again cmdhash
 case "$pid" in ''|*[!0-9]*) return 1;; esac; [ "$pid" -gt 0 ] || return 1
 obs_collect_hex /proc/$pid/stat 4096 || return 1; first=$OBS_COLLECT_HEX
 obs_collect_hex /proc/$pid/status 65536 || return 1; status=$OBS_COLLECT_HEX
 obs_collect_hex /proc/$pid/cmdline 16384 || return 1; command=$OBS_COLLECT_HEX
 obs_collect_allow 4097 || return 1; OBS_COLLECT_HELPERS=$((OBS_COLLECT_HELPERS+1))
 path=$($obs_collect_bb readlink /proc/$pid/exe 2>/dev/null) || return 1
 case "$path" in /*) ;; *) return 1;; esac; case "$path" in *' (deleted)') return 1;; esac
 [ \${#path} -le 4096 ] || return 1; OBS_COLLECT_READ_BYTES=$((OBS_COLLECT_READ_BYTES+\${#path}))
 obs_collect_file /proc/$pid/exe || return 1; stamp=$OBS_COLLECT_FILE_STAMP; digest=$OBS_COLLECT_FILE_DIGEST
 obs_collect_hex /proc/$pid/stat 4096 || return 1; after=$OBS_COLLECT_HEX
 obs_collect_hex /proc/$pid/cmdline 16384 || return 1; [ "$command" = "$OBS_COLLECT_HEX" ] || return 1
 obs_collect_allow 4097 || return 1; OBS_COLLECT_HELPERS=$((OBS_COLLECT_HELPERS+1))
 again=$($obs_collect_bb readlink /proc/$pid/exe 2>/dev/null) || return 1; [ "$again" = "$path" ] || return 1
 OBS_COLLECT_READ_BYTES=$((OBS_COLLECT_READ_BYTES+\${#again})); OBS_COLLECT_HELPERS=$((OBS_COLLECT_HELPERS+4))
 pathhex=$(printf '%s' "$path" | $obs_collect_bb od -An -v -tx1 2>/dev/null | $obs_collect_bb tr -d ' \n' 2>/dev/null) || return 1
 cmdhash=$(printf '%s' "$command" | $obs_collect_bb xxd -r -p 2>/dev/null | $obs_collect_bb sha256sum 2>/dev/null) || return 1; cmdhash=\${cmdhash%% *}
 OBS_COLLECT_MOVEMENT_BYTES=$((OBS_COLLECT_MOVEMENT_BYTES+\${#path}*16+\${#command}*8))
 OBS_COLLECT_ROW=$(printf '{"pid":%s,"stat":"%s","statAfter":"%s","status":"%s","cmdlineHash":"%s","path":"%s","stamp":"%s","digest":"%s"}' "$pid" "$first" "$after" "$status" "$cmdhash" "$pathhex" "$stamp" "$digest")
 [ \${#OBS_COLLECT_ROW} -le 196608 ] || return 1
 OBS_COLLECT_MOVEMENT_BYTES=$((OBS_COLLECT_MOVEMENT_BYTES+\${#OBS_COLLECT_ROW}))
 OBS_COLLECT_ROW_PATH=$path; OBS_COLLECT_ROW_DIGEST=$digest; OBS_COLLECT_ROW_CMDLINE=$cmdhash; OBS_COLLECT_ROW_STATUS=$status
}
obs_collect_snapshot(){
 local ids='' path count=0 pid separator=''
 for path in /proc/[0-9]*; do count=$((count+1)); [ "$count" -le 128 ] || return 1; ids="$ids \${path##*/}"; done
 [ "$count" -gt 0 ] || return 1
 OBS_COLLECT_READ_BYTES=$((OBS_COLLECT_READ_BYTES+\${#ids})); OBS_COLLECT_SNAPSHOT=''
 for pid in $ids; do
  obs_collect_proc "$pid" || return 1
  OBS_COLLECT_SNAPSHOT="$OBS_COLLECT_SNAPSHOT$separator$OBS_COLLECT_ROW"; separator=,
  [ \${#OBS_COLLECT_SNAPSHOT} -le 1048576 ] || return 1
 done
}
obs_collect_close(){
 local fd=20 key expected digest status=0
 while IFS='|' read -r expected fd digest; do
  [ -n "$fd" ] || continue
  obs_collect_stamp /proc/$$/fd/$fd && [ "$OBS_COLLECT_STAMP" = "$expected" ] || status=1
 done <<OBS_CLOSE_CHECK
$obs_collect_cache
OBS_CLOSE_CHECK
 fd=20
 while [ "$fd" -lt "$obs_collect_next" ]; do eval "exec $fd<&-" || status=1; fd=$((fd+1)); done
 exec 4<&- || status=1
 obs_collect_next=20; obs_collect_cache=''
 return "$status"
}
`.replaceAll('\\${','${');

export function busyboxObservationCollectorSource(){
 if(arguments.length)throw Error('DataObservationBusyboxCollectorSource');
 return SOURCE;
}

/** Strict DATA decode only; actual task/source/image and policy replay follow.
 * Callers prepay the decoder's full per-row obligations before invoking this. */
export function decodeBusyboxObservationRows(input){
 if(!Array.isArray(input)||types.isProxy(input)||input.length===0||input.length>128)throw Error('DataObservationBusyboxRows');
 const rows=copyNonrootJson(input);
 const decoded=rows.map(decodeBusyboxObservationProcess);
 if(new Set(decoded.map(p=>p.pid)).size!==decoded.length)throw Error('DataObservationBusyboxDuplicatePid');
 return copyNonrootJson(decoded);
}
