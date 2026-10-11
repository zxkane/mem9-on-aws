/** Fixed BusyBox common gate source for observed and later normal Go launches.
 * File rows are authenticated by the caller's complete image/source replay. */
import {inspectObservationGateFiles} from './production-nonroot-observation-gate.mjs';

const SOURCE=String.raw`
obs_gate_bb=/bin/busybox
obs_gate_held=''
obs_gate_next=10
obs_gate_newline='
'
OBS_GATE_READ_BYTES=0
obs_gate_read(){
 local value
 value=$($obs_gate_bb head -c $(($2+1)) "$1" 2>/dev/null && printf '.') || return 1
 OBS_GATE_TEXT=\${value%.}
 OBS_GATE_READ_BYTES=$((OBS_GATE_READ_BYTES+\${#OBS_GATE_TEXT}))
 [ \${#OBS_GATE_TEXT} -le "$2" ] || return 1
 while [ "\${OBS_GATE_TEXT%"$obs_gate_newline"}" != "$OBS_GATE_TEXT" ]; do OBS_GATE_TEXT=\${OBS_GATE_TEXT%"$obs_gate_newline"}; done
}
obs_gate_status(){
 local line key value seen='|' count=0
 obs_gate_read /proc/$$/status 65536 || return 1
 while IFS= read -r line; do
  key=\${line%%:*}; value=\${line#*:}; [ "$key" != "$line" ] || return 1
  case "$key" in ''|*[!A-Za-z0-9_]*) return 1;; esac
  case "$seen" in *"|$key|"*) return 1;; esac; seen="$seen$key|"
  case "$key" in
   Uid|Gid) set -- $value; [ "$#" -eq 4 ] && [ "$1:$2:$3:$4" = 1000:1000:1000:1000 ] || return 1; count=$((count+1));;
   Groups) set -- $value; for value in "$@"; do [ "$value" = 1000 ] || return 1; done; count=$((count+1));;
   NoNewPrivs) set -- $value; [ "$#" -eq 1 ] && [ "$1" = 1 ] || return 1; count=$((count+1));;
   CapInh|CapPrm|CapEff|CapBnd|CapAmb) set -- $value; [ "$#" -eq 1 ] && [ "$1" = 0000000000000000 ] || return 1; count=$((count+1));;
  esac
 done <<OBS_STATUS
$OBS_GATE_TEXT
OBS_STATUS
 [ "$count" -eq 9 ]
}
obs_gate_stamp(){
 OBS_GATE_STAMP=$($obs_gate_bb stat -Lc '%D,%i,%s,%f,%u,%g,%y,%z' "$1" 2>/dev/null) || return 1
 [ \${#OBS_GATE_STAMP} -le 1024 ]
}
obs_gate_hex(){
 case "$1" in ''|*[!a-f0-9]*) return 1;; esac
 [ \${#1} -le "$2" ] || return 1
 OBS_GATE_HEX=$1
 while [ \${#OBS_GATE_HEX} -gt 1 ] && [ "\${OBS_GATE_HEX#0}" != "$OBS_GATE_HEX" ]; do OBS_GATE_HEX=\${OBS_GATE_HEX#0}; done
}
obs_gate_inode(){
 case "$1" in ''|*[!0-9]*) return 1;; esac
 OBS_GATE_INODE=$1
 while [ \${#OBS_GATE_INODE} -gt 1 ] && [ "\${OBS_GATE_INODE#0}" != "$OBS_GATE_INODE" ]; do OBS_GATE_INODE=\${OBS_GATE_INODE#0}; done
 [ \${#OBS_GATE_INODE} -le 20 ] || return 1
 if [ \${#OBS_GATE_INODE} -eq 20 ]; then
  [ "\${OBS_GATE_INODE#1}" != "$OBS_GATE_INODE" ] || return 1
  [ "\${OBS_GATE_INODE#1}" -le 8446744073709551615 ] || return 1
 fi
}
obs_gate_maps(){
 local ranges perms offset device inode name begin end major minor dev fd path resolved stamp digest size mode found executable=0 filedev fileino rest line
 [ -n "$1" ] && [ \${#1} -le 262144 ] || return 1
 while IFS= read -r line; do
  [ -n "$line" ] || continue
  case "$line" in [a-f0-9]*) ;; *) return 1;; esac
  read -r ranges perms offset device inode name <<OBS_MAP_ROW
$line
OBS_MAP_ROW
  [ -n "$ranges" ] || return 1
  case "$ranges" in *-*) begin=\${ranges%%-*}; end=\${ranges#*-};; *) return 1;; esac
  obs_gate_hex "$begin" 16 || return 1; begin=$OBS_GATE_HEX
  obs_gate_hex "$end" 16 || return 1; end=$OBS_GATE_HEX
  [ \${#begin} -lt \${#end} ] || { [ \${#begin} -eq \${#end} ] && [ "$begin" \< "$end" ]; } || return 1
  case "$perms" in [r-][w-][x-][ps]) ;; *) return 1;; esac
  obs_gate_hex "$offset" 16 || return 1
  case "$device" in *:*) major=\${device%%:*}; minor=\${device#*:};; *) return 1;; esac
  obs_gate_hex "$major" 8 || return 1; major=$OBS_GATE_HEX
  obs_gate_hex "$minor" 8 || return 1; minor=$OBS_GATE_HEX
  obs_gate_inode "$inode" || return 1; inode=$OBS_GATE_INODE
  if [ "$name" = 'anon_inode:[io_uring]' ]; then [ "$perms" = rw-s ] && [ "$major" = 0 ] && [ "$inode" != 0 ] || return 1; continue; fi
  case "$name" in '') continue;; '['*']') [ "$name" != '[]' ] || return 1; case "\${name#?}" in *']'*']'*) return 1;; esac; continue;; /*) ;; *) return 1;; esac
  [ "$inode" != 0 ] || return 1
  dev=$(((0x$major&4095)<<8 | (0x$major&4294963200)<<32 | (0x$minor&255) | (0x$minor&4294967040)<<12))
  dev=$(printf '%x' "$dev") || return 1; found=0
  while IFS='|' read -r fd path resolved stamp digest size mode; do
   [ -n "$fd" ] && [ "$resolved" = "$name" ] || continue
   filedev=\${stamp%%,*}; rest=\${stamp#*,}; fileino=\${rest%%,*}
   obs_gate_hex "$filedev" 16 || return 1; filedev=$OBS_GATE_HEX
   [ "$filedev" = "$dev" ] && [ "$fileino" = "$inode" ] || return 1; found=1
  done <<OBS_HELD
$obs_gate_held
OBS_HELD
  [ "$found" -eq 1 ] || return 1
  [ "$name" != /bin/busybox ] || case "$perms" in ??x?) executable=1;; esac
 done <<OBS_MAPS
$1
OBS_MAPS
 [ "$executable" -eq 1 ]
}
obs_gate_close(){
 local fd status=0
 fd=10; while [ "$fd" -lt "$obs_gate_next" ]; do eval "exec $fd<&-" || status=1; fd=$((fd+1)); done
 exec 9<&- || status=1
 obs_gate_next=10; obs_gate_held=''
 return "$status"
}
obs_gate_inner(){
 local path resolved digest size mode uid gid fd before actual rest dev inode actualSize actualMode actualUid actualGid result n line current firstexe
 [ "$($obs_gate_bb uname -m 2>/dev/null)" = aarch64 ] || return 1
 obs_gate_status || return 1
 [ "$($obs_gate_bb readlink /proc/$$/exe 2>/dev/null)" = /bin/busybox ] || return 1
 exec 9</proc/$$/exe || return 1
 obs_gate_stamp /proc/$$/fd/9 || return 1; firstexe=$OBS_GATE_STAMP
 while IFS='|' read -r path resolved digest size mode uid gid; do
  [ "$($obs_gate_bb readlink -f "$path" 2>/dev/null)" = "$resolved" ] || return 1
  fd=$obs_gate_next; obs_gate_next=$((obs_gate_next+1))
  # Only the compiler's closed paths and a locally generated FD enter eval.
  eval "exec $fd< '$path'" || return 1
  obs_gate_stamp /proc/$$/fd/$fd || return 1; before=$OBS_GATE_STAMP
  IFS=, read -r dev inode actualSize actualMode actualUid actualGid rest <<OBS_STAT
$before
OBS_STAT
  [ "$actualSize" = "$size" ] && [ $((0x$actualMode&61440)) -eq 32768 ] && [ $((0x$actualMode&4095)) -eq "$mode" ] && [ "$actualUid" = "$uid" ] && [ "$actualGid" = "$gid" ] || return 1
  result=$( { { $obs_gate_bb head -c $((size+1)) /proc/$$/fd/$fd 2>/dev/null | $obs_gate_bb tee /proc/self/fd/4 2>/dev/null | $obs_gate_bb sha256sum >&3; } 4>&1 | $obs_gate_bb wc -c; } 3>&1 ) || return 1
  actual=''; n=''
  while IFS= read -r line; do case "$line" in *'  -') actual=\${line%% *};; *) n=$line;; esac; done <<OBS_HASH
$result
OBS_HASH
  [ "$n" = "$size" ] && [ "$actual" = "$digest" ] || return 1
  OBS_GATE_READ_BYTES=$((OBS_GATE_READ_BYTES+n))
  obs_gate_stamp /proc/$$/fd/$fd || return 1; [ "$before" = "$OBS_GATE_STAMP" ] || return 1
  obs_gate_stamp "$path" || return 1; [ "$before" = "$OBS_GATE_STAMP" ] || return 1
  [ "$($obs_gate_bb readlink -f "$path" 2>/dev/null)" = "$resolved" ] || return 1
  obs_gate_held="$obs_gate_held$fd|$path|$resolved|$before|$digest|$size|$mode
"
  [ "$resolved" != /bin/busybox ] || [ "$before" = "$firstexe" ] || return 1
 done <<'OBS_EXPECTED_FILES'
@@FILES@@
OBS_EXPECTED_FILES
 obs_gate_read /proc/$$/maps 262144 || return 1
 obs_gate_maps "$OBS_GATE_TEXT" || return 1
 while IFS='|' read -r fd path resolved before digest size mode; do
  [ -n "$fd" ] || continue
  obs_gate_stamp /proc/$$/fd/$fd || return 1; [ "$before" = "$OBS_GATE_STAMP" ] || return 1
  obs_gate_stamp "$path" || return 1; [ "$before" = "$OBS_GATE_STAMP" ] || return 1
  [ "$($obs_gate_bb readlink -f "$path" 2>/dev/null)" = "$resolved" ] || return 1
 done <<OBS_RECHECK
$obs_gate_held
OBS_RECHECK
 obs_gate_stamp /proc/$$/fd/9 || return 1; [ "$firstexe" = "$OBS_GATE_STAMP" ] || return 1
 obs_gate_status
}
obs_busybox_common_gate(){
 local result=0
 obs_gate_inner || result=1
 obs_gate_close || result=1
 return "$result"
}
`.replaceAll('\\${','${');

export function busyboxObservationGateSource(input){
 const files=inspectObservationGateFiles(input);
 if(!files.some(f=>f.path==='/bin/busybox'&&f.resolvedPath==='/bin/busybox'))throw Error('DataObservationBusyboxGateFiles');
 return SOURCE.replace('@@FILES@@',files.map(f=>[f.path,f.resolvedPath,f.sha256,f.size,f.mode,f.uid,f.gid].join('|')).join('\n'));
}
