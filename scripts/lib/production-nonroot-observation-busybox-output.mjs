/** Fixed BusyBox DATA emitter. Original application descriptors are neither
 * redirected nor reconfigured. The caller separately owns source/payment,
 * task/log authentication and eventual observer retirement. */
import {copyNonrootJson} from './production-nonroot-contracts.mjs';
import {describeObservationFrameGeometry} from './production-nonroot-observation-frames.mjs';

const SOURCE=String.raw`
obs_bb=/bin/busybox
obs_writer_pid=''
obs_writer_ticks=''
obs_writer_parent=$$
obs_writer_failed=0
obs_clock(){
 local seconds fraction rest
 IFS=' ' read -r seconds rest 2>/dev/null < /proc/uptime || return 75
 case "$seconds" in *.*) fraction=\${seconds#*.}; seconds=\${seconds%%.*};; *) return 75;; esac
 case "$seconds:$fraction" in *[!0-9:]*|:*|*:) return 75;; esac
 [ \${#seconds} -le 12 ] && [ \${#fraction} -eq 2 ] || return 75
 OBS_TICKS=$((seconds*100+1$fraction-100))
}
obs_writer_identity(){
 local text rest
 IFS= read -r text 2>/dev/null < /proc/$obs_writer_pid/stat || return 1
 [ \${#text} -le 4096 ] || return 75
 case "$text" in "$obs_writer_pid ("*') '*) ;; *) return 75;; esac
 rest=\${text##*) }; set -- $rest
 [ "$#" -ge 20 ] || return 75
 OBS_WRITER_STATE=$1; OBS_WRITER_PPID=$2; shift 19; OBS_WRITER_TICKS=$1
 case "$OBS_WRITER_TICKS" in ''|*[!0-9]*) return 75;; esac
 [ "$OBS_WRITER_PPID" = "$obs_writer_parent" ] || return 75
 [ -z "$obs_writer_ticks" ] || [ "$OBS_WRITER_TICKS" = "$obs_writer_ticks" ] || return 75
}
obs_writer_cleanup(){
 local status=0
 # Release a child still waiting at its start barrier before joining it.
 exec 6>&- 8>&-
 if [ -n "$obs_writer_pid" ]; then
  if obs_writer_identity; then
   case "$OBS_WRITER_STATE" in Z|X) ;; *) kill -KILL "$obs_writer_pid" 2>/dev/null || status=76;; esac
  elif [ -e /proc/$obs_writer_pid/stat ]; then status=76
  fi
  wait "$obs_writer_pid" 2>/dev/null || :
  obs_writer_pid=''; obs_writer_ticks=''
 fi
 exec 5<&- 6>&- 7<&- 8>&-
 # Only the fixed ':' pipe creators can remain in this emitter's job table.
 wait || status=76
 return "$status"
}
obs_writer_cancel(){ obs_writer_failed=1; obs_writer_cleanup || :; }
obs_write_frame(){
 local frame=$1 size=$2 deadline=$3 go=$4 start now status childlist polls=0
 [ "$obs_writer_failed" -eq 0 ] || return 75
 now=$($obs_bb date +%s 2>/dev/null) || return 75
 [ $(((now+1)*1000+1000)) -le "$deadline" ] || return 75
 # Each empty private FIFO receives one bounded write. Neither FIFO is an
 # application stream; the inherited application open-file flags stay intact.
 exec 5< <(:)
 exec 6>/proc/$$/fd/5
 exec 7< <(:)
 exec 8>/proc/$$/fd/7
 (
  IFS= read -r token <&7 || exit 75
  [ "$token" = "$go" ] || exit 75
  exec /bin/busybox dd bs="$size" count=1 iflag=fullblock status=none <&5 >&2 2>/dev/null 5<&- 7<&-
 ) 6>&- 8>&- &
 obs_writer_pid=$!
 if ! obs_writer_identity; then obs_writer_cleanup || :; return 75; fi
 obs_writer_ticks=$OBS_WRITER_TICKS
 if ! printf '%s\n' "$frame" >&6; then obs_writer_cleanup || :; return 75; fi
 exec 6>&-
 obs_clock || { obs_writer_cleanup || :; return 75; }; start=$OBS_TICKS
 if ! printf '%s\n' "$go" >&8; then obs_writer_cleanup || :; return 75; fi
 exec 8>&- 5<&- 7<&-
 while obs_writer_identity; do
  case "$OBS_WRITER_STATE" in Z|X) break;; esac
  obs_clock || { obs_writer_cleanup || :; return 75; }
  if [ "$obs_writer_failed" -ne 0 ] || [ "$OBS_TICKS" -ge $((start+100)) ] || [ "$polls" -ge 100 ]; then obs_writer_cleanup || :; return 75; fi
  polls=$((polls+1))
  $obs_bb sleep 0.01 2>/dev/null || { obs_writer_cleanup || :; return 75; }
 done
 if [ -e /proc/$obs_writer_pid/stat ] && ! obs_writer_identity; then obs_writer_cleanup || :; return 76; fi
 status=0; wait "$obs_writer_pid" || status=$?
 obs_writer_pid=''; obs_writer_ticks=''
 wait || return 76
 childlist=''; IFS= read -r childlist < /proc/$$/task/$$/children || :
 [ -z "$childlist" ] || return 76
 [ "$status" -eq 0 ] && [ "$obs_writer_failed" -eq 0 ]
}
obs_emit_busybox(){
 local raw=$1 binding=$2 capture=$3 deadline=$4 bytes whole parts part kind piece encoded digest frame size before after out app now result=0
 LC_ALL=C; export LC_ALL
 [ \${#binding} -eq 64 ] && [ \${#capture} -eq 32 ] || return 75
 case "$binding$capture" in *[!a-f0-9]*) return 75;; esac
 case "$deadline" in ''|*[!0-9]*) return 75;; esac
 [ \${#deadline} -le 16 ] && [ "$deadline" -gt 0 ] && [ "$deadline" -le 9007199254740991 ] || return 75
 # The collector emits compact ASCII JSON (all raw text fields are hex).
 # Shell variables cannot represent NUL; arbitrary binary input is unsupported.
 case "$raw" in *[![:print:]]*) return 75;; esac
 bytes=\${#raw}; [ "$bytes" -gt 0 ] && [ "$bytes" -le 1048576 ] || return 75
 now=$($obs_bb date +%s 2>/dev/null) || return 75
 [ $(((now+1)*1000+1000)) -le "$deadline" ] || return 75
 out=$($obs_bb stat -Lc '%d:%i:%F' /proc/$$/fd/2 2>/dev/null) || return 75
 app=$($obs_bb stat -Lc '%d:%i:%F' /proc/$$/fd/1 2>/dev/null) || return 75
 case "$out:$app" in *:fifo:*:fifo) ;; *) return 75;; esac
 [ "$out" != "$app" ] || return 75
 before=$($obs_bb head -c 4097 /proc/$$/fdinfo/2 2>/dev/null) || return 75
 [ \${#before} -le 4096 ] || return 75
 whole=$(printf '%s' "$raw" | $obs_bb sha256sum 2>/dev/null) || return 75; whole=\${whole%% *}
 [ \${#whole} -eq 64 ] || return 75
 parts=$(((bytes+2047)/2048)); part=0; OBS_FRAMES=0; OBS_WIRE_BYTES=0
 trap obs_writer_cancel TERM INT
 while [ "$part" -lt $((parts+2)) ]; do
  piece=''; kind=D
  if [ "$part" -eq 0 ]; then kind=B
  elif [ "$part" -eq $((parts+1)) ]; then kind=E
  else piece=\${raw:$(((part-1)*2048)):2048}
  fi
  encoded=$(printf '%s' "$piece" | $obs_bb base64 -w 0 2>/dev/null) || { result=75; break; }
  digest=$(printf '%s' "$piece" | $obs_bb sha256sum 2>/dev/null) || { result=75; break; }; digest=\${digest%% *}
  frame=$(printf '\nMEM9-OBS2|%s|%s|%s|%s|%s|%s|%s|%s|%s' "$binding" "$capture" "$kind" "$part" "$parts" "$bytes" "$whole" "$digest" "$encoded")
  size=$((\${#frame}+1)); [ "$size" -le 4096 ] || { result=75; break; }
  obs_write_frame "$frame" "$size" "$deadline" "$capture:$part" || { result=75; break; }
  OBS_FRAMES=$((OBS_FRAMES+1)); OBS_WIRE_BYTES=$((OBS_WIRE_BYTES+size)); part=$((part+1))
 done
 obs_writer_cleanup || result=76
 trap - TERM INT
 after=$($obs_bb head -c 4097 /proc/$$/fdinfo/2 2>/dev/null) || return 76
 [ "$before" = "$after" ] || return 76
 [ "$obs_writer_failed" -eq 0 ] || return 75
 return "$result"
}
`.replaceAll('\\${','${');

export function busyboxObservationOutputSource(){
 if(arguments.length)throw Error('DataObservationBusyboxSourceArguments');
 return SOURCE;
}

/** Geometry only. Original caller still prepays the full source/metadata,
 * helper/guard, encoding, raw-page, replay and cleanup obligations. */
export function describeBusyboxObservationOutputWork(input){
 const value=copyNonrootJson(input);if(Object.keys(value).join()!=='rawBytes')throw Error('DataObservationBusyboxWork');
 const geometry=describeObservationFrameGeometry(value);
 return copyNonrootJson({...geometry,maximumGuardTicks:100*geometry.frameCount,
  writerInvocations:geometry.frameCount,anonymousPipeCreators:2*geometry.frameCount,
  rawSliceScanUpperBound:geometry.rawBytes*geometry.parts,wholeHashBytes:geometry.rawBytes,pieceHashBytes:geometry.rawBytes,
  maximumWriterPipeBytes:3*geometry.maxWireBytes});
}
