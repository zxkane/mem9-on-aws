import {need,exact} from './ci-smoke-acquisition-format.mjs';

// Only applets of the authenticated image's /bin/busybox are executed. All
// output is bounded proc metadata or hashes; no environment/secret/file dump.
export const TARGET_BUSYBOX_SOURCE=String.raw`
set -eu
set -o pipefail
b=/bin/busybox
used=0
charged=0
cache=''
nextFd=10
die(){ printf 'TargetProbeRejected\n' >&2; exit 1; }
clock(){ NOW=$($b date +%s) || die; [ $(((NOW+1)*1000)) -lt "$deadline" ] || die; }
allow(){ clock; [ $((charged+$1)) -le 268435456 ] || die; }
hexread(){
 local path=$1 cap=$2 output n
 allow $(((cap+1)*16+4096))
 if output=$($b head -c $((cap+1)) "$path" 2>/dev/null | $b od -An -v -tx1 | $b tr -d ' \n'); then :; else
  used=$((used+\${#output}/2))
  charged=$((charged+(cap+1)*16+4096))
  [ ! -d "\${path%/*}" ] && return 72
  die
 fi
 n=$((\${#output}/2)); used=$((used+n)); charged=$((charged+n*16+4096))
 [ "$n" -le "$cap" ] || die
 HEX=$output
}
ids(){
 IDS=''; local p count=0
 for p in /proc/[0-9]*; do count=$((count+1)); [ "$count" -le 128 ] || die; IDS="$IDS \${p##*/}"; done
 used=$((used+\${#IDS})); charged=$((charged+\${#IDS})); allow 0
}
stamp(){ allow 4096; STAMP=$($b stat -Lc '%d,%i,%s,%f,%u,%g,%y,%z' "/proc/$$/fd/3") || die; [ \${#STAMP} -le 1024 ] || die; charged=$((charged+4096)); }
proc(){
 local pid=$1 first status cmd again path before after size mode key value='' line out n digest rest cmdhash
 hexread /proc/$pid/stat 4096 || die; first=$HEX
 hexread /proc/$pid/status 65536 || die; status=$HEX
 hexread /proc/$pid/cmdline 16384 || die; cmd=$HEX
 allow 16384; path=$($b readlink /proc/$pid/exe) || die
 case "$path" in /*) ;; *) die;; esac
 case "$path" in *' (deleted)') die;; esac
 [ \${#path} -le 4096 ] || die
 used=$((used+\${#path})); charged=$((charged+16384))
 exec 3</proc/$pid/exe || die
 stamp; before=$STAMP
 rest=\${before#*,}; rest=\${rest#*,}; size=\${rest%%,*}; rest=\${rest#*,}; mode=\${rest%%,*}
 [ "$size" -gt 0 ] && [ "$size" -le 201326592 ] && [ $((0x$mode & 61440)) -eq 32768 ] || die
 key=$before
 while IFS='|' read -r line digest; do [ "$line" != "$key" ] || value=$digest; done <<CACHE
$cache
CACHE
 if [ -z "$value" ]; then
  # tee feeds an exact byte count alongside SHA256. Five file/pipe byte
  # movements plus bounded framing are charged within the original LOCAL cap.
  allow $(((size+1)*5+8192))
  out=$( { { $b head -c $((size+1)) <&3 | $b tee /proc/self/fd/4 | $b sha256sum >&5; } 4>&1 | $b wc -c; } 5>&1 ) || die
  value=''; n=''
  while IFS= read -r line; do case "$line" in *'  -') value=\${line%% *};; *) n=$line;; esac; done <<HASH
$out
HASH
  [ \${#value} -eq 64 ] && [ "$n" = "$size" ] || die
  used=$((used+n)); charged=$((charged+n*5+8192))
  # Keep the real inode open for the cache lifetime, as the Node collector
  # does. The descriptor number is generated here, never from proc output.
  [ "$nextFd" -le 138 ] || die
  eval "exec $nextFd<&3" || die
  nextFd=$((nextFd+1))
  cache="$cache
$key|$value"
 fi
 stamp; after=$STAMP; [ "$before" = "$after" ] || die
 exec 3<&-
 hexread /proc/$pid/stat 4096 || die; again=$HEX
 hexread /proc/$pid/cmdline 16384 || die; [ "$cmd" = "$HEX" ] || die
 allow 16384; [ "$path" = "$($b readlink /proc/$pid/exe)" ] || die
 used=$((used+\${#path})); charged=$((charged+16384))
 allow $((\${#path}*16+\${#cmd}*8+8192))
 charged=$((charged+\${#path}*16+4096))
 path=$(printf '%s' "$path" | $b od -An -v -tx1 | $b tr -d ' \n') || die
 cmdhash=$(printf '%s' "$cmd" | $b xxd -r -p | $b sha256sum) || die; cmdhash=\${cmdhash%% *}
 charged=$((charged+\${#cmd}*8+4096)); allow 0
 allow 196608
 ROW=$(printf '{"pid":%s,"stat":"%s","statAfter":"%s","status":"%s","cmdlineHash":"%s","path":"%s","stamp":"%s","digest":"%s"}' "$pid" "$first" "$again" "$status" "$cmdhash" "$path" "$before" "$value")
 [ \${#ROW} -le 196608 ] || die; charged=$((charged+\${#ROW})); allow 0
}
snapshot(){
 ids; local p saved=$IDS comma=''; SNAP=''
 for p in $saved; do proc "$p"; SNAP="$SNAP$comma$ROW"; comma=,; [ \${#SNAP} -le 450000 ] || die; done
}
clock; started=$NOW
snapshot; initial=$SNAP
health=''; round=0
while [ "$round" -lt 30000 ]; do
 clock; ids; saved=$IDS
 for p in $saved; do
  [ "$p" != "$$" ] || continue
  if hexread /proc/$p/cmdline 16384; then :; else continue; fi
  case " $healthHex " in *" $HEX "*) proc "$p"; health=$ROW; clock; healthTime=$NOW; break;; esac
 done
 [ -z "$health" ] || break
 round=$((round+1)); $b sleep 0.001
done
[ -n "$health" ] || die
snapshot; final=$SNAP
clock; completed=$NOW
[ $((\${#initial}+\${#final}+\${#health}+512)) -le 1048576 ] || die
allow $((\${#initial}+\${#final}+\${#health}+512))
charged=$((charged+\${#initial}+\${#final}+\${#health}+512))
printf '{"version":2,"kind":"native-target-busybox-sample","nonce":"%s","probePid":%s,"startedSeconds":%s,"completedSeconds":%s,"initial":[%s],"final":[%s],"health":%s,"healthObservedSeconds":%s,"readBytes":%s,"chargedBytes":%s}\n' "$nonce" "$$" "$started" "$completed" "$initial" "$final" "$health" "$healthTime" "$used" "$charged"
`.replaceAll('\\${','${');

function decodeHex(v,cap){
 need(typeof v==='string'&&v.length<=2*cap&&v.length%2===0&&/^[a-f0-9]*$/.test(v),'TargetBusyboxHex');return Buffer.from(v,'hex');
}
const text=(v,cap)=>new TextDecoder('utf-8',{fatal:true}).decode(decodeHex(v,cap));
function processRow(r){
 exact(r,['pid','stat','statAfter','status','cmdlineHash','path','stamp','digest']);need(/^[a-f0-9]{64}$/.test(r.cmdlineHash),'TargetBusyboxCmdline');
 const stat=text(r.stat,4096),after=text(r.statAfter,4096),parse=s=>{
  need(s.startsWith(r.pid+' (')&&s.includes(') '),'TargetBusyboxStat');return s.slice(s.lastIndexOf(') ')+2).trim().split(/\s+/);
 },a=parse(stat),z=parse(after);
 need(a.length>=20&&a[1]===z[1]&&a[19]===z[19],'TargetBusyboxProcessChanged');
 const values=new Map();for(const line of text(r.status,65536).trimEnd().split('\n')){const at=line.indexOf(':');need(at>0&&!values.has(line.slice(0,at)),'TargetBusyboxStatus');values.set(line.slice(0,at),line.slice(at+1).trim());}
 const numbers=k=>{const s=values.get(k);need(typeof s==='string'&&/^(?:\d+(?:\s+\d+)*)?$/.test(s),'TargetBusyboxStatus');return s?s.split(/\s+/).map(Number):[];};
 const st=r.stamp.split(',');need(st.length===8&&st.slice(0,3).every(s=>/^\d+$/.test(s))&&/^[a-f0-9]+$/.test(st[3])&&st.slice(4,6).every(s=>/^\d+$/.test(s))&&/^[a-f0-9]{64}$/.test(r.digest),'TargetBusyboxFile');
 const mode=parseInt(st[3],16);need((mode&0o170000)===0o100000&&Number(st[2])>0&&Number(st[2])<=192*1048576,'TargetBusyboxFile');
 const path=text(r.path,4096);need(path.startsWith('/')&&!path.endsWith(' (deleted)')&&!/[\0\r\n]/.test(path),'TargetBusyboxPath');
 return {pid:r.pid,ppid:Number(a[1]),startTimeTicks:Number(a[19]),executablePath:path,executableDigest:'sha256:'+r.digest,file:{mode:mode&4095,uid:Number(st[4]),gid:Number(st[5])},cmdlineHash:r.cmdlineHash,uid:numbers('Uid'),gid:numbers('Gid'),groups:numbers('Groups'),noNewPrivs:Number(values.get('NoNewPrivs')),...Object.fromEntries(['Inh','Prm','Eff','Bnd','Amb'].map(k=>{const v=values.get('Cap'+k);need(/^[a-f0-9]{16}$/.test(v),'TargetBusyboxCapabilities');return ['cap'+k,v];}))};
}
export function decodeBusyboxSample(raw){
 exact(raw,['version','kind','nonce','probePid','startedSeconds','completedSeconds','initial','final','health','healthObservedSeconds','readBytes','chargedBytes']);
 need(raw.version===2&&raw.kind==='native-target-busybox-sample'&&['startedSeconds','completedSeconds','healthObservedSeconds','readBytes','chargedBytes'].every(k=>Number.isSafeInteger(raw[k])&&raw[k]>=0)&&raw.chargedBytes>=raw.readBytes&&raw.chargedBytes<=256*1048576,'TargetBusyboxSample');
 need(Array.isArray(raw.initial)&&Array.isArray(raw.final)&&raw.initial.length<=128&&raw.final.length<=128,'TargetBusyboxCoverage');
 return {version:1,kind:'native-target-proc-sample',nonce:raw.nonce,probePid:raw.probePid,startedMs:raw.startedSeconds*1000,completedMs:raw.completedSeconds*1000,initial:raw.initial.map(processRow),final:raw.final.map(processRow),health:processRow(raw.health),healthObservedMs:raw.healthObservedSeconds*1000,readBytes:raw.readBytes};
}
