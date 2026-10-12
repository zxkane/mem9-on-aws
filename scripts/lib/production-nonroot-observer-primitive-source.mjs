// DATA-only probe. Reuses the exact reviewed AArch64 kernel program; it does
// not import Node into the Go image or run an application/credential path.
import {getNonrootNativeProbeSource} from './production-nonroot-control-prerequisites.mjs';
import {createHash} from 'node:crypto';
const sha=b=>createHash('sha256').update(b).digest('hex');
const original=getNonrootNativeProbeSource(),match=/\)\(("[A-Za-z0-9+/=]+"),JSON\.parse\(process\.argv\[1\]\)\)$/.exec(original.code);
if(!match)throw Error('DataNativeSourceChanged');
export const NATIVE_BASE64=JSON.parse(match[1]);
export const NATIVE_SHA256=sha(Buffer.from(NATIVE_BASE64,'base64'));
export const ORIGINAL_PROBE_SHA256=original.sha256;
export const DATA_PROBE_SOURCE=String.raw`
set -eu
umask 077
phase=$1; flavour=$2; prefix=$3; loader=$4; native=$5; self=$6
shift 6
die(){ printf 'DataPrimitiveRejected\n' >&2; exit 1; }
# All utilities have fixed wrappers; no caller-selected executable is run.
b64(){ if [ "$flavour" = busybox ]; then /bin/busybox base64 -w 0; else /usr/bin/base64 -w 0; fi; }
head(){ if [ "$flavour" = busybox ]; then /bin/busybox head "$@"; else /usr/bin/head "$@"; fi; }
link(){ if [ "$flavour" = busybox ]; then /bin/busybox readlink -f "$1"; else /usr/bin/readlink -f "$1"; fi; }
digest(){ if [ "$flavour" = busybox ]; then /bin/busybox sha256sum "$1"; else /usr/bin/sha256sum "$1"; fi; }
metadata(){ if [ "$flavour" = busybox ]; then /bin/busybox stat -Lc '%d:%i:%s:%f:%u:%g:%Y:%Z' "$1"; else /usr/bin/stat -Lc '%d:%i:%s:%f:%u:%g:%Y:%Z' "$1"; fi; }
small(){ value=$(head -c 65537 "$1") || die; [ \${#value} -le 65536 ] || die; printf '%s' "$value" | b64; }
identity(){
 status=$(small /proc/$$/status) || die
 stat=$(small /proc/$$/stat) || die
 exe=$(link /proc/$$/exe) || die
 printf 'P|%s|%s|%s|%s|%s\n' "$1" "$$" "$status" "$stat" "$exe"
}
identity "$phase"
if [ "$phase" = before ]; then
 exec "$prefix" --no-new-privs -- /bin/sh -c "$self" -- after "$flavour" "$prefix" "$loader" "$native" "$self" "$@"
fi
if [ "$phase" = child ]; then exit 0; fi
[ "$phase" = after ] || die
/bin/sh -c "$self" -- child "$flavour" "$prefix" "$loader" "$native" "$self"
# The fixed Node child observes the real Node runtime used by both workers.
# It is an inheritance probe, not a replacement worker or a success witness.
if [ "$flavour" = glibc ]; then
 /usr/local/bin/node --input-type=module -e 'import fs from "node:fs";const p="/proc/"+process.pid;const read=n=>{const f=fs.openSync(p+n,"r"),b=Buffer.alloc(65537);try{const s=fs.readSync(f,b);if(s>65536)throw Error("DataPrimitiveRejected");return b.subarray(0,s).toString("base64");}finally{fs.closeSync(f);}};console.log(["P","node",process.pid,read("/status"),read("/stat"),fs.realpathSync(p+"/exe")].join("|"));'
fi
if [ "$flavour" = busybox ]; then
 printf '%s' "$native" | /bin/busybox base64 -d > /tmp/data-native
 /bin/busybox chmod 700 /tmp/data-native
else
 printf '%s' "$native" | /usr/bin/base64 -d > /tmp/data-native
 /usr/bin/chmod 700 /tmp/data-native
fi
/tmp/data-native > /tmp/data-native.out || die
kernel=$(b64 < /tmp/data-native.out) || die
[ \${#kernel} -le 152 ] || die
printf 'K|%s\n' "$kernel"
if [ "$flavour" = busybox ]; then /bin/busybox rm /tmp/data-native /tmp/data-native.out; else /usr/bin/rm /tmp/data-native /tmp/data-native.out; fi
for file in "$@"; do
 before=$(metadata "$file") || die
 resolved=$(link "$file") || die
 sum=$(digest "$file") || die; sum=\${sum%% *}
 after=$(metadata "$file") || die
 [ "$before" = "$after" ] || die
 printf 'F|%s|%s|%s|%s\n' "$file" "$resolved" "$sum" "$before"
done
for file in "$prefix" /bin/sh; do
 result=$("$loader" --list "$file") || die
 [ \${#result} -le 65536 ] || die
 printf 'L|%s|' "$file"; printf '%s' "$result" | b64; printf '\n'
done
if [ "$flavour" = glibc ]; then
 result=$("$loader" --list /usr/local/bin/node) || die
 [ \${#result} -le 65536 ] || die
 printf 'L|/usr/local/bin/node|'; printf '%s' "$result" | b64; printf '\n'
fi
printf 'M|'; small /proc/$$/maps; printf '\n'
identity final
`.replaceAll('\\${','${');
export const DATA_PROBE_HASH=sha(DATA_PROBE_SOURCE);
export function dataProbeArguments(plan){
 return ['-c',DATA_PROBE_SOURCE,'--','before',plan.flavour,plan.prefix,plan.loader,NATIVE_BASE64,DATA_PROBE_SOURCE,...plan.files.map(f=>f.path)];
}
