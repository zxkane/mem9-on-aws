/** Carrier-only fixed Docker probe commands with the reviewed pidfd/subreaper loop. */
import {spawn} from 'node:child_process';
import {createHash} from 'node:crypto';
import {parseAcquisitionJson} from './ci-smoke-acquisition-format.mjs';
export const CARRIER_PROBE_SUPERVISOR_SOURCE=String.raw`
import base64
import hashlib
import ctypes
import json
import os
import re
import signal
import stat
import sys
import time

DOCKER = "/usr/bin/docker"
ARGS = None
TIMEOUT = None
PROBE_HASH = "__PROBE_HASH__"
cancelled = False

def cancel(_number, _frame):
    global cancelled
    cancelled = True

def owned_signal(pid):
    fd = os.pidfd_open(pid)
    try:
        # A pidfd fixes identity. WNOWAIT verifies that identity is our child
        # without releasing a zombie PID before the signal/reap sequence.
        os.waitid(os.P_PIDFD, fd, os.WEXITED | os.WNOHANG | os.WNOWAIT | 0x40000000)
        signal.pidfd_send_signal(fd, signal.SIGKILL)
    except ProcessLookupError:
        pass
    finally:
        os.close(fd)

def signal_children():
    with open(f"/proc/self/task/{os.getpid()}/children", encoding="ascii") as file:
        text = file.read(65537)
    # Process bounded batches without abandoning supervision on overflow.
    values = text.split()
    if len(text) > 65536:
        values = values[:-1]
    for value in values[:4096]:
        pid = int(value)
        if pid <= 1 or pid == os.getpid():
            raise RuntimeError("DockerChildIdentity")
        try:
            owned_signal(pid)
        except ProcessLookupError:
            pass

def reap(state):
    for _ in range(4096):
        try:
            pid, status = os.waitpid(-1, os.WNOHANG | 0x40000000)
        except ChildProcessError:
            return True  # ECHILD, including adopted descendants (__WALL).
        if pid == 0:
            break
        state["reaped"] += 1
        if pid == state["leaderPid"] and not state["leaderEnded"]:
            state["leaderEnded"] = True
            if os.WIFEXITED(status):
                state["status"] = os.WEXITSTATUS(status)
            else:
                state["signal"] = signal.Signals(os.WTERMSIG(status)).name
        elif os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL:
            state["killedDescendants"] += 1
    return False

def cancellation(parent):
    if cancelled or os.getppid() != parent:
        return True
    try:
        # Any input or EOF requests stop. It can never select another action.
        os.read(4, 1)
        return True
    except BlockingIOError:
        return False
    except OSError:
        return True

def supervise(directory, parent):
    if not all(callable(value) for value in [getattr(os, "pidfd_open", None),
                                            getattr(os, "waitid", None),
                                            getattr(signal, "pidfd_send_signal", None)]):
        raise RuntimeError("DockerPidfdUnavailable")
    probe = os.pidfd_open(os.getpid())
    try:
        signal.pidfd_send_signal(probe, 0)
        try:
            os.waitid(os.P_PIDFD, probe, os.WEXITED | os.WNOHANG | os.WNOWAIT | 0x40000000)
        except ChildProcessError:
            pass  # Supported waitid; the supervisor is not its own child.
        else:
            raise RuntimeError("DockerPidfdOwnership")
    finally:
        os.close(probe)
    with open(f"/proc/self/task/{os.getpid()}/children", encoding="ascii") as file:
        if file.read(1):
            raise RuntimeError("DockerSupervisorNotEmpty")
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0 or libc.prctl(1, signal.SIGTERM, 0, 0, 0) != 0:
        raise RuntimeError("DockerSubreaperUnavailable")
    for number in [signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGQUIT]:
        signal.signal(number, cancel)
    signal.signal(signal.SIGCHLD, signal.SIG_DFL)
    os.set_inheritable(3, False)
    os.set_inheritable(4, False)
    os.set_blocking(4, False)
    state = {"version": 1, "kind": "carrier-native-probe-subreaper-echild",
             "supervisorPid": os.getpid(), "leaderPid": None,
             "leaderEnded": False, "status": None, "signal": None,
             "reason": None, "reaped": 0, "killedDescendants": 0}
    deadline = time.monotonic() + TIMEOUT / 1000
    if cancellation(parent):
        state["reason"] = "DockerStdinCancelled"
    else:
        leader = os.fork()
        if leader == 0:
            try:
                # The workload and all its descendants cannot forge fd 3 or
                # consume the parent's cancellation channel. Stdin is retained.
                os.close(3)
                os.close(4)
                os.setsid()
                if libc.prctl(38, 1, 0, 0, 0) != 0:
                    os._exit(74)
                env = {"PATH": "/usr/bin:/bin", "HOME": directory,
                       "DOCKER_CONFIG": directory, "LANG": "C", "LC_ALL": "C"}
                os.chdir(directory)
                os.execve(DOCKER, [DOCKER, "--host", "unix:///var/run/docker.sock", "--config", directory, *ARGS], env)
            except BaseException:
                os._exit(74)
        state["leaderPid"] = leader
    # Only the actual workload holds the stdin reader / stdout writers.
    for fd in [0, 1, 2]:
        try:
            os.close(fd)
        except OSError:
            pass
    while True:
        try:
            if reap(state):
                state["cleanupComplete"] = state["leaderPid"] is None or state["leaderEnded"]
                return state
            if state["reason"] is None:
                if cancellation(parent):
                    state["reason"] = "DockerStdinCancelled"
                elif time.monotonic() >= deadline:
                    state["reason"] = "DockerStdinTimeout"
                elif state["leaderEnded"]:
                    state["reason"] = "DockerDescendantSurvived"
            if state["reason"] is not None:
                signal_children()
        except BaseException:
            state["reason"] = "DockerSupervisionFault"
        # An operation timeout ends work, never the reaper. It retains the
        # owned tree until all remaining children are killed and reaped.
        time.sleep(0.01)

def valid_args(args):
    digest = lambda v: isinstance(v, str) and re.fullmatch(r"sha256:[a-f0-9]{64}", v)
    ident = lambda v: isinstance(v, str) and re.fullmatch(r"[a-f0-9]{64}", v)
    if not isinstance(args, list) or not all(isinstance(v, str) and "\x00" not in v for v in args):
        return False
    if len(args) == 3 and args[:2] == ["image", "inspect"]:
        return bool(digest(args[2]))
    if len(args) == 5 and args[:4] == ["image", "inspect", "--platform", "linux/arm64"]:
        return bool(digest(args[4]))
    if len(args) == 3 and args[:2] == ["container", "inspect"]:
        return bool(ident(args[2]))
    if len(args) == 4 and args[:3] == ["container", "start", "--attach"]:
        return bool(ident(args[3]))
    if len(args) == 5 and args[:4] == ["container", "rm", "--force", "--volumes"]:
        return bool(ident(args[4]))
    prefix = ["container", "create", "--pull=never", "--platform=linux/arm64", "--network=none", "--read-only", "--user=1000:1000", "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--pids-limit=32", "--memory=256m", "--cpus=1", "--restart=no", "--no-healthcheck", "--tmpfs", "/tmp:rw,nosuid,nodev,exec,size=1048576,uid=1000,gid=1000,mode=0700"]
    if args[:len(prefix)] != prefix or len(args) != len(prefix) + 15:
        return False
    a = args[len(prefix):]
    if a[0] != "--label" or a[2] != "--name" or not re.fullmatch(r"mem9-prerequisites-[a-f0-9]{32}", a[3]) or a[1] != "mem9-prerequisites-probe=" + a[3]:
        return False
    if a[4:6] != ["--entrypoint", "/bin/setpriv"] or not digest(a[6]) or a[7:12] != ["--no-new-privs", "--", "/usr/local/bin/node", "--input-type=module", "-e"] or a[13] != "--":
        return False
    if hashlib.sha256(a[12].encode()).hexdigest() != PROBE_HASH or len(a[14]) > 65536:
        return False
    paths = json.loads(a[14])
    return isinstance(paths, list) and 0 < len(paths) <= 512 and len(set(paths)) == len(paths) and all(isinstance(v, str) and len(v) <= 4096 and re.fullmatch(r"/[A-Za-z0-9_./+-]*", v) and os.path.normpath(v) == v for v in paths)

def main():
    global ARGS, TIMEOUT
    try:
        if len(sys.argv) != 6 or not re.fullmatch(r"[1-9][0-9]*", sys.argv[1]):
            raise RuntimeError("CarrierProbeArguments")
        parent, directory = int(sys.argv[1]), sys.argv[2]
        if parent <= 1 or os.getppid() != parent or os.path.realpath(directory) != directory:
            raise RuntimeError("CarrierProbeParent")
        info = os.lstat(directory)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700 or not re.fullmatch(r"mem9-prerequisites-[A-Za-z0-9_-]{6,64}", os.path.basename(directory)):
            raise RuntimeError("CarrierProbeDirectory")
        if len(sys.argv[3]) > 131072 or not re.fullmatch(r"[a-f0-9]{64}", sys.argv[4]):
            raise RuntimeError("CarrierProbeArguments")
        raw = base64.b64decode(sys.argv[3], validate=True)
        if hashlib.sha256(raw).hexdigest() != sys.argv[4]:
            raise RuntimeError("CarrierProbeArguments")
        ARGS = json.loads(raw)
        TIMEOUT = int(sys.argv[5])
        if TIMEOUT <= 0 or TIMEOUT > 30000 or not valid_args(ARGS):
            raise RuntimeError("CarrierProbeArguments")
        result = supervise(directory, parent)
    except BaseException:
        result = {"version": 1, "kind": "carrier-native-probe-subreaper-unconfirmed", "supervisorPid": os.getpid(), "cleanupComplete": False}
    try:
        payload = (json.dumps(result, separators=(",", ":")) + "\n").encode("ascii")
        if len(payload) > 4096 or os.write(3, payload) != len(payload):
            os._exit(74)
        os.close(3)
    except BaseException:
        os._exit(74)
    os._exit(0 if result["cleanupComplete"] else 74)

if __name__ == "__main__":
    main()
`;

/** No executable, environment, policy or probe override is accepted. Python
 * checks the same fixed command grammar before it creates the Docker child. */
export async function runCarrierProbeDockerCommand(args,{directory,timeoutMs=30000,signal}={}){
 const {getNonrootNativeProbeSource}=await import('./production-nonroot-control-prerequisites.mjs');
 const probe=getNonrootNativeProbeSource(),raw=Buffer.from(JSON.stringify(args));
 const need=(ok,code)=>{if(!ok)throw Error(code);};
 need(Array.isArray(args)&&args.every(v=>typeof v==='string')&&raw.length<=98304&&Number.isSafeInteger(timeoutMs)&&timeoutMs>0&&timeoutMs<=30000,'CarrierProbeArguments');
 const source=CARRIER_PROBE_SUPERVISOR_SOURCE.replace('__PROBE_HASH__',probe.sha256),hash=createHash('sha256').update(raw).digest('hex');
 return new Promise((resolve,reject)=>{
  let child,closed=false,settled=false,problem=false,cancelled=false,status,sig,timer,total=0,ackBytes=0;const out=[],err=[],ack=[];
  const stop=()=>{problem=true;if(!cancelled&&child?.stdio[4]){cancelled=true;child.stdio[4].end('X');}};
  const finish=()=>{
   if(settled||!closed)return;settled=true;clearTimeout(timer);signal?.removeEventListener('abort',stop);child?.stdio[4]?.end();let proof;
   try{if(status===0&&!sig){const p=parseAcquisitionJson(Buffer.concat(ack),4096);
    need(p.version===1&&p.kind==='carrier-native-probe-subreaper-echild'&&p.supervisorPid===child.pid&&p.cleanupComplete===true&&p.leaderEnded===true&&Number.isInteger(p.leaderPid)&&p.leaderPid>1&&Number.isInteger(p.reaped)&&p.reaped>=1&&Number.isInteger(p.killedDescendants)&&p.killedDescendants>=0&&p.killedDescendants<p.reaped,'CarrierProbeTermination');
    need(p.reason===null&&p.signal===null&&Number.isInteger(p.status)&&p.status>=0&&p.status<=255,'CarrierProbeTermination');proof=Object.freeze(p);
   }}catch{problem=true;}
   if(problem||!proof)reject(Object.assign(Error('ECLEANUP'),{code:'ECLEANUP',cleanupConfirmed:false,operationDirectory:directory}));
   else resolve({status:proof.status,stdout:Buffer.concat(out).toString('utf8'),stderr:Buffer.concat(err).toString('utf8'),termination:proof});
  };
  const collect=target=>bytes=>{total+=bytes.length;if(total>1048576)stop();else target.push(Buffer.from(bytes));};
  try{
   signal?.throwIfAborted();
   child=spawn('/usr/bin/python3',['-I','-B','-c',source,String(process.pid),directory,raw.toString('base64'),hash,String(timeoutMs)],{cwd:directory,env:{PATH:'/usr/bin:/bin',HOME:directory,DOCKER_CONFIG:directory,LANG:'C',LC_ALL:'C'},detached:true,stdio:['ignore','pipe','pipe','pipe','pipe']});
   child.stdout.on('data',collect(out));child.stderr.on('data',collect(err));child.stdio[3].on('data',b=>{ackBytes+=b.length;if(ackBytes>4096)stop();else ack.push(Buffer.from(b));});child.stdio[4].on('error',()=>{});
   child.on('error',stop);child.on('close',(code,signal)=>{closed=true;status=code;sig=signal;finish();});timer=setTimeout(stop,timeoutMs);signal?.addEventListener('abort',stop,{once:true});if(signal?.aborted)stop();
  }catch{problem=true;closed=!child;stop();finish();}
 });
}
