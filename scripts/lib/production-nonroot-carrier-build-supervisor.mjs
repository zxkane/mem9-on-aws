/** Fixed offline carrier build only. Reuses the reviewed subreaper/pidfd
 * algorithm; no Docker registry command, caller executable or environment. */
export const CARRIER_BUILD_SUPERVISOR_SOURCE=String.raw`
import ctypes
import hashlib
import json
import os
import re
import resource
import signal
import stat
import sys
import time

DOCKER = "/usr/bin/docker"
BUILD_PLAN = None
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
    state = {"version": 1, "kind": "carrier-offline-build-subreaper-echild",
             "supervisorPid": os.getpid(), "leaderPid": None,
             "leaderEnded": False, "status": None, "signal": None,
             "reason": None, "reaped": 0, "killedDescendants": 0}
    remaining = (BUILD_PLAN["deadlineMs"] - time.time() * 1000) / 1000 - 30
    if remaining <= 0:
        raise RuntimeError("CarrierBuildDeadline")
    deadline = time.monotonic() + min(120, remaining)
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
                os.umask(0o077)
                resource.setrlimit(resource.RLIMIT_FSIZE, (1048576, 1048576))
                env["DOCKER_CONFIG"] = os.path.join(directory, "docker-config")
                env["EXPERIMENTAL_BUILDKIT_SOURCE_POLICY"] = os.path.join(directory, "source-policy.json")
                env["BUILDX_METADATA_PROVENANCE"] = "max"
                env["BUILDX_NO_DEFAULT_LOAD"] = "1"
                os.execve(DOCKER, [DOCKER, "--host", "unix:///var/run/docker.sock",
                    "--config", env["DOCKER_CONFIG"], "buildx", "build", "--builder", "default",
                    "--platform", "linux/arm64", "--network", "none", "--pull=false", "--no-cache",
                    "--tag", "mem9-carrier-build:" + os.path.basename(directory).removeprefix("mem9-carrier-build-"),
                    "--provenance=mode=max", "--progress=rawjson", "--metadata-file", os.path.join(directory, "metadata.json"),
                    "--output", "type=oci,oci-artifact=true,dest=-", "--build-context", BUILD_PLAN["baseImage"] + "=oci-layout://" + os.path.join(directory, "base") + "@" + BUILD_PLAN["baseRootDigest"],
                    *(["--build-context", "carrier_runtime=" + BUILD_PLAN["derivedDirectory"]] if "derivedDirectory" in BUILD_PLAN else []),
                    "--file", os.path.join(BUILD_PLAN["contextDirectory"], "Dockerfile"), BUILD_PLAN["contextDirectory"]], env)
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

def main():
    global BUILD_PLAN
    try:
        if len(sys.argv) != 4 or not re.fullmatch(r"[1-9][0-9]*", sys.argv[1]):
            raise RuntimeError("DockerSupervisorArguments")
        parent, directory = int(sys.argv[1]), sys.argv[2]
        if parent <= 1 or os.getppid() != parent or os.path.realpath(directory) != directory:
            raise RuntimeError("DockerSupervisorParent")
        info = os.lstat(directory)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise RuntimeError("DockerSupervisorDirectory")
        if not re.fullmatch(r"mem9-carrier-build-[a-f0-9]{32}", os.path.basename(directory)):
            raise RuntimeError("DockerSupervisorDirectory")
        if not re.fullmatch(r"[a-f0-9]{64}", sys.argv[3]):
            raise RuntimeError("CarrierBuildPlan")
        with open(os.path.join(directory, "build-input.json"), "rb") as file:
            raw = file.read(65537)
        if len(raw) > 65536 or hashlib.sha256(raw).hexdigest() != sys.argv[3]:
            raise RuntimeError("CarrierBuildPlan")
        BUILD_PLAN = json.loads(raw)
        expected = ["baseImage", "baseRootDigest", "contextDirectory", "deadlineMs", "dockerfileHash", "kind", "policyHash", "version"]
        if "derivedDirectory" in BUILD_PLAN:
            expected.append("derivedDirectory")
        if sorted(BUILD_PLAN) != sorted(expected) or BUILD_PLAN["version"] != 1 or BUILD_PLAN["kind"] != "fixed-offline-carrier-build":
            raise RuntimeError("CarrierBuildPlan")
        if not re.fullmatch(r"sha256:[a-f0-9]{64}", BUILD_PLAN["baseRootDigest"]):
            raise RuntimeError("CarrierBuildPlan")
        if not re.fullmatch(r"[0-9]{12}\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com/mem9-on-aws/(preview/)?bootstrap@" + BUILD_PLAN["baseRootDigest"], BUILD_PLAN["baseImage"]):
            raise RuntimeError("CarrierBuildPlan")
        context = BUILD_PLAN["contextDirectory"]
        if not isinstance(BUILD_PLAN["deadlineMs"], int) or os.path.dirname(context) != os.path.dirname(directory) or not re.fullmatch(r"mem9-carrier-context-[a-f0-9]{32}", os.path.basename(context)) or os.path.realpath(context) != context:
            raise RuntimeError("CarrierBuildPlan")
        item = os.lstat(context)
        if not stat.S_ISDIR(item.st_mode) or item.st_uid != os.getuid() or stat.S_IMODE(item.st_mode) != 0o700:
            raise RuntimeError("CarrierBuildDirectory")
        if "derivedDirectory" in BUILD_PLAN:
            derived = BUILD_PLAN["derivedDirectory"]
            derived_parent = os.path.dirname(derived)
            if os.path.basename(derived) != "material" or os.path.dirname(derived_parent) != os.path.dirname(directory) or not re.fullmatch(r"mem9-carrier-derived-[a-f0-9]{32}", os.path.basename(derived_parent)) or os.path.realpath(derived) != derived:
                raise RuntimeError("CarrierBuildDerivedDirectory")
            for path in [derived_parent, derived]:
                item = os.lstat(path)
                if not stat.S_ISDIR(item.st_mode) or item.st_uid != os.getuid() or stat.S_IMODE(item.st_mode) != 0o700:
                    raise RuntimeError("CarrierBuildDerivedDirectory")
        for path, expected, mode in [(os.path.join(context, "Dockerfile"), BUILD_PLAN["dockerfileHash"], 0o444), (os.path.join(directory, "source-policy.json"), BUILD_PLAN["policyHash"], 0o600)]:
            item = os.lstat(path)
            if not stat.S_ISREG(item.st_mode) or item.st_uid != os.getuid() or stat.S_IMODE(item.st_mode) != mode or item.st_nlink != 1:
                raise RuntimeError("CarrierBuildPlan")
            with open(path, "rb") as file:
                data = file.read(65537)
            if len(data) > 65536 or hashlib.sha256(data).hexdigest() != expected:
                raise RuntimeError("CarrierBuildPlan")
        for name in ["base", "docker-config", "output"]:
            path = os.path.join(directory, name)
            item = os.lstat(path)
            if os.path.realpath(path) != path or not stat.S_ISDIR(item.st_mode) or item.st_uid != os.getuid() or stat.S_IMODE(item.st_mode) != 0o700:
                raise RuntimeError("CarrierBuildDirectory")
        result = supervise(directory, parent)
    except BaseException:
        result = {"version": 1, "kind": "carrier-offline-build-subreaper-unconfirmed",
                  "supervisorPid": os.getpid(), "cleanupComplete": False}
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
