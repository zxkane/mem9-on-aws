/** Fixed Linux Docker-stdin supervisor, embedded in the reviewed module graph.
 * No executable, argv, environment or network endpoint is accepted as input.
 * fd 3 is supervisor-only termination evidence; fd 4 is cancellation only. */
export const DOCKER_STDIN_SUPERVISOR_SOURCE=String.raw`
import ctypes
import json
import os
import re
import signal
import stat
import sys
import time

DOCKER = "/usr/bin/docker"
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
    state = {"version": 1, "kind": "docker-stdin-subreaper-echild",
             "supervisorPid": os.getpid(), "leaderPid": None,
             "leaderEnded": False, "status": None, "signal": None,
             "reason": None, "reaped": 0, "killedDescendants": 0}
    deadline = time.monotonic() + 120
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
                os.execve(DOCKER, [DOCKER, "--host", "unix:///var/run/docker.sock",
                                  "--config", directory, "image", "load"], env)
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
    try:
        if len(sys.argv) != 3 or not re.fullmatch(r"[1-9][0-9]*", sys.argv[1]):
            raise RuntimeError("DockerSupervisorArguments")
        parent, directory = int(sys.argv[1]), sys.argv[2]
        if parent <= 1 or os.getppid() != parent or os.path.realpath(directory) != directory:
            raise RuntimeError("DockerSupervisorParent")
        info = os.lstat(directory)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise RuntimeError("DockerSupervisorDirectory")
        if not re.fullmatch(r"mem9-control-docker-[A-Za-z0-9]{6}", os.path.basename(directory)):
            raise RuntimeError("DockerSupervisorDirectory")
        if sorted(os.listdir(directory)) != ["index.json", "oci-layout"]:
            raise RuntimeError("DockerSupervisorFiles")
        for name in ["index.json", "oci-layout"]:
            item = os.lstat(os.path.join(directory, name))
            if not stat.S_ISREG(item.st_mode) or item.st_uid != os.getuid() or stat.S_IMODE(item.st_mode) != 0o600 or item.st_nlink != 1:
                raise RuntimeError("DockerSupervisorFiles")
        result = supervise(directory, parent)
    except BaseException:
        result = {"version": 1, "kind": "docker-stdin-subreaper-unconfirmed",
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
