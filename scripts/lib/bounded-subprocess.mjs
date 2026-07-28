import { spawn } from "node:child_process";

export const SUBPROCESS_KILL_GRACE_MS = 100;
const DEFAULT_MAX_BUFFER_BYTES = 16 * 1024 * 1024;
const SIGNAL_EXIT_CODES = Object.freeze({
  SIGINT: 130,
  SIGTERM: 143,
});

function subprocessError(message, code) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function signalProcessGroup(child, signal) {
  if (child.pid === undefined) return;
  try {
    if (process.platform === "win32") {
      child.kill(signal);
    } else {
      process.kill(-child.pid, signal);
    }
  } catch (error) {
    if (error?.code !== "ESRCH") throw error;
  }
}

function processGroupExists(child) {
  if (child.pid === undefined) return false;
  if (process.platform === "win32") {
    return child.exitCode === null && child.signalCode === null;
  }
  try {
    process.kill(-child.pid, 0);
    return true;
  } catch (error) {
    if (error?.code === "ESRCH") return false;
    if (error?.code === "EPERM") return true;
    throw error;
  }
}

function abortError(signal) {
  if (signal?.reason instanceof Error) return signal.reason;
  return subprocessError("subprocess was aborted", "ABORT_ERR");
}

export function installSubprocessSignalHandlers({
  processTarget = process,
} = {}) {
  const controller = new AbortController();
  let receivedSignal;
  const handlers = new Map(
    Object.keys(SIGNAL_EXIT_CODES).map((signal) => [
      signal,
      () => {
        if (controller.signal.aborted) return;
        receivedSignal = signal;
        const error = subprocessError(
          `rollout interrupted by ${signal}`,
          "EINTR",
        );
        error.signal = signal;
        controller.abort(error);
      },
    ]),
  );
  for (const [signal, handler] of handlers) {
    processTarget.on(signal, handler);
  }
  return {
    dispose() {
      for (const [signal, handler] of handlers) {
        processTarget.off(signal, handler);
      }
    },
    get exitCode() {
      return receivedSignal ? SIGNAL_EXIT_CODES[receivedSignal] : undefined;
    },
    get receivedSignal() {
      return receivedSignal;
    },
    signal: controller.signal,
  };
}

export function remainingCommandTimeout({
  deadlineAt,
  maximumMs,
  killGraceMs = SUBPROCESS_KILL_GRACE_MS,
  now = Date.now,
}) {
  if (!Number.isFinite(maximumMs) || maximumMs <= 0) {
    throw new Error("subprocess timeout is invalid");
  }
  if (deadlineAt === undefined) return maximumMs;
  if (!Number.isFinite(deadlineAt)) {
    throw new Error("workload boundary rollout deadline is invalid");
  }
  const available = deadlineAt - now() - killGraceMs * 2;
  if (available <= 0) {
    throw new Error("workload boundary rollout deadline exceeded");
  }
  return Math.max(1, Math.min(maximumMs, available));
}

export function runBoundedCommand(
  command,
  args,
  {
    cwd,
    env = process.env,
    killGraceMs = SUBPROCESS_KILL_GRACE_MS,
    maxBufferBytes = DEFAULT_MAX_BUFFER_BYTES,
    signal,
    timeoutMs,
  },
) {
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new Error("subprocess timeout is invalid");
  }
  if (
    signal !== undefined &&
    (typeof signal !== "object" ||
      typeof signal.addEventListener !== "function" ||
      typeof signal.removeEventListener !== "function")
  ) {
    throw new Error("subprocess abort signal is invalid");
  }
  if (signal?.aborted) {
    return Promise.reject(abortError(signal));
  }
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(command, args, {
      cwd,
      detached: process.platform !== "win32",
      env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const stdout = [];
    const stderr = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let completed = false;
    let leaderClosed = false;
    let terminating = false;
    let terminationError;
    let cleanupDeadlineAt;
    let cleanupPollTimer;
    let forceKillSent = false;
    let killTimer;
    let timeoutTimer;
    const abortListener = () => terminate(abortError(signal));

    const finish = (callback, value) => {
      if (completed) return;
      completed = true;
      clearTimeout(timeoutTimer);
      clearTimeout(killTimer);
      clearTimeout(cleanupPollTimer);
      signal?.removeEventListener("abort", abortListener);
      callback(value);
    };
    const settleTerminatedProcessGroup = () => {
      if (completed || !terminating) return;
      let groupExists;
      try {
        groupExists = processGroupExists(child);
      } catch (error) {
        finish(rejectPromise, error);
        return;
      }
      if (leaderClosed && !groupExists) {
        finish(rejectPromise, terminationError);
        return;
      }
      if (!forceKillSent) return;
      if (Date.now() >= cleanupDeadlineAt) {
        const cleanupError = subprocessError(
          "subprocess group did not exit after SIGKILL",
          "ECLEANUP",
        );
        cleanupError.cause = terminationError;
        finish(rejectPromise, cleanupError);
        return;
      }
      cleanupPollTimer = setTimeout(
        settleTerminatedProcessGroup,
        Math.min(10, Math.max(1, cleanupDeadlineAt - Date.now())),
      );
    };
    const terminate = (error) => {
      if (completed || terminating) return;
      terminating = true;
      terminationError = error;
      if (child.pid === undefined) {
        finish(rejectPromise, error);
        return;
      }
      try {
        signalProcessGroup(child, "SIGTERM");
      } catch (signalError) {
        finish(rejectPromise, signalError);
        return;
      }
      killTimer = setTimeout(() => {
        forceKillSent = true;
        cleanupDeadlineAt = Date.now() + killGraceMs;
        try {
          signalProcessGroup(child, "SIGKILL");
        } catch (signalError) {
          finish(rejectPromise, signalError);
          return;
        }
        settleTerminatedProcessGroup();
      }, killGraceMs);
    };
    const collect = (chunks, isStdout) => (chunk) => {
      const buffer = Buffer.from(chunk);
      if (isStdout) {
        stdoutBytes += buffer.length;
      } else {
        stderrBytes += buffer.length;
      }
      if (stdoutBytes + stderrBytes > maxBufferBytes) {
        terminate(
          subprocessError("subprocess output exceeded its limit", "ENOBUFS"),
        );
        return;
      }
      chunks.push(buffer);
    };

    child.stdout.on("data", collect(stdout, true));
    child.stderr.on("data", collect(stderr, false));
    child.on("error", (error) => {
      if (terminating && child.pid !== undefined) return;
      finish(rejectPromise, terminating ? terminationError : error);
    });
    child.on("close", (status, closeSignal) => {
      leaderClosed = true;
      if (terminating) {
        settleTerminatedProcessGroup();
        return;
      }
      finish(resolvePromise, {
        signal: closeSignal,
        status,
        stderr: Buffer.concat(stderr).toString("utf8"),
        stdout: Buffer.concat(stdout).toString("utf8"),
      });
    });

    signal?.addEventListener("abort", abortListener, { once: true });
    if (signal?.aborted) {
      abortListener();
    }
    timeoutTimer = setTimeout(
      () =>
        terminate(
          subprocessError(
            `subprocess exceeded ${Math.ceil(timeoutMs)} ms`,
            "ETIMEDOUT",
          ),
        ),
      timeoutMs,
    );
  });
}
