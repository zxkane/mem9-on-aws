import { fork } from 'node:child_process';

export class InferenceError extends Error {
  constructor(code) { super(code); this.code = code; }
}

// One resident model, one active inference, and a bounded waiting queue.
// Native execution cannot block the HTTP supervisor's cancellation timer.
export function createInferencePool({
  workerURL = new URL('./inference-worker.mjs', import.meta.url),
  workerEnv = Object.fromEntries(['PATH', 'HOME', 'NODE_ENV', 'QWEN3_EMBED_MODEL_REPO', 'QWEN3_INTRA_OP_THREADS']
    .filter(key => process.env[key] !== undefined).map(key => [key, process.env[key]])),
  maxConcurrency = 2,
  loadTimeoutMs = 180000,
  onFatal = () => {},
} = {}) {
  if (!Number.isInteger(maxConcurrency) || maxConcurrency < 1 || maxConcurrency > 2) throw Error('Invalid embedding concurrency');
  if (!Number.isInteger(loadTimeoutMs) || loadTimeoutMs < 1 || loadTimeoutMs > 180000) throw Error('Invalid model load timeout');
  let child = null, ready = false, stopped = false, active = null, sequence = 0;
  let bootTimer, startPromise, resolveStart, rejectStart, closePromise, resolveClose;
  const queue = [];

  function settle(job, error) {
    job.signal?.removeEventListener('abort', job.abort);
    if (error) job.reject(error); else job.resolve(job.vectors);
  }
  function failQueue() { for (const job of queue.splice(0)) settle(job, new InferenceError('unavailable')); }
  function kill(error) {
    ready = false;
    if (active && !active.error) active.error = error;
    // kill() acknowledges sending a signal, not process termination.
    child?.kill('SIGKILL');
  }
  function sendText() {
    if (!active || !ready || !child || active.error) return;
    if (active.signal?.aborted) { active.abort(); return; }
    const job = active;
    job.messageId = ++sequence;
    child.send({ id: job.messageId, text: job.inputs[job.vectors.length] }, error => {
      if (error && active === job) kill(new InferenceError('unavailable'));
    });
  }
  function pump() {
    if (stopped || active || !ready || !child || queue.length === 0) return;
    active = queue.shift();
    sendText();
  }
  function boot() {
    if (stopped || child) return;
    ready = false;
    const processChild = fork(workerURL, [], { env: workerEnv, execArgv: [], stdio: ['ignore', 'ignore', 'ignore', 'ipc'], serialization: 'json' });
    child = processChild;
    let loaded = false, fatal = false;
    bootTimer = setTimeout(() => { fatal = true; kill(new InferenceError('unavailable')); }, loadTimeoutMs);
    bootTimer.unref();
    processChild.on('message', message => {
      // A timed-out boot may already have a ready message buffered in IPC.
      // Termination is final; never reopen admission before its close event.
      if (child !== processChild || stopped || fatal) return;
      if (!loaded && message?.type === 'ready') {
        loaded = true; ready = true; clearTimeout(bootTimer);
        resolveStart?.(); resolveStart = null; rejectStart = null;
        pump(); return;
      }
      if (message?.type === 'fatal') { fatal = true; kill(new InferenceError('unavailable')); return; }
      const job = active;
      if (!ready || !job || job.error) return;
      if (message?.id !== job.messageId || !['result', 'error'].includes(message.type)) {
        kill(new InferenceError('unavailable')); return;
      }
      let error;
      if (message.type === 'error') error = new InferenceError(message.code === 'dimension_mismatch' ? 'dimension_mismatch' : 'inference_failed');
      else if (!Array.isArray(message.vector) || message.vector.length !== 1024 || !message.vector.every(Number.isFinite)) error = new InferenceError('dimension_mismatch');
      if (error) { active = null; settle(job, error); setImmediate(pump); return; }
      job.vectors.push(message.vector);
      if (job.vectors.length === job.inputs.length) { active = null; settle(job); setImmediate(pump); }
      else setImmediate(sendText); // Give socket cancellation a turn before another text.
    });
    processChild.once('error', () => { fatal = !loaded; kill(new InferenceError('unavailable')); });
    // close also follows spawn errors, and follows exit for a running process.
    processChild.once('close', () => {
      if (child !== processChild) return;
      clearTimeout(bootTimer); child = null; ready = false;
      if (active) { const job = active; active = null; settle(job, job.error ?? new InferenceError('unavailable')); }
      failQueue();
      if (stopped) { rejectStart?.(new InferenceError('unavailable')); resolveClose?.(); return; }
      if (!loaded || fatal) {
        stopped = true; rejectStart?.(new InferenceError('unavailable'));
        onFatal(); return;
      }
      // Replacement starts only after the old OS process and IPC have exited.
      boot();
    });
  }
  return {
    start() {
      if (!startPromise) {
        startPromise = new Promise((resolve, reject) => { resolveStart = resolve; rejectStart = reject; });
        if (stopped) rejectStart(new InferenceError('unavailable')); else boot();
      }
      return startPromise;
    },
    status: () => ({ ready: ready && !stopped, active: active ? 1 : 0, queued: queue.length, pid: child?.pid }),
    run(inputs, { signal } = {}) {
      if (stopped || !ready) return Promise.reject(new InferenceError('unavailable'));
      if (signal?.aborted) return Promise.reject(new InferenceError('cancelled'));
      if (!Array.isArray(inputs) || inputs.length < 1 || inputs.length > 32 || !inputs.every(text => typeof text === 'string' && Buffer.byteLength(text) <= 16384)) return Promise.reject(new InferenceError('invalid_input'));
      if ((active ? 1 : 0) + queue.length >= maxConcurrency) return Promise.reject(new InferenceError('busy'));
      return new Promise((resolve, reject) => {
        const job = { inputs, signal, resolve, reject, vectors: [] };
        job.abort = () => {
          if (active === job) { kill(new InferenceError('cancelled')); return; }
          const index = queue.indexOf(job);
          if (index >= 0) { queue.splice(index, 1); settle(job, new InferenceError('cancelled')); }
        };
        signal?.addEventListener('abort', job.abort, { once: true });
        queue.push(job); pump();
      });
    },
    close() {
      if (!closePromise) {
        closePromise = new Promise(resolve => { resolveClose = resolve; });
        stopped = true; ready = false; clearTimeout(bootTimer); failQueue();
        if (child) kill(new InferenceError('unavailable')); else resolveClose();
      }
      return closePromise;
    },
  };
}
