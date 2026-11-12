// OpenAI-compatible HTTP supervisor for one always-warm Qwen ONNX process.
import { createServer } from 'node:http';
import { pathToFileURL } from 'node:url';
import { createMaintenanceAdmission } from './maintenance-admission.mjs';
import { createInferencePool, InferenceError } from './inference-pool.mjs';

export function readLimits(env = process.env) {
  const integer = (name, fallback, maximum) => {
    const value = env[name];
    if (value === undefined || value === '') return fallback;
    if (!/^[1-9][0-9]*$/.test(value) || !Number.isSafeInteger(Number(value)) || Number(value) > maximum) throw Error('Invalid embedding limit: ' + name);
    return Number(value);
  };
  return {
    bodyTimeoutMs: 15000, // Fixed production limit; factory overrides support HTTP tests.
    maxInputs: integer('QWEN3_EMBED_MAX_INPUTS', 32, 32),
    maxInputBytes: integer('QWEN3_EMBED_MAX_INPUT_BYTES', 16384, 16384),
    maxConcurrency: integer('QWEN3_EMBED_MAX_CONCURRENCY', 2, 2),
    maxBodyBytes: integer('QWEN3_EMBED_MAX_BODY_BYTES', 540672, 1048576),
    deadlineMs: integer('QWEN3_EMBED_OVERALL_DEADLINE_MS', 55000, 120000),
  };
}

function sendJson(res, status, value) {
  if (res.destroyed || res.writableEnded || res.headersSent) return;
  const body = JSON.stringify(value);
  res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) });
  res.end(body);
}
function sendError(res, status, message) { sendJson(res, status, { error: { message, type: status >= 500 ? 'server_error' : 'invalid_request_error' } }); }

// Async-iterator early-exit can destroy the socket before a 413 is sent.
function readBody(req, signal, limit, metadata, timeoutMs) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let timer;
    const cleanup = () => { clearTimeout(timer); req.off('data', data); req.off('end', end); req.off('error', failed); req.off('aborted', failed); signal.removeEventListener('abort', failed); };
    const failed = () => { cleanup(); reject(new InferenceError('cancelled')); };
    const data = chunk => {
      metadata.bytes = Math.min(limit + 1, metadata.bytes + chunk.length);
      if (metadata.bytes > limit) { cleanup(); req.resume(); reject(new InferenceError('body_too_large')); }
      else chunks.push(chunk);
    };
    const end = () => { cleanup(); resolve(Buffer.concat(chunks).toString('utf8')); };
    if (signal.aborted) { failed(); return; }
    timer = setTimeout(() => { cleanup(); req.resume(); reject(new InferenceError('body_timeout')); }, timeoutMs);
    timer.unref();
    req.on('data', data); req.once('end', end); req.once('error', failed); req.once('aborted', failed);
    signal.addEventListener('abort', failed, { once: true });
  });
}

export function createEmbeddingServer({ pool, limits = readLimits(), log = line => console.error(line), modelId = 'qwen3-embedding-0.6b', stage = 'local' }) {
  if (typeof stage !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(stage)) throw Error('Invalid embedding stage');
  const maintenanceAdmission = createMaintenanceAdmission();
  const server = createServer({ connectionsCheckingInterval: 1000 }, async (req, res) => {
    const abort = new AbortController();
    const closed = () => { if (!res.writableEnded) abort.abort(); };
    res.once('close', closed); // IncomingMessage.close also fires for a consumed body.
    const metadata = { bytes: 0, inputs: 0, maintenance: false };
    let timer, deadlineAt, deadline = false;
    const event = (code, status) => log(JSON.stringify({ msg: 'embed request outcome', event: code, status, route: 'embeddings', stage, ...metadata }));
    const reject = (status, code, message) => { event(code, status); sendError(res, status, message); };
    try {
      const url = new URL(req.url, 'http://localhost');
      if (req.method === 'GET' && ['/health', '/healthz'].includes(url.pathname)) {
        const ready = pool.status().ready;
        return sendJson(res, ready ? 200 : 503, { status: ready ? 'ok' : 'loading' });
      }
      if (req.method !== 'POST' || !['/embeddings', '/v1/embeddings'].includes(url.pathname)) return sendError(res, 404, 'route not found');
      const raw = await readBody(req, abort.signal, limits.maxBodyBytes, metadata, limits.bodyTimeoutMs);
      let payload;
      try { payload = JSON.parse(raw); }
      catch { return reject(400, 'embed_invalid_json', 'request body is not valid JSON'); }
      const inputs = typeof payload?.input === 'string' ? [payload.input] : payload?.input;
      if (!Array.isArray(inputs) || inputs.length < 1 || inputs.length > limits.maxInputs || !inputs.every(value => typeof value === 'string')) return reject(400, 'embed_invalid_input', 'input must contain a bounded non-empty list of strings');
      metadata.inputs = inputs.length;
      if (inputs.some(value => Buffer.byteLength(value) > limits.maxInputBytes)) return reject(413, 'embed_invalid_input', 'input exceeds per-text byte limit');
      const maintenance = req.headers['x-mem9-maintenance'];
      metadata.maintenance = maintenance === '1';
      if (maintenance !== undefined && (maintenance !== '1' || inputs.length !== 1 || Buffer.byteLength(inputs[0]) > 16384)) return reject(400, 'embed_invalid_maintenance', 'invalid maintenance embedding request');

      deadlineAt = performance.now() + limits.deadlineMs;
      timer = setTimeout(() => { deadline = true; abort.abort(); }, limits.deadlineMs);
      timer.unref();
      const compute = () => pool.run(inputs, { signal: abort.signal });
      let vectors;
      if (maintenance === '1') {
        const admitted = await maintenanceAdmission.run(compute);
        if (!admitted.accepted) { res.setHeader('Retry-After', '1'); return reject(429, 'embed_maintenance_busy', 'maintenance embedding busy'); }
        vectors = admitted.value;
        res.setHeader('X-Mem9-Maintenance', '1');
      } else vectors = await compute();
      if (deadline || performance.now() >= deadlineAt) return reject(503, 'embed_deadline_exceeded', 'embedding deadline exceeded');
      if (abort.signal.aborted || res.destroyed) { event('embed_client_closed', 499); return; }
      const approxTokens = Math.ceil(inputs.reduce((sum, text) => sum + text.length, 0) / 4);
      sendJson(res, 200, {
        object: 'list', data: vectors.map((embedding, index) => ({ object: 'embedding', index, embedding })),
        model: typeof payload?.model === 'string' && payload.model ? payload.model : modelId,
        usage: { prompt_tokens: approxTokens, total_tokens: approxTokens },
      });
    } catch (error) {
      const code = error instanceof InferenceError ? error.code : 'inference_failed';
      if (code === 'body_too_large' || code === 'body_timeout') {
        res.setHeader('Connection', 'close'); res.once('finish', () => req.destroy());
        if (code === 'body_timeout') reject(408, 'embed_body_timeout', 'request body timed out');
        else reject(413, 'embed_body_too_large', 'request body too large');
      } else if (deadline) reject(503, 'embed_deadline_exceeded', 'embedding deadline exceeded');
      else if (code === 'cancelled') event('embed_client_closed', 499);
      else if (code === 'busy') { res.setHeader('Retry-After', '1'); reject(429, 'embed_busy', 'embedding service busy'); }
      else if (code === 'unavailable') { res.setHeader('Retry-After', '1'); reject(503, 'embed_model_unavailable', 'embedding service unavailable'); }
      else reject(500, code === 'dimension_mismatch' ? 'embed_dim_mismatch' : 'embed_request_error', 'internal error computing embedding');
    } finally { clearTimeout(timer); res.off('close', closed); }
  });
  server.headersTimeout = 10000;
  server.requestTimeout = 15000;
  server.keepAliveTimeout = 5000;
  server.maxConnections = 64;
  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const limits = readLimits();
  const pool = createInferencePool({ maxConcurrency: limits.maxConcurrency, onFatal: () => { console.error('embed_model_unavailable'); process.exit(1); } });
  const server = createEmbeddingServer({ pool, limits, modelId: process.env.QWEN3_EMBED_MODEL_ID || 'qwen3-embedding-0.6b', stage: process.env.MEM9_STAGE || 'local' });
  const port = Number(process.env.QWEN3_EMBED_PORT || 8081);
  server.listen(port, () => { console.log('qwen3-embed supervisor listening'); });
  pool.start().then(() => console.log('qwen3-embed model ready')).catch(() => { console.error('embed_model_unavailable'); process.exit(1); });
  for (const signal of ['SIGTERM', 'SIGINT']) process.once(signal, async () => {
    server.close(); server.closeAllConnections(); await pool.close(); process.exit(0);
  });
}
