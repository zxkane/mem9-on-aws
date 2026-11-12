// Only fixed result/error messages cross the private parent IPC channel.
const MODEL_REPO = process.env.QWEN3_EMBED_MODEL_REPO || 'onnx-community/Qwen3-Embedding-0.6B-ONNX';
const threads = Number(process.env.QWEN3_INTRA_OP_THREADS || 0);
if (!process.send || !Number.isSafeInteger(threads) || threads < 0 || threads > 64) process.exit(1);
process.once('disconnect', () => process.exit(0));

try {
  const mod = await import('@huggingface/transformers');
  const options = { dtype: 'fp32' };
  if (threads > 0) options.session_options = { intraOpNumThreads: threads, interOpNumThreads: 1, executionMode: 'sequential' };
  const extractor = await mod.pipeline('feature-extraction', MODEL_REPO, options);
  let busy = false;
  process.on('message', async message => {
    if (busy || !Number.isSafeInteger(message?.id) || typeof message.text !== 'string' || Buffer.byteLength(message.text) > 16384) process.exit(1);
    busy = true;
    try {
      // Preserve single-text last_token pooling, fp32 and L2 normalization.
      const output = await extractor(message.text, { pooling: 'last_token', normalize: true });
      const vector = Array.from(output.data);
      if (vector.length !== 1024 || !vector.every(Number.isFinite)) process.send({ type: 'error', id: message.id, code: 'dimension_mismatch' });
      else process.send({ type: 'result', id: message.id, vector });
    } catch {
      process.send({ type: 'error', id: message.id, code: 'inference_failed' });
    } finally { busy = false; }
  });
  process.send({ type: 'ready' });
} catch {
  process.send({ type: 'fatal' }, () => process.exit(1));
}
