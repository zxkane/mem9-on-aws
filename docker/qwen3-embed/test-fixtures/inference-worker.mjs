import { appendFileSync } from 'node:fs';

process.on('disconnect', () => process.exit(0));
process.on('message', ({ id, text }) => {
  if (process.env.TEST_CALL_LOG) appendFileSync(process.env.TEST_CALL_LOG, JSON.stringify({ pid: process.pid, text }) + '\n', { mode: 0o600 });
  if (text === 'hang') { for (;;) { /* Deliberately block only the disposable child. */ } }
  if (text === 'crash') process.exit(7);
  if (text === 'secret-error') return process.send({ type: 'error', id, code: 'SYNTHETIC_SECRET_ERROR' });
  const reply = () => process.send({ type: 'result', id, vector: Array(text === 'wrong-dim' ? 3 : 1024).fill(process.pid) });
  if (text === 'slow') setTimeout(reply, 250);
  else reply();
});
if (process.env.TEST_BOOT === 'hang') { for (;;) {} }
else if (process.env.TEST_BOOT === 'fail') process.send({ type: 'fatal' });
else process.send({ type: 'ready' });
