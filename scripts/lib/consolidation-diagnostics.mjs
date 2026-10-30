// Only bounded classes cross the child-process/logging boundary. Never forward
// exception messages, SQL text, parameters, namespaces or arbitrary properties.
const phases = new Set(['startup', 'database', 'claim', 'neighborhood', 'defer', 'runtime', 'unknown']);
const classes = new Set([
  '57014', '40P01', '55P03', '55000', '42501', '22023', '54000', '23505',
  '08000', '08001', '08003', '08006', '57P01', '57P02', '57P03', '53300',
  'PlannerError', 'ExecutorError', 'WorkerError', 'ConnectionError', 'Deadline',
]);
const connections = new Set(['ECONNREFUSED', 'ECONNRESET', 'ETIMEDOUT', 'ENOTFOUND', 'EAI_AGAIN', 'EPIPE']);

export function consolidationFailure(error, fallbackPhase = 'unknown', kind = 'planner') {
  const value = error?.errorClass ?? error?.code;
  return {
    phase: phases.has(error?.phase) ? error.phase : phases.has(fallbackPhase) ? fallbackPhase : 'unknown',
    errorClass: classes.has(value) ? value : connections.has(value) ? 'ConnectionError'
      : kind === 'executor' ? 'ExecutorError' : kind === 'worker' ? 'WorkerError' : 'PlannerError',
  };
}

// node-postgres emits idle-connection failures outside query promises. Race
// those events with the operation and keep a listener until the client closes.
export async function withDatabaseFailures(db, operation, onFailure = () => {}) {
  let rejectFailure;
  const failure = new Promise((_, reject) => { rejectFailure = reject; });
  const onError = error => {
    onFailure();
    rejectFailure(Object.assign(Error('database connection failed'), { code: error?.code, phase: 'database' }));
  };
  db.on('error', onError);
  try { return await Promise.race([Promise.resolve().then(operation), failure]); }
  finally {
    try { await db.end(); }
    finally { db.off('error', onError); }
  }
}
