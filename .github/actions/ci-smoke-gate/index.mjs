import { main } from '../../../scripts/verify-ci-smoke-isolation.mjs';

// The Node action handler supplies artifact credentials to this process.
// Keep them here: no shell, child process, exported environment or argv input.
try {
  const env = process.env;
  const mode = env.INPUT_MODE;
  const phase = env.INPUT_PHASE ?? '';
  const phases = ['preupdate', 'preconfigure', 'presst', 'prereadiness'];
  if (process.argv.length !== 2 ||
      Object.keys(env).some(key => key.startsWith('INPUT_') && !['INPUT_MODE', 'INPUT_PHASE'].includes(key)) ||
      !['source', 'target'].includes(mode) ||
      (mode === 'source' ? phase !== '' : !phases.includes(phase)) ||
      !/^[a-z][a-z0-9-]{0,63}$/.test(env.GITHUB_JOB ?? '')) {
    throw Error('CiSmokeActionInput');
  }
  const args = [mode, '--route', env.GITHUB_JOB];
  if (mode === 'target') args.push('--phase', phase);
  console.log(JSON.stringify(await main(args, env)));
} catch {
  // Never echo caller input, credentials or an arbitrary exception message.
  console.error(JSON.stringify({ phase: 'ci-smoke-held', code: 'CiSmokeActionFailed' }));
  process.exitCode = 1;
}
