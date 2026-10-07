import { EventEmitter } from 'node:events';
import { afterEach, expect, it, vi } from 'vitest';
import { createAwsCliAdapter } from './lib/workload-permissions-boundary-aws.mjs';
import { installSubprocessSignalHandlers } from './lib/bounded-subprocess.mjs';
import { DEPLOY_ROLE_NAME, QUARANTINE_POLICY_NAME, quarantinePolicyDocument } from './lib/workload-permissions-boundary.mjs';
import { createRetainedOperatorFixture } from './test-fixtures/retained-operator.mjs';

const names = [DEPLOY_ROLE_NAME, `${DEPLOY_ROLE_NAME}-preview`, `${DEPLOY_ROLE_NAME}-prod`].sort();
const argument = (args, name) => args[args.indexOf(name) + 1];

afterEach(() => {
  vi.doUnmock('./lib/workload-permissions-boundary-aws.mjs');
  vi.doUnmock('./lib/bounded-subprocess.mjs');
  vi.doUnmock('./rollout-workload-permissions-boundary.mjs');
  vi.unstubAllEnvs();
  vi.resetModules();
});

it.each([['SIGINT', 130], ['SIGTERM', 143]])(
  'TC117: real CLI preserves bounded group recovery after %s', async (interrupt, exitCode) => {
    const metadata = createRetainedOperatorFixture();
    const quarantined = new Set(names);
    const processSignals = new EventEmitter();
    const calls = [];
    const previousExitCode = process.exitCode;
    let operationSignal, failure;
    const aws = async (args, options) => {
      const command = args.slice(0, 2).join(' '), name = argument(args, '--role-name');
      calls.push({ command, name, signal: options.signal, aborted: options.signal.aborted });
      options.signal.throwIfAborted();
      if (args[0] === 'cloudformation' || command === 'iam get-role') return metadata.invokeAws(args);
      if (command === 'iam delete-role-policy') {
        quarantined.delete(name);
        if (name === names[1]) {
          // The second deletion may have reached IAM before its reply is lost.
          // Use the real signal handler and adapter; only remote I/O is synthetic.
          processSignals.emit(interrupt);
          options.signal.throwIfAborted();
        }
        return {};
      }
      if (command === 'iam put-role-policy') {
        expect(JSON.parse(argument(args, '--policy-document'))).toEqual(quarantinePolicyDocument());
        quarantined.add(name);
        return {};
      }
      if (command === 'iam list-role-policies') return {
        PolicyNames: quarantined.has(name) ? [QUARANTINE_POLICY_NAME] : [], IsTruncated: false,
      };
      if (command === 'iam get-role-policy') {
        expect(quarantined.has(name)).toBe(true);
        return { PolicyDocument: quarantinePolicyDocument() };
      }
      if (command === 'iam simulate-custom-policy') {
        const start = args.indexOf('--action-names') + 1;
        const end = args.findIndex((value, index) => index >= start && value.startsWith('--'));
        return { EvaluationResults: args.slice(start, end < 0 ? undefined : end)
          .map(EvalActionName => ({ EvalActionName, EvalDecision: 'explicitDeny' })) };
      }
      throw new Error(`unexpected synthetic operation: ${command}`);
    };
    // Exercise the actual entrypoint's invokeAws wrapper and the actual adapter's
    // coordinated recovery. No GitHub or AWS service is contacted by this fixture.
    vi.doMock('./lib/workload-permissions-boundary-aws.mjs', () => ({ invokeAwsCli: aws }));
    vi.doMock('./lib/bounded-subprocess.mjs', () => ({
      installSubprocessSignalHandlers: () => installSubprocessSignalHandlers({ processTarget: processSignals }),
    }));
    vi.doMock('./rollout-workload-permissions-boundary.mjs', () => ({
      parseRolloutArguments: () => ({ deadlineAt: Date.now() + 60_000, reviewedCommit: 'a'.repeat(40) }),
      createGithubMaintenanceController: () => ({
        activateProductionBoundary: () => { throw new Error('unexpected activation'); },
        resumeDeployments: () => { throw new Error('unexpected resume'); },
        verifyFinalInterlock: () => { throw new Error('unexpected GitHub request'); },
      }),
      executeBoundaryRollout: async ({ invokeAws, signal, deadlineAt }) => {
        operationSignal = signal;
        const adapter = createAwsCliAdapter({
          identity: { partition: 'aws', accountId: '123456789012' }, applicationRegion: 'ap-northeast-1',
          invokeAws, signal, deadlineAt, consistencyAttempts: 1, sleep: async () => {},
        });
        await adapter.resolveDeploymentRoles();
        await adapter.deleteQuarantines({ roleNames: names, policyName: QUARANTINE_POLICY_NAME });
      },
      runBoundaryRolloutCli: async ({ execute }) => {
        try { await execute(); } catch (error) { failure = error; process.exitCode = 1; }
      },
    }));
    vi.stubEnv('WORKLOAD_BOUNDARY_GATES_VERIFIED', 'true');
    try {
      await import('./run-workload-permissions-boundary-rollout.mjs');
      expect(operationSignal.aborted).toBe(true);
      expect(failure?.message).toMatch(/release was uncertain; group restored/u);
      expect([...quarantined].sort()).toEqual(names);
      const restores = calls.filter(call => call.command === 'iam put-role-policy');
      expect(restores.map(call => call.name).sort()).toEqual(names);
      expect(restores.every(call => !call.aborted && call.signal !== operationSignal)).toBe(true);
      for (const name of names) expect(calls.some(call => call.command === 'iam get-role-policy' &&
        call.name === name && call.signal !== operationSignal && !call.aborted)).toBe(true);
      expect(process.exitCode).toBe(exitCode);
      expect(processSignals.listenerCount(interrupt)).toBe(0);
    } finally { process.exitCode = previousExitCode; }
  },
);
