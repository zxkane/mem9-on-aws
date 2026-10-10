import { main } from '../../../scripts/verify-ci-smoke-isolation.mjs';

// Error text can contain credentials. Only these literal classifications may
// leave the action; unknown errors retain the generic result.
const safeCodes = new Set([
  'CiSmokeHostIdentity', 'CiSmokeHostCommandFailed', 'CiSmokeCheckoutChanged',
  'CiSmokeActualRoute', 'CiSmokeCurrentJobsIncomplete', 'CiSmokeSourceCommitment',
  'CiSmokeSourceDigest', 'CiSmokeCurrentJobMissing', 'CiSmokeCurrentJobName',
  'CiSmokeCurrentJobAmbiguous', 'CiSmokeCurrentJobTime', 'CiSmokeCurrentJobExpired',
  'CiSmokeGithubRun', 'CiSmokeGithubJobsIncomplete', 'CiSmokeGithubJobAmbiguous',
  'CiSmokeGithubJobSource', 'CiSmokeGithubBuildFailed', 'CiSmokeGithubBuildStepFailed',
  'CiSmokeGithubSmokeFailed', 'CiSmokeGithubPublishFailed', 'CiSmokeGithubCommit',
  'CiSmokeGithubMergeRelation', 'CiSmokeGithubCandidateTree', 'CiSmokeGithubSourceRelation',
  'CiSmokeCommitmentAmbiguous', 'CiSmokeArchiveConfiguration', 'CiSmokeArchiveFields',
  'CiSmokeArchivePolicyLimit', 'CiSmokeArchiveKmsScope', 'CiSmokeReadSessionHeld',
  'CiSmokeReadSessionCleanupHeld',
  'CiSmokeSourceReceiptRequired', 'CiSmokeSourceReceiptChanged', 'CiSmokeSourceReceiptExpired',
  'CiSmokeFields', 'CiSmokeCheckpointBinding', 'CiSmokeCheckpointPhase',
  'PreviewAcquisitionScope', 'PreviewAcquisitionRole', 'PreviewAcquisitionSource',
  'PreviewAcquisitionExpired', 'PreviewAcquisitionCallLimit', 'PreviewAcquisitionLocalScope',
  'PreviewAcquisitionParameterScope', 'PreviewAcquisitionEcsScope', 'PreviewAcquisitionRoleScope',
  'PreviewAcquisitionCaller', 'PreviewAcquisitionIncomplete', 'PreviewAcquisitionBundle',
  'NonrootBudgetReadFailed', 'NonrootAcquisitionRequired', 'NonrootControlCheckout',
  'NonrootPreviewParameterInventory', 'NonrootPreviewParameterBinding', 'NonrootPreviewParameterChanged',
  'NonrootPreviewSourceScope', 'NonrootPreviewSourceChanged', 'NonrootPreviewNetwork',
  'NonrootPreviewBackendInventory', 'NonrootPreviewBackendSelection', 'NonrootPreviewBackendDefinition',
  'NonrootPreviewRetainedDataRequired', 'NonrootPreviewRetainedDataBinding', 'NonrootPreviewRetainedDataTime',
  'NonrootPreviewReadbackChanged', 'NonrootPreviewTargetNotRegistered', 'NonrootPreviewPhaseExpired',
  'NonrootPreviewWorkloadParameters', 'NonrootPreviewWorkloadParametersChanged',
  'DataReleaseInvalid', 'DataReleaseAuthorizationExpired',
]);
const targetStages = new Set(['source-receipt', 'checkpoint', 'acquisition', 'verification', 'seal', 'completion']);
const readerPhases = new Set(['precheck', 'oidc', 'assume', 'identity', 'use']);
const readerReasons = new Set([
  'CiSmokeAwsExpiration', 'CiSmokeReadSessionInput', 'CiSmokeReadSessionEnvironment',
  'CiSmokeOidcEndpoint', 'CiSmokeOidcOrigin', 'CiSmokeOidcQuery', 'CiSmokeReadSessionDeadline', 'CiSmokeReadSessionAborted',
  'CiSmokeReadSessionEndpoint', 'CiSmokeReadSessionBody', 'CiSmokeReadSessionBodyLimit',
  'CiSmokeReadSessionHttp', 'CiSmokeReadSessionToken', 'CiSmokeReadSessionNoAmbientCredentials',
  'CiSmokeReadSessionCredentials', 'CiSmokeReadSessionExpiration', 'CiSmokeReadSessionIdentity',
  'CiSmokeReadSessionFailure',
]);

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
} catch (error) {
  // Never echo caller input, credentials or an arbitrary exception message.
  const code = error?.code === 'ECLEANUP' ? 'ECLEANUP' : safeCodes.has(error?.message) ? error.message : 'CiSmokeActionFailed';
  const diagnostic = { phase: 'ci-smoke-held', code };
  if (targetStages.has(error?.ciSmokeTargetStage)) diagnostic.targetStage = error.ciSmokeTargetStage;
  if (code === 'CiSmokeReadSessionHeld') {
    if (readerPhases.has(error.phase)) diagnostic.readerPhase = error.phase;
    if (readerReasons.has(error.reason)) diagnostic.reason = error.reason;
  }
  console.error(JSON.stringify(diagnostic));
  process.exitCode = 1;
}
