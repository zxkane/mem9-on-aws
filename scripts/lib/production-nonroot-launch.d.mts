/** Pure construction/validation only. Successful validation grants no authority. */
export type NonrootDataComponent = 'mnemo-server' | 'qwen3-embed' | 'llm-proxy' | 'planner' | 'executor';
export type NonrootBackendComponent = 'mnemo-server' | 'qwen3-embed' | 'llm-proxy';
export type NonrootControlPurpose =
  | 'bootstrap-runtime-verify' | 'consolidation-control' | 'consolidation-promote'
  | 'denied-provision' | 'denied-transition' | 'audit-original-root'
  | 'bootstrap-runtime-bootstrap' | 'bootstrap-admin-probe' | 'bootstrap-admin-probe-cleanup'
  | 'preview-fixture-setup' | 'preview-fixture-pause' | 'preview-fixture-verify-planned'
  | 'preview-fixture-verify-executed' | 'preview-fixture-verify-repeated'
  | 'post-runtime-fixture' | 'canary-fixture' | 'bootstrap-schema-seed';

/** Complete immutable container JSON, including unchanged unrelated fields.
 * Unknown fields remain unknown to TypeScript; runtime values are inert JSON. */
export interface NonrootContainerDefinition {
  readonly [key: string]: unknown;
  readonly user: '1000:1000';
  readonly entryPoint: readonly string[];
  readonly command?: readonly string[];
  readonly linuxParameters: {
    readonly [key: string]: unknown;
    readonly capabilities: {readonly drop: readonly ['ALL']};
  };
}
/** Mapping must come from authenticated passwd bytes in this exact image.
 * This structure and its digest alone do not authenticate that evidence. */
export interface NamedNodeUserIdentity {
  readonly image: string;
  readonly username: 'node';
  readonly uid: 1000;
  readonly gid: 1000;
  readonly passwdSha256: string;
}
export interface ControlLaunchOptions {
  readonly namedUserIdentity?: NamedNodeUserIdentity;
}
/** Preserves the reviewed DATA application argv and wraps independent health launches. */
export function dataLaunchPolicy(component: NonrootDataComponent, original: unknown): NonrootContainerDefinition;
/** Purpose is validated against NonrootControlPurpose at runtime, allowing raw
 * JSON callers. CONTROL always selects /usr/local/bin/node absolutely. */
export function controlLaunchPolicy(purpose: string, original?: unknown, options?: ControlLaunchOptions):
  NonrootContainerDefinition & {readonly command: readonly []};

export const NONROOT_FORBIDDEN_ENVIRONMENT: readonly string[];
export interface EnvironmentVariable {readonly name: string; readonly value: string}
export interface NonrootEnvironmentInput {
  readonly imageEnvironment: readonly string[];
  readonly taskEnvironment: readonly EnvironmentVariable[];
  readonly secrets: readonly {readonly name: string; readonly valueFrom: string}[];
  readonly overrides: {readonly containerOverrides?: readonly {
    readonly name: 'ControlMem9Bootstrap'; readonly environment: readonly EnvironmentVariable[];
  }[]};
  readonly files: readonly ({readonly path: string; readonly mode: number; readonly uid: number; readonly gid: number} & (
    {readonly type: 'directory'} | {readonly type: 'file'; readonly sha256: string}
  ))[];
  readonly expectedCa: readonly {readonly path: string; readonly sha256: string}[];
}
export interface NonrootEnvironmentHashes {
  readonly imageEnvironmentHash: string;
  readonly taskEnvironmentHash: string;
  readonly secretNamesAndReferencesHash: string;
  readonly overrideHash: string;
  readonly caBindingsHash: string;
  readonly forbiddenNamesHash: string;
}
/** Validates all sources, including secret names. Returns hashes, never values/approval. */
export function validateNonrootEnvironment(input: unknown): NonrootEnvironmentHashes;

export interface CarrierRunOverridesV1 {
  readonly containerOverrides: readonly [{
    readonly name: 'ControlMem9Bootstrap';
    readonly environment: readonly [
      {readonly name: 'MEM9_SUPERSESSION_ROOT_INPUT'; readonly value: string},
      {readonly name: 'MEM9_SUPERSESSION_ROOT_HASH'; readonly value: string},
      {readonly name: 'MEM9_SUPERSESSION_ROOT_CODE_HASH'; readonly value: string},
    ];
  }];
}
export interface CarrierInvocation {
  readonly invocation: string;
  readonly runOverrides: CarrierRunOverridesV1;
}
/** Closed runtime-validated request. Every unlisted AWS request field is rejected. */
export interface CarrierRunTaskRequestV1 {
  readonly cluster: string;
  readonly count: 1;
  readonly launchType: 'FARGATE';
  readonly platformVersion: string;
  readonly networkConfiguration: {readonly awsvpcConfiguration: {
    readonly subnets: readonly string[];
    readonly securityGroups: readonly [string];
    readonly assignPublicIp: 'DISABLED';
  }};
  readonly enableExecuteCommand: false;
  readonly enableECSManagedTags: false;
  readonly propagateTags: 'NONE';
  readonly tags: readonly [{readonly key: 'mem9-supersession-owner'; readonly value: string}];
  readonly taskDefinition: string;
  readonly clientToken: string;
  readonly startedBy: string;
  readonly overrides: CarrierRunOverridesV1;
}
export interface CarrierRunTaskBindingV1 {
  readonly version: 1;
  readonly kind: 'permit-bound-carrier-runtask';
  readonly request: CarrierRunTaskRequestV1;
  readonly requestHash: string;
  readonly launchPlanHash: string;
  readonly runTaskContractHash: string;
  readonly registrationReadbackHash: string;
  readonly environmentGateHash: string;
  readonly carrierPresenceHash: string;
  readonly authorization: {
    readonly permissionsDossierHash: string;
    readonly requestHash: string;
    readonly callerArn: string;
    readonly action: 'ecs:RunTask';
    readonly taskDefinitionArn: string;
    readonly clusterArn: string;
    readonly taskRoleArn: string;
    readonly executionRoleArn: string;
    readonly decision: 'allowed';
  };
}
export interface CarrierBindingContext {
  /** Raw records are inspected by their closed runtime schemas. */
  readonly plan: unknown;
  readonly readback: unknown;
  readonly environmentGate: unknown;
  readonly carrierPresence: unknown;
  readonly permissions: unknown;
  readonly invocation: CarrierInvocation;
  readonly now: number;
  /** Independently authenticated admission commitments, never self-derived pins. */
  readonly expected: {
    readonly planHash: string; readonly readbackHash: string; readonly environmentGateHash: string;
    readonly carrierPresenceHash: string; readonly permissionsHash: string; readonly carrierBuildHash: string;
    readonly requestHash: string; readonly callerArn: string; readonly deadlineMs: number; readonly reviewExpiresMs: number;
  };
}
/** Resolves exact request data after registration; does not permit dispatch. */
export function resolveCarrierRunTaskRequest(plan: unknown, readback: unknown, invocation: CarrierInvocation): CarrierRunTaskRequestV1;
export function verifyCarrierRunTaskBinding(binding: unknown, context: CarrierBindingContext): CarrierRunTaskBindingV1;
/** Recheck after all awaits at the final API boundary. Performs no API call. */
export function assertCarrierRunTaskDispatch(request: unknown, binding: unknown, context: CarrierBindingContext): void;

export interface TargetIdentityRecheckContext {
  readonly auditStartedMs: number;
  readonly auditCompletedMs: number;
  readonly now: number;
  readonly healthCommands: Readonly<Record<NonrootBackendComponent, readonly string[]>>;
  readonly mainEntrypointIdentityHashes: Readonly<Record<NonrootBackendComponent, string>>;
}
export function verifyTargetIdentityRecheck(recheck: unknown, preTarget: unknown, context: TargetIdentityRecheckContext):
  import('./production-nonroot-contracts.mjs').TargetIdentityRecheckV1;
