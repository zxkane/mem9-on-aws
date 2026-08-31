/**
 * Minimal ambient declarations for the SST v4 + Pulumi globals used by
 * the current `infra/*.ts` modules.
 *
 * SST bootstraps full types via `.sst/platform/config.d.ts` at deploy time,
 * but CI typecheck must run without first executing `sst install` (the
 * platform's source pulls in the whole Pulumi runtime + transitive deps and
 * is strict-mode-incompatible). This shim covers only the global surface the
 * repository uses.
 *
 * When the infrastructure adds a new construct, extend this file (don't expand the
 * triple-slash reference). At `sst deploy` time the platform's real types take
 * precedence — declaration-merging order means deploy-time inference does NOT
 * use these definitions, so a slightly loose shim here can't mask a real
 * deploy-time type error.
 */

// ── Pulumi Output/Input ────────────────────────────────────────────────────
declare namespace $util {
  interface Output<T> {
    apply<U>(fn: (value: T) => U | Output<U>): Output<U>;
  }
  type Input<T> = T | Promise<T> | Output<T>;
}
type Input<T> = $util.Input<T>;
type Output<T> = $util.Output<T>;

// ── SST globals ─────────────────────────────────────────────────────────────
interface $App {
  name: string;
  stage: string;
  providers?: Record<string, unknown>;
}
declare const $app: $App;

declare function $transform<A>(
  resource: new (...args: never[]) => unknown,
  cb: (args: A) => void,
): void;

declare function $config(input: unknown): unknown;

// Pulumi's tagged-template string interpolation over Output<T> values.
declare function $interpolate(
  strings: TemplateStringsArray,
  ...values: unknown[]
): Output<string>;

// Resolve nested Output/Promise values and serialize the result as JSON.
declare function $jsonStringify(value: unknown): Output<string>;

// ── The `aws` provider surface the scaffold touches ─────────────────────────
declare namespace aws {
  // Caller identity — infra/ecs.ts uses accountId to compose the ECR image URI
  // (never a hardcoded account id in committed code).
  interface GetCallerIdentityResult {
    readonly accountId: Output<string>;
    readonly arn: Output<string>;
    readonly userId: Output<string>;
  }
  function getCallerIdentityOutput(): GetCallerIdentityResult;

  interface GetPartitionResult {
    readonly partition: Output<string>;
  }
  function getPartitionOutput(): GetPartitionResult;

  // Region lookup — infra/oauth-facade.ts composes the Cognito domain / issuer
  // URLs from the deploy region.
  interface GetRegionResult {
    readonly name: Output<string>;
  }
  function getRegionOutput(): GetRegionResult;

  namespace iam {
    class Role {
      constructor(name: string, args: Record<string, unknown>, opts?: unknown);
      readonly arn: Output<string>;
      readonly name: Output<string>;
    }
    class RolePolicy {
      constructor(name: string, args: Record<string, unknown>, opts?: unknown);
    }
  }

  // Cognito user pool + M2M/OAuth client (infra/cognito.ts + infra/oauth-facade.ts).
  namespace cognito {
    interface UserPoolArgs {
      name?: Input<string>;
      schema?: {
        name: string;
        attributeDataType: string;
        mutable?: boolean;
        required?: boolean;
      }[];
      userAttributeUpdateSettings?: {
        attributesRequireVerificationBeforeUpdate: string[];
      };
      autoVerifiedAttributes?: string[];
      tags?: Record<string, Input<string>>;
      [k: string]: unknown;
    }
    class UserPool {
      constructor(name: string, args: UserPoolArgs, opts?: unknown);
      readonly id: Output<string>;
    }
    class UserPoolDomain {
      constructor(name: string, args: Record<string, unknown>, opts?: unknown);
      readonly domain: Output<string>;
    }
    class ResourceServer {
      constructor(name: string, args: Record<string, unknown>);
      readonly identifier: Output<string>;
    }
    interface UserPoolClientArgs {
      name?: Input<string>;
      userPoolId: Input<string>;
      generateSecret?: Input<boolean>;
      explicitAuthFlows?: Input<string>[];
      allowedOauthFlows?: Input<string>[];
      allowedOauthScopes?: Input<Input<string>[]>;
      allowedOauthFlowsUserPoolClient?: Input<boolean>;
      callbackUrls?: Input<Input<string>[]>;
      logoutUrls?: Input<Input<string>[]>;
      supportedIdentityProviders?: Input<string>[];
      preventUserExistenceErrors?: Input<string>;
      enableTokenRevocation?: Input<boolean>;
      [k: string]: unknown;
    }
    class UserPoolClient {
      constructor(name: string, args: UserPoolClientArgs, opts?: unknown);
      readonly id: Output<string>;
      readonly clientSecret: Output<string>;
    }
  }

  namespace lambda {
    // Only referenced as the $transform target + its arg shape.
    interface FunctionArgs {
      runtime?: Input<string>;
      packageType?: Input<string>;
    }
    class Function {}
    interface PermissionArgs {
      action: Input<string>;
      function: Input<string>;
      principal: Input<string>;
      sourceArn?: Input<string>;
    }
    class Permission {
      constructor(name: string, args: PermissionArgs);
    }
    interface FunctionEventInvokeConfigArgs {
      functionName: Input<string>;
      maximumRetryAttempts?: Input<number>;
      maximumEventAgeInSeconds?: Input<number>;
      destinationConfig?: {
        onFailure?: { destination: Input<string> };
        onSuccess?: { destination: Input<string> };
      };
    }
    class FunctionEventInvokeConfig {
      constructor(name: string, args: FunctionEventInvokeConfigArgs);
    }
  }

  namespace ec2 {
    interface GetVpcOutputArgs {
      id?: Input<string>;
      default?: Input<boolean>;
    }
    interface GetVpcResult {
      readonly id: Output<string>;
    }
    function getVpcOutput(args: GetVpcOutputArgs): GetVpcResult;

    interface GetSubnetsFilter {
      name: string;
      values: Input<string>[];
    }
    interface GetSubnetsOutputArgs {
      filters?: GetSubnetsFilter[];
    }
    interface GetSubnetsResult {
      readonly ids: Output<string[]>;
    }
    function getSubnetsOutput(args: GetSubnetsOutputArgs): GetSubnetsResult;

    // Security group + rule shapes used by infra/db.ts.
    interface SecurityGroupRule {
      protocol: Input<string>;
      fromPort: Input<number>;
      toPort: Input<number>;
      cidrBlocks?: Input<string>[];
      securityGroups?: Input<string>[];
      description?: Input<string>;
    }
    interface SecurityGroupArgs {
      vpcId: Input<string>;
      description?: Input<string>;
      ingress?: SecurityGroupRule[];
      egress?: SecurityGroupRule[];
      tags?: Record<string, Input<string>>;
    }
    class SecurityGroup {
      constructor(name: string, args: SecurityGroupArgs);
      readonly id: Output<string>;
      readonly arn: Output<string>;
    }
  }

  namespace secretsmanager {
    interface SecretArgs {
      name?: Input<string>;
      namePrefix?: Input<string>;
      description?: Input<string>;
      recoveryWindowInDays?: Input<number>;
      tags?: Record<string, Input<string>>;
    }
    class Secret {
      constructor(name: string, args: SecretArgs);
      readonly id: Output<string>;
      readonly arn: Output<string>;
    }
    interface SecretVersionArgs {
      secretId: Input<string>;
      secretString: Input<string>;
    }
    class SecretVersion {
      constructor(name: string, args: SecretVersionArgs);
      readonly arn: Output<string>;
    }
  }

  // CloudWatch metric filters + alarms (infra/observability.ts, issue #26).
  namespace cloudwatch {
    class EventRule {
      constructor(name: string, args?: Record<string, unknown>, opts?: unknown);
      readonly arn: Output<string>;
      readonly name: Output<string>;
    }
    class EventTarget {
      constructor(
        name: string,
        args: Record<string, unknown>,
        opts?: { dependsOn?: unknown[] },
      );
    }
    class LogGroup {
      constructor(name: string, args?: Record<string, unknown>, opts?: unknown);
      readonly arn: Output<string>;
      readonly name: Output<string>;
    }
    class LogResourcePolicy {
      constructor(
        name: string,
        args: Record<string, unknown>,
        opts?: unknown,
      );
    }
    interface LogMetricFilterMetricTransformation {
      name: Input<string>;
      namespace: Input<string>;
      value: Input<string>;
      defaultValue?: Input<string>;
      dimensions?: Input<Record<string, Input<string>>>;
    }
    interface LogMetricFilterArgs {
      logGroupName: Input<string>;
      pattern: Input<string>;
      metricTransformation: LogMetricFilterMetricTransformation;
      [k: string]: unknown;
    }
    class LogMetricFilter {
      constructor(
        name: string,
        args: LogMetricFilterArgs,
        opts?: { dependsOn?: unknown[] },
      );
    }
    interface MetricAlarmMetricQuery {
      id: Input<string>;
      metric?: {
        metricName: Input<string>;
        namespace: Input<string>;
        stat: Input<string>;
        period: Input<number>;
        dimensions?: Input<Record<string, Input<string>>>;
      };
      expression?: Input<string>;
      label?: Input<string>;
      returnData?: Input<boolean>;
    }
    interface MetricAlarmArgs {
      alarmDescription?: Input<string>;
      namespace?: Input<string>;
      metricName?: Input<string>;
      dimensions?: Input<Record<string, Input<string>>>;
      statistic?: Input<string>;
      period?: Input<number>;
      evaluationPeriods: Input<number>;
      datapointsToAlarm?: Input<number>;
      threshold?: Input<number>;
      comparisonOperator: Input<string>;
      treatMissingData?: Input<string>;
      metricQueries?: MetricAlarmMetricQuery[];
      alarmActions?: Input<Input<string>[]>;
      okActions?: Input<Input<string>[]>;
    }
    class MetricAlarm {
      constructor(name: string, args: MetricAlarmArgs);
      readonly arn: Output<string>;
    }
    interface CompositeAlarmActionsSuppressor {
      alarm: Input<string>;
      waitPeriod: Input<number>;
      extensionPeriod: Input<number>;
    }
    interface CompositeAlarmArgs {
      alarmName: Input<string>;
      alarmDescription?: Input<string>;
      alarmRule: Input<string>;
      actionsSuppressor?: Input<CompositeAlarmActionsSuppressor>;
      alarmActions?: Input<Input<string>[]>;
      okActions?: Input<Input<string>[]>;
    }
    class CompositeAlarm {
      constructor(name: string, args: CompositeAlarmArgs);
    }
    interface DashboardArgs {
      dashboardName?: Input<string>;
      dashboardBody: Input<string>;
    }
    class Dashboard {
      constructor(name: string, args: DashboardArgs);
    }
  }

  // SNS (infra/observability.ts — Slack alerting).
  namespace sns {
    interface TopicArgs {
      name?: Input<string>;
      tags?: Record<string, Input<string>>;
    }
    class Topic {
      constructor(name: string, args?: TopicArgs);
      readonly arn: Output<string>;
    }
    interface TopicSubscriptionArgs {
      topic: Input<string>;
      protocol: Input<string>;
      endpoint: Input<string>;
      redrivePolicy?: Input<string>;
    }
    class TopicSubscription {
      constructor(
        name: string,
        args: TopicSubscriptionArgs,
        opts?: { dependsOn?: unknown[] },
      );
    }
  }

  namespace sqs {
    interface QueueArgs {
      messageRetentionSeconds?: Input<number>;
      sqsManagedSseEnabled?: Input<boolean>;
      tags?: Record<string, Input<string>>;
    }
    class Queue {
      constructor(name: string, args?: QueueArgs);
      readonly arn: Output<string>;
      readonly name: Output<string>;
      readonly url: Output<string>;
    }
    interface QueuePolicyArgs {
      queueUrl: Input<string>;
      policy: Input<string>;
    }
    class QueuePolicy {
      constructor(name: string, args: QueuePolicyArgs);
    }
  }

  // The decision artifact's bucket (#150). Typed as classes with an `id`, because
  // the four hardening resources all key off `bucket: artifactBucket.id` — a
  // looser `Record<string, unknown>` shim would let a typo there through, and a
  // sub-resource pointed at the wrong bucket is a bucket that silently keeps the
  // provider default (unencrypted, no expiry) instead of failing the build.
  namespace s3 {
    interface BucketV2Args {
      bucket: Input<string>;
      forceDestroy?: Input<boolean>;
      tags?: Record<string, Input<string>>;
    }
    class BucketV2 {
      constructor(
        name: string,
        args: BucketV2Args,
        opts?: { retainOnDelete?: boolean },
      );
      readonly id: Output<string>;
      readonly arn: Output<string>;
      readonly bucket: Output<string>;
    }
    class BucketPublicAccessBlock {
      constructor(name: string, args: Record<string, unknown>, opts?: unknown);
    }
    class BucketServerSideEncryptionConfigurationV2 {
      constructor(name: string, args: Record<string, unknown>, opts?: unknown);
    }
    class BucketLifecycleConfigurationV2 {
      constructor(name: string, args: Record<string, unknown>, opts?: unknown);
    }
    class BucketPolicy {
      constructor(name: string, args: Record<string, unknown>, opts?: unknown);
    }
  }

  namespace ssm {
    interface ParameterArgs {
      name: Input<string>;
      type: Input<string>;
      value: Input<string>;
      tags?: Record<string, Input<string>>;
    }
    class Parameter {
      constructor(name: string, args: ParameterArgs);
      readonly name: Output<string>;
      readonly arn: Output<string>;
    }
    interface GetParameterOutputArgs {
      name: Input<string>;
    }
    interface GetParameterResult {
      readonly value: Output<string>;
      readonly arn: Output<string>;
    }
    function getParameterOutput(
      args: GetParameterOutputArgs,
    ): GetParameterResult;
  }

  namespace scheduler {
    class ScheduleGroup {
      constructor(name: string, args: Record<string, unknown>, opts?: unknown);
      readonly arn: Output<string>;
      readonly name: Output<string>;
    }
    class Schedule {
      constructor(name: string, args: Record<string, unknown>, opts?: unknown);
      readonly arn: Output<string>;
      readonly name: Output<string>;
    }
  }
}

// ── The `random` provider (tenant identity + non-production OAuth HMAC key) ──
declare namespace random {
  interface RandomIdArgs {
    byteLength: Input<number>;
    keepers?: Record<string, Input<string>>;
  }
  class RandomId {
    constructor(name: string, args: RandomIdArgs);
    readonly hex: Output<string>;
    readonly id: Output<string>;
  }

  interface RandomPasswordArgs {
    length: Input<number>;
    special?: Input<boolean>;
    keepers?: Record<string, Input<string>>;
  }
  class RandomPassword {
    constructor(name: string, args: RandomPasswordArgs);
    readonly result: Output<string>;
  }
}

// ── The `command` provider (infra/gateway.ts provisions the GatewayTarget via a
// local command that drives the direct bedrock-agentcore-control API) ──────────
declare namespace command {
  namespace local {
    interface CommandArgs {
      create?: Input<string>;
      delete?: Input<string>;
      update?: Input<string>;
      environment?: Input<Record<string, Input<string>>>;
      triggers?: Input<unknown[]>;
      [k: string]: unknown;
    }
    class Command {
      constructor(name: string, args: CommandArgs, opts?: unknown);
      readonly stdout: Output<string>;
      readonly stderr: Output<string>;
    }
  }
}

// ── The `sst.aws` component surface infra/db.ts uses ────────────────────────
declare namespace sst {
  namespace aws {
    interface AuroraScaling {
      min?: Input<string>;
      max?: Input<string>;
      pauseAfter?: Input<string>;
    }
    interface AuroraVpc {
      subnets: Input<string[]>;
      securityGroups: Input<string>[] | Input<string[]>;
    }
    interface AuroraClusterArgs {
      skipFinalSnapshot?: Input<boolean>;
      [k: string]: unknown;
    }
    interface AuroraArgs {
      engine: Input<"postgres" | "mysql">;
      version?: Input<string>;
      database?: Input<string>;
      username?: Input<string>;
      password?: Input<string>;
      proxy?: Input<boolean>;
      scaling?: AuroraScaling;
      vpc: AuroraVpc;
      transform?: {
        cluster?: (args: AuroraClusterArgs) => void;
        proxy?: (args: Record<string, unknown>) => void;
      };
    }
    class Aurora {
      constructor(name: string, args: AuroraArgs);
      readonly host: Output<string>;
      readonly port: Output<number>;
      readonly username: Output<string>;
      readonly password: Output<string>;
      readonly database: Output<string>;
      readonly secretArn: Output<string>;
    }

    // ── ECS (infra/ecs.ts) ────────────────────────────────────────────────
    interface ClusterVpc {
      id: Input<string>;
      securityGroups: Input<string>[] | Input<string[]>;
      containerSubnets?: Input<string[]>;
      loadBalancerSubnets?: Input<string[]>;
      publicSubnets?: Input<string[]>;
    }
    interface ClusterArgs {
      vpc: ClusterVpc;
      forceUpgrade?: Input<string>;
      transform?: { cluster?: (args: Record<string, unknown>) => void };
    }
    class Cluster {
      constructor(name: string, args: ClusterArgs);
      readonly nodes: {
        cluster: { name: Output<string>; arn: Output<string> };
      };
    }

    interface ServiceLogging {
      name?: Input<string>;
      retention?: Input<string>;
    }
    interface ContainerHealth {
      command: Input<string[]>;
      startPeriod?: Input<string>;
      interval?: Input<string>;
      timeout?: Input<string>;
      retries?: Input<number>;
    }
    // One entry of a multi-container task (FargateContainerArgs). When present on
    // ServiceArgs.containers, top-level image/environment/ssm/health/logging must
    // NOT be set (SST rejects both) — they live per-container here.
    interface FargateContainer {
      name: Input<string>;
      image: Input<string>;
      cpu?: Input<string>;
      memory?: Input<string>;
      command?: Input<string[]>;
      entrypoint?: Input<string[]>;
      environment?: Input<Record<string, Input<string>>>;
      ssm?: Input<Record<string, Input<string>>>;
      health?: Input<ContainerHealth>;
      logging?: ServiceLogging;
    }
    // A task-role IAM statement (FunctionPermissionArgs shape, shared by Service).
    // SST attaches these to the TASK role — the identity the container's default
    // credential chain resolves. Used here for the llm-proxy sidecar's Bedrock calls.
    interface FargatePermission {
      effect?: Input<"allow" | "deny">;
      actions: Input<string>[];
      resources: Input<Input<string>[]>;
      // Threaded into `iam.getPolicyDocumentOutput` by SST's
      // `createTaskRole` (.sst/platform/src/components/aws/fargate.ts), where
      // `FargateArgs.permissions` is literally `FunctionArgs["permissions"]` — so
      // this mirrors a field the upstream type has always had rather than adding
      // one. #150's artifact grant needs it: `kms:Decrypt`/`kms:GenerateDataKey`
      // against `alias/aws/s3` must be `Resource: "*"` (the alias resolves to a
      // per-account key id this stack cannot name without a lookup), which makes
      // the conditions the ONLY thing scoping it.
      conditions?: Input<
        Input<{
          test: Input<string>;
          variable: Input<string>;
          values: Input<Input<string>[]>;
        }>[]
      >;
    }
    interface ServiceArgs {
      cluster: Cluster;
      architecture?: Input<"x86_64" | "arm64">;
      cpu?: Input<string>;
      memory?: Input<string>;
      // Single-container mode: image/environment/ssm at the top level.
      image?: Input<string>;
      environment?: Input<Record<string, Input<string>>>;
      ssm?: Input<Record<string, Input<string>>>;
      // Multi-container (sidecar) mode: mutually exclusive with the above.
      containers?: Input<FargateContainer>[];
      logging?: ServiceLogging;
      // IAM statements attached to the task role (SST's `permissions`).
      permissions?: Input<FargatePermission>[];
      transform?: {
        taskDefinition?: (
          args: Record<string, unknown>,
          opts: Record<string, unknown>,
        ) => void;
        service?: (
          args: Record<string, unknown>,
          opts: Record<string, unknown>,
        ) => void;
      };
    }
    class Service {
      constructor(name: string, args: ServiceArgs);
      readonly nodes: {
        service: { name: Output<string>; arn: Output<string> };
        // Output<ecs.TaskDefinition>; observability wiring reads the
        // containerDefinitions JSON to find the real awslogs-group.
        taskDefinition: Output<unknown>;
      };
      readonly service: Output<string>;
    }

    // ── one-shot Task (infra/bootstrap.ts) ────────────────────────────────
    interface TaskArgs {
      cluster: Cluster;
      architecture?: Input<"x86_64" | "arm64">;
      cpu?: Input<string>;
      memory?: Input<string>;
      image?: Input<string>;
      command?: Input<Input<string>[]>;
      entrypoint?: Input<string[]>;
      environment?: Input<Record<string, Input<string>>>;
      ssm?: Input<Record<string, Input<string>>>;
      permissions?: Input<FargatePermission>[];
      logging?: ServiceLogging;
      transform?: { taskDefinition?: (args: Record<string, unknown>) => void };
    }
    class Task {
      constructor(name: string, args: TaskArgs);
      readonly assignPublicIp: Output<boolean>;
      readonly securityGroups: Output<string[]>;
      readonly subnets: Output<string[]>;
      readonly nodes: {
        executionRole: {
          arn: Output<string>;
          name: Output<string>;
        };
        taskRole: {
          arn: Output<string>;
          name: Output<string>;
        };
        taskDefinition: Output<unknown>;
      };
      readonly taskDefinition: Output<string>;
    }

    // ── Function (infra/gateway.ts — the MCP proxy Lambda) ────────────────
    interface FunctionVpc {
      privateSubnets: Input<string[]> | Input<string>[];
      securityGroups: Input<string[]> | Input<string>[];
    }
    interface FunctionRoleTransform {
      assumeRolePolicy?: Input<string>;
      name?: Input<string>;
    }
    type FunctionRoleTransformCallback = (
      args: FunctionRoleTransform,
      opts: Record<string, unknown>,
      name: string,
    ) => void;
    interface FunctionArgs {
      handler: Input<string>;
      name?: Input<string>;
      runtime?: Input<string>;
      timeout?: Input<string>;
      architecture?: Input<"x86_64" | "arm64">;
      memory?: Input<string>;
      vpc?: FunctionVpc;
      environment?: Input<Record<string, Input<string>>>;
      permissions?: {
        actions: string[];
        resources: Input<string>[];
        conditions?: {
          test: string;
          variable: string;
          values: Input<string>[];
        }[];
      }[];
      link?: unknown[];
      transform?: {
        role?: FunctionRoleTransform | FunctionRoleTransformCallback;
      };
    }
    class Function {
      constructor(name: string, args: FunctionArgs);
      readonly arn: Output<string>;
      readonly name: Output<string>;
      readonly nodes: {
        function: { name: Output<string>; arn: Output<string> };
        // The execution role. infra/slack-approval.ts attaches the approval
        // grants to the façade Function's existing role by NAME (which is what
        // aws.iam.RolePolicy takes) rather than creating a second Lambda role
        // that would need its own workload-boundary exception.
        role: { name: Output<string>; arn: Output<string> };
      };
    }

    // ── ApiGatewayV2 (infra/oauth-facade.ts — the OAuth login facade API) ─────
    interface ApiGatewayV2Cors {
      allowOrigins?: Input<string>[];
      allowMethods?: Input<string>[];
      allowHeaders?: Input<string>[];
      maxAge?: Input<string>;
    }
    interface ApiGatewayV2Domain {
      name: Input<string>;
      dns?: unknown;
    }
    interface ApiGatewayV2Args {
      domain?: Input<string | ApiGatewayV2Domain>;
      cors?: ApiGatewayV2Cors;
    }
    interface ApiGatewayV2AuthorizerArgs {
      name: string;
      lambda: {
        function: Input<string | FunctionArgs>;
        identitySources?: Input<Input<string>[]>;
        response?: Input<"simple" | "iam">;
        ttl?: Input<string>;
      };
    }
    class ApiGatewayV2 {
      constructor(name: string, args?: ApiGatewayV2Args);
      readonly url: Output<string>;
      addAuthorizer(args: ApiGatewayV2AuthorizerArgs): {
        readonly id: Output<string>;
      };
      route(route: string, handler: Input<string>, args?: unknown): void;
    }
  }

  namespace cloudflare {
    interface DnsArgs {
      zone?: Input<string>;
      proxy?: Input<boolean>;
    }
    function dns(args?: DnsArgs): unknown;
  }

  // ── sst.Secret (infra/oauth-facade.ts — OAuth client secret / signing key) ──
  class Secret {
    constructor(name: string, defaultValue?: string);
    readonly value: Output<string>;
  }
}
