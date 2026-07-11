/**
 * Minimal ambient declarations for the SST v4 + Pulumi globals used by
 * `infra/*.ts` in the mem9-on-aws BASE SCAFFOLD.
 *
 * SST bootstraps full types via `.sst/platform/config.d.ts` at deploy time,
 * but CI typecheck must run without first executing `sst install` (the
 * platform's source pulls in the whole Pulumi runtime + transitive deps and
 * is strict-mode-incompatible). This shim covers ONLY the surface the scaffold
 * uses: `$app`, `$transform`, `$config`, `$interpolate`, `aws.ec2.getVpcOutput`,
 * `aws.ec2.getSubnetsOutput`, and `aws.ssm.Parameter`.
 *
 * When a follow-up adds a new construct, EXTEND this file (don't expand the
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

  namespace lambda {
    // Only referenced as the $transform target + its arg shape.
    interface FunctionArgs {
      runtime?: Input<string>;
      packageType?: Input<string>;
    }
    class Function {}
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
    function getParameterOutput(args: GetParameterOutputArgs): GetParameterResult;
  }
}

// ── The `random` provider (infra/bootstrap.ts uses RandomId for the tenant key) ──
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
      transform?: { cluster?: (args: Record<string, unknown>) => void };
    }
    class Cluster {
      constructor(name: string, args: ClusterArgs);
      readonly nodes: { cluster: { name: Output<string>; arn: Output<string> } };
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
      transform?: { service?: (args: Record<string, unknown>) => void };
    }
    class Service {
      constructor(name: string, args: ServiceArgs);
      readonly nodes: { service: { name: Output<string>; arn: Output<string> } };
      readonly service: Output<string>;
    }

    // ── one-shot Task (infra/bootstrap.ts) ────────────────────────────────
    interface TaskArgs {
      cluster: Cluster;
      architecture?: Input<"x86_64" | "arm64">;
      cpu?: Input<string>;
      memory?: Input<string>;
      image?: Input<string>;
      environment?: Input<Record<string, Input<string>>>;
      ssm?: Input<Record<string, Input<string>>>;
      logging?: ServiceLogging;
      transform?: { taskDefinition?: (args: Record<string, unknown>) => void };
    }
    class Task {
      constructor(name: string, args: TaskArgs);
      readonly nodes: { task: { arn: Output<string> } };
      readonly taskDefinition: Output<string>;
    }
  }
}
