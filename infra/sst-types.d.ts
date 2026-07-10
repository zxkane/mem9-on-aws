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
  }
}
