export const LAMBDA_EXECUTION_ROLE_TRUST_POLICY = JSON.stringify({
  Version: "2012-10-17",
  Statement: [
    {
      Effect: "Allow",
      Action: "sts:AssumeRole",
      Principal: { Service: "lambda.amazonaws.com" },
    },
  ],
});

export function registerLambdaExecutionRoleTrust(): void {
  $transform(sst.aws.Function, (args: sst.aws.FunctionArgs) => {
    const previousRoleTransform = args.transform?.role;
    args.transform = {
      ...args.transform,
      role(
        roleArgs: sst.aws.FunctionRoleTransform,
        opts: Record<string, unknown>,
        name: string,
      ) {
        if (typeof previousRoleTransform === "function") {
          previousRoleTransform(roleArgs, opts, name);
        } else if (previousRoleTransform) {
          Object.assign(roleArgs, previousRoleTransform);
        }
        roleArgs.assumeRolePolicy = LAMBDA_EXECUTION_ROLE_TRUST_POLICY;
      },
    };
  });
}
