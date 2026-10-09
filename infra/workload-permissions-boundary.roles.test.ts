import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { afterAll, afterEach, describe, expect, it, vi } from "vitest";
import { WORKLOAD_BOUNDARY_POLICY_NAME } from "./workload-permissions-boundary";
import {
  EXPECTED_WORKLOAD_ROLE_NAMES,
} from "./workload-permissions-boundary.test-fixtures";

// This suite synthesizes a mocked resource graph, not CI/source provenance.
// Real source authentication and Docker/AWS readbacks have dedicated tests.
vi.mock('node:child_process',async original=>{
  const actual=await original<typeof import('node:child_process')>();
  return {...actual,execFileSync:(command:string,args:string[],options:unknown)=>{
    if(command==='git'&&['ls-files','diff'].includes(args[0]))return Buffer.alloc(0);
    if(command==='git'&&args.join(' ')==='rev-parse HEAD^{tree}')return 'a'.repeat(40)+'\n';
    return actual.execFileSync(command,args,options as never);
  }};
});
vi.mock('@aws-sdk/client-ecs',async original=>{
  const actual=await original<typeof import('@aws-sdk/client-ecs')>();
  return {...actual,ECSClient:class{
    async send(command:{input:{taskDefinition:string;include:string[]}}){
      const row=recordedResources.find(r=>r.type==='aws:ecs/taskDefinition:TaskDefinition'&&mockArn(r.type,r.name)===command.input.taskDefinition);
      if(!row||command.input.include.join()!=='TAGS')throw Error('UnexpectedMockEcsReadback');
      const {unwrapRpcSecret}=await import(/* @vite-ignore */ moduleUrl('.sst/platform/node_modules/@pulumi/pulumi/runtime/rpc.js'));
      const {previewRegistrationFromProviderArgs}=await import('../scripts/lib/nonroot-preview-source.mjs');
      const {tags,...body}=previewRegistrationFromProviderArgs({...row.inputs,containerDefinitions:unwrapRpcSecret(row.inputs.containerDefinitions)});
      return {taskDefinition:{...body,taskDefinitionArn:command.input.taskDefinition,revision:Number(command.input.taskDefinition.split(':').at(-1)),status:'ACTIVE',
        registeredAt:'2026-10-08T00:00:00.000Z',registeredBy:`arn:aws:sts::${accountId}:assumed-role/preview/session`,requiresAttributes:[],compatibilities:['FARGATE']},tags};
    }
    destroy(){}
  }};
});

interface MockCallArgs {
  inputs: Record<string, unknown>;
  token: string;
}

interface MockResourceArgs {
  inputs: Record<string, unknown>;
  name: string;
  type: string;
}

interface RecordedResource {
  inputs: Record<string, unknown>;
  name: string;
  type: string;
}

const accountId = "123456789012";
const region = "ap-northeast-1";
const repositoryRoot = resolve(import.meta.dirname, "..");
const recordedResources: RecordedResource[] = [];
let sharedRpcServer:Awaited<ReturnType<typeof startSstRpcServer>>|undefined;
const maintenanceNamespaceIds = [
  "60000000-0000-4000-8000-000000000101",
  "60000000-0000-4000-8000-000000000102",
];
const maintenanceRoleNames = [
  "Mem9ConsolidationTaskRole",
  "Mem9ConsolidationExecutionRole",
  "Mem9CleanupTaskRole",
  "Mem9CleanupExecutionRole",
];
const authorizerRoleLogicalName =
  "Mem9OauthFacadeApiAuthorizerMem9OauthFacadeAllowAllHandlerRole";
const authorizerFunctionLogicalName =
  "Mem9OauthFacadeApiAuthorizerMem9OauthFacadeAllowAllHandlerFunction";
const workloadRolePrefixes = ["mem9-on-aws-", "mem9-on-aw-", "mem9-on-a-"];

function moduleUrl(path: string): string {
  return pathToFileURL(resolve(repositoryRoot, path)).href;
}

function mockArn(type: string, name: string): string {
  if(type==='aws:ecs/taskDefinition:TaskDefinition'){
    const row=recordedResources.find(r=>r.type===type&&r.name===name);
    const family=row?.inputs.family;
    const revision=recordedResources.filter(r=>r.type===type&&r.inputs.family===family).findIndex(r=>r.name===name)+1;
    return `arn:aws:ecs:${region}:${accountId}:task-definition/${family}:${revision}`;
  }
  const service = type.split(":")[1] || "mock";
  return `arn:aws:${service}:${region}:${accountId}:${name}`;
}

function mockCall(args: MockCallArgs): Record<string, unknown> {
  switch (args.token) {
    case "aws:index/getCallerIdentity:getCallerIdentity":
      return {
        accountId,
        arn: `arn:aws:iam::${accountId}:role/mock-deployer`,
        userId: "mock-user",
      };
    case "aws:index/getPartition:getPartition":
      return {
        dnsSuffix: "amazonaws.com",
        partition: "aws",
        reverseDnsPrefix: "com.amazonaws",
      };
    case "aws:index/getRegion:getRegion":
      return { description: "mock region", name: region, region };
    case "aws:ecr/getImage:getImage":
      return {...args.inputs,id:'synthetic-image',imageDigest:'sha256:'+'a'.repeat(64),imageTags:[args.inputs.imageTag],
        imageUri:`${accountId}.dkr.ecr.${region}.amazonaws.com/${args.inputs.repositoryName}@sha256:${'a'.repeat(64)}`};
    case "aws:kms/getKey:getKey":
      return {...args.inputs, arn:`arn:aws:kms:${region}:${accountId}:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee`};
    case "aws:ec2/getVpc:getVpc":
      return {
        ...args.inputs,
        cidrBlock: "10.0.0.0/16",
        default: true,
        id: "vpc-mock",
      };
    case "aws:ec2/getSubnets:getSubnets":
      return { ...args.inputs, ids: ["subnet-mock-a", "subnet-mock-b"] };
    case "aws:iam/getPolicyDocument:getPolicyDocument":
      return {
        ...args.inputs,
        json: JSON.stringify({
          Statement: args.inputs.statements ?? [],
          Version: "2012-10-17",
        }),
        statements: args.inputs.statements ?? [],
      };
    default:
      return args.inputs;
  }
}

function mockNewResource(args: MockResourceArgs): {
  id: string;
  state: Record<string, unknown>;
} {
  recordedResources.push({
    inputs: args.inputs,
    name: args.name,
    type: args.type,
  });
  const id = `${args.name}-id`;
  const state: Record<string, unknown> = {
    ...args.inputs,
    arn: mockArn(args.type, args.name),
    id,
    name: args.inputs.name ?? args.name,
  };
  switch (args.type) {
    case "aws:ec2/vpcEndpoint:VpcEndpoint": {
      const service = String(args.inputs.serviceName).split('.').at(-1);
      const endpointId = service === 'ssm' ? 'vpce-abcd' : 'vpce-abce';
      return { id: endpointId, state: { ...state, id: endpointId,
        dnsEntries: [{dnsName: `${endpointId}-synthetic.${service}.${region}.vpce.amazonaws.com`, hostedZoneId: 'synthetic-zone'}] } };
    }
    case "aws:rds/cluster:Cluster":
      Object.assign(state, {
        clusterIdentifier: args.name,
        databaseName: args.inputs.databaseName ?? "mem9",
        endpoint: "db.mock.internal",
        port: 5432,
      });
      break;
    case "aws:apigatewayv2/api:Api":
      state.apiEndpoint = "https://api.example.com";
      break;
    case "aws:cognito/userPool:UserPool":
      state.endpoint = `cognito-idp.${region}.amazonaws.com/mock`;
      break;
    case "aws:cognito/userPoolClient:UserPoolClient":
      if (args.inputs.generateSecret) state.clientSecret = "mock-client-secret";
      break;
    case "aws:servicediscovery/privateDnsNamespace:PrivateDnsNamespace":
      state.hostedZone = "zone-mock";
      break;
    case "random:index/randomId:RandomId":
      Object.assign(state, { hex: "0123456789abcdef", result: "mock-id" });
      break;
    case "random:index/randomPassword:RandomPassword":
      state.result = args.name.padEnd(64, "x");
      break;
    case "aws:ssm/parameter:Parameter":
      state.arn = `arn:aws:ssm:${region}:${accountId}:parameter${args.inputs.name}`;
      break;
  }
  return { id, state };
}

function oneResource(type: string, name: string): RecordedResource {
  const matches = recordedResources.filter((resource) => resource.type === type && resource.name === name);
  expect(matches, name).toHaveLength(1);
  return matches[0];
}

function matchesArn(pattern: string, arn: string): boolean {
  const escaped = pattern.split("*").map((part) => part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
  return new RegExp(`^${escaped.join(".*")}$`).test(arn);
}

async function verifyMaintenanceGraph(scheduleEnabled: boolean, namespaceRequired: boolean, productionMode?: string): Promise<void> {
  const [{ isRpcSecret, unwrapRpcSecret }, { expectedBoundaryPolicyDocument }] = await Promise.all([
    import(/* @vite-ignore */ moduleUrl(".sst/platform/node_modules/@pulumi/pulumi/runtime/rpc.js")),
    import(/* @vite-ignore */ moduleUrl("scripts/lib/workload-permissions-boundary.mjs")),
  ]);
  // Reuse the checked-in boundary contract; this test does not add IAM grants.
  const boundary = expectedBoundaryPolicyDocument({
    partition: "aws", accountId, applicationRegion: region,
    bedrockProjectArn: `arn:aws:bedrock-mantle:${region}:${accountId}:project/proj_mock`,
  }).Statement as Array<Record<string, any>>;
  const oneBoundary = (label: string, predicate: (statement: Record<string, any>) => boolean) => {
    const matches = boundary.filter(predicate);
    expect(matches, `unique boundary ${label}`).toHaveLength(1);
    return matches[0];
  };
  const hasAction = (statement: Record<string, any>, action: string) =>
    (Array.isArray(statement.Action) ? statement.Action : [statement.Action]).includes(action);
  const resourceScopes = oneBoundary('resource ceiling', s => s.Effect === 'Deny' &&
    (hasAction(s, 's3:GetObject') || hasAction(s, 's3:*')) && s.NotResource !== undefined).NotResource as string[];
  const actionCeiling = oneBoundary('action ceiling', s => s.Effect === 'Deny' && s.NotAction !== undefined).NotAction as string[];
  expect(actionCeiling).toEqual(expect.arrayContaining(["ssm:GetParameters", "kms:Decrypt"]));
  const kmsParameterScope = oneBoundary('KMS contexts', s => hasAction(s, 'kms:Decrypt') && s.Condition?.StringNotLikeIfExists?.['kms:EncryptionContext:PARAMETER_ARN'] !== undefined)
    .Condition.StringNotLikeIfExists["kms:EncryptionContext:PARAMETER_ARN"] as string;
  const executionRoleScopes = oneBoundary('secret execution roles', s => hasAction(s, 'kms:Decrypt') && s.Condition?.Null?.['kms:EncryptionContext:SecretARN'] === 'false' && s.Condition?.ArnNotLike !== undefined)
    .Condition.ArnNotLike["aws:PrincipalArn"] as string[];
  expect(oneBoundary('KMS services', s => hasAction(s, 'kms:Decrypt') && Array.isArray(s.Condition?.StringNotEqualsIfExists?.['kms:ViaService']))
    .Condition.StringNotEqualsIfExists["kms:ViaService"]).toContain(`ssm.${region}.amazonaws.com`);

  const parameterArn = (parameter: RecordedResource) =>
    `arn:aws:ssm:${region}:${accountId}:parameter${parameter.inputs.name}`;
  const assertSecureParameter = (name: string, path: string) => {
    const parameter = oneResource("aws:ssm/parameter:Parameter", name);
    expect(parameter.inputs).toMatchObject({ name: path, type: "SecureString" });
    expect(isRpcSecret(parameter.inputs.value), `${name} remains secret at the Pulumi RPC boundary`).toBe(true);
    const arn = parameterArn(parameter);
    expect(resourceScopes.some((pattern) => matchesArn(pattern, arn)), `${name} SSM resource scope`).toBe(true);
    expect(matchesArn(kmsParameterScope, arn), `${name} KMS parameter context`).toBe(true);
    return parameter;
  };
  const keyParameters = Object.fromEntries(["consolidation", "cleanup", "analysis"].map((service) => [
    service,
    assertSecureParameter(
      `Mem9Service${service[0].toUpperCase()}${service.slice(1)}SigningKeys`,
      `/mem9-on-aws/prod/namespace/service-${service}-signing-keys`,
    ),
  ]));
  // Distinct mock passwords preserve the real separation between service rings.
  expect(new Set(Object.values(keyParameters).map((parameter) => unwrapRpcSecret(parameter.inputs.value))).size).toBe(3);
  const bundle = assertSecureParameter("Mem9ServiceTransportSigningKeys", "/mem9-on-aws/prod/namespace/service-transport-signing-keys");

  const containers = recordedResources.filter(({ type }) => type === "aws:ecs/taskDefinition:TaskDefinition")
    .flatMap((definition) => (JSON.parse(unwrapRpcSecret(definition.inputs.containerDefinitions)) as Array<Record<string, any>>)
      .map((container) => ({ definition, container })));
  const taskContainer = (name: string) => {
    const matches = containers.filter(({ container, definition }) => container.name === name && definition.name !== 'ProductionRuntimeFallback');
    expect(matches, `${name} container`).toHaveLength(1);
    return matches[0];
  };
  const serverKeys = taskContainer("mnemo-server").container.secrets.filter(
    ({ name }: { name: string }) => name === "MNEMO_SERVICE_TRANSPORT_SIGNING_KEYS",
  );
  expect(serverKeys).toEqual(namespaceRequired ? [{
    name: "MNEMO_SERVICE_TRANSPORT_SIGNING_KEYS", valueFrom: parameterArn(bundle),
  }] : []);
  const schedules = recordedResources.filter(({ type }) => type === "aws:scheduler/schedule:Schedule");
  const legacySchedules=schedules.filter(schedule=>schedule.name==='WeeklyMemoryConsolidation');
  expect(legacySchedules).toHaveLength(namespaceRequired && scheduleEnabled ? 1 : 0);
  expect(schedules.length-legacySchedules.length).toBe(productionMode==='active'?2:0);
  if (!namespaceRequired) {
    expect(containers.filter(({ container }) =>
      ["Mem9Consolidation", "Mem9Cleanup"].includes(container.name))).toEqual([]);
    expect(recordedResources.filter(({ type, inputs }) =>
      type === "aws:ssm/parameter:Parameter" &&
      /^\/mem9-on-aws\/prod\/(?:maintenance|consolidation)\//.test(String(inputs.name)))).toEqual([]);
    expect(recordedResources.filter(({ type }) => type === "aws:scheduler/scheduleGroup:ScheduleGroup")).toEqual([]);
    return;
  }

  const targets = assertSecureParameter("MaintenanceNamespaceTargets", "/mem9-on-aws/prod/maintenance/targets");
  expect(JSON.parse(unwrapRpcSecret(targets.inputs.value))).toEqual(scheduleEnabled ? maintenanceNamespaceIds : []);
  const inlineStatements = (role: RecordedResource): Array<Record<string, any>> =>
    (role.inputs.inlinePolicies as Array<{ policy: unknown }> ?? [])
      .flatMap(({ policy }) => JSON.parse(unwrapRpcSecret(policy)).Statement)
      .filter((statement) => (statement.Effect ?? statement.effect ?? 'Allow') === 'Allow');

  for (const [service, name] of [["consolidation", "Mem9Consolidation"], ["cleanup", "Mem9Cleanup"]]) {
    const { definition, container } = taskContainer(name);
    const executionRole = oneResource("aws:iam/role:Role", `${name}ExecutionRole`);
    const taskRole = oneResource("aws:iam/role:Role", `${name}TaskRole`);
    expect(definition.inputs.executionRoleArn).toBe(mockArn(executionRole.type, executionRole.name));
    expect(definition.inputs.taskRoleArn).toBe(mockArn(taskRole.type, taskRole.name));
    expect(container.secrets).toEqual(expect.arrayContaining([{
      name: "MEM9_SERVICE_TRANSPORT_SIGNING_KEYS", valueFrom: parameterArn(keyParameters[service]),
    }]));
    const injectedServices = container.secrets.filter(({ name: key }: { name: string }) => key.includes("TRANSPORT_SIGNING_KEYS"));
    expect(injectedServices).toHaveLength(1);
    expect(container.secrets.map(({ valueFrom }: { valueFrom: string }) => valueFrom)).not.toContain(parameterArn(bundle));
    const environment = Object.fromEntries(container.environment.map(({ name: key, value }: { name: string; value: string }) => [key, value]));
    expect(environment.MEM9_SERVICE_TRANSPORT_ISSUER).toBe(`maintenance:${service}`);
    expect(environment.MEM9_NAMESPACE_ID).toBeUndefined();
    expect(environment.MEM9_SERVICE_PRINCIPAL_KEY).toBeUndefined();
    expect(JSON.stringify(container)).not.toMatch(/SLACK|APPROVAL/);
    for (const id of maintenanceNamespaceIds) expect(JSON.stringify(container)).not.toContain(id);
    expect(container.command).not.toContain("--apply");
    if (service === "consolidation") expect(environment.MEM9_CONSOLIDATION_REPORT_ONLY).toBe("1");
    const injectedTargets = container.secrets.filter(({ name: key }: { name: string }) => key === "MEM9_MAINTENANCE_TARGETS");
    expect(injectedTargets).toEqual(service === "consolidation" && scheduleEnabled
      ? [{ name: "MEM9_MAINTENANCE_TARGETS", valueFrom: parameterArn(targets) }] : []);

    // SST's execution policy is broad; the existing boundary limits its
    // effective resource/role scope. Container code never receives that role.
    expect(inlineStatements(executionRole).some(({ actions, resources }) =>
      actions.includes("ssm:GetParameters") && resources.some((pattern: string) => matchesArn(pattern, parameterArn(keyParameters[service]))))).toBe(true);
    const physicalName = executionRole.inputs.name ?? `${executionRole.inputs.namePrefix ?? `mem9-on-aws-prod-${executionRole.name}-`}fixture`;
    const executionArn = `arn:aws:iam::${accountId}:role/${physicalName}`;
    expect(executionRoleScopes.some((pattern) => matchesArn(pattern, executionArn))).toBe(true);
    const statements = inlineStatements(taskRole);
    expect(statements.flatMap(({ actions }) => actions)).not.toContain("ssm:GetParameters");
    expect(statements.flatMap(({ actions }) => actions)).not.toContain("secretsmanager:GetSecretValue");
    const s3 = statements.filter(({ actions }) => actions.some((action: string) => action.startsWith("s3:")));
    expect(s3.map(({ actions, resources }) => ({ actions, resources }))).toEqual(service === "consolidation" && scheduleEnabled ? [{
      actions: ["s3:GetObject", "s3:PutObject"],
      resources: [`arn:aws:s3:::mem9-audit-${accountId}/consolidation-digests/prod/*/current-v1.json`],
    }] : []);
  }

  if (scheduleEnabled) {
    expect(legacySchedules[0].inputs.state).toBe(productionMode ? 'DISABLED' : 'ENABLED');
    const target = legacySchedules[0].inputs.target as Record<string, any>;
    const override = JSON.parse(unwrapRpcSecret(target.input)).containerOverrides[0];
    expect(override).toMatchObject({
      name: "Mem9Consolidation", command: ["/app/scripts/dispatch-memory-consolidation.mjs"],
      environment: [
        { name: "MEM9_CONSOLIDATION_REPORT_ONLY", value: "0" },
        { name: "MEM9_CONSOLIDATION_SCHEDULED", value: "1" },
      ],
    });
    for (const id of maintenanceNamespaceIds) expect(JSON.stringify(override)).not.toContain(id);
  }
}

async function startSstRpcServer(): Promise<{
  close(): Promise<void>;
  url: string;
}> {
  const server = createServer((request, response) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk: string) => {
      body += chunk;
    });
    request.on("end", () => {
      const method = (JSON.parse(body) as { method: string }).method;
      let result;
      switch (method) {
        case "Provider.Aws.Appsync":
          result = {
            http: "https://appsync-api.example.com",
            realtime: "wss://appsync-realtime.example.com",
          };
          break;
        case "Provider.Aws.Bootstrap":
          result = {
            appsyncHttp: "https://appsync-api.example.com",
            appsyncRealtime: "wss://appsync-realtime.example.com",
            asset: "mock-asset-bucket",
            assetEcrRegistryId: accountId,
            assetEcrUrl: `${accountId}.dkr.ecr.${region}.amazonaws.com`,
            state: "mock-state-bucket",
          };
          break;
        case "Runtime.Build":
          result = {
            errors: [],
            handler: "index.handler",
            out: resolve(repositoryRoot, ".sst/platform/dist/nodejs-bridge"),
            sourcemaps: [],
          };
          break;
        default:
          response.writeHead(500, { "Content-Type": "application/json" });
          response.end(JSON.stringify({ error: `unexpected RPC ${method}` }));
          return;
      }
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ result }));
    });
  });
  await new Promise<void>((resolvePromise, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolvePromise);
  });
  const { port } = server.address() as AddressInfo;
  return {
    close: () =>
      new Promise<void>((resolvePromise, reject) => {
        server.close((error) => (error ? reject(error) : resolvePromise()));
      }),
    url: `http://127.0.0.1:${port}`,
  };
}

async function waitForRecordedRoles(expectedCount: number): Promise<void> {
  const deadline = Date.now() + 15_000;
  while (
    recordedResources.filter(({ type }) => type === "aws:iam/role:Role")
      .length < expectedCount
  ) {
    if (Date.now() >= deadline) {
      const names = recordedResources
        .filter(({ type }) => type === "aws:iam/role:Role")
        .map(({ name }) => name)
        .sort();
      throw new Error(
        `timed out waiting for the complete SST role graph; observed ${names.join(", ")}`,
      );
    }
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 10));
  }
}

const globalNames = [
  "$app",
  "$cli",
  "$util",
  "$config",
  "$dev",
  "$interpolate",
  "$jsonStringify",
  "$transform",
  "aws",
  "command",
  "random",
  "sst",
];

afterEach(() => {
  for (const name of globalNames) {
    delete (globalThis as Record<string, unknown>)[name];
  }
  recordedResources.length = 0;
  vi.unstubAllEnvs();
  vi.resetModules();
});
afterAll(async()=>{
  // SST caches RPC clients across the real component modules. Keep their local
  // endpoint alive for the whole file rather than resetting an in-flight socket
  // between otherwise independent mocked stack cases.
  const pulumi=await import(/* @vite-ignore */ moduleUrl('.sst/platform/node_modules/@pulumi/pulumi/index.js'));
  await pulumi.runtime.waitForRPCs();
  await sharedRpcServer?.close();
});

describe("workload role coverage from the real SST graph", () => {
  it.each([
    { label: "preview runtime preparation", scheduleEnabled: false, namespaceRequired: false, unsupportedFlag: undefined, runtimeReady: false },
    { label: "preview runtime ready", scheduleEnabled: false, namespaceRequired: true, unsupportedFlag: undefined, runtimeReady: true },
    { label: "preview cutover preparation", scheduleEnabled: true, namespaceRequired: true, unsupportedFlag: undefined, runtimeReady: true, productionMode: 'prepare' },
    ...["prepare","paused","ready","active"].map(productionMode=>({label:`production runtime ${productionMode}`,scheduleEnabled:true,namespaceRequired:true,unsupportedFlag:undefined,productionMode})),
    { label: "scheduler disabled, compatibility mode", scheduleEnabled: false, namespaceRequired: false, unsupportedFlag: undefined },
    { label: "scheduler disabled, required namespaces", scheduleEnabled: false, namespaceRequired: true, unsupportedFlag: undefined },
    { label: "scheduler enabled, required namespaces", scheduleEnabled: true, namespaceRequired: true, unsupportedFlag: undefined },
    ...[
      "MEM9_SLACK_APPROVAL_ENABLED",
      "MEM9_CLEANUP_SCAN_SCHEDULE_ENABLED",
      "MEM9_CLEANUP_SCAN_ENABLED",
    ].map((unsupportedFlag) => ({
      label: `scheduler enabled, unsupported ${unsupportedFlag}`,
      scheduleEnabled: true, namespaceRequired: true, unsupportedFlag,
    })),
  ])(
    "TC-FACADEAUTH-004/TC-CONSOL-026/TC-SLACKAPP-082: verifies the $label graph and configuration guard",
    async (testCase) => {
      const {scheduleEnabled, namespaceRequired, unsupportedFlag} = testCase;
      const runtimeReady = 'runtimeReady' in testCase ? testCase.runtimeReady : undefined;
      const productionMode = 'productionMode' in testCase ? testCase.productionMode : undefined;
      const preview = runtimeReady !== undefined;
      const stage = preview ? 'pr-7' : 'prod';
      vi.resetModules();
      const rpcServer = sharedRpcServer??=await startSstRpcServer();
      const environment: Record<string, string | undefined> = {
        SST_SERVER: rpcServer.url,
        WORKLOAD_BOUNDARY_PROD_ENABLED: "true",
        MEM9_AUTH_MODE: "managed",
        MEM9_RUNTIME_READY: runtimeReady ? "1" : "0",
        MEM9_PRODUCTION_RUNTIME_MODE: productionMode??"off",
        MEM9_RUNTIME_FALLBACK_IMAGES: productionMode?JSON.stringify(Object.fromEntries(["mnemo-server","qwen3-embed","llm-proxy"].map(name=>[name,`${accountId}.dkr.ecr.${region}.amazonaws.com/mem9-on-aws/${name}@sha256:${"a".repeat(64)}`]))):undefined,
        MEM9_BEDROCK_PROJECT: "proj_mock",
        MEM9_BEDROCK_PROJECT_OPENAI: "",
        MEM9_NAMESPACE_REQUIRED: namespaceRequired ? "1" : "0",
        MEM9_CONSOLIDATION_SCHEDULE_ENABLED: scheduleEnabled ? "1" : "0",
        SST_SECRET_MaintenanceNamespaceIds: JSON.stringify(scheduleEnabled ? maintenanceNamespaceIds : []),
        SST_SECRET_SlackWebhookUrl: "https://hooks.example.com/services/mock",
        SST_SECRET_OauthStateHmacKey: "synthetic-hmac-key-for-offline-sst-graph",
        MEM9_SLACK_APPROVAL_ENABLED: "0",
        MEM9_CLEANUP_SCAN_SCHEDULE_ENABLED: "0",
        MEM9_CLEANUP_SCAN_ENABLED: "0",
        MEM9_SLACK_APPROVAL_CHANNEL: undefined,
        SST_SECRET_SlackBotToken: undefined,
        SST_SECRET_SlackSigningSecret: undefined,
        MEM9_DECISION_ARTIFACT_BUCKET: `mem9-audit-${accountId}`,
        MEM9_DEPLOY_COMMIT: "a".repeat(40),
        MEM9_IMAGE_TAG:preview?'pr-aaaaaaa':'mem9-aaaaaaa',
        GITHUB_RUN_ID: "7",
        GITHUB_RUN_ATTEMPT: "1",
      };
      if (unsupportedFlag) environment[unsupportedFlag] = "1";
      for (const [name, value] of Object.entries(environment)) vi.stubEnv(name, value);
      try {
        Object.assign(globalThis, {
          $app: {
            name: "mem9-on-aws",
            protect: true,
            providers: {},
            removal: "retain",
            stage,
          },
          $cli: {
            command: "deploy",
            paths: {
              home: repositoryRoot,
              platform: resolve(repositoryRoot, ".sst/platform"),
              root: repositoryRoot,
              work: resolve(repositoryRoot, ".sst"),
            },
            rpc: "",
            state: { version: {} },
          },
          $dev: false,
        });
        const [pulumi, aws, command, random, sst, { $transform }] =
          await Promise.all([
            import(
              /* @vite-ignore */ moduleUrl(
                ".sst/platform/node_modules/@pulumi/pulumi/index.js",
              )
            ),
            import(
              /* @vite-ignore */ moduleUrl(
                ".sst/platform/node_modules/@pulumi/aws/index.js",
              )
            ),
            import(
              /* @vite-ignore */ moduleUrl(
                ".sst/platform/node_modules/@pulumi/command/index.js",
              )
            ),
            import(
              /* @vite-ignore */ moduleUrl(
                ".sst/platform/node_modules/@pulumi/random/index.js",
              )
            ),
            import(
              /* @vite-ignore */ moduleUrl(
                ".sst/platform/src/components/index.ts",
              )
            ),
            import(
              /* @vite-ignore */ moduleUrl(
                ".sst/platform/src/components/component.ts",
              )
            ),
          ]);
        pulumi.runtime.setMocks(
          {
            call: mockCall,
            newResource: mockNewResource,
          },
          "mem9-on-aws",
          stage,
          false,
        );
        Object.assign(globalThis, {
          $config: (value: unknown) => value,
          $util: pulumi,
          $interpolate: pulumi.interpolate,
          $jsonStringify: pulumi.jsonStringify,
          $transform,
          aws,
          command,
          random,
          sst,
        });

        const expectedRoleNames = [
          ...EXPECTED_WORKLOAD_ROLE_NAMES,
          ...(namespaceRequired ? maintenanceRoleNames : []),
          authorizerRoleLogicalName,
          ...(namespaceRequired && scheduleEnabled ? ["Mem9ConsolidationSchedulerRole"] : []),
          ...(productionMode?["RuntimeMem9ServerExecutionRole","SchemaMem9BootstrapExecutionRole","TransitionMem9BootstrapTaskRole","TransitionMem9BootstrapExecutionRole"]:[]),
          ...(productionMode==='active'?["Mem9ConsolidationPlannerTaskRole","Mem9ConsolidationPlannerExecutionRole","Mem9ConsolidationExecutorTaskRole","Mem9ConsolidationExecutorExecutionRole",
            "ProdMem9BootstrapTaskRole","ProdMem9BootstrapExecutionRole","ControlMem9BootstrapTaskRole","ControlMem9BootstrapExecutionRole",
            "PromoteMem9BootstrapTaskRole","PromoteMem9BootstrapExecutionRole"]:[]),
          ...(!namespaceRequired ? ["Mem9ConsolidationPlannerTaskRole", "Mem9ConsolidationPlannerExecutionRole",
            "Mem9ConsolidationExecutorTaskRole", "Mem9ConsolidationExecutorExecutionRole"] : []),
        ].sort();
        await pulumi.runtime.runInPulumiStack(async () => {
          const configModule = await import(
            /* @vite-ignore */ moduleUrl("sst.config.ts")
          );
          const config = configModule.default as {
            run(): Promise<Record<string, unknown>>;
          };
          if (unsupportedFlag) {
            // Catch inside the stack callback so rejected configuration cannot
            // leave rejected Pulumi Outputs or background RPCs after the test.
            await expect(config.run()).rejects.toThrow(
              "namespace-aware cleanup scan and Slack approval are not supported",
            );
            return {};
          }
          const outputs = await config.run();
          if (!namespaceRequired && !preview) {
            // Exercise the actual SST/Pulumi worker transforms, including the
            // execution policy replacement, alongside the unchanged prod graph.
            await pulumi.runtime.waitForRPCs();
            $app.stage = "pr-7";
            const {consolidationPreviewConfig,continuousConsolidationTasks} = await import("./consolidation-runtime");
            const previewCluster = new sst.aws.Cluster("PreviewWorkerCluster", {forceUpgrade: "v2", vpc: {
              id: "vpc-mock", securityGroups: ["sg-mock"], containerSubnets: ["subnet-mock-a"], loadBalancerSubnets: ["subnet-mock-a"],
            }});
            continuousConsolidationTasks({cluster: previewCluster, serviceDnsName: pulumi.output("backend.internal")} as any,
              {host: pulumi.output("db.mock.internal"), port: pulumi.output(5432)} as any, consolidationPreviewConfig()!,
              {revision: pulumi.output("synthetic"), serviceParameterArns: {consolidation: pulumi.output(`arn:aws:ssm:${region}:${accountId}:parameter/mem9-on-aws/pr-7/namespace/service-consolidation-signing-keys`)}} as any);
            await pulumi.runtime.waitForRPCs();
            $app.stage = "prod";
          }
          if (!preview) await waitForRecordedRoles(expectedRoleNames.length);
          return outputs;
        });
        await pulumi.runtime.waitForRPCs();
        if (preview) {
          const service = oneResource('aws:ecs/service:Service', 'Mem9ServerService');
          expect(service.inputs.name).toBe('Mem9Server');
          expect(service.inputs.desiredCount).toBe(runtimeReady ? 1 : 0);
          const scaling = oneResource('aws:appautoscaling/target:Target', 'Mem9ServerAutoScalingTarget');
          expect(scaling.inputs.minCapacity).toBe(runtimeReady ? 1 : 0);
          expect(scaling.inputs.suspendedState).toEqual({dynamicScalingInSuspended: true, dynamicScalingOutSuspended: true, scheduledScalingSuspended: true});
          const runtimeParameter = oneResource('aws:ssm/parameter:Parameter', 'RuntimeDatabaseCredential');
          expect(runtimeParameter.inputs.type).toBe('SecureString');
          const task = oneResource('aws:ecs/taskDefinition:TaskDefinition', 'Mem9ServerTask');
          const server = JSON.parse(String(task.inputs.containerDefinitions)).find((c:any) => c.name === 'mnemo-server');
          const runtimeArn = `arn:aws:ssm:${region}:${accountId}:parameter/mem9-on-aws/pr-7/runtime/database-credential`;
          expect(server.secrets.find((s:any) => s.name === 'MEM9_DB_SECRET').valueFrom).toBe(runtimeArn);
          expect(server.environment).toEqual(expect.arrayContaining([{name:'MNEMO_SCHEMA_MODE',value:'verify'},{name:'MNEMO_NAMESPACE_REQUIRED',value:'1'}]));
          const role = oneResource('aws:iam/role:Role', 'Mem9ServerExecutionRole');
          const policies = role.inputs.inlinePolicies as Array<{policy:string}>;
          const statements = JSON.parse(policies[0].policy).Statement;
          expect(statements.find((s:any) => s.Action.includes('ssm:GetParameters')).Resource).toContain(runtimeArn);
          expect(statements.find((s:any) => s.Action.includes('secretsmanager:GetSecretValue')).Resource).toHaveLength(1);
          expect(JSON.stringify(statements)).not.toContain('Mem9DbSecret');
          expect(role.inputs.managedPolicyArns).toEqual(['arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy']);
          const bootstrap = oneResource('aws:ecs/taskDefinition:TaskDefinition', 'Mem9BootstrapTask');
          const boot = JSON.parse(String(bootstrap.inputs.containerDefinitions))[0];
          expect(boot.secrets.find((s:any) => s.name === 'MEM9_RUNTIME_DB_SECRET').valueFrom).toBe(runtimeArn);
          expect(boot.secrets.find((s:any) => s.name === 'MEM9_DB_SECRET').valueFrom).not.toBe(runtimeArn);
          if(productionMode)for(const name of ['RuntimeMem9ServerExecutionRole','SchemaMem9BootstrapExecutionRole']){
            const role=oneResource('aws:iam/role:Role',name);
            expect(role.inputs.name).toBe(`mem9-on-aws-${stage}-${name}-role`);
            expect(role.inputs.permissionsBoundary).toBe(`arn:aws:iam::${accountId}:policy/${WORKLOAD_BOUNDARY_POLICY_NAME}`);
          }
          return;
        }
        if (unsupportedFlag) {
          expect(recordedResources.filter(({ type }) => !type.startsWith("pulumi:"))).toEqual([]);
          return;
        }

        const createdRoles = recordedResources.filter(
          ({ type }) => type === "aws:iam/role:Role",
        );
        expect(recordedResources.some(r=>r.name==='RuntimeDatabaseCredential')).toBe(Boolean(productionMode));
        expect(createdRoles.map(({ name }) => name).sort()).toEqual(
          expectedRoleNames,
        );
        const expectedBoundary = `arn:aws:iam::${accountId}:policy/${WORKLOAD_BOUNDARY_POLICY_NAME}`;
        expect(
          createdRoles.every(
            ({ inputs, name }) => inputs.permissionsBoundary === (['Mem9ProxyFnRole','Mem9IdentityInterceptorFnRole'].includes(name)
              ? `arn:aws:iam::${accountId}:policy/mem9-on-aws-gateway-boundary` : expectedBoundary),
          ),
        ).toBe(true);
        for (const role of createdRoles.filter(({name})=>["Mem9ProxyFnRole","Mem9IdentityInterceptorFnRole"].includes(name))) {
          expect(role.inputs.tags).toMatchObject({Project:"mem9-on-aws",Stage:stage});
        }
        await verifyMaintenanceGraph(scheduleEnabled, namespaceRequired, productionMode);
        if(productionMode){
          const {unwrapRpcSecret}=await import(/* @vite-ignore */ moduleUrl('.sst/platform/node_modules/@pulumi/pulumi/runtime/rpc.js'));
          const policyJson=(value:unknown)=>{
            const raw=unwrapRpcSecret(value);
            const policy=typeof raw==='string'?JSON.parse(raw):raw;
            return {...policy,Statement:policy.Statement.map(({Sid,...statement}:Record<string,unknown>)=>statement)};
          };
          const service=oneResource('aws:ecs/service:Service','Mem9ServerService');
          expect(service.inputs.desiredCount).toBe(productionMode==='paused'?0:1);
          const task=oneResource('aws:ecs/taskDefinition:TaskDefinition','Mem9ServerTask');
          const server=JSON.parse(unwrapRpcSecret(task.inputs.containerDefinitions)).find((c:any)=>c.name==='mnemo-server');
          const runtimeArn=`arn:aws:ssm:${region}:${accountId}:parameter/mem9-on-aws/prod/runtime/database-credential`;
          const credential=server.secrets.find((s:any)=>s.name==='MEM9_DB_SECRET').valueFrom;
          if(productionMode==='prepare')expect(credential).not.toBe(runtimeArn);
          else{
            expect(credential).toBe(runtimeArn);
            expect(task.inputs.executionRoleArn).toBe(mockArn('aws:iam/role:Role','RuntimeMem9ServerExecutionRole'));
            expect(server.environment).toContainEqual({name:'MNEMO_SCHEMA_MODE',value:'verify'});
          }
          const fallback=oneResource('aws:ecs/taskDefinition:TaskDefinition','ProductionRuntimeFallback');
          const containers=JSON.parse(unwrapRpcSecret(fallback.inputs.containerDefinitions));
          expect(containers).toHaveLength(3);
          expect(containers.every((c:any)=>/@sha256:[a-f0-9]{64}$/.test(c.image))).toBe(true);
          expect(containers.find((c:any)=>c.name==='mnemo-server').secrets).toContainEqual({name:'MEM9_DB_SECRET',valueFrom:runtimeArn});
          for(const name of ['Mem9ServerExecutionRole','Mem9ServerTaskRole','Mem9BootstrapExecutionRole','Mem9BootstrapTaskRole','Mem9ConsolidationExecutionRole','Mem9ConsolidationTaskRole','Mem9CleanupExecutionRole','Mem9CleanupTaskRole']){
            const role=oneResource('aws:iam/role:Role',name);
            expect(policyJson(role.inputs.assumeRolePolicy),`${name} inherited ECS trust`).toEqual({
              Version:'2012-10-17',Statement:[{Effect:'Allow',Action:'sts:AssumeRole',Principal:{Service:'ecs-tasks.amazonaws.com'}}],
            });
            const policy=(role.inputs.inlinePolicies as Array<{name:string;policy:string}>).find(p=>p.name==='ProductionCredentialFence');
            expect(policy,`${name} replacement credential fence`).toBeDefined();
            const statements=policyJson(policy!.policy).Statement;
            expect(statements.every((s:any)=>s.Effect==='Deny')).toBe(true);
            if(productionMode!=='prepare')expect(statements[0]).toMatchObject({Resource:'*',Action:expect.arrayContaining(['ssm:GetParameters','secretsmanager:GetSecretValue','kms:Decrypt'])});
          }
          for(const name of ['RuntimeMem9ServerExecutionRole','SchemaMem9BootstrapExecutionRole','TransitionMem9BootstrapTaskRole','TransitionMem9BootstrapExecutionRole']){
            if(name.startsWith('Runtime')||name.startsWith('Schema')){
              expect(oneResource('aws:iam/role:Role',name).inputs.name).toBe(`mem9-on-aws-${stage}-${name}-role`);
            }
            const trust=policyJson(oneResource('aws:iam/role:Role',name).inputs.assumeRolePolicy);
            expect(trust.Statement[0].Condition).toEqual({StringEquals:{'aws:SourceAccount':accountId},ArnLike:{'aws:SourceArn':`arn:aws:ecs:${region}:${accountId}:*`}});
          }
        }
        if (!namespaceRequired) {
          for (const kind of ["Planner", "Executor"]) {
            const role=oneResource("aws:iam/role:Role",`Mem9Consolidation${kind}ExecutionRole`);
            const policies=role.inputs.inlinePolicies as Array<{policy:string}>;
            const statements=JSON.parse(policies[0].policy).Statement;
            expect(statements[0].Action).toEqual(["ssm:GetParameters"]);
            expect(statements[0].Resource.every((arn:string)=>arn.includes("/mem9-on-aws/pr-7/"))).toBe(true);
            expect(JSON.stringify(statements)).not.toContain("secretsmanager:GetSecretValue");
            expect(role.inputs.managedPolicyArns).toEqual(["arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"]);
            const trust=JSON.parse(String(role.inputs.assumeRolePolicy));
            expect(trust.Statement[0].Condition.StringEquals["aws:SourceAccount"]).toBe(accountId);
          }
        }
        for (const { inputs, name } of createdRoles) {
          const physicalName = inputs.name ?? inputs.namePrefix;
          if (physicalName === undefined) {
            // These remaining roles come from SST components. Raw provider
            // roles must supply a name; their default lacks project/stage scope.
            expect(['RuntimeMem9ServerExecutionRole','SchemaMem9BootstrapExecutionRole']).not.toContain(name);
            expect(
              expectedRoleNames.includes(name),
              `${name} auto-named role must be a known workload role`,
            ).toBe(true);
            continue;
          }
          expect(
            workloadRolePrefixes.some((prefix) =>
              String(physicalName).startsWith(prefix),
            ),
            `${name} physical role name`,
          ).toBe(true);
        }

        const authorizerRole = createdRoles.find(
          ({ name }) => name === authorizerRoleLogicalName,
        );
        const authorizerFunction = recordedResources.find(
          ({ name, type }) =>
            type === "aws:lambda/function:Function" &&
            name === authorizerFunctionLogicalName,
        );
        const authorizers = recordedResources.filter(
          ({ type }) => type === "aws:apigatewayv2/authorizer:Authorizer",
        );
        expect(authorizerRole?.inputs).toMatchObject({
          name: "mem9-on-aws-prod-Mem9OauthFacadeAllowAllRole",
          permissionsBoundary: expectedBoundary,
        });
        expect(authorizerFunction?.inputs).toMatchObject({
          architectures: ["arm64"],
          name: "mem9-on-aws-prod-Mem9OauthFacadeAllowAll",
          runtime: "nodejs24.x",
        });
        expect(authorizers).toHaveLength(1);
        expect(authorizers[0]?.inputs).toMatchObject({
          authorizerPayloadFormatVersion: "2.0",
          authorizerResultTtlInSeconds: 0,
          authorizerType: "REQUEST",
          enableSimpleResponses: true,
          identitySources: [],
        });

        const routes = recordedResources.filter(
          ({ type }) => type === "aws:apigatewayv2/route:Route",
        );
        expect(routes).toHaveLength(2);
        expect(routes.map(({ inputs }) => inputs.routeKey).sort()).toEqual([
          "ANY /",
          "ANY /{proxy+}",
        ]);
        for (const { inputs } of routes) {
          expect(inputs.authorizationType).toBe("CUSTOM");
          expect(inputs.authorizerId).toBe(`${authorizers[0]?.name}-id`);
        }

        const lambdaRoleNames = [
          "Mem9AlertRouterRole",
          authorizerRoleLogicalName,
          "Mem9OauthFacadeFnRole",
          "Mem9ProxyFnRole",
        ];
        const lambdaRoles = createdRoles.filter(({ name }) =>
          lambdaRoleNames.includes(name),
        );
        expect(lambdaRoles).toHaveLength(lambdaRoleNames.length);
        for (const { inputs, name } of lambdaRoles) {
          expect(
            JSON.parse(String(inputs.assumeRolePolicy)),
            `${name} trust policy`,
          ).toEqual({
            Version: "2012-10-17",
            Statement: [
              {
                Effect: "Allow",
                Action: "sts:AssumeRole",
                Principal: { Service: "lambda.amazonaws.com" },
              },
            ],
          });
        }
      } finally {
        vi.unstubAllEnvs();
      }
    },
    120_000,
  );
});
