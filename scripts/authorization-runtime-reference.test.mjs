import {describe, expect, it} from "vitest";
import {validateProductionTaskDefinitionSecrets} from "./lib/workload-permissions-boundary.mjs";

const accountId = "123456789012", applicationRegion = "ap-northeast-1";
const prefix = `arn:aws:ssm:${applicationRegion}:${accountId}:parameter/mem9-on-aws/prod`;
const secret = name => `arn:aws:secretsmanager:${applicationRegion}:${accountId}:secret:mem9-on-aws-prod-${name}-fixture`;
function fixture() {
  const bootstrap = `arn:aws:ecs:${applicationRegion}:${accountId}:task-definition/mem9-on-aws-prod-Mem9Bootstrap:1`;
  const service = `arn:aws:ecs:${applicationRegion}:${accountId}:task-definition/mem9-on-aws-prod-Mem9RuntimeServer:1`;
  return {partition: "aws", accountId, applicationRegion, bootstrapTaskDefinitionArn: bootstrap,
    serviceTaskDefinitionArns: [service], taskDefinitions: [
      {taskDefinitionArn: bootstrap, containerDefinitions: [{name: "Mem9Bootstrap", secrets: [
        {name: "MEM9_DB_SECRET", valueFrom: `${prefix}/runtime/schema-administrator-credential`},
        {name: "MEM9_RUNTIME_DB_SECRET", valueFrom: `${prefix}/runtime/database-credential`},
        {name: "MEM9_TENANT_ID", valueFrom: secret("tenant-api-key")},
      ]}]},
      {taskDefinitionArn: service, containerDefinitions: [{name: "mnemo-server", secrets: [
        {name: "MEM9_DB_SECRET", valueFrom: `${prefix}/runtime/database-credential`},
        {name: "MEM9_TENANT_ID", valueFrom: secret("tenant-api-key")},
        {name: "MNEMO_TRANSPORT_SIGNING_KEYS", valueFrom: `${prefix}/namespace/transport-signing-keys`},
        {name: "MNEMO_SERVICE_TRANSPORT_SIGNING_KEYS", valueFrom: `${prefix}/namespace/service-transport-signing-keys`},
      ]}, {name: "qwen3-embed"}, {name: "llm-proxy"}]},
    ]};
}
const serviceSecrets = value => value.taskDefinitions[1].containerDefinitions[0].secrets;
describe("runtime task secret reference compatibility", () => {
  it("accepts the exact source-declared SSM references without reading credential values", () => {
    expect(validateProductionTaskDefinitionSecrets(fixture())).toBe(true);
  });
  for (const [label, alter] of [
    ["foreign account", value => {serviceSecrets(value)[0].valueFrom = serviceSecrets(value)[0].valueFrom.replace(accountId, "9".repeat(12));}],
    ["other region", value => {serviceSecrets(value)[0].valueFrom = serviceSecrets(value)[0].valueFrom.replace(applicationRegion, "us-west-2");}],
    ["preview stage", value => {serviceSecrets(value)[0].valueFrom = serviceSecrets(value)[0].valueFrom.replace("/prod/", "/pr-1/");}],
    ["administrator in service", value => {serviceSecrets(value)[0].valueFrom = `${prefix}/runtime/schema-administrator-credential`;}],
    ["runtime as bootstrap administrator", value => {value.taskDefinitions[0].containerDefinitions[0].secrets[0].valueFrom = `${prefix}/runtime/database-credential`;}],
    ["administrator backup", value => {serviceSecrets(value)[0].valueFrom = `${prefix}/runtime/schema-administrator-backup`;}],
    ["transition credential", value => {serviceSecrets(value)[0].valueFrom = `${prefix}/runtime/transition-credential`;}],
    ["label selector", value => {serviceSecrets(value)[0].valueFrom += ":current";}],
    ["unknown secret name", value => {serviceSecrets(value)[2].name = "UNREVIEWED_SECRET";}],
    ["wrong signing path", value => {serviceSecrets(value)[2].valueFrom = `${prefix}/namespace/service-transport-signing-keys`;}],
    ["wrong container", value => {value.taskDefinitions[1].containerDefinitions[0].name = "llm-proxy";}],
    ["duplicate reference name", value => {serviceSecrets(value).push({...serviceSecrets(value)[0]});}],
  ]) it(`rejects ${label}`, () => {
    const value = fixture(); alter(value);
    expect(() => validateProductionTaskDefinitionSecrets(value)).toThrow(/secret reference/);
  });
  it("preserves the existing Secrets Manager reference contract", () => {
    const value = fixture();
    for (const task of value.taskDefinitions) task.containerDefinitions = [{name: "legacy", secrets: [
      {name: "MEM9_DB_SECRET", valueFrom: secret("Mem9DbSecret")},
      {name: "MEM9_TENANT_ID", valueFrom: secret("tenant-api-key")},
    ]}];
    expect(validateProductionTaskDefinitionSecrets(value)).toBe(true);
  });
});
