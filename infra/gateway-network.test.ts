import { afterEach, describe, expect, it, vi } from "vitest";
import { readFileSync } from "node:fs";
import { parse } from "yaml";
import { createGatewayProxyNetwork, provisionGatewaySecretEndpoints, gatewaySecretEndpointDns, gatewaySecretEndpointPolicy } from "./gateway-network";

function out<T>(value: T): { value: T; apply: (fn: (value: T) => unknown) => unknown } {
  return { value, apply: fn => out(fn(value)) };
}
function unwrap(value: unknown): any {
  if (Array.isArray(value)) return value.map(unwrap);
  if (value && typeof value === 'object') {
    if ('value' in value) return unwrap(value.value);
    return Object.fromEntries(Object.entries(value).map(([key, nested]) => [key, unwrap(nested)]));
  }
  return value;
}
const region = 'ap-northeast-1', account = '123456789012';
const role = `arn:aws:iam::${account}:role/mem9-on-aws-prod-Mem9ProxyFnRole-synthetic`;
const tenant = `arn:aws:secretsmanager:${region}:${account}:secret:mem9-on-aws-prod-tenant-api-key-synthetic-AbCd12`;
const identity = `arn:aws:secretsmanager:${region}:${account}:secret:mem9-on-aws-prod-identity-signing-keys-synthetic-AbCd12`;
const transport = `arn:aws:ssm:${region}:${account}:parameter/mem9-on-aws/prod/namespace/transport-signing-keys`;
afterEach(() => vi.unstubAllGlobals());

describe('stage-owned gateway secret network', () => {
  it('creates only two endpoints, exact SG paths and role/resource-scoped policies, with no private hosted zone', () => {
    const created: Array<{kind: string; name: string; args: any}> = [];
    const resource = (kind: string) => class {
      id: unknown; dnsEntries: unknown;
      constructor(name: string, args: any) {
        created.push({kind, name, args}); this.id = out(name + '-id');
        if (kind === 'VpcEndpoint') {
          const service = String(unwrap(args.serviceName)).split('.').at(-1), id = service === 'ssm' ? 'vpce-abcd' : 'vpce-abce';
          this.id = out(id); this.dnsEntries = out([{dnsName: `${id}-synthetic.${service}.${region}.vpce.amazonaws.com`}]);
        }
      }
    };
    vi.stubGlobal('aws', {ec2: {SecurityGroup: resource('SecurityGroup'), SecurityGroupRule: resource('SecurityGroupRule'), VpcEndpoint: resource('VpcEndpoint')}});
    vi.stubGlobal('$jsonStringify', (value: unknown) => out(JSON.stringify(unwrap(value))));
    vi.stubGlobal('$interpolate', (parts: TemplateStringsArray, ...values: unknown[]) => out(parts.reduce((text, part, i) => text + part + (unwrap(values[i]) ?? ''), '')));
    const tags = {Project: 'mem9-on-aws', Stage: 'prod', ManagedBy: 'sst'};
    const network = createGatewayProxyNetwork({vpcId: 'vpc-synthetic', backendSecurityGroupId: 'sg-backend', tags});
    const result = provisionGatewaySecretEndpoints({vpcId: 'vpc-synthetic', subnetIds: ['subnet-a', 'subnet-b'], endpointSecurityGroupId: network.endpointSg.id,
      roleArn: role, tenantSecretArn: tenant, identitySecretArn: identity, transportParameterArn: transport, region, tags});
    const resources = created.map(row => ({...row, args: unwrap(row.args)}));
    const sg = resources.find(row => row.name === 'Mem9GatewayProxySg')!;
    expect(sg.args.egress).toEqual([
      {protocol: 'tcp', fromPort: 8080, toPort: 8080, securityGroups: ['sg-backend']},
      {protocol: 'tcp', fromPort: 443, toPort: 443, securityGroups: ['Mem9GatewaySecretEndpointSg-id']},
    ]);
    expect(resources.find(row => row.name === 'Mem9GatewaySecretEndpointSg')!.args.egress).toEqual([]);
    expect(resources.filter(row => row.kind === 'SecurityGroupRule').map(row => row.args)).toEqual([
      expect.objectContaining({type: 'ingress', securityGroupId: 'sg-backend', sourceSecurityGroupId: 'Mem9GatewayProxySg-id', fromPort: 8080, toPort: 8080}),
      expect.objectContaining({type: 'ingress', securityGroupId: 'Mem9GatewaySecretEndpointSg-id', sourceSecurityGroupId: 'Mem9GatewayProxySg-id', fromPort: 443, toPort: 443}),
    ]);
    const endpoints = resources.filter(row => row.kind === 'VpcEndpoint'); expect(endpoints).toHaveLength(2);
    for (const row of endpoints) {
      expect(row.args).toMatchObject({vpcId: 'vpc-synthetic', subnetIds: ['subnet-a', 'subnet-b'], securityGroupIds: ['Mem9GatewaySecretEndpointSg-id'],
        privateDnsEnabled: false, vpcEndpointType: 'Interface', ipAddressType: 'ipv4', tags: {...tags, Component: 'GatewaySecretsEndpoint'}});
      const service = row.args.serviceName.endsWith('.ssm') ? 'ssm' : 'secretsmanager';
      expect(JSON.parse(row.args.policy)).toEqual(gatewaySecretEndpointPolicy(service, role, service === 'ssm' ? [transport] : [tenant, identity]));
    }
    expect(unwrap(result.environment)).toEqual({MEM9_SECRET_ENDPOINT_MODE: 'private',
      MEM9_SECRET_SSM_VPCE_ID: 'vpce-abcd', MEM9_SECRET_SSM_ENDPOINT_DNS: `vpce-abcd-synthetic.ssm.${region}.vpce.amazonaws.com`,
      MEM9_SECRET_SECRETSMANAGER_VPCE_ID: 'vpce-abce', MEM9_SECRET_SECRETSMANAGER_ENDPOINT_DNS: `vpce-abce-synthetic.secretsmanager.${region}.vpce.amazonaws.com`});
    expect(JSON.stringify(resources)).not.toMatch(/0\.0\.0\.0\/0|::\/0|5432|\/32/);
    expect(resources.filter(row => !['SecurityGroup','SecurityGroupRule','VpcEndpoint'].includes(row.kind))).toEqual([]);
  });

  it('selects only the regional DNS name assigned to the exact endpoint', () => {
    const dns = `vpce-abcd-synthetic.ssm.${region}.vpce.amazonaws.com`;
    expect(gatewaySecretEndpointDns('ssm', region, 'vpce-abcd', [{dnsName: dns}, {dnsName: `vpce-abcd-synthetic-${region}a.ssm.${region}.vpce.amazonaws.com`}])).toBe(dns);
    for (const entries of [[], [{dnsName: dns}, {dnsName: dns}], [{dnsName: dns.replace('vpce-abcd','vpce-abce')}], [{dnsName: dns.replace('.ssm.','.s3.')}], [{dnsName: dns.replace(region,'us-west-2')}], [{dnsName: dns+'.example.com'}]]) {
      expect(() => gatewaySecretEndpointDns('ssm', region, 'vpce-abcd', entries)).toThrow('GatewaySecretEndpointDns');
    }
  });

  it('keeps the deploy-role endpoint grants finite and production/preview tag denies intact', () => {
    const customTags = [...['!Ref','!Sub','!GetAtt'].map(tag => ({tag,resolve:(value:string)=>value})),
      ...['!If','!Equals','!Not'].map(tag => ({tag,collection:'seq' as const,resolve:(value:unknown)=>value}))];
    const doc = parse(readFileSync(new URL('./cloudformation/github-actions-role.yaml', import.meta.url),'utf8'), {customTags});
    const statements = doc.Resources.ScaffoldPolicy.Properties.PolicyDocument.Statement;
    const reads = statements.filter((s:any) => s.Sid === 'GatewaySecretEndpointRead');
    expect(reads).toHaveLength(1);
    expect(reads[0]).toEqual({
      Sid: 'GatewaySecretEndpointRead', Effect: 'Allow',
      Action: ['ec2:DescribeVpcEndpoints', 'ec2:DescribePrefixLists'],
      Resource: '*', Condition: {StringEquals: {'aws:RequestedRegion': 'ApplicationRegion'}},
    });
    for (const action of ['ec2:CreateManagedPrefixList', 'ec2:ModifyManagedPrefixList', 'ec2:DeleteManagedPrefixList',
      'ec2:CreateVpcEndpointServiceConfiguration', 'ec2:ModifyVpcEndpointServiceConfiguration']) {
      expect(reads[0].Action).not.toContain(action);
    }
    const create = statements.find((s:any) => s.Sid === 'GatewaySecretEndpointCreate');
    expect(create.Action).toBe('ec2:CreateVpcEndpoint');expect(create.Resource).toContain(':vpc-endpoint/*');
    expect(create.Condition.StringEquals['ec2:VpceServiceName']).toEqual(['com.amazonaws.${ApplicationRegion}.ssm','com.amazonaws.${ApplicationRegion}.secretsmanager']);
    expect(create.Condition.StringEquals['aws:RequestTag/Project']).toBe('ProjectName');
    expect(create.Condition.StringEquals['aws:RequestTag/Component']).toBe('GatewaySecretsEndpoint');
    const lifecycle = statements.find((s:any) => s.Sid === 'GatewaySecretEndpointLifecycle');
    expect(lifecycle.Action).toEqual(['ec2:ModifyVpcEndpoint','ec2:DeleteVpcEndpoints']);
    expect(lifecycle.Condition.StringEquals['aws:ResourceTag/Project']).toBe('ProjectName');
    expect(lifecycle.Condition.StringEquals['aws:ResourceTag/Component']).toBe('GatewaySecretsEndpoint');
    for (const [resource,sid] of [['GitHubPreviewActionsRole','DenyTaggedProductionResources'],['GitHubProductionActionsRole','DenyTaggedPreviewResources']]) {
      expect(doc.Resources[resource].Properties.Policies[0].PolicyDocument.Statement.some((s:any) => s.Sid === sid && s.Effect === 'Deny')).toBe(true);
    }
  });
});
