type EndpointService = "ssm" | "secretsmanager";
type DnsEntry = { dnsName: string };
type Endpoint = { id: Output<string>; dnsEntries: Output<DnsEntry[]> };
type EndpointArgs = {
  vpcId: Input<string>; subnetIds: Input<string[]>; securityGroupIds: Input<string>[];
  serviceName: Input<string>; vpcEndpointType: "Interface"; privateDnsEnabled: false;
  ipAddressType: "ipv4"; policy: Input<string>; tags: Record<string, Input<string>>;
};

/** Keep endpoint ownership in this stage without claiming a VPC-wide service
 * DNS name. Only the regional AWS-assigned endpoint hostname is exported. */
export function gatewaySecretEndpointDns(service: EndpointService, region: string, id: string, entries: DnsEntry[]): string {
  if (!/^[a-z]{2}(?:-[a-z]+)+-\d+$/.test(region) || !/^vpce-[a-f0-9]+$/.test(id)) throw new Error("GatewaySecretEndpointDns");
  const pattern = new RegExp(`^${id}-[a-z0-9]+\\.${service}\\.${region}\\.vpce\\.amazonaws\\.com$`);
  const matches = entries.filter(entry => pattern.test(entry.dnsName));
  if (matches.length !== 1) throw new Error("GatewaySecretEndpointDns");
  return matches[0].dnsName;
}

/** The endpoint filters the exact role; service-side permissions still apply. */
export function gatewaySecretEndpointPolicy(service: EndpointService, roleArn: string, resources: string[], region: string) {
  function fail(): never { throw new Error("GatewaySecretEndpointPolicy"); }
  const literal = (value: unknown): value is string => typeof value === 'string' && !/[\s*?]|\$\{/.test(value);
  if (!['ssm', 'secretsmanager'].includes(service) || !literal(region) || !/^[a-z]{2}(?:-[a-z]+)+-\d+$/.test(region) ||
    !literal(roleArn) || !Array.isArray(resources) || resources.length === 0) fail();
  const role = /^arn:aws:iam::(\d{12}):role\/([\x21-\x7e]+)$/.exec(roleArn);
  if (!role) fail();
  const lastSlash = role[2].lastIndexOf('/');
  if (lastSlash + 1 > 511 || !/^[A-Za-z0-9_+=,.@-]{1,64}$/.test(role[2].slice(lastSlash + 1))) fail();
  for (const resource of resources) {
    if (!literal(resource)) fail();
    const arn = /^arn:aws:(ssm|secretsmanager):([^:]+):(\d{12}):(.+)$/.exec(resource);
    if (!arn || arn[1] !== service || arn[2] !== region || arn[3] !== role[1]) fail();
    const validName = service === 'ssm' ? /^parameter\/[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)*$/ : /^secret:[A-Za-z0-9/_+=.@-]+$/;
    if (!validName.test(arn[4])) fail();
  }
  return { Version: "2012-10-17", Statement: [{ Effect: "Allow", Principal: "*",
    Action: service === "ssm" ? "ssm:GetParameters" : "secretsmanager:GetSecretValue", Resource: [...resources],
    Condition: { ArnEquals: { 'aws:PrincipalArn': roleArn } } }] };
}

export function createGatewayProxyNetwork({ vpcId, backendSecurityGroupId, tags }: {
  vpcId: Input<string>; backendSecurityGroupId: Input<string>; tags: Record<string, Input<string>>;
}) {
  const endpointSg = new aws.ec2.SecurityGroup("Mem9GatewaySecretEndpointSg", {
    vpcId, description: "Gateway proxy secret endpoints", ingress: [], egress: [], tags,
  });
  const proxySg = new aws.ec2.SecurityGroup("Mem9GatewayProxySg", {
    vpcId, description: "Gateway proxy Lambda; backend HTTP and private secret endpoints only",
    egress: [
      { protocol: "tcp", fromPort: 8080, toPort: 8080, securityGroups: [backendSecurityGroupId] },
      { protocol: "tcp", fromPort: 443, toPort: 443, securityGroups: [endpointSg.id] },
    ], tags,
  });
  const backendIngress = new aws.ec2.SecurityGroupRule("Mem9TaskFromProxyLambda", {
    type: "ingress", securityGroupId: backendSecurityGroupId, sourceSecurityGroupId: proxySg.id,
    protocol: "tcp", fromPort: 8080, toPort: 8080, description: "Memory API from the Gateway proxy only",
  });
  const endpointIngress = new aws.ec2.SecurityGroupRule("Mem9GatewaySecretEndpointIngress", {
    type: "ingress", securityGroupId: endpointSg.id, sourceSecurityGroupId: proxySg.id,
    protocol: "tcp", fromPort: 443, toPort: 443, description: "Secret reads from the Gateway proxy only",
  });
  const securityGroups = $jsonStringify({ id: proxySg.id, backend: backendIngress.id, endpoint: endpointIngress.id })
    .apply(raw => [JSON.parse(raw).id as string]);
  return { proxySg, endpointSg, securityGroups };
}

/** Exactly the two services read by the existing proxy. No new IAM role,
 * shared endpoint mutation, Route53 zone, or public-network fallback. */
export function provisionGatewaySecretEndpoints({ vpcId, subnetIds, endpointSecurityGroupId, roleArn,
  tenantSecretArn, identitySecretArn, transportParameterArn, region, tags }: {
  vpcId: Input<string>; subnetIds: Input<string[]>; endpointSecurityGroupId: Input<string>; roleArn: Input<string>;
  tenantSecretArn: Input<string>; identitySecretArn: Input<string>; transportParameterArn: Input<string>;
  region: Input<string>; tags: Record<string, Input<string>>;
}) {
  // SST's local declaration contains only the provider surface used before this change.
  const EndpointResource = (aws.ec2 as unknown as { VpcEndpoint: new (name: string, args: EndpointArgs) => Endpoint }).VpcEndpoint;
  const resources = { secretsmanager: [tenantSecretArn, identitySecretArn], ssm: [transportParameterArn] };
  const endpoints = (['secretsmanager', 'ssm'] as const).map(service => {
    const policy = $jsonStringify({ roleArn, resources: resources[service], region })
      .apply(raw => { const value = JSON.parse(raw); return JSON.stringify(gatewaySecretEndpointPolicy(service, value.roleArn, value.resources, value.region)); });
    const endpoint = new EndpointResource(service === 'ssm' ? 'Mem9GatewaySsmEndpoint' : 'Mem9GatewaySecretsManagerEndpoint', {
      vpcId, subnetIds, securityGroupIds: [endpointSecurityGroupId],
      serviceName: $interpolate`com.amazonaws.${region}.${service}`, vpcEndpointType: 'Interface',
      privateDnsEnabled: false, ipAddressType: 'ipv4', policy, tags: { ...tags, Component: 'GatewaySecretsEndpoint' },
    });
    const binding = $jsonStringify({ region, id: endpoint.id, entries: endpoint.dnsEntries })
      .apply(raw => { const value = JSON.parse(raw); return { id: value.id as string, dns: gatewaySecretEndpointDns(service, value.region, value.id, value.entries) }; });
    return { service, endpoint, binding };
  });
  const environment = $jsonStringify(endpoints.map(({ service, binding }) => ({ service, binding }))).apply(raw => {
    const result: Record<string, string> = { MEM9_SECRET_ENDPOINT_MODE: 'private' };
    for (const { service, binding } of JSON.parse(raw)) {
      const prefix = service === 'ssm' ? 'MEM9_SECRET_SSM' : 'MEM9_SECRET_SECRETSMANAGER';
      result[prefix + '_VPCE_ID'] = binding.id; result[prefix + '_ENDPOINT_DNS'] = binding.dns;
    }
    return result;
  });
  return { environment, endpoints: endpoints.map(value => value.endpoint) };
}
