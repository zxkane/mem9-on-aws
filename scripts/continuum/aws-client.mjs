export async function clients(region) {
  const sdk = await import("@aws-sdk/client-continuum");
  const { STSClient, GetCallerIdentityCommand } = await import("@aws-sdk/client-sts");
  const { IAMClient, GetRoleCommand } = await import("@aws-sdk/client-iam");
  const { fromNodeProviderChain } = await import("@aws-sdk/credential-providers");
  const credentials = fromNodeProviderChain();
  // No SDK retry of CreateEnvironment: the service exposes no client token.
  const continuum = new sdk.ContinuumClient({ region, credentials, maxAttempts: 1 });
  const sts = new STSClient({ region, credentials, maxAttempts: 2 });
  const iam = new IAMClient({ region: "us-east-1", credentials, maxAttempts: 2 });
  const send = (client, command) => client.send(command, { abortSignal: AbortSignal.timeout(30000) });
  return {
    identity: () => send(sts, new GetCallerIdentityCommand({})),
    ciRoles: async (repository) => {
      const name = `github-actions-${repository.split("/")[1]}`;
      const roles = [];
      for (const RoleName of [name, `${name}-preview`, `${name}-prod`]) {
        try { roles.push((await send(iam, new GetRoleCommand({ RoleName }))).Role); }
        catch (error) { if (error.name !== "NoSuchEntityException" && error.name !== "NoSuchEntity") throw error; }
      }
      return roles;
    },
    integration: (integrationId) => send(continuum, new sdk.GetIntegrationCommand({ integrationId })),
    environment: (environmentId) => send(continuum, new sdk.GetEnvironmentCommand({ environmentId })),
    collectors: async (environmentId) => {
      const result = await send(continuum, new sdk.ListAssociatedCollectorsCommand({ environmentId, maxResults: 100 }));
      if (!Array.isArray(result.associatedCollectors) || result.nextToken) throw new Error("Cannot verify zero Collector associations");
      return result.associatedCollectors;
    },
    environments: async () => {
      const items = [];
      let pages = 0;
      const tokens = new Set();
      for await (const page of sdk.paginateListEnvironments({ client: continuum }, { maxResults: 100 }, { abortSignal: AbortSignal.timeout(60000) })) {
        if (++pages > 100 || !Array.isArray(page.items) || (page.nextToken && tokens.has(page.nextToken))) throw new Error("Invalid or unbounded environment inventory");
        items.push(...page.items);
        if (page.nextToken) tokens.add(page.nextToken);
      }
      return items;
    },
    create: (input) => send(continuum, new sdk.CreateEnvironmentCommand(input)),
    update: (environmentId, configuration) => send(continuum, new sdk.UpdateEnvironmentCommand({ environmentId, configuration })),
    destroy: () => { continuum.destroy(); sts.destroy(); iam.destroy(); },
  };
}
