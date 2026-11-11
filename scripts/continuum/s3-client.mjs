import * as continuum from '@aws-sdk/client-continuum';
import * as s3 from '@aws-sdk/client-s3';
import { STSClient, GetCallerIdentityCommand } from '@aws-sdk/client-sts';
import { fromNodeProviderChain } from '@aws-sdk/credential-providers';
export function createClients(region, bucket, account) {
  const credentials = fromNodeProviderChain();
  const cc = new continuum.ContinuumClient({ region, credentials, maxAttempts: 1 });
  const storage = new s3.S3Client({ region, credentials, maxAttempts: 2 });
  const sts = new STSClient({ region, credentials, maxAttempts: 2 });
  const send = (client, command) => client.send(command, { abortSignal: AbortSignal.timeout(60000) });
  const commands = Object.fromEntries([
    'GetIntegration','CreateIntegration','GetEnvironment','CreateEnvironment',
    'UpdateEnvironment','ListEnvironments','CreateCodeScan','ListCodeScans',
    'ListCodeIssues','GetCodeIssue','GetCodeFinding','ListCodeIssueArtifacts',
    'GetCodeIssueArtifact','ListAssociatedCollectors',
  ].map(name=>[name,continuum[`${name}Command`]]));
  const call = (name, input) => {
    if (!Object.hasOwn(commands,name)) throw new Error('Unsupported Continuum operation');
    return send(cc,new commands[name](input));
  };
  return {
    call,
    identity: () => send(sts, new GetCallerIdentityCommand({})),
    async list(name, input, key = name === 'ListCodeScans' ? 'scans' : 'items') {
      const items = [], seen = new Set(); let nextToken;
      let pages=0;
      do {
        if (++pages>50) throw new Error('Service inventory exceeds 50 pages');
        const result = await call(name, { ...input, maxResults: 100, ...(nextToken ? {nextToken} : {}) });
        if (!Array.isArray(result[key]) || seen.has(result.nextToken)) throw new Error('Incomplete service inventory');
        items.push(...result[key]); nextToken = result.nextToken; if (nextToken) seen.add(nextToken);
      } while (nextToken);
      return items;
    },
    async get(key, version, limit = 1024 * 1024) {
      try {
        const response = await send(storage, new s3.GetObjectCommand({ Bucket: bucket, ExpectedBucketOwner: account, Key: key, ...(version ? { VersionId: version } : {}) }));
        // Unknown lengths are still bounded during streaming below.
        if (response.ContentLength !== undefined && (!Number.isSafeInteger(response.ContentLength) || response.ContentLength < 0 || response.ContentLength > limit)) { response.Body.destroy(); throw new Error('Object size exceeded'); }
        const chunks = []; let size = 0;
        for await (const chunk of response.Body) { size += chunk.length; if (size > limit) { response.Body.destroy(); throw new Error('Object size exceeded'); } chunks.push(chunk); }
        return { bytes: Buffer.concat(chunks), etag: response.ETag, version: response.VersionId };
      } catch (error) { if (error.name === 'NoSuchKey') return null; throw error; }
    },
    put: (key, body, condition = {}) => send(storage, new s3.PutObjectCommand({ Bucket: bucket, ExpectedBucketOwner: account, Key: key, Body: body, ServerSideEncryption: 'AES256', ...condition })),
    async bucketSafe() {
      const input = { Bucket: bucket, ExpectedBucketOwner: account };
      const version = await send(storage, new s3.GetBucketVersioningCommand(input));
      const access = await send(storage, new s3.GetPublicAccessBlockCommand(input));
      if (version.Status !== 'Enabled' || Object.values(access.PublicAccessBlockConfiguration ?? {}).filter(Boolean).length !== 4) throw new Error('Bucket controls changed');
    },
    destroy: () => { cc.destroy(); storage.destroy(); sts.destroy(); },
  };
}
