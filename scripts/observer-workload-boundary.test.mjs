import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { parse } from 'yaml';
import { createAwsCliAdapter } from './lib/workload-permissions-boundary-aws.mjs';
import { expectedObserverBoundaryPolicyDocument, observerRoleStage, observerBoundaryArn,
  observerRoleTags, observerRoleDocuments, assertObserverRole, observerBoundaryProbeCases,
} from './lib/observer-workload-boundary.mjs';
import { expectedRoleBoundaryArn, verifyObserverBoundaryPolicyDocument, verifyPermanentEnforcementDocuments, quarantinePolicyDocument } from './lib/workload-permissions-boundary.mjs';

const identity = { partition: 'aws', accountId: '123456789012', applicationRegion: 'ap-northeast-1' };
const roleName = 'mem9-on-aws-pr-7-ObserverControlTaskRole-012345abcdef';
const cutoff = '2030-01-02T03:04:05.000Z';
const arn = service => `arn:aws:${service}:${identity.applicationRegion}:${identity.accountId}:`;
function bindings() {
  return Object.fromEntries([
    ['clientId', 'ssm', 'parameter/mem9-on-aws/pr-7/cognito/client-id', null],
    ['clientSecret', 'ssm', 'parameter/mem9-on-aws/pr-7/cognito/client-secret', 'a'],
    ['transportSigningKeys', 'ssm', 'parameter/mem9-on-aws/pr-7/namespace/transport-signing-keys', 'a'],
    ['tenantKey', 'secretsmanager', 'secret:mem9-on-aws-pr-7-tenant-api-key-fixture-A1b2c3', 'b'],
    ['identitySigningKeys', 'secretsmanager', 'secret:mem9-on-aws-pr-7-identity-signing-keys-fixture-D4e5f6', 'b'],
  ].map(([name, store, resource, key]) => {
    const sourceArn = arn(store) + resource;
    return [name, { store, arn: sourceArn, region: identity.applicationRegion,
      version: store === 'ssm' ? 1 : '0123456789abcdef0123456789abcdef',
      sha256: 'a'.repeat(64), bytesLength: 32,
      endpoint: `https://${store}.${identity.applicationRegion}.amazonaws.com`,
      valueType: store === 'ssm' ? (key ? 'SecureString' : 'String') : 'SecretString',
      kms: key ? { keyArn: arn('kms') + `key/00000000-0000-0000-0000-${key.repeat(12)}`,
        viaService: `${store}.${identity.applicationRegion}.amazonaws.com`,
        contextKey: store === 'ssm' ? 'PARAMETER_ARN' : 'SecretARN', contextValue: sourceArn } : null }];
  }));
}
function selection() { return { roleName, credentialBindings: bindings(), cutoff }; }
function liveRole() {
  const docs = observerRoleDocuments(selection(), identity);
  return { arn: `arn:aws:iam::${identity.accountId}:role/${roleName}`, tags: Object.entries(docs.tags).map(([Key, Value]) => ({ Key, Value })),
    permissionsBoundaryArn: observerBoundaryArn(identity), assumeRolePolicyDocument: docs.assumeRolePolicyDocument,
    inlinePolicies: [{ name: 'ObserverReadOnly', document: docs.policyDocument }], attachedPolicyArns: [] };
}

// Finite IAM evaluator for these synthetic tests; native simulation remains an
// independent owner gate. Resource-policy session grants start with allow=true.
const list = value => value === undefined ? [] : Array.isArray(value) ? value : [value];
function expand(text, context) {
  let missing = false;
  const result = text.replace(/\$\{([^}]+)\}/gu, (_, key) => { if (context[key] === undefined) missing = true; return context[key] ?? ''; });
  return missing ? undefined : result;
}
function glob(pattern, value) {
  return pattern !== undefined && value !== undefined && new RegExp('^' + pattern.split('*').map(s => s.split('?').map(RegExp.escape).join('.')).join('.*') + '$', 'u').test(value);
}
function matches(conditions, context) {
  return Object.entries(conditions ?? {}).every(([op, terms]) => Object.entries(terms).every(([key, values]) => {
    if (op === 'Null') return (context[key] === undefined) === (values === 'true');
    if (op.endsWith('IfExists') && context[key] === undefined) return true;
    if (op === 'DateGreaterThanEquals') return Date.parse(context[key]) >= Date.parse(values);
    if (op === 'DateLessThan') return Date.parse(context[key]) < Date.parse(values);
    if (!['StringEquals','StringNotEquals','StringLike','StringNotLike','StringNotEqualsIfExists','ArnLike','ArnNotLike','ArnEquals','ArnNotEquals'].includes(op)) throw Error('Unmodelled condition: ' + op);
    const matched = list(values).some(v => context[key] !== undefined &&
      (op.includes('Like') ? glob(expand(v, context), context[key]) : expand(v, context) === context[key]));
    return op.includes('Not') ? !matched : matched;
  }));
}
function decision(document, action, resource, context, sessionGrant = false) {
  let allowed = sessionGrant;
  for (const row of document.Statement) {
    const actionMatch = row.Action ? list(row.Action).some(a => glob(a.toLowerCase(), action.toLowerCase()))
      : !list(row.NotAction).some(a => glob(a.toLowerCase(), action.toLowerCase()));
    const resourceMatch = row.Resource ? list(row.Resource).some(r => glob(expand(r, context), resource))
      : !list(row.NotResource).some(r => glob(expand(r, context), resource));
    if (actionMatch && resourceMatch && matches(row.Condition, context)) {
      if (row.Effect === 'Deny') return 'explicitDeny';
      allowed = true;
    }
  }
  return allowed ? 'allowed' : 'implicitDeny';
}
function template(name, overrides = {}) {
  const customTags = [
    ...['Sub', 'Ref', 'GetAtt'].map(t => ({tag:'!'+t, resolve:v=>({['Fn::'+t]:v})})),
    ...['If', 'Not', 'Equals'].map(t => ({tag:'!'+t, collection:'seq', resolve:v=>({['Fn::'+t]:v.toJSON()})})),
  ];
  const source = parse(readFileSync(new URL('../infra/cloudformation/' + name, import.meta.url), 'utf8'), {customTags});
  const variables = { 'AWS::Partition': 'aws', 'AWS::AccountId': identity.accountId,
    'AWS::URLSuffix': 'amazonaws.com', ApplicationRegion: identity.applicationRegion,
    ProjectName: 'mem9-on-aws', GitHubRepo: 'mem9-on-aws', PolicyRevision: 'r1',
    DecisionArtifactBucketName: 'mem9-audit-' + identity.accountId, BedrockProjectArn: '', OpenAiBedrockProjectArn: '', ...overrides };
  const render = x => {
    if (Array.isArray(x)) return x.map(render);
    if (x && typeof x === 'object') {
      if (x['Fn::Sub'] !== undefined) return x['Fn::Sub'].replace(/\$\{([^}]+)\}/gu, (_, key) => key.startsWith('!') ? '${' + key.slice(1) + '}' : variables[key]);
      if (x['Fn::Ref'] !== undefined) return variables[x['Fn::Ref']] ?? x['Fn::Ref'];
      if (x['Fn::If']) {
        const [name, yes, no] = x['Fn::If'];
        const condition = name === 'InitialObserverRevision' ? variables.PolicyRevision === 'r1'
          : name === 'HasOpenAiBedrockProject' ? Boolean(variables.OpenAiBedrockProjectArn) : false;
        return render(condition ? yes : no);
      }
      return Object.fromEntries(Object.entries(x).map(([k, v]) => [k, render(v)]));
    }
    return x;
  };
  return render(source);
}

describe('observer boundary class', () => {
  it('recognizes only strict numeric preview names and keeps the ordinary class', () => {
    expect(observerRoleStage(roleName)).toBe('pr-7');
    expect(expectedRoleBoundaryArn(roleName, identity)).toBe(observerBoundaryArn(identity));
    expect(expectedRoleBoundaryArn('ordinary-workload', identity)).toContain('workload-boundary');
    for (const stage of ['prod', 'pr-x', 'pr-0', 'pr-01']) {
      expect(() => expectedRoleBoundaryArn(roleName.replace('pr-7', stage), identity)).toThrow();
    }
    expect(() => observerRoleStage(roleName.replace('012345abcdef', '012345abcdeg'))).toThrow();
  });
  it('derives exact tags from the five real-shaped source bindings', () => {
    const tags = observerRoleTags(selection(), identity);
    expect(tags).toEqual({ Project: 'mem9-on-aws', Stage: 'pr-7',
      ObserverTenantSuffix: 'fixture-A1b2c3', NamespaceIdentitySuffix: 'fixture-D4e5f6',
      ObserverSsmKeyId: '00000000-0000-0000-0000-aaaaaaaaaaaa',
      ObserverSecretKeyId: '00000000-0000-0000-0000-bbbbbbbbbbbb' });
    const changed = selection(); changed.credentialBindings.clientSecret.kms.contextValue += '-wrong';
    expect(() => observerRoleTags(changed, identity)).toThrow();
  });
  it('binds the identical literal expiry to trust and explicit session denial', () => {
    const docs = observerRoleDocuments(selection(), identity);
    expect(docs.assumeRolePolicyDocument.Statement[0].Condition.DateLessThan['aws:CurrentTime']).toBe(cutoff);
    expect(docs.policyDocument.Statement.at(-1)).toEqual({ Sid: 'Expired', Effect: 'Deny', Action: '*', Resource: '*',
      Condition: { DateGreaterThanEquals: { 'aws:CurrentTime': cutoff } } });
    const role = { arn: `arn:aws:iam::${identity.accountId}:role/${roleName}`, tags: Object.entries(docs.tags).map(([Key, Value]) => ({ Key, Value })),
      permissionsBoundaryArn: observerBoundaryArn(identity), assumeRolePolicyDocument: docs.assumeRolePolicyDocument,
      inlinePolicies: [{ name: 'ObserverReadOnly', document: docs.policyDocument }], attachedPolicyArns: [] };
    expect(() => assertObserverRole(roleName, role, identity, selection())).not.toThrow();
    role.inlinePolicies[0].document.Statement.pop();
    expect(() => assertObserverRole(roleName, role, identity, selection())).toThrow();
  });
  for (const probe of observerBoundaryProbeCases(identity)) it('policy: ' + probe.name, () => {
    expect(decision(expectedObserverBoundaryPolicyDocument(identity), probe.action, probe.resource, probe.context, true)).toBe(probe.expected);
  });
  it('renders the frozen policy in all supported partitions and force revisions', () => {
    for (const partition of ['aws', 'aws-cn', 'aws-us-gov']) for (const policyRevision of ['r1', 'r' + '9'.repeat(20)]) {
      const region = 'aa-' + 'b'.repeat(19) + '-1';
      const doc = template('workload-permissions-boundary.yaml', { 'AWS::Partition': partition,
        'AWS::URLSuffix': partition === 'aws-cn' ? 'amazonaws.com.cn' : 'amazonaws.com', ApplicationRegion: region, PolicyRevision: policyRevision });
      const expected = expectedObserverBoundaryPolicyDocument({...identity, partition, applicationRegion: region, policyRevision});
      expect(doc.Resources.ObserverPermissionsBoundary.Properties.PolicyDocument).toEqual(expected);
      expect(JSON.stringify(expected).length).toBeLessThanOrEqual(6144);
      expect(verifyObserverBoundaryPolicyDocument(expected, {...identity, partition, applicationRegion: region, policyRevision})).toBe(true);
    }
    const doc = template('workload-permissions-boundary.yaml');
    expect(Object.values(doc.Resources).map(r => r.Type)).toEqual(['AWS::IAM::ManagedPolicy','AWS::IAM::ManagedPolicy','AWS::IAM::ManagedPolicy']);
    expect(doc.Resources.ObserverPermissionsBoundary.DeletionPolicy).toBe('Retain');
    expect(doc.Resources.ObserverPermissionsBoundary.UpdateReplacePolicy).toBe('Retain');
    const changed = expectedObserverBoundaryPolicyDocument(identity); changed.Statement.pop();
    expect(verifyObserverBoundaryPolicyDocument(changed, identity)).toBe(false);
  });
  it('bounds every expanded deployment managed policy, including the scaffold additions', () => {
    for (const partition of ['aws', 'aws-cn', 'aws-us-gov']) {
      const t = template('github-actions-role.yaml', {'AWS::Partition':partition,
        ApplicationRegion:'aa-' + 'b'.repeat(19) + '-1', DecisionArtifactBucketName:'a'.repeat(33)});
      for (const [name, r] of Object.entries(t.Resources)) if (r.Type === 'AWS::IAM::ManagedPolicy') {
        expect(JSON.stringify(r.Properties.PolicyDocument).length, name).toBeLessThanOrEqual(6144);
      }
      expect(t.Resources.ObserverBoundaryPairing.Properties.Roles).toEqual(['GitHubActionsRole','GitHubPreviewActionsRole','GitHubProductionActionsRole']);
      for (const role of t.Resources.ObserverBoundaryPairing.Properties.Roles) {
        const documents = [quarantinePolicyDocument(), ...list(t.Resources[role].Properties.Policies).map(p=>p.PolicyDocument)];
        for (const resource of Object.values(t.Resources)) if (resource.Type === 'AWS::IAM::Policy' && resource.Properties.Roles.includes(role)) documents.push(resource.Properties.PolicyDocument);
        expect(documents.reduce((n,d)=>n+JSON.stringify(d).length,0), role + ' with quarantine').toBeLessThanOrEqual(10240);
      }
    }
  });
  it('keeps old two Allow boundaries and verifies all observer pairings in both directions', () => {
    const t = template('github-actions-role.yaml');
    const documents = Object.values(t.Resources).filter(r => r.Type === 'AWS::IAM::ManagedPolicy' || r === t.Resources.ObserverBoundaryPairing).map(r => r.Properties.PolicyDocument);
    const boundaryArn = `arn:aws:iam::${identity.accountId}:policy/mem9-on-aws-workload-boundary`;
    const gateway = boundaryArn.replace('workload', 'gateway'), observer = observerBoundaryArn(identity);
    expect(() => verifyPermanentEnforcementDocuments(documents, {...identity, boundaryArn})).not.toThrow();
    const selected = new Set(['EcsTaskRoleCreateWithBoundary', 'EcsTaskRolePolicyWritesWithBoundary', 'DenyUnboundedProjectRoleCreation',
      'ObserverRolesWithObserverBoundary', 'DenyObserverBoundaryOnOtherRoles',
      'DenyObserverRolesWrongBoundary', 'DenyObserverPassToOtherServices', 'DenyGatewayBoundaryOnOtherRoles', 'DenyGatewayRolesWrongBoundary', 'PassRoleConstrained']);
    const rows = documents.flatMap(d => d.Statement).filter(s => selected.has(s.Sid));
    expect(rows).toHaveLength(selected.size);
    const policy = {Statement: rows}, resource = liveRole().arn;
    const merged = rows.find(r=>r.Sid==='DenyUnboundedProjectRoleCreation');
    expect(merged.Action).toEqual(['iam:CreateRole','iam:PutRolePermissionsBoundary','iam:AttachRolePolicy','iam:PutRolePolicy']);
    expect(merged.Resource).toEqual(['mem9-on-aws','mem9-on-aw','mem9-on-a'].map(prefix=>`arn:aws:iam::${identity.accountId}:role/${prefix}-*`));
    expect(merged.Condition).toEqual({ArnNotEquals:{'iam:PermissionsBoundary':[boundaryArn,gateway,observer]}});
    for (const action of ['iam:CreateRole','iam:PutRolePermissionsBoundary','iam:PutRolePolicy','iam:AttachRolePolicy']) {
      expect(decision(policy, action, resource, {'iam:PermissionsBoundary':observer})).toBe('allowed');
      for (const wrong of [boundaryArn, gateway, 'arbitrary', undefined]) expect(decision(policy, action, resource, {'iam:PermissionsBoundary':wrong}, true)).toBe('explicitDeny');
      for (const name of ['mem9-on-aws-pr-7-Mem9BootstrapTaskRole-fixture','mem9-on-aws-pr-7-Mem9ProxyFnRole-fixture',roleName.replace('pr-7','prod')]) {
        expect(decision(policy, action, resource.replace(roleName, name), {'iam:PermissionsBoundary':observer}, true)).toBe('explicitDeny');
      }
    }
    for (const service of ['lambda.amazonaws.com','scheduler.amazonaws.com',undefined]) expect(decision(policy,'iam:PassRole',resource,{'iam:PassedToService':service},true)).toBe('explicitDeny');
    expect(decision(policy,'iam:PassRole',resource,{'iam:PassedToService':'ecs-tasks.amazonaws.com'})).toBe('allowed');
    for (const sid of ['ObserverRolesWithObserverBoundary','DenyObserverRolesWrongBoundary','DenyObserverBoundaryOnOtherRoles','DenyObserverPassToOtherServices']) {
      const changed = structuredClone(documents);
      changed.forEach(d => {d.Statement = d.Statement.filter(s => s.Sid !== sid);});
      expect(() => verifyPermanentEnforcementDocuments(changed, {...identity,boundaryArn})).toThrow();
    }
    const broadened = structuredClone(documents);
    broadened.flatMap(d => d.Statement).find(s=>s.Sid==='EcsTaskRoleCreateWithBoundary').Condition.ArnEquals['iam:PermissionsBoundary'].push(observer);
    expect(() => verifyPermanentEnforcementDocuments(broadened, {...identity,boundaryArn})).toThrow();
  });
  it('rejects altered source scope, grouping, hashes and selectors', () => {
    const changes = [
      x => {x.credentialBindings.clientId.kms = x.credentialBindings.clientSecret.kms;},
      x => {x.credentialBindings.clientSecret.region = 'us-west-2';},
      x => {x.credentialBindings.clientId.version = 0;},
      x => {x.credentialBindings.tenantKey.sha256 = 'x';},
      x => {x.credentialBindings.identitySigningKeys.arn += '*';},
      x => {x.credentialBindings.transportSigningKeys.kms.keyArn = x.credentialBindings.tenantKey.kms.keyArn;},
      x => {x.credentialBindings.tenantKey.kms.contextKey = 'PARAMETER_ARN';},
      x => {x.credentialBindings.clientId.endpoint += '/other';},
      x => {x.credentialBindings.extra = x.credentialBindings.clientId;},
    ];
    for (const change of changes) {const x=selection();change(x);expect(()=>observerRoleTags(x,identity)).toThrow();}
    expect(() => observerRoleDocuments({...selection(),cutoff:'${aws:PrincipalTag/Expires}'},identity)).toThrow();
    expect(() => observerRoleDocuments({...selection(),cutoff:'2030-02-30T00:00:00.000Z'},identity)).toThrow();
  });
  it('rejects incoming TagSession, broad trust, changed cutoff and forged same-shape sources', () => {
    const changes = [
      r=>{r.assumeRolePolicyDocument.Statement[0].Action=['sts:AssumeRole','sts:TagSession'];},
      r=>{r.assumeRolePolicyDocument.Statement.push({Effect:'Allow',Action:'sts:TagSession',Principal:{Service:'ecs-tasks.amazonaws.com'}});},
      r=>{r.assumeRolePolicyDocument.Statement[0].Principal={AWS:'*'};},
      r=>{delete r.assumeRolePolicyDocument.Statement[0].Condition.StringEquals;},
      r=>{r.assumeRolePolicyDocument.Statement[0].Condition.ArnLike['aws:SourceArn']='*';},
      r=>{r.assumeRolePolicyDocument.Statement[0].Condition.DateLessThan['aws:CurrentTime']='2031-01-02T03:04:05.000Z';},
      r=>{r.tags.push({Key:'stage',Value:'pr-8'});},
      r=>{r.attachedPolicyArns.push('arn:aws:iam::aws:policy/ReadOnlyAccess');},
      r=>{r.inlinePolicies[0].document.Statement[0].Resource.push(arn('ssm')+'parameter/other');},
    ];
    for (const change of changes) {const r=liveRole();change(r);expect(()=>assertObserverRole(roleName,r,identity,selection())).toThrow();}
    const other=selection();other.credentialBindings.tenantKey.arn+='-other';other.credentialBindings.tenantKey.kms.contextValue+='-other';
    const changed=observerRoleDocuments(other,identity),r=liveRole();
    r.tags=Object.entries(changed.tags).map(([Key,Value])=>({Key,Value}));r.inlinePolicies[0].document=changed.policyDocument;
    expect(()=>assertObserverRole(roleName,r,identity,selection())).toThrow();
  });
  it('denies an already-issued session exactly at its immutable cutoff', () => {
    const doc=observerRoleDocuments(selection(),identity).policyDocument;
    const resource=bindings().clientId.arn;
    expect(decision(doc,'ssm:GetParameter',resource,{'aws:CurrentTime':'2030-01-02T03:04:04.999Z'},true)).toBe('allowed');
    for(const now of [cutoff,'2030-01-02T03:04:05.001Z']) expect(decision(doc,'ssm:GetParameter',resource,{'aws:CurrentTime':now},true)).toBe('explicitDeny');
  });
  it('checks full provider-shaped inventory and re-reads inline bytes across awaits', async () => {
    for (const race of [false,true]) {
      const role=liveRole();let policyReads=0;
      const rawRole={Arn:role.arn,RoleName:roleName,RoleId:'AROA_SYNTHETIC',Tags:role.tags,
        AssumeRolePolicyDocument:role.assumeRolePolicyDocument,PermissionsBoundary:{PermissionsBoundaryArn:role.permissionsBoundaryArn}};
      const adapter=createAwsCliAdapter({identity:{partition:identity.partition,accountId:identity.accountId},applicationRegion:identity.applicationRegion,
        invokeAws:async args=>{
          if(args[1]==='get-role')return{Role:structuredClone(rawRole)};
          if(args[1]==='list-role-policies')return{PolicyNames:['ObserverReadOnly'],IsTruncated:false};
          if(args[1]==='list-attached-role-policies')return{AttachedPolicies:[],IsTruncated:false};
          if(args[1]==='get-role-policy'){
            const PolicyDocument=structuredClone(role.inlinePolicies[0].document);
            if(race&&++policyReads===2)PolicyDocument.Statement.pop();
            return{PolicyDocument};
          }
          throw Error('unexpected provider request '+args.slice(0,2).join(' '));
        }});
      if(race)await expect(adapter.getRole({roleName})).rejects.toThrow();
      else{
        await expect(adapter.getRole({roleName})).resolves.toMatchObject({arn:role.arn});
        rawRole.RoleId='AROA_RECREATED';
        await expect(adapter.getRole({roleName})).rejects.toThrow(/changed/u);
      }
    }
  });
  it('does not add observer reads for inventories containing only ordinary roles', async () => {
    const calls=[];
    const adapter=createAwsCliAdapter({identity:{partition:identity.partition,accountId:identity.accountId},applicationRegion:identity.applicationRegion,
      invokeAws:async args=>{calls.push(args);return{Role:{Tags:[],AssumeRolePolicyDocument:{},PermissionsBoundary:{PermissionsBoundaryArn:'ordinary'}}};}});
    await adapter.getRole({roleName:'mem9-on-aws-prod-Mem9BootstrapTaskRole-fixture'});
    expect(calls.map(a=>a.slice(0,2))).toEqual([['iam','get-role']]);
  });
});
