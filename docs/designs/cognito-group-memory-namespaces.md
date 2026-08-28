# Design Specification: Cognito group-routed memory namespaces

Feature: multiple team memory namespaces in one Aurora PostgreSQL database
Date: 2026-08-28
Status: Implemented behind a rollout gate; live AWS cutover and smoke pending

## Decision Summary

The deployment keeps one Aurora cluster, one PostgreSQL database, one mem9
tenant, and one fixed tenant `X-API-Key`. Team isolation is implemented with a
first-class `namespace_id` on every content-bearing and asynchronous data path.

Human namespace eligibility comes from managed Amazon Cognito user-pool groups:

- each configured Cognito group maps to one internal team namespace;
- a human access token must match exactly one configured namespace group;
- the server verifies an active database membership before granting access;
- a missing membership may be created just in time only for an active,
  JIT-enabled group binding;
- JIT refuses to create a second active namespace membership for a human;
- a revoked membership is never reactivated by a group claim;
- unrelated Cognito groups are ignored;
- matching zero or more than one configured namespace group fails closed;
- clients never submit or select `namespace_id`.

Cognito groups are the onboarding and routing signal. Aurora control-plane
tables are the authorization, role, revocation, and audit source of truth.

M2M clients do not use Cognito user groups. They use explicit
`client_key -> principal_id -> namespace_id` bindings and active database
memberships.

`agent_id` remains optional attribution and filtering metadata. It is not an
identity, ownership, or authorization boundary.

## Implementation Status

The repository implementation includes:

- split non-VPC identity interception and VPC target transport signing;
- Cognito human/M2M client classification and bounded group-key derivation;
- namespace, principal, group-binding, M2M-binding, membership, and migration
  control tables;
- additive, freeze/backfill, and enforcement migrations with a bounded
  database-side embedding digest, immutable legacy seed binding, and
  catalog-verified concurrent indexes;
- namespace-bound memory, session, durable-ingest, plan, worker, and status
  paths in downstream patch `0010-group-memory-namespaces.patch`;
- private one-shot reconciliation, access-management, and migration commands
  whose ECS runner reattaches to an identical active invocation and stops an
  unfinished task before deleting its short-lived inputs; an unconfirmed stop
  retains those inputs, and the container forwards termination with a bounded
  child-process watchdog;
- a retained least-privilege namespace operator role;
- `MEM9_NAMESPACE_REQUIRED`, which defaults to `0` and keeps an existing stage
  compatible until the database reaches `constraints_complete`;
- a version-controlled 278-statement scoped-SQL manifest generated from the
  complete patched upstream and local operator/DDL surfaces;
- a coverage ownership map assigning every `TC-GROUPNS-001..130` criterion to
  exactly one capability and named verification surface without claiming that
  the mapped surface has executed or passed;
- unit, infrastructure, fresh-upstream patch, and PostgreSQL migration tests.

Production remains disabled until the real AgentCore Gateway contract, IAM
invocation source, two-namespace E2E, exact-search capacity benchmark, snapshot,
and restore gates in the acceptance criteria are completed. The operator must
also execute the documented service drain and write freeze; the database
operator command intentionally does not scale ECS or mutate Gateway resources.

## User-Visible Contract

### Human users

- Two users in the same managed Cognito group share one memory namespace.
- Users in different managed groups cannot search, fetch, modify, merge, delete,
  reconcile, or inspect each other's memories, sessions, jobs, or maintenance
  artifacts.
- A user can belong to unrelated Cognito groups, but version 1 permits exactly
  one recognized mem9 namespace group per token.
- Moving a user between namespaces requires the operator access-management
  command. The command revokes old database memberships, changes the Cognito
  group, re-reads the group state, and performs an operator-only target
  membership grant. Partial failure removes access instead of broadening it.
- The user must obtain a new access token after a group change. The browser app
  client uses a 15-minute access-token lifetime to bound stale group claims.
- There is no workspace selector in version 1.

### M2M and service principals

- A Cognito M2M app client must have exactly one active namespace binding.
- Gateway `allowedClients` admission alone grants no memory access.
- Scheduled and operator services use explicit `service` principals and active
  memberships in each namespace they process.
- No M2M or service principal receives an implicit all-namespace role.

### Team-owned asynchronous work

An ingest job accepted before its submitting user's membership is normally
allowed to finish in the namespace persisted on the job. The resulting memory
is team data, not private user data. Revocation prevents new requests
immediately after the membership transaction commits.

`revoke-user --emergency` is the security-incident path. It disables the
principal and terminally cancels that principal's non-terminal jobs before
removing managed groups. Disabling a namespace terminally blocks every queued
or running job in that namespace from applying mutations.

## Goals

- Share one Aurora database across a small number of teams.
- Make namespace isolation enforceable across synchronous, asynchronous, and
  direct-SQL paths.
- Assign human users through Cognito groups without trusting caller input.
- Support immediate database revocation and bounded Cognito-token staleness.
- Avoid per-user or per-team RDS clusters, databases, schemas, ECS services, and
  embedding services.
- Provide a migration and rollback process that preserves existing embeddings
  and historical team memory.

## Non-Goals

- Personal memory namespaces.
- A user belonging to multiple selectable mem9 workspaces.
- A public namespace or membership administration API.
- A team administration UI.
- Cross-namespace search, consolidation, merge, job lookup, or cleanup.
- Per-namespace PostgreSQL databases or schemas.
- PostgreSQL row-level security in the first release.
- Namespace-aware Space Chains or webhooks.
- Allowing arbitrary Cognito group names to create namespaces automatically.

## Pre-Implementation Baseline

Verified against the repository before this implementation on 2026-08-28.

| Component                                         | Current behavior                                                        | Required change                                                                      |
| ------------------------------------------------- | ----------------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| `infra/cognito.ts`                                | One admin-created-user pool, one M2M client, no groups                  | Add explicit token lifetimes and group-management support without replacing the pool |
| `infra/oauth-facade.ts`                           | One authorization-code reader client, no access-token lifetime override | Set the human access-token lifetime to 15 minutes                                    |
| `infra/gateway.ts`                                | One VPC proxy Lambda is both interceptor and target                     | Split identity interceptor from VPC target and pass authenticated identity context   |
| `infra/gateway/scope-interceptor.mjs`             | Decodes only `scope` from the bearer payload                            | Validate client registry, derive principal/client/group keys, sign internal context  |
| `docker/bootstrap/schema.sql`                     | `memories` and `upload_tasks` have no namespace                         | Add control tables and additive namespace/audit columns                              |
| `docker/bootstrap/migrations/001_ingest_jobs.sql` | Queue, plans, and sessions are tenant-scoped only                       | Add namespace keys, actor keys, composite constraints, and migration ordering        |
| mnemo-server patch set                            | Repositories and worker operate on the whole tenant database            | Require `NamespaceScope` in repositories, jobs, status, reconciliation, and apply    |
| cleanup/consolidation scripts                     | Direct SQL defaults to the full tenant                                  | Require one namespace per content-bearing operation                                  |
| Slack cleanup approval                            | Offer/claim/artifact state is stage-wide                                | Block until every approval record and artifact is namespace-bound                    |
| `scripts/run-mcp-e2e.sh`                          | Tests M2M scope enforcement and one shared corpus                       | Add human group routing plus two-namespace denial tests                              |

The current fixed `X-API-Key` identifies the deployment's mem9 tenant. It does
not identify a human, M2M application, or namespace.

## AWS Identity Facts

Amazon Cognito user-pool groups are represented in ID and access tokens with the
`cognito:groups` claim. Group administration uses IAM-authorized APIs such as
`AdminAddUserToGroup` and `AdminRemoveUserFromGroup`.

The reader client uses access tokens for MCP authorization. The design does not
depend on custom user attributes appearing in access tokens and does not require
a Pre Token Generation trigger.

Cognito access tokens default to one hour. Cognito supports access-token
lifetimes from five minutes to one day. This design explicitly sets the reader
client access token to 15 minutes. The refresh-token flow can obtain a token
with current group claims.

AgentCore Gateway validates JWT signature, issuer, allowed client, expiry, and
at least one resource scope before invoking its request interceptor. The
interceptor receives request headers because `passRequestHeaders` is enabled.

Official references:

- [Cognito groups](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-user-groups.html)
- [Cognito access tokens](https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-the-access-token.html)
- [Cognito token validity units](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-cognito-userpoolclient-tokenvalidityunits.html)
- [AgentCore Gateway interceptors](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-interceptors-configuration.html)

## Authorization Invariants

Every content-bearing request must satisfy all applicable checks:

1. Gateway validated the token.
2. The token uses the `access` token type.
3. The app client has one configured type: `human` or `m2m`.
4. The interceptor-derived context is authentic and bound to this tool call.
5. The principal is active.
6. The namespace is active.
7. An active database membership exists.
8. A human token currently carries the group eligibility for that membership.
9. The membership role permits the action.
10. The OAuth scope permits the action.

Failure at any step denies the request before reading content-bearing tables.
There is no fallback to a default namespace or the tenant-wide corpus.

## Identifier Model

The interceptor derives non-secret stable lookup keys:

```text
principal_key =
  hex(sha256("mem9-principal-v2\0" + iss + "\0" + principal_type + "\0" + subject))

client_key =
  hex(sha256("mem9-client-v1\0" + iss + "\0" + client_id))

group_key =
  hex(sha256("mem9-cognito-group-v1\0" + iss + "\0" + cognito_group_name))
```

Rules:

- `subject` is `sub` for a configured human app client.
- `subject` is `client_id` for a configured M2M app client.
- Principal type is selected by the deployed client registry, not by the
  presence or absence of `sub`.
- A human token must have a valid `sub`.
- An M2M token must have a valid `client_id`; an unexpected human-only shape is
  rejected rather than reclassified.
- Group names are normalized only by exact Cognito string equality. They are not
  lowercased, trimmed, wildcarded, or interpreted as namespace IDs.
- Raw bearer tokens, subjects, usernames, email addresses, client IDs, and group
  names are not passed to mnemo-server or stored in content-bearing tables.
- Hashes are lookup keys, not credentials. Their unpredictability is not an
  authorization control.

Each persisted principal receives a random internal `principal_id`. Each
namespace receives a random internal `namespace_id`.

## Runtime Architecture

```text
Cognito access token
  -> AgentCore Gateway CUSTOM_JWT authorizer
       validates JWT and coarse client/scope admission
  -> non-VPC identity interceptor Lambda
       validates token_use and configured client type
       derives principal_key, client_key, and sorted group_keys
       rejects caller ownership/namespace/internal-context fields
       signs a request-bound internal context
  -> VPC target Lambda
       verifies signature, version, request hash, tool, and expiry
       strips the internal context and inbound Authorization header
       signs a short-lived target-to-server transport envelope
  -> mnemo-server namespace middleware
       verifies the transport envelope before trusting derived identity
       resolves principal and one eligible namespace
       creates JIT membership only when permitted
       checks principal, namespace, membership, role, and scope
       attaches non-optional NamespaceScope
  -> namespace-bound repositories, jobs, and operator paths
```

### Client registry

The deployed registry contains exact Cognito app client IDs classified as:

```text
human: reader authorization-code client
m2m:   selected client-credentials clients
```

The registry is checked on every request. An app client cannot be both types.
Unknown, duplicated, or conflicting entries fail deployment or cold start.

### Split Lambda trust boundary

- The interceptor has no VPC attachment, database credential, tenant key, or
  mnemo-server network path.
- The target is VPC-attached and owns the tenant key.
- The target has no public URL or API route.
- The Gateway service role can invoke the two exact functions.
- No human, application, or broad internal role receives target invocation
  permission.
- Namespace-aware mnemo endpoints reject unsigned derived identity headers and
  a bare tenant key. Target and approved service callers use separate,
  allowlisted internal issuer keys.

### Authenticated internal context

The interceptor overwrites a reserved argument:

```json
{
  "__mem9_auth_v2": {
    "kid": "current",
    "issued_at": 1787875200,
    "expires_at": 1787875230,
    "tool": "search_memories",
    "request_hash": "<64 lowercase hex>",
    "principal_key": "<64 lowercase hex>",
    "principal_type": "human",
    "client_key": "<64 lowercase hex>",
    "group_keys": ["<64 lowercase hex>"],
    "mac": "<64 lowercase hex>"
  }
}
```

`mac` is HMAC-SHA-256 over a canonical, versioned serialization of every other
field. The request hash binds the context to a canonical invocation containing
the tool name and caller arguments after removing any caller-supplied internal
argument. Object keys are sorted recursively, duplicate keys and non-finite
numbers are rejected, and UTF-8 JSON types are encoded deterministically. The
target reconstructs this invocation from the actual Gateway event rather than
from an original JSON-RPC envelope it may not receive. The expiry window is 30
seconds.

The signing key is a stage-scoped secret. Rotation supports a current signing
key and one previous verification key. Neither key is committed, logged, or
passed to mnemo-server.

Before production enablement, a real Gateway smoke test must prove all of the
following:

- the interceptor can inject the reserved argument through AgentCore schema
  processing;
- caller-supplied context is overwritten rather than merged;
- interceptor and target reconstruct the same canonical invocation after the
  real Gateway transforms the request;
- the target invocation source is the exact Gateway service role.

If unknown arguments are stripped or rejected, each tool schema must declare the
reserved property while marking it as internal in descriptions. Caller injection
remains safe because the interceptor overwrites it and the target verifies the
MAC.

After verification, the target creates a second HMAC-SHA-256 transport envelope
for mnemo-server. It uses a different secret and binds issuer, method, path,
body hash, derived identity, issued time, and a 30-second expiry. Mnemo-server
accepts the current and previous key for each allowlisted issuer. Namespace-aware
endpoints reject raw derived headers, expired or mismatched envelopes, and a bare
tenant key. Approved service REST callers use their own service issuer and
principal rather than impersonating the Gateway target.

The target rejects:

- missing or duplicate context;
- caller context that survived without interceptor replacement;
- invalid canonical encoding, MAC, request hash, tool, or time window;
- unknown `kid` or version;
- more than 32 group keys;
- duplicate or unsorted group keys;
- any caller-supplied tenant, namespace, principal, API-key, or internal-header
  field.

## Cognito Group Routing

### Recognized group rule

The interceptor derives a `group_key` for every syntactically valid value in
`cognito:groups`, up to a maximum of 32 token groups. The server compares those
keys with active `memory_cognito_group_bindings`.

Only configured group bindings count as namespace groups. Other organization,
role, or application groups are ignored.

For a human request:

- zero active recognized bindings: deny `namespace_membership_required`;
- one active recognized binding: continue;
- two or more active recognized bindings: deny `ambiguous_namespace`;
- two group keys that map to the same namespace still count as ambiguous in
  version 1, avoiding implicit role precedence.

### Database membership rule

The resolved group binding supplies the namespace and the default role for
first enrollment. Access still requires an active database membership.

- No membership and `jit_enabled=true`: create one transactionally.
- No membership and `jit_enabled=false`: deny.
- Active membership: use its persisted role.
- Revoked membership: deny and never reactivate automatically.
- Before human JIT creation, lock the principal and check for an active
  membership in any other namespace. If one exists, deny as an internal
  consistency error and require operator reconciliation.
- Disabled principal or namespace: deny.
- Membership namespace different from the group binding: deny as an internal
  consistency error.

This intersection lets the database revoke access immediately while preserving
the operational convenience of Cognito group assignment.

### Direct Cognito changes and stale tokens

The supported access-management command updates the database before changing
Cognito groups. Direct console/API group changes bypass that ordering:

- removing a group directly can leave an already issued access token valid for
  at most 15 minutes;
- adding a configured group directly can create a JIT membership only when the
  human has no other active namespace membership;
- adding a configured group while another active membership exists fails closed
  and is reported as drift;
- adding an unconfigured group grants nothing.

An operator reconciliation command reports Cognito-to-database drift. Emergency
revocation always writes the database first and does not rely on token expiry.

## Access Management

Version 1 provides operator commands, not a public administration API.

### Desired-state file

The reconciler reads a gitignored local JSON file:

```json
{
  "namespaces": [
    {
      "slug": "team-a",
      "display_name": "Team A",
      "cognito_group": "mem9-team-a",
      "default_role": "member",
      "jit_enabled": true,
      "status": "active"
    }
  ],
  "m2m_bindings": [
    {
      "client_key": "<derived-client-key>",
      "principal_key": "<derived-principal-key>",
      "namespace_slug": "team-a",
      "role": "member",
      "status": "active"
    }
  ]
}
```

The file contains no passwords, tokens, API keys, memory content, account IDs,
or resource ARNs. Real environment values remain gitignored.

### Reconciliation

`scripts/reconcile-memory-namespaces.mjs` performs an idempotent two-plane
reconciliation:

1. Validate the complete desired-state file locally.
2. Create missing Cognito groups; update descriptions if required.
3. Launch a one-shot VPC bootstrap task that upserts namespaces and bindings in
   Aurora.
4. Read back both planes and emit a content-free drift report.

The default mode never deletes a namespace, binding, group, membership, or
principal. Destructive pruning requires a separate explicit flag and operator
confirmation and is outside version 1.

### User assignment and movement

`scripts/manage-memory-access.mjs` starts one serialized, one-shot access task
and provides:

```text
assign-user --username <value> --namespace <slug>
move-user   --username <value> --namespace <slug>
revoke-user --username <value>
revoke-user --emergency --username <value>
show-user   --username <value>
```

Commands read the username from an owner-only local file or stdin rather than
placing it in committed files. The value may be present in the local process
environment and AWS audit records but is never printed in normal output.

The task holds a per-principal PostgreSQL advisory lock for the operation.
Fail-closed assign/move order:

1. Resolve the Cognito user and derive the human principal key.
2. Revoke all old active database memberships for that principal.
3. Remove the user from every managed namespace group.
4. Add the user to the selected managed group.
5. Re-read Cognito and require exactly the selected managed group.
6. Operator-upsert the target membership to `active`, including regrant of a
   previously revoked target row.

The membership grant is deliberately last. A failure after adding the group but
before the grant still leaves the user without access. Retries are idempotent,
including A-to-B-to-A moves, and concurrent commands cannot interleave.

Normal `revoke-user` revokes active memberships before removing managed groups.
`revoke-user --emergency` additionally disables the principal and terminally
cancels its queued or processing jobs with a fenced status transition before
group removal.

## Control-Plane Schema

```sql
CREATE TABLE memory_namespaces (
    namespace_id VARCHAR(36) PRIMARY KEY,
    slug VARCHAR(100) NOT NULL UNIQUE,
    display_name VARCHAR(255) NOT NULL,
    kind VARCHAR(20) NOT NULL CHECK (kind = 'team'),
    status VARCHAR(20) NOT NULL CHECK (status IN ('active', 'disabled')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE memory_principals (
    principal_id VARCHAR(36) PRIMARY KEY,
    principal_key VARCHAR(64) NOT NULL UNIQUE,
    principal_type VARCHAR(20) NOT NULL
        CHECK (principal_type IN ('human', 'm2m', 'service')),
    status VARCHAR(20) NOT NULL
        CHECK (status IN ('active', 'disabled')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE memory_cognito_group_bindings (
    group_key VARCHAR(64) PRIMARY KEY,
    namespace_id VARCHAR(36) NOT NULL,
    default_role VARCHAR(20) NOT NULL
        CHECK (default_role IN ('viewer', 'member')),
    jit_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    status VARCHAR(20) NOT NULL
        CHECK (status IN ('active', 'disabled')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (namespace_id)
        REFERENCES memory_namespaces(namespace_id)
);

CREATE TABLE memory_namespace_memberships (
    namespace_id VARCHAR(36) NOT NULL,
    principal_id VARCHAR(36) NOT NULL,
    role VARCHAR(20) NOT NULL
        CHECK (role IN ('viewer', 'member', 'owner')),
    status VARCHAR(20) NOT NULL
        CHECK (status IN ('active', 'revoked')),
    source_type VARCHAR(20) NOT NULL
        CHECK (source_type IN ('cognito_group', 'm2m_binding', 'operator', 'service')),
    source_key VARCHAR(64) NULL,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ NULL,
    PRIMARY KEY (namespace_id, principal_id),
    FOREIGN KEY (namespace_id)
        REFERENCES memory_namespaces(namespace_id),
    FOREIGN KEY (principal_id)
        REFERENCES memory_principals(principal_id)
);

CREATE TABLE memory_m2m_namespace_bindings (
    client_key VARCHAR(64) PRIMARY KEY,
    principal_id VARCHAR(36) NOT NULL UNIQUE,
    namespace_id VARCHAR(36) NOT NULL,
    role VARCHAR(20) NOT NULL
        CHECK (role IN ('viewer', 'member')),
    status VARCHAR(20) NOT NULL
        CHECK (status IN ('active', 'disabled')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    FOREIGN KEY (principal_id)
        REFERENCES memory_principals(principal_id),
    FOREIGN KEY (namespace_id)
        REFERENCES memory_namespaces(namespace_id)
);

CREATE TABLE memory_namespace_migration_state (
    singleton_id BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton_id),
    phase VARCHAR(40) NOT NULL,
    checkpoint VARCHAR(80) NULL,
    legacy_namespace_id VARCHAR(36) NULL,
    legacy_principal_id VARCHAR(36) NULL,
    legacy_namespace_slug VARCHAR(63) NULL,
    legacy_namespace_display_name VARCHAR(80) NULL,
    legacy_principal_key CHAR(64) NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

The migration-state check couples the fields to the phase:
`additive_ready`/`frozen` require every legacy binding field to be null, while
`backfilling`, `application_ready`, and `constraints_complete` require every
field to be present. A later phase cannot exist without an immutable seed.

JIT principal and membership creation uses one transaction and `ON CONFLICT`.
The transaction serializes per principal, re-reads all rows before returning
scope, refuses a second active human namespace, and never updates a revoked
membership to active.

The local desired-state generator derives both M2M lookup keys from the same
validated issuer/client input. M2M reconciliation atomically creates or resolves
the M2M principal, binding, and matching membership. Runtime resolution derives
both keys from the token and requires the active binding to reference that
principal, plus a matching active membership and namespace; any mismatch fails
closed.

Raw Cognito group names and usernames are not required in Aurora. Operators
keep the mapping file locally and the database stores only `group_key`.

## Data-Plane Schema

| Table              | Required additions                                                                                   |
| ------------------ | ---------------------------------------------------------------------------------------------------- |
| `memories`         | `namespace_id NOT NULL`; nullable `created_by_principal_id` and `updated_by_principal_id`            |
| `sessions`         | `namespace_id NOT NULL`; nullable actor principal                                                    |
| `ingest_jobs`      | `namespace_id NOT NULL`; `principal_id NOT NULL`; namespace-aware idempotency, claim, and lease keys |
| `ingest_job_plans` | `namespace_id NOT NULL`; composite foreign key to its job                                            |
| `upload_tasks`     | `namespace_id NOT NULL` before upload routes or worker processing are enabled                        |
| webhook tables     | namespace columns before webhook registration or delivery is enabled                                 |

Historical ingest jobs are backfilled with a seeded
`legacy-unattributed-service` principal. This identifies a migration placeholder,
not a human owner. Historical memories and sessions keep nullable human audit
columns.

Every data-plane `namespace_id` references `memory_namespaces`. Non-null actor
columns reference `memory_principals`. Cross-row relationships that can cross a
namespace, including job-to-plan and merge/action targets, use namespace-bearing
composite keys rather than object ID alone.

Required constraints include:

```text
ingest_jobs:
  UNIQUE (tenant_id, namespace_id, idempotency_key)
  UNIQUE (tenant_id, namespace_id, job_id)

ingest_job_plans:
  PRIMARY KEY (tenant_id, namespace_id, job_id, plan_revision)
  UNIQUE (tenant_id, namespace_id, job_id, plan_hash)
  FOREIGN KEY (tenant_id, namespace_id, job_id)
    REFERENCES ingest_jobs (tenant_id, namespace_id, job_id)

sessions:
  UNIQUE (namespace_id, app_id, session_id, content_hash)
```

Worker claim indexes are derived from the actual cross-namespace claim SQL and
validated with a production-shaped `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)`
fixture. The documented bound records the expected index name, absence of a
sequential scan, maximum candidate rows visited per page, lock-wait budget, and
p95 claim latency. Indexes are not required to begin with `namespace_id` if the
trusted worker's queue scan does not filter one namespace before claiming.
Every claimed row still carries immutable namespace identity.

## Required Namespace Scope

The Go runtime uses a non-optional scope:

```text
NamespaceScope {
  TenantID
  NamespaceID
  PrincipalID
  PrincipalType
  Role
}
```

Memory and session repository constructors require `NamespaceScope`. A trusted
worker constructs scope from the persisted job, never from the job payload.
In required mode there is no constructor fallback for an empty namespace.
Legacy empty-scope construction exists only while the database remains
`additive_ready`; startup refuses compatibility mode in every later phase.

Every get, list, count, search, update, delete, merge, existence, reconciliation,
status, lease, and apply query includes namespace identity.

## Search Correctness

Version 1 prioritizes provable namespace filtering over approximate-index
performance.

- Full-text search uses `WHERE namespace_id = $1` and the existing GIN index,
  with a namespace B-tree index available for bitmap plans.
- Vector search uses one read-only transaction and materializes the namespace
  subset before exact cosine ordering. The same snapshot supplies the row-count
  guard and result query, and `SET LOCAL statement_timeout` applies a bounded
  execution time.
- The tenant-wide HNSW index is not used for namespace-scoped result selection
  in version 1 because post-filtered ANN cannot guarantee the requested top-K.
- `EXPLAIN` must prove that the exact query does not use the tenant-wide HNSW
  index for result selection, and test results must equal an application
  brute-force namespace-local top-K baseline.
- If a namespace exceeds `MEM9_NAMESPACE_EXACT_VECTOR_MAX_ROWS`, search returns
  the stable non-retryable `namespace_vector_capacity` error.
- A statement timeout returns the separately observable retryable
  `namespace_vector_timeout` error with bounded backoff guidance.
- Neither error broadens to the tenant corpus or returns tenant-wide ANN
  candidates.

The production threshold is selected from a representative two-namespace
benchmark whose corpus size, vector dimensions, top-K, concurrency, hardware,
and approved p95 baseline are recorded. A capacity alarm fires before a
namespace reaches the ceiling. The migration drops the tenant-wide HNSW index if
no supported path still uses it; otherwise a plan-regression test proves that
namespace search cannot select it. A future per-namespace ANN strategy requires
a separate reviewed design.

## Durable Ingest

- Canonical request bytes and idempotency keys include namespace identity.
- Jobs persist tenant, namespace, actor principal, and canonical payload before
  returning accepted status.
- Namespace is immutable after insert.
- FIFO/advisory scope includes namespace where ordering semantics require it.
- Plan build and reconciliation search only the job namespace.
- Plans are bound to jobs with a composite foreign key.
- Lease, retry, heartbeat, status, and finalization predicates repeat tenant,
  namespace, and job identity.
- Atomic apply constructs memory/session repositories from the job namespace.
- A plan or payload cannot override namespace or principal.
- Normal membership revocation does not cancel an already accepted team job.
- Emergency principal disable terminally cancels that principal's non-terminal
  jobs. The job-row lock linearizes emergency revoke against apply: either apply
  commits first and revoke follows, or revoke marks the job terminal and apply
  commits no content. No mutation can commit after emergency revoke returns.
- Disabling the namespace terminally cancels non-terminal jobs in that namespace
  and prevents apply.

## Path Inventory

| Path                            | Namespace contract                                                                            |
| ------------------------------- | --------------------------------------------------------------------------------------------- |
| MCP `add_memory`                | Writes resolved namespace and actor principal                                                 |
| MCP `search_memories`           | Exact vector, FTS, filters, and confidence logic remain inside namespace                      |
| memory get/update/delete/merge  | Object ID and namespace must match                                                            |
| `ingest_messages`               | Envelope, job, plan, lease, reconciliation, and apply carry namespace                         |
| job status                      | Tenant, namespace, and job ID match; foreign ID returns generic 404                           |
| sessions                        | Upsert, list, single delete, and bulk delete carry namespace                                  |
| upload route and worker         | Disabled until task claim and generated memories carry namespace                              |
| webhook registration/delivery   | Disabled until all rows and events carry namespace                                            |
| Space Chains                    | Disabled                                                                                      |
| cleanup/restore                 | Disabled in v1; future re-enablement requires an explicit namespace and no all-namespace mode |
| consolidation                   | Disabled in v1; future re-enablement permits one namespace per content-bearing run            |
| cleanup scan and Slack approval | Disabled until offer, claim, artifact, destination, and apply are namespace-bound             |
| S3 consolidation digest         | Key includes stage and namespace                                                              |
| SSM approval state              | Key includes stage and namespace                                                              |
| analysis and sampler SQL        | Explicit namespace bind required                                                              |
| service REST calls              | Explicit service membership in target namespace                                               |

A maintained query inventory test expands the pinned upstream `MEM9_REF`, applies
the complete downstream patch stack, and classifies every SQL statement touching
a scoped table across the compiled Go source, bootstrap SQL, migrations,
operator scripts, maintenance scripts, and infrastructure tasks. The
version-controlled manifest records the statement owner, scoped tables,
namespace predicate or trusted exception, and test coverage. New or changed
unclassified statements fail CI. JavaScript templates and Go string
concatenations are reconstructed before classification. Compatibility branches
are allowed only by exact owner plus normalized-statement hash entries in
`scripts/memory-namespace-query-exceptions.json`; adding or changing a statement
cannot inherit an owner-wide exception.

## Maintenance State

### Consolidation

Current v1 state: absent from the SST application graph and CI deployment
workflow. The retained production CLI entry point also exits before creating a
database, REST, model, S3, SSM, or Slack adapter. The requirements below are
mandatory for a future re-enable.

- One content-bearing invocation handles one namespace.
- List, classify, winner checks, archive, stale marking, and mutex keys include
  namespace.
- Digest keys use
  `consolidation-digests/<stage>/<namespace_id>/current-v1.json`.
- An orchestrator may enumerate active namespaces, but each namespace result and
  failure is isolated.

### Cleanup and restore

Current v1 state: no deployed cleanup/restore task or public invocation path.
The retained direct CLI exits before creating any production adapter, including
the inactive-memory database adapter. Internal pure functions remain only as
redesign context and unit-test fixtures. The requirements below are mandatory
for a future re-enable.

- `--namespace-id` or `MEM9_NAMESPACE_ID` is required.
- Missing namespace exits before SQL, REST, S3, SSM, Slack, or model calls.
- `--ids` ignores foreign IDs as absent and never reveals their existence.

### Cleanup scan and Slack approval

The scheduled scan and approval loop remains disabled until it provides:

- one namespace per offer;
- namespace-specific SSM offer and claim keys;
- namespace-specific decision artifact keys;
- an approval destination explicitly authorized for that namespace;
- apply-time verification that offer, claim, artifact, and requested namespace
  all match.

## Failure Semantics

- Missing, invalid, expired, or forged internal context: deny before target REST
  construction.
- Missing, invalid, expired, or mismatched target/service transport envelope:
  deny before namespace middleware; bare derived identity headers are ignored.
- Unknown client type, principal, group binding, M2M binding, membership, or
  namespace: 403 without content data.
- Zero recognized human groups: 403.
- Multiple recognized human groups: 409 configuration error with no group or
  namespace names in the response.
- Revoked membership: 403 and no JIT reactivation.
- A human with another active namespace membership: internal consistency error;
  no JIT insert.
- Foreign object or job ID: generic 404 matching a random unknown ID.
- Disabled namespace: deny new requests and prevent job apply.
- Emergency-disabled principal: deny new requests and cancel non-terminal jobs.
- Job/plan/lease/action namespace mismatch: permanent internal error and no
  content transaction commit.
- Exact vector capacity: non-retryable operational error and capacity alarm.
- Exact vector timeout: retryable operational error with bounded backoff.
- Group-management partial failure: user has no access, never multiple
  namespace access.

## Migration And Cutover

Historical data is assigned to one explicitly selected legacy team namespace.
This requires an operator assertion that the current corpus is shared team
history.

### Phase 0: inventory and freeze

- Record production-shaped row counts and current index/constraint definitions.
- Drain durable ingest until pending and processing counts are zero. Migration
  does not start with an in-flight legacy canonical job.
- Create or verify the singleton migration-state table before taking the freeze.
- Disable consolidation, cleanup scan, Slack apply, imports, webhooks, and Space
  Chains.
- Disable the Gateway target and every write-capable event source.
- Scale the mnemo-server service to zero and wait for no running or pending task.
- Verify `pg_stat_activity` contains no application writer before taking the
  migration lock.
- Record phase `frozen` in `memory_namespace_migration_state`; migration and new
  application code refuse to advance from an unexpected phase.
- Prevent user and group onboarding during the migration window.
- Create a manual Aurora snapshot and record the latest restorable time.

### Phase 1: additive database release

- Create control-plane tables.
- Seed the legacy namespace and legacy service principal from the same
  stage-scoped desired-state input used by the backfill.
- Add nullable namespace and principal columns.
- Add additive checks and foreign keys whose referenced keys already exist as
  `NOT VALID`; defer the composite plan/job foreign key until its referenced
  unique key is attached.
- Do not create namespace data-plane indexes during application startup.
  The guarded operator creates them concurrently after the write freeze.
- Keep old application code compatible with the additive schema.

### Phase 2: direct-SQL backfill

- Require the exact shared-history acknowledgement.
- Backfill namespaces in bounded batches using direct SQL only.
- Backfill historical ingest actor identity with the legacy service principal.
- Persist the exact legacy namespace/principal IDs, slug, display name, and
  derived principal key before data mutation. A retry with different seed
  values fails before changing rows or indexes.
- Do not update memories through REST `PUT`; the upstream optimistic update can
  overwrite embeddings.
- Compare a deterministic ordered digest over every embedding, plus null and
  zero-vector counts, before and after memory backfill. PostgreSQL computes the
  chained digest in ID order without buffering the vector corpus in Node.js.
  The allowed mismatch count is zero.
- Verify counts, nulls, orphans, duplicate keys, and plan/job relationships.

Writes and workers remain stopped for the whole backfill and key-transition
window. There is no shadow mode that permits new null-namespace rows.

### Phase 3: key and constraint transition

The operator first creates each namespace-aware index with `CONCURRENTLY`.
Every rerun reads the PostgreSQL catalog and verifies the table, uniqueness,
key expressions, sort options, exact normalized predicate, readiness, and
validity. An invalid partial index is dropped concurrently and rebuilt. A valid
index with the expected name but a different predicate fails closed rather than
being treated as a checkpoint. After all indexes pass, the operator records
checkpoint `namespace_indexes_ready`.

The remaining key and constraint transition runs as one bounded transaction in
`003_enforce_memory_namespaces.sql`: attach the referenced composite job key,
add and validate namespace foreign keys and checks, verify zero nulls, apply
`NOT NULL`, remove the tenant-wide HNSW index, and record
`constraints_complete`. Lock and statement timeouts fail the transaction
without exposing a partial constraint state; the rerun validates and repeats
the transaction from its beginning. Writes and workers remain closed until the
transaction commits. The fault-injection and production-shaped timeout cases in
the acceptance criteria remain release gates rather than inferred guarantees.

### Phase 4: compatible application release

- First deploy the split interceptor/target, namespace middleware, bound
  repositories, and namespace-aware worker with
  `MEM9_NAMESPACE_REQUIRED=0`.
- Keep cleanup approval, consolidation, upload processing, webhooks, and Space
  Chains disabled.
- After phase 3 reaches `application_ready`, run the enforcement operator
  command. It validates the final constraints and records
  `constraints_complete`.
- Reconcile namespaces and bindings, then assign every enabled human and M2M
  client while traffic remains closed.
- Set `MEM9_NAMESPACE_REQUIRED=1` and deploy the same reviewed release. Startup
  then refuses any phase other than `constraints_complete`.
- Before any required-mode production SST deployment, CI runs the already
  deployed private operator task with `assert-phase constraints_complete`.
  Fixed mismatch exit codes let the workflow report only the observed and
  required phase and stop before infrastructure mutation.
- Run the real-Gateway, PostgreSQL, and two-namespace suites before reopening
  traffic.

The implemented operator commands check their predecessor database phase and
are idempotent. The repository variable is the application switch: a normal
deployment cannot silently enable namespace-required startup because unset
means `0`. The service-before-bootstrap workflow is safe only for the initial
compatibility deployment; the live backfill and enforcement commands run
separately while the service is scaled to zero.

PR previews do not require production namespace inputs. For a `pr-N` stage,
infrastructure creates two temporary M2M clients. The preview bootstrap
reconciles two synthetic namespaces and Cognito groups in that stage's isolated
pool and shared Aurora database, binds the default client plus the two fixture
clients, and advances the empty database through `constraints_complete`. CI
then redeploys the same commit with namespace-required startup and runs a
high-signal Gateway write/search test in both directions. Each fixture client
must recall its own marker, the default client must recall the alpha marker
through its shared namespace binding, and neither foreign-marker query may
return the other namespace's marker. The deterministic PostgreSQL integration
suite proves exhaustive row isolation; the deployed M2M test covers the
Gateway, signed transport, shared-team binding, and live search path. Human
`cognito:groups` routing remains covered by its dedicated unit, PostgreSQL, and
real browser-token Gateway-smoke criteria.

Preview cutover is resumable across workflow cancellation. If the existing task
definition carries the namespace-bootstrap version marker, the next run invokes
that task before deploying the new revision. The task resumes additive, frozen,
backfilling, or application-ready state idempotently and converges on
`constraints_complete`; the new revision then deploys directly with
namespace-required startup. A legacy preview task without the marker is treated
like a brand-new stage and first receives the compatibility deployment before
the bootstrap and second switch deployment.

### Phase 5: groups and reopen

- Reconcile namespace definitions and Cognito groups.
- Assign each memory-enabled human to exactly one managed group.
- Bind selected M2M clients.
- Reopen writes.
- Require users to obtain new access tokens.
- Run same-group sharing and cross-group denial smoke tests.
- Re-enable only maintenance paths that passed namespace-specific report-only
  verification.

## Rollback

Before a second namespace contains data, the compatible application can be
rolled back only to a release that still understands namespace columns and
membership.

After multiple namespaces are active, code that ignores namespace is never a
valid rollback target. Recovery options are:

- deploy a forward fix;
- disable affected namespaces;
- stop workers and writes;
- restore the manual snapshot or PITR state into an isolated environment;
- reconcile the corrected data before reopening.

Control tables and namespace columns remain after application rollback.

## Observability And Privacy

Content-free metrics:

- client type accepted/rejected;
- internal context accepted/rejected by reason;
- recognized group count bucket: zero, one, multiple;
- principal and membership resolution result;
- JIT create result;
- namespace resolution latency;
- exact-vector row-bound and timeout failures;
- cross-namespace invariant failure;
- management reconciliation drift count.

Metrics use bounded stage/result dimensions. Namespace, principal, client,
group, user, memory, session, and job identifiers are not CloudWatch
dimensions.

Logs must not contain:

- bearer tokens or Authorization headers;
- HMAC keys or full internal context;
- raw Cognito subject, username, email, client ID, or group name;
- principal, client, or group lookup keys at info level;
- memory content, embeddings, canonical payloads, plans, or model prompts.

Private database audit rows may contain internal random IDs and object IDs.

## Cost And Capacity

No Aurora database, schema, cluster, ECS service, embedder, or Mantle project is
created per user or namespace.

Incremental cost is limited to:

- one non-VPC interceptor Lambda separated from the target;
- small control-plane tables and indexes;
- one membership/group-binding lookup per request;
- exact namespace vector scans bounded for the small-team product;
- operator reconciliation tasks.

Production gates:

- namespace resolution p95 below 20 ms in the application VPC;
- at the documented benchmark corpus and configured ceiling, search p95 is no
  more than 120 percent of the approved exact-scan baseline, excluding embedding
  provider time;
- no Lambda-originated Aurora connection pool;
- no steady-state database connection growth per user;
- no content-bearing CloudWatch metric or log.

## Alternatives

### Custom Cognito user attribute

Rejected as the authorization source. A single custom attribute does not model
revocable roles or future multi-membership, its schema cannot be removed or
changed after creation, and the application must not assume it appears in the
access token. It may later be used as a non-authoritative UI preference.

### Cognito group as the only authorization source

Rejected. Group claims are token snapshots and do not provide immediate
database revocation, durable role audit, M2M bindings, or job ownership
invariants.

### Client-selected namespace

Rejected. It introduces an IDOR input and is unnecessary while each human token
must resolve exactly one managed namespace.

### `agent_id` as namespace

Rejected. It is caller-controlled, optional, and absent from several background
and direct-SQL paths.

### One PostgreSQL database per user or team

Rejected for the small-team cost model. It multiplies provisioning, migration,
connection, backup, restore, and teardown work.

### PostgreSQL row-level security

Deferred. The first release uses non-optional namespace-bound repositories,
database constraints, a complete query inventory, and two-namespace adversarial
tests. RLS can be added later as defense in depth after transaction-local scope
handling is proven for pooled connections.

## Implementation Slices

1. **Gateway contract spike**
   - prove reserved-context overwrite and schema passage;
   - prove canonical invocation hash reconstruction;
   - prove exact Gateway target invocation source.
2. **Identity propagation and internal transport**
   - split interceptor and target;
   - implement client registry, HMAC context, key rotation, and signed
     target/service-to-server envelopes.
3. **Namespace control plane**
   - add namespace, principal, group-binding, M2M-binding, membership, and
     migration-state tables;
   - atomically reconcile M2M principal, binding, and membership;
   - set the reader access-token lifetime.
4. **Cognito reconciliation and access management**
   - reconcile desired groups and bindings;
   - implement serialized assign, move, normal revoke, emergency revoke, and
     drift reporting.
5. **Additive data-plane schema**
   - add nullable namespace/audit columns and `NOT VALID` constraints without
     startup-time data-plane index builds.
6. **Freeze and embedding-preserving backfill**
   - implement the hard write fence, queue drain, immutable legacy seed
     binding, concurrent index preparation, and direct-SQL backfill with a
     bounded database-side embedding digest.
7. **Constraint transition and staged CI**
   - implement catalog-resumable index creation, bounded transactional
     enforcement, and four gated CI phases.
8. **Synchronous repositories and exact search**
   - bind memory/session CRUD, FTS, exact vectors, and service REST paths.
9. **Durable ingest**
   - bind canonical jobs, plans, constraints, leases, claim, reconciliation,
     cancellation, status, and atomic apply.
10. **Maintenance and background inventory**
    - bind cleanup, restore, consolidation, analysis, digests, and service paths;
    - generate the expanded-source query manifest;
    - block upload, webhook, Space Chains, and Slack approval until supported.
11. **PR-preview adversarial verification**
    - automatically create two synthetic namespaces in the shared preview
      database and run hard M2M write/recall/cross-namespace denial checks;
    - run human group movement, browser-token routing, migration failure, exact
      search, and the remaining live Gateway attacks on their named surfaces.
12. **Post-deploy recovery verification**
    - execute the manual snapshot/PITR restore rehearsal and record private
      evidence without blocking pre-merge implementation issues.

Acceptance criteria are defined in
[`../test-cases/cognito-group-memory-namespaces.md`](../test-cases/cognito-group-memory-namespaces.md).
