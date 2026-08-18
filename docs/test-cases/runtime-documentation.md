# Test cases: runtime documentation consistency

These cases review the implemented runtime documented in
[`README.md`](../../README.md), [`docs/ARCHITECTURE.md`](../ARCHITECTURE.md),
[`docs/mem9-facts.md`](../mem9-facts.md), and the runbook comments referenced by
those documents. They do not test or change runtime behavior.

| ID | Scenario | Expected |
|---|---|---|
| TC-DOCS-001 | ECS task composition | Current-state documentation names exactly the three application containers: `mnemo-server`, `qwen3-embed`, and `llm-proxy`. |
| TC-DOCS-002 | Smart-ingest LLM request path | `mnemo-server` calls `llm-proxy` on localhost; the proxy refreshes the short-term Mantle bearer, conditionally injects `OpenAI-Project` when a Bedrock Project is configured, and calls Mantle. No current-state section says that `mnemo-server` calls Mantle directly. |
| TC-DOCS-003 | Database path | `mnemo-server` and the bootstrap task use the Aurora cluster writer endpoint directly with a Secrets Manager credential. RDS Proxy appears only as a dated, rejected alternative. |
| TC-DOCS-004 | IAM terminology | Container application calls use the ECS task role and valid `bedrock-mantle:*` actions, including singular `ListTagsForResource`. Secret injection at task startup uses the ECS task execution role with `secretsmanager:GetSecretValue`. |
| TC-DOCS-005 | Current versus planned behavior | Current implementation, planned reliability work, and rejected alternatives are separate. Open reliability work is not presented as deployed behavior. |
| TC-DOCS-006 | Known contradictory phrases | The automated consistency test scans relevant source and documentation formats repository-wide. It rejects the former design-only status, direct-Mantle path, RDS Proxy current path, two-container task, future ALB/Lattice path, removed credential provider, invalid plural Mantle tag action, and claims that no Cloud Map private zone exists. |
| TC-DOCS-007 | Repository-relative links | Every relative Markdown link in the three authoritative documents resolves to an existing repository path. |
| TC-DOCS-008 | Claim provenance | Explicit citations cover ECS task roles, ECS secret injection, Aurora writer endpoints and IAM-token lifetime, AgentCore Lambda targets and permissions, Lambda VPC access, Cloud Map private DNS namespaces, and Mantle auth/projects/actions. Repository source and deployment observations are explicitly labeled empirical and dated. |
| TC-DOCS-009 | Optional production facade domain | README and architecture documentation keep the custom domain opt-in, require the Cloudflare configuration, preserve DNS-only records, keep preview stages out of the path, and cite ACM renewal behavior. |
| TC-DOCS-010 | Public-repository fork threat model | README, architecture, and workload-boundary design do not describe this public repository as private. They distinguish the fork secret and write-permission restrictions from the checked-in `secrets.AWS_ROLE_ARN` interlock, state that a role ARN is not an authorization boundary, record the retained `pull_request` OIDC subject, and require removal of every matching trust entry before untrusted PR code can receive `id-token: write`. |
