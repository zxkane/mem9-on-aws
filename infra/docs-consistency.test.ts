import { existsSync, readFileSync, readdirSync } from "node:fs";
import { dirname, extname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

const files = {
  readme: "README.md",
  architecture: "docs/ARCHITECTURE.md",
  facts: "docs/mem9-facts.md",
  ecs: "infra/ecs.ts",
} as const;

const text = Object.fromEntries(
  Object.entries(files).map(([name, path]) => [
    name,
    readFileSync(resolve(root, path), "utf8"),
  ]),
) as Record<keyof typeof files, string>;

const authoritativeDocs = `${text.readme}\n${text.architecture}\n${text.facts}`;

const ignoredDirectories = new Set([
  ".agents",
  ".git",
  ".sst",
  ".worktrees",
  "coverage",
  "dist",
  "node_modules",
]);
const relevantExtensions = new Set([
  ".bash",
  ".cjs",
  ".js",
  ".json",
  ".md",
  ".mjs",
  ".sh",
  ".sql",
  ".toml",
  ".ts",
  ".tsx",
  ".yaml",
  ".yml",
]);

function repositorySourcePaths(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    if (entry.isDirectory()) {
      return ignoredDirectories.has(entry.name)
        ? []
        : repositorySourcePaths(join(directory, entry.name));
    }
    if (!entry.isFile()) return [];

    const path = join(directory, entry.name);
    const repositoryPath = relative(root, path);
    if (repositoryPath === "infra/docs-consistency.test.ts") return [];
    return relevantExtensions.has(extname(entry.name)) ||
      entry.name === "Dockerfile" ||
      entry.name === ".env.example"
      ? [repositoryPath]
      : [];
  });
}

const repositorySources = repositorySourcePaths(root)
  .sort()
  .map((path) => [path, readFileSync(resolve(root, path), "utf8")] as const);
const auditedSources = repositorySources.map(([, source]) => source).join("\n");

function markdownSection(markdown: string, startHeading: string, endHeading: string) {
  const start = markdown.indexOf(startHeading);
  const end = markdown.indexOf(endHeading, start + startHeading.length);
  if (start < 0 || end < 0) {
    throw new Error(`missing section boundary: ${startHeading} -> ${endHeading}`);
  }
  return markdown.slice(start, end);
}

const architectureCurrent = markdownSection(
  text.architecture,
  "## Current implementation",
  "## Locked decisions",
);
const readmeCurrent = markdownSection(
  text.readme,
  "## Current implementation",
  "## Planned reliability work",
);

describe("runtime documentation", () => {
  it("TC-DOCS-001: documents the implemented three-container task", () => {
    for (const name of ["mnemo-server", "qwen3-embed", "llm-proxy"]) {
      expect(text.readme).toContain(name);
      expect(text.architecture).toContain(name);
    }
    expect(text.readme).toMatch(/\b3 containers\b/i);
    expect(text.architecture).toMatch(/\bthree containers\b/i);
  });

  it("TC-DOCS-002: routes LLM requests through the local proxy", () => {
    expect(architectureCurrent).toContain("-> llm-proxy:8082");
    expect(architectureCurrent).toContain(
      "MNEMO_LLM_BASE_URL=http://localhost:8082/v1",
    );
    expect(architectureCurrent).toContain("Injects `OpenAI-Project`");
    expect(architectureCurrent).toContain(
      "when `MEM9_BEDROCK_PROJECT` is configured",
    );
    expect(readmeCurrent).toContain("local `llm-proxy` sidecar");
    expect(readmeCurrent).toContain("proxy refreshes a short-term Mantle bearer");
    expect(readmeCurrent).toContain(
      "when `MEM9_BEDROCK_PROJECT` is configured",
    );
    for (const currentSection of [architectureCurrent, readmeCurrent]) {
      expect(currentSection).not.toContain(
        "MNEMO_LLM_BASE_URL=https://bedrock-mantle",
      );
      expect(currentSection).not.toContain("Mantle direct, NO");
    }
  });

  it("TC-DOCS-003: documents direct Aurora writer connections without RDS Proxy", () => {
    expect(authoritativeDocs).toMatch(/Aurora (cluster )?writer endpoint/i);
    expect(authoritativeDocs).toContain("RDS Proxy is not deployed");
    expect(authoritativeDocs).not.toContain("Chosen (LOCKED): RDS Proxy");
    expect(auditedSources).not.toContain("MEM9_DB_HOST    - RDS Proxy endpoint");
  });

  it("TC-DOCS-004: uses the implemented Mantle IAM namespace and ECS role names", () => {
    expect(authoritativeDocs).toContain("bedrock-mantle:CreateInference");
    expect(authoritativeDocs).toContain("bedrock-mantle:CallWithBearerToken");
    expect(authoritativeDocs).toContain("bedrock-mantle:ListTagsForResource");
    expect(text.ecs).toContain("bedrock-mantle:ListTagsForResource");
    expect(authoritativeDocs).toContain("task execution role");
    expect(authoritativeDocs).not.toContain("`bedrock:InvokeModel` on the `zai.glm-5`");
    expect(auditedSources).not.toContain("ListTagsForResources");
    expect(auditedSources).not.toContain(
      "The secret ARN — the ECS task role will get secretsmanager:GetSecretValue",
    );
  });

  it("TC-DOCS-005: separates current, planned, and rejected behavior", () => {
    expect(text.architecture).toContain("## Current implementation");
    expect(text.architecture).toContain("## Planned changes");
    expect(text.architecture).toContain("## Rejected alternatives");
    expect(text.architecture).toContain(
      "The current async `messages[]` path is a durable queue and atomic job processor.",
    );
    expect(text.architecture).toContain(
      "Regular explicit-content memory operations remain on their existing path.",
    );
    expect(authoritativeDocs).not.toContain("Status: **design only, not implemented.**");
  });

  it("TC-DOCS-006: removes known stale runbook phrases", () => {
    const stalePatterns: [string, RegExp][] = [
      ["plural Mantle tag action", /ListTagsForResources/],
      ["RDS Proxy database summary", /Aurora PostgreSQL Serverless v2 \+ RDS Proxy/],
      ["two-container task", /Two containers:/i],
      ["Lattice-to-ALB path", /(?:managed VPC Lattice|Gateway -> Lattice) (?:→|->) internal ALB/i],
      ["RDS Proxy preview cleanup", /Aurora \+ RDS Proxy \+ ECS teardown/],
      ["RDS Proxy readiness gate", /RDS Proxy target being AVAILABLE/],
      ["RDS Proxy starvation cause", /PENDING_PROXY_CAPACITY.{0,40}starv/i],
      ["removed API-key provider", /API-key credential provider for outbound auth/i],
      ["removed target dependency", /\(gateway, api-key provider\)/i],
      ["missing Cloud Map zone", /no ALB, no cert, no Lattice, no private zone/i],
      ["missing Route 53 zone", /private R53 zone/i],
      ["RDS Proxy TLS requirement", /RDS Proxy mandates TLS/],
      ["RDS Proxy Docker path", /TLS to RDS Proxy \/ Bedrock \/ embed/],
      ["secret on application task role", /ECS task role will get secretsmanager:GetSecretValue/i],
      ["unverified proportional cause", /rate PROPORTIONAL/],
      ["unverified ACU remedy", /Raising min ACU to 2\+/],
      ["future-only deploy role", /Every future resource TYPE \(Aurora/],
      ["future-only PassRole", /No role is passed by the scaffold today/],
      ["future-only ECS task", /future ECS mnemo-server task/i],
      ["future-only ECR image", /placeholder public image now/i],
      ["single ECR repository", /ONE mnemo-server repo ARN/],
      ["mnemo-only image build", /build(?:s)? the mnemo-server arm64 image/i],
      ["mnemo-only image job", /Build & push mnemo-server image/],
      ["three-image build", /For each of the 3 images/],
      ["placeholder ECS image", /service props.{0,40}placeholder image/is],
      ["single ECR bootstrap repository", /ECR repository\s*\n# for the mem9-on-aws mnemo-server/i],
      ["single ECR bootstrap scope", /ECR repository only/i],
      ["single ECR bootstrap output", /builds the arm64 image \+ pushes to this repo/i],
      ["singular out-of-band ECR resource", /GitHub Actions IAM role,.{0,20}ECR (?:repo|repository),.{0,20}Bedrock Mantle Project/is],
      ["singular ECR workflow bootstrap", /OIDC role \+ ECR repo are/i],
      ["singular ECR regional config", /ECR repo \+ Bedrock Mantle Project live/i],
      ["obsolete PR bootstrap note", /ADDED for the .* PR/i],
      ["removed RDS Proxy SG", /Aurora cluster \+ RDS Proxy SGs/],
      ["removed Route 53 dependency", /ALB\/ACM\/Route53\/VPC-Lattice networking policy/],
      ["removed Lattice grant", /agentcore\/lattice/i],
      ["future-only Lambda transform", /No Lambda exists/],
      ["base-scaffold status", /base scaffold/i],
      ["unconditional project header", /injects it \+ OpenAI-Project per forwarded request/],
      ["unconditional project runbook", /on every Mantle \/chat\/completions call/],
      ["unconditional project shell comment", /on every Mantle call/],
    ];

    for (const [claim, pattern] of stalePatterns) {
      const matches = repositorySources
        .filter(([, source]) => pattern.test(source))
        .map(([path]) => path);
      expect(
        matches,
        `repository sources contain stale ${claim}: ${matches.join(", ")}`,
      ).toEqual([]);
    }
  });

  it("TC-DOCS-007: resolves repository-relative links in authoritative docs", () => {
    for (const path of [files.readme, files.architecture, files.facts]) {
      const markdown = readFileSync(resolve(root, path), "utf8");
      const links = [...markdown.matchAll(/\[[^\]]+\]\(([^)]+)\)/g)].map(
        (match) => match[1],
      );

      for (const target of links) {
        if (/^(?:https?:|mailto:|#)/.test(target)) continue;
        const relativePath = target.split("#", 1)[0];
        expect(
          existsSync(resolve(dirname(resolve(root, path)), relativePath)),
          `${path} links to missing path ${target}`,
        ).toBe(true);
      }
    }
  });

  it("TC-DOCS-008: cites AWS docs and dates empirical deployment observations", () => {
    const citations = [
      "AmazonECS/latest/developerguide/task-iam-roles.html",
      "AmazonECS/latest/developerguide/task_execution_IAM_role.html",
      "AmazonRDS/latest/AuroraUserGuide/Aurora.Endpoints.Cluster.html",
      "AmazonRDS/latest/AuroraUserGuide/UsingWithRDS.IAMDBAuth.Connecting.html",
      "bedrock-agentcore/latest/devguide/gateway-add-target-api-target-config.html",
      "bedrock-agentcore/latest/devguide/gateway-prerequisites-permissions.html",
      "cloud-map/latest/api/API_CreatePrivateDnsNamespace.html",
      "lambda/latest/dg/configuration-vpc.html",
      "bedrock/latest/userguide/api-keys.html",
      "bedrock/latest/userguide/inference-chat-completions-mantle.html",
      "bedrock/latest/userguide/tagging.html",
      "bedrock/latest/userguide/workspaces.html",
      "service-authorization/latest/reference/list_bedrock-mantle.html",
    ];
    for (const citation of citations) {
      expect(authoritativeDocs).toContain(
        `https://docs.aws.amazon.com/${citation}`,
      );
    }

    expect(text.architecture).toContain(
      "Empirical source observation, rechecked 2026-07-24",
    );
    expect(text.architecture).toContain(
      "Repository deployment observation, empirical 2026-07-12",
    );
    expect(text.facts).toContain(
      "source-level observations are **empirical",
    );
    expect(text.facts).toContain(
      "**Empirical deployment observation, 2026-07-12:**",
    );
  });

  it("TC-DOCS-009: documents the optional production facade domain boundary", () => {
    for (const source of [text.readme, text.architecture]) {
      expect(source).toContain("MEM9_FACADE_CUSTOM_DOMAIN");
      expect(source).toMatch(/existing public Route 53\s+hosted zone/i);
      expect(source).toMatch(/Preview stages never/i);
    }
    expect(text.facts).toContain(
      "optional ACM certificate and existing-zone records for the public OAuth facade",
    );
  });
});
