import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  INTERNAL_AUTH_FIELD,
  canonicalJson,
  classifyAccessToken,
  createInternalContext,
  createTransportEnvelope,
  deriveClientKey,
  deriveGroupKey,
  derivePrincipalKey,
  parseClientRegistry,
  parseSigningKeys,
  verifyInternalContext,
  verifyTransportEnvelope,
} from "./namespace-auth.mjs";

const ISSUER = "https://cognito-idp.example.invalid/pool";
const HUMAN_CLIENT = "reader-client";
const M2M_CLIENT = "m2m-client";
const SIGNING_KEYS = {
  current: Buffer.alloc(32, 1).toString("base64url"),
  previous: Buffer.alloc(32, 2).toString("base64url"),
};
const TRANSPORT_SLOT_A = Buffer.alloc(32, 3).toString("base64url");
const TRANSPORT_SLOT_B = Buffer.alloc(32, 4).toString("base64url");
const TRANSPORT_KEYS = {
  active: "a",
  a: TRANSPORT_SLOT_A,
  b: TRANSPORT_SLOT_B,
};

function jwt(claims) {
  const encode = (value) =>
    Buffer.from(JSON.stringify(value)).toString("base64url");
  return `${encode({ alg: "RS256" })}.${encode(claims)}.signature`;
}

describe("namespace identity derivation", () => {
  it("TC-GROUPNS-014: rejects duplicate client classification", () => {
    expect(() =>
      parseClientRegistry(
        JSON.stringify({
          human: [HUMAN_CLIENT],
          m2m: [HUMAN_CLIENT],
        }),
      ),
    ).toThrow(/both human and m2m/u);
  });

  it("TC-GROUPNS-011/012/015/017: classifies access tokens from the registry", () => {
    const registry = parseClientRegistry(
      JSON.stringify({
        human: [HUMAN_CLIENT],
        m2m: [M2M_CLIENT],
      }),
    );
    const human = classifyAccessToken(
      jwt({
        iss: ISSUER,
        sub: "human-subject",
        client_id: HUMAN_CLIENT,
        token_use: "access",
        scope: "mem9-mcp/read",
        "cognito:groups": ["mem9-team-a"],
      }),
      registry,
    );
    expect(human).toMatchObject({
      issuer: ISSUER,
      clientId: HUMAN_CLIENT,
      principalType: "human",
      subject: "human-subject",
      groups: ["mem9-team-a"],
    });

    const m2m = classifyAccessToken(
      jwt({
        iss: ISSUER,
        sub: "machine-token-subject",
        client_id: M2M_CLIENT,
        token_use: "access",
        scope: "mem9-mcp/read",
      }),
      registry,
    );
    expect(m2m).toMatchObject({
      principalType: "m2m",
      subject: M2M_CLIENT,
      groups: [],
    });
    expect(
      derivePrincipalKey(m2m.issuer, m2m.principalType, m2m.subject),
    ).toBe(derivePrincipalKey(ISSUER, "m2m", M2M_CLIENT));
    expect(
      derivePrincipalKey(m2m.issuer, m2m.principalType, m2m.subject),
    ).not.toBe(derivePrincipalKey(ISSUER, "m2m", "machine-token-subject"));

    expect(() =>
      classifyAccessToken(
        jwt({
          iss: ISSUER,
          client_id: HUMAN_CLIENT,
          token_use: "access",
        }),
        registry,
      ),
    ).toThrow(/human access token requires sub/u);
    expect(() =>
      classifyAccessToken(
        jwt({
          iss: ISSUER,
          sub: "human-subject",
          client_id: HUMAN_CLIENT,
          token_use: "id",
        }),
        registry,
      ),
    ).toThrow(/token_use must be access/u);
  });

  it("TC-GROUPNS-018/019/115: bounds and preserves exact Cognito groups", () => {
    const registry = parseClientRegistry(
      JSON.stringify({ human: [HUMAN_CLIENT], m2m: [M2M_CLIENT] }),
    );
    const groups = Array.from({ length: 32 }, (_, index) => `group-${index}`);
    expect(
      classifyAccessToken(
        jwt({
          iss: ISSUER,
          sub: "human-subject",
          client_id: HUMAN_CLIENT,
          token_use: "access",
          "cognito:groups": groups,
        }),
        registry,
      ).groups,
    ).toEqual(groups);
    expect(() =>
      classifyAccessToken(
        jwt({
          iss: ISSUER,
          sub: "human-subject",
          client_id: HUMAN_CLIENT,
          token_use: "access",
          "cognito:groups": [...groups, "overflow"],
        }),
        registry,
      ),
    ).toThrow(/at most 32/u);
    expect(() =>
      classifyAccessToken(
        jwt({
          iss: ISSUER,
          sub: "human-subject",
          client_id: HUMAN_CLIENT,
          token_use: "access",
          "cognito:groups": "not-an-array",
        }),
        registry,
      ),
    ).toThrow(/array of strings/u);
  });

  it("TC-GROUPNS-021/022/023/024: produces domain-separated stable keys", () => {
    expect(
      derivePrincipalKey(ISSUER, "human", "subject-a"),
    ).toBe(derivePrincipalKey(ISSUER, "human", "subject-a"));
    expect(derivePrincipalKey(ISSUER, "human", "subject-a")).not.toBe(
      derivePrincipalKey(ISSUER, "m2m", "subject-a"),
    );
    expect(deriveGroupKey(ISSUER, "Team-A")).not.toBe(
      deriveGroupKey(ISSUER, "team-a"),
    );
    expect(deriveGroupKey(ISSUER, "Team-A")).not.toBe(
      deriveGroupKey(`${ISSUER}-other`, "Team-A"),
    );
    expect(deriveClientKey(ISSUER, HUMAN_CLIENT)).toMatch(/^[0-9a-f]{64}$/u);
  });
});

describe("canonical signed contexts", () => {
  it("TC-GROUPNS-116: canonicalizes nested JSON and rejects non-finite values", () => {
    expect(
      canonicalJson({ z: 1, nested: { b: true, a: ["x", null] } }),
    ).toBe('{"nested":{"a":["x",null],"b":true},"z":1}');
    expect(() => canonicalJson({ value: Number.NaN })).toThrow(
      /finite number/u,
    );
  });

  it("TC-GROUPNS-027/029/030/031/032/033: signs and verifies a request-bound context", () => {
    const keys = parseSigningKeys(JSON.stringify(SIGNING_KEYS));
    const invocation = {
      tool: "search_memories",
      arguments: {
        q: "arm64",
        nested: { b: 2, a: 1 },
        [INTERNAL_AUTH_FIELD]: { attacker: true },
      },
    };
    const now = 1_787_875_200;
    const context = createInternalContext({
      invocation,
      identity: {
        issuer: ISSUER,
        principalType: "human",
        subject: "human-subject",
        clientId: HUMAN_CLIENT,
        groups: ["team-b", "team-a"],
      },
      keys,
      now,
    });
    expect(context.group_keys).toEqual(
      ["team-a", "team-b"]
        .map((group) => deriveGroupKey(ISSUER, group))
        .sort(),
    );
    expect(context).not.toHaveProperty("subject");
    expect(context).not.toHaveProperty("groups");
    expect(
      verifyInternalContext({
        context,
        invocation,
        keys,
        now: now + 5,
      }),
    ).toMatchObject({
      tool: "search_memories",
      principal_type: "human",
    });

    for (const mutate of [
      (copy) => {
        copy.tool = "add_memory";
      },
      (copy) => {
        copy.principal_key = "0".repeat(64);
      },
      (copy) => {
        copy.group_keys = [...copy.group_keys].reverse();
      },
      (copy) => {
        copy.kid = "unknown";
      },
    ]) {
      const copy = structuredClone(context);
      mutate(copy);
      expect(() =>
        verifyInternalContext({
          context: copy,
          invocation,
          keys,
          now: now + 5,
        }),
      ).toThrow();
    }
    expect(() =>
      verifyInternalContext({
        context,
        invocation,
        keys,
        now: now + 31,
      }),
    ).toThrow(/expired/u);
  });

  it("TC-GROUPNS-034/126: creates a separately signed target transport envelope", () => {
    const keys = parseSigningKeys(JSON.stringify(TRANSPORT_KEYS));
    const now = 1_787_875_200;
    const body = JSON.stringify({ content: "team fact" });
    const envelope = createTransportEnvelope({
      issuer: "gateway-target",
      method: "POST",
      path: "/v1alpha2/mem9s/memories",
      body,
      identity: {
        principal_key: "a".repeat(64),
        principal_type: "human",
        client_key: "b".repeat(64),
        group_keys: ["c".repeat(64)],
      },
      keys,
      now,
    });
    expect(envelope).not.toContain("team fact");
    expect(
      verifyTransportEnvelope({
        envelope,
        issuer: "gateway-target",
        method: "POST",
        path: "/v1alpha2/mem9s/memories",
        body,
        keys,
        now: now + 5,
      }),
    ).toMatchObject({
      principal_key: "a".repeat(64),
      principal_type: "human",
    });
    expect(() =>
      verifyTransportEnvelope({
        envelope,
        issuer: "gateway-target",
        method: "POST",
        path: "/v1alpha2/mem9s/memories",
        body: JSON.stringify({ content: "changed" }),
        keys,
        now: now + 5,
      }),
    ).toThrow(/body hash/u);

    const encoded = envelope.split(".")[0];
    const decoded = JSON.parse(Buffer.from(encoded, "base64url").toString());
    expect(decoded.body_hash).toBe(
      createHash("sha256").update(body).digest("hex"),
    );
    expect(decoded.kid).toBe("a");
  });

  it("TC-GROUPNS-133: stable slot IDs preserve both rolling-deploy overlap windows", () => {
    const slotB2 = Buffer.alloc(32, 5).toString("base64url");
    const identity = {
      principal_key: "a".repeat(64),
      principal_type: "m2m",
      client_key: "b".repeat(64),
      group_keys: [],
    };
    const request = {
      issuer: "gateway-target",
      method: "GET",
      path: "/v1alpha2/mem9s/memories?q=rotation",
      identity,
      now: 1_787_875_200,
    };

    const initialVerifier = parseSigningKeys(
      JSON.stringify(TRANSPORT_KEYS),
    );
    const preparedSigner = parseSigningKeys(
      JSON.stringify({
        active: "a",
        a: TRANSPORT_SLOT_A,
        b: slotB2,
      }),
    );
    const preparedEnvelope = createTransportEnvelope({
      ...request,
      keys: preparedSigner,
    });
    expect(
      verifyTransportEnvelope({
        ...request,
        envelope: preparedEnvelope,
        keys: initialVerifier,
      }).kid,
    ).toBe("a");

    const preparedVerifier = parseSigningKeys(
      JSON.stringify({
        active: "a",
        a: TRANSPORT_SLOT_A,
        b: slotB2,
      }),
    );
    const activatedSigner = parseSigningKeys(
      JSON.stringify({
        active: "b",
        a: TRANSPORT_SLOT_A,
        b: slotB2,
      }),
    );
    const activatedEnvelope = createTransportEnvelope({
      ...request,
      keys: activatedSigner,
    });
    expect(
      verifyTransportEnvelope({
        ...request,
        envelope: activatedEnvelope,
        keys: preparedVerifier,
      }).kid,
    ).toBe("b");

    for (const invalid of [
      { active: "current", a: TRANSPORT_SLOT_A, b: TRANSPORT_SLOT_B },
      { active: "a", a: TRANSPORT_SLOT_A },
    ]) {
      expect(() => parseSigningKeys(JSON.stringify(invalid))).toThrow();
    }
  });
});
