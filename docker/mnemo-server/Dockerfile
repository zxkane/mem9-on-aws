# mnemo-server (upstream mem9) — self-contained arm64 build.
#
# Why this exists (docs/ARCHITECTURE.md §4, docs/mem9-facts.md "Build / architecture"):
#   - mem9-ai/mem9 publishes NO release, NO tag, NO public image. Its own CI
#     pushes `<branch>-<sha7>` to the maintainers' PRIVATE ECR (a different AWS
#     account) — unusable for us. So we PIN a source commit and build our own.
#   - Upstream's shipped server/Dockerfile assumes a PRE-BUILT binary (its golang
#     builder stage is commented out; the binary is compiled on the CI host, then
#     COPYed into alpine). We restore a proper multi-stage build so CI needs only
#     Docker — no host Go toolchain, no separate mem9 checkout.
#   - mem9 is pure Go (CGO_ENABLED=0), so it cross-compiles to arm64 with zero
#     source change (GOARCH=arm64). Targets AWS Graviton Fargate (§4, arm64).
#
# Pin: mem9-ai/mem9 @ d4638c8458abeb209a1b3a20472a1328c4acd149 (main, 2026-07-10).
# Bump = change MEM9_REF below + re-verify docs/mem9-facts.md against the new tree.
# Module path is github.com/qiffang/mnemos/server; the server lives under server/.

# ── builder ──────────────────────────────────────────────────────────────────
# go.mod requires Go 1.24 (toolchain go1.24.6). Alpine builder keeps the image
# small; the binary is static (CGO off) so the runtime needs no libc from here.
FROM golang:1.24-alpine AS builder

# git to fetch the pinned source; ca-certificates so `go mod download` can reach
# the module proxy over TLS.
RUN apk add --no-cache git ca-certificates

# The exact upstream commit to vendor. A full 40-char SHA (not a branch/tag) so
# the build is reproducible and can never drift under us.
ARG MEM9_REF=d4638c8458abeb209a1b3a20472a1328c4acd149
# Target arch for the static binary. arm64 for Graviton Fargate; overridable so
# the same Dockerfile can build amd64 for a local x86 smoke test.
ARG TARGETARCH=arm64

WORKDIR /src
# Shallow-fetch just the pinned commit (no full history) to keep the build fast.
RUN git init -q . \
    && git remote add origin https://github.com/mem9-ai/mem9.git \
    && git fetch -q --depth 1 origin "${MEM9_REF}" \
    && git checkout -q FETCH_HEAD

# Build the server. go.mod + the whole module live under server/.
WORKDIR /src/server
RUN go mod download \
    && CGO_ENABLED=0 GOOS=linux GOARCH="${TARGETARCH}" \
       go build -trimpath -ldflags="-s -w" -o /out/mnemo-server ./cmd/mnemo-server

# ── runtime ──────────────────────────────────────────────────────────────────
# Matches upstream's runtime base (alpine:3.19 + ca-certificates) so behavior
# tracks what the maintainers ship; the static binary + certs are all we need.
FROM alpine:3.19

# ca-certificates: TLS to RDS Proxy / Bedrock / embed. jq: the entrypoint parses
# the Secrets Manager JSON ({username,password}) and URL-encodes the password
# (RDS RandomPassword can contain DSN-reserved chars: @ / : ? #) via jq's @uri —
# far more robust than hand-rolled sed/awk. Both are small (~1-2 MB total).
RUN apk add --no-cache ca-certificates jq

COPY --from=builder /out/mnemo-server /usr/local/bin/mnemo-server
# entrypoint assembles MNEMO_DSN from the ECS-injected DB env + secret, then
# execs the server (mem9 reads a single static MNEMO_DSN and can't compose it
# from parts — see docs/mem9-facts.md "DB connection mechanism").
COPY docker/mnemo-server/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# mnemo-server listens on MNEMO_PORT (default 8080). No secrets baked in — all
# config arrives as env vars / ECS secrets at task start.
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
