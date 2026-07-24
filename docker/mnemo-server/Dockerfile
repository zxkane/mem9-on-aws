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
#
# `--platform=$BUILDPLATFORM` runs the Go toolchain NATIVELY on the builder host
# (fast on any runner) and cross-compiles to the target arch via GOARCH — instead
# of running the whole compiler under QEMU emulation, which would be slow on x86
# CI runners. mem9 is pure Go (CGO off), so cross-compiling is a plain GOARCH
# switch, no emulation needed. BUILDPLATFORM/TARGETARCH are auto-injected by
# buildx.
FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS builder

# git to fetch the pinned source; ca-certificates so `go mod download` can reach
# the module proxy over TLS.
RUN apk add --no-cache git ca-certificates

# The exact upstream commit to vendor. A full 40-char SHA (not a branch/tag) so
# the build is reproducible and can never drift under us.
ARG MEM9_REF=d4638c8458abeb209a1b3a20472a1328c4acd149
# Target arch for the static binary, auto-injected by buildx from --platform
# (linux/arm64 → arm64). Defaulted so a plain `docker build` still works.
ARG TARGETARCH=arm64

WORKDIR /src
# Shallow-fetch just the pinned commit (no full history) to keep the build fast.
RUN git init -q . \
    && git remote add origin https://github.com/mem9-ai/mem9.git \
    && git fetch -q --depth 1 origin "${MEM9_REF}" \
    && git checkout -q FETCH_HEAD

# Local patches on top of the pin (docs/designs/recall-min-confidence.md).
# `git apply` hard-fails the build if a future MEM9_REF bump drifts under a
# patch — the loud failure forces a conscious re-verify instead of silently
# shipping unpatched behavior.
COPY docker/mnemo-server/patches/ /tmp/mem9-patches/
RUN git apply --verbose /tmp/mem9-patches/*.patch

# Build the server. go.mod + the whole module live under server/. GOARCH targets
# the requested arch while the compiler itself runs on the native BUILDPLATFORM.
# The handler-package tests gate the build: they cover the patched recall
# selection (TC-RECALL-001…009), and run natively on BUILDPLATFORM (no QEMU).
WORKDIR /src/server
RUN go mod download \
    && go test ./internal/handler/ ./internal/service/ ./internal/llm/ \
    && CGO_ENABLED=0 GOOS=linux GOARCH="${TARGETARCH}" \
       go build -trimpath -ldflags="-s -w" -o /out/mnemo-server ./cmd/mnemo-server

# ── runtime ──────────────────────────────────────────────────────────────────
# Matches upstream's runtime base (alpine:3.19 + ca-certificates) so behavior
# tracks what the maintainers ship; the static binary + certs are all we need.
FROM alpine:3.19

# ca-certificates: TLS to the Aurora writer endpoint. qwen3-embed and llm-proxy
# are localhost HTTP sidecars; mnemo-server does not call Bedrock directly.
# jq parses the Secrets Manager JSON ({username,password}) and URL-encodes the
# password (RDS RandomPassword can contain DSN-reserved chars: @ / : ? #) via
# jq's @uri. Both packages are small (~1-2 MB total).
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
