# Design: durable-facts-only ingest extraction (issue #25)

## Problem

Transient session observations can dilute long-lived memory. Illustrative
examples include a tool finishing a request or a temporary connection opening.
Extraction should prefer durable decisions, gotchas, and preferences over
short-lived execution status. Operator memory contents and recall comparisons
belong in private records.

Root cause: the upstream extraction prompt (`server/internal/service/ingest.go`,
rules 12-14) is tuned for personal-assistant activity logging ("prefer a
faithful fact over an empty array", "current status should usually become one
fact"). The durable-only mode targets shared, long-lived cross-agent memory.

## Decision

Add a **prompt-level durability override**, gated by a single env var
(`MNEMO_INGEST_DURABLE_ONLY`). When enabled it appends a section after the
base rules that:

- Requires each fact to be **true and useful in future sessions** (decisions +
  rationale, stable preferences, environment/config facts, costly gotchas)
- Explicitly **rejects** session-state observations, in-session progress,
  transient identifiers (session ids, CI run numbers, checkpoint SHAs)
- **Overrides** rules 12-14 (those push toward extraction; ours push toward
  omission) — an empty facts array is correct for a routine work session
- Provides generic durability criteria and synthetic examples for verification

This is a `server/internal/service/ingest_config.go` + a 2-line wire into
`ingest.go`; the patch applies on top of `0001-recall-*.patch`. Defaults = off,
so no env = upstream behavior; `MNEMO_INGEST_DURABLE_ONLY=1` activates.

## Scope

- The extraction prompt **only** — not the reconciliation (phase 2) prompt
  which deduplicates and updates existing memories. That layer is adequate.
- The client-side hooks (dotfiles repo) are out of scope; they feed the
  same ingest pipeline unaltered.
- Retroactive cleanup of existing noisy memories is out of scope (follow-up).

## Observability

No new log line; the existing `messages ingest timings` `facts:0` line already
surfaces sessions where nothing was extracted. A future metric (#26) on
`no facts extracted` reason=`empty_after_extraction` would measure the filter's
rejection rate.

## Rollback

Unset `MNEMO_INGEST_DURABLE_ONLY`; prompts revert to upstream behavior.
