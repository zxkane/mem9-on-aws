# Design: durable-facts-only ingest extraction (issue #25)

## Problem

smart-ingest stores transient session observations as long-lived memories
(e.g. "User is using mem9 MCP server with Codex", "already authenticated to
mem9 before", "Session ID is …"). These dilute recall quality and compete with
high-value memories in vector search. Over 2026-07-16→23, manually stored
`add_memory` facts (decisions, gotchas, preferences) were consistently more
useful on recall than smart-extracted ones.

Root cause: the upstream extraction prompt (`server/internal/service/ingest.go`,
rules 12-14) is tuned for personal-assistant activity logging ("prefer a
faithful fact over an empty array", "current status should usually become one
fact"). Our deployment stores SHARED, LONG-LIVED, cross-agent memory — a
fundamentally different use case.

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
- Provides concrete examples (from real prod noise) of what to keep vs reject

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
