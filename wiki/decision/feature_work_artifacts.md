---
title: "Decision: Feature Work Artifacts"
type: decision
confidence: medium
status: accepted
decided_on: 2026-10-12
grounded_by: []
policy: human-review-required
last_validated: 2026-10-12
owners: team-reverse-engineering
code_refs: AGENTS.md | wiki/concept/llm_assisted_feature_workflow.md
stability: stable
last_verified: 2026-10-12
tags: [workflow, llm, process]
---

# Decision: Feature Work Artifacts

## Context

Some changes benefit from lightweight written context (requirements, design, verification), especially when multiple repos, schemas, or pipelines are involved.

## Decision

Use `wiki/work/<feature-slug>/` as the standard location for LLM-assisted feature work artifacts.

## Rationale

The structure separates temporary feature context from canonical wiki pages while preserving requirements, design decisions, implementation handoff, and exact verification evidence.

## Consequences

- Feature work becomes auditable and easier to hand off.
- Durable facts should be promoted from work artifacts into canonical wiki pages after the feature stabilizes.

## Alternatives Considered

- Store all feature notes directly in canonical topic pages: rejected because incomplete or changing work would pollute durable documentation.
- Require every optional artifact for every feature: rejected because the workflow is intentionally adaptive and only `brief.md` is universally required.
