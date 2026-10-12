---
title: "Decision: Feature Work Artifacts"
type: decision
confidence: medium
status: accepted
decided_on: 2026-10-12
grounded_by: []
policy: human-review-required
last_validated: 2026-10-12
tags: [workflow, llm, process]
---

# Decision: Feature Work Artifacts

## Context

Some changes benefit from lightweight written context (requirements, design, verification), especially when multiple repos, schemas, or pipelines are involved.

## Decision

Use `wiki/work/<feature-slug>/` as the standard location for LLM-assisted feature work artifacts.

## Consequences

- Feature work becomes auditable and easier to hand off.
- Durable facts should be promoted from work artifacts into canonical wiki pages after the feature stabilizes.
