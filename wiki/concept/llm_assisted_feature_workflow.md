---
title: "Concept: LLM-Assisted Feature Workflow"
type: concept
confidence: medium
grounded_by: []
policy: agent-editable
last_validated: 2026-10-12
tags: [workflow, llm, requirements, design, testing]
---

# Concept: LLM-Assisted Feature Workflow

## Purpose

The LLM-assisted feature workflow is a lightweight process for moving from an idea to implemented, tested code while preserving useful context in the wiki.

## Workflow Stages

| Stage | Purpose | Typical Artifact |
| --- | --- | --- |
| Interview | Ground in existing context, ask adaptive questions, and confirm playback | `interview.md` (optional) |
| Define functionality | Problem, goals, non-goals, behavior, acceptance criteria, test ideas | `brief.md` |
| Gather context | Repo references, specs, related pages, libraries, prior decisions | `references.md` |
| Design | Proposed approach, alternatives, risks, edge cases | `design.md` |
| Spike | Small proof-of-concept when uncertainty is high | `spike.md` |
| Plan implementation | Steps + verification checklist | `implementation_plan.md` |
| Hand off | Give a fresh developer approved, self-contained context | `dev_handoff.md` |
| Implement and verify | Code changes + exact commands, full output, and deviations | `verification.md` |
| Close out | Promote durable facts into canonical wiki pages + log follow-ups | update `wiki/log.md` |

## Invocation

Use this phrase to start a new feature skeleton:

```text
Start a new feature using the LLM-assisted feature workflow: <feature name>
```

Only `brief.md` is universally required. Create other artifacts when they add
value. Feature work is scaffolding; promote durable facts into canonical wiki
pages after implementation stabilizes. Long-running research threads may use an
`index.md` with dated snapshots instead of the bounded feature lifecycle.
