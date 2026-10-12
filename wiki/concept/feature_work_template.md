---
title: "Concept: Feature Work Template"
type: concept
confidence: medium
grounded_by: []
policy: agent-editable
last_validated: 2026-10-12
status: active
owners: team-reverse-engineering
code_refs: AGENTS.md | wiki/concept/llm_assisted_feature_workflow.md
stability: stable
last_verified: 2026-10-12
tags: [workflow, llm, template]
---

# Concept: Feature Work Template

Feature work lives under `wiki/work/<feature-slug>/`.

Required artifact:
- `brief.md`

Optional artifacts (create only when useful):
- `references.md`
- `design.md`
- `implementation_plan.md`
- `verification.md`
- `spike.md`
- `dev_handoff.md`
- `interview.md`
- `index.md` for long-running research threads

`dev_handoff.md` carries `Status: Draft | Approved` and `Architect Approval:`
fields. `verification.md` records exact commands, full output, deviations from
the handoff, known gaps, and follow-ups.
