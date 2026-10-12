---
title: "Extend OGhidra Knowledge JSON"
type: workflow
confidence: high
grounded_by:
  - src/cag/knowledge_cache.py
  - src/cag/knowledge/function_signatures.json
  - src/cag/knowledge/common_workflows.json
  - wiki/knowledge_schema/knowledge-json-concept.md
policy: agent-editable
last_validated: 2026-10-12
status: active
owners: team-reverse-engineering
code_refs: src/cag/knowledge_cache.py | src/cag/knowledge/function_signatures.json | src/cag/knowledge/common_workflows.json
stability: experimental
last_verified: 2026-10-12
tags: [workflow, knowledge-base, contributing]
---

# Extend OGhidra Knowledge JSON

Use this workflow for the two checked-in knowledge catalogs: function signatures and common workflows.

## Procedure

1. Confirm that the proposed tool or behavior exists in the actual backend/client implementation.
2. Edit the relevant source file under `src/cag/knowledge/` while preserving its recognized top-level key.
3. For function metadata, keep the map key aligned with `name`, describe parameters, return text, contexts, and related functions.
4. For workflows, add a string-valued task key with exact tool and parameter names, branches, and verification steps.
5. Parse the JSON and exercise the loader/retrieval path.
6. Refresh `ghidra_knowledge_cache/` deliberately. Directory initialization does not overwrite an existing cached file.
7. Check prompts or capability output for stale entries and update dependent documentation.
<!-- GROUND_TRUTH: src/cag/knowledge_cache.py §76-155, §339-411 -->
<!-- GROUND_TRUTH: src/cag/init_dirs.py §21-41 -->

## Contract Limits

The files are convention-based prompt metadata, not executable workflows or formal JSON Schema documents. Preload applies defaults for several missing function fields, while cache reload reconstructs dataclasses. There is no automatic referential-integrity check for tool names, parameter names, or related-function references.
<!-- GROUND_TRUTH: src/cag/knowledge_cache.py §103-146, §363-411 -->

## Verification Checklist

- JSON syntax parses.
- Loader recognizes the top-level category.
- New function records format correctly in prompt output.
- New workflow keys are found by direct lookup and, if intended, by general query enrichment.
- Cached copies are updated or intentionally left unchanged.
- Capability tests confirm the referenced operation exists.
