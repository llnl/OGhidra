---
title: "Common Workflows Knowledge Schema"
type: knowledge_schema
confidence: high
grounded_by:
  - src/cag/knowledge/common_workflows.json
  - src/cag/knowledge_cache.py
policy: agent-editable
last_validated: 2026-10-12
status: active
owners: team-reverse-engineering
code_refs: src/cag/knowledge/common_workflows.json | src/cag/knowledge_cache.py
stability: experimental
last_verified: 2026-10-12
tags: [knowledge-base, schema, workflows]
---

# Common Workflows Knowledge Schema

This file maps a human-readable task key to a string containing ordered Ghidra/MCP instructions. It is a lightweight prompt knowledge format, not a structured workflow execution graph.
<!-- GROUND_TRUTH: src/cag/knowledge/common_workflows.json §common_workflows -->

## Shape

```json
{
  "common_workflows": {
    "task key": "Step-by-step instructions with tool calls"
  }
}
```

The outer key `common_workflows` is required for the loader to recognize the file. Every child key is a string task identifier and every value is a string. The current repository examples include `decompilation`, `finding functions`, `function analysis`, `function renaming`, `identifying crypto functions`, `identifying main function`, `memory layout analysis`, and `reversing an algorithm`.

Workflow text may include numbered steps, alternative branches, tool names, parameter examples, and verification advice. It is not parsed into individual steps, and there are no declared fields for inputs, outputs, dependencies, or failure states.

## Runtime Flow

During preload, `GhidraKnowledgeCache` merges the dictionary into `common_workflows`. Lookup first tries an exact task key and then a case-insensitive partial match. General retrieval checks a fixed list of task types against the query, adds at most one matching workflow, and applies a rough character-count token budget.
<!-- GROUND_TRUTH: src/cag/knowledge_cache.py §76-155, §219-237, §239-295 -->

The cache can serialize the dictionary back to `common_workflows.json`. As with function signatures, initialization copies defaults into `ghidra_knowledge_cache/` only if a cached destination is absent, so a stale cache can hide source edits.
<!-- GROUND_TRUTH: src/cag/knowledge_cache.py §339-361 -->
<!-- GROUND_TRUTH: src/cag/init_dirs.py §21-41 -->

## Extension Procedure

1. Add a concise task key under `common_workflows`.
2. Write a self-contained sequence using the exact tool names and argument names documented by the function-signature catalog.
3. Include alternatives when the starting information may be a function name, address, or current cursor selection.
4. Include a verification step for mutating actions such as renaming.
5. Parse the JSON, refresh the project cache if needed, and test retrieval with a query containing the task key.

The `decompilation` example demonstrates the intended style: it branches on function name, address, and current-function context, then names the corresponding calls.
<!-- GROUND_TRUTH: src/cag/knowledge/common_workflows.json §decompilation -->

## Limitations

- Workflow content is advisory prompt text; it does not invoke tools or enforce sequencing.
- Retrieval depends on exact task names in a hard-coded task list for general query enrichment. A newly added key may work through direct lookup but not automatic general retrieval.
- There is no schema validator or referential-integrity check for tool names and parameter names.
