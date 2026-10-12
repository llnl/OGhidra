---
title: "Knowledge JSON Concept"
type: knowledge_schema
confidence: high
grounded_by:
  - src/cag/knowledge_cache.py
  - src/cag/knowledge/function_signatures.json
  - src/cag/knowledge/common_workflows.json
policy: agent-editable
last_validated: 2026-10-12
status: active
owners: team-reverse-engineering
code_refs: src/cag/knowledge_cache.py | src/cag/knowledge/function_signatures.json | src/cag/knowledge/common_workflows.json
stability: experimental
last_verified: 2026-10-12
tags: [knowledge-base, json, schema, cag, ghidra, llm-orchestration]
---

# Knowledge JSON Concept

OGhidra's knowledge JSON is a family of small, convention-based catalogs used by Cache-Augmented Generation. The files keep domain guidance separate from orchestration code and provide prompt material for Ghidra analysis. The current maintained source set contains function metadata and common workflow instructions; the cache class also has slots for binary patterns and analysis rules.
<!-- GROUND_TRUTH: src/cag/knowledge_cache.py §17-51 -->

## Contract

Each file is a JSON object whose recognized top-level key identifies the knowledge category. Category values are generally dictionaries keyed by a stable name. The loader maps recognized categories to Python dataclasses or dictionaries, then retrieval formats selected records into text. This means the effective schema is the combination of JSON shape, loader assumptions, and retrieval logic, rather than a standalone schema document.
<!-- GROUND_TRUTH: src/cag/knowledge_cache.py §76-155 -->

The two implemented source formats are documented in [[wiki/knowledge_schema/function-signatures-json]] and [[wiki/knowledge_schema/common-workflows-json]].

## Data Flow

1. Source files live under `src/cag/knowledge/`.
2. `GhidraKnowledgeCache.preload()` reads recognized files and merges their categories into memory.
3. CAG retrieval selects function records, one task workflow, and possibly binary patterns within a rough token limit.
4. The selected text is appended to the enhanced LLM prompt.
5. `init_dirs.py` can copy defaults to `ghidra_knowledge_cache/`; that project-level cache is also read by `GhidraMCPClient` for function metadata.
<!-- GROUND_TRUTH: src/cag/knowledge_cache.py §239-295 -->
<!-- GROUND_TRUTH: src/cag/manager.py §130-165 -->
<!-- GROUND_TRUTH: src/cag/init_dirs.py §21-41 -->
<!-- GROUND_TRUTH: src/ghidra_mcp_client.py §34-49 -->

## Schema Discipline

Treat the JSON as an API between knowledge authors, the loader, and prompt retrieval:

- Preserve recognized top-level keys.
- Keep dictionary keys stable and consistent with embedded names.
- Use exact tool and parameter names from the implementation.
- Prefer explicit, verifiable guidance over claims that the loader cannot enforce.
- Refresh or replace stale generated cache files intentionally after source changes.
- Test both parsing and retrieval; JSON syntax alone does not detect semantic drift.

There is currently no formal JSON Schema, automatic type validation, or referential-integrity test for these files. Preload is permissive for several missing fields, whereas cache reload uses dataclass constructors and can be stricter. This behavior should be considered when extending the format.
<!-- GROUND_TRUTH: src/cag/knowledge_cache.py §103-146, §363-411 -->
