---
title: "Function Signatures Knowledge Schema"
type: knowledge_schema
confidence: high
grounded_by:
  - src/cag/knowledge/function_signatures.json
  - src/cag/knowledge_cache.py
  - src/ghidra_mcp_client.py
policy: agent-editable
last_validated: 2026-10-12
status: active
owners: team-reverse-engineering
code_refs: src/cag/knowledge/function_signatures.json | src/cag/knowledge_cache.py | src/ghidra_mcp_client.py
stability: experimental
last_verified: 2026-10-12
tags: [knowledge-base, function-signatures, schema]
---

# Function Signatures Knowledge Schema

This file is a keyed catalog of Ghidra-facing functions. It is configuration and prompt metadata, not an executable API specification. The outer object must contain `function_signatures`; each entry is keyed by the function name.
<!-- GROUND_TRUTH: src/cag/knowledge/function_signatures.json §function_signatures -->

## Shape

```json
{
  "function_signatures": {
    "function_name": {
      "name": "function_name",
      "description": "What the operation does and returns.",
      "parameters": {
        "parameter_name": "Human-readable parameter guidance"
      },
      "return_type": "string",
      "common_locations": ["Analysis context"],
      "related_functions": ["related_function_name"]
    }
  }
}
```

The repository example contains these record fields:

- `name`: display and signature name. The loader actually uses the map key as the dataclass `name`, so keep the key and value consistent.
- `description`: natural-language behavior and usage guidance.
- `parameters`: an object mapping parameter names to descriptive strings; it is not a typed JSON parameter schema.
- `return_type`: display text such as `string` or `string[]`.
- `common_locations`: analysis contexts where the function is useful.
- `related_functions`: names of nearby or alternative operations.

`token_count` is an optional cache field. During preload, missing fields receive defaults and a missing `token_count` is estimated. The checked-in source file does not currently use it.
<!-- GROUND_TRUTH: src/cag/knowledge_cache.py §FunctionSignature and §GhidraKnowledgeCache.preload -->

## Runtime Flow

`GhidraKnowledgeCache.preload()` reads JSON files from `src/cag/knowledge/`, selects the `function_signatures` top-level key, and converts each record into a `FunctionSignature` dataclass. It supports exact and partial lookup, formats records into prompt text, and includes matching records in token-limited retrieval. There is no JSON Schema validation step; malformed types can fail later or produce unsuitable prompt content.
<!-- GROUND_TRUTH: src/cag/knowledge_cache.py §76-155, §157-186, §239-337 -->

The CAG directory initializer copies the default source files into the project-level `ghidra_knowledge_cache/` directory only when the destination does not already exist. `GhidraMCPClient` reads the cached copy, not this source path, so changing the source file does not overwrite an existing cache automatically.
<!-- GROUND_TRUTH: src/cag/init_dirs.py §21-41 -->
<!-- GROUND_TRUTH: src/ghidra_mcp_client.py §34-49 -->

## Extension Procedure

1. Add a new entry under `function_signatures` using the exact callable name exposed to the client.
2. Describe every accepted argument in `parameters`, including address-format requirements where relevant.
3. Use a concise return-type label and link related operations by their catalog names.
4. Validate that the JSON parses and run the CAG directory initialization or refresh the cache deliberately; an existing cache file is preserved by initialization.
5. Verify the operation is implemented by the client or server. This catalog alone does not create an endpoint.

For example, `rename_function_by_address` documents that the address must be numerical and exposes `function_address` and `new_name`; this is operational guidance consumed by humans or prompts, not an enforced type constraint.
<!-- GROUND_TRUTH: src/cag/knowledge/function_signatures.json §rename_function_by_address -->

## Limitations

- Requiredness, primitive types, enum values, and parameter validation are not formally declared.
- The preload path uses `.get()` defaults, while `load_from_disk()` reconstructs `FunctionSignature(**info)` and can reject missing or unexpected dataclass fields.
- The catalog can drift from the actual MCP implementation; callers should treat source/client behavior as authoritative.
