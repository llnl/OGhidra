---
title: "MCP in OGhidra"
type: concept
confidence: high
grounded_by:
  - src/bridge_mcp_ghidra.py
  - src/ghidra_client.py
  - tests/README.md
policy: agent-editable
last_validated: 2026-10-12
status: active
owners: team-reverse-engineering
code_refs: src/bridge_mcp_ghidra.py | src/ghidra_client.py | src/command_parser.py
stability: experimental
last_verified: 2026-10-12
tags: [concept, mcp, llm-orchestration]
---

# MCP in OGhidra

MCP is an LLM-facing tool boundary around Ghidra operations. In this repository, `src/bridge_mcp_ghidra.py` defines a FastMCP server whose tools translate calls into HTTP requests to the GhidraMCP HTTP service. The main OGhidra process can also bypass that boundary through the in-process PyGhidra backend.
<!-- GROUND_TRUTH: src/bridge_mcp_ghidra.py §14-23 -->
<!-- GROUND_TRUTH: src/bridge_mcp_ghidra.py §62-334 -->
<!-- GROUND_TRUTH: src/bridge.py §64-77 -->

## Request Path

The MCP server exposes tools such as `list_methods`, `decompile_function`, `rename_function`, `list_strings`, `get_xrefs_to`, and `read_bytes`. Each wrapper uses `safe_get` or `safe_post` to call the configured Ghidra server, returning lines or text and converting transport failures into error strings.
<!-- GROUND_TRUTH: src/bridge_mcp_ghidra.py §26-59 -->

The primary bridge does not require the MCP server when configured for PyGhidra. It selects `GhidraMCPClient` for `http` and `PyGhidraClient` for `pyghidra`, while both satisfy the abstract client contract.
<!-- GROUND_TRUTH: src/bridge.py §64-77, §119-128 -->
<!-- GROUND_TRUTH: src/ghidra_client.py §21-64, §1322-1356 -->

## Command Format

The LLM-facing parser expects `EXECUTE: tool_name(param="value")`. It also recognizes aliases such as `xref_lookup` and `string_search`, validates selected required parameters, and removes exact duplicate commands. This parser is separate from MCP; it can dispatch to either backend.
<!-- GROUND_TRUTH: src/command_parser.py §18-86, §88-245 -->

## Operational Limits

HTTP requests use a short transport timeout in the MCP wrapper, while the Python HTTP client has its own configured timeout and normalization behavior. Tool descriptions and actual backend methods can drift, so capability tests and the live client contract are authoritative.
<!-- GROUND_TRUTH: src/bridge_mcp_ghidra.py §33-59 -->
<!-- GROUND_TRUTH: src/ghidra_client.py §69-125 -->
