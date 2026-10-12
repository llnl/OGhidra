---
title: "Integration with the Maintained Ghidra Plugin"
type: integration
confidence: medium
grounded_by:
  - src/bridge_mcp_ghidra.py
  - src/ghidra_client.py
  - README.md
policy: agent-editable
last_validated: 2026-10-12
status: active
owners: team-reverse-engineering
code_refs: src/bridge_mcp_ghidra.py | src/ghidra_client.py | README.md
stability: experimental
last_verified: 2026-10-12
tags: [integration, ghidra, deprecated-java]
---

# Integration with the Maintained Ghidra Plugin

The current repository supports two Ghidra integration strategies: the HTTP GhidraMCP service and the in-process PyGhidra client. The repository does not contain an `OGhidraMCP/` source directory, although the README and build script still describe building a Gradle extension there. That build path is therefore transitional/documented externally rather than the maintained Python integration surface.
<!-- GROUND_TRUTH: src/bridge.py §64-77, §119-128 -->
<!-- GROUND_TRUTH: src/ghidra_client.py §1322-1356 -->
<!-- GROUND_TRUTH: README.md §76-149 -->
<!-- GROUND_TRUTH: build_ghidra_plugin.sh §45-72 -->

## HTTP Path

The HTTP path expects a Ghidra server at the configured URL and exposes operations through `GhidraMCPClient`. The standalone FastMCP wrapper in `src/bridge_mcp_ghidra.py` translates MCP tool calls into requests to that service. This path requires the Ghidra-side service/plugin to be running.

## PyGhidra Path

The PyGhidra client starts the Ghidra JVM, opens a binary directly into a generated project or opens an existing project, selects a program, and holds resources for the client lifetime. It requires `GHIDRA_INSTALL_DIR` and the `pyghidra` package. Existing projects with multiple programs require an explicit program selection.
<!-- GROUND_TRUTH: src/ghidra_client.py §1418-1488, §1504-1584, §1660-1739 -->

## Migration Boundary

Keep orchestration against `AbstractGhidraClient` and treat the HTTP service as a backend option, not as the only architecture. Do not infer that the legacy Java/Gradle build instructions are the long-term path: the live Python code already provides the in-process alternative, while the repository's Gradle path references a directory absent from this checkout.

## Verification

- HTTP: check the Ghidra endpoint and run the live tool capability tests.
- PyGhidra: launch with `--ghidra-backend=pyghidra` plus either `--pyghidra-project`/`--pyghidra-program` or `--pyghidra-binary`.
- Confirm cleanup by closing the PyGhidra client after use.
