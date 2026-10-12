---
title: "OGhidra End-to-End Data Flow"
type: architecture
confidence: high
grounded_by:
  - README.md
  - main.py
  - src/bridge.py
  - src/command_parser.py
  - src/ghidra_client.py
  - src/cag/manager.py
policy: agent-editable
last_validated: 2026-10-12
status: active
owners: team-reverse-engineering
code_refs: main.py | src/bridge.py | src/command_parser.py | src/ghidra_client.py | src/cag/manager.py
stability: experimental
last_verified: 2026-10-12
tags: [architecture, data-flow, mcp, llm-orchestration]
---

# OGhidra End-to-End Data Flow

OGhidra accepts a user query, enriches it with session and retrieved context, asks an LLM to plan or analyze, extracts `EXECUTE:` commands, and dispatches them through a selected Ghidra backend. Results return through the same bridge and are retained in structured session state.
<!-- GROUND_TRUTH: README.md §How It Works -->

## Runtime Path

1. `main.py` loads `.env`, builds configuration, constructs `Bridge`, and exposes GUI or interactive CLI entry points.
2. `Bridge` selects an LLM provider (`ollama`, `external`, or `custom_api`) and a Ghidra backend (`http` or `pyghidra`).
3. The bridge maintains `SessionMemory`, context management, CAG/memory services, an execution gate, coverage tracking, and lead tracking.
4. The LLM response is parsed by `CommandParser`. The canonical command form is `EXECUTE: tool_name(param=value)`; required parameters and aliases are checked before dispatch.
5. The selected `AbstractGhidraClient` implementation executes the operation. The HTTP implementation calls the GhidraMCP API; the PyGhidra implementation operates on an in-process Ghidra `Program`.
6. Tool results are recorded, compacted or cached when configured, scanned for critical artifacts, and added to subsequent prompts.
7. The bridge returns an analysis response or pauses for user review when an execution gate fires.
<!-- GROUND_TRUTH: main.py §12-18, §44-123 -->
<!-- GROUND_TRUTH: src/bridge.py §80-198 -->
<!-- GROUND_TRUTH: src/command_parser.py §13-245 -->
<!-- GROUND_TRUTH: src/ghidra_client.py §21-70 -->

## Backend Boundary

The abstract client defines a common tool surface. The HTTP backend communicates with the GhidraMCP server over HTTP, while the PyGhidra backend initializes the JVM and holds project/program resources directly. This boundary lets orchestration and command parsing remain backend-neutral, but backend behavior still depends on Ghidra version and environment setup.
<!-- GROUND_TRUTH: src/ghidra_client.py §21-30, §1322-1356 -->

## Context Boundaries

- Static knowledge is retrieved through CAG and may include function metadata, workflows, malware-pattern alerts, and vector-search documents.
- Session context contains messages, tool executions, analysis state, user preferences, and saved knowledge artifacts.
- Context management can summarize, cache, tier, and truncate tool results before prompt assembly.
- LLM interaction logging can persist prompts, responses, token counts, and timing, so logs may contain sensitive binary-analysis data.
<!-- GROUND_TRUTH: src/cag/manager.py §80-188 -->
<!-- GROUND_TRUTH: src/models/memory.py §338-549 -->
<!-- GROUND_TRUTH: docs/llm-logging.md §72-101 -->

## Failure Modes

- Missing or unhealthy Ollama, external API, GhidraMCP, or PyGhidra dependencies prevent parts of the path from operating.
- Incorrect command syntax or missing required parameters is logged and may still reach bridge-level error handling.
- Large results can be summarized, cached, truncated, or omitted based on context budgets.
- Execution gates can pause before destructive tools, on repeated calls, or after security indicators are detected.
- A successful semantic response is not proof that the underlying binary interpretation is correct.
