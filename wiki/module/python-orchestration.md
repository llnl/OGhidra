---
title: "Python Orchestration Layer"
type: module
confidence: high
grounded_by:
  - main.py
  - src/bridge.py
  - src/command_parser.py
  - src/context_manager.py
  - src/execution_gate.py
  - src/cag/manager.py
policy: agent-editable
last_validated: 2026-10-12
status: active
owners: team-reverse-engineering
code_refs: main.py | src/bridge.py | src/command_parser.py | src/context_manager.py | src/execution_gate.py | src/cag/manager.py
stability: experimental
last_verified: 2026-10-12
tags: [python, orchestration, mcp]
---

# Python Orchestration Layer

The Python layer owns provider selection, backend selection, prompt construction, command extraction, tool dispatch, execution-loop control, session state, and UI-facing status. `Bridge` is the central coordinator; `main.py` is the process entry point.
<!-- GROUND_TRUTH: main.py §12-18 -->
<!-- GROUND_TRUTH: src/bridge.py §80-298 -->

## Responsibilities

| Area | Primary implementation | Responsibility |
|---|---|---|
| Startup and modes | `main.py` | Load environment, create configuration, run GUI or interactive CLI |
| Provider/backend selection | `src/bridge.py`, `src/config.py` | Select LLM provider and HTTP or PyGhidra backend |
| Tool protocol | `src/command_parser.py` | Parse `EXECUTE:` output, aliases, required parameters, and duplicate calls |
| Prompt/context handling | `src/context_manager.py`, `src/cag/manager.py` | Compact results and inject knowledge/session context |
| Execution safety | `src/execution_gate.py` | Pause on artifacts, repeated calls, and optionally high-risk tools |
| Persistent memory | `src/memory_manager.py`, `src/session_store.py` | Store sessions and optional embeddings |
| Analysis state | `src/models/memory.py`, `src/function_graph.py` | Track functions, tool calls, findings, preferences, and relationships |

## Loop Model

The configuration distinguishes an inner execution loop, which limits tool executions per investigation, from an outer agentic loop, which limits planning/execution/analysis cycles. Results may be reviewed and used for replanning. The exact loop behavior is implemented in `Bridge`; configuration values are validated by Pydantic models.
<!-- GROUND_TRUTH: src/config.py §46-70 -->
<!-- GROUND_TRUTH: src/bridge.py §229-248 -->

## Extension Boundary

To add a backend-neutral tool, update the abstract client contract and each concrete backend, then update command validation/capabilities and tests. Adding only a knowledge entry or only a markdown capability description does not create an executable tool.
<!-- GROUND_TRUTH: src/ghidra_client.py §186-295 -->
<!-- GROUND_TRUTH: src/command_parser.py §30-86 -->
<!-- GROUND_TRUTH: tests/test_tool_calls.py §22-68 -->

## Verification

Use `tests/test_tool_calls.py` for live GhidraMCP capability checks and the focused unit tests for parser, context, execution-gate, and bridge behavior. Tests that call the HTTP backend require a running Ghidra server; the repository does not provide a universal mock path.
<!-- GROUND_TRUTH: tests/README.md §15-32 -->
