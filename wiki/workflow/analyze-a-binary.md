---
title: "Analyze a Binary with OGhidra"
type: workflow
confidence: high
grounded_by:
  - README.md
  - src/cag/workplans/progressive_analysis.md
  - src/cag/workplans/malware_analysis_triage.md
  - src/cag/workplans/knowledge_capture.md
  - src/ghidra_client.py
policy: agent-editable
last_validated: 2026-10-12
status: active
owners: team-reverse-engineering
code_refs: README.md | src/cag/workplans/progressive_analysis.md | src/cag/workplans/malware_analysis_triage.md | src/ghidra_client.py
stability: experimental
last_verified: 2026-10-12
tags: [workflow, binary-analysis, reverse-engineering]
---

# Analyze a Binary with OGhidra

This workflow is a staged static-analysis procedure. Keep conclusions tied to tool output and treat pattern matches as leads, not verdicts.

## Setup

1. Choose the HTTP GhidraMCP or PyGhidra backend.
2. For HTTP, open the binary in Ghidra CodeBrowser, enable the plugin, and verify `/methods` or `health_check`.
3. For PyGhidra, provide either a project and program or a binary path; the backend opens the project/program in-process.
4. Start OGhidra in GUI or interactive mode and verify the configured LLM and Ghidra backends.
<!-- GROUND_TRUTH: README.md §49-181, §314-388 -->
<!-- GROUND_TRUTH: src/config.py §1363-1419 -->

## Progressive Analysis

1. Establish the program overview with current program information, imports, exports, strings, and segments.
2. Identify entry-point candidates such as `main`, `_start`, `WinMain`, or `DllMain`.
3. Decompile the entry point and trace initialization and major call paths.
4. Select high-value functions using imports, strings, names, xrefs, and call relationships.
5. Use `analyze_function` for a focused function plus called-function context.
6. Rename only after behavior is supported by code and surrounding context.
7. Record findings, confidence, addresses, unresolved gaps, and next steps.
<!-- GROUND_TRUTH: src/cag/workplans/progressive_analysis.md §5-40, §41-76, §116-155 -->
<!-- GROUND_TRUTH: src/cag/workplans/knowledge_capture.md §5-83 -->

## Malware Triage Variant

For suspicious binaries, prioritize imports/exports, strings, candidate network or injection functions, and comprehensive function analysis. Review the resulting code manually; OGhidra's malware-pattern and execution-gate systems flag indicators but do not establish malicious intent.
<!-- GROUND_TRUTH: src/cag/workplans/malware_analysis_triage.md §5-60 -->
<!-- GROUND_TRUTH: src/cag/malware_patterns.py §4-62 -->

## Failure Modes

- Stripped or obfuscated binaries may not preserve source names, so name-based lookup and source mapping can fail.
- Dynamic imports and encrypted strings require behavioral and cross-reference analysis beyond simple lists.
- Large listings are paginated and may be truncated by context management; use offsets and targeted filters.
- A matched API, string, or heuristic pattern is evidence to investigate, not a classification.
