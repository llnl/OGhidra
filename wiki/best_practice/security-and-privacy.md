---
title: "Security and Privacy Practices"
type: best_practice
confidence: high
grounded_by:
  - docs/llm-logging.md
  - src/execution_gate.py
  - src/custom_api_client.py
  - src/config.py
  - tests/test_security_hardening_regressions.py
policy: agent-editable
last_validated: 2026-10-12
status: active
owners: team-reverse-engineering
code_refs: docs/llm-logging.md | src/execution_gate.py | src/custom_api_client.py | src/config.py
stability: experimental
last_verified: 2026-10-12
tags: [security, privacy, reverse-engineering, llm, deployment]
---

# Security and Privacy Practices

OGhidra handles potentially sensitive binaries and sends prompt context to the configured LLM provider. Security controls reduce accidental disclosure and unintended Ghidra modifications, but they do not replace network isolation, access control, or analyst review.

## Data Handling

- Treat LLM logs, session files, cached results, vectors, and generated reports as sensitive analysis artifacts.
- Review provider selection before analysis: Ollama is local by deployment, while external and custom providers can transmit prompts outside the host.
- Do not place API keys or real secrets in committed configuration; use `.env` outside version control.
- Custom API TLS verification is configurable and should remain enabled unless a documented trust setup requires otherwise.
<!-- GROUND_TRUTH: docs/llm-logging.md §72-101 -->
<!-- GROUND_TRUTH: src/config.py §1279-1301 -->

## Execution Safety

Execution gates can pause after critical indicators, on repeated non-investigation calls, and before configured high-risk tools. By default, the high-risk rename gate is disabled even though artifact and repetition gates default on; set policy explicitly for unattended or bulk operations.
<!-- GROUND_TRUTH: src/execution_gate.py §22-116 -->
<!-- GROUND_TRUTH: src/config.py §168-180 -->

## Interpretation Safety

Pattern detection uses weighted regular-expression indicators and thresholds. It can identify suspicious code patterns, but matches can be benign and absence of a match does not establish safety. Preserve the matched evidence and verify it in context.
<!-- GROUND_TRUTH: src/cag/malware_patterns.py §112-170 -->

## Verification

Security regression tests cover result-cache identifiers, custom API TLS warnings, health probes, UI error handling, authentication behavior, and environment persistence. They are regression checks, not a complete security audit.
<!-- GROUND_TRUTH: tests/test_security_hardening_regressions.py §44-231 -->
