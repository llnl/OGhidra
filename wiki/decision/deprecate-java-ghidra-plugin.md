---
title: "Deprecate the Java Ghidra Plugin"
type: decision
confidence: medium
grounded_by:
  - src/bridge.py
  - src/ghidra_client.py
  - README.md
  - build_ghidra_plugin.sh
policy: human-review-required
last_validated: 2026-10-12
status: proposed
owners: team-reverse-engineering
code_refs: src/bridge.py | src/ghidra_client.py | README.md | build_ghidra_plugin.sh
stability: experimental
last_verified: 2026-10-12
tags: [decision, deprecated-java, ghidra]
---

# Deprecate the Java Ghidra Plugin

## Context

The repository still documents a Gradle-built `OGhidraMCP` extension, and `build_ghidra_plugin.sh` writes into that directory. The current Python implementation also provides a backend-neutral client interface with an in-process PyGhidra implementation, while retaining HTTP GhidraMCP support.
<!-- GROUND_TRUTH: README.md §76-149 -->
<!-- GROUND_TRUTH: build_ghidra_plugin.sh §45-72 -->
<!-- GROUND_TRUTH: src/bridge.py §64-77 -->
<!-- GROUND_TRUTH: src/ghidra_client.py §1322-1356 -->

## Decision

Propose treating the Java/Gradle extension as transitional and keeping `AbstractGhidraClient` as the integration boundary. The PyGhidra backend should be the preferred long-term path where environment constraints permit; HTTP GhidraMCP remains a supported compatibility backend until an explicit removal decision is made.

## Rationale

- The orchestration layer already selects backends behind one abstract client.
- PyGhidra removes the separate Ghidra server component for supported deployments.
- The current checkout does not contain the `OGhidraMCP/` directory referenced by the build instructions.
- Retaining HTTP during migration avoids breaking existing Ghidra projects and deployments.

## Consequences

- New integrations should target the abstract Python client contract rather than Java-specific endpoints.
- Documentation must clearly distinguish current HTTP compatibility from the long-term in-process direction.
- Ghidra-version and PyGhidra compatibility need explicit release testing before HTTP removal.

## Alternatives Considered

- Keep the Gradle extension as the primary path: rejected because the live Python code now supports an in-process backend and the extension source is absent here.
- Remove HTTP immediately: rejected because the README and tests still document and exercise the HTTP service path.

<!-- REVIEW NEEDED: This is a proposed architectural direction; explicit maintainer approval is required before declaring the HTTP/Java path deprecated or removing it. -->
