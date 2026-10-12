---
title: "Docker and Release Workflow"
type: deployment
confidence: high
grounded_by:
  - Dockerfile
  - pyproject.toml
  - .github/workflows/release.yml
  - README.md
policy: agent-editable
last_validated: 2026-10-12
status: active
owners: team-reverse-engineering
code_refs: Dockerfile | pyproject.toml | .github/workflows/release.yml | README.md
stability: experimental
last_verified: 2026-10-12
tags: [deployment, docker, github-actions]
---

# Docker and Release Workflow

OGhidra has a Python package/release path and a separate container recipe that bundles a specific Ghidra release with the PyGhidra branch. These paths should not be conflated.

## Python Package

`pyproject.toml` declares Python 3.12+, Hatch/Hatch-VCS packaging, a wheel package rooted at `src`, and dependencies including Pydantic, HTTP clients, NumPy, PyGhidra, and UI libraries. The release workflow builds distributions, runs `twine check`, uploads the `dist/` directory as an artifact, and publishes tagged releases to PyPI using trusted publishing.
<!-- GROUND_TRUTH: pyproject.toml §1-46 -->
<!-- GROUND_TRUTH: .github/workflows/release.yml §1-49 -->

## Container

The Dockerfile uses Eclipse Temurin JDK 26 on UBI minimal, installs Python tooling and utilities, downloads and verifies Ghidra `12.1_PUBLIC_20260513`, clones the `pyghidra` branch, installs dependencies with `uv`, and starts an interactive Bash entrypoint. It adds `.env` into the image, so secrets must not be supplied through an unreviewed build context.
<!-- GROUND_TRUTH: Dockerfile §1-35 -->

## Operational Caveats

- The README recommends Ghidra 12.0.3, while the Dockerfile pins Ghidra 12.1; version-specific behavior must be verified per deployment.
- The Dockerfile clones a remote branch rather than building the checked-out source tree, so image contents can differ from the local commit.
- The release workflow triggers on `v*` tags or manual dispatch; manual dispatch builds but does not publish because publication is restricted to tag pushes.
- No test job appears in the release workflow; release success verifies packaging and metadata, not end-to-end Ghidra analysis.
