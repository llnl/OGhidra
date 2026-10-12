# OGhidra Wiki Index

Master catalog of all pages. Updated by the agent on every ingest.

---

## Tension

| Page | Confidence | Summary |
|------|------------|---------|
## Decision

| Page | Confidence | Summary |
|------|------------|---------|
| [[wiki/decision/deprecate-java-ghidra-plugin]] | medium | Proposed transition from the absent Java/Gradle extension toward the backend-neutral Python client and PyGhidra, while retaining HTTP compatibility. |
| [[wiki/decision/feature_work_artifacts]] | medium | Accepted location and artifact policy for LLM-assisted feature work. |
## Concept

| Page | Confidence | Summary |
|------|------------|---------|
| [[wiki/concept/mcp-in-oghidra]] | high | Explain the MCP tool boundary, HTTP wrapper, command format, and PyGhidra bypass path. |
| [[wiki/concept/feature_work_template]] | medium | Define required and optional artifacts for feature work. |
| [[wiki/concept/llm_assisted_feature_workflow]] | medium | Describe the adaptive feature workflow from interview through verification and promotion. |
## Architecture

| Page | Confidence | Summary |
|------|------------|---------|
| [[wiki/architecture/oghidra-end-to-end-data-flow]] | high | Trace query handling through provider/backend selection, command parsing, Ghidra execution, context management, and gated results. |
## Workflow

| Page | Confidence | Summary |
|------|------------|---------|
| [[wiki/workflow/analyze-a-binary]] | high | Provide a staged, evidence-based workflow for setup, progressive analysis, malware triage, and failure handling. |
| [[wiki/workflow/extend-knowledge-json]] | high | Provide a verified procedure for extending JSON catalogs, refreshing caches, and checking retrieval behavior. |
## Module

| Page | Confidence | Summary |
|------|------------|---------|
| [[wiki/module/python-orchestration]] | high | Map startup, provider/backend selection, parsing, prompt context, safety gates, memory, and extension boundaries. |
| [[wiki/module/session-memory-and-cag]] | high | Describe per-session state, persistent history, vector retrieval, prompt budgets, and context risks. |
## Knowledge_schema

| Page | Confidence | Summary |
|------|------------|---------|
| [[wiki/knowledge_schema/knowledge-json-concept]] | high | Explain the convention-based knowledge JSON family, loader contract, CAG retrieval flow, and cache boundary. |
| [[wiki/knowledge_schema/common-workflows-json]] | high | Explain the string-valued task map in src/cag/knowledge/common_workflows.json, runtime selection, and extension limits. |
| [[wiki/knowledge_schema/function-signatures-json]] | high | Document the keyed function metadata records, runtime conversion, cache boundary, and extension process. |
## Integration

| Page | Confidence | Summary |
|------|------------|---------|
| [[wiki/integration/maintained-ghidra-plugin]] | medium | Distinguish HTTP GhidraMCP compatibility from the in-process PyGhidra integration and document the missing Gradle path. |
## Benchmark

| Page | Confidence | Summary |
|------|------------|---------|
| [[wiki/benchmark/evaluation-infrastructure]] | high | Describe source-ground-truth extraction, address mapping, CAG-disabled benchmark runs, metrics, reports, and interpretation limits. |
## Deployment

| Page | Confidence | Summary |
|------|------------|---------|
| [[wiki/deployment/docker-and-release]] | high | Document Python packaging, tagged PyPI publication, container pinning, and release caveats. |
## Best_practice

| Page | Confidence | Summary |
|------|------------|---------|
| [[wiki/best_practice/using-oghidra-for-binary-analysis]] | high | Capture evidence-based analysis, scope, validation, execution-safety, and data-protection practices. |
| [[wiki/best_practice/security-and-privacy]] | high | Document provider/data handling, execution gates, heuristic limitations, and security regression coverage. |

---

*Last updated: 2026-10-12 (repository-wide ingest)*
