# OGhidra Wiki Index

Master catalog of all pages. Updated by the agent on every ingest.

---

## Tension

| Page | Confidence | Summary |
|------|------------|---------|
## Decision

| Page | Confidence | Summary |
|------|------------|---------|
| [[wiki/decision/deprecate-java-ghidra-plugin]] | low | Record the rationale, migration boundaries, compatibility concerns, and removal plan for the Java/Gradle plugin. |
## Concept

| Page | Confidence | Summary |
|------|------------|---------|
| [[wiki/concept/mcp-in-oghidra]] | low | Explain the role of MCP in exposing OGhidra capabilities to LLM-driven reverse-engineering sessions. |
## Architecture

| Page | Confidence | Summary |
|------|------------|---------|
| [[wiki/architecture/oghidra-end-to-end-data-flow]] | low | Trace a binary-analysis request from the LLM and MCP boundary through Python orchestration, Ghidra operations, and the returned analysis. |
## Workflow

| Page | Confidence | Summary |
|------|------------|---------|
| [[wiki/workflow/analyze-a-binary]] | low | Document the primary developer workflow for starting an analysis, invoking tools conversationally, and interpreting results. |
| [[wiki/workflow/extend-knowledge-json]] | low | Provide a verified procedure for adding or modifying common workflows and function-signature knowledge without breaking consumers. |
## Module

| Page | Confidence | Summary |
|------|------------|---------|
| [[wiki/module/python-orchestration]] | low | Map the Python packages and responsibilities that coordinate LLM requests, MCP interactions, workflows, and Ghidra analysis. |
## Knowledge_schema

| Page | Confidence | Summary |
|------|------------|---------|
| [[wiki/knowledge_schema/knowledge-json-concept]] | high | Explain the convention-based knowledge JSON family, loader contract, CAG retrieval flow, and cache boundary. |
| [[wiki/knowledge_schema/common-workflows-json]] | high | Explain the string-valued task map in src/cag/knowledge/common_workflows.json, runtime selection, and extension limits. |
| [[wiki/knowledge_schema/function-signatures-json]] | high | Document the keyed function metadata records, runtime conversion, cache boundary, and extension process. |
## Integration

| Page | Confidence | Summary |
|------|------------|---------|
| [[wiki/integration/maintained-ghidra-plugin]] | low | Define how OGhidra should interact with the Ghidra-maintained plugin as the replacement for the project Java extension. |
## Benchmark

| Page | Confidence | Summary |
|------|------------|---------|
| [[wiki/benchmark/evaluation-infrastructure]] | low | Describe the benchmark layout, evaluation entry points, expected outputs, and how analysis quality is assessed. |
## Deployment

| Page | Confidence | Summary |
|------|------------|---------|
| [[wiki/deployment/docker-and-release]] | low | Document the Docker packaging and GitHub Actions release path used to distribute OGhidra. |
## Best_practice

| Page | Confidence | Summary |
|------|------------|---------|
| [[wiki/best_practice/using-oghidra-for-binary-analysis]] | low | Capture evidence-based guidance for preparing binaries, structuring requests, validating results, and handling uncertain LLM output. |

---

*Last updated: 2026-10-12 (knowledge JSON ingest)*
