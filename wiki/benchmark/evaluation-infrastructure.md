---
title: "OGhidra Evaluation Infrastructure"
type: benchmark
confidence: high
grounded_by:
  - benchmark/cli.py
  - benchmark/ground_truth/extractor.py
  - benchmark/runners/benchmark_runner.py
  - benchmark/metrics/evaluator.py
  - benchmark/reports/report_generator.py
policy: agent-editable
last_validated: 2026-10-12
status: active
owners: team-reverse-engineering
code_refs: benchmark/cli.py | benchmark/ground_truth/extractor.py | benchmark/runners/benchmark_runner.py | benchmark/metrics/evaluator.py | benchmark/reports/report_generator.py
stability: experimental
last_verified: 2026-10-12
tags: [benchmarks, evaluation, reverse-engineering]
---

# OGhidra Evaluation Infrastructure

The benchmark compares an OGhidra-generated function summary from decompiled code with an LLM-generated summary from source code. It is a semantic similarity evaluation, not a direct proof of functional correctness.
<!-- GROUND_TRUTH: benchmark/README.md §1-3, §124-130 -->

## Pipeline

1. `extract` parses C/C++ source files, captures signatures/docstrings/source code, optionally generates source summaries, and writes a `GroundTruthDataset` JSON file.
2. If binary addresses are absent, the run maps source function names to Ghidra function listings. This requires preserved names or debug information.
3. `run` creates a `Bridge` with CAG disabled for a cleaner benchmark, analyzes eligible functions, and evaluates generated summaries.
4. The runner filters out functions without binary addresses or source summaries and applies complexity/tag filters.
5. Reports and intermediate JSON results are emitted under `benchmark/reports` by default.
<!-- GROUND_TRUTH: benchmark/ground_truth/extractor.py §27-115, §117-229, §231-267 -->
<!-- GROUND_TRUTH: benchmark/cli.py §78-147 -->
<!-- GROUND_TRUTH: benchmark/runners/benchmark_runner.py §111-242 -->

## Metrics

The evaluator lazily loads BERTScore F1, SentenceBERT cosine, ROUGE-L, and optional LLM-as-Judge. The combined score weights available metrics at 0.35, 0.35, 0.15, and 0.15 respectively, renormalizing over metrics that returned values.
<!-- GROUND_TRUTH: benchmark/metrics/evaluator.py §28-56, §89-169 -->

Aggregate results include per-metric statistics, combined-score statistics, exact suggested-name accuracy, and timing. Reports support Markdown, HTML, JSON, and CSV generation through `ReportGenerator`.
<!-- GROUND_TRUTH: benchmark/runners/benchmark_runner.py §277-336 -->
<!-- GROUND_TRUTH: benchmark/reports/report_generator.py §19-40 -->

## Failure Modes and Interpretation

- Source parsing or LLM source-summary generation can fail per function.
- Address mapping depends on name preservation and can exclude stripped/renamed functions.
- Missing optional metric dependencies are logged; all metrics unavailable causes evaluation failure.
- Similarity scores measure wording/semantic alignment and can reward plausible paraphrase without proving behavior.
- Results are sensitive to compiler, optimization level, binary mapping quality, model, context setting, and metric availability.

Use the benchmark for comparative experiments with fixed datasets/configuration, not as the sole security or correctness criterion.
