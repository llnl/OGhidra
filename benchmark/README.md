# OGhidra Semantic Similarity Benchmark

A framework for measuring how accurately OGhidra's AI understands decompiled code by comparing AI-generated function summaries against ground truth from source code.

## Quick Start

### Prerequisites

Install benchmark dependencies:

```bash
pip install bert-score sentence-transformers rouge-score matplotlib
```

### Basic Usage

```python
from benchmark.metrics import SemanticEvaluator

# Quick evaluation of two summaries
evaluator = SemanticEvaluator()
result = evaluator.evaluate(
    generated="This function encrypts data using AES-128 block cipher",
    reference="Encrypts a single 16-byte block with AES encryption"
)

print(f"BERTScore: {result.scores['bert_score_f1']:.3f}")
print(f"SentenceBERT: {result.scores['sbert_cosine']:.3f}")
print(f"Combined: {result.combined_score:.3f}")
```

### Command Line Interface

```bash
# Extract ground truth from a source code project
python -m benchmark.cli extract \
    --source /path/to/source \
    --binary /path/to/compiled.bin \
    --generate-summaries \
    --output benchmark/ground_truth/myproject.json

# Run benchmark (requires Ghidra + Ollama running)
python -m benchmark.cli run \
    --dataset benchmark/ground_truth/myproject.json \
    --output benchmark/reports/

# Quick evaluation of two summaries
python -m benchmark.cli evaluate \
    --generated "This function validates user input" \
    --reference "Validates and sanitizes user-provided strings"
```

## Architecture

```
benchmark/
├── __init__.py           # Package entry point
├── cli.py                # Command-line interface
├── metrics/              # Semantic similarity metrics
│   ├── evaluator.py      # Main evaluator orchestrator
│   ├── bert_score.py     # BERTScore implementation
│   ├── sentence_bert.py  # SentenceBERT cosine similarity
│   ├── rouge.py          # ROUGE-L content overlap
│   └── llm_judge.py      # LLM-as-Judge evaluation
├── ground_truth/         # Ground truth generation
│   ├── extractor.py      # Main extraction orchestrator
│   ├── source_parser.py  # C/C++ source code parser
│   └── summary_generator.py  # LLM summary from source
├── runners/              # Benchmark execution
│   ├── benchmark_runner.py   # Main benchmark orchestrator
│   └── oghidra_runner.py     # OGhidra integration
└── reports/              # Report generation
    └── report_generator.py   # Markdown, HTML, CSV reports
```

## Metrics

| Metric | Description | Speed | Quality |
|--------|-------------|-------|---------|
| **BERTScore F1** | Contextual embedding similarity | Medium | High |
| **SentenceBERT** | Sentence embedding cosine similarity | Fast | Good |
| **ROUGE-L** | Longest common subsequence overlap | Fast | Baseline |
| **LLM-as-Judge** | Human-aligned quality assessment | Slow | Highest |

### Score Interpretation

- **0.85+**: Excellent - AI nearly matches source understanding
- **0.70-0.85**: Good - Core functionality captured
- **0.55-0.70**: Moderate - Partial understanding
- **<0.55**: Poor - Significant gaps

## Full Benchmark Workflow

```python
from benchmark.ground_truth import GroundTruthExtractor
from benchmark.runners import BenchmarkRunner, BenchmarkConfig
from benchmark.reports import ReportGenerator

# 1. Extract ground truth from source
extractor = GroundTruthExtractor(ollama_client=ollama)
dataset = extractor.extract_from_project(
    source_dir="path/to/source",
    project_name="my_project",
    binary_path="path/to/binary.exe"
)

# 2. Map to binary addresses (requires Ghidra running)
dataset = extractor.map_binary_addresses(dataset, ghidra_client)

# 3. Run benchmark
config = BenchmarkConfig(
    name="my_benchmark",
    include_context=True,      # Use caller/callee context
    include_llm_judge=False,   # Faster without LLM judge
)
runner = BenchmarkRunner(bridge=oghidra_bridge, config=config)
results = runner.run(dataset)

# 4. Generate reports
generator = ReportGenerator()
generator.generate_all(results)  # Creates .md, .html, .csv, .json
```

## Research Context

This benchmark addresses the research question:

> *"Can an agentic AI, iteratively exploring a binary through Ghidra, achieve semantic understanding comparable to having the source code?"*

By comparing `similarity(AI_summary(decompiled), AI_summary(source))`, we can measure how close OGhidra gets to "perfect" understanding.
