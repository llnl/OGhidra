#!/usr/bin/env python3
"""
OGhidra Semantic Similarity Benchmark CLI
==========================================

Command-line interface for running benchmarks comparing AI-generated
function summaries from decompiled code against ground truth from source.

Usage:
    # Extract ground truth from source project
    python -m benchmark.cli extract --source /path/to/source --output ground_truth.json

    # Run benchmark
    python -m benchmark.cli run --dataset ground_truth.json --output results/

    # Generate report from existing results
    python -m benchmark.cli report --results results/benchmark.json --format all

    # Quick evaluation of two summaries
    python -m benchmark.cli evaluate --generated "..." --reference "..."
"""

import argparse
import json
import logging
import sys
from pathlib import Path

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("oghidra.benchmark.cli")


def cmd_extract(args):
    """Extract ground truth from source code project."""
    from benchmark.ground_truth import GroundTruthExtractor

    logger.info(f"Extracting ground truth from: {args.source}")

    # Initialize Ollama client if generating summaries
    ollama_client = None
    if args.generate_summaries:
        try:
            from src.config import get_config
            from src.ollama_client import OllamaClient
            config = get_config()
            ollama_client = OllamaClient(config.ollama)
            logger.info("Ollama client initialized for summary generation")
        except Exception as e:
            logger.warning(f"Could not initialize Ollama: {e}")
            logger.warning("Proceeding without LLM summary generation")

    extractor = GroundTruthExtractor(
        ollama_client=ollama_client,
        generate_summaries=args.generate_summaries,
    )

    dataset = extractor.extract_from_project(
        source_dir=args.source,
        project_name=args.name or Path(args.source).name,
        binary_path=args.binary,
        optimization_level=args.optimization,
        compiler=args.compiler,
    )

    # Save dataset
    output_path = args.output or f"benchmark/ground_truth/{dataset.name}.json"
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    dataset.save(output_path)

    logger.info(f"Extracted {len(dataset.functions)} functions")
    logger.info(f"  With docstrings: {sum(1 for f in dataset.functions if f.original_docstring)}")
    logger.info(f"  With summaries: {sum(1 for f in dataset.functions if f.llm_source_summary)}")
    logger.info(f"Saved to: {output_path}")


def cmd_run(args):
    """Run benchmark on a ground truth dataset."""
    from benchmark.ground_truth import GroundTruthExtractor
    from benchmark.ground_truth.extractor import GroundTruthDataset
    from benchmark.runners import BenchmarkRunner, BenchmarkConfig
    from benchmark.reports import ReportGenerator

    logger.info(f"Loading dataset: {args.dataset}")

    # Load dataset
    dataset = GroundTruthDataset.load(args.dataset)
    logger.info(f"Loaded {len(dataset.functions)} functions from {dataset.name}")

    # Initialize OGhidra bridge
    try:
        from src.config import get_config
        from src.bridge import Bridge

        config = get_config()
        bridge = Bridge(
            config=config,
            include_capabilities=True,
            enable_cag=False,  # Disable CAG for clean benchmark
        )
        logger.info("OGhidra bridge initialized")
    except Exception as e:
        logger.error(f"Failed to initialize OGhidra: {e}")
        logger.error("Make sure Ghidra is running with GhidraMCP and Ollama is available")
        return 1

    # Map binary addresses if not already done
    if not any(f.binary_address for f in dataset.functions):
        logger.info("Mapping function addresses from Ghidra...")
        extractor = GroundTruthExtractor()
        dataset = extractor.map_binary_addresses(dataset, bridge.ghidra)

    # Configure benchmark
    bench_config = BenchmarkConfig(
        name=args.name or f"benchmark_{dataset.name}",
        include_context=not args.no_context,
        include_llm_judge=args.llm_judge,
        use_gpu=not args.no_gpu,
        output_dir=args.output or "benchmark/reports",
    )

    # Run benchmark
    runner = BenchmarkRunner(bridge=bridge, config=bench_config)

    def progress(current, total, msg):
        print(f"\r[{current}/{total}] {msg}...", end="", flush=True)

    results = runner.run(dataset, progress_callback=progress)
    print()  # New line after progress

    # Generate reports
    if not args.no_report:
        generator = ReportGenerator(output_dir=bench_config.output_dir)
        outputs = generator.generate_all(results)
        logger.info(f"Reports generated: {list(outputs.keys())}")

    # Print summary
    stats = results.statistics
    print("\n" + "=" * 60)
    print("BENCHMARK COMPLETE")
    print("=" * 60)
    print(f"Functions evaluated: {results.functions_evaluated}")
    print(f"Functions failed: {results.functions_failed}")
    print(f"Total time: {results.total_time:.1f}s")
    print(f"\nCombined Score: {stats.get('combined', {}).get('mean', 0):.3f} "
          f"(±{stats.get('combined', {}).get('std', 0):.3f})")
    print("=" * 60)


def cmd_evaluate(args):
    """Quick evaluation of two summaries."""
    from benchmark.metrics import SemanticEvaluator

    logger.info("Initializing evaluator...")
    evaluator = SemanticEvaluator(use_gpu=not args.no_gpu)

    result = evaluator.evaluate(
        generated=args.generated,
        reference=args.reference,
    )

    print("\n" + "=" * 50)
    print("EVALUATION RESULTS")
    print("=" * 50)
    print(f"\nGenerated: {args.generated[:100]}...")
    print(f"Reference: {args.reference[:100]}...")
    print("\nScores:")
    for metric, score in result.scores.items():
        if score is not None:
            print(f"  {metric}: {score:.4f}")
    print(f"\nCombined Score: {result.combined_score:.4f}")
    print("=" * 50)


def cmd_report(args):
    """Generate reports from existing results."""
    from benchmark.runners.benchmark_runner import BenchmarkResults
    from benchmark.reports import ReportGenerator

    logger.info(f"Loading results: {args.results}")

    with open(args.results) as f:
        data = json.load(f)

    # Reconstruct results object (simplified)
    from benchmark.runners.benchmark_runner import BenchmarkConfig, FunctionBenchmarkResult

    config = BenchmarkConfig(**data['config'])
    function_results = [FunctionBenchmarkResult(**r) for r in data['function_results']]

    # Create minimal results object for report generation
    class ResultsWrapper:
        pass

    results = ResultsWrapper()
    results.config = config
    results.dataset_name = data['dataset_name']
    results.run_timestamp = data['run_timestamp']
    results.function_results = function_results
    results.statistics = data['statistics']
    results.total_time = data['total_time']
    results.functions_evaluated = data['functions_evaluated']
    results.functions_failed = data['functions_failed']

    # Generate reports
    generator = ReportGenerator(output_dir=args.output or "benchmark/reports")

    if args.format == "all":
        outputs = generator.generate_all(results)
    elif args.format == "markdown":
        outputs = {"markdown": generator.generate_markdown(results, args.output)}
    elif args.format == "html":
        outputs = {"html": generator.generate_html(results, args.output)}

    logger.info(f"Generated: {list(outputs.keys())}")


def main():
    parser = argparse.ArgumentParser(
        description="OGhidra Semantic Similarity Benchmark",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Extract command
    extract_parser = subparsers.add_parser("extract", help="Extract ground truth from source")
    extract_parser.add_argument("--source", "-s", required=True, help="Source code directory")
    extract_parser.add_argument("--output", "-o", help="Output JSON file path")
    extract_parser.add_argument("--name", "-n", help="Dataset name")
    extract_parser.add_argument("--binary", "-b", help="Path to compiled binary")
    extract_parser.add_argument("--optimization", default="O2", help="Optimization level")
    extract_parser.add_argument("--compiler", default="gcc", help="Compiler used")
    extract_parser.add_argument("--generate-summaries", "-g", action="store_true",
                               help="Generate LLM summaries from source")

    # Run command
    run_parser = subparsers.add_parser("run", help="Run benchmark on dataset")
    run_parser.add_argument("--dataset", "-d", required=True, help="Ground truth dataset JSON")
    run_parser.add_argument("--output", "-o", help="Output directory for reports")
    run_parser.add_argument("--name", "-n", help="Benchmark name")
    run_parser.add_argument("--no-context", action="store_true", help="Disable caller/callee context")
    run_parser.add_argument("--llm-judge", action="store_true", help="Include LLM-as-Judge evaluation")
    run_parser.add_argument("--no-gpu", action="store_true", help="Disable GPU acceleration")
    run_parser.add_argument("--no-report", action="store_true", help="Skip report generation")

    # Evaluate command
    eval_parser = subparsers.add_parser("evaluate", help="Quick evaluation of two summaries")
    eval_parser.add_argument("--generated", "-g", required=True, help="Generated summary")
    eval_parser.add_argument("--reference", "-r", required=True, help="Reference summary")
    eval_parser.add_argument("--no-gpu", action="store_true", help="Disable GPU acceleration")

    # Report command
    report_parser = subparsers.add_parser("report", help="Generate reports from results")
    report_parser.add_argument("--results", "-r", required=True, help="Results JSON file")
    report_parser.add_argument("--output", "-o", help="Output directory/file")
    report_parser.add_argument("--format", "-f", choices=["all", "markdown", "html", "csv"],
                              default="all", help="Report format")

    args = parser.parse_args()

    if args.command == "extract":
        cmd_extract(args)
    elif args.command == "run":
        cmd_run(args)
    elif args.command == "evaluate":
        cmd_evaluate(args)
    elif args.command == "report":
        cmd_report(args)
    else:
        parser.print_help()
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
