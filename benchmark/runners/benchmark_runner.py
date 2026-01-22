"""
Benchmark Runner
=================

Main orchestrator that ties together ground truth, OGhidra analysis,
and evaluation metrics to produce benchmark results.
"""

import json
import logging
import time
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field, asdict
from datetime import datetime

from ..metrics.evaluator import SemanticEvaluator, EvaluationResult
from ..ground_truth.extractor import GroundTruthDataset, FunctionGroundTruth
from .oghidra_runner import OGhidraRunner, OGhidraResult

logger = logging.getLogger("oghidra.benchmark.runner")


@dataclass
class BenchmarkConfig:
    """Configuration for benchmark execution."""
    name: str
    description: str = ""

    # Evaluation settings
    include_context: bool = True
    include_llm_judge: bool = False
    use_gpu: bool = True

    # Filtering
    min_complexity: int = 0
    max_complexity: int = 100
    required_tags: List[str] = field(default_factory=list)

    # Output
    save_intermediate: bool = True
    output_dir: str = "benchmark/reports"


@dataclass
class FunctionBenchmarkResult:
    """Complete benchmark result for a single function."""
    # Ground truth info
    function_id: str
    function_name: str
    source_file: str
    binary_address: str

    # Summaries
    ground_truth_summary: str
    oghidra_summary: str
    suggested_name: Optional[str]

    # Evaluation scores
    scores: Dict[str, float]
    combined_score: float

    # Metadata
    analysis_time: float
    decompiled_length: int
    context_chars: int


@dataclass
class BenchmarkResults:
    """Complete results from a benchmark run."""
    # Configuration
    config: BenchmarkConfig
    dataset_name: str
    run_timestamp: str

    # Results
    function_results: List[FunctionBenchmarkResult]

    # Aggregate statistics
    statistics: Dict[str, Any] = field(default_factory=dict)

    # Timing
    total_time: float = 0.0
    functions_evaluated: int = 0
    functions_failed: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "config": asdict(self.config),
            "dataset_name": self.dataset_name,
            "run_timestamp": self.run_timestamp,
            "function_results": [asdict(r) for r in self.function_results],
            "statistics": self.statistics,
            "total_time": self.total_time,
            "functions_evaluated": self.functions_evaluated,
            "functions_failed": self.functions_failed,
        }

    def save(self, path: str):
        """Save results to JSON file."""
        with open(path, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)
        logger.info(f"Saved benchmark results to {path}")


class BenchmarkRunner:
    """
    Main benchmark orchestrator.

    Runs the complete benchmark pipeline:
    1. Load ground truth dataset
    2. Analyze functions with OGhidra
    3. Evaluate summaries with semantic metrics
    4. Aggregate and report results
    """

    def __init__(
        self,
        bridge: Any,
        config: Optional[BenchmarkConfig] = None,
    ):
        """
        Initialize the benchmark runner.

        Args:
            bridge: OGhidra Bridge instance
            config: Benchmark configuration
        """
        self.bridge = bridge
        self.config = config or BenchmarkConfig(name="default")

        # Initialize components
        self.oghidra_runner = OGhidraRunner(
            bridge=bridge,
            include_context=self.config.include_context,
        )
        self.evaluator = SemanticEvaluator(
            use_gpu=self.config.use_gpu,
            include_llm_judge=self.config.include_llm_judge,
            ollama_client=bridge.ollama if self.config.include_llm_judge else None,
        )

        logger.info(f"BenchmarkRunner initialized: {self.config.name}")

    def run(
        self,
        dataset: GroundTruthDataset,
        progress_callback: Optional[callable] = None,
    ) -> BenchmarkResults:
        """
        Run the complete benchmark on a ground truth dataset.

        Args:
            dataset: Ground truth dataset with source summaries
            progress_callback: Optional callback(current, total, message) for progress

        Returns:
            BenchmarkResults with all evaluation data
        """
        start_time = time.time()

        # Filter functions based on config
        functions = self._filter_functions(dataset.functions)
        logger.info(f"Running benchmark on {len(functions)} functions")

        function_results = []
        failed_count = 0

        for i, func in enumerate(functions):
            if progress_callback:
                progress_callback(i + 1, len(functions), f"Analyzing {func.function_name}")

            try:
                result = self._evaluate_function(func)
                function_results.append(result)
            except Exception as e:
                logger.warning(f"Failed to evaluate {func.function_name}: {e}")
                failed_count += 1

        # Compute aggregate statistics
        statistics = self._compute_statistics(function_results)

        total_time = time.time() - start_time

        results = BenchmarkResults(
            config=self.config,
            dataset_name=dataset.name,
            run_timestamp=datetime.now().isoformat(),
            function_results=function_results,
            statistics=statistics,
            total_time=total_time,
            functions_evaluated=len(function_results),
            functions_failed=failed_count,
        )

        # Save if configured
        if self.config.save_intermediate:
            output_dir = Path(self.config.output_dir)
            output_dir.mkdir(parents=True, exist_ok=True)
            output_path = output_dir / f"benchmark_{dataset.name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            results.save(str(output_path))

        logger.info(f"Benchmark complete: {len(function_results)} evaluated, {failed_count} failed, {total_time:.1f}s total")

        return results

    def _filter_functions(
        self,
        functions: List[FunctionGroundTruth],
    ) -> List[FunctionGroundTruth]:
        """Filter functions based on benchmark config."""
        filtered = []

        for func in functions:
            # Must have binary address
            if not func.binary_address:
                continue

            # Must have ground truth summary
            if not func.llm_source_summary:
                continue

            # Complexity filter
            if func.complexity_score is not None:
                if func.complexity_score < self.config.min_complexity:
                    continue
                if func.complexity_score > self.config.max_complexity:
                    continue

            # Tag filter
            if self.config.required_tags:
                if not any(tag in func.tags for tag in self.config.required_tags):
                    continue

            filtered.append(func)

        return filtered

    def _evaluate_function(
        self,
        func: FunctionGroundTruth,
    ) -> FunctionBenchmarkResult:
        """Evaluate a single function."""
        # Get OGhidra analysis
        oghidra_result = self.oghidra_runner.analyze_function(
            address=func.binary_address,
            function_name=func.function_name if not func.function_name.startswith("FUN_") else None,
        )

        # Evaluate summary quality
        eval_result = self.evaluator.evaluate(
            generated=oghidra_result.ai_summary,
            reference=func.llm_source_summary,
            function_id=func.function_id,
        )

        return FunctionBenchmarkResult(
            function_id=func.function_id,
            function_name=func.function_name,
            source_file=func.source_file,
            binary_address=func.binary_address,
            ground_truth_summary=func.llm_source_summary,
            oghidra_summary=oghidra_result.ai_summary,
            suggested_name=oghidra_result.suggested_name,
            scores=eval_result.scores,
            combined_score=eval_result.combined_score,
            analysis_time=oghidra_result.analysis_time,
            decompiled_length=oghidra_result.metadata.get("decompiled_length", 0),
            context_chars=oghidra_result.context_chars,
        )

    def _compute_statistics(
        self,
        results: List[FunctionBenchmarkResult],
    ) -> Dict[str, Any]:
        """Compute aggregate statistics from results."""
        if not results:
            return {}

        import numpy as np

        # Collect scores by metric
        metric_scores = {}
        for result in results:
            for metric, score in result.scores.items():
                if score is not None:
                    if metric not in metric_scores:
                        metric_scores[metric] = []
                    metric_scores[metric].append(score)

        # Compute stats per metric
        stats = {}
        for metric, scores in metric_scores.items():
            arr = np.array(scores)
            stats[metric] = {
                "mean": float(np.mean(arr)),
                "std": float(np.std(arr)),
                "median": float(np.median(arr)),
                "min": float(np.min(arr)),
                "max": float(np.max(arr)),
                "count": len(scores),
            }

        # Combined score stats
        combined = [r.combined_score for r in results]
        arr = np.array(combined)
        stats["combined"] = {
            "mean": float(np.mean(arr)),
            "std": float(np.std(arr)),
            "median": float(np.median(arr)),
            "min": float(np.min(arr)),
            "max": float(np.max(arr)),
            "count": len(combined),
        }

        # Name suggestion accuracy (if ground truth names are known)
        name_matches = sum(1 for r in results if r.suggested_name == r.function_name)
        stats["name_accuracy"] = {
            "exact_matches": name_matches,
            "total": len(results),
            "accuracy": name_matches / len(results) if results else 0,
        }

        # Timing stats
        times = [r.analysis_time for r in results]
        stats["timing"] = {
            "mean_seconds": float(np.mean(times)),
            "total_seconds": float(np.sum(times)),
        }

        return stats
