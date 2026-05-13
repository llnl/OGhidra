"""
Benchmark Visualizations
=========================

Creates charts and visualizations for benchmark results.
Uses matplotlib if available, falls back to ASCII charts.
"""

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("oghidra.benchmark.visualizations")


class BenchmarkVisualizer:
    """
    Creates visualizations for benchmark results.

    Generates:
    - Score distribution histograms
    - Metric comparison bar charts
    - Correlation heatmaps
    - Time vs accuracy scatter plots
    """

    def __init__(self, output_dir: str = "benchmark/reports/figures"):
        """
        Initialize visualizer.

        Args:
            output_dir: Directory for saving figures
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self._matplotlib_available = self._check_matplotlib()

        logger.info(f"BenchmarkVisualizer initialized (matplotlib: {self._matplotlib_available})")

    def _check_matplotlib(self) -> bool:
        """Check if matplotlib is available."""
        try:
            import matplotlib

            matplotlib.use("Agg")  # Non-interactive backend
            import matplotlib.pyplot as plt

            return True
        except ImportError:
            return False

    def plot_score_distribution(
        self,
        results: Any,
        metric: str = "combined",
        output_path: Optional[str] = None,
    ) -> Optional[str]:
        """
        Plot histogram of score distribution.

        Args:
            results: BenchmarkResults object
            metric: Which metric to plot
            output_path: Optional path to save figure

        Returns:
            Path to saved figure, or None if matplotlib unavailable
        """
        if not self._matplotlib_available:
            logger.warning("matplotlib not available, skipping visualization")
            return None

        import matplotlib.pyplot as plt
        import numpy as np

        # Extract scores
        if metric == "combined":
            scores = [r.combined_score for r in results.function_results]
        else:
            scores = [r.scores.get(metric, 0) for r in results.function_results if metric in r.scores]

        if not scores:
            return None

        # Create figure
        fig, ax = plt.subplots(figsize=(10, 6))

        # Plot histogram
        ax.hist(scores, bins=20, color="#e94560", edgecolor="white", alpha=0.8)

        # Add mean line
        mean_score = np.mean(scores)
        ax.axvline(mean_score, color="#00d26a", linestyle="--", linewidth=2, label=f"Mean: {mean_score:.3f}")

        # Styling
        ax.set_xlabel("Score", fontsize=12)
        ax.set_ylabel("Frequency", fontsize=12)
        ax.set_title(f"{metric.replace('_', ' ').title()} Score Distribution", fontsize=14)
        ax.legend()
        ax.set_facecolor("#16213e")
        fig.patch.set_facecolor("#1a1a2e")
        ax.tick_params(colors="white")
        ax.xaxis.label.set_color("white")
        ax.yaxis.label.set_color("white")
        ax.title.set_color("white")

        # Save
        if output_path is None:
            output_path = self.output_dir / f"distribution_{metric}.png"

        plt.savefig(output_path, dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
        plt.close()

        logger.info(f"Saved distribution plot to {output_path}")
        return str(output_path)

    def plot_metric_comparison(
        self,
        results: Any,
        output_path: Optional[str] = None,
    ) -> Optional[str]:
        """
        Plot bar chart comparing different metrics.

        Args:
            results: BenchmarkResults object
            output_path: Optional path to save figure

        Returns:
            Path to saved figure
        """
        if not self._matplotlib_available:
            return None

        import matplotlib.pyplot as plt
        import numpy as np

        stats = results.statistics

        # Collect metrics (excluding special ones)
        metrics = []
        means = []
        stds = []

        for metric, data in stats.items():
            if metric in ["name_accuracy", "timing"]:
                continue
            if isinstance(data, dict) and "mean" in data:
                metrics.append(metric.replace("_", "\n"))
                means.append(data["mean"])
                stds.append(data["std"])

        if not metrics:
            return None

        # Create figure
        fig, ax = plt.subplots(figsize=(12, 6))

        x = np.arange(len(metrics))
        width = 0.6

        bars = ax.bar(x, means, width, yerr=stds, color="#e94560", capsize=5, alpha=0.8)

        # Styling
        ax.set_ylabel("Score", fontsize=12)
        ax.set_title("Metric Comparison", fontsize=14)
        ax.set_xticks(x)
        ax.set_xticklabels(metrics)
        ax.set_ylim(0, 1)

        # Add value labels
        for bar, mean in zip(bars, means):
            height = bar.get_height()
            ax.annotate(
                f"{mean:.3f}",
                xy=(bar.get_x() + bar.get_width() / 2, height),
                xytext=(0, 3),
                textcoords="offset points",
                ha="center",
                va="bottom",
                color="white",
            )

        ax.set_facecolor("#16213e")
        fig.patch.set_facecolor("#1a1a2e")
        ax.tick_params(colors="white")
        ax.xaxis.label.set_color("white")
        ax.yaxis.label.set_color("white")
        ax.title.set_color("white")

        # Save
        if output_path is None:
            output_path = self.output_dir / "metric_comparison.png"

        plt.savefig(output_path, dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
        plt.close()

        logger.info(f"Saved metric comparison to {output_path}")
        return str(output_path)

    def plot_complexity_vs_accuracy(
        self,
        results: Any,
        ground_truth: Any,
        output_path: Optional[str] = None,
    ) -> Optional[str]:
        """
        Plot scatter of function complexity vs accuracy.

        Args:
            results: BenchmarkResults object
            ground_truth: GroundTruthDataset with complexity scores
            output_path: Optional path to save figure

        Returns:
            Path to saved figure
        """
        if not self._matplotlib_available:
            return None

        import matplotlib.pyplot as plt

        # Build complexity lookup
        complexity_lookup = {}
        for func in ground_truth.functions:
            if func.complexity_score is not None:
                complexity_lookup[func.function_id] = func.complexity_score

        # Collect data points
        complexities = []
        scores = []

        for r in results.function_results:
            if r.function_id in complexity_lookup:
                complexities.append(complexity_lookup[r.function_id])
                scores.append(r.combined_score)

        if len(complexities) < 5:
            return None

        # Create figure
        fig, ax = plt.subplots(figsize=(10, 6))

        ax.scatter(complexities, scores, color="#e94560", alpha=0.6, s=50)

        # Styling
        ax.set_xlabel("Function Complexity", fontsize=12)
        ax.set_ylabel("Combined Score", fontsize=12)
        ax.set_title("Complexity vs Semantic Similarity Score", fontsize=14)
        ax.set_ylim(0, 1)

        ax.set_facecolor("#16213e")
        fig.patch.set_facecolor("#1a1a2e")
        ax.tick_params(colors="white")
        ax.xaxis.label.set_color("white")
        ax.yaxis.label.set_color("white")
        ax.title.set_color("white")

        # Save
        if output_path is None:
            output_path = self.output_dir / "complexity_vs_accuracy.png"

        plt.savefig(output_path, dpi=150, bbox_inches="tight", facecolor=fig.get_facecolor())
        plt.close()

        logger.info(f"Saved complexity plot to {output_path}")
        return str(output_path)

    def generate_all(
        self,
        results: Any,
        ground_truth: Optional[Any] = None,
    ) -> Dict[str, str]:
        """
        Generate all available visualizations.

        Returns:
            Dict mapping visualization name to file path
        """
        outputs = {}

        # Score distributions for key metrics
        for metric in ["combined", "bert_score_f1", "sbert_cosine"]:
            path = self.plot_score_distribution(results, metric)
            if path:
                outputs[f"distribution_{metric}"] = path

        # Metric comparison
        path = self.plot_metric_comparison(results)
        if path:
            outputs["metric_comparison"] = path

        # Complexity vs accuracy (if ground truth available)
        if ground_truth:
            path = self.plot_complexity_vs_accuracy(results, ground_truth)
            if path:
                outputs["complexity_vs_accuracy"] = path

        return outputs
