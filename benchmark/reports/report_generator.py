"""
Report Generator
=================

Generates comprehensive benchmark reports in multiple formats:
- Markdown for documentation
- HTML for interactive viewing
- JSON for programmatic access
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("oghidra.benchmark.reports")


class ReportGenerator:
    """
    Generates benchmark reports in multiple formats.

    Supports:
    - Markdown (.md) - Human-readable documentation
    - HTML (.html) - Interactive web viewing
    - JSON (.json) - Programmatic access
    - CSV (.csv) - Spreadsheet analysis
    """

    def __init__(self, output_dir: str = "benchmark/reports"):
        """
        Initialize report generator.

        Args:
            output_dir: Directory for saving reports
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        logger.info(f"ReportGenerator initialized, output: {output_dir}")

    def generate_markdown(
        self,
        results: Any,  # BenchmarkResults
        output_path: Optional[str] = None,
    ) -> str:
        """
        Generate a Markdown report from benchmark results.

        Args:
            results: BenchmarkResults object
            output_path: Optional path to save report

        Returns:
            Markdown content as string
        """
        stats = results.statistics
        config = results.config

        md = f"""# OGhidra Semantic Similarity Benchmark Report

**Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
**Dataset:** {results.dataset_name}
**Benchmark:** {config.name}

---

## Executive Summary

| Metric | Value |
|--------|-------|
| Functions Evaluated | {results.functions_evaluated} |
| Functions Failed | {results.functions_failed} |
| Total Time | {results.total_time:.1f}s |
| Avg Time per Function | {results.total_time / max(1, results.functions_evaluated):.2f}s |

---

## Semantic Similarity Scores

### Overall Results

"""
        # Add metric statistics
        if "combined" in stats:
            combined = stats["combined"]
            md += f"""| Metric | Mean | Std | Median | Min | Max |
|--------|------|-----|--------|-----|-----|
| **Combined Score** | {combined["mean"]:.3f} | {combined["std"]:.3f} | {combined["median"]:.3f} | {combined["min"]:.3f} | {combined["max"]:.3f} |
"""

        md += "\n### Individual Metrics\n\n"
        md += "| Metric | Mean | Std | Median | Min | Max | Count |\n"
        md += "|--------|------|-----|--------|-----|-----|-------|\n"

        for metric, data in stats.items():
            if metric in ["combined", "name_accuracy", "timing"]:
                continue
            if isinstance(data, dict) and "mean" in data:
                md += f"| {metric} | {data['mean']:.3f} | {data['std']:.3f} | {data['median']:.3f} | {data['min']:.3f} | {data['max']:.3f} | {data['count']} |\n"

        # Name accuracy
        if "name_accuracy" in stats:
            na = stats["name_accuracy"]
            md += f"""
---

## Function Naming Accuracy

| Metric | Value |
|--------|-------|
| Exact Matches | {na["exact_matches"]} |
| Total Functions | {na["total"]} |
| Accuracy | {na["accuracy"]:.1%} |
"""

        # Configuration
        md += f"""
---

## Benchmark Configuration

| Setting | Value |
|---------|-------|
| Include Context | {config.include_context} |
| Include LLM Judge | {config.include_llm_judge} |
| Use GPU | {config.use_gpu} |
| Min Complexity | {config.min_complexity} |
| Max Complexity | {config.max_complexity} |
"""

        # Top/Bottom performers
        if results.function_results:
            sorted_results = sorted(results.function_results, key=lambda x: x.combined_score, reverse=True)

            md += """
---

## Top 10 Best Performing Functions

| Function | Score | File |
|----------|-------|------|
"""
            for r in sorted_results[:10]:
                md += f"| {r.function_name} | {r.combined_score:.3f} | {r.source_file} |\n"

            md += """
## Bottom 10 Worst Performing Functions

| Function | Score | File |
|----------|-------|------|
"""
            for r in sorted_results[-10:]:
                md += f"| {r.function_name} | {r.combined_score:.3f} | {r.source_file} |\n"

        # Research interpretation
        md += """
---

## Interpretation Guide

### Score Ranges

- **0.85+**: Excellent - AI nearly matches source understanding
- **0.70-0.85**: Good - Core functionality captured, minor gaps
- **0.55-0.70**: Moderate - Partial understanding, significant gaps
- **0.40-0.55**: Poor - Major misunderstandings
- **<0.40**: Very Poor - Fundamentally incorrect

### Metric Descriptions

- **BERTScore F1**: Semantic similarity using contextual embeddings. Best for paraphrase detection.
- **SentenceBERT Cosine**: Fast embedding comparison. Good balance of speed and quality.
- **ROUGE-L**: Longest common subsequence overlap. Measures content coverage.
- **LLM Judge**: Human-aligned quality assessment. Most nuanced but slowest.

---

*Report generated by OGhidra Semantic Similarity Benchmark Framework*
"""

        # Save if path provided
        if output_path:
            with open(output_path, "w") as f:
                f.write(md)
            logger.info(f"Saved Markdown report to {output_path}")

        return md

    def generate_html(
        self,
        results: Any,
        output_path: Optional[str] = None,
    ) -> str:
        """
        Generate an interactive HTML report.

        Args:
            results: BenchmarkResults object
            output_path: Optional path to save report

        Returns:
            HTML content as string
        """
        stats = results.statistics

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OGhidra Benchmark Report - {results.dataset_name}</title>
    <style>
        :root {{
            --bg-primary: #1a1a2e;
            --bg-secondary: #16213e;
            --text-primary: #eee;
            --text-secondary: #aaa;
            --accent: #0f3460;
            --highlight: #e94560;
            --success: #00d26a;
            --warning: #ffc107;
        }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            margin: 0;
            padding: 20px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        h1, h2, h3 {{
            color: var(--highlight);
        }}
        .card {{
            background: var(--bg-secondary);
            border-radius: 10px;
            padding: 20px;
            margin: 20px 0;
            box-shadow: 0 4px 6px rgba(0,0,0,0.3);
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
        }}
        .stat-box {{
            background: var(--accent);
            padding: 15px;
            border-radius: 8px;
            text-align: center;
        }}
        .stat-value {{
            font-size: 2em;
            font-weight: bold;
            color: var(--success);
        }}
        .stat-label {{
            color: var(--text-secondary);
            font-size: 0.9em;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid var(--accent);
        }}
        th {{
            background: var(--accent);
            color: var(--highlight);
        }}
        tr:hover {{
            background: rgba(233, 69, 96, 0.1);
        }}
        .score-bar {{
            height: 20px;
            background: linear-gradient(90deg, var(--highlight) var(--score), var(--accent) var(--score));
            border-radius: 10px;
        }}
        .timestamp {{
            color: var(--text-secondary);
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔬 OGhidra Semantic Similarity Benchmark</h1>
        <p class="timestamp">Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} | Dataset: {results.dataset_name}</p>

        <div class="card">
            <h2>📊 Summary Statistics</h2>
            <div class="stats-grid">
                <div class="stat-box">
                    <div class="stat-value">{results.functions_evaluated}</div>
                    <div class="stat-label">Functions Evaluated</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value">{stats.get("combined", {}).get("mean", 0):.3f}</div>
                    <div class="stat-label">Mean Combined Score</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value">{results.total_time:.1f}s</div>
                    <div class="stat-label">Total Time</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value">{stats.get("name_accuracy", {}).get("accuracy", 0):.1%}</div>
                    <div class="stat-label">Name Accuracy</div>
                </div>
            </div>
        </div>

        <div class="card">
            <h2>📈 Metric Breakdown</h2>
            <table>
                <thead>
                    <tr>
                        <th>Metric</th>
                        <th>Mean</th>
                        <th>Std</th>
                        <th>Median</th>
                        <th>Min</th>
                        <th>Max</th>
                    </tr>
                </thead>
                <tbody>
"""

        for metric, data in stats.items():
            if metric in ["combined", "name_accuracy", "timing"]:
                continue
            if isinstance(data, dict) and "mean" in data:
                html += f"""                    <tr>
                        <td>{metric}</td>
                        <td>{data["mean"]:.3f}</td>
                        <td>{data["std"]:.3f}</td>
                        <td>{data["median"]:.3f}</td>
                        <td>{data["min"]:.3f}</td>
                        <td>{data["max"]:.3f}</td>
                    </tr>
"""

        html += """                </tbody>
            </table>
        </div>

        <div class="card">
            <h2>🏆 Top Performers</h2>
            <table>
                <thead>
                    <tr>
                        <th>Function</th>
                        <th>Score</th>
                        <th>File</th>
                    </tr>
                </thead>
                <tbody>
"""

        if results.function_results:
            sorted_results = sorted(results.function_results, key=lambda x: x.combined_score, reverse=True)
            for r in sorted_results[:10]:
                html += f"""                    <tr>
                        <td>{r.function_name}</td>
                        <td>{r.combined_score:.3f}</td>
                        <td>{r.source_file}</td>
                    </tr>
"""

        html += """                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
"""

        if output_path:
            with open(output_path, "w") as f:
                f.write(html)
            logger.info(f"Saved HTML report to {output_path}")

        return html

    def generate_csv(
        self,
        results: Any,
        output_path: str,
    ) -> None:
        """
        Generate CSV file with per-function results.

        Args:
            results: BenchmarkResults object
            output_path: Path to save CSV
        """
        import csv

        with open(output_path, "w", newline="") as f:
            if not results.function_results:
                return

            # Get all score keys
            score_keys = list(results.function_results[0].scores.keys())

            fieldnames = [
                "function_id",
                "function_name",
                "source_file",
                "binary_address",
                "combined_score",
                "analysis_time",
                "decompiled_length",
                "context_chars",
                "suggested_name",
            ] + score_keys

            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for r in results.function_results:
                row = {
                    "function_id": r.function_id,
                    "function_name": r.function_name,
                    "source_file": r.source_file,
                    "binary_address": r.binary_address,
                    "combined_score": r.combined_score,
                    "analysis_time": r.analysis_time,
                    "decompiled_length": r.decompiled_length,
                    "context_chars": r.context_chars,
                    "suggested_name": r.suggested_name,
                }
                row.update(r.scores)
                writer.writerow(row)

        logger.info(f"Saved CSV report to {output_path}")

    def generate_all(
        self,
        results: Any,
        base_name: Optional[str] = None,
    ) -> Dict[str, str]:
        """
        Generate reports in all supported formats.

        Args:
            results: BenchmarkResults object
            base_name: Base filename (without extension)

        Returns:
            Dict mapping format to output path
        """
        if base_name is None:
            base_name = f"benchmark_{results.dataset_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        outputs = {}

        # Markdown
        md_path = self.output_dir / f"{base_name}.md"
        self.generate_markdown(results, str(md_path))
        outputs["markdown"] = str(md_path)

        # HTML
        html_path = self.output_dir / f"{base_name}.html"
        self.generate_html(results, str(html_path))
        outputs["html"] = str(html_path)

        # CSV
        csv_path = self.output_dir / f"{base_name}.csv"
        self.generate_csv(results, str(csv_path))
        outputs["csv"] = str(csv_path)

        # JSON (raw results)
        json_path = self.output_dir / f"{base_name}.json"
        results.save(str(json_path))
        outputs["json"] = str(json_path)

        logger.info(f"Generated all report formats: {list(outputs.keys())}")

        return outputs
