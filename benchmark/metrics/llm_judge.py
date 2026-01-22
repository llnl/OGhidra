"""
LLM-as-Judge Metric Implementation
====================================

Uses a large language model to evaluate summary quality with human-like judgment.
This provides nuanced evaluation that embedding metrics may miss.

Based on research showing LLM-as-Judge correlates highly with human evaluation
when using structured evaluation criteria.
"""

import logging
from typing import List, Optional, Dict, Any

from .evaluator import BaseMetric

logger = logging.getLogger("oghidra.benchmark.metrics.llm_judge")


# Structured evaluation prompt for consistent LLM judgment
LLM_JUDGE_PROMPT = """You are an expert evaluator assessing the quality of a function summary generated from decompiled binary code.

## Task
Compare the GENERATED SUMMARY (from decompiled code) against the REFERENCE SUMMARY (from source code) and rate how well the generated summary captures the function's purpose and behavior.

## Reference Summary (Ground Truth from Source Code):
{reference}

## Generated Summary (From Decompiled Code):
{candidate}

## Evaluation Criteria
Rate each criterion on a scale of 1-5:

1. **Semantic Accuracy (1-5)**: Does the generated summary correctly identify what the function does?
   - 5: Perfectly captures the function's purpose
   - 3: Partially correct, missing some key aspects
   - 1: Completely wrong or misleading

2. **Completeness (1-5)**: Are all important behaviors and side effects mentioned?
   - 5: All key behaviors identified
   - 3: Some behaviors missing
   - 1: Most behaviors missing

3. **Technical Precision (1-5)**: Are technical details (data types, operations, protocols) correct?
   - 5: All technical details accurate
   - 3: Some inaccuracies
   - 1: Major technical errors

4. **Clarity (1-5)**: Is the summary clear and well-structured?
   - 5: Very clear and well-organized
   - 3: Understandable but could be clearer
   - 1: Confusing or poorly written

## Response Format
Provide your evaluation as JSON:
```json
{{
    "semantic_accuracy": <1-5>,
    "completeness": <1-5>,
    "technical_precision": <1-5>,
    "clarity": <1-5>,
    "overall_score": <1-5>,
    "reasoning": "<brief explanation of your ratings>"
}}
```

Evaluate now:"""


class LLMJudgeMetric(BaseMetric):
    """
    LLM-as-Judge metric using Ollama for evaluation.

    This metric uses a language model to evaluate summary quality,
    providing human-aligned judgment that captures nuances missed
    by embedding-based metrics.

    The final score is normalized to 0-1 range for consistency
    with other metrics.
    """

    def __init__(
        self,
        ollama_client: Any,
        model: Optional[str] = None,
        temperature: float = 0.1,
    ):
        """
        Initialize LLM-as-Judge metric.

        Args:
            ollama_client: OllamaClient instance for generation
            model: Model to use (defaults to client's configured model)
            temperature: Temperature for generation (low for consistency)
        """
        self.ollama_client = ollama_client
        self.model = model
        self.temperature = temperature

        logger.info(f"LLM-as-Judge initialized (model: {model or 'default'})")

    @property
    def name(self) -> str:
        return "llm_judge"

    def score(self, candidate: str, reference: str) -> float:
        """
        Get LLM judgment score for candidate vs reference.

        Args:
            candidate: Generated summary from decompiled code
            reference: Ground truth summary from source code

        Returns:
            Normalized score (0-1, higher is better)
        """
        detailed = self.detailed_score(candidate, reference)
        return detailed.get("overall_score", 0.0) / 5.0  # Normalize to 0-1

    def detailed_score(self, candidate: str, reference: str) -> Dict[str, Any]:
        """
        Get detailed LLM judgment with all criteria scores.

        Returns:
            Dict with individual criterion scores and reasoning
        """
        prompt = LLM_JUDGE_PROMPT.format(
            reference=reference,
            candidate=candidate,
        )

        try:
            response = self.ollama_client.generate(
                prompt=prompt,
                model=self.model,
                temperature=self.temperature,
            )

            # Parse JSON from response
            return self._parse_response(response)

        except Exception as e:
            logger.error(f"LLM-as-Judge evaluation failed: {e}")
            return {
                "semantic_accuracy": 0,
                "completeness": 0,
                "technical_precision": 0,
                "clarity": 0,
                "overall_score": 0,
                "reasoning": f"Evaluation failed: {e}",
                "error": str(e),
            }

    def _parse_response(self, response: str) -> Dict[str, Any]:
        """Parse LLM response to extract scores."""
        import json
        import re

        # Try to extract JSON from response
        json_match = re.search(r'\{[^{}]*\}', response, re.DOTALL)
        if json_match:
            try:
                result = json.loads(json_match.group())
                # Validate expected keys
                expected_keys = ["semantic_accuracy", "completeness", "technical_precision", "clarity", "overall_score"]
                for key in expected_keys:
                    if key not in result:
                        result[key] = 3  # Default to middle score if missing
                return result
            except json.JSONDecodeError:
                pass

        # Fallback: try to extract numbers from response
        logger.warning("Could not parse JSON from LLM response, using fallback parsing")
        numbers = re.findall(r'\b([1-5])\b', response)
        if len(numbers) >= 4:
            return {
                "semantic_accuracy": int(numbers[0]),
                "completeness": int(numbers[1]),
                "technical_precision": int(numbers[2]),
                "clarity": int(numbers[3]),
                "overall_score": int(numbers[4]) if len(numbers) > 4 else 3,
                "reasoning": "Parsed from unstructured response",
            }

        # Ultimate fallback
        return {
            "semantic_accuracy": 3,
            "completeness": 3,
            "technical_precision": 3,
            "clarity": 3,
            "overall_score": 3,
            "reasoning": "Could not parse LLM response",
            "raw_response": response[:500],
        }

    def batch_score(self, candidates: List[str], references: List[str]) -> List[float]:
        """
        Score multiple pairs (sequentially - LLM calls are not easily batched).

        Note: This is slower than other metrics due to sequential LLM calls.
        Consider using only for final evaluation, not hyperparameter tuning.
        """
        return [self.score(c, r) for c, r in zip(candidates, references)]
