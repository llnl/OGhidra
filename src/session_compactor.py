"""
Session Compactor — Smart context pruning to prevent overflow.

Inspired by OpenCode's SessionCompaction system. Two strategies:
1. prune() — Deterministic: walk backwards through tool outputs, keep recent
   results detailed, replace old results with cache-id references.
2. compact() — LLM-driven: summarize all results into a continuation prompt
   for the next agentic cycle.

This solves the empty-response problem that occurs when accumulated
tool results exhaust the context window.
"""

import logging
from typing import Optional, Tuple
from pydantic import BaseModel

logger = logging.getLogger(__name__)

# Default: protect last 10 results at full detail
PRUNE_PROTECT_COUNT = 10
# Minimum chars to bother pruning (OpenCode uses 20K tokens ≈ 80K chars)
PRUNE_MINIMUM_CHARS = 20000


class CompactionResult(BaseModel):
    """Result of a compaction operation."""

    strategy: str  # "prune" or "compact"
    original_chars: int
    compacted_chars: int
    results_pruned: int = 0
    summary: Optional[str] = None  # LLM-generated summary (compact strategy)


class SessionCompactor:
    """
    Smart context compaction when approaching context window limits.

    Two strategies:
    1. prune() — Drop old tool outputs, keep cache references
    2. compact() — LLM-summarize the session into a continuation prompt

    Usage in bridge.py:
        if compactor.should_compact(exec_results):
            exec_results = compactor.prune(exec_results)
            if compactor.should_compact(exec_results):
                summary = compactor.compact(exec_results, goal)
    """

    def __init__(self, config, llm_client=None):
        """
        Args:
            config: BridgeConfig or OllamaConfig with compaction settings
            llm_client: LLM client for compact() strategy (optional)
        """
        self.enabled = getattr(config, "compaction_enabled", True)
        self.threshold = getattr(config, "compaction_threshold", 0.75)
        self.auto = getattr(config, "compaction_auto", True)
        self.context_budget = getattr(config, "context_budget", 200000)
        self.llm_client = llm_client

        # Protect last N results from pruning
        self.protect_count = PRUNE_PROTECT_COUNT

        logger.info(
            f"SessionCompactor initialized: enabled={self.enabled}, threshold={self.threshold}, budget={self.context_budget}"
        )

    def estimate_context_usage(self, exec_results) -> Tuple[int, float]:
        """Estimate total context usage from execution results.

        Returns:
            Tuple of (total_chars, usage_fraction)
        """
        total_chars = 0
        for te in exec_results.tool_executions:
            total_chars += len(str(te.result or ""))
            total_chars += len(str(te.parameters or ""))
            total_chars += len(te.tool_name or "")

        # Also account for goal + plan text
        total_chars += len(exec_results.goal or "")
        total_chars += len(exec_results.plan or "")

        usage_fraction = total_chars / max(self.context_budget, 1)
        return total_chars, usage_fraction

    def should_compact(self, exec_results) -> bool:
        """Check if context usage exceeds the compaction threshold.

        Args:
            exec_results: ExecutionPhaseResults from the current cycle

        Returns:
            True if compaction should be triggered
        """
        if not self.enabled:
            return False

        total_chars, usage = self.estimate_context_usage(exec_results)
        should = usage > self.threshold

        if should:
            logger.info(f"Compaction triggered: {total_chars} chars ({usage:.0%} of {self.context_budget} budget)")

        return should

    def prune(self, exec_results) -> CompactionResult:
        """Deterministic pruning: replace old tool outputs with cache references.

        Mirrors OpenCode's prune() pattern:
        - Walk backwards from most recent results
        - Protect the last N results at full detail
        - Replace older results with truncated summaries + cache-id refs

        Args:
            exec_results: ExecutionPhaseResults to prune (modified in-place)

        Returns:
            CompactionResult with pruning stats
        """
        total_executions = len(exec_results.tool_executions)
        if total_executions <= self.protect_count:
            logger.info(f"Nothing to prune: {total_executions} <= {self.protect_count} protected")
            return CompactionResult(
                strategy="prune",
                original_chars=self.estimate_context_usage(exec_results)[0],
                compacted_chars=self.estimate_context_usage(exec_results)[0],
                results_pruned=0,
            )

        original_chars = self.estimate_context_usage(exec_results)[0]
        pruned_count = 0

        # Prune everything except the last protect_count results
        prune_boundary = total_executions - self.protect_count

        for i in range(prune_boundary):
            te = exec_results.tool_executions[i]
            result_str = str(te.result or "")

            if len(result_str) > 200:
                # Keep first 100 chars as a preview + cache reference
                preview = result_str[:100].replace("\n", " ")
                te.result = (
                    f"[PRUNED — {len(result_str)} chars] {preview}... [Use get_cached_result('step_{i + 1}') for full output]"
                )
                pruned_count += 1

        compacted_chars = self.estimate_context_usage(exec_results)[0]

        logger.info(
            f"Pruned {pruned_count} results: "
            f"{original_chars} → {compacted_chars} chars "
            f"({(1 - compacted_chars / max(original_chars, 1)):.0%} reduction)"
        )

        return CompactionResult(
            strategy="prune",
            original_chars=original_chars,
            compacted_chars=compacted_chars,
            results_pruned=pruned_count,
        )

    def compact(self, exec_results, goal: str) -> CompactionResult:
        """LLM-driven compaction: summarize all results into a continuation prompt.

        Uses a dedicated LLM call with OpenCode's compaction prompt pattern:
        "Provide a detailed prompt for continuing our investigation..."

        Args:
            exec_results: ExecutionPhaseResults to summarize
            goal: The investigation goal

        Returns:
            CompactionResult with the generated summary
        """
        if not self.llm_client:
            logger.warning("No LLM client for compaction, falling back to prune-only")
            return self.prune(exec_results)

        original_chars = self.estimate_context_usage(exec_results)[0]

        # Build the compaction prompt (mirrors OpenCode's approach)
        results_text = []
        for i, te in enumerate(exec_results.tool_executions, 1):
            result_preview = str(te.result or "")[:500]
            results_text.append(f"Step {i}: {te.tool_name}({te.parameters})\nResult: {result_preview}")

        compaction_prompt = (
            f"You are summarizing an ongoing binary analysis investigation.\n\n"
            f"Goal: {goal}\n\n"
            f"Plan: {exec_results.plan}\n\n"
            f"Results so far:\n" + "\n\n".join(results_text) + "\n\n"
            "Provide a detailed summary for continuing this investigation. "
            "Focus on:\n"
            "- What we analyzed and what we found\n"
            "- Key findings (functions, addresses, patterns)\n"
            "- What we should investigate next\n"
            "- Any critical security findings discovered\n\n"
            "Be specific about function names, addresses, and data. "
            "This summary will replace the full results in the next cycle."
        )

        try:
            # Make compaction LLM call
            summary = self._call_llm_for_summary(compaction_prompt)

            compacted_chars = len(summary)
            logger.info(
                f"LLM compaction: {original_chars} → {compacted_chars} chars "
                f"({(1 - compacted_chars / max(original_chars, 1)):.0%} reduction)"
            )

            return CompactionResult(
                strategy="compact",
                original_chars=original_chars,
                compacted_chars=compacted_chars,
                summary=summary,
            )
        except Exception as e:
            logger.error(f"LLM compaction failed: {e}, falling back to prune")
            return self.prune(exec_results)

    def _call_llm_for_summary(self, prompt: str) -> str:
        """Make a dedicated LLM call for compaction summary.

        Uses a smaller/faster model if available, otherwise the main model.
        """
        try:
            # Try using the LLM client's chat method
            response = self.llm_client.chat(
                model=getattr(self.llm_client, "_model", None) or "default",
                messages=[
                    {
                        "role": "system",
                        "content": "You are a precise technical summarizer for binary analysis investigations. Be concise but preserve critical details like addresses, function names, and security findings.",
                    },
                    {"role": "user", "content": prompt},
                ],
                options={"temperature": 0.3, "num_predict": 2000},
            )

            if isinstance(response, dict):
                return response.get("message", {}).get("content", str(response))
            return str(response)
        except Exception as e:
            logger.error(f"LLM summary call failed: {e}")
            # Fallback: create a structured summary without LLM
            return self._fallback_summary(prompt)

    def _fallback_summary(self, prompt: str) -> str:
        """Create a non-LLM summary by extracting key information."""
        # Simple extraction: just compress the results text
        lines = prompt.split("\n")
        key_lines = [
            l
            for l in lines
            if any(
                kw in l.lower()
                for kw in [
                    "step",
                    "found",
                    "function",
                    "address",
                    "0x",
                    "import",
                    "vulnerability",
                    "privilege",
                    "crypto",
                    "network",
                ]
            )
        ]
        return "## Compacted Investigation Summary\n" + "\n".join(key_lines[:30])

    def reset(self):
        """Reset compactor state (if any)."""
        logger.debug("SessionCompactor reset")
