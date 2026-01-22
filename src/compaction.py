"""
Result Compaction Module for OGhidra
=====================================

Implements Claude Code-style conversation compaction for tool execution results.
Prevents context window overflow by progressively summarizing older results
while preserving recent context and key findings.

Algorithm:
1. Tier 0 (Recent): Last N results kept at full detail
2. Tier 1 (Summary): Older results compressed to 2-3 sentence summaries
3. Tier 2 (Statistics): Ancient results aggregated into statistics
4. Hard budget enforcement with graceful degradation
"""

import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from collections import defaultdict

logger = logging.getLogger("oghidra.compaction")


class CompactionTier(Enum):
    """Compaction levels for results."""
    FULL = 0       # Complete result (recent)
    SUMMARY = 1    # 2-3 sentence summary (older)
    STATISTICS = 2 # Aggregated stats only (ancient)
    DROPPED = 3    # Not included (budget exceeded)


@dataclass
class CompactedResult:
    """A result after compaction processing."""
    step_id: str
    tool_name: str
    parameters: Dict[str, Any]
    tier: CompactionTier
    content: str  # The compacted content
    original_chars: int
    compacted_chars: int
    key_findings: List[str] = field(default_factory=list)

    @property
    def compression_ratio(self) -> float:
        """How much the result was compressed."""
        if self.original_chars == 0:
            return 1.0
        return self.compacted_chars / self.original_chars


@dataclass
class CompactionStats:
    """Statistics about the compaction process."""
    total_results: int = 0
    tier_counts: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    original_chars: int = 0
    compacted_chars: int = 0
    budget_used: int = 0
    budget_total: int = 0

    @property
    def compression_ratio(self) -> float:
        if self.original_chars == 0:
            return 1.0
        return self.compacted_chars / self.original_chars

    def summary(self) -> str:
        return (
            f"Compaction: {self.original_chars:,} → {self.compacted_chars:,} chars "
            f"({self.compression_ratio:.1%}), "
            f"Budget: {self.budget_used:,}/{self.budget_total:,} "
            f"({100*self.budget_used/max(1,self.budget_total):.0f}%)"
        )


class ResultCompactor:
    """
    Compacts tool execution results to fit within context budget.

    Uses a tiered approach inspired by Claude Code's /compact command:
    - Recent results (last N) get full detail
    - Older results get LLM-summarized to key points
    - Ancient results become aggregated statistics
    - Hard budget stops adding content when exhausted

    Example:
        compactor = ResultCompactor(ollama_client, budget_chars=50000)
        compacted = compactor.compact(exec_results.tool_executions)
        formatted = compactor.format_for_prompt(compacted)
    """

    def __init__(
        self,
        ollama_client=None,
        budget_chars: int = 50000,
        full_detail_count: int = 3,      # Last N results at full detail
        summary_count: int = 7,           # Next N results as summaries
        max_full_chars: int = 8000,       # Max chars for a single full result
        max_summary_chars: int = 500,     # Max chars for a summary
        enable_llm_summary: bool = True,
    ):
        self.ollama_client = ollama_client
        self.budget_chars = budget_chars
        self.full_detail_count = full_detail_count
        self.summary_count = summary_count
        self.max_full_chars = max_full_chars
        self.max_summary_chars = max_summary_chars
        self.enable_llm_summary = enable_llm_summary and ollama_client is not None

        logger.info(f"ResultCompactor initialized: budget={budget_chars}, "
                   f"full={full_detail_count}, summary={summary_count}")

    def compact(
        self,
        tool_executions: List[Any],
        goal: str = ""
    ) -> Tuple[List[CompactedResult], CompactionStats]:
        """
        Compact a list of tool executions to fit within budget.

        Args:
            tool_executions: List of ToolExecution objects from execution phase
            goal: The investigation goal (helps prioritize relevant content)

        Returns:
            Tuple of (compacted_results, stats)
        """
        if not tool_executions:
            return [], CompactionStats()

        stats = CompactionStats(
            total_results=len(tool_executions),
            budget_total=self.budget_chars
        )

        total = len(tool_executions)
        compacted_results = []
        chars_used = 0

        # Process results from oldest to newest, but assign tiers based on recency
        for i, exec_result in enumerate(tool_executions):
            recency_index = total - i - 1  # 0 = newest, higher = older

            # Determine tier based on recency
            if recency_index < self.full_detail_count:
                target_tier = CompactionTier.FULL
            elif recency_index < self.full_detail_count + self.summary_count:
                target_tier = CompactionTier.SUMMARY
            else:
                target_tier = CompactionTier.STATISTICS

            # Extract data from execution result
            tool_name = getattr(exec_result, 'tool_name', str(type(exec_result)))
            parameters = getattr(exec_result, 'parameters', {})
            result_text = str(getattr(exec_result, 'result', exec_result))
            step_id = f"step_{i+1}"

            stats.original_chars += len(result_text)

            # Compact based on tier and remaining budget
            remaining_budget = self.budget_chars - chars_used
            compacted = self._compact_result(
                step_id=step_id,
                tool_name=tool_name,
                parameters=parameters,
                result_text=result_text,
                target_tier=target_tier,
                remaining_budget=remaining_budget,
                goal=goal
            )

            # Check if we exceeded budget
            if compacted.tier == CompactionTier.DROPPED:
                stats.tier_counts["dropped"] += 1
                continue

            chars_used += compacted.compacted_chars
            stats.tier_counts[compacted.tier.name.lower()] += 1
            compacted_results.append(compacted)

        stats.compacted_chars = chars_used
        stats.budget_used = chars_used

        logger.info(f"Compaction complete: {stats.summary()}")

        return compacted_results, stats

    def _compact_result(
        self,
        step_id: str,
        tool_name: str,
        parameters: Dict,
        result_text: str,
        target_tier: CompactionTier,
        remaining_budget: int,
        goal: str
    ) -> CompactedResult:
        """Compact a single result based on tier and budget."""

        original_chars = len(result_text)

        # Check if we have any budget left
        if remaining_budget <= 100:
            return CompactedResult(
                step_id=step_id,
                tool_name=tool_name,
                parameters=parameters,
                tier=CompactionTier.DROPPED,
                content="[DROPPED - budget exceeded]",
                original_chars=original_chars,
                compacted_chars=0
            )

        # Try compaction at target tier
        if target_tier == CompactionTier.FULL:
            content = self._compact_to_full(result_text, remaining_budget)
        elif target_tier == CompactionTier.SUMMARY:
            content = self._compact_to_summary(result_text, tool_name, goal, remaining_budget)
        else:
            content = self._compact_to_statistics(result_text, tool_name, remaining_budget)

        # If still too large, escalate tier
        actual_tier = target_tier
        while len(content) > remaining_budget and actual_tier.value < CompactionTier.DROPPED.value:
            actual_tier = CompactionTier(actual_tier.value + 1)
            if actual_tier == CompactionTier.SUMMARY:
                content = self._compact_to_summary(result_text, tool_name, goal, remaining_budget)
            elif actual_tier == CompactionTier.STATISTICS:
                content = self._compact_to_statistics(result_text, tool_name, remaining_budget)
            else:
                content = "[DROPPED - could not fit in budget]"

        # Extract key findings for later reference
        key_findings = self._extract_key_findings(result_text, tool_name)

        return CompactedResult(
            step_id=step_id,
            tool_name=tool_name,
            parameters=parameters,
            tier=actual_tier,
            content=content,
            original_chars=original_chars,
            compacted_chars=len(content),
            key_findings=key_findings
        )

    def _compact_to_full(self, result_text: str, max_chars: int) -> str:
        """Keep full result, but smart-truncate if needed."""
        limit = min(self.max_full_chars, max_chars)

        if len(result_text) <= limit:
            return result_text

        # Smart truncation: keep beginning and end
        keep_start = int(limit * 0.7)
        keep_end = limit - keep_start - 50

        return (
            f"{result_text[:keep_start]}\n"
            f"... [truncated {len(result_text) - limit:,} chars] ...\n"
            f"{result_text[-keep_end:]}"
        )

    def _compact_to_summary(
        self,
        result_text: str,
        tool_name: str,
        goal: str,
        max_chars: int
    ) -> str:
        """Compress to a 2-3 sentence summary using LLM."""

        limit = min(self.max_summary_chars, max_chars)

        if self.enable_llm_summary and len(result_text) > 500:
            try:
                # Truncate input to avoid token overflow in summarization call
                input_text = result_text[:8000] if len(result_text) > 8000 else result_text

                prompt = f"""Summarize this {tool_name} output in 2-3 sentences.
Preserve: function names, addresses, key patterns, important values.
Context: {goal[:200] if goal else 'Binary analysis'}

{input_text}

Summary (2-3 sentences):"""

                summary = self.ollama_client.generate(
                    prompt=prompt,
                    temperature=0.3,
                    max_tokens=150
                )

                if summary and len(summary.strip()) > 20:
                    summary_text = summary.strip()
                    if len(summary_text) > limit:
                        summary_text = summary_text[:limit-3] + "..."
                    return f"[SUMMARY] {summary_text}"

            except Exception as e:
                logger.warning(f"LLM summarization failed: {e}")

        # Fallback: extractive summary
        return self._extractive_summary(result_text, tool_name, limit)

    def _extractive_summary(self, result_text: str, tool_name: str, max_chars: int) -> str:
        """Create summary by extracting key lines (no LLM)."""
        lines = result_text.split('\n')

        # For list-type results, show count + first few
        if tool_name.startswith('list_') or len(lines) > 20:
            preview_lines = [l for l in lines[:5] if l.strip()]
            return f"[SUMMARY] {len(lines)} items. First: {'; '.join(preview_lines)[:max_chars-50]}"

        # For decompiled code, extract signature
        if 'decompile' in tool_name:
            for line in lines[:10]:
                if '(' in line and ')' in line and '{' not in line:
                    return f"[SUMMARY] Function: {line.strip()[:max_chars-30]}"

        # For xrefs, count and sample
        if 'xref' in tool_name:
            return f"[SUMMARY] {len(lines)} cross-references found"

        # Default: first meaningful content
        content = ' '.join(lines[:3])[:max_chars-20]
        return f"[SUMMARY] {content}"

    def _compact_to_statistics(self, result_text: str, tool_name: str, max_chars: int) -> str:
        """Compress to bare statistics only."""
        lines = result_text.split('\n')
        char_count = len(result_text)
        line_count = len(lines)

        # Tool-specific statistics
        if tool_name.startswith('list_'):
            return f"[STATS] {tool_name}: {line_count} items"
        elif 'decompile' in tool_name:
            return f"[STATS] {tool_name}: {line_count} lines, {char_count:,} chars"
        elif 'xref' in tool_name:
            return f"[STATS] {tool_name}: {line_count} references"
        elif 'read_bytes' in tool_name:
            return f"[STATS] {tool_name}: {char_count:,} bytes read"
        else:
            return f"[STATS] {tool_name}: {line_count} lines"

    def _extract_key_findings(self, result_text: str, tool_name: str) -> List[str]:
        """Extract key findings for quick reference."""
        findings = []

        # Look for function names (common pattern: word followed by parentheses)
        import re
        func_matches = re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', result_text[:2000])
        if func_matches:
            unique_funcs = list(dict.fromkeys(func_matches))[:5]
            findings.append(f"Functions: {', '.join(unique_funcs)}")

        # Look for addresses (0x...)
        addr_matches = re.findall(r'0x[0-9a-fA-F]{4,}', result_text[:2000])
        if addr_matches:
            unique_addrs = list(dict.fromkeys(addr_matches))[:3]
            findings.append(f"Addresses: {', '.join(unique_addrs)}")

        # Look for error indicators
        if 'error' in result_text.lower()[:500]:
            findings.append("Contains errors")

        return findings

    def format_for_prompt(
        self,
        compacted_results: List[CompactedResult],
        stats: CompactionStats,
        include_stats_header: bool = True
    ) -> str:
        """
        Format compacted results for inclusion in analysis prompt.

        Args:
            compacted_results: Output from compact()
            stats: Compaction statistics
            include_stats_header: Whether to include compaction stats at top

        Returns:
            Formatted string ready for prompt insertion
        """
        sections = []

        # Optional stats header
        if include_stats_header:
            sections.append(f"[Compaction: {stats.total_results} results → "
                          f"{stats.compacted_chars:,} chars "
                          f"({stats.compression_ratio:.0%} of original)]")
            sections.append("")

        # Group by tier for organized output
        by_tier = defaultdict(list)
        for result in compacted_results:
            by_tier[result.tier].append(result)

        # Full results first (most recent/important)
        if by_tier[CompactionTier.FULL]:
            sections.append("### Recent Results (Full Detail)")
            for r in by_tier[CompactionTier.FULL]:
                sections.append(f"\n**{r.step_id}: {r.tool_name}**")
                sections.append(f"Parameters: {r.parameters}")
                sections.append(f"Result:\n{r.content}")

        # Summaries next
        if by_tier[CompactionTier.SUMMARY]:
            sections.append("\n### Earlier Results (Summarized)")
            for r in by_tier[CompactionTier.SUMMARY]:
                sections.append(f"- **{r.step_id}: {r.tool_name}** - {r.content}")

        # Statistics last
        if by_tier[CompactionTier.STATISTICS]:
            sections.append("\n### Previous Results (Statistics Only)")
            stat_lines = [f"- {r.step_id}: {r.content}" for r in by_tier[CompactionTier.STATISTICS]]
            sections.append('\n'.join(stat_lines))

        # Dropped results warning
        if stats.tier_counts.get("dropped", 0) > 0:
            sections.append(f"\n[⚠️ {stats.tier_counts['dropped']} results dropped due to budget limits]")

        return '\n'.join(sections)

    def create_findings_summary(self, compacted_results: List[CompactedResult]) -> str:
        """Create a quick-reference summary of key findings across all results."""
        all_findings = []
        for r in compacted_results:
            if r.key_findings:
                all_findings.extend([f"{r.step_id}: {f}" for f in r.key_findings])

        if not all_findings:
            return ""

        return "### Key Findings Reference\n" + '\n'.join(all_findings[:20])
