"""Semantic compaction for worker tool execution history.

When a worker's LLM loop runs past a configurable step threshold, older
tool results are compacted into a categorical digest while the most
recent results are preserved in full.  This keeps the context window
useful without unbounded growth.
"""

from typing import Dict, List, Tuple

from src.models.memory import ToolExecution

# Map tool names → semantic categories for digest grouping.
_CATEGORY_MAP: Dict[str, str] = {
    "list_imports": "discovery",
    "list_exports": "discovery",
    "list_strings": "discovery",
    "list_functions": "discovery",
    "search_strings_in_binary": "discovery",
    "decompile_function": "decompilation",
    "decompile_function_by_address": "decompilation",
    "get_xrefs_to": "xrefs",
    "get_xrefs_from": "xrefs",
    "get_function_xrefs": "xrefs",
}

DEFAULT_THRESHOLD = 6
DEFAULT_PRESERVE_RECENT = 4


class WorkerContextCompactor:
    """Compacts older tool executions into a categorical digest.

    Usage::

        compactor = WorkerContextCompactor(threshold=6)
        if compactor.should_compact(step, len(all_executions)):
            digest, preserved = compactor.compact(all_executions)
    """

    def __init__(
        self,
        threshold: int = DEFAULT_THRESHOLD,
        preserve_recent: int = DEFAULT_PRESERVE_RECENT,
    ):
        self.threshold = threshold
        self.preserve_recent = preserve_recent

    def should_compact(self, step: int, total_executions: int) -> bool:
        """Return True when compaction is worthwhile."""
        return (
            step >= self.threshold
            and total_executions > self.preserve_recent
        )

    def compact(
        self, executions: List[ToolExecution]
    ) -> Tuple[str, List[ToolExecution]]:
        """Split executions into a digest string + preserved recent list.

        Returns:
            (digest_string, preserved_recent_executions)
        """
        if len(executions) <= self.preserve_recent:
            return ("", executions)

        cutoff = len(executions) - self.preserve_recent
        older = executions[:cutoff]
        preserved = executions[cutoff:]

        digest = self._build_digest(older)
        return (digest, preserved)

    # ── Internals ────────────────────────────────────────────────────

    @staticmethod
    def _build_digest(executions: List[ToolExecution]) -> str:
        """Group older executions by category and produce a compact digest."""
        categories: Dict[str, List[str]] = {}

        for te in executions:
            cat = _CATEGORY_MAP.get(te.tool_name, "other")
            if cat not in categories:
                categories[cat] = []

            if cat == "discovery":
                categories[cat].append(te.tool_name)
            elif cat == "decompilation":
                addr = te.parameters.get(
                    "address", te.parameters.get("name", "?")
                )
                categories[cat].append(str(addr))
            elif cat == "xrefs":
                addr = te.parameters.get(
                    "address", te.parameters.get("name", "?")
                )
                categories[cat].append(f"{te.tool_name}({addr})")
            else:
                param_str = ", ".join(
                    f"{k}={v!r}" for k, v in list(te.parameters.items())[:2]
                )
                status = "OK" if te.success else "ERR"
                categories[cat].append(
                    f"{te.tool_name}({param_str}) [{status}]"
                )

        lines = ["## Earlier Work (compacted digest)"]

        if "discovery" in categories:
            tools = categories["discovery"]
            unique = sorted(set(tools))
            lines.append(
                f"- **Discovery**: {len(tools)} calls "
                f"({', '.join(unique)})"
            )

        if "decompilation" in categories:
            addrs = categories["decompilation"]
            lines.append(
                f"- **Decompilation**: analyzed {len(addrs)} functions "
                f"({', '.join(addrs[:10])}"
                f"{'...' if len(addrs) > 10 else ''})"
            )

        if "xrefs" in categories:
            refs = categories["xrefs"]
            lines.append(
                f"- **Xref lookups**: {len(refs)} traces "
                f"({', '.join(refs[:8])}"
                f"{'...' if len(refs) > 8 else ''})"
            )

        if "other" in categories:
            others = categories["other"]
            lines.append(
                f"- **Other**: {len(others)} calls "
                f"({', '.join(others[:6])}"
                f"{'...' if len(others) > 6 else ''})"
            )

        return "\n".join(lines)
