"""Cross-worker tool health tracking.

Tracks per-tool success/failure counts across all workers in an
investigation session.  After a configurable number of global failures
a tool is blacklisted, and the orchestrator is warned not to assign
tasks that depend on it.
"""

import logging
import threading
from typing import Dict, Set

logger = logging.getLogger(__name__)

DEFAULT_FAILURE_THRESHOLD = 5


class ToolHealthTracker:
    """Thread-safe global tool health monitor.

    Instantiated once per investigation (lives on the Blackboard).
    Every worker calls ``record_success`` / ``record_failure`` after
    each tool execution; the orchestrator reads ``get_health_summary``
    when building the next-task prompt.
    """

    def __init__(self, failure_threshold: int = DEFAULT_FAILURE_THRESHOLD):
        self._lock = threading.RLock()
        self.failure_threshold = failure_threshold
        self.tool_successes: Dict[str, int] = {}
        self.tool_failures: Dict[str, int] = {}
        self.blacklisted: Set[str] = set()

    # ── Recording ────────────────────────────────────────────────────

    def record_success(self, tool_name: str) -> None:
        with self._lock:
            self.tool_successes[tool_name] = (
                self.tool_successes.get(tool_name, 0) + 1
            )

    def record_failure(self, tool_name: str) -> None:
        with self._lock:
            count = self.tool_failures.get(tool_name, 0) + 1
            self.tool_failures[tool_name] = count
            if count >= self.failure_threshold and tool_name not in self.blacklisted:
                self.blacklisted.add(tool_name)
                logger.warning(
                    "[ToolHealth] Tool '%s' blacklisted after %d global failures",
                    tool_name,
                    count,
                )

    # ── Queries ──────────────────────────────────────────────────────

    def is_healthy(self, tool_name: str) -> bool:
        with self._lock:
            return tool_name not in self.blacklisted

    def get_health_summary(self) -> str:
        """Return a prompt-injectable summary of unhealthy tools.

        Returns an empty string when every tool is healthy.
        """
        with self._lock:
            if not self.tool_failures:
                return ""

            lines = []

            if self.blacklisted:
                bl = ", ".join(sorted(self.blacklisted))
                lines.append(
                    f"## Tool Health Warning\n"
                    f"The following tools have FAILED repeatedly across workers "
                    f"and are BLACKLISTED — do NOT assign tasks that require them:\n"
                    f"  {bl}"
                )

            degraded = [
                f"{name} ({count} failures)"
                for name, count in sorted(self.tool_failures.items())
                if name not in self.blacklisted and count >= 2
            ]
            if degraded:
                lines.append(
                    "Degraded tools (multiple failures, still usable): "
                    + ", ".join(degraded)
                )

            return "\n".join(lines)

    # ── Reset ────────────────────────────────────────────────────────

    def reset(self) -> None:
        """Clear all counters (called at investigation start)."""
        with self._lock:
            self.tool_successes.clear()
            self.tool_failures.clear()
            self.blacklisted.clear()
