"""
Orchestrator Investigation Logger — Persistent debug log for orchestrator runs.

Captures the full lifecycle of an orchestrator investigation in a structured
markdown file saved to ``logs/``.  This provides post-hoc visibility into:

  - Strategy classification decision
  - Each cycle: task created, worker results, notebook entries (accepted + rejected)
  - Coverage progression per cycle
  - Correlation rule firings
  - The final synthesized report
  - Performance metrics (timing, tool counts, token estimates)

The log is written incrementally (flushed after each cycle) so that even
investigations that crash mid-way leave useful diagnostic data on disk.

Usage::

    logger = OrchestratorLogger()          # auto-creates timestamped file
    logger.log_start(query, strategy, config_info)
    logger.log_cycle_start(cycle, coverage_ratio, func_count, func_total)
    logger.log_task_created(task)
    logger.log_worker_result(result)
    logger.log_notebook_update(accepted, rejected)
    logger.log_correlation_fired(rule_name, task_goal)
    logger.log_cycle_end(cycle, coverage_ratio)
    logger.log_final_report(report, exit_reason, cycles, metrics)
    filepath = logger.filepath                # retrieve saved file path
"""

import logging
import os
from datetime import datetime
from typing import Optional, List, Dict, Any

logger = logging.getLogger("oghidra.orchestrator_logger")


class OrchestratorLogger:
    """Persistent investigation log writer for orchestrator runs."""

    def __init__(self, logs_dir: Optional[str] = None):
        if logs_dir is None:
            src_dir = os.path.dirname(os.path.abspath(__file__))
            logs_dir = os.path.join(os.path.dirname(src_dir), "logs")

        self.logs_dir = logs_dir
        os.makedirs(logs_dir, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self._filename = f"orchestrator_{timestamp}.md"
        self.filepath = os.path.join(logs_dir, self._filename)

        self._start_time = datetime.now()
        self._buffer: List[str] = []
        self._flushed = False

        logger.info(f"OrchestratorLogger: will write to {self.filepath}")

    # ──────────────────────────────────────────────────────────────────
    # Lifecycle events
    # ──────────────────────────────────────────────────────────────────

    def log_start(
        self,
        query: str,
        strategy: str,
        max_cycles: int,
        soft_limit: int,
        worker_max_steps: int,
        worker_soft_limit: int,
    ):
        """Log investigation start with configuration."""
        self._write("# Orchestrator Investigation Log\n")
        self._write(f"**Started:** {self._start_time.isoformat()}")
        self._write(f"**Query:** {query}")
        self._write(f"**Strategy:** {strategy}\n")
        self._write("## Configuration")
        self._write(f"| Setting | Value |")
        self._write(f"|---------|-------|")
        self._write(f"| Max cycles | {max_cycles} |")
        self._write(f"| Soft limit | {soft_limit} |")
        self._write(f"| Worker max steps | {worker_max_steps} |")
        self._write(f"| Worker soft limit | {worker_soft_limit} |")
        self._write("")
        self._flush()

    def log_cycle_start(
        self,
        cycle: int,
        coverage_ratio: float,
        functions_analyzed: int,
        functions_total: int,
    ):
        """Log the beginning of an orchestrator cycle."""
        self._write(f"\n---\n## Cycle {cycle}")
        self._write(f"**Area coverage:** {coverage_ratio:.0%}")
        if functions_total > 0:
            self._write(
                f"**Functions analyzed:** {functions_analyzed}/{functions_total} "
                f"({functions_analyzed / functions_total:.1%})"
            )
        elif functions_analyzed > 0:
            self._write(f"**Functions analyzed:** {functions_analyzed}")

    def log_task_created(self, task_goal: str, task_details: Dict[str, Any]):
        """Log the task the orchestrator created for this cycle."""
        self._write(f"\n### Task Created")
        self._write(f"**Goal:** {task_goal}")
        if task_details.get("strategy_hint"):
            self._write(f"**Strategy hint:** {task_details['strategy_hint'][:200]}")
        if task_details.get("focus_addresses"):
            self._write(f"**Focus addresses:** {task_details['focus_addresses']}")
        if task_details.get("suggested_tools"):
            self._write(f"**Suggested tools:** {', '.join(task_details['suggested_tools'])}")
        if task_details.get("focus_areas"):
            self._write(f"**Focus areas:** {', '.join(task_details['focus_areas'])}")
        self._write(
            f"**Budget:** soft={task_details.get('soft_limit', '?')}, "
            f"max={task_details.get('max_steps', '?')}"
        )

    def log_worker_result(
        self,
        task_id: str,
        exit_reason: str,
        real_tool_count: int,
        is_complete: bool,
        findings_summary: str,
        tool_executions: Optional[List[Dict[str, Any]]] = None,
    ):
        """Log worker execution results."""
        self._write(f"\n### Worker Result")
        self._write(f"**Task:** {task_id}")
        self._write(f"**Exit:** {exit_reason} | **Tools:** {real_tool_count} | **Complete:** {is_complete}")

        if findings_summary:
            self._write(f"\n**Findings summary:**")
            # Cap at 500 chars to keep log readable
            self._write(f"```\n{findings_summary[:500]}\n```")

        if tool_executions:
            self._write(f"\n**Tool execution log:**")
            for te in tool_executions:
                name = te.get("tool_name", "?")
                if name == "<no_command>":
                    continue
                success = "OK" if te.get("success") else "ERR"
                result_preview = (te.get("result", "") or "")[:150]
                params_str = str(te.get("parameters", {}))[:100]
                self._write(f"- `{name}({params_str})` → [{success}] {result_preview}")

    def log_notebook_update(
        self,
        accepted: List[Dict[str, str]],
        rejected: List[Dict[str, str]],
    ):
        """Log notebook entries that were accepted and rejected."""
        self._write(f"\n### Notebook Update")
        if accepted:
            self._write(f"**Accepted ({len(accepted)}):**")
            for entry in accepted:
                self._write(
                    f"- [{entry.get('severity', '?').upper()}] "
                    f"{entry.get('title', '?')} ({entry.get('status', '?')})"
                )
        if rejected:
            self._write(f"**Rejected ({len(rejected)}):**")
            for entry in rejected:
                self._write(
                    f"- ~~[{entry.get('severity', '?').upper()}] "
                    f"{entry.get('title', '?')}~~ — {entry.get('reason', 'filtered')}"
                )
        if not accepted and not rejected:
            self._write("No entries generated.")

    def log_correlation_fired(self, rule_name: str, task_goal: str):
        """Log when a vulnerability correlation rule fires."""
        self._write(f"\n### Correlation Rule Fired")
        self._write(f"**Rule:** `{rule_name}`")
        self._write(f"**Injected task:** {task_goal[:200]}")

    def log_cycle_end(self, cycle: int, coverage_ratio: float):
        """Flush the cycle's data to disk."""
        self._write(f"\n*Cycle {cycle} complete — coverage now {coverage_ratio:.0%}*")
        self._flush()

    def log_final_report(
        self,
        report: str,
        exit_reason: str,
        cycles_used: int,
        metrics: Dict[str, Any],
    ):
        """Log the final synthesized report and investigation metrics."""
        elapsed = (datetime.now() - self._start_time).total_seconds()

        self._write(f"\n---\n## Investigation Complete")
        self._write(f"**Exit reason:** {exit_reason}")
        self._write(f"**Cycles used:** {cycles_used}")
        self._write(f"**Elapsed time:** {elapsed:.1f}s")
        self._write(f"**Area coverage:** {metrics.get('coverage_ratio', 0):.0%}")
        self._write(
            f"**Functions analyzed:** {metrics.get('functions_analyzed', 0)}"
            f"/{metrics.get('functions_total', '?')}"
        )
        self._write(
            f"**Notebook entries:** {metrics.get('notebook_entries', 0)} "
            f"({metrics.get('confirmed_count', 0)} confirmed)"
        )

        self._write(f"\n---\n## Final Report\n")
        self._write(report)

        self._write(f"\n---\n*Log saved to: {self.filepath}*")
        self._write(f"*Completed: {datetime.now().isoformat()}*")
        self._flush()
        logger.info(f"OrchestratorLogger: investigation log saved to {self.filepath}")

    # ──────────────────────────────────────────────────────────────────
    # Internal
    # ──────────────────────────────────────────────────────────────────

    def _write(self, line: str):
        """Append a line to the buffer."""
        self._buffer.append(line)

    def _flush(self):
        """Write buffered content to disk (append mode)."""
        try:
            mode = "a" if self._flushed else "w"
            with open(self.filepath, mode, encoding="utf-8") as f:
                f.write("\n".join(self._buffer) + "\n")
            self._buffer.clear()
            self._flushed = True
        except Exception as e:
            logger.warning(f"OrchestratorLogger flush failed: {e}")
