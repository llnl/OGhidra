"""
BlackboardAccess — Unified interface to the shared investigation blackboard.

All investigation state lives in discrete components (SessionMemory,
CoverageTracker, LeadTracker, FunctionRegistry, InvestigationNotebook,
ContextManager).  BlackboardAccess wraps them in a single object that the
Orchestrator, WorkerAgent, and ToolExecutor can query and update without
knowing where each piece of data is stored.

Design goals:
  - Read methods are cheap (no LLM calls, no I/O).
  - Write methods update exactly one component.
  - ``format_for_prompt`` helpers produce text suitable for injection into
    system prompts via SystemContextBuilder.
"""

import logging
from typing import List, Dict, Optional, Any

from src.models.memory import (
    AnalysisState,
    DiscoveryCache,
    FunctionAnalysis,
    FunctionRegistry,
    NotebookEntry,
    InvestigationNotebook,
    KnowledgeArtifact,
    SessionMemory,
)
from src.coverage_tracker import CoverageTracker
from src.lead_tracker import LeadTracker
from src.context_manager import ContextManager
from src.tool_health import ToolHealthTracker


class BlackboardAccess:
    """
    Unified read/write facade over every shared investigation component.

    Constructed once per investigation and shared by reference.

    Usage::

        blackboard = BlackboardAccess(session, coverage, leads, context_mgr)
        prompt_section = blackboard.get_coverage_prompt()
        blackboard.register_function(my_analysis)
    """

    def __init__(
        self,
        session: SessionMemory,
        coverage: CoverageTracker,
        leads: LeadTracker,
        context_manager: Optional[ContextManager] = None,
        function_registry: Optional[FunctionRegistry] = None,
        notebook: Optional[InvestigationNotebook] = None,
        discovery_cache: Optional[DiscoveryCache] = None,
        tool_health: Optional[ToolHealthTracker] = None,
        logger: Optional[logging.Logger] = None,
    ):
        self.session = session
        self.coverage = coverage
        self.leads = leads
        self.context_manager = context_manager
        self.function_registry = function_registry or FunctionRegistry()
        self.notebook = notebook or InvestigationNotebook()
        self.discovery_cache = discovery_cache or DiscoveryCache()
        self.tool_health = tool_health or ToolHealthTracker()
        self.logger = logger or logging.getLogger(__name__)

        # Total functions in the binary (set during investigation initialization
        # if available from analysis state).  Used for function-level coverage.
        self.total_binary_functions: int = 0

        # Code cache: address → decompiled source code.
        # Persists full function code across worker boundaries so the
        # orchestrator and final report can reference actual code, not just
        # 1-2 sentence FunctionAnalysis summaries.
        self._code_cache: Dict[str, str] = {}

    # ------------------------------------------------------------------
    # Analysis State reads
    # ------------------------------------------------------------------

    def get_analysis_state(self) -> AnalysisState:
        """Return the current AnalysisState model."""
        return self.session.analysis_state

    def get_functions_decompiled(self) -> set:
        return self.session.analysis_state.functions_decompiled

    def get_functions_renamed(self) -> Dict[str, str]:
        return self.session.analysis_state.functions_renamed

    def get_functions_analyzed(self) -> set:
        return self.session.analysis_state.functions_analyzed

    # ------------------------------------------------------------------
    # Knowledge reads
    # ------------------------------------------------------------------

    def get_knowledge_summary(self) -> str:
        """Formatted summary of all persistent knowledge artifacts."""
        return self.session.get_knowledge_summary()

    def get_knowledge_artifacts(self) -> List[KnowledgeArtifact]:
        return self.session.knowledge_base

    # ------------------------------------------------------------------
    # Coverage reads / writes
    # ------------------------------------------------------------------

    def get_coverage_prompt(self) -> str:
        """Coverage prompt section ready for system prompt injection."""
        return self.coverage.format_for_prompt()

    def get_uncovered_areas(self) -> List[str]:
        return [area.name for area in self.coverage.get_uncovered()]

    def coverage_ratio(self) -> float:
        return self.coverage.coverage_ratio()

    def function_coverage_ratio(self) -> float:
        """Ratio of analyzed functions to total binary functions.

        Returns 0.0 if total_binary_functions is not set.
        """
        if self.total_binary_functions == 0:
            return 0.0
        return self.function_registry.analyzed_count / self.total_binary_functions

    def mark_coverage(self, area_name: str, tool_used: str, result_summary: str = ""):
        self.coverage.mark_covered(area_name, tool_used, result_summary)

    # ------------------------------------------------------------------
    # Lead reads / writes
    # ------------------------------------------------------------------

    def get_leads_prompt(self) -> str:
        """Leads prompt section ready for system prompt injection."""
        return self.leads.format_for_prompt()

    def get_active_leads(self, limit: int = 5) -> list:
        return self.leads.get_active_leads(limit=limit)

    def add_lead(self, description: str, priority: str = "MEDIUM", address: str = None) -> bool:
        return self.leads.add_lead(description, priority, address)

    def mark_lead_completed(self, description_partial: str):
        self.leads.mark_completed(description_partial)

    # ------------------------------------------------------------------
    # Function Registry reads / writes
    # ------------------------------------------------------------------

    def get_function_registry_prompt(self, max_entries: int = 20) -> str:
        """Function registry prompt section for system prompt injection."""
        return self.function_registry.format_for_prompt(max_entries=max_entries)

    def get_orchestrator_registry_prompt(self, max_entries: int = 30) -> str:
        """Function registry formatted for orchestrator task creation.

        Groups functions by analysis depth and flags over-decompiled ones,
        helping the orchestrator avoid assigning redundant work.
        """
        return self.function_registry.format_for_orchestrator(max_entries=max_entries)

    def is_function_analyzed(self, address: str) -> bool:
        return self.function_registry.is_analyzed(address)

    def get_function_analysis(self, address: str) -> Optional[FunctionAnalysis]:
        return self.function_registry.get(address)

    def get_functions_by_tag(self, tag: str) -> List[FunctionAnalysis]:
        return self.function_registry.get_by_tag(tag)

    def get_functions_with_security_notes(self) -> List[FunctionAnalysis]:
        return self.function_registry.get_with_security_notes()

    def register_function(self, analysis: FunctionAnalysis):
        self.function_registry.register(analysis)
        self.logger.debug(f"Registered function analysis: {analysis.name} @ {analysis.address}")

    # ------------------------------------------------------------------
    # Investigation Notebook reads / writes
    # ------------------------------------------------------------------

    def get_notebook_prompt(self, max_entries: int = 15) -> str:
        """Notebook prompt section for system prompt injection."""
        return self.notebook.format_for_prompt(max_entries=max_entries)

    def get_notebook_report(self) -> str:
        """Full notebook formatted as the final investigation report."""
        return self.notebook.format_as_report()

    def get_high_severity_findings(self) -> List[NotebookEntry]:
        return self.notebook.get_high_severity()

    def get_findings_needing_investigation(self) -> List[NotebookEntry]:
        return self.notebook.get_needing_investigation()

    def add_notebook_entry(self, entry: NotebookEntry):
        self.notebook.add_finding(entry)
        self.logger.debug(f"Notebook entry added: [{entry.severity}] {entry.title}")

    def add_task_completed(self, task_id: str, summary: str):
        """Record that a worker task completed (metadata for orchestrator)."""
        self.notebook.add_task_completed(f"{task_id}: {summary}")

    # ------------------------------------------------------------------
    # Discovery Cache reads / writes
    # ------------------------------------------------------------------

    def get_discovery_prompt(self, max_imports: int = 40, max_strings: int = 20) -> str:
        """Discovery cache prompt section for system prompt injection."""
        return self.discovery_cache.format_for_prompt(
            max_imports=max_imports, max_strings=max_strings
        )

    def get_tool_health_prompt(self) -> str:
        """Tool health summary for system prompt injection."""
        return self.tool_health.get_health_summary()

    def cache_discovery(self, tool_name: str, params: dict, result_lines: List[str]) -> None:
        """Store raw tool results in the discovery cache for reuse by future workers.

        Automatically routes to the correct cache slot based on tool_name.

        Args:
            tool_name: The tool that produced the results (e.g., ``"list_imports"``).
            params: The parameters the tool was called with.
            result_lines: Parsed result lines to cache.
        """
        if not result_lines:
            return

        if tool_name == "list_imports":
            self.discovery_cache.store_imports(result_lines)
            self.logger.debug(
                f"Cached {len(result_lines)} import entries"
            )
        elif tool_name == "list_exports":
            self.discovery_cache.store_exports(result_lines)
            self.logger.debug(
                f"Cached {len(result_lines)} export entries"
            )
        elif tool_name in ("list_strings", "search_strings_in_binary"):
            filter_key = params.get("filter", params.get("search_term", "all"))
            self.discovery_cache.store_strings(str(filter_key), result_lines)
            self.logger.debug(
                f"Cached {len(result_lines)} string entries (filter={filter_key})"
            )
        elif tool_name == "list_functions":
            # Extract total from result if possible
            import re
            total = 0
            for line in result_lines[-3:]:
                m = re.search(r"(?:total|found)[:\s]*(\d+)", line, re.IGNORECASE)
                if m:
                    total = int(m.group(1))
                    break
            self.discovery_cache.store_functions(result_lines, total=total)
            self.logger.debug(
                f"Cached {len(result_lines)} function entries (total={total})"
            )

    # ------------------------------------------------------------------
    # Code cache reads / writes
    # ------------------------------------------------------------------

    def cache_code(self, address: str, code: str) -> None:
        """Store decompiled function code in the persistent code cache.

        Called by workers after decompilation so the code survives beyond
        the worker's lifetime.  The orchestrator and final report can then
        reference actual source instead of 1-2 sentence summaries.

        Args:
            address: Normalized hex address (e.g., ``"00405b60"``).
            code: Full decompiled C source.
        """
        if not address or not code:
            return
        self._code_cache[address] = code
        self.logger.debug(
            f"Code cache updated: {address} ({len(code)} chars, "
            f"{len(code.splitlines())} lines)"
        )

    def cache_code_bulk(self, functions: Dict[str, str]) -> None:
        """Bulk-store decompiled function code.

        Convenience wrapper used by recipe mode to persist
        ``RecipeResult.gathered_functions`` in one call.
        """
        for addr, code in functions.items():
            self.cache_code(addr, code)

    def get_cached_code(self, address: str) -> Optional[str]:
        """Retrieve cached decompiled code for a function address."""
        return self._code_cache.get(address)

    def get_all_cached_code(self) -> Dict[str, str]:
        """Return the full code cache (address → source)."""
        return dict(self._code_cache)

    def get_code_cache_summary(self, max_functions: int = 10,
                                max_lines_per_func: int = 50) -> str:
        """Format cached code for inclusion in report prompts.

        Returns a compact summary with the first ``max_lines_per_func``
        lines of each cached function, prioritizing functions that appear
        in notebook entries or have security notes.
        """
        if not self._code_cache:
            return ""

        # Prioritize functions referenced in notebook findings
        finding_addrs = set()
        for entry in self.notebook.entries:
            finding_addrs.update(entry.addresses)

        # Also prioritize functions with security notes
        sec_addrs = {
            fa.address for fa in self.get_functions_with_security_notes()
        }
        priority_addrs = finding_addrs | sec_addrs

        # Sort: priority functions first, then remaining
        sorted_addrs = sorted(
            self._code_cache.keys(),
            key=lambda a: (a not in priority_addrs, a),
        )

        parts = []
        for addr in sorted_addrs[:max_functions]:
            code = self._code_cache[addr]
            lines = code.splitlines()
            # Get function name from registry if available
            fa = self.function_registry.get(addr)
            name = fa.name if fa else f"FUN_{addr}"
            if len(lines) > max_lines_per_func:
                snippet = "\n".join(lines[:max_lines_per_func])
                snippet += f"\n... ({len(lines) - max_lines_per_func} more lines)"
            else:
                snippet = code
            parts.append(f"### {name} @ {addr}\n```c\n{snippet}\n```")

        return "\n\n".join(parts)

    # ------------------------------------------------------------------
    # Knowledge writes
    # ------------------------------------------------------------------

    def add_knowledge(self, key: str, value: str, category: str = "general", tags: List[str] = None):
        """Persist a knowledge artifact to session memory."""
        self.session.add_knowledge(key, value, category, tags)

    # ------------------------------------------------------------------
    # Composite queries (used by orchestrator for task planning)
    # ------------------------------------------------------------------

    def get_investigation_summary(self) -> Dict[str, Any]:
        """Return a compact dict summarizing the entire investigation state.

        Useful for the orchestrator's LLM call to decide the next task.
        """
        # Function coverage string
        analyzed_count = self.function_registry.analyzed_count
        if self.total_binary_functions > 0:
            func_cov = (
                f"{analyzed_count}/{self.total_binary_functions} "
                f"({analyzed_count / self.total_binary_functions:.0%})"
            )
        else:
            func_cov = (
                f"{analyzed_count} analyzed "
                f"(total unknown — use list_functions to enumerate)"
            )

        return {
            "coverage_ratio": self.coverage_ratio(),
            "uncovered_areas": self.get_uncovered_areas(),
            "active_leads_count": len(self.get_active_leads(limit=100)),
            "top_leads": [
                {"description": lead.description, "priority": lead.priority}
                for lead in self.get_active_leads(limit=5)
            ],
            "functions_registered": len(self.function_registry.functions),
            "function_coverage": func_cov,
            "functions_with_security_notes": len(self.get_functions_with_security_notes()),
            "notebook_entries_count": len(self.notebook.entries),
            "high_severity_count": len(self.get_high_severity_findings()),
            "needs_investigation_count": len(self.get_findings_needing_investigation()),
        }
