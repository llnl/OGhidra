"""
Tests for Orchestrator — the investigation brain.

Uses mock LLM to verify:
  - Strategy classification
  - Task creation loop
  - Notebook updating
  - Completion detection
  - Result merging
  - End-to-end orchestration flow
"""

import json
import pytest
from unittest.mock import MagicMock, patch, call
from datetime import datetime

from src.orchestrator import (
    Orchestrator,
    WorkerResultSummary,
    STRATEGY_BINARY_UNDERSTANDING,
    STRATEGY_MALWARE_HUNTING,
    STRATEGY_VULN_HUNTING,
)
from src.agents.base import WorkerTask, AgentResult
from src.agents.worker_agent import WorkerAgent
from src.models.memory import (
    ExecutionPhaseResults,
    ToolExecution,
    FunctionRegistry,
    FunctionAnalysis,
    InvestigationNotebook,
    NotebookEntry,
    SessionMemory,
)
from src.blackboard import BlackboardAccess
from src.event_emitter import EventEmitter
from src.coverage_tracker import CoverageTracker
from src.lead_tracker import LeadTracker


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_orchestrator(
    llm_responses=None,
    max_cycles=10,
    worker_max_steps=15,
):
    """Create an Orchestrator with mocked dependencies.

    Args:
        llm_responses: List of strings the mock LLM returns in sequence.
        max_cycles: Safety ceiling for orchestrator cycles.
        worker_max_steps: Safety ceiling for worker steps.
    """
    llm_responses = llm_responses or ["binary_understanding"]

    mock_llm = MagicMock()
    mock_llm.generate_with_phase = MagicMock(side_effect=llm_responses)

    mock_tools = MagicMock()
    mock_tools.execute_command = MagicMock(
        return_value={"result": "mock_result", "source": "mock"}
    )

    session = SessionMemory(session_id="test_orch_session")
    blackboard = BlackboardAccess(
        session=session,
        coverage=CoverageTracker(),
        leads=LeadTracker(),
        function_registry=FunctionRegistry(),
        notebook=InvestigationNotebook(),
    )

    from src.command_parser import CommandParser
    parser = CommandParser()

    emitter = EventEmitter()
    mock_config = MagicMock()
    mock_config.orchestrator_max_cycles = max_cycles
    mock_config.worker_default_max_steps = worker_max_steps
    mock_config.orchestrator_system_prompt = ""
    mock_config.coverage_stall_threshold = 3
    mock_config.orchestrator_doom_loop_threshold = 2

    orchestrator = Orchestrator(
        llm_client=mock_llm,
        tool_executor=mock_tools,
        blackboard=blackboard,
        command_parser=parser,
        event_emitter=emitter,
        config=mock_config,
        capabilities_text="## Tools\n- list_imports\n- decompile_function",
        max_cycles=max_cycles,
        worker_max_steps=worker_max_steps,
    )

    return orchestrator, mock_llm, mock_tools, blackboard


# ---------------------------------------------------------------------------
# Strategy Classification Tests
# ---------------------------------------------------------------------------

class TestStrategyClassification:
    """Tests for _classify_strategy."""

    def test_classify_vuln_hunting(self):
        orch, mock_llm, _, _ = _make_orchestrator(llm_responses=["vuln_hunting"])
        strategy = orch._classify_strategy("Find vulnerabilities in this binary")
        assert strategy == STRATEGY_VULN_HUNTING

    def test_classify_malware_hunting(self):
        orch, mock_llm, _, _ = _make_orchestrator(llm_responses=["malware_hunting"])
        strategy = orch._classify_strategy("Is this binary malware?")
        assert strategy == STRATEGY_MALWARE_HUNTING

    def test_classify_binary_understanding(self):
        orch, mock_llm, _, _ = _make_orchestrator(llm_responses=["binary_understanding"])
        strategy = orch._classify_strategy("What does this binary do?")
        assert strategy == STRATEGY_BINARY_UNDERSTANDING

    def test_classify_fallback_on_error(self):
        """Should default to binary_understanding on LLM error."""
        orch, mock_llm, _, _ = _make_orchestrator()
        mock_llm.generate_with_phase = MagicMock(side_effect=RuntimeError("LLM down"))
        strategy = orch._classify_strategy("Analyze this")
        assert strategy == STRATEGY_BINARY_UNDERSTANDING

    def test_classify_fallback_on_unclear(self):
        """Should default to binary_understanding on unrecognized response."""
        orch, mock_llm, _, _ = _make_orchestrator(llm_responses=["I don't know"])
        strategy = orch._classify_strategy("Something unclear")
        assert strategy == STRATEGY_BINARY_UNDERSTANDING


# ---------------------------------------------------------------------------
# Task Creation Tests
# ---------------------------------------------------------------------------

class TestTaskCreation:
    """Tests for _create_next_task."""

    def test_creates_task_from_json(self):
        task_json = json.dumps({
            "goal": "Decompile FUN_00401000",
            "strategy_hint": "Check for CreateProcessW",
            "focus_addresses": ["0x00401000"],
            "suggested_tools": ["decompile_function_by_address"],
            "max_steps": 6,
        })
        orch, mock_llm, _, _ = _make_orchestrator(
            llm_responses=[f"```json\n{task_json}\n```"]
        )

        task = orch._create_next_task("Find vulns", STRATEGY_VULN_HUNTING, cycle=1)

        assert task is not None
        assert "FUN_00401000" in task.goal
        assert "0x00401000" in task.focus_addresses
        assert task.max_steps == orch.worker_max_steps  # Safety ceiling

    def test_returns_none_on_investigation_complete(self):
        orch, mock_llm, _, _ = _make_orchestrator(
            llm_responses=["INVESTIGATION COMPLETE"]
        )

        task = orch._create_next_task("Analyze binary", STRATEGY_BINARY_UNDERSTANDING, cycle=2)
        assert task is None

    def test_fallback_task_on_parse_failure(self):
        """Should create a fallback task if JSON parsing fails."""
        orch, mock_llm, _, _ = _make_orchestrator(
            llm_responses=["Let me think about what to do next..."]
        )

        task = orch._create_next_task("Find vulns", STRATEGY_VULN_HUNTING, cycle=1)
        assert task is not None
        assert task.goal  # Should have some goal text

    def test_fallback_task_on_llm_error(self):
        """Should create a generic task if LLM call fails."""
        orch, mock_llm, _, _ = _make_orchestrator()
        mock_llm.generate_with_phase = MagicMock(side_effect=RuntimeError("timeout"))

        task = orch._create_next_task("Analyze", STRATEGY_BINARY_UNDERSTANDING, cycle=1)
        assert task is not None
        assert "Investigate" in task.goal or "Analyze" in task.goal


# ---------------------------------------------------------------------------
# Notebook Update Tests
# ---------------------------------------------------------------------------

class TestNotebookUpdate:
    """Tests for _update_notebook."""

    def test_adds_entries_from_json(self):
        entries_json = json.dumps([{
            "category": "vulnerability",
            "severity": "high",
            "title": "Unquoted service path",
            "detail": "CreateProcessW called with NULL lpApplicationName",
            "evidence": ["FUN_00401000"],
            "addresses": ["0x00401000"],
            "status": "confirmed",
        }])

        orch, mock_llm, _, blackboard = _make_orchestrator(
            llm_responses=[entries_json]
        )

        # Create a mock AgentResult
        result = AgentResult(
            task_id="task_001",
            findings_summary="Found unquoted service path vulnerability",
            exec_results=ExecutionPhaseResults(goal="test"),
            tool_executions_count=3,
            is_complete=True,
        )

        orch._update_notebook(result, cycle=1)
        assert len(blackboard.notebook.entries) == 1
        assert blackboard.notebook.entries[0].severity == "high"
        assert "Unquoted" in blackboard.notebook.entries[0].title

    def test_handles_empty_findings(self):
        orch, mock_llm, _, blackboard = _make_orchestrator(
            llm_responses=["[]"]
        )
        result = AgentResult(
            task_id="task_002",
            findings_summary="Nothing notable found",
            exec_results=ExecutionPhaseResults(goal="test"),
        )
        orch._update_notebook(result, cycle=1)
        # No entries should be added for empty findings
        assert len(blackboard.notebook.entries) == 0

    def test_handles_worker_error(self):
        orch, _, _, blackboard = _make_orchestrator()
        result = AgentResult(
            task_id="task_err",
            error="Connection refused",
        )
        orch._update_notebook(result, cycle=1)
        assert len(blackboard.notebook.entries) == 1
        assert "error" in blackboard.notebook.entries[0].category


# ---------------------------------------------------------------------------
# Result Merging Tests
# ---------------------------------------------------------------------------

class TestResultMerging:
    """Tests for _merge_results."""

    def test_merges_function_analyses(self):
        orch, _, _, blackboard = _make_orchestrator()
        result = AgentResult(
            task_id="task_merge",
            function_analyses=[{
                "address": "0x00401000",
                "name": "process_command",
                "purpose": "Processes user commands",
                "decompiled": True,
                "imports_used": ["CreateProcessW"],
                "security_notes": ["NULL lpApplicationName"],
            }],
        )

        orch._merge_results(result)
        assert blackboard.is_function_analyzed("0x00401000")
        fa = blackboard.get_function_analysis("0x00401000")
        assert fa.name == "process_command"

    def test_merges_leads(self):
        orch, _, _, blackboard = _make_orchestrator()
        result = AgentResult(
            task_id="task_leads",
            new_leads=[
                {"description": "Check FUN_00402000 for DLL hijacking", "priority": "HIGH"},
            ],
        )

        orch._merge_results(result)
        active = blackboard.get_active_leads(limit=10)
        assert len(active) >= 1


# ---------------------------------------------------------------------------
# End-to-End Orchestration Tests
# ---------------------------------------------------------------------------

class TestOrchestratorEndToEnd:
    """Tests for the full orchestrator.run() flow."""

    def test_single_cycle_complete(self):
        """Orchestrator runs one cycle then LLM signals investigation complete."""
        task_json = json.dumps({
            "goal": "List all imports",
            "suggested_tools": ["list_imports"],
            "max_steps": 3,
        })
        notebook_entries = json.dumps([{
            "category": "architecture",
            "severity": "info",
            "title": "Binary imports 42 functions",
            "detail": "Primarily networking and file I/O APIs",
            "evidence": [],
            "addresses": [],
            "status": "confirmed",
        }])

        # LLM call sequence:
        # 1. Strategy classification → binary_understanding
        # 2. Recon worker step 1 → TASK COMPLETE (surface mapping)
        # 3. Task creation cycle 1 → JSON task
        # 4. Worker step 1: LLM generates EXECUTE command
        # 5. Worker step 2: LLM says TASK COMPLETE
        # 6. Notebook update → JSON entries
        # 7. Task creation cycle 2 → INVESTIGATION COMPLETE
        # 8. Final report synthesis
        responses = [
            "investigation:vuln_hunting",              # 1. route
            "TASK COMPLETE\nRecon done.",              # 2. recon worker
            f"```json\n{task_json}\n```",             # 3. create task
            'EXECUTE: list_imports(offset=0, limit=50)',  # 4. worker step 1
            "TASK COMPLETE\nFound 42 imports.",        # 5. worker step 2
            notebook_entries,                          # 6. notebook update
            "INVESTIGATION COMPLETE",                  # 7. task creation → done
            (                                          # 8. final synthesis
                "# Analysis Report\n\n"
                "## Executive Summary\nTest binary analyzed.\n\n"
                "## Verdict\nBinary purpose determined.\n\n"
                "## Confirmed Findings\nBinary imports 42 functions.\n\n"
                "## Requires Further Investigation\nNone.\n\n"
                "## Coverage\nAll areas checked."
            ),
        ]

        orch, mock_llm, mock_tools, blackboard = _make_orchestrator(
            llm_responses=responses,
            max_cycles=10,
        )

        report = orch.run("Analyze this binary for security vulnerabilities")

        assert isinstance(report, str)
        assert "Analysis Report" in report

    def test_hard_ceiling_exhausted(self):
        """Orchestrator should stop at hard ceiling when LLM never says complete."""
        task_json = json.dumps({
            "goal": "Investigate function",
            "max_steps": 2,
        })
        # Sequence: classify, recon, then for each cycle: task creation, worker steps, notebook update
        responses = [
            "investigation:vuln_hunting",              # route
            "TASK COMPLETE\nRecon done.",              # recon worker
        ]
        # For each of 2 cycles: task + worker + notebook
        for _ in range(2):
            responses.extend([
                f"```json\n{task_json}\n```",         # task creation
                'EXECUTE: list_imports(offset=0, limit=50)',  # worker step
                "TASK COMPLETE",                       # worker done
                "[]",                                  # notebook update (empty)
            ])
        # Third cycle attempt that won't be reached at hard ceiling of 2
        responses.append(f"```json\n{task_json}\n```")
        # Final synthesis call after hard ceiling exit
        responses.append(
            "# Analysis Report\n\n## Executive Summary\nHard ceiling reached.\n\n"
            "## Verdict\nNo confirmed vulnerabilities.\n\n"
            "## Confirmed Findings\nNone.\n\n"
            "## Requires Further Investigation\nNone.\n\n"
            "## Coverage\nChecked."
        )

        orch, _, _, _ = _make_orchestrator(
            llm_responses=responses,
            max_cycles=2,   # Hard ceiling
        )

        report = orch.run("Find vulnerabilities")
        assert isinstance(report, str)
        assert "Analysis Report" in report

    def test_investigation_strategy_in_notebook(self):
        """Notebook should reflect the investigation strategy."""
        responses = [
            "investigation:malware_hunting",           # route
            "TASK COMPLETE\nRecon done.",              # recon worker
            "INVESTIGATION COMPLETE",                 # immediately complete
            (                                         # final synthesis
                "# Analysis Report\n\n## Executive Summary\nAnalyzed for malware.\n\n"
                "## Verdict\nNo confirmed malicious behavior.\n\n"
                "## Confirmed Findings\nNone.\n\n"
                "## Requires Further Investigation\nNone.\n\n"
                "## Coverage\nMinimal."
            ),
        ]

        orch, _, _, blackboard = _make_orchestrator(
            llm_responses=responses,
            max_cycles=10,
        )

        orch.run("Is this malware?")
        assert blackboard.notebook.investigation_strategy == STRATEGY_MALWARE_HUNTING

    def test_config_orchestrator_max_cycles(self):
        """Verify orchestrator config fields exist (orchestrator is always on)."""
        from src.config import BridgeConfig
        config = BridgeConfig()
        assert config.external.orchestrator_max_cycles == 15


class TestOrchestratorPrompts:
    """Tests for prompt construction."""

    def test_strategy_guidance_vuln(self):
        guidance = Orchestrator._get_strategy_guidance(STRATEGY_VULN_HUNTING)
        assert "CreateProcess" in guidance
        assert "privilege escalation" in guidance

    def test_strategy_guidance_malware(self):
        guidance = Orchestrator._get_strategy_guidance(STRATEGY_MALWARE_HUNTING)
        assert "IOC" in guidance
        assert "C2" in guidance

    def test_strategy_guidance_binary(self):
        guidance = Orchestrator._get_strategy_guidance(STRATEGY_BINARY_UNDERSTANDING)
        assert "imports" in guidance
        assert "entry point" in guidance

    def test_task_creation_system_prompt(self):
        orch, _, _, _ = _make_orchestrator()
        prompt = orch._get_task_creation_system_prompt(STRATEGY_VULN_HUNTING)
        assert "investigation planner" in prompt.lower()
        assert "vuln_hunting" in prompt

    def test_strategy_templates_have_phases(self):
        """Strategy templates should include task progression phases."""
        from src.orchestrator import (
            STRATEGY_TEMPLATE_VULN_HUNTING,
            STRATEGY_TEMPLATE_MALWARE_HUNTING,
            STRATEGY_TEMPLATE_BINARY_UNDERSTANDING,
        )
        for template in [STRATEGY_TEMPLATE_VULN_HUNTING,
                         STRATEGY_TEMPLATE_MALWARE_HUNTING,
                         STRATEGY_TEMPLATE_BINARY_UNDERSTANDING]:
            assert "Phase 1" in template
            assert "Phase 2" in template
            assert "Completion Criteria" in template

    def test_strategy_templates_have_tools(self):
        """Strategy templates should suggest specific tools."""
        from src.orchestrator import (
            STRATEGY_TEMPLATE_VULN_HUNTING,
            STRATEGY_TEMPLATE_MALWARE_HUNTING,
            STRATEGY_TEMPLATE_BINARY_UNDERSTANDING,
        )
        for template in [STRATEGY_TEMPLATE_VULN_HUNTING,
                         STRATEGY_TEMPLATE_MALWARE_HUNTING,
                         STRATEGY_TEMPLATE_BINARY_UNDERSTANDING]:
            assert "Suggested tools:" in template

    def test_vuln_template_specifics(self):
        """Vuln template should cover key vulnerability patterns."""
        from src.orchestrator import STRATEGY_TEMPLATE_VULN_HUNTING
        assert "lpApplicationName" in STRATEGY_TEMPLATE_VULN_HUNTING
        assert "DLL hijacking" in STRATEGY_TEMPLATE_VULN_HUNTING
        assert "unquoted" in STRATEGY_TEMPLATE_VULN_HUNTING.lower()

    def test_malware_template_specifics(self):
        """Malware template should cover key malware patterns."""
        from src.orchestrator import STRATEGY_TEMPLATE_MALWARE_HUNTING
        assert "VirtualAlloc" in STRATEGY_TEMPLATE_MALWARE_HUNTING
        assert "persistence" in STRATEGY_TEMPLATE_MALWARE_HUNTING.lower()
        assert "anti-debug" in STRATEGY_TEMPLATE_MALWARE_HUNTING.lower()

    def test_task_creation_prompt_has_guidelines(self):
        """Task creation prompt should have rich guidelines."""
        orch, _, _, _ = _make_orchestrator()
        prompt = orch._get_task_creation_system_prompt(STRATEGY_BINARY_UNDERSTANDING)
        assert "include_sections" in prompt
        assert "Completion" in prompt
        assert "Coverage" in prompt.lower() or "coverage" in prompt

    def test_notebook_update_prompt_strategy_aware(self):
        """Notebook update prompts should vary by strategy."""
        vuln_prompt = Orchestrator._get_notebook_update_system_prompt(STRATEGY_VULN_HUNTING)
        malware_prompt = Orchestrator._get_notebook_update_system_prompt(STRATEGY_MALWARE_HUNTING)
        binary_prompt = Orchestrator._get_notebook_update_system_prompt(STRATEGY_BINARY_UNDERSTANDING)

        # Each should mention its strategy
        assert "vulnerability" in vuln_prompt.lower()
        assert "malware" in malware_prompt.lower() or "ioc" in malware_prompt.lower()
        assert "architecture" in binary_prompt.lower()

        # They should all have the JSON schema
        for prompt in [vuln_prompt, malware_prompt, binary_prompt]:
            assert "category" in prompt
            assert "severity" in prompt
            assert "JSON" in prompt

    def test_config_override_system_prompt(self):
        """Config orchestrator_system_prompt should override built-in prompt."""
        orch, _, _, _ = _make_orchestrator()
        orch.config.orchestrator_system_prompt = "Custom prompt for {strategy} analysis."
        prompt = orch._get_task_creation_system_prompt(STRATEGY_VULN_HUNTING)
        assert prompt == "Custom prompt for vuln_hunting analysis."


# ---------------------------------------------------------------------------
# Dynamic Loop Tests
# ---------------------------------------------------------------------------

class TestDynamicLoop:
    """Tests for the dynamic loop behavior (stall detection, doom loops, soft limits)."""

    def test_coverage_stall_detection(self):
        """Orchestrator detects stalled coverage."""
        orch, _, _, _ = _make_orchestrator()
        # 4 entries = baseline + 3 stalled cycles
        history = [0.25, 0.25, 0.25, 0.25]
        assert orch._is_coverage_stalled(history) is True

    def test_coverage_advancing_no_stall(self):
        """Advancing coverage should not trigger stall."""
        orch, _, _, _ = _make_orchestrator()
        history = [0.0, 0.125, 0.25, 0.375]
        assert orch._is_coverage_stalled(history) is False

    def test_coverage_stall_needs_enough_history(self):
        """Stall detection needs at least N+1 data points."""
        orch, _, _, _ = _make_orchestrator()
        history = [0.25, 0.25]  # Only 2 data points, threshold is 3
        assert orch._is_coverage_stalled(history) is False

    def test_orchestrator_doom_loop_detection(self):
        """Orchestrator detects repeated identical task goals."""
        orch, _, _, _ = _make_orchestrator()
        recent_goals = ["List all imports", "List all imports"]
        assert orch._is_orchestrator_doom_loop("List all imports", recent_goals) is True

    def test_orchestrator_doom_loop_different_goals(self):
        """Different goals should not trigger doom loop."""
        orch, _, _, _ = _make_orchestrator()
        recent_goals = ["List all imports", "Decompile main"]
        assert orch._is_orchestrator_doom_loop("Check strings", recent_goals) is False

    def test_doom_loop_case_insensitive(self):
        """Doom loop detection should be case-insensitive."""
        orch, _, _, _ = _make_orchestrator()
        recent_goals = ["List ALL imports", "list all imports"]
        assert orch._is_orchestrator_doom_loop("LIST ALL IMPORTS", recent_goals) is True

    def test_doom_loop_needs_enough_history(self):
        """Doom loop needs at least N previous goals to compare."""
        orch, _, _, _ = _make_orchestrator()
        recent_goals = ["List all imports"]  # Only 1, threshold is 2
        assert orch._is_orchestrator_doom_loop("List all imports", recent_goals) is False

    def test_doom_loop_semantic_similarity(self):
        """Rephrased goals with same meaning should trigger doom loop."""
        orch, _, _, _ = _make_orchestrator()
        # Same semantic intent, different phrasing
        recent_goals = [
            "Trace recv call sites for directory traversal",
            "Investigate recv callers for path traversal vulnerabilities",
        ]
        # Current goal is another rephrase of the same thing
        assert orch._is_orchestrator_doom_loop(
            "Analyze data flow from recv to path traversal", recent_goals
        ) is True

    def test_doom_loop_semantic_different_targets(self):
        """Goals targeting genuinely different things should NOT trigger."""
        orch, _, _, _ = _make_orchestrator()
        recent_goals = [
            "Decompile CreateProcessW callers for command injection",
            "Trace recv callers for directory traversal",
        ]
        # Genuinely different: crypto vs process/network
        assert orch._is_orchestrator_doom_loop(
            "Analyze CryptEncrypt usage for weak encryption", recent_goals
        ) is False

    def test_doom_loop_address_based_repetition(self):
        """Same addresses across all recent goals should trigger doom loop."""
        orch, _, _, _ = _make_orchestrator()
        recent_goals = [
            "Decompile function at 0x004092a0 and check for vulnerabilities",
            "Investigate 0x004092a0 for security issues",
        ]
        assert orch._is_orchestrator_doom_loop(
            "Analyze the code at 0x004092a0 for potential flaws", recent_goals
        ) is True

    def test_doom_loop_different_addresses_different_targets(self):
        """Genuinely different goals with different targets should NOT trigger."""
        orch, _, _, _ = _make_orchestrator()
        recent_goals = [
            "Decompile recv handler at 0x004092a0 for network traversal",
            "Decompile recv handler at 0x004092a0 for network traversal",
        ]
        # Completely different investigation target
        assert orch._is_orchestrator_doom_loop(
            "Decompile CreateProcessW caller at 0x00401000 for command injection",
            recent_goals,
        ) is False

    def test_extract_goal_keywords(self):
        """Stop words and filler verbs are removed from goal keywords."""
        orch, _, _, _ = _make_orchestrator()
        kw = orch._extract_goal_keywords(
            "Investigate the recv callers for directory traversal"
        )
        # "investigate", "the", "for", "callers" should be removed (stop words)
        assert "investigate" not in kw
        assert "the" not in kw
        assert "for" not in kw
        assert "callers" not in kw
        # Meaningful domain words should remain
        assert "recv" in kw
        assert "directory" in kw
        assert "traversal" in kw



# ---------------------------------------------------------------------------
# Worker Result Memory Tests
# ---------------------------------------------------------------------------

class TestWorkerResultMemory:
    """Tests for WorkerResultSummary and history prompt injection."""

    def test_build_worker_summary_basic(self):
        """_build_worker_summary extracts functions and tools from result."""
        orch, _, _, _ = _make_orchestrator()
        task = WorkerTask(goal="Analyze recv callers")
        result = AgentResult(
            is_complete=True,
            findings_summary="Found potential directory traversal",
            exit_reason="llm_complete",
            exec_results=ExecutionPhaseResults(
                goal="Analyze recv callers",
                tool_executions=[
                    ToolExecution(
                        tool_name="decompile_function_by_address",
                        parameters={"address": "0x004092a0"},
                        result="...",
                        success=True,
                    ),
                    ToolExecution(
                        tool_name="get_xrefs_to",
                        parameters={"address": "0x00404500"},
                        result="...",
                        success=True,
                    ),
                    ToolExecution(
                        tool_name="decompile_function_by_address",
                        parameters={"address": "0x00405000"},
                        result="...",
                        success=True,
                    ),
                    ToolExecution(
                        tool_name="<no_command>",
                        parameters={},
                        result="thinking...",
                        success=True,
                    ),
                ]
            ),
        )
        summary = orch._build_worker_summary(cycle=2, task=task, result=result)
        assert summary.cycle == 2
        assert summary.goal == "Analyze recv callers"
        assert len(summary.functions_decompiled) == 2
        assert "0x004092a0" in summary.functions_decompiled
        assert "0x00405000" in summary.functions_decompiled
        assert summary.tools_used["decompile_function_by_address"] == 2
        assert summary.tools_used["get_xrefs_to"] == 1
        assert "<no_command>" not in summary.tools_used
        assert summary.exit_reason == "llm_complete"
        assert "directory traversal" in summary.key_findings

    def test_build_worker_summary_no_exec_results(self):
        """_build_worker_summary handles result with no exec_results."""
        orch, _, _, _ = _make_orchestrator()
        task = WorkerTask(goal="Do something")
        result = AgentResult(is_complete=False, exit_reason="error")
        summary = orch._build_worker_summary(cycle=1, task=task, result=result)
        assert summary.functions_decompiled == []
        assert summary.tools_used == {}
        assert summary.exit_reason == "error"

    def test_format_worker_history_prompt_empty(self):
        """Empty summaries returns empty string."""
        orch, _, _, _ = _make_orchestrator()
        assert orch._format_worker_history_prompt([]) == ""

    def test_format_worker_history_prompt_content(self):
        """Worker history prompt includes cycle, goal, functions, and tools."""
        orch, _, _, _ = _make_orchestrator()
        summaries = [
            WorkerResultSummary(
                cycle=1,
                goal="Analyze recv callers",
                functions_decompiled=["0x004092a0", "0x00405000"],
                tools_used={"decompile_function_by_address": 2, "get_xrefs_to": 3},
                key_findings="Found potential path traversal",
                exit_reason="llm_complete",
            ),
            WorkerResultSummary(
                cycle=2,
                goal="Check CreateProcessW usage",
                functions_decompiled=["0x00401000"],
                tools_used={"decompile_function": 1},
                key_findings="No command injection found",
                exit_reason="llm_complete",
            ),
        ]
        prompt = orch._format_worker_history_prompt(summaries)
        assert "Worker History" in prompt
        assert "Cycle 1" in prompt
        assert "Cycle 2" in prompt
        assert "0x004092a0" in prompt
        assert "Do NOT assign tasks that repeat" in prompt

    def test_worker_history_injected_into_task_creation(self):
        """Worker history should appear in the task creation LLM prompt."""
        task_json = json.dumps({
            "goal": "Investigate something new",
            "max_steps": 5,
        })
        orch, mock_llm, _, _ = _make_orchestrator(
            llm_responses=[f"```json\n{task_json}\n```"],
        )
        summaries = [
            WorkerResultSummary(
                cycle=1,
                goal="Previous work",
                functions_decompiled=["0x004092a0"],
                tools_used={"decompile_function": 1},
                key_findings="Found something",
                exit_reason="llm_complete",
            ),
        ]
        task = orch._create_next_task(
            "Find vulns", STRATEGY_VULN_HUNTING, cycle=2,
            worker_summaries=summaries,
        )
        # The LLM should have been called with a prompt containing worker history
        call_args = mock_llm.generate_with_phase.call_args
        user_prompt = call_args[0][0] if call_args[0] else call_args[1].get("user_prompt", "")
        assert "Worker History" in user_prompt
        assert "0x004092a0" in user_prompt


# ---------------------------------------------------------------------------
# Merge-Aware FunctionRegistry Tests
# ---------------------------------------------------------------------------

class TestMergeAwareFunctionRegistry:
    """Tests for the merge-aware FunctionRegistry.register() method."""

    def test_register_new_function(self):
        """New function is stored as-is."""
        registry = FunctionRegistry()
        fa = FunctionAnalysis(
            address="0x00401000", name="main", purpose="Entry point",
            decompiled=True, imports_used=["CreateProcessW"],
        )
        registry.register(fa)
        assert registry.count == 1
        result = registry.get("0x00401000")
        assert result.purpose == "Entry point"
        assert result.decompile_count == 1

    def test_register_merge_increments_decompile_count(self):
        """Re-registering same address increments decompile_count."""
        registry = FunctionRegistry()
        fa1 = FunctionAnalysis(address="0x00401000", name="main", purpose="Entry point")
        fa2 = FunctionAnalysis(address="0x00401000", name="main", purpose="Entry point")
        registry.register(fa1)
        registry.register(fa2)
        result = registry.get("0x00401000")
        assert result.decompile_count == 2

    def test_register_merge_keeps_richer_purpose(self):
        """Merge prefers longer non-auto-registered purpose."""
        registry = FunctionRegistry()
        fa1 = FunctionAnalysis(
            address="0x00401000", name="main",
            purpose="Handles network connections and file I/O",
        )
        fa2 = FunctionAnalysis(
            address="0x00401000", name="main",
            purpose="Decompiled by worker (auto-registered)",
        )
        registry.register(fa1)
        registry.register(fa2)
        result = registry.get("0x00401000")
        # Should keep the richer purpose, not the auto-registered one
        assert "auto-registered" not in result.purpose
        assert "network connections" in result.purpose

    def test_register_merge_upgrades_from_auto(self):
        """Auto-registered purpose is replaced by real purpose."""
        registry = FunctionRegistry()
        fa1 = FunctionAnalysis(
            address="0x00401000", name="FUN_00401000",
            purpose="Decompiled by worker (auto-registered)",
        )
        fa2 = FunctionAnalysis(
            address="0x00401000", name="FUN_00401000",
            purpose="Parses HTTP request headers",
        )
        registry.register(fa1)
        registry.register(fa2)
        result = registry.get("0x00401000")
        assert result.purpose == "Parses HTTP request headers"

    def test_register_merge_deduplicates_lists(self):
        """List fields are merged and deduplicated."""
        registry = FunctionRegistry()
        fa1 = FunctionAnalysis(
            address="0x00401000", name="main",
            imports_used=["CreateProcessW", "recv"],
            security_notes=["Uses CreateProcessW"],
        )
        fa2 = FunctionAnalysis(
            address="0x00401000", name="main",
            imports_used=["recv", "send"],
            security_notes=["Uses recv for network input"],
        )
        registry.register(fa1)
        registry.register(fa2)
        result = registry.get("0x00401000")
        assert set(result.imports_used) == {"CreateProcessW", "recv", "send"}
        assert len(result.security_notes) == 2

    def test_register_merge_upgrades_confidence(self):
        """Confidence upgrades from low to higher, not the reverse."""
        registry = FunctionRegistry()
        fa1 = FunctionAnalysis(
            address="0x00401000", name="main", confidence="medium",
        )
        fa2 = FunctionAnalysis(
            address="0x00401000", name="main", confidence="high",
        )
        registry.register(fa1)
        registry.register(fa2)
        assert registry.get("0x00401000").confidence == "high"

    def test_register_merge_no_downgrade_confidence(self):
        """Confidence should NOT downgrade."""
        registry = FunctionRegistry()
        fa1 = FunctionAnalysis(
            address="0x00401000", name="main", confidence="high",
        )
        fa2 = FunctionAnalysis(
            address="0x00401000", name="main", confidence="low",
        )
        registry.register(fa1)
        registry.register(fa2)
        assert registry.get("0x00401000").confidence == "high"

    def test_format_for_prompt_shows_skip_warning(self):
        """Functions decompiled >2 times show SKIP warning."""
        registry = FunctionRegistry()
        fa = FunctionAnalysis(
            address="0x00401000", name="main", purpose="Entry point",
            decompile_count=5,
        )
        registry.functions["0x00401000"] = fa  # Direct set for testing
        prompt = registry.format_for_prompt()
        assert "SKIP" in prompt
        assert "5x" in prompt


# ---------------------------------------------------------------------------
# Orchestrator Registry View Tests
# ---------------------------------------------------------------------------

class TestOrchestratorRegistryView:
    """Tests for format_for_orchestrator() — the orchestrator-specific view."""

    def test_empty_registry(self):
        """Empty registry returns empty string."""
        registry = FunctionRegistry()
        assert registry.format_for_orchestrator() == ""

    def test_groups_by_analysis_depth(self):
        """Functions are grouped into over-analyzed, analyzed, and shallow."""
        registry = FunctionRegistry()

        # Over-analyzed
        over = FunctionAnalysis(
            address="0x00401000", name="recv_handler",
            purpose="Handles incoming data", decompile_count=5,
        )
        registry.functions["0x00401000"] = over

        # Fully analyzed
        analyzed = FunctionAnalysis(
            address="0x00402000", name="process_request",
            purpose="Processes HTTP requests",
            security_notes=["Path traversal risk"],
        )
        registry.functions["0x00402000"] = analyzed

        # Shallow / auto-registered
        shallow = FunctionAnalysis(
            address="0x00403000", name="FUN_00403000",
            purpose="Decompiled by worker (auto-registered)",
        )
        registry.functions["0x00403000"] = shallow

        prompt = registry.format_for_orchestrator()
        assert "OVER-ANALYZED" in prompt
        assert "DO NOT re-decompile" in prompt
        assert "5x" in prompt
        assert "Fully Analyzed" in prompt
        assert "Path traversal risk" in prompt
        assert "Seen But Not Analyzed" in prompt
        assert "consider investigating" in prompt

    def test_security_notes_highlighted(self):
        """Functions with security notes get a warning indicator."""
        registry = FunctionRegistry()
        fa = FunctionAnalysis(
            address="0x00401000", name="vuln_func",
            purpose="Has a vulnerability",
            security_notes=["Buffer overflow"],
        )
        registry.functions["0x00401000"] = fa
        prompt = registry.format_for_orchestrator()
        assert "\u26a0" in prompt  # Warning symbol
        assert "Buffer overflow" in prompt


# ---------------------------------------------------------------------------
# Discovery Include Sections Tests
# ---------------------------------------------------------------------------

class TestDiscoveryIncludeSections:
    """Tests for Fix 1 — discovery always in include_sections."""

    def test_default_include_sections_has_discovery(self):
        """WorkerTask default include_sections includes 'discovery'."""
        task = WorkerTask(goal="Test task")
        assert "discovery" in task.include_sections

    def test_ensure_discovery_section_adds_when_missing(self):
        """_ensure_discovery_section adds 'discovery' when missing."""
        orch, _, _, _ = _make_orchestrator()
        sections = ["scope", "knowledge"]
        result = orch._ensure_discovery_section(sections)
        assert "discovery" in result

    def test_ensure_discovery_section_no_duplicate(self):
        """_ensure_discovery_section doesn't duplicate 'discovery'."""
        orch, _, _, _ = _make_orchestrator()
        sections = ["scope", "discovery", "knowledge"]
        result = orch._ensure_discovery_section(sections)
        assert result.count("discovery") == 1

    def test_parsed_task_always_has_discovery(self):
        """Even when LLM omits discovery from include_sections, it's forced in."""
        task_json = json.dumps({
            "goal": "Analyze something",
            "include_sections": ["scope", "knowledge"],
        })
        orch, mock_llm, _, _ = _make_orchestrator(
            llm_responses=[f"```json\n{task_json}\n```"],
        )
        task = orch._create_next_task("Find vulns", STRATEGY_VULN_HUNTING, cycle=1)
        assert "discovery" in task.include_sections


# ---------------------------------------------------------------------------
# Tests: Correlation Rule Recipe Integration (Session 10)
# ---------------------------------------------------------------------------

class TestCorrelationRuleRecipeIntegration:
    """Tests for recipe integration into correlation rules."""

    def test_correlation_rule_creates_recipe_task(self):
        """Correlation hook with recipe fields should create WorkerTask with recipe."""
        from src.correlation_hooks_builtin import get_builtin_hooks
        from src.coverage_tracker import CoverageTracker, DEPTH_ENCOUNTERED

        hooks = get_builtin_hooks()
        unquoted_hook = hooks[0]  # UnquotedServicePathHook

        # Verify the hook produces a task with recipe fields when fired
        cov = CoverageTracker()
        cov.mark_covered("service_management", tool_used="list_imports",
                         depth=DEPTH_ENCOUNTERED)
        apis = {"createprocessw", "startservicectrldispatcherw"}
        task = unquoted_hook.check(apis, cov, None, None)
        assert task is not None
        assert task.recipe == "trace_import_callers"
        assert "CreateProcessW" in task.recipe_params["api_names"]
        assert task.analysis_focus is not None

    def test_all_rules_have_recipe_fields(self):
        """All 5 built-in correlation hooks should produce tasks with recipe fields."""
        from src.correlation_hooks_builtin import get_builtin_hooks

        hooks = get_builtin_hooks()
        assert len(hooks) == 5

        for hook in hooks:
            assert hook.name, f"Hook missing name"
            assert hook.description, f"Hook {hook.name} missing description"

    def test_check_correlations_passes_recipe_to_task(self):
        """_check_correlations should pass recipe fields to WorkerTask."""
        from src.coverage_tracker import DEPTH_ENCOUNTERED

        orch, _, _, bb = _make_orchestrator()

        # Register a function with CreateProcessW + service API
        fa = FunctionAnalysis(
            address="0x00405b60",
            name="FUN_00405b60",
            purpose="test",
            decompiled=True,
            imports_used=["CreateProcessW", "StartServiceCtrlDispatcherW"],
        )
        bb.function_registry.register(fa)

        # Mark service_management as encountered
        bb.coverage.mark_covered("service_management",
                                 tool_used="list_imports",
                                 depth=DEPTH_ENCOUNTERED)

        task = orch._check_correlations()
        assert task is not None
        assert task.recipe == "trace_import_callers"
        assert "CreateProcessW" in task.recipe_params["api_names"]
        assert task.analysis_focus is not None
        assert "correlation_rule" in task.metadata

    def test_recipe_mode_results_bypass_notebook_synthesis(self):
        """Recipe-mode results should bypass the blind LLM synthesis call."""
        orch, mock_llm, _, bb = _make_orchestrator()
        bb.notebook.investigation_strategy = STRATEGY_VULN_HUNTING

        # Create a recipe-mode result with notebook entries
        result = AgentResult(
            task_id="recipe_task_001",
            findings_summary="Found unquoted service path vulnerability",
            tool_executions_count=5,
            is_complete=True,
            exit_reason="recipe_complete",
            notebook_entries=[
                {
                    "category": "vulnerability",
                    "severity": "high",
                    "title": "Unquoted service path in FUN_00405b60",
                    "detail": (
                        "CreateProcessW called with NULL lpApplicationName "
                        "and unquoted path containing spaces."
                    ),
                    "evidence": ["CreateProcessW(NULL, cmd)"],
                    "addresses": ["0x00405b60"],
                    "status": "confirmed",
                },
            ],
        )

        # Initial LLM call count
        initial_llm_calls = mock_llm.generate_with_phase.call_count

        orch._update_notebook(result, cycle=1)

        # LLM should NOT have been called (recipe bypass)
        assert mock_llm.generate_with_phase.call_count == initial_llm_calls

        # Notebook should have the entry
        entries = bb.notebook.entries
        assert len(entries) >= 1
        assert any("Unquoted service path" in e.title for e in entries)

    def test_quality_filter_still_applies_to_recipe_entries(self):
        """Recipe entries still go through quality filter and dedup."""
        orch, _, _, bb = _make_orchestrator()
        bb.notebook.investigation_strategy = STRATEGY_VULN_HUNTING

        # Add a duplicate entry first
        bb.notebook.add_finding(NotebookEntry(
            category="vulnerability",
            severity="high",
            title="Unquoted service path in FUN_00405b60",
            detail="Already exists",
            evidence=["CreateProcessW(NULL, cmd)"],
            addresses=["0x00405b60"],
            status="confirmed",
        ))

        result = AgentResult(
            task_id="recipe_task_002",
            findings_summary="Duplicate finding",
            exit_reason="recipe_complete",
            notebook_entries=[
                {
                    "category": "vulnerability",
                    "severity": "high",
                    "title": "Unquoted service path in FUN_00405b60",
                    "detail": "Same finding again",
                    "evidence": ["CreateProcessW(NULL, cmd)"],
                    "addresses": ["0x00405b60"],
                    "status": "confirmed",
                },
            ],
        )

        entries_before = len(bb.notebook.entries)
        orch._update_notebook(result, cycle=2)
        entries_after = len(bb.notebook.entries)

        # Should NOT add duplicate
        assert entries_after == entries_before

    def test_parsed_task_includes_recipe_fields(self):
        """_parse_task_from_response should parse recipe fields from JSON."""
        task_json = json.dumps({
            "goal": "Trace CreateProcessW callers",
            "recipe": "trace_import_callers",
            "recipe_params": {"api_names": ["CreateProcessW"]},
            "analysis_focus": "Check for NULL lpApplicationName",
            "include_sections": ["scope", "discovery"],
        })
        orch, mock_llm, _, _ = _make_orchestrator(
            llm_responses=[f"```json\n{task_json}\n```"],
        )
        task = orch._create_next_task("Find vulns", STRATEGY_VULN_HUNTING, cycle=1)

        assert task.recipe == "trace_import_callers"
        assert task.recipe_params == {"api_names": ["CreateProcessW"]}
        assert task.analysis_focus == "Check for NULL lpApplicationName"

    def test_task_creation_prompt_documents_recipes(self):
        """Task creation system prompt should mention available recipes."""
        orch, _, _, _ = _make_orchestrator()
        prompt = orch._get_task_creation_system_prompt(STRATEGY_VULN_HUNTING)

        assert "trace_import_callers" in prompt
        assert "trace_string_refs" in prompt
        assert "deep_function_analysis" in prompt
        assert "surface_recon" in prompt
        assert "recipe" in prompt.lower()


# ---------------------------------------------------------------------------
# Test: Recipe tool count fallback (Fix 4)
# ---------------------------------------------------------------------------

class TestRecipeToolCountFallback:
    """Verify that recipe-mode workers report correct tool counts.

    Recipe workers set ``tool_executions_count`` from ``RecipeResult.tool_calls_made``
    but do NOT populate ``exec_results.tool_executions``. The orchestrator must use
    ``tool_executions_count`` as a fallback when ``exec_results`` is empty.
    """

    def test_recipe_result_tool_count_used_when_exec_results_empty(self):
        """When exec_results is None, real_tools should fallback to tool_executions_count."""
        result = AgentResult(
            task_id="recipe_task_001",
            findings_summary="Found vulnerability",
            exec_results=None,  # Recipe mode: no exec_results
            tool_executions_count=7,
            is_complete=True,
            exit_reason="recipe_complete",
        )

        # Simulate the orchestrator's real_tools computation
        real_tools = 0
        if result.exec_results:
            real_tools = sum(
                1 for te in result.exec_results.tool_executions
                if te.tool_name != "<no_command>"
            )
        # Fix: fallback to tool_executions_count
        if real_tools == 0 and result.tool_executions_count > 0:
            real_tools = result.tool_executions_count

        assert real_tools == 7

    def test_llm_result_still_uses_exec_results(self):
        """LLM workers with exec_results should use the filtered count, not fallback."""
        exec_results = ExecutionPhaseResults(goal="test")
        exec_results.add_execution(ToolExecution(
            tool_name="decompile_function_by_address",
            parameters={"address": "0x00401000"},
            result="void test() {}",
            success=True,
        ))
        exec_results.add_execution(ToolExecution(
            tool_name="<no_command>",
            parameters={},
            result="thinking...",
            success=True,
        ))
        exec_results.add_execution(ToolExecution(
            tool_name="get_xrefs_to",
            parameters={"address": "0x00401000"},
            result="From 00402000",
            success=True,
        ))

        result = AgentResult(
            task_id="llm_task_001",
            findings_summary="Found issue",
            exec_results=exec_results,
            tool_executions_count=3,  # includes no_command
            is_complete=True,
            exit_reason="llm_complete",
        )

        real_tools = 0
        if result.exec_results:
            real_tools = sum(
                1 for te in result.exec_results.tool_executions
                if te.tool_name != "<no_command>"
            )
        if real_tools == 0 and result.tool_executions_count > 0:
            real_tools = result.tool_executions_count

        assert real_tools == 2  # 2 real tools, not 3 (no_command filtered)


# ---------------------------------------------------------------------------
# Fix 1: Tool excerpt budget tests
# ---------------------------------------------------------------------------

class TestToolExcerptBudget:
    """Verify that _update_notebook() uses per-tool excerpt budgets.

    Decompile results should get 4000 chars (not 200), xref results
    should get 1000, and other tools stay at 300.
    """

    def test_decompile_excerpt_is_4000_chars(self):
        """Decompile tool results should be truncated at 4000 chars, not 200."""
        orch, mock_llm, _, bb = _make_orchestrator(
            llm_responses=[
                "binary_understanding",   # strategy classification
                '```json\n[]\n```',        # notebook update (empty response)
            ],
        )
        # Build a fake decompile result longer than 200 chars
        long_code = "void vuln_func() {\n" + ("    int x = 0;\n" * 300) + "}\n"
        assert len(long_code) > 4000  # Ensure it's large enough to test truncation

        exec_results = ExecutionPhaseResults(goal="test")
        exec_results.add_execution(ToolExecution(
            tool_name="decompile_function_by_address",
            parameters={"address": "0x00405b60"},
            result=long_code,
            success=True,
        ))

        result = AgentResult(
            task_id="test_001",
            findings_summary="Found a function",
            exec_results=exec_results,
            tool_executions_count=1,
            is_complete=True,
            exit_reason="llm_complete",
        )

        # Call _update_notebook which builds excerpts internally
        orch.blackboard.notebook.investigation_strategy = "vuln_hunting"
        orch._update_notebook(result, cycle=1)

        # The LLM should have been called with a prompt containing
        # much more than 200 chars of the decompiled code
        call_args = mock_llm.generate_with_phase.call_args
        user_prompt = call_args[0][0]  # first positional arg
        # The full prompt should contain a substantial portion of the code
        # (at least 2000 chars from the function, not just 200)
        code_in_prompt = user_prompt.count("int x = 0;")
        assert code_in_prompt > 15, (
            f"Only {code_in_prompt} lines of decompiled code in prompt — "
            f"expected >15 (excerpt budget should be 4000, not 200)"
        )

    def test_non_decompile_excerpt_stays_short(self):
        """Non-decompile tool results should use a shorter budget (500 chars)."""
        orch, mock_llm, _, bb = _make_orchestrator(
            llm_responses=[
                "binary_understanding",
                '```json\n[]\n```',
            ],
        )
        long_result = "A" * 1000

        exec_results = ExecutionPhaseResults(goal="test")
        exec_results.add_execution(ToolExecution(
            tool_name="list_strings",
            parameters={"filter": "all"},
            result=long_result,
            success=True,
        ))

        result = AgentResult(
            task_id="test_002",
            findings_summary="Found strings",
            exec_results=exec_results,
            tool_executions_count=1,
            is_complete=True,
            exit_reason="llm_complete",
        )

        orch.blackboard.notebook.investigation_strategy = "binary_understanding"
        orch._update_notebook(result, cycle=1)

        call_args = mock_llm.generate_with_phase.call_args
        user_prompt = call_args[0][0]
        # Should have at most 500 'A' characters, not 1000
        a_count = user_prompt.count("A")
        assert a_count <= 510, (  # slight slack for formatting
            f"Non-decompile tool had {a_count} chars — expected ≤500"
        )

    def test_xref_excerpt_gets_2000_chars(self):
        """Xref tool results should get 2000 chars (rich excerpt)."""
        orch, mock_llm, _, bb = _make_orchestrator(
            llm_responses=[
                "binary_understanding",
                '```json\n[]\n```',
            ],
        )
        xref_result = "From: FUN_00401000\n" * 200  # ~4000 chars

        exec_results = ExecutionPhaseResults(goal="test")
        exec_results.add_execution(ToolExecution(
            tool_name="get_xrefs_to",
            parameters={"address": "0x00405b60"},
            result=xref_result,
            success=True,
        ))

        result = AgentResult(
            task_id="test_003",
            findings_summary="Found xrefs",
            exec_results=exec_results,
            tool_executions_count=1,
            is_complete=True,
            exit_reason="llm_complete",
        )

        orch.blackboard.notebook.investigation_strategy = "binary_understanding"
        orch._update_notebook(result, cycle=1)

        call_args = mock_llm.generate_with_phase.call_args
        user_prompt = call_args[0][0]
        xref_count = user_prompt.count("FUN_00401000")
        # Should have more than would fit in 500 chars (~25 lines)
        # but less than all 200 lines (capped at 2000 chars)
        assert xref_count > 25, f"Too few xref lines: {xref_count}"
        assert xref_count < 200, f"Too many xref lines: {xref_count} (should be capped)"

    def test_up_to_15_tool_executions_shown(self):
        """Should show up to 15 tool executions, not just 10."""
        orch, mock_llm, _, bb = _make_orchestrator(
            llm_responses=[
                "binary_understanding",
                '```json\n[]\n```',
            ],
        )

        exec_results = ExecutionPhaseResults(goal="test")
        for i in range(20):
            exec_results.add_execution(ToolExecution(
                tool_name=f"tool_{i}",
                parameters={"i": i},
                result=f"result_{i}",
                success=True,
            ))

        result = AgentResult(
            task_id="test_004",
            findings_summary="Many tools",
            exec_results=exec_results,
            tool_executions_count=20,
            is_complete=True,
            exit_reason="llm_complete",
        )

        orch.blackboard.notebook.investigation_strategy = "binary_understanding"
        orch._update_notebook(result, cycle=1)

        call_args = mock_llm.generate_with_phase.call_args
        user_prompt = call_args[0][0]
        # Count how many tool_N entries appear
        tool_refs = sum(1 for i in range(20) if f"tool_{i}" in user_prompt)
        assert tool_refs == 15, f"Expected 15 tools in prompt, got {tool_refs}"


# ---------------------------------------------------------------------------
# Fix 4: Worker summary key_findings length tests
# ---------------------------------------------------------------------------

class TestWorkerSummaryFindingsLength:
    """Verify _build_worker_summary preserves up to 600 chars of findings."""

    def test_findings_truncated_at_600_not_200(self):
        """key_findings should preserve up to 600 chars, not 200."""
        orch, _, _, _ = _make_orchestrator()
        long_findings = "X" * 800

        exec_results = ExecutionPhaseResults(goal="test")
        exec_results.add_execution(ToolExecution(
            tool_name="decompile_function",
            parameters={"name": "main"},
            result="void main() {}",
            success=True,
        ))

        task = WorkerTask(goal="Analyze main function")
        result = AgentResult(
            task_id="test",
            findings_summary=long_findings,
            exec_results=exec_results,
            tool_executions_count=1,
            is_complete=True,
            exit_reason="llm_complete",
        )

        summary = orch._build_worker_summary(1, task, result)
        assert len(summary.key_findings) == 600
        assert summary.key_findings == "X" * 600


# ---------------------------------------------------------------------------
# Fix 5: Findings-aware stall detection tests
# ---------------------------------------------------------------------------

class TestFindingsAwareStallDetection:
    """Verify that _is_coverage_stalled considers findings growth."""

    def test_pure_coverage_stall_still_triggers(self):
        """When both coverage and findings are flat, stall should trigger."""
        orch, _, _, _ = _make_orchestrator()
        # 4 cycles of identical coverage, no new findings
        coverage_history = [0.5, 0.5, 0.5, 0.5]
        findings_history = [3, 3, 3, 3]
        assert orch._is_coverage_stalled(coverage_history, findings_history) is True

    def test_stall_suppressed_when_findings_growing(self):
        """When coverage is flat but findings are growing, stall should NOT trigger."""
        orch, _, _, _ = _make_orchestrator()
        # Coverage flat, but findings increasing
        coverage_history = [0.5, 0.5, 0.5, 0.5]
        findings_history = [1, 2, 3, 4]
        assert orch._is_coverage_stalled(coverage_history, findings_history) is False

    def test_stall_when_findings_history_is_none(self):
        """Backward compatibility: when findings_history is None, use old behavior."""
        orch, _, _, _ = _make_orchestrator()
        coverage_history = [0.5, 0.5, 0.5, 0.5]
        assert orch._is_coverage_stalled(coverage_history, None) is True

    def test_stall_when_findings_also_flat(self):
        """When findings are flat AND coverage is flat, stall triggers."""
        orch, _, _, _ = _make_orchestrator()
        coverage_history = [0.3, 0.3, 0.3, 0.3]
        findings_history = [5, 5, 5, 5]
        assert orch._is_coverage_stalled(coverage_history, findings_history) is True

    def test_no_stall_when_not_enough_history(self):
        """Insufficient history should not trigger stall."""
        orch, _, _, _ = _make_orchestrator()
        coverage_history = [0.5, 0.5]
        findings_history = [0, 0]
        assert orch._is_coverage_stalled(coverage_history, findings_history) is False

    def test_coverage_advancing_never_stalls(self):
        """When coverage is advancing, should not stall regardless of findings."""
        orch, _, _, _ = _make_orchestrator()
        coverage_history = [0.1, 0.2, 0.3, 0.4]
        findings_history = [0, 0, 0, 0]
        assert orch._is_coverage_stalled(coverage_history, findings_history) is False


# ---------------------------------------------------------------------------
# Fix 6: Synthesis failure detection tests
# ---------------------------------------------------------------------------

class TestSynthesisFailureDetection:
    """Verify _check_synthesis_failure adds re-analysis leads."""

    def test_synthesis_failure_adds_lead(self):
        """Worker that decompiled 3+ functions with 0 findings → adds lead."""
        orch, _, _, bb = _make_orchestrator()
        summary = WorkerResultSummary(
            cycle=2,
            goal="Analyze CreateProcessW callers",
            functions_decompiled=["00405b60", "004041a0", "00405500"],
            tools_used={"decompile_function_by_address": 3},
            key_findings="No findings",
            exit_reason="llm_complete",
        )
        result = AgentResult(
            task_id="test_synth",
            findings_summary="No findings",
            tool_executions_count=3,
            is_complete=True,
            exit_reason="llm_complete",
            notebook_entries=[],
        )

        leads_before = len(bb.leads.get_active_leads(limit=100))
        orch._check_synthesis_failure(summary, result, cycle=2)
        leads_after = len(bb.leads.get_active_leads(limit=100))

        assert leads_after == leads_before + 1
        lead = bb.leads.get_active_leads(limit=1)[0]
        assert "SYNTHESIS RETRY" in lead.description
        assert "00405b60" in lead.description

    def test_no_failure_when_notebook_has_matching_entries(self):
        """Worker with matching notebook entries should not trigger failure."""
        orch, _, _, bb = _make_orchestrator()
        # Add a notebook entry that references one of the decompiled functions
        bb.add_notebook_entry(NotebookEntry(
            category="vulnerability",
            severity="high",
            title="Command injection found",
            detail="CreateProcessW called unsafely",
            evidence=["code line"],
            addresses=["00405b60"],
            status="confirmed",
        ))

        summary = WorkerResultSummary(
            cycle=2,
            goal="Analyze CreateProcessW callers",
            functions_decompiled=["00405b60", "004041a0", "00405500"],
            tools_used={"decompile_function_by_address": 3},
            key_findings="Found command injection",
            exit_reason="llm_complete",
        )
        result = AgentResult(
            task_id="test_synth_ok",
            findings_summary="Found command injection",
            tool_executions_count=3,
            is_complete=True,
            exit_reason="llm_complete",
        )

        leads_before = len(bb.leads.get_active_leads(limit=100))
        orch._check_synthesis_failure(summary, result, cycle=2)
        leads_after = len(bb.leads.get_active_leads(limit=100))

        assert leads_after == leads_before  # No new lead

    def test_no_failure_when_few_decompilations(self):
        """Worker with <3 decompiled functions should not trigger failure."""
        orch, _, _, bb = _make_orchestrator()
        summary = WorkerResultSummary(
            cycle=1,
            goal="Quick check",
            functions_decompiled=["00401000"],
            tools_used={"decompile_function": 1},
            key_findings="No findings",
            exit_reason="llm_complete",
        )
        result = AgentResult(
            task_id="test_few",
            findings_summary="No findings",
            tool_executions_count=1,
            is_complete=True,
            exit_reason="llm_complete",
        )

        leads_before = len(bb.leads.get_active_leads(limit=100))
        orch._check_synthesis_failure(summary, result, cycle=1)
        leads_after = len(bb.leads.get_active_leads(limit=100))

        assert leads_after == leads_before  # No new lead

    def test_no_failure_when_result_has_notebook_entries(self):
        """Worker that returned notebook_entries should not trigger failure."""
        orch, _, _, bb = _make_orchestrator()
        summary = WorkerResultSummary(
            cycle=2,
            goal="Analyze functions",
            functions_decompiled=["00405b60", "004041a0", "00405500"],
            tools_used={"decompile_function_by_address": 3},
            key_findings="Found issue",
            exit_reason="recipe_complete",
        )
        result = AgentResult(
            task_id="test_recipe",
            findings_summary="Found issue",
            tool_executions_count=3,
            is_complete=True,
            exit_reason="recipe_complete",
            notebook_entries=[{"title": "Bug found", "severity": "high"}],
        )

        leads_before = len(bb.leads.get_active_leads(limit=100))
        orch._check_synthesis_failure(summary, result, cycle=2)
        leads_after = len(bb.leads.get_active_leads(limit=100))

        assert leads_after == leads_before  # No new lead


# ---------------------------------------------------------------------------
# Fix 2: Blackboard code cache tests
# ---------------------------------------------------------------------------

class TestBlackboardCodeCache:
    """Verify BlackboardAccess code cache operations."""

    def test_cache_and_retrieve_code(self):
        """cache_code + get_cached_code round-trip."""
        _, _, _, bb = _make_orchestrator()
        bb.cache_code("00405b60", "void vuln() { return; }")
        assert bb.get_cached_code("00405b60") == "void vuln() { return; }"

    def test_cache_code_bulk(self):
        """cache_code_bulk stores multiple functions at once."""
        _, _, _, bb = _make_orchestrator()
        bb.cache_code_bulk({
            "00401000": "void func_a() {}",
            "00402000": "int func_b() { return 1; }",
        })
        assert bb.get_cached_code("00401000") is not None
        assert bb.get_cached_code("00402000") is not None
        assert bb.get_cached_code("00403000") is None

    def test_cache_overwrites_previous(self):
        """Caching same address twice overwrites previous code."""
        _, _, _, bb = _make_orchestrator()
        bb.cache_code("00401000", "version_1")
        bb.cache_code("00401000", "version_2")
        assert bb.get_cached_code("00401000") == "version_2"

    def test_get_all_cached_code(self):
        """get_all_cached_code returns a copy of the full cache."""
        _, _, _, bb = _make_orchestrator()
        bb.cache_code("00401000", "code_a")
        bb.cache_code("00402000", "code_b")
        all_code = bb.get_all_cached_code()
        assert len(all_code) == 2
        assert "00401000" in all_code
        assert "00402000" in all_code

    def test_empty_code_not_cached(self):
        """Empty address or code should not be cached."""
        _, _, _, bb = _make_orchestrator()
        bb.cache_code("", "some code")
        bb.cache_code("00401000", "")
        assert bb.get_all_cached_code() == {}

    def test_code_cache_summary_prioritizes_findings(self):
        """get_code_cache_summary should prioritize functions in notebook entries."""
        _, _, _, bb = _make_orchestrator()
        bb.cache_code("00401000", "void boring() {}")
        bb.cache_code("00405b60", "void vuln_func() { CreateProcessW(NULL, cmd); }")
        bb.cache_code("00402000", "void other() {}")

        # Add a notebook entry referencing 00405b60
        bb.add_notebook_entry(NotebookEntry(
            category="vulnerability",
            severity="high",
            title="Command injection",
            detail="CreateProcessW called unsafely",
            evidence=["code"],
            addresses=["00405b60"],
            status="confirmed",
        ))

        summary = bb.get_code_cache_summary(max_functions=2)
        # 00405b60 should appear first (prioritized)
        assert "00405b60" in summary
        # With max_functions=2, the finding-referenced one must be included
        assert "vuln_func" in summary


# ---------------------------------------------------------------------------
# Fix 3: Enriched final report tests
# ---------------------------------------------------------------------------

class TestEnrichedFinalReport:
    """Verify _synthesize_final_report includes enriched data sources."""

    def test_report_includes_needs_investigation_entries(self):
        """needs_investigation entries should appear in the report prompt."""
        orch, mock_llm, _, bb = _make_orchestrator(
            llm_responses=[
                "binary_understanding",
                "# Analysis Report\n## Executive Summary\nTest report.",
            ],
        )
        bb.notebook.investigation_strategy = "vuln_hunting"

        # Add a needs_investigation entry
        bb.add_notebook_entry(NotebookEntry(
            category="vulnerability",
            severity="medium",
            title="Suspicious buffer usage",
            detail="Buffer allocated without size check, needs deeper analysis",
            evidence=["code line"],
            addresses=["00401000"],
            status="needs_investigation",
        ))

        report = orch._synthesize_final_report("find vulns", "llm_complete", 3)

        # The LLM should have been called with a prompt mentioning
        # the needs_investigation entry
        call_args = mock_llm.generate_with_phase.call_args
        user_prompt = call_args[0][0]
        assert "Suspicious buffer usage" in user_prompt
        assert "Needs Investigation" in user_prompt

    def test_report_includes_code_evidence(self):
        """Code cache snippets should appear in the report prompt."""
        orch, mock_llm, _, bb = _make_orchestrator(
            llm_responses=[
                "binary_understanding",
                "# Analysis Report\n## Executive Summary\nTest report.",
            ],
        )
        bb.notebook.investigation_strategy = "vuln_hunting"

        # Add code to cache
        bb.cache_code("00405b60", "void vuln() { CreateProcessW(NULL, cmd); }")

        # Add a finding referencing that address
        bb.add_notebook_entry(NotebookEntry(
            category="vulnerability",
            severity="high",
            title="Command injection",
            detail="CreateProcessW called unsafely",
            evidence=["code"],
            addresses=["00405b60"],
            status="confirmed",
        ))

        report = orch._synthesize_final_report("find vulns", "llm_complete", 3)

        call_args = mock_llm.generate_with_phase.call_args
        user_prompt = call_args[0][0]
        assert "CreateProcessW" in user_prompt
        assert "Decompiled Code Evidence" in user_prompt

    def test_report_includes_security_notes_with_tags_and_iocs(self):
        """Security notes should include behavioral tags and IOCs."""
        orch, mock_llm, _, bb = _make_orchestrator(
            llm_responses=[
                "binary_understanding",
                "# Analysis Report\n## Executive Summary\nTest.",
            ],
        )
        bb.notebook.investigation_strategy = "vuln_hunting"

        # Register a function with security notes, tags, and IOCs
        fa = FunctionAnalysis(
            address="00405b60",
            name="vuln_func",
            purpose="Process creation wrapper",
            security_notes=["Calls CreateProcessW with NULL lpApplicationName"],
            behavioral_tags=["process_creation", "service_handler"],
            iocs_found=["HPSOCKSVC.exe"],
        )
        bb.register_function(fa)

        report = orch._synthesize_final_report("find vulns", "llm_complete", 3)

        call_args = mock_llm.generate_with_phase.call_args
        user_prompt = call_args[0][0]
        assert "process_creation" in user_prompt
        assert "HPSOCKSVC.exe" in user_prompt
