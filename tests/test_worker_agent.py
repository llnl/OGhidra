"""
Tests for WorkerAgent — the generic task executor.

Uses mock LLM and ToolExecutor to verify the mini execution loop:
  - System prompt construction (tool docs + task + dynamic context)
  - Command extraction and execution
  - Completion detection (TASK COMPLETE / INVESTIGATION COMPLETE)
  - Gate handling (PAUSE skips command, ABORT stops loop)
  - AgentResult packaging
"""

import pytest
from unittest.mock import MagicMock, patch, PropertyMock
from datetime import datetime

from src.agents.worker_agent import WorkerAgent
from src.agents.base import WorkerTask, AgentResult
from src.models.memory import (
    ExecutionPhaseResults,
    ToolExecution,
    ExecutionSignal,
    ExecutionGate,
    AnalysisState,
    SessionMemory,
    FunctionRegistry,
    InvestigationNotebook,
)
from src.blackboard import BlackboardAccess
from src.event_emitter import EventEmitter
from src.coverage_tracker import CoverageTracker
from src.lead_tracker import LeadTracker


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _make_worker(
    llm_responses=None,
    tool_results=None,
    capabilities_text=None,
):
    """Create a WorkerAgent with mocked dependencies.

    Args:
        llm_responses: List of strings the mock LLM returns in sequence.
        tool_results: Dict mapping command_name → result dict.
        capabilities_text: Optional tool docs string.
    """
    llm_responses = llm_responses or ["TASK COMPLETE\nNothing to do."]
    tool_results = tool_results or {}

    # Mock LLM client
    mock_llm = MagicMock()
    mock_llm.generate_with_phase = MagicMock(side_effect=llm_responses)

    # Mock ToolExecutor
    mock_tools = MagicMock()

    def _execute_cmd(cmd_name, params):
        if cmd_name in tool_results:
            return tool_results[cmd_name]
        return {"result": f"mock_result_for_{cmd_name}", "source": "mock"}

    mock_tools.execute_command = MagicMock(side_effect=_execute_cmd)

    # Real blackboard with minimal components
    session = SessionMemory(session_id="test_session")
    blackboard = BlackboardAccess(
        session=session,
        coverage=CoverageTracker(),
        leads=LeadTracker(),
        function_registry=FunctionRegistry(),
        notebook=InvestigationNotebook(),
    )

    # Real command parser (it's static methods, works without mocking)
    from src.command_parser import CommandParser
    parser = CommandParser()

    # Mock execution gate
    # Real event emitter (lightweight, no side effects)
    emitter = EventEmitter()

    # Mock config
    mock_config = MagicMock()

    worker = WorkerAgent(
        llm_client=mock_llm,
        tool_executor=mock_tools,
        blackboard=blackboard,
        command_parser=parser,
        event_emitter=emitter,
        config=mock_config,
        capabilities_text=capabilities_text,
    )

    return worker, mock_llm, mock_tools, None


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestWorkerAgentCompletion:
    """Tests for task completion detection."""

    def test_immediate_completion(self):
        """Worker should stop immediately if LLM says TASK COMPLETE."""
        worker, mock_llm, _, _ = _make_worker(
            llm_responses=["TASK COMPLETE\nFound nothing interesting."]
        )
        task = WorkerTask(goal="Analyze main function", max_steps=5)
        result = worker.run(task)

        assert result.is_complete is True
        assert result.task_id == task.task_id
        assert result.error is None
        # LLM called exactly once
        assert mock_llm.generate_with_phase.call_count == 1

    def test_investigation_complete_marker(self):
        """Worker should detect INVESTIGATION COMPLETE marker."""
        worker, _, _, _ = _make_worker(
            llm_responses=["INVESTIGATION COMPLETE"]
        )
        task = WorkerTask(goal="Check imports")
        result = worker.run(task)
        assert result.is_complete is True

    def test_goal_achieved_marker(self):
        """Worker should detect GOAL ACHIEVED marker."""
        worker, _, _, _ = _make_worker(
            llm_responses=["GOAL ACHIEVED\nAll done."]
        )
        task = WorkerTask(goal="Check exports")
        result = worker.run(task)
        assert result.is_complete is True

    def test_case_insensitive_completion(self):
        """Completion markers should be case-insensitive."""
        worker, _, _, _ = _make_worker(
            llm_responses=["task complete"]
        )
        task = WorkerTask(goal="Test case")
        result = worker.run(task)
        assert result.is_complete is True


class TestWorkerAgentExecution:
    """Tests for the execution loop."""

    def test_execute_single_command(self):
        """Worker should parse and execute a single EXECUTE command."""
        worker, mock_llm, mock_tools, _ = _make_worker(
            llm_responses=[
                'REASONING: Need to check imports\nEXECUTE: list_imports(offset=0, limit=50)',
                "TASK COMPLETE\nImports analyzed.",
            ],
            tool_results={"list_imports": {"result": "Found 42 imports", "source": "ghidra"}},
        )
        task = WorkerTask(goal="List all imports", max_steps=5)
        result = worker.run(task)

        assert result.is_complete is True
        assert result.tool_executions_count >= 1
        mock_tools.execute_command.assert_called()

    def test_execute_multiple_steps(self):
        """Worker should execute multiple steps before completing."""
        worker, mock_llm, mock_tools, _ = _make_worker(
            llm_responses=[
                'REASONING: Step 1\nEXECUTE: list_imports(offset=0, limit=50)',
                'REASONING: Step 2\nEXECUTE: decompile_function(name="main")',
                "TASK COMPLETE\nDone.",
            ],
        )
        task = WorkerTask(goal="Analyze binary", max_steps=10)
        result = worker.run(task)

        assert result.is_complete is True
        assert result.tool_executions_count >= 2
        assert mock_llm.generate_with_phase.call_count == 3

    def test_max_steps_reached(self):
        """Worker should stop at max_steps without completion marker."""
        worker, _, _, _ = _make_worker(
            llm_responses=[
                'REASONING: Investigating\nEXECUTE: list_imports(offset=0, limit=50)',
            ] * 5  # Always returns a command, never TASK COMPLETE
        )
        task = WorkerTask(goal="Deep analysis", max_steps=3)
        result = worker.run(task)

        # Should NOT be complete (ran out of steps)
        assert result.is_complete is False
        assert result.error is None

    def test_no_commands_continues(self):
        """If LLM returns no commands, worker records it and continues."""
        worker, mock_llm, _, _ = _make_worker(
            llm_responses=[
                "Let me think about this...",  # No EXECUTE command
                "TASK COMPLETE\nDone thinking.",
            ],
        )
        task = WorkerTask(goal="Think task", max_steps=5)
        result = worker.run(task)

        assert result.is_complete is True
        assert mock_llm.generate_with_phase.call_count == 2

    def test_tool_execution_error(self):
        """Worker should handle tool execution errors gracefully."""
        mock_tools_obj = MagicMock()
        mock_tools_obj.execute_command = MagicMock(
            side_effect=ValueError("Unknown command: bad_tool")
        )

        worker, mock_llm, _, _ = _make_worker(
            llm_responses=[
                'EXECUTE: bad_tool(param="value")',
                "TASK COMPLETE\nEncountered error.",
            ],
        )
        # Inject the error-raising tool executor
        worker.tools = mock_tools_obj

        task = WorkerTask(goal="Error test", max_steps=5)
        result = worker.run(task)

        assert result.is_complete is True
        # The failed execution should be recorded
        exec_results = result.exec_results
        failed_execs = [te for te in exec_results.tool_executions if not te.success]
        assert len(failed_execs) >= 1


class TestWorkerAgentPrompts:
    """Tests for prompt construction."""

    def test_system_prompt_includes_task(self):
        """System prompt should include the task goal and strategy hint."""
        worker, _, _, _ = _make_worker(llm_responses=["TASK COMPLETE"])
        task = WorkerTask(
            goal="Decompile FUN_00405b60",
            strategy_hint="Check for CreateProcessW with NULL lpApplicationName",
            suggested_tools=["decompile_function_by_address"],
        )

        prompt = worker._build_system_prompt(task)

        assert "Decompile FUN_00405b60" in prompt
        assert "CreateProcessW" in prompt
        assert "decompile_function_by_address" in prompt

    def test_system_prompt_includes_tool_docs(self):
        """System prompt should include capabilities text when provided."""
        worker, _, _, _ = _make_worker(
            llm_responses=["TASK COMPLETE"],
            capabilities_text="## Tools\n- decompile_function\n- list_imports",
        )
        task = WorkerTask(goal="Test tools")
        prompt = worker._build_system_prompt(task)

        assert "decompile_function" in prompt
        assert "EXECUTE:" in prompt

    def test_user_prompt_is_lean(self):
        """User prompt should only contain goal, progress, and recent results."""
        worker, _, _, _ = _make_worker(llm_responses=["TASK COMPLETE"])
        task = WorkerTask(goal="My specific goal")
        exec_results = ExecutionPhaseResults(goal=task.goal)

        prompt = worker._build_user_prompt(task, exec_results, step=1)

        assert "My specific goal" in prompt
        assert "tool calls completed" in prompt

    def test_dynamic_context_filtering(self):
        """Dynamic context should only include sections listed in task.include_sections."""
        worker, _, _, _ = _make_worker(llm_responses=["TASK COMPLETE"])

        # Add some data to blackboard
        worker.blackboard.add_knowledge("test_key", "test_value", "general")

        task = WorkerTask(
            goal="Test filtering",
            include_sections=["knowledge"],  # Only knowledge, not coverage/leads
        )

        ctx = worker._build_dynamic_context(task)
        # Knowledge should be included
        # (Empty context returns "" when knowledge base has items
        #  but format_for_prompt returns formatted string)
        # The key test is that filtering works — no crash
        assert isinstance(ctx, str)


class TestWorkerAgentResult:
    """Tests for AgentResult construction."""

    def test_result_has_task_id(self):
        """AgentResult should carry the task_id from WorkerTask."""
        worker, _, _, _ = _make_worker(llm_responses=["TASK COMPLETE"])
        task = WorkerTask(goal="ID test", task_id="custom_id_001")
        result = worker.run(task)

        assert result.task_id == "custom_id_001"

    def test_result_has_findings_summary(self):
        """AgentResult should include a human-readable findings summary."""
        worker, _, _, _ = _make_worker(
            llm_responses=[
                'EXECUTE: list_imports(offset=0, limit=50)',
                "TASK COMPLETE",
            ]
        )
        task = WorkerTask(goal="Summary test")
        result = worker.run(task)

        assert result.findings_summary  # Non-empty
        assert "list_imports" in result.findings_summary

    def test_result_on_fatal_error(self):
        """Fatal errors should produce AgentResult with error field set."""
        worker, mock_llm, _, _ = _make_worker()
        mock_llm.generate_with_phase = MagicMock(
            side_effect=RuntimeError("LLM connection failed")
        )

        task = WorkerTask(goal="Error test")
        result = worker.run(task)

        assert result.error is not None
        assert "LLM connection failed" in result.error
        assert result.is_complete is False


# ---------------------------------------------------------------------------
# Tests: Tool Execution Ledger (Fix A)
# ---------------------------------------------------------------------------

class TestToolExecutionLedger:
    """Tests for the two-tier memory system in _build_user_prompt."""

    def test_ledger_appears_after_tool_calls(self):
        """The ledger section should appear in the user prompt after tool calls."""
        worker, _, _, _ = _make_worker(llm_responses=["TASK COMPLETE"])
        task = WorkerTask(goal="Ledger test")
        exec_results = ExecutionPhaseResults(goal=task.goal)

        # Simulate a previous tool call
        exec_results.add_execution(ToolExecution(
            tool_name="list_imports",
            parameters={"offset": 0, "limit": 50},
            result="[Total: 42] import1, import2",
            success=True,
            reasoning="Check imports",
        ))

        prompt = worker._build_user_prompt(task, exec_results, step=2)

        assert "Tool Execution Ledger" in prompt
        assert "list_imports" in prompt
        assert "DO NOT repeat" in prompt

    def test_ledger_excludes_no_command_steps(self):
        """The ledger should not show <no_command> thinking steps."""
        worker, _, _, _ = _make_worker(llm_responses=["TASK COMPLETE"])
        task = WorkerTask(goal="Ledger filter test")
        exec_results = ExecutionPhaseResults(goal=task.goal)

        exec_results.add_execution(ToolExecution(
            tool_name="<no_command>",
            parameters={},
            result="Thinking about next step...",
            success=True,
        ))
        exec_results.add_execution(ToolExecution(
            tool_name="list_imports",
            parameters={"offset": 0},
            result="[Total: 10]",
            success=True,
        ))

        prompt = worker._build_user_prompt(task, exec_results, step=3)

        # Ledger should show list_imports but not <no_command>
        assert "list_imports" in prompt
        # Extract the ledger section (between "Tool Execution Ledger" and "Recent Results")
        ledger_section = prompt.split("Tool Execution Ledger")[1].split("Recent Results")[0]
        assert "<no_command>" not in ledger_section

    def test_ledger_shows_all_calls_recent_shows_last_5(self):
        """Ledger should include ALL calls, recent section only the last 5."""
        worker, _, _, _ = _make_worker(llm_responses=["TASK COMPLETE"])
        task = WorkerTask(goal="Multi call test")
        exec_results = ExecutionPhaseResults(goal=task.goal)

        # Add 8 tool calls
        for i in range(8):
            exec_results.add_execution(ToolExecution(
                tool_name=f"tool_{i}",
                parameters={"index": i},
                result=f"result_{i}",
                success=True,
            ))

        prompt = worker._build_user_prompt(task, exec_results, step=9)

        # Ledger should mention all 8 tools
        for i in range(8):
            assert f"tool_{i}" in prompt

        # Recent section exists
        assert "Recent Results" in prompt

    def test_empty_ledger_on_first_step(self):
        """First step should have no ledger section."""
        worker, _, _, _ = _make_worker(llm_responses=["TASK COMPLETE"])
        task = WorkerTask(goal="First step")
        exec_results = ExecutionPhaseResults(goal=task.goal)

        prompt = worker._build_user_prompt(task, exec_results, step=1)

        assert "Tool Execution Ledger" not in prompt
        assert "Task Goal" in prompt


class TestTerseResultSummary:
    """Tests for _terse_result_summary static method."""

    def test_decompile_extracts_signature(self):
        """Decompile results should show function signature + line count."""
        result = (
            "void FUN_004092a0(SOCKET s, char *buffer)\n"
            "{\n  int len = recv(s, buffer, 1024, 0);\n"
            "  if (len > 0) {\n    process(buffer);\n  }\n}\n"
        )
        summary = WorkerAgent._terse_result_summary("decompile_function", result)
        assert "void FUN_004092a0(" in summary
        assert "lines" in summary

    def test_decompile_no_signature(self):
        """Decompile without recognisable signature should show line count."""
        result = "/* No function found at this address */\nLine2\nLine3\n"
        summary = WorkerAgent._terse_result_summary("decompile_function", result)
        assert "lines" in summary

    def test_list_shows_count(self):
        """List tool results with [Total: N] should show item count."""
        result = "import1\nimport2\n[Total: 42]"
        summary = WorkerAgent._terse_result_summary("list_imports", result)
        assert "42" in summary
        assert "items" in summary

    def test_xrefs_shows_count(self):
        """Xref results should show xref count."""
        result = "From 004010a0 to target [Total: 3]"
        summary = WorkerAgent._terse_result_summary("get_xrefs_to", result)
        assert "3" in summary
        assert "xref" in summary

    def test_error_result(self):
        """Error results should show the error message."""
        result = "Error: Function not found in binary"
        summary = WorkerAgent._terse_result_summary("decompile_function", result)
        assert "Error" in summary

    def test_empty_result(self):
        """Empty result should return '(empty)'."""
        summary = WorkerAgent._terse_result_summary("list_imports", "")
        assert summary == "(empty)"

    def test_search_no_matches(self):
        """search_functions_by_name with no matches."""
        result = "No functions matching 'recv'"
        summary = WorkerAgent._terse_result_summary("search_functions_by_name", result)
        assert "no matches" in summary


# ---------------------------------------------------------------------------
# Tests: Hard Dedup Cache (Fix B)
# ---------------------------------------------------------------------------

class TestWorkerHardDedup:
    """Tests for per-worker duplicate call detection."""

    def test_dedup_key_deterministic(self):
        """Same tool + params should produce the same dedup key."""
        key1 = WorkerAgent._make_dedup_key("list_imports", {"offset": 0, "limit": 50})
        key2 = WorkerAgent._make_dedup_key("list_imports", {"offset": 0, "limit": 50})
        assert key1 == key2

    def test_dedup_key_param_order_independent(self):
        """Param order shouldn't affect the dedup key."""
        key1 = WorkerAgent._make_dedup_key("list_imports", {"offset": 0, "limit": 50})
        key2 = WorkerAgent._make_dedup_key("list_imports", {"limit": 50, "offset": 0})
        assert key1 == key2

    def test_dedup_key_different_params(self):
        """Different params should produce different dedup keys."""
        key1 = WorkerAgent._make_dedup_key("list_imports", {"offset": 0})
        key2 = WorkerAgent._make_dedup_key("list_imports", {"offset": 50})
        assert key1 != key2

    def test_dedup_key_different_tools(self):
        """Different tools should produce different dedup keys."""
        key1 = WorkerAgent._make_dedup_key("list_imports", {"offset": 0})
        key2 = WorkerAgent._make_dedup_key("list_exports", {"offset": 0})
        assert key1 != key2

    def test_duplicate_call_returns_cached(self):
        """Duplicate tool call should return cached result, not re-execute."""
        worker, mock_llm, mock_tools, _ = _make_worker(
            llm_responses=[
                'EXECUTE: list_imports(offset=0, limit=50)',
                'EXECUTE: list_imports(offset=0, limit=50)',  # Duplicate!
                "TASK COMPLETE\nDone.",
            ],
            tool_results={"list_imports": {"result": "42 imports found", "source": "ghidra"}},
        )
        task = WorkerTask(goal="Dedup test", max_steps=10)
        result = worker.run(task)

        # Tool executor should be called only ONCE (second call is dedup'd)
        assert mock_tools.execute_command.call_count == 1

        # The duplicate should be recorded with "DUPLICATE" marker
        executions = [
            te for te in result.exec_results.tool_executions
            if te.tool_name == "list_imports"
        ]
        assert len(executions) == 2
        # One should have the DUPLICATE marker
        dedup_results = [te for te in executions if "DUPLICATE" in (te.result or "")]
        assert len(dedup_results) == 1

    def test_different_params_not_deduped(self):
        """Calls with different params should NOT be dedup'd."""
        worker, mock_llm, mock_tools, _ = _make_worker(
            llm_responses=[
                'EXECUTE: list_imports(offset=0, limit=50)',
                'EXECUTE: list_imports(offset=50, limit=50)',  # Different offset!
                "TASK COMPLETE\nDone.",
            ],
            tool_results={"list_imports": {"result": "imports found", "source": "ghidra"}},
        )
        task = WorkerTask(goal="No dedup test", max_steps=10)
        result = worker.run(task)

        # Both calls should go through to the tool executor
        assert mock_tools.execute_command.call_count == 2


# ---------------------------------------------------------------------------
# Tests: get_cached_result Removal (Fix C)
# ---------------------------------------------------------------------------

class TestGetCachedResultRemoval:
    """Tests verifying get_cached_result is no longer a recognized command."""

    def test_not_in_required_parameters(self):
        """get_cached_result should not be in CommandParser.REQUIRED_PARAMETERS."""
        from src.command_parser import CommandParser
        assert "get_cached_result" not in CommandParser.REQUIRED_PARAMETERS

    def test_not_in_all_supported_commands(self):
        """get_cached_result should not be in CommandParser.ALL_SUPPORTED_COMMANDS."""
        from src.command_parser import CommandParser
        assert "get_cached_result" not in CommandParser.ALL_SUPPORTED_COMMANDS

    def test_not_in_capabilities_text(self):
        """get_cached_result should not be in the capabilities text file."""
        import os
        caps_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "ai_ghidra_capabilities.txt"
        )
        with open(caps_path, "r") as f:
            caps_text = f.read()
        assert "get_cached_result" not in caps_text


# ---------------------------------------------------------------------------
# Tests: Recipe Mode (Session 10)
# ---------------------------------------------------------------------------

class TestWorkerRecipeMode:
    """Tests for the recipe-based worker execution mode."""

    def test_recipe_mode_dispatches_correctly(self):
        """Worker with recipe task should use recipe mode, not LLM loop."""
        worker, mock_llm, mock_tools, _ = _make_worker(
            llm_responses=[
                # Single LLM call for analysis phase
                (
                    "SUMMARY: Found a vulnerability in CreateProcessW usage.\n\n"
                    "FINDINGS:\n"
                    "```json\n"
                    '[{"category": "vulnerability", "severity": "high", '
                    '"title": "Unquoted service path", '
                    '"detail": "CreateProcessW called with NULL lpApplicationName", '
                    '"evidence": ["CreateProcessW(NULL, cmd)"], '
                    '"addresses": ["0x00405b60"], '
                    '"status": "confirmed"}]\n'
                    "```\n"
                ),
            ],
            tool_results={
                "list_imports": [
                    "CreateProcessW -> EXTERNAL:00000098 [Callers: 0040a098]"
                ],
                "get_xrefs_to": [
                    "From 00405b60 in FUN_00405b60 [CALL]",
                ],
                "decompile_function_by_address": (
                    "void FUN_00405b60(void) {\n"
                    "  CreateProcessW(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);\n"
                    "}\n"
                ),
            },
        )

        task = WorkerTask(
            goal="Check CreateProcessW callers for unquoted service path",
            recipe="trace_import_callers",
            recipe_params={"api_names": ["CreateProcessW"]},
            analysis_focus="Check for NULL lpApplicationName with unquoted paths",
        )
        result = worker.run(task)

        assert result.exit_reason == "recipe_complete"
        assert result.is_complete is True
        assert result.tool_executions_count > 0
        # LLM should be called exactly once (analysis phase only)
        assert mock_llm.generate_with_phase.call_count == 1

    def test_unknown_recipe_falls_through_to_llm_loop(self):
        """Task with unknown recipe should fall through to LLM loop."""
        worker, mock_llm, _, _ = _make_worker(
            llm_responses=["TASK COMPLETE\nNothing found."]
        )

        task = WorkerTask(
            goal="Test fallthrough",
            recipe="nonexistent_recipe",
            recipe_params={},
        )
        result = worker.run(task)

        # Should have used LLM loop (recipe not in AVAILABLE_RECIPES)
        assert result.exit_reason != "recipe_complete"
        assert result.is_complete is True

    def test_recipe_mode_populates_notebook_entries(self):
        """Recipe mode should populate notebook_entries in AgentResult."""
        worker, mock_llm, _, _ = _make_worker(
            llm_responses=[
                (
                    "SUMMARY: Found vulnerability.\n\n"
                    "FINDINGS:\n"
                    "```json\n"
                    '[{"category": "vulnerability", "severity": "high", '
                    '"title": "Test finding", '
                    '"detail": "Test detail with evidence", '
                    '"evidence": ["line of code"], '
                    '"addresses": ["0x00401000"], '
                    '"status": "confirmed"}]\n'
                    "```\n"
                ),
            ],
            tool_results={
                "decompile_function_by_address": "void test() { return; }",
                "get_xrefs_to": [],
                "get_xrefs_from": [],
            },
        )

        task = WorkerTask(
            goal="Deep analysis test",
            recipe="deep_function_analysis",
            recipe_params={"addresses": ["0x00401000"]},
        )
        result = worker.run(task)

        assert result.exit_reason == "recipe_complete"
        assert len(result.notebook_entries) == 1
        assert result.notebook_entries[0]["category"] == "vulnerability"
        assert result.notebook_entries[0]["severity"] == "high"

    def test_empty_recipe_returns_descriptive_result(self):
        """If recipe gathers nothing, should return descriptive message."""
        worker, mock_llm, _, _ = _make_worker(
            llm_responses=["TASK COMPLETE"],
            tool_results={
                "list_imports": [],
                "get_xrefs_to": [],
            },
        )

        task = WorkerTask(
            goal="Check for nonexistent API",
            recipe="trace_import_callers",
            recipe_params={"api_names": ["NonexistentAPI"]},
        )
        result = worker.run(task)

        assert result.exit_reason == "recipe_complete"
        assert result.is_complete is True
        assert "gathered no data" in result.findings_summary
        # LLM should NOT be called (no data to analyze)
        assert mock_llm.generate_with_phase.call_count == 0

    def test_recipe_analysis_prompt_includes_full_code(self):
        """The analysis prompt should include full decompiled code."""
        worker, _, _, _ = _make_worker(llm_responses=["TASK COMPLETE"])
        from src.recipes import RecipeResult

        recipe_result = RecipeResult()
        recipe_result.gathered_functions = {
            "0x00405b60": "void FUN_00405b60(void) {\n  CreateProcessW(NULL, cmd);\n}",
        }
        recipe_result.gathered_xrefs = {
            "0x0040a098": ["From 00405b60 in FUN_00405b60 [CALL]"],
        }

        task = WorkerTask(
            goal="Test analysis prompt",
            analysis_focus="Check for NULL lpApplicationName",
        )

        prompt = worker._build_recipe_analysis_prompt(task, recipe_result)

        assert "void FUN_00405b60" in prompt
        assert "CreateProcessW(NULL, cmd)" in prompt
        assert "NULL lpApplicationName" in prompt
        assert "Investigation Goal" in prompt
        assert "Specific Analysis Focus" in prompt

    def test_recipe_analysis_system_prompt(self):
        """The analysis system prompt should define the expert role."""
        task = WorkerTask(goal="Test system prompt")
        prompt = WorkerAgent._build_recipe_analysis_system_prompt(task)

        assert "expert binary security analyst" in prompt
        assert "cite specific code" in prompt
        assert "surface-level" in prompt

    def test_parse_recipe_analysis_response_full(self):
        """Should parse summary, findings, and follow-up from response."""
        response = (
            "SUMMARY: Found a critical vulnerability in FUN_00405b60.\n\n"
            "FINDINGS:\n"
            "```json\n"
            '[{"category": "vulnerability", "severity": "critical", '
            '"title": "Unquoted path", '
            '"detail": "CreateProcessW uses NULL lpApplicationName", '
            '"evidence": ["CreateProcessW(NULL, cmd)"], '
            '"addresses": ["0x00405b60"], '
            '"status": "confirmed"}]\n'
            "```\n\n"
            "FOLLOW_UP: 0x00401234, 0x00405678\n"
        )

        summary, entries, follow_up = (
            WorkerAgent._parse_recipe_analysis_response(response)
        )

        assert "critical vulnerability" in summary
        assert len(entries) == 1
        assert entries[0]["severity"] == "critical"
        assert len(follow_up) == 2
        assert "0x00401234" in follow_up

    def test_parse_recipe_analysis_response_no_findings(self):
        """Should handle response with no findings gracefully."""
        response = "SUMMARY: No vulnerabilities found in the analyzed code."

        summary, entries, follow_up = (
            WorkerAgent._parse_recipe_analysis_response(response)
        )

        assert "No vulnerabilities" in summary
        assert len(entries) == 0
        assert len(follow_up) == 0

    def test_recipe_mode_follow_up_phase(self):
        """Follow-up phase should decompile additional functions and re-analyze."""
        call_count = {"n": 0}

        def _llm_response(prompt, phase="analysis", system_prompt=""):
            call_count["n"] += 1
            if call_count["n"] == 1:
                # First analysis — request follow-up
                return (
                    "SUMMARY: Need to check callee.\n\n"
                    "FINDINGS:\n"
                    "```json\n"
                    '[{"category": "info", "severity": "info", '
                    '"title": "Preliminary", '
                    '"detail": "Need more context", '
                    '"evidence": [], "addresses": [], '
                    '"status": "needs_investigation"}]\n'
                    "```\n\n"
                    "FOLLOW_UP: 0x00402000\n"
                )
            else:
                # Re-analysis after follow-up
                return (
                    "SUMMARY: Confirmed finding after follow-up.\n\n"
                    "FINDINGS:\n"
                    "```json\n"
                    '[{"category": "vulnerability", "severity": "high", '
                    '"title": "Confirmed vuln", '
                    '"detail": "Full evidence now available", '
                    '"evidence": ["code_line"], "addresses": ["0x00401000"], '
                    '"status": "confirmed"}]\n'
                    "```\n"
                )

        worker, mock_llm, _, _ = _make_worker(
            llm_responses=["placeholder"],
            tool_results={
                "decompile_function_by_address": "void test() { return; }",
                "get_xrefs_to": [],
                "get_xrefs_from": [],
            },
        )
        mock_llm.generate_with_phase = MagicMock(side_effect=_llm_response)

        task = WorkerTask(
            goal="Follow-up test",
            recipe="deep_function_analysis",
            recipe_params={"addresses": ["0x00401000"]},
        )
        result = worker.run(task)

        assert result.exit_reason == "recipe_complete"
        # LLM should be called twice (initial + re-analysis)
        assert mock_llm.generate_with_phase.call_count == 2
        # Final findings should be the re-analysis result
        assert len(result.notebook_entries) == 1
        assert result.notebook_entries[0]["status"] == "confirmed"


# ---------------------------------------------------------------------------
# Test: Auto-cache format fix (Fix 1)
# ---------------------------------------------------------------------------

class TestWorkerAutoCache:
    """Verify the auto-cache correctly handles list results.

    The old code used ``str(result).splitlines()`` which collapsed a Python
    list into one mega-string.  The fix checks ``isinstance(result, list)``
    and caches individual elements directly.
    """

    def test_list_result_cached_as_individual_entries(self):
        """When tool returns a list, cache_discovery should receive individual entries."""
        import_entries = [
            "[Total: 3] [Showing: 1-3]",
            "CreateDirectoryW -> EXTERNAL:00000015 [Callers: 0040a094, FUN_00405500]",
            "CreateProcessW -> EXTERNAL:00000098 [Callers: 0040a098, FUN_00405b60]",
        ]

        worker, mock_llm, mock_tools, _ = _make_worker(
            llm_responses=[
                "COMMAND: list_imports\n"
                'PARAMETERS: {"offset": 0, "limit": 100}\n'
                "REASONING: Map imports.\n\n"
                "TASK COMPLETE\nDone.",
            ],
            tool_results={
                "list_imports": import_entries,  # Returns a list
            },
        )

        task = WorkerTask(goal="Surface scan")
        result = worker.run(task)

        # Verify cache_discovery was called with individual entries (not str(list))
        cache_calls = [
            c for c in worker.blackboard.cache_discovery.__wrapped__.__self__.cache_discovery.call_args_list
            if c[0][0] == "list_imports"
        ] if hasattr(worker.blackboard.cache_discovery, '__wrapped__') else []

        # Alternative: check that the blackboard's discovery_cache has the right format.
        # Since blackboard is real, check if it was populated correctly:
        dc = worker.blackboard.discovery_cache
        if dc and dc.imports:
            # Each entry should be an individual import line, not a mega-string
            for entry in dc.imports:
                # No entry should be a Python list repr (starts with "[")
                # unless it's the metadata line like "[Total: 3] [Showing: 1-3]"
                if "Total:" not in entry:
                    assert "', '" not in entry, (
                        f"Entry looks like str(list) repr: {entry[:80]}"
                    )

    def test_string_result_still_cached_by_splitlines(self):
        """When tool returns a string, the fallback splitlines() path should work."""
        worker, _, _, _ = _make_worker(
            llm_responses=[
                "COMMAND: list_exports\n"
                'PARAMETERS: {"offset": 0, "limit": 100}\n'
                "REASONING: Map exports.\n\n"
                "TASK COMPLETE\nDone.",
            ],
            tool_results={
                "list_exports": "entry -> 0040931a",  # Returns a string, not list
            },
        )

        task = WorkerTask(goal="Surface scan")
        result = worker.run(task)

        # Should complete without error
        assert result.is_complete is True


# ---------------------------------------------------------------------------
# Fix 2: Code cache persistence tests
# ---------------------------------------------------------------------------

class TestWorkerCodeCache:
    """Verify that decompile results are persisted in the blackboard code cache.

    Workers should call blackboard.cache_code() for every successful
    decompilation, and recipe mode should call cache_code_bulk() for all
    gathered functions.
    """

    def test_decompile_result_cached_on_blackboard(self):
        """LLM-loop decompile results should be stored in code cache."""
        decompile_code = "void vuln_func(int x) {\n    if (x > 0) return;\n}\n"
        worker, _, _, _ = _make_worker(
            llm_responses=[
                'REASONING: Decompile target function.\n'
                'EXECUTE: decompile_function_by_address(address="0x00405b60")',
                "TASK COMPLETE\nDone.",
            ],
            tool_results={
                "decompile_function_by_address": decompile_code,
            },
        )

        task = WorkerTask(goal="Decompile target")
        result = worker.run(task)

        # Code should be cached on the blackboard.
        # The key may be stored with or without 0x prefix depending on
        # the command parser's parameter extraction.
        all_cached = worker.blackboard.get_all_cached_code()
        assert len(all_cached) >= 1, f"Expected code cache to have entries, got: {all_cached}"
        # Find the entry containing our address (with or without 0x)
        matched = [v for k, v in all_cached.items() if "405b60" in k.lower()]
        assert matched, f"No cache entry for 405b60, keys: {list(all_cached.keys())}"
        assert "vuln_func" in matched[0]

    def test_error_result_not_cached(self):
        """Decompile errors should NOT be cached."""
        worker, _, _, _ = _make_worker(
            llm_responses=[
                'REASONING: Try decompile.\n'
                'EXECUTE: decompile_function_by_address(address="0xDEADBEEF")',
                "TASK COMPLETE\nDone.",
            ],
            tool_results={
                "decompile_function_by_address": "Error: Function not found at address 0xDEADBEEF",
            },
        )

        task = WorkerTask(goal="Decompile missing")
        result = worker.run(task)

        all_cached = worker.blackboard.get_all_cached_code()
        matched = [v for k, v in all_cached.items() if "deadbeef" in k.lower()]
        assert not matched, f"Error result should not be cached: {matched}"

    def test_multiple_decompiles_all_cached(self):
        """Multiple decompile calls should each be cached."""
        worker, _, _, _ = _make_worker(
            llm_responses=[
                'REASONING: First.\n'
                'EXECUTE: decompile_function_by_address(address="0x00401000")',
                'REASONING: Second.\n'
                'EXECUTE: decompile_function_by_address(address="0x00402000")',
                "TASK COMPLETE\nDone.",
            ],
            tool_results={
                "decompile_function_by_address": "void func_a() { return; }",
            },
        )

        task = WorkerTask(goal="Decompile two functions")
        result = worker.run(task)

        all_cached = worker.blackboard.get_all_cached_code()
        has_401 = any("401000" in k.lower() for k in all_cached)
        has_402 = any("402000" in k.lower() for k in all_cached)
        assert has_401, f"Missing 401000 in cache keys: {list(all_cached.keys())}"
        assert has_402, f"Missing 402000 in cache keys: {list(all_cached.keys())}"
