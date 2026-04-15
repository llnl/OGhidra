"""
WorkerAgent — Generic task executor for the OGhidra orchestration system.

A WorkerAgent receives a ``WorkerTask`` from the Orchestrator, runs a
dynamic execution loop (LLM → parse commands → execute tools → repeat),
and returns an ``AgentResult`` with findings.

There is only ONE WorkerAgent class — no subclasses.  Specialization comes
entirely from the *task assignment* (goal, strategy hint, suggested tools,
included context sections).  This prevents recreating the old rigid phases
under new names.

Key design decisions:
  - The worker sees ONLY the blackboard sections listed in
    ``task.include_sections`` (filtered via SystemContextBuilder).
  - The worker builds its own system prompt from: tool docs, task
    assignment, and filtered dynamic context.
  - The worker's user prompt is lean: goal, step progress, recent results
    from *this worker's* run only.
  - Post-execution hooks (analysis state, coverage) run automatically via
    the shared ToolExecutor's ``on_command_executed`` callback.
  - The ExecutionGatekeeper is shared — doom-loop/artifact detection works
    identically to the monolithic loop.

Dynamic loop model (inspired by opencode sub-agents):
  - The loop is ``while True`` — the LLM decides when the task is done.
  - A *soft limit* (``task.soft_limit``) injects budget warnings into the
    system prompt, advising the LLM to wrap up.
  - A *hard ceiling* (``task.max_steps``) is the safety abort if the LLM
    ignores all warnings.
  - Doom-loop detection auto-terminates if the same tool+params are called
    N times consecutively.
"""

import json
import logging
from datetime import datetime
from typing import Dict, Optional, List, Any

from src.agents.base import WorkerTask, AgentResult
from src.models.memory import (
    SystemContextBuilder,
    ExecutionPhaseResults,
    ToolExecution,
    ExecutionSignal,
    ExecutionGate,
    NotebookEntry,
)
from src.recipes import (
    RecipeExecutor,
    RecipeResult,
    AVAILABLE_RECIPES,
    MAX_CODE_LINES_PER_FUNCTION,
)
from src.recipe_registry import RecipeRegistry


class WorkerAgent:
    """
    Generic task executor.  Runs a dynamic execution loop for an assigned task.

    Usage::

        worker = WorkerAgent(
            llm_client=ollama,
            tool_executor=tool_executor,
            blackboard=blackboard,
            command_parser=command_parser,
            execution_gate=gate,
            event_emitter=emitter,
            config=llm_config,
            capabilities_text=caps,
        )
        result = worker.run(task)
    """

    # Sentinel strings the LLM can emit to signal task completion
    COMPLETION_MARKERS = ("INVESTIGATION COMPLETE", "TASK COMPLETE", "GOAL ACHIEVED")

    # Number of identical consecutive tool calls that trigger doom-loop abort
    DOOM_LOOP_THRESHOLD = 3

    # Maximum consecutive errors for the same tool before auto-skipping
    CONSECUTIVE_ERROR_THRESHOLD = 3

    @staticmethod
    def _make_dedup_key(tool_name: str, params: dict) -> str:
        """Create a deterministic cache key for a (tool, params) pair.

        Sorts params so that key order doesn't matter, and uses JSON
        serialisation for determinism.
        """
        try:
            params_canonical = json.dumps(params, sort_keys=True, default=str)
        except (TypeError, ValueError):
            params_canonical = str(sorted(params.items()))
        return f"{tool_name}::{params_canonical}"

    def __init__(
        self,
        llm_client,
        tool_executor,
        blackboard,
        command_parser,
        event_emitter,
        config,
        capabilities_text: Optional[str] = None,
        logger: Optional[logging.Logger] = None,
        recipe_registry: Optional[RecipeRegistry] = None,
    ):
        """
        Args:
            llm_client: OllamaClient / ExternalClient / CustomAPIClient instance.
            tool_executor: Shared ``ToolExecutor`` for executing Ghidra commands.
            blackboard: ``BlackboardAccess`` for reading shared investigation state.
            command_parser: ``CommandParser`` for extracting EXECUTE commands from LLM text.
            event_emitter: ``EventEmitter`` for CoT / gate events.
            config: LLM configuration object (has ``execution_system_prompt``, model_map, etc.).
            capabilities_text: Optional tool documentation string (from ai_ghidra_capabilities.txt).
            logger: Optional logger instance.
        """
        self.llm = llm_client
        self.tools = tool_executor
        self.blackboard = blackboard
        self.parser = command_parser
        self.emitter = event_emitter
        self.config = config
        self.capabilities_text = capabilities_text
        self.logger = logger or logging.getLogger(__name__)
        self.recipe_registry = recipe_registry

        # Worker context compaction (reduces token waste on long runs)
        from src.worker_compactor import WorkerContextCompactor
        try:
            threshold = int(getattr(config, "worker_compaction_threshold", 6))
        except (TypeError, ValueError):
            threshold = 6
        self._compactor = WorkerContextCompactor(threshold=threshold)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(self, task: WorkerTask) -> AgentResult:
        """Execute a task and return structured results.

        Dispatches to recipe mode or legacy LLM loop based on the task:
          - If ``task.recipe`` is set and valid → ``_run_recipe_mode()``
          - Otherwise → ``_run_llm_loop()`` (legacy behavior)

        Args:
            task: The ``WorkerTask`` from the Orchestrator.

        Returns:
            ``AgentResult`` containing findings, tool execution history,
            discovered leads, and completion status.
        """
        recipe_known = (
            (self.recipe_registry and self.recipe_registry.has_recipe(task.recipe))
            or task.recipe in AVAILABLE_RECIPES
        )
        if task.recipe and recipe_known:
            return self._run_recipe_mode(task)
        return self._run_llm_loop(task)

    def _run_llm_loop(self, task: WorkerTask) -> AgentResult:
        """Legacy LLM-driven execution loop.

        Dynamic execution loop:
          1. Build system prompt (tool docs + task assignment + filtered context)
          2. Loop until completion, budget exhaustion, or safety ceiling:
             a. Check hard ceiling (safety abort)
             b. Inject budget warnings at soft limit
             c. Build lean user prompt (goal + step progress + recent results)
             d. Call LLM
             e. Check for completion markers (primary exit)
             f. Parse EXECUTE commands
             g. Gate check → execute tool → gate check
             h. Record result
             i. Check for doom loops (repeated identical calls)
          3. Package everything into an ``AgentResult``

        Args:
            task: The ``WorkerTask`` from the Orchestrator.

        Returns:
            ``AgentResult`` containing findings, tool execution history,
            discovered leads, and completion status.
        """
        self.logger.info(f"[Worker:{task.task_id}] Starting task: {task.goal[:80]}...")
        self.emitter.emit_cot("Worker", f"Starting task {task.task_id}: {task.goal[:100]}")

        exec_results = ExecutionPhaseResults(goal=task.goal)
        exit_reason = ""
        step = 0
        # Per-worker dedup cache: maps (tool, params) → (result_str, success, step)
        # Prevents identical Ghidra calls within the same worker run.
        dedup_cache: Dict[str, tuple] = {}

        try:
            # Build system prompt once (static for this worker's lifetime)
            system_prompt = self._build_system_prompt(task)

            while True:
                step += 1

                # ── HARD CEILING (safety abort) ──
                if step > task.max_steps:
                    self.logger.warning(
                        f"[Worker:{task.task_id}] Hard ceiling reached at step {step - 1}"
                    )
                    exit_reason = "hard_ceiling"
                    break

                # Rebuild dynamic context each step (blackboard may have changed)
                dynamic_ctx = self._build_dynamic_context(task)
                full_system = (
                    system_prompt + "\n\n" + dynamic_ctx if dynamic_ctx else system_prompt
                )

                # Lean user prompt
                user_prompt = self._build_user_prompt(task, exec_results, step)

                # ----- LLM call -----
                step_label = f"Step {step}/{task.max_steps}"

                self.emitter.emit_cot(
                    "Tool",
                    f"[Worker:{task.task_id}] {step_label}",
                    also_print=True,
                )
                real_tools = sum(
                    1 for te in exec_results.tool_executions
                    if te.tool_name != "<no_command>"
                )
                self.emitter.emit_agent_event("worker_step", {
                    "task_id": task.task_id,
                    "step": step,
                    "tool_count": exec_results.total_steps,
                    "real_tool_count": real_tools,
                })

                response = self.llm.generate_with_phase(
                    user_prompt, phase="execution", system_prompt=full_system
                )

                # ----- Completion check (primary exit) -----
                if self._is_complete(response):
                    self.logger.info(f"[Worker:{task.task_id}] Task complete at step {step}")
                    exec_results.investigation_complete = True
                    exec_results.completed_at = datetime.now()
                    # Save the LLM's final response — this contains the actual answer
                    exec_results.compaction_summary = response
                    exit_reason = "llm_complete"
                    break

                # ----- Extract reasoning (for logging) -----
                reasoning = self._extract_reasoning(response)
                if reasoning:
                    self.emitter.emit_cot("Reasoning", reasoning, also_print=False)

                # ----- Parse commands -----
                commands = self.parser.extract_commands(response)
                if not commands:
                    self.logger.debug(
                        f"[Worker:{task.task_id}] Step {step}: no commands extracted, continuing"
                    )
                    # Record the response as a "thinking" step so the LLM sees it next iteration
                    exec_results.add_execution(ToolExecution(
                        tool_name="<no_command>",
                        parameters={},
                        result=response[:500],
                        success=True,
                        reasoning=reasoning,
                    ))
                    continue

                # Cap commands per response to prevent runaway multi-execution
                MAX_COMMANDS_PER_RESPONSE = 3
                if len(commands) > MAX_COMMANDS_PER_RESPONSE:
                    self.logger.info(
                        f"[Worker:{task.task_id}] Capping {len(commands)} commands "
                        f"to {MAX_COMMANDS_PER_RESPONSE} per response"
                    )
                    commands = commands[:MAX_COMMANDS_PER_RESPONSE]

                # ----- Execute each command -----
                for cmd_name, cmd_params in commands:
                    # Skip tool if it has failed too many times consecutively
                    if self._count_consecutive_errors(cmd_name, exec_results) >= self.CONSECUTIVE_ERROR_THRESHOLD:
                        self.logger.warning(
                            f"[Worker:{task.task_id}] Skipping {cmd_name} — "
                            f"failed {self.CONSECUTIVE_ERROR_THRESHOLD}x consecutively"
                        )
                        exec_results.add_execution(ToolExecution(
                            tool_name=cmd_name,
                            parameters=cmd_params,
                            result=f"SKIPPED: {cmd_name} has failed "
                                   f"{self.CONSECUTIVE_ERROR_THRESHOLD} times consecutively. "
                                   f"Try a different tool or approach.",
                            success=False,
                            reasoning="Consecutive error threshold reached",
                        ))
                        continue

                    # ── Hard dedup: skip identical (tool, params) calls ──
                    dedup_key = self._make_dedup_key(cmd_name, cmd_params)
                    if dedup_key in dedup_cache:
                        cached_result, cached_success, cached_step = dedup_cache[dedup_key]
                        self.logger.info(
                            f"[Worker:{task.task_id}] DEDUP HIT: {cmd_name} "
                            f"(same params as step {cached_step}) — returning cached result"
                        )
                        result_str = (
                            f"[DUPLICATE — identical call was already made in step "
                            f"{cached_step}. Cached result returned. Do NOT repeat "
                            f"this call.]\n{cached_result}"
                        )
                        exec_results.add_execution(ToolExecution(
                            tool_name=cmd_name,
                            parameters=cmd_params,
                            result=result_str[:2000],
                            success=cached_success,
                            reasoning=f"Dedup hit (step {cached_step})",
                        ))
                        continue

                    # Execute
                    try:
                        result = self.tools.execute_command(cmd_name, cmd_params)
                        result_str = str(result)
                        success = True
                        self.blackboard.tool_health.record_success(cmd_name)
                    except Exception as e:
                        result_str = f"ERROR: {str(e)[:500]}"
                        result = result_str
                        success = False
                        self.blackboard.tool_health.record_failure(cmd_name)
                        self.logger.warning(
                            f"[Worker:{task.task_id}] Tool error: {cmd_name} → {str(e)[:200]}"
                        )

                    # Store in dedup cache (both successes and errors)
                    dedup_cache[dedup_key] = (result_str[:2000], success, step)

                    # Record execution
                    exec_results.add_execution(ToolExecution(
                        tool_name=cmd_name,
                        parameters=cmd_params,
                        result=result_str[:2000],  # Cap storage size
                        success=success,
                        reasoning=reasoning,
                    ))

                    # Auto-mark coverage from tool results
                    # (In orchestrator mode, the legacy bridge loop doesn't run,
                    #  so the worker must update coverage directly.)
                    if success:
                        try:
                            self.blackboard.coverage.auto_mark_from_result(
                                cmd_name, str(cmd_params), result_str,
                            )
                        except Exception as e:
                            self.logger.debug(f"Coverage auto-mark failed: {e}")

                        # Update total binary function count from list_functions
                        if cmd_name == "list_functions" and result_str:
                            self._update_function_count(result_str)

                        # Auto-register decompiled functions to FunctionRegistry
                        # and persist full code in code cache for cross-worker use
                        if cmd_name in ("decompile_function", "decompile_function_by_address"):
                            self._auto_register_function(cmd_name, cmd_params, result_str)
                            # Persist full decompiled code on the blackboard
                            _code_addr = cmd_params.get(
                                "address", cmd_params.get("name", "")
                            )
                            if _code_addr and success and not result_str.startswith("Error"):
                                try:
                                    self.blackboard.cache_code(
                                        str(_code_addr), result_str
                                    )
                                except Exception as e:
                                    self.logger.debug(f"Code cache failed: {e}")

                        # Auto-cache discovery results for future workers
                        if cmd_name in ("list_imports", "list_exports", "list_strings",
                                        "search_strings_in_binary", "list_functions"):
                            try:
                                # Use the raw result (list) directly when available.
                                # str(list) produces a single-line Python repr that
                                # corrupts per-entry structure when split by newlines.
                                if isinstance(result, list):
                                    parsed = [
                                        str(item).strip() for item in result
                                        if str(item).strip()
                                        and not str(item).startswith("Error")
                                    ]
                                else:
                                    parsed = [
                                        line.strip()
                                        for line in result_str.splitlines()
                                        if line.strip()
                                        and not line.startswith("Error")
                                    ]
                                if parsed:
                                    self.blackboard.cache_discovery(
                                        cmd_name, cmd_params, parsed
                                    )
                            except Exception as e:
                                self.logger.debug(f"Discovery cache failed: {e}")

                    self.emitter.emit_cot(
                        "Tool",
                        f"[Worker:{task.task_id}] {cmd_name} → {'OK' if success else 'ERR'}",
                    )

                    # Artifact scanning — detect security patterns in results
                    from src.artifact_scanner import scan_for_artifacts
                    artifacts = scan_for_artifacts(result_str)
                    if artifacts:
                        self._promote_scan_artifacts_to_notebook(
                            cmd_name, task, artifacts,
                        )

                # ── DOOM LOOP DETECTION ──
                if self._detect_doom_loop(exec_results):
                    self.logger.warning(
                        f"[Worker:{task.task_id}] Doom loop detected at step {step}"
                    )
                    self.emitter.emit_cot(
                        "Worker",
                        f"[Worker:{task.task_id}] Doom loop — same tool+params "
                        f"repeated {self.DOOM_LOOP_THRESHOLD}x. Stopping.",
                    )
                    exit_reason = "doom_loop"
                    break

            # Mark completed_at if not already set
            if not exec_results.completed_at:
                exec_results.completed_at = datetime.now()

        except Exception as e:
            self.logger.error(f"[Worker:{task.task_id}] Fatal error: {e}", exc_info=True)
            self.emitter.emit_cot("Worker", f"[{task.task_id}] FATAL: {e}")
            real_count = sum(
                1 for te in exec_results.tool_executions
                if te.tool_name != "<no_command>"
            )
            return AgentResult(
                task_id=task.task_id,
                error=str(e),
                exec_results=exec_results,
                tool_executions_count=real_count,
                exit_reason="error",
            )

        # ----- Build AgentResult -----
        findings = self._extract_findings(exec_results, exit_reason)
        real_count = sum(
            1 for te in exec_results.tool_executions
            if te.tool_name != "<no_command>"
        )

        self.emitter.emit_cot(
            "Worker",
            f"Task {task.task_id} finished: {real_count} tool calls "
            f"({exec_results.total_steps} total steps), "
            f"complete={exec_results.investigation_complete}, exit={exit_reason}",
        )

        # The LLM's final response (when it said TASK COMPLETE) contains
        # the actual answer — use it as final_response for conversational mode
        final_response = None
        if exec_results.compaction_summary and exit_reason == "llm_complete":
            # Strip the TASK COMPLETE marker from the response text
            raw = exec_results.compaction_summary
            for marker in ("TASK COMPLETE", "INVESTIGATION COMPLETE", "GOAL ACHIEVED"):
                raw = raw.replace(marker, "")
            final_response = raw.strip()

        return AgentResult(
            task_id=task.task_id,
            findings_summary=findings,
            final_response=final_response,
            exec_results=exec_results,
            tool_executions_count=real_count,
            is_complete=exec_results.investigation_complete,
            exit_reason=exit_reason,
        )

    # ------------------------------------------------------------------
    # Prompt building
    # ------------------------------------------------------------------

    def _build_system_prompt(self, task: WorkerTask) -> str:
        """Build the static portion of the worker's system prompt.

        Includes: role definition, tool documentation, task assignment,
        and execution response format instructions.
        """
        sections: List[str] = []

        # 1. Role definition
        sections.append(
            "You are an expert reverse engineer using Ghidra. "
            "Answer the user's question by using the available tools to "
            "gather information, then provide a clear, detailed response.\n\n"
            "**Your goal is to ANSWER THE QUESTION, not just call tools.** "
            "Use tools to gather the data you need, then synthesize your "
            "findings into a helpful response."
        )

        # 2. Tool documentation
        if self.capabilities_text:
            sections.append(
                f"## Available Tools\n"
                f"You have access to the following Ghidra interaction tools.\n\n"
                f"{self.capabilities_text}\n\n"
                f"## Tool Execution Format\n"
                f"To call a tool, use this EXACT format:\n"
                f"EXECUTE: tool_name(param1=\"value1\", param2=\"value2\")\n\n"
                f"Rules:\n"
                f"- Output ONLY the EXECUTE line, no extra text around it\n"
                f"- String values MUST be in double quotes\n"
                f"- Numerical values should NOT be quoted\n"
                f"- Use exact tool and parameter names from the list above\n"
                f"- Do NOT repeat a tool call with identical parameters — results are deterministic\n"
                f"- Listing tools return max 20 items per page. Use offset pagination for more\n"
                f"- Check the Discovery section in your context — imports/exports/strings may already\n"
                f"  be cached from a previous worker. Do NOT re-call tools for data you already have\n\n"
                f"Examples:\n"
                f"EXECUTE: decompile_function(name=\"main\")\n"
                f"EXECUTE: rename_function(old_name=\"FUN_140011a8\", new_name=\"process_data\")\n"
                f"EXECUTE: list_imports(offset=0, limit=50)\n"
            )

        # 3. Task assignment
        sections.append(task.format_for_prompt())

        # 4. Response format
        sections.append(
            "## How to Respond\n\n"
            "**While gathering data**, use tools:\n"
            "EXECUTE: tool_name(param1=\"value1\")\n\n"
            "You may call multiple tools per response. Add brief reasoning "
            "before your EXECUTE commands.\n\n"
            "**When you have enough information to answer**, respond with:\n"
            "TASK COMPLETE\n\n"
            "Then write your full answer to the user's question. This is the "
            "most important part — provide a clear, detailed, well-structured "
            "response that directly addresses what the user asked.\n\n"
            "**Important guidelines:**\n"
            "- Do NOT over-explore. Gather what you need, then answer.\n"
            "- A decompiled function with 468 lines does NOT need to be "
            "re-fetched — you already have the full output.\n"
            "- If you've called a tool and seen the result, do NOT call it again.\n"
            "- For simple questions (what does this function do?), 2-3 tool calls "
            "should be sufficient. Do not call 20+ tools for a simple question.\n"
            "- Your TASK COMPLETE response should be the actual answer the user wants, "
            "not a list of what tools you called."
        )

        return "\n\n".join(sections)

    def _build_dynamic_context(self, task: WorkerTask) -> str:
        """Build the dynamic context section filtered by task.include_sections."""
        builder = SystemContextBuilder(
            analysis_state=self.blackboard.get_analysis_state(),
            knowledge_summary=self.blackboard.get_knowledge_summary() or None,
            coverage_section=self.blackboard.get_coverage_prompt() or None,
            leads_section=self.blackboard.get_leads_prompt() or None,
            function_registry_summary=self.blackboard.get_function_registry_prompt() or None,
            notebook_summary=self.blackboard.get_notebook_prompt() or None,
            discovery_summary=self.blackboard.get_discovery_prompt() or None,
            tool_health_summary=self.blackboard.get_tool_health_prompt() or None,
        )
        return builder.build_dynamic_context(include_sections=task.include_sections)

    def _build_user_prompt(
        self, task: WorkerTask, exec_results: ExecutionPhaseResults, step: int
    ) -> str:
        """Build user prompt: goal + tool ledger + recent results.

        Two-tier memory system:
        1. **Tool Execution Ledger**: compact 1-line summaries of ALL previous
           tool calls (always visible, prevents re-calling).
        2. **Recent Results**: full output of the last 5 tool calls for
           detailed analysis.

        The ledger prevents the LLM from re-calling tools it used in earlier
        steps (which would otherwise fall out of the recent-results window).
        """
        real_calls = sum(
            1 for te in exec_results.tool_executions if te.tool_name != "<no_command>"
        )
        sections: List[str] = [
            f"## Task Goal\n{task.goal}",
            f"\n## Progress: {real_calls} tool calls completed",
        ]

        # ── Tool execution ledger: compact summary of ALL calls ──
        real_executions = [
            te for te in exec_results.tool_executions
            if te.tool_name != "<no_command>"
        ]

        # Apply compaction when past threshold — replaces older entries
        # with a categorical digest, preserving full detail for recent work.
        compacted_digest = ""
        ledger_executions = real_executions
        if self._compactor.should_compact(step, len(real_executions)):
            compacted_digest, ledger_executions = self._compactor.compact(
                real_executions
            )

        if compacted_digest:
            sections.append(compacted_digest)

        if ledger_executions:
            ledger_lines = [
                "\n## Tool Execution Ledger (DO NOT repeat these calls):"
            ]
            offset = len(real_executions) - len(ledger_executions)
            for i, te in enumerate(ledger_executions, offset + 1):
                # Compact 1-line summary: tool(params) → terse outcome
                terse = self._terse_result_summary(te.tool_name, te.result or "")
                param_str = ", ".join(
                    f'{k}={v!r}' for k, v in te.parameters.items()
                )
                status = "OK" if te.success else "ERR"
                ledger_lines.append(
                    f"{i}. {te.tool_name}({param_str}) → [{status}] {terse}"
                )
            sections.append("\n".join(ledger_lines))

        # ── Recent results: full output of last 5 for detailed analysis ──
        # Decompile results get a much larger window so the LLM can
        # actually read the code (500 chars was only the function signature).
        _DECOMPILE_TOOLS = {"decompile_function", "decompile_function_by_address"}
        recent = exec_results.tool_executions[-5:]
        if recent:
            sections.append("\n## Recent Results (full output):")
            for i, te in enumerate(recent, 1):
                idx = exec_results.total_steps - len(recent) + i
                # Give decompile results 6000 chars (enough for ~200 lines)
                # Other results get 1000 chars
                max_chars = 6000 if te.tool_name in _DECOMPILE_TOOLS else 1000
                result_preview = (te.result or "")[:max_chars]
                if len(te.result or "") > max_chars:
                    result_preview += f"\n... [{len(te.result)} total chars]"
                sections.append(
                    f"\nStep {idx}: {te.tool_name}({te.parameters})\n"
                    f"Result: {result_preview}"
                )

        sections.append(
            "\n## Next Step\n"
            "Based on the task, strategy, and results above, determine what "
            "to do next. Do NOT re-call any tool listed in the ledger above "
            "with the same parameters."
        )

        return "\n".join(sections)

    @staticmethod
    def _terse_result_summary(tool_name: str, result: str) -> str:
        """Produce a compact 1-line summary of a tool result for the ledger.

        Keeps the ledger small enough to fit the full history without
        blowing up the context window.
        """
        if not result:
            return "(empty)"

        # Early error detection (all tool types)
        if result.lstrip().startswith("Error") or result.lstrip().startswith("ERROR"):
            return result[:80].replace('\n', ' ')

        # For decompile results: extract function signature line
        if tool_name in ("decompile_function", "decompile_function_by_address"):
            # Look for the function signature (type + name + params)
            import re
            sig_match = re.search(
                r'(?:undefined\d?|void|int|long|char|bool|uint|ulong|DWORD|BOOL|HANDLE|LPVOID|LPCSTR)\s+\w+\s*\(',
                result[:300],
            )
            if sig_match:
                line_count = result.count('\n')
                return f"{sig_match.group(0).strip()}...) [{line_count} lines]"
            line_count = result.count('\n')
            return f"[{line_count} lines of decompiled code]"

        # For list results: extract total count
        if tool_name.startswith("list_") or tool_name == "search_functions_by_name":
            import re
            total_match = re.search(r'\[Total:\s*(\d+)\]', result)
            if total_match:
                return f"{total_match.group(1)} items"
            if "No functions matching" in result:
                return "no matches"
            return result[:60]

        # For xref results: extract count and key addresses
        if "xrefs" in tool_name or tool_name == "get_xrefs_to":
            import re
            total_match = re.search(r'\[Total:\s*(\d+)\]', result)
            if total_match:
                count = total_match.group(1)
                # Extract first address
                addr_match = re.search(r'From\s+([0-9a-fA-F]+)', result)
                addr = f" from {addr_match.group(1)}" if addr_match else ""
                return f"{count} xref(s){addr}"
            return result[:60]

        # For errors
        if "Error" in result[:50]:
            return result[:80]

        # Default: first 60 chars
        return result[:60].replace('\n', ' ')

    # ------------------------------------------------------------------
    # Gate artifact → notebook promotion
    # ------------------------------------------------------------------

    # Maps gate artifact categories → notebook entry categories
    def _promote_scan_artifacts_to_notebook(
        self,
        cmd_name: str,
        task: WorkerTask,
        artifacts: list,
    ):
        """Promote artifact-scanner matches to NotebookEntry objects.

        Makes security-relevant patterns visible in the final report.
        """
        import re
        for artifact in artifacts:
            pattern_desc = artifact.get("pattern", "Unknown pattern")
            match_text = artifact.get("match", "")

            # Map pattern description to notebook category
            desc_lower = pattern_desc.lower()
            if "privilege" in desc_lower or "token" in desc_lower:
                notebook_category = "vulnerability"
            elif "crypto" in desc_lower or "credential" in desc_lower:
                notebook_category = "vulnerability"
            elif "c2" in desc_lower or "ip" in desc_lower or "url" in desc_lower:
                notebook_category = "ioc"
            elif "shellcode" in desc_lower or "injection" in desc_lower:
                notebook_category = "vulnerability"
            elif "service" in desc_lower or "path" in desc_lower:
                notebook_category = "vulnerability"
            elif "debug" in desc_lower:
                notebook_category = "behavior"
            else:
                notebook_category = "vulnerability"

            addresses = re.findall(
                r'\b(?:0x)?[0-9a-fA-F]{6,8}\b', match_text
            )
            if task.focus_addresses:
                addresses.extend(task.focus_addresses[:3])

            entry = NotebookEntry(
                category=notebook_category,
                severity="high",
                title=f"Auto-detected: {pattern_desc}",
                detail=(
                    f"Artifact scanner detected a security-relevant "
                    f"pattern in `{cmd_name}` output: {match_text}"
                ),
                evidence=[
                    f"Detected in: {cmd_name}",
                    f"Pattern: {pattern_desc}",
                    f"Match: {match_text[:200]}",
                ],
                addresses=list(set(addresses))[:5],
                status="suspected",
            )

            try:
                self.blackboard.add_notebook_entry(entry)
                self.emitter.emit_cot(
                    "Scanner",
                    f"Artifact promoted to notebook: [{notebook_category}] {pattern_desc}",
                )
            except Exception as e:
                self.logger.warning(f"Failed to promote artifact to notebook: {e}")

    # ------------------------------------------------------------------
    # Binary metadata helpers
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # Auto-register decompiled functions to FunctionRegistry
    # ------------------------------------------------------------------

    def _auto_register_function(self, cmd_name: str, cmd_params: dict, result_str: str):
        """Auto-register a FunctionAnalysis to the blackboard after decompile.

        Creates a minimal FunctionAnalysis from the decompile result so the
        function_registry.analyzed_count reflects actual work done by workers.
        Without this, the function coverage display stays at 0% even though
        functions ARE being decompiled.

        Address extraction strategy (multiple fallbacks):
          1. From cmd_params["address"] (decompile_function_by_address)
          2. From cmd_params["name"] if it's a FUN_<hex> pattern
          3. From result text: 0x-prefixed hex literal
          4. From result text: FUN_<hex> pattern in the function signature
          5. From result text: bare 8+ digit hex address
        """
        import re
        from src.models.memory import FunctionAnalysis

        # Only for decompile commands
        if cmd_name not in ("decompile_function", "decompile_function_by_address"):
            return

        # Extract address and name from params
        address = cmd_params.get("address", "")
        name = cmd_params.get("name", "")

        # For decompile_function (by name), try multiple strategies to get address
        if cmd_name == "decompile_function" and not address:
            # Strategy 1: Extract from the name param itself (e.g., "FUN_00405b60")
            fun_name_match = re.match(r'FUN_([0-9a-fA-F]{6,})', name)
            if fun_name_match:
                address = f"0x{fun_name_match.group(1)}"
            else:
                # Strategy 2: Look for 0x-prefixed address in result
                addr_match = re.search(
                    r'\b(0x[0-9a-fA-F]{6,})\b', result_str[:500]
                )
                if addr_match:
                    address = addr_match.group(1)
                else:
                    # Strategy 3: Look for FUN_<hex> in result signature
                    fun_match = re.search(
                        r'FUN_([0-9a-fA-F]{6,})', result_str[:500]
                    )
                    if fun_match:
                        address = f"0x{fun_match.group(1)}"
                    else:
                        # Strategy 4: Bare hex address (8+ digits, likely an address)
                        bare_match = re.search(
                            r'\b([0-9a-fA-F]{8,})\b', result_str[:500]
                        )
                        if bare_match:
                            address = f"0x{bare_match.group(1)}"
                        else:
                            self.logger.debug(
                                f"Auto-register skipped: no address found for "
                                f"decompile_function(name={name!r})"
                            )
                            return  # Can't register without an address

        if not address:
            return

        # Normalize address format (ensure 0x prefix)
        if not address.startswith("0x") and not address.startswith("0X"):
            address = f"0x{address}"

        # Note: We do NOT early-return if the function is already analyzed.
        # The merge-aware FunctionRegistry.register() handles re-registration
        # by incrementing decompile_count and merging fields. This lets the
        # orchestrator see how many times each function was decompiled.

        # Extract function name from result header if not provided
        if not name:
            name_match = re.search(
                r'(?:undefined\d?|void|int|long|char|bool|uint|ulong|DWORD|BOOL|HANDLE|LPVOID)\s+(\w+)\s*\(',
                result_str[:500]
            )
            if name_match:
                name = name_match.group(1)
            else:
                name = f"FUN_{address.replace('0x', '')}"

        # Extract API calls from decompiled code (likely Win32 APIs: PascalCase + W/A suffix)
        api_pattern = re.findall(r'\b([A-Z][a-zA-Z]+(?:W|A|Ex|ExW)?)\s*\(', result_str)
        imports_used = list(set(api for api in api_pattern if len(api) >= 5))[:10]

        try:
            fa = FunctionAnalysis(
                address=address,
                name=name,
                original_name=name if name.startswith("FUN_") else "",
                purpose=f"Decompiled by worker (auto-registered)",
                decompiled=True,
                imports_used=imports_used,
            )
            self.blackboard.register_function(fa)
            self.logger.debug(f"Auto-registered function: {name} @ {address}")
        except Exception as e:
            self.logger.debug(f"Auto-register function failed: {e}")

    def _update_function_count(self, list_functions_result: str):
        """Extract total function count from list_functions output and store it.

        The orchestrator uses ``blackboard.total_binary_functions`` for
        function-level coverage tracking.  If the field is already set we
        skip the update to avoid overwriting a more accurate value.
        """
        if self.blackboard.total_binary_functions > 0:
            return  # Already set

        import re
        # list_functions typically outputs "Total: N functions" or similar
        match = re.search(r"(?:total|found)[:\s]*(\d+)", list_functions_result, re.IGNORECASE)
        if match:
            count = int(match.group(1))
            if count > 0:
                self.blackboard.total_binary_functions = count
                self.logger.info(f"Set total_binary_functions = {count}")

    # ------------------------------------------------------------------
    # Budget warning
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # Doom loop detection
    # ------------------------------------------------------------------

    def _detect_doom_loop(self, exec_results: ExecutionPhaseResults) -> bool:
        """Check if the last N tool calls are identical (same tool + same params).

        Filters out ``<no_command>`` entries before checking.
        """
        real_calls = [
            te for te in exec_results.tool_executions
            if te.tool_name != "<no_command>"
        ]
        if len(real_calls) < self.DOOM_LOOP_THRESHOLD:
            return False

        recent = real_calls[-self.DOOM_LOOP_THRESHOLD:]
        first = (recent[0].tool_name, str(recent[0].parameters))
        return all(
            (te.tool_name, str(te.parameters)) == first
            for te in recent[1:]
        )

    # ------------------------------------------------------------------
    # Consecutive error detection
    # ------------------------------------------------------------------

    @staticmethod
    def _count_consecutive_errors(tool_name: str, exec_results) -> int:
        """Count how many times the given tool has failed consecutively (most recent)."""
        count = 0
        for te in reversed(exec_results.tool_executions):
            if te.tool_name == "<no_command>":
                continue
            if te.tool_name == tool_name and not te.success:
                count += 1
            else:
                break
        return count

    # ------------------------------------------------------------------
    # Response parsing helpers
    # ------------------------------------------------------------------

    def _is_complete(self, response: str) -> bool:
        """Check if the LLM response signals task completion."""
        upper = response.upper()
        return any(marker in upper for marker in self.COMPLETION_MARKERS)

    @staticmethod
    def _extract_reasoning(response: str) -> str:
        """Extract REASONING: block from the LLM response."""
        for line in response.split("\n"):
            stripped = line.strip()
            if stripped.upper().startswith("REASONING:"):
                return stripped[len("REASONING:"):].strip()
        return ""

    def _extract_findings(
        self, exec_results: ExecutionPhaseResults, exit_reason: str
    ) -> str:
        """Build a human-readable summary of what the worker accomplished.

        Summarizes: tools executed, key results, completion status, and exit reason.
        """
        # Collect successful tool names + brief result excerpts (skip thinking steps)
        summaries = []
        for te in exec_results.tool_executions:
            if te.tool_name == "<no_command>":
                continue
            status = "OK" if te.success else "ERR"
            excerpt = (te.result or "")[:120]
            summaries.append(f"- {te.tool_name}: [{status}] {excerpt}")

        real_tools = len(summaries)
        if real_tools == 0:
            return "No tools were executed."

        if exec_results.investigation_complete:
            completion_text = "Task completed."
        elif exit_reason == "hard_ceiling":
            completion_text = "Task incomplete (hard ceiling reached)."
        elif exit_reason == "doom_loop":
            completion_text = "Task stopped (doom loop detected)."
        elif exit_reason == "abort":
            completion_text = "Task aborted (gate triggered)."
        else:
            completion_text = f"Task incomplete ({exit_reason})."

        header = f"Executed {real_tools} tool calls. {completion_text}"

        if exec_results.gates_triggered:
            header += f" ({len(exec_results.gates_triggered)} gate(s) triggered)"

        return header + "\n" + "\n".join(summaries[:15])

    # ------------------------------------------------------------------
    # Recipe Mode — deterministic gather → LLM analysis
    # ------------------------------------------------------------------

    def _run_recipe_mode(self, task: WorkerTask) -> AgentResult:
        """Execute a task using a deterministic recipe.

        Three-phase model:
          1. **Gather**: ``RecipeExecutor`` deterministically gathers all
             relevant code (no LLM involvement).
          2. **Analyze**: A single LLM call receives ALL gathered code and
             produces: summary + JSON notebook entries + optional follow-up.
          3. **Follow-up** (optional): ≤3 additional decompilations if the
             LLM requests them, then a re-analysis.

        This replaces the LLM-driven tool-selection loop for recipe-enabled
        tasks.  The LLM is only used for what it's good at: reasoning about
        code and producing findings.
        """
        self.logger.info(
            f"[Worker:{task.task_id}] Recipe mode: {task.recipe}({task.recipe_params})"
        )
        self.emitter.emit_cot(
            "Worker",
            f"Starting recipe {task.recipe} for task {task.task_id}",
        )

        try:
            # ── Phase 1: Deterministic Gather ──
            recipe_exec = RecipeExecutor(
                tool_executor=self.tools,
                blackboard=self.blackboard,
                logger=self.logger,
                registry=self.recipe_registry,
            )
            recipe_result = recipe_exec.execute(
                task.recipe, task.recipe_params or {}
            )

            self.emitter.emit_cot(
                "Worker",
                f"Recipe gathered {len(recipe_result.gathered_functions)} functions, "
                f"{recipe_result.tool_calls_made} tool calls",
            )

            # Persist all gathered code on the blackboard so the
            # orchestrator and final report can reference actual source
            if recipe_result.gathered_functions:
                self.blackboard.cache_code_bulk(
                    recipe_result.gathered_functions
                )

            # Emit step events for UI tracking
            self.emitter.emit_agent_event("worker_step", {
                "task_id": task.task_id,
                "step": 1,
                "tool_count": recipe_result.tool_calls_made,
                "real_tool_count": recipe_result.tool_calls_made,
                "phase": "gathering",
            })

            if not recipe_result.gathered_functions and not recipe_result.gathered_strings:
                # Nothing gathered — return early with descriptive result
                self.emitter.emit_cot(
                    "Worker",
                    f"Recipe {task.recipe} gathered nothing — no functions or strings found",
                )
                return AgentResult(
                    task_id=task.task_id,
                    findings_summary=(
                        f"Recipe {task.recipe} gathered no data. "
                        f"Errors: {'; '.join(recipe_result.errors) if recipe_result.errors else 'None'}. "
                        f"The target APIs/patterns may not be present in this binary."
                    ),
                    tool_executions_count=recipe_result.tool_calls_made,
                    is_complete=True,
                    exit_reason="recipe_complete",
                    notebook_entries=[],
                )

            # ── Phase 2: LLM Analysis ──
            self.emitter.emit_agent_event("worker_step", {
                "task_id": task.task_id,
                "step": 2,
                "tool_count": recipe_result.tool_calls_made,
                "real_tool_count": recipe_result.tool_calls_made,
                "phase": "analyzing",
            })

            analysis_prompt = self._build_recipe_analysis_prompt(
                task, recipe_result
            )
            analysis_system = self._build_recipe_analysis_system_prompt(task)

            response = self.llm.generate_with_phase(
                analysis_prompt,
                phase="analysis",
                system_prompt=analysis_system,
            )

            findings, notebook_entries, follow_up_addrs = (
                self._parse_recipe_analysis_response(response)
            )

            # ── Phase 3: Follow-up (optional) ──
            if follow_up_addrs:
                follow_up_addrs = follow_up_addrs[:3]  # Cap at 3
                self.logger.info(
                    f"[Worker:{task.task_id}] Follow-up: decompiling {follow_up_addrs}"
                )

                new_functions = {}
                for addr in follow_up_addrs:
                    if addr in recipe_result.gathered_functions:
                        continue
                    code = recipe_exec._decompile_function(addr, recipe_result)
                    if code:
                        new_functions[addr] = code
                        recipe_exec._auto_register_and_mark(
                            addr, code, recipe_result
                        )

                if new_functions:
                    # Re-analyze with the additional functions
                    self.emitter.emit_agent_event("worker_step", {
                        "task_id": task.task_id,
                        "step": 3,
                        "tool_count": recipe_result.tool_calls_made + len(new_functions),
                        "real_tool_count": recipe_result.tool_calls_made + len(new_functions),
                        "phase": "follow_up",
                    })
                    recipe_result.gathered_functions.update(new_functions)
                    analysis_prompt = self._build_recipe_analysis_prompt(
                        task, recipe_result
                    )
                    response = self.llm.generate_with_phase(
                        analysis_prompt,
                        phase="analysis",
                        system_prompt=analysis_system,
                    )
                    findings, notebook_entries, _ = (
                        self._parse_recipe_analysis_response(response)
                    )

            # ── Build AgentResult ──
            self.emitter.emit_cot(
                "Worker",
                f"Recipe complete: {len(notebook_entries)} findings, "
                f"{recipe_result.tool_calls_made} tool calls total",
            )

            return AgentResult(
                task_id=task.task_id,
                findings_summary=findings or (
                    f"Recipe {task.recipe} analyzed "
                    f"{len(recipe_result.gathered_functions)} functions. "
                    f"No significant findings."
                ),
                tool_executions_count=recipe_result.tool_calls_made,
                is_complete=True,
                exit_reason="recipe_complete",
                notebook_entries=notebook_entries,
            )

        except Exception as e:
            self.logger.error(
                f"[Worker:{task.task_id}] Recipe mode error: {e}",
                exc_info=True,
            )
            self.emitter.emit_cot(
                "Worker",
                f"[{task.task_id}] Recipe ERROR: {e}",
            )
            return AgentResult(
                task_id=task.task_id,
                error=str(e),
                tool_executions_count=0,
                exit_reason="error",
            )

    def _build_recipe_analysis_prompt(
        self, task: WorkerTask, recipe_result: RecipeResult
    ) -> str:
        """Build the user prompt for the recipe analysis LLM call.

        Includes: ALL gathered decompiled code (full, not truncated!),
        xref graph, call graph, matched strings, and analysis instructions.
        """
        sections: List[str] = []

        # Goal & focus
        sections.append(f"## Investigation Goal\n{task.goal}")
        if task.analysis_focus:
            sections.append(f"\n## Specific Analysis Focus\n{task.analysis_focus}")

        # Gathered functions — full decompiled code
        if recipe_result.gathered_functions:
            sections.append(
                f"\n## Decompiled Functions ({len(recipe_result.gathered_functions)} total)"
            )
            for addr, code in recipe_result.gathered_functions.items():
                # Cap very long functions
                code_lines = code.splitlines()
                if len(code_lines) > MAX_CODE_LINES_PER_FUNCTION:
                    code = "\n".join(
                        code_lines[:MAX_CODE_LINES_PER_FUNCTION]
                    ) + f"\n... [{len(code_lines) - MAX_CODE_LINES_PER_FUNCTION} more lines truncated]"
                sections.append(f"\n### Function at {addr}\n```c\n{code}\n```")

        # Cross-reference graph
        if recipe_result.gathered_xrefs:
            sections.append("\n## Cross-References")
            for addr, xrefs in recipe_result.gathered_xrefs.items():
                xref_text = "\n".join(f"  - {x}" for x in xrefs[:20])
                sections.append(f"\n### Xrefs for {addr}\n{xref_text}")

        # Call graph
        if recipe_result.call_graph:
            sections.append("\n## Call Graph")
            for addr, callees in recipe_result.call_graph.items():
                sections.append(f"  {addr} → {', '.join(callees)}")

        # Matched strings
        if recipe_result.gathered_strings:
            sections.append(
                "\n## Matched Strings\n"
                + "\n".join(f"  - {s}" for s in recipe_result.gathered_strings[:50])
            )

        # Errors encountered
        if recipe_result.errors:
            sections.append(
                "\n## Gathering Errors\n"
                + "\n".join(f"  - {e}" for e in recipe_result.errors)
            )

        # Instructions for the LLM
        sections.append(
            "\n## Your Task\n"
            "Analyze the decompiled code above in the context of the investigation goal. "
            "Produce:\n\n"
            "1. **SUMMARY**: A paragraph summarizing your analysis and findings.\n\n"
            "2. **FINDINGS**: A JSON array of notebook entries, each with these fields:\n"
            "```json\n"
            "[\n"
            "  {\n"
            '    "category": "vulnerability|behavior|ioc|info",\n'
            '    "severity": "critical|high|medium|low|info",\n'
            '    "title": "Short descriptive title",\n'
            '    "detail": "Detailed explanation with specific code evidence",\n'
            '    "evidence": ["specific line of code or API call"],\n'
            '    "addresses": ["0x00401000"],\n'
            '    "status": "confirmed|suspected|needs_investigation"\n'
            "  }\n"
            "]\n"
            "```\n\n"
            "3. **FOLLOW_UP** (optional): If you need to see additional functions "
            "to confirm a finding, list their addresses:\n"
            "FOLLOW_UP: 0x00401234, 0x00405678\n\n"
            "IMPORTANT:\n"
            "- Only report findings with SPECIFIC code evidence (cite exact lines)\n"
            "- Do NOT report surface-level API presence (e.g., 'binary uses CreateProcessW')\n"
            "- A confirmed vulnerability needs: the exact vulnerable code pattern, "
            "why it's exploitable, and what an attacker can achieve\n"
            "- 'suspected' status is for patterns that look vulnerable but need "
            "more context to confirm"
        )

        return "\n".join(sections)

    @staticmethod
    def _build_recipe_analysis_system_prompt(task: WorkerTask) -> str:
        """Build the system prompt for the recipe analysis LLM call."""
        from src.orchestrator import SEVERITY_DEFINITIONS
        return (
            "You are an expert binary security analyst reviewing decompiled code "
            "from a Ghidra reverse engineering session.\n\n"
            "Your job is to analyze the provided code for security vulnerabilities, "
            "malicious behavior, or other findings relevant to the investigation goal.\n\n"
            "## Quality Standards\n"
            "- You MUST cite specific code as evidence for every finding\n"
            "- Do NOT produce surface-level API observations (e.g., "
            "'the binary imports CreateProcessW' is NOT a finding)\n"
            "- A vulnerability finding must explain: WHAT is vulnerable, WHERE "
            "in the code, WHY it's exploitable, and WHAT an attacker can achieve\n"
            f"- {SEVERITY_DEFINITIONS}\n"
            "## Response Format\n"
            "Always respond with:\n"
            "1. SUMMARY: paragraph\n"
            "2. FINDINGS: JSON array\n"
            "3. FOLLOW_UP: addresses (optional)\n"
        )

    @staticmethod
    def _parse_recipe_analysis_response(
        response: str,
    ) -> tuple:
        """Parse the LLM analysis response into structured components.

        Returns:
            (findings_summary, notebook_entries, follow_up_addresses)
        """
        import re

        # Extract summary
        summary = ""
        summary_match = re.search(
            r"(?:SUMMARY|Summary)[:\s]*\n?(.*?)(?=\n\s*(?:FINDINGS|FOLLOW_UP|\Z))",
            response,
            re.DOTALL | re.IGNORECASE,
        )
        if summary_match:
            summary = summary_match.group(1).strip()
        else:
            # Fallback: use first paragraph
            paragraphs = response.strip().split("\n\n")
            if paragraphs:
                summary = paragraphs[0].strip()

        # Extract notebook entries JSON
        notebook_entries = []
        json_match = re.search(
            r"```json\s*(.*?)\s*```", response, re.DOTALL
        )
        if json_match:
            try:
                entries = json.loads(json_match.group(1))
                if isinstance(entries, list):
                    notebook_entries = entries
                elif isinstance(entries, dict):
                    notebook_entries = [entries]
            except json.JSONDecodeError:
                pass

        if not notebook_entries:
            # Try bare JSON array
            bare_match = re.search(
                r"FINDINGS[:\s]*\n?\s*(\[.*?\])",
                response,
                re.DOTALL | re.IGNORECASE,
            )
            if bare_match:
                try:
                    entries = json.loads(bare_match.group(1))
                    if isinstance(entries, list):
                        notebook_entries = entries
                except json.JSONDecodeError:
                    pass

        # Extract follow-up addresses
        follow_up = []
        follow_match = re.search(
            r"FOLLOW_UP[:\s]*(.*)",
            response,
            re.IGNORECASE,
        )
        if follow_match:
            addr_matches = re.findall(
                r"(?:0x)?([0-9a-fA-F]{6,})", follow_match.group(1)
            )
            follow_up = [
                f"0x{a}" if not a.startswith("0x") else a
                for a in addr_matches
            ]

        return summary, notebook_entries, follow_up
