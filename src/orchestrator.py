"""
Orchestrator — The investigation brain for OGhidra.

The Orchestrator is the only LLM-driven decision maker in the sub-agent
architecture.  It does NOT execute tools — it only reasons about strategy.

Responsibilities:
  1. Classify the user query → investigation strategy
     (binary_understanding | malware_hunting | vuln_hunting)
  2. Create specific ``WorkerTask`` instances based on blackboard state + strategy
  3. Spawn ``WorkerAgent`` instances to execute tasks
  4. Update the ``InvestigationNotebook`` after each worker returns
     (continuous synthesis — no separate synthesis step)
  5. Merge worker results into the blackboard
     (function analyses → FunctionRegistry, leads → LeadTracker, etc.)
  6. Decide when the investigation is complete or max cycles exhausted

The Orchestrator makes lightweight LLM calls for:
  - Strategy classification (one call)
  - Task creation per cycle (one call, reads blackboard state)
  - Notebook updating per cycle (one call, reads worker findings)

It does NOT execute Ghidra tools directly.
"""

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, Dict, Any, Set

from src.agents.base import WorkerTask, AgentResult
from src.agents.worker_agent import WorkerAgent
from src.coverage_tracker import CoverageTracker, DEPTH_ENCOUNTERED, DEPTH_ANALYZED
from src.models.memory import (
    DiscoveryCache,
    FunctionAnalysis,
    NotebookEntry,
    InvestigationNotebook,
    FunctionRegistry,
)
from src.orchestrator_logger import OrchestratorLogger


# ── Doom loop detection ───────────────────────────────────────────────────

_GOAL_STOP_WORDS = frozenset({
    # Common English stop words
    "the", "a", "an", "and", "or", "to", "for", "in", "of", "on", "with",
    "from", "by", "is", "are", "that", "this", "it", "its", "be", "was",
    "were", "been", "being", "have", "has", "had", "do", "does", "did",
    # RE-specific filler verbs (add no semantic meaning to goals)
    "investigate", "analyze", "examine", "check", "verify", "confirm",
    "trace", "review", "inspect", "assess", "evaluate", "determine",
    "look", "find", "search", "identify", "explore", "study",
    # Common filler nouns/adjectives in RE investigation goals
    "function", "functions", "binary", "code", "operations", "operation",
    "call", "calls", "calling", "called", "callers", "sites",
    "using", "used", "whether", "if",
    "any", "all", "each", "more", "further", "also", "specific",
    "data", "flow", "potential", "possible", "vulnerabilities",
    "vulnerability", "issues", "flaws", "problems",
})


# ── Strategy constants ─────────────────────────────────────────────────────
STRATEGY_BINARY_UNDERSTANDING = "binary_understanding"
STRATEGY_MALWARE_HUNTING = "malware_hunting"
STRATEGY_VULN_HUNTING = "vuln_hunting"
VALID_STRATEGIES = {STRATEGY_BINARY_UNDERSTANDING, STRATEGY_MALWARE_HUNTING, STRATEGY_VULN_HUNTING}


# ── Worker result memory ──────────────────────────────────────────────────

@dataclass
class WorkerResultSummary:
    """Compact summary of what a worker accomplished, for orchestrator memory.

    The orchestrator accumulates these across cycles so the task-creation LLM
    can see exactly what each previous worker did — preventing duplicate work.
    """
    cycle: int
    goal: str
    functions_decompiled: List[str] = field(default_factory=list)
    tools_used: Dict[str, int] = field(default_factory=dict)
    key_findings: str = ""
    exit_reason: str = "unknown"


# ── Strategy templates ────────────────────────────────────────────────────
# ── Shared severity definitions (used by notebook synthesis + recipe analysis) ──
# Single source of truth: prevents drift between the two prompt paths.
SEVERITY_DEFINITIONS = (
    "Severity levels:\n"
    "- critical: Confirmed arbitrary code execution or privilege escalation "
    "with a clear exploit path\n"
    "- high: Suspected code execution / privilege escalation with plausible "
    "exploit path, or confirmed data breach\n"
    "- medium: Denial of service, information disclosure, or limited-impact "
    "vulnerability\n"
    "- low: Theoretical weakness requiring additional conditions to exploit, "
    "or purely informational\n"
)


# Detailed guidance for the orchestrator's task creation LLM call.
# Each template describes: priorities, task progression, key APIs, tools,
# and completion criteria for a specific investigation strategy.

STRATEGY_TEMPLATE_VULN_HUNTING = """\
Focus on finding exploitable security flaws: privilege escalation, code
injection, DLL hijacking, unquoted service paths, directory traversal,
and similar vulnerabilities.

### Priority Order
1. Privilege escalation (highest impact)
2. Arbitrary code execution / command injection
3. Network input to sensitive operations (path traversal, request injection)
4. DLL hijacking / side-loading
5. Unquoted service paths
6. Information disclosure

### Recommended Task Progression

**Phase 1 — Surface Mapping (handled by recon worker — skip if discovery cache populated):**
- The recon phase has already listed imports, exports, and strings.
  Review the discovery cache in your context for API surface.

**Phase 2 — Caller Tracing (cycles 1-3):**
- Task: "Decompile all callers of CreateProcessW and check for:
   (a) lpApplicationName=NULL with unquoted lpCommandLine,
   (b) command line constructed from external input (registry, config file),
   (c) paths containing spaces without quotes"
  Suggested tools: decompile_function_by_address, get_xrefs_to
  include_sections: [scope, function_registry, knowledge, discovery]
- Task: "For each LoadLibrary caller, check for relative paths (DLL hijacking)"
  Suggested tools: decompile_function_by_address, get_xrefs_to
  include_sections: [scope, function_registry, discovery]
- Task: "If binary handles network input (recv/accept/bind), trace data flow
   from network receive to file operations (CreateFile/ReadFile). Check for
   directory traversal (../ in path without validation)."
  Suggested tools: get_xrefs_to, decompile_function_by_address
  include_sections: [scope, function_registry, discovery]

**Phase 3 — Deep Verification (cycles 3-5+):**
- Task: "Trace data flow from RegQueryValueEx/config reads to execution APIs"
  Suggested tools: decompile_function_by_address, get_xrefs_from
  include_sections: [function_registry, knowledge, leads, discovery]
- Task: "Verify suspected vulnerability at [address]: confirm exploitability
   by tracing full argument chain from input to API call"
  include_sections: [function_registry, knowledge, leads, discovery]

### Completion Criteria
Consider investigation complete when:
- All security-critical API callers have been decompiled and analyzed
- If binary handles network input, data flow traced to file/exec operations
- Data flow traces are done for confirmed or suspected vulnerability paths
- High-severity findings have status='confirmed' or 'not_exploitable'
- No high-priority leads remain unresolved"""

STRATEGY_TEMPLATE_MALWARE_HUNTING = """\
Focus on detecting malicious behavior: IOC extraction, C2 protocol analysis,
persistence mechanisms, process injection, and anti-analysis techniques.

### Priority Order
1. C2 communication (network callback, beacon, exfiltration)
2. Persistence mechanisms (registry Run keys, services, scheduled tasks)
3. Process injection / shellcode execution
4. Anti-analysis / evasion techniques
5. IOC extraction (IPs, URLs, mutexes, file paths, registry keys)

### Recommended Task Progression

**Phase 1 — IOC Extraction (cycles 1-2):**
- Task: "Search strings for IP addresses, URLs, domain names, file paths,
   registry keys, mutexes, and embedded configuration data"
  Suggested tools: search_strings_in_binary
  include_sections: [scope]
- Task: "List all imports and flag: VirtualAlloc + WriteProcessMemory (injection),
   IsDebuggerPresent + NtQueryInformationProcess (anti-debug),
   InternetOpen + WSAStartup + connect (network),
   RegSetValueEx + CreateService (persistence),
   CryptEncrypt + CryptDecrypt (crypto)"
  Suggested tools: list_imports
  include_sections: [scope]

**Phase 2 — Behavioral Analysis (cycles 2-4):**
- Task: "Decompile functions calling VirtualAlloc and trace shellcode injection:
   VirtualAlloc → memcpy/WriteProcessMemory → CreateRemoteThread/NtCreateThread"
  Suggested tools: decompile_function_by_address, get_xrefs_to
  include_sections: [function_registry, knowledge]
- Task: "Trace all registry operations — check for Run key persistence,
   service installation, COM object hijacking"
  Suggested tools: decompile_function_by_address, get_xrefs_to
  include_sections: [function_registry, knowledge]
- Task: "Analyze network initialization functions — identify C2 protocol:
   connection targets, encoding/encryption, beacon interval, command format"
  Suggested tools: decompile_function_by_address, get_xrefs_to
  include_sections: [function_registry, knowledge, leads]

**Phase 3 — Evasion & Deep Analysis (cycles 4-5+):**
- Task: "Check for anti-debugging: IsDebuggerPresent, NtQueryInformationProcess
   with ProcessDebugPort, CheckRemoteDebuggerPresent, timing checks (RDTSC,
   GetTickCount comparisons)"
  Suggested tools: decompile_function_by_address, get_xrefs_to
  include_sections: [function_registry]
- Task: "Analyze string decoding/decryption routines — trace encoded strings
   through XOR/RC4/custom cipher to plaintext IOCs"
  Suggested tools: decompile_function_by_address
  include_sections: [function_registry, knowledge, leads]

### Completion Criteria
Consider investigation complete when:
- IOCs are extracted (IPs, URLs, file paths, registry keys, mutexes)
- C2 protocol is identified or ruled out (network functions analyzed)
- Persistence mechanism identified or ruled out
- Injection technique identified or ruled out
- Anti-analysis techniques cataloged
- No high-priority leads remain unresolved"""

STRATEGY_TEMPLATE_BINARY_UNDERSTANDING = """\
Focus on understanding the binary's purpose, architecture, key components,
data flow, and external dependencies.

### Priority Order
1. Identify binary purpose and high-level architecture
2. Map major functional subsystems
3. Understand entry points and initialization flow
4. Trace primary data flow (input → processing → output)
5. Document external dependencies and API usage patterns

### Recommended Task Progression

**Phase 1 — Surface Mapping (cycles 1-2):**
- Task: "List all imports and categorize by functionality:
   file I/O (CreateFile, ReadFile, WriteFile),
   network (WSAStartup, connect, send, recv, InternetOpen),
   crypto (CryptEncrypt, BCrypt*),
   UI (CreateWindow, MessageBox),
   process management (CreateProcess, CreateThread),
   registry (RegOpenKey, RegQueryValue),
   service (StartServiceCtrlDispatcher, RegisterServiceCtrlHandler)"
  Suggested tools: list_imports
  include_sections: [scope]
- Task: "List all exports and identify entry points, service registration,
   and DLL interface functions"
  Suggested tools: list_exports, list_entry_points
  include_sections: [scope]

**Phase 2 — Core Analysis (cycles 2-4):**
- Task: "Decompile the main entry point (or ServiceMain / DllMain) and describe
   the startup sequence: initialization, configuration loading, thread creation"
  Suggested tools: decompile_function, decompile_function_by_address
  include_sections: [scope, function_registry, analysis_state]
- Task: "Identify the top 5 most-referenced internal functions (use xrefs)
   and decompile them — these form the program's core logic"
  Suggested tools: get_function_xrefs, decompile_function_by_address
  include_sections: [function_registry]
- Task: "Trace the primary data flow: where does input come from (network,
   file, pipe, registry)? How is it processed? Where does output go?"
  Suggested tools: decompile_function_by_address, get_xrefs_from
  include_sections: [function_registry, knowledge, leads]

**Phase 3 — Deep Dive (cycles 4-5+):**
- Task: "Analyze secondary subsystems identified from leads (error handling,
   logging, config parsing, IPC mechanisms)"
  Suggested tools: decompile_function_by_address
  include_sections: [function_registry, knowledge, leads]
- Task: "If security-relevant APIs were found, note them: potential
   vulnerabilities or security features (authentication, access control)"
  include_sections: [function_registry, knowledge, leads]

### Completion Criteria
Consider investigation complete when:
- Binary purpose is identified (what does this program do?)
- Major subsystems are mapped (core logic, I/O, networking if present)
- Entry point and initialization flow are documented
- Key internal functions (top 5-10 by xref count) are analyzed
- External API usage patterns are understood
- No critical coverage gaps remain (imports, exports, and entry point covered)"""


# ── Vulnerability Correlation Hooks ─────────────────────────────────────
# The 5 built-in correlation rules have been extracted to:
#   src/correlation_hooks.py       — CorrelationHook ABC + CorrelationHookRegistry
#   src/correlation_hooks_builtin.py — 5 concrete hook classes
#
# Custom hooks can be added by placing .py files with CorrelationHook
# subclasses in the directory specified by CUSTOM_HOOKS_DIR.


# ── Query Routing (keyword-based, zero LLM calls) ─────────────────────
# Investigation queries are detected by keyword match and routed to the
# full 3-layer orchestrator.  Everything else uses a conversational
# single-loop (like claw-code's run_turn).

_LEGACY_TRIAGE_SYSTEM_PROMPT = """\
DEPRECATED — kept for reference. Query routing is now keyword-based.
You are a query complexity router for a reverse engineering assistant.

## Available Ghidra tools (one call each):
- decompile_function(name): Decompile a function by name
- decompile_function_by_address(address): Decompile a function at hex address
- list_imports(offset, limit): List imported API functions (paginated)
- list_exports(): List exported functions
- list_strings(filter): List strings matching filter
- search_strings_in_binary(query): Search strings with semantic query
- list_functions(offset, limit): List all functions (paginated)
- get_xrefs_to(address): Get cross-references TO an address
- get_xrefs_from(address): Get cross-references FROM an address
- get_function_xrefs(name): Get xrefs for a named function
- rename_function(old_name, new_name): Rename a function by name
- rename_function_by_address(function_address, new_name): Rename by address
- set_comment(address, comment): Add a comment at an address
- list_segments(): List binary segments
- list_namespaces(): List namespaces
- get_current_address(): Get cursor address in Ghidra
- get_current_function(): Get function at cursor

## Classification tiers:

**direct** — Answerable with 0-1 tool calls. Simple lookups, single function queries, \
single rename/comment operations. The user wants a quick answer, not a deep investigation.
Examples: "What does FUN_00401000 do?", "Rename FUN_004010a0 to main", \
"Find references to CreateProcessW", "List all imports", "What is at address 0x401000?", \
"What function am I looking at?", "Add a comment at 0x401000"

**focused** — Requires 2-8 tool calls. Multi-step but bounded tasks: analyzing a \
function and its callers, renaming a handful of related functions, tracing a specific \
data flow. NOT binary-wide. The user wants a targeted answer covering a small area.
Examples: "What does this function do and what calls it?", \
"Decompile the entry point and its first-level callees", \
"Rename the functions that handle network I/O", \
"Trace how data flows from recv to file operations in FUN_00405b60"

**investigation** — Binary-wide or open-ended analysis requiring many cycles. \
Full vulnerability audits, malware analysis, complete architecture mapping, \
renaming ALL functions, comprehensive security reviews.
Examples: "Find all vulnerabilities", "Is this binary malicious?", \
"Map the complete architecture", "Rename all functions based on behavior", \
"Review all strings and imports for malicious indicators", \
"Comprehensive security audit"

## Response format
Respond with ONLY a JSON object (no markdown, no explanation):

For direct: {"tier": "direct", "tool": "tool_name", "params": {"param1": "value1"}}
  - If no tool needed (pure knowledge question): {"tier": "direct", "tool": null, "params": {}}
For focused: {"tier": "focused", "goal": "concise task description", "suggested_tools": ["tool1", "tool2"]}
For investigation: {"tier": "investigation"}"""

TRIAGE_USER_PROMPT = 'Classify this query: "{query}"'

# Action tools that modify the binary (no LLM summary needed after execution)
_ACTION_TOOLS = frozenset({
    "rename_function", "rename_function_by_address", "set_comment",
})


class Orchestrator:
    """
    Investigation brain — creates tasks, spawns workers, maintains notebook.

    Usage::

        orchestrator = Orchestrator(
            llm_client=ollama,
            tool_executor=tool_executor,
            blackboard=blackboard,
            command_parser=parser,
            execution_gate=gate,
            event_emitter=emitter,
            config=llm_config,
            capabilities_text=caps_text,
        )
        report = orchestrator.run("Analyze this binary for vulnerabilities")
    """

    def __init__(
        self,
        llm_client,
        tool_executor,
        blackboard,
        command_parser,
        event_emitter,
        config,
        capabilities_text: Optional[str] = None,
        max_cycles: Optional[int] = None,
        worker_max_steps: Optional[int] = None,
        logger: Optional[logging.Logger] = None,
        recipe_registry=None,
        conversation_history: Optional[List[Dict]] = None,
    ):
        """
        Args:
            llm_client: LLM client (OllamaClient / ExternalClient / CustomAPIClient).
            tool_executor: Shared ``ToolExecutor`` (passed through to workers).
            blackboard: ``BlackboardAccess`` — shared investigation state.
            command_parser: ``CommandParser`` (passed through to workers).
            event_emitter: ``EventEmitter`` for CoT events.
            config: LLM configuration object.
            capabilities_text: Tool documentation string (passed through to workers).
            max_cycles: Override for max worker dispatches per investigation.
            worker_max_steps: Override for default max tool steps per worker.
            logger: Optional logger instance.
            conversation_history: List of prior query/response pairs for multi-turn context.
        """
        self.llm = llm_client
        self.tool_executor = tool_executor
        self.blackboard = blackboard
        self.command_parser = command_parser
        self.emitter = event_emitter
        self.config = config
        self.capabilities_text = capabilities_text
        self.logger = logger or logging.getLogger(__name__)
        self.recipe_registry = recipe_registry
        self.conversation_history = conversation_history or []

        # Safety ceilings — hard stops to prevent runaway loops
        self.max_cycles = max_cycles or getattr(config, "orchestrator_max_cycles", 15)
        self.worker_max_steps = worker_max_steps or getattr(config, "worker_default_max_steps", 20)

        # Dynamic loop safety mechanisms
        self.coverage_stall_threshold = getattr(config, "coverage_stall_threshold", 3)
        self.doom_loop_threshold = getattr(config, "orchestrator_doom_loop_threshold", 2)

        # Vulnerability correlation hooks (extensible rule system)
        from src.correlation_hooks import CorrelationHookRegistry
        self._hook_registry = CorrelationHookRegistry()
        if getattr(config, "correlation_hooks_enabled", True):
            self._hook_registry.register_builtin_hooks(
                self.worker_max_steps, self.worker_max_steps
            )
            custom_dir = getattr(config, "custom_hooks_dir", "")
            if custom_dir:
                self._hook_registry.load_custom_hooks(custom_dir)
        self._pending_correlation_task: Optional[WorkerTask] = None

    # ──────────────────────────────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────────────────────────────

    def run(self, query: str) -> str:
        """Run a query and return the response.

        Two modes (inspired by claw-code's single-loop + OGhidra's
        domain-specific investigation):

        - **Conversational** (default): Single worker loop — the LLM sees
          tools, calls them, sees results, responds. No separate planning,
          synthesis, or triage LLM calls. Like claw-code's ``run_turn()``.

        - **Investigation**: Full 3-layer orchestrator for binary-wide
          analysis (vuln hunting, malware analysis, architecture mapping).
          Triggered by keyword detection (zero LLM calls for routing).

        Args:
            query: Natural-language query from the user.

        Returns:
            The response string.
        """
        self.emitter.emit_cot("Orchestrator", f"Query: {query[:100]}")

        # Single LLM call: route + classify strategy in one shot
        mode, strategy = self._route_query(query)

        if mode == "investigation":
            return self._run_investigation(query, strategy=strategy)
        return self._run_conversational(query)

    # ──────────────────────────────────────────────────────────────────────
    # Query routing (single LLM call — replaces regex + separate strategy)
    # ──────────────────────────────────────────────────────────────────────

    def _route_query(self, query: str):
        """Classify query as conversational or investigation in ONE LLM call.

        Also returns the investigation strategy if applicable (merges what
        used to be separate triage + strategy classification calls).

        Returns:
            Tuple of (mode, strategy).
            mode: "conversational" or "investigation"
            strategy: one of the VALID_STRATEGIES (only meaningful for investigation)
        """
        # Build context so the LLM knows what was already discussed
        history_ctx = ""
        if self.conversation_history:
            lines = []
            for turn in self.conversation_history[-3:]:
                lines.append(
                    f"User: {turn['query']}\n"
                    f"Assistant: {turn['response_summary'][:200]}"
                )
            history_ctx = "\n## Recent Conversation\n" + "\n---\n".join(lines)

        state_ctx = ""
        if self.blackboard.function_registry.count > 0:
            state_ctx = (
                f"\n## Session State: {self.blackboard.function_registry.count} "
                f"functions analyzed, "
                f"{len(self.blackboard.notebook.entries)} findings"
            )

        prompt = (
            f"Classify this reverse-engineering query into ONE of:\n\n"
            f"**conversational** — questions, single-function tasks, follow-ups, "
            f"rename/comment operations, explanations. Anything that can be answered "
            f"by examining a few functions or using a handful of tool calls.\n"
            f"Examples: 'what does this function do?', 'rename it to X', "
            f"'find references to Y', 'is there a vuln here?', 'proceed', "
            f"'can you verify that?', 'explain the caller'\n\n"
            f"**investigation:vuln_hunting** — binary-WIDE vulnerability hunting "
            f"across ALL functions. Full security audit.\n"
            f"Examples: 'find all vulnerabilities', 'security audit this binary', "
            f"'check for privilege escalation across the binary'\n\n"
            f"**investigation:malware_hunting** — binary-WIDE malware analysis. "
            f"IOC extraction, C2, persistence.\n"
            f"Examples: 'is this malware?', 'extract IOCs', 'check for C2'\n\n"
            f"**investigation:binary_understanding** — binary-WIDE architecture "
            f"mapping, full understanding.\n"
            f"Examples: 'map the complete architecture', 'what does this binary do "
            f"end to end?', 'rename all functions based on behavior'\n\n"
            f"{history_ctx}{state_ctx}\n\n"
            f"Query: \"{query}\"\n\n"
            f"Respond with ONLY the classification (e.g., 'conversational' or "
            f"'investigation:vuln_hunting'). Nothing else."
        )

        try:
            response = self.llm.generate_with_phase(
                prompt, phase="planning",
                system_prompt="You are a query router. Classify concisely.",
            )
            cleaned = response.strip().lower().replace("'", "").replace('"', "")

            if "investigation:vuln_hunting" in cleaned or "vuln_hunting" in cleaned:
                self.emitter.emit_cot("Orchestrator", "Route: investigation (vuln_hunting)")
                return "investigation", STRATEGY_VULN_HUNTING
            if "investigation:malware_hunting" in cleaned or "malware_hunting" in cleaned:
                self.emitter.emit_cot("Orchestrator", "Route: investigation (malware_hunting)")
                return "investigation", STRATEGY_MALWARE_HUNTING
            if "investigation:binary_understanding" in cleaned or "binary_understanding" in cleaned:
                self.emitter.emit_cot("Orchestrator", "Route: investigation (binary_understanding)")
                return "investigation", STRATEGY_BINARY_UNDERSTANDING
            if "investigation" in cleaned:
                self.emitter.emit_cot("Orchestrator", "Route: investigation (binary_understanding)")
                return "investigation", STRATEGY_BINARY_UNDERSTANDING

            self.emitter.emit_cot("Orchestrator", "Route: conversational")
            return "conversational", ""

        except Exception as e:
            self.logger.warning(f"Query routing failed: {e} — defaulting to conversational")
            return "conversational", ""

    def _run_conversational(self, query: str) -> str:
        """Single-loop conversational mode — one worker, no overhead.

        The worker's LLM loop IS the conversation: it sees tools,
        calls them, sees results, and responds. No separate triage,
        strategy classification, task creation, or synthesis LLM calls.
        """
        self.emitter.emit_cot("Orchestrator", "Conversational mode")
        self.emitter.emit_agent_event("orchestrator_start", {
            "max_cycles": 1, "soft_limit": 1, "strategy": "conversational",
        })

        # Build conversation context for the worker
        conv_context = ""
        if self.conversation_history:
            lines = []
            for turn in self.conversation_history[-5:]:
                lines.append(
                    f"User: {turn['query']}\n"
                    f"Assistant: {turn['response_summary'][:400]}"
                )
            conv_context = (
                "## Prior Conversation\n"
                + "\n---\n".join(lines)
                + "\n\nUse this context to understand follow-up references."
            )

        task = WorkerTask(
            goal=query,
            strategy_hint=conv_context or "Answer the user's question using the available tools.",
            max_steps=20,
            include_sections=[
                "scope", "function_registry", "discovery",
                "notebook", "tool_health",
            ],
        )

        self.emitter.emit_agent_event("worker_dispatch", {
            "task_id": task.task_id,
            "goal": query[:100],
            "max_steps": task.max_steps,
            "soft_limit": task.max_steps,
            "recipe": "",
        })

        worker = self._spawn_worker()
        result = worker.run(task)

        real_tools = 0
        if result.exec_results:
            real_tools = sum(
                1 for te in result.exec_results.tool_executions
                if te.tool_name != "<no_command>"
            )
        self.emitter.emit_agent_event("worker_complete", {
            "task_id": task.task_id,
            "exit_reason": result.exit_reason,
            "tool_count": result.tool_executions_count,
            "real_tool_count": real_tools,
            "is_complete": result.is_complete,
        })
        self.emitter.emit_agent_event("orchestrator_complete", {
            "exit_reason": f"conversational_{result.exit_reason}",
            "cycles_used": 1,
            "coverage_ratio": 0,
            "functions_analyzed": real_tools,
            "functions_total": 0,
        })

        # Return the worker's response directly — no synthesis LLM call
        response = result.final_response or ""

        # If the worker hit the ceiling without a proper TASK COMPLETE response,
        # do ONE synthesis call to produce a useful answer from the gathered data
        if not response and result.exec_results:
            try:
                # Collect the most useful tool results
                code_results = []
                for te in result.exec_results.tool_executions:
                    if te.tool_name in ("decompile_function", "decompile_function_by_address"):
                        code_results.append(te.result[:4000] if te.result else "")
                    elif te.tool_name == "get_current_function" and te.result:
                        code_results.append(te.result[:500])

                if code_results:
                    ctx = "\n\n".join(code_results[:3])
                    response = self.llm.generate_with_phase(
                        f"## User Question\n{query}\n\n"
                        f"## Gathered Data\n{ctx}\n\n"
                        "Based on the data above, answer the user's question. "
                        "Be specific and reference actual code/data.",
                        phase="analysis",
                        system_prompt=(
                            "You are an expert reverse engineer. Provide a "
                            "direct, informative answer."
                        ),
                    )
            except Exception:
                pass

        if not response:
            response = result.findings_summary or ""
        if not response and result.error:
            response = f"Error: {result.error}"
        return response

    # ──────────────────────────────────────────────────────────────────────
    # Investigation mode (3-layer orchestrator for complex tasks)
    # ──────────────────────────────────────────────────────────────────────

    def _run_investigation(self, query: str, strategy: str = "") -> str:
        """Full investigation with recon, correlation hooks, multi-cycle loop."""
        self._inv_logger = OrchestratorLogger()

        # Strategy already classified by _route_query() — fallback if missing
        if not strategy:
            strategy = self._classify_strategy(query)
        self.emitter.emit_cot("Orchestrator", f"Strategy: {strategy}")
        self.emitter.emit_agent_event("orchestrator_start", {
            "max_cycles": self.max_cycles,
            "soft_limit": self.max_cycles,
            "strategy": strategy,
        })

        # ── 2. Initialize blackboard ──
        self._initialize_investigation(query, strategy)

        # ── Log investigation start ──
        self._inv_logger.log_start(
            query=query,
            strategy=strategy,
            max_cycles=self.max_cycles,
            soft_limit=self.max_cycles,
            worker_max_steps=self.worker_max_steps,
            worker_soft_limit=self.worker_max_steps,
        )

        # ── 2b. Dedicated reconnaissance phase ──
        # Skip if discovery cache is already populated from a prior query
        if not self.blackboard.discovery_cache.is_empty():
            self.emitter.emit_cot(
                "Orchestrator",
                f"Recon skipped — discovery cache already populated "
                f"({len(self.blackboard.discovery_cache.imports)} imports, "
                f"{len(self.blackboard.discovery_cache.exports)} exports)",
            )
        else:
            self._run_recon_phase(strategy)

        # ── 2c. Batch-fire correlation hooks after recon ──
        # Run ALL matching hooks at once instead of one-per-cycle.
        # This prevents hooks from consuming 4-5 orchestrator cycles.
        try:
            corr_tasks = self._batch_fire_correlations()
        except Exception as e:
            self.logger.warning(f"Batch correlation check failed: {e}")
            corr_tasks = []

        for corr_task in corr_tasks:
            try:
                rule_name = corr_task.metadata.get("correlation_rule", "unknown")
                self.emitter.emit_cot(
                    "Orchestrator",
                    f"Correlation hook fired: {rule_name} — running targeted worker",
                )
                self.emitter.emit_agent_event("worker_dispatch", {
                    "task_id": corr_task.task_id,
                    "goal": corr_task.goal[:100],
                    "max_steps": corr_task.max_steps,
                    "soft_limit": corr_task.max_steps,
                    "recipe": corr_task.recipe or "",
                })
                corr_worker = self._spawn_worker()
                corr_result = corr_worker.run(corr_task)
                real_tools = corr_result.tool_executions_count or 0
                self.emitter.emit_agent_event("worker_complete", {
                    "task_id": corr_task.task_id,
                    "exit_reason": corr_result.exit_reason,
                    "tool_count": corr_result.tool_executions_count,
                    "real_tool_count": real_tools,
                    "is_complete": corr_result.is_complete,
                })
                self._update_notebook(corr_result, cycle=0)
                self._merge_results(corr_result)
            except Exception as e:
                self.logger.warning(
                    f"Correlation worker failed for {corr_task.metadata}: {e}"
                )
                self.emitter.emit_cot(
                    "Orchestrator",
                    f"Correlation worker ERROR: {e}",
                )

        # ── 3. Dynamic orchestration loop ──
        cycle = 0
        coverage_history: List[float] = []
        findings_history: List[int] = []
        recent_goals: List[str] = []
        worker_summaries: List[WorkerResultSummary] = []
        exit_reason = "unknown"

        while True:
            cycle += 1

            # ── HARD CEILING (safety abort) ──
            if cycle > self.max_cycles:
                self.emitter.emit_cot(
                    "Orchestrator",
                    f"Hard ceiling reached ({self.max_cycles} cycles). Stopping.",
                )
                exit_reason = "hard_ceiling"
                break

            # ── Track coverage + findings for stall detection ──
            current_coverage = self.blackboard.coverage_ratio()
            coverage_history.append(current_coverage)
            findings_history.append(len(self.blackboard.notebook.entries))
            func_analyzed = self.blackboard.function_registry.analyzed_count
            func_total = self.blackboard.total_binary_functions
            self.emitter.emit_agent_event("cycle_start", {
                "cycle": cycle,
                "coverage_ratio": current_coverage,
                "functions_analyzed": func_analyzed,
                "functions_total": func_total,
            })
            self._inv_logger.log_cycle_start(
                cycle=cycle,
                coverage_ratio=current_coverage,
                functions_analyzed=func_analyzed,
                functions_total=func_total,
            )

            # ── STALL DETECTION ──
            if self._is_coverage_stalled(coverage_history, findings_history):
                self.emitter.emit_cot(
                    "Orchestrator",
                    f"Coverage stalled at {current_coverage:.0%} for "
                    f"{self.coverage_stall_threshold} consecutive cycles. Stopping.",
                )
                exit_reason = "coverage_stall"
                break

            # ── DIMINISHING RETURNS ──
            if self._is_diminishing_returns(findings_history):
                self.emitter.emit_cot(
                    "Orchestrator",
                    "Diminishing returns: no new findings for 3 consecutive "
                    "cycles. Stopping.",
                )
                exit_reason = "diminishing_returns"
                break

            # 3a. Ask LLM for next task
            task = self._create_next_task(
                query, strategy, cycle, coverage_history,
                worker_summaries=worker_summaries,
            )

            if task is None:
                # LLM says investigation is complete
                self.emitter.emit_cot("Orchestrator", "Investigation complete (LLM decision)")
                exit_reason = "llm_complete"
                break

            # ── Log the task ──
            self._inv_logger.log_task_created(
                task_goal=task.goal,
                task_details={
                    "strategy_hint": task.strategy_hint,
                    "focus_addresses": task.focus_addresses,
                    "suggested_tools": task.suggested_tools,
                    "focus_areas": task.focus_areas,
                    "soft_limit": task.max_steps,
                    "max_steps": task.max_steps,
                },
            )

            # ── DOOM LOOP DETECTION (identical task goals) ──
            if self._is_orchestrator_doom_loop(task.goal, recent_goals):
                self.emitter.emit_cot(
                    "Orchestrator",
                    f"Doom loop detected: same task goal repeated "
                    f"{self.doom_loop_threshold} times. Stopping.",
                )
                exit_reason = "doom_loop"
                break
            recent_goals.append(task.goal)

            # 3b. Spawn worker
            self.emitter.emit_cot(
                "Orchestrator",
                f"Dispatching worker: {task.goal[:80]}...",
            )
            self.emitter.emit_agent_event("worker_dispatch", {
                "task_id": task.task_id,
                "goal": task.goal,
                "max_steps": task.max_steps,
                "soft_limit": task.max_steps,
                "recipe": task.recipe or "",
            })
            worker = self._spawn_worker()
            result = worker.run(task)
            real_tools = 0
            if result.exec_results:
                real_tools = sum(
                    1 for te in result.exec_results.tool_executions
                    if te.tool_name != "<no_command>"
                )
            # Recipe mode doesn't populate exec_results — use tool_executions_count
            if real_tools == 0 and result.tool_executions_count > 0:
                real_tools = result.tool_executions_count
            self.emitter.emit_agent_event("worker_complete", {
                "task_id": task.task_id,
                "exit_reason": result.exit_reason,
                "tool_count": result.tool_executions_count,
                "real_tool_count": real_tools,
                "is_complete": result.is_complete,
            })

            # ── Log worker result ──
            tool_exec_log = None
            if result.exec_results:
                tool_exec_log = [
                    {
                        "tool_name": te.tool_name,
                        "parameters": te.parameters,
                        "success": te.success,
                        "result": te.result,
                    }
                    for te in result.exec_results.tool_executions
                ]
            self._inv_logger.log_worker_result(
                task_id=task.task_id,
                exit_reason=result.exit_reason,
                real_tool_count=real_tools,
                is_complete=result.is_complete,
                findings_summary=result.findings_summary or "",
                tool_executions=tool_exec_log,
            )

            # 3c. Update notebook with findings
            self._update_notebook(result, cycle)

            # 3d. Merge results into blackboard
            self._merge_results(result)

            # 3d½. Build compact worker summary for orchestrator memory
            worker_summary = self._build_worker_summary(cycle, task, result)
            worker_summaries.append(worker_summary)

            # 3d¾. Synthesis failure detection — if a worker decompiled
            # 3+ functions but produced zero notebook entries, flag it.
            # The orchestrator can then re-attempt with richer context.
            self._check_synthesis_failure(worker_summary, result, cycle)

            self.blackboard.add_task_completed(
                task.task_id,
                f"[Cycle {cycle}] {task.goal[:60]} → {result.tool_executions_count} steps, "
                f"complete={result.is_complete}, exit={result.exit_reason}",
            )

            # ── Log cycle end ──
            self._inv_logger.log_cycle_end(
                cycle=cycle,
                coverage_ratio=self.blackboard.coverage_ratio(),
            )

        # ── 4. Synthesize final report ──
        report = self._synthesize_final_report(query, exit_reason, cycle)

        # ── Emit completion metrics ──
        area_ratio = self.blackboard.coverage_ratio()
        func_count = self.blackboard.function_registry.analyzed_count
        func_total = self.blackboard.total_binary_functions

        # ── Log final report to persistent investigation log ──
        self._inv_logger.log_final_report(
            report=report,
            exit_reason=exit_reason,
            cycles_used=cycle,
            metrics={
                "coverage_ratio": area_ratio,
                "functions_analyzed": func_count,
                "functions_total": func_total,
                "notebook_entries": len(self.blackboard.notebook.entries),
                "confirmed_count": sum(
                    1 for e in self.blackboard.notebook.entries
                    if e.status == "confirmed"
                ),
            },
        )

        self.emitter.emit_cot(
            "Orchestrator",
            f"Investigation finished ({exit_reason}) — "
            f"{len(self.blackboard.notebook.entries)} findings in {cycle} cycles, "
            f"area coverage {area_ratio:.0%}, {func_count} functions analyzed",
        )
        self.emitter.emit_agent_event("orchestrator_complete", {
            "exit_reason": exit_reason,
            "cycles_used": cycle,
            "coverage_ratio": area_ratio,
            "functions_analyzed": func_count,
            "functions_total": func_total,
            "log_file": self._inv_logger.filepath,
        })
        self.emitter.emit_cot(
            "Orchestrator",
            f"Investigation log saved to: {self._inv_logger.filepath}",
        )
        return report

    # ──────────────────────────────────────────────────────────────────────
    # Strategy classification
    # ──────────────────────────────────────────────────────────────────────

    def _classify_strategy(self, query: str) -> str:
        """Ask the LLM to classify the user's query into a strategy.

        Falls back to ``binary_understanding`` if the LLM response is unclear.
        """
        prompt = (
            "Classify the following reverse-engineering investigation request "
            "into EXACTLY ONE of these categories:\n\n"
            "- binary_understanding: Understanding what a binary does, its architecture, "
            "components, and data flow.\n"
            "  Examples: 'What does this binary do?', 'Analyze this executable', "
            "'Describe the program architecture', 'What are the main components?'\n\n"
            "- malware_hunting: Detecting malicious behavior, extracting IOCs, "
            "understanding evasion and C2 protocols.\n"
            "  Examples: 'Is this malware?', 'Extract IOCs', 'Check for C2', "
            "'Look for persistence mechanisms', 'Analyze this suspicious binary'\n\n"
            "- vuln_hunting: Finding exploitable security flaws like privilege "
            "escalation, code injection, unquoted paths, DLL hijacking.\n"
            "  Examples: 'Find vulnerabilities', 'Check for privilege escalation', "
            "'Look for DLL hijacking', 'Security audit', 'Find CVEs'\n\n"
            f"User request: \"{query}\"\n\n"
            "Respond with ONLY the category name (e.g., 'vuln_hunting'). Nothing else."
        )

        try:
            response = self.llm.generate_with_phase(
                prompt, phase="planning", system_prompt="You are a classification assistant."
            )
            # Extract strategy from response
            cleaned = response.strip().lower().replace("'", "").replace('"', "")
            for strategy in VALID_STRATEGIES:
                if strategy in cleaned:
                    return strategy
        except Exception as e:
            self.logger.warning(f"Strategy classification failed: {e}")

        # Default fallback
        return STRATEGY_BINARY_UNDERSTANDING

    # ──────────────────────────────────────────────────────────────────────
    # Investigation initialization
    # ──────────────────────────────────────────────────────────────────────

    def _initialize_investigation(self, query: str, strategy: str):
        """Prepare blackboard for a new investigation cycle.

        Resets coverage and leads tracking but PRESERVES the function
        registry (accumulated analyses) and discovery cache (import/export
        data) across queries so follow-up investigations benefit from
        prior work.  Only the notebook is reset to create a fresh
        findings list for the new investigation question.
        """
        self.blackboard.coverage.reset()
        self.blackboard.leads.reset()

        # Fresh notebook for this investigation, but keep registry + discovery
        self.blackboard.notebook = InvestigationNotebook(
            investigation_strategy=strategy,
        )
        # Discovery cache: keep if populated (avoids redundant recon)
        # Function registry: always keep (accumulated function analyses)

        # Reset correlation hooks for fresh investigation
        self._hook_registry.reset()
        self._pending_correlation_task = None

        # Attempt to set total binary function count from analysis state
        # (populated if list_functions was called in a prior session)
        analysis_state = self.blackboard.get_analysis_state()
        total_funcs = getattr(analysis_state, "total_functions", 0)
        if total_funcs:
            self.blackboard.total_binary_functions = total_funcs

        self.logger.info(
            f"Investigation initialized: strategy={strategy}, "
            f"max_cycles={self.max_cycles}, worker_steps={self.worker_max_steps}"
        )

    def _run_recon_phase(self, strategy: str):
        """Run the dedicated reconnaissance phase (surface mapping)."""
        recon_task = WorkerTask(
            goal=(
                "Map the binary's attack surface: list ALL imports (use pagination "
                "to get them all), search for security-relevant strings (.exe, .dll, "
                "http, cmd, service, .., path, file), and list all exported functions. "
                "Do NOT decompile anything yet."
            ),
            strategy_hint=(
                "Focus on complete surface mapping. Call list_imports with "
                "pagination to get ALL imports. Call list_strings with filters "
                "for: .exe, .dll, http, cmd, service, .., path, file. "
                "Call list_exports. This data will be cached for all future workers."
            ),
            suggested_tools=[
                "list_imports", "list_exports", "list_strings",
                "search_strings_in_binary", "list_functions",
            ],
            focus_areas=[],
            max_steps=self.worker_max_steps,
            include_sections=["scope"],
            metadata={"cycle": 0, "strategy": strategy, "phase": "recon"},
        )

        self.emitter.emit_cot("Orchestrator", "Reconnaissance phase — mapping binary surface")
        self.emitter.emit_agent_event("worker_dispatch", {
            "task_id": recon_task.task_id,
            "goal": recon_task.goal,
            "max_steps": recon_task.max_steps,
            "soft_limit": recon_task.max_steps,
            "recipe": recon_task.recipe or "",
        })
        self._inv_logger.log_cycle_start(
            cycle=0, coverage_ratio=0.0,
            functions_analyzed=0, functions_total=0,
        )
        self._inv_logger.log_task_created(
            task_goal=recon_task.goal,
            task_details={"phase": "recon", "max_steps": recon_task.max_steps},
        )

        recon_worker = self._spawn_worker()
        recon_result = recon_worker.run(recon_task)
        recon_real_tools = 0
        if recon_result.exec_results:
            recon_real_tools = sum(
                1 for te in recon_result.exec_results.tool_executions
                if te.tool_name != "<no_command>"
            )
        if recon_real_tools == 0 and recon_result.tool_executions_count > 0:
            recon_real_tools = recon_result.tool_executions_count
        self.emitter.emit_agent_event("worker_complete", {
            "task_id": recon_task.task_id,
            "exit_reason": recon_result.exit_reason,
            "tool_count": recon_result.tool_executions_count,
            "real_tool_count": recon_real_tools,
            "is_complete": recon_result.is_complete,
        })
        recon_tool_log = None
        if recon_result.exec_results:
            recon_tool_log = [
                {"tool_name": te.tool_name, "parameters": te.parameters,
                 "success": te.success, "result": te.result}
                for te in recon_result.exec_results.tool_executions
            ]
        self._inv_logger.log_worker_result(
            task_id=recon_task.task_id, exit_reason=recon_result.exit_reason,
            real_tool_count=recon_real_tools, is_complete=recon_result.is_complete,
            findings_summary=recon_result.findings_summary or "",
            tool_executions=recon_tool_log,
        )
        self._merge_results(recon_result)
        self.blackboard.add_task_completed(
            recon_task.task_id,
            f"[Recon] Surface mapping -> {recon_real_tools} tool calls, "
            f"exit={recon_result.exit_reason}",
        )
        self._inv_logger.log_cycle_end(
            cycle=0, coverage_ratio=self.blackboard.coverage_ratio()
        )
        self.emitter.emit_cot(
            "Orchestrator",
            f"Recon complete: {recon_real_tools} tool calls, "
            f"discovery cache populated "
            f"({len(self.blackboard.discovery_cache.imports)} imports, "
            f"{len(self.blackboard.discovery_cache.exports)} exports, "
            f"{len(self.blackboard.discovery_cache.strings)} string filters)",
        )

    # ──────────────────────────────────────────────────────────────────────
    # Task creation (LLM-driven)
    # ──────────────────────────────────────────────────────────────────────

    def _create_next_task(
        self,
        query: str,
        strategy: str,
        cycle: int,
        coverage_history: Optional[List[float]] = None,
        worker_summaries: Optional[List[WorkerResultSummary]] = None,
    ) -> Optional[WorkerTask]:
        """Ask the LLM what the most valuable next task is.

        The LLM sees: strategy, notebook state, coverage gaps, active leads,
        function registry summary, worker history, and budget/momentum context.

        Returns ``None`` if the LLM determines the investigation is complete.
        """
        coverage_history = coverage_history or []

        # Build context for the orchestrator LLM call
        investigation_summary = self.blackboard.get_investigation_summary()
        notebook_prompt = self.blackboard.get_notebook_prompt(max_entries=10)
        coverage_prompt = self.blackboard.get_coverage_prompt()
        leads_prompt = self.blackboard.get_leads_prompt()
        registry_prompt = self.blackboard.get_orchestrator_registry_prompt(max_entries=30)

        system_prompt = self._get_task_creation_system_prompt(strategy)

        # ── Coverage momentum (no cycle counter — let LLM decide based on state) ──
        coverage_momentum = ""
        if len(coverage_history) >= 2:
            prev = coverage_history[-2]
            curr = coverage_history[-1]
            delta = curr - prev
            if delta > 0.005:
                coverage_momentum = f"- Coverage momentum: +{delta:.0%} (advancing)"
            elif delta < -0.005:
                coverage_momentum = f"- Coverage momentum: {delta:.0%} (regressing?)"
            else:
                coverage_momentum = "- Coverage momentum: 0% (stalled — consider wrapping up)"

        # No cycle counter — let LLM decide based on investigation state alone
        momentum_line = f"\n{coverage_momentum}" if coverage_momentum else ""
        user_prompt = (
            f"## Investigation Request\n{query}\n\n"
            f"## Strategy: {strategy}"
            f"{momentum_line}\n\n"
        )

        # Inject conversation history so follow-up queries have context
        if self.conversation_history:
            history_lines = []
            for turn in self.conversation_history[-3:]:
                history_lines.append(
                    f"**User:** {turn['query']}\n"
                    f"**Result:** {turn['response_summary'][:300]}"
                )
            user_prompt += (
                "## Prior Conversation Context\n"
                + "\n---\n".join(history_lines) + "\n\n"
            )

        if notebook_prompt:
            user_prompt += f"{notebook_prompt}\n\n"
        if coverage_prompt:
            user_prompt += f"{coverage_prompt}\n\n"
        if leads_prompt:
            user_prompt += f"{leads_prompt}\n\n"
        if registry_prompt:
            user_prompt += f"{registry_prompt}\n\n"

        # Inject worker history so the LLM knows what was already done
        worker_history_prompt = self._format_worker_history_prompt(
            worker_summaries or []
        )
        if worker_history_prompt:
            user_prompt += f"{worker_history_prompt}\n\n"

        # Inject tool health warnings (blacklisted/degraded tools)
        health_summary = self.blackboard.get_tool_health_prompt()
        if health_summary:
            user_prompt += f"{health_summary}\n\n"

        user_prompt += (
            "Based on the above, decide the NEXT investigation task.\n"
            "If the investigation is sufficiently complete, respond with:\n"
            "INVESTIGATION COMPLETE\n\n"
            "Otherwise, respond with a JSON task specification:\n"
            "```json\n"
            "{\n"
            '  "goal": "Specific task description",\n'
            '  "strategy_hint": "Guidance for the worker",\n'
            '  "focus_addresses": ["0x00401000"],\n'
            '  "suggested_tools": ["decompile_function_by_address", "get_xrefs_to"],\n'
            '  "focus_areas": ["process_creation"],\n'
            '  "max_steps": 8,\n'
            '  "include_sections": ["scope", "knowledge", "function_registry", "discovery"]\n'
            "}\n"
            "```"
        )

        try:
            response = self.llm.generate_with_phase(
                user_prompt,
                phase="planning",
                system_prompt=system_prompt,
            )
        except Exception as e:
            self.logger.error(f"Task creation LLM call failed: {e}")
            # Fallback: create a generic recon task
            return WorkerTask(
                goal=f"Investigate: {query[:100]}",
                strategy_hint=f"Strategy: {strategy}. Cycle {cycle}.",
                max_steps=self.worker_max_steps,
                )

        # Check for completion
        if "INVESTIGATION COMPLETE" in response.upper():
            return None

        # Parse JSON task specification
        return self._parse_task_from_response(response, query, strategy, cycle)

    def _parse_task_from_response(
        self, response: str, query: str, strategy: str, cycle: int
    ) -> WorkerTask:
        """Parse a WorkerTask from the LLM's JSON response.

        Falls back to a reasonable default task if parsing fails.
        """
        # Try to extract JSON from response
        json_match = re.search(r"```json\s*(.*?)\s*```", response, re.DOTALL)
        if not json_match:
            # Try bare JSON
            json_match = re.search(r"\{[^{}]*\}", response, re.DOTALL)

        if json_match:
            try:
                task_dict = json.loads(json_match.group(1) if "```" in response else json_match.group(0))
                requested_steps = task_dict.get("max_steps", self.worker_max_steps)
                task_kwargs = {
                    "goal": task_dict.get("goal", f"Investigate: {query[:80]}"),
                    "strategy_hint": task_dict.get("strategy_hint", ""),
                    "focus_addresses": task_dict.get("focus_addresses", []),
                    "focus_areas": task_dict.get("focus_areas", []),
                    "suggested_tools": task_dict.get("suggested_tools", []),
                    "max_steps": self.worker_max_steps,  # Safety ceiling
                    "include_sections": self._ensure_discovery_section(
                        task_dict.get("include_sections", [
                            "scope", "knowledge", "analysis_state",
                            "function_registry", "discovery"
                        ])
                    ),
                    "metadata": {"cycle": cycle, "strategy": strategy},
                }
                # Parse recipe fields if present
                if task_dict.get("recipe"):
                    task_kwargs["recipe"] = task_dict["recipe"]
                if task_dict.get("recipe_params"):
                    task_kwargs["recipe_params"] = task_dict["recipe_params"]
                if task_dict.get("analysis_focus"):
                    task_kwargs["analysis_focus"] = task_dict["analysis_focus"]
                return WorkerTask(**task_kwargs)
            except (json.JSONDecodeError, KeyError) as e:
                self.logger.warning(f"Failed to parse task JSON: {e}")

        # Fallback: extract goal from plain text
        self.logger.warning("Could not parse structured task — using fallback")
        goal = response.strip()[:200] if response.strip() else f"Continue {strategy} investigation"

        return WorkerTask(
            goal=goal,
            strategy_hint=f"Strategy: {strategy}. Cycle {cycle} of {self.max_cycles}.",
            max_steps=self.worker_max_steps,  # Safety ceiling
            metadata={"cycle": cycle, "strategy": strategy, "fallback": True},
        )

    # ──────────────────────────────────────────────────────────────────────
    # Worker spawning
    # ──────────────────────────────────────────────────────────────────────

    def _spawn_worker(self) -> WorkerAgent:
        """Create a new WorkerAgent with shared dependencies."""
        return WorkerAgent(
            llm_client=self.llm,
            tool_executor=self.tool_executor,
            blackboard=self.blackboard,
            command_parser=self.command_parser,
            event_emitter=self.emitter,
            config=self.config,
            capabilities_text=self.capabilities_text,
            logger=self.logger,
            recipe_registry=self.recipe_registry,
        )

    # ──────────────────────────────────────────────────────────────────────
    # Notebook updating (LLM-driven continuous synthesis)
    # ──────────────────────────────────────────────────────────────────────

    def _update_notebook(self, result: AgentResult, cycle: int):
        """Update the investigation notebook with worker findings.

        Two paths:
          - **Recipe mode**: If the worker produced direct notebook entries
            (``exit_reason == "recipe_complete"``), apply them directly through
            the quality filter — no blind LLM synthesis needed.
          - **LLM loop mode**: Ask the LLM to synthesize notebook entries from
            200-char tool result excerpts (legacy behavior).
        """
        # Early branch: recipe-mode results bypass the blind synthesis LLM
        if (
            result.exit_reason == "recipe_complete"
            and result.notebook_entries
        ):
            self._apply_direct_notebook_entries(result, cycle)
            return

        if not result.findings_summary and result.error:
            # Worker failed — just log the error
            self.blackboard.add_notebook_entry(NotebookEntry(
                category="error",
                severity="info",
                title=f"Worker error in cycle {cycle}",
                detail=result.error[:300],
                evidence=[],
                addresses=[],
                status="confirmed",
            ))
            return

        # Build context for the notebook update LLM call
        current_notebook = self.blackboard.get_notebook_prompt(max_entries=10)

        # Collect tool execution details for the LLM.
        # Decompile results need enough code for the LLM to spot
        # vulnerabilities — function signatures alone are useless.
        _DECOMPILE_TOOLS = {
            "decompile_function", "decompile_function_by_address",
        }
        _RICH_EXCERPT_TOOLS = _DECOMPILE_TOOLS | {
            "get_xrefs_to", "get_xrefs_from", "get_function_xrefs",
        }
        exec_summary_parts = []
        if result.exec_results:
            for te in result.exec_results.tool_executions[:15]:
                if te.tool_name == "<no_command>":
                    continue
                if te.tool_name in _DECOMPILE_TOOLS:
                    excerpt = (te.result or "")[:8000]
                elif te.tool_name in _RICH_EXCERPT_TOOLS:
                    excerpt = (te.result or "")[:2000]
                else:
                    excerpt = (te.result or "")[:500]
                exec_summary_parts.append(f"- {te.tool_name}({te.parameters}): {excerpt}")

        exec_summary = "\n".join(exec_summary_parts) if exec_summary_parts else "No tools executed."

        strategy = self.blackboard.notebook.investigation_strategy
        system_prompt = self._get_notebook_update_system_prompt(strategy)

        user_prompt = (
            f"## Current Notebook\n{current_notebook or 'Empty — first cycle.'}\n\n"
            f"## Worker Findings (Cycle {cycle})\n"
            f"**Summary:** {result.findings_summary}\n\n"
            f"**Tool Results:**\n{exec_summary}\n\n"
            "Produce notebook entries for any NEW findings. Return a JSON array."
        )

        try:
            response = self.llm.generate_with_phase(
                user_prompt, phase="analysis", system_prompt=system_prompt
            )
            entries = self._parse_notebook_entries(response)

            # Programmatic quality filter — reject noise entries that the
            # LLM generated despite prompt instructions
            accepted = []
            rejected = []
            for entry in entries:
                rejection = self._validate_notebook_entry(entry, strategy)
                if rejection:
                    self.logger.info(
                        f"Notebook entry rejected: {entry.title!r} — {rejection}"
                    )
                    rejected.append({
                        "severity": entry.severity,
                        "title": entry.title,
                        "reason": rejection,
                    })
                    continue
                if self._is_duplicate_entry(entry):
                    self.logger.info(
                        f"Notebook entry deduplicated: {entry.title!r}"
                    )
                    rejected.append({
                        "severity": entry.severity,
                        "title": entry.title,
                        "reason": "duplicate",
                    })
                    continue
                accepted.append(entry)

            for entry in accepted:
                self.blackboard.add_notebook_entry(entry)

            # Log accepted + rejected to investigation logger
            if hasattr(self, "_inv_logger"):
                self._inv_logger.log_notebook_update(
                    accepted=[
                        {
                            "severity": e.severity,
                            "title": e.title,
                            "status": e.status,
                        }
                        for e in accepted
                    ],
                    rejected=rejected,
                )

            if accepted:
                self.emitter.emit_cot(
                    "Orchestrator",
                    f"Notebook updated: +{len(accepted)} entries "
                    f"({len(entries) - len(accepted)} filtered)",
                )
        except Exception as e:
            self.logger.warning(f"Notebook update failed: {e}")
            # Fallback: add a raw finding entry
            self.blackboard.add_notebook_entry(NotebookEntry(
                category="info",
                severity="info",
                title=f"Worker findings from cycle {cycle}",
                detail=result.findings_summary[:500],
                evidence=[],
                addresses=[],
                status="needs_investigation",
            ))

    def _apply_direct_notebook_entries(
        self, result: AgentResult, cycle: int
    ):
        """Apply notebook entries produced directly by recipe-mode workers.

        These entries came from an LLM that saw FULL decompiled code (not
        200-char excerpts), so they are higher quality than the blind
        synthesis path.  We still apply the quality filter and dedup check.
        """
        strategy = self.blackboard.notebook.investigation_strategy
        accepted = []
        rejected = []

        for entry_dict in result.notebook_entries:
            try:
                entry = NotebookEntry(
                    category=entry_dict.get("category", "info"),
                    severity=entry_dict.get("severity", "info"),
                    title=entry_dict.get("title", "Untitled finding"),
                    detail=entry_dict.get("detail", ""),
                    evidence=entry_dict.get("evidence", []),
                    addresses=entry_dict.get("addresses", []),
                    status=entry_dict.get("status", "needs_investigation"),
                )
            except Exception as e:
                self.logger.warning(
                    f"Invalid notebook entry from recipe: {e}"
                )
                continue

            # Apply the same quality filter as the LLM synthesis path
            rejection = self._validate_notebook_entry(entry, strategy)
            if rejection:
                self.logger.info(
                    f"Recipe notebook entry rejected: {entry.title!r} — {rejection}"
                )
                rejected.append({
                    "severity": entry.severity,
                    "title": entry.title,
                    "reason": rejection,
                })
                continue

            if self._is_duplicate_entry(entry):
                self.logger.info(
                    f"Recipe notebook entry deduplicated: {entry.title!r}"
                )
                rejected.append({
                    "severity": entry.severity,
                    "title": entry.title,
                    "reason": "duplicate",
                })
                continue

            accepted.append(entry)

        for entry in accepted:
            self.blackboard.add_notebook_entry(entry)

        # Log to investigation logger
        if hasattr(self, "_inv_logger"):
            self._inv_logger.log_notebook_update(
                accepted=[
                    {
                        "severity": e.severity,
                        "title": e.title,
                        "status": e.status,
                    }
                    for e in accepted
                ],
                rejected=rejected,
            )

        if accepted:
            self.emitter.emit_cot(
                "Orchestrator",
                f"Recipe notebook entries: +{len(accepted)} accepted, "
                f"{len(rejected)} filtered (direct from recipe analysis)",
            )
        elif rejected:
            self.emitter.emit_cot(
                "Orchestrator",
                f"Recipe notebook entries: all {len(rejected)} filtered",
            )

    def _parse_notebook_entries(self, response: str) -> List[NotebookEntry]:
        """Parse NotebookEntry objects from the LLM's JSON response."""
        # Try to extract JSON array
        json_match = re.search(r"```json\s*(.*?)\s*```", response, re.DOTALL)
        raw = json_match.group(1) if json_match else response

        # Find the JSON array in the text
        bracket_match = re.search(r"\[.*\]", raw, re.DOTALL)
        if not bracket_match:
            return []

        try:
            entries_data = json.loads(bracket_match.group(0))
        except json.JSONDecodeError:
            self.logger.warning("Failed to parse notebook entries JSON")
            return []

        if not isinstance(entries_data, list):
            return []

        entries = []
        for item in entries_data:
            if not isinstance(item, dict):
                continue
            try:
                entries.append(NotebookEntry(
                    category=item.get("category", "info"),
                    severity=item.get("severity", "info"),
                    title=item.get("title", "Untitled finding"),
                    detail=item.get("detail", ""),
                    evidence=item.get("evidence", []),
                    addresses=item.get("addresses", []),
                    status=item.get("status", "needs_investigation"),
                ))
            except Exception as e:
                self.logger.debug(f"Skipping malformed notebook entry: {e}")

        return entries

    # ──────────────────────────────────────────────────────────────────────
    # Notebook entry quality filtering (programmatic, not LLM-dependent)
    # ──────────────────────────────────────────────────────────────────────

    # Maximum number of entries in the notebook before we start rejecting
    # lower-severity entries to prevent unbounded growth
    MAX_NOTEBOOK_ENTRIES = 25

    # Noise indicator phrases — if the title or detail contains these,
    # the entry is likely surface-level reconnaissance, not a real finding.
    # These are only applied for vuln_hunting and malware_hunting strategies
    # (for binary_understanding, import observations ARE valid findings).
    _NOISE_PHRASES_SECURITY = [
        "binary imports",
        "imports the following",
        "uses the api",
        "common api usage",
        "standard api pattern",
        "general observation",
        "utilizes windows api",
        "imports found",
        "api listing",
        "import summary",
    ]

    def _validate_notebook_entry(
        self, entry: NotebookEntry, strategy: str
    ) -> Optional[str]:
        """Validate a notebook entry before adding it. Returns rejection reason or None.

        This is a programmatic quality gate that catches noise entries the LLM
        generated despite prompt instructions. Rules are strategy-specific.

        Returns:
            None if the entry passes validation, or a string reason for rejection.
        """
        title_lower = entry.title.lower()
        detail_lower = entry.detail.lower()
        combined = f"{title_lower} {detail_lower}"

        # ── Universal rules ──

        # Reject entries with no title or generic titles
        if len(entry.title.strip()) < 10:
            return "title too short (< 10 chars)"

        # Reject entries with no detail
        if len(entry.detail.strip()) < 20:
            return "detail too short (< 20 chars)"

        # Reject noise phrases in title (security strategies only — for
        # binary_understanding, import/API observations are valid findings)
        if strategy in (STRATEGY_VULN_HUNTING, STRATEGY_MALWARE_HUNTING):
            for phrase in self._NOISE_PHRASES_SECURITY:
                if phrase in combined:
                    return f"noise phrase detected: '{phrase}'"

        # Enforce notebook size cap — only accept high+ severity when full
        current_count = len(self.blackboard.notebook.entries)
        if current_count >= self.MAX_NOTEBOOK_ENTRIES:
            if entry.severity not in ("critical", "high"):
                return (
                    f"notebook full ({current_count} entries), "
                    f"only accepting critical/high severity"
                )

        # ── Strategy-specific rules ──

        if strategy == STRATEGY_VULN_HUNTING:
            # For vuln_hunting: reject info/low severity entirely
            if entry.severity in ("info", "low"):
                return f"severity '{entry.severity}' too low for vuln_hunting"

            # Reject entries without any address evidence
            if not entry.addresses and not any(
                re.search(r'(?:0x)?[0-9a-fA-F]{6,}', ev)
                for ev in entry.evidence
            ):
                return "vuln_hunting entry has no address evidence"

            # Reject entries that are just "API found in code" observations
            api_observation_patterns = [
                r"binary (?:uses|calls|imports)\s+\w+",
                r"(?:found|detected|observed|identified)\s+(?:the\s+)?(?:use|call|import)\s+of",
                r"presence of\s+\w+\s+api",
            ]
            for pattern in api_observation_patterns:
                if re.search(pattern, combined):
                    # Only reject if there's no exploit path described
                    if "exploit" not in combined and "attacker" not in combined:
                        return f"surface-level API observation without exploit path"

        elif strategy == STRATEGY_MALWARE_HUNTING:
            # For malware_hunting: reject plain info severity
            if entry.severity == "info":
                return f"severity 'info' too low for malware_hunting notebook"

        return None  # Entry passes validation

    def _is_duplicate_entry(self, entry: NotebookEntry) -> bool:
        """Check if a substantially similar entry already exists in the notebook.

        Uses a combination of:
          - Exact title match
          - Overlapping addresses (same function analyzed)
          - Title word overlap > 60% (fuzzy dedup)
        """
        existing = self.blackboard.notebook.entries
        entry_title_words = set(entry.title.lower().split())

        for existing_entry in existing:
            # Exact title match
            if existing_entry.title.lower() == entry.title.lower():
                return True

            # Same addresses (same function = likely duplicate finding)
            if entry.addresses and existing_entry.addresses:
                overlap = set(entry.addresses) & set(existing_entry.addresses)
                if overlap:
                    # Same address AND similar category → duplicate
                    if entry.category == existing_entry.category:
                        return True

            # Title word overlap > 60% → likely duplicate
            existing_words = set(existing_entry.title.lower().split())
            if entry_title_words and existing_words:
                intersection = entry_title_words & existing_words
                smaller = min(len(entry_title_words), len(existing_words))
                if smaller > 0 and len(intersection) / smaller > 0.6:
                    return True

        return False

    # ──────────────────────────────────────────────────────────────────────
    # Final report synthesis
    # ──────────────────────────────────────────────────────────────────────

    # Strategy-specific verdict questions for the synthesis LLM call
    _VERDICT_QUESTIONS = {
        STRATEGY_VULN_HUNTING: (
            "Is this binary vulnerable? State the verdict clearly: "
            "VULNERABLE (with specifics) or NO CONFIRMED VULNERABILITIES "
            "(with what was checked)."
        ),
        STRATEGY_MALWARE_HUNTING: (
            "Is this binary malicious? State the verdict clearly: "
            "MALICIOUS (with capability summary) or "
            "NO MALICIOUS BEHAVIOR CONFIRMED (with what was checked)."
        ),
        STRATEGY_BINARY_UNDERSTANDING: (
            "What does this binary do? State its purpose and key "
            "capabilities in 2-3 sentences."
        ),
    }

    def _synthesize_final_report(
        self, query: str, exit_reason: str, cycles_used: int
    ) -> str:
        """Synthesize a clean, human-readable final report.

        Makes ONE final LLM call that sees the full investigation picture —
        confirmed findings, coverage, function analysis — and produces a
        structured 5-section report with executive summary and verdict.

        Falls back to ``_build_structured_fallback_report()`` if the LLM
        call fails, ensuring the user always gets a well-structured report.
        """
        strategy = self.blackboard.notebook.investigation_strategy

        # ── Gather data (all cheap blackboard reads) ──

        confirmed = [
            e for e in self.blackboard.notebook.entries
            if e.status == "confirmed"
        ]
        suspected = [
            e for e in self.blackboard.notebook.entries
            if e.status == "suspected"
        ]
        needs_inv = [
            e for e in self.blackboard.notebook.entries
            if e.status == "needs_investigation"
        ]

        # Confirmed findings: full detail (these are the signal)
        if confirmed:
            parts = []
            for e in confirmed:
                ev_str = "; ".join(e.evidence[:3]) if e.evidence else "no evidence cited"
                addr_str = ", ".join(e.addresses[:3]) if e.addresses else ""
                parts.append(
                    f"- [{e.severity.upper()}] {e.title}\n"
                    f"  Detail: {e.detail[:300]}\n"
                    f"  Evidence: {ev_str}"
                    + (f"\n  Addresses: {addr_str}" if addr_str else "")
                )
            confirmed_text = "\n".join(parts)
        else:
            confirmed_text = "None."

        # Suspected findings: titles only (context, not featured)
        suspected_text = "\n".join(
            f"- [{e.severity.upper()}] {e.title}" for e in suspected[:5]
        ) or "None."

        # Coverage metrics
        analyzed_areas = self.blackboard.coverage.get_covered()
        uncovered = self.blackboard.coverage.get_uncovered()
        total_areas = len(self.blackboard.coverage.areas)
        func_count = self.blackboard.function_registry.analyzed_count
        func_total = self.blackboard.total_binary_functions

        # Functions with security notes (expanded from 5 to 15)
        sec_funcs = self.blackboard.get_functions_with_security_notes()
        sec_funcs_parts = []
        for f in sec_funcs[:15]:
            line = f"- {f.name} ({f.address}): " + "; ".join(f.security_notes[:3])
            if f.behavioral_tags:
                line += f"  [tags: {', '.join(f.behavioral_tags[:3])}]"
            if f.iocs_found:
                line += f"  [IOCs: {', '.join(f.iocs_found[:3])}]"
            sec_funcs_parts.append(line)
        sec_funcs_text = "\n".join(sec_funcs_parts) or "None."

        # Needs-investigation entries (previously dropped entirely)
        if needs_inv:
            needs_inv_text = "\n".join(
                f"- [{e.severity.upper()}] {e.title}: {e.detail[:150]}"
                for e in needs_inv[:5]
            )
        else:
            needs_inv_text = "None."

        # Key imports from discovery cache (security-relevant context)
        discovery_summary = self.blackboard.get_discovery_prompt(
            max_imports=30, max_strings=10
        )

        # Decompiled code for finding-referenced functions (from code cache)
        code_evidence = self.blackboard.get_code_cache_summary(
            max_functions=5, max_lines_per_func=40
        )

        # ── Build synthesis prompt ──

        verdict_question = self._VERDICT_QUESTIONS.get(
            strategy, self._VERDICT_QUESTIONS[STRATEGY_BINARY_UNDERSTANDING]
        )

        system_prompt = (
            "You are writing the final report for a binary analysis investigation. "
            "Be concise and definitive. Only state what is confirmed by evidence. "
            "Do NOT speculate or pad the report with unverified observations. "
            "Include code evidence where available to substantiate findings."
        )

        area_names = ", ".join(a.name for a in analyzed_areas) if analyzed_areas else "none"
        gap_names = ", ".join(a.name for a in uncovered) if uncovered else "none"
        func_str = (
            f"{func_count}/{func_total}" if func_total > 0
            else f"{func_count} (total unknown)"
        )

        # Build optional enrichment sections
        enrichment_parts = []
        if needs_inv_text and needs_inv_text != "None.":
            enrichment_parts.append(
                f"## Needs Investigation\n{needs_inv_text}"
            )
        if code_evidence:
            enrichment_parts.append(
                f"## Decompiled Code Evidence\n{code_evidence}"
            )
        if discovery_summary:
            enrichment_parts.append(
                f"## Key Imports & Strings\n{discovery_summary}"
            )
        enrichment_section = "\n\n".join(enrichment_parts)

        user_prompt = (
            f"## Investigation: {query[:120]}\n"
            f"**Strategy:** {strategy} | **Cycles:** {cycles_used} | "
            f"**Exit:** {exit_reason}\n\n"

            f"## Confirmed Findings\n{confirmed_text}\n\n"
            f"## Suspected (Unverified)\n{suspected_text}\n\n"
            f"## Functions with Security Notes\n{sec_funcs_text}\n\n"

            + (f"{enrichment_section}\n\n" if enrichment_section else "")

            + f"## Coverage\n"
            f"- Areas analyzed: {area_names} ({len(analyzed_areas)}/{total_areas})\n"
            f"- Functions deeply analyzed: {func_str}\n"
            f"- Gaps: {gap_names}\n\n"

            f"## Your Task\n"
            f"Write the final report with EXACTLY this structure (use markdown):\n"
            f"1. **Executive Summary** (2-3 sentences: what is this binary, "
            f"what did we find)\n"
            f"2. **Verdict** ({verdict_question})\n"
            f"3. **Confirmed Findings** (confirmed items with evidence and "
            f"relevant code snippets — or 'None')\n"
            f"4. **Requires Further Investigation** (1-line per suspected "
            f"or needs-investigation item — or 'None')\n"
            f"5. **Coverage** (1-2 lines: what was checked, what gaps remain)\n\n"
            f"Start with '# Analysis Report'. "
            f"Do NOT add findings beyond what is listed above. Do NOT speculate."
        )

        try:
            report = self.llm.generate_with_phase(
                user_prompt,
                phase="analysis",
                system_prompt=system_prompt,
            )
            # Ensure it starts with a heading
            if not report.strip().startswith("#"):
                report = f"# Analysis Report\n\n{report}"
            return report
        except Exception as e:
            self.logger.warning(f"Final synthesis LLM call failed: {e}")
            return self._build_structured_fallback_report(
                query, strategy, exit_reason, cycles_used,
                confirmed, suspected, needs_inv,
                analyzed_areas, uncovered, func_count, func_total,
            )

    def _build_structured_fallback_report(
        self,
        query: str,
        strategy: str,
        exit_reason: str,
        cycles_used: int,
        confirmed: List[NotebookEntry],
        suspected: List[NotebookEntry],
        needs_inv: List[NotebookEntry],
        analyzed_areas: list,
        uncovered: list,
        func_count: int,
        func_total: int,
    ) -> str:
        """Build a structured report programmatically (no LLM call).

        Used as a fallback when the synthesis LLM call fails, and also
        provides the report template that the LLM synthesis follows.
        Same 5-section structure: Executive Summary, Verdict, Confirmed
        Findings, Requires Further Investigation, Coverage.
        """
        total_areas = len(self.blackboard.coverage.areas)
        binary_name = self.blackboard.notebook.binary_name or "Unknown binary"
        lines = [f"# Analysis Report: {binary_name}"]
        lines.append(
            f"**Strategy:** {strategy} | **Cycles:** {cycles_used} | "
            f"**Exit:** {exit_reason}\n"
        )

        # 1. Executive Summary
        lines.append("## Executive Summary")
        lines.append(
            f"Investigated '{query[:80]}' using {strategy} strategy over "
            f"{cycles_used} cycle(s). Found {len(confirmed)} confirmed "
            f"finding(s) and {len(suspected)} suspected."
        )

        # 2. Verdict
        lines.append("\n## Verdict")
        if strategy == STRATEGY_VULN_HUNTING:
            if confirmed:
                vuln_titles = "; ".join(e.title for e in confirmed[:3])
                lines.append(
                    f"**VULNERABLE** — {len(confirmed)} confirmed: {vuln_titles}"
                )
            else:
                lines.append(
                    "**No confirmed vulnerabilities.** See suspected items below "
                    "for leads that require further investigation."
                )
        elif strategy == STRATEGY_MALWARE_HUNTING:
            if any(e.severity in ("critical", "high") for e in confirmed):
                lines.append(
                    f"**MALICIOUS BEHAVIOR CONFIRMED** — "
                    f"{len(confirmed)} confirmed finding(s)."
                )
            else:
                lines.append("**No confirmed malicious behavior.**")
        else:
            purpose = self.blackboard.notebook.binary_purpose
            lines.append(
                purpose if purpose
                else "Binary purpose could not be fully determined from analysis."
            )

        # 3. Confirmed Findings
        lines.append("\n## Confirmed Findings")
        if confirmed:
            for e in confirmed:
                lines.append(f"\n### [{e.severity.upper()}] {e.title}")
                if e.detail:
                    lines.append(e.detail[:400])
                if e.evidence:
                    lines.append("**Evidence:** " + "; ".join(e.evidence[:4]))
                if e.addresses:
                    lines.append(f"**Addresses:** {', '.join(e.addresses[:5])}")
        else:
            lines.append("No findings were confirmed during this investigation.")

        # 4. Requires Further Investigation
        lines.append("\n## Requires Further Investigation")
        all_unverified = suspected + needs_inv
        if all_unverified:
            for e in all_unverified[:5]:
                lines.append(f"- [{e.severity.upper()}] {e.title}")
        else:
            lines.append("None.")

        # 5. Coverage
        lines.append("\n## Coverage")
        area_names = (
            ", ".join(a.name for a in analyzed_areas)
            if analyzed_areas else "none"
        )
        gap_names = (
            ", ".join(a.name for a in uncovered)
            if uncovered else "none"
        )
        lines.append(
            f"Areas analyzed: {area_names} "
            f"({len(analyzed_areas)}/{total_areas})"
        )
        lines.append(f"Gaps: {gap_names}")
        if func_total > 0:
            lines.append(
                f"Functions: {func_count}/{func_total} "
                f"({func_count / func_total:.1%} deeply analyzed)"
            )
        elif func_count > 0:
            lines.append(f"Functions: {func_count} deeply analyzed")

        return "\n".join(lines)

    # ──────────────────────────────────────────────────────────────────────
    # Result merging
    # ──────────────────────────────────────────────────────────────────────

    def _merge_results(self, result: AgentResult):
        """Merge worker results into the blackboard.

        - Function analyses → FunctionRegistry
        - New leads → LeadTracker
        - Coverage is auto-updated by ToolExecutor during execution

        This method also parses lightweight structured data from the
        AgentResult's metadata fields (populated by the orchestrator or
        future worker post-processing).
        """
        # Merge explicit function analyses
        for fa_dict in result.function_analyses:
            try:
                fa = FunctionAnalysis(**fa_dict) if isinstance(fa_dict, dict) else fa_dict
                self.blackboard.register_function(fa)
            except Exception as e:
                self.logger.debug(f"Skipping malformed function analysis: {e}")

        # Merge explicit leads
        for lead_dict in result.new_leads:
            try:
                desc = lead_dict.get("description", str(lead_dict))
                priority = lead_dict.get("priority", "MEDIUM")
                address = lead_dict.get("address")
                self.blackboard.add_lead(desc, priority, address)
            except Exception as e:
                self.logger.debug(f"Skipping malformed lead: {e}")

        # Auto-extract leads from tool execution results (heuristic)
        if result.exec_results:
            self._auto_extract_leads(result)

    def _auto_extract_leads(self, result: AgentResult):
        """Heuristic lead extraction from tool execution results.

        Looks for patterns in tool results that suggest follow-up investigation:
        - Cross-references to unanalyzed functions
        - Security-relevant API calls
        - Suspicious string patterns
        """
        if not result.exec_results:
            return

        for te in result.exec_results.tool_executions:
            if not te.success or te.tool_name == "<no_command>":
                continue

            result_text = te.result or ""

            # If xrefs returned, add unanalyzed targets as leads
            if te.tool_name in ("get_xrefs_to", "get_xrefs_from", "get_function_xrefs"):
                # Look for function addresses in result
                addresses = re.findall(r"(?:0x)?([0-9a-fA-F]{6,})", result_text)
                for addr in addresses[:5]:
                    if not self.blackboard.is_function_analyzed(addr):
                        self.blackboard.add_lead(
                            f"Unanalyzed xref target: {addr} (from {te.tool_name})",
                            priority="LOW",
                            address=addr,
                        )

    # ──────────────────────────────────────────────────────────────────────
    # Synthesis failure detection
    # ──────────────────────────────────────────────────────────────────────

    # Minimum decompiled functions before triggering synthesis failure
    _SYNTH_FAILURE_MIN_DECOMPS = 3

    def _check_synthesis_failure(
        self,
        summary: WorkerResultSummary,
        result: AgentResult,
        cycle: int,
    ) -> None:
        """Detect workers that analyzed many functions but produced no findings.

        When a worker decompiles 3+ functions but the notebook didn't grow,
        it indicates a synthesis failure — the LLM saw the code but couldn't
        identify or articulate findings.  This adds a high-priority lead
        directing the next cycle to re-examine those functions with an
        explicit analysis focus.
        """
        if len(summary.functions_decompiled) < self._SYNTH_FAILURE_MIN_DECOMPS:
            return

        # Count notebook entries that were added during this cycle's
        # _update_notebook() call.  We check this by comparing the
        # current notebook size to what it was before.
        # Since we don't track exact pre-cycle size, check if any
        # notebook entry has an address matching what we decompiled.
        decompiled_set = set(summary.functions_decompiled)
        found_entries = [
            e for e in self.blackboard.notebook.entries
            if any(addr in decompiled_set for addr in e.addresses)
        ]

        # Also check if the result itself carried notebook entries
        result_had_entries = bool(result.notebook_entries)

        if found_entries or result_had_entries:
            return  # Findings were produced — no failure

        # Synthesis failure detected
        funcs_str = ", ".join(summary.functions_decompiled[:5])
        self.logger.warning(
            f"Synthesis failure in cycle {cycle}: decompiled "
            f"{len(summary.functions_decompiled)} functions "
            f"({funcs_str}) but produced 0 findings"
        )
        self.emitter.emit_cot(
            "Orchestrator",
            f"⚠ Synthesis failure: {len(summary.functions_decompiled)} "
            f"functions decompiled with 0 findings — adding re-analysis lead",
        )

        # Add a high-priority lead for re-examination with explicit focus
        self.blackboard.add_lead(
            f"SYNTHESIS RETRY: Re-examine functions {funcs_str} — "
            f"previous analysis (cycle {cycle}) decompiled "
            f"{len(summary.functions_decompiled)} functions but found "
            f"nothing.  Focus on: parameter validation, unsafe API usage, "
            f"unquoted paths, buffer handling, NULL pointer issues.",
            priority="HIGH",
            address=summary.functions_decompiled[0] if summary.functions_decompiled else None,
        )

    # ──────────────────────────────────────────────────────────────────────
    # Worker result memory
    # ──────────────────────────────────────────────────────────────────────

    def _build_worker_summary(
        self, cycle: int, task: WorkerTask, result: AgentResult
    ) -> WorkerResultSummary:
        """Extract a compact summary from a worker result for orchestrator memory.

        Called after each worker completes. The accumulated summaries are
        injected into the next task-creation LLM call so the orchestrator
        knows what has already been done and avoids duplicate work.
        """
        functions_decompiled: List[str] = []
        tools_used: Dict[str, int] = {}

        if result.exec_results:
            for te in result.exec_results.tool_executions:
                if te.tool_name == "<no_command>" or not te.success:
                    continue
                tools_used[te.tool_name] = tools_used.get(te.tool_name, 0) + 1
                if te.tool_name in (
                    "decompile_function",
                    "decompile_function_by_address",
                ):
                    addr = te.parameters.get(
                        "address", te.parameters.get("name", "unknown")
                    )
                    functions_decompiled.append(str(addr))

        return WorkerResultSummary(
            cycle=cycle,
            goal=task.goal[:120],
            functions_decompiled=functions_decompiled,
            tools_used=tools_used,
            key_findings=(
                result.findings_summary[:600]
                if result.findings_summary
                else "No findings"
            ),
            exit_reason=result.exit_reason or "unknown",
        )

    def _format_worker_history_prompt(
        self,
        summaries: List[WorkerResultSummary],
        max_show: int = 8,
    ) -> str:
        """Format accumulated worker history for the task-creation LLM prompt.

        Produces a compact, structured summary of what each previous worker
        did — functions decompiled, tools used, findings, and exit reason.
        The task-creation LLM uses this to avoid assigning duplicate work.
        """
        if not summaries:
            return ""
        lines = ["## Worker History (previous cycles)"]
        for ws in summaries[-max_show:]:
            decomp = (
                ", ".join(ws.functions_decompiled[:5])
                if ws.functions_decompiled
                else "none"
            )
            top_tools = ", ".join(
                f"{t}\u00d7{c}"
                for t, c in sorted(
                    ws.tools_used.items(), key=lambda x: -x[1]
                )[:4]
            )
            lines.append(
                f"- **Cycle {ws.cycle}**: {ws.goal}\n"
                f"  Functions decompiled: {decomp} | Tools: {top_tools}\n"
                f"  Result: {ws.key_findings} ({ws.exit_reason})"
            )
        lines.append(
            "\n**IMPORTANT**: Do NOT assign tasks that repeat work already done above. "
            "Do NOT re-decompile functions already listed. Focus on UNANALYZED "
            "functions and UNCOVERED areas."
        )
        return "\n".join(lines)

    # ──────────────────────────────────────────────────────────────────────
    # Vulnerability correlation engine
    # ──────────────────────────────────────────────────────────────────────

    def _check_correlations(self) -> Optional[WorkerTask]:
        """Check vulnerability correlation hooks against current investigation state.

        Collects all APIs seen across analyzed functions and coverage-encountered
        areas, then delegates to the hook registry.  If a hook fires, returns a
        mandatory ``WorkerTask``; otherwise returns ``None``.

        Called after each worker completes and results are merged into the
        blackboard.  Only one hook fires per check (first match wins).
        """
        fn_registry = self.blackboard.function_registry
        coverage = self.blackboard.coverage

        # Collect all APIs seen across all analyzed functions
        all_apis: Set[str] = set()
        for fa in fn_registry.functions.values():
            all_apis.update(api.lower() for api in fa.imports_used)

        # Also include APIs from coverage-encountered/analyzed areas
        for area in coverage.areas.values():
            if area.depth in (DEPTH_ENCOUNTERED, DEPTH_ANALYZED):
                all_apis.update(api.lower() for api in area.apis)

        task = self._hook_registry.check_all(
            all_apis, coverage, fn_registry, self.blackboard.discovery_cache
        )
        if task is not None:
            rule_name = (task.metadata or {}).get("correlation_rule", "unknown")
            self.emitter.emit_cot(
                "Orchestrator",
                f"Correlation hook fired: {rule_name} — "
                f"spawning targeted investigation task",
            )
        return task

    def _batch_fire_correlations(self) -> List[WorkerTask]:
        """Fire ALL matching correlation hooks at once.

        Called once after the recon phase to collect every applicable
        vulnerability-pattern task.  Returns a (possibly empty) list
        of ``WorkerTask`` objects.
        """
        fn_registry = self.blackboard.function_registry
        coverage = self.blackboard.coverage

        all_apis: Set[str] = set()
        for fa in fn_registry.functions.values():
            all_apis.update(api.lower() for api in fa.imports_used)
        for area in coverage.areas.values():
            if area.depth in (DEPTH_ENCOUNTERED, DEPTH_ANALYZED):
                all_apis.update(api.lower() for api in area.apis)

        tasks = self._hook_registry.check_all_batch(
            all_apis, coverage, fn_registry, self.blackboard.discovery_cache
        )
        for t in tasks:
            rule_name = (t.metadata or {}).get("correlation_rule", "unknown")
            self._inv_logger.log_correlation_fired(
                rule_name=rule_name, task_goal=t.goal,
            )
        return tasks

    # ──────────────────────────────────────────────────────────────────────
    # Dynamic loop helpers
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def _ensure_discovery_section(sections: List[str]) -> List[str]:
        """Ensure 'discovery' is always in include_sections.

        The LLM may omit it from the task JSON. Discovery data (cached imports,
        exports, strings) must always be visible to workers.
        """
        if "discovery" not in sections:
            sections.append("discovery")
        return sections

    def _is_coverage_stalled(
        self,
        coverage_history: List[float],
        findings_history: Optional[List[int]] = None,
    ) -> bool:
        """Check if coverage has not improved for N consecutive cycles.

        Returns ``True`` if the last ``coverage_stall_threshold`` coverage
        values are all within 1% of the value before that window **and**
        no new findings were produced during that window.

        If findings are still being added (notebook growing), the
        investigation is making qualitative progress even if the coverage
        ratio hasn't changed — e.g., deep-diving a single complex function.
        """
        n = self.coverage_stall_threshold
        if len(coverage_history) < n + 1:
            return False
        baseline = coverage_history[-(n + 1)]
        coverage_flat = all(
            abs(coverage_history[-(i + 1)] - baseline) < 0.01
            for i in range(n)
        )
        if not coverage_flat:
            return False

        # Coverage is flat — but are we still producing findings?
        if findings_history and len(findings_history) >= n + 1:
            baseline_findings = findings_history[-(n + 1)]
            current_findings = findings_history[-1]
            if current_findings > baseline_findings:
                # Findings still growing despite flat coverage — not stalled
                return False

        return True

    @staticmethod
    def _is_diminishing_returns(
        findings_history: List[int],
        window: int = 3,
    ) -> bool:
        """Check if the investigation has stopped producing new findings.

        Returns ``True`` if the last *window* cycles added zero new notebook
        entries.  This catches the case where coverage stall doesn't trigger
        (e.g., new areas get marked "encountered" but no actual findings
        emerge) — the exact problem seen in 14-cycle over-runs.
        """
        if len(findings_history) < window + 1:
            return False
        baseline = findings_history[-(window + 1)]
        return all(
            findings_history[-(i + 1)] == baseline
            for i in range(window)
        )

    @staticmethod
    def _extract_goal_keywords(goal: str) -> Set[str]:
        """Extract meaningful keywords from a goal string.

        Removes common English stop words and RE-specific filler verbs so
        that rephrased goals ("Analyze recv callers" vs "Investigate recv
        call sites") produce similar keyword sets.
        """
        words = set(re.findall(r'[a-z0-9_]+', goal.lower()))
        return words - _GOAL_STOP_WORDS

    @staticmethod
    def _extract_goal_addresses(goal: str) -> Set[str]:
        """Extract hex addresses from a goal string."""
        return set(re.findall(r'(?:0x)?[0-9a-fA-F]{6,}', goal.lower()))

    def _is_orchestrator_doom_loop(
        self, current_goal: str, recent_goals: List[str]
    ) -> bool:
        """Check if the orchestrator is generating semantically similar tasks.

        Uses Jaccard similarity on keywords (after removing stop words and
        RE-specific filler verbs).  Threshold: 0.5 overlap = same task.
        Also checks for repeated target addresses across recent goals.

        Returns ``True`` only if ALL recent goals within the doom_loop_threshold
        window are similar to the current goal.
        """
        if len(recent_goals) < self.doom_loop_threshold:
            return False

        current_kw = self._extract_goal_keywords(current_goal)
        if not current_kw:
            return False

        last_n = recent_goals[-self.doom_loop_threshold:]

        # Check 1: Keyword similarity (Jaccard)
        keyword_doom = True
        for prev_goal in last_n:
            prev_kw = self._extract_goal_keywords(prev_goal)
            if not prev_kw:
                keyword_doom = False
                break
            intersection = current_kw & prev_kw
            union = current_kw | prev_kw
            similarity = len(intersection) / len(union) if union else 0.0
            if similarity < 0.5:
                keyword_doom = False
                break

        if keyword_doom:
            return True

        # Check 2: Address-based repetition (same addresses in ALL recent goals)
        current_addrs = self._extract_goal_addresses(current_goal)
        if current_addrs and len(current_addrs) <= 3:
            for prev_goal in last_n:
                prev_addrs = self._extract_goal_addresses(prev_goal)
                if current_addrs != prev_addrs:
                    break
            else:
                return True  # All recent goals target the same addresses

        # Check 3: API-name overlap — catches rephrased goals that target
        # the same Windows APIs (e.g., "Trace callers of CreateProcessW"
        # vs "Analyze CreateProcessW callers for unquoted paths").
        api_pattern = re.compile(
            r'\b([A-Z][a-z]+(?:[A-Z][a-z]*)+[WA]?)\b'  # PascalCase API names
        )
        current_apis = set(api_pattern.findall(current_goal))
        if current_apis and len(current_apis) <= 6:
            api_doom = True
            for prev_goal in last_n:
                prev_apis = set(api_pattern.findall(prev_goal))
                if not prev_apis:
                    api_doom = False
                    break
                overlap = len(current_apis & prev_apis) / max(
                    len(current_apis | prev_apis), 1
                )
                if overlap < 0.4:
                    api_doom = False
                    break
            if api_doom:
                return True

        return False

    # ──────────────────────────────────────────────────────────────────────
    # System prompts
    # ──────────────────────────────────────────────────────────────────────

    def _get_task_creation_system_prompt(self, strategy: str) -> str:
        """Return the system prompt for the task-creation LLM call.

        If ``config.orchestrator_system_prompt`` is set, it is used as-is
        (after {strategy} substitution).  Otherwise the built-in detailed
        prompt is used.

        This is a detailed prompt that teaches the orchestrator LLM how to:
        - Read blackboard state (coverage, leads, function registry, notebook)
        - Create focused, well-scoped tasks
        - Choose appropriate include_sections for context filtering
        - Decide when the investigation is complete
        """
        # Allow config override
        custom = getattr(self.config, "orchestrator_system_prompt", "")
        if custom:
            return custom.replace("{strategy}", strategy)

        strategy_guidance = self._get_strategy_guidance(strategy)

        return (
            "You are an expert reverse engineering investigation planner. "
            "You direct an investigation by creating focused tasks for worker agents "
            "that have access to Ghidra reverse engineering tools.\n\n"

            "## Your Role\n"
            "You do NOT execute tools yourself. You analyze the current investigation "
            "state and decide the single most valuable next task for a worker to execute. "
            "Each worker gets ONE task with a specific goal and returns findings.\n\n"

            f"## Investigation Strategy: {strategy}\n"
            f"{strategy_guidance}\n\n"

            "## How to Read the Investigation State\n"
            "The user message contains the current blackboard state:\n"
            "- **Coverage ratio**: Percentage of security-relevant areas investigated "
            "(0% = nothing explored, 100% = thorough)\n"
            "- **Uncovered areas**: Investigation areas not yet touched — prioritize these\n"
            "- **Functions analyzed**: Count of functions with rich analysis in the registry\n"
            "- **Security findings**: Functions with security-relevant observations\n"
            "- **Active leads**: Specific follow-up items from previous tasks — address HIGH-priority first\n"
            "- **Notebook entries**: Running findings from the investigation so far\n\n"

            "## Task Creation Guidelines\n"
            "1. **Be specific**: 'Decompile FUN_00405b60 and check CreateProcessW arguments' "
            "is better than 'Look at interesting functions'\n"
            "2. **One clear goal**: Each task should accomplish one thing well\n"
            "3. **5-10 tool steps**: Tasks should be achievable in 5-10 tool executions\n"
            "4. **Build on findings**: Reference specific addresses, function names, and "
            "patterns found in previous cycles\n"
            "5. **Avoid duplication**: Check the function registry — don't re-analyze functions "
            "that already have rich analysis\n"
            "6. **Follow the strategy progression**: Start with surface mapping, then "
            "caller tracing / behavioral analysis, then deep verification\n"
            "7. **Address leads**: HIGH-priority leads should be investigated before "
            "creating exploratory tasks\n\n"

            "## include_sections — Context Filtering\n"
            "Workers see only the blackboard sections you specify. Choose wisely:\n"
            "- **scope**: Binary metadata (imports, exports) — always useful for early tasks\n"
            "- **analysis_state**: What functions were decompiled/renamed — prevents duplicate work\n"
            "- **function_registry**: Rich analysis of previously-analyzed functions — "
            "essential for deep-dive tasks that build on prior findings\n"
            "- **knowledge**: Persistent findings (IOCs, vuln indicators) — useful for "
            "correlation tasks\n"
            "- **coverage**: Investigation coverage areas — useful for gap-filling tasks\n"
            "- **leads**: Active investigation leads — useful when task follows up on leads\n"
            "- **notebook**: Current findings summary — useful for synthesis-oriented tasks\n"
            "- **discovery**: Cached binary surface data (imports, exports, strings) from the "
            "recon phase — ALWAYS include this\n\n"
            "Note: 'discovery' MUST always be included in include_sections. It provides "
            "pre-cached binary surface data that prevents redundant tool calls.\n\n"
            "Early recon tasks need fewer sections (scope + analysis_state + discovery). "
            "Deep analysis tasks need more (function_registry + knowledge + leads + discovery).\n\n"

            "## Task Sizing\n"
            "Each worker task should be achievable in **5-8 actual tool calls**. "
            "If a goal requires more, split it into multiple tasks across cycles.\n"
            "BAD: 'Identify all security-critical API imports and search for strings "
            "and trace all callers' (too broad, will exhaust budget)\n"
            "GOOD: 'Trace callers of CreateProcessW — decompile each and check for "
            "NULL lpApplicationName' (focused, 3-5 decompile calls)\n\n"

            "## Recipe Mode (Preferred for API Tracing)\n"
            "Workers support **deterministic recipes** that gather all relevant code "
            "automatically, then a single LLM call analyzes the full code. Recipes are "
            "more efficient and produce better results than letting the worker LLM "
            "select tools.\n\n"
            "Available recipes:\n"
            "- **trace_import_callers**: Traces imported API callers. "
            "Params: `{\"api_names\": [\"CreateProcessW\"], \"depth\": 1}`\n"
            "- **trace_string_refs**: Finds string references and decompiles referencing funcs. "
            "Params: `{\"patterns\": [\".exe\", \"cmd\"]}`\n"
            "- **deep_function_analysis**: Decompiles target + callers + callees. "
            "Params: `{\"addresses\": [\"0x00401000\"], \"depth\": 1}`\n"
            "- **surface_recon**: Gathers imports/exports/strings (used automatically in cycle 0). "
            "Params: `{\"string_filters\": [\".exe\", \"cmd\"]}`\n\n"
            "To use a recipe, include these fields in your JSON response:\n"
            "```\n"
            "\"recipe\": \"trace_import_callers\",\n"
            "\"recipe_params\": {\"api_names\": [\"CreateProcessW\"]},\n"
            "\"analysis_focus\": \"Check for NULL lpApplicationName with unquoted paths\"\n"
            "```\n\n"
            "Use recipes for ALL API-tracing tasks. Only use the default LLM loop for "
            "tasks that don't fit a recipe pattern (e.g., open-ended exploration).\n\n"

            "## When to Complete the Investigation\n"
            "Respond with INVESTIGATION COMPLETE when:\n"
            "- The strategy's completion criteria are met (see strategy section above)\n"
            "- Coverage ratio is high (> 70-80%) for the strategy-relevant areas\n"
            "- All HIGH-severity findings have been verified (confirmed or ruled out)\n"
            "- No HIGH-priority leads remain unresolved\n"
            "- Further cycles would yield diminishing returns\n\n"

            "## Response Format\n"
            "Either respond with 'INVESTIGATION COMPLETE' or a JSON task specification "
            "(see user message for the exact JSON schema)."
        )

    @staticmethod
    def _get_strategy_guidance(strategy: str) -> str:
        """Return strategy-specific guidance for the orchestrator's task creation.

        Each strategy template includes:
          - Investigation priorities and focus areas
          - Recommended task progression (initial → mid → deep)
          - Key APIs and patterns to target
          - Suggested tool usage per task type
          - Completion criteria
        """
        if strategy == STRATEGY_VULN_HUNTING:
            return STRATEGY_TEMPLATE_VULN_HUNTING
        elif strategy == STRATEGY_MALWARE_HUNTING:
            return STRATEGY_TEMPLATE_MALWARE_HUNTING
        else:  # binary_understanding
            return STRATEGY_TEMPLATE_BINARY_UNDERSTANDING

    @staticmethod
    def _get_notebook_update_system_prompt(strategy: str) -> str:
        """Return the system prompt for the notebook-update LLM call.

        Teaches the LLM how to:
        - Categorize findings correctly for the strategy
        - Assess severity accurately
        - Determine finding status (confirmed vs suspected)
        - Produce well-structured JSON entries
        """
        # Strategy-specific category guidance
        if strategy == STRATEGY_VULN_HUNTING:
            category_guidance = (
                "For vulnerability hunting, prefer these categories:\n"
                "- 'vulnerability': Confirmed or suspected security flaw "
                "(unquoted path, NULL lpApplicationName, DLL hijacking, injection)\n"
                "- 'architecture': Structural findings relevant to attack surface "
                "ONLY IF they identify a specific exploitable pattern or entry point\n\n"
                f"{SEVERITY_DEFINITIONS}\n"
                "IMPORTANT — DO NOT create entries for:\n"
                "- Merely listing which APIs are imported (e.g., 'binary imports "
                "GetWindowTextW') — this is surface-level reconnaissance, not a finding\n"
                "- Generic observations like 'uses CreateDirectoryW for file operations'\n"
                "- Restating tool output without security analysis\n"
                "- Findings with severity 'info' — if it's not at least 'low' severity, "
                "it does not belong in a vulnerability report\n"
                "- Seeing AdjustTokenPrivileges, OpenProcessToken, or "
                "LookupPrivilegeValue in decompiled code — these are NORMAL "
                "privilege adjustment patterns in Windows services, NOT vulnerabilities "
                "unless the adjusted privileges enable a specific exploit path you "
                "can describe with attacker-controlled input\n"
                "- Seeing LoadLibraryW/A/ExW in code — DLL hijacking requires a "
                "RELATIVE path (not absolute) AND the binary running from an "
                "attacker-writable directory. Simply calling LoadLibrary is not a "
                "vulnerability. Only report if the path is attacker-controllable\n"
                "- Multiple instances of the same pattern in different functions — "
                "consolidate into ONE entry (e.g., 3 functions calling LoadLibraryW "
                "is ONE finding about DLL loading, not three separate entries)\n\n"
                "DEDUPLICATION RULES:\n"
                "- Before adding an entry, check the current notebook for similar "
                "titles or the same API/pattern. If a similar entry exists, skip it\n"
                "- Same API in different functions = ONE entry covering all locations\n"
                "- Same vulnerability class (e.g., 'DLL hijacking') = ONE entry "
                "with all affected addresses in the evidence/addresses fields\n\n"
                "A valid vulnerability finding MUST have:\n"
                "- A specific function address where the issue occurs\n"
                "- Concrete evidence from decompiled code (parameter values, data flow)\n"
                "- An explanation of the EXPLOITABLE PATH: what input does the attacker "
                "control, how does it reach the dangerous API, and what is the impact?\n"
                "- If you cannot describe attacker-controlled input reaching the "
                "dangerous sink, the finding is NOT a vulnerability — skip it"
            )
        elif strategy == STRATEGY_MALWARE_HUNTING:
            category_guidance = (
                "For malware hunting, prefer these categories:\n"
                "- 'ioc': Indicators of compromise (IPs, URLs, domains, file paths, "
                "registry keys, mutexes, encoded strings)\n"
                "- 'behavior': Malicious behavior patterns (injection, persistence, "
                "evasion, C2 communication)\n"
                "- 'threat': Threat assessment (malware family, capability, sophistication)\n"
                "- 'architecture': Binary structure relevant to malware analysis "
                "(packing, obfuscation, anti-debug)\n"
                "- 'info': Contextual information (import summary, benign functionality)\n\n"
                "Severity for malware findings:\n"
                "- critical: Active C2 communication or destructive capability confirmed\n"
                "- high: Process injection, persistence, or credential theft confirmed\n"
                "- medium: Suspicious behavior (anti-debug, obfuscation) that suggests malice\n"
                "- low: Weak indicator, could be benign (e.g., a single network API import)\n"
                "- info: Contextual information about the binary"
            )
        else:  # binary_understanding
            category_guidance = (
                "For binary understanding, prefer these categories:\n"
                "- 'architecture': Major structural findings (subsystems, data flow, "
                "entry points, initialization sequence)\n"
                "- 'behavior': Behavioral findings (what the binary does at runtime)\n"
                "- 'info': General observations (import categories, string patterns)\n"
                "- 'vulnerability': Only if genuine security concerns are found during analysis\n\n"
                "Severity for binary understanding:\n"
                "- high: Core finding about primary purpose or major subsystem\n"
                "- medium: Secondary subsystem or notable pattern\n"
                "- low: Minor detail or peripheral observation\n"
                "- info: Metadata or structural observation"
            )

        return (
            "You are a reverse engineering analyst updating an investigation notebook "
            "with structured findings from a worker agent's task execution.\n\n"

            "## Your Task\n"
            "Given the worker's findings and tool execution results, produce new notebook "
            "entries as a JSON array. Each entry captures ONE distinct finding.\n\n"

            "## Entry Schema\n"
            "Each entry MUST have these fields:\n"
            "- **category**: Type of finding (see strategy-specific guidance below)\n"
            "- **severity**: Impact level: 'critical', 'high', 'medium', 'low', or 'info'\n"
            "- **title**: Short descriptive title (max 80 chars) — be specific, not vague\n"
            "- **detail**: Full description (2-4 sentences). Include: what was found, "
            "where (function name + address), why it matters\n"
            "- **evidence**: List of specific evidence strings — function names, addresses, "
            "API calls, parameter values, decompiled code snippets\n"
            "- **addresses**: List of hex addresses related to this finding (e.g., ['0x00405b60'])\n"
            "- **status**: Confidence level:\n"
            "  - 'confirmed': Directly verified through decompilation or trace\n"
            "  - 'suspected': Strong indicators but not fully verified\n"
            "  - 'needs_investigation': Flagged for follow-up\n\n"

            f"## Strategy: {strategy}\n"
            f"{category_guidance}\n\n"

            "## Quality Guidelines\n"
            "- Only add entries for NEW findings not already in the notebook\n"
            "- Be specific in titles: 'CreateProcessW called with NULL lpApplicationName "
            "at 0x00405b60' not 'Possible vulnerability found'\n"
            "- Include concrete evidence: function names, addresses, API parameters\n"
            "- If the worker found nothing significant, return an empty array: []\n"
            "  Returning [] is PREFERRED over creating low-quality noise entries\n"
            "- Don't duplicate entries — check the current notebook first\n"
            "- One finding per entry — don't combine unrelated findings\n"
            "- QUALITY OVER QUANTITY: 1 high-quality vulnerability finding is worth "
            "more than 10 surface-level import observations. When in doubt, "
            "skip the entry rather than dilute the report with noise.\n"
            "- MAXIMUM 3 entries per update. If the worker touched many functions, "
            "pick only the top 3 most security-relevant findings. The rest can be "
            "investigated in future cycles.\n"
            "- For vuln_hunting: if none of the findings have a concrete exploit "
            "path with attacker-controlled input, return []. This is STRONGLY "
            "preferred over padding the notebook with noise.\n\n"

            "## Response Format\n"
            "Return ONLY a JSON array. No explanation, no markdown. Example:\n"
            "[{\"category\": \"vulnerability\", \"severity\": \"high\", "
            "\"title\": \"Unquoted service path in CreateProcessW\", "
            "\"detail\": \"FUN_00405b60 calls CreateProcessW with lpApplicationName=NULL "
            "and lpCommandLine from registry without quotes\", "
            "\"evidence\": [\"FUN_00405b60\", \"CreateProcessW\", \"lpApplicationName=NULL\"], "
            "\"addresses\": [\"0x00405b60\"], \"status\": \"confirmed\"}]"
        )
