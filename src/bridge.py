#!/usr/bin/env python3
"""
Ollama-GhidraMCP Bridge
-----------------------
This application acts as a bridge between a locally hosted Ollama AI model
and GhidraMCP, enabling AI-assisted reverse engineering tasks within Ghidra.
"""

import argparse
import json
import logging
import sys
import os
import re
from typing import Dict, Any, Iterable, List, Mapping, Optional, Sequence, Tuple

from src.config import DEFAULT_SYSTEM_PROMPT, BridgeConfig
from src.ollama_client import OllamaClient
from src.external_client import ExternalClient
from src.custom_api_client import CustomAPIClient
from src.ghidra_client import GhidraMCPClient, AbstractGhidraClient, PyGhidraClient
from src.command_parser import CommandParser
from src.models.memory import (
    SessionMemory,
    MessageRole,
    CAGContext,
    StructuredPrompt,
    ExecutionPhaseResults,
    ToolExecution,
    ExecutionSignal,
    ExecutionGate,
)
from src.execution_gate import ExecutionGatekeeper
from src.user_question import UserQuestion
from src.session_compactor import SessionCompactor
from src.context_manager import ContextManager
from src.analysis_dump import AnalysisDumper
from src.coverage_tracker import CoverageTracker
from src.lead_tracker import LeadTracker
from src.agent.plugins import AnalysisPlugin, FunctionRAGPlugin, PluginContext, PluginHook, PluginManager
from src.agent.program import DSPyCompletionClient, OGhidraAgent, OGhidraDSPyProgram
from datetime import datetime


# Configure logging
def setup_logging(config):
    """Set up logging configuration."""
    handlers = []

    if config.log_console:
        handlers.append(logging.StreamHandler(sys.stdout))

    if config.log_file_enabled:
        handlers.append(logging.FileHandler(config.log_file))

    logging.basicConfig(
        level=getattr(logging, config.log_level),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=handlers,
    )

    return logging.getLogger("ollama-ghidra-bridge")


def select_ghidra_client_class(
    config: BridgeConfig,
) -> tuple[type[AbstractGhidraClient], str]:
    """Return the configured Ghidra backend class and a short label."""
    backend = getattr(config.ghidra, "backend", "http")
    if backend == "pyghidra":
        if PyGhidraClient is None:
            raise RuntimeError(
                "Ghidra backend 'pyghidra' selected but PyGhidraClient is not available. "
                "Ensure pyghidra is installed and importable."
            )
        return PyGhidraClient, "pyGhidra"

    return GhidraMCPClient, "HTTP GhidraMCP"


class Bridge:
    """Main bridge class that connects Ollama with GhidraMCP."""

    _ollama_client = None

    def __init__(
        self,
        config: BridgeConfig,
        include_capabilities: bool = False,
        enable_cag: bool = True,
        plugins: Optional[Iterable[AnalysisPlugin]] = None,
    ):
        """Initialize the bridge with configuration."""
        self.config = config
        self.logger = logging.getLogger("ollama-ghidra-bridge")

        # Select LLM Provider and Config
        self.provider = getattr(config, "llm_provider", "ollama")

        # Handle 'google' alias for backward compatibility
        if self.provider == "google":
            self.provider = "external"

        if self.provider == "external":
            self.llm_config = config.external
            self.ollama = ExternalClient(config=self.llm_config)
            self.logger.info(f"Using External Provider ({self.llm_config.provider}) as LLM")
        elif self.provider == "custom_api":
            self.llm_config = config.custom_api
            self.ollama = CustomAPIClient(config=self.llm_config)
            self.logger.info("Using Custom API as LLM provider")
        else:
            self.llm_config = config.ollama
            self.ollama = OllamaClient(config=self.llm_config)
            self.logger.info("Using Ollama as LLM provider")

        # DSPy owns all language-model reasoning. The provider client is kept
        # underneath the adapter for embeddings, health checks, and existing
        # authentication/retry behavior.
        self.raw_llm_client = self.ollama
        self.dspy_program = OGhidraDSPyProgram(self.raw_llm_client)
        self.ollama = DSPyCompletionClient(self.raw_llm_client, self.dspy_program)

        # Extension lifecycle. Installed packages may contribute plugins via
        # the ``oghidra.plugins`` entry-point group.
        self.plugin_manager = PluginManager(plugins=plugins, logger=self.logger)
        if not any(plugin.name == FunctionRAGPlugin.name for plugin in self.plugin_manager.plugins):
            self.plugin_manager.register(FunctionRAGPlugin())
        self.plugin_manager.discover()
        self._active_plugin_context = None

        # Select Ghidra backend class based on configuration. Default is HTTP
        # GhidraMCP server; "pyghidra" uses an in-process pyGhidra client.
        ghidra_cls, backend_label = select_ghidra_client_class(config)
        self.logger.info("Using %s backend for Ghidra integration", backend_label)

        self.ghidra_client = ghidra_cls(config=config.ghidra, ollama_client=self.ollama)

        # Set Ollama client for embeddings
        Bridge.set_ollama_client(self.ollama)

        # Command parser for extracting tool calls
        self.command_parser = CommandParser()

        # Session memory (Pydantic-based structured storage)
        session_id = f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.session = SessionMemory(session_id=session_id)

        # Tool capabilities
        self.include_capabilities = include_capabilities
        self.capabilities_text = None
        if include_capabilities:
            self.capabilities_text = self._load_capabilities_text()

        # CAG Configuration
        self.enable_cag = enable_cag
        self.cag_manager = None

        # Memory/knowledge manager
        self.memory_manager = None

        # Context manager for intelligent result handling
        # All size limits come from config (scales with CONTEXT_BUDGET)
        self.context_manager = ContextManager(
            ollama_client=self.ollama,
            context_budget=self.llm_config.context_budget,
            execution_fraction=self.llm_config.context_budget_execution,
            enable_summarization=self.llm_config.enable_result_summarization,
            enable_caching=self.llm_config.result_cache_enabled,
            enable_tiered_context=self.llm_config.tiered_context_enabled,
            max_detailed_steps=getattr(self.llm_config, "max_detailed_steps", 10),
            current_loop_max_chars=getattr(self.llm_config, "current_loop_max_chars", 4000),
            prev_loop_max_chars=getattr(self.llm_config, "prev_loop_max_chars", 800),
            older_loop_max_chars=getattr(self.llm_config, "older_loop_max_chars", 200),
        )

        # Deterministic compaction for prompt stability (reduces 429/504)
        try:
            from src.result_compactor import ResultCompactor, CompactionConfig

            max_chars = int(getattr(self.llm_config, "compaction_max_chars", 2000))
            self.result_compactor = ResultCompactor(CompactionConfig(max_chars=max_chars))
        except Exception:
            self.result_compactor = None

        # Analysis dumper for capturing raw context before truncation
        self.analysis_dumper = AnalysisDumper()

        if self.enable_cag:
            try:
                from .cag import CAGManager

                self.cag_manager = CAGManager(config, session=self.session)
                # Set bridge reference for cache stats
                self.cag_manager._bridge_ref = self
                # Memory manager is part of CAG manager
                self.memory_manager = self.cag_manager.memory_manager if hasattr(self.cag_manager, "memory_manager") else None

            except ImportError as e:
                self.logger.warning(f"CAG dependencies not available: {e}. Running without CAG.")
                self.enable_cag = False
            except ImportError as e:
                self.logger.warning(f"CAG dependencies not available: {e}. Running without CAG.")
                self.enable_cag = False

        # Mutable compatibility view used by the existing GUI panels. Values
        # point at the structured session's collections.
        self.analysis_state = {
            "functions_decompiled": self.session.analysis_state.functions_decompiled,
            "functions_renamed": self.session.analysis_state.functions_renamed,
            "comments_added": self.session.analysis_state.comments_added,
            "functions_analyzed": self.session.analysis_state.functions_analyzed,
            "cached_results": self.session.analysis_state.cached_results,
        }

        # Enhanced function tracking with address mapping
        self.function_address_mapping = {}

        # Store function analysis summaries
        self.function_summaries = {}

        # KNOWLEDGE GRAPH: Track function relationships for architectural understanding
        self.function_graph = None
        try:
            from src.function_graph import FunctionGraph

            self.function_graph = FunctionGraph()
            self.logger.info("[OK] Knowledge Graph initialized for architectural analysis")
        except Exception as e:
            self.logger.warning(f"[WARN] Knowledge Graph initialization failed: {e}. Graph features disabled.")

        # Initialize caches and statistics
        self._init_caches()

        # Agent workflow state
        self.current_goal = None
        self.goal_achieved = False
        self.current_plan = ""
        self.executed_tools = set()  # Track (cmd_name:params_signature) to avoid duplicates
        self.step_result_map = {}  # Map cmd_signature -> (loop_step_id, result_excerpt)
        self.current_loop_number = 1  # Track current agentic loop/cycle number

        # Workflow stage tracking for UI integration
        self.current_workflow_stage = None  # Can be: 'planning', 'execution', 'analysis', 'review', None

        # Task mode controls how much guidance we inject.
        # Modes: off (no special mode), purpose_id, malware, vuln, custom
        self.task_mode_enabled = False
        self.task_mode = "off"

        # Grep layer (hybrid search) state
        self.grep_layer_enabled = False

        # Load sticky user preferences (custom mode notepad) from disk
        try:
            from src.user_prefs_store import load_user_prefs

            persisted = load_user_prefs()
            if isinstance(persisted, dict) and persisted:
                for k, v in persisted.items():
                    self.session.set_user_preference(k, v)

                # Also restore task mode state if present
                try:
                    self.task_mode_enabled = bool(persisted.get("task_mode_enabled", False))
                    self.task_mode = str(persisted.get("task_mode", "off") or "off")
                    self.grep_layer_enabled = bool(persisted.get("grep_layer_enabled", False))
                except Exception:
                    pass

                # Note: focus_function tracking was removed as it caused confusion during
                # cross-reference analysis. Users should explicitly query "current function"
                # when needed, which will call get_current_function() from Ghidra.
        except Exception:
            pass

        # UI callback for chain of thought updates (set by UI if present)
        self._ui_cot_callback = None

        # Interactive Execution Gate (OpenCode-inspired)
        self.execution_gate = ExecutionGatekeeper(self.llm_config)
        self._ui_gate_callback = None  # Set by UI for gate events

        self._ui_question_callback = None  # Set by UI for typed DSPy questions

        # Session Compactor - Smart context pruning (OpenCode-inspired)
        self.session_compactor = SessionCompactor(self.llm_config, self.ollama)

        # Coverage Tracker        # Initialize coverage tracker
        self.coverage_tracker = CoverageTracker()

        # Initialize lead tracker
        self.lead_tracker = LeadTracker()

        self.logger.info("Bridge initialized successfully")

        # The public query entry point is a DSPy module; bounded Python control
        # flow remains explicit and inspectable inside the module.
        self.agent = OGhidraAgent(self, self.plugin_manager)

    def reload_llm_client(self):
        """Re-initializes the LLM client based on current configuration."""
        self.logger.info("Reloading LLM client...")

        # Select LLM Provider and Config
        self.provider = getattr(self.config, "llm_provider", "ollama")

        # Handle 'google' alias for backward compatibility
        if self.provider == "google":
            self.provider = "external"

        if self.provider == "external":
            self.llm_config = self.config.external
            self.ollama = ExternalClient(config=self.llm_config)
            self.logger.info(f"Switched to External Provider: {self.llm_config.provider}")
        elif self.provider == "custom_api":
            self.llm_config = self.config.custom_api
            self.ollama = CustomAPIClient(config=self.llm_config)
            self.logger.info("Switched to Custom API Provider")
        else:
            self.llm_config = self.config.ollama
            self.ollama = OllamaClient(config=self.llm_config)

        self.raw_llm_client = self.ollama
        self.dspy_program = OGhidraDSPyProgram(self.raw_llm_client)
        self.ollama = DSPyCompletionClient(self.raw_llm_client, self.dspy_program)

        # Update dependencies
        if hasattr(self, "ghidra_client"):
            self.ghidra_client.ollama_client = self.ollama

        if hasattr(self, "context_manager"):
            self.context_manager.ollama_client = self.ollama
            # Update generic context settings if they changed
            self.context_manager.context_budget = self.llm_config.context_budget
            self.context_manager.execution_fraction = self.llm_config.context_budget_execution

        Bridge.set_ollama_client(self.ollama)
        print(f"[Bridge] Client reloaded. Provider: {self.provider}")

    def register_plugin(self, plugin: AnalysisPlugin) -> AnalysisPlugin:
        """Register a plugin for this Bridge instance."""
        return self.plugin_manager.register(plugin)

    def _run_plugin_hook(self, hook: PluginHook, **updates: Any) -> PluginContext:
        context = self._active_plugin_context or PluginContext(bridge=self, query=self.current_goal or "")
        for key, value in updates.items():
            if hasattr(context, key):
                setattr(context, key, value)
            else:
                context.data[key] = value
        return self.plugin_manager.run(hook, context)

    def prepare_functions_for_analysis(
        self, functions: Sequence[Any], metadata: Optional[Mapping[str, Any]] = None
    ) -> list[Any]:
        """Run pre-analysis phases and plugin-defined function ordering."""
        context = PluginContext(
            bridge=self,
            query=self.current_goal or "bulk function analysis",
            functions=list(functions),
            data=dict(metadata or {}),
        )
        self.plugin_manager.run(PluginHook.BEFORE_FUNCTION_ANALYSIS, context)
        return self.plugin_manager.order_functions(context.functions, context)

    def finalize_function_analysis(
        self,
        function_results: Sequence[Mapping[str, Any]],
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> PluginContext:
        """Run post-analysis phases such as whole-program RAG construction."""
        context = PluginContext(
            bridge=self,
            query=self.current_goal or "bulk function analysis",
            function_results=list(function_results),
            data=dict(metadata or {}),
        )
        return self.plugin_manager.run(PluginHook.AFTER_FUNCTION_ANALYSIS, context)

    def set_task_mode(self, enabled: bool, mode: str = "off") -> None:
        """Set task mode and persist it."""
        self.task_mode_enabled = bool(enabled)
        self.task_mode = mode or "off"
        try:
            self.session.set_user_preference("task_mode_enabled", self.task_mode_enabled)
            self.session.set_user_preference("task_mode", self.task_mode)

            # Log the change
            if self.task_mode_enabled:
                self.logger.info(f"Task mode enabled: {self.task_mode}")
            else:
                self.logger.info("Task mode disabled")
        except Exception as e:
            self.logger.warning(f"Could not persist task mode: {e}")

    def get_task_mode_state(self) -> dict:
        """Get the current task mode state."""
        return {
            "enabled": bool(getattr(self, "task_mode_enabled", False)),
            "mode": getattr(self, "task_mode", "off"),
        }

    def set_grep_layer_enabled(self, enabled: bool) -> None:
        """Enable or disable the hybrid search (grep layer) functionality."""
        self.grep_layer_enabled = bool(enabled)

        # Reload capabilities text to include/exclude search_function_summaries
        if self.include_capabilities:
            self.capabilities_text = self._load_capabilities_text()

        try:
            self.session.set_user_preference("grep_layer_enabled", self.grep_layer_enabled)

            # Log the change
            if self.grep_layer_enabled:
                self.logger.info("Hybrid search (grep layer) enabled - search_function_summaries available")
            else:
                self.logger.info("Hybrid search (grep layer) disabled - search_function_summaries hidden")
        except Exception as e:
            self.logger.warning(f"Could not persist grep layer state: {e}")

    def get_grep_layer_state(self) -> bool:
        """Get the current grep layer state."""
        return bool(getattr(self, "grep_layer_enabled", False))

    def _update_scope_from_query(self, query: str) -> None:
        """Best-effort scope anchoring to reduce goal drift across turns."""
        try:
            q = (query or "").lower()
            scope = "binary"
            if any(
                k in q
                for k in [
                    "current function",
                    "this function",
                    "the function",
                    "decompile",
                    "disassemble function",
                    "review function",
                ]
            ):
                scope = "function"
            if any(
                k in q
                for k in ["whole binary", "entire binary", "full binary", "whole program", "entire program", "all functions"]
            ):
                scope = "binary"

            self.session.set_user_preference("active_goal", (query or "").strip())
            self.session.set_user_preference("scope_lock", scope)
        except Exception:
            return

    def _build_scope_card(self) -> str:
        """Compact, authoritative session scope card injected into prompts.

        Note: focus_function tracking was removed. Users should explicitly ask about
        "the current function" when needed, which calls get_current_function() from Ghidra.
        """
        try:
            prefs = getattr(self.session, "user_preferences", {}) or {}
            active_goal = str(prefs.get("active_goal", "")).strip()
            scope_lock = str(prefs.get("scope_lock", "")).strip() or "binary"

            lines = ["## SESSION SCOPE (AUTHORITATIVE)"]
            if active_goal:
                lines.append(f"- active_goal: {active_goal}")
            lines.append(f"- scope_lock: {scope_lock}")
            lines.append("- rule: Do not broaden scope unless user explicitly requests")
            return "\n".join(lines)
        except Exception:
            return ""

    def _maybe_update_custom_workplan(self, user_query: str, final_response: str) -> None:
        """Update the custom-mode notepad/workplan after a query completes.

        This is intentionally small to avoid rate limiting and prompt bloat.
        """
        try:
            if not bool(getattr(self, "task_mode_enabled", False)):
                return
            if getattr(self, "task_mode", "off") != "custom":
                return

            existing = ""
            try:
                existing = str(self.session.user_preferences.get("custom_workplan", "")).strip()
            except Exception:
                existing = ""

            prompt = (
                "You maintain a short user-specific investigation notepad.\n"
                "Update the NOTEPAD based on the latest user query and the assistant's final response.\n\n"
                "Rules:\n"
                "- Keep it concise (max 12 bullets).\n"
                "- Prefer concrete preferences (tools to use, ordering, evidence standards, formatting).\n"
                "- Remove duplicates and outdated items.\n"
                "- Do NOT add generic advice.\n"
                "- Output ONLY the updated notepad as bullet points (no headings).\n\n"
                f"CURRENT NOTEPAD:\n{existing}\n\n"
                f"LATEST USER QUERY:\n{user_query}\n\n"
                f"LATEST ASSISTANT RESPONSE:\n{final_response[:2000]}\n"
            )

            updated = self.ollama.generate(
                prompt=prompt,
                system_prompt="You update a short notepad. Output ONLY bullet points.",
                phase="analysis",
                max_tokens=250,
            )

            updated = (updated or "").strip()
            if updated:
                self.session.set_user_preference("custom_workplan", updated)
                try:
                    from src.user_prefs_store import save_user_prefs

                    save_user_prefs(self.session.user_preferences)
                except Exception:
                    pass
        except Exception:
            return



    def _get_max_result_chars(self) -> int:
        """
        Calculate max result characters based on context budget from config.

        The limit scales proportionally with CONTEXT_BUDGET from .env:
        - Baseline: 10% of total execution character budget
        - Dynamic: 25% of remaining execution budget (if higher than baseline)
        - Minimum: 5000 chars to ensure basic functionality
        - Fallback: 10000 chars when context_manager not available

        Returns:
            Maximum number of characters allowed for a single result.
        """
        if self.context_manager and hasattr(self.context_manager, "budget"):
            budget = self.context_manager.budget
            # Total execution chars = execution_budget * chars_per_token
            total_exec_chars = budget.execution_budget * int(budget.chars_per_token)
            # Baseline: 10% of total execution budget (scales with context window)
            baseline_limit = max(5000, total_exec_chars // 10)

            # Dynamic: 25% of remaining execution budget
            remaining = budget.get_remaining_execution_chars()
            dynamic_limit = max(baseline_limit, remaining // 4)

            return dynamic_limit
        else:
            # Fallback when context_manager not available
            return 10000

    @classmethod
    def get_embeddings(cls, texts: List[str], model: str = None) -> List[List[float]]:
        """Get embeddings using the configured LLM client's embedding service (Ollama or External)."""
        logger = logging.getLogger("ollama-ghidra-bridge")

        if not hasattr(cls, "_ollama_client") or cls._ollama_client is None:
            logger.debug("LLM client not initialized. Embeddings unavailable.")
            return []

        # Filter out empty/None texts which cause 400 errors
        valid_texts = []
        for text in texts:
            if text and isinstance(text, str) and text.strip():
                valid_texts.append(text.strip())
            else:
                logger.warning(f"Skipping invalid text for embedding: {repr(text)[:50]}")

        if not valid_texts:
            logger.warning("No valid texts to embed after filtering")
            return []

        # Use provided model or default from client config
        # Use nomic-embed-text as default if config doesn't have it
        client_config = getattr(cls._ollama_client, "config", None)
        embedding_model = model or getattr(client_config, "embedding_model", "nomic-embed-text")

        try:
            embeddings = []
            for text in valid_texts:
                embedding = cls._ollama_client.embed(text, model=embedding_model)
                if embedding:
                    embeddings.append(embedding)
                else:
                    logger.debug(f"Failed to generate embedding for text: {text[:50]}...")
                    return []  # Return empty if any embedding fails

            provider_name = getattr(cls._ollama_client, "provider", "Ollama")
            logger.debug(f"✅ Generated {len(embeddings)} embeddings using {provider_name} {embedding_model}")
            return embeddings
        except Exception as e:
            logger.error(f"Failed to generate embeddings: {e}")
            return []

    @classmethod
    def set_ollama_client(cls, ollama_client):
        """Set the Ollama client for embeddings."""
        cls._ollama_client = ollama_client

    def _init_caches(self):
        """Initialize decompilation and function caches."""
        # Enhanced decompilation cache with multiple cache keys
        self.decompilation_cache = {}  # function_name -> result
        self.function_cache = {}  # address -> function_data
        self.cache_stats = {"hits": 0, "misses": 0, "cache_size": 0}

    def _emit_cot(self, update_type: str, content: str, also_print: bool = True):
        """Emit a chain of thought update to both terminal and UI.

        This method provides live visibility into the AI agent's reasoning
        during the agentic loop, mirroring output to both console and UI.

        Args:
            update_type: Type of update ('Cycle', 'Phase', 'Reasoning', 'Tool', 'Status')
            content: The update content to display
            also_print: Whether to also print to terminal (default True)
        """
        if also_print:
            if update_type.upper() == "REASONING":
                pass  # Don't double print reasoning as it's often long
            else:
                print(f"[{update_type}] {content}")

        # Send to UI callback if registered
        if self._ui_cot_callback:
            self._ui_cot_callback(update_type, content)

    def _emit_gate(self, gate: ExecutionGate):
        """Emit a gate event to terminal and UI."""
        self._emit_cot("Gate", f"\u26a0\ufe0f EXECUTION PAUSED: {gate.reason} [trigger={gate.trigger}]")
        if self._ui_gate_callback:
            self._ui_gate_callback(gate)

    def _load_capabilities_text(self) -> Optional[str]:
        """Load the capabilities text from the file if the flag is set."""
        if not self.include_capabilities:
            return None

        capabilities_file = "ai_ghidra_capabilities.txt"
        capabilities_content = None

        try:
            # Assuming the script is run from the project root
            file_path = os.path.join(os.path.dirname(__file__), "..", capabilities_file)
            if os.path.exists(file_path):
                with open(file_path, "r", encoding="utf-8") as f:
                    capabilities_content = f.read()
            else:
                # Try reading from the current working directory as a fallback
                if os.path.exists(capabilities_file):
                    with open(capabilities_file, "r", encoding="utf-8") as f:
                        capabilities_content = f.read()
                else:
                    self.logger.warning(f"Capabilities file '{capabilities_file}' not found.")
                    return None
        except Exception as e:
            self.logger.error(f"Error reading capabilities file '{capabilities_file}': {str(e)}")
            return None

        # Conditionally add search_function_summaries when Hybrid Search is enabled
        if capabilities_content and getattr(self, "grep_layer_enabled", False):
            # Find the "Context Management:" section and add search_function_summaries
            search_func_desc = (
                "- search_function_summaries(query, search_type, top_k): Search analyzed function summaries (when available). "
                'Use search_type="hybrid" (keyword+semantic), "keyword" (grep-style), "semantic" (embeddings-only), or "name" (match function name). '
                'Requires function summaries to be present; hybrid search is intended to be enabled via the "Enable Hybrid Search" checkbox.'
            )

            # Insert after the get_cached_result line in Context Management section
            context_mgmt_marker = "- get_cached_result(result_id):"
            if context_mgmt_marker in capabilities_content:
                # Find the end of the get_cached_result line
                marker_pos = capabilities_content.find(context_mgmt_marker)
                next_section_pos = capabilities_content.find("\n\n", marker_pos)
                if next_section_pos != -1:
                    # Insert before the next section
                    capabilities_content = (
                        capabilities_content[:next_section_pos]
                        + "\n"
                        + search_func_desc
                        + capabilities_content[next_section_pos:]
                    )

        return capabilities_content


    def _build_phase_context(self, phase: str = None) -> tuple:
        """Build the static guidance and dynamic evidence passed to DSPy.

        Args:
            phase: Optional phase name to customize the prompt

        Returns:
            Tuple of (system_prompt, user_prompt)
        """
        # ========== SYSTEM PROMPT SECTIONS (Static Instructions) ==========
        system_sections = []

        # 1. Role and expertise definition
        system_sections.append(DEFAULT_SYSTEM_PROMPT)

        # 2. Available tools section (static)
        if self.include_capabilities and self.capabilities_text:
            tools_section = (
                f"## Available Tools\n"
                f"You have access to the following Ghidra interaction tools.\n\n"
                f"{self.capabilities_text}\n"
            )
            system_sections.append(tools_section)

        # 3. Phase-specific instructions (static rules)
        if phase == "planning":
            # Task mode gating: only use deployment-vuln planning prompt when explicitly in vuln mode.
            use_vuln_prompt = bool(getattr(self, "task_mode_enabled", False)) and getattr(self, "task_mode", "off") == "vuln"
            planning_template = (
                getattr(self.llm_config, "planning_system_prompt_vuln", "")
                if use_vuln_prompt
                else self.llm_config.planning_system_prompt
            )
            if not planning_template:
                planning_template = self.llm_config.planning_system_prompt
            phase_instructions = planning_template.replace(
                "{user_task_description}", "[User's goal will be provided in the user message]"
            )
            system_sections.append(phase_instructions)
        elif phase == "execution":
            # Choose execution system prompt based on task mode
            task_mode_enabled = bool(getattr(self, "task_mode_enabled", False))

            if task_mode_enabled:
                # Use detailed investigation methodology prompt for task mode
                execution_template = getattr(
                    self.llm_config, "execution_system_prompt_task_mode", self.llm_config.execution_system_prompt
                )
            else:
                # Use simple, direct prompt for normal queries
                execution_template = self.llm_config.execution_system_prompt

            phase_instructions = execution_template.format(
                user_task_description="[User's goal will be provided in the user message]",
                FUNCTION_CALL_BEST_PRACTICES=self.llm_config.FUNCTION_CALL_BEST_PRACTICES,
            )
            if getattr(self, "grep_layer_enabled", False):
                phase_instructions += (
                    "\nHybrid search is enabled. Use search_function_summaries for behavioral discovery "
                    "and decompile promising matches before drawing conclusions."
                )
            system_sections.append(phase_instructions)
        # Combine all system sections
        system_prompt = "\n\n".join(system_sections)

        # ========== USER PROMPT SECTIONS (Dynamic Context) ==========
        # Use Pydantic StructuredPrompt for clean separation and ordering

        # Build CAG context if enabled
        cag_context_obj = None
        # By default we keep prompts lean when Task Mode is off.
        # If the user explicitly enables Hybrid Search (grep layer), we allow CAG/RAG
        # knowledge injection even when Task Mode is off.
        task_mode_enabled = bool(getattr(self, "task_mode_enabled", False))
        grep_layer_enabled = bool(getattr(self, "grep_layer_enabled", False))

        # Direct function context injection when Hybrid Search is enabled
        function_context_section = None
        if grep_layer_enabled and phase == "execution":
            try:
                # Get latest user query
                recent_user_msgs = self.session.get_recent_messages(limit=1, role_filter=[MessageRole.USER])
                if recent_user_msgs:
                    user_query = recent_user_msgs[0].content

                    # Try to get relevant functions directly
                    relevant_funcs = self._get_relevant_functions_for_query(
                        user_query, top_k=5, search_type="hybrid", grep_enabled=True
                    )
                    if relevant_funcs:
                        function_context_section = self._format_function_context(relevant_funcs)
                        if function_context_section:
                            self.logger.info(
                                f"📚 Injecting {len(relevant_funcs)} relevant function(s) as context (Hybrid Search)"
                            )
            except Exception as e:
                self.logger.debug(f"Function context injection failed: {e}")

        if self.enable_cag and self.cag_manager and (task_mode_enabled or grep_layer_enabled):
            try:
                if grep_layer_enabled and not task_mode_enabled:
                    self.logger.info("CAG/RAG context injection enabled (trigger: Hybrid Search)")
            except Exception:
                pass
            latest_user_query = None

            # Get latest user query from session
            recent_user_msgs = self.session.get_recent_messages(limit=1, role_filter=[MessageRole.USER])
            if recent_user_msgs:
                latest_user_query = recent_user_msgs[0].content

            if latest_user_query:
                cag_text = self.cag_manager.enhance_prompt(latest_user_query, phase)
                if cag_text:
                    # Create CAGContext object
                    cag_context_obj = CAGContext(workplans=[cag_text])

        # Build phase-specific instructions
        phase_instructions = None
        latest_user_role = self.session.messages[-1].role.value if self.session.messages else None

        if latest_user_role == "user":
            if phase == "planning":
                phase_instructions = (
                    "## Current Task\nCreate a plan to address the goal above. Do not execute any commands yet."
                )
            else:
                phase_instructions = "## Current Task\nExecute the necessary tools to gather information for the goal above."

        # Build structured prompt using Pydantic model
        structured_prompt = StructuredPrompt(
            goal=self.current_goal,
            analysis_state=self.session.analysis_state,
            current_plan=self.current_plan,
            cag_context=cag_context_obj,
            tool_results=self.session.get_recent_tool_executions(limit=5),
            conversation_history=self.session.get_recent_messages(limit=self.config.context_limit),
            phase_specific_instructions=phase_instructions,
        )

        # Generate user prompt with conversation history ALWAYS at the end
        user_prompt = structured_prompt.build_user_prompt(max_history_items=self.config.context_limit)

        # Inject relevant functions context (Hybrid Search)
        if function_context_section:
            user_prompt = function_context_section + "\n\n" + user_prompt

        # Inject compact scope card ONLY when task mode is enabled
        task_mode_enabled = bool(getattr(self, "task_mode_enabled", False))
        if task_mode_enabled:
            scope_card = self._build_scope_card()
            if scope_card:
                user_prompt = scope_card + "\n\n" + user_prompt

        # --- INJECT KNOWLEDGE ARTIFACTS ---
        knowledge_summary = self.session.get_knowledge_summary()
        if knowledge_summary:
            user_prompt = knowledge_summary + "\n\n" + user_prompt
        # ----------------------------------

        # --- INJECT USER PREFERENCES (CUSTOM MODE NOTEPAD) ---
        # Only inject preferences when task mode is enabled AND in custom mode.
        prefs_summary = ""
        try:
            if bool(getattr(self, "task_mode_enabled", False)) and getattr(self, "task_mode", "off") == "custom":
                prefs_summary = self.session.get_user_preferences_summary()
        except Exception:
            prefs_summary = ""
        if prefs_summary:
            user_prompt = prefs_summary + "\n\n" + user_prompt
        # ----------------------------------

        # --- INJECT COMPLETED STEPS SUMMARY ---
        # Get all unique executed tools from session for this goal
        executed_tools = self.session.get_all_tool_executions()
        if executed_tools:
            # Create a compact summary of what has been done
            completed_summary = ["\n## COMPLETED STEPS (DO NOT REPEAT):"]

            # Group by tool name for cleaner display
            tools_by_name = {}
            for tool in executed_tools:
                name = tool.tool_name
                # Skip pagination tools from the summary to avoid clutter
                if name in ["list_functions", "list_imports", "list_exports", "list_strings"]:
                    params_str = f"offset={tool.parameters.get('offset', '?')}"
                else:
                    # Format parameters compactly
                    params_str = ", ".join([f"{k}={v}" for k, v in tool.parameters.items()])

                if name not in tools_by_name:
                    tools_by_name[name] = []
                tools_by_name[name].append(params_str)

            for name, params_list in tools_by_name.items():
                # Limit to last 3 calls per tool to save context
                params_display = "; ".join(params_list[-3:] if len(params_list) > 3 else params_list)
                completed_summary.append(f"- {name}: {params_display}")

            user_prompt += "\n".join(completed_summary) + "\n"
        # -------------------------------------

        return (system_prompt, user_prompt)


    def _normalize_command_name(self, command_name: str) -> str:
        """
        Normalize a command name (e.g., convert camelCase to snake_case).

        Args:
            command_name: The command name to normalize

        Returns:
            The normalized command name or empty string if not found
        """
        # First check if the command name already exists
        if hasattr(self.ghidra_client, command_name):
            return command_name

        # Try converting camelCase to snake_case
        snake_case = re.sub(r"(?<!^)(?=[A-Z])", "_", command_name).lower()

        # Only return the snake_case version if it exists
        if hasattr(self.ghidra_client, snake_case):
            logging.info(f"Normalized command name from '{command_name}' to '{snake_case}'")
            return snake_case

        return ""

    def _check_command_exists(self, command_name: str) -> Tuple[bool, str, List[str], List[str]]:
        """
        Check if a command exists and provide suggestions if it doesn't.

        Args:
            command_name: The command name to check

        Returns:
            Tuple of (exists, error_message, similar_commands, all_available_commands)
        """
        normalized_command = self._normalize_command_name(command_name)
        available_commands = [
            name for name in dir(self.ghidra_client) if not name.startswith("_") and callable(getattr(self.ghidra_client, name))
        ]

        if normalized_command:
            return True, "", [], available_commands  # Return all commands even if found

        # Command not found, provide helpful suggestions
        # available_commands already computed above

        # Find similar commands
        similar_commands = []
        for cmd in available_commands:
            # Simple similarity check - could be improved
            if command_name.lower() in cmd.lower() or cmd.lower() in command_name.lower():
                similar_commands.append(cmd)

        suggestion_msg = ""
        if similar_commands:
            suggestion_msg = f"\nDid you mean one of these? {', '.join(similar_commands)}"

        if command_name == "decompile":
            suggestion_msg = "\nDid you mean 'decompile_function(name=\"function_name\")' or 'decompile_function_by_address(address=\"1400011a8\")'?"
        elif command_name == "disassemble":
            suggestion_msg = (
                "\nThere is no 'disassemble' command. Try 'decompile_function_by_address(address=\"1400011a8\")' instead."
            )

        error_message = f"Unknown command: {command_name}{suggestion_msg}"
        return False, error_message, similar_commands, available_commands


    def get_cached_result(self, result_id: str) -> str:
        """
        Retrieve the full content of a cached result by its ID.

        This allows the AI to request the full content of results that
        were previously summarized or truncated due to context budget limits.

        Args:
            result_id: The cached result ID (e.g., "r5_decompile_function_abc123")

        Returns:
            Full result content, or error message if not found
        """
        if not self.context_manager or not self.context_manager.result_cache:
            return "Error: Result caching is not enabled"

        full_result = self.context_manager.get_full_result(result_id)

        if full_result:
            self.logger.info(f"Retrieved cached result: {result_id} ({len(full_result)} chars)")
            return full_result
        else:
            return f"Error: Cached result '{result_id}' not found. Available IDs: {list(self.context_manager.result_cache.cache.keys())[:5]}"

    def _extract_behavior_summary(self, text: str) -> str:
        """
        Extract the first sentence after '**Behavior Summary:**' from function analysis.
        Returns concise one-sentence description of function behavior.

        Args:
            text: Full function analysis text containing behavior summary

        Returns:
            First sentence of behavior summary, or fallback text if not found

        Example:
            Input: "**Function Analysis:**\\n...\\n**Behavior Summary:**\\nThis function does X. It also does Y."
            Output: "This function does X."
        """
        import re

        lines = text.split("\n")

        # Find "**Behavior Summary:**" section
        for i, line in enumerate(lines):
            if "**Behavior Summary:**" in line:
                # Get content from next non-empty line
                for j in range(i + 1, len(lines)):
                    content = lines[j].strip()
                    # Skip empty lines and section headers
                    if content and not content.startswith("**"):
                        # Extract first sentence - improved regex to handle abbreviations
                        # Look for sentence terminators (. ! ?) followed by space and capital letter, or end of string
                        # This avoids breaking on "C.R.T." or "U.S.A." type abbreviations
                        match = re.search(r"[.!?](?:\s+[A-Z]|\s*$)", content)
                        if match:
                            # Include the period but not the following space/letter
                            end_pos = match.start() + 1
                            return content[:end_pos].strip()
                        # No sentence terminator found - return up to 200 chars
                        return content[:200].strip()
                break

        # Fallback 1: Try plain "Behavior:" (backward compatibility with older format)
        for i, line in enumerate(lines):
            if "Behavior:" in line and "**Behavior Summary:**" not in line:
                remaining = "\n".join(lines[i:]).replace("Behavior:", "").strip()
                match = re.search(r"[.!?](?:\s+[A-Z]|\s*$)", remaining)
                if match:
                    end_pos = match.start() + 1
                    return remaining[:end_pos].strip()
                return remaining[:200].strip()

        # Fallback 2: Return truncated full text
        return text[:200].strip() if text else "No summary available"

    def _search_function_summaries(self, query: str, search_type: str = "hybrid", top_k: int = 5) -> str:
        """
        Search through analyzed function summaries using hybrid keyword + semantic search.

        Args:
            query: Search query (function name, keyword, or concept)
            search_type: "hybrid" (both), "keyword" (grep), "semantic" (RAG), or "name" (exact)
            top_k: Number of results to return (1-20)

        Returns:
            Formatted string with matching functions
        """
        # Check if grep layer is enabled
        grep_enabled = getattr(self, "grep_layer_enabled", False)

        # Validate search_type
        valid_types = ["hybrid", "keyword", "semantic", "name"]
        if search_type not in valid_types:
            return f"Error: search_type must be one of {valid_types}, got '{search_type}'"

        # Clamp top_k
        top_k = max(1, min(int(top_k), 20))

        results = self._get_relevant_functions_for_query(query, top_k, search_type, grep_enabled)

        if not results:
            return f"No results found for query: '{query}'"

        # Format results
        output = [f"Found {len(results)} function(s) matching '{query}':\n"]

        for i, result in enumerate(results, 1):
            doc = result.get("document", {})
            score = result.get("score", 0.0)

            name = doc.get("name", "Unknown")
            metadata = doc.get("metadata", {})
            address = metadata.get("address", "unknown")
            old_name = metadata.get("old_name", "")

            # Get summary from text using extraction method
            text = doc.get("text", "")
            summary = self._extract_behavior_summary(text)

            output.append(f"{i}. {name} @ {address}")
            if old_name and old_name != name:
                output.append(f"   (renamed from: {old_name})")
            output.append(f"   Score: {score:.3f}")
            output.append(f"   Summary: {summary}")
            output.append("")

        return "\n".join(output)

    def _get_relevant_functions_for_query(
        self, query: str, top_k: int = 5, search_type: str = "hybrid", grep_enabled: bool = False
    ):
        """
        Get relevant functions for a query using various search strategies.
        Returns list of result dicts with 'document' and 'score' keys.
        """
        # Build list of function documents from analyzed functions
        function_docs = []

        # Try to get functions from UI panel
        try:
            if hasattr(self, "_ui_instance"):
                ui = self._ui_instance
                panel = getattr(ui, "renamed_functions_panel", None)
                if panel and hasattr(panel, "get_rows_snapshot"):
                    # Read the thread-safe row model, not the Treeview. This is
                    # safe to call from this worker thread and includes every
                    # row whose data is known, even ones whose widget insert is
                    # still queued (no poll-tick lag / missing rows).
                    for values in panel.get_rows_snapshot():
                        try:
                            if len(values) >= 4:
                                doc = {
                                    "text": f"Function: {values[2]}\nOriginal: {values[1]}\nAddress: {values[0]}\nBehavior: {values[3]}",
                                    "type": "function_analysis",
                                    "name": values[2],
                                    "metadata": {"address": values[0], "old_name": values[1], "new_name": values[2]},
                                }
                                function_docs.append(doc)
                        except Exception:
                            continue
        except Exception as e:
            self.logger.debug(f"Could not get functions from UI: {e}")

        # Fallback: get from function_summaries dict
        if not function_docs:
            # Prefer structured mapping if available (preserves names)
            fam = getattr(self, "function_address_mapping", None)
            fsum = getattr(self, "function_summaries", None)
            if isinstance(fam, dict) and isinstance(fsum, dict):
                for addr, info in fam.items():
                    try:
                        old_name = info.get("old_name", "Unknown")
                        new_name = info.get("new_name", "Unknown")
                        summary = fsum.get(addr, "") or fsum.get(old_name, "") or fsum.get(new_name, "")
                        if not summary:
                            continue
                        doc = {
                            "text": f"Function: {new_name}\nOriginal: {old_name}\nAddress: {addr}\nBehavior: {summary}",
                            "type": "function_analysis",
                            "name": new_name,
                            "metadata": {"address": addr, "old_name": old_name, "new_name": new_name},
                        }
                        function_docs.append(doc)
                    except Exception:
                        continue

            # Last resort: raw summaries only
            if not function_docs and isinstance(fsum, dict):
                for addr, summary in fsum.items():
                    if not summary:
                        continue
                    doc = {
                        "text": f"Address: {addr}\nBehavior: {summary}",
                        "type": "function_analysis",
                        "name": f"FUN_{addr}",
                        "metadata": {"address": addr},
                    }
                    function_docs.append(doc)

        if not function_docs:
            return []

        # Perform search based on type
        if search_type == "name":
            # Direct name search
            query_lower = query.lower()
            matches = []
            for doc in function_docs:
                name = doc.get("name", "").lower()
                if query_lower in name:
                    score = len(query_lower) / max(len(name), 1)
                    matches.append({"document": doc, "score": score})
            matches.sort(key=lambda x: x["score"], reverse=True)
            return matches[:top_k]

        elif search_type == "keyword" or (search_type == "hybrid" and grep_enabled):
            # Keyword search (grep-style) or hybrid when grep layer is enabled
            from src.cag.vector_store import SimpleVectorStore

            temp_store = SimpleVectorStore(function_docs, [])
            return temp_store._keyword_search(query, top_k=top_k)

        elif search_type == "semantic":
            # Semantic search requires CAG manager with vectors
            if not self.cag_manager or not self.cag_manager.vector_store:
                # Fall back to keyword
                from src.cag.vector_store import SimpleVectorStore

                temp_store = SimpleVectorStore(function_docs, [])
                return temp_store._keyword_search(query, top_k=top_k)

            return self.cag_manager.vector_store.search(query, top_k=top_k)

        elif search_type == "hybrid":
            # Hybrid search (keyword + semantic)
            if not self.cag_manager or not self.cag_manager.vector_store:
                # Fall back to keyword-only
                from src.cag.vector_store import SimpleVectorStore

                temp_store = SimpleVectorStore(function_docs, [])
                return temp_store._keyword_search(query, top_k=top_k)

            # True hybrid search
            results = self.cag_manager.vector_store.search_hybrid(query, top_k=top_k, use_keywords=True)

            # ============ KNOWLEDGE GRAPH ENHANCEMENT ============
            # Expand primary results with graph neighbors for better architectural context
            if self.function_graph and len(self.function_graph) > 0 and results:
                try:
                    # Extract addresses from primary results
                    primary_addresses = []
                    for result in results:
                        metadata = result.get("document", {}).get("metadata", {})
                        addr = metadata.get("address", "")
                        if addr:
                            primary_addresses.append(addr)

                    if primary_addresses:
                        # Expand with graph neighbors
                        expanded_addresses = self.function_graph.expand_context_for_rag(
                            primary_addresses,
                            expansion_depth=1,  # Immediate neighbors only
                            max_expanded=top_k * 2,  # Allow doubling the context
                        )

                        # Add expanded functions to results
                        for addr in expanded_addresses:
                            if addr not in primary_addresses and addr in self.function_address_mapping:
                                func_data = self.function_address_mapping[addr]
                                # Create document for graph neighbor
                                doc = {
                                    "text": f"Function: {func_data.get('new_name', addr)}\nAddress: {addr}",
                                    "type": "function_analysis",
                                    "name": func_data.get("new_name", addr),
                                    "metadata": {
                                        "address": addr,
                                        "new_name": func_data.get("new_name", addr),
                                        "graph_expanded": True,  # Mark as graph-added
                                    },
                                }
                                # Score based on centrality
                                centrality = self.function_graph.calculate_centrality(addr)
                                results.append(
                                    {
                                        "document": doc,
                                        "score": 0.3 + (centrality * 0.3),  # 0.3-0.6 range for graph neighbors
                                    }
                                )

                        self.logger.info(
                            f"📊 Graph expanded {len(primary_addresses)} results to {len(results)} (added {len(results) - len(primary_addresses)} neighbors)"
                        )

                        # Re-sort with graph additions
                        results.sort(key=lambda x: x.get("score", 0), reverse=True)

                except Exception as graph_error:
                    self.logger.debug(f"Graph expansion failed: {graph_error}")

            return results[: top_k * 2]  # Return more when graph-enhanced

        return []

    def _format_function_context(self, results):
        """Format relevant functions as context section for prompt injection."""
        if not results:
            return None

        lines = ["## 📚 Relevant Functions from Analysis"]
        lines.append("The following functions may be relevant to your query:\n")

        for i, result in enumerate(results[:5], 1):  # Limit to top 5
            doc = result.get("document", {})
            name = doc.get("name", "Unknown")
            metadata = doc.get("metadata", {})
            address = metadata.get("address", "unknown")

            # Get summary using extraction method
            text = doc.get("text", "")
            summary = self._extract_behavior_summary(text)

            lines.append(f"### {i}. {name} @ {address}")
            lines.append(f"{summary}")
            lines.append("")

        lines.append(
            "💡 Tip: These functions were automatically retrieved based on your query. You can decompile them for more details."
        )
        return "\n".join(lines)

    def _collect_all_paginated_list_results(self, tool_method, **params):
        """Collect all pages from a paginated list tool and strip metadata lines."""
        aggregated = []
        current_params = params.copy()
        page_count = 0
        max_pages = 1000

        while page_count < max_pages:
            batch_result = tool_method(**current_params)

            if isinstance(batch_result, str):
                raw_batch = [line.strip() for line in batch_result.splitlines() if line.strip()]
            elif isinstance(batch_result, list):
                raw_batch = [str(line).strip() for line in batch_result if str(line).strip()]
            else:
                return aggregated

            if not raw_batch:
                break

            if any(line.lower().startswith(("error", "request failed")) for line in raw_batch):
                if aggregated:
                    break
                error_line = raw_batch[0]
                if error_line.lower().startswith("error:"):
                    return "ERROR:" + error_line[6:]
                return f"ERROR: {error_line}"

            next_match = None
            for line in raw_batch:
                if line.startswith("["):
                    match = re.search(r"\[Next: offset=(\d+), limit=(\d+)\]", line)
                    if match:
                        next_match = (int(match.group(1)), int(match.group(2)))
                    continue
                aggregated.append(line)

            if not next_match:
                break

            current_params["offset"] = next_match[0]
            current_params["limit"] = next_match[1]
            page_count += 1

        if page_count >= max_pages:
            self.logger.warning("Reached maximum pagination depth while collecting tool results")

        return aggregated

    def execute_command(self, command_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a command with parameters.

        Args:
            command_name: The name of the command to execute
            params: The parameters to pass to the command

        Returns:
            The result of the command execution
        """
        try:
            # Handle bridge-level commands FIRST (before Ghidra client validation)
            normalized_bridge_cmd = command_name.lower().replace("-", "_").replace(" ", "_")

            if normalized_bridge_cmd == "get_cached_result":
                result_id = params.get("result_id", "")
                result = self.get_cached_result(result_id)
                return {"result": result, "source": "context_cache"}

            if normalized_bridge_cmd == "search_function_summaries":
                # Check if hybrid search is enabled
                if not getattr(self, "grep_layer_enabled", False):
                    return {
                        "result": "Error: search_function_summaries is only available when 'Enable Hybrid Search' is turned on in the UI. Please enable it in the Task Mode section.",
                        "source": "function_search",
                    }

                # Search through analyzed function summaries
                query = params.get("query", "")
                search_type = params.get("search_type", "hybrid")  # hybrid, keyword, semantic, name
                top_k = params.get("top_k", 5)

                if not query:
                    return {"result": "Error: 'query' parameter is required", "source": "function_search"}

                result = self._search_function_summaries(query, search_type, top_k)
                return {"result": result, "source": "function_search"}

            if normalized_bridge_cmd == "scan_function_pointer_tables":
                # This is handled by ghidra_client, so let it pass through
                pass

            # Normalize command name and parameters for Ghidra client commands
            normalized_command = self._normalize_command_name(command_name)
            if not normalized_command:
                exists, error_message, similar_commands, all_available_commands = self._check_command_exists(command_name)
                if not exists:
                    # Provide concise error with suggestions only
                    if similar_commands:
                        suggestion_str = f" Did you mean: {', '.join(similar_commands[:3])}?"
                    else:
                        suggestion_str = ""

                    enhanced_unknown_command_error = f"{error_message}{suggestion_str}"
                    raise ValueError(enhanced_unknown_command_error)

            # Check for required parameters
            params = self.command_parser.normalize_parameters(normalized_command, params)
            is_valid, error_message = self.command_parser.validate_command_parameters(normalized_command, params)
            if not is_valid:
                enhanced_error = self.command_parser.get_enhanced_error_message(command_name, params, error_message)
                raise ValueError(enhanced_error)

            # --- IMPROVEMENT: Semantic String Categorization ---
            # If the command is 'list_strings' and a 'category' or generic filter is used,
            # translate it to a regular expression for the backend string search.
            if normalized_command == "list_strings":
                str_filter = params.get("filter", "")

                # Check for "category" pseudo-argument in filter or explicit param
                # Note: The agent might pass category="filesystem" or filter="category:filesystem"
                category = params.get("category")
                if not category and str_filter and str_filter.startswith("category:"):
                    category = str_filter.split(":", 1)[1]

                if category:
                    if category == "filesystem":
                        # Regex for paths (drive letters, UNC, extensions)
                        # Ghidra simple search might not fully support complex regex, but basic patterns work.
                        # We'll use a broad pattern or just specific extension terms if regex isn't reliable.
                        # Assuming the backend supports contains check or basic regex.
                        # Let's set a reliable text filter for now.
                        params["filter"] = ".exe"  # Default to executables if generic
                        # If we can support regex in the backend, we would pass that.
                        # For now, we inject a clearer filter.
                        self.logger.info("🔄 Converted category='filesystem' to filter='.exe' (approximate)")

                    elif category == "registry":
                        params["filter"] = "HKLM"  # Basic start
                        self.logger.info("🔄 Converted category='registry' to filter='HKLM'")

                    elif category == "urls":
                        params["filter"] = "http"
                        self.logger.info("🔄 Converted category='urls' to filter='http'")

            # ---------------------------------------------------

            # Enhanced CAG memory-based duplicate detection
            if self.enable_cag and self.cag_manager:
                # Check if CAG memory suggests skipping this command
                should_skip, skip_reason = self.cag_manager.should_skip_command(normalized_command, params)
                if should_skip:
                    self.logger.warning(f"🧠 CAG Memory suggests skipping: {skip_reason}")

                    # Try to get cached result from CAG memory
                    cached_result = self.cag_manager.get_cached_command_result(normalized_command, params)
                    if cached_result:
                        self.logger.info(f"🎯 Using CAG cached result for {normalized_command}")
                        return {"result": cached_result, "source": "cag_cache"}
                    else:
                        # Return a guidance message instead of executing
                        guidance_msg = f"Command '{normalized_command}' skipped due to recent execution. {skip_reason}"
                        return {"result": guidance_msg, "source": "cag_skip", "skipped": True}

            # Find the command in the Ghidra client
            command_func = getattr(self.ghidra_client, normalized_command)

            # Enhanced caching for multiple command types
            cache_key = self._generate_cache_key(normalized_command, params)
            cached_result = self._get_cached_result(normalized_command, cache_key, params)

            if cached_result is not None:
                self.cache_stats["hits"] += 1
                self.logger.info(
                    f"🎯 Cache HIT for {normalized_command} (key: {cache_key}) - Stats: {self.cache_stats['hits']} hits, {self.cache_stats['misses']} misses"
                )
                return cached_result

            # Cache miss - execute the command
            self.cache_stats["misses"] += 1
            self.logger.info(f"💫 Cache MISS for {normalized_command} (key: {cache_key}) - Executing...")

            result = command_func(**params)

            # --- IMPROVEMENT: Auto-fallback for Import XREFs ---
            # if get_function_xrefs returns nothing, it might be an import thunk (e.g. LoadLibraryW)
            # We should hint the user to use get_xrefs_to on the address if possible, or try to resolve it.
            if normalized_command == "get_function_xrefs" and (not result or "0" in str(result)):
                # If empty result for a function name, it might be an import.
                # We can't easily auto-chain without address, but we can provide a specific hint.
                if not result:
                    result = []  # Ensure it's a list if None

                # Add a "fake" result entry with a hint
                hint_entry = {
                    "name": "HINT: Import Thunk?",
                    "address": "TRY_BELOW",
                    "references": [
                        "If this is an external API (like LoadLibrary), split into two steps:",
                        "1. Find address: list_imports(filter='name')",
                        "2. Get XREFs: get_xrefs_to(address='...')",
                    ],
                }
                if isinstance(result, list):
                    result.append(hint_entry)
            # ---------------------------------------------------

            # Cache the result for future use
            self._cache_result(normalized_command, cache_key, params, result)

            # Update CAG memory with the executed command and result
            if self.enable_cag and self.cag_manager:
                self.cag_manager.update_command_execution(normalized_command, params, str(result))

            # Update analysis state to track the command execution
            command_dict = {"name": normalized_command, "params": params}
            self._update_analysis_state(command_dict, str(result))

            return result
        except Exception as e:
            error_message = str(e)
            enhanced_error = self.command_parser.get_enhanced_error_message(command_name, params, error_message)
            raise ValueError(enhanced_error) from e

    def _generate_cache_key(self, command_name: str, params: Dict[str, Any]) -> str:
        """
        Generate a cache key for a command and its parameters.

        Args:
            command_name: The command name
            params: The command parameters

        Returns:
            A unique cache key string
        """
        # For functions, use name if available, otherwise use current function
        if command_name in ["decompile_function", "analyze_function"]:
            if "name" in params and params["name"]:
                return f"{command_name}:{params['name']}"
            elif "address" in params and params["address"]:
                return f"{command_name}:{params['address']}"
            else:
                # For current function, we need to get the current function name/address
                try:
                    current_func = self.ghidra_client.get_current_function()
                    if isinstance(current_func, str) and "Function:" in current_func:
                        # Extract function name from "Function: FUN_12345 at 12345"
                        import re

                        match = re.search(r"Function:\s*(\w+)", current_func)
                        if match:
                            func_name = match.group(1)
                            return f"{command_name}:current:{func_name}"
                except Exception as e:
                    self.logger.warning(f"Failed to resolve current function for {command_name}: {e}")
                    pass
                return f"{command_name}:current"

        elif command_name == "get_current_function":
            # For get_current_function, cache per session but allow invalidation
            return f"{command_name}:session"

        else:
            # For other commands, create key from sorted params
            param_str = ":".join([f"{k}={v}" for k, v in sorted(params.items())])
            return f"{command_name}:{param_str}" if param_str else command_name

    def _get_cached_result(self, command_name: str, cache_key: str, params: Dict[str, Any]):
        """
        Get a cached result if available.

        Args:
            command_name: The command name
            cache_key: The cache key
            params: The command parameters

        Returns:
            Cached result or None if not found
        """
        # Commands that should NOT be cached (real-time or state-dependent)
        NO_CACHE_COMMANDS = [
            "list_imports",  # May change with binary state
            "list_exports",  # May change with binary state
            "list_strings",  # Large results, may change
            "list_segments",  # Binary structure
            "get_current_address",  # Dynamic state
            "check_health",  # Real-time check
            "health_check",  # Real-time check
        ]

        # Don't use cache for these commands
        if command_name in NO_CACHE_COMMANDS:
            return None

        # Check different cache stores based on command type
        if command_name in ["decompile_function", "analyze_function"]:
            return self.decompilation_cache.get(cache_key)
        elif command_name == "get_current_function":
            return self.function_cache.get(cache_key)
        else:
            # Generic cache for other commands
            return self.decompilation_cache.get(cache_key)

    def _cache_result(self, command_name: str, cache_key: str, params: Dict[str, Any], result: Any):
        """
        Cache a command result.

        Args:
            command_name: The command name
            cache_key: The cache key
            params: The command parameters
            result: The result to cache
        """
        # Commands that should NOT be cached (real-time or state-dependent)
        NO_CACHE_COMMANDS = [
            "list_imports",  # May change with binary state
            "list_exports",  # May change with binary state
            "list_strings",  # Large results, may change
            "list_segments",  # Binary structure
            "get_current_address",  # Dynamic state
            "check_health",  # Real-time check
            "health_check",  # Real-time check
        ]

        # Don't cache these commands
        if command_name in NO_CACHE_COMMANDS:
            return

        # Check if result is an error - don't cache errors
        if isinstance(result, str) and result.startswith("ERROR:"):
            self.logger.debug(f"[WARN] Not caching error result for {command_name}")
            return

        # Check if result is empty or indicates failure - don't cache
        if isinstance(result, (list, dict)) and not result:
            self.logger.debug(f"[WARN] Not caching empty result for {command_name}")
            return

        # Cache in appropriate store
        if command_name in ["decompile_function", "analyze_function"]:
            self.decompilation_cache[cache_key] = result
            self.cache_stats["cache_size"] = len(self.decompilation_cache)
            self.logger.debug(f"📦 Cached {command_name} result for key: {cache_key}")
        elif command_name == "get_current_function":
            self.function_cache[cache_key] = result
            self.logger.debug(f"📦 Cached {command_name} result for key: {cache_key}")
        else:
            # Generic cache for other commands (but only cacheable ones)
            self.decompilation_cache[cache_key] = result
            self.cache_stats["cache_size"] = len(self.decompilation_cache)

    def clear_cache(self):
        """Clear all caches."""
        self.decompilation_cache.clear()
        self.function_cache.clear()
        self.cache_stats = {"hits": 0, "misses": 0, "cache_size": 0}
        self.logger.info("🧹 All caches cleared")

    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        total_requests = self.cache_stats["hits"] + self.cache_stats["misses"]
        hit_rate = (self.cache_stats["hits"] / total_requests * 100) if total_requests > 0 else 0

        return {
            "hits": self.cache_stats["hits"],
            "misses": self.cache_stats["misses"],
            "hit_rate": f"{hit_rate:.1f}%",
            "cache_size": self.cache_stats["cache_size"],
            "total_requests": total_requests,
        }

    def process_query_with_agentic_loop(self, query: str) -> str:
        """
        Process a query with multi-cycle agentic loop.

        Loops through Planning → Execution → Analysis → Evaluation
        until goal is achieved or max cycles reached.

        Args:
            query: Natural language query from the user

        Returns:
            Final analysis response
        """
        try:
            self.logger.info(f"🚀 Starting agentic query processing: '{query}'")
            self.logger.info(
                f"📊 Config: max_agentic_cycles={self.llm_config.max_agentic_cycles}, max_execution_steps={self.llm_config.max_execution_steps}"
            )

            # Store the query as our current goal
            self.current_goal = query
            self._update_scope_from_query(query)
            self.goal_achieved = False
            self.executed_tools = set()  # Reset tool tracking for new query
            self.step_result_map = {}  # Reset step result map for new query

            # Reset coverage tracker for fresh investigation
            if self.coverage_tracker:
                self.coverage_tracker.reset()
            # Reset lead tracker
            if self.lead_tracker:
                self.lead_tracker.reset()

            # Depth escalation: each cycle gets progressively deeper instructions
            # NOTE: These depth instructions are ONLY used when Task Mode is enabled
            # When Task Mode is OFF, the AI should handle simple queries directly without forced investigation paths
            DEPTH_INSTRUCTIONS = {
                1: "RECONNAISSANCE: List imports, strings, exports. Identify binary purpose, compiler, and key security-related APIs. Cover as many investigation areas as possible at a surface level.",
                2: "TARGETED SEARCH: Follow up on HIGH-priority leads from cycle 1. Search for service/privilege/path/registry strings. Focus on uncovered investigation areas.",
                3: "DEEP TRACE: Decompile callers of security-critical APIs. Trace data flow (lpApplicationName, lpCommandLine, file paths) to find concrete vulnerabilities.",
                4: "VERIFICATION: Confirm or deny hypotheses. Check if paths are quoted, permissions are validated, DLLs load from absolute paths, etc.",
                5: "GAP FILL: Address ALL remaining uncovered checklist items. Re-verify HIGH findings. Summarize confirmed vulnerabilities with evidence.",
            }

            # Check if task mode is enabled - only apply depth instructions if it is
            task_mode_enabled = bool(getattr(self, "task_mode_enabled", False))

            # Add user query to context
            self.add_to_context("user", query)

            # Get configuration
            # Disabling the multi-cycle mode now means one pass through the same
            # DSPy workflow instead of switching to the retired legacy agent.
            max_cycles = self.llm_config.max_agentic_cycles if self.llm_config.agentic_loop_enabled else 1
            max_exec_steps = self.llm_config.max_execution_steps

            best_response = ""
            all_cycle_results = []

            # OUTER LOOP: Agentic cycles
            for cycle in range(1, max_cycles + 1):
                self.logger.info(f"{'=' * 70}")
                self.logger.info(f"AGENTIC CYCLE {cycle}/{max_cycles}")
                self.logger.info(f"{'=' * 70}")

                # Emit cycle start to UI
                self._emit_cot("Cycle", f"AGENTIC CYCLE {cycle}/{max_cycles}")

                # Track current loop number for step ID generation
                self.current_loop_number = cycle

                # PHASE 1: Planning
                self.logger.info(f"📋 Cycle {cycle} - Phase 1: Planning")
                self._emit_cot("Phase", "Phase 1: Planning")
                self.current_workflow_stage = "planning"

                # For cycles after the first, add context about what we learned
                if cycle > 1:
                    cycle_context = "\n\n## Previous Cycle Results\n"
                    cycle_context += f"Cycles completed: {cycle - 1}\n"
                    cycle_context += f"Previous evaluation: {all_cycle_results[-1]['reason']}\n"

                    # Build summary of tools already executed to prevent redundant calls
                    cycle_context += "\n### Already Executed Tools (DO NOT repeat these exact calls):\n"
                    for cmd_sig, (step_id, excerpt) in self.step_result_map.items():
                        # Parse the command signature to show a readable format
                        cmd_parts = cmd_sig.split(":", 1)
                        cmd_name = cmd_parts[0] if cmd_parts else cmd_sig
                        cycle_context += f"- {step_id}: {cmd_name} -> {excerpt[:80]}...\n"

                    cycle_context += "\nContinue investigating based on the gaps identified above. "
                    cycle_context += 'Use get_cached_result(result_id="step_L{loop}_{N}") to retrieve any previous result.\n'
                    plan_response = self._generate_plan(query + cycle_context)
                else:
                    plan_response = self._generate_plan(query)

                # Inject depth instruction ONLY if Task Mode is enabled
                # When Task Mode is OFF, allow the AI to handle queries naturally without forced investigation paths
                if task_mode_enabled:
                    depth_instruction = DEPTH_INSTRUCTIONS.get(cycle, DEPTH_INSTRUCTIONS[5])
                    plan_response = f"## Cycle {cycle} Depth: {depth_instruction}\n\n{plan_response}"
                    depth_label = depth_instruction.split(":")[0]
                    self.logger.info(f"✅ Planning completed: {len(plan_response)} chars (Depth: {depth_label})")
                    self._emit_cot("Depth", f"Cycle {cycle}: {depth_label}")
                else:
                    # Task Mode OFF - no depth instructions, simpler logging
                    self.logger.info(f"✅ Planning completed: {len(plan_response)} chars (Task Mode: OFF)")

                self._emit_cot("Status", f"Planning completed ({len(plan_response)} chars)")

                # PHASE 2: Execution Loop (INNER LOOP)
                self.logger.info(f"🔧 Cycle {cycle} - Phase 2: Execution Loop (max {max_exec_steps} steps)")
                self._emit_cot("Phase", f"Phase 2: Execution Loop (max {max_exec_steps} steps)")
                self.current_workflow_stage = "execution"
                exec_results = self._execution_loop(plan_response, max_steps=max_exec_steps)
                self.logger.info(f"✅ Execution loop completed: {exec_results.total_steps} steps executed")
                self._emit_cot("Status", f"Execution completed: {exec_results.total_steps} tools executed")

                # Check if execution gate triggered during this cycle
                if exec_results.gates_triggered:
                    gate_count = len(exec_results.gates_triggered)
                    gate_summary = "; ".join(g.reason[:60] for g in exec_results.gates_triggered[-3:])
                    self._emit_cot("Gate", f"[WARN] {gate_count} gate(s) triggered this cycle: {gate_summary}")
                    self.logger.info(f"🚧 {gate_count} gate(s) fired during execution: {gate_summary}")

                # Check if AI asked a question - pause for user input
                if exec_results.pending_question:
                    q = exec_results.pending_question
                    self._emit_cot("Status", f"[PAUSED] Waiting for user answer: {q.question[:80]}")
                    self.logger.info("[PAUSED] Question pending - Phase 1: Log and continue")
                    # Phase 1: Log and continue (Phase 2 will add UI blocking)
                    # Clear the question so the loop can proceed
                    exec_results.pending_question = None

                # Session Compaction — Check if context is approaching limits
                if self.session_compactor and self.session_compactor.should_compact(exec_results):
                    self._emit_cot("Compaction", "📦 Context approaching limit, compacting...")
                    self.logger.info("📦 Triggering session compaction")

                    # Strategy 1: Prune old tool outputs
                    prune_result = self.session_compactor.prune(exec_results)
                    self._emit_cot(
                        "Compaction",
                        f"📦 Pruned {prune_result.results_pruned} results: "
                        f"{prune_result.original_chars} → {prune_result.compacted_chars} chars",
                    )

                    # Strategy 2: If still over budget, LLM-summarize
                    if self.session_compactor.should_compact(exec_results):
                        compact_result = self.session_compactor.compact(exec_results, query)
                        if compact_result.summary:
                            exec_results.compaction_summary = compact_result.summary
                            self._emit_cot("Compaction", f"📦 LLM compaction: {compact_result.compacted_chars} chars summary")
                            self.logger.info(f"📦 LLM compaction complete: {compact_result.compacted_chars} chars")

                # PHASE 3: Analysis
                self.logger.info(f"🧠 Cycle {cycle} - Phase 3: Analysis")
                self._emit_cot("Phase", "Phase 3: Analysis")
                self.current_workflow_stage = "analysis"
                response = self._analyze_execution_results(exec_results)
                self.logger.info(f"✅ Analysis completed: {len(response)} chars")
                self._emit_cot("Status", f"Analysis completed ({len(response)} chars)")

                # Store best response so far
                best_response = response

                # PHASE 4: Evaluation
                self.logger.info(f"🔍 Cycle {cycle} - Phase 4: Goal Evaluation")
                self._emit_cot("Phase", "Phase 4: Goal Evaluation")
                self.current_workflow_stage = "evaluation"
                goal_achieved, reason = self._evaluate_goal_achievement(
                    goal=query, analysis=response, exec_results=exec_results
                )

                # Store cycle results
                all_cycle_results.append(
                    {
                        "cycle": cycle,
                        "goal_achieved": goal_achieved,
                        "reason": reason,
                        "tools_executed": exec_results.total_steps,
                    }
                )

                if goal_achieved:
                    self.logger.info(f"✅ Goal achieved in cycle {cycle}!")
                    self.logger.info(f"   Total cycles used: {cycle}/{max_cycles}")
                    self.logger.info(f"   Total tools executed: {sum(r['tools_executed'] for r in all_cycle_results)}")
                    self._emit_cot(
                        "Status",
                        f"Goal achieved in cycle {cycle}! Total tools: {sum(r['tools_executed'] for r in all_cycle_results)}",
                    )
                    self.goal_achieved = True
                    break
                else:
                    self.logger.warning(f"[WARN] Goal not achieved in cycle {cycle}")
                    self.logger.warning(f"   Reason: {reason}")
                    self._emit_cot("Status", f"Goal not yet achieved: {reason[:100]}...")

                    if cycle < max_cycles:
                        self.logger.info(f"[INFO] Looping back to planning for cycle {cycle + 1}")
                        self._emit_cot("Status", f"Looping back to planning for cycle {cycle + 1}")
                        # Add evaluation result to context for next planning
                        eval_context = f"Cycle {cycle} evaluation: Goal not yet achieved. {reason}"
                        self.add_to_context("evaluation", eval_context)
                    else:
                        self.logger.warning(f"[WARN] Max cycles ({max_cycles}) reached")
                        self.logger.warning(f"   Returning best effort response from {len(all_cycle_results)} cycles")
                        self._emit_cot("Status", f"Max cycles ({max_cycles}) reached - returning best effort response")

            # Add final summary to response if multiple cycles were used
            if len(all_cycle_results) > 1:
                cycle_summary = f"\n\n---\n**Investigation Summary**: Completed {len(all_cycle_results)} investigation cycle(s) with {sum(r['tools_executed'] for r in all_cycle_results)} total tool executions."
                best_response += cycle_summary

            # Add assistant response to context
            self.add_to_context("assistant", best_response)

            # Workflow complete
            self.current_workflow_stage = None
            self.logger.info("🎯 Agentic query processing completed successfully")

            # Custom mode: update notepad/workplan after query
            self._maybe_update_custom_workplan(user_query=query, final_response=best_response)

            return best_response

        except Exception as e:
            # Log the exception with full traceback
            import traceback

            self.logger.error(f"❌ Error in agentic query processing: {str(e)}")
            self.logger.error(f"Full traceback: {traceback.format_exc()}")

            # Reset workflow stage on error
            self.current_workflow_stage = None

            # Return error message
            return f"Error in query processing: {str(e)}"


    def process_query(self, query: str) -> str:
        """
        Main entry point for query processing.

        Runs the DSPy-owned workflow. Disabling multi-cycle mode limits that
        same workflow to one Planning→Execution→Analysis cycle.

        Args:
            query: Natural language query from the user

        Returns:
            Result of processing the query
        """
        self.logger.info("[INFO] Processing query with DSPy agent module")
        return self.agent(query=query).answer

    def _generate_plan(self, query: str) -> str:
        """
        Generate a plan for addressing the query using Ollama.

        Args:
            query: Natural language query from the user

        Returns:
            Plan response
        """
        logging.info("Starting planning phase")
        plugin_context = self._run_plugin_hook(PluginHook.BEFORE_PLANNING, query=query, cycle=self.current_loop_number)
        query = plugin_context.query

        # Build prompts (system and user)
        system_prompt, user_prompt = self._build_phase_context(phase="planning")
        user_prompt += f"\n\nUser Query: {query}"

        # Generate planning response with properly separated prompts
        response = self.dspy_program.plan(system_prompt, user_prompt)

        # Extract plan
        self.current_plan = response
        logging.info(f"Received planning response: {response[:100]}...")

        plugin_context.plan = response
        self.plugin_manager.run(PluginHook.AFTER_PLANNING, plugin_context)
        response = plugin_context.plan
        self.current_plan = response

        self.add_to_context("plan", response)

        logging.info("Planning phase completed")
        return response

    def _display_tool_result(self, cmd_name: str, result: Any) -> None:
        """
        Display a tool result to the user in a clear, formatted way.

        Args:
            cmd_name: The name of the command executed
            result: The result from the command execution
        """
        # List of "verbose" commands that should display their full results
        verbose_commands = [
            "list_functions",
            "list_methods",
            "list_imports",
            "list_exports",
            "search_functions_by_name",
            "decompile_function",
            "decompile_function_by_address",
        ]

        # Special handling based on command type
        if cmd_name in verbose_commands:
            print("\n" + "=" * 60)
            print(f"Results from {cmd_name}:")
            print("=" * 60)

            # Format based on result type
            if isinstance(result, list):
                # For lists like function lists, show with numbering
                for i, item in enumerate(result, 1):
                    if isinstance(item, dict) and "name" in item and "address" in item:
                        print(f"{i:3d}. {item['name']} @ {item['address']}")
                    elif isinstance(item, dict):
                        print(f"{i:3d}. {item}")
                    else:
                        print(f"{i:3d}. {item}")
                print(f"\nTotal: {len(result)} items")
            elif isinstance(result, dict):
                # For dictionary results
                for key, value in result.items():
                    print(f"{key}: {value}")
            elif isinstance(result, str) and len(result) > 500:
                # For long string results (like decompiled code)
                print(f"{result[:500]}...\n[Showing first 500 characters of {len(result)} total]")
            else:
                # For other results
                print(result)

            print("=" * 60 + "\n")
        else:
            # For non-verbose commands, just show a success message
            print(f"✓ Successfully executed {cmd_name}")



    def _clean_final_response(self, response: str) -> str:
        """
        Clean up response formatting for display.

        Args:
            response: The raw final response

        Returns:
            Cleaned response text
        """
        if not response:
            return ""

        # Handle code blocks wrapping the entire response
        # Only strip if the response starts and ends with ```
        cleaned = response.strip()
        if cleaned.startswith("```") and cleaned.endswith("```"):
            # Check if it's just one big block
            lines = cleaned.split("\n")
            if len(lines) >= 2:
                # Remove first and last line
                cleaned = "\n".join(lines[1:-1])

        return cleaned.strip()


    def _execution_loop(self, plan: str, max_steps: int = 10) -> ExecutionPhaseResults:
        """
        Execute tools in a loop until investigation is complete.

        This implements the multi-tool execution loop that allows the AI to:
        1. Execute multiple tools sequentially (Batching)
        2. Accumulate results for comprehensive analysis
        3. Decide when investigation is complete
        4. Capture reasoning for Chain of Thought

        Args:
            plan: The execution plan from planning phase
            max_steps: Maximum number of tool executions allowed

        Returns:
            ExecutionPhaseResults with all accumulated tool executions
        """
        plugin_context = self._run_plugin_hook(
            PluginHook.BEFORE_EXECUTION,
            plan=plan,
            cycle=self.current_loop_number,
        )
        plan = plugin_context.plan

        # Initialize execution results
        exec_results = ExecutionPhaseResults(goal=self.current_goal or "Investigation", plan=plan)

        # Reset gatekeeper state for this loop
        self.execution_gate.reset()

        # Check for any user feedback from a previous gate pause
        gate_feedback = self.execution_gate.consume_feedback()
        if gate_feedback:
            self.logger.info(f"📝 Injecting user feedback from previous gate: {gate_feedback[:100]}")
            plan = plan + f"\n\n## User Guidance\n{gate_feedback}"

        self.logger.info(f"🔄 Starting execution loop (max {max_steps} steps)")

        # Initialize analysis dumper for this loop
        if hasattr(self, "analysis_dumper") and self.analysis_dumper:
            self.analysis_dumper.start_loop(self.current_loop_number)
            self.analysis_dumper.set_goal(exec_results.goal)
            self.analysis_dumper.set_plan(plan)

        for step in range(1, max_steps + 1):
            self.logger.info(f"📍 Execution loop step {step}/{max_steps}")

            # Build prompt for next tool execution
            system_prompt, user_prompt = self._build_execution_loop_prompt(exec_results, step)

            # DSPy returns typed actions, completion state, and an optional
            # question. No EXECUTE/ASK_USER text parsing is needed here.
            print(f"[Bridge] Execution Loop Step {step}: Requesting AI decision...")
            decision = self.dspy_program.decide(system_prompt, user_prompt)
            reasoning = decision.reasoning.strip()
            commands = [(action.tool, dict(action.parameters)) for action in decision.actions]
            print(f"[Bridge] Received {len(commands)} typed action(s)")
            self.logger.info("Received execution decision: %d action(s), complete=%s", len(commands), decision.complete)

            if reasoning:
                self.logger.info(f"🤔 Reasoning: {reasoning}")

            if decision.complete:
                if commands:
                    self.logger.warning("Ignoring complete=True because the same decision contains tool actions")
                else:
                    self.logger.info("✅ AI indicates investigation is complete")
                    exec_results.investigation_complete = True
                    exec_results.completed_at = datetime.now()
                    break

            if decision.question:
                question = UserQuestion(
                    question=decision.question,
                    header=decision.question[:30],
                    options=decision.question_options,
                )
                self.logger.info(f"❓ AI asks: {question.question}")
                self._emit_cot("Question", f"❓ AI asks: {question.question}")
                if self._ui_question_callback:
                    self._ui_question_callback(question)
                exec_results.pending_question = question
                break

            # Live CoT View - emit reasoning to both terminal and UI
            if reasoning and getattr(self.config.ollama, "show_reasoning", True):
                self._emit_cot("Reasoning", f"REASONING: {reasoning}")

            # Check if any commands were extracted
            if not commands:
                self.logger.warning(f"[WARN] No tool call found in response at step {step}")
                # Give AI one more chance
                if step < max_steps:
                    continue
                else:
                    break

            # Execute tools (Batching Support)
            for cmd_name, cmd_params in commands:
                # CRITICAL: Reset filtering state at start of each iteration
                # This prevents stale data from previous iterations leaking into cache
                full_result_before_filter = None

                # --- PRE-EXECUTION GATE CHECK ---
                gate_signal = self.execution_gate.check_before_execution(cmd_name, cmd_params, exec_results.tool_executions)
                if gate_signal == ExecutionSignal.PAUSE:
                    gate = self.execution_gate.get_gate_reason()
                    if gate:
                        exec_results.gates_triggered.append(gate)
                        self._emit_gate(gate)
                    self.logger.warning(f"🚧 Pre-execution gate paused loop at step {step}")
                    # Phase 1: Log and continue (Phase 2 will truly block)
                elif gate_signal == ExecutionSignal.ABORT:
                    gate = self.execution_gate.get_gate_reason()
                    if gate:
                        exec_results.gates_triggered.append(gate)
                        self._emit_gate(gate)
                    exec_results.investigation_complete = True
                    exec_results.completed_at = datetime.now()
                    return exec_results

                try:
                    # Generate signature for duplicate detection
                    param_sig = str(sorted(cmd_params.items())) if cmd_params else ""
                    cmd_signature = f"{cmd_name}:{param_sig}"

                    # Check for duplicate tool execution
                    # EXCEPTION: Never skip get_cached_result - AI should always be able to fetch cached context
                    if cmd_signature in self.executed_tools and cmd_name != "get_cached_result":
                        self.logger.warning(f"Skipping duplicate tool call: {cmd_name}({cmd_params})")

                        # Get original step info for helpful message (now includes loop prefix)
                        original_step_id, result_excerpt = self.step_result_map.get(cmd_signature, (None, None))

                        if original_step_id and result_excerpt:
                            # Include loop-prefixed step reference so AI clearly knows which loop it came from
                            skip_note = (
                                f"[Already executed in {original_step_id}. "
                                f"Result excerpt: {result_excerpt[:150]}... "
                                f'Use get_cached_result(result_id="{original_step_id}") for full content]'
                            )
                        else:
                            skip_note = "[Skipped - already executed with same parameters]"

                        tool_exec = ToolExecution(
                            tool_name=cmd_name,
                            parameters=cmd_params,
                            result=skip_note,
                            success=True,
                            reasoning=f"Duplicate call skipped: {reasoning}",
                        )
                        exec_results.add_execution(tool_exec)
                        continue

                    # Track this execution
                    self.executed_tools.add(cmd_signature)

                    self.logger.info(f"🔧 Executing: {cmd_name}({cmd_params})")

                    # Emit tool execution to UI
                    params_str = ", ".join(f"{k}={v}" for k, v in cmd_params.items()) if cmd_params else ""
                    self._emit_cot("Tool", f"Executing: {cmd_name}({params_str})")

                    # Execute the tool
                    result = self.execute_command(cmd_name, cmd_params)

                    # AUTOMATIC CONTINUATION: Fetch remaining lines for truncated decompilation
                    # If decompilation shows "[Total Lines: X] [Showing Lines: 1-Y]" where Y < X,
                    # automatically fetch the remaining lines
                    if cmd_name in ["decompile_function", "decompile_function_by_address"]:
                        result_str = str(result)
                        # Check for truncation pattern: [Total Lines: 427] [Showing Lines: 1-100]
                        match = re.search(r"\[Total Lines: (\d+)\].*\[Showing Lines: \d+-(\d+)\]", result_str)
                        if match:
                            total_lines = int(match.group(1))
                            shown_lines = int(match.group(2))

                            if shown_lines < total_lines:
                                remaining = total_lines - shown_lines
                                self.logger.info(
                                    f"🔄 Auto-continuation: Fetching remaining {remaining} lines (shown: {shown_lines}/{total_lines})"
                                )

                                try:
                                    # Fetch the rest in one call
                                    remaining_result = self.execute_command(
                                        cmd_name, {**cmd_params, "offset": shown_lines, "limit": remaining}
                                    )

                                    # Combine results
                                    if isinstance(result, str) and isinstance(remaining_result, str):
                                        # Remove header from continuation
                                        remaining_clean = re.sub(r"\[Total Lines:.*?\].*?\n", "", remaining_result, count=1)
                                        result = result + "\n" + remaining_clean
                                        self.logger.info(
                                            f"[OK] Auto-continuation complete: Now showing all {total_lines} lines"
                                        )

                                except Exception as e:
                                    self.logger.warning(f"[WARN] Auto-continuation failed: {e}. Original result kept.")

                    # EXECUTION-PHASE RANKING: Filter large results to preserve analysis context
                    LARGE_RESULT_TOOLS = ["list_functions", "list_imports", "list_strings", "list_exports"]
                    RANKING_THRESHOLD = 100  # Filter if result has >100 items

                    if cmd_name in LARGE_RESULT_TOOLS:
                        # Check if result is large enough to warrant filtering
                        item_count = 0
                        if isinstance(result, list):
                            item_count = len(result)
                        elif isinstance(result, dict):
                            item_count = (
                                len(result.get("items", []))
                                or len(result.get("functions", []))
                                or len(result.get("imports", []))
                            )

                        if item_count > RANKING_THRESHOLD:
                            self.logger.info(f"📊 Large result detected ({item_count} items), applying execution-phase ranking")

                            # IMPORTANT: Store full result BEFORE filtering
                            # This ensures get_cached_result() can access the complete data
                            full_result_before_filter = result

                            # Filter result to top 20 most relevant items
                            filtered_result = self._execution_agent_rank(
                                tool_name=cmd_name, result=result, goal=exec_results.goal, max_items=20
                            )

                            # Replace result with filtered version for analysis
                            result = filtered_result

                            # Add a note about the filtering so the user/agent knows
                            if isinstance(result, list):
                                result.append(f"... (Showing top 20 of {item_count} items. Full list cached.)")
                            elif isinstance(result, dict) and "items" in result:
                                result["note"] = f"Showing top 20 of {item_count} items. Full list cached."

                            self.logger.info(
                                f"💾 Using filtered version for analysis ({len(result) if isinstance(result, list) else 'dict'} items)"
                            )

                    # Display the result to the user
                    self._display_tool_result(cmd_name, result)

                    # Format result
                    if isinstance(result, (dict, list)):
                        result_str = json.dumps(result, indent=2)
                    else:
                        result_str = str(result)

                    # Deterministic compaction: reduce prompt size and LLM load.
                    # Full result is cached separately via full_result_str.
                    prompt_result_str = result_str
                    if self.result_compactor is not None:
                        try:
                            prompt_result_str = self.result_compactor.compact(cmd_name, result)
                        except Exception:
                            prompt_result_str = result_str

                    # Store the full result for caching before truncation
                    # If ranking was applied, cache the ORIGINAL unfiltered result
                    if full_result_before_filter is not None:
                        if isinstance(full_result_before_filter, (dict, list)):
                            full_result_str = json.dumps(full_result_before_filter, indent=2)
                        else:
                            full_result_str = str(full_result_before_filter)
                    else:
                        full_result_str = result_str

                    # Generate step ID early so we can reference it in truncation message
                    # Use loop-prefixed ID: step_L{loop}_{step} for unambiguous cross-loop references
                    current_step = exec_results.total_steps + 1
                    loop_step_id = f"step_L{self.current_loop_number}_{current_step}"

                    # Capture full result in analysis dump BEFORE truncation
                    was_truncated = False
                    truncated_to = 0

                    # Dynamic truncation based on context budget from config
                    # This scales with CONTEXT_BUDGET from .env
                    max_result_chars = self._get_max_result_chars()
                    logging.debug(f"[Context Budget] Allocated for result: {max_result_chars} chars")

                    if len(prompt_result_str) > max_result_chars:
                        was_truncated = True
                        truncated_to = max_result_chars
                        original_len = len(prompt_result_str)
                        dropped_chars = original_len - max_result_chars

                        logging.warning(
                            f"[TRUNCATION] Result too large: {original_len} chars > limit {max_result_chars}. Dropped {dropped_chars} chars."
                        )
                        logging.warning(f"[TRUNCATION] Full content cached with ID: {loop_step_id}")

                        prompt_result_str = prompt_result_str[:max_result_chars] + (
                            f"\n... [Truncated {dropped_chars} chars. "
                            f'Use get_cached_result(result_id="{loop_step_id}") for full content]'
                        )

                    # Add to analysis dump for manual review (captures full result)
                    if hasattr(self, "analysis_dumper") and self.analysis_dumper:
                        self.analysis_dumper.add_execution(
                            tool_name=cmd_name,
                            parameters=cmd_params,
                            result=full_result_str,  # Full result before truncation
                            reasoning=reasoning,
                            was_truncated=was_truncated,
                            truncated_to=truncated_to,
                        )

                    # Add to execution results
                    tool_exec = ToolExecution(
                        tool_name=cmd_name, parameters=cmd_params, result=prompt_result_str, success=True, reasoning=reasoning
                    )
                    exec_results.add_execution(tool_exec)

                    # Store step result for duplicate reference and caching
                    result_excerpt = prompt_result_str[:200].replace("\n", " ").strip()
                    self.step_result_map[cmd_signature] = (loop_step_id, result_excerpt)

                    # Note: Automatic focus_function tracking was removed to prevent confusion
                    # during cross-reference analysis. Users should explicitly ask about
                    # "the current function" when needed.

                    # Cache FULL result with loop-prefixed ID for retrieval via get_cached_result
                    if self.context_manager and self.context_manager.result_cache:
                        self.context_manager.result_cache.store(
                            tool_name=cmd_name,
                            parameters=cmd_params,
                            result=full_result_str,  # Store full result, not truncated
                            custom_id=loop_step_id,
                        )

                    # Also add to session for tracking
                    self.session.add_tool_execution(
                        tool_name=cmd_name, parameters=cmd_params, result=prompt_result_str, success=True, reasoning=reasoning
                    )

                    # MALWARE PATTERN DETECTION: Check code/strings/disassembly in malware task mode
                    if (
                        self.task_mode_enabled
                        and self.task_mode == "malware"
                        and cmd_name
                        in ["decompile_function", "decompile_function_by_address", "disassemble_function", "list_strings"]
                        and self.enable_cag
                        and self.cag_manager
                    ):
                        try:
                            # Extract context for reporting
                            if cmd_name in ["decompile_function", "decompile_function_by_address", "disassemble_function"]:
                                context = cmd_params.get("address", cmd_params.get("name", "unknown"))
                            else:  # list_strings
                                context = f"strings_filter={cmd_params.get('filter', 'none')}"

                            # Fetch assembly if we're decompiling (for better pattern detection)
                            assembly_code = None
                            if cmd_name in ["decompile_function_by_address"] and "address" in cmd_params:
                                try:
                                    asm_result = self.ghidra_client.disassemble_function(cmd_params["address"])
                                    # disassemble_function returns a list, convert to string
                                    if isinstance(asm_result, list):
                                        assembly_code = "\n".join(asm_result)
                                    else:
                                        assembly_code = str(asm_result)
                                    self.logger.debug(f"Fetched assembly for pattern detection at {cmd_params['address']}")
                                except Exception as asm_err:
                                    self.logger.debug(f"Could not fetch assembly for pattern detection: {asm_err}")

                            # Run pattern detection
                            pattern_check = self.cag_manager.check_function_for_malware_patterns(
                                decompiled_code=full_result_str, assembly=assembly_code, function_address=str(context)
                            )

                            # Store result for prompt enhancement in next LLM call (ephemeral - 1 cycle)
                            if pattern_check.get("has_matches", False):
                                self.cag_manager._last_pattern_check_result = pattern_check
                                self.logger.info(f"🚨 Malware patterns detected in {context} ({cmd_name})")

                                # PERSISTENT: Store HIGH severity patterns in session state (survives pruning)
                                high_patterns = [m["pattern_name"] for m in pattern_check["matches"] if m["severity"] == "HIGH"]
                                if high_patterns and self.session:
                                    self.session.analysis_state.pattern_detections[str(context)] = high_patterns
                                    self.logger.debug(f"Stored {len(high_patterns)} HIGH patterns for {context} in session")

                                # Emit to UI if available
                                if pattern_check.get("matches"):
                                    high_count = sum(1 for m in pattern_check["matches"] if m["severity"] == "HIGH")
                                    pattern_names = [m["pattern_name"] for m in pattern_check["matches"][:2]]
                                    self._emit_cot(
                                        "Pattern Detection",
                                        f"🚨 {high_count} HIGH severity pattern(s) in {cmd_name}: {', '.join(pattern_names)}",
                                    )
                        except Exception as e:
                            self.logger.warning(f"Pattern detection failed: {e}")

                    # Update analysis state
                    self._update_analysis_state({"name": cmd_name, "params": cmd_params}, prompt_result_str)

                    # Auto-mark coverage from tool results
                    if self.coverage_tracker:
                        newly_covered = self.coverage_tracker.auto_mark_from_result(
                            tool_name=cmd_name, tool_params=cmd_params, result=prompt_result_str
                        )
                        if newly_covered:
                            self._emit_cot("Coverage", f"📋 Covered: {', '.join(newly_covered)}")

                    self.logger.info(f"Step {step} complete: {cmd_name}")

                    # --- POST-EXECUTION GATE CHECK ---
                    # Pass session for auto-artifact extraction
                    gate_signal = self.execution_gate.check_after_execution(
                        cmd_name, prompt_result_str, exec_results.tool_executions, session=self.session
                    )
                    if gate_signal == ExecutionSignal.PAUSE:
                        gate = self.execution_gate.get_gate_reason()
                        if gate:
                            exec_results.gates_triggered.append(gate)
                            self._emit_gate(gate)
                        self.logger.warning(f"🚧 Post-execution gate: critical artifact found in {cmd_name} result")
                        # Phase 1: Log and continue (Phase 2 will truly block)

                except Exception as e:
                    error_msg = f"ERROR: {str(e)}"
                    self.logger.error(f"❌ Error in execution loop step {step}: {error_msg}")

                    # Add error to execution results
                    tool_exec = ToolExecution(
                        tool_name=cmd_name,
                        parameters=cmd_params,
                        result=error_msg,
                        success=False,
                        error=error_msg,
                        reasoning=reasoning,
                    )
                    exec_results.add_execution(tool_exec)

                    # Continue to next command in batch
                    continue

        # Mark as complete
        if not exec_results.investigation_complete:
            exec_results.completed_at = datetime.now()
            self.logger.warning(f"[WARN] Execution loop ended after {step} steps (max reached)")

        plugin_context.data["execution_results"] = exec_results
        self.plugin_manager.run(PluginHook.AFTER_EXECUTION, plugin_context)
        exec_results = plugin_context.data.get("execution_results", exec_results)
        self.logger.info(f"[OK] Execution loop complete: {exec_results.total_steps} steps executed")
        return exec_results

    def _execution_agent_rank(self, tool_name: str, result: Any, goal: str, max_items: int = 20) -> Any:
        """Filter a large result using DSPy's typed index selection."""
        container_key = None
        if isinstance(result, list):
            items = result
        elif isinstance(result, dict):
            container_key = next(
                (key for key in ("items", "functions", "imports", "exports", "strings") if isinstance(result.get(key), list)),
                None,
            )
            if container_key is None:
                return result
            items = result[container_key]
        else:
            return result

        preview_lines = []
        preview_size = 0
        for index, item in enumerate(items):
            line = f"{index}: {str(item)[:500]}"
            if preview_size + len(line) > 12000:
                break
            preview_lines.append(line)
            preview_size += len(line)

        try:
            indices = self.dspy_program.rank(goal, tool_name, "\n".join(preview_lines), max_items)
            indices = list(dict.fromkeys(index for index in indices if 0 <= index < len(items)))
            if not indices:
                return result
            selected = [items[index] for index in indices]
            if container_key is None:
                return selected
            filtered = dict(result)
            filtered[container_key] = selected
            return filtered
        except Exception as exc:
            self.logger.warning("Execution ranking failed: %s", exc)
            return result

    def _build_execution_loop_prompt(self, exec_results: ExecutionPhaseResults, current_step: int) -> Tuple[str, str]:
        """Build the dynamic evidence state for a typed DSPy execution decision."""
        system_prompt, _ = self._build_phase_context(phase="execution")
        loop_num = self.current_loop_number
        sections = [
            f"## Goal\n{exec_results.goal}",
            f"## Plan\n{exec_results.plan}",
            f"## Progress\nCycle {loop_num}, decision {current_step}; "
            f"{exec_results.total_steps} tool actions completed this cycle.",
        ]

        previous = [
            (step_id, excerpt)
            for step_id, excerpt in self.step_result_map.values()
            if not step_id.startswith(f"step_L{loop_num}_")
        ]
        if previous:
            lines = [f"- {step_id}: {excerpt[:100]}" for step_id, excerpt in previous[:5]]
            sections.append("## Earlier-cycle evidence (cached)\n" + "\n".join(lines))

        if exec_results.tool_executions:
            lines = []
            for index, execution in enumerate(exec_results.tool_executions, 1):
                preview = str(execution.result)
                if len(preview) > 500:
                    preview = preview[:500] + "…"
                lines.append(
                    f"step_L{loop_num}_{index}: {execution.tool_name}({execution.parameters})\nResult: {preview}"
                )
            sections.append("## Current-cycle evidence\n" + "\n\n".join(lines))

        if self.task_mode_enabled and self.coverage_tracker:
            sections.append(self.coverage_tracker.format_for_prompt())
        if self.task_mode_enabled and self.lead_tracker:
            if exec_results.analysis_dump:
                self.lead_tracker.parse_analysis_dump(exec_results.analysis_dump)
            sections.append(self.lead_tracker.format_for_prompt())
        if self.grep_layer_enabled:
            sections.append(
                "Hybrid search is available for behavioral function discovery; "
                "decompile relevant matches before treating them as evidence."
            )

        sections.append(
            "Choose the next necessary tool actions. Ask a question only if a user choice is required. "
            "Set complete only when the evidence is sufficient to answer the goal."
        )
        return system_prompt, "\n\n".join(section for section in sections if section)

    def _analyze_execution_results(self, exec_results: ExecutionPhaseResults) -> str:
        """
        Analysis phase: Review all execution results and provide comprehensive analysis.

        Uses a HYBRID approach with per-cycle isolation:
        - Filters to current cycle's results only
        - Applies relevance ranking (top-N per category)
        - Builds correlation hints for cross-tool patterns
        - Phase 3a: Consolidate findings into structured JSON
        - Phase 3b: Synthesize final report from consolidated data
        - Stores CycleConclusions for next planning phase

        Args:
            exec_results: Accumulated results from execution loop

        Returns:
            Final analysis response
        """
        self.logger.info("📊 Starting analysis phase (hybrid approach)")
        plugin_context = self._run_plugin_hook(
            PluginHook.BEFORE_ANALYSIS,
            cycle=self.current_loop_number,
            execution_results=exec_results,
        )
        exec_results = plugin_context.data.get("execution_results", exec_results)

        # Import the hybrid context components
        from src.context_manager import RelevanceRanker, CorrelationHintBuilder

        # Reset context manager for fresh budget tracking
        self.context_manager.reset()

        # STEP 1: Filter to current cycle only
        current_cycle = self.current_loop_number
        current_cycle_executions = [
            te for te in exec_results.tool_executions if getattr(te, "loop_number", current_cycle) == current_cycle
        ]
        self.logger.info(
            f"📍 Filtering to cycle {current_cycle}: {len(current_cycle_executions)}/{len(exec_results.tool_executions)} executions"
        )

        # STEP 2: Apply relevance ranking
        top_n = getattr(self.llm_config, "top_n_per_category", 10)
        ranker = RelevanceRanker(top_n_per_category=top_n)
        ranked_results = ranker.rank_results(current_cycle_executions, exec_results.goal)
        max_chars_per_cat = getattr(self.llm_config, "ranked_max_chars_per_category", 800)
        formatted_ranked = ranker.format_ranked_for_prompt(
            ranked_results,
            max_chars_per_category=max_chars_per_cat,
        )

        # STEP 3: Build correlation hints
        min_mentions = getattr(self.llm_config, "min_correlation_mentions", 2)
        correlator = CorrelationHintBuilder(min_mentions=min_mentions)
        correlation_hints = correlator.build_hints(current_cycle_executions)
        max_corr_hints = getattr(self.llm_config, "correlation_max_hints", 8)
        formatted_hints = correlator.format_for_prompt(correlation_hints, max_hints=max_corr_hints)

        self.logger.info(
            f"📊 Ranked: {sum(len(v) for v in ranked_results.values())} results across {len(ranked_results)} categories"
        )
        self.logger.info(f"🔗 Correlations: {len(correlation_hints)} cross-tool patterns found")

        # STEP 4: Consolidate findings with ranked results + hints
        consolidated_findings = self._consolidate_findings_hybrid(
            exec_results=exec_results, formatted_ranked=formatted_ranked, formatted_hints=formatted_hints
        )

        # STEP 5: Synthesize final report and extract conclusions
        response, cycle_conclusions = self._synthesize_report_with_conclusions(
            findings=consolidated_findings,
            goal=exec_results.goal,
            cycle_number=current_cycle,
            correlation_hints=correlation_hints,
        )

        # STEP 6: Store conclusions for next planning phase
        if not hasattr(self, "cycle_conclusions_history"):
            self.cycle_conclusions_history = []
        if cycle_conclusions:
            self.cycle_conclusions_history.append(cycle_conclusions)
            self.last_cycle_conclusions = cycle_conclusions
            self.logger.info(f"[NOTE] Stored conclusions for cycle {current_cycle}")
        else:
            self.logger.warning(f"[WARN] No conclusions generated for cycle {current_cycle}")

        # Clean up the response
        final_response = self._clean_final_response(response)

        self.logger.info("✅ Analysis phase complete (hybrid approach)")

        # Save analysis dump for manual review
        if hasattr(self, "analysis_dumper") and self.analysis_dumper:
            try:
                # Add consolidated findings and conclusions to the dump
                self.analysis_dumper.add_artifact(
                    "analysis", "consolidated_findings", json.dumps(consolidated_findings, indent=2)
                )
                self.analysis_dumper.add_artifact(
                    "analysis", "correlation_hints", json.dumps([h for h in correlation_hints[:10]], indent=2)
                )
                if cycle_conclusions:
                    self.analysis_dumper.add_artifact("analysis", "cycle_conclusions", cycle_conclusions.format_for_planning())
                dump_path = self.analysis_dumper.save()
                self.logger.info(f"📝 Analysis dump saved to: {dump_path}")
            except Exception as e:
                self.logger.warning(f"Failed to save analysis dump: {e}")

        plugin_context.response = final_response
        plugin_context.data["consolidated_findings"] = consolidated_findings
        self.plugin_manager.run(PluginHook.AFTER_ANALYSIS, plugin_context)
        return plugin_context.response

    def _generate_minimal_findings_from_raw(
        self, exec_results: ExecutionPhaseResults, formatted_ranked: str, formatted_hints: str
    ) -> dict:
        """
        Generate minimal structured findings when LLM consolidation fails or returns empty.
        Parses raw results directly to extract basic information.

        Args:
            exec_results: Execution results
            formatted_ranked: Ranked results string
            formatted_hints: Correlation hints string

        Returns:
            Minimal findings dict
        """
        self.logger.info("📝 Generating minimal findings from raw execution results...")

        findings = {
            "binary_purpose": f"Binary analyzed with {exec_results.total_steps} tool executions",
            "security_apis": [],
            "investigation_leads": [],
            "artifacts": [],
            "key_functions": [],
            "investigation_gaps": ["LLM consolidation returned empty response - manual review recommended"],
            "recommended_next_steps": [],
        }

        # Extract tool names and build next steps
        tool_names = list(set([te.tool_name for te in exec_results.tool_executions]))
        if tool_names:
            findings["recommended_next_steps"].append(f"Review results from: {', '.join(tool_names[:5])}")

        # Parse formatted_ranked for addresses and API names
        import re

        # Look for API names in imports
        api_matches = re.findall(r"(\w+)\s*->\s*EXTERNAL:([0-9a-fA-F]+)", formatted_ranked)
        for api_name, address in api_matches[:10]:
            findings["security_apis"].append(
                {"address": f"EXTERNAL:{address}", "name": api_name, "context": "Imported API (from raw results)"}
            )

        # Look for function addresses
        func_matches = re.findall(r"(FUN_[0-9a-fA-F]{8}|0x[0-9a-fA-F]{6,})", formatted_ranked)
        for func in set(func_matches[:10]):
            findings["key_functions"].append(
                {
                    "address": func,
                    "name": func if func.startswith("FUN_") else f"FUN_{func}",
                    "purpose": "Identified in analysis (review recommended)",
                }
            )

        # Look for memory addresses in correlations
        if formatted_hints:
            addr_matches = re.findall(r"0x([0-9a-fA-F]{6,})", formatted_hints)
            for addr in set(addr_matches[:5]):
                findings["investigation_leads"].append(
                    {
                        "address": f"0x{addr}",
                        "observation": "Appears in multiple tool results (correlation detected)",
                        "hypothesis": "May be significant function or data location",
                        "priority": "MEDIUM",
                        "next_step": f"Decompile or investigate 0x{addr}",
                    }
                )

        # Add recommendation to review full results
        findings["recommended_next_steps"].append("Use get_cached_result() to retrieve full tool outputs")
        findings["recommended_next_steps"].append("Re-run analysis with different model or higher token limit")

        self.logger.info(
            f"✅ Generated minimal findings: {len(findings['security_apis'])} APIs, "
            f"{len(findings['key_functions'])} functions, "
            f"{len(findings['investigation_leads'])} leads"
        )

        return findings

    def _consolidate_findings_hybrid(
        self, exec_results: ExecutionPhaseResults, formatted_ranked: str, formatted_hints: str
    ) -> dict:
        """Consolidate ranked evidence through DSPy's typed output contract."""
        self.logger.info("🔍 Phase 3a: Consolidating findings with DSPy...")
        try:
            findings = self.dspy_program.consolidate(
                goal=exec_results.goal,
                ranked_evidence=formatted_ranked,
                correlations=formatted_hints,
            )
            self.logger.info(
                "✅ Consolidated: %d APIs, %d leads, %d gaps",
                len(findings["security_apis"]),
                len(findings["investigation_leads"]),
                len(findings["investigation_gaps"]),
            )
            return findings
        except Exception as exc:
            self.logger.warning("DSPy evidence consolidation failed: %s", exc)
            return self._generate_minimal_findings_from_raw(exec_results, formatted_ranked, formatted_hints)



    def _synthesize_report(self, findings: dict, goal: str) -> str:
        """Render typed findings as the final evidence-based report."""
        self.logger.info("📝 Phase 3b: Synthesizing final report with DSPy...")
        guidance = (
            "Write a complete, concise Markdown reverse-engineering report. "
            "Directly answer the goal, distinguish evidence from hypotheses, cite addresses, "
            "identify important gaps, and end with concrete next steps."
        )
        evidence = f"Goal:\n{goal}\n\nStructured findings:\n{json.dumps(findings, indent=2)}"
        try:
            response = self.dspy_program.analyze(
                guidance=guidance,
                evidence=evidence,
                max_tokens=getattr(self.llm_config, "analysis_report_max_tokens", 1600),
            )
            return response if response and response.strip() else self._generate_fallback_report(findings, goal)
        except Exception as exc:
            self.logger.error("Report synthesis failed: %s", exc)
            return self._generate_fallback_report(findings, goal, error=str(exc))

    def _generate_fallback_report(self, findings: dict, goal: str, error: str = None) -> str:
        """
        Generate a comprehensive fallback report when LLM synthesis fails or returns empty.

        Args:
            findings: Consolidated findings dict
            goal: Original investigation goal
            error: Optional error message if synthesis failed

        Returns:
            Formatted report string
        """
        report_lines = []

        if error:
            report_lines.append(f"## Analysis Report (Synthesis Error: {error})")
            report_lines.append("")
        else:
            report_lines.append("## Analysis Report")
            report_lines.append("*(Generated from structured findings due to empty LLM response)*")
            report_lines.append("")

        # Binary Purpose
        report_lines.append("### Binary Purpose")
        report_lines.append(findings.get("binary_purpose", "Unknown"))
        report_lines.append("")

        # Security APIs
        security_apis = findings.get("security_apis", [])
        if security_apis:
            report_lines.append(f"### Security APIs ({len(security_apis)} found)")
            for api in security_apis[:10]:
                report_lines.append(f"- **{api.get('name', 'Unknown')}** @ `{api.get('address', 'unknown')}`")
                report_lines.append(f"  {api.get('context', '')}")
            report_lines.append("")

        # Investigation Leads
        leads = findings.get("investigation_leads", [])
        if leads:
            report_lines.append(f"### Investigation Leads ({len(leads)} identified)")
            for lead in leads[:10]:
                priority = lead.get("priority", "MEDIUM")
                emoji = "🔴" if priority == "HIGH" else "🟡" if priority == "MEDIUM" else "🟢"
                report_lines.append(f"{emoji} **{lead.get('address', 'unknown')}** [{priority}]")
                report_lines.append(f"  - Observation: {lead.get('observation', '')}")
                report_lines.append(f"  - Hypothesis: {lead.get('hypothesis', '')}")
                report_lines.append(f"  - Next Step: {lead.get('next_step', '')}")
                report_lines.append("")

        # Key Functions
        functions = findings.get("key_functions", [])
        if functions:
            report_lines.append(f"### Key Functions ({len(functions)} identified)")
            for func in functions[:10]:
                report_lines.append(f"- **{func.get('name', 'Unknown')}** @ `{func.get('address', 'unknown')}`")
                report_lines.append(f"  {func.get('purpose', '')}")
            report_lines.append("")

        # Artifacts
        artifacts = findings.get("artifacts", [])
        if artifacts:
            report_lines.append(f"### Artifacts ({len(artifacts)} found)")
            for artifact in artifacts[:10]:
                report_lines.append(f"- **{artifact.get('type', 'unknown')}** @ `{artifact.get('address', 'unknown')}`")
                report_lines.append(f"  `{artifact.get('value', '')}`")
            report_lines.append("")

        # Investigation Gaps
        gaps = findings.get("investigation_gaps", [])
        if gaps:
            report_lines.append("### Investigation Gaps")
            for gap in gaps[:5]:
                report_lines.append(f"- {gap}")
            report_lines.append("")

        # Recommended Next Steps
        next_steps = findings.get("recommended_next_steps", [])
        if next_steps:
            report_lines.append("### Recommended Next Steps")
            for i, step in enumerate(next_steps[:5], 1):
                report_lines.append(f"{i}. {step}")
            report_lines.append("")

        # Conclusion
        report_lines.append("### Conclusion")
        high_priority_count = len([line for line in leads if line.get("priority") == "HIGH"])
        if high_priority_count > 0:
            report_lines.append(f"Found {high_priority_count} high-priority investigation leads that warrant further analysis.")
        report_lines.append(
            f"Analysis identified {len(functions)} key functions and {len(security_apis)} security-relevant APIs."
        )
        if gaps:
            report_lines.append(f"There are {len(gaps)} investigation gaps that require additional analysis.")

        return "\n".join(report_lines)

    def _synthesize_report_with_conclusions(
        self, findings: dict, goal: str, cycle_number: int, correlation_hints: list
    ) -> Tuple[str, Any]:
        """
        Phase 3b: Generate final report AND extract CycleConclusions for next planning.

        This method produces both the user-facing report and structured conclusions
        that feed into the next cycle's planning phase.

        Args:
            findings: Consolidated findings from hybrid consolidation
            goal: Original investigation goal
            cycle_number: Current cycle number
            correlation_hints: List of correlation hint dicts

        Returns:
            Tuple of (report_text, CycleConclusions)
        """
        from src.models.memory import CycleConclusions

        self.logger.info("📝 Phase 3b: Synthesizing report with conclusions...")

        # Generate the report using standard method
        report = self._synthesize_report(findings, goal)

        # Extract CycleConclusions from findings
        key_findings = []

        # Add security APIs as findings
        for api in findings.get("security_apis", [])[:5]:
            key_findings.append(
                {
                    "address": api.get("address", "unknown"),
                    "finding": f"API: {api.get('name', 'unknown')} - {api.get('context', '')}",
                    "confidence": "HIGH",
                }
            )

        # Add investigation leads as findings
        for lead in findings.get("investigation_leads", [])[:5]:
            key_findings.append(
                {
                    "address": lead.get("address", "unknown"),
                    "finding": f"{lead.get('observation', '')} - {lead.get('hypothesis', '')}",
                    "confidence": lead.get("priority", "MEDIUM"),
                }
            )

        # Extract correlation insights
        correlation_insights = []
        for hint in correlation_hints[:5]:
            if hint.get("significance") in ["HIGH", "MEDIUM"]:
                mentions_summary = ", ".join(m.split(":")[0] for m in hint.get("mentions", [])[:3])
                correlation_insights.append(f"{hint.get('address', '?')} appears in: {mentions_summary}")

        # Build CycleConclusions
        conclusions = CycleConclusions(
            cycle_number=cycle_number,
            binary_purpose=findings.get("binary_purpose", "Unknown"),
            key_findings=key_findings,
            investigation_gaps=findings.get("investigation_gaps", []),
            recommended_next_steps=findings.get("recommended_next_steps", []),
            correlation_insights=correlation_insights,
            tools_executed=len(findings.get("key_functions", [])),  # Rough proxy
        )

        self.logger.info(
            f"✅ Cycle {cycle_number} conclusions: "
            f"{len(key_findings)} findings, "
            f"{len(correlation_insights)} correlations, "
            f"{len(conclusions.investigation_gaps)} gaps"
        )

        return report, conclusions

    def _evaluate_goal_achievement(self, goal: str, analysis: str, exec_results: ExecutionPhaseResults) -> Tuple[bool, str]:
        """
        Evaluate if the investigation goal has been achieved.

        This is used in the agentic loop to determine if another
        Planning→Execution→Analysis cycle is needed.

        Args:
            goal: The original user goal/query
            analysis: The analysis response from current cycle
            exec_results: All execution results from current cycle

        Returns:
            Tuple of (goal_achieved: bool, reason: str)
        """
        self.logger.info("🔍 Evaluating goal achievement...")
        plugin_context = self._run_plugin_hook(
            PluginHook.BEFORE_EVALUATION,
            query=goal,
            response=analysis,
            cycle=self.current_loop_number,
            execution_results=exec_results,
        )
        goal = plugin_context.query
        analysis = plugin_context.response
        exec_results = plugin_context.data.get("execution_results", exec_results)

        # Smart truncation: preserve beginning (context) AND end (conclusions)
        # The conclusion is critical for goal evaluation and often appears at the end
        EVAL_MAX_CHARS = 4000
        PRESERVE_START = 2000
        PRESERVE_END = 1500

        if len(analysis) > EVAL_MAX_CHARS:
            has_conclusion = any(
                marker in analysis.lower()
                for marker in ["conclusion", "summary", "in summary", "overall assessment", "investigation complete"]
            )

            truncated_analysis = (
                f"{analysis[:PRESERVE_START]}\n\n"
                f"[... {len(analysis) - PRESERVE_START - PRESERVE_END:,} chars truncated for evaluation ...]\n\n"
                f"{analysis[-PRESERVE_END:]}"
            )

            # Add completion signal hints
            completion_hints = []
            if has_conclusion:
                completion_hints.append("Contains conclusion/summary section")
            if completion_hints:
                truncated_analysis += f"\n\n[Completion signals detected: {', '.join(completion_hints)}]"
        else:
            truncated_analysis = analysis

        user_prompt = f"""
## Original User Goal
{goal}

## Investigation Summary (Current Cycle)
- Total tools executed: {exec_results.total_steps}
- Investigation marked complete by AI: {exec_results.investigation_complete}
- Tools used: {", ".join([te.tool_name for te in exec_results.tool_executions])}

## Analysis Provided
{truncated_analysis}

## Your Task

Evaluate if the original goal has been **completely and thoroughly** achieved based on the analysis above.

Consider:
1. Does the analysis directly answer the user's question?
2. Is the information comprehensive and complete?
3. Are there obvious gaps or missing details?
4. Would the user be satisfied with this response?

Be strict: set goal_achieved only when the goal is fully and completely
satisfied, and explain any remaining gap in one concise sentence.
"""

        evaluation_guidance = (
            "Evaluate completion conservatively. Analysis alone does not satisfy a goal that requested a mutation; "
            "the corresponding tool must have completed successfully. Return the typed DSPy fields."
        )
        goal_achieved, reason = self.dspy_program.evaluate(evaluation_guidance, user_prompt)

        plugin_context.data["goal_achieved"] = goal_achieved
        plugin_context.data["evaluation_reason"] = reason
        self.plugin_manager.run(PluginHook.AFTER_EVALUATION, plugin_context)
        goal_achieved = bool(plugin_context.data.get("goal_achieved", goal_achieved))
        reason = str(plugin_context.data.get("evaluation_reason", reason))

        self.logger.info(
            f"{'[OK]' if goal_achieved else '[WARN]'} Evaluation: {'Achieved' if goal_achieved else 'Not achieved'}"
        )
        if not goal_achieved:
            self.logger.info(f"   Reason: {reason}")

        return goal_achieved, reason


    def _add_function_to_rag(self, function_identifier: str, func_data: Dict[str, Any]) -> int:
        """
        Add a function with enhanced metadata as a RAG vector AND to the knowledge graph.

        Args:
            function_identifier: Function address or name identifier
            func_data: Complete function data dict with metadata
        """
        added_count = 0
        try:
            self.logger.info(f"DEBUG: _add_function_to_rag called for {function_identifier}")

            # ============ KNOWLEDGE GRAPH: Add function to graph ============
            if self.function_graph and "address" in func_data:
                try:
                    address = func_data["address"]
                    name = func_data.get("new_name", function_identifier)
                    self.function_graph.add_function(address, name, func_data)
                    self.logger.debug(f"📊 Added {name} to Knowledge Graph")
                except Exception as graph_error:
                    self.logger.warning(f"Failed to add to graph: {graph_error}")

            # Check if CAG manager is available and RAG is enabled
            has_cag = hasattr(self, "cag_manager") and self.cag_manager
            rag_enabled = getattr(self.cag_manager, "use_vector_store_for_prompts", True) if has_cag else False

            self.logger.info(f"DEBUG: has_cag_manager: {has_cag}, rag_enabled: {rag_enabled}")

            if not (has_cag and rag_enabled):
                self.logger.warning(f"DEBUG: Skipping RAG integration - has_cag: {has_cag}, rag_enabled: {rag_enabled}")
                return 0

            # Build rich RAG documents when metadata is available.
            try:
                from src.rag_document_builder import RAGDocumentBuilder

                builder = RAGDocumentBuilder()

                # Check if we should use multi-vector (configurable)
                use_multi_vector = getattr(self.config, "use_multi_vector_rag", False) if hasattr(self, "config") else False

                if use_multi_vector:
                    # Build multiple focused vectors per function
                    rag_documents = builder.build_multi_vector_documents(func_data)
                else:
                    # Build single comprehensive document
                    rag_documents = [builder.build_primary_document(func_data)]

            except Exception as build_error:
                self.logger.error(f"Enhanced RAG document building failed: {build_error}")
                # Fall back to a minimal document if enrichment fails.
                new_name = func_data.get("new_name", function_identifier)
                old_name = func_data.get("old_name", "Unknown")
                summary = func_data.get("raw_summary", func_data.get("summary", ""))

                rag_documents = [
                    {
                        "title": f"Function: {new_name}",
                        "content": f"Address: {function_identifier}\nOriginal: {old_name}\nRenamed: {new_name}\n\n{summary}",
                        "metadata": {
                            "type": "function_analysis",
                            "address": function_identifier,
                            "new_name": new_name,
                        },
                    }
                ]

            # Add each document to vector store
            if hasattr(self.cag_manager, "vector_store") and self.cag_manager.vector_store:
                try:
                    import numpy as np

                    for rag_doc in rag_documents:
                        # Generate embedding
                        content_text = rag_doc["content"]
                        embeddings = Bridge.get_embeddings([content_text])
                        if not embeddings:
                            self.logger.warning("Embedding service unavailable – skipping this document")
                            continue

                        embedding = np.array(embeddings[0], dtype=np.float32)

                        # Convert to SimpleVectorStore format
                        vector_doc = {
                            "text": content_text,
                            "type": rag_doc["metadata"].get("type", "function_analysis"),
                            "name": rag_doc["metadata"].get("new_name", "unknown"),
                            "metadata": rag_doc["metadata"],
                        }

                        # Add document
                        self.cag_manager.vector_store.documents.append(vector_doc)

                        # Add embedding
                        if (
                            isinstance(self.cag_manager.vector_store.embeddings, list)
                            and len(self.cag_manager.vector_store.embeddings) > 0
                        ):
                            if isinstance(self.cag_manager.vector_store.embeddings[0], np.ndarray):
                                self.cag_manager.vector_store.embeddings.append(embedding)
                            else:
                                embeddings_array = np.array(self.cag_manager.vector_store.embeddings)
                                new_embeddings = np.vstack([embeddings_array, embedding.reshape(1, -1)])
                                self.cag_manager.vector_store.embeddings = [
                                    new_embeddings[i] for i in range(len(new_embeddings))
                                ]
                        else:
                            self.cag_manager.vector_store.embeddings = [embedding]

                        added_count += 1

                    if added_count and hasattr(self.cag_manager.vector_store, "_build_faiss_index"):
                        self.cag_manager.vector_store._build_faiss_index()

                    new_name = func_data.get("new_name", function_identifier)
                    self.logger.info(f"✅ Successfully added {added_count} vector(s) for '{new_name}' to RAG")
                    self.logger.info(f"📊 Total documents: {len(self.cag_manager.vector_store.documents)}")

                    # Trigger memory panel refresh if UI is available
                    try:
                        if hasattr(self, "_ui_memory_panel_refresh"):
                            self._ui_memory_panel_refresh()
                    except Exception as e:
                        self.logger.debug(f"Could not refresh memory panel: {e}")

                except Exception as e:
                    self.logger.error(f"Error adding function to RAG: {e}")

        except Exception as e:
            self.logger.warning(f"Failed to add function to RAG vectors: {e}")
        return added_count

    def _get_current_timestamp(self) -> str:
        """Get current timestamp as string."""
        from datetime import datetime

        return datetime.now().isoformat()


    def _update_analysis_state(self, command: Dict[str, Any], result: str) -> None:
        """
        Update the internal analysis state based on the executed command and result.

        Args:
            command: The executed command
            result: The result of the command
        """
        # Only update state if command was successful
        if "ERROR" in result or "Failed" in result:
            return

        # Function summaries are produced by the dedicated bulk-analysis path,
        # not inferred from transient agent text.
        if command["name"] == "decompile_function_by_address" and "address" in command["params"]:
            address = command["params"]["address"]
            self.analysis_state["functions_decompiled"].add(address)
            # Don't add to functions_analyzed - decompilation is not the same as analysis
            # Only actual analysis commands should increment the analyzed count

        elif command["name"] == "analyze_function":
            # This is the actual analysis command that should increment the analyzed count
            address = command["params"].get("address")
            if address:
                # Only add to functions_analyzed if not already in functions_renamed
                # to avoid double-counting the same function
                if address not in self.analysis_state.get("functions_renamed", {}):
                    self.analysis_state["functions_analyzed"].add(address)

        # Track renamed functions
        elif command["name"] == "rename_function" and "old_name" in command["params"] and "new_name" in command["params"]:
            old_name = command["params"]["old_name"]
            new_name = command["params"]["new_name"]
            self.logger.info(f"DEBUG: Processing rename_function command: {old_name} -> {new_name}")

            # Smart address extraction - try multiple methods to get the correct address
            address = None

            # Method 1: Extract address from old_name if it contains hex pattern
            import re

            address_match = re.search(r"([0-9a-fA-F]{8,})", old_name)
            if address_match:
                address = address_match.group(1)
                self.logger.info(f"DEBUG: Extracted address from old_name: {address}")

            # Method 2: If no address in old_name, try get_current_function (single function rename scenario)
            if not address:
                try:
                    current_function_result = self.ghidra_client.get_current_function()
                    if isinstance(current_function_result, str) and "at " in current_function_result:
                        # Extract address from result like "Function: FUN_401000 at 401000"
                        match = re.search(r"at\s+([0-9a-fA-F]+)", current_function_result)
                        if match:
                            address = match.group(1)
                            self.logger.info(f"DEBUG: Extracted address from current_function: {address}")
                except Exception as e:
                    self.logger.warning(f"DEBUG: Failed to get current function: {e}")

            # Method 3: If still no address, try to get it from decompiling the function by name
            if not address:
                try:
                    decompile_result = self.ghidra_client.decompile_function(old_name)
                    if isinstance(decompile_result, str):
                        addr_match = re.search(r"([0-9a-fA-F]{8,})", decompile_result)
                        if addr_match:
                            address = addr_match.group(1)
                            self.logger.info(f"DEBUG: Extracted address from decompile_function: {address}")
                except Exception as e:
                    self.logger.warning(f"DEBUG: Failed to decompile function {old_name}: {e}")

            # Store the function rename information
            if address:
                # Use the real address as the key
                self.analysis_state["functions_renamed"][address] = new_name
                self.function_address_mapping[address] = {"old_name": old_name, "new_name": new_name}
                self.logger.info(f"DEBUG: Stored function mapping at address {address}: {old_name} -> {new_name}")

            else:
                # Fallback: no address found, use old_name as identifier
                self.analysis_state["functions_renamed"][old_name] = new_name
                fake_addr = f"name_{old_name}"
                self.function_address_mapping[fake_addr] = {"old_name": old_name, "new_name": new_name}
                self.logger.info(f"DEBUG: No address found, using fallback storage with fake_addr: {fake_addr}")

            self.logger.info(f"DEBUG: Total functions in analysis_state: {len(self.analysis_state['functions_renamed'])}")
            self.logger.info(f"DEBUG: Total functions in address_mapping: {len(self.function_address_mapping)}")

        elif (
            command["name"] == "rename_function_by_address"
            and "function_address" in command["params"]
            and "new_name" in command["params"]
        ):
            address = command["params"]["function_address"]
            new_name = command["params"]["new_name"]
            self.analysis_state["functions_renamed"][address] = new_name

            # Store complete function information
            self.function_address_mapping[address] = {"old_name": "Unknown", "new_name": new_name}

        # Track comments added
        elif (
            command["name"] in ["set_decompiler_comment", "set_disassembly_comment"]
            and "address" in command["params"]
            and "comment" in command["params"]
        ):
            self.analysis_state["comments_added"][command["params"]["address"]] = command["params"]["comment"]

        # Clean up any duplicates between functions_analyzed and functions_renamed
        self._cleanup_duplicate_function_tracking()

    def _cleanup_duplicate_function_tracking(self) -> None:
        """
        Clean up duplicate function tracking between functions_analyzed and functions_renamed.
        If a function is in both sets, prefer functions_renamed as it has more complete data.
        """
        if not hasattr(self, "analysis_state"):
            return

        functions_renamed = self.analysis_state.get("functions_renamed", {})
        functions_analyzed = self.analysis_state.get("functions_analyzed", set())

        # Remove any functions from functions_analyzed that are already in functions_renamed
        duplicates_to_remove = set()
        for analyzed_func in functions_analyzed:
            if analyzed_func in functions_renamed:
                duplicates_to_remove.add(analyzed_func)

        # Remove duplicates
        for duplicate in duplicates_to_remove:
            functions_analyzed.discard(duplicate)
            self.logger.debug(f"Removed duplicate function tracking: {duplicate} (kept in functions_renamed)")









    def add_to_context(self, role: str, content: str) -> None:
        """Add an entry to the structured session history.

        Args:
            role: The role of the entry ('user', 'assistant', 'tool_call', 'tool_result', etc.)
            content: The content of the entry
        """
        try:
            message_role = MessageRole(role.lower())
            self.session.add_message(message_role, content)
        except ValueError:
            # If role is not in MessageRole enum, default to SYSTEM
            self.logger.warning(f"Unknown role '{role}', defaulting to SYSTEM")
            self.session.add_message(MessageRole.SYSTEM, content)

    @property
    def ghidra(self):
        """Compatibility alias for integrations that predate ``ghidra_client``."""
        return self.ghidra_client

    def _get_latest_agent_analysis_text(self) -> str:
        """Retrieve the text analysis from the latest agent dump."""
        try:
            import glob
            import os

            # Use the configured logs directory
            logs_dir = self.analysis_dumper.logs_dir
            if not os.path.exists(logs_dir):
                return ""

            dump_files = glob.glob(os.path.join(logs_dir, "analysis_dump_*.md"))

            if not dump_files:
                return ""

            # Get the latest file
            latest_file = max(dump_files, key=os.path.getmtime)
            self.logger.info(f"Using analysis dump for report context: {latest_file}")

            with open(latest_file, "r", encoding="utf-8") as f:
                content = f.read()

            # Strategy 1: Look for "AI AGENT RESPONSE" section
            parts = content.split("AI AGENT RESPONSE")
            if len(parts) > 1:
                # Get the part after the header
                analysis_part = parts[-1]
                # Remove the separator line if present
                analysis_part = analysis_part.split("============================================================")[-1]
                return analysis_part.strip()

            # Strategy 2: Look for "Investigation Goal" and "Statistics" to exclude them
            # and return the rest if it looks like a report
            # But "Binary Analysis Report" is a common header in the response
            if "# Binary Analysis Report" in content:
                return content.split("# Binary Analysis Report", 1)[1]

            return ""

        except Exception as e:
            self.logger.warning(f"Failed to read latest analysis dump: {e}")
            return ""

    def generate_software_report(self, report_format: str = "markdown") -> str:
        """
        Generate a comprehensive software analysis report using AI-powered analysis.

        This method performs complete software behavior analysis including:
        - Software type classification and architecture analysis
        - Security risk assessment with detailed scoring
        - Function categorization and behavioral pattern analysis
        - Comprehensive findings summary with actionable insights

        Args:
            report_format: Output format ("markdown", "text", "json")

        Returns:
            Comprehensive software analysis report string
        """
        try:
            self.logger.info("Starting comprehensive software report generation")

            # Set workflow stage for UI integration
            self.current_workflow_stage = "planning"

            # Phase 1: Data Collection - Gather all available binary information
            self.logger.info("Phase 1: Collecting binary data...")
            report_data = self._collect_comprehensive_binary_data()

            # Phase 2: AI Analysis - Analyze collected data with specialized prompts
            self.current_workflow_stage = "analysis"
            self.logger.info("Phase 2: Performing AI-powered analysis...")
            analysis_results = self._perform_comprehensive_ai_analysis(report_data)

            # Phase 3: Report Generation - Structure and format the final report
            self.current_workflow_stage = "review"
            self.logger.info("Phase 3: Generating structured report...")
            final_report = self._generate_structured_software_report(report_data, analysis_results, report_format)

            # Clear workflow stage
            self.current_workflow_stage = None

            self.logger.info("Software report generation completed successfully")
            return final_report

        except Exception as e:
            self.logger.error(f"Error generating software report: {e}")
            self.current_workflow_stage = None
            return f"Error generating software report: {e}"

    def _collect_comprehensive_binary_data(self) -> Dict[str, Any]:
        """Collect all available binary data for analysis."""
        data = {
            "functions": [],
            "renamed_functions": [],
            "function_summaries": {},
            "function_addresses": {},  # Map function names to addresses
            "imports": [],
            "exports": [],
            "strings": [],
            "segments": [],
            "classes": [],
            "namespaces": [],
            "data_items": [],
            "analysis_state": self.analysis_state.copy(),
            "metadata": {"total_functions": 0, "renamed_count": 0, "analyzed_count": 0},
        }

        try:
            # Collect function information
            functions_result = self._collect_all_paginated_list_results(self.ghidra_client.list_functions)
            if isinstance(functions_result, list):
                data["functions"] = functions_result
            elif isinstance(functions_result, str) and not functions_result.startswith("ERROR:"):
                data["functions"] = [f.strip() for f in functions_result.split("\n") if f.strip()]

            # Parse function addresses from function names
            # Format is typically "address functionName" or just "functionName"
            import re

            for func in data["functions"]:
                # Try to extract address and name
                match = re.match(r"^(0x[0-9a-fA-F]+)\s+(.+)$", func)
                if match:
                    addr, name = match.groups()
                    data["function_addresses"][name] = addr
                    data["function_addresses"][func] = addr  # Also store by full string
                else:
                    # Try alternate formats: just address, or name@address
                    addr_match = re.search(r"(0x[0-9a-fA-F]+)", func)
                    if addr_match:
                        data["function_addresses"][func] = addr_match.group(1)

            data["metadata"]["total_functions"] = len(data["functions"])

            # Collect renamed functions from analysis state
            data["renamed_functions"] = list(self.analysis_state["functions_renamed"].items())
            data["metadata"]["renamed_count"] = len(data["renamed_functions"])

            # Collect function summaries
            data["function_summaries"] = self.function_summaries.copy()
            data["metadata"]["analyzed_count"] = len(data["function_summaries"])

            # Collect imports
            imports_result = self._collect_all_paginated_list_results(self.ghidra_client.list_imports)
            if isinstance(imports_result, (list, str)) and not str(imports_result).startswith("ERROR:"):
                if isinstance(imports_result, str):
                    data["imports"] = [i.strip() for i in imports_result.split("\n") if i.strip()]
                else:
                    data["imports"] = imports_result

            # Collect exports
            exports_result = self._collect_all_paginated_list_results(self.ghidra_client.list_exports)
            if isinstance(exports_result, (list, str)) and not str(exports_result).startswith("ERROR:"):
                if isinstance(exports_result, str):
                    data["exports"] = [e.strip() for e in exports_result.split("\n") if e.strip()]
                else:
                    data["exports"] = exports_result

            # Collect memory segments
            segments_result = self._collect_all_paginated_list_results(self.ghidra_client.list_segments)
            if isinstance(segments_result, (list, str)) and not str(segments_result).startswith("ERROR:"):
                if isinstance(segments_result, str):
                    data["segments"] = [s.strip() for s in segments_result.split("\n") if s.strip()]
                else:
                    data["segments"] = segments_result

            # Collect classes/namespaces
            classes_result = self._collect_all_paginated_list_results(self.ghidra_client.list_classes)
            if isinstance(classes_result, (list, str)) and not str(classes_result).startswith("ERROR:"):
                if isinstance(classes_result, str):
                    data["classes"] = [c.strip() for c in classes_result.split("\n") if c.strip()]
                else:
                    data["classes"] = classes_result
            namespaces_result = self._collect_all_paginated_list_results(self.ghidra_client.list_namespaces)
            if isinstance(namespaces_result, (list, str)) and not str(namespaces_result).startswith("ERROR:"):
                if isinstance(namespaces_result, str):
                    data["namespaces"] = [n.strip() for n in namespaces_result.split("\n") if n.strip()]
                else:
                    data["namespaces"] = namespaces_result

            # Collect data items
            data_items_result = self._collect_all_paginated_list_results(self.ghidra_client.list_data_items)
            if isinstance(data_items_result, (list, str)) and not str(data_items_result).startswith("ERROR:"):
                if isinstance(data_items_result, str):
                    data["data_items"] = [d.strip() for d in data_items_result.split("\n") if d.strip()]
                else:
                    data["data_items"] = data_items_result

            # Collect strings with addresses for evidence
            try:
                strings_result = self._collect_all_paginated_list_results(self.ghidra_client.list_strings)
                if isinstance(strings_result, list):
                    data["strings"] = strings_result  # JSON format likely includes addresses
                elif isinstance(strings_result, str) and not strings_result.startswith("ERROR:"):
                    data["strings"] = [s.strip() for s in strings_result.split("\n") if s.strip()]
            except Exception as string_err:
                self.logger.debug(f"Error collecting strings: {string_err}")

        except Exception as e:
            self.logger.warning(f"Error collecting some binary data: {e}")

        # Collect previous agent analysis for correlation
        data["agent_analysis_history"] = self._get_latest_agent_analysis_text()

        # Collect binary name and info
        try:
            program_info = self.ghidra_client.get_current_program_info()
            data["metadata"]["binary_name"] = program_info.get("name", "Unknown Binary")
            data["metadata"]["project_name"] = program_info.get("project", "Unknown Project")
            self.logger.info(f"Collected binary info: {data['metadata']['binary_name']}")
        except Exception as e:
            self.logger.warning(f"Failed to collect binary info: {e}")
            data["metadata"]["binary_name"] = "Unknown Binary"

        return data

    def _perform_comprehensive_ai_analysis(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze whole-program evidence through one typed DSPy signature."""
        evidence = {
            "metadata": data.get("metadata", {}),
            "imports": data.get("imports", [])[:200],
            "exports": data.get("exports", [])[:100],
            "strings": data.get("strings", [])[:200],
            "segments": data.get("segments", [])[:50],
            "classes": data.get("classes", [])[:100],
            "namespaces": data.get("namespaces", [])[:100],
            "renamed_functions": data.get("renamed_functions", [])[:200],
            "function_summaries": dict(list(data.get("function_summaries", {}).items())[:300]),
            "prior_agent_analysis": data.get("agent_analysis_history", "")[-12000:],
        }

        # Reuse the whole-program function index when available instead of
        # rebuilding ad-hoc prompt-specific retrieval pipelines.
        rag_context = []
        seen = set()
        vector_store = getattr(getattr(self, "cag_manager", None), "vector_store", None)
        if vector_store:
            for query in (
                "software purpose and primary workflows",
                "security sensitive behavior and dangerous APIs",
                "architecture modules interfaces and initialization",
            ):
                try:
                    for match in vector_store.search(query, top_k=12):
                        document = match.get("document", {})
                        identity = document.get("metadata", {}).get("address") or document.get("name")
                        if identity in seen:
                            continue
                        seen.add(identity)
                        rag_context.append(document)
                except Exception as exc:
                    self.logger.debug("Report RAG query failed: %s", exc)
        evidence["rag_function_context"] = rag_context[:30]

        try:
            return self.dspy_program.analyze_software(json.dumps(evidence, default=str))
        except Exception as exc:
            self.logger.error("Whole-program DSPy analysis failed: %s", exc)
            return {
                "software_classification": {},
                "security_assessment": {},
                "function_categorization": {},
                "behavioral_analysis": {},
                "architecture_analysis": {},
                "risk_assessment": {},
                "error": str(exc),
            }





























    # Response parsing methods






    def _generate_structured_software_report(self, data: Dict[str, Any], analysis: Dict[str, Any], format_type: str) -> str:
        """Generate the final structured software report."""
        if format_type.lower() == "json":
            return self._generate_json_report(data, analysis)
        elif format_type.lower() == "text":
            return self._generate_text_report(data, analysis)
        elif format_type.lower() == "html":
            return self._generate_html_report(data, analysis)
        else:  # Default to markdown
            return self._generate_markdown_report(data, analysis)

    def _generate_markdown_report(self, data: Dict[str, Any], analysis: Dict[str, Any]) -> str:
        """Generate markdown-formatted software report."""
        timestamp = self._get_current_timestamp()

        report = f"""# Comprehensive Software Analysis Report

**Generated:** {timestamp}
**Analysis Tool:** OGhidra AI-Powered Reverse Engineering Platform

---

## 📊 Executive Summary

### Software Classification
- **Type:** {analysis.get("software_classification", {}).get("type", "Unknown")}
- **Primary Purpose:** {analysis.get("software_classification", {}).get("purpose", "Not determined")}
- **Classification Confidence:** {analysis.get("software_classification", {}).get("confidence", "N/A")}

### Risk Assessment
- **Overall Risk Level:** {analysis.get("risk_assessment", {}).get("rating", "Not assessed")}
- **Security Risk Score:** {analysis.get("security_assessment", {}).get("risk_score", "N/A")}/100
- **Threat Level:** {analysis.get("risk_assessment", {}).get("threat_level", "Unknown")}

---

## 🔍 Binary Overview

### Statistical Summary
- **Total Functions:** {data["metadata"]["total_functions"]}
- **Analyzed Functions:** {data["metadata"]["analyzed_count"]} ({(data["metadata"]["analyzed_count"] / data["metadata"]["total_functions"] * 100) if data["metadata"]["total_functions"] > 0 else 0:.1f}%)
- **Renamed Functions:** {data["metadata"]["renamed_count"]}
- **Imported Symbols:** {len(data["imports"])}
- **Exported Symbols:** {len(data["exports"])}
- **Memory Segments:** {len(data["segments"])}

### Key Imports
{self._format_imports_for_report(data["imports"])}

### Key Exports
{self._format_exports_for_report(data["exports"])}

---

## Architecture Analysis

### Design Pattern
**Pattern:** {analysis.get("architecture_analysis", {}).get("pattern", "Not identified")}

### Architecture Quality
{analysis.get("architecture_analysis", {}).get("quality", "Not assessed")}

---

## 🎯 Function Analysis

### Function Categories
{self._format_function_categories_for_report(analysis.get("function_categorization", {}))}

### Renamed Functions
{self._format_renamed_functions_for_report(data["renamed_functions"])}

---

## 🔒 Security Assessment

### Risk Breakdown
- **Overall Risk:** {analysis.get("security_assessment", {}).get("risk_level", "Not assessed")}
- **Risk Score:** {analysis.get("security_assessment", {}).get("risk_score", "N/A")}/100

### Suspicious Indicators
{analysis.get("security_assessment", {}).get("indicators", "None identified")}

### Security Recommendations
{analysis.get("risk_assessment", {}).get("recommendations", "No specific recommendations available")}

---

## 🔄 Behavioral Analysis

### Primary Workflows
{analysis.get("behavioral_analysis", {}).get("workflows", "Not analyzed")}

### Behavioral Fingerprint
{analysis.get("behavioral_analysis", {}).get("fingerprint", "Not identified")}

---

## 📋 Key Findings

### Evidence Supporting Classification
{analysis.get("software_classification", {}).get("evidence", "No specific evidence documented")}

### Function Insights
{analysis.get("function_categorization", {}).get("insights", "No insights available")}

---

## 🔬 Detailed Findings with Addresses

This section provides specific addresses and evidence for key findings identified during analysis.

### Security-Related Findings
{self._format_findings_with_addresses(analysis.get("security_assessment", {}).get("addresses", []), max_findings=15)}

### Classification Evidence with Addresses
{self._format_findings_with_addresses(analysis.get("software_classification", {}).get("addresses", []), max_findings=10)}

### Behavioral Patterns with Addresses
{self._format_findings_with_addresses(analysis.get("behavioral_analysis", {}).get("addresses", []), max_findings=10)}

### Risk Factors with Addresses
{self._format_findings_with_addresses(analysis.get("risk_assessment", {}).get("addresses", []), max_findings=10)}

---

## [WARN] Risk Mitigation

### Recommended Actions
{analysis.get("risk_assessment", {}).get("recommendations", "No specific recommendations")}

### Monitoring Recommendations
{analysis.get("risk_assessment", {}).get("monitoring", "Standard monitoring protocols recommended")}

---

## 📈 Analysis Statistics

- **Analysis Completion:** {(sum(1 for a in analysis.values() if a) / len(analysis) * 100):.1f}%
- **Data Quality:** {"High" if data["metadata"]["analyzed_count"] > 10 else "Medium" if data["metadata"]["analyzed_count"] > 0 else "Low"}
- **Confidence Level:** {analysis.get("software_classification", {}).get("confidence", "Not determined")}

---

*Report generated by OGhidra AI-Powered Reverse Engineering Platform*
*For questions or additional analysis, consult the detailed function summaries and analysis logs.*
"""
        return report

    def _generate_html_report(self, data: Dict[str, Any], analysis: Dict[str, Any]) -> str:
        """Generate an HTML report from typed DSPy section specifications."""
        from src.report_template import (
            ReportMetadata,
            ReportSection,
            build_attack_vectors,
            build_key_findings,
            build_security_imports,
            build_stats_grid,
            build_table,
            build_timeline,
            build_vulnerability_discovery,
            generate_html_report,
        )

        evidence = {
            "metadata": data.get("metadata", {}),
            "imports": data.get("imports", [])[:50],
            "exports": data.get("exports", [])[:50],
            "strings": data.get("strings", [])[:50],
            "function_summaries": dict(list(data.get("function_summaries", {}).items())[:50]),
            "analysis": analysis,
        }
        try:
            ai_metadata, specifications = self.dspy_program.render_html_report(
                json.dumps(evidence, default=str)
            )
            sections = []
            list_builders = {
                "stats": build_stats_grid,
                "attack_vectors": build_attack_vectors,
                "key_findings": build_key_findings,
                "discovery": build_vulnerability_discovery,
                "security_imports": build_security_imports,
                "timeline": build_timeline,
            }
            for specification in specifications:
                content = specification.content
                if specification.content_type in list_builders and isinstance(content, list):
                    content = list_builders[specification.content_type](content)
                elif specification.content_type == "table" and isinstance(content, dict):
                    headers = content.get("headers", [])
                    rows = content.get("rows", [])
                    address_columns = [0] if headers and "Address" in str(headers[0]) else []
                    content = build_table(headers, rows, address_columns)
                sections.append(
                    ReportSection(
                        id=specification.id,
                        title=specification.title,
                        icon=specification.icon,
                        content_type=specification.content_type,
                        content=str(content),
                    )
                )
            if not sections:
                return self._generate_fallback_html_report(data, analysis)

            metadata = ReportMetadata(
                binary_name=data.get("metadata", {}).get("binary_name", "Unknown Binary"),
                severity=ai_metadata.get("severity", "MEDIUM"),
                subtitle=ai_metadata.get("subtitle", "AI-Powered Binary Analysis Report"),
                tool_name="OGhidra MCP",
            )
            return generate_html_report(sections, metadata)
        except Exception as exc:
            self.logger.error("Typed HTML report generation failed: %s", exc)
            return self._generate_fallback_html_report(data, analysis)






    def _generate_fallback_html_report(self, data: Dict[str, Any], analysis: Dict[str, Any]) -> str:
        """Generate a basic HTML report without AI, as fallback."""
        from src.report_template import generate_html_report, ReportSection, ReportMetadata

        binary_name = data.get("metadata", {}).get("binary_name", "Unknown Binary")

        metadata = ReportMetadata(
            binary_name=binary_name,
            severity=analysis.get("security_assessment", {}).get("risk_level", "MEDIUM").upper(),
            subtitle="Binary Analysis Report (Fallback)",
        )

        # Create basic sections from the analysis data
        sections = []

        # Executive Summary
        exec_content = f"""
        <div class="summary-content">
            <p><strong>Software Type:</strong> {analysis.get("software_classification", {}).get("type", "Unknown")}</p>
            <p><strong>Risk Level:</strong> {analysis.get("security_assessment", {}).get("risk_level", "Unknown")}</p>
            <p><strong>Purpose:</strong> {analysis.get("software_classification", {}).get("purpose", "Not determined")}</p>
        </div>
        """
        sections.append(
            ReportSection(
                id="executive_summary", title="Executive Summary", icon="📋", content_type="html", content=exec_content
            )
        )

        # Statistics
        stats_content = f"""
        <div class="grid">
            <div class="card">
                <div class="card-header">
                    <div class="card-icon">📦</div>
                    <h3>Functions</h3>
                </div>
                <div class="stat-value">{data.get("metadata", {}).get("total_functions", 0)}</div>
            </div>
            <div class="card">
                <div class="card-header">
                    <div class="card-icon">🔗</div>
                    <h3>Imports</h3>
                </div>
                <div class="stat-value">{len(data.get("imports", []))}</div>
            </div>
            <div class="card">
                <div class="card-header">
                    <div class="card-icon">📤</div>
                    <h3>Exports</h3>
                </div>
                <div class="stat-value">{len(data.get("exports", []))}</div>
            </div>
        </div>
        """
        sections.append(
            ReportSection(id="statistics", title="Statistics", icon="📊", content_type="html", content=stats_content)
        )

        return generate_html_report(sections, metadata)

    def _generate_json_report(self, data: Dict[str, Any], analysis: Dict[str, Any]) -> str:
        """Generate JSON-formatted software report."""
        report_data = {
            "metadata": {
                "generated_timestamp": self._get_current_timestamp(),
                "tool": "OGhidra AI-Powered Reverse Engineering Platform",
                "version": "1.0",
            },
            "executive_summary": {
                "software_type": analysis.get("software_classification", {}).get("type", "Unknown"),
                "primary_purpose": analysis.get("software_classification", {}).get("purpose", "Not determined"),
                "risk_level": analysis.get("risk_assessment", {}).get("rating", "Not assessed"),
                "risk_score": analysis.get("security_assessment", {}).get("risk_score", "N/A"),
                "threat_level": analysis.get("risk_assessment", {}).get("threat_level", "Unknown"),
            },
            "binary_overview": {
                "statistics": data["metadata"],
                "imports": data["imports"][:20],  # Limit for size
                "exports": data["exports"][:20],
                "segments": data["segments"],
            },
            "analysis_results": {
                "classification": analysis.get("software_classification", {}),
                "security": analysis.get("security_assessment", {}),
                "functions": analysis.get("function_categorization", {}),
                "behavior": analysis.get("behavioral_analysis", {}),
                "architecture": analysis.get("architecture_analysis", {}),
                "risk": analysis.get("risk_assessment", {}),
            },
            "detailed_findings": {
                "security_findings": analysis.get("security_assessment", {}).get("addresses", []),
                "classification_evidence": analysis.get("software_classification", {}).get("addresses", []),
                "behavioral_patterns": analysis.get("behavioral_analysis", {}).get("addresses", []),
                "risk_factors": analysis.get("risk_assessment", {}).get("addresses", []),
                "function_addresses": analysis.get("function_categorization", {}).get("addresses", []),
            },
            "function_data": {"renamed_functions": data["renamed_functions"], "summaries": data["function_summaries"]},
        }

        import json

        return json.dumps(report_data, indent=2, default=str)

    def _generate_text_report(self, data: Dict[str, Any], analysis: Dict[str, Any]) -> str:
        """Generate plain text software report."""
        # Convert markdown to plain text by removing markdown formatting
        markdown_report = self._generate_markdown_report(data, analysis)

        # Simple markdown to text conversion
        text_report = markdown_report
        text_report = text_report.replace("#", "")  # Remove headers
        text_report = text_report.replace("**", "")  # Remove bold
        text_report = text_report.replace("*", "")  # Remove italics
        text_report = text_report.replace("---", "=" * 50)  # Replace separators

        return text_report

    def _format_imports_for_report(self, imports: List[str]) -> str:
        """Format imports for report display."""
        if not imports:
            return "- No imports detected"

        formatted = []
        for imp in imports[:15]:  # Show top 15
            formatted.append(f"- {imp}")

        if len(imports) > 15:
            formatted.append(f"- ... and {len(imports) - 15} more imports")

        return "\n".join(formatted)

    def _format_exports_for_report(self, exports: List[str]) -> str:
        """Format exports for report display."""
        if not exports:
            return "- No exports detected"

        formatted = []
        for exp in exports[:10]:  # Show top 10
            formatted.append(f"- {exp}")

        if len(exports) > 10:
            formatted.append(f"- ... and {len(exports) - 10} more exports")

        return "\n".join(formatted)

    def _format_function_categories_for_report(self, categories: Dict[str, str]) -> str:
        """Format function categories for report display."""
        if not categories:
            return "- Function categorization not available"

        formatted = []
        for category, description in categories.items():
            if "raw_response" not in category:
                formatted.append(f"- **{category.title()}:** {description}")

        return "\n".join(formatted) if formatted else "- No function categories identified"

    def _format_renamed_functions_for_report(self, renamed_functions: List[tuple]) -> str:
        """Format renamed functions for report display."""
        if not renamed_functions:
            return "- No functions have been renamed in this analysis"

        formatted = []
        for old_name, new_name in renamed_functions[:20]:  # Show top 20
            formatted.append(f"- `{old_name}` → `{new_name}`")

        if len(renamed_functions) > 20:
            formatted.append(f"- ... and {len(renamed_functions) - 20} more renamed functions")

        return "\n".join(formatted)

    # ------------------------------------------------------------------
    # Address and Evidence Extraction Helpers
    # ------------------------------------------------------------------


    def _format_findings_with_addresses(self, findings: List[Dict[str, str]], max_findings: int = 20) -> str:
        """
        Format a list of findings with addresses for report display.

        Args:
            findings: List of finding dictionaries with address info
            max_findings: Maximum number of findings to include

        Returns:
            Formatted string for report
        """
        if not findings:
            return "No specific findings with addresses available."

        formatted = []
        for i, finding in enumerate(findings[:max_findings], 1):
            addr = finding.get("address", "unknown")
            func = finding.get("function", "unknown")
            context = finding.get("context", "No details")

            formatted.append(f"{i}. **Address {addr}** (Function: `{func}`)")
            formatted.append(f"   {context}")
            formatted.append("")

        if len(findings) > max_findings:
            formatted.append(f"*... and {len(findings) - max_findings} more findings*")

        return "\n".join(formatted)


    # ------------------------------------------------------------------
    # X-ref context helper
    # ------------------------------------------------------------------


    # ------------------------------------------------------------------
    #  Address normalisation helpers
    # ------------------------------------------------------------------



def main():
    """Main entry point for the bridge application."""
    parser = argparse.ArgumentParser(description="Ollama-GhidraMCP Bridge")
    parser.add_argument("--ollama-url", help="Ollama server URL")
    parser.add_argument("--ghidra-url", help="GhidraMCP server URL")
    parser.add_argument("--model", help="Ollama model to use")

    # Add model arguments for each phase
    parser.add_argument("--planning-model", help="Model to use for the planning phase")
    parser.add_argument("--execution-model", help="Model to use for the execution phase")
    parser.add_argument("--analysis-model", help="Model to use for the analysis phase")

    parser.add_argument("--interactive", action="store_true", help="Run in interactive mode")
    parser.add_argument("--list-models", action="store_true", help="List available models")
    parser.add_argument("--list-context", action="store_true", help="List current conversation context")
    parser.add_argument("--mock", action="store_true", help="Run in mock mode (simulated GhidraMCP)")
    parser.add_argument("--log-level", help="Set log level (DEBUG, INFO, WARNING, ERROR)")
    parser.add_argument("--include-capabilities", action="store_true", help="Include capabilities.txt content in prompts")
    parser.add_argument("--max-steps", type=int, default=5, help="Maximum number of steps for agentic execution loop")

    args = parser.parse_args()

    # Set log level from arguments or environment
    if args.log_level:
        os.environ["LOG_LEVEL"] = args.log_level

    # Configure based on arguments and environment variables
    config = BridgeConfig()

    # Override with command line arguments
    if args.ollama_url:
        config.ollama.base_url = args.ollama_url
    if args.ghidra_url:
        config.ghidra.base_url = args.ghidra_url
    if args.model:
        config.ollama.model = args.model
    if args.mock:
        config.ghidra.mock_mode = True

    # Handle model switching - update the model map
    if args.planning_model:
        config.ollama.model_map["planning"] = args.planning_model
    if args.execution_model:
        config.ollama.model_map["execution"] = args.execution_model
    if args.analysis_model:
        config.ollama.model_map["analysis"] = args.analysis_model
    config.ollama.max_execution_steps = args.max_steps

    # Initialize clients
    ollama_client = OllamaClient(config.ollama)
    ghidra_cls, _backend_label = select_ghidra_client_class(config)
    ghidra_client = ghidra_cls(config.ghidra)

    # List models if requested
    if args.list_models:
        models = ollama_client.list_models()
        if models:
            print("Available Ollama models:")
            for model in models:
                print(f"  - {model}")
        else:
            print("No models found or error connecting to Ollama")
        return 0

    # Initialize the bridge
    bridge = Bridge(config=config, include_capabilities=args.include_capabilities)

    # Health check for Ollama and GhidraMCP
    ollama_health = "OK" if ollama_client.check_health() else "FAIL"
    ghidra_health = "OK" if ghidra_client.check_health() else "FAIL"

    # List context if requested
    if args.list_context:
        print("\nCurrent conversation context:")
        for i, item in enumerate(bridge.context):
            print(f"{i}: {item.get('role', 'unknown')}: {item.get('content', '')[:50]}...")
        return 0

    # Interactive mode
    if args.interactive:
        # Display banner
        print(
            "+==================================================================+\n"
            "|                                                                  |\n"
            "|  OGhidra - Simplified Three-Phase Architecture                   |\n"
            "|  ------------------------------------------                      |\n"
            "|                                                                  |\n"
            "|  1. Planning Phase: Create a plan for addressing the query       |\n"
            "|  2. Tool Calling Phase: Execute tools to gather information      |\n"
            "|  3. Analysis Phase: Analyze results and provide answers          |\n"
            "|                                                                  |\n"
            "|  For more information, see README-ARCHITECTURE.md                |\n"
            "|                                                                  |\n"
            "+==================================================================+"
        )

        print("Ollama-GhidraMCP Bridge (Interactive Mode)")
        print(f"Default model: {config.ollama.model}")

        # Show health status
        if ollama_health != "OK" or ghidra_health != "OK":
            print(f"Health check: Ollama: {ollama_health}, GhidraMCP: {ghidra_health}")

        # Main interaction loop
        while True:
            try:
                prompt = input("\nQuery (or 'exit', 'quit', 'health', 'models'): ")

                if prompt.lower() in ["exit", "quit"]:
                    break

                elif prompt.lower() == "health":
                    ollama_health = "OK" if ollama_client.check_health() else "FAIL"
                    ghidra_health = "OK" if ghidra_client.check_health() else "FAIL"
                    print(f"Health check: Ollama: {ollama_health}, GhidraMCP: {ghidra_health}")

                elif prompt.lower() == "models":
                    models = ollama_client.list_models()
                    if models:
                        print("Available Ollama models:")
                        for model in models:
                            print(f"  - {model}")
                    else:
                        print("No models found or error connecting to Ollama")

                elif prompt.strip():  # Only process non-empty prompts
                    response = bridge.process_query(prompt)
                    print(f"\n{response}")

            except KeyboardInterrupt:
                print("\nExiting...")
                break

            except Exception as e:
                print(f"Error: {str(e)}")

        return 0

    # Non-interactive mode - process input from stdin
    else:
        user_input = ""
        for line in sys.stdin:
            user_input += line

        if user_input.strip():
            response = bridge.process_query(user_input)
            print(response)

        return 0


if __name__ == "__main__":
    main()
