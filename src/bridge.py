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
import re  # Added for pattern matching in enhanced error feedback
from typing import Dict, Any, List, Optional, Tuple
import threading

from src.config import BridgeConfig
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
from src.user_question import QuestionHandler
from src.session_compactor import SessionCompactor
from src.context_manager import ContextManager
from src.analysis_dump import AnalysisDumper
from src.coverage_tracker import CoverageTracker
from src.lead_tracker import LeadTracker
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

    # Class-level singleton for SentenceTransformer model
    _sentence_transformer_model = None
    _model_load_lock = None
    _ollama_client = None

    def __init__(
        self, config: BridgeConfig, include_capabilities: bool = False, max_agent_steps: int = 5, enable_cag: bool = True
    ):
        """Initialize the bridge with configuration."""
        self.config = config
        self.logger = logging.getLogger("ollama-ghidra-bridge")

        # Initialize threading lock for model loading
        if Bridge._model_load_lock is None:
            Bridge._model_load_lock = threading.Lock()

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

        # Initialize clients
        # Note: self.ollama is used as the generic LLM client name to avoid massive refactoring

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

        # Legacy context support (for backward compatibility during transition)
        self.context = []  # Will be deprecated in favor of self.session

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

        # Analysis state tracking (legacy dict - now points to session's Pydantic model)
        # The actual state is stored in self.session.analysis_state (AnalysisState model)
        # This dict is maintained for backward compatibility
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
            self.logger.info("✅ Knowledge Graph initialized for architectural analysis")
        except Exception as e:
            self.logger.warning(f"⚠️  Knowledge Graph initialization failed: {e}. Graph features disabled.")

        # Initialize caches and statistics
        self._init_caches()

        # Agentic workflow settings
        self.max_goal_steps = max_agent_steps
        self.goal_steps_taken = 0
        self.current_goal = None
        self.goal_achieved = False
        self.current_plan = ""
        self.current_plan_tools = []
        self.executed_tools = set()  # Track (cmd_name:params_signature) to avoid duplicates
        self.step_result_map = {}  # Map cmd_signature -> (loop_step_id, result_excerpt)
        self.tool_repetition_limit = 999  # TEMPORARILY DISABLED - was causing cache misses (original: 2)
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

        # Partial outputs storage
        self.partial_outputs = []

        # UI callback for chain of thought updates (set by UI if present)
        self._ui_cot_callback = None

        # Interactive Execution Gate (OpenCode-inspired)
        self.execution_gate = ExecutionGatekeeper(self.llm_config)
        self._ui_gate_callback = None  # Set by UI for gate events

        # Question Tool — AI asks user mid-investigation (OpenCode-inspired)
        self.question_handler = QuestionHandler()
        self._ui_question_callback = None  # Set by UI for question display

        # Session Compactor — Smart context pruning (OpenCode-inspired)
        self.session_compactor = SessionCompactor(self.llm_config, self.ollama)

        # Coverage Tracker        # Initialize coverage tracker
        self.coverage_tracker = CoverageTracker()

        # Initialize lead tracker
        self.lead_tracker = LeadTracker()

        self.logger.info("Bridge initialized successfully")

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

    def _should_analyze_findings(self, tools_executed: int) -> bool:
        """
        Check if we should pause for analysis checkpoint.

        Forces analysis after every 3 tool executions to prevent the AI from
        drowning in data without reflection. This implements a key lesson from
        the ninja trojan investigation failure.

        Args:
            tools_executed: Number of tools executed in current loop

        Returns:
            True if analysis checkpoint is needed
        """
        # After every 3 tool executions, force analysis
        return tools_executed > 0 and tools_executed % 3 == 0

    def _create_analysis_checkpoint(self, execution_results: List) -> str:
        """
        Create analysis checkpoint prompt that forces reflection.

        This is inspired by OpenCode's iterative feedback loops where the
        agent must explain its findings before continuing. It prevents the
        "execution without thought" pattern that caused investigation failures.

        Args:
            execution_results: List of recent tool executions

        Returns:
            Formatted checkpoint prompt
        """
        # Get last 3 tool names
        recent_tools = []
        for ex in execution_results[-3:]:
            if hasattr(ex, "cmd_name"):
                recent_tools.append(ex.cmd_name)
            elif isinstance(ex, dict):
                recent_tools.append(ex.get("cmd_name", "unknown"))

        checkpoint_prompt = f"""
🔍 ANALYSIS CHECKPOINT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

You have executed: {", ".join(recent_tools)}

MANDATORY REFLECTION: Before executing more tools, analyze your findings:

1. **Data Summary**: What data was returned from the tools above?
   - List the key findings (addresses, function names, strings, etc.)

2. **Pattern Detection**: Are there suspicious patterns?
   - Security APIs (privilege escalation, crypto, etc.)
   - Network indicators (URLs, IPs, suspicious domains)
   - Malicious behaviors (obfuscation, hidden files, etc.)

3. **Verification Required**: Do you need to decompile any functions?
   - For each suspicious finding, identify the function to decompile
   - State the address and why it's suspicious

4. **Next Action**: Based on these findings, what's your next step?
   - Decompile a function? (provide address)
   - Search for related strings? (provide filter)
   - Trace cross-references? (provide address)
   - Declare investigation complete? (provide evidence)

⚠️  CRITICAL: You must complete this analysis before executing more tools.
Do NOT skip to tool execution. Provide concrete details from the data above.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
        return checkpoint_prompt

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
    def get_sentence_transformer(cls):
        """DEPRECATED: Use get_ollama_embeddings instead for local embedding generation."""
        import logging

        logger = logging.getLogger("ollama-ghidra-bridge")
        logger.warning("get_sentence_transformer is DEPRECATED. Use get_ollama_embeddings for local embeddings.")
        logger.warning("To ensure no HuggingFace API calls, this method now returns None.")

        # Return None to force usage of Ollama embeddings
        return None

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
    def get_ollama_embeddings(cls, texts: List[str], model: str = None) -> List[List[float]]:
        """DEPRECATED: Use get_embeddings instead. Legacy alias for backward compatibility."""
        return cls.get_embeddings(texts, model)

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

    # REMOVED: _parse_and_save_artifacts - text-based ARTIFACT format was never used
    # Artifacts now auto-populated from execution gate triggers
    # def _parse_and_save_artifacts(self, response: str):
    #     """Parse text-based artifacts from LLM response."""
    #     pass

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

    def _remove_search_function_summaries_refs(self, prompt_text: str) -> str:
        """
        Remove references to search_function_summaries from prompt text when hybrid search is disabled.
        This includes removing entire sections that discuss the tool.
        """
        if not prompt_text:
            return prompt_text

        # Remove sections that start with markers about hybrid search or search_function_summaries
        import re

        # Pattern 1: Remove entire sections bordered by emoji dividers that mention hybrid search
        # This matches sections like: 🔥 HYBRID SEARCH STRATEGY ... ━━━━━
        pattern1 = r"🔥\s*HYBRID SEARCH[^━]*?━{20,}.*?━{20,}"
        prompt_text = re.sub(pattern1, "", prompt_text, flags=re.DOTALL | re.IGNORECASE)

        # Pattern 2: Remove standalone sections about function summary search
        # This matches sections like: 🔍 FUNCTION SUMMARY SEARCH ... ━━━━━
        pattern2 = r"🔍\s*FUNCTION SUMMARY SEARCH[^━]*?━{20,}.*?━{20,}"
        prompt_text = re.sub(pattern2, "", prompt_text, flags=re.DOTALL | re.IGNORECASE)

        # Pattern 3: Remove individual lines that mention search_function_summaries
        lines = prompt_text.split("\n")
        filtered_lines = []
        skip_until_blank = False

        for line in lines:
            # If we're in a section to skip, check if we've reached a blank line or new section
            if skip_until_blank:
                if line.strip() == "" or line.strip().startswith("##") or line.strip().startswith("**"):
                    skip_until_blank = False
                else:
                    continue

            # Check if line mentions search_function_summaries
            if "search_function_summaries" in line.lower():
                # If it's an EXECUTE line or part of a usage example, skip it
                if "EXECUTE:" in line or "search_function_summaries(" in line:
                    continue
                # If it's part of a description, skip until we hit a blank line
                skip_until_blank = True
                continue

            # Check if line mentions "Hybrid Search" or "hybrid search" in instructional context
            if re.search(r"(when|use|enable|available).*hybrid\s+search", line, re.IGNORECASE):
                skip_until_blank = True
                continue

            filtered_lines.append(line)

        prompt_text = "\n".join(filtered_lines)

        # Clean up excessive blank lines
        prompt_text = re.sub(r"\n{3,}", "\n\n", prompt_text)

        return prompt_text

    def _build_structured_prompt(self, phase: str = None) -> tuple:
        """
        Build structured prompts with proper separation between system and user prompts.

        SYSTEM PROMPT contains:
        - Role definition
        - Available tools and their syntax
        - Formatting rules and best practices
        - Phase-specific instructions (planning/execution/analysis)

        USER PROMPT contains:
        - User's goal and query
        - Current execution state
        - Tool execution results and history
        - Dynamic context from CAG

        Args:
            phase: Optional phase name to customize the prompt

        Returns:
            Tuple of (system_prompt, user_prompt)
        """
        # ========== SYSTEM PROMPT SECTIONS (Static Instructions) ==========
        system_sections = []

        # 1. Role and expertise definition
        role_definition = """You are an AI assistant specialized in reverse engineering with Ghidra.
You can help analyze binary files by executing commands through GhidraMCP."""
        system_sections.append(role_definition)

        # 2. Available tools section (static)
        if self.include_capabilities and self.capabilities_text:
            tools_section = (
                f"## Available Tools\n"
                f"You have access to the following Ghidra interaction tools.\n\n"
                f"{self.capabilities_text}\n\n"
                f"## Tool Execution Format\n"
                f"To call a tool, use this EXACT format:\n"
                f'EXECUTE: tool_name(param1="value1", param2="value2")\n\n'
                f"Rules:\n"
                f"- Output ONLY the EXECUTE line, no extra text\n"
                f"- String values MUST be in double quotes\n"
                f"- Numerical values should NOT be quoted\n"
                f"- Use exact tool and parameter names from the list above\n\n"
                f"Examples:\n"
                f'EXECUTE: decompile_function(name="main")\n'
                f'EXECUTE: rename_function(old_name="FUN_140011a8", new_name="process_data")\n'
                f"EXECUTE: list_imports(offset=0, limit=50)\n"
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
            # Remove search_function_summaries references if hybrid search is disabled
            if not getattr(self, "grep_layer_enabled", False):
                phase_instructions = self._remove_search_function_summaries_refs(phase_instructions)
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
            # Remove search_function_summaries references if hybrid search is disabled
            if not getattr(self, "grep_layer_enabled", False):
                phase_instructions = self._remove_search_function_summaries_refs(phase_instructions)
            system_sections.append(phase_instructions)
        elif phase == "evaluation":
            phase_instructions = self.llm_config.evaluation_system_prompt.replace(
                "{user_task_description}", "[User's goal will be provided in the user message]"
            )
            system_sections.append(phase_instructions)
        elif phase == "analysis":
            phase_instructions = self.llm_config.analysis_system_prompt.replace(
                "{user_task_description}", "[User's goal will be provided in the user message]"
            )
            system_sections.append(phase_instructions)
        elif phase == "review":
            # Review phase: Concise, focused on quality assessment and guidance
            thoroughness = getattr(self.llm_config, "review_thoroughness", "standard")

            # Define thoroughness-specific criteria
            if thoroughness == "basic":
                criteria_detail = """
    - Basic: Quick sanity check - did we accomplish the user's goal at all?
    - Focus: PASS/FAIL assessment only
    - Depth: Minimal - just check if the main objective was addressed"""
            elif thoroughness == "thorough":
                criteria_detail = """
    - Thorough: Comprehensive deep review
    - Focus: Detailed verification of all aspects, edge cases, and potential issues
    - Depth: Full - scrutinize methodology, verify all claims, check for missing analysis"""
            else:  # standard
                criteria_detail = """
    - Standard: Balanced review of completeness and quality
    - Focus: Core objectives met, major gaps identified
    - Depth: Moderate - verify key points and identify obvious issues"""

            review_instructions = f"""
    You are a Quality Review Assistant for reverse engineering analysis.

    YOUR REVIEW TASK (Thoroughness: {thoroughness}):
    1. Evaluate the completeness and accuracy of the analysis performed
    2. Identify any gaps, errors, or areas that need improvement
    3. Assess whether the stated goal has been fully achieved
    4. Suggest specific next steps or phases if the analysis is incomplete
    {criteria_detail}

    OUTPUT FORMAT:
    Provide a structured review with:
    1. **Status**: APPROVED or NEEDS_IMPROVEMENT
    2. **Summary**: Brief assessment of what was accomplished
    3. **Gaps/Issues**: List any problems or missing elements (skip if APPROVED)
    4. **Next Steps**: Specific recommendations for improvement (if applicable)
       - Suggest which phase to revisit (Planning/Execution/Analysis)
       - Recommend specific tools or approaches to use
       - Prioritize the most critical actions

    Be constructive and specific in your feedback.
            """
            system_sections.append(review_instructions)

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

        # ENHANCED: Direct function context injection when Hybrid Search is enabled
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
                self.cag_manager.update_session_from_bridge_context(
                    self.context if isinstance(self.context, list) else self.context.get("history", [])
                )
                cag_text = self.cag_manager.enhance_prompt(latest_user_query, phase)
                if cag_text:
                    # Create CAGContext object
                    cag_context_obj = CAGContext(workplans=[cag_text])

        # Build phase-specific instructions
        phase_instructions = None
        latest_user_role = None
        if isinstance(self.context, list) and self.context:
            latest_user_role = self.context[-1].get("role")
        elif isinstance(self.context, dict) and self.context.get("history", []):
            latest_user_role = self.context["history"][-1].get("role")

        if latest_user_role == "user":
            if phase == "planning" or not self.current_plan:
                phase_instructions = (
                    "## Current Task\nCreate a plan to address the goal above. Do not execute any commands yet."
                )
            elif phase == "execution":
                phase_instructions = "## Current Task\nExecute the necessary tools to gather information for the goal above."
            elif phase == "analysis":
                phase_instructions = (
                    "## Current Task\nAnalyze the gathered information and provide a comprehensive answer to the goal above."
                )
            else:
                phase_instructions = "## Current Task\nAddress the goal above using the available tools."

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

    def _check_final_response_quality(self, response: str) -> bool:
        """
        Check if the final response is of good quality and doesn't indicate tool limitations.
        Also verifies that all critical planned tools have been executed.

        Args:
            response: The potential final response text

        Returns:
            True if the response is complete and satisfactory, False if it indicates incomplete analysis
        """
        # Look for phrases that indicate the model couldn't complete the task
        limitation_phrases = [
            "i cannot",
            "cannot directly",
            "i'm unable to",
            "unable to",
            "doesn't include",
            "not available",
            "no way to",
            "would need",
            "don't have access",
            "no access to",
            "not possible with",
            "not able to",
            "couldn't find",
            "missing",
            "not found",
            "not supported",
            "no tool",
            "no command",
            "doesn't exist",
            "the current toolset doesn't",
        ]

        # Check if the response contains any of these limitation phrases
        response_lower = response.lower()
        for phrase in limitation_phrases:
            if phrase in response_lower:
                self.logger.info(f"Final response indicates limitation: '{phrase}'")
                return False

        # Check if response is too short
        if len(response.strip()) < 150:
            self.logger.info(f"Final response is too short ({len(response.strip())} chars)")
            return False

        # Check if final response has error messages
        if "ERROR:" in response or "Failed" in response:
            self.logger.info("Final response contains error messages")
            return False

        # Check if all critical planned tools have been executed
        # Update the pending_critical list based on current execution status
        pending_critical = [
            tool
            for tool in self.planned_tools_tracker["planned"]
            if tool["is_critical"] and tool["execution_status"] == "pending"
        ]

        if pending_critical:
            tool_names = ", ".join([tool["tool"] for tool in pending_critical])
            self.logger.info(f"Critical planned tools not executed: {tool_names}")

            # Check if the response falsely claims actions that weren't performed
            for tool in pending_critical:
                tool_name = tool["tool"]
                # Check for phrases that indicate the tool was used when it actually wasn't
                false_claim_patterns = [
                    "renamed to",
                    "renamed the function",
                    "function is now named",
                    "have renamed",
                    "renamed",
                    "new name",
                    "changed the name",
                    "added comment",
                    "commented",
                    "set a comment",
                    "decompiled",
                ]

                for pattern in false_claim_patterns:
                    if pattern in response_lower and any(rename_tool in tool_name for rename_tool in ["rename", "comment"]):
                        self.logger.warning(
                            f"Response falsely claims an action was performed: '{pattern}' but {tool_name} was not executed"
                        )
                        return False

            # If the response doesn't falsely claim completion but critical tools are missing, still return False
            return False

        return True

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

    def _normalize_command_params(self, command_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize command parameters based on command requirements.

        Args:
            command_name: The normalized command name
            params: The original parameters

        Returns:
            Normalized parameters
        """
        normalized_params = {}

        # Common parameter name mappings
        param_mappings = {
            "functionAddress": "address",
            "function_address": "address",
            "functionName": "name",
            "function_name": "name",
            "oldName": "old_name",
            "newName": "new_name",
        }

        # Special case normalizations for specific commands
        command_specific_mappings = {
            "rename_function_by_address": {"address": "function_address"},
            "decompile_function_by_address": {"function_address": "address"},
        }

        # Apply command-specific normalizations first
        if command_name in command_specific_mappings:
            for orig_key, new_key in command_specific_mappings[command_name].items():
                if orig_key in params:
                    normalized_params[new_key] = params[orig_key]
                    logging.info(f"Normalized parameter '{orig_key}' to '{new_key}' for command '{command_name}'")

        # Then apply general normalizations
        for key, value in params.items():
            if key in normalized_params:
                continue  # Skip if already processed by command-specific normalization

            # Apply general parameter name mapping
            norm_key = param_mappings.get(key, key)
            if norm_key != key:
                logging.info(f"Normalized parameter '{key}' to '{norm_key}' for command '{command_name}'")

            normalized_params[norm_key] = value

        return normalized_params

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
                if hasattr(ui, "renamed_functions_panel") and ui.renamed_functions_panel:
                    if hasattr(ui.renamed_functions_panel, "tree"):
                        for item in ui.renamed_functions_panel.tree.get_children():
                            try:
                                values = ui.renamed_functions_panel.tree.item(item, "values")
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

                # NEW: Search through analyzed function summaries
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
            self.logger.debug(f"⚠️ Not caching error result for {command_name}")
            return

        # Check if result is empty or indicates failure - don't cache
        if isinstance(result, (list, dict)) and not result:
            self.logger.debug(f"⚠️ Not caching empty result for {command_name}")
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
            self.goal_steps_taken = 0
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

            # Ensure context is initialized
            if not isinstance(self.context, list):
                if isinstance(self.context, dict) and "history" in self.context:
                    self.context = self.context["history"]
                else:
                    self.context = []

            # Add user query to context
            self.add_to_context("user", query)

            # Get configuration
            max_cycles = self.llm_config.max_agentic_cycles
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
                    self._emit_cot("Gate", f"⚠️ {gate_count} gate(s) triggered this cycle: {gate_summary}")
                    self.logger.info(f"🚧 {gate_count} gate(s) fired during execution: {gate_summary}")

                # Check if AI asked a question — pause for user input
                if exec_results.pending_question:
                    q = exec_results.pending_question
                    self._emit_cot("Status", f"⏸️ Waiting for user answer: {q.question[:80]}")
                    self.logger.info("⏸️ Question pending — Phase 1: Log and continue")
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
                    self.logger.warning(f"⚠️ Goal not achieved in cycle {cycle}")
                    self.logger.warning(f"   Reason: {reason}")
                    self._emit_cot("Status", f"Goal not yet achieved: {reason[:100]}...")

                    if cycle < max_cycles:
                        self.logger.info(f"🔄 Looping back to planning for cycle {cycle + 1}")
                        self._emit_cot("Status", f"Looping back to planning for cycle {cycle + 1}")
                        # Add evaluation result to context for next planning
                        eval_context = f"Cycle {cycle} evaluation: Goal not yet achieved. {reason}"
                        self.add_to_context("evaluation", eval_context)
                    else:
                        self.logger.warning(f"⚠️ Max cycles ({max_cycles}) reached")
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

    def process_query_single_pass(self, query: str) -> str:
        """
        Process a natural language query with a single Planning→Execution→Analysis pass.

        This is the original behavior - one cycle only, no goal evaluation or re-planning.

        Args:
            query: Natural language query from the user

        Returns:
            Result of processing the query
        """
        try:
            self.logger.info(f"🚀 Starting query processing: '{query}'")

            # Store the query as our current goal
            self.current_goal = query
            self._update_scope_from_query(query)
            self.goal_achieved = False
            self.goal_steps_taken = 0
            self.executed_tools = set()  # Reset tool tracking for new query
            self.step_result_map = {}  # Reset step result map for new query

            # Ensure context is initialized as a list if it's not already
            if not isinstance(self.context, list):
                if isinstance(self.context, dict) and "history" in self.context:
                    self.context = self.context["history"]
                else:
                    self.context = []

            # Add user query to context
            self.add_to_context("user", query)

            # PHASE 1: Planning - determine what tools need to be called
            self.logger.info("📋 Phase 1: Starting planning phase")
            self.current_workflow_stage = "planning"
            plan_response = self._generate_plan(query)
            self.logger.info(f"✅ Planning completed: {len(plan_response)} chars")

            # Check if execution loop is enabled
            use_execution_loop = self.llm_config.execution_loop_enabled

            if use_execution_loop:
                # NEW: Multi-tool execution loop
                self.logger.info("🔄 Phase 2: Starting execution loop (multi-tool mode)")
                self.current_workflow_stage = "execution"
                max_steps = self.llm_config.max_execution_steps
                exec_results = self._execution_loop(plan_response, max_steps=max_steps)
                self.logger.info(f"✅ Execution loop completed: {exec_results.total_steps} steps")

                # PHASE 3: Analysis - analyze accumulated results
                self.logger.info("🧠 Phase 3: Starting analysis phase with accumulated results")
                self.current_workflow_stage = "analysis"
                response = self._analyze_execution_results(exec_results)
                self.logger.info(f"✅ Analysis completed: {len(response)} chars")
            else:
                # LEGACY: Single-shot execution (original behavior)
                self.logger.info("🔧 Phase 2: Starting execution phase (legacy single-shot mode)")
                self.current_workflow_stage = "execution"
                result = self._execute_plan()
                self.logger.info(f"✅ Execution completed: {len(result)} chars")

                # PHASE 3: Analysis - analyze results and generate final response
                self.logger.info("🧠 Phase 3: Starting analysis phase")
                self.current_workflow_stage = "analysis"
                response = self._generate_analysis(query, result)
                self.logger.info(f"✅ Analysis completed: {len(response)} chars")

            # Add assistant response to context
            self.add_to_context("assistant", response)

            # Workflow complete
            self.current_workflow_stage = None
            self.logger.info("🎯 Query processing completed successfully")

            # Custom mode: update notepad/workplan after query
            self._maybe_update_custom_workplan(user_query=query, final_response=response)

            return response
        except Exception as e:
            # Log the exception with full traceback
            import traceback

            self.logger.error(f"❌ Error in query processing: {str(e)}")
            self.logger.error(f"Full traceback: {traceback.format_exc()}")

            # Reset workflow stage on error
            self.current_workflow_stage = None

            # Return error message
            return f"Error in query processing: {str(e)}"

    def process_query(self, query: str) -> str:
        """
        Main entry point for query processing.

        Routes to appropriate processing method based on configuration:
        - Agentic loop: Multiple Planning→Execution→Analysis cycles with goal evaluation
        - Single-pass: One Planning→Execution→Analysis cycle (original behavior)

        Args:
            query: Natural language query from the user

        Returns:
            Result of processing the query
        """
        # Check if agentic loop is enabled
        if self.llm_config.agentic_loop_enabled:
            self.logger.info("🔄 Using multi-cycle agentic loop mode")
            return self.process_query_with_agentic_loop(query)
        else:
            self.logger.info("➡️ Using single-pass mode (legacy)")
            return self.process_query_single_pass(query)

    def _generate_plan(self, query: str) -> str:
        """
        Generate a plan for addressing the query using Ollama.

        Args:
            query: Natural language query from the user

        Returns:
            Plan response
        """
        # Use CAG manager to enhance context with knowledge and session data
        if self.enable_cag and self.cag_manager:
            # Update session cache with current context
            self.cag_manager.update_session_from_bridge_context(self.context)

        logging.info("Starting planning phase")

        # Build prompts (system and user)
        system_prompt, user_prompt = self._build_structured_prompt(phase="planning")
        user_prompt += f"\n\nUser Query: {query}"

        # Generate planning response with properly separated prompts
        response = self.ollama.generate_with_phase(user_prompt, phase="planning", system_prompt=system_prompt)

        # Extract plan
        self.current_plan = response
        logging.info(f"Received planning response: {response[:100]}...")

        # Parse the planned tools
        self.current_plan_tools = self._parse_plan_tools(response)
        logging.info(f"Extracted {len(self.current_plan_tools)} planned tools from plan")

        # Add plan to context
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

    def _execute_plan(self) -> str:
        """
        Execute the generated plan.
        Returns:
            A string representing all tool results or errors.
        """
        # --- Duplicate-detection helpers ---
        READ_ONLY_PAGINATED = {"list_strings", "list_imports", "list_exports", "list_segments"}

        def _canonical_params(cmd, params):
            """Strip default offset/limit values for read-only tools so signatures match."""
            defaults = {"offset": 0, "limit": 500}
            if cmd in READ_ONLY_PAGINATED:
                cleaned = {k: v for k, v in params.items() if defaults.get(k) != v}
            else:
                cleaned = params
            return tuple(sorted(cleaned.items()))

        logging.info("Starting execution phase")

        all_results = []
        self.goal_steps_taken = 0
        step_count = 0
        goal_statement = f"Goal: {self.current_goal}"

        executed_commands = {}  # cmd_name+params -> count

        # Loop until we hit max steps or goal is achieved
        while step_count < self.max_goal_steps and not self.goal_achieved:
            step_count += 1
            self.goal_steps_taken = step_count

            logging.info(f"Step {step_count}/{self.max_goal_steps}: Sending query to Ollama")

            # Build prompts for tool execution
            system_prompt, user_prompt = self._build_structured_prompt(phase="execution")
            user_prompt += (
                f"\n\n{goal_statement}\n\nStep {step_count}: Determine the next tool to call or mark the goal as completed."
            )

            # Use CAG to enhance context with knowledge and session data
            if self.enable_cag and self.cag_manager:
                # Update session cache with current context
                self.cag_manager.update_session_from_bridge_context(self.context)

                # Get memory-enhanced prompt context to prevent redundant operations
                memory_context = self.cag_manager.enhance_prompt_with_memory_context(self.current_goal or "analysis")
                if memory_context:
                    user_prompt = f"{memory_context}\n\n{user_prompt}"

            # Generate execution step with properly separated prompts
            response = self.ollama.generate_with_phase(user_prompt, phase="execution", system_prompt=system_prompt)
            logging.info(f"Received response from Ollama: {response[:100]}...")

            # REMOVED: Text-based ARTIFACT parsing (never used)
            # Artifacts now auto-populated from execution gate triggers
            # self._parse_and_save_artifacts(response)

            # Extract commands to execute
            commands = self.command_parser.extract_commands(response)

            # Check for format violations and provide feedback to LLM
            format_feedback = self.command_parser.generate_format_feedback(response, commands)
            if format_feedback:
                self.logger.warning("Format violations detected in LLM response")
                # Add feedback as a system message so LLM can learn from it
                self.add_to_context("system", format_feedback)
                # If no commands were extracted despite violations, ask LLM to retry
                if not commands:
                    self.add_to_context("system", "No valid commands could be extracted. Please retry with correct format.")
                    return response  # Return response as-is, feedback will guide next attempt

            # ENFORCE HYBRID SEARCH (GREP LAYER) ON FIRST STEP
            # If Hybrid Search is enabled, always run a function-summary search first so the
            # agent has relevant candidates before expensive decompilation.
            try:
                if step_count == 1 and bool(getattr(self, "grep_layer_enabled", False)):
                    already_searching = bool(commands) and commands[0][0] == "search_function_summaries"
                    # Skip enforcement if the user query is clearly about a specific function/address.
                    q_text = self.current_goal or ""
                    if not q_text:
                        recent_user_msgs = self.session.get_recent_messages(limit=1, role_filter=[MessageRole.USER])
                        if recent_user_msgs:
                            q_text = str(recent_user_msgs[0].content or "")
                    looks_specific = False
                    if q_text:
                        import re

                        looks_specific = bool(
                            re.search(r"\b0x[0-9a-fA-F]{6,}\b|\b[0-9a-fA-F]{8,}\b|\bFUN_[0-9A-Fa-f]{6,}\b", q_text)
                        )

                    if not already_searching and not looks_specific:
                        commands = [
                            ("search_function_summaries", {"query": q_text or "analysis", "search_type": "hybrid", "top_k": 5})
                        ]
                        self.add_to_context(
                            "system",
                            "Hybrid Search is enabled: running search_function_summaries first to retrieve relevant analyzed functions before other tools.",
                        )
            except Exception:
                pass

            # Enhanced duplicate detection using CAG memory system
            if commands:
                cmd_name, cmd_params = commands[0]  # Get first command

                # Create signature for this exact command
                cmd_signature = f"{cmd_name}({_canonical_params(cmd_name, cmd_params)})"

                # First check CAG memory for intelligent duplicate detection
                skip_due_to_memory = False
                if self.enable_cag and self.cag_manager:
                    should_skip, skip_reason = self.cag_manager.should_skip_command(cmd_name, cmd_params)
                    if should_skip:
                        self.logger.warning(f"🧠 CAG Memory: {skip_reason}")

                        # Get memory-enhanced guidance
                        memory_guidance = self.cag_manager.enhance_prompt_with_memory_context(
                            self.current_goal or "analysis", cmd_name, cmd_params
                        )

                        guidance_msg = f"CAG Memory Guidance: {skip_reason}\n\n{memory_guidance}"
                        self.add_to_context("system", guidance_msg)
                        skip_due_to_memory = True

                # Fallback to original duplicate detection if CAG didn't catch it
                if not skip_due_to_memory and executed_commands.get(cmd_signature, 0) >= 1:
                    self.logger.warning(f"🚫 Skipping duplicate command: {cmd_signature}")
                    self.add_to_context(
                        "assistant",
                        f"ERROR: Duplicate command `{cmd_name}` was skipped. Please choose a different tool or change parameters.",
                    )
                    skip_due_to_memory = True

                if skip_due_to_memory:
                    continue

                executed_commands[cmd_signature] = executed_commands.get(cmd_signature, 0) + 1

                # Track tool usage
                tool_count = self.executed_tools.count(cmd_name)

                # Special validation for rename_function to prevent context mismatches
                if cmd_name == "rename_function" and "old_name" in cmd_params:
                    old_name = cmd_params["old_name"]
                    new_name = cmd_params.get("new_name", "")
                    rename_count = self.executed_tools.count("rename_function")

                    # Check for same-name rename (useless operation)
                    if old_name == new_name:
                        logging.warning(
                            f"Detected same-name rename: '{old_name}' -> '{new_name}'. This is a useless operation."
                        )
                        same_name_guidance = f"""
                        ATTENTION: You're trying to rename '{old_name}' to '{new_name}' - this is the SAME NAME!

                        This is a useless operation. The function is already named '{old_name}'.

                        If the function is already properly named, respond with "GOAL ACHIEVED".
                        If you need to rename it, choose a DIFFERENT, more descriptive name based on the function's purpose.
                        """
                        self.add_to_context("system", same_name_guidance)
                        continue  # Skip this command and get a new one

                    if rename_count >= 2:  # After 2 rename attempts, provide guidance
                        logging.warning("Multiple rename_function calls detected. Checking for context mismatch.")
                        if getattr(self.config.ghidra, "backend", "http") == "pyghidra":
                            rename_target_guidance = (
                                "1. Do NOT call get_current_function(); the pyGhidra backend does not track the live Ghidra GUI selection\n"
                                "2. Reuse an explicit function address or name from the current query/tool output\n"
                                '3. If you have already renamed the intended function, respond with "GOAL ACHIEVED"'
                            )
                        else:
                            rename_target_guidance = (
                                "1. Call get_current_function() to see which function is currently selected in Ghidra\n"
                                "2. Only rename the function that is currently selected\n"
                                '3. If you have already renamed the correct function, respond with "GOAL ACHIEVED"'
                            )
                        context_guidance = f"""
                        ATTENTION: You've called 'rename_function' {rename_count} times.

                        You're trying to rename '{old_name}'. Please verify this is the CURRENT function:
                        {rename_target_guidance}

                        Do NOT rename functions from previous contexts or conversations.
                        """
                        self.add_to_context("system", context_guidance)

                if tool_count >= self.tool_repetition_limit:
                    logging.warning(
                        f"Tool '{cmd_name}' has been called {tool_count} times. Possible repetitive behavior detected."
                    )

                    # Inject a guidance prompt to help the AI break out of the loop
                    guidance_prompt = f"""
                    ATTENTION: You've called '{cmd_name}' {tool_count} times already. This suggests you may be stuck in a loop.

                    Based on the goal: "{self.current_goal}"

                    Please review what you've accomplished so far and either:
                    1. If you have enough information, proceed to the ACTION step (e.g., rename_function)
                    2. If the goal is complete, respond with "GOAL ACHIEVED"
                    3. If you need different information, use a different tool

                    Do NOT repeat the same tool call again.
                    """
                    self.add_to_context("system", guidance_prompt)

            # If no commands but the response indicates goal completion, mark as achieved
            if not commands and ("INVESTIGATION COMPLETE" in response.upper() or "GOAL ACHIEVED" in response.upper()):
                logging.info("AI indicates the goal has been achieved")
                self.goal_achieved = True
                all_results.append(f"Step {step_count} - Goal achievement indicated: {response}")
                break

            # Execute commands
            execution_result = ""
            for cmd_name, cmd_params in commands:
                try:
                    # Add tool call to context
                    tool_call = f"EXECUTE: {cmd_name}({', '.join([f'{k}="{v}"' for k, v in cmd_params.items()])})"
                    self.add_to_context("tool_call", tool_call)

                    # Execute command with parameter normalization
                    logging.info(f"Executing GhidraMCP command: {cmd_name} with params: {cmd_params}")
                    result = self.execute_command(cmd_name, cmd_params)

                    # Display the result to the user
                    self._display_tool_result(cmd_name, result)

                    # Format the result for context and logging
                    if isinstance(result, dict) or isinstance(result, list):
                        execution_result = json.dumps(result, indent=2)
                    else:
                        execution_result = str(result)

                    # Dynamic truncation based on context budget from config
                    max_result_chars = self._get_max_result_chars()

                    context_result = execution_result
                    if len(execution_result) > max_result_chars:
                        # For list-like results, show a summary instead of full output
                        lines = execution_result.split("\n")
                        if len(lines) > 50:
                            # Show first 30 and last 15 lines with a summary (increased from 20/10)
                            first_lines = "\n".join(lines[:30])
                            last_lines = "\n".join(lines[-15:])
                            truncation_msg = f"\n... [Truncated {len(lines) - 45} lines for context efficiency] ...\n"
                            context_result = (
                                f"{first_lines}{truncation_msg}{last_lines}\n\nSummary: {len(lines)} total items returned"
                            )
                            logging.info(
                                f"Truncated large result ({len(execution_result)} chars -> {len(context_result)} chars)"
                            )
                        else:
                            # Simple truncation for non-list results
                            context_result = (
                                execution_result[:max_result_chars]
                                + f"\n... [Truncated {len(execution_result) - max_result_chars} chars]"
                            )

                    # Add to Pydantic session (structured storage)
                    self.session.add_tool_execution(
                        tool_name=cmd_name, parameters=cmd_params, result=context_result, success=True
                    )

                    # Add command result to context (legacy - for backward compatibility)
                    self.add_to_context("tool_result", context_result)
                    # Cache signature for duplicate detection intelligence
                    sig_exec = f"{cmd_name}({_canonical_params(cmd_name, cmd_params)})"
                    self.analysis_state.setdefault("cached_results", {})[sig_exec] = True

                    # Update analysis state
                    command = {"name": cmd_name, "params": cmd_params}
                    self._update_analysis_state(command, execution_result)

                    # Add to all results
                    all_results.append(f"Command: {cmd_name}\nResult: {execution_result}\n")

                except Exception as e:
                    error_msg = f"ERROR: {str(e)}"
                    logging.error(f"Error executing {cmd_name}: {error_msg}")
                    execution_result = error_msg
                    self.add_to_context("tool_error", error_msg)
                    all_results.append(f"Command: {cmd_name}\nError: {error_msg}\n")
                    print(f"❌ Error executing {cmd_name}: {error_msg}")

            # If no commands were found, note this and end loop if it's the second consecutive time
            if not commands:
                logging.info("No commands found in AI response, ending tool execution loop")
                all_results.append(f"Step {step_count} - No tool calls: {response}")
                break

        if step_count >= self.max_goal_steps:
            logging.info(f"Reached maximum steps ({self.max_goal_steps}), ending tool execution loop")

        logging.info("Execution phase completed")
        return "\n".join(all_results)

    def _evaluate_goal_completion(self, query: str, execution_results: str) -> bool:
        """
        Ask the AI to evaluate if the goal has been completed.

        Args:
            query: The original user query.
            execution_results: A summary of the execution phase.

        Returns:
            True if the goal is considered complete, False otherwise.
        """
        self.logger.info("Evaluating goal completion...")

        # Format the evaluation prompt with the user's task description
        prompt = self.llm_config.evaluation_system_prompt.format(user_task_description=query)

        # Add the execution results for context
        full_prompt = f"{prompt}\n\nExecution Summary:\n{execution_results}"

        response = self.ollama.generate(full_prompt)
        self.logger.info(f"Received evaluation response: {response.strip()}")

        return "goal achieved" in response.strip().lower()

    def _clean_final_response(self, response: str) -> str:
        """
        Clean up the final response for display by removing markers and formatting.

        Args:
            response: The raw final response

        Returns:
            Cleaned response text
        """
        if not response:
            return ""

        # Remove "FINAL RESPONSE:" marker if present
        cleaned = re.sub(r"^FINAL RESPONSE:\s*", "", response, flags=re.IGNORECASE)

        # Remove any trailing executing instructions
        cleaned = re.sub(r"\n+\s*EXECUTE:.*$", "", cleaned, flags=re.MULTILINE)

        # Handle code blocks wrapping the entire response
        # Only strip if the response starts and ends with ```
        cleaned = cleaned.strip()
        if cleaned.startswith("```") and cleaned.endswith("```"):
            # Check if it's just one big block
            lines = cleaned.split("\n")
            if len(lines) >= 2:
                # Remove first and last line
                cleaned = "\n".join(lines[1:-1])

        return cleaned.strip()

    def _generate_analysis(self, query: str, execution_results: str) -> str:
        """
        Analyze the results of tool executions and generate a final response.

        Args:
            query: The original query
            execution_results: Results from tool executions

        Returns:
            Final analysis response
        """
        logging.info("Starting review and reasoning phase")

        # Update workflow stage to review
        self.current_workflow_stage = "review"

        self.goal_achieved = False
        review_steps = 0
        max_review_steps = self.max_goal_steps
        final_response = ""
        review_results = []

        # Phase to iteratively review and refine our understanding
        while not self.goal_achieved and review_steps < max_review_steps:
            review_steps += 1
            logging.info(f"Review step {review_steps}/{max_review_steps}: Sending query to Ollama")

            # Build prompts for review
            system_prompt, user_prompt = self._build_structured_prompt(phase="review")
            user_prompt += f"\n\nGoal: {self.current_goal}\n\nExecution Results:\n{execution_results}\n\n"

            # Add directive based on whether we have execution results
            if execution_results and len(execution_results.strip()) > 50:
                user_prompt += """Review the execution results above carefully.

INVESTIGATION CRITERIA - Did you:
✓ Examine ALL error messages and strings in the code?
✓ Identify the protocol/technology (HTTP/2, TLS, etc.)?
✓ Understand the function's primary purpose from error messages?
✓ Extract semantic meaning from string literals?
✓ Use the AI analysis summary if available?

NAMING QUALITY CHECK:
❌ AVOID generic names like: "data_processing", "handle_something", "process_data"
✅ USE specific names based on: error messages, protocol operations, actual behavior
   Examples: "handle_http2_stream_close", "validate_tls_handshake", "parse_certificate_data"

Only provide FINAL RESPONSE when:
1. The function name is SPECIFIC and DESCRIPTIVE (not generic)
2. You've investigated all available information (strings, errors, AI analysis)
3. No further investigation would improve the result

If investigation is incomplete or name is too generic, use EXECUTE to call tools."""
            else:
                user_prompt += "No tool execution results are available yet. You MUST use the EXECUTE format to call the necessary tools to accomplish the goal. Do NOT provide a FINAL RESPONSE until tools have been executed and results obtained."

            # Use CAG to enhance context
            if self.enable_cag and self.cag_manager:
                self.cag_manager.update_session_from_bridge_context(self.context)

            # Generate review response with properly separated prompts
            review_response = self.ollama.generate_with_phase(user_prompt, phase="analysis", system_prompt=system_prompt)
            logging.info(f"Received review response: {review_response[:100]}...")

            # Check for the final response marker
            final_response_match = re.search(r"FINAL RESPONSE:\s*(.*?)(?:\n\s*$|\Z)", review_response, re.DOTALL)
            if final_response_match:
                final_response = final_response_match.group(1).strip()

                # Check if the "final response" actually contains instructions to execute tools
                # Common patterns: "should rename", "need to call", "must execute", "will rename", etc.
                instruction_patterns = [
                    r"\b(should|must|need to|will|let\'s)\s+(call|execute|rename|analyze|use)",
                    r"\brename\s+.*\s+to\s+",
                    r"\bcall\s+the\s+\w+\s+(function|tool|command)",
                    r"\bexecute\s+.*\s+with\s+",
                ]
                contains_instructions = any(
                    re.search(pattern, final_response, re.IGNORECASE) for pattern in instruction_patterns
                )

                if contains_instructions:
                    logging.warning(
                        "FINAL RESPONSE contains instructions instead of results - AI is describing actions rather than executing them"
                    )
                    logging.warning(f"Problematic response preview: {final_response[:200]}")
                    # Don't treat this as a valid final response, continue review loop
                    final_response = None
                    review_results.append(
                        f"⚠️ Review step {review_steps}: AI provided instructions instead of executing tools. Response ignored."
                    )
                    continue

                # Validate that the final response is reasonable
                if final_response and len(final_response) > 100:
                    logging.info("Found high-quality 'FINAL RESPONSE' marker in review, ending review loop")
                    self.goal_achieved = True
                    break
                elif final_response:
                    if "unable" in final_response.lower() or "limit" in final_response.lower():
                        logging.info(f"Final response is too short ({len(final_response)} chars)")
                        logging.info("Found 'FINAL RESPONSE' marker but response indicates limitations, continuing review")
                else:
                    logging.info("'FINAL RESPONSE' marker found but unable to extract response")

            # Check for additional tool calls in the review
            commands = self.command_parser.extract_commands(review_response)
            if commands:
                new_execution_results = []
                for cmd_name, cmd_params in commands:
                    try:
                        # Execute command
                        result = self.execute_command(cmd_name, cmd_params)

                        # Format result for display
                        formatted_result = self.command_parser.format_command_results(cmd_name, cmd_params, result)
                        logging.info(f"Review command executed: {cmd_name}")

                        # Add result to context
                        self.add_to_context("tool_result", formatted_result)

                        # Store for injection back into execution_results
                        tool_result_entry = (
                            f"Tool Call: {cmd_name}\nParameters: {cmd_params}\nTool Result: {formatted_result}\n"
                        )
                        review_results.append(tool_result_entry)
                        new_execution_results.append(tool_result_entry)
                    except Exception as e:
                        error_msg = f"ERROR: {str(e)}"
                        logging.error(f"Error executing review command {cmd_name}: {error_msg}")
                        self.add_to_context("tool_error", error_msg)
                        error_entry = f"Error executing {cmd_name}: {error_msg}"
                        review_results.append(error_entry)
                        new_execution_results.append(error_entry)

                # Inject new results back into execution_results for next iteration
                if new_execution_results:
                    execution_results += "\n" + "\n".join(new_execution_results)
                    logging.info(f"Injected {len(new_execution_results)} new tool results into execution context")

            # If no commands and no final response yet, continue
            if not commands and not final_response:
                review_results.append(f"Review step {review_steps}: {review_response}")

        # If we have a final response, add it to the results
        if final_response:
            # Clean up the response for display
            display_response = self._clean_final_response(final_response)
            review_results.append(f"FINAL RESPONSE:\n{display_response}")
        else:
            review_results.append("No final response generated during review")

        return "\n".join(review_results)

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

            # Ask AI: "What's the next tool to execute?"
            print(f"[Bridge] Execution Loop Step {step}: Requesting AI decision...")
            response = self.ollama.generate_with_phase(user_prompt, phase="execution", system_prompt=system_prompt)
            print(f"[Bridge] Received AI response (len={len(response)})")

            self.logger.info(f"Received execution loop response: {response[:100]}...")

            # Extract reasoning first
            reasoning = None
            reasoning_match = re.search(r"REASONING:\s*(.*?)(?:\nEXECUTE:|$)", response, re.DOTALL)
            if reasoning_match:
                reasoning = reasoning_match.group(1).strip()
                self.logger.info(f"🤔 Reasoning: {reasoning}")

            # Extract commands from the response
            commands = self.command_parser.extract_commands(response)

            # Check if investigation is complete
            has_completion_signal = "INVESTIGATION COMPLETE" in response.upper() or "GOAL ACHIEVED" in response.upper()

            if has_completion_signal:
                # CRITICAL: Check if LLM violated completion rules by mixing commands and completion
                if commands:
                    self.logger.error(
                        "⚠️  COMPLETION RULE VIOLATION: LLM output EXECUTE commands AND completion signal in same response!"
                    )
                    self.logger.warning(
                        "📝 This violates the prompt rules. Ignoring completion signal and continuing execution..."
                    )

                    # Add feedback to help LLM learn
                    self.add_to_context(
                        "system",
                        "⚠️  FORMAT VIOLATION: You output both EXECUTE commands and 'INVESTIGATION COMPLETE' in the same response.\n"
                        "This is explicitly forbidden. You must:\n"
                        "1. Execute tools → Wait for results → Then decide\n"
                        "2. NEVER output completion signals in the same response as tool calls\n"
                        "Please continue with analysis of the tool results.",
                    )
                    # Don't mark as complete - continue execution
                else:
                    self.logger.info("✅ AI indicates investigation is complete")
                    exec_results.investigation_complete = True
                    exec_results.completed_at = datetime.now()
                    break

            # Check for user question (ASK_USER directive)
            if "ASK_USER:" in response:
                question = self.question_handler.parse_from_response(response)
                if question:
                    self.logger.info(f"❓ AI asks: {question.question}")
                    self._emit_cot("Question", f"❓ AI asks: {question.question}")
                    if question.options:
                        self._emit_cot("Question", f"   Options: {' | '.join(question.options)}")

                    # Emit to UI if callback is set
                    if self._ui_question_callback:
                        self._ui_question_callback(question)

                    exec_results.pending_question = question
                    self.logger.info("⏸️ Execution paused — waiting for user input")
                    break  # Pause execution loop

            # Live CoT View - emit reasoning to both terminal and UI
            if reasoning and getattr(self.config.ollama, "show_reasoning", True):
                self._emit_cot("Reasoning", f"REASONING: {reasoning}")

            # Check if any commands were extracted
            if not commands:
                self.logger.warning(f"⚠️ No tool call found in response at step {step}")
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
                                        self.logger.info(f"✅ Auto-continuation complete: Now showing all {total_lines} lines")

                                except Exception as e:
                                    self.logger.warning(f"⚠️  Auto-continuation failed: {e}. Original result kept.")

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
            self.logger.warning(f"⚠️ Execution loop ended after {step} steps (max reached)")

        self.logger.info(f"✅ Execution loop complete: {exec_results.total_steps} steps executed")
        return exec_results

    def _execution_agent_rank(self, tool_name: str, result: Any, goal: str, max_items: int = 20) -> Any:
        """Ask execution agent to rank/filter large results for relevance."""
        result_str = json.dumps(result, indent=2) if isinstance(result, (dict, list)) else str(result)
        item_count = (
            len(result) if isinstance(result, list) else len(result.get("items", [])) if isinstance(result, dict) else 0
        )

        preview = "\n".join(result_str.split("\n")[:50])
        if len(result_str.split("\n")) > 50:
            preview += f"\n... ({len(result_str.split(chr(10))) - 50} more lines)"

        ranking_prompt = f"""Executed {tool_name}, got {item_count} results. GOAL: {goal}

Results Preview:
{preview}

Select top {max_items} MOST RELEVANT. Prioritize: security APIs, suspicious patterns, entry points, goal-specific.
Output ONLY JSON (same structure), top {max_items} items."""

        try:
            self.logger.info(f"🎯 Ranking {item_count} from {tool_name}")
            resp = self.ollama.generate(prompt=ranking_prompt, system_prompt="Filter. Output JSON only.", phase="execution")
            cleaned = "\n".join([line for line in resp.strip().split("\n") if not line.startswith("```")]).strip()
            filtered = json.loads(cleaned)
            self.logger.info(
                f"✅ Kept {len(filtered) if isinstance(filtered, list) else len(filtered.get('items', []))}/{item_count}"
            )
            return filtered
        except Exception as e:
            self.logger.warning(f"⚠️ Ranking failed: {e}")
            return result

    def _build_execution_loop_prompt(self, exec_results: ExecutionPhaseResults, current_step: int) -> Tuple[str, str]:
        """
        Build prompt for execution loop iteration.

        Shows AI the goal, plan, and results so far, asks for next tool.

        Args:
            exec_results: Accumulated execution results so far
            current_step: Current step number

        Returns:
            Tuple of (system_prompt, user_prompt)
        """
        # Build base structured prompt for execution phase
        system_prompt, _ = self._build_structured_prompt(phase="execution")

        # Build custom user prompt (dynamic - shows progress)
        loop_num = self.current_loop_number
        user_sections = [
            f"## Investigation Goal\n{exec_results.goal}",
            f"\n## Execution Plan\n{exec_results.plan}",
            f"\n## Progress: Loop {loop_num}, Step {current_step} (completed {exec_results.total_steps} steps in this loop)",
        ]

        # Show previous loop results if this is cycle 2+
        if loop_num > 1 and self.step_result_map:
            prev_loop_results = [
                (sid, exc) for sid, exc in self.step_result_map.values() if not sid.startswith(f"step_L{loop_num}_")
            ]
            if prev_loop_results:
                user_sections.append("\n## Results from Previous Loop(s) (available via get_cached_result):")
                for step_id, excerpt in prev_loop_results[:5]:  # Limit to 5 to avoid bloat
                    user_sections.append(f"- {step_id}: {excerpt[:100]}...")
                if len(prev_loop_results) > 5:
                    user_sections.append(f"  ... and {len(prev_loop_results) - 5} more results")

        # Show execution results so far in current loop
        if exec_results.tool_executions:
            user_sections.append(f"\n## Execution Results (Loop {loop_num}):")
            for i, tool_exec in enumerate(exec_results.tool_executions, 1):
                step_id = f"step_L{loop_num}_{i}"
                result_preview = str(tool_exec.result)[:500]  # Truncate for context
                if len(str(tool_exec.result)) > 500:
                    result_preview += "..."
                user_sections.append(f"\n{step_id}: {tool_exec.tool_name}({tool_exec.parameters})")
                user_sections.append(f"Result: {result_preview}")

        # Helper to get coverage info (ONLY when task mode is enabled)
        coverage_section = ""
        task_mode_enabled = bool(getattr(self, "task_mode_enabled", False))

        if task_mode_enabled and self.coverage_tracker:
            coverage_section = self.coverage_tracker.format_for_prompt()

        # Helper to get lead info (ONLY when task mode is enabled)
        leads_section = ""
        if task_mode_enabled and self.lead_tracker:
            # Parse leads from previous cycle results if any
            if exec_results.analysis_dump:
                self.lead_tracker.parse_analysis_dump(exec_results.analysis_dump)
            leads_section = self.lead_tracker.format_for_prompt()

        # Instructions for next step - WITH or WITHOUT investigation methodology based on task mode
        if task_mode_enabled:
            # Task Mode ON: Simplified instructions (methodology moved to system prompt)

            # Add hybrid search reminder banner if enabled
            hybrid_search_banner = ""
            if self.grep_layer_enabled:
                hybrid_search_banner = """
🔥 **HYBRID SEARCH ENABLED** - Use search_function_summaries with BEHAVIORAL queries
   Example: "Find code that reads credential files with obfuscated path construction"
   (See system prompt for query construction guide)

"""

            user_sections.append(f"""
{hybrid_search_banner}{coverage_section}

{leads_section}

## Your Task

Based on the goal, plan, and results so far, determine the NEXT step(s).

Use search_function_summaries with behavioral/semantic queries for discovery.
Follow the 4-step methodology (DISCOVER → LOCATE → TRACE → VERIFY) from the system prompt.

REASONING: [Why you're executing these tools - which area/lead are you investigating?]
EXECUTE: tool_name(param1="value1", param2="value2")

If investigation is complete: "INVESTIGATION COMPLETE"
""")
        else:
            # Task Mode OFF: Simple, direct instructions

            # Add hybrid search reminder banner if enabled
            hybrid_search_banner = ""
            if self.grep_layer_enabled:
                hybrid_search_banner = """
🔥 **HYBRID SEARCH ENABLED** - Use search_function_summaries with BEHAVIORAL queries
   Example: "Find functions that decode configuration data at runtime"
   (See system prompt for full query guide)

"""

            user_sections.append(f"""
{hybrid_search_banner}## Your Task

Answer the user's question using the appropriate Ghidra tools.

Focus on what was asked - don't over-investigate unless it's a security analysis task.
Use behavioral queries with search_function_summaries when discovering functions.

REASONING: [What you're doing]
EXECUTE: tool_name(param1="value1")

If done: "INVESTIGATION COMPLETE"
""")

        user_prompt = "\n".join(user_sections)

        return (system_prompt, user_prompt)

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
            self.logger.info(f"📝 Stored conclusions for cycle {current_cycle}")
        else:
            self.logger.warning(f"⚠️ No conclusions generated for cycle {current_cycle}")

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

        return final_response

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
        """
        Phase 3a: Consolidate findings using ranked results and correlation hints.

        This replaces the original _consolidate_findings with hybrid context.

        Args:
            exec_results: Full execution results (for metadata)
            formatted_ranked: Pre-formatted ranked results by category
            formatted_hints: Pre-formatted correlation hints

        Returns:
            Structured dict with consolidated findings
        """
        self.logger.info("🔍 Phase 3a: Consolidating findings (hybrid)...")

        # Build prompt with ranked results + hints
        consolidation_prompt = f"""
## Task: Extract Structured Findings

You are analyzing binary analysis results that have been ranked by relevance and include cross-tool correlations.

## Investigation Goal
{exec_results.goal}

## Ranked Results ({exec_results.total_steps} total steps, showing top per category)
{formatted_ranked}

{formatted_hints}

## Required Output Format

Return ONLY valid JSON with this exact structure (no markdown, no explanation):

{{
  "binary_purpose": "Brief 1-2 sentence description of what the binary does",
  "security_apis": [
    {{"address": "0x...", "name": "API_Name", "context": "How it's used (1 sentence)"}}
  ],
  "investigation_leads": [
    {{"address": "0x...", "observation": "What you observed", "hypothesis": "What this might indicate", "priority": "HIGH/MEDIUM/LOW", "next_step": "Specific action to verify"}}
  ],
  "artifacts": [
    {{"address": "0x...", "type": "manifest/string/key", "value": "The actual content (truncated if long)"}}
  ],
  "key_functions": [
    {{"address": "0x...", "name": "Function name", "purpose": "What it does"}}
  ],
  "investigation_gaps": [
    "What aspect still needs investigation"
  ],
  "recommended_next_steps": [
    "Specific action or tool to use next"
  ]
}}

RULES:
1. Include items based on EVIDENCE from the ranked results above
2. PAY SPECIAL ATTENTION to the Cross-Tool Correlations - these are high-value patterns
3. investigation_leads captures patterns you find interesting or suspicious
4. investigation_gaps identifies what's still unknown
5. recommended_next_steps suggests specific tools/actions for follow-up
6. Limit each array to the 10 MOST IMPORTANT items
7. Keep descriptions concise (under 100 chars)
8. If no items for a category, use an empty array []
9. Return ONLY the JSON object, nothing else
"""

        system_prompt = """You are a binary analysis expert extracting structured findings.
Output ONLY valid JSON. No markdown code blocks. No explanations. Just the JSON object."""

        try:
            response = self.ollama.generate(
                prompt=consolidation_prompt,
                system_prompt=system_prompt,
                phase="analysis",
                max_tokens=getattr(self.llm_config, "analysis_consolidation_max_tokens", 1200),
            )

            # CRITICAL: Check if response is empty (happens with reasoning models)
            if not response or len(response.strip()) == 0:
                self.logger.error("⚠️  Consolidation returned EMPTY response - likely exhausted tokens on reasoning")
                self.logger.info("📝 Generating minimal findings structure from raw results...")
                return self._generate_minimal_findings_from_raw(exec_results, formatted_ranked, formatted_hints)

            # Clean response - remove any markdown code blocks if present
            cleaned = response.strip()
            if cleaned.startswith("```"):
                lines = cleaned.split("\n")
                lines = [line for line in lines if not line.startswith("```")]
                cleaned = "\n".join(lines)

            # Try to parse JSON
            findings = json.loads(cleaned)

            # Validate required keys
            required_keys = [
                "binary_purpose",
                "security_apis",
                "investigation_leads",
                "artifacts",
                "key_functions",
                "investigation_gaps",
                "recommended_next_steps",
            ]
            for key in required_keys:
                if key not in findings:
                    findings[key] = [] if key != "binary_purpose" else "Unknown"

            self.logger.info(
                f"✅ Consolidated (hybrid): {len(findings.get('security_apis', []))} APIs, "
                f"{len(findings.get('investigation_leads', []))} leads, "
                f"{len(findings.get('investigation_gaps', []))} gaps"
            )

            return findings

        except json.JSONDecodeError as e:
            self.logger.warning(f"JSON parse failed in hybrid consolidation: {e}")
            return {
                "binary_purpose": "Analysis consolidation failed - see raw results",
                "security_apis": [],
                "investigation_leads": [],
                "artifacts": [],
                "key_functions": [],
                "investigation_gaps": ["Consolidation failed - check logs"],
                "recommended_next_steps": ["Retry analysis"],
                "_raw_response": response[:2000] if response else "",
            }
        except Exception as e:
            self.logger.error(f"Hybrid consolidation failed: {e}")
            # Fail-open: return a minimal structure plus compact previews so the run is usable even
            # under 429/504 conditions.
            ranked_preview = formatted_ranked
            hints_preview = formatted_hints
            try:
                if self.result_compactor is not None:
                    ranked_preview = self.result_compactor._cap_chars(str(formatted_ranked))
                    hints_preview = self.result_compactor._cap_chars(str(formatted_hints))
                else:
                    ranked_preview = str(formatted_ranked)[:1500]
                    hints_preview = str(formatted_hints)[:800]
            except Exception:
                ranked_preview = str(formatted_ranked)[:1500]
                hints_preview = str(formatted_hints)[:800]

            return {
                "binary_purpose": f"Consolidation error: {str(e)}",
                "security_apis": [],
                "investigation_leads": [],
                "artifacts": [],
                "key_functions": [],
                "investigation_gaps": ["LLM consolidation failed; see ranked preview"],
                "recommended_next_steps": ["Retry analysis", "Use get_cached_result for key steps"],
                "_ranked_preview": ranked_preview,
                "_correlation_preview": hints_preview,
            }

    def _format_results_with_context(self, exec_results: ExecutionPhaseResults) -> str:
        """
        Format execution results with context-aware truncation and summarization.

        Uses the context manager to:
        - Apply sliding window: last MAX_DETAILED_STEPS get full context
        - Apply tiered summarization: current loop > previous loop > older loops
        - Summarize or truncate large results
        - Stay within context budget

        Args:
            exec_results: Accumulated tool execution results

        Returns:
            Formatted string suitable for prompt inclusion
        """
        if not exec_results.tool_executions:
            return "No tool executions recorded."

        # Set current loop for tiered context
        self.context_manager.set_current_loop(self.current_loop_number)

        sections = []
        total = len(exec_results.tool_executions)

        # Determine sliding window boundary
        sliding_window_start = max(0, total - self.context_manager.MAX_DETAILED_STEPS)

        for i, tool_exec in enumerate(exec_results.tool_executions, 1):
            # Determine if within sliding window (recent steps)
            is_in_sliding_window = (i - 1) >= sliding_window_start

            # Process result through context manager with tiered context
            result_text = str(tool_exec.result) if tool_exec.result else "No result"
            step_id = f"step_L{self.current_loop_number}_{i}"

            # Get loop number for this result (default to current loop)
            result_loop = getattr(tool_exec, "loop_number", self.current_loop_number)

            if is_in_sliding_window:
                # Within sliding window: use tiered display based on loop age
                display_content = self.context_manager.get_tiered_display_content(
                    result=result_text, result_loop=result_loop, tool_name=tool_exec.tool_name, step_id=step_id
                )

                # Build full section
                section_lines = [f"\n### {step_id}: {tool_exec.tool_name}"]

                # Add reasoning if present
                if tool_exec.reasoning:
                    # Truncate long reasoning
                    reasoning_text = (
                        tool_exec.reasoning[:150] + "..." if len(tool_exec.reasoning) > 150 else tool_exec.reasoning
                    )
                    section_lines.append(f"Reasoning: {reasoning_text}")

                # Add parameters
                param_str = ", ".join([f'{k}="{v}"' for k, v in tool_exec.parameters.items()])
                section_lines.append(f"Parameters: {param_str}")

                # Add result
                section_lines.append(f"Result:\n{display_content}")

                sections.append("\n".join(section_lines))
            else:
                # Outside sliding window: compressed one-liner with cache hint
                section = f"\n• {step_id}: {tool_exec.tool_name} - "
                if len(result_text) > 100:
                    section += f'{len(result_text):,} chars [use get_cached_result("{step_id}")]'
                else:
                    section += result_text[:100]
                sections.append(section)

        return "\n".join(sections)

    def _consolidate_findings(self, exec_results: ExecutionPhaseResults) -> dict:
        """
        Phase 3a: Extract and structure key findings from execution results.

        This is the first step of two-phase analysis. It extracts key findings
        into a structured JSON format, drastically reducing context size for
        the subsequent synthesis step.

        Args:
            exec_results: Accumulated results from execution loop

        Returns:
            Structured dict with consolidated findings
        """
        self.logger.info("🔍 Phase 3a: Consolidating findings...")

        # Format results (compressed for consolidation)
        formatted_results = self._format_results_with_context(exec_results)

        consolidation_prompt = f"""
## Task: Extract Structured Findings

You are analyzing binary analysis results. Extract the KEY findings into a structured JSON format.

## Investigation Goal
{exec_results.goal}

## Execution Results ({exec_results.total_steps} steps)
{formatted_results}

## Required Output Format

Return ONLY valid JSON with this exact structure (no markdown, no explanation):

{{
  "binary_purpose": "Brief 1-2 sentence description of what the binary does",
  "security_apis": [
    {{"address": "0x...", "name": "API_Name", "context": "How it's used (1 sentence)"}}
  ],
  "investigation_leads": [
    {{"address": "0x...", "observation": "What you observed", "hypothesis": "What this might indicate", "priority": "HIGH/MEDIUM/LOW", "next_step": "Specific action to verify"}}
  ],
  "artifacts": [
    {{"address": "0x...", "type": "manifest/string/key", "value": "The actual content (truncated if long)"}}
  ],
  "key_functions": [
    {{"address": "0x...", "name": "Function name", "purpose": "What it does"}}
  ]
}}

RULES:
1. Include items based on EVIDENCE from the tool results above
2. investigation_leads captures patterns YOU find interesting or suspicious:
   - observation: What did you see in the data? (API call, string, pattern, behavior)
   - hypothesis: What could this mean? (potential capability, vulnerability, behavior)
   - priority: How security-relevant is this lead?
   - next_step: What specific action would verify or disprove your hypothesis?
3. Be autonomous - identify leads based on YOUR analysis, not a predefined list
4. Include leads for anything that warrants deeper investigation
5. Limit each array to the 10 MOST IMPORTANT items
6. Keep descriptions concise (under 100 chars)
7. If no items for a category, use an empty array []
8. Return ONLY the JSON object, nothing else
"""

        system_prompt = """You are a binary analysis expert extracting structured findings.
Output ONLY valid JSON. No markdown code blocks. No explanations. Just the JSON object."""

        try:
            response = self.ollama.generate(
                prompt=consolidation_prompt,
                system_prompt=system_prompt,
                phase="analysis",
                max_tokens=getattr(self.llm_config, "analysis_consolidation_max_tokens", 1200),
            )

            # Clean response - remove any markdown code blocks if present
            cleaned = response.strip()
            if cleaned.startswith("```"):
                # Remove markdown code block
                lines = cleaned.split("\n")
                lines = [line for line in lines if not line.startswith("```")]
                cleaned = "\n".join(lines)

            # Try to parse JSON
            findings = json.loads(cleaned)

            # Validate required keys
            required_keys = ["binary_purpose", "security_apis", "investigation_leads", "artifacts", "key_functions"]
            for key in required_keys:
                if key not in findings:
                    findings[key] = [] if key != "binary_purpose" else "Unknown"

            self.logger.info(
                f"✅ Consolidated: {len(findings.get('security_apis', []))} APIs, "
                f"{len(findings.get('investigation_leads', []))} leads, "
                f"{len(findings.get('key_functions', []))} functions"
            )

            return findings

        except json.JSONDecodeError as e:
            self.logger.warning(f"JSON parse failed in consolidation: {e}")
            # Return minimal structure with raw response for fallback
            return {
                "binary_purpose": "Analysis consolidation failed - see raw results",
                "security_apis": [],
                "investigation_leads": [],
                "artifacts": [],
                "key_functions": [],
                "_raw_response": response[:2000] if response else "",
            }
        except Exception as e:
            self.logger.error(f"Consolidation failed: {e}")
            return {
                "binary_purpose": f"Consolidation error: {str(e)}",
                "security_apis": [],
                "investigation_leads": [],
                "artifacts": [],
                "key_functions": [],
            }

    def _synthesize_report(self, findings: dict, goal: str) -> str:
        """
        Phase 3b: Generate final analysis report from consolidated findings.

        This is the second step of two-phase analysis. It receives the compact
        structured findings (not raw results) and writes a complete report.

        Args:
            findings: Consolidated findings dict from _consolidate_findings
            goal: Original investigation goal

        Returns:
            Final analysis report string
        """
        self.logger.info("📝 Phase 3b: Synthesizing final report...")

        # Format findings for the synthesis prompt
        findings_text = json.dumps(findings, indent=2)

        synthesis_prompt = f"""
## Task: Write Final Analysis Report

Based on the consolidated findings below, write a comprehensive analysis report.

## Original Goal
{goal}

## Consolidated Findings
{findings_text}

## Report Requirements

Write a clear, well-structured report that:

1. **Binary Purpose**: Describe what the binary does based on the findings
2. **Security Assessment**:
   - Discuss investigation leads and their security implications
   - Highlight HIGH priority leads that warrant further analysis
   - Note any confirmed or strongly suspected security issues
3. **Key Artifacts**: Reference important addresses and their significance
4. **Recommended Next Steps**: What to investigate further based on the leads

## Format

Start your response with "FINAL RESPONSE:" and provide a complete analysis.
Use markdown formatting. Include specific addresses where relevant.
End with a clear conclusion - do NOT leave the report incomplete.
"""

        system_prompt = """You are writing a final binary analysis report.
Be thorough but concise. Include specific addresses.
IMPORTANT: You must provide a COMPLETE report with a conclusion. Do not truncate."""

        try:
            response = self.ollama.generate(
                prompt=synthesis_prompt,
                system_prompt=system_prompt,
                phase="analysis",
                max_tokens=getattr(self.llm_config, "analysis_report_max_tokens", 1600),
            )

            # CRITICAL: Check if response is empty (happens with reasoning models)
            if not response or len(response.strip()) == 0:
                self.logger.error("⚠️  LLM returned EMPTY response - likely exhausted tokens on reasoning")
                self.logger.info("📝 Generating fallback report from structured findings...")

                # Generate a comprehensive fallback report from findings
                return self._generate_fallback_report(findings, goal)

            return response

        except Exception as e:
            self.logger.error(f"Synthesis failed: {e}")
            # Fallback: return findings as formatted text
            return self._generate_fallback_report(findings, goal, error=str(e))

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
        report_lines = ["FINAL RESPONSE:", ""]

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

        # Build evaluation prompt
        system_prompt, _ = self._build_structured_prompt(phase="evaluation")

        # Smart truncation: preserve beginning (context) AND end (conclusions)
        # The conclusion is critical for goal evaluation and often appears at the end
        EVAL_MAX_CHARS = 4000
        PRESERVE_START = 2000
        PRESERVE_END = 1500

        if len(analysis) > EVAL_MAX_CHARS:
            # Check for completion indicators to help evaluation
            has_final_response = "FINAL RESPONSE:" in analysis
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
            if has_final_response:
                completion_hints.append("Contains 'FINAL RESPONSE' marker")
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

Respond with EXACTLY ONE of these formats:

**If goal is fully achieved:**
GOAL ACHIEVED

**If more investigation needed:**
GOAL NOT ACHIEVED: [one sentence explaining what's missing]

Examples:
- "GOAL ACHIEVED"
- "GOAL NOT ACHIEVED: Need to investigate callers to understand usage"
- "GOAL NOT ACHIEVED: Missing information about error handling"

Be strict: Only mark as GOAL ACHIEVED if the goal is FULLY and COMPLETELY satisfied.
"""

        response = self.ollama.generate_with_phase(user_prompt, phase="evaluation", system_prompt=system_prompt)

        # Retry if empty response (extends retry-on-empty to evaluation phase)
        if not response or not response.strip():
            self.logger.warning("Empty evaluation response - retrying with clarification...")
            retry_prompt = (
                user_prompt
                + "\n\n[NOTE: Your previous response was empty. Please respond with either 'GOAL ACHIEVED' or 'GOAL NOT ACHIEVED: [reason]']"
            )
            response = self.ollama.generate_with_phase(retry_prompt, phase="evaluation", system_prompt=system_prompt)

        # Parse response
        response_clean = response.strip() if response else ""
        goal_achieved = "GOAL ACHIEVED" in response_clean.upper() and "NOT ACHIEVED" not in response_clean.upper()

        if goal_achieved:
            reason = "Goal fully satisfied based on analysis"
        else:
            # Extract reason after "GOAL NOT ACHIEVED:"
            if "GOAL NOT ACHIEVED:" in response_clean:
                reason = response_clean.split("GOAL NOT ACHIEVED:", 1)[1].strip()
            elif not response_clean:
                reason = "Evaluation returned empty response after retry"
            else:
                reason = response_clean

        self.logger.info(f"{'✅' if goal_achieved else '⚠️'} Evaluation: {'Achieved' if goal_achieved else 'Not achieved'}")
        if not goal_achieved:
            self.logger.info(f"   Reason: {reason}")

        return goal_achieved, reason

    def _capture_function_summary(self, function_identifier: str, analysis_text: str) -> None:
        """
        Capture and store a function summary from AI analysis text.

        Args:
            function_identifier: Function address or name identifier
            analysis_text: The AI analysis text to extract summary from
        """
        self.logger.info(
            f"DEBUG: _capture_function_summary called for {function_identifier}, text length: {len(analysis_text)}"
        )
        summary = self._extract_function_summary(analysis_text)
        self.logger.info(f"DEBUG: _extract_function_summary returned: '{summary}'")

        if summary and summary != "No clear summary found":
            # Store in bridge summaries
            if not hasattr(self, "function_summaries"):
                self.function_summaries = {}
            self.function_summaries[function_identifier] = summary
            self.logger.info(f"DEBUG: Captured summary for {function_identifier}: {summary[:100]}...")

            # RAG integration removed - use "Load Vectors" button for vector operations
            # self._add_function_to_rag(function_identifier, summary)

            # ------------------------------------------------------------------
            #  NEW: Attempt to gather caller x-refs for this function
            # ------------------------------------------------------------------
            addr = self._normalize_address(str(function_identifier))
            if addr:
                try:
                    self._collect_xref_context(addr)
                except Exception as e:
                    self.logger.debug(f"Xref context collection failed for {function_identifier}: {e}")
        else:
            self.logger.warning(f"DEBUG: No valid summary extracted for {function_identifier}")

    def _add_function_to_rag(self, function_identifier: str, func_data: Dict[str, Any]) -> None:
        """
        Add a function with enhanced metadata as a RAG vector AND to the knowledge graph.

        Args:
            function_identifier: Function address or name identifier
            func_data: Complete function data dict with metadata
        """
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
                return

            # ============ ENHANCED RAG DOCUMENT BUILDING ============
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
                # Fallback to legacy format
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

                    added_count = 0

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
                    self.logger.error(f"Failed to add function to RAG vectors: {e}")
                    import traceback

                    self.logger.error(f"Full traceback: {traceback.format_exc()}")

        except Exception as e:
            self.logger.warning(f"Failed to add function to RAG vectors: {e}")

    def _get_current_timestamp(self) -> str:
        """Get current timestamp as string."""
        from datetime import datetime

        return datetime.now().isoformat()

    def _extract_function_summary(self, analysis_text: str) -> str:
        """Extract a concise function summary from AI analysis text."""
        if not analysis_text:
            return ""

        # Look for key phrases that indicate function purpose
        lines = analysis_text.split("\n")
        summary_indicators = [
            "this function",
            "the function",
            "it appears to",
            "appears to be",
            "responsible for",
            "purpose is",
            "main purpose",
            "primary function",
            "function does",
            "function is",
            "seems to",
            "likely",
            "probably",
        ]

        best_summary = ""
        for line in lines:
            line = line.strip()
            if len(line) > 20 and len(line) < 200:  # Reasonable length
                line_lower = line.lower()
                if any(indicator in line_lower for indicator in summary_indicators):
                    # Clean up the line
                    if line.endswith("."):
                        line = line[:-1]
                    # Remove common prefixes
                    for prefix in ["Based on the analysis, ", "It appears that ", "The function "]:
                        if line.startswith(prefix):
                            line = line[len(prefix) :]

                    if len(line) > len(best_summary) and len(line) < 150:
                        best_summary = line

        # Fallback: look for any descriptive sentence
        if not best_summary:
            for line in lines:
                line = line.strip()
                if (
                    len(line) > 30
                    and len(line) < 150
                    and ("." in line or "," in line)
                    and not line.startswith("EXECUTE:")
                    and not line.startswith("Step ")
                    and "function" in line.lower()
                ):
                    best_summary = line
                    break

        return best_summary[:150] if best_summary else "Analysis performed"

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

        # Track decompiled functions and capture summaries
        if command["name"] == "decompile_function" and "name" in command["params"]:
            function_name = command["params"]["name"]
            # Don't add to functions_analyzed - decompilation is not the same as analysis
            # Only actual analysis commands should increment the analyzed count

            # Capture summary from the most recent AI response
            if hasattr(self, "partial_outputs") and self.partial_outputs:
                for output in reversed(self.partial_outputs):
                    if output.get("type") in ["reasoning", "review"] and output.get("content"):
                        self._capture_function_summary(function_name, output["content"])
                        break

        elif command["name"] == "decompile_function_by_address" and "address" in command["params"]:
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
            else:
                # If no address provided, analyze_function uses current function
                # We'll add it when we capture the summary with the actual address
                pass

            # Capture summary from the most recent AI response
            if hasattr(self, "partial_outputs") and self.partial_outputs:
                for output in reversed(self.partial_outputs):
                    if output.get("type") in ["reasoning", "review"] and output.get("content"):
                        # Use address if provided, otherwise we'll need to extract it from the result
                        identifier = address if address else "current_function"
                        self._capture_function_summary(identifier, output["content"])
                        break

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
                    current_function_result = self.ghidra.get_current_function()
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
                    decompile_result = self.ghidra.decompile_function(old_name)
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

                # Capture summary from the most recent AI response for rename workflow
                self.logger.info(
                    f"DEBUG: Checking partial_outputs for summary extraction, has partial_outputs: {hasattr(self, 'partial_outputs')}"
                )
                if hasattr(self, "partial_outputs"):
                    self.logger.info(f"DEBUG: partial_outputs length: {len(self.partial_outputs)}")

                    for output in reversed(self.partial_outputs):
                        if output.get("type") in ["reasoning", "review"] and output.get("content"):
                            self.logger.info("DEBUG: Found suitable partial_output for summary extraction")
                            self._capture_function_summary(address, output["content"])
                            break
                    else:
                        self.logger.warning("DEBUG: No suitable partial_outputs found for summary extraction")
                else:
                    self.logger.warning("DEBUG: No partial_outputs attribute found")
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

    def _check_for_clarification_request(self, response: str) -> bool:
        """
        Check if the AI's response is a request for clarification from the user.

        Args:
            response: The AI's response text

        Returns:
            True if the response is a clarification request, False otherwise
        """
        # Simple heuristic: look for question marks near the end of the response
        # and check if the response doesn't contain any tool calls
        if "EXECUTE:" not in response and "?" in response:
            last_paragraph = response.split("\n\n")[-1].strip()
            # If the last paragraph ends with a question mark, it's likely a clarification request
            if last_paragraph.endswith("?"):
                # Additional check: make sure it's not just showing code examples with question marks
                if not ("`" in last_paragraph or "```" in last_paragraph):
                    return True
        return False

    def _extract_suggestions(self, response: str) -> Tuple[str, List[str]]:
        """
        Extract tool improvement suggestions from the AI's response.

        Args:
            response: The AI's response text

        Returns:
            Tuple of (cleaned_response, list_of_suggestions)
        """
        suggestions = []
        cleaned_lines = []

        # Simple parsing: look for lines starting with "SUGGESTION:"
        for line in response.split("\n"):
            if line.strip().startswith("SUGGESTION:"):
                suggestion = line.strip()[len("SUGGESTION:") :].strip()
                suggestions.append(suggestion)
            else:
                cleaned_lines.append(line)

        # If suggestions were found, log them
        if suggestions:
            self.logger.info(f"Found {len(suggestions)} tool improvement suggestions")
            for suggestion in suggestions:
                self.logger.info(f"Tool suggestion: {suggestion}")

        return "\n".join(cleaned_lines), suggestions

    def _generate_cohesive_report(self) -> str:
        """
        Generate a cohesive report from various data gathered during the analysis.

        Returns:
            A comprehensive report as a string
        """
        if not self.partial_outputs:
            return "No analysis was performed or captured."

        # Organize our partial outputs into sections for the report
        report_sections = {
            "plan": [],  # Added section for the initial plan
            "findings": [],
            "insights": [],
            "analysis": [],
            "tools": [],
            "errors": [],  # Added section for errors
            "conclusions": [],
        }

        # First, process the raw responses to capture information that might be truncated in cleaned responses
        raw_responses = []
        for output in self.partial_outputs:
            if output["type"] in ["raw_response", "raw_review"]:
                raw_responses.append(output["content"])

        # Process partial outputs to populate sections
        for output in self.partial_outputs:
            content = output.get("content", "")
            output_type = output.get("type", "")

            # --- Capture Initial Plan ---
            if output_type == "planning":
                report_sections["plan"].append(content)
                continue  # Skip further processing for plan content

            # --- Process Reasoning (Cleaned & Raw) ---
            if output_type in ["reasoning", "review"]:
                # Use the cleaned reasoning/review content for keyword/structure matching

                # Extract numbered insights
                numbered_insights = []
                in_numbered_list = False
                current_insight = ""
                for line in content.split("\n"):
                    if re.match(r"^\s*\d+\.\s", line):
                        if in_numbered_list and current_insight.strip():
                            numbered_insights.append(current_insight.strip())
                        in_numbered_list = True
                        current_insight = line.strip()
                    elif in_numbered_list and line.strip():
                        current_insight += " " + line.strip()
                    elif in_numbered_list:  # End of item
                        if current_insight.strip():
                            numbered_insights.append(current_insight.strip())
                        in_numbered_list = False
                        current_insight = ""
                if in_numbered_list and current_insight.strip():
                    numbered_insights.append(current_insight.strip())
                if numbered_insights:
                    report_sections["insights"].extend(numbered_insights)

                # Extract bulleted findings
                findings_section = False
                for line in content.split("\n"):
                    if any(marker in line.lower() for marker in ["i found:", "findings:", "key observations:", "key finding"]):
                        findings_section = True
                    elif findings_section and not line.strip():
                        findings_section = False
                    if findings_section or line.strip().startswith("- ") or line.strip().startswith("* "):
                        if line.strip():
                            report_sections["findings"].append(line.strip())

                # Extract conclusions
                if any(
                    marker in content.lower()
                    for marker in ["in conclusion", "to summarize", "in summary", "conclusion:", "final analysis"]
                ):
                    conclusion_text = ""
                    in_conclusion = False
                    for line in content.split("\n"):
                        if any(
                            marker in line.lower()
                            for marker in ["in conclusion", "to summarize", "in summary", "conclusion:", "final analysis"]
                        ):
                            in_conclusion = True
                        if in_conclusion and line.strip():
                            conclusion_text += line + "\n"
                    if conclusion_text:
                        report_sections["conclusions"].append(conclusion_text.strip())

                # Extract general analysis (exclude already captured parts)
                analysis_content = content
                for category in ["findings", "insights", "conclusions"]:
                    for item in report_sections[category]:
                        analysis_content = analysis_content.replace(item, "")
                if analysis_content.strip():
                    # Only add if it contains relevant technical terms
                    if any(
                        term in analysis_content.lower()
                        for term in [
                            "function",
                            "address",
                            "import",
                            "export",
                            "binary",
                            "assembly",
                            "code",
                            "decompile",
                            "call",
                            "pointer",
                            "struct",
                        ]
                    ):
                        report_sections["analysis"].append(analysis_content.strip())

        # --- Process Raw Responses for Additional Detail (before EXECUTE) ---
        for raw_response in raw_responses:
            # Extract text before the first EXECUTE block
            pre_execute_text = raw_response.split("EXECUTE:", 1)[0].strip()
            if not pre_execute_text:
                continue

            # Extract numbered insights from raw text
            numbered_insights_raw = []
            in_numbered_list_raw = False
            current_insight_raw = ""
            for line in pre_execute_text.split("\n"):
                if re.match(r"^\s*\d+\.\s", line):
                    if in_numbered_list_raw and current_insight_raw.strip():
                        numbered_insights_raw.append(current_insight_raw.strip())
                    in_numbered_list_raw = True
                    current_insight_raw = line.strip()
                elif in_numbered_list_raw and line.strip():
                    current_insight_raw += " " + line.strip()
                elif in_numbered_list_raw:
                    if current_insight_raw.strip():
                        numbered_insights_raw.append(current_insight_raw.strip())
                    in_numbered_list_raw = False
                    current_insight_raw = ""
            if in_numbered_list_raw and current_insight_raw.strip():
                numbered_insights_raw.append(current_insight_raw.strip())
            if numbered_insights_raw:
                report_sections["insights"].extend(numbered_insights_raw)

            # Extract bulleted findings from raw text
            for line in pre_execute_text.split("\n"):
                if line.strip().startswith("- ") or line.strip().startswith("* "):
                    if line.strip():
                        report_sections["findings"].append(line.strip())

            # Extract general analysis from raw text (exclude already captured parts)
            analysis_content_raw = pre_execute_text
            for category in ["findings", "insights"]:
                for item in report_sections[category]:
                    analysis_content_raw = analysis_content_raw.replace(item, "")
            if analysis_content_raw.strip():
                if any(
                    term in analysis_content_raw.lower()
                    for term in [
                        "function",
                        "address",
                        "import",
                        "export",
                        "binary",
                        "assembly",
                        "code",
                        "decompile",
                        "call",
                        "pointer",
                        "struct",
                    ]
                ):
                    report_sections["analysis"].append(analysis_content_raw.strip())

        # --- Process Tool Results & Errors ---
        tool_results = []
        for output in self.partial_outputs:
            if output["type"] in ["tool_result", "review_tool_result"]:
                result_text = output.get("result", "")
                step_info = f"Step {output.get('step', output.get('review_step', '?'))}"
                tool_info = (
                    f"{output.get('tool', 'unknown')}({', '.join([f'{k}={v}' for k, v in output.get('params', {}).items()])})"
                )

                # Check for errors
                if "ERROR:" in result_text or "Failed" in result_text:
                    report_sections["errors"].append(f"{step_info}: {tool_info} -> {result_text}")
                else:
                    # Successful result - summarize and add to tools list
                    result_lines = result_text.split("\n")
                    # Remove the RESULT: prefix if present
                    result_content = "\n".join([line.replace("RESULT: ", "", 1) for line in result_lines if line.strip()])
                    result_summary = result_content[:150] + ("..." if len(result_content) > 150 else "")
                    tool_results.append(f"{step_info}: {tool_info} -> {result_summary}")

        report_sections["tools"] = tool_results

        # --- Deduplicate Sections ---
        for section in report_sections:
            if isinstance(report_sections[section], list):
                seen = set()
                # Keep order, filter duplicates (case-insensitive for strings)
                report_sections[section] = [
                    x
                    for x in report_sections[section]
                    if not (
                        (x.lower() if isinstance(x, str) else x) in seen or seen.add((x.lower() if isinstance(x, str) else x))
                    )
                ]

        # Option 1: Build a structured report manually
        report = self._build_structured_report(report_sections)

        # Return the manually structured report
        return report

    def _build_structured_report(self, report_sections):
        """
        Build a structured report from the collected sections.

        Args:
            report_sections: Dict of report sections

        Returns:
            A formatted report string
        """
        report = "# Analysis Report\n\n"

        if report_sections["plan"]:
            report += "## Initial Plan\n"
            report += "\n".join(report_sections["plan"]) + "\n\n"

        if report_sections["insights"]:
            report += "## Key Insights\n"
            report += "\n".join(report_sections["insights"]) + "\n\n"

        if report_sections["findings"]:
            report += "## Findings\n"
            report += "\n".join(report_sections["findings"]) + "\n\n"

        if report_sections["analysis"]:
            report += "## Analysis Details\n"
            report += "\n\n".join(report_sections["analysis"]) + "\n\n"

        if report_sections["tools"]:
            report += "## Tools Used (Successful)\n"
            report += "\n".join([f"- {tool}" for tool in report_sections["tools"]]) + "\n\n"

        if report_sections["errors"]:
            report += "## Errors Encountered\n"
            report += "\n".join([f"- {error}" for error in report_sections["errors"]]) + "\n\n"

        if report_sections["conclusions"]:
            report += "## Conclusions\n"
            report += "\n".join(report_sections["conclusions"]) + "\n"

        return report.strip()

    def _parse_plan_tools(self, plan: str) -> List[Dict[str, Any]]:
        """Parses the PLAN section from the AI's response."""
        tools = []
        # Regex to find all TOOL: lines
        tool_lines = re.findall(r"TOOL:\s*(.*)", plan)

        for line in tool_lines:
            try:
                # Split the line into the tool name and its parameters part
                parts = line.split(" PARAMS: ", 1)
                command_name = parts[0].strip()
                params_str = parts[1].strip() if len(parts) > 1 else ""

                params = {}
                if params_str:
                    # Use a more robust regex to parse key-value pairs
                    # This handles quoted strings and unquoted numbers
                    param_pairs = re.findall(r'(\w+)\s*=\s*(".*?"|\S+)', params_str)
                    for key, value in param_pairs:
                        # Strip quotes from string values
                        if value.startswith('"') and value.endswith('"'):
                            params[key] = value[1:-1]
                        else:
                            # Attempt to convert to int/float, otherwise keep as string
                            try:
                                if "." in value:
                                    params[key] = float(value)
                                else:
                                    params[key] = int(value)
                            except ValueError:
                                params[key] = value

                tools.append({"tool": command_name, "params": params})

            except Exception as e:
                self.logger.error(f"Error parsing tool line '{line}': {e}")

        self.logger.info(f"Extracted {len(tools)} planned tools from plan")
        return tools

    def _mark_tool_as_executed(self, command_name: str, params: Dict[str, Any]) -> None:
        """
        Mark a tool as executed in the planned tools tracker.

        Args:
            command_name: The name of the executed command
            params: The parameters used for the command
        """
        for tool_entry in self.planned_tools_tracker["planned"]:
            if tool_entry["tool"] == command_name:
                tool_entry["execution_status"] = "executed"
                break

    def _get_pending_critical_tools_prompt(self) -> str:
        """
        Generate a prompt section about pending critical tools.

        Returns:
            A string to be included in the review prompt if there are pending critical tools
        """
        # Update the pending_critical list based on current execution status
        self.planned_tools_tracker["pending_critical"] = [
            tool
            for tool in self.planned_tools_tracker["planned"]
            if tool["is_critical"] and tool["execution_status"] == "pending"
        ]

        if not self.planned_tools_tracker["pending_critical"]:
            return ""

        # Generate the prompt
        pending_tools_prompt = "\n\nThere are pending critical tool calls that appear necessary but have not been executed:\n"

        for tool in self.planned_tools_tracker["pending_critical"]:
            pending_tools_prompt += f'- {tool["tool"]}: Mentioned in context "{tool["context"]}"\n'

        pending_tools_prompt += "\nPlease ensure these critical tool calls are explicitly executed before concluding the task."

        return pending_tools_prompt

    def _check_implied_actions_without_commands(self, response_text: str) -> str:
        """
        Check if the response text implies actions that should be taken but doesn't include
        the actual EXECUTE commands to perform those actions.

        Args:
            response_text: The AI's response text

        Returns:
            A prompt string asking for explicit commands if needed, otherwise empty string
        """
        # Skip if there are already commands in the response
        if "EXECUTE:" in response_text:
            return ""

        # Check if this is a review prompt we generated - if so, don't re-analyze it
        if "Your response implies certain actions should be taken" in response_text:
            return ""

        # Patterns that indicate implied actions without explicit commands
        implied_action_patterns = [
            (r"(should|will|going to|let's) rename", "rename_function"),
            (r"(should|will|going to|let's) add comment", "set_decompiler_comment"),
            (r"(suggest|proposed|recommend) (naming|naming it|renaming)", "rename_function"),
            (r"(suggest|proposed|recommend) (to|that) name", "rename_function"),
            (r"(appropriate|suitable|better|good|descriptive) name would be", "rename_function"),
            (r"function (should|could|would) be (named|called)", "rename_function"),
            (r"rename (the|this) function (to|as)", "rename_function"),
            (r"naming it ['\"]([\w_]+)['\"]", "rename_function"),
        ]

        response_lower = response_text.lower()

        # Check for implied actions
        implied_actions = []
        for pattern, related_tool in implied_action_patterns:
            if re.search(pattern, response_lower):
                implied_actions.append((pattern, related_tool))

        if not implied_actions:
            return ""

        # Generate a prompt asking for explicit commands
        action_prompt = (
            "\n\nYour response implies certain actions should be taken, but you didn't include explicit EXECUTE commands:\n"
        )

        for pattern, tool in implied_actions:
            matches = re.findall(pattern, response_lower)
            if matches:
                action_prompt += f"- You mentioned: '{pattern.replace('|', ' or ')}'\n"

        action_prompt += "\nPlease provide explicit EXECUTE commands to perform these actions."
        return action_prompt

    def add_to_context(self, role: str, content: str) -> None:
        """
        Add an entry to the context history.

        This method now uses the Pydantic SessionMemory for structured storage
        while maintaining backward compatibility with the legacy context list.

        Args:
            role: The role of the entry ('user', 'assistant', 'tool_call', 'tool_result', etc.)
            content: The content of the entry
        """
        # Add to new Pydantic session (primary storage)
        try:
            message_role = MessageRole(role.lower())
            self.session.add_message(message_role, content)
        except ValueError:
            # If role is not in MessageRole enum, default to SYSTEM
            self.logger.warning(f"Unknown role '{role}', defaulting to SYSTEM")
            self.session.add_message(MessageRole.SYSTEM, content)

        # Maintain legacy context for backward compatibility
        if isinstance(self.context, list):
            self.context.append({"role": role, "content": content})
        elif isinstance(self.context, dict):
            if "history" not in self.context:
                self.context["history"] = []
            self.context["history"].append({"role": role, "content": content})
        else:
            # Create a new list if neither
            self.context = [{"role": role, "content": content}]

    @property
    def ghidra(self):
        """Property for backward compatibility with code referencing bridge.ghidra."""
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
            functions_result = self._collect_all_paginated_list_results(self.ghidra.list_functions)
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
            imports_result = self._collect_all_paginated_list_results(self.ghidra.list_imports)
            if isinstance(imports_result, (list, str)) and not str(imports_result).startswith("ERROR:"):
                if isinstance(imports_result, str):
                    data["imports"] = [i.strip() for i in imports_result.split("\n") if i.strip()]
                else:
                    data["imports"] = imports_result

            # Collect exports
            exports_result = self._collect_all_paginated_list_results(self.ghidra.list_exports)
            if isinstance(exports_result, (list, str)) and not str(exports_result).startswith("ERROR:"):
                if isinstance(exports_result, str):
                    data["exports"] = [e.strip() for e in exports_result.split("\n") if e.strip()]
                else:
                    data["exports"] = exports_result

            # Collect memory segments
            segments_result = self._collect_all_paginated_list_results(self.ghidra.list_segments)
            if isinstance(segments_result, (list, str)) and not str(segments_result).startswith("ERROR:"):
                if isinstance(segments_result, str):
                    data["segments"] = [s.strip() for s in segments_result.split("\n") if s.strip()]
                else:
                    data["segments"] = segments_result

            # Collect classes/namespaces
            classes_result = self._collect_all_paginated_list_results(self.ghidra.list_classes)
            if isinstance(classes_result, (list, str)) and not str(classes_result).startswith("ERROR:"):
                if isinstance(classes_result, str):
                    data["classes"] = [c.strip() for c in classes_result.split("\n") if c.strip()]
                else:
                    data["classes"] = classes_result
            namespaces_result = self._collect_all_paginated_list_results(self.ghidra.list_namespaces)
            if isinstance(namespaces_result, (list, str)) and not str(namespaces_result).startswith("ERROR:"):
                if isinstance(namespaces_result, str):
                    data["namespaces"] = [n.strip() for n in namespaces_result.split("\n") if n.strip()]
                else:
                    data["namespaces"] = namespaces_result

            # Collect data items
            data_items_result = self._collect_all_paginated_list_results(self.ghidra.list_data_items)
            if isinstance(data_items_result, (list, str)) and not str(data_items_result).startswith("ERROR:"):
                if isinstance(data_items_result, str):
                    data["data_items"] = [d.strip() for d in data_items_result.split("\n") if d.strip()]
                else:
                    data["data_items"] = data_items_result

            # Collect strings with addresses for evidence
            try:
                strings_result = self._collect_all_paginated_list_results(self.ghidra.list_strings)
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
            program_info = self.ghidra.get_current_program_info()
            data["metadata"]["binary_name"] = program_info.get("name", "Unknown Binary")
            data["metadata"]["project_name"] = program_info.get("project", "Unknown Project")
            self.logger.info(f"Collected binary info: {data['metadata']['binary_name']}")
        except Exception as e:
            self.logger.warning(f"Failed to collect binary info: {e}")
            data["metadata"]["binary_name"] = "Unknown Binary"

        return data

    def _perform_comprehensive_ai_analysis(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Perform AI-powered analysis of collected binary data."""
        analysis = {
            "software_classification": {},
            "security_assessment": {},
            "function_categorization": {},
            "behavioral_analysis": {},
            "architecture_analysis": {},
            "risk_assessment": {},
        }

        try:
            # Software Classification Analysis
            classification_prompt = self._build_classification_prompt(data)
            classification_response = self.ollama.generate(prompt=classification_prompt)
            analysis["software_classification"] = self._parse_classification_response(classification_response)

            # Security Assessment Analysis
            security_prompt = self._build_security_assessment_prompt(data)
            security_response = self.ollama.generate(prompt=security_prompt)
            analysis["security_assessment"] = self._parse_security_response(security_response)

            # Function Categorization Analysis
            function_prompt = self._build_function_categorization_prompt(data)
            function_response = self.ollama.generate(prompt=function_prompt)
            analysis["function_categorization"] = self._parse_function_response(function_response)

            # Behavioral Pattern Analysis
            behavior_prompt = self._build_behavioral_analysis_prompt(data)
            behavior_response = self.ollama.generate(prompt=behavior_prompt)
            analysis["behavioral_analysis"] = self._parse_behavioral_response(behavior_response)

            # Architecture Analysis
            architecture_prompt = self._build_architecture_prompt(data)
            architecture_response = self.ollama.generate(prompt=architecture_prompt)
            analysis["architecture_analysis"] = self._parse_architecture_response(architecture_response)

            # Overall Risk Assessment
            risk_prompt = self._build_risk_assessment_prompt(data, analysis)
            risk_response = self.ollama.generate(prompt=risk_prompt)
            analysis["risk_assessment"] = self._parse_risk_response(risk_response)

        except Exception as e:
            self.logger.error(f"Error during AI analysis: {e}")
            # Return partial analysis with error noted
            analysis["error"] = str(e)

        return analysis

    def _format_agent_analysis_context(self, data: Dict[str, Any], analysis_type: str = "analysis") -> str:
        """
        Format the agent analysis history section for prompts.

        Handles empty analysis gracefully by providing fallback content
        and explicit permission to speculate based on available data.

        Args:
            data: Binary data dict containing 'agent_analysis_history'
            analysis_type: Type of analysis for context-specific guidance

        Returns:
            Formatted analysis context string
        """
        analysis_history = data.get("agent_analysis_history", "")

        # Check if analysis history is empty or just whitespace
        if not analysis_history or not analysis_history.strip():
            return f"""No prior agent analysis available for this binary.

**IMPORTANT GUIDANCE:**
- You may SPECULATE based on the binary data provided above (imports, exports, function names, strings).
- Base your {analysis_type} on the concrete evidence available (function names, API imports, string references).
- Clearly indicate when you are inferring behavior vs. reporting confirmed findings.
- Do NOT refuse to analyze - provide your best assessment based on available data.
- If certain about something, state it confidently. If uncertain, use phrases like "likely", "appears to", "suggests"."""
        else:
            return analysis_history

    def _build_classification_prompt(self, data: Dict[str, Any]) -> str:
        """Build prompt for software classification analysis."""
        return f"""Analyze this binary and classify the software type and purpose.

**Binary Information:**
- Total Functions: {data["metadata"]["total_functions"]}
- Renamed Functions: {data["metadata"]["renamed_count"]}
- Analyzed Functions: {data["metadata"]["analyzed_count"]}
- Imports: {len(data["imports"])} ({", ".join(data["imports"][:10])}{"..." if len(data["imports"]) > 10 else ""})
- Exports: {len(data["exports"])} ({", ".join(data["exports"][:10])}{"..." if len(data["exports"]) > 10 else ""})
- Memory Segments: {len(data["segments"])}
- Classes/Namespaces: {len(data["classes"]) + len(data["namespaces"])}

**Function Summaries:**
{self._format_summaries_for_prompt(data["function_summaries"])}

**Analysis Requirements:**
Provide a structured classification following this EXACT format:

**SOFTWARE_TYPE:** [Select ONE: Application, Library, Driver, Malware, System_Tool, Game, Utility, Service, Other]
**PRIMARY_PURPOSE:** [Brief description of main functionality]
**SECONDARY_FUNCTIONS:** [List of additional capabilities]
**TARGET_PLATFORM:** [Windows/Linux/macOS/Cross-platform/Embedded]
**ARCHITECTURE_STYLE:** [Monolithic/Modular/Service-oriented/Plugin-based/Other]
**COMPLEXITY_LEVEL:** [Low/Medium/High/Very_High]
**CLASSIFICATION_CONFIDENCE:** [0-100%]
**EVIDENCE:** [Key evidence supporting this classification - MUST include specific function addresses, function names, and string examples. Format: "Function at address 0x... named '...' does X", "String 'Y' found at Z"]

**PREVIOUS AGENT ANALYSIS:**
{self._format_agent_analysis_context(data, "classification")}

**IMPORTANT:** If prior analysis exists, use it as the PRIMARY SOURCE of truth. Otherwise, base your classification on the Binary Information above."""

    def _build_security_assessment_prompt(self, data: Dict[str, Any]) -> str:
        """Build prompt for security risk assessment."""
        return f"""Perform a comprehensive security assessment of this binary.

**Binary Data for Analysis:**
- Functions: {data["metadata"]["total_functions"]} total, {data["metadata"]["renamed_count"]} renamed
- Key Imports: {", ".join(data["imports"][:15])}{"..." if len(data["imports"]) > 15 else ""}
- Function Summaries: {len(data["function_summaries"])} available

**Renamed Functions and Behaviors:**
{self._format_function_behaviors_for_security(data)}

**Security Analysis Requirements:**
Analyze for security risks and provide assessment in this EXACT format:

**IMPORTANT:** For EACH suspicious indicator, security concern, or finding, you MUST provide:
1. The specific function address (e.g., 0x401000)
2. The function name
3. Actual string values, API calls, or code patterns found
4. Concrete examples from the binary

**OVERALL_RISK_LEVEL:** [CRITICAL/HIGH/MEDIUM/LOW]
**RISK_SCORE:** [0-100]
**SECURITY_CATEGORIES:**
- Network_Operations: [NONE/LOW/MEDIUM/HIGH/CRITICAL] - [description with specific addresses and functions]
- File_System_Access: [NONE/LOW/MEDIUM/HIGH/CRITICAL] - [description with specific addresses and functions]
- Registry_Manipulation: [NONE/LOW/MEDIUM/HIGH/CRITICAL] - [description with specific addresses and functions]
- Process_Manipulation: [NONE/LOW/MEDIUM/HIGH/CRITICAL] - [description with specific addresses and functions]
- Cryptographic_Operations: [NONE/LOW/MEDIUM/HIGH/CRITICAL] - [description with specific addresses and functions]
- Memory_Management: [NONE/LOW/MEDIUM/HIGH/CRITICAL] - [description with specific addresses and functions]
- Persistence_Mechanisms: [NONE/LOW/MEDIUM/HIGH/CRITICAL] - [description with specific addresses and functions]
**SUSPICIOUS_INDICATORS:** [List EACH concerning behavior with format: "Description at address 0x... in function '...' - Evidence: specific API/string/pattern"]
**MITIGATION_RECOMMENDATIONS:** [Security recommendations]
**IOCS:** [Potential Indicators of Compromise with specific addresses and strings found]

**PREVIOUS AGENT ANALYSIS:**
{self._format_agent_analysis_context(data, "security assessment")}

**IMPORTANT:** If prior analysis exists, use it as the PRIMARY SOURCE of truth. Otherwise, assess security risks based on the imports, function names, and behaviors observable in the Binary Data above."""

    def _build_function_categorization_prompt(self, data: Dict[str, Any]) -> str:
        """Build prompt for function categorization analysis."""
        return f"""Categorize all functions in this binary by their primary purpose and behavior.

**Available Function Data:**
- Total Functions: {data["metadata"]["total_functions"]}
- Renamed Functions with Summaries: {data["metadata"]["analyzed_count"]}
- Sample Functions: {", ".join(data["functions"][:10])}{"..." if len(data["functions"]) > 10 else ""}

**Function Summaries for Categorization:**
{self._format_summaries_for_categorization(data["function_summaries"])}

**Renamed Functions:**
{self._format_renamed_functions(data["renamed_functions"])}

**Categorization Requirements:**
Analyze and categorize functions into standard categories. Provide results in this EXACT format:

**IMPORTANT:** For each category with functions, list notable functions WITH their addresses in format: "function_name at 0x..."

**FUNCTION_CATEGORIES:**
**Network_Operations:** [count] - [function names WITH addresses (0x...) and brief descriptions]
**File_IO_Operations:** [count] - [function names WITH addresses (0x...) and brief descriptions]
**Memory_Management:** [count] - [function names WITH addresses (0x...) and brief descriptions]
**Cryptographic_Functions:** [count] - [function names WITH addresses (0x...) and brief descriptions]
**String_Processing:** [count] - [function names WITH addresses (0x...) and brief descriptions]
**UI_Interface:** [count] - [function names WITH addresses (0x...) and brief descriptions]
**Registry_Operations:** [count] - [function names WITH addresses (0x...) and brief descriptions]
**Process_Control:** [count] - [function names WITH addresses (0x...) and brief descriptions]
**Authentication:** [count] - [function names WITH addresses (0x...) and brief descriptions]
**Configuration:** [count] - [function names WITH addresses (0x...) and brief descriptions]
**Utility_Helper:** [count] - [function names WITH addresses (0x...) and brief descriptions]
**Error_Handling:** [count] - [function names WITH addresses (0x...) and brief descriptions]
**Main_Core:** [count] - [function names WITH addresses (0x...) and brief descriptions]
**Unknown_Other:** [count] - [function names WITH addresses (0x...) and brief descriptions]

**CATEGORY_INSIGHTS:** [Analysis of what the function distribution reveals about software purpose, cite specific address examples]

**PREVIOUS AGENT ANALYSIS:**
{self._format_agent_analysis_context(data, "function categorization")}

**IMPORTANT:** If prior analysis exists, use it to guide categorization. Otherwise, categorize based on function names, import patterns, and observable code structure."""

    def _build_behavioral_analysis_prompt(self, data: Dict[str, Any]) -> str:
        """Build prompt for behavioral pattern analysis."""
        return f"""Analyze behavioral patterns and workflows in this binary.

**Behavioral Data:**
- Function Summaries: {len(data["function_summaries"])} detailed analyses
- Import Dependencies: {", ".join(data["imports"][:20])}
- Export Capabilities: {", ".join(data["exports"][:10])}

**Function Behavior Details:**
{self._format_behavioral_data(data)}

**Behavioral Analysis Requirements:**
Identify patterns, workflows, and behavioral characteristics. Format response as:

**IMPORTANT:** Cite specific function addresses demonstrating each behavioral pattern. Use format: "Behavior demonstrated by function at 0x..."

**PRIMARY_WORKFLOWS:** [Main execution flows and processes - cite specific function addresses]
**DATA_FLOW_PATTERNS:** [How data moves through the application - cite specific function addresses]
**INTERACTION_PATTERNS:** [User, network, file, system interactions - cite specific function addresses and strings]
**EXECUTION_MODELS:** [How the software operates - service, interactive, batch, etc. - cite specific function addresses]
**DEPENDENCY_ANALYSIS:** [Key dependencies and their purposes - cite specific import/export addresses]
**OPERATIONAL_MODES:** [Different modes of operation - cite specific function addresses]
**TRIGGER_MECHANISMS:** [What causes different behaviors - cite specific addresses and conditions]
**BEHAVIORAL_FINGERPRINT:** [Unique behavioral characteristics that identify this software - cite specific addresses and evidence]

**PREVIOUS AGENT ANALYSIS:**
{self._format_agent_analysis_context(data, "behavioral analysis")}

**IMPORTANT:** If prior analysis exists, use it as the PRIMARY SOURCE. Otherwise, infer behavioral patterns from imports, exports, and function structures."""

    def _build_architecture_prompt(self, data: Dict[str, Any]) -> str:
        """Build prompt for software architecture analysis."""
        return f"""Analyze the software architecture and design patterns used in this binary.

**Architecture Data:**
- Code Organization: {len(data["classes"])} classes, {len(data["namespaces"])} namespaces
- Memory Layout: {len(data["segments"])} segments
- Function Structure: {data["metadata"]["total_functions"]} functions
- Data Structures: {len(data["data_items"])} data items

**Function Architecture:**
{self._format_architecture_data(data)}

**Architecture Analysis Requirements:**
Analyze the software architecture and provide results in this EXACT format:

**ARCHITECTURAL_PATTERN:** [Layered/MVC/Component-based/Microservices/Monolithic/Other]
**CODE_ORGANIZATION:** [How code is structured and organized]
**MODULE_STRUCTURE:** [How different modules/components are arranged]
**DESIGN_PATTERNS:** [Observable design patterns like Singleton, Factory, Observer, etc.]
**MEMORY_LAYOUT:** [How memory is organized and used]
**INTERFACE_DESIGN:** [How different components interface with each other]
**SCALABILITY_DESIGN:** [How the architecture supports scalability]
**ARCHITECTURE_QUALITY:** [Assessment of architectural quality and maintainability]
**COMPLEXITY_METRICS:** [Analysis of architectural complexity]

**PREVIOUS AGENT ANALYSIS:**
{self._format_agent_analysis_context(data, "architecture analysis")}

**IMPORTANT:** If prior analysis exists, align your architecture analysis with it. Otherwise, derive architectural insights from code organization and structure."""

    def _build_risk_assessment_prompt(self, data: Dict[str, Any], analysis: Dict[str, Any]) -> str:
        """Build prompt for overall risk assessment."""
        return f"""Provide a comprehensive risk assessment based on all analysis conducted.

**Analysis Summary:**
- Software Classification: {analysis.get("software_classification", {}).get("type", "Unknown")}
- Security Assessment: {analysis.get("security_assessment", {}).get("risk_level", "Unknown")}
- Function Categories: {len(analysis.get("function_categorization", {}))} categories analyzed
- Architecture: {analysis.get("architecture_analysis", {}).get("pattern", "Unknown")}

**Risk Assessment Requirements:**
Provide final risk assessment in this EXACT format:

**IMPORTANT:** For EACH risk factor identified, cite the specific address where the risk was identified. Format: "Risk description at address 0x... in function '...'"

**OVERALL_RISK_RATING:** [CRITICAL/HIGH/MEDIUM/LOW]
**RISK_SCORE:** [0-100]
**PRIMARY_RISK_FACTORS:** [Top 3-5 risk factors WITH specific addresses and function names where identified]
**THREAT_LEVEL:** [IMMEDIATE/HIGH/MODERATE/LOW/MINIMAL]
**RECOMMENDED_ACTIONS:** [Specific actions to take, referencing specific addresses/functions if applicable]
**MONITORING_RECOMMENDATIONS:** [What to monitor if deployed, cite specific functions/addresses to watch]
**CONTAINMENT_STRATEGY:** [How to safely contain or isolate if needed]
**BUSINESS_IMPACT:** [Potential business/operational impact]
**TECHNICAL_RISK:** [Technical risks and implications with specific addresses]

**PREVIOUS AGENT ANALYSIS:**
{self._format_agent_analysis_context(data, "risk assessment")}

**IMPORTANT:** If prior analysis exists, use it as the PRIMARY SOURCE for risk calculation. Otherwise, assess risks based on the analysis summary and observable indicators."""

    def _format_summaries_for_prompt(self, summaries: Dict[str, str]) -> str:
        """Format function summaries for AI prompts with comprehensive RAG retrieval."""
        if not summaries:
            return "No function summaries available."

        formatted = []

        # Enhanced RAG approach: Use vector store to find ALL relevant functions
        if (
            hasattr(self, "enable_cag")
            and self.enable_cag
            and hasattr(self, "cag_manager")
            and self.cag_manager
            and hasattr(self.cag_manager, "vector_store")
            and self.cag_manager.vector_store
        ):
            # Use comprehensive multi-vector retrieval
            enhanced_context = self._get_comprehensive_function_context(summaries)
            if enhanced_context:
                return enhanced_context

        # Fallback to basic formatting with limited functions
        for func, summary in list(summaries.items())[:10]:  # Limit for prompt size
            formatted.append(f"- {func}: {summary[:100]}{'...' if len(summary) > 100 else ''}")

        if len(summaries) > 10:
            formatted.append(f"... and {len(summaries) - 10} more functions with summaries")

        return "\n".join(formatted)

    def _get_comprehensive_function_context(self, summaries: Dict[str, str]) -> str:
        """Get comprehensive function context using multi-vector RAG retrieval."""
        try:
            vector_store = self.cag_manager.vector_store
            all_context = []

            # Strategy 1: Search for different categories of functions
            search_queries = [
                "security cryptography authentication encryption",
                "network communication socket http tcp",
                "file system disk read write open",
                "memory allocation buffer management",
                "process thread execution control",
                "registry configuration system settings",
                "string parsing text processing",
                "user interface input output display",
                "database storage data management",
                "error handling exception logging",
                "main entry point initialization",
                "malware persistence backdoor",
            ]

            retrieved_functions = set()
            query_results = []

            # Perform multiple targeted searches
            for query in search_queries:
                results = vector_store.search(query, top_k=5)
                for result in results:
                    doc = result["document"]
                    if doc.get("type") == "function_analysis" and doc.get("name") not in retrieved_functions:
                        query_results.append(
                            {
                                "name": doc.get("name"),
                                "content": doc.get("text", ""),
                                "score": result["score"],
                                "category": query.split()[0],  # First word as category
                            }
                        )
                        retrieved_functions.add(doc.get("name"))

            # Strategy 2: Include high-priority functions from summaries
            priority_keywords = [
                "main",
                "entry",
                "init",
                "start",
                "connect",
                "send",
                "receive",
                "read",
                "write",
                "create",
                "delete",
                "encrypt",
                "decrypt",
                "auth",
            ]

            for func_name, summary in summaries.items():
                if func_name not in retrieved_functions and any(
                    keyword.lower() in func_name.lower() or keyword.lower() in summary.lower() for keyword in priority_keywords
                ):
                    query_results.append({"name": func_name, "content": summary, "score": 1.0, "category": "priority"})
                    retrieved_functions.add(func_name)

            # Strategy 3: Add remaining functions by relevance score
            remaining_functions = []
            for func_name, summary in summaries.items():
                if func_name not in retrieved_functions:
                    # Simple relevance scoring based on summary length and keywords
                    relevance_score = len(summary) / 500.0  # Longer summaries get higher scores
                    if any(
                        keyword in summary.lower() for keyword in ["critical", "important", "key", "main", "core", "primary"]
                    ):
                        relevance_score += 0.5

                    remaining_functions.append(
                        {"name": func_name, "content": summary, "score": relevance_score, "category": "additional"}
                    )

            # Sort by score and add top remaining functions
            remaining_functions.sort(key=lambda x: x["score"], reverse=True)
            query_results.extend(remaining_functions[:20])  # Add top 20 remaining

            # Format comprehensive context
            if query_results:
                all_context.append("## COMPREHENSIVE FUNCTION ANALYSIS")
                all_context.append(f"**Total Functions Analyzed: {len(query_results)} of {len(summaries)}**\n")

                # Group by category for better organization
                categories = {}
                for result in query_results:
                    category = result["category"]
                    if category not in categories:
                        categories[category] = []
                    categories[category].append(result)

                # Format each category
                for category, functions in categories.items():
                    if len(functions) > 0:
                        all_context.append(f"### {category.upper()} FUNCTIONS:")
                        for func in functions[:10]:  # Limit per category for readability
                            name = func["name"]
                            content = func["content"]
                            # Truncate very long content but be more generous
                            truncated_content = content[:300] + "..." if len(content) > 300 else content
                            all_context.append(f"- **{name}**: {truncated_content}")

                        if len(functions) > 10:
                            all_context.append(f"  *... and {len(functions) - 10} more {category} functions*")
                        all_context.append("")

                return "\n".join(all_context)

        except Exception as e:
            self.logger.warning(f"Error in comprehensive RAG retrieval: {e}")

        return None

    def _format_function_behaviors_for_security(self, data: Dict[str, Any]) -> str:
        """Format function behaviors specifically for security analysis with comprehensive RAG."""
        # Enhanced RAG approach for security analysis
        if (
            hasattr(self, "enable_cag")
            and self.enable_cag
            and hasattr(self, "cag_manager")
            and self.cag_manager
            and hasattr(self.cag_manager, "vector_store")
            and self.cag_manager.vector_store
        ):
            enhanced_security_context = self._get_comprehensive_security_context(data)
            if enhanced_security_context:
                return enhanced_security_context

        # Fallback to basic formatting
        formatted = []

        # Add renamed functions with their behaviors
        for old_name, new_name in data["renamed_functions"][:15]:
            summary = data["function_summaries"].get(old_name, "No summary available")
            formatted.append(f"- {old_name} → {new_name}: {summary[:150]}{'...' if len(summary) > 150 else ''}")

        return "\n".join(formatted) if formatted else "No renamed functions with behavioral data available."

    def _get_comprehensive_security_context(self, data: Dict[str, Any]) -> str:
        """Get comprehensive security-focused function context using RAG."""
        try:
            vector_store = self.cag_manager.vector_store
            all_context = []

            # Security-focused search queries
            security_queries = [
                "authentication login password credential verification",
                "encryption cryptography cipher hash algorithm",
                "network socket communication tcp udp http",
                "file access read write permission disk",
                "registry key value configuration system",
                "process execution spawn thread creation",
                "memory allocation buffer overflow protection",
                "privilege escalation administrator elevation",
                "persistence startup autorun service",
                "injection code dll payload shellcode",
                "obfuscation packing anti-analysis stealth",
                "communication c2 command control callback",
            ]

            retrieved_functions = set()
            security_results = []

            # Perform security-focused searches
            for query in security_queries:
                results = vector_store.search(query, top_k=8)  # More results for security
                for result in results:
                    doc = result["document"]
                    if doc.get("type") == "function_analysis" and doc.get("name") not in retrieved_functions:
                        # Calculate security relevance score
                        content = doc.get("text", "")
                        security_score = self._calculate_security_score(content)

                        security_results.append(
                            {
                                "old_name": doc.get("name", "unknown"),
                                "new_name": self._find_renamed_function(doc.get("name"), data),
                                "content": content,
                                "vector_score": result["score"],
                                "security_score": security_score,
                                "category": query.split()[0],
                            }
                        )
                        retrieved_functions.add(doc.get("name"))

            # Add high-risk functions from renamed functions
            for old_name, new_name in data["renamed_functions"]:
                if old_name not in retrieved_functions:
                    summary = data["function_summaries"].get(old_name, "")
                    security_score = self._calculate_security_score(summary)

                    if security_score > 0.3:  # Only include if security-relevant
                        security_results.append(
                            {
                                "old_name": old_name,
                                "new_name": new_name,
                                "content": summary,
                                "vector_score": 0.8,
                                "security_score": security_score,
                                "category": "renamed",
                            }
                        )

            # Sort by combined security and vector scores
            security_results.sort(key=lambda x: (x["security_score"] + x["vector_score"]) / 2, reverse=True)

            if security_results:
                all_context.append("## COMPREHENSIVE SECURITY ANALYSIS")
                all_context.append(f"**Security-Relevant Functions Analyzed: {len(security_results)}**\n")

                # Group by security risk level
                high_risk = [r for r in security_results if r["security_score"] > 0.7]
                medium_risk = [r for r in security_results if 0.4 <= r["security_score"] <= 0.7]
                low_risk = [r for r in security_results if r["security_score"] < 0.4]

                if high_risk:
                    all_context.append("### 🔴 HIGH SECURITY RISK FUNCTIONS:")
                    for result in high_risk[:15]:  # Top 15 high-risk
                        self._format_security_function(result, all_context)
                    all_context.append("")

                if medium_risk:
                    all_context.append("### 🟡 MEDIUM SECURITY RISK FUNCTIONS:")
                    for result in medium_risk[:10]:  # Top 10 medium-risk
                        self._format_security_function(result, all_context)
                    all_context.append("")

                if low_risk:
                    all_context.append("### 🟢 LOWER RISK / UTILITY FUNCTIONS:")
                    for result in low_risk[:5]:  # Top 5 low-risk for completeness
                        self._format_security_function(result, all_context)
                    all_context.append("")

                return "\n".join(all_context)

        except Exception as e:
            self.logger.warning(f"Error in comprehensive security RAG retrieval: {e}")

        return None

    def _calculate_security_score(self, content: str) -> float:
        """Calculate security relevance score for function content."""
        if not content:
            return 0.0

        content_lower = content.lower()
        score = 0.0

        # High-risk indicators
        high_risk_keywords = [
            "encrypt",
            "decrypt",
            "password",
            "credential",
            "authentication",
            "privilege",
            "administrator",
            "system",
            "registry",
            "service",
            "network",
            "socket",
            "http",
            "tcp",
            "udp",
            "connect",
            "send",
            "file",
            "read",
            "write",
            "delete",
            "create",
            "access",
            "process",
            "thread",
            "spawn",
            "execute",
            "injection",
            "memory",
            "allocation",
            "buffer",
            "overflow",
            "shellcode",
            "persistence",
            "startup",
            "autorun",
            "malware",
            "backdoor",
        ]

        # Medium-risk indicators
        medium_risk_keywords = [
            "string",
            "parse",
            "format",
            "validate",
            "check",
            "verify",
            "error",
            "exception",
            "log",
            "debug",
            "config",
            "setting",
        ]

        # Count occurrences
        for keyword in high_risk_keywords:
            if keyword in content_lower:
                score += 0.15

        for keyword in medium_risk_keywords:
            if keyword in content_lower:
                score += 0.05

        # Bonus for function names that indicate security functions
        if any(name in content_lower for name in ["auth", "crypt", "security", "protect", "verify"]):
            score += 0.2

        return min(score, 1.0)  # Cap at 1.0

    def _find_renamed_function(self, old_name: str, data: Dict[str, Any]) -> str:
        """Find the new name for a renamed function."""
        for old, new in data["renamed_functions"]:
            if old == old_name:
                return new
        return old_name  # Return original if not renamed

    def _format_security_function(self, result: Dict[str, Any], context_list: List[str]) -> None:
        """Format a security function result for the context."""
        old_name = result["old_name"]
        new_name = result["new_name"]
        content = result["content"]
        security_score = result["security_score"]

        # Truncate content but be more generous for security analysis
        truncated_content = content[:400] + "..." if len(content) > 400 else content

        if old_name != new_name:
            context_list.append(f"- **{old_name} → {new_name}** (Security Risk: {security_score:.2f}): {truncated_content}")
        else:
            context_list.append(f"- **{old_name}** (Security Risk: {security_score:.2f}): {truncated_content}")

    def _format_summaries_for_categorization(self, summaries: Dict[str, str]) -> str:
        """Format summaries for function categorization with comprehensive RAG."""
        # Use the same comprehensive approach as the main formatter
        return self._format_summaries_for_prompt(summaries)

    def _format_renamed_functions(self, renamed_functions: List[tuple]) -> str:
        """Format renamed functions list."""
        if not renamed_functions:
            return "No functions have been renamed yet."

        formatted = []
        for old_name, new_name in renamed_functions[:20]:
            formatted.append(f"- {old_name} → {new_name}")

        if len(renamed_functions) > 20:
            formatted.append(f"... and {len(renamed_functions) - 20} more renamed functions")

        return "\n".join(formatted)

    def _format_behavioral_data(self, data: Dict[str, Any]) -> str:
        """Format behavioral data with comprehensive RAG analysis."""
        # Enhanced RAG approach for behavioral analysis
        if (
            hasattr(self, "enable_cag")
            and self.enable_cag
            and hasattr(self, "cag_manager")
            and self.cag_manager
            and hasattr(self.cag_manager, "vector_store")
            and self.cag_manager.vector_store
        ):
            enhanced_behavioral_context = self._get_comprehensive_behavioral_context(data)
            if enhanced_behavioral_context:
                return enhanced_behavioral_context

        # Fallback to basic behavioral data
        return self._format_summaries_for_prompt(data["function_summaries"])

    def _get_comprehensive_behavioral_context(self, data: Dict[str, Any]) -> str:
        """Get comprehensive behavioral context using RAG."""
        try:
            vector_store = self.cag_manager.vector_store
            all_context = []

            # Behavioral analysis search queries
            behavioral_queries = [
                "initialization startup entry point main",
                "workflow process sequence execution flow",
                "data processing transformation parsing",
                "communication interaction interface api",
                "state management configuration settings",
                "event handling callback response trigger",
                "loop iteration recursive repetitive",
                "decision logic conditional branching",
                "cleanup finalization termination shutdown",
                "validation verification check constraint",
            ]

            retrieved_functions = set()
            behavioral_results = []

            # Perform behavioral-focused searches
            for query in behavioral_queries:
                results = vector_store.search(query, top_k=6)
                for result in results:
                    doc = result["document"]
                    if doc.get("type") == "function_analysis" and doc.get("name") not in retrieved_functions:
                        content = doc.get("text", "")
                        behavioral_score = self._calculate_behavioral_score(content)

                        behavioral_results.append(
                            {
                                "name": doc.get("name"),
                                "content": content,
                                "vector_score": result["score"],
                                "behavioral_score": behavioral_score,
                                "category": query.split()[0],
                            }
                        )
                        retrieved_functions.add(doc.get("name"))

            # Add important functions from summaries
            for func_name, summary in data["function_summaries"].items():
                if func_name not in retrieved_functions:
                    behavioral_score = self._calculate_behavioral_score(summary)
                    if behavioral_score > 0.4:  # Only include behaviorally significant functions
                        behavioral_results.append(
                            {
                                "name": func_name,
                                "content": summary,
                                "vector_score": 0.7,
                                "behavioral_score": behavioral_score,
                                "category": "identified",
                            }
                        )
                        retrieved_functions.add(func_name)

            # Sort by behavioral relevance
            behavioral_results.sort(key=lambda x: x["behavioral_score"], reverse=True)

            if behavioral_results:
                all_context.append("## COMPREHENSIVE BEHAVIORAL ANALYSIS")
                all_context.append(f"**Behaviorally Significant Functions: {len(behavioral_results)}**\n")

                # Group by behavioral significance
                core_behavior = [r for r in behavioral_results if r["behavioral_score"] > 0.8]
                supporting_behavior = [r for r in behavioral_results if 0.5 <= r["behavioral_score"] <= 0.8]
                utility_behavior = [r for r in behavioral_results if r["behavioral_score"] < 0.5]

                if core_behavior:
                    all_context.append("### 🎯 CORE BEHAVIORAL FUNCTIONS:")
                    for result in core_behavior[:12]:
                        self._format_behavioral_function(result, all_context)
                    all_context.append("")

                if supporting_behavior:
                    all_context.append("### 🔧 SUPPORTING BEHAVIORAL FUNCTIONS:")
                    for result in supporting_behavior[:15]:
                        self._format_behavioral_function(result, all_context)
                    all_context.append("")

                if utility_behavior:
                    all_context.append("### ⚙️ UTILITY / HELPER FUNCTIONS:")
                    for result in utility_behavior[:8]:
                        self._format_behavioral_function(result, all_context)
                    all_context.append("")

                return "\n".join(all_context)

        except Exception as e:
            self.logger.warning(f"Error in comprehensive behavioral RAG retrieval: {e}")

        return None

    def _calculate_behavioral_score(self, content: str) -> float:
        """Calculate behavioral significance score for function content."""
        if not content:
            return 0.0

        content_lower = content.lower()
        score = 0.0

        # Core behavioral indicators
        core_indicators = [
            "main",
            "entry",
            "start",
            "initialize",
            "init",
            "setup",
            "process",
            "execute",
            "run",
            "handle",
            "manage",
            "control",
            "create",
            "generate",
            "build",
            "construct",
            "parse",
            "connect",
            "communicate",
            "send",
            "receive",
            "transfer",
            "validate",
            "verify",
            "check",
            "authenticate",
            "authorize",
        ]

        # Supporting behavioral indicators
        supporting_indicators = [
            "configure",
            "setup",
            "prepare",
            "cleanup",
            "finalize",
            "update",
            "modify",
            "change",
            "transform",
            "convert",
            "save",
            "load",
            "read",
            "write",
            "store",
            "retrieve",
            "format",
            "encode",
            "decode",
            "compress",
            "extract",
        ]

        # State and flow indicators
        flow_indicators = [
            "loop",
            "iterate",
            "repeat",
            "while",
            "for",
            "next",
            "if",
            "then",
            "else",
            "switch",
            "case",
            "condition",
            "callback",
            "event",
            "trigger",
            "signal",
            "notify",
            "wait",
            "sleep",
            "pause",
            "resume",
            "continue",
            "stop",
        ]

        # Count occurrences with different weights
        for indicator in core_indicators:
            if indicator in content_lower:
                score += 0.25

        for indicator in supporting_indicators:
            if indicator in content_lower:
                score += 0.15

        for indicator in flow_indicators:
            if indicator in content_lower:
                score += 0.10

        # Bonus for function names that suggest behavioral significance
        behavioral_names = ["main", "entry", "process", "handle", "execute", "init"]
        if any(name in content_lower for name in behavioral_names):
            score += 0.3

        return min(score, 1.0)  # Cap at 1.0

    def _format_behavioral_function(self, result: Dict[str, Any], context_list: List[str]) -> None:
        """Format a behavioral function result for the context."""
        name = result["name"]
        content = result["content"]
        behavioral_score = result["behavioral_score"]

        # Truncate content but preserve behavioral details
        truncated_content = content[:350] + "..." if len(content) > 350 else content

        context_list.append(f"- **{name}** (Behavioral Score: {behavioral_score:.2f}): {truncated_content}")

    def _format_architecture_data(self, data: Dict[str, Any]) -> str:
        """Format architecture data with comprehensive analysis."""
        # Enhanced RAG approach for architecture analysis
        if (
            hasattr(self, "enable_cag")
            and self.enable_cag
            and hasattr(self, "cag_manager")
            and self.cag_manager
            and hasattr(self.cag_manager, "vector_store")
            and self.cag_manager.vector_store
        ):
            enhanced_architecture_context = self._get_comprehensive_architecture_context(data)
            if enhanced_architecture_context:
                return enhanced_architecture_context

        # Fallback to basic architecture data
        return self._format_summaries_for_prompt(data["function_summaries"])

    def _get_comprehensive_architecture_context(self, data: Dict[str, Any]) -> str:
        """Get comprehensive architecture context using RAG."""
        try:
            vector_store = self.cag_manager.vector_store
            all_context = []

            # Architecture-focused search queries
            architecture_queries = [
                "initialization setup configuration startup",
                "interface api public private function",
                "module component service layer structure",
                "dependency injection factory pattern",
                "data model structure class object",
                "controller handler manager coordinator",
                "utility helper common shared library",
                "persistence storage database file system",
                "logging debug error monitoring trace",
                "cleanup disposal finalize terminate",
            ]

            retrieved_functions = set()
            architecture_results = []

            # Perform architecture-focused searches
            for query in architecture_queries:
                results = vector_store.search(query, top_k=5)
                for result in results:
                    doc = result["document"]
                    if doc.get("type") == "function_analysis" and doc.get("name") not in retrieved_functions:
                        content = doc.get("text", "")
                        architecture_score = self._calculate_architecture_score(content)

                        architecture_results.append(
                            {
                                "name": doc.get("name"),
                                "content": content,
                                "vector_score": result["score"],
                                "architecture_score": architecture_score,
                                "category": query.split()[0],
                            }
                        )
                        retrieved_functions.add(doc.get("name"))

            # Sort by architectural significance
            architecture_results.sort(key=lambda x: x["architecture_score"], reverse=True)

            if architecture_results:
                all_context.append("## COMPREHENSIVE ARCHITECTURE ANALYSIS")
                all_context.append(f"**Architecturally Significant Functions: {len(architecture_results)}**\n")

                # Group by architectural layer/role
                categories = {}
                for result in architecture_results:
                    category = result["category"]
                    if category not in categories:
                        categories[category] = []
                    categories[category].append(result)

                # Format each architectural category
                for category, functions in categories.items():
                    if len(functions) > 0:
                        all_context.append(f"### {category.upper()} LAYER:")
                        for func in functions[:8]:  # Limit per category
                            self._format_architecture_function(func, all_context)
                        all_context.append("")

                return "\n".join(all_context)

        except Exception as e:
            self.logger.warning(f"Error in comprehensive architecture RAG retrieval: {e}")

        return None

    def _calculate_architecture_score(self, content: str) -> float:
        """Calculate architectural significance score for function content."""
        if not content:
            return 0.0

        content_lower = content.lower()
        score = 0.0

        # Architecture pattern indicators
        pattern_indicators = [
            "factory",
            "singleton",
            "observer",
            "strategy",
            "adapter",
            "facade",
            "proxy",
            "decorator",
            "builder",
            "command",
        ]

        # Component/layer indicators
        layer_indicators = [
            "controller",
            "service",
            "repository",
            "model",
            "view",
            "handler",
            "manager",
            "coordinator",
            "processor",
            "engine",
        ]

        # Structure indicators
        structure_indicators = [
            "interface",
            "abstract",
            "base",
            "parent",
            "child",
            "public",
            "private",
            "static",
            "dynamic",
            "virtual",
        ]

        # Count architectural significance
        for indicator in pattern_indicators:
            if indicator in content_lower:
                score += 0.3

        for indicator in layer_indicators:
            if indicator in content_lower:
                score += 0.2

        for indicator in structure_indicators:
            if indicator in content_lower:
                score += 0.1

        return min(score, 1.0)  # Cap at 1.0

    def _format_architecture_function(self, result: Dict[str, Any], context_list: List[str]) -> None:
        """Format an architecture function result for the context."""
        name = result["name"]
        content = result["content"]
        architecture_score = result["architecture_score"]

        # Truncate content for architecture analysis
        truncated_content = content[:300] + "..." if len(content) > 300 else content

        context_list.append(f"- **{name}** (Arch Score: {architecture_score:.2f}): {truncated_content}")

    def _format_summaries_for_categorization(self, summaries: Dict[str, str]) -> str:
        """Format summaries for function categorization with comprehensive RAG."""
        # Use the same comprehensive approach as the main formatter
        return self._format_summaries_for_prompt(summaries)

    def _format_renamed_functions(self, renamed_functions: List[tuple]) -> str:
        """Format renamed functions list."""
        if not renamed_functions:
            return "No functions have been renamed yet."

        formatted = []
        for old_name, new_name in renamed_functions[:20]:
            formatted.append(f"- {old_name} → {new_name}")

        if len(renamed_functions) > 20:
            formatted.append(f"... and {len(renamed_functions) - 20} more renamed functions")

        return "\n".join(formatted)

    def _format_behavioral_data(self, data: Dict[str, Any]) -> str:
        """Format data for behavioral analysis."""
        return self._format_summaries_for_prompt(data["function_summaries"])

    def _format_architecture_data(self, data: Dict[str, Any]) -> str:
        """Format data for architecture analysis."""
        formatted = []
        if data["classes"]:
            formatted.append(f"Classes: {', '.join(data['classes'][:10])}")
        if data["namespaces"]:
            formatted.append(f"Namespaces: {', '.join(data['namespaces'][:10])}")
        if data["segments"]:
            formatted.append(f"Memory Segments: {', '.join(data['segments'][:5])}")

        return "\n".join(formatted) if formatted else "Limited architecture data available."

    # Response parsing methods
    def _parse_classification_response(self, response: str) -> Dict[str, str]:
        """Parse software classification response."""
        parsed = {}
        try:
            lines = response.split("\n")
            for line in lines:
                if "**SOFTWARE_TYPE:**" in line:
                    parsed["type"] = line.split("**SOFTWARE_TYPE:**")[1].strip()
                elif "**PRIMARY_PURPOSE:**" in line:
                    parsed["purpose"] = line.split("**PRIMARY_PURPOSE:**")[1].strip()
                elif "**CLASSIFICATION_CONFIDENCE:**" in line:
                    parsed["confidence"] = line.split("**CLASSIFICATION_CONFIDENCE:**")[1].strip()
                elif "**EVIDENCE:**" in line:
                    parsed["evidence"] = line.split("**EVIDENCE:**")[1].strip()

            # Extract addresses from the evidence section
            parsed["addresses"] = self._extract_addresses_from_analysis(response)
        except Exception as e:
            self.logger.warning(f"Error parsing classification response: {e}")
            parsed["raw_response"] = response

        return parsed

    def _parse_security_response(self, response: str) -> Dict[str, str]:
        """Parse security assessment response."""
        parsed = {}
        try:
            lines = response.split("\n")
            indicators_section = []
            capturing_indicators = False

            for line in lines:
                if "**OVERALL_RISK_LEVEL:**" in line:
                    parsed["risk_level"] = line.split("**OVERALL_RISK_LEVEL:**")[1].strip()
                elif "**RISK_SCORE:**" in line:
                    parsed["risk_score"] = line.split("**RISK_SCORE:**")[1].strip()
                elif "**SUSPICIOUS_INDICATORS:**" in line:
                    capturing_indicators = True
                    # Get initial content after the header
                    remainder = line.split("**SUSPICIOUS_INDICATORS:**")[1].strip()
                    if remainder:
                        indicators_section.append(remainder)
                elif "**MITIGATION_RECOMMENDATIONS:**" in line or "**IOCS:**" in line:
                    capturing_indicators = False
                elif capturing_indicators and line.strip():
                    indicators_section.append(line.strip())

            if indicators_section:
                parsed["indicators"] = "\n".join(indicators_section)

            # Extract addresses from suspicious indicators and entire response
            parsed["addresses"] = self._extract_addresses_from_analysis(response)

            # Extract IOCs section if present
            if "**IOCS:**" in response:
                iocs_match = response.split("**IOCS:**")[1].split("**")[0] if "**IOCS:**" in response else ""
                parsed["iocs"] = iocs_match.strip()

        except Exception as e:
            self.logger.warning(f"Error parsing security response: {e}")
            parsed["raw_response"] = response

        return parsed

    def _parse_function_response(self, response: str) -> Dict[str, str]:
        """Parse function categorization response."""
        parsed = {}
        try:
            # Extract function categories with addresses preserved
            import re

            categories = re.findall(r"\*\*([^:]+):\*\* \[(\d+)\] - ([^*]+)", response)
            for category, count, description in categories:
                # Keep the full description which should now include addresses
                parsed[category.lower().replace("_", " ")] = f"{count} functions: {description.strip()}"

            # Extract all addresses from function categorization
            parsed["addresses"] = self._extract_addresses_from_analysis(response)

            # Also capture insights if present
            if "**CATEGORY_INSIGHTS:**" in response:
                insights_match = (
                    response.split("**CATEGORY_INSIGHTS:**")[1].split("**")[0] if "**CATEGORY_INSIGHTS:**" in response else ""
                )
                parsed["insights"] = insights_match.strip()

        except Exception as e:
            self.logger.warning(f"Error parsing function response: {e}")
            parsed["raw_response"] = response

        return parsed

    def _parse_behavioral_response(self, response: str) -> Dict[str, str]:
        """Parse behavioral analysis response."""
        parsed = {}
        try:
            lines = response.split("\n")
            for line in lines:
                if "**PRIMARY_WORKFLOWS:**" in line:
                    parsed["workflows"] = line.split("**PRIMARY_WORKFLOWS:**")[1].strip()
                elif "**BEHAVIORAL_FINGERPRINT:**" in line:
                    parsed["fingerprint"] = line.split("**BEHAVIORAL_FINGERPRINT:**")[1].strip()

            # Extract addresses from behavioral analysis
            parsed["addresses"] = self._extract_addresses_from_analysis(response)

        except Exception as e:
            self.logger.warning(f"Error parsing behavioral response: {e}")
            parsed["raw_response"] = response

        return parsed

    def _parse_architecture_response(self, response: str) -> Dict[str, str]:
        """Parse architecture analysis response."""
        parsed = {}
        try:
            lines = response.split("\n")
            for line in lines:
                if "**ARCHITECTURAL_PATTERN:**" in line:
                    parsed["pattern"] = line.split("**ARCHITECTURAL_PATTERN:**")[1].strip()
                elif "**ARCHITECTURE_QUALITY:**" in line:
                    parsed["quality"] = line.split("**ARCHITECTURE_QUALITY:**")[1].strip()
        except Exception as e:
            self.logger.warning(f"Error parsing architecture response: {e}")
            parsed["raw_response"] = response

        return parsed

    def _parse_risk_response(self, response: str) -> Dict[str, str]:
        """Parse risk assessment response."""
        parsed = {}
        try:
            lines = response.split("\n")
            risk_factors_section = []
            capturing_factors = False

            for line in lines:
                if "**OVERALL_RISK_RATING:**" in line:
                    parsed["rating"] = line.split("**OVERALL_RISK_RATING:**")[1].strip()
                elif "**THREAT_LEVEL:**" in line:
                    parsed["threat_level"] = line.split("**THREAT_LEVEL:**")[1].strip()
                elif "**RECOMMENDED_ACTIONS:**" in line:
                    capturing_factors = False
                    parsed["recommendations"] = line.split("**RECOMMENDED_ACTIONS:**")[1].strip()
                elif "**PRIMARY_RISK_FACTORS:**" in line:
                    capturing_factors = True
                    remainder = line.split("**PRIMARY_RISK_FACTORS:**")[1].strip()
                    if remainder:
                        risk_factors_section.append(remainder)
                elif capturing_factors and line.strip() and not line.startswith("**"):
                    risk_factors_section.append(line.strip())

            if risk_factors_section:
                parsed["risk_factors"] = "\n".join(risk_factors_section)

            # Extract addresses from risk assessment
            parsed["addresses"] = self._extract_addresses_from_analysis(response)

        except Exception as e:
            self.logger.warning(f"Error parsing risk response: {e}")
            parsed["raw_response"] = response

        return parsed

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

## 🏗️ Architecture Analysis

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

## ⚠️ Risk Mitigation

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
        """
        Generate HTML-formatted vulnerability report using AI.

        This method:
        1. Builds a context summary from analysis data
        2. Calls the LLM with html_report_generation_prompt to get structured JSON
        3. Parses the JSON response into sections
        4. Assembles final HTML using the report_template module
        """
        from src.report_template import generate_html_report, ReportMetadata

        # Build context for the AI
        context = self._build_html_report_context(data, analysis)

        # Get the HTML report generation prompt
        prompt = self.config.ollama.html_report_generation_prompt

        # Build the full prompt with context
        full_prompt = f"""{prompt}

## ANALYSIS DATA TO REPORT:

### Binary Information:
- **Binary Name:** {data.get("metadata", {}).get("binary_name", "Unknown Binary")}
- **Total Functions:** {data.get("metadata", {}).get("total_functions", 0)}
- **Analyzed Functions:** {data.get("metadata", {}).get("analyzed_count", 0)}
- **Renamed Functions:** {data.get("metadata", {}).get("renamed_count", 0)}
- **Imports:** {len(data.get("imports", []))}
- **Exports:** {len(data.get("exports", []))}

### Security Assessment:
- **Risk Level:** {analysis.get("security_assessment", {}).get("risk_level", "Not assessed")}
- **Risk Score:** {analysis.get("security_assessment", {}).get("risk_score", "N/A")}/100
- **Indicators:** {analysis.get("security_assessment", {}).get("indicators", "None")}

### Software Classification:
- **Type:** {analysis.get("software_classification", {}).get("type", "Unknown")}
- **Purpose:** {analysis.get("software_classification", {}).get("purpose", "Unknown")}
- **Confidence:** {analysis.get("software_classification", {}).get("confidence", "N/A")}

### Risk Assessment:
- **Rating:** {analysis.get("risk_assessment", {}).get("rating", "Not assessed")}
- **Threat Level:** {analysis.get("risk_assessment", {}).get("threat_level", "Unknown")}
- **Recommendations:** {analysis.get("risk_assessment", {}).get("recommendations", "None")}

### Key Imports (sample):
{self._format_imports_sample(data.get("imports", [])[:20])}

### Behavioral Analysis:
- **Workflows:** {analysis.get("behavioral_analysis", {}).get("workflows", "Not analyzed")}
- **Fingerprint:** {analysis.get("behavioral_analysis", {}).get("fingerprint", "Not identified")}

### Evidence with Addresses:
{self._format_address_evidence(analysis)}

Finally here is some context that will be helpful:
{context}

Now generate the JSON report based on this data.
"""

        try:
            # Call LLM to generate the structured report
            response = self._call_llm_for_html_report(full_prompt)

            # Parse the JSON response
            sections, ai_metadata = self._parse_html_report_response(response)

            # If no sections were generated, use the fallback report
            if not sections:
                self.logger.info("No sections generated from AI, using fallback report")
                return self._generate_fallback_html_report(data, analysis)

            # Create metadata
            binary_name = data.get("metadata", {}).get("binary_name", "Unknown Binary")
            metadata = ReportMetadata(
                binary_name=binary_name,
                severity=ai_metadata.get("severity", "MEDIUM"),
                subtitle=ai_metadata.get("subtitle", "AI-Powered Binary Analysis Report"),
                tool_name="OGhidra MCP",
            )

            # Generate the final HTML
            return generate_html_report(sections, metadata)

        except Exception as e:
            self.logger.error(f"Error generating HTML report: {e}")
            # Fallback to a basic HTML report
            return self._generate_fallback_html_report(data, analysis)

    def _build_html_report_context(self, data: Dict[str, Any], analysis: Dict[str, Any]) -> str:
        """Build context string for HTML report generation."""
        context_parts = []

        # Add function summaries if available
        summaries = data.get("function_summaries", {})
        if summaries:
            context_parts.append("## Key Function Summaries:")
            for name, summary in list(summaries.items())[:10]:
                context_parts.append(f"- **{name}:** {summary[:200]}...")

        return "\n".join(context_parts)

    def _format_imports_sample(self, imports: List[str]) -> str:
        """Format a sample of imports for the prompt."""
        if not imports:
            return "No imports available"
        return "\n".join(f"- {imp}" for imp in imports[:15])

    def _format_address_evidence(self, analysis: Dict[str, Any]) -> str:
        """Format address evidence from analysis for the prompt."""
        evidence = []

        # Collect addresses from various sections
        for section_name in ["security_assessment", "software_classification", "risk_assessment"]:
            section = analysis.get(section_name, {})
            addresses = section.get("addresses", [])
            if addresses:
                for addr_info in addresses[:5]:
                    if isinstance(addr_info, dict):
                        evidence.append(f"- {addr_info.get('address', 'N/A')}: {addr_info.get('context', 'No context')}")

        return "\n".join(evidence) if evidence else "No specific address evidence available"

    def _call_llm_for_html_report(self, prompt: str) -> str:
        """Call the LLM to generate the HTML report structure."""
        try:
            # Use the configured LLM client (self.ollama holds either OllamaClient or ExternalClient)
            if hasattr(self, "ollama") and self.ollama:
                # Both clients support the generate method
                response = self.ollama.generate(prompt=prompt)
                return response
            else:
                self.logger.warning("No LLM client available for HTML report generation")
                return "{}"
        except Exception as e:
            self.logger.error(f"Error calling LLM for HTML report: {e}")
            return "{}"

    def _parse_html_report_response(self, response: str) -> tuple:
        """
        Parse the AI's JSON response into ReportSection objects.

        Returns:
            Tuple of (List[ReportSection], metadata_dict)
        """
        from src.report_template import ReportSection, build_stats_grid, build_attack_vectors, build_timeline, build_table
        import json
        import re

        sections = []
        metadata = {"severity": "MEDIUM", "subtitle": "Binary Analysis Report"}

        try:
            # Try to extract JSON from the response
            # Handle cases where the AI might wrap it in markdown code blocks
            json_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", response, re.DOTALL)
            if json_match:
                json_str = json_match.group(1)
            else:
                # Try to find raw JSON
                json_start = response.find("{")
                json_end = response.rfind("}") + 1
                if json_start >= 0 and json_end > json_start:
                    json_str = response[json_start:json_end]
                else:
                    raise ValueError("No JSON found in response")

            report_data = json.loads(json_str)

            # Extract metadata
            if "metadata" in report_data:
                metadata = report_data["metadata"]

            # Process sections
            for section_data in report_data.get("sections", []):
                section_id = section_data.get("id", "unknown")
                title = section_data.get("title", "Section")
                icon = section_data.get("icon", "📄")
                content_type = section_data.get("content_type", "html")
                content = section_data.get("content", "")

                # Process content based on type
                if content_type == "stats" and isinstance(content, (str, list)):
                    if isinstance(content, str):
                        try:
                            content = json.loads(content)
                        except Exception as e:
                            self.logger.warning(f"Failed to load JSON for 'stats': {e}")
                            pass
                    if isinstance(content, list):
                        content = build_stats_grid(content)

                elif content_type == "attack_vectors" and isinstance(content, (str, list)):
                    if isinstance(content, str):
                        try:
                            content = json.loads(content)
                        except Exception as e:
                            self.logger.warning(f"Failed to load JSON for 'attack_vectors': {e}")
                            pass
                    if isinstance(content, list):
                        content = build_attack_vectors(content)

                elif content_type == "timeline" and isinstance(content, (str, list)):
                    if isinstance(content, str):
                        try:
                            content = json.loads(content)
                        except Exception as e:
                            self.logger.warning(f"Failed to load JSON for 'timeline': {e}")
                            pass
                    if isinstance(content, list):
                        content = build_timeline(content)

                elif content_type == "table" and isinstance(content, (str, dict)):
                    if isinstance(content, str):
                        try:
                            content = json.loads(content)
                        except Exception as e:
                            self.logger.warning(f"Failed to load JSON for 'table': {e}")
                            pass
                    if isinstance(content, dict):
                        headers = content.get("headers", [])
                        rows = content.get("rows", [])
                        address_cols = [0] if headers and "Address" in headers[0] else []
                        content = build_table(headers, rows, address_cols)

                elif content_type == "discovery" and isinstance(content, (str, list)):
                    from src.report_template import build_vulnerability_discovery

                    if isinstance(content, str):
                        try:
                            content = json.loads(content)
                        except Exception as e:
                            self.logger.warning(f"Failed to load JSON for 'discovery': {e}")
                            pass
                    if isinstance(content, list):
                        content = build_vulnerability_discovery(content)

                elif content_type == "key_findings" and isinstance(content, (str, list)):
                    from src.report_template import build_key_findings

                    if isinstance(content, str):
                        try:
                            content = json.loads(content)
                        except Exception as e:
                            self.logger.warning(f"Failed to load JSON for 'key_findings': {e}")
                            pass
                    if isinstance(content, list):
                        content = build_key_findings(content)

                elif content_type == "security_imports" and isinstance(content, (str, list)):
                    from src.report_template import build_security_imports

                    if isinstance(content, str):
                        try:
                            content = json.loads(content)
                        except Exception as e:
                            self.logger.warning(f"Failed to load JSON for 'security_imports': {e}")
                            pass
                    if isinstance(content, list):
                        content = build_security_imports(content)

                sections.append(
                    ReportSection(id=section_id, title=title, icon=icon, content_type=content_type, content=str(content))
                )

            # If parsing succeeded but no sections were created, add fallback
            if not sections:
                raise ValueError("No sections found in parsed response")

        except Exception as e:
            self.logger.warning(f"Error parsing HTML report response: {e}")
            # Create a fallback section with the raw response
            if response and response.strip() and response != "{}":
                sections.append(
                    ReportSection(
                        id="raw_analysis",
                        title="Analysis Results",
                        icon="📋",
                        content_type="html",
                        content=f'<div class="summary-content"><pre>{response[:5000]}</pre></div>',
                    )
                )
            else:
                # No valid response - return empty sections to trigger full fallback
                self.logger.warning("Empty or invalid LLM response, using fallback report")

        return sections, metadata

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

    def _extract_addresses_from_analysis(self, analysis_text: str) -> List[Dict[str, str]]:
        """
        Extract addresses and their associated findings from AI analysis text.

        Args:
            analysis_text: The AI-generated analysis text

        Returns:
            List of dictionaries with 'address', 'context', 'finding' keys
        """
        import re

        findings = []

        # Pattern to match addresses with context
        # Matches patterns like: "at address 0x401000", "0x401000 in function", etc.
        address_patterns = [
            r'(?:at|in|address)\s+(0x[0-9a-fA-F]{6,})\s+(?:in\s+)?(?:function\s+)?["\']?([^"\'\n,.:]+)?',
            r'(0x[0-9a-fA-F]{6,})\s+["\']([^"\'\n,.:]+)["\']',
            r'function\s+["\']?([^"\'\s]+)["\']?\s+at\s+(0x[0-9a-fA-F]{6,})',
        ]

        lines = analysis_text.split("\n")
        for line in lines:
            for pattern in address_patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for match in matches:
                    groups = match.groups()
                    # Handle different capture group orders
                    address = None
                    function = None

                    for group in groups:
                        if group and group.startswith("0x"):
                            address = group
                        elif group and not group.startswith("0x"):
                            function = group

                    if address:
                        findings.append(
                            {
                                "address": address,
                                "function": function or "unknown",
                                "context": line.strip(),
                                "finding": line.strip(),
                            }
                        )

        return findings

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

    def _enrich_findings_with_locations(self, analysis: Dict[str, Any], data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich analysis findings with specific location data.

        Args:
            analysis: The analysis dictionary from AI
            data: The collected binary data

        Returns:
            Enriched analysis with location data
        """
        enriched = analysis.copy()

        # Extract addresses from all analysis sections
        all_findings = []

        for section_key, section_value in analysis.items():
            if isinstance(section_value, dict):
                for key, value in section_value.items():
                    if isinstance(value, str):
                        findings = self._extract_addresses_from_analysis(value)
                        for finding in findings:
                            finding["section"] = section_key
                            finding["subsection"] = key
                            all_findings.append(finding)
            elif isinstance(section_value, str):
                findings = self._extract_addresses_from_analysis(section_value)
                for finding in findings:
                    finding["section"] = section_key
                    all_findings.append(finding)

        # Add extracted findings to enriched analysis
        enriched["extracted_findings"] = all_findings

        return enriched

    # ------------------------------------------------------------------
    # X-ref context helper
    # ------------------------------------------------------------------

    def _collect_xref_context(self, address: str, max_funcs: int = 10) -> None:
        """Fetch functions that reference *address* and capture quick summaries.

        Stores results in self.function_xrefs[address] = [caller_addrs].
        Also decompiles and extracts summaries for new callers (up to *max_funcs*).
        """
        if not hasattr(self, "function_xrefs"):
            self.function_xrefs = {}

        if address in self.function_xrefs:
            # Already collected
            return

        # Call MCP client
        xrefs = []
        try:
            xrefs = self.ghidra.get_xrefs_to(address, limit=max_funcs)  # type: ignore
        except Exception as e:
            self.logger.debug(f"get_xrefs_to failed for {address}: {e}")
            return

        # Normalise list to raw addresses
        caller_addrs = []
        for ref in xrefs[:max_funcs]:
            if isinstance(ref, dict):
                addr = ref.get("from") or ref.get("address") or ""
            else:
                addr = str(ref)
            if addr and re.fullmatch(r"[0-9a-fA-F]{6,}", addr):
                caller_addrs.append(addr)

        self.function_xrefs[address] = caller_addrs

        # Capture summaries for each caller if not already known
        for caller in caller_addrs:
            if hasattr(self, "function_summaries") and caller in self.function_summaries:
                continue
            try:
                decomp = self.ghidra.decompile_function_by_address(caller)  # type: ignore
                if isinstance(decomp, str):
                    caller_summary = self._extract_function_summary(decomp)
                    if caller_summary:
                        if not hasattr(self, "function_summaries"):
                            self.function_summaries = {}
                        self.function_summaries[caller] = caller_summary
            except Exception as e:
                self.logger.debug(f"Failed to decompile caller {caller}: {e}")

    # ------------------------------------------------------------------
    #  Address normalisation helpers
    # ------------------------------------------------------------------

    def _normalize_address(self, identifier: str) -> Optional[str]:
        """Try to extract a pure hexadecimal address from various identifier
        forms (e.g. 'FUN_401000', 'thunk_FUN_401000', '0x401000',
        'Function: FUN_401000 at 401000').

        Returns the hex string (lower-case, no '0x' prefix) or ``None`` if
        no valid address can be found.
        """
        if not identifier:
            return None

        # Strip common 0x prefix if present
        if identifier.startswith(("0x", "0X")):
            identifier = identifier[2:]

        # Already a bare hex value?
        if re.fullmatch(r"[0-9a-fA-F]{6,}", identifier):
            return identifier.lower()

        # Search for a hex substring of length ≥6 anywhere in the string
        match = re.search(r"([0-9a-fA-F]{6,})", identifier)
        if match:
            return match.group(1).lower()

        return None


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
    bridge = Bridge(config=config, include_capabilities=args.include_capabilities, max_agent_steps=args.max_steps)

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
            "╔══════════════════════════════════════════════════════════════════╗\n"
            "║                                                                  ║\n"
            "║  OGhidra - Simplified Three-Phase Architecture                   ║\n"
            "║  ------------------------------------------                      ║\n"
            "║                                                                  ║\n"
            "║  1. Planning Phase: Create a plan for addressing the query       ║\n"
            "║  2. Tool Calling Phase: Execute tools to gather information      ║\n"
            "║  3. Analysis Phase: Analyze results and provide answers          ║\n"
            "║                                                                  ║\n"
            "║  For more information, see README-ARCHITECTURE.md                ║\n"
            "║                                                                  ║\n"
            "╚══════════════════════════════════════════════════════════════════╝"
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
