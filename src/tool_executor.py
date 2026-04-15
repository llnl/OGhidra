"""
ToolExecutor — Shared command execution engine for the OGhidra orchestration system.

Extracted from Bridge to enable both the legacy agentic loop and the new
Orchestrator/WorkerAgent architecture to share a single tool execution pipeline.

Responsibilities:
  - Command name normalization (camelCase → snake_case)
  - Command existence validation (with suggestions on miss)
  - Parameter normalization (parameter name mappings)
  - Decompilation/function cache management
  - CAG memory-based duplicate detection (optional)
  - Semantic string category translation (list_strings improvement)
  - Import thunk hint injection (get_function_xrefs improvement)
  - Post-execution hook for analysis state tracking

The Bridge, WorkerAgent, and any future components hold a reference to the same
ToolExecutor instance; it does NOT own the GhidraClient or CommandParser — those
are injected at construction time.
"""

import logging
import re
from typing import Dict, Any, List, Optional, Callable, Tuple


class ToolExecutor:
    """
    Shared command execution engine.

    Usage::

        executor = ToolExecutor(ghidra_client, command_parser, context_manager)
        executor.register_bridge_command("search_function_summaries", my_handler)
        result = executor.execute_command("decompile_function", {"name": "main"})
    """

    # Commands that should NOT be cached (real-time or state-dependent)
    NO_CACHE_COMMANDS = frozenset([
        "list_imports",
        "list_exports",
        "list_strings",
        "list_segments",
        "get_current_address",
        "check_health",
        "health_check",
    ])

    def __init__(
        self,
        ghidra_client,
        command_parser,
        context_manager=None,
        cag_manager=None,
        enable_cag: bool = False,
        logger: Optional[logging.Logger] = None,
        on_command_executed: Optional[Callable] = None,
    ):
        """
        Args:
            ghidra_client: GhidraMCPClient instance for Ghidra tool calls.
            command_parser: CommandParser for validation & enhanced errors.
            context_manager: ContextManager for result caching / retrieval.
            cag_manager: Optional CAGManager for duplicate-command detection.
            enable_cag: Whether CAG deduplication is active.
            logger: Optional logger; falls back to module-level logger.
            on_command_executed: Optional callback ``(command_dict, result_str) -> None``
                invoked after every successful Ghidra command execution so callers
                can update analysis state, coverage, FunctionRegistry, etc.
        """
        self.ghidra_client = ghidra_client
        self.command_parser = command_parser
        self.context_manager = context_manager
        self.cag_manager = cag_manager
        self.enable_cag = enable_cag
        self.logger = logger or logging.getLogger(__name__)
        self.on_command_executed = on_command_executed

        # --- Caching infrastructure (previously Bridge._init_caches) ---
        self.decompilation_cache: Dict[str, Any] = {}
        self.function_cache: Dict[str, Any] = {}
        self.cache_stats: Dict[str, int] = {
            "hits": 0,
            "misses": 0,
            "cache_size": 0,
        }

        # --- Bridge-level command handlers ---
        # Commands handled locally (not forwarded to ghidra_client).
        # Registered via ``register_bridge_command(name, handler)``.
        self._bridge_commands: Dict[str, Callable] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def register_bridge_command(self, name: str, handler: Callable):
        """Register a local command handler (not forwarded to Ghidra).

        Args:
            name: Normalized command name (snake_case, lowercase).
            handler: ``(params: dict) -> dict`` returning a result dict.
        """
        self._bridge_commands[name.lower().replace("-", "_").replace(" ", "_")] = handler

    def execute_command(self, command_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a command with parameters.

        Routes through:
          1. Registered bridge-level commands (get_cached_result, etc.)
          2. Command normalization & existence check
          3. Parameter validation
          4. Semantic category translation (list_strings improvement)
          5. CAG deduplication (optional)
          6. Cache lookup
          7. Ghidra client execution
          8. Cache storage + post-execution hook

        Args:
            command_name: The command name (camelCase or snake_case accepted).
            params: Parameters for the command.

        Returns:
            Result dict (varies by command).

        Raises:
            ValueError: On unknown command or parameter validation failure.
        """
        try:
            # ----- 1. Bridge-level command dispatch -----
            normalized_bridge_cmd = command_name.lower().replace("-", "_").replace(" ", "_")

            # NOTE: get_cached_result was removed — it depends on context_manager.result_cache
            # which is always empty in orchestrator mode. Workers now use the tool
            # execution ledger (visible in user prompt) + hard dedup cache instead.

            # Registered bridge commands
            if normalized_bridge_cmd in self._bridge_commands:
                return self._bridge_commands[normalized_bridge_cmd](params)

            # ----- 2. Normalize command name -----
            normalized_command = self._normalize_command_name(command_name)
            if not normalized_command:
                exists, error_message, similar_commands, _ = self._check_command_exists(command_name)
                if not exists:
                    if similar_commands:
                        suggestion_str = f" Did you mean: {', '.join(similar_commands[:3])}?"
                    else:
                        suggestion_str = ""
                    enhanced_unknown_command_error = f"{error_message}{suggestion_str}"
                    raise ValueError(enhanced_unknown_command_error)

            # ----- 3. Parameter validation -----
            is_valid, error_message = self.command_parser.validate_command_parameters(
                normalized_command, params
            )
            if not is_valid:
                enhanced_error = self.command_parser.get_enhanced_error_message(
                    command_name, params, error_message
                )
                raise ValueError(enhanced_error)

            # ----- 4. Semantic string category translation (list_strings) -----
            if normalized_command == "list_strings":
                params = self._translate_string_category(params)

            # ----- 5. CAG duplicate detection -----
            if self.enable_cag and self.cag_manager:
                should_skip, skip_reason = self.cag_manager.should_skip_command(normalized_command, params)
                if should_skip:
                    self.logger.warning(f"🧠 CAG Memory suggests skipping: {skip_reason}")
                    cached_result = self.cag_manager.get_cached_command_result(normalized_command, params)
                    if cached_result:
                        self.logger.info(f"🎯 Using CAG cached result for {normalized_command}")
                        return {"result": cached_result, "source": "cag_cache"}
                    else:
                        guidance_msg = (
                            f"Command '{normalized_command}' skipped due to recent execution. {skip_reason}"
                        )
                        return {"result": guidance_msg, "source": "cag_skip", "skipped": True}

            # ----- 6. Cache lookup -----
            command_func = getattr(self.ghidra_client, normalized_command)
            cache_key = self._generate_cache_key(normalized_command, params)
            cached_result = self._get_cached_result(normalized_command, cache_key, params)

            if cached_result is not None:
                self.cache_stats["hits"] += 1
                self.logger.info(
                    f"🎯 Cache HIT for {normalized_command} (key: {cache_key}) - "
                    f"Stats: {self.cache_stats['hits']} hits, {self.cache_stats['misses']} misses"
                )
                return cached_result

            # ----- 7. Execute via Ghidra client -----
            self.cache_stats["misses"] += 1
            self.logger.info(f"💫 Cache MISS for {normalized_command} (key: {cache_key}) - Executing...")

            result = command_func(**params)

            # Import thunk hint injection (get_function_xrefs improvement)
            if normalized_command == "get_function_xrefs" and (not result or "0" in str(result)):
                result = self._inject_xref_hint(result)

            # ----- 8. Cache storage -----
            self._cache_result(normalized_command, cache_key, params, result)

            # Update CAG memory
            if self.enable_cag and self.cag_manager:
                self.cag_manager.update_command_execution(normalized_command, params, str(result))

            # Post-execution hook (analysis state, coverage, FunctionRegistry, etc.)
            if self.on_command_executed:
                command_dict = {"name": normalized_command, "params": params}
                self.on_command_executed(command_dict, str(result))

            return result

        except Exception as e:
            error_message = str(e)
            enhanced_error = self.command_parser.get_enhanced_error_message(
                command_name, params, error_message
            )
            raise ValueError(enhanced_error) from e

    # ------------------------------------------------------------------
    # Command normalization
    # ------------------------------------------------------------------

    def _normalize_command_name(self, command_name: str) -> str:
        """Normalize a command name (e.g., convert camelCase to snake_case).

        Returns the normalized name or empty string if not found.
        """
        if hasattr(self.ghidra_client, command_name):
            return command_name

        snake_case = re.sub(r"(?<!^)(?=[A-Z])", "_", command_name).lower()
        if hasattr(self.ghidra_client, snake_case):
            logging.info(f"Normalized command name from '{command_name}' to '{snake_case}'")
            return snake_case

        return ""

    def _check_command_exists(self, command_name: str) -> Tuple[bool, str, List[str], List[str]]:
        """Check if a command exists and provide suggestions if not.

        Returns:
            ``(exists, error_message, similar_commands, all_available_commands)``
        """
        normalized_command = self._normalize_command_name(command_name)
        available_commands = [
            name
            for name in dir(self.ghidra_client)
            if not name.startswith("_") and callable(getattr(self.ghidra_client, name))
        ]

        if normalized_command:
            return True, "", [], available_commands

        # Not found — build suggestions
        similar_commands = []
        for cmd in available_commands:
            if command_name.lower() in cmd.lower() or cmd.lower() in command_name.lower():
                similar_commands.append(cmd)

        suggestion_msg = ""
        if similar_commands:
            suggestion_msg = f"\nDid you mean one of these? {', '.join(similar_commands)}"

        if command_name == "decompile":
            suggestion_msg = (
                "\nDid you mean 'decompile_function(name=\"function_name\")' "
                "or 'decompile_function_by_address(address=\"1400011a8\")'?"
            )
        elif command_name == "disassemble":
            suggestion_msg = (
                "\nThere is no 'disassemble' command. "
                "Try 'decompile_function_by_address(address=\"1400011a8\")' instead."
            )

        error_message = f"Unknown command: {command_name}{suggestion_msg}"
        return False, error_message, similar_commands, available_commands

    def _normalize_command_params(self, command_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize command parameters (camelCase keys, command-specific renames)."""
        normalized_params: Dict[str, Any] = {}

        param_mappings = {
            "functionAddress": "address",
            "function_address": "address",
            "functionName": "name",
            "function_name": "name",
            "oldName": "old_name",
            "newName": "new_name",
        }

        command_specific_mappings = {
            "rename_function_by_address": {"address": "function_address"},
            "decompile_function_by_address": {"function_address": "address"},
        }

        # Command-specific first
        if command_name in command_specific_mappings:
            for orig_key, new_key in command_specific_mappings[command_name].items():
                if orig_key in params:
                    normalized_params[new_key] = params[orig_key]
                    logging.info(
                        f"Normalized parameter '{orig_key}' to '{new_key}' for command '{command_name}'"
                    )

        # General mappings
        for key, value in params.items():
            if key in normalized_params:
                continue
            norm_key = param_mappings.get(key, key)
            if norm_key != key:
                logging.info(
                    f"Normalized parameter '{key}' to '{norm_key}' for command '{command_name}'"
                )
            normalized_params[norm_key] = value

        return normalized_params

    # ------------------------------------------------------------------
    # Caching infrastructure
    # ------------------------------------------------------------------

    def _generate_cache_key(self, command_name: str, params: Dict[str, Any]) -> str:
        """Generate a unique cache key for a command invocation."""
        if command_name in ("decompile_function", "analyze_function"):
            if "name" in params and params["name"]:
                return f"{command_name}:{params['name']}"
            elif "address" in params and params["address"]:
                return f"{command_name}:{params['address']}"
            else:
                try:
                    current_func = self.ghidra_client.get_current_function()
                    if isinstance(current_func, str) and "Function:" in current_func:
                        match = re.search(r"Function:\s*(\w+)", current_func)
                        if match:
                            return f"{command_name}:current:{match.group(1)}"
                except Exception:
                    pass
                return f"{command_name}:current"

        elif command_name == "get_current_function":
            return f"{command_name}:session"

        else:
            param_str = ":".join(f"{k}={v}" for k, v in sorted(params.items()))
            return f"{command_name}:{param_str}" if param_str else command_name

    def _get_cached_result(self, command_name: str, cache_key: str, params: Dict[str, Any]):
        """Return cached result or ``None``."""
        if command_name in self.NO_CACHE_COMMANDS:
            return None

        if command_name in ("decompile_function", "analyze_function"):
            return self.decompilation_cache.get(cache_key)
        elif command_name == "get_current_function":
            return self.function_cache.get(cache_key)
        else:
            return self.decompilation_cache.get(cache_key)

    def _cache_result(
        self, command_name: str, cache_key: str, params: Dict[str, Any], result: Any
    ):
        """Store a result in the appropriate cache."""
        if command_name in self.NO_CACHE_COMMANDS:
            return

        # Don't cache errors
        if isinstance(result, str) and result.startswith("ERROR:"):
            self.logger.debug(f"⚠️ Not caching error result for {command_name}")
            return

        # Don't cache empty results
        if isinstance(result, (list, dict)) and not result:
            self.logger.debug(f"⚠️ Not caching empty result for {command_name}")
            return

        if command_name in ("decompile_function", "analyze_function"):
            self.decompilation_cache[cache_key] = result
            self.cache_stats["cache_size"] = len(self.decompilation_cache)
            self.logger.debug(f"📦 Cached {command_name} result for key: {cache_key}")
        elif command_name == "get_current_function":
            self.function_cache[cache_key] = result
            self.logger.debug(f"📦 Cached {command_name} result for key: {cache_key}")
        else:
            self.decompilation_cache[cache_key] = result
            self.cache_stats["cache_size"] = len(self.decompilation_cache)

    def clear_cache(self):
        """Clear all command result caches."""
        self.decompilation_cache.clear()
        self.function_cache.clear()
        self.cache_stats = {"hits": 0, "misses": 0, "cache_size": 0}
        self.logger.info("🧹 All caches cleared")

    def get_cache_stats(self) -> Dict[str, Any]:
        """Return cache hit/miss statistics."""
        total_requests = self.cache_stats["hits"] + self.cache_stats["misses"]
        hit_rate = (self.cache_stats["hits"] / total_requests * 100) if total_requests > 0 else 0

        return {
            "hits": self.cache_stats["hits"],
            "misses": self.cache_stats["misses"],
            "hit_rate": f"{hit_rate:.1f}%",
            "cache_size": self.cache_stats["cache_size"],
            "total_requests": total_requests,
        }

    # ------------------------------------------------------------------
    # Context-manager result retrieval (bridge-level command)
    # ------------------------------------------------------------------

    def _get_context_cached_result(self, result_id: str) -> str:
        """Retrieve the full content of a context-cached result by its ID.

        Used by the ``get_cached_result`` bridge command.
        """
        if not self.context_manager or not self.context_manager.result_cache:
            return "Error: Result caching is not enabled"

        full_result = self.context_manager.get_full_result(result_id)
        if full_result:
            self.logger.info(f"Retrieved cached result: {result_id} ({len(full_result)} chars)")
            return full_result
        else:
            available = list(self.context_manager.result_cache.cache.keys())[:5]
            return f"Error: Cached result '{result_id}' not found. Available IDs: {available}"

    # ------------------------------------------------------------------
    # Tool-execution improvements (list_strings, xref hints)
    # ------------------------------------------------------------------

    def _translate_string_category(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Translate semantic ``category`` param to a concrete ``filter`` for list_strings."""
        str_filter = params.get("filter", "")
        category = params.get("category")

        if not category and str_filter and str_filter.startswith("category:"):
            category = str_filter.split(":", 1)[1]

        if category:
            mapping = {
                "filesystem": ".exe",
                "registry": "HKLM",
                "urls": "http",
            }
            if category in mapping:
                params["filter"] = mapping[category]
                self.logger.info(
                    f"🔄 Converted category='{category}' to filter='{mapping[category]}' (approximate)"
                )

        return params

    @staticmethod
    def _inject_xref_hint(result):
        """Append a hint when get_function_xrefs returns empty (possible import thunk)."""
        if not result:
            result = []

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
        return result
