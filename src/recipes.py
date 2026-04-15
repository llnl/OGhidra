"""
Deterministic Analysis Recipes for OGhidra.

Recipes replace LLM-driven tool selection with deterministic data
gathering algorithms.  Each recipe follows a fixed pattern: resolve
targets → trace xrefs → decompile callers/callees → return gathered
code for LLM analysis.

Design principles:
  - Zero LLM involvement during gathering (deterministic only).
  - All tool calls go through ``ToolExecutor`` (inherits cache/validation).
  - Auto-register decompiled functions to ``FunctionRegistry``.
  - Auto-mark coverage via ``CoverageTracker.auto_mark_from_result()``.
  - Respect a configurable ``max_functions`` cap to prevent runaway gathering.
  - Skip functions already decompiled >2 times (use cached summary).

Available recipes:
  - ``trace_import_callers`` — API name → import address → xrefs → decompile callers
  - ``trace_string_refs`` — string pattern → string addresses → xrefs → decompile refs
  - ``deep_function_analysis`` — function address → decompile + callers + callees
  - ``surface_recon`` — paginated imports + exports + filtered strings
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Set

from src.models.memory import FunctionAnalysis


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_MAX_FUNCTIONS = 15

RECIPE_TRACE_IMPORT_CALLERS = "trace_import_callers"
RECIPE_TRACE_STRING_REFS = "trace_string_refs"
RECIPE_DEEP_FUNCTION_ANALYSIS = "deep_function_analysis"
RECIPE_SURFACE_RECON = "surface_recon"

AVAILABLE_RECIPES = frozenset({
    RECIPE_TRACE_IMPORT_CALLERS,
    RECIPE_TRACE_STRING_REFS,
    RECIPE_DEEP_FUNCTION_ANALYSIS,
    RECIPE_SURFACE_RECON,
})

# Max lines of decompiled code to keep per function (prevents prompt blowup)
MAX_CODE_LINES_PER_FUNCTION = 250


# ---------------------------------------------------------------------------
# RecipeResult
# ---------------------------------------------------------------------------

@dataclass
class RecipeResult:
    """Gathered data from a deterministic recipe execution."""

    gathered_functions: Dict[str, str] = field(default_factory=dict)
    """address → full decompiled code"""

    gathered_xrefs: Dict[str, List[str]] = field(default_factory=dict)
    """address → list of xref result lines"""

    gathered_imports: List[str] = field(default_factory=list)
    """Full import list (from paginated list_imports)"""

    gathered_strings: List[str] = field(default_factory=list)
    """Matched strings from list_strings searches"""

    call_graph: Dict[str, List[str]] = field(default_factory=dict)
    """address → [callee addresses]"""

    tool_calls_made: int = 0
    """Total Ghidra tool calls executed during this recipe"""

    errors: List[str] = field(default_factory=list)
    """Non-fatal errors encountered during gathering"""

    functions_registered: List[FunctionAnalysis] = field(default_factory=list)
    """FunctionAnalysis objects auto-registered during gathering"""


# ---------------------------------------------------------------------------
# RecipeExecutor
# ---------------------------------------------------------------------------

class RecipeExecutor:
    """Deterministic recipe executor — gathers data without LLM involvement.

    All tool calls go through the shared ``ToolExecutor`` (inheriting its
    cache, parameter validation, and error handling).
    """

    def __init__(
        self,
        tool_executor,
        blackboard,
        max_functions: int = DEFAULT_MAX_FUNCTIONS,
        logger: Optional[logging.Logger] = None,
        registry=None,
    ):
        self.tools = tool_executor
        self.blackboard = blackboard
        self.max_functions = max_functions
        self.logger = logger or logging.getLogger(__name__)

        # Recipe registry — always register built-ins so the real
        # callables are available even if the registry was pre-created
        if registry is not None:
            self.registry = registry
        else:
            from src.recipe_registry import RecipeRegistry
            self.registry = RecipeRegistry()
        self._register_builtins()

    # ------------------------------------------------------------------
    # Built-in registration
    # ------------------------------------------------------------------

    def _register_builtins(self) -> None:
        """Register the 4 built-in recipes with the registry."""
        self.registry.register_builtin(
            RECIPE_TRACE_IMPORT_CALLERS,
            lambda executor, params: executor.trace_import_callers(
                api_names=params.get("api_names", []),
                depth=params.get("depth", 1),
            ),
            "API name -> import thunk -> xrefs -> decompile callers",
        )
        self.registry.register_builtin(
            RECIPE_TRACE_STRING_REFS,
            lambda executor, params: executor.trace_string_refs(
                patterns=params.get("patterns", []),
            ),
            "String patterns -> list_strings -> xrefs -> decompile",
        )
        self.registry.register_builtin(
            RECIPE_DEEP_FUNCTION_ANALYSIS,
            lambda executor, params: executor.deep_function_analysis(
                addresses=params.get("addresses", []),
                depth=params.get("depth", 1),
            ),
            "Target address -> decompile + callers + callees",
        )
        self.registry.register_builtin(
            RECIPE_SURFACE_RECON,
            lambda executor, params: executor.surface_recon(
                string_filters=params.get("string_filters"),
            ),
            "Paginated imports + exports + filtered strings",
        )

    # ------------------------------------------------------------------
    # Dispatch
    # ------------------------------------------------------------------

    def execute(self, recipe_name: str, params: Dict[str, Any]) -> RecipeResult:
        """Dispatch to a recipe via the registry.

        Args:
            recipe_name: Name of any registered recipe (built-in or custom).
            params: Recipe-specific parameters.

        Returns:
            ``RecipeResult`` with all gathered data.

        Raises:
            ValueError: If ``recipe_name`` is not registered.
        """
        return self.registry.execute(recipe_name, self, params)

    # ------------------------------------------------------------------
    # Recipe: trace_import_callers
    # ------------------------------------------------------------------

    def trace_import_callers(
        self, api_names: List[str], depth: int = 1
    ) -> RecipeResult:
        """Trace callers of imported APIs.

        Algorithm (two-path resolution):
          1. Resolve each API name from the import list.
          2. **Direct path** (preferred): If ``FUN_XXXXXXXX`` caller names
             are present in the ``[Callers:]`` field, decompile them directly
             — no xref round-trip needed.
          3. **Fallback path**: If only a bare thunk address is available,
             use ``get_xrefs_to`` on the thunk → extract caller locations.
          4. Optionally recurse into callers of callers (depth > 1).
        """
        result = RecipeResult()
        import_map = self._resolve_import_callers(api_names, result)

        for api_name, (thunk_addr, caller_addrs) in import_map.items():
            if not thunk_addr and not caller_addrs:
                result.errors.append(
                    f"Could not resolve import address for {api_name}"
                )
                continue

            # Direct path: decompile known callers from import line
            if caller_addrs:
                for caller_addr in caller_addrs:
                    if len(result.gathered_functions) >= self.max_functions:
                        break
                    if caller_addr in result.gathered_functions:
                        continue
                    code = self._decompile_function(caller_addr, result)
                    if code:
                        result.gathered_functions[caller_addr] = code
                        self._auto_register_and_mark(caller_addr, code, result)
                        # Recurse into callers-of-callers if requested
                        if depth > 1:
                            self._trace_callers_recursive(
                                caller_addr, f"caller_of_{api_name}",
                                depth - 1, result, visited=set(),
                            )

            # Fallback: thunk + xrefs (only when no named callers found)
            elif thunk_addr:
                self._trace_callers_recursive(
                    thunk_addr, api_name, depth, result, visited=set()
                )

        self.logger.info(
            f"trace_import_callers({api_names}): gathered "
            f"{len(result.gathered_functions)} functions, "
            f"{result.tool_calls_made} tool calls"
        )
        return result

    # ------------------------------------------------------------------
    # Recipe: trace_string_refs
    # ------------------------------------------------------------------

    def trace_string_refs(self, patterns: List[str]) -> RecipeResult:
        """Find strings matching patterns and decompile referencing functions.

        Algorithm:
          1. ``list_strings(filter=pattern)`` for each pattern.
          2. Extract string addresses from results.
          3. ``get_xrefs_to`` on each string address → referencing functions.
          4. Decompile each unique referencing function.
        """
        result = RecipeResult()

        for pattern in patterns:
            try:
                resp = self.tools.execute_command(
                    "list_strings", {"filter": pattern, "offset": 0, "limit": 100}
                )
                result.tool_calls_made += 1
                lines = self._parse_list_result(resp)
                result.gathered_strings.extend(lines)
            except Exception as e:
                result.errors.append(f"list_strings(filter={pattern!r}) failed: {e}")
                continue

            for line in lines:
                addr_match = re.search(r'(?:0x)?([0-9a-fA-F]{6,})', str(line))
                if not addr_match:
                    continue
                str_addr = self._normalize_addr(addr_match.group(0))
                self._trace_callers_recursive(
                    str_addr, f"string:{pattern}", 1, result, visited=set()
                )
                if len(result.gathered_functions) >= self.max_functions:
                    break

            if len(result.gathered_functions) >= self.max_functions:
                break

        self.logger.info(
            f"trace_string_refs({patterns}): gathered "
            f"{len(result.gathered_functions)} functions, "
            f"{result.tool_calls_made} tool calls"
        )
        return result

    # ------------------------------------------------------------------
    # Recipe: deep_function_analysis
    # ------------------------------------------------------------------

    def deep_function_analysis(
        self, addresses: List[str], depth: int = 1
    ) -> RecipeResult:
        """Decompile target functions plus their callers and callees.

        Algorithm:
          1. Decompile each target function.
          2. ``get_xrefs_to`` → decompile callers.
          3. ``get_xrefs_from`` → record callees, decompile unique ones.
        """
        result = RecipeResult()

        for address in addresses:
            address = self._normalize_addr(address)
            if len(result.gathered_functions) >= self.max_functions:
                break

            # Decompile the target
            code = self._decompile_function(address, result)
            if code:
                result.gathered_functions[address] = code
                self._auto_register_and_mark(address, code, result)

            # Callers (xrefs_to)
            try:
                xref_resp = self.tools.execute_command(
                    "get_xrefs_to", {"address": address}
                )
                result.tool_calls_made += 1
                xref_lines = self._parse_list_result(xref_resp)
                result.gathered_xrefs[address] = xref_lines

                for caller in self._extract_function_addresses_from_xrefs(xref_lines):
                    if len(result.gathered_functions) >= self.max_functions:
                        break
                    if caller in result.gathered_functions:
                        continue
                    caller_code = self._decompile_function(caller, result)
                    if caller_code:
                        result.gathered_functions[caller] = caller_code
                        self._auto_register_and_mark(caller, caller_code, result)
            except Exception as e:
                result.errors.append(f"get_xrefs_to({address}) failed: {e}")

            # Callees (xrefs_from)
            try:
                xref_from_resp = self.tools.execute_command(
                    "get_xrefs_from", {"address": address}
                )
                result.tool_calls_made += 1
                xref_from_lines = self._parse_list_result(xref_from_resp)
                callees = self._extract_function_addresses_from_xrefs(xref_from_lines)
                result.call_graph[address] = callees

                for callee in callees:
                    if len(result.gathered_functions) >= self.max_functions:
                        break
                    if callee in result.gathered_functions:
                        continue
                    callee_code = self._decompile_function(callee, result)
                    if callee_code:
                        result.gathered_functions[callee] = callee_code
                        self._auto_register_and_mark(callee, callee_code, result)
            except Exception as e:
                result.errors.append(f"get_xrefs_from({address}) failed: {e}")

        self.logger.info(
            f"deep_function_analysis({addresses}): gathered "
            f"{len(result.gathered_functions)} functions, "
            f"{result.tool_calls_made} tool calls"
        )
        return result

    # ------------------------------------------------------------------
    # Recipe: surface_recon
    # ------------------------------------------------------------------

    def surface_recon(
        self, string_filters: Optional[List[str]] = None
    ) -> RecipeResult:
        """Deterministic surface mapping of the binary.

        Gathers all imports, exports, and security-relevant strings.
        Does NOT decompile anything.
        """
        result = RecipeResult()
        string_filters = string_filters or [
            ".exe", ".dll", "http", "cmd", "service", "..", "path", "file",
        ]

        # Paginated imports
        self._paginated_list_imports(result)

        # Exports
        try:
            resp = self.tools.execute_command(
                "list_exports", {"offset": 0, "limit": 100}
            )
            result.tool_calls_made += 1
            lines = self._parse_list_result(resp)
            self.blackboard.cache_discovery("list_exports", {}, lines)
        except Exception as e:
            result.errors.append(f"list_exports failed: {e}")

        # String searches
        for filt in string_filters:
            try:
                resp = self.tools.execute_command(
                    "list_strings", {"filter": filt, "offset": 0, "limit": 100}
                )
                result.tool_calls_made += 1
                lines = self._parse_list_result(resp)
                result.gathered_strings.extend(lines)
                self.blackboard.cache_discovery("list_strings", {"filter": filt}, lines)
            except Exception as e:
                result.errors.append(f"list_strings(filter={filt!r}) failed: {e}")

        # Function list (for total count)
        try:
            resp = self.tools.execute_command(
                "list_functions", {"offset": 0, "limit": 100}
            )
            result.tool_calls_made += 1
            lines = self._parse_list_result(resp)
            self.blackboard.cache_discovery("list_functions", {}, lines)
        except Exception as e:
            result.errors.append(f"list_functions failed: {e}")

        self.logger.info(
            f"surface_recon: {len(result.gathered_imports)} imports, "
            f"{len(result.gathered_strings)} strings, "
            f"{result.tool_calls_made} tool calls"
        )
        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _resolve_import_callers(
        self, api_names: List[str], result: RecipeResult
    ) -> Dict[str, tuple]:
        """Resolve API names to thunk addresses AND direct caller addresses.

        Uses the discovery cache if available, otherwise calls
        ``list_imports`` with pagination.

        Import line format (from Ghidra)::

          CreateProcessW -> EXTERNAL:00000098 [Refs: 2] [Callers: 0040a098, FUN_00405b60]

        The ``[Callers:]`` field contains:
          - The IAT thunk address (bare hex, e.g. ``0040a098``)
          - Named function callers (``FUN_XXXXXXXX`` format)

        We extract the ``FUN_`` entries as **direct callers** (decompile
        them immediately, no xref needed) and keep the thunk as a
        **fallback** for the xref-based path.

        Returns:
            Dict mapping api_name → ``(thunk_addr, [caller_func_addrs])``.
        """
        imports_data = getattr(self.blackboard, 'discovery_cache', None)
        if imports_data and hasattr(imports_data, 'imports') and imports_data.imports:
            all_imports = imports_data.imports
        else:
            all_imports = self._paginated_list_imports(result)

        import_map: Dict[str, tuple] = {}
        for api_name in api_names:
            import_map[api_name] = self._find_import_callers(
                api_name, all_imports
            )
        return import_map

    def _find_import_callers(
        self, api_name: str, imports_data: List[str]
    ) -> tuple:
        """Extract the IAT thunk address AND named caller functions.

        Returns:
            ``(thunk_addr_or_None, [caller_func_addrs])`` where
            ``caller_func_addrs`` are addresses extracted from
            ``FUN_XXXXXXXX`` entries in the ``[Callers:]`` field.
        """
        api_lower = api_name.lower()
        for line in imports_data:
            line_str = str(line)
            line_lower = line_str.lower()

            # Must contain the API name
            if api_lower not in line_lower:
                continue

            # Verify match is before the "->" (the import name, not a
            # coincidental substring in caller names or metadata).
            arrow_idx = line_lower.find('->')
            if arrow_idx >= 0 and api_lower not in line_lower[:arrow_idx]:
                continue

            thunk_addr: Optional[str] = None
            caller_addrs: List[str] = []

            # Extract from [Callers: ...] field
            callers_section = re.search(
                r'\[Callers?:\s*([^\]]+)\]', line_str
            )
            if callers_section:
                callers_text = callers_section.group(1)

                # Named function callers: FUN_XXXXXXXX → direct addresses
                for func_match in re.finditer(
                    r'FUN_([0-9a-fA-F]+)', callers_text
                ):
                    caller_addrs.append(
                        self._normalize_addr(func_match.group(1))
                    )

                # First bare hex address = IAT thunk (fallback)
                thunk_match = re.search(
                    r'(?:^|,\s*)([0-9a-fA-F]{6,})(?:\s*,|\s*$)',
                    callers_text,
                )
                if thunk_match:
                    thunk_addr = self._normalize_addr(thunk_match.group(1))

            # If no thunk from Callers, try EXTERNAL: field
            if not thunk_addr:
                ext_match = re.search(
                    r'EXTERNAL:([0-9a-fA-F]+)', line_str
                )
                if ext_match:
                    thunk_addr = self._normalize_addr(ext_match.group(1))

            return thunk_addr, caller_addrs

        return None, []

    def _paginated_list_imports(self, result: RecipeResult) -> List[str]:
        """Call ``list_imports`` with pagination to gather all imports."""
        all_imports: List[str] = []
        offset = 0
        limit = 100
        max_pages = 20  # Safety cap

        for _ in range(max_pages):
            try:
                resp = self.tools.execute_command(
                    "list_imports", {"offset": offset, "limit": limit}
                )
                result.tool_calls_made += 1
                lines = self._parse_list_result(resp)
                if not lines:
                    break
                all_imports.extend(lines)
                self.blackboard.cache_discovery(
                    "list_imports", {"offset": offset, "limit": limit}, lines
                )
                # Check if we got everything
                total_match = re.search(r'\[Total:\s*(\d+)\]', str(resp))
                if total_match:
                    total = int(total_match.group(1))
                    if offset + limit >= total:
                        break
                if len(lines) < limit:
                    break
                offset += limit
            except Exception as e:
                result.errors.append(f"list_imports(offset={offset}) failed: {e}")
                break

        result.gathered_imports = all_imports
        return all_imports

    def _trace_callers_recursive(
        self,
        address: str,
        label: str,
        depth: int,
        result: RecipeResult,
        visited: Set[str],
    ):
        """Get xrefs_to an address and decompile each unique caller."""
        address = self._normalize_addr(address)
        if address in visited:
            return
        visited.add(address)

        if len(result.gathered_functions) >= self.max_functions:
            return

        # Get xrefs to this address
        try:
            xref_resp = self.tools.execute_command(
                "get_xrefs_to", {"address": address}
            )
            result.tool_calls_made += 1
            xref_lines = self._parse_list_result(xref_resp)
            result.gathered_xrefs[address] = xref_lines
        except Exception as e:
            result.errors.append(f"get_xrefs_to({address}) [{label}] failed: {e}")
            return

        # Extract unique caller function addresses
        caller_addrs = self._extract_function_addresses_from_xrefs(xref_lines)

        for caller_addr in caller_addrs:
            if len(result.gathered_functions) >= self.max_functions:
                break
            if caller_addr in result.gathered_functions:
                continue

            # Skip over-analyzed functions
            existing = self.blackboard.function_registry.get(caller_addr)
            if existing and existing.decompile_count > 2:
                self.logger.info(
                    f"Skipping {caller_addr} (decompiled {existing.decompile_count}x already)"
                )
                result.gathered_functions[caller_addr] = (
                    f"[CACHED — decompiled {existing.decompile_count}x] "
                    f"{existing.purpose}"
                )
                continue

            # Decompile
            code = self._decompile_function(caller_addr, result)
            if code:
                result.gathered_functions[caller_addr] = code
                self._auto_register_and_mark(caller_addr, code, result)

                # Recurse if depth > 1
                if depth > 1:
                    self._trace_callers_recursive(
                        caller_addr, f"caller_of_{label}",
                        depth - 1, result, visited,
                    )

    def _decompile_function(
        self, address: str, result: RecipeResult
    ) -> Optional[str]:
        """Decompile a function by address, returning full code or None."""
        address = self._normalize_addr(address)
        try:
            resp = self.tools.execute_command(
                "decompile_function_by_address", {"address": address}
            )
            result.tool_calls_made += 1
            code = str(resp) if resp else None
            return code
        except Exception as e:
            result.errors.append(f"decompile({address}) failed: {e}")
            return None

    def _auto_register_and_mark(
        self, address: str, code: str, result: RecipeResult
    ):
        """Auto-register a decompiled function and mark coverage."""
        address = self._normalize_addr(address)

        # Extract function name from signature
        name_match = re.search(
            r'(?:undefined\d?|void|int|long|char|bool|uint|ulong|'
            r'DWORD|BOOL|HANDLE|LPVOID|LPCSTR|LPWSTR|HINSTANCE|'
            r'SC_HANDLE|LSTATUS|SOCKET)\s+(?:__\w+\s+)?(\w+)\s*\(',
            code[:500],
        )
        name = name_match.group(1) if name_match else f"FUN_{address.replace('0x', '')}"

        # Extract Win32 API calls
        api_matches = re.findall(
            r'\b([A-Z][a-zA-Z]+(?:W|A|Ex|ExW)?)\s*\(', code
        )
        imports_used = list(set(api for api in api_matches if len(api) >= 5))[:15]

        fa = FunctionAnalysis(
            address=address,
            name=name,
            original_name=name if name.startswith("FUN_") else "",
            purpose="Gathered by recipe (auto-registered)",
            decompiled=True,
            imports_used=imports_used,
        )
        try:
            self.blackboard.register_function(fa)
            result.functions_registered.append(fa)
        except Exception as e:
            self.logger.debug(f"Auto-register failed for {address}: {e}")

        # Mark coverage
        try:
            self.blackboard.coverage.auto_mark_from_result(
                "decompile_function_by_address", str({"address": address}), code,
            )
        except Exception as e:
            self.logger.debug(f"Coverage auto-mark failed for {address}: {e}")

    def _extract_function_addresses_from_xrefs(
        self, xref_lines: List[str]
    ) -> List[str]:
        """Extract unique function addresses from xref result lines.

        Xref format: ``From 00405b60 in FUN_00405b60 [CALL]``
        We extract the ``in FUN_XXXXXXXX`` part (the containing function),
        not the raw ``From`` address (which is a specific instruction offset).
        """
        addresses: List[str] = []
        seen: Set[str] = set()

        for line in xref_lines:
            line_str = str(line)
            # Skip metadata lines like [Total: N]
            if line_str.startswith('[') or not line_str.strip():
                continue

            # Primary: extract function name "in FUN_XXXXXXXX"
            func_match = re.search(r'in\s+(FUN_[0-9a-fA-F]+)', line_str)
            if func_match:
                func_name = func_match.group(1)
                addr = self._normalize_addr(func_name.replace("FUN_", ""))
                if addr not in seen:
                    seen.add(addr)
                    addresses.append(addr)
                continue

            # Fallback: extract "From XXXXXXXX" address
            from_match = re.search(
                r'(?:From|from)\s+(?:0x)?([0-9a-fA-F]{6,})', line_str
            )
            if from_match:
                addr = self._normalize_addr(from_match.group(1))
                if addr not in seen:
                    seen.add(addr)
                    addresses.append(addr)

        return addresses

    @staticmethod
    def _normalize_addr(raw: str) -> str:
        """Normalize an address to ``0xXXXXXXXX`` format."""
        clean = raw.strip().lower()
        if clean.startswith("fun_"):
            clean = clean[4:]
        if clean.startswith("0x"):
            return clean
        return f"0x{clean}"

    @staticmethod
    def _parse_list_result(resp) -> List[str]:
        """Parse a tool response into a list of strings.

        Handles: list, dict with ``result`` key, or raw string.
        """
        if isinstance(resp, list):
            return [str(item) for item in resp if str(item).strip()]
        if isinstance(resp, dict):
            result_val = resp.get("result", "")
            if isinstance(result_val, list):
                return [str(item) for item in result_val if str(item).strip()]
            return [
                line.strip()
                for line in str(result_val).splitlines()
                if line.strip()
            ]
        return [
            line.strip()
            for line in str(resp).splitlines()
            if line.strip()
        ]
