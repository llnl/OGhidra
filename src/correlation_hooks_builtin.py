"""Built-in vulnerability correlation hooks.

These 5 hooks are extracted verbatim from the original hardcoded
``_build_default_correlation_rules()`` in ``orchestrator.py``.
Each hook produces the same ``WorkerTask`` as the original rule.
"""

from typing import List, Optional, Set

from src.agents.base import WorkerTask
from src.correlation_hooks import CorrelationHook
from src.coverage_tracker import DEPTH_ENCOUNTERED, DEPTH_ANALYZED


class _BaseBuiltinHook(CorrelationHook):
    """Convenience base that stores worker limits."""

    def __init__(self, worker_max_steps: int, worker_soft_limit: int = 0):
        super().__init__()
        self._max_steps = worker_max_steps


# ── Rule 1: Unquoted Service Path (CVE-2019-18915 pattern) ───────────


class UnquotedServicePathHook(_BaseBuiltinHook):
    @property
    def name(self) -> str:
        return "unquoted_service_path"

    @property
    def description(self) -> str:
        return (
            "CreateProcessW + service APIs detected — check for unquoted "
            "service path vulnerability"
        )

    def check(self, all_apis, coverage, function_registry, discovery_cache) -> Optional[WorkerTask]:
        has_create_process = (
            "createprocessw" in all_apis or "createprocessa" in all_apis
        )
        if not has_create_process:
            return None

        svc_area = coverage.areas.get("service_management")
        svc_encountered = (
            svc_area is not None
            and svc_area.depth in (DEPTH_ENCOUNTERED, DEPTH_ANALYZED)
        )
        svc_apis = any(
            api in all_apis
            for api in (
                "startservicectrldispatcherw",
                "startservicectrldispatcher",
                "createservicew",
                "openscmanagerw",
            )
        )
        if not (svc_encountered or svc_apis):
            return None

        return WorkerTask(
            goal=(
                "Decompile all callers of CreateProcessW/CreateProcessA. "
                "For each call, check: "
                "(a) Is lpApplicationName NULL? "
                "(b) Is lpCommandLine constructed from a path containing spaces? "
                "(c) Is the path quoted with double quotes? "
                "If lpApplicationName is NULL and the command line path contains "
                "spaces without quotes, this is an unquoted service path "
                "vulnerability (CVE pattern). "
                "Also check if the binary registers as a Windows service "
                "(StartServiceCtrlDispatcher) and whether the service executable "
                "path is properly quoted in the service registration."
            ),
            strategy_hint=(
                "Focus on the CreateProcessW parameter pattern: when "
                "lpApplicationName is NULL, Windows parses lpCommandLine by "
                "splitting on spaces. A path like "
                "'C:\\Program Files\\App\\binary.exe' without quotes causes "
                "Windows to try 'C:\\Program.exe' first, enabling privilege "
                "escalation if the service runs as SYSTEM."
            ),
            focus_areas=["service_management", "process_creation"],
            suggested_tools=[
                "get_xrefs_to", "decompile_function_by_address",
            ],
            include_sections=[
                "scope", "function_registry", "knowledge",
                "discovery",
            ],
            max_steps=self._max_steps,
            metadata={"correlation_rule": self.name},
            recipe="trace_import_callers",
            recipe_params={
                "api_names": ["CreateProcessW", "CreateProcessA"],
            },
            analysis_focus=(
                "Check each CreateProcessW/CreateProcessA call for: "
                "(1) lpApplicationName=NULL, "
                "(2) lpCommandLine contains unquoted path with spaces, "
                "(3) binary runs as SYSTEM service. "
                "If all three are true, this is a confirmed unquoted service path vuln."
            ),
        )


# ── Rule 2: DLL Hijacking via LoadLibrary ────────────────────────────


class DllHijackingHook(_BaseBuiltinHook):
    @property
    def name(self) -> str:
        return "dll_hijacking"

    @property
    def description(self) -> str:
        return (
            "LoadLibrary + file operations detected — check for DLL "
            "hijacking vectors"
        )

    def check(self, all_apis, coverage, function_registry, discovery_cache) -> Optional[WorkerTask]:
        has_loadlib = any(
            api in all_apis
            for api in ("loadlibraryw", "loadlibraryexw", "loadlibrarya")
        )
        if not has_loadlib:
            return None

        file_area = coverage.areas.get("file_operations")
        if file_area is None or file_area.depth not in (DEPTH_ENCOUNTERED, DEPTH_ANALYZED):
            return None

        return WorkerTask(
            goal=(
                "Decompile all callers of LoadLibraryW/LoadLibraryExW/"
                "LoadLibraryA. For each call, check if the DLL path is: "
                "(a) relative (no drive letter or leading backslash), "
                "(b) constructed from user-controllable input, or "
                "(c) loaded from a writable directory. "
                "Flag any DLL loads without full absolute paths as "
                "potential DLL hijacking vectors."
            ),
            strategy_hint=(
                "When LoadLibrary is called with a relative path, Windows "
                "searches directories in a specific order. If an attacker "
                "can place a malicious DLL earlier in the search order "
                "(e.g., the application directory), it will be loaded instead."
            ),
            focus_areas=["dll_loading", "file_operations"],
            suggested_tools=[
                "get_xrefs_to", "decompile_function_by_address",
            ],
            include_sections=[
                "scope", "function_registry", "discovery",
            ],
            max_steps=self._max_steps,
            metadata={"correlation_rule": self.name},
            recipe="trace_import_callers",
            recipe_params={
                "api_names": ["LoadLibraryW", "LoadLibraryExW", "LoadLibraryA"],
            },
            analysis_focus=(
                "Check each LoadLibrary call for: "
                "(1) relative DLL path (no drive letter / leading backslash), "
                "(2) user-controllable input used to construct the path, "
                "(3) DLL loaded from a writable directory. "
                "Relative paths without SetDllDirectory protection = DLL hijacking."
            ),
        )


# ── Rule 3: Command Injection via External Input ─────────────────────


class CommandInjectionHook(_BaseBuiltinHook):
    @property
    def name(self) -> str:
        return "command_injection"

    @property
    def description(self) -> str:
        return (
            "CreateProcessW + registry/env reads detected — check for "
            "command injection via unsanitized external input"
        )

    def check(self, all_apis, coverage, function_registry, discovery_cache) -> Optional[WorkerTask]:
        has_create_process = (
            "createprocessw" in all_apis or "createprocessa" in all_apis
        )
        if not has_create_process:
            return None

        has_external_input = any(
            api in all_apis
            for api in (
                "regqueryvalueexw",
                "regqueryvalueex",
                "getenvironmentvariablew",
                "getenvironmentvariable",
                "getprivateprofilestringw",
            )
        )
        if not has_external_input:
            return None

        return WorkerTask(
            goal=(
                "Trace data flow from registry reads (RegQueryValueExW) "
                "and environment variable reads (GetEnvironmentVariableW) "
                "to CreateProcessW/ShellExecuteW calls. Check if external "
                "input is concatenated into command lines without "
                "sanitization or proper quoting."
            ),
            strategy_hint=(
                "Look for patterns where registry values or environment "
                "variables are read into a buffer, then concatenated or "
                "formatted into a command string passed to CreateProcessW. "
                "Verify whether the concatenated path is quoted."
            ),
            focus_areas=["process_creation", "registry_persistence"],
            suggested_tools=[
                "get_xrefs_to", "decompile_function_by_address",
                "get_xrefs_from",
            ],
            include_sections=[
                "scope", "function_registry", "knowledge", "leads",
                "discovery",
            ],
            max_steps=self._max_steps,
            metadata={"correlation_rule": self.name},
            recipe="trace_import_callers",
            recipe_params={
                "api_names": [
                    "CreateProcessW", "RegQueryValueExW",
                    "GetEnvironmentVariableW",
                ],
            },
            analysis_focus=(
                "Check if registry/environment values flow into CreateProcessW "
                "command lines without sanitization. Trace: RegQueryValueExW → "
                "buffer → sprintf/strcat → CreateProcessW. Unsanitized external "
                "input in command lines = command injection."
            ),
        )


# ── Rule 4: Privilege Escalation via Token Manipulation ──────────────


class TokenPrivilegeEscalationHook(_BaseBuiltinHook):
    @property
    def name(self) -> str:
        return "token_privilege_escalation"

    @property
    def description(self) -> str:
        return (
            "Token manipulation + service context detected — analyze "
            "privilege escalation chain"
        )

    def check(self, all_apis, coverage, function_registry, discovery_cache) -> Optional[WorkerTask]:
        if "adjusttokenprivileges" not in all_apis:
            return None
        if "openprocesstoken" not in all_apis:
            return None

        svc_area = coverage.areas.get("service_management")
        if svc_area is None or svc_area.depth not in (DEPTH_ENCOUNTERED, DEPTH_ANALYZED):
            return None

        return WorkerTask(
            goal=(
                "Analyze the privilege escalation chain: trace "
                "OpenProcessToken -> AdjustTokenPrivileges -> privileged "
                "operation. Determine which privileges are being enabled, "
                "whether the binary runs as a service (SYSTEM context), "
                "and whether the elevated privileges are used for "
                "security-sensitive operations."
            ),
            strategy_hint=(
                "Map the full chain: which token is opened (own process "
                "vs remote), which privileges are requested (SeDebug, "
                "SeImpersonate, etc.), and what privileged operations "
                "follow. If running as SYSTEM service, privilege "
                "manipulation may be unnecessary but indicates potential "
                "for lateral movement."
            ),
            focus_areas=["privilege_escalation", "service_management"],
            suggested_tools=[
                "get_xrefs_to", "decompile_function_by_address",
                "get_xrefs_from",
            ],
            include_sections=[
                "scope", "function_registry", "knowledge",
                "discovery",
            ],
            max_steps=self._max_steps,
            metadata={"correlation_rule": self.name},
            recipe="trace_import_callers",
            recipe_params={
                "api_names": ["AdjustTokenPrivileges", "OpenProcessToken"],
            },
            analysis_focus=(
                "Map the privilege escalation chain: which token is opened, "
                "which privileges are requested (SeDebug, SeImpersonate), "
                "and what privileged operations follow. If running as SYSTEM "
                "service, check for lateral movement potential."
            ),
        )


# ── Rule 5: Network Input → File Operations (Directory Traversal) ───


class NetworkFileTraversalHook(_BaseBuiltinHook):
    @property
    def name(self) -> str:
        return "network_file_traversal"

    @property
    def description(self) -> str:
        return (
            "Network input + file I/O detected — check for directory "
            "traversal and arbitrary file read/write"
        )

    def check(self, all_apis, coverage, function_registry, discovery_cache) -> Optional[WorkerTask]:
        has_network = any(
            api in all_apis
            for api in ("recv", "recvfrom", "wsarecv", "accept", "bind", "listen")
        )
        if not has_network:
            return None

        file_area = coverage.areas.get("file_operations")
        if file_area is None or file_area.depth not in (DEPTH_ENCOUNTERED, DEPTH_ANALYZED):
            return None

        return WorkerTask(
            goal=(
                "Trace data flow from network input (recv/accept) to file "
                "operations (CreateFile/ReadFile). Check: (a) Is received data "
                "used to construct a file path? (b) Are path components validated "
                "(.. filtering, canonicalization)? (c) Can attacker use ../ sequences "
                "to escape the intended directory?"
            ),
            strategy_hint=(
                "Directory traversal: recv() -> buffer -> sprintf/strcat -> "
                "CreateFile. Missing '..' check = arbitrary file read. "
                "Look for HTTP request parsing that extracts URL paths and "
                "concatenates them to a base directory without validation."
            ),
            focus_areas=[
                "input_handling", "file_operations", "network_comms",
            ],
            suggested_tools=[
                "get_xrefs_to", "decompile_function_by_address",
            ],
            include_sections=[
                "scope", "function_registry", "knowledge", "discovery",
            ],
            max_steps=self._max_steps,
            metadata={"correlation_rule": self.name},
            recipe="trace_import_callers",
            recipe_params={
                "api_names": ["recv", "recvfrom", "CreateFileW", "ReadFile"],
            },
            analysis_focus=(
                "Trace data flow: recv() → buffer → path construction → "
                "CreateFile/ReadFile. Check for missing '../' validation, "
                "missing path canonicalization. HTTP servers: check URL path "
                "extraction → directory concatenation."
            ),
        )


# ── Factory ──────────────────────────────────────────────────────────


def get_builtin_hooks(
    worker_max_steps: int = 20,
    worker_soft_limit: int = 8,
) -> List[CorrelationHook]:
    """Return fresh instances of all 5 built-in correlation hooks."""
    return [
        UnquotedServicePathHook(worker_max_steps, worker_soft_limit),
        DllHijackingHook(worker_max_steps, worker_soft_limit),
        CommandInjectionHook(worker_max_steps, worker_soft_limit),
        TokenPrivilegeEscalationHook(worker_max_steps, worker_soft_limit),
        NetworkFileTraversalHook(worker_max_steps, worker_soft_limit),
    ]
