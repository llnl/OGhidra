#!/usr/bin/env python3
"""
Coverage Tracker — Investigation Area Checklist
------------------------------------------------
Tracks which security investigation areas have been explored during
a binary analysis session. Injects a checklist into the execution prompt
so the AI always sees what it hasn't investigated yet.

Uses a two-tier depth model:
  - **encountered**: API/string was seen in surface-level tool output
    (e.g., import listing, string search).  Informational only — the area
    exists in the binary but callers have NOT been analyzed.
  - **analyzed**: A deep-analysis tool (decompile, xrefs, disassemble) found
    the API/string.  The investigator actually looked at the code.

Only "analyzed" areas count toward ``coverage_ratio()``.  The prompt
checklist shows all three tiers so the orchestrator can see
"encountered but not analyzed" as a gap that needs follow-up.

Inspired by the post-mortem of the WiseBootAssistant investigation,
where the AI never searched for service-related APIs or strings because
nothing reminded it to check that area, and the CVE-2019-18915
investigation where ``list_imports`` prematurely marked service_management
as "covered" before any callers were decompiled.
"""

import logging
import re
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set

logger = logging.getLogger(__name__)


# ── Depth constants ──────────────────────────────────────────────────
DEPTH_NONE = "none"
DEPTH_ENCOUNTERED = "encountered"
DEPTH_ANALYZED = "analyzed"

# Ordered so we can compute max(current, new)
_DEPTH_ORDER = {DEPTH_NONE: 0, DEPTH_ENCOUNTERED: 1, DEPTH_ANALYZED: 2}


def _max_depth(a: str, b: str) -> str:
    """Return the deeper of two depth values."""
    return a if _DEPTH_ORDER.get(a, 0) >= _DEPTH_ORDER.get(b, 0) else b


# ── Tool classification ─────────────────────────────────────────────

# Tools whose results indicate deep analysis (callers decompiled, xrefs traced)
ANALYSIS_TOOLS: Set[str] = {
    "decompile_function",
    "decompile_function_by_address",
    "disassemble_function",
    "get_xrefs_to",
    "get_xrefs_from",
    "get_function_xrefs",
}

# Tools that only provide surface-level discovery (imports, strings, listings)
SURFACE_TOOLS: Set[str] = {
    "list_imports",
    "list_exports",
    "list_functions",
    "list_entry_points",
    "search_strings_in_binary",
    "list_strings",
}


@dataclass
class CoverageArea:
    """A single investigation area with its check targets."""
    name: str
    description: str
    apis: List[str] = field(default_factory=list)
    strings: List[str] = field(default_factory=list)
    depth: str = DEPTH_NONE               # "none" | "encountered" | "analyzed"
    covered_by: Optional[str] = None      # Which tool call covered it
    result_summary: Optional[str] = None  # Brief summary of what was found
    hits: int = 0                         # How many API/string hits were found

    # Backward-compat property so existing code that reads `area.covered` still works
    @property
    def covered(self) -> bool:
        """True only when the area has been deeply analyzed."""
        return self.depth == DEPTH_ANALYZED

    @covered.setter
    def covered(self, value: bool):
        """Backward-compat setter: True sets depth to analyzed, False to none."""
        self.depth = DEPTH_ANALYZED if value else DEPTH_NONE


# Default security checklist for binary analysis
DEFAULT_CHECKLIST: Dict[str, dict] = {
    "service_management": {
        "description": "Windows service registration and management",
        "apis": ["CreateServiceW", "OpenServiceW", "OpenSCManagerW",
                 "StartServiceW", "ChangeServiceConfigW", "DeleteService",
                 "StartServiceCtrlDispatcherW", "StartServiceCtrlDispatcher",
                 "RegisterServiceCtrlHandlerW", "RegisterServiceCtrlHandler"],
        "strings": ["service", "svc", "boot", "WiseBoot", "BootTime",
                     "SYSTEM\\\\CurrentControlSet\\\\Services"],
    },
    "process_creation": {
        "description": "Process spawning and command execution",
        "apis": ["CreateProcessW", "CreateProcessA", "ShellExecuteW",
                 "ShellExecuteExW", "WinExec", "system"],
        "strings": [".exe", "cmd.exe", "powershell"],
    },
    "privilege_escalation": {
        "description": "Token and privilege manipulation",
        "apis": ["AdjustTokenPrivileges", "OpenProcessToken",
                 "LookupPrivilegeValueW", "ImpersonateLoggedOnUser",
                 "SetTokenInformation", "DuplicateTokenEx"],
        "strings": ["SeDebug", "SeTakeOwnership", "SeBackup",
                     "privilege", "impersonate"],
    },
    "file_operations": {
        "description": "Filesystem paths and file handling (unquoted paths, temp files, traversal)",
        "apis": ["CreateFileW", "CreateFileA", "MoveFileW", "CopyFileW",
                 "GetTempPathW", "GetTempFileNameW", "ReadFile", "WriteFile"],
        "strings": ["Program Files", "C:\\\\", "AppData", "TEMP",
                     "system32", "ProgramData", "..", "../"],
    },
    "registry_persistence": {
        "description": "Registry persistence, service registration, and startup",
        "apis": ["RegOpenKeyExW", "RegSetValueExW", "RegCreateKeyExW",
                 "RegDeleteKeyW", "RegQueryValueExW"],
        "strings": ["HKLM", "CurrentControlSet", "Run", "RunOnce",
                     "SOFTWARE\\\\Microsoft"],
    },
    "dll_loading": {
        "description": "Dynamic library loading (DLL hijacking vectors)",
        "apis": ["LoadLibraryW", "LoadLibraryExW", "LoadLibraryA",
                 "SetDllDirectoryW", "AddDllDirectory"],
        "strings": [".dll", "version.dll", "dwmapi.dll", "winhttp.dll"],
    },
    "network_comms": {
        "description": "Network communication and connections",
        "apis": ["connect", "send", "recv", "WSAStartup",
                 "InternetOpenW", "HttpOpenRequestW", "WinHttpConnect"],
        "strings": ["http", "://", "443", "80", "socket"],
    },
    "crypto_operations": {
        "description": "Cryptographic operations and key management",
        "apis": ["CryptEncrypt", "CryptDecrypt", "BCryptEncrypt",
                 "CryptHashData", "CryptCreateHash"],
        "strings": ["AES", "RSA", "encrypt", "decrypt", "hash", "key"],
    },
    "input_handling": {
        "description": "Network input parsing and request handling (web servers, protocol parsers)",
        "apis": ["recv", "recvfrom", "WSARecv", "accept", "bind", "listen",
                 "getpeername", "InternetReadFile", "WinHttpReadData"],
        "strings": ["GET", "POST", "HTTP", "Content-Type", "Content-Length",
                     "Server:", "404", "200", "Host:", ".."],
    },
}


class CoverageTracker:
    """
    Tracks investigation coverage across binary analysis sessions.

    Uses a two-tier depth model to distinguish between areas that have been
    *encountered* (API seen in an import list) versus truly *analyzed*
    (callers decompiled and reviewed).  Only analyzed areas count toward
    ``coverage_ratio()``.
    """

    def __init__(self, checklist: Optional[Dict[str, dict]] = None):
        """
        Initialize the coverage tracker.

        Args:
            checklist: Custom checklist dict, or None to use DEFAULT_CHECKLIST.
        """
        raw = DEFAULT_CHECKLIST if checklist is None else checklist
        self.areas: Dict[str, CoverageArea] = {}
        self._lock = threading.RLock()
        for name, spec in raw.items():
            self.areas[name] = CoverageArea(
                name=name,
                description=spec.get("description", ""),
                apis=list(spec.get("apis", [])),
                strings=list(spec.get("strings", [])),
            )
        logger.info(f"CoverageTracker initialized with {len(self.areas)} areas")

    # ── Public API ──────────────────────────────────────────────────

    def mark_covered(self, area_name: str, tool_used: str,
                     result_summary: str = "",
                     depth: str = DEPTH_ANALYZED) -> None:
        """Manually mark an area at a given depth (thread-safe).

        Args:
            area_name: Name of the coverage area.
            tool_used: Name of the tool that produced the evidence.
            result_summary: Brief summary of what was found.
            depth: Depth level — ``"analyzed"`` (default) or ``"encountered"``.
        """
        with self._lock:
            if area_name in self.areas:
                area = self.areas[area_name]
                area.depth = _max_depth(area.depth, depth)
                area.covered_by = tool_used
                area.result_summary = result_summary
                logger.info(
                    f"Coverage: '{area_name}' marked {area.depth} by {tool_used}"
                )

    def auto_mark_from_result(self, tool_name: str, tool_params: dict,
                              result: str) -> List[str]:
        """
        Automatically scan a tool result for coverage matches (thread-safe).

        Sets depth based on the tool type:
          - **Analysis tools** (decompile, xrefs, disassemble) → ``analyzed``
          - **Surface tools** (list_imports, search_strings) → ``encountered``
          - **Unknown tools** → ``analyzed`` (conservative default)

        Args:
            tool_name: Name of the tool that was executed.
            tool_params: Parameters the tool was called with.
            result: Full text result from the tool.

        Returns:
            List of area names that were newly **analyzed** (depth changed
            to ``"analyzed"``).  Areas only promoted to ``"encountered"``
            are NOT included — the caller should check ``get_encountered()``
            if interested.
        """
        newly_analyzed = []
        combined_text = f"{tool_name} {str(tool_params)} {result}".lower()

        # Determine depth tier based on tool classification
        if tool_name in ANALYSIS_TOOLS:
            new_depth = DEPTH_ANALYZED
        elif tool_name in SURFACE_TOOLS:
            new_depth = DEPTH_ENCOUNTERED
        else:
            # Unknown tool — treat as analysis (conservative)
            new_depth = DEPTH_ANALYZED

        with self._lock:
            for name, area in self.areas.items():
                # Skip already fully analyzed areas
                if area.depth == DEPTH_ANALYZED:
                    continue

                hits = 0

                # Check for API name matches (case-insensitive)
                for api in area.apis:
                    if api.lower() in combined_text:
                        hits += 1

                # Check for string pattern matches (case-insensitive)
                for pattern in area.strings:
                    if pattern.lower() in combined_text:
                        hits += 1

                if hits > 0:
                    old_depth = area.depth
                    area.depth = _max_depth(area.depth, new_depth)
                    area.covered_by = tool_name
                    area.hits = max(area.hits, hits)
                    area.result_summary = (
                        f"{hits} matches ({area.depth} via {tool_name})"
                    )

                    # Only report in return list if we reached "analyzed"
                    if area.depth == DEPTH_ANALYZED and old_depth != DEPTH_ANALYZED:
                        newly_analyzed.append(name)

                    logger.info(
                        f"Coverage: '{name}' depth={area.depth} ({hits} hits) "
                        f"from {tool_name} (was {old_depth})"
                    )

        return newly_analyzed

    def get_uncovered(self) -> List[CoverageArea]:
        """Return areas that have NOT been fully analyzed (thread-safe).

        Includes both "none" and "encountered" areas — i.e., anything
        that still needs deeper investigation.
        """
        with self._lock:
            return [a for a in self.areas.values() if a.depth != DEPTH_ANALYZED]

    def get_covered(self) -> List[CoverageArea]:
        """Return areas that HAVE been fully analyzed (thread-safe)."""
        with self._lock:
            return [a for a in self.areas.values() if a.depth == DEPTH_ANALYZED]

    def get_encountered(self) -> List[CoverageArea]:
        """Return areas at 'encountered' depth — seen but not analyzed (thread-safe)."""
        with self._lock:
            return [a for a in self.areas.values() if a.depth == DEPTH_ENCOUNTERED]

    def coverage_ratio(self) -> float:
        """Return coverage as a ratio (0.0 to 1.0) (thread-safe).

        Only fully **analyzed** areas count toward coverage.
        """
        with self._lock:
            total = len(self.areas)
            if total == 0:
                return 1.0
            analyzed = sum(1 for a in self.areas.values() if a.depth == DEPTH_ANALYZED)
            return analyzed / total

    def format_for_prompt(self) -> str:
        """
        Format the checklist for injection into the execution prompt.

        Shows three tiers:
          1. Not Yet Investigated (depth == "none")
          2. Encountered — needs deeper analysis (depth == "encountered")
          3. Fully Analyzed (depth == "analyzed")

        Thread-safe.
        """
        with self._lock:
            return self._format_for_prompt_unlocked()

    def _format_for_prompt_unlocked(self) -> str:
        """Internal format_for_prompt — must be called with _lock held."""
        lines = ["## Investigation Coverage"]

        analyzed = [a for a in self.areas.values() if a.depth == DEPTH_ANALYZED]
        encountered = [a for a in self.areas.values() if a.depth == DEPTH_ENCOUNTERED]
        not_seen = [a for a in self.areas.values() if a.depth == DEPTH_NONE]

        total = len(self.areas)
        ratio = len(analyzed) / total if total > 0 else 1.0
        lines.append(
            f"Progress: {len(analyzed)}/{len(self.areas)} areas fully analyzed "
            f"({ratio:.0%}), {len(encountered)} encountered but not analyzed"
        )
        lines.append("")

        # Show not-yet-seen areas first (highest priority)
        if not_seen:
            lines.append("### Not Yet Investigated")
            for area in not_seen:
                api_hint = ", ".join(area.apis[:4])
                str_hint = ", ".join(area.strings[:3])
                lines.append(
                    f"- **{area.name}**: {area.description}"
                )
                lines.append(
                    f"  Search for: APIs=[{api_hint}] "
                    f"Strings=[{str_hint}]"
                )
            lines.append("")

        # Show encountered areas (need follow-up — medium priority)
        if encountered:
            lines.append("### Encountered (needs deeper analysis)")
            for area in encountered:
                summary = area.result_summary or f"seen via {area.covered_by}"
                lines.append(
                    f"- **{area.name}**: {summary}"
                )
                lines.append(
                    f"  APIs found but callers NOT decompiled. "
                    f"Investigate with get_xrefs_to + decompile_function_by_address."
                )
            lines.append("")

        # Show fully analyzed (briefly)
        if analyzed:
            lines.append("### Fully Analyzed")
            for area in analyzed:
                summary = area.result_summary or "analyzed"
                lines.append(
                    f"- **{area.name}**: {summary} "
                    f"(via {area.covered_by})"
                )

        return "\n".join(lines)

    def reset(self) -> None:
        """Reset all coverage (for new investigation). Thread-safe."""
        with self._lock:
            for area in self.areas.values():
                area.depth = DEPTH_NONE
                area.covered_by = None
                area.result_summary = None
                area.hits = 0
            logger.info("CoverageTracker reset")
