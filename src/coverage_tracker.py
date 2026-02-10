#!/usr/bin/env python3
"""
Coverage Tracker — Investigation Area Checklist
------------------------------------------------
Tracks which security investigation areas have been explored during
a binary analysis session. Injects a checklist into the execution prompt
so the AI always sees what it hasn't investigated yet.

Inspired by the post-mortem of the WiseBootAssistant investigation,
where the AI never searched for service-related APIs or strings because
nothing reminded it to check that area.
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class CoverageArea:
    """A single investigation area with its check targets."""
    name: str
    description: str
    apis: List[str] = field(default_factory=list)
    strings: List[str] = field(default_factory=list)
    covered: bool = False
    covered_by: Optional[str] = None          # Which tool call covered it
    result_summary: Optional[str] = None      # Brief summary of what was found
    hits: int = 0                             # How many API/string hits were found


# Default security checklist for binary analysis
DEFAULT_CHECKLIST: Dict[str, dict] = {
    "service_management": {
        "description": "Windows service registration and management",
        "apis": ["CreateServiceW", "OpenServiceW", "OpenSCManagerW",
                 "StartServiceW", "ChangeServiceConfigW", "DeleteService"],
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
        "description": "Filesystem paths and file handling (unquoted paths, temp files)",
        "apis": ["CreateFileW", "MoveFileW", "CopyFileW",
                 "GetTempPathW", "GetTempFileNameW"],
        "strings": ["Program Files", "C:\\\\", "AppData", "TEMP",
                     "system32", "ProgramData"],
    },
    "registry_persistence": {
        "description": "Registry persistence, service registration, and startup",
        "apis": ["RegOpenKeyExW", "RegSetValueExW", "RegCreateKeyExW",
                 "RegDeleteKeyW"],
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
}


class CoverageTracker:
    """
    Tracks investigation coverage across binary analysis sessions.
    
    Maintains a checklist of security-relevant investigation areas and
    automatically marks them as covered when tool results contain matching
    API names or strings.
    """
    
    def __init__(self, checklist: Optional[Dict[str, dict]] = None):
        """
        Initialize the coverage tracker.
        
        Args:
            checklist: Custom checklist dict, or None to use DEFAULT_CHECKLIST.
        """
        raw = DEFAULT_CHECKLIST if checklist is None else checklist
        self.areas: Dict[str, CoverageArea] = {}
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
                     result_summary: str = "") -> None:
        """Manually mark an area as covered."""
        if area_name in self.areas:
            area = self.areas[area_name]
            area.covered = True
            area.covered_by = tool_used
            area.result_summary = result_summary
            logger.info(f"Coverage: '{area_name}' marked covered by {tool_used}")
    
    def auto_mark_from_result(self, tool_name: str, tool_params: dict,
                              result: str) -> List[str]:
        """
        Automatically scan a tool result for coverage matches.
        
        Checks if the tool result or the tool parameters contain any
        of the API names or string patterns from uncovered areas.
        
        Args:
            tool_name: Name of the tool that was executed.
            tool_params: Parameters the tool was called with.
            result: Full text result from the tool.
            
        Returns:
            List of area names that were newly covered.
        """
        newly_covered = []
        combined_text = f"{tool_name} {str(tool_params)} {result}".lower()
        
        for name, area in self.areas.items():
            if area.covered:
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
                area.covered = True
                area.covered_by = tool_name
                area.hits = hits
                area.result_summary = f"{hits} matches found"
                newly_covered.append(name)
                logger.info(
                    f"Coverage: '{name}' auto-covered ({hits} hits) "
                    f"from {tool_name}"
                )
        
        return newly_covered
    
    def get_uncovered(self) -> List[CoverageArea]:
        """Return list of areas that have NOT been investigated."""
        return [a for a in self.areas.values() if not a.covered]
    
    def get_covered(self) -> List[CoverageArea]:
        """Return list of areas that HAVE been investigated."""
        return [a for a in self.areas.values() if a.covered]
    
    def coverage_ratio(self) -> float:
        """Return coverage as a ratio (0.0 to 1.0)."""
        total = len(self.areas)
        if total == 0:
            return 1.0
        covered = sum(1 for a in self.areas.values() if a.covered)
        return covered / total
    
    def format_for_prompt(self) -> str:
        """
        Format the checklist for injection into the execution prompt.
        
        Returns a compact markdown checklist showing covered (✅) and
        uncovered (❌) areas with suggestions for uncovered areas.
        """
        lines = ["## Investigation Coverage"]
        
        covered = self.get_covered()
        uncovered = self.get_uncovered()
        
        ratio = self.coverage_ratio()
        lines.append(
            f"Progress: {len(covered)}/{len(self.areas)} areas "
            f"({ratio:.0%})"
        )
        lines.append("")
        
        # Show uncovered first (more important — the AI should focus here)
        if uncovered:
            lines.append("### ❌ Not Yet Investigated")
            for area in uncovered:
                api_hint = ", ".join(area.apis[:3])
                str_hint = ", ".join(area.strings[:3])
                lines.append(
                    f"- **{area.name}**: {area.description}"
                )
                lines.append(
                    f"  Search for: APIs=[{api_hint}] "
                    f"Strings=[{str_hint}]"
                )
            lines.append("")
        
        # Show covered (briefly)
        if covered:
            lines.append("### ✅ Covered")
            for area in covered:
                summary = area.result_summary or "checked"
                lines.append(
                    f"- **{area.name}**: {summary} "
                    f"(via {area.covered_by})"
                )
        
        return "\n".join(lines)
    
    def reset(self) -> None:
        """Reset all coverage (for new investigation)."""
        for area in self.areas.values():
            area.covered = False
            area.covered_by = None
            area.result_summary = None
            area.hits = 0
        logger.info("CoverageTracker reset")
