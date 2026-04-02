"""Lightweight artifact scanner for security-relevant patterns.

Scans tool result text for critical security patterns (privilege
escalation, crypto, C2 indicators, shellcode, etc.) and returns
structured matches.  Used by workers to auto-promote findings to
the investigation notebook.

Extracted from the former ExecutionGatekeeper to remove the
over-engineered PAUSE/feedback/doom-loop wrapper.
"""

import re
from typing import Dict, List

# Patterns that indicate critical security artifacts in tool results.
# Each tuple: (regex_pattern, human_description)
CRITICAL_ARTIFACT_PATTERNS = [
    # Privilege escalation indicators
    (r"SeTakeOwnershipPrivilege", "Privilege escalation: SeTakeOwnershipPrivilege"),
    (r"SeDebugPrivilege", "Privilege escalation: SeDebugPrivilege"),
    (r"SeImpersonatePrivilege", "Privilege escalation: SeImpersonatePrivilege"),
    (r"SeLoadDriverPrivilege", "Privilege escalation: SeLoadDriverPrivilege"),
    (r"AdjustTokenPrivileges", "Token manipulation: AdjustTokenPrivileges"),
    (r"OpenProcessToken", "Token manipulation: OpenProcessToken"),
    # Crypto / credential patterns
    (r"(?i)CryptEncrypt|CryptDecrypt|BCryptEncrypt|BCryptDecrypt", "Cryptographic operation detected"),
    (r"(?i)(?:password|passwd|credential|secret)\s*[:=]", "Possible hardcoded credential"),
    (r"(?i)-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----", "Embedded private key"),
    # C2 / network indicators
    (r"(?:https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", "Hardcoded IP URL (possible C2)"),
    # Shellcode / injection patterns
    (r"VirtualAlloc.*PAGE_EXECUTE", "Executable memory allocation (possible shellcode)"),
    (r"WriteProcessMemory", "Process memory write (possible injection)"),
    (r"NtCreateThreadEx|RtlCreateUserThread", "Remote thread creation"),
    # Service path issues
    (r"(?i)Unquoted\s+(?:Service\s+)?Path", "Unquoted service path vulnerability"),
    (r"StartServiceCtrlDispatcher", "Windows service entry point"),
    # Anti-analysis
    (r"IsDebuggerPresent|NtQueryInformationProcess", "Anti-debugging technique"),
]

# Pre-compiled for performance
_COMPILED_PATTERNS = [
    (re.compile(pat), desc) for pat, desc in CRITICAL_ARTIFACT_PATTERNS
]


def scan_for_artifacts(text: str) -> List[Dict[str, str]]:
    """Scan text for security-relevant artifact patterns.

    Args:
        text: Tool result text to scan.

    Returns:
        List of dicts with ``"pattern"`` (description) and ``"match"``
        (the matched text snippet, max 200 chars).
    """
    if not text:
        return []

    matches = []
    for compiled, description in _COMPILED_PATTERNS:
        m = compiled.search(text)
        if m:
            # Extract a snippet around the match for context
            start = max(0, m.start() - 40)
            end = min(len(text), m.end() + 40)
            snippet = text[start:end].strip()
            matches.append({
                "pattern": description,
                "match": snippet[:200],
            })

    return matches
