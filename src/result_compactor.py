"""Deterministic compaction for tool results.

Goal: Reduce prompt size and LLM load (rate limits/504) by compacting verbose tool
outputs before they are injected into prompts. Full results remain available via
get_cached_result().
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable
import json


_DEFAULT_KEYWORDS = [
    # execution
    "exec",
    "execve",
    "system",
    "popen",
    "fork",
    "CreateProcess",
    "ShellExecute",
    # env / creds
    "getenv",
    "environ",
    "password",
    "shadow",
    "token",
    "key",
    # files
    "/tmp",
    "/var/tmp",
    "AppData",
    "Program Files",
    "HKLM",
    "RunOnce",
    "CurrentControlSet",
    # compilers/build
    "gcc",
    "g++",
    "clang",
    "ld ",
    "--bootstrap",
    # network
    "http://",
    "https://",
    "socket",
    "connect",
    "send",
    "recv",
    # obfuscation
    "xor",
    "base64",
]


@dataclass(frozen=True)
class CompactionConfig:
    max_chars: int = 2000
    max_list_items: int = 25
    head_lines: int = 40
    tail_lines: int = 10


class ResultCompactor:
    def __init__(self, config: CompactionConfig | None = None, keywords: Iterable[str] | None = None):
        self.config = config or CompactionConfig()
        self.keywords = [k.lower() for k in (keywords or _DEFAULT_KEYWORDS)]

    def compact(self, tool_name: str, result: Any) -> str:
        """Compact a tool result into a small, prompt-safe string."""
        # Lists of strings are common for list_* tools
        if isinstance(result, list):
            return self._compact_list(tool_name, result)

        # Dict results
        if isinstance(result, dict):
            return self._compact_dict(tool_name, result)

        # Strings (e.g., decompilation)
        return self._compact_text(tool_name, str(result))

    def _compact_list(self, tool_name: str, items: list[Any]) -> str:
        # If list contains non-strings, JSON it.
        if any(not isinstance(x, str) for x in items):
            return self._compact_text(tool_name, json.dumps(items, indent=2))

        lines = [x for x in items if x is not None]

        # Keep header lines like "[Total: ...]" if present
        header = []
        body = lines
        if body and isinstance(body[0], str) and body[0].lstrip().startswith("[Total:"):
            header = [body[0]]
            body = body[1:]

        # Prefer lines matching keywords
        kw_hits = [line for line in body if self._line_has_keyword(line)]

        # Build a compact set: header + keyword hits + head + tail
        max_items = self.config.max_list_items
        out: list[str] = []
        out.extend(header)

        # Keyword hits first (bounded)
        for line in kw_hits:
            if len(out) >= max_items:
                break
            if line not in out:
                out.append(line)

        # Then head
        for line in body[: max(0, max_items - len(out))]:
            if len(out) >= max_items:
                break
            if line not in out:
                out.append(line)

        # Then tail (only if we still have space)
        if len(out) < max_items and len(body) > 0:
            tail = body[-min(5, len(body)) :]
            for line in tail:
                if len(out) >= max_items:
                    break
                if line not in out:
                    out.append(line)

        # Add a note if we dropped content
        dropped = max(0, len(lines) - len(out))
        if dropped > 0:
            out.append(f"... [{dropped} more lines omitted; use get_cached_result(...) for full output]")

        return self._cap_chars("\n".join(out))

    def _compact_dict(self, tool_name: str, obj: dict[str, Any]) -> str:
        # Common shapes: {"result": [...]} or {"items": [...]} etc.
        for k in ("items", "imports", "functions"):
            if k in obj and isinstance(obj.get(k), list):
                head = {"keys": sorted(list(obj.keys()))}
                compact_list = self._compact_list(tool_name, obj.get(k) or [])
                return self._cap_chars(json.dumps(head, indent=2) + "\n" + compact_list)

        return self._compact_text(tool_name, json.dumps(obj, indent=2))

    def _compact_text(self, tool_name: str, text: str) -> str:
        # Decompilation/disassembly: keep head + keyword lines + tail
        lines = text.splitlines()
        if len(lines) <= (self.config.head_lines + self.config.tail_lines):
            return self._cap_chars(text)

        head = lines[: self.config.head_lines]
        tail = lines[-self.config.tail_lines :]

        kw_lines: list[str] = []
        for line in lines[self.config.head_lines : -self.config.tail_lines]:
            if self._line_has_keyword(line):
                kw_lines.append(line)
                if len(kw_lines) >= 30:
                    break

        out = []
        out.extend(head)
        if kw_lines:
            out.append("... [keyword hits] ...")
            out.extend(kw_lines)
        out.append("... [tail] ...")
        out.extend(tail)
        out.append("... [content omitted; use get_cached_result(...) for full output]")

        return self._cap_chars("\n".join(out))

    def _line_has_keyword(self, line: str) -> bool:
        low = line.lower()
        return any(k in low for k in self.keywords)

    def _cap_chars(self, text: str) -> str:
        if len(text) <= self.config.max_chars:
            return text
        keep = self.config.max_chars
        return text[:keep] + "\n... [truncated by compactor]"
