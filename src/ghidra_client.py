"""
Client for interacting with the GhidraMCP API.
"""

import logging
import re
import struct
import base64
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse

import httpx

from src.config import GhidraMCPConfig

logger = logging.getLogger("ollama-ghidra-bridge.ghidra")


@dataclass
class _PyGhidraProgramEntry:
    key: str
    program: Any
    name: str
    project: str
    program_path: str
    consumer: Any = None
    program_ctx: Any = None
    open_program_cm: Any = None

    @classmethod
    def from_program(
        cls,
        program,
        *,
        selected_path: str | None = None,
        project=None,
        existing_keys: set[str] | None = None,
        slot: int = 1,
        consumer=None,
        program_ctx=None,
        open_program_cm=None,
    ) -> "_PyGhidraProgramEntry":
        info = {
            "name": "Unknown Binary",
            "project": "Unknown Project",
            "program_path": selected_path or "",
        }

        try:
            domain_file = program.getDomainFile()
            if domain_file is not None:
                try:
                    info["name"] = str(domain_file.getName())
                except Exception:
                    pass
                try:
                    info["program_path"] = str(domain_file.getPathname())
                except Exception:
                    pass
                try:
                    domain_project = domain_file.getProject()
                    if domain_project is not None:
                        info["project"] = str(domain_project.getName())
                except Exception:
                    pass
        except Exception:
            pass

        try:
            if info["name"] == "Unknown Binary":
                info["name"] = str(program.getName())
        except Exception:
            pass

        if info["project"] == "Unknown Project":
            try:
                if project is not None and hasattr(project, "getName"):
                    info["project"] = str(project.getName())
            except Exception:
                pass

        base_key = info["program_path"] or info["name"] or f"program_{slot}"
        key = base_key
        suffix = 2
        existing_keys = set() if existing_keys is None else existing_keys
        while key in existing_keys:
            key = f"{base_key}#{suffix}"
            suffix += 1

        return cls(
            key=key,
            program=program,
            name=info["name"],
            project=info["project"],
            program_path=info["program_path"],
            consumer=consumer,
            program_ctx=program_ctx,
            open_program_cm=open_program_cm,
        )

    def info(self) -> Dict[str, str]:
        return {
            "name": self.name,
            "project": self.project,
            "program_path": self.program_path,
        }

    def selector(self) -> str:
        return self.program_path or self.name or self.key

    def label(self, *, duplicate_name: bool = False) -> str:
        name = self.name or "Unknown Binary"
        path = self.program_path or self.key
        if duplicate_name and path and path != name:
            return f"{name} ({path})"
        return name if name != "Unknown Binary" else path

    def instance_info(self) -> Dict[str, str]:
        return {
            "program_key": self.key,
            "file": self.name or "Unknown Binary",
            "project": self.project or "Unknown Project",
            "program_path": self.program_path,
            "backend": "pyghidra",
        }


class AbstractGhidraClient(ABC):
    """Abstract base class for Ghidra clients.

    Concrete backends (HTTP GhidraMCP server, pyGhidra, etc.) should
    implement the same public tool surface. Shared backend-agnostic
    helpers live here.
    """

    def __init__(self, config: GhidraMCPConfig, ollama_client=None) -> None:
        self.config = config
        self.ollama_client = ollama_client

    # ------------------------------------------------------------------
    # Backend lifecycle / introspection hooks
    # ------------------------------------------------------------------

    @abstractmethod
    def health_check(self) -> bool:
        """Check whether the backend is currently usable."""

    @abstractmethod
    def check_health(self) -> bool:
        """Alternate health-check entry point used by the UI/tests."""

    @abstractmethod
    def instances_list(self) -> str:
        """List available Ghidra instances/programs for this backend."""

    @abstractmethod
    def instances_discover(self, host: str = "localhost", start_port: int = 8192, end_port: int = 8200) -> str:
        """Discover available instances/programs for this backend."""

    @abstractmethod
    def instances_use(self, port: int) -> str:
        """Switch the active instance/program when supported."""

    @abstractmethod
    def instances_current(self) -> str:
        """Describe the current active instance/program."""

    @abstractmethod
    def get_current_program_info(self) -> Dict[str, str]:
        """Return structured metadata for the active program."""

    def get_command_context(self, command_name: str, params: Dict[str, Any]) -> Dict[str, str]:
        """Return backend-specific command context, defaulting to current program info."""
        return self.get_current_program_info()

    # ------------------------------------------------------------------
    # Shared helpers and backend-agnostic high-level tool surface
    # ------------------------------------------------------------------

    # Safe limit enforcement for bulk operations to prevent context overflow
    MAX_SAFE_LIMIT = 20
    LIMIT_WARNING_TEMPLATE = (
        "⚠️  {method} limit {limit} exceeds MAX_SAFE_LIMIT={max_safe}. "
        "Using targeted searches with 'filter' parameter is recommended. Capping to MAX_SAFE_LIMIT."
    )

    def _coerce_int_param(self, value: Any, *, param_name: str, default: int) -> int:
        """Best-effort conversion for int params crossing the LLM boundary."""
        if value is None:
            return default
        # bool is a subclass of int; treat it as invalid here
        if isinstance(value, bool):
            logger.warning(f"Invalid {param_name}=bool; using default={default}")
            return default
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            s = value.strip()
            try:
                return int(s)
            except ValueError:
                logger.warning(f"Invalid {param_name}='{value}'; using default={default}")
                return default
        logger.warning(f"Invalid {param_name} type={type(value).__name__}; using default={default}")
        return default

    def _get_offset_limit(self, offset: Any, limit: Any, *, default_limit: int = 100) -> Tuple[int, int]:
        """Parse non-negative offset/limit pairs consistently across backends."""
        parsed_offset = max(0, self._coerce_int_param(offset, param_name="offset", default=0))
        parsed_limit = max(
            0,
            self._coerce_int_param(limit, param_name="limit", default=default_limit),
        )
        return parsed_offset, parsed_limit

    @staticmethod
    def _paginate_lines(lines: List[str], offset: int, limit: int) -> List[str]:
        """Slice a list of rendered lines using MCP-style pagination."""
        if limit == 0:
            return []
        return lines[offset : offset + limit]

    def _render_paginated_lines(self, lines: List[str], offset: int, limit: int) -> List[str]:
        """Render list pagination metadata in the same shape as the HTTP plugin."""
        total = len(lines)
        start = max(0, offset)
        end = min(total, offset + limit)

        if start >= total:
            return [f"[Total: {total}] [Showing: 0 items - offset {offset} exceeds total]"]

        header = f"[Total: {total}] [Showing: {start + 1}-{end}]"
        if end < total:
            header += f" [Next: offset={end}, limit={limit}]"

        return [header, *lines[start:end]]

    def _render_paginated_text(self, text: str, offset: int, limit: int) -> str:
        """Render text pagination metadata in the same shape as the HTTP plugin."""
        if text is None:
            return ""

        normalized = text.strip()
        lines = normalized.splitlines()
        total = len(lines)
        start = max(0, offset)
        end = min(total, offset + limit)

        if start >= total:
            return f"[Total Lines: {total}] [Showing: 0 lines - offset {offset} exceeds total]"

        parts = [f"[Total Lines: {total}] [Showing Lines: {start + 1}-{end}]"]
        parts.extend(lines[start:end])
        if end < total:
            parts.append(f"... [Next: offset={end}, limit={limit}]")
        return "\n".join(parts)

    @staticmethod
    def _escape_display_string(value: str | None) -> str:
        """Escape non-printable characters similarly to the HTTP plugin."""
        if value is None:
            return ""

        pieces: List[str] = []
        for char in value:
            codepoint = ord(char)
            if 32 <= codepoint < 127:
                pieces.append(char)
            elif char == "\n":
                pieces.append("\\n")
            elif char == "\r":
                pieces.append("\\r")
            elif char == "\t":
                pieces.append("\\t")
            else:
                pieces.append(f"\\x{codepoint & 0xFF:02x}")
        return "".join(pieces)

    @staticmethod
    def _normalize_addr(identifier: str) -> str:
        """Return canonical hexadecimal address without any '0x' prefix, lower-cased."""
        if not identifier:
            return ""

        if identifier.isalnum() and all(c in "0123456789abcdefABCDEF" for c in identifier):
            return identifier.lower()

        if identifier.lower().startswith("0x"):
            return identifier[2:].lower()

        match = re.search(r"([0-9a-fA-F]{6,})", identifier)
        if match:
            return match.group(1).lower()

        return identifier

    @abstractmethod
    def list_methods(self, offset: int = 0, limit: int = 100) -> List[str]:
        """List all function names in the program with pagination."""

    @abstractmethod
    def list_classes(self, offset: int = 0, limit: int = 100) -> List[str]:
        """List all namespace/class names in the program with pagination."""

    @abstractmethod
    def decompile_function(self, name: str, offset: int = 0, limit: int = 500) -> str:
        """Decompile a specific function by name and return the decompiled C code."""

    @abstractmethod
    def rename_function(self, old_name: str, new_name: str) -> str:
        """Rename a function by its current name to a new user-defined name."""

    @abstractmethod
    def rename_data(self, address: str, new_name: str) -> str:
        """Rename a data label at the specified address."""

    @abstractmethod
    def list_segments(self, offset: int = 0, limit: int = 100) -> List[str]:
        """List all memory segments in the program with pagination."""

    @abstractmethod
    def list_imports(self, offset: int = 0, limit: int = 100) -> List[str]:
        """List imported symbols in the program with pagination."""

    @abstractmethod
    def list_exports(self, offset: int = 0, limit: int = 100) -> List[str]:
        """List exported functions/symbols with pagination."""

    @abstractmethod
    def list_namespaces(self, offset: int = 0, limit: int = 100) -> List[str]:
        """List all non-global namespaces in the program with pagination."""

    @abstractmethod
    def list_data_items(self, offset: int = 0, limit: int = 100) -> List[str]:
        """List defined data labels and their values with pagination."""

    @abstractmethod
    def list_strings(self, offset: int = 0, limit: int = 100, filter: str | None = None) -> List[str]:
        """List defined strings or search them by substring."""

    @abstractmethod
    def search_functions_by_name(self, query: str, offset: int = 0, limit: int = 100) -> List[str]:
        """Search for functions whose name contains the given substring."""

    @abstractmethod
    def rename_variable(self, function_name: str, old_name: str, new_name: str) -> str:
        """Rename a local variable within a function."""

    @abstractmethod
    def get_function_by_address(self, address: str) -> str:
        """Get a function by its address."""

    @abstractmethod
    def get_current_address(self) -> str:
        """Get the address currently selected by the user."""

    @abstractmethod
    def get_current_function(self) -> str:
        """Get the function currently selected by the user."""

    @abstractmethod
    def list_functions(self, offset: int = 0, limit: int = 100) -> List[str]:
        """List all functions in the database with pagination."""

    @abstractmethod
    def decompile_function_by_address(self, address: str, offset: int = 0, limit: int = 500) -> str:
        """Decompile a function by address and return the decompiled C code."""

    @abstractmethod
    def disassemble_function(self, address: str) -> List[str]:
        """Get assembly code for a function."""

    @abstractmethod
    def set_decompiler_comment(self, address: str, comment: str) -> str:
        """Set a comment for a given address in the function pseudocode."""

    @abstractmethod
    def set_disassembly_comment(self, address: str, comment: str) -> str:
        """Set a comment for a given address in the function disassembly."""

    @abstractmethod
    def rename_function_by_address(self, function_address: str, new_name: str) -> str:
        """Rename a function by its address."""

    @abstractmethod
    def set_function_prototype(self, function_address: str, prototype: str) -> str:
        """Set a function prototype."""

    @abstractmethod
    def set_local_variable_type(self, function_address: str, variable_name: str, new_type: str) -> str:
        """Set a local variable type."""

    @abstractmethod
    def get_xrefs_to(self, address: str, offset: int = 0, limit: int = 100):
        """List all xrefs to an address."""

    @abstractmethod
    def get_xrefs_from(self, address: str, offset: int = 0, limit: int = 100):
        """List all xrefs from an address."""

    @abstractmethod
    def get_function_xrefs(self, name: str, offset: int = 0, limit: int = 100):
        """List xrefs to a function or symbol."""

    @abstractmethod
    def read_bytes(self, address: str, length: int = 16, format: str = "hex") -> str:
        """Read raw bytes from memory."""

    def analyze_function(self, address: str = None) -> str:
        """
        Analyze a function, including its decompiled code and all functions it calls.
        If no address is provided, uses the current function.

        Args:
            address: Function address (optional)

        Returns:
            Comprehensive function analysis including decompiled code and referenced functions
        """
        if address is None:
            determined_address = None
            # Try with get_current_function() first
            current_function_info = self.get_current_function()  # Expected: "FunctionName @ Address" or error string

            if not current_function_info.startswith("Error"):
                if "@ " in current_function_info:
                    parts = current_function_info.split("@ ", 1)
                    if len(parts) == 2:
                        potential_address = parts[1].strip()
                        # Validate if the extracted address is a non-empty hex string
                        if potential_address and all(c in "0123456789abcdefABCDEF" for c in potential_address):
                            determined_address = potential_address
                            logger.info(
                                f"analyze_function: Determined address '{determined_address}' from get_current_function() result: '{current_function_info}'."
                            )
                        else:
                            logger.warning(
                                f"analyze_function: Extracted part '{potential_address}' from get_current_function() result ('{current_function_info}') is not a valid hex address."
                            )
                    else:
                        # This case should ideally not be reached if "@ " is present and split is limited to 1
                        logger.warning(
                            f"analyze_function: Unexpected split result from get_current_function() ('{current_function_info}') despite '@ ' being present."
                        )
                else:
                    logger.warning(
                        f"analyze_function: Result from get_current_function() ('{current_function_info}') does not contain '@ '. Attempting get_current_address()."
                    )
            else:
                logger.warning(
                    f"analyze_function: get_current_function() returned an error: '{current_function_info}'. Attempting get_current_address()."
                )

            # If get_current_function() didn't yield a valid address, try get_current_address()
            if determined_address is None:
                logger.info("analyze_function: Trying get_current_address() as fallback to determine function address.")
                current_address_str = self.get_current_address()  # Expected: "Address" or error string
                # Validate if current_address_str is a non-empty hex string and not an error
                if (
                    not current_address_str.startswith("Error")
                    and current_address_str
                    and all(c in "0123456789abcdefABCDEF" for c in current_address_str)
                ):
                    determined_address = current_address_str
                    logger.info(f"analyze_function: Determined address '{determined_address}' from get_current_address().")
                else:
                    logger.warning(
                        f"analyze_function: get_current_address() did not yield a valid hex address. Result: '{current_address_str}'"
                    )

            if determined_address:
                address = determined_address
            else:
                logger.error(
                    "analyze_function: Could not determine current function address automatically after trying get_current_function() and get_current_address()."
                )
                return "Error: Could not determine current function address. Please provide an address or ensure a function/address is selected in Ghidra."

        # Get the decompiled code for the target function
        decompiled_code = self.decompile_function_by_address(address)
        if decompiled_code.startswith("Error"):
            return f"Error analyzing function at {address}: {decompiled_code}"

        # Extract function calls from the decompiled code
        function_calls = []
        for line in decompiled_code.splitlines():
            matches = re.finditer(r"\b(\w+)\s*\(", line)
            for match in matches:
                func_name = match.group(1)
                if func_name not in ["if", "while", "for", "switch", "return", "sizeof"]:
                    function_calls.append(func_name)

        function_calls = list(set(function_calls))

        # If AI analysis is available, generate semantic summary
        if self.ollama_client:
            try:
                # Prepare analysis prompt for AI
                analysis_prompt = (
                    f"Analyze this decompiled function and provide a concise summary.\n\n"
                    f"INSTRUCTIONS:\n"
                    f"1. Identify the function's PRIMARY PURPOSE in one sentence\n"
                    f"2. List KEY OPERATIONS it performs\n"
                    f"3. Note any IMPORTANT STRINGS or error messages that reveal its purpose\n"
                    f"4. Identify what PROTOCOL/TECHNOLOGY it relates to (if applicable)\n"
                    f"5. Suggest a DESCRIPTIVE FUNCTION NAME based on its behavior\n\n"
                    f"Format your response as:\n"
                    f"PRIMARY PURPOSE: <one sentence>\n"
                    f"KEY OPERATIONS: <bullet points>\n"
                    f"NOTABLE STRINGS: <relevant strings found in code>\n"
                    f"TECHNOLOGY: <protocol/library/framework if identified>\n"
                    f"SUGGESTED NAME: <descriptive_function_name>\n\n"
                    f"DECOMPILED CODE:\n{decompiled_code[:4000]}\n"  # Limit to avoid context overflow
                )

                ai_summary = self.ollama_client.generate(prompt=analysis_prompt, temperature=0.3)

                # Build result with AI analysis first
                result = [
                    f"=== AI-POWERED ANALYSIS OF FUNCTION AT {address} ===",
                    "",
                    ai_summary,
                    "",
                    "=== RAW DECOMPILED CODE (TRUNCATED) ===",
                    "",
                    decompiled_code[:2000],  # Show limited code sample
                    "... [Code truncated for context efficiency] ..." if len(decompiled_code) > 2000 else "",
                    "",
                ]

                logger.info(f"AI analysis generated for function at {address}")

            except Exception as e:
                logger.warning(f"AI analysis failed for function at {address}: {e}. Falling back to raw code.")
                # Fallback to raw code if AI analysis fails
                result = [f"=== ANALYSIS OF FUNCTION AT {address} ===", "", decompiled_code, ""]
        else:
            # No AI available, use raw code
            result = [f"=== ANALYSIS OF FUNCTION AT {address} ===", "", decompiled_code, ""]

        # Optionally append a few key referenced functions (not all to save context)
        if function_calls and len(function_calls) > 0:
            result.append("=== KEY REFERENCED FUNCTIONS (SAMPLE) ===")
            result.append("")
            # Limit to first 3 most interesting functions
            for func_name in list(function_calls)[:3]:
                try:
                    func_code = self.decompile_function(func_name)
                    if not func_code.startswith("Error"):
                        result.append(f"--- Function: {func_name} ---")
                        result.append(func_code[:500])  # Truncate individual functions
                        result.append("...")
                        result.append("")
                except Exception as e:
                    logger.debug(f"Could not decompile referenced function {func_name}: {e}")

        return "\n".join(result)

    # =========================================================================
    # Smart Analysis Tools - Algorithmic scanning without LLM intervention
    # =========================================================================

    def scan_function_pointer_tables(
        self,
        min_table_entries: int = 3,
        pointer_size: int = 8,
        max_scan_size: int = 524288,  # 512KB per segment max
        alignment: int = 8,
    ) -> List[Dict]:
        """
        Scan the binary for function pointer tables without LLM assistance.

        Algorithm:
        1. Get all memory segments and identify data segments
        2. Get all known function addresses to build a lookup set
        3. Scan data segments for pointer-aligned sequences
        4. Identify consecutive values that match valid function addresses
        5. Return list of suspected tables with their entries

        Args:
            min_table_entries: Minimum consecutive function pointers to qualify as a table (default: 3)
            pointer_size: Size of pointers in bytes (8 for x64, 4 for x86)
            max_scan_size: Maximum bytes to scan per segment
            alignment: Expected pointer alignment

        Returns:
            List of dicts: {
                'table_address': str,
                'entry_count': int,
                'entries': [{'offset': int, 'pointer': str, 'function_name': str}, ...]
            }
        """
        results = []

        # Step 1: Get all function addresses and build a lookup table
        logger.info("Building function address lookup table...")
        functions_raw = self.list_functions()
        function_map = {}  # address -> name

        for line in functions_raw:
            # Parse "FUN_140001234 at 140001234" or "main at 140001234"
            if " at " in line:
                parts = line.split(" at ")
                if len(parts) == 2:
                    name = parts[0].strip()
                    addr_str = parts[1].strip()
                    try:
                        addr_int = int(addr_str, 16)
                        function_map[addr_int] = name
                    except ValueError:
                        continue

        if not function_map:
            logger.warning("No functions found, cannot scan for tables")
            return []

        # Determine code address range for quick filtering
        min_func_addr = min(function_map.keys())
        max_func_addr = max(function_map.keys())
        logger.info(f"Found {len(function_map)} functions in range 0x{min_func_addr:x} - 0x{max_func_addr:x}")

        # Step 2: Get memory segments and identify data segments
        logger.info("Analyzing memory segments...")
        segments_raw = self.list_segments()
        data_segments = []

        for line in segments_raw:
            # Parse segment info - Ghidra format: ".text: 401000 - 41d5ff"
            # Look for the pattern after the colon: "start - end" where start/end are hex
            seg_match = re.match(r"^([^:]+):\s*([0-9a-fA-F]+)\s*-\s*([0-9a-fA-F]+)", line)
            if seg_match:
                try:
                    seg_name = seg_match.group(1).strip()
                    start = int(seg_match.group(2), 16)
                    end = int(seg_match.group(3), 16)
                    size = end - start
                    if size > 0:
                        data_segments.append({"start": start, "end": end, "name": seg_name, "size": size})
                        logger.debug(f"Parsed segment: {seg_name} 0x{start:x} - 0x{end:x} ({size} bytes)")
                except ValueError:
                    continue

        # If we couldn't parse segments, try scanning around function addresses
        if not data_segments:
            logger.warning("Could not parse data segments, scanning around function address range")
            # Create a pseudo-segment covering the function address space + some buffer
            data_segments = [
                {
                    "start": max(0, min_func_addr - 0x10000),
                    "end": max_func_addr + 0x10000,
                    "name": "inferred",
                    "size": (max_func_addr - min_func_addr) + 0x20000,
                }
            ]

        # Prioritize data segments where function tables are likely to be found
        # Skip code segments (.text) and special segments
        # Note: .bss is uninitialized data (zeros) so unlikely to have pointers
        skip_segments = {
            ".text",
            ".pdata",
            ".xdata",
            ".rsrc",
            ".buildid",
            "headers",
            ".bss",
            ".reloc",
            ".gnu_debuglink",
            ".comment",
        }
        priority_segments = {".rdata", ".data", ".rodata", ".got", ".got.plt", ".idata"}

        # Sort segments: priority segments first, then others, skip unwanted
        def segment_priority(seg):
            name_lower = seg["name"].lower()
            if name_lower in skip_segments:
                return 2  # Skip these
            if name_lower in priority_segments:
                return 0  # Scan first
            return 1  # Scan after priority

        scannable_segments = [s for s in data_segments if s["name"].lower() not in skip_segments]
        scannable_segments.sort(key=segment_priority)

        logger.info(f"Scanning {len(scannable_segments)} segment(s) for function pointer tables (skipping code segments)")

        # Step 3: Scan each segment for function pointer sequences
        for segment in scannable_segments:
            scan_size = min(segment["size"], max_scan_size)
            logger.info(f"Scanning segment {segment['name']}: 0x{segment['start']:x} ({segment['size']} bytes)")
            tables_in_segment = self._scan_segment_for_tables(
                segment["start"],
                scan_size,
                function_map,
                min_func_addr,
                max_func_addr,
                pointer_size,
                min_table_entries,
                alignment,
            )
            if tables_in_segment:
                logger.info(f"Found {len(tables_in_segment)} table(s) in segment {segment['name']}")
            results.extend(tables_in_segment)

        # Log summary
        if results:
            logger.info(f"Total: Found {len(results)} potential function pointer tables")
        else:
            logger.info(f"No function pointer tables found (require {min_table_entries}+ consecutive pointers)")
            logger.info("Tip: Some binaries (especially C programs) may not have traditional pointer tables")

        return results

    def _scan_segment_for_tables(
        self,
        start_addr: int,
        scan_length: int,
        function_map: Dict[int, str],
        min_func_addr: int,
        max_func_addr: int,
        pointer_size: int,
        min_table_entries: int,
        alignment: int,
    ) -> List[Dict]:
        """
        Scan a memory region for function pointer tables.

        Returns list of detected tables.
        """
        tables = []
        chunk_size = 4096  # Read 4KB at a time

        for offset in range(0, scan_length, chunk_size):
            read_size = min(chunk_size, scan_length - offset)
            current_addr = start_addr + offset

            try:
                # Read raw bytes (base64 encoded)
                raw_result = self.read_bytes(hex(current_addr), length=read_size, format="raw")

                if not raw_result or "Error" in raw_result or "No program" in raw_result:
                    continue

                # Decode base64 to bytes
                try:
                    data = base64.b64decode(raw_result.strip())
                    if len(data) < pointer_size:
                        continue
                except Exception:
                    continue

                # Scan for consecutive function pointers
                tables_in_chunk = self._find_pointer_sequences(
                    data, current_addr, function_map, min_func_addr, max_func_addr, pointer_size, min_table_entries, alignment
                )
                tables.extend(tables_in_chunk)

            except Exception as e:
                logger.debug(f"Error scanning at 0x{current_addr:x}: {e}")
                continue

        return tables

    def _find_pointer_sequences(
        self,
        data: bytes,
        base_addr: int,
        function_map: Dict[int, str],
        min_func_addr: int,
        max_func_addr: int,
        pointer_size: int,
        min_table_entries: int,
        alignment: int,
    ) -> List[Dict]:
        """
        Find sequences of consecutive function pointers in a byte array.
        """
        tables = []

        # Track current sequence
        current_table_start = None
        current_entries = []

        # Format string for struct.unpack (little-endian)
        ptr_format = "<Q" if pointer_size == 8 else "<I"

        i = 0
        while i <= len(data) - pointer_size:
            try:
                # Extract pointer value
                ptr_bytes = data[i : i + pointer_size]
                ptr_value = struct.unpack(ptr_format, ptr_bytes)[0]

                # Quick range check then lookup
                is_valid_func = min_func_addr <= ptr_value <= max_func_addr and ptr_value in function_map

                if is_valid_func:
                    # We found a valid function pointer
                    if current_table_start is None:
                        current_table_start = base_addr + i

                    current_entries.append(
                        {
                            "offset": len(current_entries) * pointer_size,
                            "pointer": f"0x{ptr_value:x}",
                            "function_name": function_map[ptr_value],
                        }
                    )
                    i += alignment
                    continue

                # Not a valid function pointer - check if we should end current sequence
                if current_entries:
                    if len(current_entries) >= min_table_entries:
                        tables.append(
                            {
                                "table_address": f"0x{current_table_start:x}",
                                "entry_count": len(current_entries),
                                "entries": current_entries.copy(),
                            }
                        )
                    current_table_start = None
                    current_entries = []

                i += alignment

            except struct.error:
                i += alignment
                continue

        # Don't forget the last sequence
        if current_entries and len(current_entries) >= min_table_entries:
            tables.append(
                {
                    "table_address": f"0x{current_table_start:x}",
                    "entry_count": len(current_entries),
                    "entries": current_entries.copy(),
                }
            )

        return tables

    def format_table_scan_results(self, tables: List[Dict], max_entries_shown: int = 10) -> str:
        """
        Format the scan results for human-readable output.

        Args:
            tables: List of table dicts from scan_function_pointer_tables
            max_entries_shown: Maximum entries to show per table (default: 10)

        Returns:
            Formatted string with table information
        """
        if not tables:
            return "No function pointer tables detected."

        lines = [f"Found {len(tables)} function pointer table(s):\n"]

        for i, table in enumerate(tables, 1):
            lines.append(f"## Table {i}: {table['table_address']} ({table['entry_count']} entries)")

            entries_to_show = table["entries"][:max_entries_shown]
            for entry in entries_to_show:
                lines.append(f"  [{entry['offset']:4d}] {entry['pointer']} -> {entry['function_name']}")

            if len(table["entries"]) > max_entries_shown:
                lines.append(f"  ... and {len(table['entries']) - max_entries_shown} more entries")
            lines.append("")

        return "\n".join(lines)


class GhidraMCPClient(AbstractGhidraClient):
    """HTTP-based client for interacting with GhidraMCP API."""

    def __init__(self, config: GhidraMCPConfig, ollama_client=None):
        """
        Initialize the GhidraMCP client.

        Args:
            config: GhidraMCPConfig object with connection details
            ollama_client: Optional OllamaClient for AI-powered analysis
        """
        super().__init__(config=config, ollama_client=ollama_client)
        self.client = httpx.Client(timeout=config.timeout)
        self.api_version = None

        # Instance management
        self.active_instances = {}  # port -> info_dict
        self.current_instance_port = None

        # Parse default port from config.base_url
        try:
            parsed = urlparse(str(config.base_url))
            if parsed.port:
                self.default_port = parsed.port
                # We'll set this as active initially, but verify it later
                self.current_instance_port = self.default_port
                self.active_instances[self.default_port] = {"url": str(config.base_url).rstrip("/")}
            else:
                self.default_port = 8080
                self.current_instance_port = 8080
        except Exception:
            self.default_port = 8080
            self.current_instance_port = 8080

        # Thread-safety: serialize all HTTP requests for future parallel workers
        self._request_lock = threading.Lock()

        logger.info(f"Initialized GhidraMCP client at: {config.base_url}")

        # Try to detect API version and available endpoints
        self._detect_api()

        # Auto-discover other instances on startup
        try:
            self.instances_list()
        except AttributeError:
            # Methods might not be added yet if doing partial update
            pass

    def _detect_api(self):
        """Detect the API version and available endpoints."""
        try:
            # Try to get available methods
            response = self._http_get_lines("methods", {"offset": 0, "limit": 1})
            # Check if response is valid (list of strings, not error strings)
            if (
                response
                and isinstance(response, list)
                and not (response and (response[0].startswith("Error") or response[0].startswith("Request failed")))
            ):
                logger.info("Successfully connected to GhidraMCP API")
                # Update info for current instance
                if self.current_instance_port:
                    self._update_instance_info(self.current_instance_port)
            else:
                logger.warning(f"Failed to connect to GhidraMCP API: {response}")
        except Exception as e:
            logger.warning(f"Error detecting API: {str(e)}")

    def _get_base_url(self) -> str:
        """Get the base URL for the current active instance."""
        if self.current_instance_port and self.current_instance_port in self.active_instances:
            return self.active_instances[self.current_instance_port]["url"]
        return str(self.config.base_url).rstrip("/")

    def _http_request_text(
        self,
        method: str,
        endpoint: str,
        *,
        params: Dict[str, Any] | None = None,
        data: Dict[str, Any] | str | None = None,
    ) -> str:
        """Execute an HTTP request against the current GhidraMCP instance."""
        if params is None:
            params = {}

        base_url = self._get_base_url()
        endpoint = endpoint.lstrip("/")
        url = f"{base_url}/{endpoint}"

        try:
            with self._request_lock:
                if method.upper() == "GET":
                    response = self.client.get(url, params=params, timeout=self.config.timeout)
                elif isinstance(data, dict):
                    response = self.client.post(
                        url,
                        params=params,
                        data=data,
                        timeout=self.config.timeout,
                    )
                elif data is None:
                    response = self.client.post(url, params=params, timeout=self.config.timeout)
                else:
                    response = self.client.post(
                        url,
                        params=params,
                        data=data.encode("utf-8"),
                        timeout=self.config.timeout,
                    )
        except Exception as exc:
            error_msg = f"Request failed: {exc}"
            logger.error(error_msg)
            return error_msg

        response.encoding = "utf-8"
        if response.status_code == 200:
            return response.text if method.upper() == "GET" else response.text.strip()
        return f"Error {response.status_code}: {response.text.strip()}"

    def _http_get_lines(self, endpoint: str, params: Dict[str, Any] | None = None) -> List[str]:
        """GET an endpoint and return split text lines."""
        text = self._http_request_text("GET", endpoint, params=params)
        return text.splitlines()

    def _http_post_text(
        self,
        endpoint: str,
        data: Dict[str, Any] | str,
        *,
        params: Dict[str, Any] | None = None,
    ) -> str:
        """POST to an endpoint and return response text."""
        return self._http_request_text("POST", endpoint, params=params, data=data)

    def health_check(self) -> bool:
        """
        Check if the GhidraMCP server is available.

        Returns:
            True if the server is available, False otherwise
        """
        try:
            response = self._http_get_lines("methods", {"offset": 0, "limit": 1})
            return bool(response) and not response[0].startswith(("Error", "Request failed"))
        except Exception as e:
            logger.error(f"GhidraMCP server health check failed: {str(e)}")
            return False

    def check_health(self) -> bool:
        """
        Check if the GhidraMCP server is reachable and responding.

        Returns:
            True if GhidraMCP is healthy, False otherwise
        """
        try:
            response = self._http_get_lines("methods", {"offset": 0, "limit": 1})
            return bool(response) and not response[0].startswith(("Error", "Request failed"))
        except Exception as e:
            logger.error(f"GhidraMCP health check failed: {str(e)}")
            return False

    # =========================================================================
    # Instance Management
    #
    # Multi-instance discovery and management architecture adapted from:
    # GhydraMCP - https://github.com/starsong/GhydraMCP
    # Authors: starsong and contributors
    #
    # This allows the AI to discover and interact with multiple Ghidra instances
    # simultaneously, each analyzing a different binary on a unique port.
    # =========================================================================

    def instances_list(self) -> str:
        """
        List all active Ghidra instances and auto-discover new ones on localhost.

        Returns:
            Formatted string listing instances and their status
        """
        # Range of ports to scan (standard GhidraMCP ports)
        # Port 8080 is often default, 8192+ are dynamic allocations
        ports_to_scan = [8080, 8081] + list(range(8192, 8200))

        self._discover_instances_internal(ports_to_scan)

        if not self.active_instances:
            return "No active Ghidra instances found. Make sure Ghidra is running with the MCP plugin enabled."

        result = ["=== Active Ghidra Instances ==="]
        for port, info in self.active_instances.items():
            status = "(CURRENT)" if port == self.current_instance_port else ""
            program = info.get("file", "Unknown binary")
            project = info.get("project", "Unknown project")
            result.append(f"• Port {port}: {program} [{project}] {status}")

        result.append("\nUse 'instances_use(port=...)' to switch between instances.")
        return "\n".join(result)

    def instances_discover(self, host: str = "localhost", start_port: int = 8192, end_port: int = 8200) -> str:
        """
        Discover Ghidra instances on a specific host and port range.

        Args:
            host: Hostname to scan (default: localhost)
            start_port: Start of port range
            end_port: End of port range

        Returns:
            Discovery results
        """
        ports = list(range(start_port, end_port + 1))
        # Add common default ports if not in range
        if 8080 not in ports:
            ports = [8080] + ports

        self._discover_instances_internal(ports, host=host)
        return self.instances_list()

    def instances_use(self, port: int) -> str:
        """
        Switch the active Ghidra instance to the specified port.

        Args:
            port: The port number of the instance to use

        Returns:
            Confirmation message
        """
        try:
            port = int(port)
        except ValueError:
            return f"Error: Port must be an integer, got '{port}'"

        if port not in self.active_instances:
            # Try to discover it first just in case
            self._discover_instances_internal([port])

        if port in self.active_instances:
            self.current_instance_port = port
            info = self.active_instances[port]

            # Recache info to be sure
            self._update_instance_info(port)
            info = self.active_instances[port]

            return f"Switched to Ghidra instance on port {port} analyzing '{info.get('file', 'unknown')}'"
        else:
            return f"Error: No Ghidra instance found on port {port}. Use 'instances_list' to see available instances."

    def instances_current(self) -> str:
        """
        Get information about the currently active Ghidra instance.

        Returns:
            Instance information
        """
        if not self.current_instance_port or self.current_instance_port not in self.active_instances:
            if not self.active_instances:
                return "No active instance selected and no instances found."
            # Fallback to first available if none selected but some exist
            default_port = next(iter(self.active_instances))
            self.current_instance_port = default_port
            return f"No instance explicitly selected. Defaulting to port {default_port}.\n" + self.instances_current()

        info = self.active_instances[self.current_instance_port]
        result = [
            f"=== Current Instance: Port {self.current_instance_port} ===",
            f"Binary: {info.get('file', 'Unknown')}",
            f"Project: {info.get('project', 'Unknown')}",
            f"URL: {info.get('url')}",
            f"Plugin Version: {info.get('plugin_version', 'Unknown')}",
        ]
        return "\n".join(result)

    def get_current_program_info(self) -> Dict[str, str]:
        """
        Get structured information about the currently active program.

        Returns:
            Dict containing 'name', 'project', 'port', etc.
        """
        # Ensure we have a valid current instance
        if not self.current_instance_port or self.current_instance_port not in self.active_instances:
            if self.active_instances:
                # Auto-select first available if needed
                self.current_instance_port = next(iter(self.active_instances))
            else:
                return {"name": "Unknown Binary", "project": "Unknown", "error": "No active instance"}

        # Update info to be fresh
        self._update_instance_info(self.current_instance_port)

        info = self.active_instances.get(self.current_instance_port, {})
        return {
            "name": info.get("file", "Unknown Binary"),
            "project": info.get("project", "Unknown Project"),
            "port": str(self.current_instance_port),
            "url": info.get("url", ""),
            "plugin_version": info.get("plugin_version", "Unknown"),
        }

    def _discover_instances_internal(self, ports: List[int], host: str = "localhost") -> int:
        """Internal helper to scan ports and update active_instances."""
        count = 0

        for port in ports:
            url = f"http://{host}:{port}"
            try:
                # Check plugin version endpoint which is standard in GhidraMCP
                resp = self.client.get(f"{url}/plugin-version", timeout=0.2)
                if resp.status_code == 200:
                    self._update_instance_info(port, url)
                    count += 1
            except Exception:
                continue
        return count

    def _update_instance_info(self, port: int, url: str = None):
        """Update information for a specific instance."""
        if not url:
            # If we don't know the URL, assume localhost if it was default
            if port in self.active_instances:
                url = self.active_instances[port]["url"]
            else:
                url = f"http://localhost:{port}"

        info = {"url": url}

        try:
            # Get program info
            resp = self.client.get(f"{url}/program", timeout=1.0)
            if resp.status_code == 200:
                data = resp.json()
                if "result" in data and isinstance(data["result"], dict):
                    res = data["result"]
                    info["file"] = res.get("name", "Unknown")
                    info["program_id"] = res.get("programId", "")

                    # Parse project from programId if possible
                    pid = res.get("programId", "")
                    if ":" in pid:
                        info["project"] = pid.split(":")[0]

                # Check plugin version too
                ver_resp = self.client.get(f"{url}/plugin-version", timeout=1.0)
                if ver_resp.status_code == 200:
                    ver_data = ver_resp.json()
                    if "result" in ver_data and isinstance(ver_data["result"], dict):
                        info["plugin_version"] = ver_data["result"].get("plugin_version", "unknown")
        except Exception:
            pass

        self.active_instances[port] = info

    # ------------------------------------------------------------------
    # HTTP-backed public tool surface
    # ------------------------------------------------------------------

    def list_methods(self, offset: int = 0, limit: int = 100) -> List[str]:
        offset, limit = self._get_offset_limit(offset, limit)
        return self._http_get_lines("methods", {"offset": offset, "limit": limit})

    def list_classes(self, offset: int = 0, limit: int = 100) -> List[str]:
        offset, limit = self._get_offset_limit(offset, limit)
        return self._http_get_lines("classes", {"offset": offset, "limit": limit})

    def decompile_function(self, name: str, offset: int = 0, limit: int = 500) -> str:
        offset, limit = self._get_offset_limit(offset, limit, default_limit=500)
        return self._http_post_text(
            "decompile",
            name,
            params={"offset": offset, "limit": limit},
        )

    def rename_function(self, old_name: str, new_name: str) -> str:
        return self._http_post_text("renameFunction", {"oldName": old_name, "newName": new_name})

    def rename_data(self, address: str, new_name: str) -> str:
        return self._http_post_text("renameData", {"address": address, "newName": new_name})

    def list_segments(self, offset: int = 0, limit: int = 100) -> List[str]:
        offset, limit = self._get_offset_limit(offset, limit)
        if limit > self.MAX_SAFE_LIMIT:
            logger.warning(
                self.LIMIT_WARNING_TEMPLATE.format(
                    method="list_segments",
                    limit=limit,
                    max_safe=self.MAX_SAFE_LIMIT,
                )
            )
            limit = self.MAX_SAFE_LIMIT
        return self._http_get_lines("segments", {"offset": offset, "limit": limit})

    def list_imports(self, offset: int = 0, limit: int = 100) -> List[str]:
        offset, limit = self._get_offset_limit(offset, limit)
        if limit > self.MAX_SAFE_LIMIT:
            logger.warning(
                self.LIMIT_WARNING_TEMPLATE.format(
                    method="list_imports",
                    limit=limit,
                    max_safe=self.MAX_SAFE_LIMIT,
                )
            )
            limit = self.MAX_SAFE_LIMIT
        return self._http_get_lines("imports", {"offset": offset, "limit": limit})

    def list_exports(self, offset: int = 0, limit: int = 100) -> List[str]:
        offset, limit = self._get_offset_limit(offset, limit)
        if limit > self.MAX_SAFE_LIMIT:
            logger.warning(
                self.LIMIT_WARNING_TEMPLATE.format(
                    method="list_exports",
                    limit=limit,
                    max_safe=self.MAX_SAFE_LIMIT,
                )
            )
            limit = self.MAX_SAFE_LIMIT
        return self._http_get_lines("exports", {"offset": offset, "limit": limit})

    def list_namespaces(self, offset: int = 0, limit: int = 100) -> List[str]:
        offset, limit = self._get_offset_limit(offset, limit)
        return self._http_get_lines("namespaces", {"offset": offset, "limit": limit})

    def list_data_items(self, offset: int = 0, limit: int = 100) -> List[str]:
        offset, limit = self._get_offset_limit(offset, limit)
        if limit > self.MAX_SAFE_LIMIT:
            logger.warning(
                self.LIMIT_WARNING_TEMPLATE.format(
                    method="list_data_items",
                    limit=limit,
                    max_safe=self.MAX_SAFE_LIMIT,
                )
            )
            limit = self.MAX_SAFE_LIMIT
        return self._http_get_lines("data", {"offset": offset, "limit": limit})

    def list_strings(self, offset: int = 0, limit: int = 100, filter: str | None = None) -> List[str]:
        offset = self._coerce_int_param(offset, param_name="offset", default=0)
        limit = self._coerce_int_param(limit, param_name="limit", default=100)

        max_limit = 50 if filter else self.MAX_SAFE_LIMIT
        if limit > max_limit:
            logger.warning(
                self.LIMIT_WARNING_TEMPLATE.format(method="list_strings", limit=limit, max_safe=max_limit)
                + (" Consider using 'filter' parameter for targeted searches." if not filter else "")
            )
            limit = max_limit

        params: Dict[str, Any] = {"offset": offset, "limit": limit}
        if filter:
            params["filter"] = filter
        return self._http_get_lines("strings", params)

    def search_functions_by_name(self, query: str, offset: int = 0, limit: int = 100) -> List[str]:
        if not query:
            return ["Error: query string is required"]
        offset, limit = self._get_offset_limit(offset, limit)
        return self._http_get_lines(
            "searchFunctions",
            {"query": query, "offset": offset, "limit": limit},
        )

    def rename_variable(self, function_name: str, old_name: str, new_name: str) -> str:
        return self._http_post_text(
            "renameVariable",
            {"functionName": function_name, "oldName": old_name, "newName": new_name},
        )

    def get_function_by_address(self, address: str) -> str:
        return "\n".join(self._http_get_lines("get_function_by_address", {"address": address}))

    def get_current_address(self) -> str:
        return "\n".join(self._http_get_lines("get_current_address"))

    def get_current_function(self) -> str:
        return "\n".join(self._http_get_lines("get_current_function"))

    def list_functions(self, offset: int = 0, limit: int = 100) -> List[str]:
        offset, limit = self._get_offset_limit(offset, limit)
        max_functions_limit = 10000
        if limit > max_functions_limit:
            logger.warning(
                "list_functions limit %s exceeds MAX_FUNCTIONS_LIMIT=%s. Capping to MAX_FUNCTIONS_LIMIT.",
                limit,
                max_functions_limit,
            )
            limit = max_functions_limit

        return self._http_get_lines("list_functions", {"offset": offset, "limit": limit})

    def decompile_function_by_address(self, address: str, offset: int = 0, limit: int = 500) -> str:
        offset, limit = self._get_offset_limit(offset, limit, default_limit=500)
        return "\n".join(
            self._http_get_lines(
                "decompile_function",
                {"address": address, "offset": offset, "limit": limit},
            )
        )

    def disassemble_function(self, address: str) -> List[str]:
        return self._http_get_lines("disassemble_function", {"address": address})

    def set_decompiler_comment(self, address: str, comment: str) -> str:
        return self._http_post_text("set_decompiler_comment", {"address": address, "comment": comment})

    def set_disassembly_comment(self, address: str, comment: str) -> str:
        return self._http_post_text("set_disassembly_comment", {"address": address, "comment": comment})

    def rename_function_by_address(self, function_address: str, new_name: str) -> str:
        return self._http_post_text(
            "rename_function_by_address",
            {"function_address": function_address, "new_name": new_name},
        )

    def set_function_prototype(self, function_address: str, prototype: str) -> str:
        return self._http_post_text(
            "set_function_prototype",
            {"function_address": function_address, "prototype": prototype},
        )

    def set_local_variable_type(self, function_address: str, variable_name: str, new_type: str) -> str:
        return self._http_post_text(
            "set_local_variable_type",
            {
                "function_address": function_address,
                "variable_name": variable_name,
                "new_type": new_type,
            },
        )

    def get_xrefs_to(self, address: str, offset: int = 0, limit: int = 100):
        offset, limit = self._get_offset_limit(offset, limit)
        norm_addr = self._normalize_addr(address)
        return self._http_get_lines("xrefs_to", {"address": norm_addr, "offset": offset, "limit": limit})

    def get_xrefs_from(self, address: str, offset: int = 0, limit: int = 100):
        offset, limit = self._get_offset_limit(offset, limit)
        norm_addr = self._normalize_addr(address)
        return self._http_get_lines("xrefs_from", {"address": norm_addr, "offset": offset, "limit": limit})

    def get_function_xrefs(self, name: str, offset: int = 0, limit: int = 100):
        if name.upper().startswith("0X") or name[:3].upper() == "FUN" or name.isalnum() and len(name) >= 6:
            return self.get_xrefs_to(name, offset=offset, limit=limit)

        offset, limit = self._get_offset_limit(offset, limit)
        return self._http_get_lines("function_xrefs", {"name": name, "offset": offset, "limit": limit})

    def read_bytes(self, address: str, length: int = 16, format: str = "hex") -> str:
        norm_addr = self._normalize_addr(address)
        return "\n".join(
            self._http_get_lines(
                "read_bytes",
                {"address": norm_addr, "length": length, "format": format},
            )
        )


class PyGhidraClient(AbstractGhidraClient):
    """pyGhidra-backed implementation of the Ghidra client.

    This backend talks directly to the current Ghidra Program through
    pyGhidra and overrides the same public tool methods exposed by the
    HTTP-backed client. Shared backend-agnostic behavior remains in
    :class:`AbstractGhidraClient`.
    """

    def __init__(self, config: GhidraMCPConfig, ollama_client=None):
        super().__init__(config=config, ollama_client=ollama_client)

        # Keep a subset of the HTTP client attributes for compatibility with
        # callers that may introspect them.
        self.api_version = None
        self.active_instances = {}
        self.current_instance_port = None
        self.default_port = None
        self._request_lock = threading.Lock()

        # pyGhidra-specific state
        self._pyghidra = None
        self._project = None
        self._program = None  # Primary/default program for compatibility
        self._current_program_key = None
        self._program_entries: List[_PyGhidraProgramEntry] = []
        self._program_entries_by_key: Dict[str, _PyGhidraProgramEntry] = {}
        self._decomp = None  # Lazy-initialized decompiler interface
        self._decomp_monitor = None
        self._decomp_program_key = None
        self._project_ctx = None
        self._DefinedStringIterator = None
        self._defined_string_iterator_warning_emitted = False
        self._use_defined_string_iterator = True

        self._init_pyghidra()

    def close(self) -> None:
        """Release pyGhidra project/program resources if possible.

        This is a best-effort cleanup method; failures are logged but do not
        raise. It is safe to call multiple times.
        """
        try:
            if self._decomp is not None:
                try:
                    self._decomp.dispose()
                except Exception:
                    logger.exception("Error disposing pyGhidra decompiler interface")
                finally:
                    self._decomp = None
                    self._decomp_program_key = None
                    self._decomp_monitor = None

            for entry in reversed(getattr(self, "_program_entries", [])):
                if entry.consumer is None:
                    continue
                try:
                    entry.program.release(entry.consumer)
                except Exception:
                    logger.exception("Error releasing pyGhidra program consumer")

            for entry in reversed(getattr(self, "_program_entries", [])):
                if entry.program_ctx is None:
                    continue
                try:
                    entry.program_ctx.__exit__(None, None, None)  # type: ignore[call-arg]
                except Exception:
                    logger.exception("Error closing pyGhidra program context")

            # Close the project context manager if we created one
            if getattr(self, "_project_ctx", None) is not None:
                try:
                    self._project_ctx.__exit__(None, None, None)  # type: ignore[call-arg]
                except Exception:
                    logger.exception("Error closing pyGhidra project context")
                finally:
                    self._project_ctx = None  # type: ignore[attr-defined]

            for entry in reversed(getattr(self, "_program_entries", [])):
                if entry.open_program_cm is None:
                    continue
                try:
                    entry.open_program_cm.__exit__(None, None, None)  # type: ignore[call-arg]
                except Exception:
                    logger.exception("Error closing pyGhidra open_program context")

            self._program_entries = []
            self._current_program_key = None
            self._program_entries_by_key = {}
            self.active_instances = {}
            self.current_instance_port = None
            self.default_port = None
            self._program = None
            self._project = None
        except Exception:
            logger.exception("Unexpected error while closing PyGhidraClient")

    # ------------------------------------------------------------------
    # pyGhidra bootstrap
    # ------------------------------------------------------------------

    def _init_pyghidra(self) -> None:
        """Initialize pyGhidra and open the configured project/program.

        This is a best-effort generic bootstrap. Many setups will want to
        customize this logic; it is deliberately simple so it is easy to
        adjust.
        """

        # Ensure GHIDRA_INSTALL_DIR from .env is normalized for this runtime.
        # The main entrypoint already loads .env via python-dotenv, so the
        # value will be in os.environ if configured there. When running on
        # Linux/WSL with a Windows-style path (e.g. "C:\\Program Files\\ghidra"),
        # convert it to a /mnt/c/... path so pyGhidra can find the install.
        import os
        import re

        install_dir = os.environ.get("GHIDRA_INSTALL_DIR")
        if install_dir and os.name == "posix":
            # Detect simple Windows path pattern like "C:\\..." or "C:/..."
            if re.match(r"^[A-Za-z]:[\\/].*", install_dir):
                drive = install_dir[0].lower()
                rest = install_dir[2:].lstrip("\\/")
                translated = f"/mnt/{drive}/{rest.replace('\\', '/')}"
                logger.info(
                    "Normalized GHIDRA_INSTALL_DIR from '%s' to '%s' for Linux runtime",
                    install_dir,
                    translated,
                )
                install_dir = translated
                os.environ["GHIDRA_INSTALL_DIR"] = translated

        try:
            import pyghidra  # type: ignore[import]
        except ImportError as exc:  # pragma: no cover - environment-specific
            raise RuntimeError(
                "PyGhidra backend selected but the 'pyghidra' package is not installed. "
                "Install it (e.g. 'pip install pyghidra') and ensure Ghidra is configured."
            ) from exc

        # Start the JVM / Ghidra once via pyGhidra. This relies on the
        # GHIDRA_INSTALL_DIR environment variable, which is expected to be set
        # in the project's .env and already loaded into os.environ by
        # python-dotenv at process startup.
        try:  # pragma: no cover - environment-specific
            started_fn = getattr(pyghidra, "started", None)
            start_fn = getattr(pyghidra, "start", None)
            if callable(started_fn) and callable(start_fn):
                if not started_fn():
                    if install_dir:
                        from pathlib import Path

                        start_fn(install_dir=Path(install_dir))
                    else:
                        start_fn()
            elif callable(start_fn):
                # Older/alternate API: best-effort start if not clearly tracked
                if install_dir:
                    from pathlib import Path

                    start_fn(install_dir=Path(install_dir))
                else:
                    start_fn()
        except Exception as exc:
            raise RuntimeError(f"Failed to start pyGhidra with GHIDRA_INSTALL_DIR={install_dir!r}: {exc}") from exc

        # Don't import 'ghidra' here. pyGhidra is responsible for starting the
        # JVM and setting up the classpath when we open a project/program. The
        # various helpers that need Ghidra APIs (e.g. _ensure_decompiler) will
        # import from ghidra.* after that initialization has occurred.

        self._pyghidra = pyghidra

        # Prefer Ghidra's native string iterator to avoid the Python/JVM
        # boundary cost of repeatedly calling DataType helpers in a Python loop.
        try:
            from ghidra.program.util import DefinedStringIterator
        except Exception as exc:
            self._warn_slow_string_path(
                "DefinedStringIterator unavailable in this pyGhidra environment; "
                "list_strings() will use the slower listing scan across the "
                "Python/JVM boundary and performance may suffer",
                exc,
            )
            DefinedStringIterator = None
        self._DefinedStringIterator = DefinedStringIterator

        binary_path = getattr(self.config, "pyghidra_binary", None)
        project_path = getattr(self.config, "pyghidra_project_path", None)
        program_name = getattr(self.config, "pyghidra_program", None)

        # If a binary path is provided and no explicit project is configured,
        # use pyghidra.open_program() to create a new project+program for this
        # binary. The project location defaults to a "pyghidra_projects"
        # directory under the current working directory, or can be overridden
        # via config.ghidra.pyghidra_projects_dir / PYGHIDRA_PROJECTS_DIR.
        if binary_path and not project_path:
            from pathlib import Path
            import os

            bpath = Path(binary_path)
            if not bpath.is_file():
                raise RuntimeError(f"PyGhidraClient: pyghidra_binary '{binary_path}' does not exist or is not a file.")

            # Determine base directory for pyGhidra projects
            projects_dir_cfg = getattr(self.config, "pyghidra_projects_dir", None)
            if projects_dir_cfg:
                projects_dir = Path(projects_dir_cfg)
            else:
                projects_dir = Path("pyghidra_projects")

            try:
                projects_dir.mkdir(parents=True, exist_ok=True)
            except Exception as exc:
                raise RuntimeError(f"Failed to create pyGhidra projects directory '{projects_dir}': {exc}") from exc

            project_location = str(projects_dir)
            project_name = bpath.name  # e.g. "vivado.exe"

            try:  # pragma: no cover - environment-specific
                open_prog_cm = self._pyghidra.open_program(
                    str(bpath),
                    project_location=project_location,
                    project_name=project_name,
                )
            except Exception as exc:
                raise RuntimeError(
                    f"Failed to open binary '{binary_path}' via pyghidra.open_program: {exc}. "
                    "Please verify the path and that Ghidra/pyGhidra support this binary type."
                ) from exc

            # Keep the context manager alive so the FlatProgramAPI/program
            # remain valid for the lifetime of this client.
            flat_api = open_prog_cm.__enter__()

            try:
                program = flat_api.getCurrentProgram()
            except Exception as exc:
                raise RuntimeError(
                    f"pyghidra.open_program returned an unexpected object: {exc}. "
                    "Expected FlatProgramAPI with getCurrentProgram()."
                ) from exc

            self._register_open_program(program, open_program_cm=open_prog_cm)

            # Best-effort project discovery for logging; not strictly required
            try:
                domain_file = program.getDomainFile()
                if domain_file is not None:
                    self._project = domain_file.getProject()
                    project_path = str(domain_file.getProject().getProjectLocator())
            except Exception:
                self._project = None

            logger.info(
                "Initialized PyGhidraClient from binary '%s' in project dir '%s'",
                binary_path,
                projects_dir,
            )
            return

        if not project_path:
            raise RuntimeError(
                "PyGhidraClient requires config.ghidra.pyghidra_project_path (or --pyghidra-project) "
                "to be set when backend='pyghidra', or config.ghidra.pyghidra_binary/--pyghidra-binary "
                "to be provided."
            )

        # First open the project. Different pyghidra versions use different
        # signatures for open_project(), so we try the simplest form first and
        # fall back to a (directory, name) variant if needed.
        try:
            try:
                # Common newer signature: open_project(path_or_gpr)
                project_ctx = self._pyghidra.open_project(project_path)
            except TypeError:
                # Some pyghidra builds expect open_project(project_dir, name)
                from pathlib import Path

                p = Path(project_path)
                project_dir = str(p.parent) if str(p.parent) else str(p)
                project_name = p.stem
                project_ctx = self._pyghidra.open_project(project_dir, project_name)

            # Keep the project context manager alive so the project stays
            # open for the lifetime of this client.
            self._project_ctx = project_ctx
            self._project = project_ctx.__enter__()
        except Exception as exc:  # pragma: no cover - environment-specific
            raise RuntimeError(
                f"Failed to open pyGhidra project at '{project_path}': {exc}. "
                "Please adjust PyGhidraClient._init_pyghidra to your environment."
            ) from exc

        # Discover available programs in the project so we can either validate
        # the requested program or auto-select when only one exists. Prefer the
        # modern pyghidra.walk_programs / program_context API when available.

        discovered: List[Tuple[str, str]] = []  # (name, project_path)

        walk_programs = getattr(self._pyghidra, "walk_programs", None)
        program_context = getattr(self._pyghidra, "program_context", None)
        consume_program = getattr(self._pyghidra, "consume_program", None)

        if callable(walk_programs):
            try:

                def _collect(df, prog):
                    try:
                        name = df.getName()
                        path = df.getPathname()  # e.g. "/MyProgram" or "/folder/MyProgram"
                        discovered.append((str(name), str(path)))
                    except Exception:
                        return

                walk_programs(self._project, _collect, start="/")
            except Exception:
                discovered = []
        else:
            # Fallback: introspect the project object via the Ghidra API
            try:
                project_data = self._project.getProjectData()
                root = project_data.getRootFolder()
                stack = [root]
                while stack:
                    folder = stack.pop()
                    try:
                        for df in folder.getFiles():
                            try:
                                if hasattr(df, "isProgram") and df.isProgram():
                                    name = df.getName()
                                    path = df.getPathname()
                                    discovered.append((str(name), str(path)))
                            except Exception:
                                continue
                        for sub in folder.getFolders():
                            stack.append(sub)
                    except Exception:
                        continue
            except Exception:
                discovered = []

        requested_programs = self._parse_requested_programs(program_name)
        selected_paths = self._select_project_program_paths(discovered, requested_programs, project_path)

        if not requested_programs and len(selected_paths) == 1 and len(discovered) == 1:
            logger.info(
                "pyGhidra: auto-selected sole program '%s' at '%s' from project '%s'",
                discovered[0][0],
                selected_paths[0],
                project_path,
            )
        elif not requested_programs and len(selected_paths) > 1:
            logger.info(
                "pyGhidra: no explicit program selection provided; opening all %d discovered programs from project '%s'",
                len(selected_paths),
                project_path,
            )

        selected_path = "<unknown>"
        try:
            for selected_path in selected_paths:
                if callable(consume_program):
                    # Preferred modern API: keep programs alive with explicit
                    # consumers; caller is responsible for releasing when done.
                    program, consumer = consume_program(self._project, selected_path)
                    self._register_open_program(program, selected_path=selected_path, consumer=consumer)
                elif callable(program_context):
                    # Fallback: keep the context manager alive so the program
                    # isn't closed prematurely.
                    program_ctx = program_context(self._project, selected_path)
                    program = program_ctx.__enter__()
                    self._register_open_program(program, selected_path=selected_path, program_ctx=program_ctx)
                else:
                    # Legacy fallback: rely on project.open_program(path)
                    if hasattr(self._project, "open_program"):
                        program_ctx = self._project.open_program(selected_path)
                        program = program_ctx.__enter__()
                        self._register_open_program(program, selected_path=selected_path, program_ctx=program_ctx)
                    else:
                        raise RuntimeError(
                            "pyGhidra does not provide consume_program() or program_context(), "
                            "and the project object has no open_program() method."
                        )

        except Exception as exc:  # pragma: no cover - environment-specific
            self.close()
            raise RuntimeError(
                f"Failed to initialize pyGhidra program '{selected_path}' from project "
                f"'{project_path}': {exc}. Please verify the program path/name and that "
                "the project contains this program."
            ) from exc

        logger.info(
            "Initialized PyGhidraClient with project '%s', program(s) %s",
            project_path,
            ", ".join(selected_paths),
        )

    # ------------------------------------------------------------------
    # Health checks (override HTTP-focused defaults)
    # ------------------------------------------------------------------

    def health_check(self) -> bool:
        """Check that the pyGhidra backend is usable.

        For the in-process backend, "healthy" means we have an open Program
        and the decompiler can be initialized successfully.
        """

        if not self._program_entries:
            logger.error("pyGhidra health_check failed: no program is open")
            return False

        try:
            for _program_key, program, _info in self._iter_program_entries():
                program.getFunctionManager()
            self._ensure_decompiler()
            return True
        except Exception as exc:  # pragma: no cover - environment-specific
            logger.error("pyGhidra health_check failed: %s", exc)
            return False

    def check_health(self) -> bool:
        """UI/tests entry point for health checks.

        Delegate to :meth:`health_check` so both methods share the same
        semantics in the pyGhidra backend.
        """

        return self.health_check()

    def instances_list(self) -> str:
        """List open pyGhidra programs and indicate the active selection."""
        self._refresh_program_instance_index()

        if not self.active_instances:
            return "No pyGhidra program is open"

        result = ["=== Open pyGhidra Programs ==="]
        for slot, info in self.active_instances.items():
            status = "(CURRENT)" if slot == self.current_instance_port else ""
            result.append(
                f"• Program {slot}: {info.get('file', 'Unknown binary')} "
                f"[{info.get('project', 'Unknown project')}] {status} -> {info.get('program_path', 'Unknown')}"
            )

        if len(self.active_instances) > 1:
            result.append("\nUse 'instances_use(port=...)' to switch between open pyGhidra programs by number.")
            result.append("Use '<program>::<function-or-address>' to target a specific program directly.")
        return "\n".join(result)

    def instances_discover(self, host: str = "localhost", start_port: int = 8192, end_port: int = 8200) -> str:
        """pyGhidra runs in-process; discovery is equivalent to listing open programs."""
        return self.instances_list()

    def instances_use(self, port: int) -> str:
        """Switch the active pyGhidra program using its numbered slot."""
        self._refresh_program_instance_index()

        try:
            slot = int(port)
        except ValueError:
            return f"Error: Program selector must be an integer, got '{port}'"

        info = self.active_instances.get(slot)
        if info is None:
            if not self.active_instances:
                return "Error: No pyGhidra program is open"
            return (
                f"Error: No open pyGhidra program found in slot {slot}. "
                "Use 'instances_list()' to see available program numbers."
            )

        program_key = info.get("program_key")
        if not program_key:
            return f"Error: Internal pyGhidra state is missing the program key for slot {slot}"

        self._set_active_program(program_key)
        return (
            f"Switched to pyGhidra program {slot} analyzing "
            f"'{info.get('file', 'unknown')}' at {info.get('program_path', 'Unknown')}"
        )

    def instances_current(self) -> str:
        """Describe the currently active pyGhidra program."""
        self._refresh_program_instance_index()

        if not self._program_entries or self.current_instance_port is None:
            return "No pyGhidra program is open"

        info = self.active_instances[self.current_instance_port]
        lines = [
            f"=== Current Instance: pyGhidra Program {self.current_instance_port} ===",
            f"Binary: {info.get('file', 'Unknown Binary')}",
            f"Project: {info.get('project', 'Unknown Project')}",
            f"Program Path: {info.get('program_path', 'Unknown')}",
        ]
        if len(self.active_instances) > 1:
            lines.append(f"Open Programs: {len(self.active_instances)}")
            lines.append("Use 'instances_list()' to see all open programs.")
        return "\n".join(lines)

    def get_current_program_info(self) -> Dict[str, str]:
        """Return structured information about the currently active program."""
        if not self._program_entries:
            return {
                "name": "Unknown Binary",
                "project": "Unknown Project",
                "program_path": "",
                "error": "No pyGhidra program is open",
                "backend": "pyghidra",
            }

        self._refresh_program_instance_index()
        active_entry = self._active_program_entry()
        if active_entry is None:
            return {
                "name": "Unknown Binary",
                "project": "Unknown Project",
                "program_path": "",
                "error": "No pyGhidra program is open",
                "backend": "pyghidra",
            }

        info = active_entry.info()
        info["backend"] = "pyghidra"
        info["active_program"] = self._program_label(active_entry.key)
        info["open_program_count"] = str(len(self._program_entries))
        if self.current_instance_port is not None:
            info["program_slot"] = str(self.current_instance_port)
        info["open_programs"] = ", ".join(
            f"{index}. {self._program_label(entry.key)} ({entry.program_path or 'Unknown'})"
            for index, entry in enumerate(self._program_entries, start=1)
        )

        return info

    def get_command_context(self, command_name: str, params: Dict[str, Any]) -> Dict[str, str]:
        """Return the pyGhidra program context a command will operate on."""
        entry = self._active_program_entry()

        selector_keys = ("name", "address", "function_name", "function_address", "old_name")
        for key in selector_keys:
            value = params.get(key)
            if not isinstance(value, str) or "::" not in value or len(self._program_entries) <= 1:
                continue
            selector, _remainder = value.split("::", 1)
            program_key = self._resolve_program_selector(selector)
            if program_key is not None:
                entry = self._program_entry(program_key)
                break

        if command_name == "instances_use":
            try:
                slot = int(params.get("port"))
            except Exception:
                slot = None
            if slot is not None:
                self._refresh_program_instance_index()
                target = self.active_instances.get(slot, {})
                program_key = target.get("program_key")
                if program_key:
                    entry = self._program_entry(program_key)

        if entry is None:
            return {
                "name": "Unknown Binary",
                "project": "Unknown Project",
                "program_path": "",
                "backend": "pyghidra",
            }

        info = entry.info()
        info["backend"] = "pyghidra"
        info["program_key"] = entry.key
        slot = self._program_slot(entry.key)
        if slot is not None:
            info["program_slot"] = str(slot)
        info["active_program"] = self._program_label(entry.key)
        return info

    # _init_pyghidra_auto removed: pyGhidra backend now always operates on an
    # explicitly specified project, and either an explicit program selection or
    # all discovered project programs by default.

    # ------------------------------------------------------------------
    # Direct pyGhidra-backed public methods and internal helpers
    # ------------------------------------------------------------------

    def _parse_requested_programs(self, requested_programs: str | None) -> List[str]:
        """Parse comma-separated project program selectors."""
        if requested_programs is None:
            return []

        requested: List[str] = []
        seen = set()
        for raw_selector in requested_programs.split(","):
            selector = raw_selector.strip()
            if not selector or selector in seen:
                continue
            requested.append(selector)
            seen.add(selector)
        return requested

    @staticmethod
    def _format_available_programs(discovered: List[Tuple[str, str]]) -> str:
        return ", ".join(f"{name} ({path})" for name, path in discovered) or "<none>"

    def _select_project_program_paths(
        self,
        discovered: List[Tuple[str, str]],
        requested_programs: List[str],
        project_path: str,
    ) -> List[str]:
        """Resolve requested project program selectors to concrete project paths."""
        if not requested_programs:
            if discovered:
                return [path for _name, path in discovered]
            raise RuntimeError(
                "PyGhidra project appears to contain no programs, or they could not be "
                "discovered automatically. Please import a program into the project."
            )

        selected_paths: List[str] = []
        seen = set()
        pretty = self._format_available_programs(discovered)

        for requested_program in requested_programs:
            if requested_program.startswith("/"):
                if discovered and not any(path == requested_program for _, path in discovered):
                    raise RuntimeError(
                        f"PyGhidra could not find program path '{requested_program}' in project "
                        f"'{project_path}'. Available programs: {pretty}"
                    )
                resolved_path = requested_program
            else:
                matches = [path for name, path in discovered if name == requested_program]
                if len(matches) == 1:
                    resolved_path = matches[0]
                elif len(matches) > 1:
                    raise RuntimeError(
                        f"PyGhidra found multiple programs named '{requested_program}' in project "
                        f"'{project_path}'. Please use full project paths via --pyghidra-program. "
                        f"Matching paths: {', '.join(matches)}"
                    )
                else:
                    raise RuntimeError(
                        f"PyGhidra could not find program named '{requested_program}' in project "
                        f"'{project_path}'. Available programs: {pretty}"
                    )

            if resolved_path not in seen:
                selected_paths.append(resolved_path)
                seen.add(resolved_path)

        return selected_paths

    def _register_open_program(
        self,
        program,
        *,
        selected_path: str | None = None,
        consumer=None,
        program_ctx=None,
        open_program_cm=None,
    ) -> str:
        for entry in self._program_entries:
            if entry.program is program:
                return entry.key

        entry = _PyGhidraProgramEntry.from_program(
            program,
            selected_path=selected_path,
            project=self._project,
            existing_keys=set(self._program_entries_by_key),
            slot=len(self._program_entries) + 1,
            consumer=consumer,
            program_ctx=program_ctx,
            open_program_cm=open_program_cm,
        )
        self._program_entries.append(entry)
        self._program_entries_by_key[entry.key] = entry

        if self._current_program_key is None:
            self._current_program_key = entry.key
        if self._program is None:
            self._program = program
        self._refresh_program_instance_index()

        return entry.key

    def _active_program_entry(self) -> Optional[_PyGhidraProgramEntry]:
        if self._current_program_key is not None:
            entry = self._program_entries_by_key.get(self._current_program_key)
            if entry is not None:
                return entry
        if not self._program_entries:
            return None
        return self._program_entries[0]

    def _program_entry(self, program_key: str | None = None) -> _PyGhidraProgramEntry:
        if program_key is None:
            entry = self._active_program_entry()
            if entry is None:
                raise RuntimeError("pyGhidra program is not initialized")
            return entry

        entry = self._program_entries_by_key.get(program_key)
        if entry is None:
            raise RuntimeError(f"pyGhidra program '{program_key}' is not initialized")
        return entry

    def _refresh_program_instance_index(self) -> None:
        self.active_instances = {}
        active_slot = None

        for slot, entry in enumerate(self._program_entries, start=1):
            self.active_instances[slot] = entry.instance_info()
            if entry.key == self._current_program_key:
                active_slot = slot

        if not self._program_entries:
            self._current_program_key = None
            self.current_instance_port = None
            self.default_port = None
            self._program = None
            return

        if active_slot is None:
            first_entry = self._program_entries[0]
            self._current_program_key = first_entry.key
            self._program = first_entry.program
            active_slot = 1

        self.default_port = 1
        self.current_instance_port = active_slot
        self._program = self._program_entries[active_slot - 1].program

    def _set_active_program(self, program_key: str) -> None:
        entry = self._program_entry(program_key)
        self._current_program_key = entry.key
        self._program = entry.program
        self._refresh_program_instance_index()

    def _program_slot(self, program_key: str) -> Optional[int]:
        for slot, entry in enumerate(self._program_entries, start=1):
            if entry.key == program_key:
                return slot
        return None

    def _iter_program_entries(self):
        for entry in self._program_entries:
            yield entry.key, entry.program, entry.info()

    def _program_label(self, program_key: str) -> str:
        entry = self._program_entry(program_key)
        duplicate_name = sum(1 for candidate in self._program_entries if candidate.name == entry.name) > 1
        return entry.label(duplicate_name=duplicate_name)

    def _resolve_program_selector(self, selector: str) -> Optional[str]:
        selector = selector.strip()
        if not selector:
            return None

        selector_lower = selector.lower()
        matches: List[str] = []
        for entry in self._program_entries:
            candidates = {entry.key.lower()}
            if entry.program_path:
                candidates.add(entry.program_path.lower())
            if entry.name:
                candidates.add(entry.name.lower())
            if selector_lower in candidates:
                matches.append(entry.key)

        if len(matches) > 1:
            raise RuntimeError(
                f"Program selector '{selector}' is ambiguous. Open programs: "
                f"{', '.join(self._program_entry(key).selector() for key in matches)}"
            )
        return matches[0] if matches else None

    def _split_program_qualified_identifier(self, value: str) -> Tuple[Optional[str], str]:
        if not value or "::" not in value or len(self._program_entries) <= 1:
            return None, value

        selector, remainder = value.split("::", 1)
        program_key = self._resolve_program_selector(selector)
        if program_key is None:
            return None, value

        remainder = remainder.strip()
        if not remainder:
            raise RuntimeError(f"Missing function or address after program selector '{selector.strip()}'.")
        return program_key, remainder

    def _resolve_function(self, identifier: str):
        program_key, function_name = self._split_program_qualified_identifier(identifier)
        function_name = function_name.strip()
        if not function_name:
            raise RuntimeError("Function name is required")

        if program_key is not None:
            program = self._require_program(program_key)
            func = self._find_function_by_name(function_name, program=program)
            if func is None:
                raise RuntimeError(
                    f"Function '{function_name}' not found in program '{self._program_label(program_key)}'"
                )
            return program_key, program, self._program_entry(program_key).info(), func, function_name

        current_entry = self._active_program_entry()
        current_key = current_entry.key if current_entry is not None else None
        if current_entry is not None:
            current_program = current_entry.program
            current_func = self._find_function_by_name(function_name, program=current_program)
            if current_func is not None:
                return current_key, current_program, current_entry.info(), current_func, function_name

        matches = []
        for key, program, info in self._iter_program_entries():
            if key == current_key:
                continue
            func = self._find_function_by_name(function_name, program=program)
            if func is not None:
                matches.append((key, program, info, func, function_name))

        if len(matches) == 1:
            return matches[0]
        if not matches:
            raise RuntimeError(f"Function '{function_name}' not found")

        candidates = ", ".join(
            f"{self._program_entry(key).selector()}::{function_name}"
            for key, _program, _info, _func, _name in matches
        )
        raise RuntimeError(
            f"Function '{function_name}' exists in multiple open programs. "
            f"Qualify it as '<program>::{function_name}'. Candidates: {candidates}"
        )

    def _program_contains_address(self, program, addr) -> bool:
        mem = program.getMemory()
        if hasattr(mem, "contains"):
            return bool(mem.contains(addr))
        if hasattr(mem, "getBlock"):
            return mem.getBlock(addr) is not None
        return True

    def _resolve_program_address(self, identifier: str, *, function_lookup: str | None = None):
        program_key, raw_identifier = self._split_program_qualified_identifier(identifier)
        norm_addr = self._normalize_addr(raw_identifier)
        if not norm_addr:
            raise RuntimeError("Address parameter is required")

        if program_key is not None:
            program = self._require_program(program_key)
            addr = self._address_from_hex(norm_addr, program=program)
            return program_key, program, self._program_entry(program_key).info(), addr, norm_addr

        primary_entry = self._active_program_entry()
        primary_program_key = primary_entry.key if primary_entry is not None else None
        if primary_entry is not None:
            program = primary_entry.program
            addr = self._address_from_hex(norm_addr, program=program)
            matches_current = False
            if function_lookup == "at":
                matches_current = program.getFunctionManager().getFunctionAt(addr) is not None
            elif function_lookup == "containing":
                matches_current = self._get_function_for_address(addr, program=program) is not None
            else:
                matches_current = self._program_contains_address(program, addr)

            if matches_current:
                return primary_program_key, program, primary_entry.info(), addr, norm_addr

        candidates = []
        for key, program, info in self._iter_program_entries():
            if key == primary_program_key:
                continue
            try:
                addr = self._address_from_hex(norm_addr, program=program)
                if function_lookup == "at":
                    if program.getFunctionManager().getFunctionAt(addr) is None:
                        continue
                elif function_lookup == "containing":
                    if self._get_function_for_address(addr, program=program) is None:
                        continue
                elif not self._program_contains_address(program, addr):
                    continue
                candidates.append((key, program, info, addr, norm_addr))
            except Exception:
                continue

        if len(candidates) == 1:
            return candidates[0]
        if not candidates:
            raise RuntimeError(
                f"Address '{raw_identifier.strip()}' could not be resolved in any open program. "
                "Use '<program>::<address>' to target a specific binary."
            )

        candidate_text = ", ".join(
            f"{self._program_entry(key).selector()}::{norm_addr}"
            for key, _program, _info, _addr, _norm in candidates
        )
        raise RuntimeError(
            f"Address '{raw_identifier.strip()}' is ambiguous across multiple open programs. "
            f"Qualify it as '<program>::{norm_addr}'. Candidates: {candidate_text}"
        )

    def _collect_program_lines(self, collector) -> List[str]:
        active_entry = self._active_program_entry()
        if active_entry is None:
            return []
        return collector(active_entry.key, active_entry.program) or []

    def _format_program_status(self, message: str, program_key: str) -> str:
        if len(self._program_entries) <= 1:
            return message
        return f"[{self._program_label(program_key)}] {message}"

    def _find_symbol_address(self, name: str, program):
        symbol_table = program.getSymbolTable()
        func = self._find_function_by_name(name, program=program)
        if func is not None:
            return func.getEntryPoint(), "function"

        for sym in symbol_table.getExternalSymbols():
            try:
                if sym.getName() == name:
                    return sym.getAddress(), "external"
            except Exception:
                continue

        try:
            syms = symbol_table.getSymbols(name, None)
        except TypeError:
            syms = symbol_table.getSymbols(name)

        for sym in syms:
            try:
                return sym.getAddress(), sym.getSymbolType().toString().lower()
            except Exception:
                continue

        return None, ""

    def _require_program(self, program_key: str | None = None):
        """Return the default or selected program or raise a stable backend error."""
        entry = self._program_entry(program_key)
        self._program = entry.program
        return entry.program

    def _operation_error(self, operation: str, exc: Exception) -> str:
        """Format backend errors to match the previous pyGhidra surface."""
        if str(exc) == "pyGhidra program is not initialized":
            return f"Error: {exc}"
        logger.error("pyGhidra %s failed: %s", operation, exc)
        return f"Error: pyGhidra {operation} failed: {exc}"

    def _operation_error_lines(self, operation: str, exc: Exception) -> List[str]:
        return [self._operation_error(operation, exc)]

    def _address_from_hex(self, addr_str: str, *, program=None):
        """Convert a hex string (with or without 0x) to a Ghidra Address."""
        program = self._require_program() if program is None else program
        af = program.getAddressFactory()
        s = addr_str.strip()
        if s.lower().startswith("0x"):
            s = s[2:]
        space = af.getDefaultAddressSpace()
        return space.getAddress(int(s, 16))

    def _get_function_for_address(self, addr, *, program=None):
        """Return the function at or containing the given address."""
        program = self._require_program() if program is None else program
        func_mgr = program.getFunctionManager()
        func = func_mgr.getFunctionAt(addr)
        if func is None:
            func = func_mgr.getFunctionContaining(addr)
        return func

    def _find_function_by_name(self, name: str, *, program=None):
        """Best-effort lookup of a Function by name."""
        program = self._require_program() if program is None else program
        func_mgr = program.getFunctionManager()
        st = program.getSymbolTable()

        syms = st.getSymbols(name, None)
        for sym in syms:
            try:
                if sym.getSymbolType().toString() == "FUNCTION":
                    func = func_mgr.getFunctionAt(sym.getAddress())
                    if func is not None:
                        return func
            except Exception:
                continue

        try:
            funcs_iter = func_mgr.getFunctions(True)
            for func in funcs_iter:
                try:
                    if str(func.getName()) == name:
                        return func
                except Exception:
                    continue
        except Exception:
            pass

        m = re.search(r"([0-9a-fA-F]{6,})", name)
        if m:
            try:
                addr = self._address_from_hex(m.group(1), program=program)
                func = func_mgr.getFunctionAt(addr)
                if func is not None:
                    return func
            except Exception:
                pass

        return None

    def _ensure_decompiler(self, *, program=None, program_key: str | None = None):
        """Lazily initialize or switch the Ghidra decompiler interface."""
        if program is None:
            if program_key is not None:
                program = self._require_program(program_key)
            else:
                entry = self._program_entry()
                program = entry.program
                program_key = entry.key

        if program_key is None:
            for entry in self._program_entries:
                if entry.program is program:
                    program_key = entry.key
                    break

        if self._decomp is not None and self._decomp_program_key == program_key:
            return self._decomp

        if self._decomp is not None:
            try:
                self._decomp.dispose()
            except Exception:
                logger.exception("Error disposing pyGhidra decompiler interface while switching programs")
            finally:
                self._decomp = None
                self._decomp_monitor = None
                self._decomp_program_key = None

        try:
            from ghidra.app.decompiler import DecompInterface  # type: ignore[import]
            from ghidra.util.task import ConsoleTaskMonitor  # type: ignore[import]
        except ImportError as exc:  # pragma: no cover - environment-specific
            raise RuntimeError("Ghidra decompiler classes not available in pyGhidra environment") from exc

        decomp = DecompInterface()
        decomp.openProgram(program)
        self._decomp_monitor = ConsoleTaskMonitor()
        self._decomp = decomp
        self._decomp_program_key = program_key
        return decomp

    def _run_program_transaction(self, description: str, action, *, program=None) -> None:
        """Run a program mutation under pyGhidra transaction support when available."""
        program = self._require_program() if program is None else program
        tx = getattr(self._pyghidra, "transaction", None)
        tm_fn = getattr(self._pyghidra, "task_monitor", None)

        if callable(tx):
            monitor = tm_fn() if callable(tm_fn) else None
            with tx(program, description):
                action()
            if monitor is not None:
                try:
                    program.save(description, monitor)
                except Exception:
                    pass
            return

        action()

    def _list_function_lines(self, *, offset: int, limit: int, include_addresses: bool) -> List[str]:
        def _collect(_program_key, program):
            func_mgr = program.getFunctionManager()
            funcs_iter = func_mgr.getFunctions(True)
            lines: List[str] = []
            for func in funcs_iter:
                try:
                    name = str(func.getName())
                    if include_addresses:
                        entry = func.getEntryPoint()
                        addr_text = str(entry) if entry is not None else "0"
                        lines.append(f"{name} at {addr_text}")
                    else:
                        lines.append(name)
                except Exception:
                    continue
            return lines

        return self._render_paginated_lines(self._collect_program_lines(_collect), offset, limit)

    def _warn_slow_string_path(self, message: str, exc: Exception | None = None) -> None:
        """Emit a one-time error when list_strings() must use the slow path."""
        if getattr(self, "_defined_string_iterator_warning_emitted", False):
            return

        self._defined_string_iterator_warning_emitted = True
        if exc is None:
            logger.error("%s", message)
        else:
            logger.error("%s: %s", message, exc)

    def _get_defined_string_iterator(self, program):
        """Return the fast Ghidra string iterator when it is usable."""
        iterator_cls = getattr(self, "_DefinedStringIterator", None)
        if iterator_cls is None:
            self._warn_slow_string_path(
                "DefinedStringIterator unavailable in this pyGhidra environment; "
                "list_strings() is using the slower listing scan across the "
                "Python/JVM boundary and performance may suffer"
            )
            return None

        if not getattr(self, "_use_defined_string_iterator", True):
            return None

        try:
            return iterator_cls.forProgram(program)
        except Exception as exc:
            self._use_defined_string_iterator = False
            self._warn_slow_string_path(
                "DefinedStringIterator failed during list_strings(); falling back "
                "to the slower listing scan across the Python/JVM boundary and "
                "performance may suffer",
                exc,
            )
            return None

    def _iter_string_entries(self, program=None):
        """Yield string-like entries via the slow fallback listing scan."""
        if program is None:
            program = self._require_program()
        listing = program.getListing()
        for data in listing.getDefinedData(True):
            try:
                dt_name = str(data.getDataType().getDisplayName()).lower()
                if "string" in dt_name or "unicode" in dt_name or "char" in dt_name:
                    yield data
            except Exception:
                continue

    @staticmethod
    def _string_entry_value(entry) -> str:
        """Normalize string entry objects from multiple Ghidra iterators."""
        if hasattr(entry, "value"):
            value = entry.value
        elif hasattr(entry, "getValue"):
            value = entry.getValue()
        else:
            value = None
        return "" if value is None else str(value)

    @staticmethod
    def _string_entry_address(entry):
        """Normalize address extraction across iterator entry shapes."""
        if hasattr(entry, "minAddress"):
            return entry.minAddress
        if hasattr(entry, "getMinAddress"):
            return entry.getMinAddress()
        if hasattr(entry, "getAddress"):
            return entry.getAddress()
        return ""

    def list_methods(self, offset: int = 0, limit: int = 100) -> List[str]:
        try:
            offset, limit = self._get_offset_limit(offset, limit)
            return self._list_function_lines(offset=offset, limit=limit, include_addresses=False)
        except Exception as exc:
            return self._operation_error_lines("list_methods", exc)

    def list_classes(self, offset: int = 0, limit: int = 100) -> List[str]:
        return self.list_namespaces(offset=offset, limit=limit)

    def decompile_function(self, name: str, offset: int = 0, limit: int = 500) -> str:
        try:
            offset, limit = self._get_offset_limit(offset, limit, default_limit=500)
            program_key, program, _info, func, function_name = self._resolve_function(name)

            decomp = self._ensure_decompiler(program=program, program_key=program_key)
            results = decomp.decompileFunction(func, 60, self._decomp_monitor)
            df = results.getDecompiledFunction()
            if df is None:
                return f"Error: Decompilation failed for function '{function_name}'"
            return self._render_paginated_text(df.getC(), offset, limit)
        except Exception as exc:
            return self._operation_error("decompile_function(name)", exc)

    def rename_function(self, old_name: str, new_name: str) -> str:
        if not old_name or not new_name:
            return "Error: 'oldName' and 'newName' are required for renameFunction"

        try:
            from ghidra.program.model.symbol import SourceType  # type: ignore[import]

            program_key, program, _info, target_func, function_name = self._resolve_function(old_name)

            desc = f"rename_function: {function_name} -> {new_name}"
            self._run_program_transaction(
                desc,
                lambda: target_func.setName(new_name, SourceType.USER_DEFINED),
                program=program,
            )
            return self._format_program_status(f"Renamed function '{function_name}' to '{new_name}'", program_key)
        except Exception as exc:
            return self._operation_error("renameFunction", exc)

    def rename_data(self, address: str, new_name: str) -> str:
        if not address or not new_name:
            return "Error: 'address' and 'newName' are required for renameData"

        try:
            from ghidra.program.model.symbol import SourceType  # type: ignore[import]

            program_key, program, _info, addr, norm_addr = self._resolve_program_address(address)
            st = program.getSymbolTable()

            def action() -> None:
                sym = st.getPrimarySymbol(addr)
                if sym is not None:
                    sym.setName(new_name, SourceType.USER_DEFINED)
                else:
                    st.createLabel(addr, new_name, None, SourceType.USER_DEFINED)

            desc = f"rename_data: {norm_addr} -> {new_name}"
            self._run_program_transaction(desc, action, program=program)
            return self._format_program_status(f"Renamed data at {norm_addr} to '{new_name}'", program_key)
        except Exception as exc:
            return self._operation_error("renameData", exc)

    def list_segments(self, offset: int = 0, limit: int = 100) -> List[str]:
        try:
            offset, limit = self._get_offset_limit(offset, limit)
            if limit > self.MAX_SAFE_LIMIT:
                logger.warning(
                    self.LIMIT_WARNING_TEMPLATE.format(
                        method="list_segments",
                        limit=limit,
                        max_safe=self.MAX_SAFE_LIMIT,
                    )
                )
                limit = self.MAX_SAFE_LIMIT

            def _collect(_program_key, program):
                mem = program.getMemory()
                lines: List[str] = []
                for blk in mem.getBlocks():
                    try:
                        name = blk.getName()
                        start = blk.getStart().getOffset()
                        end = blk.getEnd().getOffset()
                        lines.append(f"{name}: {start:x} - {end:x}")
                    except Exception:
                        continue
                return lines

            return self._render_paginated_lines(self._collect_program_lines(_collect), offset, limit)
        except Exception as exc:
            return self._operation_error_lines("list_segments", exc)

    def list_imports(self, offset: int = 0, limit: int = 100) -> List[str]:
        try:
            offset, limit = self._get_offset_limit(offset, limit)
            if limit > self.MAX_SAFE_LIMIT:
                logger.warning(
                    self.LIMIT_WARNING_TEMPLATE.format(
                        method="list_imports",
                        limit=limit,
                        max_safe=self.MAX_SAFE_LIMIT,
                    )
                )
                limit = self.MAX_SAFE_LIMIT

            def _collect(_program_key, program):
                st = program.getSymbolTable()
                ref_mgr = program.getReferenceManager()
                func_mgr = program.getFunctionManager()
                lines: List[str] = []
                for sym in st.getExternalSymbols():
                    try:
                        line = f"{sym.getName()} -> {sym.getAddress()}"
                        callers: List[str] = []
                        ref_count = 0
                        for ref in ref_mgr.getReferencesTo(sym.getAddress()):
                            ref_count += 1
                            if ref_count <= 5:
                                from_addr = ref.getFromAddress()
                                caller = func_mgr.getFunctionContaining(from_addr)
                                callers.append(str(caller.getName()) if caller is not None else str(from_addr))

                        if ref_count > 0:
                            line += f" [Refs: {ref_count}]"
                            if callers:
                                line += f" [Callers: {', '.join(callers)}"
                                if ref_count > 5:
                                    line += ", ..."
                                line += "]"

                        lines.append(line)
                    except Exception:
                        continue
                return lines

            return self._render_paginated_lines(self._collect_program_lines(_collect), offset, limit)
        except Exception as exc:
            return self._operation_error_lines("list_imports", exc)

    def list_exports(self, offset: int = 0, limit: int = 100) -> List[str]:
        try:
            offset, limit = self._get_offset_limit(offset, limit)
            if limit > self.MAX_SAFE_LIMIT:
                logger.warning(
                    self.LIMIT_WARNING_TEMPLATE.format(
                        method="list_exports",
                        limit=limit,
                        max_safe=self.MAX_SAFE_LIMIT,
                    )
                )
                limit = self.MAX_SAFE_LIMIT

            def _collect(_program_key, program):
                st = program.getSymbolTable()
                lines: List[str] = []
                for sym in st.getAllSymbols(True):
                    try:
                        if hasattr(sym, "isExternalEntryPoint") and sym.isExternalEntryPoint():
                            lines.append(f"{sym.getName()} -> {sym.getAddress()}")
                    except Exception:
                        continue
                return lines

            return self._render_paginated_lines(self._collect_program_lines(_collect), offset, limit)
        except Exception as exc:
            return self._operation_error_lines("list_exports", exc)

    def list_namespaces(self, offset: int = 0, limit: int = 100) -> List[str]:
        try:
            offset, limit = self._get_offset_limit(offset, limit)
            def _collect(_program_key, program):
                st = program.getSymbolTable()
                names = set()
                for sym in st.getAllSymbols(True):
                    try:
                        namespace = sym.getParentNamespace()
                        if namespace is None:
                            continue

                        is_global = False
                        try:
                            is_global = bool(namespace.isGlobal())
                        except Exception:
                            is_global = str(namespace.getName()) == "Global"

                        if not is_global:
                            names.add(str(namespace.getName()))
                    except Exception:
                        continue
                return sorted(names)

            return self._render_paginated_lines(self._collect_program_lines(_collect), offset, limit)
        except Exception as exc:
            return self._operation_error_lines("list_namespaces", exc)

    def list_data_items(self, offset: int = 0, limit: int = 100) -> List[str]:
        try:
            offset, limit = self._get_offset_limit(offset, limit)
            if limit > self.MAX_SAFE_LIMIT:
                logger.warning(
                    self.LIMIT_WARNING_TEMPLATE.format(
                        method="list_data_items",
                        limit=limit,
                        max_safe=self.MAX_SAFE_LIMIT,
                    )
                )
                limit = self.MAX_SAFE_LIMIT

            def _collect(_program_key, program):
                listing = program.getListing()
                lines: List[str] = []
                for data in listing.getDefinedData(True):
                    try:
                        label = data.getLabel() if hasattr(data, "getLabel") else None
                        value_repr = (
                            data.getDefaultValueRepresentation()
                            if hasattr(data, "getDefaultValueRepresentation")
                            else str(data.getValue())
                        )
                        lines.append(f"{data.getAddress()}: {label or '(unnamed)'} = {value_repr}")
                    except Exception:
                        continue
                return lines

            return self._render_paginated_lines(self._collect_program_lines(_collect), offset, limit)
        except Exception as exc:
            return self._operation_error_lines("list_data_items", exc)

    def list_strings(self, offset: int = 0, limit: int = 100, filter: str | None = None) -> List[str]:
        offset = self._coerce_int_param(offset, param_name="offset", default=0)
        limit = self._coerce_int_param(limit, param_name="limit", default=100)

        max_limit = 50 if filter else self.MAX_SAFE_LIMIT
        if limit > max_limit:
            logger.warning(
                self.LIMIT_WARNING_TEMPLATE.format(method="list_strings", limit=limit, max_safe=max_limit)
                + (" Consider using 'filter' parameter for targeted searches." if not filter else "")
            )
            limit = max_limit

        try:
            def _collect(_program_key, program):
                strings = []
                data_iter = self._get_defined_string_iterator(program)
                if data_iter is not None:
                    for entry in data_iter:
                        value = entry.value
                        if value is None:
                            value = ""
                        if filter and filter not in value:
                            continue
                        strings.append(f"{entry.minAddress}: {value}")
                else:
                    for entry in self._iter_string_entries(program):
                        value = self._string_entry_value(entry)
                        if filter and filter not in value:
                            continue
                        addr = self._string_entry_address(entry)
                        strings.append(f"{addr}: {value}")
                return strings

            return self._render_paginated_lines(self._collect_program_lines(_collect), offset, limit)
        except Exception as exc:
            return self._operation_error_lines("list_strings", exc)

    def search_functions_by_name(self, query: str, offset: int = 0, limit: int = 100) -> List[str]:
        if not query:
            return ["Error: query string is required"]

        try:
            offset, limit = self._get_offset_limit(offset, limit)
            def _collect(_program_key, program):
                func_mgr = program.getFunctionManager()
                matches: List[str] = []
                for func in func_mgr.getFunctions(True):
                    try:
                        name = str(func.getName())
                        if query.lower() in name.lower():
                            matches.append(f"{name} @ {func.getEntryPoint()}")
                    except Exception:
                        continue
                matches.sort()
                return matches

            return self._render_paginated_lines(self._collect_program_lines(_collect), offset, limit)
        except Exception as exc:
            return self._operation_error_lines("search_functions", exc)

    def rename_variable(self, function_name: str, old_name: str, new_name: str) -> str:
        if not function_name or not old_name or not new_name:
            return "Error: 'functionName', 'oldName', and 'newName' are required for renameVariable"

        try:
            from ghidra.program.model.symbol import SourceType  # type: ignore[import]

            program_key, program, _info, func, resolved_function_name = self._resolve_function(function_name)

            try:
                vars_iter = func.getAllVariables()
            except Exception:
                vars_iter = list(func.getParameters()) + list(func.getLocalVariables())

            target = None
            for var in vars_iter:
                try:
                    if var.getName() == old_name:
                        target = var
                        break
                except Exception:
                    continue

            if target is None:
                return f"Error: variable '{old_name}' not found in function '{resolved_function_name}'"

            desc = f"rename_variable: {resolved_function_name}.{old_name} -> {new_name}"
            self._run_program_transaction(
                desc,
                lambda: target.setName(new_name, SourceType.USER_DEFINED),
                program=program,
            )
            return self._format_program_status(
                f"Renamed variable '{old_name}' to '{new_name}' in function '{resolved_function_name}'",
                program_key,
            )
        except Exception as exc:
            return self._operation_error("renameVariable", exc)

    def get_function_by_address(self, address: str) -> str:
        if not address:
            return "Error: 'address' parameter is required for get_function_by_address"

        try:
            _program_key, program, _info, addr, _norm_addr = self._resolve_program_address(address, function_lookup="at")
            func = program.getFunctionManager().getFunctionAt(addr)
            if func is None:
                return f"Error: No function found at address {address}"

            entry = func.getEntryPoint()
            return (
                f"Function: {func.getName()} at {entry}\n"
                f"Signature: {func.getSignature()}\n"
                f"Entry: {entry}\n"
                f"Body: {func.getBody().getMinAddress()} - "
                f"{func.getBody().getMaxAddress()}"
            )
        except Exception as exc:
            return self._operation_error("get_function_by_address", exc)

    def get_current_address(self) -> str:
        return (
            "Error: get_current_address is unavailable in the pyGhidra backend "
            "because it does not track the live Ghidra GUI cursor. Use an explicit "
            "address instead."
        )

    def get_current_function(self) -> str:
        return (
            "Error: get_current_function is unavailable in the pyGhidra backend "
            "because it does not track the live Ghidra GUI selection. Use an explicit "
            "function address or name instead."
        )

    def list_functions(self, offset: int = 0, limit: int = 100) -> List[str]:
        try:
            offset, limit = self._get_offset_limit(offset, limit)
            max_functions_limit = 10000
            if limit > max_functions_limit:
                logger.warning(
                    f"list_functions limit {limit} exceeds "
                    f"MAX_FUNCTIONS_LIMIT={max_functions_limit}. "
                    "Capping to MAX_FUNCTIONS_LIMIT."
                )
                limit = max_functions_limit

            return self._list_function_lines(offset=offset, limit=limit, include_addresses=True)
        except Exception as exc:
            return self._operation_error_lines("list_functions", exc)

    def decompile_function_by_address(self, address: str, offset: int = 0, limit: int = 500) -> str:
        if not address:
            return "Error: 'address' parameter is required for decompile_function"

        try:
            offset, limit = self._get_offset_limit(offset, limit, default_limit=500)
            program_key, program, _info, addr, _norm_addr = self._resolve_program_address(
                address,
                function_lookup="containing",
            )
            func = self._get_function_for_address(addr, program=program)
            if func is None:
                return f"Error: No function found at or containing address {address}"

            decomp = self._ensure_decompiler(program=program, program_key=program_key)
            results = decomp.decompileFunction(func, 60, self._decomp_monitor)
            df = results.getDecompiledFunction()
            if df is None:
                return f"Error: Decompilation failed for {address}"
            return self._render_paginated_text(df.getC(), offset, limit)
        except Exception as exc:
            return self._operation_error("decompile_function", exc)

    def disassemble_function(self, address: str) -> List[str]:
        if not address:
            return ["Error: 'address' parameter is required for disassemble_function"]

        try:
            _program_key, program, _info, addr, _norm_addr = self._resolve_program_address(
                address,
                function_lookup="containing",
            )
            func = self._get_function_for_address(addr, program=program)
            if func is None:
                return [f"Error: No function found at or containing address {address}"]

            listing = program.getListing()
            body = func.getBody()
            lines: List[str] = []
            for cu in listing.getCodeUnits(body, True):
                try:
                    comment = listing.getComment(cu.EOL_COMMENT, cu.getAddress())
                    comment_suffix = f" ; {comment}" if comment else ""
                    instr = cu.toString()
                    lines.append(f"{cu.getAddress()}: {instr}{comment_suffix}")
                except Exception:
                    continue
            return lines
        except Exception as exc:
            return self._operation_error_lines("disassemble_function", exc)

    def set_decompiler_comment(self, address: str, comment: str) -> str:
        if not address or comment is None:
            return "Error: 'address' and 'comment' are required for set_decompiler_comment"

        try:
            from ghidra.program.model.listing import CodeUnit  # type: ignore[import]

            program_key, program, _info, addr, norm_addr = self._resolve_program_address(address)
            listing = program.getListing()
            code_unit = listing.getCodeUnitAt(addr)
            if code_unit is None:
                return f"Error: No code unit at address {address}"

            desc = f"set_decompiler_comment at {norm_addr}"
            self._run_program_transaction(
                desc,
                lambda: code_unit.setComment(CodeUnit.PRE_COMMENT, comment),
                program=program,
            )
            return self._format_program_status(f"Set decompiler comment at {norm_addr}", program_key)
        except Exception as exc:
            return self._operation_error("set_decompiler_comment", exc)

    def set_disassembly_comment(self, address: str, comment: str) -> str:
        if not address or comment is None:
            return "Error: 'address' and 'comment' are required for set_disassembly_comment"

        try:
            from ghidra.program.model.listing import CodeUnit  # type: ignore[import]

            program_key, program, _info, addr, norm_addr = self._resolve_program_address(address)
            listing = program.getListing()
            code_unit = listing.getCodeUnitAt(addr)
            if code_unit is None:
                return f"Error: No code unit at address {address}"

            desc = f"set_disassembly_comment at {norm_addr}"
            self._run_program_transaction(
                desc,
                lambda: code_unit.setComment(CodeUnit.EOL_COMMENT, comment),
                program=program,
            )
            return self._format_program_status(f"Set disassembly comment at {norm_addr}", program_key)
        except Exception as exc:
            return self._operation_error("set_disassembly_comment", exc)

    def rename_function_by_address(self, function_address: str, new_name: str) -> str:
        if not function_address or not new_name:
            return "Error: 'function_address' and 'new_name' are required for rename_function_by_address"

        try:
            from ghidra.program.model.symbol import SourceType  # type: ignore[import]

            program_key, program, _info, addr, norm_addr = self._resolve_program_address(
                function_address,
                function_lookup="containing",
            )
            func = self._get_function_for_address(addr, program=program)
            if func is None:
                return f"Error: No function found at or containing address {function_address}"

            desc = f"rename_function_by_address: {norm_addr} -> {new_name}"
            self._run_program_transaction(
                desc,
                lambda: func.setName(new_name, SourceType.USER_DEFINED),
                program=program,
            )
            return self._format_program_status(f"Renamed function at {norm_addr} to '{new_name}'", program_key)
        except Exception as exc:
            return self._operation_error("rename_function_by_address", exc)

    def set_function_prototype(self, function_address: str, prototype: str) -> str:
        if not function_address or not prototype:
            return "Error: 'function_address' and 'prototype' are required for set_function_prototype"

        try:
            program_key, program, _info, addr, norm_addr = self._resolve_program_address(
                function_address,
                function_lookup="containing",
            )
            func = self._get_function_for_address(addr, program=program)
            if func is None:
                return f"Error: No function found at or containing address {function_address}"

            desc = f"set_function_prototype at {norm_addr}"
            tx = getattr(self._pyghidra, "transaction", None)

            if hasattr(func, "setPrototypeString") and callable(tx):
                self._run_program_transaction(
                    desc,
                    lambda: func.setPrototypeString(prototype),  # type: ignore[call-arg]
                    program=program,
                )
                return self._format_program_status(
                    f"Set prototype for function at {norm_addr} to '{prototype}'",
                    program_key,
                )

            try:
                from ghidra.app.util.cparser.C import CParser  # type: ignore[import]
            except ImportError:
                return "Error: CParser not available to set function prototype; consider upgrading Ghidra/pyGhidra."

            from ghidra.program.model.symbol import SourceType  # type: ignore[import]

            dtm = program.getDataTypeManager()
            parser = CParser(dtm)
            func_dt = parser.parseFunction(prototype)

            ret_type = func_dt.getReturnType()
            params = func_dt.getArguments()

            def action() -> None:
                func.setReturnType(ret_type, SourceType.USER_DEFINED)
                from ghidra.app.services import FunctionUpdateType  # type: ignore[import]

                func.replaceParameters(params, FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, True)

            self._run_program_transaction(desc, action, program=program)
            return self._format_program_status(
                f"Set prototype for function at {norm_addr} to '{prototype}'",
                program_key,
            )
        except Exception as exc:
            return self._operation_error("set_function_prototype", exc)

    def set_local_variable_type(self, function_address: str, variable_name: str, new_type: str) -> str:
        if not function_address or not variable_name or not new_type:
            return "Error: 'function_address', 'variable_name', and 'new_type' are required for set_local_variable_type"

        try:
            from ghidra.program.model.symbol import SourceType  # type: ignore[import]
            from ghidra.app.util.cparser.C import CParser  # type: ignore[import]

            program_key, program, _info, addr, norm_addr = self._resolve_program_address(
                function_address,
                function_lookup="containing",
            )
            func = self._get_function_for_address(addr, program=program)
            if func is None:
                return f"Error: No function found at or containing address {function_address}"

            dtm = program.getDataTypeManager()
            parser = CParser(dtm)

            proto_src = f"void __tmp({new_type} {variable_name});"
            tmp_func_dt = parser.parseFunction(proto_src)
            args = tmp_func_dt.getArguments()
            if not args:
                return f"Error: Could not parse type '{new_type}'"
            desired_dt = args[0].getDataType()

            try:
                vars_iter = func.getAllVariables()
            except Exception:
                vars_iter = list(func.getParameters()) + list(func.getLocalVariables())

            target = None
            for var in vars_iter:
                try:
                    if var.getName() == variable_name:
                        target = var
                        break
                except Exception:
                    continue

            if target is None:
                return f"Error: variable '{variable_name}' not found in function at {function_address}"

            desc = f"set_local_variable_type for {variable_name} at {norm_addr}"
            self._run_program_transaction(
                desc,
                lambda: target.setDataType(desired_dt, SourceType.USER_DEFINED),
                program=program,
            )
            return self._format_program_status(
                f"Set type of variable '{variable_name}' in function at {norm_addr} to '{new_type}'",
                program_key,
            )
        except Exception as exc:
            return self._operation_error("set_local_variable_type", exc)

    def get_xrefs_to(self, address: str, offset: int = 0, limit: int = 100):
        _program_key, raw_address = self._split_program_qualified_identifier(address)
        if not self._normalize_addr(raw_address):
            return ["Error: 'address' parameter is required for xrefs_to"]

        try:
            offset, limit = self._get_offset_limit(offset, limit)
            _program_key, program, _info, addr, _resolved_addr = self._resolve_program_address(address)
            ref_mgr = program.getReferenceManager()
            func_mgr = program.getFunctionManager()
            lines: List[str] = []
            for ref in ref_mgr.getReferencesTo(addr):
                try:
                    from_addr = ref.getFromAddress()
                    ref_type = ref.getReferenceType().toString()
                    from_func = func_mgr.getFunctionContaining(from_addr)
                    func_info = f" in {from_func.getName()}" if from_func else ""
                    lines.append(f"From {from_addr}{func_info} [{ref_type}]")
                except Exception:
                    continue
            return self._render_paginated_lines(lines, offset, limit)
        except Exception as exc:
            return self._operation_error_lines("get_xrefs_to", exc)

    def get_xrefs_from(self, address: str, offset: int = 0, limit: int = 100):
        _program_key, raw_address = self._split_program_qualified_identifier(address)
        if not self._normalize_addr(raw_address):
            return ["Error: 'address' parameter is required for xrefs_from"]

        try:
            offset, limit = self._get_offset_limit(offset, limit)
            _program_key, program, _info, addr, _resolved_addr = self._resolve_program_address(address)
            ref_mgr = program.getReferenceManager()
            func_mgr = program.getFunctionManager()
            listing = program.getListing()
            lines: List[str] = []
            for ref in ref_mgr.getReferencesFrom(addr):
                try:
                    to_addr = ref.getToAddress()
                    ref_type = ref.getReferenceType().toString()
                    target_info = ""
                    to_func = func_mgr.getFunctionAt(to_addr)
                    if to_func is not None:
                        target_info = f" to function {to_func.getName()}"
                    else:
                        data = listing.getDataAt(to_addr)
                        if data is not None:
                            label = data.getLabel() or getattr(data, "getPathName", lambda: "")()
                            target_info = f" to data {label}"
                    lines.append(f"To {to_addr}{target_info} [{ref_type}]")
                except Exception:
                    continue
            return self._render_paginated_lines(lines, offset, limit)
        except Exception as exc:
            return self._operation_error_lines("get_xrefs_from", exc)

    def get_function_xrefs(self, name: str, offset: int = 0, limit: int = 100):
        if not name:
            return ["Error: 'name' parameter is required for function_xrefs"]

        qualified_program_key, qualified_name = self._split_program_qualified_identifier(name)
        if qualified_name.upper().startswith("0X") or qualified_name[:3].upper() == "FUN" or qualified_name.isalnum() and len(qualified_name) >= 6:
            addr = self._normalize_addr(qualified_name)
            if qualified_program_key is not None:
                addr = f"{self._program_entry(qualified_program_key).selector()}::{addr}"
            return self.get_xrefs_to(addr, offset=offset, limit=limit)

        try:
            offset, limit = self._get_offset_limit(offset, limit)
            target_name = qualified_name.strip()
            matches = []

            if qualified_program_key is not None:
                program = self._require_program(qualified_program_key)
                target_address, target_type = self._find_symbol_address(target_name, program)
                if target_address is None:
                    return [f"Error: function or symbol '{target_name}' not found"]
                matches.append((qualified_program_key, program, target_address, target_type))
            else:
                for program_key, program, _info in self._iter_program_entries():
                    target_address, target_type = self._find_symbol_address(target_name, program)
                    if target_address is not None:
                        matches.append((program_key, program, target_address, target_type))

                if not matches:
                    return [f"Error: function or symbol '{target_name}' not found"]
                if len(matches) > 1:
                    candidates = ", ".join(
                        f"{self._program_entry(program_key).selector()}::{target_name}"
                        for program_key, _program, _target_address, _target_type in matches
                    )
                    return [
                        f"Error: function or symbol '{target_name}' exists in multiple open programs. "
                        f"Qualify it as '<program>::{target_name}'. Candidates: {candidates}"
                    ]

            lines: List[str] = []
            _program_key, program, target_address, _target_type = matches[0]
            ref_mgr = program.getReferenceManager()
            func_mgr = program.getFunctionManager()
            for ref in ref_mgr.getReferencesTo(target_address):
                try:
                    from_addr = ref.getFromAddress()
                    ref_type = ref.getReferenceType().toString()
                    from_func = func_mgr.getFunctionContaining(from_addr)
                    func_info = f" in {from_func.getName()}" if from_func else ""
                    lines.append(f"From {from_addr}{func_info} [{ref_type}]")
                except Exception:
                    continue

            return self._render_paginated_lines(lines, offset, limit)
        except Exception as exc:
            return self._operation_error_lines("get_function_xrefs", exc)

    def read_bytes(self, address: str, length: int = 16, format: str = "hex") -> str:
        _program_key, raw_address = self._split_program_qualified_identifier(address)
        norm_addr = self._normalize_addr(raw_address)
        if not norm_addr:
            return "Error: 'address' parameter is required for read_bytes"

        try:
            length = int(length or 16)
        except Exception as exc:
            return f"Request failed: {exc}"

        if length <= 0 or length > 4096:
            return "Error: length must be 1-4096 bytes"

        fmt = (format or "hex").lower()

        try:
            _program_key, program, _info, addr, _resolved_addr = self._resolve_program_address(address)
            mem = program.getMemory()
            data = bytearray(length)
            bytes_read = mem.getBytes(addr, data)

            if bytes_read <= 0:
                return f"Error: Could not read bytes at address {address}"

            raw_bytes = bytes(data[:bytes_read])

            if fmt == "raw":
                return base64.b64encode(raw_bytes).decode("ascii")

            bytes_per_line = 16
            lines: List[str] = []
            for chunk_offset in range(0, len(raw_bytes), bytes_per_line):
                chunk = raw_bytes[chunk_offset : chunk_offset + bytes_per_line]
                try:
                    line_addr = str(addr.add(chunk_offset))
                except Exception:
                    line_addr = f"{int(norm_addr, 16) + chunk_offset:x}"

                hex_bytes = " ".join(f"{byte:02X}" for byte in chunk)
                if len(chunk) < bytes_per_line:
                    hex_bytes += "   " * (bytes_per_line - len(chunk))
                ascii_repr = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in chunk)
                lines.append(f"{line_addr}: {hex_bytes} |{ascii_repr}|")

            return "\n".join(lines)
        except Exception as exc:
            return self._operation_error("read_bytes", exc)
