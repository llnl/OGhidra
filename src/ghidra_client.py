"""
Client for interacting with the GhidraMCP API.
"""

import json
import logging
import time
import re
import struct
import base64
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse

import httpx

from src.config import GhidraMCPConfig

logger = logging.getLogger("ollama-ghidra-bridge.ghidra")

class GhidraMCPClient:
    """Client for interacting with GhidraMCP API."""
    
    def __init__(self, config: GhidraMCPConfig, ollama_client=None):
        """
        Initialize the GhidraMCP client.
        
        Args:
            config: GhidraMCPConfig object with connection details
            ollama_client: Optional OllamaClient for AI-powered analysis
        """
        self.config = config
        self.client = httpx.Client(timeout=config.timeout)
        self.api_version = None
        self.ollama_client = ollama_client
        
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
                self.active_instances[self.default_port] = {"url": str(config.base_url).rstrip('/')}
            else:
                self.default_port = 8080
                self.current_instance_port = 8080
        except Exception:
            self.default_port = 8080
            self.current_instance_port = 8080
            
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
            response = self.safe_get("methods", {"offset": 0, "limit": 1})
            # Check if response is valid (list of strings, not error strings)
            if response and isinstance(response, list) and not (response and (response[0].startswith("Error") or response[0].startswith("Request failed"))):
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
        return str(self.config.base_url).rstrip('/')
    
    def safe_get(self, endpoint: str, params: Dict[str, Any] = None) -> List[str]:
        """
        Perform a GET request safely and return the response lines.
        
        Args:
            endpoint: The endpoint to request (without leading slash)
            params: Query parameters
            
        Returns:
            List of response lines
        """
        if params is None:
            params = {}
            
        # Ensure proper URL construction by removing trailing slash from base_url
        # and ensuring endpoint doesn't start with slash
        base_url = self._get_base_url()
        endpoint = endpoint.lstrip('/')
        url = f"{base_url}/{endpoint}"
        
        try:
            logger.debug(f"Sending GET request to GhidraMCP: {endpoint} with params: {params}")
            response = self.client.get(url, params=params, timeout=self.config.timeout)
            response.encoding = 'utf-8'
            
            if response.status_code == 200:
                return response.text.splitlines()
            else:
                return [f"Error {response.status_code}: {response.text.strip()}"]
        except Exception as e:
            error_msg = f"Request failed: {str(e)}"
            logger.error(error_msg)
            return [error_msg]
    
    def safe_post(self, endpoint: str, data: Dict[str, Any] | str) -> str:
        """
        Perform a POST request with data.
        
        Args:
            endpoint: The endpoint to request (without leading slash)
            data: Data to send (dict or string)
            
        Returns:
            Response text
        """
        # Ensure proper URL construction by removing trailing slash from base_url
        # and ensuring endpoint doesn't start with slash
        base_url = self._get_base_url()
        endpoint = endpoint.lstrip('/')
        url = f"{base_url}/{endpoint}"
        
        try:
            logger.debug(f"Sending POST request to GhidraMCP: {endpoint} with data: {data}")
            
            if isinstance(data, dict):
                response = self.client.post(url, data=data, timeout=self.config.timeout)
            else:
                response = self.client.post(url, data=data.encode("utf-8"), timeout=self.config.timeout)
            
            response.encoding = 'utf-8'
            
            if response.status_code == 200:
                return response.text.strip()
            else:
                return f"Error {response.status_code}: {response.text.strip()}"
        except Exception as e:
            error_msg = f"Request failed: {str(e)}"
            logger.error(error_msg)
            return error_msg
    
    def health_check(self) -> bool:
        """
        Check if the GhidraMCP server is available.
        
        Returns:
            True if the server is available, False otherwise
        """
        try:
            response = self.safe_get("methods", {"offset": 0, "limit": 1})
            return response and not response[0].startswith("Error")
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
            # Use the same URL construction pattern as other methods
            base_url = self._get_base_url()
            url = f"{base_url}/methods"
            
            response = self.client.get(url, params={"offset": 0, "limit": 1})
            response.raise_for_status()
            return True
        except Exception as e:
            logger.error(f"GhidraMCP health check failed: {str(e)}")
            return False
    
    # Implement GhidraMCP API methods
    
    def list_methods(self, offset: int = 0, limit: int = 100) -> List[str]:
        """
        List all function names in the program with pagination.
        
        Args:
            offset: Offset to start from
            limit: Maximum number of results
            
        Returns:
            List of function names
        """
        return self.safe_get("methods", {"offset": offset, "limit": limit})
    
    def list_classes(self, offset: int = 0, limit: int = 100) -> List[str]:
        """
        List all namespace/class names in the program with pagination.
        
        Args:
            offset: Offset to start from
            limit: Maximum number of results
            
        Returns:
            List of class names
        """
        return self.safe_get("classes", {"offset": offset, "limit": limit})
    
    def decompile_function(self, name: str) -> str:
        """
        Decompile a specific function by name and return the decompiled C code.
        
        Args:
            name: Function name
            
        Returns:
            Decompiled C code
        """
        return self.safe_post("decompile", name)
    
    def rename_function(self, old_name: str, new_name: str) -> str:
        """
        Rename a function by its current name to a new user-defined name.
        
        Args:
            old_name: Current function name
            new_name: New function name
            
        Returns:
            Result of the rename operation
        """
        return self.safe_post("renameFunction", {"oldName": old_name, "newName": new_name})
    
    def rename_data(self, address: str, new_name: str) -> str:
        """
        Rename a data label at the specified address.
        
        Args:
            address: Data address
            new_name: New data name
            
        Returns:
            Result of the rename operation
        """
        return self.safe_post("renameData", {"address": address, "newName": new_name})
    
    def list_segments(self, offset: int = 0, limit: int = 100) -> List[str]:
        """
        List all memory segments in the program with pagination.
        
        Args:
            offset: Offset to start from
            limit: Maximum number of results
            
        Returns:
            List of memory segments
        """
        return self.safe_get("segments", {"offset": offset, "limit": limit})
    
    def list_imports(self, offset: int = 0, limit: int = 100) -> List[str]:
        """
        List imported symbols in the program with pagination.
        
        Args:
            offset: Offset to start from
            limit: Maximum number of results
            
        Returns:
            List of imported symbols
        """
        return self.safe_get("imports", {"offset": offset, "limit": limit})
    
    def list_exports(self, offset: int = 0, limit: int = 100) -> List[str]:
        """
        List exported functions/symbols with pagination.
        
        Args:
            offset: Offset to start from
            limit: Maximum number of results
            
        Returns:
            List of exported symbols
        """
        return self.safe_get("exports", {"offset": offset, "limit": limit})
    
    def list_namespaces(self, offset: int = 0, limit: int = 100) -> List[str]:
        """
        List all non-global namespaces in the program with pagination.
        
        Args:
            offset: Offset to start from
            limit: Maximum number of results
            
        Returns:
            List of namespaces
        """
        return self.safe_get("namespaces", {"offset": offset, "limit": limit})
    
    def list_data_items(self, offset: int = 0, limit: int = 100) -> List[str]:
        """
        List defined data labels and their values with pagination.
        
        Args:
            offset: Offset to start from
            limit: Maximum number of results
            
        Returns:
            List of data items
        """
        return self.safe_get("data", {"offset": offset, "limit": limit})
    
    def list_strings(self, offset: int = 0, limit: int = 100, filter: str | None = None) -> List[str]:
        """
        List defined strings (or search with substring filter).

        Args:
            offset: Pagination offset
            limit: Maximum number of results
            filter: Optional substring to restrict results (alias: string_search)

        Returns:
            List of strings (raw API response)
        """
        params = {"offset": offset, "limit": limit}
        if filter:
            params["filter"] = filter
        return self.safe_get("strings", params)
    
    def search_functions_by_name(self, query: str, offset: int = 0, limit: int = 100) -> List[str]:
        """
        Search for functions whose name contains the given substring.
        
        Args:
            query: Search query
            offset: Offset to start from
            limit: Maximum number of results
            
        Returns:
            List of matching functions
        """
        if not query:
            return ["Error: query string is required"]
        return self.safe_get("searchFunctions", {"query": query, "offset": offset, "limit": limit})
    
    def rename_variable(self, function_name: str, old_name: str, new_name: str) -> str:
        """
        Rename a local variable within a function.
        
        Args:
            function_name: Function name
            old_name: Current variable name
            new_name: New variable name
            
        Returns:
            Result of the rename operation
        """
        return self.safe_post("renameVariable", {
            "functionName": function_name,
            "oldName": old_name,
            "newName": new_name
        })
    
    def get_function_by_address(self, address: str) -> str:
        """
        Get a function by its address.
        
        Args:
            address: Function address
            
        Returns:
            Function information
        """
        result = self.safe_get("get_function_by_address", {"address": address})
        return "\n".join(result)
    
    def get_current_address(self) -> str:
        """
        Get the address currently selected by the user.
        
        Returns:
            Current address
        """
        result = self.safe_get("get_current_address")
        return "\n".join(result)
    
    def get_current_function(self) -> str:
        """
        Get the function currently selected by the user.
        
        Returns:
            Current function
        """
        result = self.safe_get("get_current_function")
        return "\n".join(result)
    
    def list_functions(self, offset: int = 0, limit: int = 100) -> List[str]:
        """
        List all functions in the database with pagination.
        
        Args:
            offset: Offset to start from (default: 0)
            limit: Maximum number of results (default: 100)
        
        Returns:
            List of functions with pagination metadata
        """
        return self.safe_get("list_functions", {"offset": offset, "limit": limit})
    
    def decompile_function_by_address(self, address: str) -> str:
        """
        Decompile a function at the given address.
        
        Args:
            address: Function address
            
        Returns:
            Decompiled function
        """
        result = self.safe_get("decompile_function", {"address": address})
        return "\n".join(result)
    
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
            current_function_info = self.get_current_function() # Expected: "FunctionName @ Address" or error string
            
            if not current_function_info.startswith("Error"):
                if "@ " in current_function_info:
                    parts = current_function_info.split("@ ", 1)
                    if len(parts) == 2:
                        potential_address = parts[1].strip()
                        # Validate if the extracted address is a non-empty hex string
                        if potential_address and all(c in "0123456789abcdefABCDEF" for c in potential_address):
                            determined_address = potential_address
                            logger.info(f"analyze_function: Determined address '{determined_address}' from get_current_function() result: '{current_function_info}'.")
                        else:
                            logger.warning(f"analyze_function: Extracted part '{potential_address}' from get_current_function() result ('{current_function_info}') is not a valid hex address.")
                    else:
                        # This case should ideally not be reached if "@ " is present and split is limited to 1
                        logger.warning(f"analyze_function: Unexpected split result from get_current_function() ('{current_function_info}') despite '@ ' being present.")
                else:
                    logger.warning(f"analyze_function: Result from get_current_function() ('{current_function_info}') does not contain '@ '. Attempting get_current_address().")
            else:
                logger.warning(f"analyze_function: get_current_function() returned an error: '{current_function_info}'. Attempting get_current_address().")

            # If get_current_function() didn't yield a valid address, try get_current_address()
            if determined_address is None:
                logger.info("analyze_function: Trying get_current_address() as fallback to determine function address.")
                current_address_str = self.get_current_address() # Expected: "Address" or error string
                # Validate if current_address_str is a non-empty hex string and not an error
                if not current_address_str.startswith("Error") and current_address_str and all(c in "0123456789abcdefABCDEF" for c in current_address_str):
                    determined_address = current_address_str
                    logger.info(f"analyze_function: Determined address '{determined_address}' from get_current_address().")
                else:
                    logger.warning(f"analyze_function: get_current_address() did not yield a valid hex address. Result: '{current_address_str}'")
            
            if determined_address:
                address = determined_address
            else:
                logger.error("analyze_function: Could not determine current function address automatically after trying get_current_function() and get_current_address().")
                return "Error: Could not determine current function address. Please provide an address or ensure a function/address is selected in Ghidra."
        
        # Get the decompiled code for the target function
        decompiled_code = self.decompile_function_by_address(address)
        if decompiled_code.startswith("Error"):
            return f"Error analyzing function at {address}: {decompiled_code}"
            
        # Extract function calls from the decompiled code
        function_calls = []
        for line in decompiled_code.splitlines():
            matches = re.finditer(r'\b(\w+)\s*\(', line)
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
                    ""
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
    
    def disassemble_function(self, address: str) -> List[str]:
        """
        Get assembly code (address: instruction; comment) for a function.
        
        Args:
            address: Function address
            
        Returns:
            Disassembled function
        """
        return self.safe_get("disassemble_function", {"address": address})
    
    def set_decompiler_comment(self, address: str, comment: str) -> str:
        """
        Set a comment for a given address in the function pseudocode.
        
        Args:
            address: Address
            comment: Comment
            
        Returns:
            Result of the operation
        """
        return self.safe_post("set_decompiler_comment", {"address": address, "comment": comment})
    
    def set_disassembly_comment(self, address: str, comment: str) -> str:
        """
        Set a comment for a given address in the function disassembly.
        
        Args:
            address: Address
            comment: Comment
            
        Returns:
            Result of the operation
        """
        return self.safe_post("set_disassembly_comment", {"address": address, "comment": comment})
    
    def rename_function_by_address(self, function_address: str, new_name: str) -> str:
        """
        Rename a function by its address.
        
        Args:
            function_address: Function address
            new_name: New name
            
        Returns:
            Result of the rename operation
        """
        return self.safe_post("rename_function_by_address", {"function_address": function_address, "new_name": new_name})
    
    def set_function_prototype(self, function_address: str, prototype: str) -> str:
        """
        Set a function's prototype.
        
        Args:
            function_address: Function address
            prototype: Function prototype
            
        Returns:
            Result of the operation
        """
        return self.safe_post("set_function_prototype", {"function_address": function_address, "prototype": prototype})
    
    def set_local_variable_type(self, function_address: str, variable_name: str, new_type: str) -> str:
        """
        Set a local variable's type.
        
        Args:
            function_address: Function address
            variable_name: Variable name
            new_type: New type
            
        Returns:
            Result of the operation
        """
        return self.safe_post("set_local_variable_type", {
            "function_address": function_address,
            "variable_name": variable_name,
            "new_type": new_type
        }) 

    # ------------------------------------------------------------------
    # 🔄 Address helper & cross-reference endpoints (extended)
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_addr(identifier: str) -> str:
        """Return canonical hexadecimal address **without** any "0x" prefix, lower-cased.

        Accepts typical variants such as:
        • "0x0047DE88"
        • "0047de88"
        • "FUN_0047DE88" / "thunk_FUN_0047DE88"

        and converts them to "0047de88" which is the address format required by
        most GhidraMCP endpoints (all lowercase, no prefix).
        """

        if not identifier:
            return ""

        # Fast-path: already looks like an address with no prefix
        if identifier.isalnum() and all(c in "0123456789abcdefABCDEF" for c in identifier):
            return identifier.lower()

        # If it starts with 0x/0X remove the prefix
        if identifier.lower().startswith("0x"):
            return identifier[2:].lower()

        # Extract the first long hex substring (6+ chars)
        import re
        m = re.search(r"([0-9a-fA-F]{6,})", identifier)
        if m:
            return m.group(1).lower()

        # Fallback: return as-is (may produce server error, but avoids crash)
        return identifier

    # -- incoming xrefs
    def get_xrefs_to(self, address: str, offset: int = 0, limit: int = 100):
        """List all x-refs *to* `address`. Returns list/str depending on API."""
        norm_addr = self._normalize_addr(address)
        lines = self.safe_get("xrefs_to", {"address": norm_addr, "offset": offset, "limit": limit})
        return lines

    # -- outgoing xrefs
    def get_xrefs_from(self, address: str, offset: int = 0, limit: int = 100):
        """List all x-refs *from* `address`."""
        norm_addr = self._normalize_addr(address)
        lines = self.safe_get("xrefs_from", {"address": norm_addr, "offset": offset, "limit": limit})
        return lines

    # -- name-based helper
    def get_function_xrefs(self, name: str, offset: int = 0, limit: int = 100):
        """List x-refs to a function by `name`. If an address is mistakenly passed,
        we treat it as address form and call get_xrefs_to instead."""
        # Detect address-like input
        if name.upper().startswith("0X") or name[:3].upper() == "FUN" or name.isalnum() and len(name) >=6:
            addr = self._normalize_addr(name)
            return self.get_xrefs_to(addr, offset=offset, limit=limit)

        lines = self.safe_get("function_xrefs", {"name": name, "offset": offset, "limit": limit})
        return lines

    # ------------------------------------------------------------------
    # Raw byte reading capability
    # ------------------------------------------------------------------

    def read_bytes(self, address: str, length: int = 16, format: str = "hex") -> str:
        """
        Read raw bytes from memory at the specified address.
        
        Args:
            address: Starting address in hex format (e.g. "0x1400010a0")
            length: Number of bytes to read (1-4096, default: 16)
            format: "hex" for hex dump with ASCII representation, 
                    "raw" for base64 encoded bytes
            
        Returns:
            Hex dump string or base64-encoded raw bytes
        """
        norm_addr = self._normalize_addr(address)
        result = self.safe_get("read_bytes", {
            "address": norm_addr,
            "length": length,
            "format": format
        })
        return "\n".join(result)

    # =========================================================================
    # Smart Analysis Tools - Algorithmic scanning without LLM intervention
    # =========================================================================

    def scan_function_pointer_tables(
        self, 
        min_table_entries: int = 3,
        pointer_size: int = 8,
        max_scan_size: int = 524288,  # 512KB per segment max
        alignment: int = 8
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
            # Parse segment info - Ghidra format: ".text: 100401000 - 10041d5ff"
            # Look for the pattern after the colon: "start - end" where start/end are hex
            seg_match = re.match(r'^([^:]+):\s*([0-9a-fA-F]+)\s*-\s*([0-9a-fA-F]+)', line)
            if seg_match:
                try:
                    seg_name = seg_match.group(1).strip()
                    start = int(seg_match.group(2), 16)
                    end = int(seg_match.group(3), 16)
                    size = end - start
                    if size > 0:
                        data_segments.append({
                            'start': start, 
                            'end': end, 
                            'name': seg_name,
                            'size': size
                        })
                        logger.debug(f"Parsed segment: {seg_name} 0x{start:x} - 0x{end:x} ({size} bytes)")
                except ValueError:
                    continue
        
        # If we couldn't parse segments, try scanning around function addresses
        if not data_segments:
            logger.warning("Could not parse data segments, scanning around function address range")
            # Create a pseudo-segment covering the function address space + some buffer
            data_segments = [{
                'start': max(0, min_func_addr - 0x10000),
                'end': max_func_addr + 0x10000,
                'name': 'inferred',
                'size': (max_func_addr - min_func_addr) + 0x20000
            }]
        
        # Prioritize data segments where function tables are likely to be found
        # Skip code segments (.text) and special segments
        # Note: .bss is uninitialized data (zeros) so unlikely to have pointers
        skip_segments = {'.text', '.pdata', '.xdata', '.rsrc', '.buildid', 'headers', 
                         '.bss', '.reloc', '.gnu_debuglink', '.comment'}
        priority_segments = {'.rdata', '.data', '.rodata', '.got', '.got.plt', '.idata'}
        
        # Sort segments: priority segments first, then others, skip unwanted
        def segment_priority(seg):
            name_lower = seg['name'].lower()
            if name_lower in skip_segments:
                return 2  # Skip these
            if name_lower in priority_segments:
                return 0  # Scan first
            return 1  # Scan after priority
        
        scannable_segments = [s for s in data_segments if s['name'].lower() not in skip_segments]
        scannable_segments.sort(key=segment_priority)
        
        logger.info(f"Scanning {len(scannable_segments)} segment(s) for function pointer tables (skipping code segments)")
        
        # Step 3: Scan each segment for function pointer sequences
        for segment in scannable_segments:
            scan_size = min(segment['size'], max_scan_size)
            logger.info(f"Scanning segment {segment['name']}: 0x{segment['start']:x} ({segment['size']} bytes)")
            tables_in_segment = self._scan_segment_for_tables(
                segment['start'],
                scan_size,
                function_map,
                min_func_addr,
                max_func_addr,
                pointer_size,
                min_table_entries,
                alignment
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
        alignment: int
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
                raw_result = self.read_bytes(
                    hex(current_addr), 
                    length=read_size, 
                    format="raw"
                )
                
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
                    data,
                    current_addr,
                    function_map,
                    min_func_addr,
                    max_func_addr,
                    pointer_size,
                    min_table_entries,
                    alignment
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
        alignment: int
    ) -> List[Dict]:
        """
        Find sequences of consecutive function pointers in a byte array.
        """
        tables = []
        
        # Track current sequence
        current_table_start = None
        current_entries = []
        
        # Format string for struct.unpack (little-endian)
        ptr_format = '<Q' if pointer_size == 8 else '<I'
        
        i = 0
        while i <= len(data) - pointer_size:
            try:
                # Extract pointer value
                ptr_bytes = data[i:i + pointer_size]
                ptr_value = struct.unpack(ptr_format, ptr_bytes)[0]
                
                # Quick range check then lookup
                is_valid_func = (
                    min_func_addr <= ptr_value <= max_func_addr and 
                    ptr_value in function_map
                )
                
                if is_valid_func:
                    # We found a valid function pointer
                    if current_table_start is None:
                        current_table_start = base_addr + i
                    
                    current_entries.append({
                        'offset': len(current_entries) * pointer_size,
                        'pointer': f"0x{ptr_value:x}",
                        'function_name': function_map[ptr_value]
                    })
                    i += alignment
                    continue
                
                # Not a valid function pointer - check if we should end current sequence
                if current_entries:
                    if len(current_entries) >= min_table_entries:
                        tables.append({
                            'table_address': f"0x{current_table_start:x}",
                            'entry_count': len(current_entries),
                            'entries': current_entries.copy()
                        })
                    current_table_start = None
                    current_entries = []
                
                i += alignment
                
            except struct.error:
                i += alignment
                continue
        
        # Don't forget the last sequence
        if current_entries and len(current_entries) >= min_table_entries:
            tables.append({
                'table_address': f"0x{current_table_start:x}",
                'entry_count': len(current_entries),
                'entries': current_entries.copy()
            })
        
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
            
            entries_to_show = table['entries'][:max_entries_shown]
            for entry in entries_to_show:
                lines.append(f"  [{entry['offset']:4d}] {entry['pointer']} -> {entry['function_name']}")
            
            if len(table['entries']) > max_entries_shown:
                lines.append(f"  ... and {len(table['entries']) - max_entries_shown} more entries")
            lines.append("")
        
        return "\n".join(lines)

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
        if 8080 not in ports: ports = [8080] + ports
        
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
            f"Plugin Version: {info.get('plugin_version', 'Unknown')}"
        ]
        return "\n".join(result)

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