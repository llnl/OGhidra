#!/usr/bin/env python3
"""
GhidraMCP API Client
This module provides a client interface for the GhidraMCP API.
It implements the functions defined in the function_signatures.json file.
"""

import requests
import logging
import os
import json
from typing import Dict, List, Optional, Any, Union

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

class GhidraMCPClient:
    """
    Client for interacting with the GhidraMCP API.
    Implements the functionality defined in function_signatures.json.
    """
    
    def __init__(self, config):
        """
        Initialize the GhidraMCP client.
        
        Args:
            config: GhidraMCPConfig object
        """
        self.base_url = str(config.base_url)
        self.config = config
        self.function_signatures = self._load_function_signatures()
        
    def _load_function_signatures(self) -> Dict[str, Any]:
        """
        Load function signatures from JSON file.
        
        Returns:
            Dict: Function signatures configuration
        """
        try:
            file_path = os.path.join("ghidra_knowledge_cache", "function_signatures.json")
            with open(file_path, "r") as f:
                return json.load(f)["function_signatures"]
        except Exception as e:
            logger.error(f"Error loading function signatures: {e}")
            return {}
    
    def _get_request(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> requests.Response:
        """
        Make a GET request to the API.
        
        Args:
            endpoint: API endpoint
            params: Optional query parameters
            
        Returns:
            Response object from the requests library
        """
        url = f"{self.base_url}/{endpoint}"
        response = requests.get(url, params=params)
        response.raise_for_status()
        return response
    
    def _post_request(self, endpoint: str, data: Dict[str, Any]) -> requests.Response:
        """
        Make a POST request to the API.
        
        Args:
            endpoint: API endpoint
            data: Data to send in the request body
            
        Returns:
            Response object from the requests library
        """
        url = f"{self.base_url}/{endpoint}"
        response = requests.post(url, json=data)
        response.raise_for_status()
        return response

    # ------------------------------------------------------------------
    # Helper: Address normalisation to meet API expectations
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_addr(identifier: str) -> str:
        """Return canonical hexadecimal address (lowercase, *no* "0x" prefix)."""

        if not identifier:
            return ""

        # Already looks like address
        if identifier.isalnum() and all(c in "0123456789abcdefABCDEF" for c in identifier):
            return identifier.lower()

        if identifier.lower().startswith("0x"):
            return identifier[2:].lower()

        import re
        m = re.search(r"([0-9a-fA-F]{6,})", identifier)
        if m:
            return m.group(1).lower()

        return identifier
    
    def list_functions(self) -> List[str]:
        """
        Lists all functions in the currently loaded program.
        
        Returns:
            List of function names
        """
        try:
            response = self._get_request("methods")
            functions = response.text.strip().split('\n')
            return functions
        except Exception as e:
            logger.error(f"Error listing functions: {e}")
            return []
    
    def decompile_function(self, name: str) -> str:
        """
        Decompiles a function by name using Ghidra's decompiler.
        
        Args:
            name: The name of the function to decompile
            
        Returns:
            C-like representation of the function's code
        """
        try:
            response = self._get_request(f"method/{name}")
            return response.text
        except Exception as e:
            logger.error(f"Error decompiling function {name}: {e}")
            return f"// Error decompiling function: {e}"
    
    def decompile_function_by_address(self, address: str) -> str:
        """
        Decompiles a function at the specified address using Ghidra's decompiler.
        
        Args:
            address: The address of the function to decompile
            
        Returns:
            C-like representation of the function's code
        """
        try:
            response = self._get_request(f"address/{address}")
            return response.text
        except Exception as e:
            logger.error(f"Error decompiling function at address {address}: {e}")
            return f"// Error decompiling function at address {address}: {e}"
    
    def rename_function(self, old_name: str, new_name: str) -> str:
        """
        Renames a function from its current name to a new name.
        
        Args:
            old_name: Current function name
            new_name: New function name
            
        Returns:
            Success message
        """
        try:
            response = self._post_request("rename", {
                "old_name": old_name,
                "new_name": new_name
            })
            
            # Try to parse as JSON, fallback to text
            try:
                return response.json()
            except:
                return response.text
        except Exception as e:
            logger.error(f"Error renaming function {old_name} to {new_name}: {e}")
            return f"Error: {e}"
    
    def rename_function_by_address(self, function_address: str, new_name: str) -> str:
        """
        Renames a function at the specified address to a new name.
        
        Args:
            function_address: The address of the function to rename
            new_name: New function name
            
        Returns:
            Success message
        """
        try:
            response = self._post_request("rename", {
                "function_address": function_address,
                "new_name": new_name
            })
            
            # Try to parse as JSON, fallback to text
            try:
                return response.json()
            except:
                return response.text
        except Exception as e:
            logger.error(f"Error renaming function at address {function_address} to {new_name}: {e}")
            return f"Error: {e}"
    
    def list_imports(self, offset: int = 0, limit: int = 100) -> List[str]:
        """
        Lists imported symbols in the program with pagination.
        
        Args:
            offset: Offset to start from
            limit: Maximum number of results
            
        Returns:
            List of imported symbol names
        """
        try:
            response = self._get_request("imports", {
                "offset": offset,
                "limit": limit
            })
            # Parse the response - assuming it's JSON
            try:
                return response.json()
            except:
                # If the response isn't JSON, try parsing it as text
                return response.text.strip().split('\n')
        except Exception as e:
            logger.error(f"Error listing imports: {e}")
            return []
    
    def list_exports(self, offset: int = 0, limit: int = 100) -> List[str]:
        """
        Lists exported functions/symbols in the program with pagination.
        
        Args:
            offset: Offset to start from
            limit: Maximum number of results
            
        Returns:
            List of exported symbol names
        """
        try:
            response = self._get_request("exports", {
                "offset": offset,
                "limit": limit
            })
            try:
                return response.json()
            except Exception:
                return response.text.strip().split('\n')
        except Exception as e:
            logger.error(f"Error listing exports: {e}")
            return []

    # ------------------------------------------------------------------
    # Xref & String-search support (new GhidraMCP endpoints)
    # ------------------------------------------------------------------

    def get_xrefs_to(self, address: str, offset: int = 0, limit: int = 100) -> Union[List[Any], str]:
        """Get all cross-references *to* the specified address.

        Args:
            address: Target address in hex format (e.g. "0x1400010a0")
            offset: Pagination offset
            limit: Maximum number of results to return

        Returns:
            A list (preferred) or raw text response with the xrefs.
        """
        try:
            norm_addr = self._normalize_addr(address)
            response = self._get_request("xrefs_to", {
                "address": norm_addr,
                "offset": offset,
                "limit": limit
            })
            try:
                return response.json()
            except Exception:
                return response.text.strip().split("\n")
        except Exception as e:
            logger.error(f"Error getting xrefs_to for {address}: {e}")
            return []

    def get_xrefs_from(self, address: str, offset: int = 0, limit: int = 100) -> Union[List[Any], str]:
        """Get all cross-references *from* the specified address."""
        try:
            norm_addr = self._normalize_addr(address)
            response = self._get_request("xrefs_from", {
                "address": norm_addr,
                "offset": offset,
                "limit": limit
            })
            try:
                return response.json()
            except Exception:
                return response.text.strip().split("\n")
        except Exception as e:
            logger.error(f"Error getting xrefs_from for {address}: {e}")
            return []

    def get_function_xrefs(self, name: str, offset: int = 0, limit: int = 100) -> Union[List[Any], str]:
        """Get cross-references to a function by name."""
        try:
            # If the caller accidentally passed an address, normalise it and
            # switch to the address-based endpoint.
            if name and name.upper().startswith("0X") or name[:3].upper() == "FUN":
                alt = self._normalize_addr(name)
                return self.get_xrefs_to(alt, offset=offset, limit=limit)

            response = self._get_request("function_xrefs", {
                "name": name,
                "offset": offset,
                "limit": limit
            })
            try:
                return response.json()
            except Exception:
                return response.text.strip().split("\n")
        except Exception as e:
            logger.error(f"Error getting function_xrefs for {name}: {e}")
            return []

    def list_strings(self, offset: int = 0, limit: int = 2000, filter: Optional[str] = None) -> Union[List[Any], str]:
        """List program strings (with optional filter text).

        Args:
            offset: Pagination offset
            limit: Maximum number of strings to return (Ghidra default large value 2000)
            filter: Optional substring to match within string contents
        """
        params = {"offset": offset, "limit": limit}
        if filter:
            params["filter"] = filter
        try:
            response = self._get_request("strings", params)
            try:
                return response.json()
            except Exception:
                return response.text.strip().split("\n")
        except Exception as e:
            logger.error(f"Error listing strings: {e}")
            return []
    
    def list_segments(self, offset: int = 0, limit: int = 100) -> List[str]:
        """
        Lists all memory segments in the program with pagination.
        
        Args:
            offset: Offset to start from
            limit: Maximum number of results
            
        Returns:
            List of memory segment information
        """
        try:
            response = self._get_request("segments", {
                "offset": offset,
                "limit": limit
            })
            # Parse the response - assuming it's JSON
            try:
                return response.json()
            except:
                # If the response isn't JSON, try parsing it as text
                return response.text.strip().split('\n')
        except Exception as e:
            logger.error(f"Error listing segments: {e}")
            return []
    
    def search_functions_by_name(self, query: str, offset: int = 0, limit: int = 100) -> List[str]:
        """
        Searches for functions by name substring.
        
        Args:
            query: Search query string
            offset: Offset to start from
            limit: Maximum number of results
            
        Returns:
            List of matching function names
        """
        try:
            response = self._get_request("functions/search", {
                "query": query,
                "offset": offset,
                "limit": limit
            })
            # Parse the response - assuming it's JSON
            try:
                return response.json()
            except:
                # If the response isn't JSON, try parsing it as text
                return response.text.strip().split('\n')
        except Exception as e:
            logger.error(f"Error searching functions by name: {e}")
            return []
    
    def get_current_function(self) -> str:
        """
        Gets the function at the current cursor position or selection in Ghidra.
        
        Returns:
            Function address and name
        """
        try:
            response = self._get_request("current/function")
            # Parse the response - assuming it's JSON
            try:
                return response.json()
            except:
                # If the response isn't JSON, return it as text
                return response.text
        except Exception as e:
            logger.error(f"Error getting current function: {e}")
            return f"Error: {e}"
    
    def get_current_address(self) -> str:
        """
        Gets the address at the current cursor position in Ghidra.
        
        Returns:
            Current address
        """
        try:
            response = self._get_request("current/address")
            # Parse the response - assuming it's JSON
            try:
                return response.json()
            except:
                # If the response isn't JSON, return it as text
                return response.text
        except Exception as e:
            logger.error(f"Error getting current address: {e}")
            return f"Error: {e}"
    
    def get_bytes(self, address: str, length: int = 16) -> str:
        """
        Gets raw bytes at a specific address.
        
        Args:
            address: The address to read from
            length: Number of bytes to read
            
        Returns:
            Hexadecimal string of bytes
        """
        try:
            response = self._get_request(f"bytes/{address}/{length}")
            return response.text
        except Exception as e:
            logger.error(f"Error getting bytes at address {address}: {e}")
            return f"Error: {e}"
    
    def get_labels(self) -> List[str]:
        """
        Gets all labels in the program.
        
        Returns:
            List of labels
        """
        try:
            response = self._get_request("labels")
            return response.text.strip().split('\n')
        except Exception as e:
            logger.error(f"Error getting labels: {e}")
            return []
    
    def get_structures(self) -> str:
        """
        Gets data structures information.
        
        Returns:
            Data structures information
        """
        try:
            response = self._get_request("structures")
            return response.text
        except Exception as e:
            logger.error(f"Error getting structures: {e}")
            return f"Error: {e}"

# Example usage
if __name__ == "__main__":
    client = GhidraMCPClient()
    
    try:
        print("Listing functions:")
        functions = client.list_functions()
        for i, func in enumerate(functions[:5]):  # Show first 5 functions
            print(f"  {i+1}. {func}")
        
        if functions:
            print(f"\nDecompiling first function: {functions[0]}")
            decompiled = client.decompile_function(functions[0])
            print(decompiled[:500] + "..." if len(decompiled) > 500 else decompiled)
            
            # Test renaming function
            first_function = functions[0]
            new_name = f"{first_function}_test"
            print(f"\nRenaming {first_function} to {new_name}")
            result = client.rename_function(first_function, new_name)
            print(f"Result: {result}")
            
            # Rename back
            print(f"\nRenaming {new_name} back to {first_function}")
            result = client.rename_function(new_name, first_function)
            print(f"Result: {result}")
        
        # Test getting bytes
        if functions and '_' in functions[0]:
            address = functions[0].split('_')[1]
            print(f"\nGetting bytes at address {address}:")
            bytes_data = client.get_bytes(address, 16)
            print(bytes_data)
        
        # Test getting structures
        print("\nGetting data structures:")
        structures = client.get_structures()
        print(structures[:500] + "..." if len(structures) > 500 else structures)
        
    except Exception as e:
        print(f"Error: {e}") 