#!/usr/bin/env python3
"""
Test script for the GhidraMCP API to verify the communication endpoints
used by our AI agent. This script is focused on understanding which endpoints
actually work and how they should be properly called.
"""

import json
import requests
import argparse
import sys
import traceback
import inspect
import os
from typing import Dict, List, Any, Optional
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

class GhidraMCPTester:
    def __init__(self, base_url: str = "http://localhost:8080"):
        """Initialize the tester with the GhidraMCP server URL."""
        self.base_url = base_url
        self.available_functions = []
        self.available_addresses = []
        
    def test_methods(self) -> Dict[str, Any]:
        """Test the /methods endpoint which returns available functions."""
        try:
            response = requests.get(f"{self.base_url}/methods")
            response.raise_for_status()
            
            # Response is a text list of method names, one per line
            methods = response.text.strip().split('\n')
            self.available_functions = methods
            
            # Try to extract addresses from function names (assuming format like FUN_140001030)
            for method in methods:
                if '_' in method:
                    try:
                        address = method.split('_')[1]
                        if all(c in '0123456789abcdefABCDEF' for c in address):
                            self.available_addresses.append(address)
                    except:
                        pass
            
            return {
                "success": True,
                "data": methods,
                "type": "string[]",
                "description": "Returns list of all function names in the program"
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def test_direct_tool_call(self, tool_name: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Test calling a tool directly, simulating how the Bridge class would call it.
        
        Args:
            tool_name: The name of the tool to call
            params: The parameters to pass to the tool
            
        Returns:
            Dictionary with the result
        """
        if params is None:
            params = {}
            
        try:
            # Try to import the GhidraMCPClient directly to see how it calls methods
            sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
            from src.ghidra_client import GhidraMCPClient
            from src.config import GhidraMCPConfig
            
            # Create a config
            config = GhidraMCPConfig()
            config.base_url = self.base_url
            
            # Create a client instance
            client = GhidraMCPClient(config)
            
            # Check if the tool exists
            if not hasattr(client, tool_name):
                return {
                    "success": False,
                    "error": f"Tool {tool_name} does not exist in GhidraMCPClient"
                }
                
            # Get the tool function
            tool_func = getattr(client, tool_name)
            
            # Get the function signature for better error messages
            sig = inspect.signature(tool_func)
            
            # Call the tool
            result = tool_func(**params)
            
            # Format the result
            if isinstance(result, list):
                display_result = result[:5] if len(result) > 5 else result
                if len(result) > 5:
                    display_result.append("... truncated ...")
            else:
                display_result = result
                
            return {
                "success": True,
                "data": result,
                "display_data": display_result,
                "type": type(result).__name__,
                "description": f"Direct call to {tool_name} with params {params}",
                "signature": str(sig)
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "traceback": traceback.format_exc()
            }
    
    def run_tests(self, specific_tools=None):
        """
        Run tests for either specific tools or a pre-defined set of common tools.
        
        Args:
            specific_tools: Optional list of specific tools to test
            
        Returns:
            Dictionary of test results
        """
        # First get methods to populate available functions and addresses
        methods_result = self.test_methods()
        results = {"methods": methods_result}
        
        print(f"\n=== Methods Test ===")
        if methods_result["success"]:
            print(f"✅ Success: Found {len(self.available_functions)} functions")
            print(f"Sample functions: {self.available_functions[:5]}")
        else:
            print(f"❌ Failed: {methods_result['error']}")
            return results  # Exit early if methods test fails
        
        # Define tools to test (either from parameter or default list)
        test_tools = []
        if specific_tools:
            test_tools = specific_tools
        else:
            # Default tools to test - these should cover most functionality
            test_tools = [
                {"name": "list_methods", "params": {"offset": 0, "limit": 10}},
                {"name": "get_current_function", "params": {}},
                {"name": "list_functions", "params": {}}
            ]
            
            # Add a test with the first available address if we have one
            if self.available_addresses:
                addr = self.available_addresses[0]
                test_tools.append({"name": "decompile_function_by_address", "params": {"address": addr}})
                
            # Add a test with the first available function if we have one
            if self.available_functions:
                func = self.available_functions[0]
                test_tools.append({"name": "decompile_function", "params": {"name": func}})
                
        # Run tests for each tool
        for tool in test_tools:
            tool_name = tool["name"] if isinstance(tool, dict) else tool
            params = tool.get("params", {}) if isinstance(tool, dict) else {}
            
            print(f"\n=== Testing {tool_name} ===")
            print(f"Parameters: {params}")
            
            result = self.test_direct_tool_call(tool_name, params)
            results[tool_name] = result
            
            if result["success"]:
                print(f"✅ Success")
                print(f"Return Type: {result['type']}")
                print(f"Function Signature: {result.get('signature', 'unknown')}")
                print(f"Sample Data: {json.dumps(result.get('display_data', 'No data'), indent=2)[:200]}")
            else:
                print(f"❌ Failed: {result['error']}")
                if "traceback" in result:
                    tb_lines = result["traceback"].split("\n")
                    # Print the last 5 lines of the traceback
                    print("Traceback summary:")
                    for line in tb_lines[-5:]:
                        print(f"  {line}")
            
            print("-" * 50)
        
        return results

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Test the Ghidra MCP API to understand how tools are called")
    parser.add_argument("--url", default="http://localhost:8080", help="URL of the Ghidra MCP server")
    parser.add_argument("--tool", action="append", help="Specific tool(s) to test")
    parser.add_argument("--param", action="append", help="Parameters for the tool(s) in key=value format")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    args = parser.parse_args()
    
    tester = GhidraMCPTester(args.url)
    
    # If specific tools were specified, parse them and their parameters
    specific_tools = None
    if args.tool:
        specific_tools = []
        params_dict = {}
        
        # Parse parameters if provided
        if args.param:
            for param in args.param:
                if "=" in param:
                    key, value = param.split("=", 1)
                    params_dict[key.strip()] = value.strip()
        
        # Create tool entries
        for tool_name in args.tool:
            specific_tools.append({
                "name": tool_name,
                "params": params_dict
            })
    
    # Run tests
    results = tester.run_tests(specific_tools)
    
    # Output as JSON if requested
    if args.json:
        print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main() 