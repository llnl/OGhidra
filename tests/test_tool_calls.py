#!/usr/bin/env python3
"""
Comprehensive test script for verifying all GhidraMCP tool call capabilities.
This script directly tests the methods available in GhidraMCPClient that our AI agent uses to interact with Ghidra.
"""

import json
import sys
import os
import inspect
import traceback
import argparse
from typing import Dict, List, Any, Optional, Set
import logging
import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

class ToolCapabilityTester:
    """Tester for verifying all Ghidra tool call capabilities."""
    
    def __init__(self, base_url: str = "http://localhost:8080"):
        """Initialize the tester with the GhidraMCP server URL."""
        self.base_url = base_url
        self.client = None
        self.available_tools = []
        self.test_results = {}
        self.available_functions = []
        self.available_addresses = []
        
        # Set up basic parameter values for testing various functions
        self.test_data = {
            "function_name": "",
            "function_address": "",
            "comment": "Test comment added by API test",
            "prototype": "void test_function(int param1, char* param2)",
            "variable_name": "local_10",
            "new_type": "char*",
            "string_query": "test" # Added for list_strings, though it doesn't take a query
        }
        
        # Initialize the client
        self._initialize_client()
    
    def _initialize_client(self) -> None:
        """Initialize the GhidraMCPClient."""
        try:
            # Add the parent directory to sys.path to import from src
            sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
            from src.ghidra_client import GhidraMCPClient
            from src.config import GhidraMCPConfig
            
            # Create a config
            config = GhidraMCPConfig()
            config.base_url = self.base_url
            
            # Create a client instance
            self.client = GhidraMCPClient(config)
            
            # Get all public methods
            self.available_tools = [name for name in dir(self.client) 
                                   if not name.startswith('_') and callable(getattr(self.client, name))]
            
            print(f"Successfully initialized GhidraMCPClient with {len(self.available_tools)} available tools")
        except Exception as e:
            print(f"Failed to initialize GhidraMCPClient: {str(e)}")
            traceback.print_exc()
            sys.exit(1)
    
    def gather_function_data(self) -> None:
        """Gather function names and addresses for testing."""
        try:
            # Get list of methods/functions
            methods = self.client.list_methods()
            if methods:
                self.available_functions = methods
                
                # Extract addresses from function names (e.g., FUN_140001030)
                for method in methods:
                    if '_' in method:
                        try:
                            address = method.split('_')[1]
                            if all(c in '0123456789abcdefABCDEF' for c in address):
                                self.available_addresses.append(address)
                        except:
                            pass
                
                # Set sample function name and address for tests
                if self.available_functions:
                    self.test_data["function_name"] = self.available_functions[0]
                if self.available_addresses:
                    self.test_data["function_address"] = self.available_addresses[0]
                
                print(f"Found {len(self.available_functions)} functions and {len(self.available_addresses)} addresses for testing")
                print(f"Sample function: {self.test_data['function_name']}")
                print(f"Sample address: {self.test_data['function_address']}")
            else:
                print("No functions found. Testing will be limited.")
        except Exception as e:
            print(f"Error gathering function data: {str(e)}")
            traceback.print_exc()
    
    def get_function_parameters(self, func) -> Dict[str, Dict[str, Any]]:
        """Get the parameters of a function and their details."""
        params = {}
        try:
            sig = inspect.signature(func)
            for name, param in sig.parameters.items():
                if name == 'self':
                    continue
                
                params[name] = {
                    'default': None if param.default is inspect.Parameter.empty else param.default,
                    'required': param.default is inspect.Parameter.empty,
                    'annotation': str(param.annotation) if param.annotation is not inspect.Parameter.empty else 'Any'
                }
        except Exception as e:
            logger.warning(f"Error getting parameters for function: {str(e)}")
            
        return params
    
    def prepare_test_params(self, tool_name: str, params_info: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Prepare test parameters for a tool based on its signature."""
        test_params = {}
        
        # Map of parameter names to values in test_data
        param_mapping = {
            'name': 'function_name',
            'old_name': 'function_name', 
            'new_name': 'function_name_renamed',
            'address': 'function_address',
            'function_address': 'function_address',
            'comment': 'comment',
            'prototype': 'prototype',
            'variable_name': 'variable_name',
            'function_name': 'function_name',
            'new_type': 'new_type',
            'query': 'function_name',
            'offset': 0,
            'limit': 10
        }
        
        # Add a renamed function version
        self.test_data['function_name_renamed'] = f"{self.test_data['function_name']}_renamed_test"
        
        # Fill in parameters based on mapping
        for param_name, param_info in params_info.items():
            if param_name in param_mapping:
                # Use the mapped value from test_data
                mapped_key = param_mapping[param_name]
                if mapped_key in self.test_data:
                    test_params[param_name] = self.test_data[mapped_key]
                else:
                    # For direct values like offset, limit
                    test_params[param_name] = mapped_key
            elif not param_info['required']:
                # Use default for optional parameters
                test_params[param_name] = param_info['default']
        
        # Special handling for specific tools
        if tool_name == 'rename_function':
            if 'new_name' in test_params:
                test_params['new_name'] = f"{self.test_data['function_name']}_renamed_test"
        elif tool_name == 'rename_function_by_address':
            if 'new_name' in test_params:
                test_params['new_name'] = f"func_{self.test_data['function_address']}_renamed_test"
        
        return test_params
    
    def test_tool(self, tool_name: str) -> Dict[str, Any]:
        """Test a specific tool by calling it with appropriate parameters."""
        if not self.client or not hasattr(self.client, tool_name):
            return {
                "success": False,
                "error": f"Tool {tool_name} not found or client not initialized",
                "parameters": {}
            }
        
        func = getattr(self.client, tool_name)
        params_info = self.get_function_parameters(func)
        test_params = self.prepare_test_params(tool_name, params_info)
        
        try:
            print(f"Testing {tool_name} with parameters: {test_params}")
            
            # Call the function
            result = func(**test_params)
            
            # Format the result for display
            if isinstance(result, list):
                display_result = result[:5] if len(result) > 5 else result
                if len(result) > 5:
                    display_result.append("... truncated ...")
            else:
                display_result = str(result)[:300] + ("..." if len(str(result)) > 300 else "")
            
            return {
                "success": True,
                "parameters": test_params,
                "parameters_info": params_info,
                "result": result,
                "display_result": display_result,
                "result_type": type(result).__name__,
                "signature": str(inspect.signature(func)),
                "docstring": inspect.getdoc(func)
            }
        except Exception as e:
            return {
                "success": False,
                "parameters": test_params,
                "parameters_info": params_info,
                "error": str(e),
                "traceback": traceback.format_exc(),
                "signature": str(inspect.signature(func)),
                "docstring": inspect.getdoc(func)
            }
    
    def run_all_tests(self, specific_tools: Optional[List[str]] = None) -> Dict[str, Dict[str, Any]]:
        """Run tests for all available tools or specific tools if provided."""
        tools_to_test = specific_tools if specific_tools else self.available_tools
        
        # Test basic functions first to gather data for other tests
        basic_tools = [
            'check_health', 'list_methods', 'get_current_function', 
            'list_functions', 'list_strings' # Added list_strings
        ]
        
        # Start with basic tools
        for tool in basic_tools:
            if tool in tools_to_test:
                self.test_results[tool] = self.test_tool(tool)
                
        # Gather function data if not already available
        if not self.available_functions or not self.available_addresses:
            self.gather_function_data()
        
        # Test remaining tools
        for tool in tools_to_test:
            if tool not in self.test_results and tool not in ['safe_get', 'safe_post']:
                self.test_results[tool] = self.test_tool(tool)
        
        return self.test_results
    
    def print_test_summary(self) -> None:
        """Print a summary of test results."""
        successful = 0
        failed = 0
        
        print("\n=== GhidraMCP Tool Call Test Summary ===")
        print(f"Tested {len(self.test_results)} tools:")
        
        # Group by success/failure
        successful_tools = []
        failed_tools = []
        
        for tool_name, result in self.test_results.items():
            if result["success"]:
                successful += 1
                successful_tools.append(tool_name)
            else:
                failed += 1
                failed_tools.append((tool_name, result.get("error", "Unknown error")))
        
        # Print successful tools
        if successful_tools:
            print(f"\n✅ {successful} Successful Tool Calls:")
            for tool in successful_tools:
                params = self.test_results[tool]["parameters"]
                param_str = ", ".join([f"{k}={v}" for k, v in params.items()])
                result_type = self.test_results[tool]["result_type"]
                print(f"  - {tool}({param_str}) -> {result_type}")
        
        # Print failed tools
        if failed_tools:
            print(f"\n❌ {failed} Failed Tool Calls:")
            for tool, error in failed_tools:
                params = self.test_results[tool]["parameters"]
                param_str = ", ".join([f"{k}={v}" for k, v in params.items()])
                print(f"  - {tool}({param_str}): {error}")
        
        # Print success rate
        if self.test_results:
            success_rate = (successful / len(self.test_results)) * 100
            print(f"\nOverall Success Rate: {success_rate:.2f}%")
        
        print("\n=== End of Summary ===")
    
    def generate_documentation(self, output_file: Optional[str] = "tool_capabilities.md") -> None:
        """Generate comprehensive documentation for available tools."""
        if not output_file:
            return
            
        with open(output_file, "w", encoding="utf-8") as f:
            f.write("# GhidraMCP Tool Capabilities\n\n")
            f.write("This document provides a comprehensive list of all available tools in the GhidraMCP API.\n\n")
            
            f.write("## Tool Overview\n\n")
            f.write("| Tool | Description | Parameters | Return Type | Test Status |\n")
            f.write("|------|-------------|------------|-------------|-------------|\n")
            
            for tool_name in sorted(self.available_tools):
                if tool_name not in self.test_results:
                    continue
                    
                result = self.test_results[tool_name]
                docstring = result.get("docstring", "No description available").split('\n')[0]
                params = ", ".join([f"{name}" for name in result.get("parameters_info", {}).keys()])
                return_type = result.get("signature", "").split("->")[1].strip() if "->" in result.get("signature", "") else "Unknown"
                status = "✅ Success" if result.get("success", False) else "❌ Failed"
                
                f.write(f"| {tool_name} | {docstring} | {params} | {return_type} | {status} |\n")
            
            f.write("\n## Detailed Tool Documentation\n\n")
            
            for tool_name in sorted(self.available_tools):
                if tool_name not in self.test_results:
                    continue
                    
                result = self.test_results[tool_name]
                
                f.write(f"### {tool_name}\n\n")
                
                # Write docstring
                if result.get("docstring"):
                    f.write(f"{result['docstring']}\n\n")
                else:
                    f.write("No description available.\n\n")
                
                # Write signature
                f.write("**Signature:**\n```python\n")
                f.write(f"{tool_name}{result.get('signature', '')}\n")
                f.write("```\n\n")
                
                # Write parameters
                f.write("**Parameters:**\n")
                params_info = result.get("parameters_info", {})
                if params_info:
                    f.write("| Name | Required | Default | Type |\n")
                    f.write("|------|----------|---------|------|\n")
                    for name, info in params_info.items():
                        required = "Yes" if info.get("required", False) else "No"
                        default = str(info.get("default", "None"))
                        param_type = info.get("annotation", "Any")
                        f.write(f"| {name} | {required} | {default} | {param_type} |\n")
                else:
                    f.write("No parameters.\n")
                f.write("\n")
                
                # Write test results
                f.write("**Test Results:**\n")
                if result.get("success", False):
                    f.write("- Status: ✅ Success\n")
                    f.write(f"- Return Type: {result.get('result_type', 'Unknown')}\n")
                    f.write("- Sample Result:\n")
                    f.write("```\n")
                    if isinstance(result.get("display_result"), list):
                        for item in result.get("display_result", []):
                            f.write(f"{item}\n")
                    else:
                        f.write(f"{result.get('display_result', 'No result')}\n")
                    f.write("```\n")
                else:
                    f.write("- Status: ❌ Failed\n")
                    f.write(f"- Error: {result.get('error', 'Unknown error')}\n")
                
                f.write("\n---\n\n")
            
            f.write("## Calling Tools from AI Agent\n\n")
            f.write("When using these tools from the AI agent, use the following format:\n\n")
            f.write("```\nEXECUTE: tool_name(param1=\"value1\", param2=\"value2\")\n```\n\n")
            f.write("For example:\n\n")
            f.write("```\nEXECUTE: decompile_function(name=\"main\")\n```\n\n")
            
            # Get current date and time
            current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            f.write("## Generated Documentation\n\n")
            f.write(f"This documentation was automatically generated by the ToolCapabilityTester on {current_time}.\n")
        
        print(f"Documentation generated: {output_file}")

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Test GhidraMCP tool call capabilities")
    parser.add_argument("--url", default="http://localhost:8080", help="URL of the Ghidra MCP server")
    parser.add_argument("--tool", action="append", help="Specific tool(s) to test")
    parser.add_argument("--doc", default="tool_capabilities.md", help="Output documentation file")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    parser.add_argument("--no-doc", action="store_true", help="Skip documentation generation")
    args = parser.parse_args()
    
    # Initialize the tester
    tester = ToolCapabilityTester(args.base_url if hasattr(args, 'base_url') else args.url)
    
    # Run tests
    results = tester.run_all_tests(args.tool)
    
    # Print test summary
    tester.print_test_summary()
    
    # Generate documentation
    if not args.no_doc:
        tester.generate_documentation(args.doc)
    
    # Output as JSON if requested
    if args.json:
        print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main() 