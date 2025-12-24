#!/usr/bin/env python3
"""
Main entry point for the Ollama-GhidraMCP Bridge application.
"""

import os
import sys
import argparse
import json
from dotenv import load_dotenv

# Load environment variables from .env file if present
load_dotenv()

# Import after loading environment variables
from src.config import get_config, BridgeConfig
from src.bridge import Bridge
from src.ollama_client import OllamaClient
from src.ghidra_client import GhidraMCPClient

def print_header():
    """Print the application header."""
    width = 70
    header = [
        "OGhidra - Simplified Three-Phase Architecture",
        "------------------------------------------",
        "",
        "1. Planning Phase: Create a plan for addressing the query",
        "2. Tool Calling Phase: Execute tools to gather information",
        "3. Analysis Phase: Analyze results and provide answers",
        "",
        "For more information, see README-ARCHITECTURE.md"
    ]
    
    print('+' + '-' * (width - 2) + '+')
    for line in header:
        padding = (width - 2 - len(line))
        left_padding = padding // 2
        right_padding = padding - left_padding
        print('|' + ' ' * left_padding + line + ' ' * right_padding + '|')
    print('+' + '-' * (width - 2) + '+')

def run_interactive_mode(bridge: Bridge, config: BridgeConfig):
    """Run the bridge in interactive mode."""
    print("Ollama-GhidraMCP Bridge (Interactive Mode)")
    print(f"Default model: {bridge.ollama.config.model if hasattr(bridge, 'ollama') and hasattr(bridge.ollama, 'config') else config.ollama.model}") 
    
    # Initialize a list to store outputs from the current session for review
    current_session_log = []

    while True:
        try:
            user_input = input("Query (or 'exit', 'help', 'health', 'analyze-function', 'enumerate-binary', 'review-session'): ")
            if not user_input:
                continue

            if user_input.lower() in ('exit', 'quit'): # Allow 'quit' as well
                break
            elif user_input.lower() == 'health':
                # Check Ollama and GhidraMCP health
                # Corrected: Use bridge.ollama and bridge.ghidra
                ollama_health = bridge.ollama.check_health() if hasattr(bridge, 'ollama') else False
                ghidra_health = bridge.ghidra.check_health() if hasattr(bridge, 'ghidra') else False
                
                print("\n=== Health Check ===")
                print(f"Ollama API: {'OK' if ollama_health else 'NOT OK'}")
                print(f"GhidraMCP API: {'OK' if ghidra_health else 'NOT OK'}")
                print("====================\n")
                
                # Display vector store information if CAG is enabled
                if bridge.enable_cag and bridge.cag_manager:
                    print("\n=== Vector Store Information ===")
                    # Get vector store info from bridge
                    try:
                        vector_store_enabled = config.session_history.use_vector_embeddings if hasattr(config, 'session_history') else False
                        print(f"Vector embeddings: {'Enabled ✅' if vector_store_enabled else 'Disabled ❌'}")
                        
                        if vector_store_enabled and hasattr(bridge, 'memory_manager') and bridge.memory_manager is not None:
                            mm = bridge.memory_manager
                            if mm.vector_store:
                                vector_count = mm.vector_store.vectors.shape[0] if (hasattr(mm.vector_store, 'vectors') and 
                                                                               mm.vector_store.vectors is not None) else 0
                                print(f"Vectors available: {'Yes ✅' if vector_count > 0 else 'No ❌'}")
                                print(f"Vector count: {vector_count}")
                                
                                if vector_count > 0:
                                    print(f"Vector dimension: {mm.vector_store.vectors.shape[1]}")
                                    # Calculate mean norm
                                    import numpy as np
                                    norms = np.linalg.norm(mm.vector_store.vectors, axis=1)
                                    print(f"Mean vector norm: {float(np.mean(norms)):.4f}")
                                    
                                    # Show session IDs if available
                                    if hasattr(mm.vector_store, 'get_session_ids'):
                                        session_ids = mm.vector_store.get_session_ids()
                                        if session_ids:
                                            print(f"\nStored Session IDs ({len(session_ids)}):")
                                            for i, sid in enumerate(session_ids[:5]):  # Show first 5
                                                print(f"  {i+1}. {sid}")
                                            if len(session_ids) > 5:
                                                print(f"  ... and {len(session_ids) - 5} more")
                    except Exception as e:
                        print(f"Error displaying vector store info: {e}")
                    
                    print("===============================\n")
                continue
            elif user_input.lower() == 'vector-store':
                # Add dedicated command for vector store inspection
                print("\n=== Vector Store Information ===")
                # Get vector store info from bridge
                try:
                    vector_store_enabled = config.session_history.use_vector_embeddings if hasattr(config, 'session_history') else False
                    print(f"Vector embeddings: {'Enabled ✅' if vector_store_enabled else 'Disabled ❌'}")
                    
                    if vector_store_enabled and hasattr(bridge, 'memory_manager') and bridge.memory_manager is not None:
                        mm = bridge.memory_manager
                        if mm.vector_store:
                            vector_count = mm.vector_store.vectors.shape[0] if (hasattr(mm.vector_store, 'vectors') and 
                                                                           mm.vector_store.vectors is not None) else 0
                            print(f"Vectors available: {'Yes ✅' if vector_count > 0 else 'No ❌'}")
                            print(f"Vector count: {vector_count}")
                            
                            if vector_count > 0:
                                print(f"Vector dimension: {mm.vector_store.vectors.shape[1]}")
                                # Calculate mean norm
                                import numpy as np
                                norms = np.linalg.norm(mm.vector_store.vectors, axis=1)
                                print(f"Mean vector norm: {float(np.mean(norms)):.4f}")
                                
                                # Show session IDs if available
                                if hasattr(mm.vector_store, 'get_session_ids'):
                                    session_ids = mm.vector_store.get_session_ids()
                                    if session_ids:
                                        print(f"\nStored Session IDs ({len(session_ids)}):")
                                        for i, sid in enumerate(session_ids):
                                            print(f"  {i+1}. {sid}")
                except Exception as e:
                    print(f"Error displaying vector store info: {e}")
                
                print("===============================\n")
                continue
            elif user_input.lower() == 'models':
                # List available models
                # Corrected: Use bridge.ollama
                models = bridge.ollama.list_models() if hasattr(bridge, 'ollama') else []
                
                print("\n=== Available Models ===")
                for model in models:
                    print(f"- {model}")
                print("========================\n")
                continue
            elif user_input.lower() == 'tools':
                # Display all available Ghidra tools and their parameters
                print("\n=== Available Ghidra Tools ===")
                
                try:
                    # Corrected: Use bridge.ghidra
                    client = bridge.ghidra if hasattr(bridge, 'ghidra') else GhidraMCPClient(config.ghidra) # Fallback if bridge.ghidra not init
                    
                    # Get all public methods (excluding those starting with _ and known non-tools)
                    non_tool_methods = ['check_health', 'get_config', 'is_mock_mode', 'base_url', 'timeout', 'api_path', 'config']
                    tools = [name for name in dir(client) if not name.startswith('_') and callable(getattr(client, name)) and name not in non_tool_methods]
                    
                    print(f"Found {len(tools)} available tools (via run-tool command):\n")
                    
                    for tool_name in sorted(tools):
                        tool_func = getattr(client, tool_name)
                        import inspect
                        signature = inspect.signature(tool_func)
                        params_desc = []
                        for param_name, param in signature.parameters.items():
                            if param_name == 'self': continue
                            if param.default is inspect.Parameter.empty:
                                params_desc.append(f"{param_name} (required)")
                            else:
                                default_val_str = f"\'{param.default}\'" if isinstance(param.default, str) else str(param.default)
                                params_desc.append(f"{param_name}={default_val_str}")
                        
                        doc = tool_func.__doc__.strip().split('\n')[0] if tool_func.__doc__ else "No description available"
                        print(f"  {tool_name}({', '.join(params_desc)})")
                        print(f"    {doc}")
                        print()
                except Exception as e:
                    print(f"Error loading tools: {str(e)}")
                print("===========================\n")
                continue
            elif user_input.lower() == 'cag': # Restored CAG command
                print("\n=== CAG Status ===")
                # Use bridge.enable_cag for the overall status
                print(f"CAG System Enabled: {'Yes' if bridge.enable_cag else 'No'}")
                
                if bridge.enable_cag and bridge.cag_manager:
                    # Get detailed info from the CAGManager
                    cag_details = bridge.cag_manager.get_debug_info()
                    
                    # Knowledge Base status from cag_details
                    kb_enabled = cag_details.get('enable_kb', False)
                    print(f"Knowledge Base Enabled (within CAG): {'Yes' if kb_enabled else 'No'}")
                    if kb_enabled and 'vector_store' in cag_details:
                        vs_info = cag_details['vector_store']
                        print(f"  Vector Store - Function Signatures: {vs_info.get('function_signatures', 0)}")
                        print(f"  Vector Store - Binary Patterns: {vs_info.get('binary_patterns', 0)}")
                        print(f"  Vector Store - Analysis Rules: {vs_info.get('analysis_rules', 0)}")
                        print(f"  Vector Store - Common Workflows: {vs_info.get('common_workflows', 0)}")

                    # Session Cache status from cag_details
                    session_cache_info = cag_details.get('session_cache')
                    if session_cache_info:
                        print(f"Session Cache Active: {'Yes' if session_cache_info else 'No'}")
                        print(f"  Session ID: {session_cache_info.get('session_id', 'N/A')}")
                        print(f"  Context History Items: {session_cache_info.get('context_history', 0)}")
                        print(f"  Decompiled Functions: {session_cache_info.get('decompiled_functions', 0)}")
                        print(f"  Renamed Entities: {session_cache_info.get('renamed_entities', 0)}")
                        print(f"  Analysis Results Cached: {session_cache_info.get('analysis_results', 0)}")
                    else:
                        print(f"Session Cache Active: No")
                    
                    # Token limit is part of BridgeConfig, not CAGManager debug info directly
                    # However, the cag_manager might have its own internal token limits for enhancement logic
                    # For now, we assume the relevant token limit for display is from the main config if needed.
                    # If cag_manager.config.token_limit exists, it could be displayed, but let's rely on BridgeConfig for overall settings.
                    if hasattr(bridge.config, 'cag_token_limit'): # Assuming token_limit is in BridgeConfig.cag_token_limit
                         print(f"CAG Token Limit (config): {bridge.config.cag_token_limit}")

                elif not bridge.enable_cag:
                    print("CAG System is disabled in the bridge configuration.")
                else: # bridge.enable_cag is true but no cag_manager (should not happen if init is correct)
                    print("CAG System is enabled but the manager is not available.")
                print("=================\n")
                continue
            elif user_input.lower() == 'help': # Restored help command
                print("\n=== Available Commands ===")
                print("\nMain Commands:")
                print("  help                              - Display this help message")
                print("  exit, quit                        - Exit the application")
                print("  health                            - Check API health and vector store status")
                print("\nAnalysis Commands:")
                print("  analyze-function [address]        - Analyze current function or specified address")
                print("  enumerate-binary                  - Full enumeration: analyze + rename all functions, load vectors")
                print("  review-session                    - Ask a query about the current session's interactions")
                print("\nAdvanced Commands (hidden from prompt):")
                print("  vector-store                      - Display detailed vector store information")
                print("  models                            - List available Ollama models")
                print("  tools                             - List all available Ghidra tools with parameters")
                print("  run-tool tool_name(p1='v1')       - Execute a specific Ghidra tool directly")
                print("  cag                               - Display Context-Aware Generation status")
                print("  clear_log                         - Clear the in-memory log for the current session review")
                print("\nℹ️  Any other input will be treated as a query to the AI agent.")
                print("=========================\n")
                continue
            elif user_input.lower().startswith('run-tool '):
                # Execute a specific tool directly
                tool_str = user_input[9:].strip()  # Remove 'run-tool ' prefix
                
                TOOLS_WITH_AI_ANALYSIS = [
                    "analyze_function", 
                    "decompile_function", "decompile_function_by_address",
                    "list_functions", 
                    "list_imports", 
                    "list_exports", 
                    "list_strings"
                ]

                try:
                    if '(' not in tool_str or ')' not in tool_str:
                        print("\nInvalid format. Use: run-tool tool_name(param1='value1', param2='value2')\n")
                        continue
                        
                    tool_name = tool_str[:tool_str.find('(')].strip()
                    raw_params_str = tool_str[tool_str.find('(')+1:tool_str.rfind(')')].strip()
                    
                    params = {}
                    if raw_params_str:
                        # Improved parameter parsing to handle various types and quotes robustly
                        param_pairs = []
                        buffer = ""
                        in_quotes = False
                        quote_char = ''
                        paren_level = 0
                        for char in raw_params_str:
                            if char == ',' and not in_quotes and paren_level == 0:
                                param_pairs.append(buffer)
                                buffer = ""
                                continue
                            buffer += char
                            if char in ('"', "'"):
                                if not in_quotes:
                                    in_quotes = True
                                    quote_char = char
                                elif char == quote_char: # Closing quote
                                    # Check if this quote is escaped
                                    if buffer.endswith(f'\\\\{quote_char}'): # Check for escaped quote like \\" or \\'
                                        pass # It's an escaped quote, part of the string
                                    else:
                                        in_quotes = False
                                        quote_char = ''
                            elif char == '(' and not in_quotes:
                                paren_level +=1
                            elif char == ')' and not in_quotes:
                                paren_level -=1
                        param_pairs.append(buffer) # Add the last parameter

                        for pair in param_pairs:
                            if '=' in pair:
                                key, value_str_full = pair.split('=', 1)
                                key = key.strip()
                                value_str_from_pair = value_str_full.strip()
                                
                                if (value_str_from_pair.startswith("'") and value_str_from_pair.endswith("'")) or \
                                   (value_str_from_pair.startswith('"') and value_str_from_pair.endswith('"')):
                                    final_value_for_param = value_str_from_pair[1:-1].encode('utf-8').decode('unicode_escape') # Handle escapes
                                else: # Try to infer type for unquoted values
                                    if value_str_from_pair.lower() == "true": final_value_for_param = True
                                    elif value_str_from_pair.lower() == "false": final_value_for_param = False
                                    elif value_str_from_pair.lower() == "none": final_value_for_param = None
                                    elif value_str_from_pair.isdigit(): # Positive integers
                                        final_value_for_param = int(value_str_from_pair)
                                    elif value_str_from_pair.startswith('-') and value_str_from_pair[1:].isdigit(): # Negative integers
                                        final_value_for_param = int(value_str_from_pair)
                                    else: # Default to string if no other type matches
                                        try: # Check for float
                                            final_value_for_param = float(value_str_from_pair)
                                        except ValueError:
                                            final_value_for_param = value_str_from_pair # Fallback to string
                                params[key] = final_value_for_param
                    
                    # Corrected: Use bridge.ghidra
                    if hasattr(bridge.ghidra, tool_name):
                        tool_method = getattr(bridge.ghidra, tool_name)
                        
                        params_for_log = ', '.join([f'{k}={repr(v)}' for k, v in params.items()])
                        bridge.logger.info(f"Executing direct tool call via 'run-tool': {tool_name} with params: {params}")
                        raw_tool_result = tool_method(**params)

                        if tool_name in TOOLS_WITH_AI_ANALYSIS:
                            is_error = isinstance(raw_tool_result, str) and raw_tool_result.lower().startswith("error:")
                            
                            if not is_error:
                                formatted_tool_data = ""
                                if isinstance(raw_tool_result, dict) or isinstance(raw_tool_result, list):
                                    try:
                                        formatted_tool_data = json.dumps(raw_tool_result, indent=2)
                                    except TypeError: # Handle non-serializable data
                                        formatted_tool_data = str(raw_tool_result)
                                else:
                                    formatted_tool_data = str(raw_tool_result)
                            
                                print(f"\n=== Raw Output from {tool_name} (to be sent to AI) ===")
                                print(formatted_tool_data)
                                print("===========================================================")
                                current_session_log.append(f"=== Raw Output from {tool_name}({params_for_log}) ===\\n{formatted_tool_data}\\n")

                                analysis_prompt = None
                                if tool_name == "analyze_function":
                                    analysis_prompt = (
                                        f"The Ghidra tool '{tool_name}' was executed (parameters: {params_for_log}). "
                                        f"Its output is below. Based *only* on this provided data:\\n"
                                        f"1. Identify the primary function being analyzed (name and address).\\n"
                                        f"2. Summarize its apparent purpose or main actions based on decompiled code snippets and called functions.\\n"
                                        f"3. List any notable cross-references (calls to other functions, or data references) mentioned in the output.\\n"
                                        f"4. Point out any immediate observations a reverse engineer might find interesting (e.g., unusual patterns, specific API calls, complex logic, potential vulnerabilities like buffer overflows, format string bugs, etc.).\\n"
                                        f"Tool Output:\\n```json\\n{formatted_tool_data}\\n```"
                                    )
                                elif tool_name in ["decompile_function", "decompile_function_by_address"]:
                                    func_id = params.get('name', params.get('address', 'unknown function'))
                                    analysis_prompt = (
                                        f"The Ghidra tool '{tool_name}' was executed for function '{func_id}'. Its output (decompiled C code) is below. "
                                        f"Based *only* on this provided code:\\n"
                                        f"1. Provide a concise summary of the function's apparent purpose in one or two sentences.\\n"
                                        f"2. List any parameters and the inferred return type if visible.\\n"
                                        f"3. Identify any notable loops, conditional statements, or complex logic.\\n"
                                        f"4. Are there any calls to other functions or standard library functions? If so, list a few key ones and their likely purpose in this context.\\n"
                                        f"5. Are there any obvious security concerns (e.g., use of unsafe functions like strcpy, potential buffer overflows, format string vulnerabilities, hardcoded secrets)?\\n"
                                        f"Tool Output:\\n```c\\n{formatted_tool_data}\\n```"
                                    )
                                elif tool_name == "list_functions":
                                    analysis_prompt = (
                                        f"The Ghidra tool '{tool_name}' was executed. Its output (a list of functions) is below. "
                                        f"Based *only* on this provided data:\\n"
                                        f"1. How many functions are listed in this segment of the output?\\n"
                                        f"2. Are there any common prefixes or naming patterns observed in the function names (e.g., FUN_, LAB_, sub_, user_defined_)?\\n"
                                        f"3. List 5-10 function names that seem particularly interesting or suggestive of the program's core functionality (e.g., 'encrypt_data', 'network_send', 'parse_input', 'main').\\n"
                                        f"4. Are there any functions that suggest error handling or utility routines?\\n"
                                        f"Tool Output:\\n```json\\n{formatted_tool_data}\\n```"
                                    )
                                elif tool_name == "list_imports":
                                    analysis_prompt = (
                                        f"The Ghidra tool '{tool_name}' was executed. Its output (a list of imported functions/symbols and their source libraries) is below. "
                                        f"Based *only* on this provided data:\\n"
                                        f"1. What are the top 3-5 DLLs (libraries) from which functions are most frequently imported, if discernible? List them.\\n"
                                        f"2. For each of these top DLLs, list 2-3 example functions imported from it.\\n"
                                        f"3. Based on the imported functions, what are some general capabilities this program likely possesses (e.g., file I/O, network communication, cryptography, UI interaction, registry access)?\\n"
                                        f"4. Are there any specific imported functions that might be particularly interesting or suspicious from a security or reverse engineering perspective (e.g., related to encryption, process injection, anti-debugging, networking)? List a few and briefly state why.\\n"
                                        f"Tool Output:\\n```json\\n{formatted_tool_data}\\n```"
                                    )
                                elif tool_name == "list_exports":
                                    analysis_prompt = (
                                        f"The Ghidra tool '{tool_name}' was executed. Its output (a list of exported functions/symbols) is below. "
                                        f"This indicates functions that the binary makes available for other modules to call. Based *only* on this provided data:\\n"
                                        f"1. How many functions/symbols are exported in this segment of the output?\\n"
                                        f"2. List 3-5 exported names that seem most significant or indicative of the library's/program's primary purpose.\\n"
                                        f"3. Do any of the export names suggest this is a library (DLL/SO) providing an API, or an executable with specific entry points?\\n"
                                        f"4. Are there any names that look like standard C/C++ mangled names, or are they mostly human-readable?\\n"
                                        f"Tool Output:\\n```json\\n{formatted_tool_data}\\n```"
                                    )
                                elif tool_name == "list_strings":
                                    analysis_prompt = f"""The Ghidra tool '{tool_name}' was executed. Its output (a list of strings found in the binary) is below. 
Based *only* on this provided data:
1. Are there any strings in this segment of output that look like file paths, URLs, or IP addresses?
2. Are there any error messages or debug messages shown?
3. Are there any strings shown that suggest user interface elements (e.g., button labels, menu items)?
4. Do any strings shown hint at specific functionalities (e.g., "Enter password", "Encryption key", "Connecting to server...")?
5. Are there any unusual or obfuscated-looking strings in this segment?
6. Most importantly, are there any malicious or suspicious strings?
7. What can we infer about the behavior of the binary based on the strings?
Tool Output:
```json
{formatted_tool_data}
```"""
                                
                                if analysis_prompt:
                                    print(f"Sending output from {tool_name} to AI for analysis...")
                                    try:
                                        ai_analysis = bridge.ollama.generate(prompt=analysis_prompt) if hasattr(bridge, 'ollama') else "Ollama client not available."
                                        
                                        bridge.logger.info(f"AI analysis received snippet: '{ai_analysis[:50]}...'")
                                        print(f"DEBUG: AI Response Type: {type(ai_analysis)}, Is None: {ai_analysis is None}, Is Empty Str: {ai_analysis == ''}, Length: {len(ai_analysis) if ai_analysis else 0}")

                                        if ai_analysis == "Ollama client not available.":
                                            print(f"\n{ai_analysis}")
                                            current_session_log.append(f"=== AI Analysis of {tool_name}({params_for_log}): Ollama client not available ===\\n")
                                        elif ai_analysis and ai_analysis.strip():
                                            print("\n=== AI Analysis of Function Output ===")
                                            print(ai_analysis)
                                            print("=====================================")
                                            current_session_log.append(f"=== AI Analysis of {tool_name}({params_for_log}) ===\\n{ai_analysis}\\n")
                                        else:
                                            print("\nAI analysis returned empty or whitespace-only response.")
                                            current_session_log.append(f"=== AI Analysis of {tool_name}({params_for_log}) returned empty. ===\\n")

                                    except Exception as e:
                                        print(f"Error during AI analysis: {e}")
                                        bridge.logger.error(f"Error during AI analysis for {tool_name}: {e}", exc_info=True)
                                        current_session_log.append(f"=== Error during AI analysis of {tool_name}({params_for_log}): {e} ===\\n")
                                else:
                                    print(f"No specific AI analysis prompt configured for tool: {tool_name}. Raw output printed above.")
                            else: # Error in raw_tool_result
                                print(f"Error from tool {tool_name}: {raw_tool_result}")
                                current_session_log.append(f"=== Error from tool {tool_name}({params_for_log}): {raw_tool_result} ===\\n")
                        else: # Tool not in TOOLS_WITH_AI_ANALYSIS or tool execution error already handled
                             print(f"\nResult of {tool_name}({raw_params_str}):\\n{raw_tool_result}\\n") # Print raw result if no AI analysis
                             current_session_log.append(f"=== Result of {tool_name}({params_for_log}) ===\\n{raw_tool_result}\\n")
                    else:
                        print(f"\nUnknown tool: {tool_name}. Type 'tools' for a list of available tools.\\n")
                        
                except Exception as e:
                    print(f"Error executing tool: {e}")
                    bridge.logger.error(f"Error executing tool '{tool_str}': {e}", exc_info=True)
                    current_session_log.append(f"=== Error executing tool command '{tool_str}': {e} ===\\n")
            
            elif user_input.lower().startswith('analyze-function'): # Restored analyze-function shortcut
                try:
                    address = None
                    # Define TOOLS_WITH_AI_ANALYSIS here or ensure it's accessible
                    # For this edit, let's define it locally if not already in scope
                    # Or better, ensure it's defined at a higher scope if used in multiple places
                    TOOLS_WITH_AI_ANALYSIS = [
                        "analyze_function", 
                        "decompile_function", "decompile_function_by_address",
                        "list_functions", 
                        "list_imports", 
                        "list_exports", 
                        "list_strings"
                    ]

                    if user_input.lower().startswith('analyze-function '):
                        address_part = user_input[len('analyze-function '):].strip()
                        if address_part: # Ensure address_part is not empty
                            address = address_part
                    
                    params_for_log = f"address={repr(address)}" if address else ""
                    print(f"\nExecuting: analyze_function({f'address=\\"{address}\\"' if address else ''})")
                    
                    raw_tool_result = bridge.ghidra.analyze_function(address=address) if hasattr(bridge, 'ghidra') else "Ghidra client not available."
                    
                    print("\n============================================================")
                    print(f"Results from analyze_function:")
                    print("============================================================")
                    current_session_log.append(f"=== Result of analyze-function({params_for_log}) ===\\n{raw_tool_result}\\n")
                    print(raw_tool_result) # Print raw output
                    print("============================================================\n")

                    # AI Analysis Step for analyze-function shortcut
                    if raw_tool_result != "Ghidra client not available." and not (isinstance(raw_tool_result, str) and raw_tool_result.lower().startswith("error:")):
                        formatted_tool_data = ""
                        if isinstance(raw_tool_result, dict) or isinstance(raw_tool_result, list):
                            try:
                                formatted_tool_data = json.dumps(raw_tool_result, indent=2)
                            except TypeError:
                                formatted_tool_data = str(raw_tool_result)
                        else:
                            formatted_tool_data = str(raw_tool_result)

                        analysis_prompt = (
                            f"The Ghidra tool 'analyze_function' was executed with parameters: ({params_for_log}). "
                            f"Its output is below. Based *only* on this provided data:\\n"
                            f"1. Identify the primary function being analyzed (name and address).\\n"
                            f"2. Summarize its apparent purpose or main actions based on decompiled code snippets and called functions.\\n"
                            f"3. List any notable cross-references (calls to other functions, or data references) mentioned in the output.\\n"
                            f"4. Point out any immediate observations a reverse engineer might find interesting (e.g., unusual patterns, specific API calls, complex logic, potential vulnerabilities like buffer overflows, format string bugs, etc.).\\n"
                            f"Tool Output:\\n```json\\n{formatted_tool_data}\\n```"
                        )
                        
                        print(f"Sending output from analyze-function to AI for analysis...")
                        try:
                            ai_analysis = bridge.ollama.generate(prompt=analysis_prompt) if hasattr(bridge, 'ollama') else "Ollama client not available."
                            
                            bridge.logger.info(f"AI analysis received snippet: '{ai_analysis[:50]}...'")
                            # print(f"DEBUG: AI Response Type: {type(ai_analysis)}, Is None: {ai_analysis is None}, Is Empty Str: {ai_analysis == ''}, Length: {len(ai_analysis) if ai_analysis else 0}")

                            if ai_analysis == "Ollama client not available.":
                                print(f"\n{ai_analysis}")
                                current_session_log.append(f"=== AI Analysis of analyze-function({params_for_log}): Ollama client not available ===\\n")
                            elif ai_analysis and ai_analysis.strip():
                                print("\n=== AI Analysis of Function Output ===")
                                print(ai_analysis)
                                print("=====================================")
                                current_session_log.append(f"=== AI Analysis of analyze-function({params_for_log}) ===\\n{ai_analysis}\\n")
                            else:
                                print("\nAI analysis returned empty or whitespace-only response.")
                                current_session_log.append(f"=== AI Analysis of analyze-function({params_for_log}) returned empty. ===\\n")

                        except Exception as e:
                            print(f"Error during AI analysis: {e}")
                            bridge.logger.error(f"Error during AI analysis for analyze-function shortcut: {e}", exc_info=True)
                            current_session_log.append(f"=== Error during AI analysis of analyze-function({params_for_log}): {e} ===\\n")
                    elif isinstance(raw_tool_result, str) and raw_tool_result.lower().startswith("error:"):
                         print(f"Skipping AI analysis due to tool error: {raw_tool_result}")
                    
                except Exception as e:
                    print(f"Error analyzing function: {str(e)}")
                    bridge.logger.error(f"Error in 'analyze-function' shortcut: {e}", exc_info=True)
                    current_session_log.append(f"=== Error in analyze-function shortcut: {e} ===\\n")
                continue # Keep continue for now, as this block is self-contained for analysis

            elif user_input.lower() == 'enumerate-binary':
                # Perform full binary enumeration: rename all functions + load vectors
                print("\n=== Enumerate Binary Workflow ===")
                print("This will perform the following operations:")
                print("1. Decompile all functions in the binary")
                print("2. Gather caller/callee context for each function")
                print("3. Analyze each function with AI using contextual information")
                print("4. Rename functions with generic names (FUN_, sub_, etc.) based on AI suggestions")
                print("5. Load all analyzed functions into the vector store for RAG queries")
                print("\nℹ️  Functions with descriptive names will be analyzed but NOT renamed.")
                print("⚠️  This may take considerable time depending on the number of functions.")
                print("    Expect ~3-8 seconds per function (includes context gathering).")
                
                confirm = input("\nDo you want to proceed? (yes/no): ")
                if confirm.lower() not in ('yes', 'y'):
                    print("Enumeration cancelled.")
                    continue
                
                try:
                    import time
                    start_time = time.time()
                    
                    # Step 1: Get all functions
                    print("\n[Step 1] Getting function list...")
                    functions_result = bridge.ghidra.list_functions() if hasattr(bridge, 'ghidra') else []
                    
                    if isinstance(functions_result, str) and functions_result.lower().startswith("error:"):
                        print(f"Error getting functions: {functions_result}")
                        continue
                    
                    # Parse function list
                    valid_functions = []
                    if isinstance(functions_result, list):
                        valid_functions = functions_result
                    elif isinstance(functions_result, str):
                        import re
                        # Parse format: "FUN_00401000 at 00401000"
                        function_lines = functions_result.strip().split('\n')
                        for line in function_lines:
                            line = line.strip()
                            if line and not line.startswith('=') and not line.startswith('-'):
                                valid_functions.append(line)
                    
                    if not valid_functions:
                        print("No functions found to enumerate.")
                        continue
                    
                    total_functions = len(valid_functions)
                    print(f"Found {total_functions} functions to enumerate.")
                    
                    # Step 2: Enumerate each function (full enumeration mode)
                    print(f"\n[Step 2] Enumerating all {total_functions} functions...")
                    successful_enumerations = 0
                    failed_enumerations = 0
                    processed_functions_data = []
                    
                    for i, full_function_string in enumerate(valid_functions, 1):
                        try:
                            # Extract function name and address
                            if " at " in full_function_string:
                                function_name = full_function_string.split(" at ")[0].strip()
                                address = full_function_string.split(" at ")[1].strip()
                            else:
                                function_name = full_function_string.strip()
                                import re
                                name_address_match = re.search(r'([0-9a-fA-F]{8,})', function_name)
                                address = name_address_match.group(1) if name_address_match else function_name
                            
                            print(f"\nProcessing [{i}/{total_functions}]: {function_name}")
                            
                            # Decompile the function
                            function_decompile_result = bridge.ghidra.decompile_function(name=function_name) if hasattr(bridge, 'ghidra') else None
                            if not function_decompile_result or (isinstance(function_decompile_result, str) and function_decompile_result.lower().startswith("error:")):
                                print(f"  ⚠ Failed to decompile: {function_decompile_result}")
                                failed_enumerations += 1
                                continue
                            
                            print(f"  ✓ Decompiled ({len(function_decompile_result)} chars)")
                            
                            # STEP 1.5: Gather contextual information (callers and callees)
                            context = {'callers_code': [], 'callees_code': [], 'truncated': False, 'total_chars': 0}
                            try:
                                print(f"  🔍 Gathering context (callers/callees)...")
                                
                                # Get callers (who calls this function?)
                                try:
                                    callers_result = bridge.ghidra.get_xrefs_to(address=address) if hasattr(bridge.ghidra, 'get_xrefs_to') else []
                                    if isinstance(callers_result, list) and callers_result:
                                        caller_addresses = []
                                        for c in callers_result[:5]:  # Limit to 5 callers
                                            if isinstance(c, dict):
                                                addr = c.get('from_address') or c.get('from') or c.get('fromAddress')
                                                if addr:
                                                    caller_addresses.append(addr)
                                            elif isinstance(c, str):
                                                import re
                                                match = re.search(r'(?:from[:\s]+)?([0-9a-fA-F]{6,})', c, re.IGNORECASE)
                                                if match:
                                                    caller_addresses.append(match.group(1))
                                        
                                        # Decompile top 3 callers
                                        for caller_addr in caller_addresses[:3]:
                                            try:
                                                caller_code = bridge.ghidra.decompile_function_by_address(address=str(caller_addr))
                                                if caller_code and not caller_code.lower().startswith("error"):
                                                    if len(caller_code) > 1000:
                                                        caller_code = caller_code[:1000] + "...[truncated]"
                                                    context['callers_code'].append({'address': caller_addr, 'code': caller_code})
                                            except:
                                                pass
                                except:
                                    pass
                                
                                # Get callees (what does this function call?)
                                try:
                                    callees_result = bridge.ghidra.get_xrefs_from(address=address) if hasattr(bridge.ghidra, 'get_xrefs_from') else []
                                    if isinstance(callees_result, list) and callees_result:
                                        callee_addresses = []
                                        for c in callees_result[:5]:  # Limit to 5 callees
                                            if isinstance(c, dict):
                                                addr = c.get('to_address') or c.get('to') or c.get('toAddress')
                                                if addr:
                                                    callee_addresses.append(addr)
                                            elif isinstance(c, str):
                                                import re
                                                match = re.search(r'(?:to[:\s]+)?([0-9a-fA-F]{6,})', c, re.IGNORECASE)
                                                if match:
                                                    callee_addresses.append(match.group(1))
                                        
                                        # Decompile top 3 callees
                                        for callee_addr in callee_addresses[:3]:
                                            try:
                                                callee_code = bridge.ghidra.decompile_function_by_address(address=str(callee_addr))
                                                if callee_code and not callee_code.lower().startswith("error"):
                                                    if len(callee_code) > 1000:
                                                        callee_code = callee_code[:1000] + "...[truncated]"
                                                    context['callees_code'].append({'address': callee_addr, 'code': callee_code})
                                            except:
                                                pass
                                except:
                                    pass
                                
                                # Calculate context size
                                context['total_chars'] = sum(len(c['code']) for c in context['callers_code'])
                                context['total_chars'] += sum(len(c['code']) for c in context['callees_code'])
                                
                                if context['callers_code'] or context['callees_code']:
                                    callers_count = len(context['callers_code'])
                                    callees_count = len(context['callees_code'])
                                    print(f"  ✓ Context: {callers_count} caller(s), {callees_count} callee(s) ({context['total_chars']} chars)")
                                else:
                                    print(f"  ℹ️  No caller/callee context found")
                            except Exception as e:
                                print(f"  ⚠ Context gathering failed: {e}")
                            
                            # Format context for prompt
                            contextual_info = ""
                            if context['callers_code'] or context['callees_code']:
                                sections = []
                                if context['callers_code']:
                                    sections.append("\n## CALLER FUNCTIONS (Functions that call this function):")
                                    for idx, caller in enumerate(context['callers_code'], 1):
                                        sections.append(f"\n### Caller {idx} at address {caller['address']}:")
                                        sections.append(f"```c\n{caller['code']}\n```")
                                
                                if context['callees_code']:
                                    sections.append("\n## CALLEE FUNCTIONS (Functions called by this function):")
                                    for idx, callee in enumerate(context['callees_code'], 1):
                                        sections.append(f"\n### Callee {idx} at address {callee['address']}:")
                                        sections.append(f"```c\n{callee['code']}\n```")
                                
                                contextual_info = "\n".join(sections)
                            
                            # AI Analysis with enhanced prompt (including context) - matching UI format
                            analysis_query = f"""Analyze the function '{function_name}' and provide a highly descriptive rename suggestion.

## TARGET FUNCTION: {function_name}
```c
{function_decompile_result}
```
{contextual_info}

Based on the target function's code AND the contextual information about its callers and callees above, analyze the function thoroughly and provide a highly descriptive rename suggestion.

You MUST follow this EXACT format in your response:

**Function Analysis:**
[Provide comprehensive analysis: What does this function do? Identify specific operations like memory allocation, string manipulation, network operations, file I/O, cryptographic operations, data validation, etc. Examine parameters, return values, called functions, and code patterns. Look for domain-specific functionality.]

**Behavior Summary:**
[Write a precise 1-4 sentence summary describing the function's primary behavior, data flow, and purpose in the program architecture based on the target function and its relationship with callers/callees]

**Suggested Name:** [descriptiveSpecificFunctionName]
**Rationale:** [Explain in detail why this name accurately captures the function's specific purpose and distinguishes it from other functions]

ENHANCED NAMING REQUIREMENTS:
- Be HIGHLY SPECIFIC about the operation (e.g., "parseHttpHeaders" not "parseData", "validateEmailFormat" not "validateInput")
- Include data type/domain context (e.g., "processNetworkPacket", "decryptUserCredentials", "compressImageBuffer")
- Use action verbs that describe the EXACT operation: parse, validate, encrypt, decrypt, compress, decompress, serialize, deserialize, allocate, deallocate, transform, convert, extract, insert, remove, update, calculate, generate, verify, authenticate, etc.
- Use precise nouns: Buffer, Packet, Header, Payload, Token, Credential, Session, Connection, Registry, Configuration, Certificate, Signature, etc.
- Be domain-aware: If it's crypto operations use crypto terms, if it's network use network terms, if it's file system use file terms
- Use camelCase format
- Length: 2-5 words (prioritize clarity over brevity)
- Avoid generic terms: process, handle, manage, data, function, method, routine, etc.

EXAMPLES of good names:
- parseJsonConfiguration (not parseData)
- validateTlsCertificate (not validateInput)
- encryptAesPayload (not encryptData)
- allocateMemoryBuffer (not allocateMemory)
- extractRegistryKeys (not extractData)
- calculateChecksumValue (not calculateValue)

CRITICAL: You MUST include all four sections with the exact headers shown above. Focus on making the suggested name as specific and descriptive as possible."""
                            
                            ai_response = bridge.ollama.generate(prompt=analysis_query) if hasattr(bridge, 'ollama') else None
                            
                            if ai_response and ai_response.strip():
                                function_summary = ai_response.strip()
                                print(f"  ✓ AI analysis complete")
                                
                                # Extract suggested name from AI response (same logic as UI)
                                suggested_name = None
                                lines = ai_response.split('\n')
                                
                                # Look for "Suggested Name:" pattern
                                for line in lines:
                                    line_stripped = line.strip()
                                    if 'Suggested Name:' in line_stripped or 'suggested name:' in line_stripped.lower():
                                        name_part = line_stripped.split(':', 1)[1].strip() if ':' in line_stripped else line_stripped
                                        name_part = name_part.replace('**', '').replace('*', '').strip()
                                        import re
                                        name_match = re.search(r'\b([a-z][a-zA-Z0-9_]*[a-zA-Z0-9]|[a-z][a-zA-Z0-9]*)\b', name_part)
                                        if name_match:
                                            suggested_name = name_match.group(1)
                                            break
                                
                                # Fallback extraction logic (look for camelCase names in response)
                                if not suggested_name:
                                    import re
                                    camel_case_matches = re.findall(r'\b([a-z][a-zA-Z0-9]*[A-Z][a-zA-Z0-9]*)\b', ai_response)
                                    excluded_words = {'function', 'name', 'suggest', 'analysis', 'code', 'parameter', 'value', 'data', 'result', 'return', 'call', 'method', 'functionName', 'newFunctionName', 'descriptiveFunctionName'}
                                    
                                    for match in camel_case_matches:
                                        if (len(match) > 4 and 
                                            match.lower() not in excluded_words and 
                                            not match.startswith('FUN_') and
                                            not any(word in match.lower() for word in ['function', 'name', 'example'])):
                                            suggested_name = match
                                            break
                                    
                                    # If still no match, look for any reasonable identifier
                                    if not suggested_name:
                                        simple_matches = re.findall(r'\b([a-z][a-zA-Z0-9_]*)\b', ai_response)
                                        for match in simple_matches:
                                            if (len(match) > 6 and 
                                                match.lower() not in excluded_words and 
                                                not match.startswith('FUN_') and
                                                not any(word in match.lower() for word in ['function', 'name', 'example', 'analysis', 'response'])):
                                                suggested_name = match
                                                break
                                
                                # Check if function has generic name
                                is_generic_name = function_name.startswith(('FUN_', 'sub_', 'loc_', 'unk_', 'j_'))
                                
                                # Rename if we have a suggestion and it's a generic name
                                final_name = function_name
                                if suggested_name and is_generic_name:
                                    print(f"  📝 Extracted name: {suggested_name}")
                                    
                                    # Perform the rename using bridge
                                    try:
                                        from src.bridge import Bridge
                                        if hasattr(bridge, 'execute_command'):
                                            rename_result = bridge.execute_command("rename_function", {"old_name": function_name, "new_name": suggested_name})
                                        else:
                                            # Fallback to direct ghidra call
                                            rename_result = bridge.ghidra.rename_function(old_name=function_name, new_name=suggested_name)
                                        
                                        if isinstance(rename_result, str) and rename_result.lower().startswith("error:"):
                                            print(f"  ⚠ Rename failed: {rename_result}")
                                            print(f"  ℹ️  Keeping original name: {function_name}")
                                        else:
                                            print(f"  ✅ Renamed: {function_name} → {suggested_name}")
                                            final_name = suggested_name
                                    except Exception as e:
                                        print(f"  ⚠ Rename exception: {e}")
                                        print(f"  ℹ️  Keeping original name: {function_name}")
                                        bridge.logger.warning(f"Failed to rename {function_name}: {e}")
                                elif suggested_name and not is_generic_name:
                                    print(f"  ℹ️  Already has descriptive name: {function_name} (AI suggested: {suggested_name})")
                                elif not suggested_name:
                                    print(f"  ⚠ Could not extract function name from AI response")
                                    print(f"  ℹ️  Keeping original name: {function_name}")
                                
                                # Store function summary
                                if hasattr(bridge, 'function_summaries'):
                                    bridge.function_summaries[address] = function_summary
                                
                                # Store for vector creation (use final name after rename)
                                processed_functions_data.append({
                                    'address': address,
                                    'old_name': function_name,
                                    'new_name': final_name,
                                    'summary': function_summary,
                                    'timestamp': time.time()
                                })
                                
                                successful_enumerations += 1
                                current_session_log.append(f"=== Processed: {function_name} → {final_name} at {address} ===\\n{function_summary}\\n")
                            else:
                                print(f"  ⚠ AI analysis failed or returned empty")
                                failed_enumerations += 1
                        
                        except Exception as e:
                            print(f"  ✗ Error processing {function_name}: {e}")
                            bridge.logger.error(f"Error enumerating function {function_name}: {e}", exc_info=True)
                            failed_enumerations += 1
                            continue
                    
                    enumeration_time = time.time() - start_time
                    print(f"\n[Step 2 Complete] Enumerated {successful_enumerations}/{total_functions} functions")
                    print(f"  Time: {enumeration_time:.1f}s, Average: {enumeration_time/max(1, successful_enumerations):.2f}s per function")
                    
                    # Step 3: Load vectors
                    print(f"\n[Step 3] Loading {len(processed_functions_data)} functions into vector store...")
                    
                    if not processed_functions_data:
                        print("  No functions to load into vectors.")
                    else:
                        # Check if CAG/RAG is available
                        if not (hasattr(bridge, 'enable_cag') and bridge.enable_cag and 
                                hasattr(bridge, 'cag_manager') and bridge.cag_manager):
                            print("  ⚠ RAG system is not enabled. Vector loading skipped.")
                            print("  Enable CAG in configuration to use vector operations.")
                        else:
                            try:
                                vectors_loaded = 0
                                vectors_failed = 0
                                
                                # Import necessary modules
                                from src.bridge import Bridge
                                import numpy as np
                                
                                # Test Ollama embeddings availability
                                test_embeddings = Bridge.get_ollama_embeddings(["test"])
                                if not test_embeddings:
                                    print("  ⚠ Ollama embedding model (nomic-embed-text) not available.")
                                    print("  Please run: ollama pull nomic-embed-text")
                                else:
                                    print("  ✓ Ollama embeddings available")
                                    
                                    # Process in batches
                                    BATCH_SIZE = 50
                                    num_batches = (len(processed_functions_data) + BATCH_SIZE - 1) // BATCH_SIZE
                                    
                                    for batch_num in range(num_batches):
                                        batch_start = batch_num * BATCH_SIZE
                                        batch_end = min(batch_start + BATCH_SIZE, len(processed_functions_data))
                                        batch = processed_functions_data[batch_start:batch_end]
                                        
                                        print(f"  Processing batch {batch_num + 1}/{num_batches}...")
                                        
                                        # Generate embeddings for batch
                                        batch_texts = [func['summary'] for func in batch]
                                        batch_embeddings_list = Bridge.get_ollama_embeddings(batch_texts)
                                        
                                        if not batch_embeddings_list:
                                            print(f"    ⚠ Failed to generate embeddings for batch {batch_num + 1}")
                                            vectors_failed += len(batch)
                                            continue
                                        
                                        # Convert to numpy arrays
                                        batch_embeddings = [np.array(emb) for emb in batch_embeddings_list]
                                        
                                        # Add to vector store
                                        for func_data, embedding in zip(batch, batch_embeddings):
                                            try:
                                                # Create function document
                                                function_doc = {
                                                    "text": f"Function: {func_data['new_name']}\\nOriginal: {func_data['old_name']}\\nAddress: {func_data['address']}\\nBehavior: {func_data['summary']}",
                                                    "type": "function_analysis",
                                                    "name": func_data['new_name'], 
                                                    "metadata": {
                                                        "address": func_data['address'],
                                                        "old_name": func_data['old_name'],
                                                        "new_name": func_data['new_name']
                                                    }
                                                }
                                                
                                                # Add to vector store
                                                vector_store = bridge.cag_manager.vector_store
                                                if vector_store:
                                                    vector_store.documents.append(function_doc)
                                                    
                                                    # Add embedding
                                                    if isinstance(vector_store.embeddings, list):
                                                        vector_store.embeddings.append(embedding)
                                                    else:
                                                        if len(vector_store.embeddings) == 0:
                                                            vector_store.embeddings = [embedding]
                                                        else:
                                                            vector_store.embeddings = np.vstack([vector_store.embeddings, embedding.reshape(1, -1)])
                                                    
                                                    vectors_loaded += 1
                                            except Exception as e:
                                                bridge.logger.warning(f"Failed to add {func_data['new_name']} to vector store: {e}")
                                                vectors_failed += 1
                                    
                                    print(f"  ✓ Loaded {vectors_loaded} vectors into store")
                                    if vectors_failed > 0:
                                        print(f"  ⚠ Failed to load {vectors_failed} vectors")
                            
                            except Exception as e:
                                print(f"  ✗ Error loading vectors: {e}")
                                bridge.logger.error(f"Error loading vectors: {e}", exc_info=True)
                    
                    # Final summary
                    total_time = time.time() - start_time
                    avg_time = total_time / max(1, successful_enumerations)
                    print("\n" + "="*60)
                    print("🎉 BINARY ENUMERATION COMPLETE 🎉")
                    print("="*60)
                    print(f"📊 Summary:")
                    print(f"  • Total functions: {total_functions}")
                    print(f"  • Successfully processed: {successful_enumerations}")
                    print(f"  • Failed: {failed_enumerations}")
                    print(f"  • Vectors loaded: {vectors_loaded if 'vectors_loaded' in locals() else 0}")
                    print(f"⚡ Performance:")
                    print(f"  • Total time: {total_time:.1f}s")
                    print(f"  • Average per function: {avg_time:.2f}s")
                    print(f"\nℹ️  Functions with generic names (FUN_, sub_, etc.) were renamed.")
                    print(f"ℹ️  Functions with descriptive names were analyzed but kept their original names.")
                    print(f"ℹ️  All analyses are available in the vector store for enhanced queries.")
                    print("="*60 + "\n")
                
                except Exception as e:
                    print(f"\n✗ Error during binary enumeration: {e}")
                    bridge.logger.error(f"Error in enumerate-binary: {e}", exc_info=True)
                    current_session_log.append(f"=== Error in enumerate-binary: {e} ===\\n")
                
                continue
            
            elif user_input.lower() == 'review-session':
                if not current_session_log:
                    print("\nNo interactions yet in this session to review.")
                    continue

                review_query = input("What would you like to ask about the work done in this session? (Type 'cancel' to abort): ")
                if not review_query or review_query.lower() == 'cancel':
                    print("Session review cancelled.")
                    continue

                print("\nCompiling session log for review...")
                session_context_str = "\n\n".join(current_session_log)
                
                review_prompt = (
                    f"You are an AI assistant. The user has been interacting with Ghidra tools in the current session. "
                    f"Below is a chronological log of the raw tool outputs and any subsequent AI analyses performed on those outputs. "
                    f"Please carefully review this entire session context to answer the user's question about the session.\\n\\n"
                    f"=============== BEGIN SESSION CONTEXT ===============\\n"
                    f"{session_context_str}\\n"
                    f"================ END SESSION CONTEXT ================\\n\\n"
                    f"USER'S QUESTION ABOUT THIS SESSION:\\n{review_query}\\n\\n"
                    f"Based on the provided session context, please provide a comprehensive answer to the user's question:"
                )

                print("Sending session context and query to AI for review...")
                try:
                    # Ensure bridge.ollama is used
                    ai_review_response = bridge.ollama.generate(prompt=review_prompt) if hasattr(bridge, 'ollama') else "Ollama client not available."
                    if ai_review_response and ai_review_response.strip() and ai_review_response != "Ollama client not available.":
                        print("\n=== AI Review of Session ===")
                        print(ai_review_response)
                        print("============================")
                    elif ai_review_response == "Ollama client not available.":
                         print(f"\n{ai_review_response}")
                    else:
                        print("\nAI review returned an empty or whitespace-only response.")
                except Exception as e:
                    print(f"Error during AI session review: {e}")
                    bridge.logger.error(f"Error during AI session review: {e}", exc_info=True)

            elif user_input.lower() == 'clear_log': 
                current_session_log.clear()
                print("Current session log cleared.")
            
            else:
                # Default to sending the query to the bridge for a general response
                # Ensure bridge.process_query is used
                try:
                    if hasattr(bridge, 'process_query'):
                        print("\nProcessing query with AI agent...")
                        result = bridge.process_query(user_input) # Assumes bridge has process_query
                        print("\n=== AI Agent Response ===")
                        print(result)
                        print("=========================\n")
                        current_session_log.append(f"=== AI Agent Response to Query: '{user_input}' ===\\n{result}\\n")
                    else:
                        print("\nBridge does not have process_query method. Cannot process general query.")
                        current_session_log.append(f"=== Attempted general query (not processed): '{user_input}' ===\\n")

                except Exception as e:
                    bridge.logger.error(f"Error processing query: {e}", exc_info=True)
                    print(f"\nError processing query: {type(e).__name__} - {e}\n")
                    current_session_log.append(f"=== Error processing query '{user_input}': {e} ===\\n")

        except (KeyboardInterrupt, EOFError):
            print("\nExiting...")
            break
        except Exception as e: # Catch-all for other unexpected errors in the loop
            print(f"An unexpected error occurred in the interactive loop: {e}")
            bridge.logger.error(f"Unexpected error in interactive loop: {e}", exc_info=True)
            # Optionally, decide if you want to break or continue
            # break 

def main():
    """Main entry point for the Ollama-GhidraMCP Bridge CLI."""
    # Initialize configuration from environment variables
    config = get_config()

    parser = argparse.ArgumentParser(description="Ollama-GhidraMCP Bridge")
    parser.add_argument("--interactive", "-i", action="store_true", help="Enable interactive mode")
    parser.add_argument("--query", "-q", type=str, help="Single query to execute (non-interactive mode)")
    # UI now defaults to ON when no other mode flags are passed
    parser.add_argument("--ui", action="store_true", help="Launch the graphical user interface (default)")

    # Capabilities list is now included by default; provide opt-out flag instead
    parser.add_argument("--no-capabilities", "--no-cap", action="store_true",
                       help="Do NOT include tool capabilities in the prompt")
    parser.add_argument("--disable-cag", action="store_true", 
                       help="Disable Cache-Augmented Generation (CAG)")
    
    args = parser.parse_args()
    
    # ------------------------------------------------------------------
    # Determine default operating mode
    # ------------------------------------------------------------------
    # If the user did not specify any primary mode flags, fall back to GUI
    if not args.interactive and not args.query and not args.ui:
        args.ui = True

    # Capabilities are ON by default unless explicitly disabled
    include_capabilities = not args.no_capabilities
    
    # Override CAG settings from command line if specified
    if args.disable_cag:
        config.cag_enabled = False
    
    # Create the bridge
    bridge = Bridge(
        config=config,
        include_capabilities=include_capabilities,
        max_agent_steps=config.max_steps,
        enable_cag=config.cag_enabled
    )
    
    # Print header (only for non-UI modes)
    if not args.ui:
        print_header()
    
    if args.ui:
        # Launch GUI mode directly - no automatic vector DB initialization
        # Vector operations are now user-controlled via "Load Vectors" button
        
        # Launch GUI mode
        try:
            from src.ui import launch_ui
            launch_ui(bridge, config)
        except ImportError as e:
            print(f"Error: Unable to launch UI. {e}")
            print("Make sure tkinter is installed and available.")
            return 1
    elif args.interactive:
        run_interactive_mode(bridge, config)
    else:
        # Single query mode
        result = bridge.process_query(args.query)
        print(result)

def check_and_initialize_vector_db():
    """Check if vector database exists and initialize if needed."""
    from pathlib import Path
    import logging
    
    logger = logging.getLogger("main.vector_init")
    
    # Check if vector database exists
    vector_db_path = Path("data/vector_db")
    vectors_file = vector_db_path / "vectors.npy"
    
    if vectors_file.exists():
        try:
            import numpy as np
            vectors = np.load(vectors_file)
            logger.info(f"✅ Found existing vector database with {vectors.shape[0]} vectors")
            return True
        except Exception as e:
            logger.warning(f"Found vector database files but couldn't load them: {e}")
    
    # Check if we have knowledge base files to initialize from
    kb_files = [
        "knowledge_base/knowledge_base.md",
        "src/cag/knowledge/common_workflows.json",
        "src/cag/knowledge/function_signatures.json"
    ]
    
    available_kb_files = [f for f in kb_files if Path(f).exists()]
    
    if not available_kb_files:
        logger.info("No knowledge base files found, skipping vector DB initialization")
        return False
    
    logger.info(f"🚀 Initializing vector database from {len(available_kb_files)} knowledge sources...")
    
    try:
        # Import and run the vector DB initialization
        from initialize_vector_db import initialize_vector_database
        
        # Call the initialization function
        success = initialize_vector_database()
        
        if success:
            logger.info("✅ Vector database initialized successfully!")
            return True
        else:
            logger.warning("⚠️  Vector database initialization completed with warnings")
            return False
            
    except Exception as e:
        logger.error(f"❌ Failed to initialize vector database: {e}")
        logger.info("You can manually run: python initialize_vector_db.py")
        return False

if __name__ == "__main__":
    sys.exit(main()) 