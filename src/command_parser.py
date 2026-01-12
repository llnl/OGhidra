"""
Command parser module for extracting and executing GhidraMCP commands from AI responses.
"""

import json
import logging
import re
from typing import Dict, Any, List, Tuple, Optional

logger = logging.getLogger("ollama-ghidra-bridge.parser")

class CommandParser:
    """
    Parser for extracting and validating commands from AI responses.
    """
    
    # Command format: EXECUTE: command_name(param1=value1, param2=value2)
    COMMAND_PATTERN = r'EXECUTE:\s*([\w_]+)\((.*?)\)'
    
    # This pattern will attempt to capture tool_execution and other incorrect formats
    ALTERNATE_FORMATS = [
        (r'```tool_execution\s*([\w_]+)\((.*?)\)\s*```', 'tool_execution with code blocks'),
        (r'tool_execution\s*([\w_]+)\((.*?)\)', 'tool_execution without code blocks'),
        (r'```tool_code\s*([\w_]+)\((.*?)\)\s*```', 'tool_code markdown blocks'),
        (r'```\s*([\w_]+)\((.*?)\)\s*```', 'generic code blocks with tool calls'),
        (r'```json\s*\{\s*"tool"\s*:\s*"([\w_]+)"\s*,\s*"parameters"\s*:\s*\{(.*?)\}\s*\}\s*```', 'JSON tool format')
    ]
    
    # Define the required parameters for each command
    REQUIRED_PARAMETERS = {
        "decompile_function": ["name"],
        "decompile_function_by_address": ["address"],
        "disassemble_function": ["address"],
        "rename_function": ["old_name", "new_name"],
        "rename_function_by_address": ["function_address", "new_name"],
        "search_functions_by_name": ["query"],
        "get_xrefs_to": ["address"],
        "get_xrefs_from": ["address"],
        "get_function_xrefs": ["name"],
        "read_bytes": ["address"],
        "scan_function_pointer_tables": [],  # All params optional
        "get_cached_result": ["result_id"],  # Retrieve full cached result
    }
    
    # List of all supported commands for validation purposes
    ALL_SUPPORTED_COMMANDS = [
        "decompile_function",
        "decompile_function_by_address",
        "rename_function",
        "rename_function_by_address",
        "search_functions_by_name",
        "list_methods",
        "list_classes", 
        "list_functions",
        "list_imports",
        "list_exports",
        "list_segments",
        "list_strings",
        "get_xrefs_to",
        "get_xrefs_from",
        "get_function_xrefs",
        "xref_lookup",  # alias
        "string_search",  # alias
        "get_current_function",
        "get_current_address",
        "analyze_function",
        "list_data_items",
        "list_namespaces",
        "get_function_by_address",
        "rename_data",
        "disassemble_function",
        "read_bytes",  # Read raw bytes from memory addresses
        "scan_function_pointer_tables",  # Scan for function pointer tables (vtables, dispatch tables)
        "get_cached_result",  # Retrieve full content of a cached/summarized result
        "health_check",
        "check_health"
        # Disabled tools:
        # "rename_variable",
        # "safe_get", 
        # "safe_post",
        # "set_decompiler_comment",
        # "set_disassembly_comment",
        # "set_function_prototype",
        # "set_local_variable_type"
    ]
    
    @staticmethod
    def validate_command_parameters(command_name: str, params: Dict[str, str]) -> Tuple[bool, str]:
        """
        Validate that a command has all required parameters.
        
        Args:
            command_name: The name of the command
            params: The parameters dictionary
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if command_name not in CommandParser.REQUIRED_PARAMETERS:
            return True, ""  # No required parameters defined for this command
            
        required_params = CommandParser.REQUIRED_PARAMETERS[command_name]
        missing_params = [param for param in required_params if param not in params]
        
        if missing_params:
            missing_list = ", ".join(missing_params)
            error_message = f"Missing required parameter(s): {missing_list} for command '{command_name}'"
            return False, error_message
            
        return True, ""
    
    @staticmethod
    def extract_commands(response: str) -> List[Tuple[str, Dict[str, str]]]:
        """
        Extract commands and their parameters from an AI response.
        
        Args:
            response: The AI's response text
            
        Returns:
            List of tuples containing (command_name, parameters_dict)
        """
        commands = []
        seen_commands = set()  # Track unique command signatures for deduplication
        
        # Clean up malformed output - sometimes AI outputs "EXECUTE: cmd()REASONING:"
        # Split on known keywords to isolate EXECUTE statements
        cleaned_response = response
        for keyword in ['REASONING:', 'EXPLANATION:', 'INVESTIGATION', 'GOAL']:
            # Ensure newline before keyword if it follows a command
            cleaned_response = re.sub(
                r'(\))\s*(' + keyword + ')', 
                r'\1\n\2', 
                cleaned_response
            )
        
        # Find all command occurrences in the response using the correct format
        matches = re.finditer(CommandParser.COMMAND_PATTERN, cleaned_response, re.MULTILINE)
        
        for match in matches:
            command_name = match.group(1)
            params_text = match.group(2).strip()
            
            # Parse parameters
            params = CommandParser._parse_parameters(params_text)
            
            # Validate the command has all required parameters
            is_valid, error_message = CommandParser.validate_command_parameters(command_name, params)
            if not is_valid:
                logger.warning(error_message)
                # We'll still append the command, and the Bridge will handle the error
            
            # Validate and transform parameters for specific commands
            params = CommandParser._validate_and_transform_params(command_name, params)
            
            # Create signature for deduplication (command + sorted params)
            param_str = str(sorted(params.items())) if params else ""
            cmd_signature = f"{command_name}:{param_str}"
            
            # Skip if we've already seen this exact command
            if cmd_signature in seen_commands:
                logger.debug(f"Skipping duplicate command: {command_name}")
                continue
            
            seen_commands.add(cmd_signature)
            commands.append((command_name, params))
            logger.debug(f"Extracted command: {command_name} with params: {params}")
        
        # If no commands found with correct format, check for alternate formats
        if not commands:
            for pattern, format_name in CommandParser.ALTERNATE_FORMATS:
                alt_matches = re.finditer(pattern, response, re.MULTILINE | re.DOTALL)
                
                for match in alt_matches:
                    command_name = match.group(1)
                    params_text = match.group(2).strip()
                    
                    # For JSON format, we need special handling
                    if 'JSON' in format_name:
                        # This is a simple approach, would need better parsing for production
                        params = {}
                        param_matches = re.finditer(r'"([\w_]+)"\s*:\s*"?([^",}]+)"?', params_text)
                        for p_match in param_matches:
                            params[p_match.group(1)] = p_match.group(2).strip()
                    else:
                        params = CommandParser._parse_parameters(params_text)
                    
                    # Log the incorrect format
                    logger.warning(f"Found command using incorrect format ({format_name}): {command_name}")
                    logger.warning(f"Commands should use format: EXECUTE: command_name(param1=\"value1\")")
                    
                    # Validate the command has all required parameters
                    is_valid, error_message = CommandParser.validate_command_parameters(command_name, params)
                    if not is_valid:
                        logger.warning(error_message)
                    
                    # Try to validate and transform the parameters
                    params = CommandParser._validate_and_transform_params(command_name, params)
                    
                    commands.append((command_name, params))
                    logger.debug(f"Extracted command (from {format_name}): {command_name} with params: {params}")
            
        return commands
    
    @staticmethod
    def _validate_and_transform_params(command_name: str, params: Dict[str, str]) -> Dict[str, str]:
        """
        Validate and potentially transform parameters for specific commands.
        This helps catch common errors before they reach the GhidraMCP client.
        
        Args:
            command_name: The name of the command
            params: The parsed parameters
            
        Returns:
            Validated and potentially transformed parameters
        """
        # Make a copy to avoid modifying the original
        validated_params = params.copy()
        
        # list_functions now supports pagination parameters (offset, limit)
        # No special handling needed - parameters are accepted
        
        # Map alias commands to canonical ones and normalise parameters
        alias_mapping = {
            "string_search": "list_strings",
            "xref_lookup": None  # handled dynamically below
        }

        if command_name in alias_mapping and alias_mapping[command_name]:
            # Simple alias mapping (string_search -> list_strings)
            command_name = alias_mapping[command_name]
            logger.info(f"Alias command mapped to '{command_name}'")

        # Special handling for xref_lookup alias
        if command_name == "xref_lookup":
            # Decide which underlying xref function to call based on params
            if "name" in validated_params:
                command_name = "get_function_xrefs"
            else:
                direction = validated_params.pop("direction", "from").lower()
                if direction == "to":
                    command_name = "get_xrefs_to"
                else:
                    command_name = "get_xrefs_from"  # default
            logger.info(f"xref_lookup mapped to '{command_name}' with params {validated_params}")
        
        # Map of common incorrect parameter names to correct ones for each command
        param_corrections = {
            "rename_function": {
                "function_name": "old_name",
                "name": "old_name"
            },
            "rename_function_by_address": {
                "address": "function_address",
                "functionAddress": "function_address"
            },
            "decompile_function": {
                "function_name": "name",
                "address": "name" # If they use address, assume it's a name like FUN_...
            },
            "decompile_function_by_address": {
                "function_address": "address",
                "functionAddress": "address",
                "name": "address" # If they use name, assume it's an address
            },
            "disassemble_function": {
                "function_name": "address",  # Map function_name to address
                "name": "address"            # Map name to address
            }
        }
        
        # Apply parameter name corrections if needed
        if command_name in param_corrections:
            for wrong_name, correct_name in param_corrections[command_name].items():
                if wrong_name in validated_params and correct_name not in validated_params:
                    logger.info(f"Correcting parameter for '{command_name}': from '{wrong_name}' to '{correct_name}'")
                    validated_params[correct_name] = validated_params.pop(wrong_name)
        
        # For rename_function_by_address, check if function_address is a function name
        if command_name == "rename_function_by_address" and "function_address" in validated_params:
            addr = validated_params["function_address"]
            
            # If it starts with "FUN_" and the rest is hex, extract just the hex part
            if addr.startswith("FUN_") and all(c in "0123456789abcdefABCDEF" for c in addr[4:]):
                # Extract just the address portion
                validated_params["function_address"] = addr[4:]
                logger.info(f"Transformed function address from '{addr}' to '{addr[4:]}'")
        
        # Handle 0x prefix in addresses for various functions
        address_param_names = ["address", "function_address"] # function_address included for safety
        for param_name in address_param_names:
            if param_name in validated_params:
                addr = str(validated_params[param_name])
                # If it starts with "0x", remove it
                if addr.startswith("0x") or addr.startswith("0X"):
                    validated_params[param_name] = addr[2:]
                    logger.info(f"Transformed address from '{addr}' to '{addr[2:]}'")
        
        return validated_params
    
    @staticmethod
    def _parse_parameters(params_text: str) -> Dict[str, str]:
        """
        Parse parameters from the parameter text string.
        
        Args:
            params_text: The parameter text (e.g. 'param1="value1", param2="value2"')
            
        Returns:
            Dictionary of parameter names to values
        """
        params = {}
        
        if not params_text:
            return params
            
        # Split by commas, but not within quotes
        param_list = []
        current = ""
        in_quotes = False
        quote_char = None
        
        for char in params_text:
            if char in ('"', "'") and (not in_quotes or quote_char == char):
                in_quotes = not in_quotes
                if in_quotes:
                    quote_char = char
                else:
                    quote_char = None
                current += char
            elif char == ',' and not in_quotes:
                param_list.append(current.strip())
                current = ""
            else:
                current += char
                
        if current:
            param_list.append(current.strip())
            
        # Process each parameter
        for param in param_list:
            if '=' in param:
                key, value = param.split('=', 1)
                key = key.strip()
                value = value.strip()
                
                # Remove quotes if present
                if (value.startswith('"') and value.endswith('"')) or \
                   (value.startswith("'") and value.endswith("'")):
                    value = value[1:-1]
                    
                params[key] = value
        
        return params
    
    @staticmethod
    def format_command_results(command: str, params: Dict[str, str], result: Dict[str, Any]) -> str:
        """
        Format the results of a command execution.
        
        Args:
            command: The command that was executed
            params: The parameters that were used
            result: The result dictionary from the command execution
            
        Returns:
            Formatted string representation of the results
        """
        formatted_result = f"Results of {command}:\n"
        formatted_result += json.dumps(result, indent=2)
        return formatted_result
    
    @staticmethod
    def replace_command_with_result(response: str, cmd_match: re.Match, result: str) -> str:
        """
        Replace a command in the response with its execution result.
        
        Args:
            response: The original AI response
            cmd_match: The regex match object for the command
            result: The formatted result string
            
        Returns:
            The response with the command replaced by its result
        """
        start, end = cmd_match.span()
        return response[:start] + result + response[end:]
    
    @staticmethod
    def remove_commands(text: str) -> str:
        """
        Remove EXECUTE command blocks from text to get the clean response.
        
        Args:
            text: The text containing EXECUTE blocks
            
        Returns:
            Clean text with EXECUTE blocks removed
        """
        # Simple pattern to remove EXECUTE: command() blocks
        clean_text = re.sub(r'EXECUTE:\s*[\w_]+\([^)]*\)', '', text)
        
        # Clean up any resulting double newlines
        clean_text = re.sub(r'\n\s*\n\s*\n', '\n\n', clean_text)
        
        return clean_text.strip()
    
    @staticmethod
    def get_enhanced_error_message(command_name: str, params: Dict[str, str], error: str) -> str:
        """
        Generate an enhanced error message with specific guidance based on the command and error.
        
        Args:
            command_name: The command that was attempted
            params: The parameters that were used
            error: The original error message
            
        Returns:
            Enhanced error message with guidance
        """
        # Default to the original error
        enhanced_error = f"ERROR: {error}"
        
        # Add specific guidance based on the command and parameters
        if command_name == "rename_function_by_address":
            addr = params.get("function_address", params.get("address", ""))
            if addr.startswith("FUN_"):
                return (
                    f"ERROR: Invalid parameter 'function_address'. Expected numerical address (e.g., '{addr[4:]}'), "
                    f"but received function name ('{addr}'). "
                    f"Use the correct address or the 'rename_function' tool if you only have the name."
                )
            elif "Failed to rename function" in error:
                return (
                    f"ERROR: Failed to rename function at address '{addr}'. "
                    f"This could be because the function doesn't exist at that address, "
                    f"or the new name is invalid or already in use. "
                    f"Try using get_function_by_address(address='{addr}') to verify the function exists."
                )
        elif command_name.startswith("decompile_"):
            if "not found" in error.lower() or "does not exist" in error.lower():
                return (
                    f"ERROR: {error}. "
                    f"The function may not exist or may not be a valid target for decompilation. "
                    f"Try list_functions() to see available functions."
                )
        
        # Check for camelCase vs snake_case errors in the command name
        if re.search(r'[a-z][A-Z]', command_name):
            snake_case = re.sub(r'(?<!^)(?=[A-Z])', '_', command_name).lower()
            return (
                f"ERROR: Command '{command_name}' may be using camelCase format instead of snake_case. "
                f"Try using '{snake_case}' instead. "
                f"All command names must use snake_case with underscores."
            )
            
        # Check for common parameter name errors
        common_param_errors = {
            "address": "function_address (in rename_function_by_address)"
        }
        
        for param_name in params.keys():
            if param_name in common_param_errors:
                return (
                    f"ERROR: Parameter '{param_name}' may be incorrect. "
                    f"Try using '{common_param_errors[param_name]}' instead. "
                    f"Check the parameter names in function_signatures.json for reference."
                )
                
        return enhanced_error 
