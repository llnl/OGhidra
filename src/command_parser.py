"""Validation and normalization for typed Ghidra tool actions."""

import logging
import re
from typing import Any, ClassVar

logger = logging.getLogger("ollama-ghidra-bridge.parser")


class CommandParser:
    """Validate and normalize tool actions emitted by DSPy."""

    # Define the required parameters for each command
    REQUIRED_PARAMETERS: ClassVar[dict[str, list[str]]] = {
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
    ALL_SUPPORTED_COMMANDS: ClassVar[list[str]] = [
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
        "check_health",
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
    def validate_command_parameters(command_name: str, params: dict[str, Any]) -> tuple[bool, str]:
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
    def normalize_parameters(command_name: str, params: dict[str, Any]) -> dict[str, Any]:
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

        # Map of common incorrect parameter names to correct ones for each command
        # key: Name of the command
        # value: Mapping of wrong-to-right param renames for this command
        #       key: Wrong name
        #       value: The correct name
        param_corrections = {
            "rename_function": {"function_name": "old_name", "name": "old_name"},
            "rename_function_by_address": {"address": "function_address", "functionAddress": "function_address"},
            "decompile_function": {
                "function_name": "name",
                "address": "name",  # If they use address, assume it's a name like FUN_...
            },
            "decompile_function_by_address": {
                "function_address": "address",
                "functionAddress": "address",
                "name": "address",  # If they use name, assume it's an address
            },
            "disassemble_function": {
                "function_name": "address",  # Map function_name to address
                "name": "address",  # Map name to address
            },
        }

        # Apply parameter name corrections if needed
        if command_name in param_corrections:
            for wrong_name, correct_name in param_corrections[command_name].items():
                if wrong_name in validated_params and correct_name not in validated_params:
                    logger.info(f"Correcting parameter for '{command_name}': from '{wrong_name}' to '{correct_name}'")
                    validated_params[correct_name] = validated_params.pop(wrong_name)

        # Coerce common numeric parameters even if quoted
        numeric_param_names = {
            "offset",
            "limit",
            "length",
            "start_port",
            "end_port",
            "min_table_entries",
            "pointer_size",
        }
        for n in numeric_param_names:
            if n in validated_params and isinstance(validated_params[n], str):
                s = validated_params[n].strip()
                if re.fullmatch(r"-?\d+", s):
                    try:
                        validated_params[n] = int(s)
                    except ValueError:
                        pass

        # For rename_function_by_address, check if function_address is a function name
        if command_name == "rename_function_by_address" and "function_address" in validated_params:
            addr = str(validated_params["function_address"])

            # If it starts with "FUN_" and the rest is hex, extract just the hex part
            if addr.startswith("FUN_") and all(c in "0123456789abcdefABCDEF" for c in addr[4:]):
                # Extract just the address portion
                validated_params["function_address"] = addr[4:]
                logger.info(f"Transformed function address from '{addr}' to '{addr[4:]}'")

        # Handle 0x prefix in addresses for various functions
        address_param_names = ["address", "function_address"]  # function_address included for safety
        for param_name in address_param_names:
            if param_name in validated_params:
                addr = str(validated_params[param_name])
                # If it starts with "0x", remove it
                if addr.startswith(("0x", "0X")):
                    validated_params[param_name] = addr[2:]
                    logger.info(f"Transformed address from '{addr}' to '{addr[2:]}'")

        return validated_params

    @staticmethod
    def get_enhanced_error_message(command_name: str, params: dict[str, str], error: str) -> str:
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
        if re.search(r"[a-z][A-Z]", command_name):
            snake_case = re.sub(r"(?<!^)(?=[A-Z])", "_", command_name).lower()
            return (
                f"ERROR: Command '{command_name}' may be using camelCase format instead of snake_case. "
                f"Try using '{snake_case}' instead. "
                f"All command names must use snake_case with underscores."
            )

        # Check for common parameter name errors
        common_param_errors = {"address": "function_address (in rename_function_by_address)"}

        for param_name in params:
            if param_name in common_param_errors:
                return (
                    f"ERROR: Parameter '{param_name}' may be incorrect. "
                    f"Try using '{common_param_errors[param_name]}' instead. "
                    f"Check the parameter names in function_signatures.json for reference."
                )

        return enhanced_error
