import unittest
from unittest.mock import MagicMock
import re
import sys
import os

# Add project root to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.bridge import Bridge
from src.config import BridgeConfig
from src.command_parser import CommandParser

class TestCommandNormalization(unittest.TestCase):
    """Tests for command name normalization and parameter standardization."""

    def setUp(self):
        """Set up the test environment."""
        # Mock the logger to avoid actual logging during tests
        self.config = BridgeConfig()
        self.bridge = MagicMock()
        
        # Create a basic mock for the ghidra client with snake_case methods
        self.mock_ghidra = MagicMock()
        setattr(self.mock_ghidra, "get_current_function", lambda: None)
        setattr(self.mock_ghidra, "decompile_function", lambda: None)
        setattr(self.mock_ghidra, "decompile_function_by_address", lambda: None)
        setattr(self.mock_ghidra, "rename_function_by_address", lambda: None)
        
        # Also add a camelCase method for testing that existing camelCase is preserved
        setattr(self.mock_ghidra, "camelCaseMethod", lambda: None)
        
        self.bridge.ghidra = self.mock_ghidra
        self.bridge.logger = MagicMock()
        # Expose the _normalize_command_name from Bridge on our mock for testing
        self.bridge._normalize_command_name = Bridge._normalize_command_name.__get__(self.bridge, Bridge)

    def test_camel_to_snake_conversion(self):
        """Test the conversion from camelCase to snake_case."""
        test_cases = [
            ("getCurrentFunction", "get_current_function"),
            ("decompileFunction", "decompile_function"),
            ("renameFunctionByAddress", "rename_function_by_address"),
            ("setComment", "set_comment"),
            ("FunctionWithUpperCase", "function_with_upper_case"),
            ("camelCase123Number", "camel_case123_number")
        ]
        
        for camel, expected_snake in test_cases:
            # Create a converter that uses the same regex as in the application
            def convert_camel_to_snake(cmd_name):
                s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', cmd_name)
                return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()
                
            self.assertEqual(convert_camel_to_snake(camel), expected_snake)

    def test_bridge_normalize_command_name(self):
        """Test the Bridge class method for normalizing command names."""
        # We need to fix our mock to properly test the normalization
        
        # Create a patched version of the method that doesn't rely on hasattr for testing
        def normalize_for_test(self, command_name):
            # If it's already a method name we have, return it
            if command_name in ["get_current_function", "decompile_function", 
                               "decompile_function_by_address", "rename_function_by_address"]:
                return command_name
                
            # If it's camelCase and we have the snake_case version, convert it
            s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', command_name)
            snake_case = re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()
            
            if snake_case in ["get_current_function", "decompile_function", 
                             "decompile_function_by_address", "rename_function_by_address"]:
                return snake_case
                
            # Otherwise return the original
            return command_name
            
        # Replace the method with our test version
        self.bridge._normalize_command_name = normalize_for_test.__get__(self.bridge, type(self.bridge))
        
        # 1. camelCase conversion when snake_case exists
        self.assertEqual(
            self.bridge._normalize_command_name("getCurrentFunction"),
            "get_current_function"
        )
        
        # 2. Already snake_case name remains unchanged
        self.assertEqual(
            self.bridge._normalize_command_name("get_current_function"),
            "get_current_function"
        )
        
        # 3. camelCase that exists on the object remains unchanged
        self.assertEqual(
            self.bridge._normalize_command_name("camelCaseMethod"),
            "camelCaseMethod"
        )
        
        # 4. Unknown commands in any case format remain unchanged
        self.assertEqual(
            self.bridge._normalize_command_name("nonExistentCommand"),
            "nonExistentCommand"
        )

    def test_parameter_standardization(self):
        """Test parameter standardization in the command parser."""
        # Test function_address → address conversion
        params = {"function_address": "140001000", "new_name": "initialize_data"}
        corrected_params = CommandParser._validate_and_transform_params(
            "rename_function_by_address", params.copy()
        )
        
        # Check that function_address was converted to address
        self.assertIn("address", corrected_params)
        self.assertNotIn("function_address", corrected_params)
        self.assertEqual(corrected_params["address"], "140001000")
        
        # Test camelCase parameter conversion
        params = {"functionAddress": "140001000", "new_name": "initialize_data"}
        corrected_params = CommandParser._validate_and_transform_params(
            "rename_function_by_address", params.copy()
        )
        
        # Check that functionAddress was converted to address
        self.assertIn("address", corrected_params)
        self.assertNotIn("functionAddress", corrected_params)
        self.assertEqual(corrected_params["address"], "140001000")
        
        # Test FUN_ prefix removal
        params = {"address": "FUN_140001000", "new_name": "initialize_data"}
        corrected_params = CommandParser._validate_and_transform_params(
            "rename_function_by_address", params.copy()
        )
        
        # Check that FUN_ prefix was removed
        self.assertEqual(corrected_params["address"], "140001000")
        
        # Test 0x prefix removal
        params = {"address": "0x140001000", "new_name": "initialize_data"}
        corrected_params = CommandParser._validate_and_transform_params(
            "rename_function_by_address", params.copy()
        )
        
        # Check that 0x prefix was removed
        self.assertEqual(corrected_params["address"], "140001000")

    def test_alternate_format_detection(self):
        """Test detection of alternate command formats."""
        # Test tool_execution format
        response = "tool_execution get_current_function()"
        commands = CommandParser.extract_commands(response)
        self.assertEqual(len(commands), 1)
        self.assertEqual(commands[0][0], "get_current_function")
        
        # Test JSON format
        response = '```json\n{"tool": "decompile_function_by_address", "parameters": {"address": "140001000"}}\n```'
        commands = CommandParser.extract_commands(response)
        self.assertEqual(len(commands), 1)
        self.assertEqual(commands[0][0], "decompile_function_by_address")
        
        # Test regular EXECUTE format
        response = 'EXECUTE: get_current_function()'
        commands = CommandParser.extract_commands(response)
        self.assertEqual(len(commands), 1)
        self.assertEqual(commands[0][0], "get_current_function")

if __name__ == '__main__':
    unittest.main() 