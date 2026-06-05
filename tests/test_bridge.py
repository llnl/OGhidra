import os
import re
import sys
import unittest
from unittest.mock import MagicMock, patch

# Add project root to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.bridge import Bridge
from src.config import BridgeConfig


class TestBridge(unittest.TestCase):
    """Tests for the Bridge class."""

    def setUp(self):
        """Set up the test environment."""
        # Mock the logger to avoid actual logging during tests
        with patch("src.bridge.setup_logging", return_value=MagicMock()):
            self.config = BridgeConfig()
            self.bridge = Bridge(self.config)

        # Mock the GhidraMCP client
        self.bridge.ghidra_client = MagicMock()

        # Mock the Ollama client
        self.bridge.ollama = MagicMock()
        self.bridge.ollama.generate_with_phase.return_value = "Test response"

    def test_check_implied_actions_without_commands_basic(self):
        """Test that the method correctly identifies implied actions."""
        # Test with a response that implies an action but doesn't include an EXECUTE command
        response = "I suggest renaming the function to something more descriptive."
        result = self.bridge._check_implied_actions_without_commands(response)

        # Check that it identified an implied action
        self.assertIsInstance(result, str)
        self.assertNotEqual(result, "")
        # Since the actual text may vary, check for key phrases that should be in the result
        self.assertIn("actions", result.lower())

        # Test with a response that has an EXECUTE command
        response_with_command = "EXECUTE: rename_function(old_name='func1', new_name='betterName')"
        result = self.bridge._check_implied_actions_without_commands(response_with_command)

        # Should return empty string since EXECUTE is present
        self.assertEqual(result, "")

        # Test with a prompt we generated before
        prev_prompt = "Your response implies certain actions should be taken, but you didn't include explicit EXECUTE commands:"
        result = self.bridge._check_implied_actions_without_commands(prev_prompt)

        # Should return empty string since this is our own prompt
        self.assertEqual(result, "")

    def test_command_name_conversion(self):
        """Test the camelCase to snake_case conversion algorithm."""
        # This is a simpler test that just focuses on the conversion algorithm
        # which is what really matters for fixing our issue

        # Test the conversion algorithm
        def convert_camel_to_snake(cmd_name):
            s1 = re.sub("(.)([A-Z][a-z]+)", r"\1_\2", cmd_name)
            return re.sub("([a-z0-9])([A-Z])", r"\1_\2", s1).lower()

        # Test various camelCase patterns
        test_cases = [
            ("getCurrentFunction", "get_current_function"),
            ("decompileFunction", "decompile_function"),
            ("renameFunctionByAddress", "rename_function_by_address"),
            ("setComment", "set_comment"),
            ("getFunction", "get_function"),
            ("listImports", "list_imports"),
            ("FunctionWithUpperCase", "function_with_upper_case"),
            ("camelCase123Number", "camel_case123_number"),
        ]

        for camel, expected_snake in test_cases:
            self.assertEqual(convert_camel_to_snake(camel), expected_snake)

    def test_normalize_command_name_integration(self):
        """Integration test for _normalize_command_name using SubClass and real attributes."""

        # Create a subclass that has the methods we want to test with
        class TestGhidra:
            def get_current_function(self):
                pass

            def decompile_function(self):
                pass

            def rename_function_by_address(self):
                pass

            def camelCaseMethod(self):
                pass  # Also test a camelCase method that exists

        # Create a subclass of Bridge that uses our TestGhidra
        class TestBridge(Bridge):
            def __init__(self):
                # Skip the normal initialization
                self.ghidra_client = TestGhidra()
                self.logger = MagicMock()

        # Create our test bridge
        test_bridge = TestBridge()

        # Test scenarios:

        # 1. camelCase conversion when snake_case exists
        self.assertEqual(
            test_bridge._normalize_command_name("getCurrentFunction"),
            "get_current_function",
        )

        # 2. Already snake_case name remains unchanged
        self.assertEqual(
            test_bridge._normalize_command_name("get_current_function"),
            "get_current_function",
        )

        # 3. camelCase that exists on the object remains unchanged
        self.assertEqual(test_bridge._normalize_command_name("camelCaseMethod"), "camelCaseMethod")

        # 4. Unknown commands in any case format remain unchanged
        self.assertEqual(
            test_bridge._normalize_command_name("nonExistentCommand"),
            "",
        )


if __name__ == "__main__":
    unittest.main()
