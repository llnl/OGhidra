"""Regression and Bridge integration tests for CustomAPIClient Issue #53."""

import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock, patch

from src.bridge import Bridge
from src.config import BridgeConfig
from src.custom_api_client import CustomAPIClient, extract_chat_completion_text


class CustomAPIResponseParsingTests(unittest.TestCase):
    def _make_client(self) -> CustomAPIClient:
        config = SimpleNamespace(
            api_url="http://localhost:8000",
            api_key="test-key",
            model="openai/gpt-oss-120b",
            embedding_model="",
            temperature=0.7,
            max_tokens=1024,
            timeout=30,
            max_retries=0,
            verify_ssl=True,
            model_map={},
            llm_logging_enabled=False,
        )
        client = CustomAPIClient(config)
        client.logger = Mock()
        return client

    @staticmethod
    def _mock_response(payload):
        resp = Mock(status_code=200)
        resp.raise_for_status.return_value = None
        resp.json.return_value = payload
        return resp

    def test_standard_string_content_takes_precedence_over_reasoning(self):
        payload = {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": 'EXECUTE: decompile_function(name="main")',
                        "reasoning_content": "Scratchpad thought that should not override content.",
                    },
                    "finish_reason": "stop",
                }
            ]
        }
        self.assertEqual(
            extract_chat_completion_text(payload),
            ('EXECUTE: decompile_function(name="main")', "content"),
        )

    @patch("src.custom_api_client.requests.post")
    def test_null_content_with_completed_reasoning_returns_reasoning_text(self, post):
        client = self._make_client()
        expected = "REASONING: Inspect entry point.\nEXECUTE: list_functions()"
        for field in ("reasoning_content", "reasoning", "thinking"):
            with self.subTest(field=field):
                post.return_value = self._mock_response(
                    {
                        "choices": [
                            {
                                "message": {"role": "assistant", "content": None, field: expected},
                                "finish_reason": "stop",
                            }
                        ]
                    }
                )
                result = client.generate("Analyze binary")
                self.assertEqual(result, expected)

    def test_truncated_reasoning_on_length_returns_empty_string_for_bridge_recovery(self):
        truncated_payload = {
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "reasoning_content": 'Thinking about examples like EXECUTE: rename_function(old_name="a", new_name="b")...',
                    },
                    "finish_reason": "length",
                }
            ]
        }
        self.assertEqual(extract_chat_completion_text(truncated_payload), ("", "empty"))

    def test_structured_content_blocks_and_reasoning_details(self):
        mixed_blocks = {
            "choices": [
                {
                    "message": {
                        "content": [
                            {"type": "reasoning", "text": "Checking imports first."},
                            {"type": "text", "text": "FINAL RESPONSE: Binary initializes Winsock."},
                        ]
                    }
                }
            ]
        }
        self.assertEqual(
            extract_chat_completion_text(mixed_blocks),
            ("FINAL RESPONSE: Binary initializes Winsock.", "content"),
        )

        reasoning_details_payload = {
            "choices": [
                {
                    "message": {
                        "content": None,
                        "reasoning_details": [{"type": "reasoning.text", "text": "EXECUTE: get_current_function()"}],
                    },
                    "finish_reason": "stop",
                }
            ]
        }
        self.assertEqual(
            extract_chat_completion_text(reasoning_details_payload),
            ("EXECUTE: get_current_function()", "reasoning"),
        )

    @patch("src.custom_api_client.requests.post")
    def test_null_content_and_malformed_payloads_always_return_string(self, post):
        client = self._make_client()
        for payload, expected in (
            ({"choices": [{"message": {"content": None}, "finish_reason": "length"}]}, ""),
            ({"choices": [{"message": {"content": None, "refusal": "Blocked"}}]}, "Blocked"),
            ({"choices": None}, ""),
            ({"choices": []}, ""),
            ({}, ""),
            (None, ""),
        ):
            with self.subTest(payload=payload):
                post.return_value = self._mock_response(payload)
                result = client.generate("Analyze binary")
                self.assertIsInstance(result, str)
                self.assertEqual(result, expected)

    @patch("src.custom_api_client.requests.post")
    def test_bridge_execution_loop_end_to_end_with_gpt_oss_payloads(self, post):
        """Reproduces Issue #53's Bridge._execution_loop path across real gpt-oss-120b payloads."""
        with (
            patch("src.bridge.setup_logging", return_value=MagicMock()),
            patch("src.bridge.GhidraMCPClient", return_value=MagicMock()),
            patch("src.bridge.OllamaClient", return_value=MagicMock()),
        ):
            bridge = Bridge(BridgeConfig())
        bridge.analysis_dumper = None
        bridge.ollama = self._make_client()
        bridge.execute_command = MagicMock(return_value="main @ 0x401000")

        post.side_effect = [
            # Step 1 (vllm#30498): max_tokens hit mid-reasoning -> must retry, NOT crash or run quoted tool
            self._mock_response(
                {
                    "choices": [
                        {
                            "message": {
                                "role": "assistant",
                                "content": None,
                                "reasoning": 'Prompt example says EXECUTE: rename_function(old_name="a", new_name="b")...',
                            },
                            "finish_reason": "length",
                        }
                    ]
                }
            ),
            # Step 2 (vllm#41902): both content and reasoning null -> must retry, NOT crash len(None)
            self._mock_response(
                {
                    "choices": [
                        {
                            "message": {"role": "assistant", "content": None, "reasoning": None},
                            "finish_reason": "stop",
                        }
                    ]
                }
            ),
            # Step 3 (vllm#32791 / Issue #53): completed stop turn in reasoning_content -> executes tool
            self._mock_response(
                {
                    "choices": [
                        {
                            "message": {
                                "role": "assistant",
                                "content": None,
                                "reasoning_content": "REASONING: Check functions.\nEXECUTE: list_functions()",
                            },
                            "finish_reason": "stop",
                        }
                    ]
                }
            ),
            # Step 4: clean completion
            self._mock_response(
                {
                    "choices": [
                        {
                            "message": {"role": "assistant", "content": "INVESTIGATION COMPLETE"},
                            "finish_reason": "stop",
                        }
                    ]
                }
            ),
        ]

        results = bridge._execution_loop(plan="Inspect entry functions", max_steps=4)

        self.assertTrue(results.investigation_complete)
        self.assertEqual(results.total_steps, 1)
        bridge.execute_command.assert_called_once_with("list_functions", {})


if __name__ == "__main__":
    unittest.main()
