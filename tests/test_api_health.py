"""Regression coverage for provider-independent Custom API health probes."""

import unittest
from unittest.mock import Mock, patch

import requests

from src.api_health import build_health_request, health_error_detail, post_health_request


class APIHealthTests(unittest.TestCase):
    def setUp(self):
        self.request = build_health_request("https://example.test/v1", "secret", "deployment-alias", True)

    @staticmethod
    def response(status, message=""):
        response = Mock(status_code=status)
        response.json.return_value = {"error": {"message": message}}
        return response

    def test_url_variants_and_isolated_budget(self):
        for suffix in ("", "/", "/v1", "/v1/", "/v1/chat/completions", "/v1/chat/completions/"):
            with self.subTest(suffix=suffix):
                request = build_health_request("https://example.test" + suffix, "secret", "alias", False)
                self.assertEqual(request["url"], "https://example.test/v1/chat/completions")
                self.assertEqual(request["json"]["max_completion_tokens"], 4096)
                self.assertEqual(request["timeout"], (10, 60))
                self.assertFalse(request["verify"])
                self.assertNotIn("temperature", request["json"])
                self.assertNotIn("reasoning_effort", request["json"])

    @patch("src.api_health.requests.post")
    def test_modern_parameter_succeeds_without_retry(self, post):
        post.return_value = self.response(200)
        self.assertIs(post_health_request(self.request), post.return_value)
        post.assert_called_once_with(**self.request)

    @patch("src.api_health.requests.post")
    def test_explicit_rejection_retries_legacy_field_without_mutating_input(self, post):
        for message in (
            "Unsupported parameter: 'max_completion_tokens'. Use 'max_tokens' instead.",
            "max_completion_tokens is not supported with this model",
            "Unknown field: max_completion_tokens",
        ):
            with self.subTest(message=message):
                post.reset_mock()
                success = self.response(200)
                post.side_effect = [self.response(400, message), success]
                self.assertIs(post_health_request(self.request), success)
                self.assertEqual(post.call_count, 2)
                first = post.call_args_list[0].kwargs
                second = post.call_args_list[1].kwargs
                self.assertEqual(first["json"]["max_completion_tokens"], 4096)
                self.assertEqual(second["json"]["max_tokens"], 4096)
                self.assertNotIn("max_completion_tokens", second["json"])
                self.assertTrue(second["verify"])
                self.assertIn("max_completion_tokens", self.request["json"])

    @patch("src.api_health.requests.post")
    def test_no_retry_for_unrelated_errors(self, post):
        for status, message in (
            (400, "Could not finish because max_completion_tokens was reached"),
            (400, "Unsupported parameter: temperature"),
            (401, "Unauthorized"),
            (404, "Model not found"),
            (429, "Rate limit"),
            (500, "Internal error"),
        ):
            with self.subTest(status=status, message=message):
                post.reset_mock()
                post.return_value = self.response(status, message)
                self.assertIs(post_health_request(self.request), post.return_value)
                post.assert_called_once()

    @patch("src.api_health.requests.post")
    def test_retry_is_bounded_and_final_error_is_preserved(self, post):
        error = self.response(400, "Unsupported parameter: max_completion_tokens")
        final = self.response(400, "max_tokens is not supported")
        post.side_effect = [error, final]
        self.assertIs(post_health_request(self.request), final)
        self.assertEqual(post.call_count, 2)

    @patch("src.api_health.requests.post")
    def test_network_errors_propagate_without_parameter_retry(self, post):
        for error in (requests.ConnectionError("DNS lookup failed"), requests.Timeout("Read timed out")):
            with self.subTest(error=error):
                post.reset_mock()
                post.side_effect = error
                with self.assertRaises(type(error)):
                    post_health_request(self.request)
                post.assert_called_once()

    def test_non_json_error_is_preserved(self):
        response = Mock(text="Gateway unavailable")
        response.json.side_effect = ValueError("not JSON")
        self.assertEqual(health_error_detail(response), "Gateway unavailable")


if __name__ == "__main__":
    unittest.main()
