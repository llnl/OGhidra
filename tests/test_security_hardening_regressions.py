"""
Focused regression tests for recent security hardening changes.
"""

import hashlib
import json
import os
import re
import sys
import tempfile
import types
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

if "tkinter" not in sys.modules:
    fake_tkinter = types.ModuleType("tkinter")
    fake_ttk = types.ModuleType("tkinter.ttk")
    fake_messagebox = types.SimpleNamespace(showinfo=lambda *args, **kwargs: None, showerror=lambda *args, **kwargs: None)
    fake_tkinter.ttk = fake_ttk
    fake_tkinter.messagebox = fake_messagebox
    sys.modules["tkinter"] = fake_tkinter
    sys.modules["tkinter.ttk"] = fake_ttk

from src.context_manager import ResultCache
from src.custom_api_client import CustomAPIClient
from src.enhanced_session_manager import EnhancedSessionManager
from src.gui.server_config_dialog import ServerConfigDialog, _ValueProxy


class FakeVar:
    """Simple stand-in for Tk variables in dialog helper tests."""

    def __init__(self, value):
        self._value = value

    def get(self):
        return self._value


class SecurityHardeningRegressionTests(unittest.TestCase):
    @staticmethod
    def _make_custom_api_config(**overrides):
        config = {
            "api_url": "https://api.example.com/v1/chat/completions",
            "api_key": "secret",
            "model": "gpt-test",
            "verify_ssl": False,
            "llm_logging_enabled": False,
        }
        config.update(overrides)
        return SimpleNamespace(**config)

    def test_result_cache_uses_sha256_for_short_parameter_hash(self):
        cache = ResultCache(max_cache_size=5)
        params = {"name": "main", "offset": 1}

        result = cache.store("decompile_function", params, "int main(void) { return 0; }")
        expected_suffix = hashlib.sha256(json.dumps(params, sort_keys=True).encode("utf-8")).hexdigest()[:8]

        self.assertEqual(result.result_id, f"r1_decompile_function_{expected_suffix}")

    def test_enhanced_session_manager_session_ids_keep_shape(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = EnhancedSessionManager(sessions_dir=tmpdir)
            session_id = manager.create_session("example session")

        self.assertRegex(session_id, r"^session_\d+_[0-9a-f]{8}$")
        expected_suffix = hashlib.sha256(b"example session").hexdigest()[:8]
        self.assertTrue(session_id.endswith(expected_suffix))

    def test_server_dialog_builds_custom_api_request_with_verify_ssl(self):
        dialog = ServerConfigDialog.__new__(ServerConfigDialog)
        dialog.custom_api_url_var = FakeVar("https://api.example.com/v1/chat/completions")
        dialog.custom_api_key_var = FakeVar("secret")
        dialog.custom_api_model_var = FakeVar("gpt-test")
        dialog.custom_api_verify_ssl_var = FakeVar(True)

        request_data = dialog._build_custom_api_test_request()

        self.assertEqual(request_data["url"], "https://api.example.com/v1/chat/completions")
        self.assertEqual(request_data["headers"]["Authorization"], "Bearer secret")
        self.assertTrue(request_data["verify"])
        self.assertEqual(request_data["json"]["model"], "gpt-test")

    def test_client_health_uses_shared_probe_without_changing_generation_budget(self):
        client = CustomAPIClient(self._make_custom_api_config(max_tokens=16000))
        client.logger = Mock()
        with patch("src.api_health.requests.post") as post:
            post.return_value = Mock(status_code=200)
            self.assertTrue(client.check_health())
            self.assertEqual(post.call_args.kwargs["json"]["max_completion_tokens"], 4096)
            self.assertEqual(client.max_tokens, 16000)
            post.return_value = Mock(status_code=400)
            post.return_value.json.return_value = {"error": {"message": "Unknown model"}}
            self.assertFalse(client.check_health())
            self.assertIn("Unknown model", client.logger.error.call_args.args[2])

    def test_dialog_displays_network_and_non_json_errors(self):
        import requests

        dialog = ServerConfigDialog.__new__(ServerConfigDialog)
        dialog.provider_var = FakeVar("custom_api")
        dialog.custom_api_url_var = FakeVar("https://example.test/v1")
        dialog.custom_api_key_var = FakeVar("secret")
        dialog.custom_api_model_var = FakeVar("alias")
        dialog.custom_api_verify_ssl_var = FakeVar(True)
        dialog.ghidra_url_var = FakeVar("http://localhost:8080")
        dialog.config = SimpleNamespace(ghidra=SimpleNamespace(backend="http"))
        with (
            patch("src.gui.server_config_dialog.threading.Thread") as thread,
            patch("src.gui.server_config_dialog.run_on_ui", side_effect=lambda callback: callback()),
            patch("src.gui.server_config_dialog.messagebox.showinfo") as show,
            patch("requests.get", return_value=Mock(status_code=200)),
            patch("src.api_health.requests.post") as post,
        ):
            thread.side_effect = lambda target, **kwargs: SimpleNamespace(start=target)
            post.side_effect = requests.ConnectionError("DNS lookup failed")
            dialog._test_connections()
            self.assertIn("Custom API: [ERROR] DNS lookup failed", show.call_args.args[1])
            post.side_effect = None
            post.return_value = Mock(status_code=502, text="Gateway unavailable")
            post.return_value.json.side_effect = ValueError("not JSON")
            dialog._test_connections()
            self.assertIn("HTTP 502", show.call_args.args[1])
            self.assertIn("Gateway unavailable", show.call_args.args[1])

    def test_ollama_dialog_authenticates_tags_and_both_embedding_endpoints(self):
        dialog = ServerConfigDialog.__new__(ServerConfigDialog)
        dialog.provider_var = FakeVar("ollama")
        dialog.ollama_url_var = FakeVar("https://ollama.example.test")
        dialog.embedding_model_var = FakeVar("embedding-model")
        dialog.ghidra_url_var = FakeVar("http://localhost:8080")
        dialog.config = SimpleNamespace(
            ollama=SimpleNamespace(username="test-user", password="test-password"),
            ghidra=SimpleNamespace(backend="http"),
        )
        expected_auth = ("test-user", "test-password")
        with (
            patch("src.gui.server_config_dialog.threading.Thread") as thread,
            patch("src.gui.server_config_dialog.run_on_ui", side_effect=lambda callback: callback()),
            patch("src.gui.server_config_dialog.messagebox.showinfo") as show,
            patch("requests.get", return_value=Mock(status_code=200)) as get,
            patch("requests.post") as post,
        ):
            thread.side_effect = lambda target, **kwargs: SimpleNamespace(start=target)
            post.side_effect = [Mock(status_code=404), Mock(status_code=200)]
            dialog._test_connections()
            get.assert_any_call("https://ollama.example.test/api/tags", timeout=5, auth=expected_auth)
            self.assertEqual(post.call_count, 2)
            for call, endpoint in zip(post.call_args_list, ("embed", "embeddings"), strict=True):
                self.assertEqual(call.args[0], f"https://ollama.example.test/api/{endpoint}")
                self.assertEqual(call.kwargs["auth"], expected_auth)
            for call in get.call_args_list:
                if call.args[0].startswith("http://localhost:8080"):
                    self.assertNotIn("auth", call.kwargs)
            self.assertIn("Ollama: [OK] Connected", show.call_args.args[1])
            self.assertIn("Available (legacy API)", show.call_args.args[1])
            self.assertNotIn("test-password", show.call_args.args[1])

    def test_server_dialog_env_updates_persist_verify_ssl(self):
        dialog = ServerConfigDialog.__new__(ServerConfigDialog)
        dialog.ollama_model_var = FakeVar("gemma3:27b")
        dialog.embedding_model_var = FakeVar("nomic-embed-text")
        dialog.ext_provider_var = FakeVar("google")
        dialog.ext_key_var = FakeVar("ext-key")
        dialog.ext_model_var = FakeVar("gemini-3.1")
        dialog.ext_embed_var = FakeVar("gemini-embedding")
        dialog.custom_api_url_var = FakeVar("https://api.example.com/v1/chat/completions")
        dialog.custom_api_key_var = FakeVar("custom-key")
        dialog.custom_api_model_var = FakeVar("gpt-test")
        dialog.custom_api_embed_var = FakeVar("text-embedding-3-small")
        dialog.custom_api_max_tokens_var = FakeVar("2048")
        dialog.custom_api_verify_ssl_var = _ValueProxy(False)

        env_updates = dialog._build_env_updates("http://localhost:11434", "http://localhost:8080", "custom_api")

        self.assertEqual(env_updates["CUSTOM_API_VERIFY_SSL"], "false")
        self.assertEqual(env_updates["CUSTOM_API_MODEL"], "gpt-test")
        self.assertEqual(env_updates["LLM_PROVIDER"], "custom_api")

    def test_custom_api_tls_warning_emits_only_once(self):
        ui_callback = Mock()
        client = CustomAPIClient(self._make_custom_api_config(ui_event_callback=ui_callback, verify_ssl=False))
        client.logger = Mock()

        client._warn_if_tls_verification_disabled("chat completions")
        client._warn_if_tls_verification_disabled("embeddings")

        client.logger.warning.assert_called_once()
        warning_message = client.logger.warning.call_args[0][0]
        self.assertIn("TLS certificate verification is disabled", warning_message)
        self.assertIn("chat completions", warning_message)
        ui_callback.assert_called_once_with(
            "security_warning",
            {
                "provider": "custom_api",
                "operation": "chat completions",
                "verify_ssl": False,
                "message": warning_message,
            },
        )
        self.assertTrue(client._tls_warning_emitted)

    def test_custom_api_tls_warning_skipped_when_verification_enabled(self):
        ui_callback = Mock()
        client = CustomAPIClient(self._make_custom_api_config(ui_event_callback=ui_callback, verify_ssl=True))
        client.logger = Mock()

        client._warn_if_tls_verification_disabled("chat completions")

        client.logger.warning.assert_not_called()
        ui_callback.assert_not_called()
        self.assertFalse(client._tls_warning_emitted)

    def test_touched_files_use_ascii_only(self):
        files_to_check = [
            "src/custom_api_client.py",
            "src/context_manager.py",
            "src/enhanced_session_manager.py",
            "src/gui/server_config_dialog.py",
        ]

        non_ascii = re.compile(r"[^\x00-\x7F]")
        for relative_path in files_to_check:
            with open(relative_path, "r", encoding="utf-8") as handle:
                contents = handle.read()
            self.assertIsNone(non_ascii.search(contents), msg=f"Found non-ASCII text in {relative_path}")


if __name__ == "__main__":
    unittest.main()
