#!/usr/bin/env python3
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
from src.enhanced_session_manager import EnhancedSessionManager
from src.gui.server_config_dialog import ServerConfigDialog, _ValueProxy


class FakeVar:
    """Simple stand-in for Tk variables in dialog helper tests."""

    def __init__(self, value):
        self._value = value

    def get(self):
        return self._value


class SecurityHardeningRegressionTests(unittest.TestCase):
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
        expected_suffix = hashlib.sha256("example session".encode("utf-8")).hexdigest()[:8]
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
