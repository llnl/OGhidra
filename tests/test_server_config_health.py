"""Regression tests for Server Configuration connection checks and Ghidra backends (Issue #34)."""

import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock, patch

from src.config import BridgeConfig
from src.gui.server_config_dialog import ServerConfigDialog, _ValueProxy
from src.gui.ui import OGhidraUI


class ServerConfigHealthTests(unittest.TestCase):
    def _make_dialog(self, *, backend: str = "http", ghidra_url: str = "http://localhost:8080/"):
        dialog = ServerConfigDialog.__new__(ServerConfigDialog)
        dialog.ghidra_client = None
        dialog.provider_var = _ValueProxy("ollama")
        dialog.ollama_url_var = _ValueProxy("http://localhost:11434/")
        dialog.embedding_model_var = _ValueProxy("")
        dialog.ghidra_backend_var = _ValueProxy(backend)
        dialog.ghidra_url_var = _ValueProxy(ghidra_url)
        dialog.pyghidra_project_path_var = _ValueProxy("/tmp/proj.gpr")
        dialog.pyghidra_program_var = _ValueProxy("sample.exe")
        dialog.pyghidra_binary_var = _ValueProxy("")
        dialog.config = SimpleNamespace(
            ollama=SimpleNamespace(username="", password=""),
            ghidra=SimpleNamespace(
                base_url=ghidra_url,
                backend=backend,
                api_path="",
                timeout=30,
                mock_mode=False,
                pyghidra_project_path="/tmp/proj.gpr",
                pyghidra_program="sample.exe",
                pyghidra_binary=None,
            ),
        )
        return dialog

    def test_http_mode_strips_trailing_slash_and_probes_ghidramcp_once(self):
        """Trailing slash from AnyHttpUrl must not produce //methods (HTTP 404) or duplicate lines."""
        dialog = self._make_dialog(backend="http", ghidra_url="http://localhost:8080/")
        with (
            patch("src.gui.server_config_dialog.threading.Thread") as thread,
            patch("src.gui.server_config_dialog.run_on_ui", side_effect=lambda cb: cb()),
            patch("src.gui.server_config_dialog.messagebox.showinfo") as show,
            patch("requests.get", return_value=Mock(status_code=200)) as get,
        ):
            thread.side_effect = lambda target, **kwargs: SimpleNamespace(start=target)
            dialog._test_connections()

        urls = [call.args[0] for call in get.call_args_list]
        self.assertEqual(urls, ["http://localhost:11434/api/tags", "http://localhost:8080/methods"])
        message = show.call_args.args[1]
        self.assertEqual(message.count("GhidraMCP:"), 1)
        self.assertIn("GhidraMCP: [OK] Connected", message)

    def test_pyghidra_mode_reuses_matching_live_client_and_skips_http_probe(self):
        dialog = self._make_dialog(backend="pyghidra")
        live_client = MagicMock()
        live_client.config = dialog.config.ghidra
        live_client.check_health.return_value = True
        dialog.ghidra_client = live_client

        with (
            patch("src.gui.server_config_dialog.threading.Thread") as thread,
            patch("src.gui.server_config_dialog.run_on_ui", side_effect=lambda cb: cb()),
            patch("src.gui.server_config_dialog.messagebox.showinfo") as show,
            patch("requests.get", return_value=Mock(status_code=200)) as get,
            patch("src.ghidra_client.PyGhidraClient") as pyghidra_cls,
        ):
            thread.side_effect = lambda target, **kwargs: SimpleNamespace(start=target)
            dialog._test_connections()

        live_client.check_health.assert_called_once()
        pyghidra_cls.assert_not_called()
        self.assertEqual([c.args[0] for c in get.call_args_list], ["http://localhost:11434/api/tags"])
        message = show.call_args.args[1]
        self.assertIn("PyGhidra: [OK] Connected", message)
        self.assertNotIn("GhidraMCP:", message)

    def test_pyghidra_mode_probes_and_closes_temporary_client_when_target_changed(self):
        dialog = self._make_dialog(backend="pyghidra")
        dialog.pyghidra_program_var = _ValueProxy("new_target.exe")
        temp_client = MagicMock()
        temp_client.check_health.return_value = True

        with (
            patch("src.gui.server_config_dialog.threading.Thread") as thread,
            patch("src.gui.server_config_dialog.run_on_ui", side_effect=lambda cb: cb()),
            patch("src.gui.server_config_dialog.messagebox.showinfo") as show,
            patch("requests.get", return_value=Mock(status_code=200)),
            patch("src.ghidra_client.PyGhidraClient", return_value=temp_client) as pyghidra_cls,
        ):
            thread.side_effect = lambda target, **kwargs: SimpleNamespace(start=target)
            dialog._test_connections()

        pyghidra_cls.assert_called_once()
        self.assertEqual(pyghidra_cls.call_args.args[0].pyghidra_program, "new_target.exe")
        temp_client.close.assert_called_once()
        self.assertIn("PyGhidra: [OK] Connected", show.call_args.args[1])

    def test_ui_recreates_ghidra_client_when_url_or_backend_changes(self):
        ui = OGhidraUI.__new__(OGhidraUI)
        ui.root = MagicMock()
        ui.config = BridgeConfig()
        old_client = MagicMock()
        ui.bridge = SimpleNamespace(
            ghidra_client=old_client,
            ollama=MagicMock(),
            reload_llm_client=MagicMock(),
        )
        new_client = MagicMock()

        def fake_dialog(_root, config, ghidra_client=None):
            self.assertIs(ghidra_client, old_client)
            config.ghidra.backend = "pyghidra"
            config.ghidra.pyghidra_binary = "/tmp/a.out"
            return SimpleNamespace(result=True)

        with (
            patch("src.gui.ui.ServerConfigDialog", side_effect=fake_dialog),
            patch("src.bridge.select_ghidra_client_class", return_value=(MagicMock(return_value=new_client), "pyghidra")),
            patch("src.gui.ui.messagebox.showinfo"),
        ):
            ui._configure_servers()

        old_client.close.assert_called_once()
        self.assertIs(ui.bridge.ghidra_client, new_client)

    def test_end_to_end_health_check_and_test_connections_match_against_ghidramcp_router(self):
        """Real BridgeConfig + GhidraMCPClient + OGhidraUI._health_check + ServerConfigDialog agree."""
        from urllib.parse import urlsplit

        import httpx

        from src.ghidra_client import GhidraMCPClient

        def ghidramcp_status(url: str) -> tuple[int, str]:
            # Mirrors OGhidraMCP GhidraMCPPlugin.java HttpServer.createContext("/methods", ...):
            # "/methods" returns 200, whereas "//methods" (unstripped AnyHttpUrl trailing slash) returns 404.
            path = urlsplit(url).path
            if path == "/methods":
                return 200, "main\n"
            if path == "/api/tags":
                return 200, '{"models":[]}'
            return 404, "<h1>404 Not Found</h1>No context found for request"

        self.assertEqual(ghidramcp_status("http://localhost:8080//methods")[0], 404)

        config = BridgeConfig(ghidra={"base_url": "http://localhost:8080"})
        self.assertEqual(str(config.ghidra.base_url), "http://localhost:8080/")

        def httpx_handler(request: httpx.Request) -> httpx.Response:
            code, body = ghidramcp_status(str(request.url))
            return httpx.Response(code, text=body)

        def requests_get(url: str, **kwargs):
            code, body = ghidramcp_status(url)
            return Mock(status_code=code, text=body, json=lambda: {"models": []})

        real_httpx_client = httpx.Client
        with patch(
            "src.ghidra_client.httpx.Client",
            side_effect=lambda **kw: real_httpx_client(transport=httpx.MockTransport(httpx_handler)),
        ):
            ghidra_client = GhidraMCPClient(config.ghidra)

        ui = OGhidraUI.__new__(OGhidraUI)
        ui.config = config
        ui.bridge = SimpleNamespace(
            ollama=SimpleNamespace(check_health=lambda: True),
            ghidra=ghidra_client,
            enable_cag=True,
        )

        dialog = self._make_dialog(backend=config.ghidra.backend, ghidra_url=str(config.ghidra.base_url))

        with (
            patch("src.gui.ui.threading.Thread", side_effect=lambda target, **kw: SimpleNamespace(start=target)),
            patch("src.gui.ui.ui_thread.run_on_ui", side_effect=lambda cb: cb()),
            patch(
                "src.gui.server_config_dialog.threading.Thread", side_effect=lambda target, **kw: SimpleNamespace(start=target)
            ),
            patch("src.gui.server_config_dialog.run_on_ui", side_effect=lambda cb: cb()),
            patch("tkinter.messagebox.showinfo") as showinfo,
            patch("requests.get", side_effect=requests_get),
        ):
            ui._health_check()
            dialog._test_connections()

        health_msg = showinfo.call_args_list[0].args[1]
        dialog_msg = showinfo.call_args_list[1].args[1]
        self.assertIn("GhidraMCP API: OK", health_msg)
        self.assertEqual(dialog_msg.count("GhidraMCP:"), 1)
        self.assertIn("GhidraMCP: [OK] Connected", dialog_msg)

    def test_save_persists_pyghidra_settings_and_real_pyghidra_import_resolves(self):
        """_save() updates BridgeConfig + .env, and pyghidra mode imports real PyGhidraClient cleanly."""
        import tempfile
        from pathlib import Path

        config = BridgeConfig()
        dialog = ServerConfigDialog.__new__(ServerConfigDialog)
        dialog.config = config
        dialog.ghidra_client = None
        dialog.dialog = MagicMock()
        dialog.provider_var = _ValueProxy("ollama")
        dialog.ollama_url_var = _ValueProxy("http://localhost:11434")
        dialog.ollama_model_var = _ValueProxy("gemma3:27b")
        dialog.embedding_model_var = _ValueProxy("nomic-embed-text")
        dialog.ghidra_backend_var = _ValueProxy("pyghidra")
        dialog.ghidra_url_var = _ValueProxy("")
        dialog.pyghidra_project_path_var = _ValueProxy("/tmp/rev.gpr")
        dialog.pyghidra_program_var = _ValueProxy("target.bin")
        dialog.pyghidra_binary_var = _ValueProxy("/tmp/target.bin")
        dialog.ext_provider_var = _ValueProxy("google")
        dialog.ext_key_var = _ValueProxy("")
        dialog.ext_model_var = _ValueProxy("gemini-1.5-flash")
        dialog.ext_embed_var = _ValueProxy("text-embedding-004")
        dialog.custom_api_url_var = _ValueProxy("https://api.example.com/v1/chat/completions")
        dialog.custom_api_key_var = _ValueProxy("")
        dialog.custom_api_model_var = _ValueProxy("gpt-4")
        dialog.custom_api_embed_var = _ValueProxy("text-embedding-ada-002")
        dialog.custom_api_max_tokens_var = _ValueProxy("4096")
        dialog.custom_api_verify_ssl_var = _ValueProxy(False)

        with tempfile.TemporaryDirectory() as tmpdir:
            fake_module_file = Path(tmpdir) / "gui" / "server_config_dialog.py"
            fake_module_file.parent.mkdir(parents=True, exist_ok=True)
            with patch("src.gui.server_config_dialog.__file__", str(fake_module_file)):
                dialog._save()
            env_text = (Path(tmpdir) / ".env").read_text(encoding="utf-8")

        self.assertTrue(dialog.result)
        self.assertEqual(config.ghidra.backend, "pyghidra")
        self.assertEqual(config.ghidra.pyghidra_project_path, "/tmp/rev.gpr")
        self.assertEqual(config.ghidra.pyghidra_program, "target.bin")
        self.assertEqual(config.ghidra.pyghidra_binary, "/tmp/target.bin")
        self.assertIn("GHIDRA_BACKEND=pyghidra\n", env_text)
        self.assertIn("PYGHIDRA_PROJECT_PATH=/tmp/rev.gpr\n", env_text)
        self.assertIn("PYGHIDRA_PROGRAM=target.bin\n", env_text)
        self.assertIn("PYGHIDRA_BINARY=/tmp/target.bin\n", env_text)

        # Run _test_connections without mocking PyGhidraClient import to prove relative import works
        with (
            patch(
                "src.gui.server_config_dialog.threading.Thread", side_effect=lambda target, **kw: SimpleNamespace(start=target)
            ),
            patch("src.gui.server_config_dialog.run_on_ui", side_effect=lambda cb: cb()),
            patch("src.gui.server_config_dialog.messagebox.showinfo") as test_popup,
            patch("requests.get", return_value=Mock(status_code=200)),
        ):
            dialog._test_connections()

        msg = test_popup.call_args.args[1]
        self.assertNotIn("No module named 'src.gui.ghidra_client'", msg)
        self.assertNotIn("GhidraMCP:", msg)
        self.assertIn("PyGhidra:", msg)


if __name__ == "__main__":
    unittest.main()
