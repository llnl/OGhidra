import os
import sys
import unittest
from unittest.mock import patch

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

from src.config import GhidraMCPConfig  # noqa: E402
from src.ghidra_client import GhidraMCPClient  # noqa: E402


class FakeResponse:
    def __init__(self, status_code=200, text="", json_data=None):
        self.status_code = status_code
        self.text = text
        self.encoding = None
        self._json_data = json_data

    def json(self):
        if self._json_data is None:
            return {}
        return self._json_data


class FakeHttpClient:
    def __init__(self, routes=None):
        self.routes = routes or {}
        self.calls = []

    def get(self, url, params=None, timeout=None):
        self.calls.append(("GET", url, params, timeout))
        response = self.routes.get(url)
        if isinstance(response, Exception):
            raise response
        if response is None:
            raise OSError(f"No route for {url}")
        return response

    def post(self, url, params=None, data=None, timeout=None):
        self.calls.append(("POST", url, params, timeout))
        response = self.routes.get(url)
        if isinstance(response, Exception):
            raise response
        if response is None:
            raise OSError(f"No route for {url}")
        return response


class TestGhidraMCPClientConnection(unittest.TestCase):
    def make_client(self, config, fake_http):
        with patch("src.ghidra_client.httpx.Client", return_value=fake_http):
            return GhidraMCPClient(config)

    def test_failed_default_port_is_not_reported_as_active(self):
        fake_http = FakeHttpClient()
        config = GhidraMCPConfig(base_url="http://localhost:8080/")

        client = self.make_client(config, fake_http)

        self.assertEqual(client.active_instances, {})
        self.assertIn("No active Ghidra instances found", client.instances_list())

    def test_discovers_dynamic_port_when_default_port_is_unavailable(self):
        fake_http = FakeHttpClient(
            {
                "http://localhost:8192/plugin-version": FakeResponse(
                    json_data={"result": {"plugin_version": "Custom-OGhidraMCP"}}
                ),
                "http://localhost:8192/program": FakeResponse(
                    json_data={"result": {"name": "sample.exe", "programId": "proj:sample.exe"}}
                ),
                "http://localhost:8192/methods": FakeResponse(text="FUN_140001000\n"),
            }
        )
        config = GhidraMCPConfig(base_url="http://localhost:8080/")

        client = self.make_client(config, fake_http)

        self.assertEqual(client.current_instance_port, 8192)
        self.assertEqual(client._get_base_url(), "http://localhost:8192")
        self.assertTrue(client.check_health())
        self.assertIn(8192, client.active_instances)

    def test_api_path_is_applied_to_configured_and_discovered_urls(self):
        fake_http = FakeHttpClient(
            {
                "http://localhost:8080/ghidra/methods": FakeResponse(text="FUN_140001000\n"),
                "http://localhost:8080/ghidra/program": FakeResponse(
                    json_data={"result": {"name": "sample.exe", "programId": "proj:sample.exe"}}
                ),
                "http://localhost:8080/ghidra/plugin-version": FakeResponse(
                    json_data={"result": {"plugin_version": "Custom-OGhidraMCP"}}
                ),
            }
        )
        config = GhidraMCPConfig(base_url="http://localhost:8080", api_path="/ghidra")

        client = self.make_client(config, fake_http)

        self.assertEqual(client._get_base_url(), "http://localhost:8080/ghidra")
        self.assertEqual(client.list_methods(offset=0, limit=1), ["FUN_140001000"])


if __name__ == "__main__":
    unittest.main()
