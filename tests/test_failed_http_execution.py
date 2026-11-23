"""HTTP failures must remain failed investigations, not cached successful evidence."""

import io
import logging
import threading
import unittest
from contextlib import redirect_stdout
from types import SimpleNamespace
from unittest.mock import Mock

import httpx

from src.bridge import Bridge
from src.command_parser import CommandParser
from src.coverage_tracker import CoverageTracker
from src.ghidra_client import GhidraMCPClient
from src.models.memory import ExecutionSignal


class FailedHttpExecutionTests(unittest.TestCase):
    def make_bridge(self, replies, commands):
        requests = []
        response_queue = iter(replies)

        def handle(request):
            requests.append(request)
            item = next(response_queue)
            if isinstance(item, Exception):
                raise item
            status, text = item
            return httpx.Response(status, text=text)

        # Use the real HTTP client and Ghidra methods with an in-process transport.
        # Never connect to Ghidra or a model provider during this regression test.
        client = GhidraMCPClient.__new__(GhidraMCPClient)
        client.config = SimpleNamespace(base_url="http://ghidra.invalid:8080", timeout=1)
        client.current_instance_port = None
        client.active_instances = {}
        client._request_lock = threading.Lock()
        client.client = httpx.Client(transport=httpx.MockTransport(handle), trust_env=False)
        self.addCleanup(client.client.close)

        bridge = Bridge.__new__(Bridge)
        bridge.logger = logging.getLogger("test.http-execution")
        bridge.config = SimpleNamespace(ollama=SimpleNamespace(show_reasoning=False))
        bridge.ghidra_client = client
        bridge.command_parser = CommandParser()
        bridge.current_goal = "Investigate network behavior"
        bridge.current_loop_number = 1
        bridge.executed_tools = set()
        bridge.step_result_map = {}
        bridge.cache_stats = {"hits": 0, "misses": 0, "cache_size": 0}
        bridge.decompilation_cache = {}
        bridge.function_cache = {}
        bridge.enable_cag = False
        bridge.cag_manager = None
        bridge.context_manager = None
        bridge.result_compactor = None
        bridge.analysis_dumper = None
        bridge.task_mode_enabled = False
        bridge.session = Mock()
        bridge.coverage_tracker = CoverageTracker()
        bridge.execution_gate = Mock()
        bridge.execution_gate.consume_feedback.return_value = None
        bridge.execution_gate.check_before_execution.return_value = ExecutionSignal.CONTINUE
        bridge.execution_gate.check_after_execution.return_value = ExecutionSignal.CONTINUE
        bridge._build_execution_loop_prompt = Mock(return_value=("system", "user"))
        bridge._get_max_result_chars = Mock(return_value=10000)
        bridge._update_analysis_state = Mock()
        bridge._display_tool_result = Mock()
        bridge._emit_cot = Mock()
        bridge.ollama = SimpleNamespace(generate_with_phase=Mock(side_effect=commands))
        return bridge, requests

    def execute(self, bridge, steps=2):
        with redirect_stdout(io.StringIO()):
            return bridge._execution_loop("Inspect the selected function", max_steps=steps)

    def test_http_error_is_not_successful_cached_or_covered(self):
        bridge, requests = self.make_bridge(
            [(503, "backend unavailable")],
            ['EXECUTE: decompile_function(name="connect_helper")', "INVESTIGATION COMPLETE"],
        )
        result = self.execute(bridge)
        self.assertEqual(len(requests), 1)
        self.assertFalse(result.tool_executions[0].success)
        self.assertIn("503", result.tool_executions[0].error)
        self.assertFalse(bridge.coverage_tracker.areas["network_comms"].covered)
        self.assertEqual(bridge.decompilation_cache, {})

    def test_timeout_is_not_successful_or_covered(self):
        bridge, _ = self.make_bridge(
            [httpx.ReadTimeout("timed out")],
            ['EXECUTE: list_strings(filter="service")', "INVESTIGATION COMPLETE"],
        )
        result = self.execute(bridge)
        self.assertFalse(result.tool_executions[0].success)
        self.assertFalse(bridge.coverage_tracker.areas["service_management"].covered)
        self.assertEqual(bridge.decompilation_cache, {})

    def test_identical_call_can_be_retried_after_transport_recovers(self):
        bridge, requests = self.make_bridge(
            [(503, "backend unavailable"), (200, "void connect_helper(void) {}")],
            [
                'EXECUTE: decompile_function(name="connect_helper")',
                'EXECUTE: decompile_function(name="connect_helper")',
                "INVESTIGATION COMPLETE",
            ],
        )
        result = self.execute(bridge, steps=3)
        self.assertEqual(len(requests), 2)
        self.assertEqual([entry.success for entry in result.tool_executions], [False, True])
        self.assertTrue(bridge.coverage_tracker.areas["network_comms"].covered)
        self.assertEqual(len(bridge.decompilation_cache), 1)

    def test_error_looking_binary_content_on_http_200_remains_data(self):
        text = "Error 503: this text is evidence from the binary"
        bridge, _ = self.make_bridge(
            [(200, text)],
            ['EXECUTE: decompile_function(name="connect_helper")', "INVESTIGATION COMPLETE"],
        )
        result = self.execute(bridge)
        self.assertTrue(result.tool_executions[0].success)
        self.assertEqual(result.tool_executions[0].result, text)
        self.assertTrue(bridge.coverage_tracker.areas["network_comms"].covered)
        self.assertEqual(len(bridge.decompilation_cache), 1)


if __name__ == "__main__":
    unittest.main()
