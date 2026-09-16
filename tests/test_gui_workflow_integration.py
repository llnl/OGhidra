"""Headless integration checks for the real bulk GUI workflow method."""

import unittest
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from unittest.mock import Mock, patch

from src.gui import tool_buttons_panel as gui_tools
from src.workflow import WorkItem, WorkResult
from src.workflow_host import WorkflowHost


class ImmediateThread:
    def __init__(self, target, daemon=False):
        self.target = target

    def start(self):
        self.target()


class GuiWorkflowIntegrationTests(unittest.TestCase):
    def make_panel(self, functions=None):
        panel = gui_tools.ToolButtonsPanel.__new__(gui_tools.ToolButtonsPanel)
        client = SimpleNamespace(list_functions=Mock(return_value=functions or ["FUN_a at 1000", "FUN_b at 2000"]))
        panel.bridge = SimpleNamespace(
            ghidra=client,
            ghidra_client=client,
            config=SimpleNamespace(plugin_paths=[], plugin_settings={}, plugin_context_budget=2000),
            cag_manager=None,
        )
        panel.should_stop = False
        panel.response_panel = Mock()
        panel.workflow_diagram = Mock()
        panel.renamed_functions_panel = SimpleNamespace(functions={}, add_function_with_summary=Mock())
        panel._set_tool_running = Mock()
        panel._create_batch_rag_vectors = Mock(side_effect=lambda records: len(records))
        panel._get_cache_stats = Mock(return_value={"hits": 0, "hit_rate_pct": 0, "misses": 0, "total_requests": 0})
        panel._clear_decompilation_cache = Mock()
        panel.session_manager = Mock()
        panel.session_manager.save_current_session.return_value = True
        return panel

    @staticmethod
    def success(function, result_type="enumerated"):
        name, address = function.split(" at ")
        return {
            "success": True,
            "result_type": result_type,
            "function_name": name,
            "address": address,
            "suggested_name": f"analyzed_{name}",
            "summary": f"summary of {name}",
            "function_data": {"address": address, "old_name": name, "new_name": f"analyzed_{name}"},
        }

    def run_bulk(self, panel, *, host=None, skip_analyzed=False):
        host = host or WorkflowHost(panel.bridge)
        panel.bridge.workflow_host = host
        with (
            patch.object(gui_tools, "threading", SimpleNamespace(Thread=ImmediateThread)),
            patch.object(gui_tools, "DaemonThreadPoolExecutor", ThreadPoolExecutor),
        ):
            panel._run_bulk_rename_workflow("Analyze all", "full_enumeration", skip_analyzed=skip_analyzed)
        return host

    @staticmethod
    def messages(panel):
        return "\n".join(str(call.args) for call in panel.response_panel.add_response.call_args_list)

    def test_real_host_applies_plan_dependencies_and_preserves_worker_and_ui(self):
        panel = self.make_panel()
        calls = []
        panel._process_single_function_for_bulk_rename = Mock(
            side_effect=lambda index, function, mode, total: (
                calls.append((index, function, mode, total))
                or self.success(function, "renamed" if index == 1 else "enumerated")
            )
        )
        host = WorkflowHost(panel.bridge)

        def reverse(plan, context):
            plan.items.reverse()
            plan.items[1].depends_on = (plan.items[0].id,)
            return plan

        host.runtime.add_hook("workflow.plan", reverse)
        recorded = []
        host.runtime.subscribe("analysis.completed", lambda event, ctx: recorded.append(event.data["item"].input["address"]))
        self.run_bulk(panel, host=host)
        self.assertEqual(calls, [(2, "FUN_b at 2000", "full_enumeration", 2), (1, "FUN_a at 1000", "full_enumeration", 2)])
        self.assertEqual(recorded, ["2000", "1000"])
        self.assertEqual(panel.renamed_functions_panel.add_function_with_summary.call_count, 2)
        records = panel._create_batch_rag_vectors.call_args.args[0]
        self.assertEqual([record["address"] for record in records], ["2000", "1000"])
        stats = panel.session_manager.save_current_session.call_args.kwargs["performance_stats"]
        self.assertEqual(stats["successful_renames"], 1)
        self.assertEqual(stats["enumerated_functions"], 1)
        panel._set_tool_running.assert_any_call(False)
        self.assertNotIn("Error during bulk rename", self.messages(panel))

    def test_real_host_preserves_worker_failures_and_maps_uncaught_exceptions(self):
        panel = self.make_panel()

        def worker(index, function, mode, total):
            if index == 1:
                return {
                    "success": False,
                    "result_type": "failed",
                    "function_name": "reported name",
                    "error_msg": "decompile unavailable",
                }
            raise RuntimeError("backend disconnected")

        panel._process_single_function_for_bulk_rename = Mock(side_effect=worker)
        self.run_bulk(panel)
        self.assertIn("reported name", self.messages(panel))
        self.assertIn("decompile unavailable", self.messages(panel))
        self.assertIn("backend disconnected", self.messages(panel))
        self.assertEqual(panel._process_single_function_for_bulk_rename.call_count, 2)
        self.assertEqual(panel.session_manager.save_current_session.call_args.kwargs["performance_stats"]["failed_renames"], 2)
        panel._create_batch_rag_vectors.assert_not_called()

    def test_loaded_session_filter_runs_before_host_scheduling(self):
        panel = self.make_panel()
        panel._collect_analyzed_keys = Mock(return_value=({"1000"}, set()))
        panel._process_single_function_for_bulk_rename = Mock(
            side_effect=lambda i, function, mode, total: self.success(function)
        )
        self.run_bulk(panel, skip_analyzed=True)
        panel._process_single_function_for_bulk_rename.assert_called_once_with(1, "FUN_b at 2000", "full_enumeration", 1)
        self.assertIn("Skipped 1 function", self.messages(panel))

    def test_cancelled_result_closes_host_iterator_and_keeps_collected_records(self):
        panel = self.make_panel()
        panel._process_single_function_for_bulk_rename = Mock(
            side_effect=lambda i, function, mode, total: self.success(function)
        )
        closed = []
        options = {}

        def iterate(functions, mode, analyze, **kwargs):
            options.update(kwargs)
            try:
                item = WorkItem(
                    "first", "function.analyze", {"function": functions[0], "index": 1, "enumeration_mode": mode, "total": 2}
                )
                value = analyze(item, None)
                yield item, WorkResult(item.id, item.operation, "completed", value)
                cancelled = WorkItem("second", "function.analyze", {"function": functions[1]})
                yield cancelled, WorkResult(cancelled.id, cancelled.operation, "cancelled", error="Active program changed")
                self.fail("The GUI must stop consuming after cancellation")
            finally:
                closed.append(True)

        self.run_bulk(panel, host=SimpleNamespace(iter_functions=iterate))
        self.assertEqual(closed, [True])
        self.assertEqual(options["max_workers"], 5)
        self.assertIs(options["executor_factory"], ThreadPoolExecutor)
        self.assertFalse(options["cancelled"]())
        panel.should_stop = True
        self.assertTrue(options["cancelled"]())
        self.assertIn("Active program changed", self.messages(panel))
        self.assertEqual(panel._process_single_function_for_bulk_rename.call_count, 1)
        self.assertGreaterEqual(panel._create_batch_rag_vectors.call_count, 1)
        for call in panel._create_batch_rag_vectors.call_args_list:
            self.assertEqual([record["address"] for record in call.args[0]], ["1000"])
        panel._set_tool_running.assert_any_call(False)

    def test_dependency_skipped_result_updates_existing_skip_counter(self):
        panel = self.make_panel()
        panel._process_single_function_for_bulk_rename = Mock()

        def iterate(functions, mode, analyze, **kwargs):
            item = WorkItem("skipped", "function.analyze", {"function": functions[0], "name": "FUN_a"})
            yield item, WorkResult(item.id, item.operation, "skipped", error="Unsuccessful dependency")

        self.run_bulk(panel, host=SimpleNamespace(iter_functions=iterate))
        self.assertEqual(
            panel.session_manager.save_current_session.call_args.kwargs["performance_stats"]["skipped_functions"], 1
        )
        panel._process_single_function_for_bulk_rename.assert_not_called()


if __name__ == "__main__":
    unittest.main()
