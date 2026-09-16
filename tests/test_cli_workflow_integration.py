"""CLI workflow and plugin flags with fake Ghidra/model clients only."""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import main as cli
from src.workflow_host import WorkflowHost

STRATEGIC_MANIFEST = Path(__file__).resolve().parents[1] / "examples/plugins/strategic_ordering/plugin.toml"


def config():
    return SimpleNamespace(
        ghidra=SimpleNamespace(backend="http"),
        ollama=SimpleNamespace(model="offline"),
        plugin_paths=[],
        plugin_settings={},
        plugin_context_budget=2000,
        cag_enabled=False,
        max_steps=2,
    )


class CLIEnumerationTests(unittest.TestCase):
    def enumerate(self, functions, decompile=None, response=None, strategic=False):
        settings = config()
        if strategic:
            settings.plugin_paths = [str(STRATEGIC_MANIFEST)]
        ghidra = SimpleNamespace(
            list_functions=Mock(return_value=functions),
            decompile_function=Mock(side_effect=decompile or (lambda name: "int function(void) { return 1; }")),
            get_xrefs_to=Mock(return_value=[]),
            get_xrefs_from=Mock(return_value=[]),
            get_current_program_info=Mock(return_value={"name": "offline.exe", "program_id": "offline"}),
            rename_function_by_address=Mock(return_value="Renamed"),
        )
        prompts = []

        def generate(prompt):
            prompts.append(prompt)
            if response:
                return response(prompt)
            return "**Behavior Summary:** initialization evidence.\n**Suggested Name:** parseRecord\n**Rationale:** Reads a record."

        model = SimpleNamespace(config=settings.ollama, generate=generate)
        bridge = SimpleNamespace(
            config=settings, ghidra=ghidra, ghidra_client=ghidra, logger=Mock(), function_summaries={}, enable_cag=False
        )
        host = WorkflowHost(bridge)
        bridge.workflow_host = host
        bridge.ollama = host.wrap_model(model)
        records = {}
        results = []

        def completed(event, run):
            if event.data["item"].operation == "function.analyze":
                results.append(event.data["result"])
                records.update(run.state["analysis_records"])

        host.runtime.subscribe("operation.completed", completed)
        host.runtime.subscribe("operation.failed", completed)
        output = io.StringIO()
        with patch("builtins.input", side_effect=["enumerate-binary", "yes", "exit"]), contextlib.redirect_stdout(output):
            cli.run_interactive_mode(bridge, settings)
        return bridge, prompts, records, results, output.getvalue()

    def test_baseline_preserves_order_counters_and_successful_records(self):
        bridge, prompts, records, results, output = self.enumerate(
            ["descriptiveName at 401000", "badFunction at 402000"],
            decompile=lambda name: "Error: unavailable" if name == "badFunction" else "int f(void) { return 1; }",
        )
        self.assertIn("Enumerated 1/2 functions", output)
        self.assertIn("Successfully processed: 1", output)
        self.assertIn("Failed: 1", output)
        self.assertEqual([result.status for result in results], ["completed", "failed"])
        self.assertEqual(list(records), ["401000"])
        self.assertEqual(records["401000"]["summary"], bridge.function_summaries["401000"])
        self.assertTrue(prompts[0].startswith("Analyze the function 'descriptiveName'"))
        self.assertIn("## TARGET FUNCTION: descriptiveName", prompts[0])
        bridge.ghidra.rename_function_by_address.assert_not_called()

    def test_strategic_plugin_changes_order_and_later_prompt_sees_prior_analysis(self):
        _, prompts, records, results, output = self.enumerate(
            ["parse_packet at 402000", "main at 401000"],
            strategic=True,
        )
        self.assertTrue(prompts[0].startswith("Analyze the function 'main'"))
        self.assertTrue(prompts[1].startswith("Analyze the function 'parse_packet'"))
        self.assertIn("Earlier analysis main at 401000:", prompts[1])
        self.assertIn("initialization evidence", prompts[1])
        self.assertEqual(records["401000"]["strategic_category"], "entry_points")
        self.assertEqual(len(results), 2)
        self.assertIn("Enumerated 2/2 functions", output)

    def test_generic_rename_returns_actual_saved_function_data(self):
        bridge, _, records, results, output = self.enumerate(["FUN_401000 at 401000"])
        bridge.ghidra.rename_function_by_address.assert_called_once_with(
            function_address="401000",
            new_name="parseRecord",
        )
        self.assertEqual(results[0].value["result_type"], "renamed")
        self.assertEqual(results[0].value["function_data"]["new_name"], "parseRecord")
        self.assertEqual(records["401000"]["old_name"], "FUN_401000")
        self.assertIn("Enumerated 1/1 functions", output)

    def test_failed_and_empty_analysis_continue_to_next_function(self):
        def response(prompt):
            if "'first'" in prompt:
                raise ValueError("provider failed")
            if "'second'" in prompt:
                return ""
            return "**Behavior Summary:** Reads records.\n**Suggested Name:** parseRecord"

        _, _, records, results, output = self.enumerate(
            ["first at 401000", "second at 402000", "third at 403000"],
            response=response,
        )
        self.assertEqual([result.status for result in results], ["failed", "failed", "completed"])
        self.assertEqual(list(records), ["403000"])
        self.assertIn("Enumerated 1/3 functions", output)
        self.assertIn("Failed: 2", output)


class CLIPluginFlagTests(unittest.TestCase):
    def run_main(self, args, settings):
        bridge = Mock()
        with (
            patch.object(cli, "get_config", return_value=settings),
            patch.object(cli, "Bridge", return_value=bridge) as build,
            patch("sys.argv", ["main.py", "--query", "offline query", *args]),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            cli.main()
        return build

    def test_repeatable_manifests_and_settings_are_applied_before_bridge_creation(self):
        settings = config()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "settings.json"
            path.write_text(json.dumps({"oghidra.strategic_ordering": {"enabled": False}}), encoding="utf-8")
            build = self.run_main(
                ["--plugin", "one/plugin.toml", "--plugin", "two/plugin.toml", "--plugin-settings", str(path)], settings
            )
        self.assertIs(build.call_args.kwargs["config"], settings)
        self.assertEqual(settings.plugin_paths, ["one/plugin.toml", "two/plugin.toml"])
        self.assertEqual(settings.plugin_settings, {"oghidra.strategic_ordering": {"enabled": False}})

    def test_omitted_flags_preserve_configured_plugins(self):
        settings = config()
        settings.plugin_paths = ["configured/plugin.toml"]
        settings.plugin_settings = {"configured": {"enabled": True}}
        self.run_main([], settings)
        self.assertEqual(settings.plugin_paths, ["configured/plugin.toml"])
        self.assertEqual(settings.plugin_settings, {"configured": {"enabled": True}})

    def test_invalid_settings_fail_before_bridge_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "settings.json"
            for text in ("not JSON", "[]", '{"plugin": false}'):
                with self.subTest(text=text):
                    path.write_text(text, encoding="utf-8")
                    with (
                        patch.object(cli, "get_config", return_value=config()),
                        patch.object(cli, "Bridge") as build,
                        patch("sys.argv", ["main.py", "--query", "x", "--plugin-settings", str(path)]),
                        contextlib.redirect_stderr(io.StringIO()),
                        self.assertRaises(SystemExit) as caught,
                    ):
                        cli.main()
                    self.assertEqual(caught.exception.code, 2)
                    build.assert_not_called()

    def test_missing_settings_fail_before_bridge_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "missing.json"
            with (
                patch.object(cli, "get_config", return_value=config()),
                patch.object(cli, "Bridge") as build,
                patch("sys.argv", ["main.py", "--query", "x", "--plugin-settings", str(path)]),
                contextlib.redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit) as caught,
            ):
                cli.main()
            self.assertEqual(caught.exception.code, 2)
            build.assert_not_called()


if __name__ == "__main__":
    unittest.main()
