"""Offline integration tests for Bridge workflows, model routing and graph scope."""

import copy
import json
import logging
import os
import threading
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from src.workflow import ContextBlock, WorkItem, WorkPlan, WorkResult, get_current_work_context
from src.workflow_host import (
    InlineExecutor,
    WorkflowHost,
    WorkflowModelClient,
    canonical_address,
    function_identity,
    get_workflow_host,
    workflow_operation,
)

PLUGIN = Path(__file__).resolve().parents[1] / "examples/plugins/strategic_ordering/plugin.toml"


class FakeGhidra:
    def __init__(self, functions=(), references=None, info=None):
        self.functions = list(functions)
        self.references = references or {}
        self.info = info if info is not None else {"program_id": "program-a", "name": "example"}
        self.calls = []
        self.current_instance_port = 8080

    def get_current_program_info(self):
        self.calls.append(("info",))
        if isinstance(self.info, Exception):
            raise self.info
        return self.info

    def list_functions(self, offset=0, limit=100):
        self.calls.append(("functions", offset, limit))
        return self.functions[offset:offset + limit]

    def get_xrefs_to(self, address, offset=0, limit=100):
        self.calls.append(("xrefs", address, offset, limit))
        value = self.references.get((address, offset), self.references.get(address, []))
        if isinstance(value, Exception):
            raise value
        if callable(value):
            return value(offset)
        return value


class FakeModel:
    def __init__(self):
        self.calls = []
        self.model = "baseline"
        self.config = SimpleNamespace(context_budget=2000, context_budget_execution=0.5)

    def generate(self, **kwargs):
        self.calls.append(("generate", copy.deepcopy(kwargs), threading.get_ident()))
        return "generated"

    def generate_with_phase(self, **kwargs):
        self.calls.append(("generate_with_phase", copy.deepcopy(kwargs), threading.get_ident()))
        return self.generate(**kwargs)

    def embed(self, value):
        return [float(len(value))]


def make_bridge(*, client=None, plugin_paths=None, config=None):
    return SimpleNamespace(
        config=config if config is not None else SimpleNamespace(
            plugin_paths=plugin_paths or [], plugin_settings={}, plugin_context_budget=2000,
        ),
        ghidra_client=client,
    )


class WorkflowHostTests(unittest.TestCase):
    def setUp(self):
        quiet = patch("src.workflow.runtime.logger.warning")
        quiet.start()
        self.addCleanup(quiet.stop)

    def test_canonical_identity_and_address_deduplication(self):
        for value, expected in [("0x000A", "a"), ("0X000A", "a"), ("00AF", "af"), (0, "0"),
                                ("ram:0010", "ram:0010"), ("not an address", "not an address"), (None, "")]:
            self.assertEqual(canonical_address(value), expected)
        self.assertEqual(function_identity("name at part at 0x0100"), ("name at part", "100"))
        self.assertEqual(function_identity(" plain_name "), ("plain_name", ""))
        host = WorkflowHost(make_bridge())
        plan = host.function_plan(
            ["same at 0x000A", "alias at 0Xa", "same at b", "nameless", "nameless", "other"], "rename",
        )
        self.assertEqual(len(plan.items), 4)
        self.assertEqual([item.id for item in plan.items], [
            "function:address:a", "function:address:b", "function:index:2", "function:index:3",
        ])
        self.assertEqual([item.input["index"] for item in plan.items], [1, 2, 3, 4])
        self.assertTrue(all(item.input["total"] == 4 for item in plan.items))
        self.assertTrue(all(item.input["enumeration_mode"] == "rename" for item in plan.items))

    def test_no_plugins_preserve_input_thread_result_and_do_not_scan(self):
        client = FakeGhidra()
        host = WorkflowHost(make_bridge(client=client))
        thread_id = threading.get_ident()
        arguments = {"prompt": "exact prompt", "phase": "analysis", "temperature": 0.25, "nested": {"x": [1, 2]}}
        seen = []
        result = host.invoke(
            "custom.operation", arguments,
            lambda values: seen.append((values, threading.get_ident())) or {"original": True},
        )
        self.assertEqual(result, {"original": True})
        self.assertEqual(seen, [(arguments, thread_id)])
        self.assertEqual(client.calls, [])
        self.assertEqual(host.plugins.inventory(), [])
        self.assertEqual(next(iter(host.last_results.values())).status, "completed")

    def test_original_exception_is_preserved_and_side_effect_occurs_once(self):
        host = WorkflowHost(make_bridge())
        failure = LookupError("original failure")
        seen = []

        def fail(values):
            seen.append(values)
            raise failure

        with self.assertRaises(LookupError) as caught:
            host.invoke("custom.operation", {"a": 1}, fail)
        self.assertIs(caught.exception, failure)
        self.assertEqual(seen, [{"a": 1}])
        self.assertEqual(next(iter(host.last_results.values())).status, "failed")

    def test_plan_removing_required_item_fails_clearly(self):
        host = WorkflowHost(make_bridge())
        host.runtime.add_hook("workflow.plan", lambda plan, run: replace(plan, items=[]))
        with self.assertRaisesRegex(RuntimeError, "removed its required result"):
            host.invoke("tool.execute", {}, lambda values: self.fail("Should not execute"))

    def test_noncomplete_operation_fails_without_rerunning(self):
        host = WorkflowHost(make_bridge())
        seen = []

        def execute(values):
            item = get_current_work_context().item
            seen.append(item.id)
            return WorkResult(item.id, item.operation, "skipped", error="deliberately skipped")

        with self.assertRaisesRegex(RuntimeError, "deliberately skipped"):
            host.invoke("tool.execute", {}, execute)
        self.assertEqual(len(seen), 1)

    def test_workflow_decorator_binds_original_arguments_and_preserves_defaults(self):
        seen = []

        class Adapter:
            @workflow_operation("tool.execute")
            def original(self, name, count=3, *, enabled=True):
                seen.append((name, count, enabled, threading.get_ident()))
                return count

        adapter = Adapter()
        self.assertEqual(adapter.original("x", enabled=False), 3)
        self.assertEqual(adapter.original("y", 4), 4)
        self.assertEqual(seen, [("x", 3, False, threading.get_ident()), ("y", 4, True, threading.get_ident())])
        self.assertIs(get_workflow_host(adapter), adapter.workflow_host)
        with self.assertRaises(TypeError):
            adapter.original()
        with self.assertRaises(TypeError):
            adapter.original("x", name="duplicate")

    def test_inline_executor_value_exception_context_and_validation(self):
        with self.assertRaises(ValueError):
            InlineExecutor(2)
        with InlineExecutor() as executor:
            self.assertEqual(executor.submit(lambda x, y: x + y, 2, y=3).result(), 5)
            error = ValueError("worker error")
            def fail():
                raise error
            with self.assertRaises(ValueError) as caught:
                executor.submit(fail).result()
            self.assertIs(caught.exception, error)
        with self.assertRaisesRegex(RuntimeError, "consumer"), InlineExecutor():
            raise RuntimeError("consumer")

    def test_context_configuration_fallback_and_explicit_state(self):
        host = WorkflowHost(make_bridge(config=SimpleNamespace(
            plugin_paths="not-a-list", plugin_settings=None, plugin_context_budget="bad",
        )))
        context = host._context("test", state={"custom": 1}, services={"extra": 2})
        self.assertEqual(context.context_budget, 2000)
        self.assertEqual(context.state["custom"], 1)
        self.assertEqual(context.services["extra"], 2)
        self.assertFalse(context.cancelled())
        host = WorkflowHost(SimpleNamespace())
        self.assertEqual(host._context("no-config").context_budget, 2000)

    def test_program_key_reads_only_identifying_fields_when_plugins_configured(self):
        client = FakeGhidra(info={"program_id": "a", "name": "A", "extra": "ignore", "project": "", "port": 8080})
        host = WorkflowHost(make_bridge(client=client))
        host._plugins_configured = True
        key = host.program_key()
        self.assertIn('"program_id": "a"', key)
        self.assertNotIn("extra", key)
        self.assertNotIn("project", key)
        self.assertEqual(client.calls, [("info",)])
        for info in [RuntimeError("offline"), [], {}]:
            client.info = info
            self.assertIn('"session":', host.program_key())
        client._program = object()
        before = host.program_key()
        client._program = object()
        self.assertNotEqual(before, host.program_key())

    def test_program_changed_event_emits_once_per_identity(self):
        client = FakeGhidra()
        host = WorkflowHost(make_bridge(client=client))
        host._plugins_configured = True
        seen = []
        host.runtime.subscribe("program.changed", lambda event, run: seen.append(event.data))
        host._context("first")
        host._context("same")
        client.info = {"program_id": "b"}
        host._context("changed")
        self.assertEqual(len(seen), 2)
        self.assertEqual(seen[0]["previous"], "")
        self.assertEqual(seen[1]["previous"], seen[0]["current"])
        self.assertNotEqual(seen[1]["current"], seen[0]["current"])

    def test_function_iteration_defaults_preserve_order_and_thread(self):
        client = FakeGhidra()
        host = WorkflowHost(make_bridge(client=client))
        seen = []

        def analyze(item, ctx):
            seen.append((item.input["name"], threading.get_ident()))
            return {"result_type": "enumerated", "summary": item.input["name"]}

        rows = list(host.iter_functions(["first at 100", "second at 200"], "enumerate", analyze))
        self.assertEqual([item.input["name"] for item, result in rows], ["first", "second"])
        self.assertEqual(seen, [("first", threading.get_ident()), ("second", threading.get_ident())])
        self.assertEqual([result.status for item, result in rows], ["completed", "completed"])
        self.assertEqual(client.calls, [])

    def test_analysis_failure_skip_success_and_transformed_record_semantics(self):
        host = WorkflowHost(make_bridge())
        accepted = []
        runs = []
        outputs = [
            {"result_type": "skipped", "success": True, "summary": "do not retain skipped"},
            {"success": False, "error_msg": "failed explicitly"},
            {"result_type": "failed"},
            "non-record text",
            {"result_type": "unknown", "summary": "unconfirmed"},
            {"result_type": "enumerated", "summary": "original", "suggested_name": "accepted_name"},
            {"success": True, "function_data": {"summary": "nested", "new_name": "nested_name"}},
        ]

        def transform(result, ctx):
            if ctx.item.input["address"] == "600":
                result.value["summary"] = "transformed"
            return result

        host.runtime.add_hook("result.transform", transform)
        host.runtime.subscribe("analysis.completed", lambda event, run: accepted.append(
            copy.deepcopy(run.state["analysis_records"]),
        ))
        host.runtime.subscribe("workflow.finished", lambda event, run: runs.append(run))
        rows = list(host.iter_functions(
            [f"f{index} at {index}00" for index in range(1, 8)], "enumerate",
            lambda item, ctx: outputs[item.input["index"] - 1],
        ))
        self.assertEqual([result.status for item, result in rows], [
            "skipped", "failed", "failed", "completed", "completed", "completed", "completed",
        ])
        self.assertEqual(rows[1][1].error, "failed explicitly")
        self.assertEqual(rows[2][1].error, "Analysis failed")
        records = runs[-1].state["analysis_records"]
        self.assertEqual(set(records), {"600", "700"})
        self.assertEqual(records["600"]["summary"], "transformed")
        self.assertEqual(records["600"]["new_name"], "accepted_name")
        self.assertEqual(records["700"]["summary"], "nested")
        self.assertEqual(accepted[-2]["600"]["summary"], "transformed")

    def test_record_fallback_identity_and_nonanalysis_ignored(self):
        host = WorkflowHost(make_bridge())
        runs = []
        host.runtime.subscribe("workflow.finished", lambda event, run: runs.append(run))
        rows = list(host.iter_functions(["unaddressed"], "enumerate", lambda item, ctx: {
            "success": True, "summary": "unaddressed summary",
        }))
        item = rows[0][0]
        self.assertEqual(runs[-1].state["analysis_records"][item.id]["new_name"], "unaddressed")
        unrelated = WorkItem("tool", "tool.execute")
        host._record_analysis(unrelated, WorkResult("tool", "tool.execute", "completed", {"success": True}), runs[-1])
        self.assertEqual(len(runs[-1].state["analysis_records"]), 1)

    def test_parallel_executor_override_and_cancellation(self):
        host = WorkflowHost(make_bridge())
        entered = []
        class CountingExecutor(InlineExecutor):
            def __init__(self, max_workers=1):
                entered.append(max_workers)
        rows = list(host.iter_functions(
            ["a at 100"], "enumerate", lambda item, ctx: "done", max_workers=2, executor_factory=CountingExecutor,
        ))
        self.assertEqual(entered, [2])
        self.assertEqual(rows[0][1].value, "done")
        rows = list(host.iter_functions(
            ["a at 100"], "enumerate", lambda item, ctx: self.fail("cancelled"), cancelled=lambda: True,
        ))
        self.assertEqual(rows[0][1].status, "cancelled")
        rows = list(host.iter_functions(["a at 100"], "enumerate", lambda item, ctx: "threaded", max_workers=2))
        self.assertEqual(rows[0][1].value, "threaded")

    def test_program_switch_cancels_stale_results_and_pending_work(self):
        client = FakeGhidra()
        host = WorkflowHost(make_bridge(client=client))
        host._plugins_configured = True
        runs = []
        completed = []
        analyzed = []
        host.runtime.subscribe("workflow.finished", lambda event, run: runs.append(run))
        host.runtime.subscribe("analysis.completed", lambda event, run: completed.append(event.item_id))

        def analyze(item, ctx):
            analyzed.append(item.id)
            client.info = {"program_id": "changed"}
            return {"success": True, "summary": "stale"}

        rows = list(host.iter_functions(["a at 100", "b at 200"], "enumerate", analyze))
        self.assertEqual([result.status for item, result in rows], ["cancelled", "cancelled"])
        self.assertEqual(len(analyzed), 1)
        self.assertEqual(completed, [])
        self.assertEqual(runs[-1].state["analysis_records"], {})
        # A stale recorder cannot add a late callback after program identity changed.
        host._record_analysis(rows[0][0], WorkResult(
            rows[0][0].id, "function.analyze", "completed", {"success": True, "summary": "late"},
        ), runs[-1])
        self.assertEqual(runs[-1].state["analysis_records"], {})
        self.assertEqual(host._context("new").state["analysis_records"], {})

    def test_plan_can_insert_distinct_builtin_operations_without_replaying_original(self):
        seen = []

        class Adapter:
            @workflow_operation("tool.execute")
            def execute_command(self, command):
                seen.append(("tool", command))
                return "tool result"

            def _generate_plan(self, question):
                seen.append(("plan", question))
                return "plan result"

        bridge = Adapter()
        host = get_workflow_host(bridge)
        provider = FakeModel()
        host.wrap_model(provider)

        def expand(plan, run):
            if plan.workflow != "expanded":
                return plan
            required = replace(plan.items[0], depends_on=("extra-model",))
            return replace(plan, items=[
                WorkItem("extra-tool", "tool.execute", {"command": "inspect"}),
                WorkItem("extra-plan", "agent.plan", {"question": "continue"}, depends_on=("extra-tool",)),
                WorkItem("extra-model", "llm.generate", {"prompt": "model step"}, depends_on=("extra-plan",)),
                required,
            ])

        host.runtime.add_hook("workflow.plan", expand)
        result = host.invoke(
            "agent.query", {"query": "original"},
            lambda values: seen.append(("original", values["query"])) or "answer", workflow="expanded",
        )
        self.assertEqual(result, "answer")
        self.assertEqual(seen, [("tool", "inspect"), ("plan", "continue"), ("original", "original")])
        self.assertEqual(provider.calls[0][1]["prompt"], "model step")
        self.assertEqual(len(provider.calls), 1)
        self.assertEqual(len(host.last_results), 4)

    def test_host_registered_operation_without_invocation_reports_error(self):
        host = WorkflowHost(make_bridge())
        host._register("host.extra", host._invoke)
        context = host._context("missing")
        results = host.runtime.run(WorkPlan([WorkItem("missing", "host.extra")]), context)
        self.assertEqual(results["missing"].status, "failed")
        self.assertIn("No host invocation", results["missing"].error)


class WorkflowModelTests(unittest.TestCase):
    def test_gateway_preserves_model_values_and_delegates_once(self):
        host = WorkflowHost(make_bridge())
        provider = FakeModel()
        model = host.wrap_model(provider)
        self.assertIsInstance(model, WorkflowModelClient)
        self.assertIs(host.wrap_model(model), model)
        self.assertEqual(model.embed("abcd"), [4.0])
        model.model = "updated"
        self.assertEqual(provider.model, "updated")
        self.assertIs(model.config, provider.config)
        self.assertEqual(model.generate("prompt", "model", "system", 0.3, 80, "execution"), "generated")
        self.assertEqual(provider.calls[0][1], {
            "prompt": "prompt", "model": "model", "system_prompt": "system",
            "temperature": 0.3, "max_tokens": 80, "phase": "execution",
        })
        self.assertEqual(provider.calls[0][2], threading.get_ident())
        self.assertEqual(model.generate_with_phase("second", "analysis", "system"), "generated")
        self.assertEqual(provider.calls[1][0], "generate_with_phase")
        self.assertEqual(provider.calls[1][1], {"prompt": "second", "phase": "analysis", "system_prompt": "system"})

    def test_invalid_gateway_arguments_fail_before_provider(self):
        provider = FakeModel()
        model = WorkflowHost(make_bridge()).wrap_model(provider)
        for call in [
            lambda: model.generate(),
            lambda: model.generate("x", prompt="duplicate"),
            lambda: model.generate(*range(7)),
            lambda: model.generate_with_phase("x", "phase", "sys", "extra"),
        ]:
            with self.assertRaises(TypeError):
                call()
        self.assertEqual(provider.calls, [])

    def test_context_once_for_generate_and_phase_with_nested_annotations(self):
        host = WorkflowHost(make_bridge())
        provider = FakeModel()
        model = host.wrap_model(provider)
        observed = []
        completions = []

        def context(item, ctx):
            if item.operation == "llm.generate":
                observed.append((copy.deepcopy(item.annotations), ctx.run.cancelled()))
                return [ContextBlock("UNIQUE EVIDENCE", source="test")]
            return []

        host.runtime.add_hook("context.collect", context)
        host.runtime.subscribe("analysis.completed", lambda event, run: completions.append(event.item_id))

        def annotate(plan, run):
            if plan.workflow == "functions.analyze":
                plan.items[0].annotations["strategic_category"] = "entry_points"
                plan.items[0].annotations["custom_annotation"] = "preserve"
            return plan

        host.runtime.add_hook("workflow.plan", annotate)

        def analyze(item, ctx):
            model.generate("first")
            host.invoke("agent.analyze", {}, lambda values: model.generate_with_phase("second", "analysis"))
            return {"success": True, "summary": "done"}

        rows = list(host.iter_functions(["main at 100"], "enumerate", analyze))
        self.assertEqual(len(observed), 2)
        for annotations, cancelled in observed:
            self.assertEqual(annotations["strategic_category"], "entry_points")
            self.assertEqual(annotations["function_address"], "100")
            self.assertEqual(annotations["custom_annotation"], "preserve")
            self.assertIn("parent_item_id", annotations)
            self.assertNotIn("completion_event", annotations)
            self.assertFalse(cancelled)
        self.assertEqual(completions, [rows[0][0].id])
        self.assertTrue(all(call[1]["prompt"].count("UNIQUE EVIDENCE") == 1 for call in provider.calls))

    def test_bridge_attach_and_reload_routes_every_model_reference(self):
        from src.bridge import Bridge

        bridge = Bridge.__new__(Bridge)
        bridge.config = SimpleNamespace(
            plugin_paths=[], plugin_settings={}, plugin_context_budget=2000, llm_provider="ollama",
            ollama=SimpleNamespace(context_budget=900, context_budget_execution=0.4),
        )
        bridge.logger = logging.getLogger("workflow-test")
        bridge.ghidra_client = SimpleNamespace()
        bridge.context_manager = SimpleNamespace()
        bridge.session_compactor = SimpleNamespace()
        first, second = FakeModel(), FakeModel()
        bridge.ollama = first
        with patch.object(Bridge, "set_ollama_client") as shared, patch("src.bridge.OllamaClient", return_value=second):
            bridge._attach_workflow_model()
            wrapped = bridge.ollama
            bridge._attach_workflow_model()
            self.assertIs(bridge.ollama, wrapped)
            with patch("builtins.print"):
                bridge.reload_llm_client()
            self.assertIs(bridge.ollama._client, second)
            for owner, attribute in [
                (bridge.ghidra_client, "ollama_client"),
                (bridge.context_manager, "ollama_client"),
                (bridge.session_compactor, "llm_client"),
            ]:
                self.assertIs(getattr(owner, attribute), bridge.ollama)
            self.assertIs(shared.call_args.args[0], bridge.ollama)
            self.assertEqual(bridge.ollama.generate("after reload"), "generated")
        self.assertEqual(first.calls, [])
        self.assertEqual(len(second.calls), 1)

    def test_real_strategic_plugin_orders_work_and_injects_committed_prior_context(self):
        functions = ["parse_packet at 200", "main at 100", "FUN_300 at 300"]
        client = FakeGhidra(functions, {"200": ["From 0104 in main [UNCONDITIONAL_CALL]"]})
        bridge = make_bridge(client=client, plugin_paths=[str(PLUGIN)])
        host = WorkflowHost(bridge)
        self.assertEqual(host.plugins.inventory()[0]["status"], "active")
        provider = FakeModel()
        model = host.wrap_model(provider)
        snapshots = []

        def snapshot_twice(plan, run):
            if plan.workflow == "functions.analyze":
                snapshots.extend([run.services["function_snapshot"](), run.services["function_snapshot"]()])
            return plan

        host.runtime.add_hook("workflow.plan", snapshot_twice)
        seen = []

        def analyze(item, ctx):
            seen.append((item.input["name"], item.annotations["strategic_category"]))
            model.generate_with_phase(f"Analyze {item.input['name']}", "analysis")
            return {"success": True, "summary": f"SUMMARY {item.input['name']}"}

        rows = list(host.iter_functions(functions, "enumerate", analyze))
        self.assertEqual(seen, [
            ("main", "entry_points"), ("parse_packet", "leaf_utilities"), ("FUN_300", "isolated_functions"),
        ])
        self.assertEqual(len(rows), 3)
        self.assertIs(snapshots[0], snapshots[1])
        prompts = [kwargs["prompt"] for method, kwargs, thread in provider.calls if method == "generate_with_phase"]
        self.assertNotIn("Earlier analysis", prompts[0])
        self.assertIn("Earlier analysis main at 100: SUMMARY main", prompts[1])
        self.assertIn("Earlier analysis parse_packet at 200: SUMMARY parse_packet", prompts[2])
        self.assertEqual(len([call for call in client.calls if call[0] == "xrefs"]), 3)

    def test_wrapped_client_can_move_hosts_without_double_routing(self):
        first, second = WorkflowHost(make_bridge()), WorkflowHost(make_bridge())
        provider = FakeModel()
        first_model = first.wrap_model(provider)
        first.runtime.add_hook("context.collect", lambda item, ctx: [ContextBlock("FIRST HOST")])
        second.runtime.add_hook("context.collect", lambda item, ctx: [ContextBlock("SECOND HOST")])
        model = second.wrap_model(first_model)
        self.assertIsNot(model, first_model)
        self.assertEqual(model.generate("prompt"), "generated")
        prompt = provider.calls[0][1]["prompt"]
        self.assertIn("SECOND HOST", prompt)
        self.assertNotIn("FIRST HOST", prompt)
        replacement = FakeModel()
        model._client = replacement
        self.assertEqual(model.generate("replacement"), "generated")
        self.assertEqual(len(replacement.calls), 1)


class FunctionSnapshotTests(unittest.TestCase):
    def host_and_items(self, functions=None, references=None, client=None):
        functions = functions or ["main at 100", "worker at 200"]
        client = client if client is not None else FakeGhidra(functions, references)
        host = WorkflowHost(make_bridge(client=client))
        return host, host.function_plan(functions, "enumerate").items, client

    def test_complete_graph_derives_both_directions_and_ignores_data_refs(self):
        host, items, _client = self.host_and_items(references={
            "100": [{"function": "worker", "reference_type": "DATA"}, "From 204 in worker [DATA]"],
            "200": [{"caller": "main", "type": "CALL", "caller_address": "0X00100"}],
        })
        graph = host.collect_function_snapshot(items)
        self.assertEqual(graph["100"]["callees"], ("200",))
        self.assertEqual(graph["200"]["callers"], ("100",))
        self.assertTrue(all(record["relationships_known"] for record in graph.values()))

    def test_incoming_reference_pagination(self):
        host, items, client = self.host_and_items(references={
            ("200", 0): ["From 104 in main [CALL]", "[next: offset 100]"],
            ("200", 100): [{"from_function": "main", "reference_type": "CALL"}],
        })
        graph = host.collect_function_snapshot(items)
        self.assertEqual(graph["200"]["callers"], ("100",))
        self.assertIn(("xrefs", "200", 100, 100), client.calls)
        self.assertTrue(graph["200"]["relationships_known"])

    def test_full_reference_pages_fetch_next_without_marker(self):
        host, items, client = self.host_and_items(references={
            ("200", 0): ["From 104 in main [CALL]"] * 100,
            ("200", 100): [],
        })
        graph = host.collect_function_snapshot(items)
        self.assertEqual(graph["100"]["callees"], ("200",))
        self.assertIn(("xrefs", "200", 100, 100), client.calls)
        self.assertTrue(graph["100"]["relationships_known"])

    def test_xref_errors_malformed_and_unresolved_are_unknown(self):
        invalid = [
            RuntimeError("offline"), {"unexpected": True}, ["Error: unavailable"],
            ["Malformed CALL record"], [17], [{}],
            ["From 555 in missing [CALL]"],
            [{"from_function_address": "999", "type": "CALL"}],
        ]
        for value in invalid:
            with self.subTest(value=value):
                host, items, _client = self.host_and_items(references={"200": value})
                graph = host.collect_function_snapshot(items)
                self.assertTrue(all(not row["relationships_known"] for row in graph.values()))

    def test_ambiguous_names_and_partial_calls_do_not_claim_complete_graph(self):
        host, items, _client = self.host_and_items(
            ["duplicate at 100", "duplicate at 200", "target at 300"],
            {"300": ["From 104 in duplicate [CALL]"]},
        )
        graph = host.collect_function_snapshot(items)
        self.assertEqual(graph["300"]["callers"], ())
        self.assertFalse(graph["300"]["relationships_known"])

    def test_repeated_xref_pages_and_page_cap_are_unknown_and_bounded(self):
        host, items, client = self.host_and_items(references={"200": ["From 104 in main [CALL]", "[next: yes]"]})
        graph = host.collect_function_snapshot(items)
        self.assertFalse(graph["200"]["relationships_known"])
        self.assertEqual(len([call for call in client.calls if call[:2] == ("xrefs", "200")]), 2)
        host, items, client = self.host_and_items(references={
            "200": lambda offset: [f"From {offset + 100:x} in main [CALL]", "[next: yes]"],
        })
        graph = host.collect_function_snapshot(items)
        self.assertFalse(graph["200"]["relationships_known"])
        self.assertEqual(len([call for call in client.calls if call[:2] == ("xrefs", "200")]), 100)

    def test_no_client_and_cancelled_graph_stay_unknown(self):
        host = WorkflowHost(make_bridge())
        items = host.function_plan(["main at 100"], "enumerate").items
        self.assertFalse(host.collect_function_snapshot(items)["100"]["relationships_known"])
        host, items, client = self.host_and_items()
        graph = host.collect_function_snapshot(items, cancelled=lambda: True)
        self.assertTrue(all(not row["relationships_known"] for row in graph.values()))
        self.assertFalse(any(call[0] == "xrefs" for call in client.calls))

    def test_inventory_includes_functions_omitted_from_work_plan(self):
        client = FakeGhidra(
            ["eligible at 100", "already_named at 200"],
            {"200": ["From 104 in eligible [CALL]"]},
        )
        host, items, client = self.host_and_items(["eligible at 100"], client=client)
        graph = host.collect_function_snapshot(items)
        self.assertIn("200", graph)
        self.assertEqual(graph["100"]["callees"], ("200",))
        self.assertTrue(graph["100"]["relationships_known"])

    def test_inventory_missing_api_or_failure_cannot_claim_known_isolation(self):
        for client in [
            SimpleNamespace(get_xrefs_to=lambda **kwargs: []),
            SimpleNamespace(list_functions=lambda **kwargs: ["Error: unavailable"], get_xrefs_to=lambda **kwargs: []),
        ]:
            host, items, client = self.host_and_items(client=client)
            graph = host.collect_function_snapshot(items)
            self.assertTrue(all(not row["relationships_known"] for row in graph.values()))

    def test_inventory_pagination_markers_and_full_pages(self):
        for first_page in [
            ["main at 100", "[next: offset 100]"],
            [f"item{index} at {index + 4096:x}" for index in range(100)],
        ]:
            with self.subTest(count=len(first_page)):
                host, items, client = self.host_and_items()
                pages = [first_page, ["extra at abcd"]]
                calls = []
                def listing(offset=0, limit=100, calls=calls, pages=pages):
                    calls.append(offset)
                    return pages[offset // 100]
                client.list_functions = listing
                graph = host.collect_function_snapshot(items)
                self.assertIn("abcd", graph)
                self.assertTrue(all(row["relationships_known"] for row in graph.values()))
                self.assertEqual(calls, [0, 100])

    def test_inventory_malformed_repeated_and_excess_pages_are_bounded_unknown(self):
        for lines in [{"unexpected": True}, [None], ["not a function"], ["main at 100", "[next: yes]"]]:
            with self.subTest(lines=lines):
                host, items, client = self.host_and_items()
                calls = []
                def listing(offset=0, limit=100, calls=calls, lines=lines):
                    calls.append(offset)
                    return lines
                client.list_functions = listing
                graph = host.collect_function_snapshot(items)
                self.assertTrue(all(not row["relationships_known"] for row in graph.values()))
                self.assertLessEqual(len(calls), 2)

        host, items, client = self.host_and_items()
        calls = []
        def unending(offset=0, limit=100):
            calls.append(offset)
            return [f"function{offset} at {offset + 4096:x}", "[next: yes]"]
        client.list_functions = unending
        graph = host.collect_function_snapshot(items)
        self.assertEqual(len(calls), 100)
        self.assertTrue(all(not row["relationships_known"] for row in graph.values()))



class PluginConfigurationTests(unittest.TestCase):
    def test_plugin_defaults_are_empty_independent_and_have_bounded_context(self):
        from src.config import BridgeConfig

        with patch.dict(os.environ, {}, clear=True):
            first = BridgeConfig(_env_file=None)
            second = BridgeConfig(_env_file=None)
        self.assertEqual(first.plugin_paths, [])
        self.assertEqual(first.plugin_settings, {})
        self.assertEqual(first.plugin_context_budget, 2000)
        first.plugin_paths.append("example/plugin.toml")
        first.plugin_settings["example"] = {"enabled": False}
        self.assertEqual(second.plugin_paths, [])
        self.assertEqual(second.plugin_settings, {})

    def test_plugin_environment_fields_preserve_underscores_and_nested_settings(self):
        from src.config import BridgeConfig

        settings = {"oghidra.strategic_ordering": {"enabled": False, "active_skills": ["function_review"]}}
        values = {
            "PLUGIN_PATHS": json.dumps([str(PLUGIN)]),
            "PLUGIN_SETTINGS": json.dumps(settings),
            "PLUGIN_CONTEXT_BUDGET": "4096",
        }
        with patch.dict(os.environ, values, clear=True):
            config = BridgeConfig(_env_file=None)
        self.assertEqual(config.plugin_paths, [str(PLUGIN)])
        self.assertEqual(config.plugin_settings, settings)
        self.assertEqual(config.plugin_context_budget, 4096)

    def test_plugin_budget_environment_validation(self):
        from pydantic import ValidationError

        from src.config import BridgeConfig

        for value in ["-1", "50001", "not-a-number"]:
            with self.subTest(value=value), patch.dict(
                os.environ, {"PLUGIN_CONTEXT_BUDGET": value}, clear=True,
            ), self.assertRaises(ValidationError):
                BridgeConfig(_env_file=None)
        for value in ["0", "50000"]:
            with self.subTest(value=value), patch.dict(
                os.environ, {"PLUGIN_CONTEXT_BUDGET": value}, clear=True,
            ):
                self.assertEqual(BridgeConfig(_env_file=None).plugin_context_budget, int(value))

    def test_disabled_only_plugin_configuration_does_not_collect_graph(self):
        client = FakeGhidra(["parse_packet at 200", "main at 100"])
        config = SimpleNamespace(
            plugin_paths=[str(PLUGIN)],
            plugin_settings={"oghidra.strategic_ordering": {"enabled": False}},
            plugin_context_budget=2000,
        )
        host = WorkflowHost(make_bridge(client=client, config=config))
        rows = list(host.iter_functions(
            client.functions, "enumerate", lambda item, ctx: {"success": True, "summary": "done"},
        ))
        self.assertEqual(host.plugins.inventory()[0]["status"], "disabled")
        self.assertEqual([item.input["name"] for item, result in rows], ["parse_packet", "main"])
        self.assertFalse(any(call[0] in {"functions", "xrefs"} for call in client.calls))
        # Configured manifests still enable program identity checks, even disabled ones.
        self.assertTrue(any(call[0] == "info" for call in client.calls))

    def test_nested_context_shares_state_and_committed_predecessor_results(self):
        host = WorkflowHost(make_bridge())
        provider = FakeModel()
        model = host.wrap_model(provider)
        observed = []

        def context(item, ctx):
            if item.operation == "llm.generate":
                observed.append((ctx.run.state, dict(ctx.results)))
                ctx.run.state["nested_count"] = ctx.run.state.get("nested_count", 0) + 1
            return []

        host.runtime.add_hook("context.collect", context)
        parent_states = []

        def analyze(item, ctx):
            parent_states.append(ctx.run.state)
            model.generate(item.input["name"])
            self.assertEqual(ctx.run.state["nested_count"], item.input["index"])
            return {"success": True, "summary": item.input["name"]}

        list(host.iter_functions(["first at 100", "second at 200"], "enumerate", analyze))
        self.assertIs(observed[0][0], parent_states[0])
        self.assertIs(observed[1][0], parent_states[1])
        self.assertEqual(observed[0][1], {})
        self.assertEqual(observed[1][1]["function:address:100"].value["summary"], "first")
        self.assertEqual(observed[1][1]["function:address:100"].status, "completed")


if __name__ == "__main__":
    unittest.main()

