"""Offline checks of legacy policy extraction and host stage/context contracts."""

import importlib.util
import threading
import unittest
from pathlib import Path

from src.workflow import RunContext, WorkContext, WorkflowRuntime, WorkItem, WorkPlan

PLUGIN_DIRECTORY = Path(__file__).resolve().parents[1] / "examples" / "plugins" / "strategic_ordering"
spec = importlib.util.spec_from_file_location("strategic_ordering_example", PLUGIN_DIRECTORY / "strategic_ordering.py")
plugin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plugin)


def item(address, name, **kwargs):
    return WorkItem(id=address, operation="function.analyze", input={"address": address, "name": name}, **kwargs)


def edges(callers=(), callees=()):
    return {"callers": callers, "callees": callees, "relationships_known": True}


class StrategicPolicyTests(unittest.TestCase):
    def test_active_legacy_priority_fixture(self):
        # Expected categories from the active EnumerationProcessor, not the
        # different legacy ui.py policy. Includes overlaps (main + hub).
        functions = [
            {"address": "7", "name": "FUN_7"},
            {"address": "6", "name": "FUN_6"},
            {"address": "5", "name": "FUN_5"},
            {"address": "4", "name": "parse_packet"},
            {"address": "3", "name": "setup_env"},
            {"address": "2", "name": "FUN_2"},
            {"address": "1", "name": "main"},
        ]
        graph = {
            "1": edges(("a", "b", "c"), ("d", "e", "f")),
            "2": edges(("a", "b"), ("c", "d")),
            "3": edges(("a",), ("b",)),
            "4": edges(("a",), ()),
            "5": edges(),
            "6": edges(("a",), ("b", "c", "d", "e", "f")),
        }
        result = plugin.classify_functions(functions, graph)
        self.assertEqual([row["function"]["address"] for row in result], ["1", "2", "3", "4", "5", "7", "6"])
        self.assertEqual([row["category"] for row in result], list(plugin.CATEGORIES) + ["remaining_functions"])
        self.assertTrue(all(row["reason"] for row in result))

    def test_legacy_thresholds_do_not_promote_name_only_hub_or_generic_leaf(self):
        functions = [
            {"address": "1", "name": "main"},
            {"address": "2", "name": "manager"},
            {"address": "3", "name": "FUN_3"},
            {"address": "4", "name": "parse"},
        ]
        result = plugin.classify_functions(functions, {"3": edges(("1",), ())})
        by_address = {row["function"]["address"]: row["category"] for row in result}
        self.assertEqual(
            by_address, {"1": "entry_points", "2": "remaining_functions", "3": "remaining_functions", "4": "leaf_utilities"}
        )

    def test_export_fallback_only_when_no_stronger_entry_exists(self):
        export = {"address": "2", "name": "CreateSession"}
        self.assertEqual(plugin.classify_functions([export])[0]["category"], "entry_points")
        result = plugin.classify_functions([export, {"address": "1", "name": "main"}])
        self.assertEqual(result[1]["category"], "architectural_components")

    def test_missing_graph_is_unknown_and_confirmed_entry_is_supported(self):
        functions = [{"address": "1", "name": "FUN_1"}, {"address": "2", "name": "FUN_2"}, {"address": "3", "name": "FUN_3"}]
        result = plugin.classify_functions(functions, {"2": edges(), "3": {"is_entry": True}})
        self.assertEqual(
            [(row["function"]["address"], row["category"]) for row in result],
            [("3", "entry_points"), ("2", "isolated_functions"), ("1", "remaining_functions")],
        )

    def test_address_identity_deduplicates_aliases_but_not_duplicate_names(self):
        functions = [
            {"address": "0x000A", "name": "same"},
            {"address": "a", "name": "renamed"},
            {"address": "b", "name": "same"},
        ]
        result = plugin.classify_functions(functions)
        self.assertEqual([row["function"] for row in result], [functions[0], functions[2]])

    def test_graph_cycles_do_not_change_stable_remaining_order(self):
        functions = [{"address": "b", "name": "FUN_b"}, {"address": "a", "name": "FUN_a"}]
        graph = {"a": edges(("b",), ("b",)), "b": edges(("a",), ("a",))}
        self.assertEqual([row["function"] for row in plugin.classify_functions(functions, graph)], functions)

    def test_distinct_address_spaces_do_not_merge_functions_or_graph_evidence(self):
        functions = [
            {"address": "ram:0010", "name": "same"},
            {"address": "overlay:0010", "name": "same"},
        ]
        result = plugin.classify_functions(functions, {"ram:0010": edges()})
        self.assertEqual(
            [(row["function"]["address"], row["category"]) for row in result],
            [("ram:0010", "isolated_functions"), ("overlay:0010", "remaining_functions")],
        )


class StrategicRuntimeTests(unittest.TestCase):
    def runtime(self):
        runtime = WorkflowRuntime()
        runtime.register_operation("function.analyze", lambda work, context: work.id)
        plugin.activate(runtime)
        return runtime

    def test_preserves_ids_dependencies_and_uses_linear_barriers(self):
        items = [item("b", "parse", depends_on=("a",)), item("a", "main")]
        plan = WorkPlan(items, workflow="functions.analyze")
        prepared = self.runtime().prepare_plan(plan, RunContext())
        functions = [work for work in prepared.items if work.operation == "function.analyze"]
        barriers = [work for work in prepared.items if work.operation == "workflow.barrier"]
        self.assertEqual([work.id for work in functions], ["a", "b"])
        self.assertEqual(len(barriers), 1)
        self.assertEqual(barriers[0].depends_on, ("a",))
        self.assertIn("a", functions[1].depends_on)
        self.assertIn(barriers[0].id, functions[1].depends_on)
        self.assertNotIn("strategic_category", plan.items[0].annotations)
        self.assertEqual(plugin.plan_functions(prepared, RunContext()), prepared)

    def test_empty_or_non_function_plan_does_not_request_graph_snapshot(self):
        def unexpected_snapshot():
            self.fail("No graph scan is needed without function analysis work")

        runtime = self.runtime()
        runtime.register_operation("custom.noop", lambda work, context: work.id)
        for items in ([], [WorkItem("unrelated", "custom.noop")]):
            with self.subTest(items=items):
                plan = WorkPlan(items, workflow="functions.analyze")
                run = RunContext(services={"function_snapshot": unexpected_snapshot})
                self.assertEqual(runtime.prepare_plan(plan, run), plan)
                self.assertNotIn("hook_errors", run.state)

    def test_generated_barrier_id_cannot_replace_existing_work(self):
        reserved_id = f"{plugin.PLUGIN_ID}.barrier.0"
        existing = [WorkItem(reserved_id, "workflow.barrier"), WorkItem(reserved_id + "_", "workflow.barrier")]
        plan = WorkPlan(existing + [item("b", "parse"), item("a", "main")], workflow="functions.analyze")
        prepared = self.runtime().prepare_plan(plan, RunContext())
        by_id = {work.id: work for work in prepared.items}
        self.assertEqual(len(prepared.items), len(by_id))
        for original in existing:
            self.assertEqual(by_id[original.id], original)
        barrier = by_id[reserved_id + "__"]
        self.assertTrue(barrier.annotations["strategic_barrier"])
        self.assertEqual(barrier.depends_on, ("a",))
        self.assertIn(barrier.id, by_id["b"].depends_on)

    def test_existing_reverse_dependency_rolls_back_without_state_mutation(self):
        plan = WorkPlan([item("a", "main", depends_on=("b",)), item("b", "parse")], workflow="functions.analyze")
        run = RunContext()
        prepared = self.runtime().prepare_plan(plan, run)
        self.assertEqual(prepared, plan)
        self.assertNotIn("strategic_ordering_categories", run.state)
        self.assertTrue(run.state.get("hook_errors"))

    def test_disabled_and_unrelated_workflow_keep_baseline_plan(self):
        plan = WorkPlan([item("b", "parse"), item("a", "main")], workflow="functions.analyze")
        baseline = WorkflowRuntime()
        baseline.register_operation("function.analyze", lambda work, context: work.id)
        self.assertEqual(baseline.prepare_plan(plan, RunContext()), plan)
        unrelated = WorkPlan(plan.items, workflow="custom")
        self.assertEqual(self.runtime().prepare_plan(unrelated, RunContext()), unrelated)

    def test_stage_barrier_waits_for_all_results_and_continues_after_failure(self):
        runtime = WorkflowRuntime()
        plugin.activate(runtime)
        recorded = []
        both_started = threading.Barrier(2)

        def analyze(work, context):
            if work.id in ("a", "b"):
                both_started.wait(timeout=3)
                if work.id == "b":
                    raise RuntimeError("one function cannot decompile")
            else:
                self.assertEqual(set(recorded), {"a", "b"})
            return work.id

        runtime.register_operation("function.analyze", analyze)
        plan = WorkPlan([item("c", "parse"), item("a", "main"), item("b", "_start")], workflow="functions.analyze")

        def record(work, result):
            if work.operation == "function.analyze" and work.id in ("a", "b"):
                recorded.append(work.id)

        results = runtime.run(plan, RunContext(), max_workers=2, on_result=record)
        self.assertEqual(results["b"].status, "failed")
        self.assertEqual(results["c"].status, "completed")

    def test_cancellation_prevents_next_stage(self):
        runtime = WorkflowRuntime()
        plugin.activate(runtime)
        stopped = threading.Event()

        def analyze(work, context):
            stopped.set()
            return work.id

        runtime.register_operation("function.analyze", analyze)
        plan = WorkPlan([item("b", "parse"), item("a", "main")], workflow="functions.analyze")
        results = runtime.run(plan, RunContext(cancelled=stopped.is_set), max_workers=1)
        self.assertEqual(results["b"].status, "cancelled")


class StrategicLoaderTests(unittest.TestCase):
    def test_manifest_loads_and_explicit_disable_preserves_baseline(self):
        from src.plugins import PluginManager

        plan = WorkPlan([item("b", "parse"), item("a", "main")], workflow="functions.analyze")
        for enabled in (False, True):
            with self.subTest(enabled=enabled):
                runtime = WorkflowRuntime()
                runtime.register_operation("function.analyze", lambda work, context: work.id)
                manager = PluginManager(runtime)
                status = manager.load([PLUGIN_DIRECTORY / "plugin.toml"], {plugin.PLUGIN_ID: {"enabled": enabled}})[0]
                self.assertEqual(status.status, "active" if enabled else "disabled", status.error)
                prepared = runtime.prepare_plan(plan, RunContext())
                functions = [work.id for work in prepared.items if work.operation == "function.analyze"]
                self.assertEqual(functions, ["a", "b"] if enabled else ["b", "a"])

    def test_nested_generation_sees_committed_prior_stage_record(self):
        from src.plugins import PluginManager

        runtime = WorkflowRuntime()
        runtime.register_operation("llm.generate", lambda work, context: work.input["prompt"])
        run = RunContext(state={"analysis_records": {}})
        prompts = {}

        def analyze(work, context):
            generated = WorkItem(
                "llm-" + work.id,
                "llm.generate",
                input={"prompt": "Analyze code"},
                annotations=dict(work.annotations, function_address=work.input["address"]),
            )
            result = runtime.run(WorkPlan([generated], workflow="generation"), context.run)[generated.id]
            prompts[work.id] = result.value
            return "initialization evidence" if work.id == "a" else "parser evidence"

        runtime.register_operation("function.analyze", analyze)
        status = PluginManager(runtime).load([PLUGIN_DIRECTORY / "plugin.toml"])[0]
        self.assertEqual(status.status, "active", status.error)

        def record(work, result):
            if work.operation == "function.analyze" and result.status == "completed":
                run.state["analysis_records"][work.id] = {
                    "address": work.input["address"],
                    "name": work.input["name"],
                    "status": result.status,
                    "summary": result.value,
                    "strategic_category": work.annotations["strategic_category"],
                }

        runtime.run(
            WorkPlan([item("b", "parse"), item("a", "main")], workflow="functions.analyze"),
            run,
            max_workers=2,
            on_result=record,
        )
        self.assertNotIn("initialization evidence", prompts["a"])
        self.assertIn("Earlier analysis main at a: initialization evidence", prompts["b"])


class StrategicContextTests(unittest.TestCase):
    def test_only_successful_earlier_stages_are_contributed(self):
        work = WorkItem("llm", "llm.generate", annotations={"strategic_category": "leaf_utilities", "function_address": "d"})
        run = RunContext(
            state={
                "analysis_records": {
                    "a": {
                        "status": "completed",
                        "address": "a",
                        "new_name": "main",
                        "summary": "startup evidence",
                        "strategic_category": "entry_points",
                    },
                    "b": {"status": "failed", "summary": "failed evidence", "strategic_category": "entry_points"},
                    "c": {"status": "completed", "summary": "same stage evidence", "strategic_category": "leaf_utilities"},
                    "e": {"status": "completed", "summary": "future evidence", "strategic_category": "remaining_functions"},
                }
            }
        )
        blocks = plugin.collect_context(work, WorkContext(run, work))
        self.assertEqual(len(blocks), 1)
        self.assertIn("startup evidence", blocks[0].text)
        for text in ("failed evidence", "same stage evidence", "future evidence"):
            self.assertNotIn(text, blocks[0].text)
        run.context_budget = 0
        self.assertEqual(plugin.collect_context(work, WorkContext(run, work)), [])

    def test_current_function_is_not_used_as_its_own_prior_stage_evidence(self):
        work = WorkItem(
            "llm",
            "llm.generate",
            annotations={"strategic_category": "leaf_utilities", "function_address": "401000"},
        )
        run = RunContext(
            state={
                "analysis_records": {
                    "self": {
                        "status": "completed",
                        "address": "0x0000401000",
                        "summary": "self-reinforcing claim",
                        "strategic_category": "entry_points",
                    },
                    "other": {
                        "status": "completed",
                        "address": "402000",
                        "summary": "other function interpretation",
                        "strategic_category": "entry_points",
                    },
                }
            }
        )
        text = plugin.collect_context(work, WorkContext(run, work))[0].text
        self.assertNotIn("self-reinforcing claim", text)
        self.assertIn("other function interpretation", text)

    def test_context_is_bounded_and_ignores_non_llm_operations(self):
        work = WorkItem("llm", "llm.generate", annotations={"strategic_category": "remaining_functions"})
        run = RunContext(
            context_budget=30,
            state={
                "analysis_records": {
                    str(index): {"status": "completed", "summary": "x" * 5000, "strategic_category": "entry_points"}
                    for index in range(30)
                }
            },
        )
        self.assertLessEqual(len(plugin.collect_context(work, WorkContext(run, work))[0].text), 120)
        work.operation = "function.analyze"
        self.assertEqual(plugin.collect_context(work, WorkContext(run, work)), [])


if __name__ == "__main__":
    unittest.main()
