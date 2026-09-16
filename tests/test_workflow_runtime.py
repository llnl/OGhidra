"""Offline behavioral tests for the generic workflow runtime."""

import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Event, Lock

from src.workflow import (
    ContextBlock,
    RunContext,
    WorkContext,
    WorkflowRuntime,
    WorkItem,
    WorkPlan,
    WorkResult,
    get_current_work_context,
)


class WorkflowRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.runtime = WorkflowRuntime()
        self.runtime.register_operation("echo", lambda item, ctx: item.input.get("value", item.id))

    def plan(self, *items):
        return WorkPlan(list(items))

    def test_default_contracts_do_not_share_mutable_state(self):
        left, right = WorkItem("a", "echo"), WorkItem("b", "echo")
        left.input["x"] = 1
        self.assertEqual(right.input, {})
        run1, run2 = RunContext(), RunContext()
        self.assertNotEqual(run1.run_id, run2.run_id)
        run1.state["x"] = 1
        self.assertEqual(run2.state, {})
        self.assertFalse(run1.cancelled())
        self.assertIs(WorkContext(run1, left).services, run1.services)

    def test_empty_plan_lifecycle_and_barrier_builtin(self):
        events = []
        self.runtime.subscribe("*", lambda event, ctx, events=events: events.append(event.name))
        self.assertEqual(self.runtime.run(self.plan(), RunContext()), {})
        self.assertEqual(events, ["workflow.started", "workflow.completed", "workflow.finished"])
        result = self.runtime.run(self.plan(WorkItem("barrier", "workflow.barrier")), RunContext())
        self.assertEqual(result["barrier"].status, "completed")
        self.assertIsNone(result["barrier"].value)

    def test_reject_duplicate_operation_and_bad_registration(self):
        for name, handler in [("", lambda *_: None), ("x", None), (None, lambda *_: None)]:
            with self.assertRaises((TypeError, ValueError)):
                self.runtime.register_operation(name, handler)
        with self.assertRaisesRegex(ValueError, "already registered"):
            self.runtime.register_operation("echo", lambda *_: None)
        for stage, callback, priority in [("", lambda *_: None, 0), ("x", None, 0), ("x", lambda *_: None, True)]:
            with self.assertRaises((TypeError, ValueError)):
                self.runtime.add_hook(stage, callback, priority=priority)
        with self.assertRaises((TypeError, ValueError)):
            self.runtime.subscribe("workflow.plan", lambda *_: None)
        with self.assertRaises((TypeError, ValueError)):
            self.runtime.emit("workflow.plan", {}, RunContext())

    def test_registration_rollback_removes_partial_plugin(self):
        snapshot = self.runtime.snapshot_registrations()
        self.runtime.register_operation("extra", lambda *_: "extra")
        self.runtime.add_hook("workflow.plan", lambda plan, ctx: WorkPlan([]), plugin_id="partial")
        self.runtime.restore_registrations(snapshot)
        result = self.runtime.run(self.plan(WorkItem("a", "echo")), RunContext())
        self.assertEqual(result["a"].value, "a")
        with self.assertRaisesRegex(ValueError, "Unknown operation"):
            self.runtime.validate_plan(self.plan(WorkItem("x", "extra")))
        with self.assertRaises((TypeError, ValueError)):
            self.runtime.restore_registrations({})

    def test_invalid_plans_rejected_before_any_handler(self):
        bad_plans = [
            None,
            WorkPlan(()),
            WorkPlan([], workflow=""),
            WorkPlan([], annotations=[]),
            self.plan("wrong"),
            self.plan(WorkItem("", "echo")),
            self.plan(WorkItem("a", "missing")),
            self.plan(WorkItem("a", "echo", input=[])),
            self.plan(WorkItem("a", "echo", annotations=[])),
            self.plan(WorkItem("a", "echo", priority=True)),
            self.plan(WorkItem("a", "echo", depends_on="a")),
            self.plan(WorkItem("a", "echo", depends_on=(1,))),
            self.plan(WorkItem("a", "echo", depends_on=("b", "b")), WorkItem("b", "echo")),
            self.plan(WorkItem("a", "echo"), WorkItem("a", "echo")),
            self.plan(WorkItem("a", "echo", depends_on=("missing",))),
            self.plan(WorkItem("a", "echo", depends_on=("a",))),
            self.plan(WorkItem("a", "echo", depends_on=("b",)), WorkItem("b", "echo", depends_on=("a",))),
        ]
        for plan in bad_plans:
            with self.subTest(plan=plan), self.assertRaises((TypeError, ValueError)):
                self.runtime.run(plan, RunContext())

    def test_invalid_limits_rejected(self):
        for workers in [0, -1, True, 1.5]:
            with self.subTest(workers=workers), self.assertRaises((TypeError, ValueError)):
                self.runtime.run(self.plan(), RunContext(), max_workers=workers)
        for budget in [-1, "100"]:
            with self.subTest(budget=budget), self.assertRaises((TypeError, ValueError)):
                self.runtime.run(self.plan(), RunContext(context_budget=budget))

    def test_priority_and_equal_priority_preserve_plan_order(self):
        order = []
        self.runtime.register_operation("record", lambda item, ctx: order.append(item.id))
        self.runtime.run(
            self.plan(
                WorkItem("low", "record", priority=-1),
                WorkItem("first", "record", priority=2),
                WorkItem("second", "record", priority=2),
                WorkItem("middle", "record"),
            ),
            RunContext(),
        )
        self.assertEqual(order, ["first", "second", "middle", "low"])

    def test_plan_hooks_order_and_rollback_in_place_mutation(self):
        order = []

        def good(plan, context):
            order.append("good")
            plan.items[0].input["value"] = "accepted"
            return plan

        def broken(plan, context):
            order.append("broken")
            plan.items[0].input["value"] = "corrupt"
            raise RuntimeError("optional hook failed")

        def invalid(plan, context):
            order.append("invalid")
            return replace(plan, items=plan.items + plan.items)

        self.runtime.add_hook("workflow.plan", invalid, plugin_id="invalid", priority=-1)
        self.runtime.add_hook("workflow.plan", good, plugin_id="good", priority=2)
        self.runtime.add_hook("workflow.plan", broken, plugin_id="broken", priority=2)
        original = self.plan(WorkItem("a", "echo"))
        context = RunContext()
        result = self.runtime.run(original, context)
        self.assertEqual(order, ["good", "broken", "invalid"])
        self.assertEqual(result["a"].value, "accepted")
        self.assertEqual(original.items[0].input, {})
        self.assertEqual(len(context.state["hook_errors"]), 2)

    def test_dependency_barrier_waits_for_entire_prior_stage(self):
        entered = Event()
        release = Event()
        completion_order = []
        lock = Lock()

        def stage(item, context):
            if item.id == "slow":
                entered.set()
                self.assertTrue(release.wait(2))
            elif item.id == "fast":
                self.assertTrue(entered.wait(2))
                release.set()
            else:
                self.assertEqual(context.results["slow"].status, "completed")
                self.assertEqual(context.results["fast"].status, "completed")
                self.assertEqual(context.results["barrier"].status, "completed")
            with lock:
                completion_order.append(item.id)

        self.runtime.register_operation("stage", stage)
        result = self.runtime.run(
            self.plan(
                WorkItem("slow", "stage"),
                WorkItem("fast", "stage"),
                WorkItem("barrier", "workflow.barrier", depends_on=("slow", "fast")),
                WorkItem("next", "stage", priority=100, depends_on=("barrier",)),
            ),
            RunContext(),
            max_workers=2,
        )
        self.assertEqual(result["next"].status, "completed")
        self.assertEqual(completion_order[-1], "next")

    def test_bounded_concurrency_does_not_submit_whole_plan(self):
        active = 0
        high_water = 0
        lock = Lock()
        reached_two = Event()

        def operation(item, context):
            nonlocal active, high_water
            with lock:
                active += 1
                high_water = max(high_water, active)
                if active == 2:
                    reached_two.set()
            self.assertTrue(reached_two.wait(2))
            with lock:
                active -= 1
            return item.id

        self.runtime.register_operation("parallel", operation)
        results = self.runtime.run(self.plan(*[WorkItem(str(i), "parallel") for i in range(6)]), RunContext(), max_workers=2)
        self.assertEqual(len(results), 6)
        self.assertEqual(high_water, 2)

    def test_failed_dependencies_skip_transitively_but_independent_work_runs(self):
        self.runtime.register_operation("fail", lambda item, ctx: (_ for _ in ()).throw(RuntimeError("nope")))
        results = self.runtime.run(
            self.plan(
                WorkItem("last", "echo", depends_on=("middle",)),
                WorkItem("middle", "echo", depends_on=("failed",)),
                WorkItem("failed", "fail"),
                WorkItem("ok", "echo"),
            ),
            RunContext(),
        )
        self.assertEqual(results["failed"].status, "failed")
        self.assertEqual(results["last"].status, "skipped")
        self.assertEqual(results["middle"].status, "skipped")
        self.assertEqual(results["ok"].status, "completed")

    def test_settled_barrier_continues_after_failure_but_normal_deps_do_not(self):
        self.runtime.register_operation("fail", lambda item, ctx: WorkResult(item.id, item.operation, "failed", error="failed"))
        result = self.runtime.run(
            self.plan(
                WorkItem("a", "fail"),
                WorkItem("b", "echo"),
                WorkItem("barrier", "workflow.barrier", depends_on=("a", "b"), annotations={"dependency_policy": "settled"}),
                WorkItem("c", "echo", depends_on=("barrier",)),
                WorkItem("d", "echo", depends_on=("a",), annotations={"dependency_policy": "settled"}),
            ),
            RunContext(),
            max_workers=2,
        )
        self.assertEqual(result["barrier"].status, "completed")
        self.assertEqual(result["c"].status, "completed")
        self.assertEqual(result["d"].status, "skipped")

    def test_cancel_before_run_does_not_dispatch(self):
        results = self.runtime.run(self.plan(WorkItem("a", "echo")), RunContext(cancelled=lambda: True))
        self.assertEqual(results["a"].status, "cancelled")

    def test_cancellation_records_running_operation_without_retry(self):
        stop = Event()
        calls = []

        def operation(item, context):
            calls.append(item.id)
            stop.set()
            return "write completed"

        self.runtime.register_operation("write", operation)
        result = self.runtime.run(self.plan(WorkItem("a", "write"), WorkItem("b", "write")), RunContext(cancelled=stop.is_set))
        self.assertEqual(calls, ["a"])
        self.assertEqual(result["a"].status, "completed")
        self.assertEqual(result["b"].status, "cancelled")

    def test_cancel_during_prepare_never_calls_handler(self):
        stop = Event()

        def cancel(item, context):
            stop.set()
            return item

        self.runtime.add_hook("request.prepare", cancel)
        result = self.runtime.run(self.plan(WorkItem("a", "echo")), RunContext(cancelled=stop.is_set))
        self.assertEqual(result["a"].status, "cancelled")

    def test_started_observer_cancellation_prevents_side_effect(self):
        stop = Event()
        calls = []
        self.runtime.register_operation("write", lambda item, ctx: calls.append(item.id))
        self.runtime.subscribe("operation.started", lambda event, ctx: stop.set())
        result = self.runtime.run(self.plan(WorkItem("a", "write")), RunContext(cancelled=stop.is_set))
        self.assertEqual(calls, [])
        self.assertEqual(result["a"].status, "cancelled")

    def test_program_validation_rejects_stale_completion(self):
        valid = {"value": True}

        def change(item, context):
            valid["value"] = False
            return "stale"

        self.runtime.register_operation("change", change)
        context = RunContext(services={"validate_program": lambda run: valid["value"]})
        result = self.runtime.run(self.plan(WorkItem("a", "change"), WorkItem("b", "echo")), context)
        self.assertEqual(result["a"].status, "cancelled")
        self.assertIsNone(result["a"].value)
        self.assertEqual(result["b"].status, "cancelled")

    def test_program_validator_exception_stops_dispatch(self):
        def broken(run):
            raise RuntimeError("missing program")

        result = self.runtime.run(self.plan(WorkItem("a", "echo")), RunContext(services={"validate_program": broken}))
        self.assertEqual(result["a"].status, "cancelled")

    def test_request_and_prompt_transforms_receive_copies_and_preserve_graph(self):
        def prepare(item, context):
            item.input["value"] = "prepared"
            return item

        def invalid(item, context):
            item.input["value"] = "bad"
            item.depends_on = ("elsewhere",)
            return item

        def prompt(item, context):
            item.input["value"] += "-prompt"
            return item

        self.runtime.add_hook("request.prepare", prepare)
        self.runtime.add_hook("request.prepare", invalid)
        self.runtime.add_hook("prompt.transform", prompt)
        context = RunContext()
        original = WorkItem("a", "echo")
        result = self.runtime.run(self.plan(original), context)
        self.assertEqual(result["a"].value, "prepared-prompt")
        self.assertEqual(original.input, {})
        self.assertEqual(context.state["hook_errors"][0]["stage"], "request.prepare")

    def test_context_is_sorted_deduplicated_and_budgeted_without_replacing_original_prompt(self):
        self.runtime.register_operation("llm.generate", lambda item, ctx: item.input["prompt"])
        self.runtime.add_hook(
            "context.collect",
            lambda item, ctx: [
                ContextBlock("duplicate", source="low", priority=-1),
                ContextBlock("duplicate", source="verified", priority=10),
                ContextBlock("instruction text", kind="instructions", priority=5),
                ContextBlock("x" * 1000, priority=0),
            ],
        )
        result = self.runtime.run(
            self.plan(WorkItem("a", "llm.generate", {"prompt": "original"})), RunContext(context_budget=40)
        )
        prompt = result["a"].value
        self.assertTrue(prompt.startswith("original\n\n[Evidence: verified]"))
        self.assertEqual(prompt.count("duplicate"), 1)
        self.assertNotIn("[Evidence: low]", prompt)
        self.assertIn("[Instructions]", prompt)
        self.assertLessEqual(len(prompt) - len("original\n\n"), 160)
        self.assertTrue(prompt.endswith("…"))

    def test_context_zero_budget_empty_contributors_and_non_model_operations(self):
        self.runtime.register_operation("llm.generate", lambda item, ctx: item.input.get("prompt"))
        self.runtime.add_hook("context.collect", lambda item, ctx: None)
        self.runtime.add_hook("context.collect", lambda item, ctx: [ContextBlock(""), ContextBlock("x", source="long source")])
        result = self.runtime.run(
            self.plan(WorkItem("a", "llm.generate", {"prompt": "original"})), RunContext(context_budget=0)
        )
        self.assertEqual(result["a"].value, "original")
        result = self.runtime.run(
            self.plan(WorkItem("b", "llm.generate", {"prompt": None}), WorkItem("c", "echo")), RunContext()
        )
        self.assertIsNone(result["b"].value)
        self.assertEqual(result["c"].value, "c")

    def test_bad_context_contributors_are_isolated(self):
        self.runtime.register_operation("llm.generate", lambda item, ctx: item.input["prompt"])
        for value in [["string"], [ContextBlock("text", kind="system")], [ContextBlock("text", source=1)]]:
            self.runtime.add_hook("context.collect", lambda item, ctx, value=value: value)
        self.runtime.add_hook("context.collect", lambda item, ctx: [ContextBlock("good")])
        context = RunContext()
        result = self.runtime.run(self.plan(WorkItem("a", "llm.generate", {"prompt": "original"})), context)
        self.assertIn("good", result["a"].value)
        self.assertEqual(len(context.state["hook_errors"]), 3)

    def test_host_composer_can_handle_other_operations_and_fails_to_original(self):
        self.runtime.add_hook("context.collect", lambda item, ctx: [ContextBlock("supplied")])

        def compose(item, context, blocks):
            item.input["value"] = blocks[0].text
            return item

        result = self.runtime.run(self.plan(WorkItem("a", "echo")), RunContext(services={"compose_context": compose}))
        self.assertEqual(result["a"].value, "supplied")

        def broken(item, context, blocks):
            item.input["value"] = "bad"
            item.id = "changed"
            return item

        context = RunContext(services={"compose_context": broken})
        result = self.runtime.run(self.plan(WorkItem("a", "echo")), context)
        self.assertEqual(result["a"].value, "a")
        self.assertEqual(context.state["hook_errors"][0]["stage"], "context.compose")

    def test_result_transform_cannot_launder_failure_or_change_identity(self):
        self.runtime.add_hook("result.transform", lambda result, ctx: replace(result, value="presented"))
        self.runtime.add_hook("result.transform", lambda result, ctx: replace(result, status="failed"))
        self.runtime.add_hook("result.transform", lambda result, ctx: replace(result, item_id="other"))
        context = RunContext()
        result = self.runtime.run(self.plan(WorkItem("a", "echo")), context)
        self.assertEqual(result["a"].status, "completed")
        self.assertEqual(result["a"].value, "presented")
        self.assertEqual(len(context.state["hook_errors"]), 2)

    def test_handler_returning_invalid_result_fails_once(self):
        self.runtime.register_operation("bad", lambda item, ctx: WorkResult(item.id, item.operation, "unknown"))
        result = self.runtime.run(self.plan(WorkItem("a", "bad")), RunContext())
        self.assertEqual(result["a"].status, "failed")
        self.assertIn("Invalid result status", result["a"].error)

    def test_observers_see_recorded_result_and_are_isolated(self):
        events = []

        def broken(event, context):
            self.assertEqual(context.state["workflow_results"][event.item_id].status, "completed")
            event.data["result"].status = "failed"
            raise RuntimeError("observer failed after write")

        self.runtime.subscribe("operation.completed", broken)
        self.runtime.subscribe("analysis.completed", lambda event, ctx: events.append(event.data["result"].status))
        context = RunContext()
        result = self.runtime.run(
            self.plan(WorkItem("a", "echo", annotations={"completion_event": "analysis.completed"})), context
        )
        self.assertEqual(result["a"].status, "completed")
        self.assertEqual(events, ["completed"])
        self.assertEqual(len(context.state["hook_errors"]), 1)

    def test_invalid_alias_cannot_invoke_transform_as_observer(self):
        context = RunContext()
        result = self.runtime.run(self.plan(WorkItem("a", "echo", annotations={"completion_event": "workflow.plan"})), context)
        self.assertEqual(result["a"].status, "completed")

    def test_contextvars_nested_run_restores_parent_and_inherits_results(self):
        contexts = []

        def child(item, ctx):
            self.assertIs(get_current_work_context(), ctx)
            self.assertEqual(ctx.results["first"].value, "first")
            with self.assertRaises(TypeError):
                ctx.results["insert"] = None
            # Even a malformed plugin cannot mutate scheduler dependency status
            # through the result objects in its local snapshot.
            ctx.results["first"].status = "failed"
            return "child"

        def parent(item, ctx):
            self.assertIs(get_current_work_context(), ctx)
            child_result = self.runtime.run(self.plan(WorkItem("child", "child")), ctx.run)
            self.assertIs(get_current_work_context(), ctx)
            contexts.append(ctx.item.id)
            return child_result["child"].value

        self.runtime.register_operation("parent", parent)
        self.runtime.register_operation("child", child)
        result = self.runtime.run(
            self.plan(WorkItem("first", "echo"), WorkItem("parent", "parent", depends_on=("first",))), RunContext()
        )
        self.assertEqual(result["parent"].value, "child")
        self.assertEqual(result["first"].status, "completed")
        self.assertEqual(contexts, ["parent"])
        self.assertIsNone(get_current_work_context())

    def test_executor_factory_and_result_callback(self):
        calls = []

        def factory(**kwargs):
            calls.append(kwargs["max_workers"])
            return ThreadPoolExecutor(**kwargs)

        results_seen = []
        self.runtime.run(
            self.plan(WorkItem("a", "echo")),
            RunContext(services={"executor_factory": factory}),
            on_result=lambda item, result: results_seen.append((item.id, result.status)),
        )
        self.assertEqual(calls, [1])
        self.assertEqual(results_seen, [("a", "completed")])

    def test_closing_generator_records_inflight_work_and_stops_new_dispatch(self):
        entered = Event()
        release = Event()

        def operation(item, ctx):
            if item.id == "first":
                self.assertTrue(entered.wait(2))
            else:
                entered.set()
                self.assertTrue(release.wait(2))
            return item.id

        self.runtime.register_operation("blocking", operation)
        context = RunContext()
        iterator = self.runtime.iter_results(
            self.plan(WorkItem("first", "blocking"), WorkItem("second", "blocking"), WorkItem("pending", "echo")),
            context,
            max_workers=2,
        )
        first_item, _ = next(iterator)
        self.assertEqual(first_item.id, "first")
        release.set()
        iterator.close()
        self.assertEqual(context.state["workflow_results"]["second"].status, "completed")
        self.assertNotIn("pending", context.state["workflow_results"])


class WorkflowLifecycleTests(unittest.TestCase):
    def test_outcome_events_follow_committed_results(self):
        for status in ("completed", "failed", "cancelled", "skipped"):
            with self.subTest(status=status):
                runtime = WorkflowRuntime()
                runtime.register_operation(
                    "operation", lambda item, ctx, status=status: WorkResult(item.id, item.operation, status)
                )
                events = []
                runtime.subscribe("*", lambda event, ctx, events=events: events.append(event.name))
                runtime.run(WorkPlan([WorkItem("item", "operation")]), RunContext())
                expected = "failed" if status == "skipped" else status
                self.assertEqual(
                    events,
                    [
                        "workflow.started",
                        "operation.started",
                        f"operation.{status}",
                        f"workflow.{expected}",
                        "workflow.finished",
                    ],
                )

    def test_result_callback_exception_never_retries_operation(self):
        runtime = WorkflowRuntime()
        calls = []
        runtime.register_operation("write", lambda item, ctx: calls.append(item.id))
        context = RunContext()

        def fail(item, result):
            raise RuntimeError("UI unavailable")

        with self.assertRaisesRegex(RuntimeError, "UI unavailable"):
            runtime.run(WorkPlan([WorkItem("first", "write"), WorkItem("pending", "write")]), context, on_result=fail)
        self.assertEqual(calls, ["first"])
        self.assertEqual(context.state["workflow_results"]["first"].status, "completed")


if __name__ == "__main__":
    unittest.main()
