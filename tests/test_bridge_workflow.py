"""Offline integration tests for real Bridge entry points and extension boundaries."""

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from src.bridge import Bridge
from src.custom_api_client import CustomAPIClient
from src.external_client import ExternalClient
from src.models.memory import ExecutionPhaseResults
from src.ollama_client import OllamaClient
from src.workflow import ContextBlock, RunContext, WorkflowRuntime, WorkItem, WorkPlan
from src.workflow_host import WorkflowHost, WorkflowModelClient, get_workflow_host


class FakeModel:
    """A phase adapter that delegates internally, as the real providers do."""

    def __init__(self):
        self.calls = []
        self.responses = {}
        self.default_model = "offline-model"
        self.health_check = Mock(return_value=True)

    def generate(self, prompt, model=None, system_prompt=None, temperature=None, max_tokens=None, phase=None):
        self.calls.append(
            {
                "prompt": prompt,
                "model": model,
                "system_prompt": system_prompt,
                "temperature": temperature,
                "max_tokens": max_tokens,
                "phase": phase,
            }
        )
        response = self.responses.get(phase, "model response")
        if isinstance(response, Exception):
            raise response
        return response

    def generate_with_phase(self, prompt, phase=None, system_prompt=None):
        return self.generate(prompt=prompt, phase=phase, system_prompt=system_prompt)


class BridgeWorkflowTests(unittest.TestCase):
    def make_bridge(self, *, agentic=False, execution_loop=False, plugin_paths=None):
        bridge = Bridge.__new__(Bridge)
        bridge.config = SimpleNamespace(plugin_paths=plugin_paths or [], plugin_settings={}, plugin_context_budget=1000)
        bridge.llm_config = SimpleNamespace(
            agentic_loop_enabled=agentic,
            execution_loop_enabled=execution_loop,
            max_agentic_cycles=3,
            max_execution_steps=4,
        )
        bridge.logger = Mock()
        bridge.ghidra_client = SimpleNamespace(get_current_program_info=Mock(return_value={"program_id": "offline"}))
        bridge.context = []
        bridge.enable_cag = False
        bridge.cag_manager = None
        bridge.coverage_tracker = Mock()
        bridge.lead_tracker = Mock()
        bridge.session_compactor = None
        bridge.max_goal_steps = 1
        bridge._build_structured_prompt = Mock(return_value=("system instructions", "assembled context"))
        bridge._parse_plan_tools = Mock(return_value=[])
        bridge._update_scope_from_query = Mock()
        bridge.add_to_context = Mock()
        bridge._emit_cot = Mock()
        bridge._maybe_update_custom_workplan = Mock()
        bridge._clean_final_response = Mock(side_effect=lambda response: response)
        bridge.command_parser = SimpleNamespace(
            extract_commands=Mock(return_value=[]),
            validate_command_parameters=Mock(return_value=(True, "")),
            get_enhanced_error_message=Mock(side_effect=lambda name, params, error: error),
        )
        provider = FakeModel()
        host = get_workflow_host(bridge)
        bridge.ollama = host.wrap_model(provider)
        return bridge, host, provider

    def test_plugin_free_single_pass_keeps_original_plan_review_and_provider_arguments(self):
        bridge, host, provider = self.make_bridge()
        final = "The function validates a packet length before accessing its payload. " * 3
        provider.responses.update(planning="Inspect packet bounds", analysis="FINAL RESPONSE: " + final)
        bridge._execute_plan = Mock(return_value="Validated bounds and observed packet parsing. " * 3)
        response = bridge.process_query("Explain the parser")
        self.assertEqual(response, "FINAL RESPONSE:\n" + final.strip())
        self.assertEqual(bridge.current_plan, "Inspect packet bounds")
        self.assertTrue(bridge.goal_achieved)
        self.assertIsNone(bridge.current_workflow_stage)
        self.assertEqual([call["phase"] for call in provider.calls], ["planning", "analysis"])
        self.assertEqual(provider.calls[0]["prompt"], "assembled context\n\nUser Query: Explain the parser")
        self.assertTrue(all(call["system_prompt"] == "system instructions" for call in provider.calls))
        self.assertEqual(host.plugins.inventory(), [])
        bridge.ghidra_client.get_current_program_info.assert_not_called()
        bridge._execute_plan.assert_called_once_with()
        bridge._maybe_update_custom_workplan.assert_called_once_with(
            user_query="Explain the parser",
            final_response=response,
        )

    def test_plugin_free_single_pass_execution_loop_keeps_configured_step_limit(self):
        bridge, _, provider = self.make_bridge(execution_loop=True)
        execution = ExecutionPhaseResults(goal="Explain", total_steps=2)
        bridge._execution_loop = Mock(return_value=execution)
        bridge._analyze_execution_results = Mock(return_value="Two observations")
        provider.responses["planning"] = "Two-step plan"
        self.assertEqual(bridge.process_query("Explain"), "Two observations")
        bridge._execution_loop.assert_called_once_with("Two-step plan", max_steps=4)
        bridge._analyze_execution_results.assert_called_once_with(execution)
        bridge.ghidra_client.get_current_program_info.assert_not_called()

    def test_real_multi_cycle_controller_accepts_replaced_phases_and_stops_on_success(self):
        bridge, host, provider = self.make_bridge(agentic=True)
        stages = []
        evaluations = iter([(False, "Trace the caller"), (True, "Caller verified")])

        def execute(item, context):
            stages.append("execute")
            self.assertEqual(item.input["max_steps"], 4)
            return ExecutionPhaseResults(goal=bridge.current_goal, total_steps=2)

        def analyze(item, context):
            stages.append("analyze")
            self.assertIsInstance(item.input["exec_results"], ExecutionPhaseResults)
            return "Verified analysis"

        def evaluate(item, context):
            stages.append("evaluate")
            return next(evaluations)

        replacements = {"agent.execute": execute, "agent.analyze": analyze, "agent.evaluate": evaluate}
        for operation, handler in replacements.items():
            host.runtime.register_operation("example." + operation, handler)

        def replace_phases(item, context):
            if item.operation in replacements:
                item.operation = "example." + item.operation
            return item

        host.runtime.add_hook("request.prepare", replace_phases)
        provider.responses["planning"] = "Inspect relevant calls"
        response = bridge.process_query("Trace the parser")
        self.assertTrue(response.startswith("Verified analysis"))
        self.assertIn("Completed 2 investigation cycle(s) with 4 total tool executions", response)
        self.assertEqual(stages, ["execute", "analyze", "evaluate"] * 2)
        self.assertEqual(len(provider.calls), 2)
        self.assertIn("Previous evaluation: Trace the caller", provider.calls[1]["prompt"])
        self.assertTrue(bridge.goal_achieved)
        bridge.coverage_tracker.reset.assert_called_once_with()
        bridge.lead_tracker.reset.assert_called_once_with()

    def test_context_hook_reaches_final_model_prompt_once_and_inherits_phase_annotations(self):
        bridge, host, provider = self.make_bridge()
        observed = []

        def annotate(item, context):
            if item.operation == "agent.plan":
                item.annotations["review_focus"] = "bounds"
            return item

        def context_for_model(item, context):
            if item.operation != "llm.generate":
                return []
            observed.append(item.annotations["review_focus"])
            return [ContextBlock("Caller bounds evidence", source="caller 1000")]

        host.runtime.add_hook("request.prepare", annotate)
        host.runtime.add_hook("context.collect", context_for_model)
        self.assertEqual(bridge._generate_plan("Explain"), "model response")
        self.assertEqual(observed, ["bounds"])
        self.assertEqual(len(provider.calls), 1)
        self.assertEqual(provider.calls[0]["prompt"].count("Caller bounds evidence"), 1)
        self.assertEqual(provider.calls[0]["system_prompt"], "system instructions")
        self.assertIn("[Evidence: caller 1000]", provider.calls[0]["prompt"])

    def test_named_builtin_prelude_calls_planner_instead_of_original_query(self):
        bridge, host, provider = self.make_bridge()
        bridge.process_query_single_pass = Mock(return_value="query result")

        def add_plan(plan, context):
            if plan.workflow == "agent.default":
                plan.items[0].depends_on = ("prelude",)
                plan.items.insert(0, WorkItem("prelude", "agent.plan", {"query": "Prelude question"}))
            return plan

        host.runtime.add_hook("workflow.plan", add_plan)
        self.assertEqual(bridge.process_query("Main question"), "query result")
        self.assertEqual(len(provider.calls), 1)
        self.assertIn("User Query: Prelude question", provider.calls[0]["prompt"])
        bridge.process_query_single_pass.assert_called_once_with("Main question")
        self.assertEqual(host.last_results["prelude"].value, "model response")

    def test_model_prelude_in_query_uses_provider_without_reentering_query(self):
        bridge, host, provider = self.make_bridge()
        bridge.process_query_single_pass = Mock(return_value="query result")

        def add_model(plan, context):
            if plan.workflow == "agent.default":
                plan.items[0].depends_on = ("model-prelude",)
                plan.items.insert(0, WorkItem("model-prelude", "llm.generate", {"prompt": "Independent prompt"}))
            return plan

        host.runtime.add_hook("workflow.plan", add_model)
        self.assertEqual(bridge.process_query("Main question"), "query result")
        self.assertEqual([call["prompt"] for call in provider.calls], ["Independent prompt"])
        bridge.process_query_single_pass.assert_called_once_with("Main question")

    def test_model_prelude_in_phase_request_accepts_full_generate_signature(self):
        bridge, host, provider = self.make_bridge()

        def add_model(plan, context):
            if plan.workflow == "model.request":
                plan.items[0].depends_on = ("model-prelude",)
                plan.items.insert(
                    0,
                    WorkItem(
                        "model-prelude", "llm.generate", {"prompt": "Prelude", "model": "reasoning-model", "max_tokens": 128}
                    ),
                )
            return plan

        host.runtime.add_hook("workflow.plan", add_model)
        self.assertEqual(bridge.ollama.generate_with_phase("Main prompt", phase="planning"), "model response")
        self.assertEqual([call["prompt"] for call in provider.calls], ["Prelude", "Main prompt"])
        self.assertEqual(provider.calls[0]["model"], "reasoning-model")
        self.assertEqual(provider.calls[0]["max_tokens"], 128)
        self.assertEqual(provider.calls[1]["phase"], "planning")

    def test_manifest_loaded_custom_operation_can_replace_query_without_core_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "extension.py").write_text(
                "def activate(api):\n"
                "    api.register_operation('example.answer', lambda item, context: 'Plugin answer: ' + item.input['query'])\n"
                "    def transform(plan, context):\n"
                "        if plan.workflow == 'agent.default':\n"
                "            plan.items[0].operation = 'example.answer'\n"
                "        return plan\n"
                "    api.add_hook('workflow.plan', transform)\n",
                encoding="utf-8",
            )
            manifest = root / "plugin.toml"
            fields = {
                "id": "example.answer",
                "version": "1.0",
                "host_api": ">=1,<2",
                "entrypoint": "extension:activate",
                "contributions": ["operations", "workflow.plan"],
            }
            manifest.write_text("\n".join(f"{key} = {json.dumps(value)}" for key, value in fields.items()), encoding="utf-8")
            bridge, host, provider = self.make_bridge(plugin_paths=[str(manifest)])
            bridge.process_query_single_pass = Mock(side_effect=AssertionError("Original query should be replaced"))
            self.assertEqual(bridge.process_query("Explain"), "Plugin answer: Explain")
            self.assertEqual(host.plugins.inventory()[0]["status"], "active")
            self.assertEqual(provider.calls, [])
            bridge.process_query_single_pass.assert_not_called()

    def test_prelude_results_and_plugin_state_reach_nested_phase_and_model_context(self):
        bridge, host, provider = self.make_bridge(execution_loop=True)
        bridge._execution_loop = Mock(return_value=ExecutionPhaseResults(goal="Explain"))
        bridge._analyze_execution_results = Mock(return_value="Final")
        observations = []

        def seed(item, context):
            context.run.state["example.fact"] = "fact at address 1000"
            return "predecessor evidence"

        host.runtime.register_operation("example.seed", seed)

        def add_seed(plan, context):
            if plan.workflow == "agent.default":
                plan.items[0].depends_on = ("seed",)
                plan.items.insert(0, WorkItem("seed", "example.seed"))
            return plan

        def collect(item, context):
            if item.operation == "llm.generate":
                observations.append((context.results["seed"].value, context.run.state["example.fact"]))
                context.run.state["example.model_seen"] = True
            return []

        host.runtime.add_hook("workflow.plan", add_seed)
        host.runtime.add_hook("context.collect", collect)
        finished = []
        host.runtime.subscribe("workflow.finished", lambda event, ctx: finished.append((ctx.workflow, dict(ctx.state))))
        self.assertEqual(bridge.process_query("Explain"), "Final")
        self.assertEqual(observations, [("predecessor evidence", "fact at address 1000")])
        root_state = next(state for workflow, state in reversed(finished) if workflow == "agent.default")
        self.assertTrue(root_state["example.model_seen"])
        self.assertFalse(any(state.get("hook_errors") for _, state in finished))
        self.assertEqual(len(provider.calls), 1)

    def test_provider_exception_keeps_type_identity_and_is_not_retried(self):
        bridge, host, provider = self.make_bridge()
        error = TimeoutError("Provider request timed out")
        provider.responses["planning"] = error
        failed = []
        host.runtime.subscribe("operation.failed", lambda event, ctx: failed.append(event.data["result"]))
        with self.assertRaises(TimeoutError) as caught:
            bridge._generate_plan("Explain")
        self.assertIs(caught.exception, error)
        self.assertEqual(len(provider.calls), 1)
        self.assertEqual({result.operation for result in failed}, {"agent.plan", "llm.generate"})

    def test_existing_query_error_conversion_still_handles_provider_failure(self):
        bridge, _, provider = self.make_bridge()
        provider.responses["planning"] = TimeoutError("offline")
        self.assertEqual(bridge.process_query("Explain"), "Error in query processing: offline")
        self.assertEqual(len(provider.calls), 1)
        self.assertIsNone(bridge.current_workflow_stage)

    def test_tool_request_transform_preserves_real_dispatch_cache_and_failure_behavior(self):
        bridge, host, _ = self.make_bridge()
        bridge._normalize_command_name = Mock(side_effect=lambda name: name)
        bridge._get_cached_result = Mock(return_value=None)
        bridge._cache_result = Mock()
        bridge._update_analysis_state = Mock()
        bridge.cache_stats = {"hits": 0, "misses": 0}
        bridge.ghidra_client.rename_function = Mock(return_value="renamed")

        def choose_name(item, context):
            if item.operation == "tool.execute":
                item.input["params"]["new_name"] = "parse_packet"
            return item

        host.runtime.add_hook("request.prepare", choose_name)
        self.assertEqual(bridge.execute_command("rename_function", {"address": "1000", "new_name": "old"}), "renamed")
        bridge.ghidra_client.rename_function.assert_called_once_with(address="1000", new_name="parse_packet")
        self.assertEqual(bridge.cache_stats["misses"], 1)
        bridge._cache_result.assert_called_once()
        bridge.ghidra_client.rename_function.side_effect = RuntimeError("backend unavailable")
        with self.assertRaisesRegex(ValueError, "backend unavailable"):
            bridge.execute_command("rename_function", {"address": "1000", "new_name": "old"})
        self.assertEqual(bridge.ghidra_client.rename_function.call_count, 2)

    def test_model_gateway_forwards_both_public_signatures_and_non_generation_attributes(self):
        bridge, _, provider = self.make_bridge()
        self.assertEqual(bridge.ollama.generate("prompt", "override", "system", 0.25, 512, "analysis"), "model response")
        self.assertEqual(
            provider.calls[0],
            {
                "prompt": "prompt",
                "model": "override",
                "system_prompt": "system",
                "temperature": 0.25,
                "max_tokens": 512,
                "phase": "analysis",
            },
        )
        bridge.ollama.generate_with_phase("phase prompt", "planning", "system")
        self.assertEqual(provider.calls[1]["phase"], "planning")
        self.assertTrue(bridge.ollama.health_check())
        bridge.ollama.default_model = "updated"
        self.assertEqual(provider.default_model, "updated")
        with self.assertRaises(TypeError):
            bridge.ollama.generate("prompt", prompt="duplicate")
        with self.assertRaises(TypeError):
            bridge.ollama.generate()
        with self.assertRaises(TypeError):
            bridge.ollama.generate_with_phase("p", "phase", "system", "extra")
        self.assertEqual(len(provider.calls), 2)

    def test_phase_generation_option_changes_preserve_provider_phase_model_selection(self):
        for provider_class in (OllamaClient, CustomAPIClient, ExternalClient):
            with self.subTest(provider=provider_class.__name__):
                bridge, host, _ = self.make_bridge()
                provider = provider_class.__new__(provider_class)
                provider.model_map = {"planning": "gemini-phase-model"}
                provider.provider = "google"
                provider.logger = Mock()
                provider.generate = Mock(return_value="configured response")
                bridge.ollama = host.wrap_model(provider)

                def configure(item, context):
                    item.input.update(temperature=0.1, max_tokens=256)
                    return item

                host.runtime.add_hook("request.prepare", configure)
                self.assertEqual(bridge.ollama.generate_with_phase("Prompt", phase="planning"), "configured response")
                provider.generate.assert_called_once_with(
                    prompt="Prompt",
                    phase="planning",
                    model="gemini-phase-model",
                    temperature=0.1,
                    max_tokens=256,
                )

    def test_explicit_model_override_in_phase_request_is_respected(self):
        bridge, host, provider = self.make_bridge()
        provider.model_map = {"planning": "configured-phase-model"}

        def override(item, context):
            item.input.update(model="plugin-model")
            return item

        host.runtime.add_hook("request.prepare", override)
        self.assertEqual(bridge.ollama.generate_with_phase("Prompt", phase="planning"), "model response")
        self.assertEqual(provider.calls[0]["model"], "plugin-model")

    def test_promoted_google_phase_request_keeps_existing_invalid_model_fallback(self):
        bridge, host, _ = self.make_bridge()
        provider = ExternalClient.__new__(ExternalClient)
        provider.provider = "google"
        provider.model_map = {"planning": "local-only-model"}
        provider.logger = Mock()
        provider.generate = Mock(return_value="google response")
        bridge.ollama = host.wrap_model(provider)

        def configure(item, context):
            item.input["max_tokens"] = 256
            return item

        host.runtime.add_hook("request.prepare", configure)
        self.assertEqual(bridge.ollama.generate_with_phase("Prompt", phase="planning"), "google response")
        self.assertIsNone(provider.generate.call_args.kwargs.get("model"))
        self.assertEqual(provider.generate.call_args.kwargs["max_tokens"], 256)

    def test_reattachment_reuses_gateway_and_updates_shared_model_consumers(self):
        bridge, host, provider = self.make_bridge()
        bridge.context_manager = SimpleNamespace(ollama_client=None)
        bridge.session_compactor = SimpleNamespace(llm_client=None)
        original = bridge.ollama
        with patch.object(Bridge, "_ollama_client", None):
            bridge._attach_workflow_model()
            self.assertIs(bridge.ollama, original)
            self.assertIs(bridge.context_manager.ollama_client, original)
            self.assertIs(bridge.session_compactor.llm_client, original)
            self.assertIs(bridge.ghidra_client.ollama_client, original)
            self.assertIs(Bridge._ollama_client, original)
        replacement_host = WorkflowHost(bridge)
        replacement = replacement_host.wrap_model(original)
        self.assertIsInstance(replacement, WorkflowModelClient)
        self.assertIs(replacement._client, provider)
        self.assertIs(replacement._host, replacement_host)
        self.assertIs(host.wrap_model(original), original)

    def test_nested_generic_runtime_does_not_inherit_other_program_results(self):
        outer, inner = WorkflowRuntime(), WorkflowRuntime()
        inner.register_operation("inspect", lambda item, context: dict(context.results))
        outer.register_operation("seed", lambda item, context: "program A evidence")
        outer.register_operation(
            "nested",
            lambda item, context: (
                inner.run(WorkPlan([WorkItem("inspect", "inspect")]), RunContext(program_key="program B"))["inspect"].value
            ),
        )
        results = outer.run(
            WorkPlan([WorkItem("seed", "seed"), WorkItem("nested", "nested", depends_on=("seed",))]),
            RunContext(program_key="program A"),
        )
        self.assertEqual(results["nested"].value, {})

    def test_recorder_failure_reports_once_without_retrying_completed_side_effect(self):
        runtime = WorkflowRuntime()
        operation = Mock(return_value="side effect complete")
        recorder = Mock(side_effect=OSError("journal unavailable"))
        runtime.register_operation("example.write", operation)
        context = RunContext(services={"record_result": recorder})
        observed = []
        runtime.subscribe("operation.completed", lambda event, ctx: observed.append(ctx.state["workflow_results"]["write"]))
        with self.assertLogs("src.workflow.runtime", level="WARNING"):
            results = runtime.run(WorkPlan([WorkItem("write", "example.write")]), context)
        operation.assert_called_once()
        recorder.assert_called_once()
        self.assertEqual(results["write"].status, "completed")
        self.assertEqual(observed, [results["write"]])
        self.assertEqual(context.state["hook_errors"][0]["stage"], "result.record")


if __name__ == "__main__":
    unittest.main()
