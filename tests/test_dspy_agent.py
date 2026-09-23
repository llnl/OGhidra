from types import SimpleNamespace

import dspy

from src.agent.plugins import (
    AddressOrderPlugin,
    AnalysisPlugin,
    FunctionRAGPlugin,
    PluginContext,
    PluginHook,
    PluginManager,
    PluginPhase,
)
from src.agent.program import DSPyCompletionClient, OGhidraAgent, OGhidraDSPyProgram


class FakeProviderClient:
    def __init__(self):
        self.config = SimpleNamespace(model="test-model", temperature=0.0, max_tokens=1000)
        self.default_model = "test-model"
        self.model_map = {"planning": "planner", "execution": "executor"}
        self.calls = []

    def generate(self, **kwargs):
        self.calls.append(kwargs)
        prompt = kwargs["prompt"]
        if "goal_achieved" in prompt:
            return (
                "[[ ## goal_achieved ## ]]\nTrue\n"
                "[[ ## reason ## ]]\nEnough evidence was collected.\n"
                "[[ ## completed ## ]]"
            )
        if "[[ ## plan ## ]]" in prompt:
            return "[[ ## plan ## ]]\nInspect imports, then decompile main.\n[[ ## completed ## ]]"
        if "[[ ## reasoning ## ]]" in prompt:
            return (
                "[[ ## reasoning ## ]]\nInspect imports before choosing a function.\n"
                '[[ ## actions ## ]]\n[{"tool":"list_imports","parameters":{"offset":0,"limit":50}}]\n'
                "[[ ## complete ## ]]\nFalse\n"
                "[[ ## question ## ]]\n\n"
                "[[ ## question_options ## ]]\n[]\n"
                "[[ ## completed ## ]]"
            )
        if "[[ ## selected_indices ## ]]" in prompt:
            return "[[ ## selected_indices ## ]]\n[1, 0]\n[[ ## completed ## ]]"
        if "[[ ## binary_purpose ## ]]" in prompt:
            return (
                "[[ ## binary_purpose ## ]]\nTest binary\n"
                "[[ ## security_apis ## ]]\n[]\n"
                "[[ ## investigation_leads ## ]]\n[]\n"
                "[[ ## artifacts ## ]]\n[]\n"
                "[[ ## key_functions ## ]]\n[]\n"
                "[[ ## investigation_gaps ## ]]\n[]\n"
                "[[ ## recommended_next_steps ## ]]\n[]\n"
                "[[ ## completed ## ]]"
            )
        if "[[ ## software_classification ## ]]" in prompt:
            return (
                '[[ ## software_classification ## ]]\n{"type":"Utility","purpose":"Testing"}\n'
                '[[ ## security_assessment ## ]]\n{"risk_level":"LOW"}\n'
                "[[ ## function_categorization ## ]]\n{}\n"
                "[[ ## behavioral_analysis ## ]]\n{}\n"
                "[[ ## architecture_analysis ## ]]\n{}\n"
                '[[ ## risk_assessment ## ]]\n{"rating":"LOW"}\n'
                "[[ ## completed ## ]]"
            )
        if "[[ ## metadata ## ]]" in prompt and "[[ ## sections ## ]]" in prompt:
            return (
                '[[ ## metadata ## ]]\n{"severity":"LOW","subtitle":"Test report"}\n'
                '[[ ## sections ## ]]\n[{"id":"summary","title":"Summary","content":"Safe"}]\n'
                "[[ ## completed ## ]]"
            )
        if "[[ ## behavior_summary ## ]]" in prompt and "[[ ## suggested_name ## ]]" in prompt:
            return (
                "[[ ## analysis ## ]]\nParses a configuration buffer.\n"
                "[[ ## behavior_summary ## ]]\nDecodes and validates configuration values.\n"
                "[[ ## suggested_name ## ]]\nparseConfigurationBuffer\n"
                "[[ ## rationale ## ]]\nThe name reflects the input and primary operation.\n"
                "[[ ## completed ## ]]"
            )
        if "[[ ## analysis ## ]]" in prompt:
            return "[[ ## analysis ## ]]\nThe evidence identifies the program entry path.\n[[ ## completed ## ]]"
        return "[[ ## response ## ]]\nAuxiliary result\n[[ ## completed ## ]]"


def test_dspy_program_uses_typed_phase_signatures():
    client = FakeProviderClient()
    program = OGhidraDSPyProgram(client)

    assert program.plan("Use Ghidra tools", "Find main") == "Inspect imports, then decompile main."
    decision = program.decide("Use one tool", "No tools run yet")
    assert decision.actions[0].tool == "list_imports"
    assert program.analyze("Be grounded", "Import evidence").startswith("The evidence identifies")
    assert program.evaluate("Be strict", "Goal and evidence") == (True, "Enough evidence was collected.")
    assert program.rank("Find main", "list_functions", "0: a\n1: main", 2) == [1, 0]
    assert program.consolidate("Find main", "ranked", "none")["binary_purpose"] == "Test binary"
    assert program.analyze_software("binary evidence")["software_classification"]["type"] == "Utility"
    function_analysis = program.analyze_function("FUN_1000", "return parse(buffer);")
    assert function_analysis.suggested_name == "parseConfigurationBuffer"
    assert "**Behavior Summary:**" in function_analysis.as_markdown()
    metadata, sections = program.render_html_report("report evidence")
    assert metadata["severity"] == "LOW"
    assert sections[0].id == "summary"
    assert program(task="Find main", guidance="Use Ghidra tools", phase="planning").output == (
        "Inspect imports, then decompile main."
    )

    assert [call["phase"] for call in client.calls] == [
        "planning",
        "execution",
        "analysis",
        "evaluation",
        "execution",
        "analysis",
        "analysis",
        "analysis",
        "analysis",
        "planning",
    ]
    assert client.calls[0]["model"] == "planner"
    assert client.calls[1]["model"] == "executor"


def test_completion_client_routes_auxiliary_generation_through_dspy():
    client = FakeProviderClient()
    completion_client = DSPyCompletionClient(client, OGhidraDSPyProgram(client))

    result = completion_client.generate("Summarize this", system_prompt="Be concise")

    assert result == "Auxiliary result"
    assert completion_client.default_model == "test-model"


class PhasePlugin(AnalysisPlugin):
    name = "phase_test"

    def __init__(self, events):
        self.events = events

    def phases(self):
        return (
            PluginPhase("third", PluginHook.AFTER_ANALYSIS, lambda context: self.events.append("third"), after=("second",)),
            PluginPhase("first", PluginHook.AFTER_ANALYSIS, lambda context: self.events.append("first"), before=("second",)),
            PluginPhase("second", PluginHook.AFTER_ANALYSIS, lambda context: self.events.append("second")),
        )


def test_plugin_phase_dependencies_are_topologically_ordered():
    events = []
    manager = PluginManager([PhasePlugin(events)])

    manager.run(PluginHook.AFTER_ANALYSIS, PluginContext(bridge=object()))

    assert events == ["first", "second", "third"]


def test_function_order_and_rag_are_plugin_extensions():
    class Bridge:
        def __init__(self):
            self.indexed = []

        def _add_function_to_rag(self, address, data):
            self.indexed.append((address, data["new_name"]))
            return 1

    bridge = Bridge()
    manager = PluginManager([AddressOrderPlugin(), FunctionRAGPlugin()])
    context = PluginContext(bridge=bridge)

    ordered = manager.order_functions(["last at 00402000", "first at 00401000"], context)
    assert ordered == ["first at 00401000", "last at 00402000"]

    context.function_results = [
        {"address": "00401000", "new_name": "entry"},
        {"function_data": {"address": "00402000", "new_name": "worker"}},
    ]
    manager.run(PluginHook.AFTER_FUNCTION_ANALYSIS, context)

    assert bridge.indexed == [("00401000", "entry"), ("00402000", "worker")]
    assert context.data["function_rag"] == {"indexed": 2, "failures": []}


def test_top_level_dspy_agent_runs_query_lifecycle():
    events = []

    class LifecyclePlugin(AnalysisPlugin):
        name = "lifecycle"

        def phases(self):
            return (
                PluginPhase("start", PluginHook.QUERY_START, lambda context: events.append("start")),
                PluginPhase("end", PluginHook.QUERY_END, lambda context: events.append("end")),
            )

    class Bridge:
        llm_config = SimpleNamespace(agentic_loop_enabled=False)
        _active_plugin_context = None

        def process_query_with_agentic_loop(self, query):
            events.append(query)
            return "answer"

    bridge = Bridge()
    agent = OGhidraAgent(bridge, PluginManager([LifecyclePlugin()]))

    prediction = agent(query="question")

    assert isinstance(prediction, dspy.Prediction)
    assert prediction.answer == "answer"
    assert events == ["start", "question", "end"]
    assert bridge._active_plugin_context is None
