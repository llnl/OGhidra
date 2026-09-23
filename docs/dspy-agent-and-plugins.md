# DSPy agent and plugin development

OGhidra routes model reasoning through `OGhidraDSPyProgram`. The program uses typed DSPy signatures for planning, choosing the next Ghidra action, analyzing evidence, and evaluating whether the goal is complete. `OGhidraAgent` is the top-level DSPy module and retains an explicit bounded Python loop for predictable execution and UI progress reporting.

LangGraph is intentionally not a runtime dependency. OGhidra's flow is a bounded loop with existing Pydantic session state, rather than a durable or distributed graph that needs checkpointed nodes. DSPy modules plus ordinary Python control flow provide optimization and observability without duplicating state management. A future workflow that needs durable pauses, resumable distributed execution, or independently checkpointed branches would be a good reason to revisit LangGraph.

## Built-in signatures

- `PlanAnalysis`: user goal and current guidance to an ordered plan.
- `ChooseExecutionAction`: execution state to typed tool actions, completion state, or a user question.
- `RankToolResults`: typed selection of relevant items from oversized tool results.
- `ConsolidateEvidence`: typed findings, artifacts, gaps, and follow-up actions without JSON prompt parsing.
- `AnalyzeEvidence`: collected evidence to a grounded report or requested artifact.
- `AnalyzeFunction`: decompiled code and caller/callee context to typed analysis, behavior summary, rename, and rationale fields.
- `AnalyzeSoftwareReport`: whole-program evidence to typed classification, security, behavior, architecture, and risk sections.
- `RenderHTMLReport`: analyzed evidence to typed report metadata and section specifications.
- `EvaluateGoal`: evidence to typed `goal_achieved: bool` and `reason: str` outputs.
- `CompletePhase`: auxiliary summarization and other free-form completions that do not need a dedicated signature.

The provider clients still own embeddings, health checks, credentials, and their established retry behavior. `OGhidraClientLM` adapts them to DSPy's typed LM contract, so Ollama, Google, and OpenAI-compatible endpoints continue to use the existing configuration.

## Plugin lifecycle

Plugins inherit `AnalysisPlugin` and can provide ordered `PluginPhase` objects at these hooks:

- `QUERY_START` and `QUERY_END`
- `BEFORE_PLANNING` and `AFTER_PLANNING`
- `BEFORE_EXECUTION` and `AFTER_EXECUTION`
- `BEFORE_ANALYSIS` and `AFTER_ANALYSIS`
- `BEFORE_EVALUATION` and `AFTER_EVALUATION`
- `BEFORE_FUNCTION_ANALYSIS` and `AFTER_FUNCTION_ANALYSIS`

Phases at the same hook are ordered first by `before`/`after` dependencies, then by numeric priority and phase name. Cycles and duplicate phase names fail fast.

```python
from src.agent import AnalysisPlugin, PluginHook, PluginPhase


class FindingsExportPlugin(AnalysisPlugin):
    name = "findings_export"

    def phases(self):
        return (
            PluginPhase(
                name="export_findings",
                hook=PluginHook.AFTER_ANALYSIS,
                handler=self.export,
                after=("normalize_findings",),
            ),
        )

    def export(self, context):
        findings = context.data.get("consolidated_findings", {})
        # Export to the plugin's chosen destination.
```

Pass local plugins when constructing a bridge:

```python
bridge = Bridge(config, plugins=[FindingsExportPlugin()])
```

Installed packages can be discovered without changing OGhidra by publishing an entry point:

```toml
[project.entry-points."oghidra.plugins"]
findings-export = "my_oghidra_plugin:FindingsExportPlugin"
```

Entry-point plugins execute in the OGhidra process and have the same access to binaries and local files as OGhidra, so install only trusted plugin packages.

## Controlling function order

Override `order_functions` to prioritize analysis targets. Plugins compose in plugin priority order, so each plugin receives the order produced by the previous plugin.

```python
from src.agent import AnalysisPlugin


class EntryPointsFirst(AnalysisPlugin):
    name = "entry_points_first"
    priority = 20

    def order_functions(self, functions, context):
        return sorted(functions, key=lambda item: "entry" not in str(item).lower())
```

`AddressOrderPlugin` is included as a small reusable example.

## Adding a whole-program RAG phase

`FunctionRAGPlugin` is registered by default. Bulk analysis passes every completed function result to its `AFTER_FUNCTION_ANALYSIS` phase. The plugin builds the existing hierarchical RAG documents, generates embeddings, updates the vector store, and records this summary in `context.data`:

```python
{
    "function_rag": {
        "indexed": 127,
        "failures": ["00401230: embedding service unavailable"],
    }
}
```

The same pattern can implement a different vector database or add a pre-analysis corpus phase: create a plugin phase at `BEFORE_FUNCTION_ANALYSIS` or `AFTER_FUNCTION_ANALYSIS`, consume `context.functions` or `context.function_results`, and publish artifacts through `context.data`.

## Optimizing the DSPy program

The DSPy predictors are normal module parameters, so optimizers can compile `OGhidraDSPyProgram` against benchmark examples and a project-specific metric. Keep compiled programs and evaluation datasets outside runtime session data. Optimizer integration should use representative binaries and must score both answer quality and safe, valid Ghidra tool selection.
