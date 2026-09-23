"""DSPy signatures and modules used by OGhidra's analysis agent."""

from __future__ import annotations

import re
from typing import Any

import dspy
from pydantic import BaseModel, Field

from .plugins import PluginContext, PluginHook, PluginManager


class PlanAnalysis(dspy.Signature):
    """Create a focused reverse-engineering plan that satisfies the user's goal."""

    guidance: str = dspy.InputField(desc="Available tools, constraints, memory, and current analysis state")
    goal: str = dspy.InputField(desc="The user's reverse-engineering goal")
    plan: str = dspy.OutputField(desc="A concrete ordered investigation plan")


class ToolAction(BaseModel):
    """One validated tool request selected by the execution program."""

    tool: str
    parameters: dict[str, Any] = Field(default_factory=dict)


class ExecutionDecision(BaseModel):
    """Typed execution-loop decision, replacing text directive parsing."""

    reasoning: str = ""
    actions: list[ToolAction] = Field(default_factory=list)
    complete: bool = False
    question: str = ""
    question_options: list[str] = Field(default_factory=list)


class ChooseExecutionAction(dspy.Signature):
    """Choose the next Ghidra actions or declare that the investigation is complete."""

    guidance: str = dspy.InputField(desc="Tool rules and execution policy")
    execution_state: str = dspy.InputField(desc="Goal, plan, prior tool results, and current progress")
    reasoning: str = dspy.OutputField(desc="A concise explanation of why these actions are next")
    actions: list[ToolAction] = dspy.OutputField(desc="Zero or more tool calls; batch related read-only calls")
    complete: bool = dspy.OutputField(desc="True only when no more tool calls are required")
    question: str = dspy.OutputField(desc="A question for the user only when progress requires their choice")
    question_options: list[str] = dspy.OutputField(desc="Optional concise choices for the question")


class AnalyzeEvidence(dspy.Signature):
    """Analyze reverse-engineering evidence and produce the requested artifact or report."""

    guidance: str = dspy.InputField(desc="Analysis requirements and output constraints")
    evidence: str = dspy.InputField(desc="User goal and collected Ghidra evidence")
    analysis: str = dspy.OutputField(desc="Grounded analysis in the requested format")


class FunctionAnalysis(BaseModel):
    """Typed result for per-function analysis and rename suggestions."""

    analysis: str
    behavior_summary: str
    suggested_name: str
    rationale: str

    def as_markdown(self) -> str:
        """Render the result for existing CLI, GUI, and RAG consumers."""
        return (
            f"**Function Analysis:**\n{self.analysis}\n\n"
            f"**Behavior Summary:**\n{self.behavior_summary}\n\n"
            f"**Suggested Name:** {self.suggested_name}\n"
            f"**Rationale:** {self.rationale}"
        )


class AnalyzeFunction(dspy.Signature):
    """Analyze one decompiled function and propose a precise identifier."""

    function_name: str = dspy.InputField(desc="Current function name")
    decompiled_code: str = dspy.InputField(desc="Decompiled target function")
    related_context: str = dspy.InputField(desc="Optional caller and callee evidence")
    analysis: str = dspy.OutputField(desc="Grounded explanation of the function's operations and purpose")
    behavior_summary: str = dspy.OutputField(desc="A precise one-to-four sentence behavioral summary")
    suggested_name: str = dspy.OutputField(desc="A specific valid camelCase function identifier")
    rationale: str = dspy.OutputField(desc="Why the suggested name accurately distinguishes the function")


class EvaluateGoal(dspy.Signature):
    """Decide whether the evidence and analysis completely satisfy the user's goal."""

    guidance: str = dspy.InputField(desc="Evaluation criteria")
    evidence: str = dspy.InputField(desc="Goal, execution summary, and current analysis")
    goal_achieved: bool = dspy.OutputField(desc="True only if the goal is fully satisfied")
    reason: str = dspy.OutputField(desc="A concise explanation of the decision")


class ConsolidateEvidence(dspy.Signature):
    """Extract a compact, typed evidence model from ranked reverse-engineering results."""

    goal: str = dspy.InputField(desc="The investigation goal")
    ranked_evidence: str = dspy.InputField(desc="Tool results ranked by relevance")
    correlations: str = dspy.InputField(desc="Addresses or artifacts corroborated across tool results")
    binary_purpose: str = dspy.OutputField(desc="A brief evidence-based description of the binary")
    security_apis: list[dict[str, str]] = dspy.OutputField(desc="Relevant APIs with address, name, and context")
    investigation_leads: list[dict[str, str]] = dspy.OutputField(
        desc="Leads with address, observation, hypothesis, priority, and next_step"
    )
    artifacts: list[dict[str, str]] = dspy.OutputField(desc="Artifacts with address, type, and value")
    key_functions: list[dict[str, str]] = dspy.OutputField(desc="Functions with address, name, and purpose")
    investigation_gaps: list[str] = dspy.OutputField(desc="Important unanswered questions")
    recommended_next_steps: list[str] = dspy.OutputField(desc="Concrete follow-up actions")


class RankToolResults(dspy.Signature):
    """Select the most goal-relevant items from a large tool result."""

    goal: str = dspy.InputField(desc="The investigation goal")
    tool_name: str = dspy.InputField(desc="The tool that produced the result")
    indexed_preview: str = dspy.InputField(desc="Numbered candidate items")
    max_items: int = dspy.InputField(desc="Maximum number of indices to select")
    selected_indices: list[int] = dspy.OutputField(desc="Zero-based indices of the most relevant candidates")


class AnalyzeSoftwareReport(dspy.Signature):
    """Produce the structured analysis consumed by OGhidra's report renderers."""

    binary_evidence: str = dspy.InputField(desc="Collected program metadata, symbols, strings, and function summaries")
    software_classification: dict[str, Any] = dspy.OutputField(
        desc="Classification with type, purpose, secondary_functions, platform, architecture, complexity, confidence, evidence"
    )
    security_assessment: dict[str, Any] = dspy.OutputField(
        desc="Security assessment with risk_level, risk_score, categories, indicators, recommendations, iocs, and addresses"
    )
    function_categorization: dict[str, Any] = dspy.OutputField(
        desc="Function categories, counts, notable addressed functions, insights, and addresses"
    )
    behavioral_analysis: dict[str, Any] = dspy.OutputField(
        desc="Workflows, data flows, interactions, execution models, dependencies, triggers, fingerprint, and addresses"
    )
    architecture_analysis: dict[str, Any] = dspy.OutputField(
        desc="Pattern, organization, modules, design patterns, memory layout, interfaces, quality, complexity, and addresses"
    )
    risk_assessment: dict[str, Any] = dspy.OutputField(
        desc="Rating, score, risk factors, threat_level, recommendations, monitoring, containment, impact, and addresses"
    )


class HTMLReportSection(BaseModel):
    """One section in the generated HTML report."""

    id: str
    title: str
    icon: str = "📄"
    content_type: str = "html"
    content: Any


class RenderHTMLReport(dspy.Signature):
    """Design a structured HTML vulnerability report from analyzed evidence."""

    report_evidence: str = dspy.InputField(desc="Binary statistics and typed whole-program analysis")
    metadata: dict[str, str] = dspy.OutputField(desc="Report severity and subtitle")
    sections: list[HTMLReportSection] = dspy.OutputField(
        desc="Report sections using html, stats, key_findings, discovery, security_imports, timeline, or table content"
    )


class CompletePhase(dspy.Signature):
    """Complete an auxiliary reverse-engineering task according to its constraints."""

    guidance: str = dspy.InputField(desc="System guidance and output format")
    request: str = dspy.InputField(desc="The task and available evidence")
    response: str = dspy.OutputField(desc="The requested completion")


class OGhidraClientLM(dspy.BaseLM):
    """Typed DSPy adapter around OGhidra's existing provider clients.

    The provider clients remain useful for embeddings, health checks, and their
    existing authentication behavior.  Generation is routed through this
    adapter so every model call is owned by a DSPy module.
    """

    forward_contract = "typed_lm"

    def __init__(self, client: Any, phase: str | None = None):
        self.client = client
        self.phase = phase
        model_map = getattr(client, "model_map", {}) or {}
        default_model = getattr(client, "default_model", None) or getattr(getattr(client, "config", None), "model", "model")
        selected_model = model_map.get(phase) or default_model
        config = getattr(client, "config", None)
        super().__init__(
            model=f"oghidra/{selected_model}",
            temperature=getattr(config, "temperature", None),
            max_tokens=getattr(config, "max_tokens", None),
            cache=False,
            num_retries=0,
        )

    def forward(self, request: dspy.LMRequest) -> dspy.LMResponse:
        system_parts: list[str] = []
        conversation: list[str] = []
        for message in request.messages:
            text = message.text or ""
            if message.role in {"system", "developer"}:
                system_parts.append(text)
            else:
                conversation.append(f"{message.role.upper()}:\n{text}")

        model_map = getattr(self.client, "model_map", {}) or {}
        selected_model = model_map.get(self.phase) or None
        max_tokens = getattr(request.config, "max_tokens", None)
        temperature = getattr(request.config, "temperature", None)
        response = self.client.generate(
            prompt="\n\n".join(conversation),
            model=selected_model,
            system_prompt="\n\n".join(system_parts),
            temperature=temperature,
            max_tokens=max_tokens,
            phase=self.phase,
        )
        return dspy.LMResponse.from_text(str(response or ""), model=request.model)


class OGhidraDSPyProgram(dspy.Module):
    """Reusable DSPy program for all OGhidra reasoning phases."""

    def __init__(self, client: Any):
        super().__init__()
        self.plan_module = dspy.Predict(PlanAnalysis)
        self.execution_module = dspy.Predict(ChooseExecutionAction)
        self.analysis_module = dspy.Predict(AnalyzeEvidence)
        self.function_analysis_module = dspy.Predict(AnalyzeFunction)
        self.evaluation_module = dspy.Predict(EvaluateGoal)
        self.consolidation_module = dspy.Predict(ConsolidateEvidence)
        self.ranking_module = dspy.Predict(RankToolResults)
        self.software_report_module = dspy.Predict(AnalyzeSoftwareReport)
        self.html_report_module = dspy.Predict(RenderHTMLReport)
        self.auxiliary_module = dspy.Predict(CompletePhase)
        self._lms = {phase: OGhidraClientLM(client, phase) for phase in ("planning", "execution", "analysis", "evaluation", "review")}

    def forward(self, task: str, guidance: str = "", phase: str = "analysis"):
        """Run one phase through the standard DSPy ``Module`` interface.

        Runtime code uses the named helpers below, while this entry point makes
        the program directly evaluable and compilable with DSPy optimizers.
        """
        if phase == "planning":
            return dspy.Prediction(output=self.plan(guidance, task))
        if phase == "execution":
            decision = self.decide(guidance, task)
            return dspy.Prediction(output=decision.model_dump_json(), **decision.model_dump())
        if phase == "evaluation":
            achieved, reason = self.evaluate(guidance, task)
            return dspy.Prediction(output=reason, goal_achieved=achieved, reason=reason)
        return dspy.Prediction(output=self.analyze(guidance, task, phase=phase))

    def _context(self, phase: str, max_tokens: int | None = None):
        lm = self._lms.get(phase, self._lms["analysis"])
        if max_tokens is not None:
            lm = lm.copy(max_tokens=max_tokens)
        return dspy.context(lm=lm)

    def plan(self, guidance: str, goal: str) -> str:
        with self._context("planning"):
            return self.plan_module(guidance=guidance, goal=goal).plan

    def decide(self, guidance: str, execution_state: str) -> ExecutionDecision:
        with self._context("execution"):
            prediction = self.execution_module(guidance=guidance, execution_state=execution_state)
        return ExecutionDecision(
            reasoning=prediction.reasoning,
            actions=prediction.actions,
            complete=prediction.complete,
            question=prediction.question,
            question_options=prediction.question_options,
        )

    def analyze(self, guidance: str, evidence: str, phase: str = "analysis", max_tokens: int | None = None) -> str:
        with self._context(phase, max_tokens=max_tokens):
            return self.analysis_module(guidance=guidance, evidence=evidence).analysis

    def evaluate(self, guidance: str, evidence: str) -> tuple[bool, str]:
        with self._context("evaluation"):
            prediction = self.evaluation_module(guidance=guidance, evidence=evidence)
        return bool(prediction.goal_achieved), str(prediction.reason)

    def analyze_function(
        self,
        function_name: str,
        decompiled_code: str,
        related_context: str = "",
    ) -> FunctionAnalysis:
        """Return typed function semantics without format prompts or regex parsing."""
        with self._context("analysis"):
            prediction = self.function_analysis_module(
                function_name=function_name,
                decompiled_code=decompiled_code,
                related_context=related_context,
            )
        candidate = str(prediction.suggested_name).strip().replace("`", "")
        identifier = re.search(r"\b[a-z][a-zA-Z0-9_]*\b", candidate)
        return FunctionAnalysis(
            analysis=str(prediction.analysis),
            behavior_summary=str(prediction.behavior_summary),
            suggested_name=identifier.group(0) if identifier else "",
            rationale=str(prediction.rationale),
        )

    def consolidate(self, goal: str, ranked_evidence: str, correlations: str) -> dict[str, Any]:
        """Return structured findings without a hand-written JSON prompt or parser."""
        with self._context("analysis"):
            prediction = self.consolidation_module(
                goal=goal,
                ranked_evidence=ranked_evidence,
                correlations=correlations,
            )
        return {
            "binary_purpose": prediction.binary_purpose,
            "security_apis": prediction.security_apis,
            "investigation_leads": prediction.investigation_leads,
            "artifacts": prediction.artifacts,
            "key_functions": prediction.key_functions,
            "investigation_gaps": prediction.investigation_gaps,
            "recommended_next_steps": prediction.recommended_next_steps,
        }

    def rank(self, goal: str, tool_name: str, indexed_preview: str, max_items: int) -> list[int]:
        """Select result indices through a typed output instead of parsing JSON text."""
        with self._context("execution"):
            prediction = self.ranking_module(
                goal=goal,
                tool_name=tool_name,
                indexed_preview=indexed_preview,
                max_items=max_items,
            )
        return [int(index) for index in prediction.selected_indices[:max_items]]

    def analyze_software(self, binary_evidence: str) -> dict[str, dict[str, Any]]:
        """Analyze a whole binary in one typed DSPy call."""
        with self._context("analysis"):
            prediction = self.software_report_module(binary_evidence=binary_evidence)
        return {
            "software_classification": prediction.software_classification,
            "security_assessment": prediction.security_assessment,
            "function_categorization": prediction.function_categorization,
            "behavioral_analysis": prediction.behavioral_analysis,
            "architecture_analysis": prediction.architecture_analysis,
            "risk_assessment": prediction.risk_assessment,
        }

    def render_html_report(self, report_evidence: str) -> tuple[dict[str, str], list[HTMLReportSection]]:
        """Return typed report metadata and section specifications."""
        with self._context("analysis"):
            prediction = self.html_report_module(report_evidence=report_evidence)
        return prediction.metadata, prediction.sections

    def complete(
        self,
        request: str,
        guidance: str = "",
        phase: str | None = None,
        max_tokens: int | None = None,
    ) -> str:
        selected_phase = phase or "analysis"
        with self._context(selected_phase, max_tokens=max_tokens):
            return self.auxiliary_module(guidance=guidance, request=request).response


class DSPyCompletionClient:
    """Provider-shaped adapter for non-agent summarization and reporting helpers."""

    def __init__(self, client: Any, program: OGhidraDSPyProgram):
        self.raw_client = client
        self.program = program

    def __getattr__(self, name: str) -> Any:
        return getattr(self.raw_client, name)

    def generate(
        self,
        prompt: str,
        model: str | None = None,
        system_prompt: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
        phase: str | None = None,
    ) -> str:
        del model, temperature  # Model and temperature are selected by the phase LM.
        if phase in {"analysis", "review"}:
            return self.program.analyze(system_prompt or "", prompt, phase=phase, max_tokens=max_tokens)
        return self.program.complete(prompt, system_prompt or "", phase=phase, max_tokens=max_tokens)


class OGhidraAgent(dspy.Module):
    """Top-level DSPy module that owns OGhidra's bounded analysis workflow."""

    def __init__(self, bridge: Any, plugins: PluginManager):
        super().__init__()
        self.bridge = bridge
        self.plugins = plugins

    def forward(self, query: str):
        context = PluginContext(bridge=self.bridge, query=query)
        self.bridge._active_plugin_context = context
        try:
            self.plugins.run(PluginHook.QUERY_START, context)
            answer = self.bridge.process_query_with_agentic_loop(context.query)
            context.response = answer
            self.plugins.run(PluginHook.QUERY_END, context)
            return dspy.Prediction(answer=context.response, plugin_data=dict(context.data))
        finally:
            self.bridge._active_plugin_context = None
