"""
Pydantic models for memory and session management.

This module provides structured, type-safe models for managing:
- Conversation history
- Tool execution results
- Analysis state
- CAG context
- Prompt sections

Using Pydantic ensures data validation, clear structure, and easier maintenance.
"""

from typing import List, Dict, Optional, Literal, Any, Set
from pydantic import BaseModel, Field, PrivateAttr, validator
from datetime import datetime
from enum import Enum
import threading


class MessageRole(str, Enum):
    """Enum for message roles in conversation history."""
    USER = "user"
    ASSISTANT = "assistant"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    PLAN = "plan"
    SUMMARY = "summary"
    EVALUATION = "evaluation"
    SYSTEM = "system"


class ConversationMessage(BaseModel):
    """A single message in the conversation history."""
    role: MessageRole
    content: str
    timestamp: Optional[datetime] = Field(default_factory=datetime.now)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    class Config:
        # Don't use use_enum_values - keep as enum for type safety
        arbitrary_types_allowed = True
    
    def format_for_prompt(self) -> str:
        """Format this message for inclusion in a prompt."""
        role_labels = {
            MessageRole.USER: "User",
            MessageRole.ASSISTANT: "Assistant",
            MessageRole.TOOL_CALL: "Tool Call",
            MessageRole.TOOL_RESULT: "Tool Result",
            MessageRole.PLAN: "Plan",
            MessageRole.SUMMARY: "Summary",
            MessageRole.EVALUATION: "Evaluation",
            MessageRole.SYSTEM: "System"
        }
        
        # Handle both MessageRole enum and string values
        if isinstance(self.role, MessageRole):
            label = role_labels.get(self.role, self.role.value.capitalize())
        else:
            # If role is a string, capitalize it
            label = str(self.role).capitalize()
        
        return f"**{label}**: {self.content}"


class ToolExecution(BaseModel):
    """Record of a tool execution."""
    tool_name: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    result: Optional[str] = None
    success: bool = True
    error: Optional[str] = None
    reasoning: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.now)
    
    def format_for_prompt(self) -> str:
        """Format this tool execution for inclusion in a prompt."""
        param_str = ", ".join([f'{k}="{v}"' for k, v in self.parameters.items()])
        lines = []
        if self.reasoning:
            lines.append(f"Reasoning: {self.reasoning}")
        lines.append(f"Command: {self.tool_name}({param_str})")
        if self.result:
            lines.append(f"Result: {self.result}")
        return "\n".join(lines)


class AnalysisState(BaseModel):
    """Current state of the analysis session."""
    functions_decompiled: Set[str] = Field(default_factory=set)
    functions_renamed: Dict[str, str] = Field(default_factory=dict)  # old_name -> new_name
    functions_analyzed: Set[str] = Field(default_factory=set)
    comments_added: Dict[str, str] = Field(default_factory=dict)  # address -> comment
    cached_results: Dict[str, Any] = Field(default_factory=dict)
    pattern_detections: Dict[str, List[str]] = Field(default_factory=dict)  # address -> pattern names (HIGH severity)
    
    class Config:
        # Allow sets in Pydantic model
        arbitrary_types_allowed = True
    
    def format_for_prompt(self) -> Optional[str]:
        """Format analysis state for inclusion in a prompt."""
        if not any([self.functions_decompiled, self.functions_renamed, 
                   self.functions_analyzed, self.comments_added, self.cached_results]):
            return None
        
        lines = ["## Current Analysis State"]
        if self.functions_decompiled:
            lines.append(f"- Already decompiled: {', '.join(sorted(self.functions_decompiled))}")
        if self.functions_renamed:
            renamed = [f"{old} -> {new}" for old, new in self.functions_renamed.items()]
            lines.append(f"- Already renamed: {', '.join(renamed)}")
        if self.comments_added:
            lines.append(f"- Comments added to: {', '.join(sorted(self.comments_added.keys()))}")
        if self.functions_analyzed:
            lines.append(f"- Already analyzed: {', '.join(sorted(self.functions_analyzed))}")
        if self.cached_results:
            lines.append(f"- Cached results available for {len(self.cached_results)} commands")
        
        return "\n".join(lines)


class CAGContext(BaseModel):
    """Context-Aware Generation context."""
    workplans: List[str] = Field(default_factory=list)
    relevant_memories: List[str] = Field(default_factory=list)
    phase_guidance: Optional[str] = None
    
    def format_for_prompt(self) -> Optional[str]:
        """Format CAG context for inclusion in a prompt."""
        if not any([self.workplans, self.relevant_memories, self.phase_guidance]):
            return None
        
        sections = []
        
        if self.workplans:
            sections.append("## Relevant Workplans\n" + "\n\n".join(self.workplans))
        
        if self.relevant_memories:
            sections.append("## Relevant Past Experience\n" + "\n\n".join(self.relevant_memories))
        
        if self.phase_guidance:
            sections.append(f"## Phase Guidance\n{self.phase_guidance}")
        
        return "\n\n".join(sections) if sections else None


class PromptSection(BaseModel):
    """A section of the prompt with ordering."""
    name: str
    content: str
    order: int  # Lower numbers appear first
    required: bool = True  # If False, can be omitted if empty
    
    class Config:
        frozen = True  # Make immutable for consistent ordering


class StructuredPrompt(BaseModel):
    """
    A structured prompt with clear separation of concerns.
    
    Sections are ordered as:
    1. Current Goal (what user wants NOW)
    2. Analysis State (what we've done)
    3. Current Plan (what we're executing)
    4. CAG Context (relevant guidance and workplans)
    5. Tool Results (recent execution results)
    6. Conversation History (past interactions) ← ALWAYS LAST
    """
    goal: Optional[str] = None
    analysis_state: Optional[AnalysisState] = None
    current_plan: Optional[str] = None
    cag_context: Optional[CAGContext] = None
    tool_results: List[ToolExecution] = Field(default_factory=list)
    conversation_history: List[ConversationMessage] = Field(default_factory=list)
    phase_specific_instructions: Optional[str] = None
    
    def build_user_prompt(self, max_history_items: int = 10) -> str:
        """
        Build the user prompt with proper section ordering.
        
        CRITICAL: Conversation history is ALWAYS at the end to prevent confusion.
        """
        sections = []
        
        # Section 1: Current Goal (HIGHEST PRIORITY - what user wants NOW)
        if self.goal:
            sections.append(f"## Your Current Goal\n{self.goal}")
        
        # Section 2: Analysis State (what we've done so far)
        if self.analysis_state:
            state_str = self.analysis_state.format_for_prompt()
            if state_str:
                sections.append(state_str)
        
        # Section 3: Current Plan (what we're executing)
        if self.current_plan:
            sections.append(f"## Current Plan\n{self.current_plan}")
        
        # Section 4: CAG Context (relevant guidance - NOT conversation history)
        if self.cag_context:
            cag_str = self.cag_context.format_for_prompt()
            if cag_str:
                sections.append(cag_str)
        
        # Section 5: Recent Tool Results (execution context)
        if self.tool_results:
            results_section = ["## Recent Tool Executions"]
            for tool_exec in self.tool_results[-5:]:  # Last 5 tool executions
                results_section.append(tool_exec.format_for_prompt())
            sections.append("\n\n".join(results_section))
        
        # Section 6: Phase-specific instructions (if any)
        if self.phase_specific_instructions:
            sections.append(self.phase_specific_instructions)
        
        # Section 7: Conversation History (ALWAYS LAST - prevents confusion)
        # NOTE: Skip if only 1-2 items and goal is already stated (reduces duplication)
        if self.conversation_history and len(self.conversation_history) > 2:
            history_section = ["## Conversation History (For Context Only)"]
            history_section.append("The following is prior conversation context. Your CURRENT goal is stated above.")
            history_section.append("")
            
            # Limit history to prevent token overflow and filter out goal duplicates
            recent_history = self.conversation_history[-max_history_items:]
            goal_lower = self.goal.lower() if self.goal else ""
            
            for msg in recent_history:
                # Skip messages that are just the goal repeated
                if goal_lower and msg.content.lower().strip() == goal_lower.strip():
                    continue
                history_section.append(msg.format_for_prompt())
            
            # Only add if we have meaningful history beyond goal
            if len(history_section) > 3:
                sections.append("\n".join(history_section))
        
        return "\n\n".join(sections)

    def build_lean_user_prompt(self, max_history_items: int = 5) -> str:
        """
        Build a lean user prompt containing ONLY:
        1. The user's goal (what they want)
        2. Recent tool results (what the model is responding to)
        3. Minimal conversation history (if meaningful)

        All instructions, orchestration state, knowledge, and context
        belong in the system prompt via SystemContextBuilder.
        """
        sections = []

        # Section 1: Current Goal (the ONLY instructional content in user prompt)
        if self.goal:
            sections.append(f"## Your Current Goal\n{self.goal}")

        # Section 2: Recent Tool Results (immediate execution context)
        if self.tool_results:
            results_section = ["## Recent Tool Executions"]
            for tool_exec in self.tool_results[-5:]:
                results_section.append(tool_exec.format_for_prompt())
            sections.append("\n\n".join(results_section))

        # Section 3: Minimal Conversation History (LAST, only if meaningful)
        if self.conversation_history and len(self.conversation_history) > 2:
            history_section = ["## Conversation History (For Context Only)"]
            history_section.append("Your CURRENT goal is stated above.")
            history_section.append("")

            recent_history = self.conversation_history[-max_history_items:]
            goal_lower = self.goal.lower() if self.goal else ""

            for msg in recent_history:
                if goal_lower and msg.content.lower().strip() == goal_lower.strip():
                    continue
                history_section.append(msg.format_for_prompt())

            if len(history_section) > 3:
                sections.append("\n".join(history_section))

        return "\n\n".join(sections)

    @validator('conversation_history')
    def validate_history_not_too_long(cls, v):
        """Warn if conversation history is getting very long."""
        if len(v) > 100:
            # Could log a warning here
            pass
        return v


class SystemContextBuilder(BaseModel):
    """
    Builds the dynamic context portion of the system prompt.

    All orchestration state, knowledge, and instructions go here --
    NOT in the user prompt. The user prompt should be lean
    (goal + immediate execution results only).

    Future-proofing: This builder is reusable for sub-agent architectures.
    Different agent types can select which sections to include via the
    include_sections parameter.
    """
    # Dynamic state
    analysis_state: Optional[AnalysisState] = None
    current_plan: Optional[str] = None
    cag_context: Optional[CAGContext] = None
    phase_specific_instructions: Optional[str] = None

    # Knowledge and preferences
    knowledge_summary: Optional[str] = None
    scope_card: Optional[str] = None
    user_preferences: Optional[str] = None

    # Execution tracking
    completed_steps_summary: Optional[str] = None
    coverage_section: Optional[str] = None
    leads_section: Optional[str] = None

    # Search context
    function_context: Optional[str] = None

    # Blackboard context (for orchestrator/sub-agent architecture)
    function_registry_summary: Optional[str] = None
    notebook_summary: Optional[str] = None
    discovery_summary: Optional[str] = None
    tool_health_summary: Optional[str] = None

    def build_dynamic_context(self, include_sections: Optional[List[str]] = None) -> str:
        """
        Build the dynamic context string for injection into the system prompt.

        Args:
            include_sections: Optional list of section names to include.
                            If None, all non-empty sections are included.
                            Valid names: 'analysis_state', 'plan', 'cag',
                            'knowledge', 'scope', 'preferences', 'completed_steps',
                            'coverage', 'leads', 'function_context', 'phase_instructions',
                            'function_registry', 'notebook'

        Returns:
            Formatted string of dynamic context sections, or empty string.
        """
        # Ordered list of (section_name, header, content_getter)
        section_defs = [
            ("scope", None, lambda: self.scope_card),
            ("preferences", None, lambda: self.user_preferences),
            ("knowledge", None, lambda: self.knowledge_summary),
            ("function_context", None, lambda: self.function_context),
            ("function_registry", None, lambda: self.function_registry_summary),
            ("notebook", None, lambda: self.notebook_summary),
            ("discovery", None, lambda: self.discovery_summary),
            ("tool_health", None, lambda: self.tool_health_summary),
            ("analysis_state", None, lambda: self.analysis_state.format_for_prompt() if self.analysis_state else None),
            ("plan", "## Current Plan", lambda: self.current_plan),
            ("cag", None, lambda: self.cag_context.format_for_prompt() if self.cag_context else None),
            ("coverage", None, lambda: self.coverage_section),
            ("leads", None, lambda: self.leads_section),
            ("completed_steps", None, lambda: self.completed_steps_summary),
            ("phase_instructions", None, lambda: self.phase_specific_instructions),
        ]

        sections = []
        for name, header, getter in section_defs:
            if include_sections and name not in include_sections:
                continue
            content = getter()
            if content:
                if header:
                    sections.append(f"{header}\n{content}")
                else:
                    sections.append(content)

        if not sections:
            return ""

        return "\n--- DYNAMIC CONTEXT ---\n\n" + "\n\n".join(sections)


# ============================================================================
# BLACKBOARD MODELS — Shared state for orchestrator/sub-agent architecture
# ============================================================================

class FunctionAnalysis(BaseModel):
    """
    Rich structured analysis of a single function, stored on the shared blackboard.

    When a worker decompiles and analyzes a function, the results are stored here
    so future workers can see what was found without re-decompiling.
    """
    address: str                                        # "0x00405b60"
    name: str                                           # Current name (may have been renamed)
    original_name: str = ""                             # Original Ghidra auto-name (e.g., FUN_00405b60)
    purpose: str = ""                                   # 1-2 sentence summary of what the function does
    decompiled: bool = False                            # Whether decompilation was performed
    calls: List[str] = Field(default_factory=list)      # Addresses of functions this calls
    called_by: List[str] = Field(default_factory=list)  # Addresses of functions that call this
    imports_used: List[str] = Field(default_factory=list)  # Windows APIs called (CreateProcessW, etc.)
    security_notes: List[str] = Field(default_factory=list)  # Security-relevant observations
    behavioral_tags: List[str] = Field(default_factory=list)  # ["file_io", "registry", "network", "crypto"]
    iocs_found: List[str] = Field(default_factory=list)  # IOCs extracted (IPs, URLs, paths)
    confidence: str = "low"                             # "low", "medium", "high"
    decompile_count: int = 1                            # How many times decompiled across workers
    analyzed_by_task: Optional[str] = None              # Which worker task analyzed this
    timestamp: datetime = Field(default_factory=datetime.now)

    def format_for_prompt(self) -> str:
        """Compact one-line summary for prompt injection."""
        security = f" | SECURITY: {', '.join(self.security_notes[:2])}" if self.security_notes else ""
        tags = f" [{', '.join(self.behavioral_tags)}]" if self.behavioral_tags else ""
        skip = f" (decompiled {self.decompile_count}x \u2014 SKIP)" if self.decompile_count > 2 else ""
        return f"- {self.name} ({self.address}): {self.purpose}{tags}{security}{skip}"


class FunctionRegistry(BaseModel):
    """
    Registry of all analyzed functions — shared across all workers via the blackboard.

    Workers read this to see what functions are already known and what was found.
    The orchestrator and ToolExecutor write to this after analysis.

    Thread-safe: all mutations and reads are protected by an RLock.
    """
    functions: Dict[str, FunctionAnalysis] = Field(default_factory=dict)  # address → analysis
    _lock: threading.RLock = PrivateAttr(default_factory=threading.RLock)

    def register(self, analysis: FunctionAnalysis):
        """Register or merge a function analysis (thread-safe).

        If the function already exists:
        - Increment decompile_count
        - Keep the RICHER purpose (longer, non-auto-registered)
        - Merge list fields (imports_used, security_notes, etc.) with dedup
        - Upgrade confidence only if new analysis is higher
        - Preserve earlier timestamp and original_name
        """
        with self._lock:
            existing = self.functions.get(analysis.address)
            if existing is None:
                self.functions[analysis.address] = analysis
                return

            # Increment decompile count
            existing.decompile_count += 1

            # Keep richer purpose (prefer longer, non-auto-registered)
            auto_tag = "auto-registered"
            if (
                auto_tag in existing.purpose
                and auto_tag not in analysis.purpose
                and analysis.purpose
            ):
                existing.purpose = analysis.purpose
            elif (
                len(analysis.purpose) > len(existing.purpose)
                and auto_tag not in analysis.purpose
            ):
                existing.purpose = analysis.purpose

            # Merge list fields (deduplicated, order-preserving)
            for field_name in (
                "imports_used", "security_notes", "behavioral_tags",
                "iocs_found", "calls", "called_by",
            ):
                existing_list = getattr(existing, field_name)
                new_list = getattr(analysis, field_name)
                merged = list(dict.fromkeys(existing_list + new_list))
                setattr(existing, field_name, merged)

            # Upgrade confidence only if new is higher
            confidence_order = {"low": 0, "medium": 1, "high": 2}
            if confidence_order.get(analysis.confidence, 0) > confidence_order.get(
                existing.confidence, 0
            ):
                existing.confidence = analysis.confidence

            # Preserve original name if not yet set
            if analysis.original_name and not existing.original_name:
                existing.original_name = analysis.original_name

            # Update name if new one is more meaningful
            if (
                analysis.name
                and not analysis.name.startswith("FUN_")
                and existing.name.startswith("FUN_")
            ):
                existing.name = analysis.name

    def get(self, address: str) -> Optional[FunctionAnalysis]:
        """Get analysis for a specific function address."""
        with self._lock:
            return self.functions.get(address)

    def get_by_name(self, name: str) -> Optional[FunctionAnalysis]:
        """Find function analysis by name (current or original)."""
        with self._lock:
            for func in self.functions.values():
                if func.name == name or func.original_name == name:
                    return func
            return None

    def get_by_tag(self, tag: str) -> List[FunctionAnalysis]:
        """Get all functions with a specific behavioral tag."""
        with self._lock:
            return [f for f in self.functions.values() if tag in f.behavioral_tags]

    def get_with_security_notes(self) -> List[FunctionAnalysis]:
        """Get all functions that have security-relevant observations."""
        with self._lock:
            return [f for f in self.functions.values() if f.security_notes]

    def get_unanalyzed_callers(self, address: str) -> List[str]:
        """Find functions that call this address but haven't been analyzed yet."""
        with self._lock:
            func = self.functions.get(address)
            if not func:
                return []
            return [addr for addr in func.called_by if addr not in self.functions]

    def is_analyzed(self, address: str) -> bool:
        """Check if a function has been analyzed (not just decompiled)."""
        with self._lock:
            func = self.functions.get(address)
            return func is not None and bool(func.purpose)

    @property
    def count(self) -> int:
        with self._lock:
            return len(self.functions)

    @property
    def analyzed_count(self) -> int:
        with self._lock:
            return sum(1 for f in self.functions.values() if f.purpose)

    def format_for_prompt(self, max_entries: int = 20) -> str:
        """Format registry as context for injection into prompts."""
        with self._lock:
            if not self.functions:
                return ""
            lines = ["## Known Functions (from previous analysis)"]
            # Show security-relevant functions first, then by recency
            sorted_funcs = sorted(
                self.functions.values(),
                key=lambda f: (bool(f.security_notes), f.timestamp),
                reverse=True
            )
            for func in sorted_funcs[:max_entries]:
                lines.append(func.format_for_prompt())
            if len(self.functions) > max_entries:
                lines.append(f"  ... and {len(self.functions) - max_entries} more analyzed functions")
            lines.append(f"\nTotal: {self.count} functions registered, {self.analyzed_count} fully analyzed")
            return "\n".join(lines)

    def format_for_orchestrator(self, max_entries: int = 30) -> str:
        """Format registry for the orchestrator's task-creation prompt.

        Groups functions by analysis depth and flags over-decompiled functions.
        This view helps the orchestrator assign work on UNANALYZED functions
        and avoid re-decompiling functions that have been examined many times.
        """
        with self._lock:
            if not self.functions:
                return ""

            analyzed = []
            shallow = []  # registered but no meaningful purpose
            over_decompiled = []

            for func in self.functions.values():
                if func.decompile_count > 2:
                    over_decompiled.append(func)
                elif func.purpose and "auto-registered" not in func.purpose:
                    analyzed.append(func)
                else:
                    shallow.append(func)

            lines = [
                f"## Function Registry "
                f"({len(self.functions)} registered, {self.analyzed_count} analyzed)"
            ]

            if over_decompiled:
                lines.append("\n### OVER-ANALYZED (DO NOT re-decompile):")
                for f in over_decompiled[:10]:
                    lines.append(
                        f"- {f.name} ({f.address}) \u2014 decompiled "
                        f"{f.decompile_count}x. {f.purpose[:60]}"
                    )

            if analyzed:
                lines.append(f"\n### Fully Analyzed ({len(analyzed)}):")
                sorted_analyzed = sorted(
                    analyzed,
                    key=lambda x: bool(x.security_notes),
                    reverse=True,
                )
                for f in sorted_analyzed[:max_entries]:
                    sec = (
                        f" \u26a0 {', '.join(f.security_notes[:2])}"
                        if f.security_notes
                        else ""
                    )
                    lines.append(
                        f"- {f.name} ({f.address}): {f.purpose[:80]}{sec}"
                    )

            if shallow:
                lines.append(
                    f"\n### Seen But Not Analyzed "
                    f"({len(shallow)} \u2014 consider investigating):"
                )
                for f in shallow[:10]:
                    lines.append(f"- {f.name} ({f.address})")

            return "\n".join(lines)


class NotebookEntry(BaseModel):
    """
    Single finding in the investigation notebook.

    The notebook is updated incrementally by the orchestrator after each worker completes.
    Entries are categorized and severity-rated for continuous synthesis.
    """
    category: str              # "vulnerability", "behavior", "ioc", "architecture", "threat"
    severity: str              # "critical", "high", "medium", "low", "info"
    title: str                 # "Unquoted service path in CreateProcessW call"
    detail: str = ""           # Full description of the finding
    evidence: List[str] = Field(default_factory=list)    # Supporting evidence strings
    addresses: List[str] = Field(default_factory=list)   # Related function addresses
    status: str = "suspected"  # "confirmed", "suspected", "needs_investigation", "dismissed"
    timestamp: datetime = Field(default_factory=datetime.now)

    def format_for_prompt(self) -> str:
        """Format entry for prompt injection."""
        icon = {"critical": "!!!", "high": "!!", "medium": "!", "low": "~", "info": "-"}.get(self.severity, "-")
        evidence_str = f" | Evidence: {'; '.join(self.evidence[:2])}" if self.evidence else ""
        return f"  {icon} [{self.severity.upper()}] {self.title} ({self.status}){evidence_str}"

    def format_for_report(self) -> str:
        """Format entry for the final user-facing report."""
        lines = [f"### [{self.severity.upper()}] {self.title}"]
        lines.append(f"**Status**: {self.status}")
        if self.detail:
            lines.append(f"\n{self.detail}")
        if self.evidence:
            lines.append("\n**Evidence:**")
            for ev in self.evidence:
                lines.append(f"- {ev}")
        if self.addresses:
            lines.append(f"\n**Affected functions:** {', '.join(self.addresses)}")
        return "\n".join(lines)


class InvestigationNotebook(BaseModel):
    """
    Running synthesis document maintained by the orchestrator.

    Updated incrementally after each worker completes. The final report is generated
    by formatting the accumulated entries — no separate synthesis step needed.

    Thread-safe: mutations are protected by an RLock.
    """
    binary_name: str = ""
    binary_purpose: str = ""
    investigation_strategy: str = ""   # "binary_understanding", "malware_hunting", "vuln_hunting"
    entries: List[NotebookEntry] = Field(default_factory=list)
    tasks_completed: List[str] = Field(default_factory=list)  # Log of completed worker tasks
    _lock: threading.RLock = PrivateAttr(default_factory=threading.RLock)

    def add_finding(self, entry: NotebookEntry):
        """Add a new finding to the notebook (thread-safe)."""
        with self._lock:
            self.entries.append(entry)

    def add_task_completed(self, task_description: str):
        """Record that a worker task was completed."""
        self.tasks_completed.append(task_description)

    def get_by_category(self, category: str) -> List[NotebookEntry]:
        """Get all entries for a specific category."""
        return [e for e in self.entries if e.category == category]

    def get_high_severity(self) -> List[NotebookEntry]:
        """Get all critical and high severity findings."""
        return [e for e in self.entries if e.severity in ("critical", "high")]

    def get_needing_investigation(self) -> List[NotebookEntry]:
        """Get entries that still need investigation."""
        return [e for e in self.entries if e.status == "needs_investigation"]

    @property
    def finding_count(self) -> int:
        return len(self.entries)

    @property
    def confirmed_count(self) -> int:
        return sum(1 for e in self.entries if e.status == "confirmed")

    def format_for_prompt(self, max_entries: int = 15) -> str:
        """Format notebook as context for orchestrator decision-making."""
        if not self.entries:
            return "## Investigation Notebook\nNo findings yet."
        lines = [f"## Investigation Notebook ({self.investigation_strategy})"]
        if self.binary_purpose:
            lines.append(f"Binary: {self.binary_name} -- {self.binary_purpose}")
        lines.append(f"Findings: {self.finding_count} total, {self.confirmed_count} confirmed")
        lines.append("")

        # Group by category
        categories = {}
        for entry in self.entries:
            categories.setdefault(entry.category, []).append(entry)

        entries_shown = 0
        for cat, cat_entries in categories.items():
            if entries_shown >= max_entries:
                break
            lines.append(f"**{cat.upper()}:**")
            for entry in cat_entries:
                if entries_shown >= max_entries:
                    break
                lines.append(entry.format_for_prompt())
                entries_shown += 1

        if self.finding_count > max_entries:
            lines.append(f"\n  ... and {self.finding_count - max_entries} more findings")

        if self.tasks_completed:
            lines.append(f"\nTasks completed: {len(self.tasks_completed)}")

        return "\n".join(lines)

    def format_as_report(self) -> str:
        """
        Format the complete notebook as the final user-facing report.

        Groups findings by category, sorts by severity within each category,
        and includes full evidence for confirmed findings.
        """
        lines = []
        if self.binary_name:
            lines.append(f"# Analysis Report: {self.binary_name}")
        else:
            lines.append("# Analysis Report")
        if self.binary_purpose:
            lines.append(f"\n**Binary Purpose:** {self.binary_purpose}")
        lines.append(f"**Strategy:** {self.investigation_strategy}")
        lines.append(f"**Total Findings:** {self.finding_count} ({self.confirmed_count} confirmed)")
        lines.append("")

        if not self.entries:
            lines.append("No significant findings were identified during this investigation.")
            return "\n".join(lines)

        # Group by category and sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        categories = {}
        for entry in self.entries:
            categories.setdefault(entry.category, []).append(entry)

        for cat, cat_entries in categories.items():
            lines.append(f"\n---\n## {cat.replace('_', ' ').title()}")
            sorted_entries = sorted(cat_entries, key=lambda e: severity_order.get(e.severity, 5))
            for entry in sorted_entries:
                lines.append(f"\n{entry.format_for_report()}")

        if self.tasks_completed:
            lines.append(f"\n---\n## Investigation Summary")
            lines.append(f"**Tasks executed:** {len(self.tasks_completed)}")
            for i, task in enumerate(self.tasks_completed, 1):
                lines.append(f"{i}. {task}")

        return "\n".join(lines)


class DiscoveryCache:
    """
    Stores raw discovery results (imports, exports, strings, functions) for reuse.

    When a worker calls ``list_imports``, ``list_exports``, ``list_strings``,
    or ``list_functions``, the results are cached here so subsequent workers
    can access them via the ``"discovery"`` include_section instead of
    re-calling the same tools.

    Thread-safe: all mutations and reads are protected by an RLock.
    """

    def __init__(self):
        self.imports: List[str] = []
        self.exports: List[str] = []
        self.strings: Dict[str, List[str]] = {}  # filter_key → result entries
        self.functions_list: List[str] = []
        self.total_functions: int = 0
        self._lock = threading.RLock()

    # ── Store methods (thread-safe, deduplicated) ──────────────────

    def store_imports(self, entries: List[str]) -> None:
        """Append import entries, deduplicating against existing."""
        with self._lock:
            existing = set(self.imports)
            for entry in entries:
                if entry not in existing:
                    self.imports.append(entry)
                    existing.add(entry)

    def store_exports(self, entries: List[str]) -> None:
        """Append export entries, deduplicating against existing."""
        with self._lock:
            existing = set(self.exports)
            for entry in entries:
                if entry not in existing:
                    self.exports.append(entry)
                    existing.add(entry)

    def store_strings(self, filter_key: str, entries: List[str]) -> None:
        """Store string search results keyed by the search filter used."""
        with self._lock:
            if filter_key not in self.strings:
                self.strings[filter_key] = []
            existing = set(self.strings[filter_key])
            for entry in entries:
                if entry not in existing:
                    self.strings[filter_key].append(entry)
                    existing.add(entry)

    def store_functions(self, entries: List[str], total: int = 0) -> None:
        """Store function listing results."""
        with self._lock:
            existing = set(self.functions_list)
            for entry in entries:
                if entry not in existing:
                    self.functions_list.append(entry)
                    existing.add(entry)
            if total > 0:
                self.total_functions = max(self.total_functions, total)

    # ── Read methods ───────────────────────────────────────────────

    def has_imports(self) -> bool:
        with self._lock:
            return len(self.imports) > 0

    def has_exports(self) -> bool:
        with self._lock:
            return len(self.exports) > 0

    def has_strings(self, filter_key: Optional[str] = None) -> bool:
        with self._lock:
            if filter_key:
                return bool(self.strings.get(filter_key))
            return len(self.strings) > 0

    def has_functions(self) -> bool:
        with self._lock:
            return len(self.functions_list) > 0

    def is_empty(self) -> bool:
        with self._lock:
            return (
                not self.imports
                and not self.exports
                and not self.strings
                and not self.functions_list
            )

    # ── Prompt formatting ──────────────────────────────────────────

    def format_for_prompt(
        self, max_imports: int = 40, max_strings: int = 20
    ) -> str:
        """Format cached discovery data for injection into worker system prompts.

        Returns empty string if cache is empty.

        The output explicitly tells the worker not to re-call these tools,
        eliminating the redundant ``list_imports`` calls that wasted 21% of
        tool budget in the Easy Chat Server investigation.
        """
        with self._lock:
            if self.is_empty():
                return ""

            lines = [
                "## Binary Discovery (cached — do NOT re-call these tools)"
            ]

            # Imports
            if self.imports:
                lines.append(f"### Imports ({len(self.imports)} total)")
                shown = self.imports[:max_imports]
                lines.append(", ".join(shown))
                if len(self.imports) > max_imports:
                    lines.append(
                        f"  ... and {len(self.imports) - max_imports} more imports"
                    )

            # Exports
            if self.exports:
                lines.append(f"### Exports ({len(self.exports)} total)")
                lines.append(", ".join(self.exports[:20]))
                if len(self.exports) > 20:
                    lines.append(
                        f"  ... and {len(self.exports) - 20} more exports"
                    )

            # Strings (grouped by filter)
            if self.strings:
                lines.append("### Strings")
                for filt, entries in self.strings.items():
                    shown = entries[:max_strings]
                    lines.append(
                        f'Filter "{filt}": {shown}'
                    )
                    if len(entries) > max_strings:
                        lines.append(
                            f"  ... and {len(entries) - max_strings} more"
                        )

            # Functions
            if self.functions_list:
                total_label = (
                    f" of {self.total_functions}"
                    if self.total_functions > 0
                    else ""
                )
                lines.append(
                    f"### Functions ({len(self.functions_list)}{total_label} listed)"
                )
                lines.append(", ".join(self.functions_list[:30]))
                if len(self.functions_list) > 30:
                    lines.append(
                        f"  ... and {len(self.functions_list) - 30} more"
                    )

            return "\n".join(lines)


class ExecutionPhaseResults(BaseModel):
    """
    Accumulated results from the execution phase.

    This is separate from conversation history and provides
    a clean view of all tool executions for the analysis phase.
    """
    goal: str
    plan: Optional[str] = None
    tool_executions: List[ToolExecution] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    investigation_complete: bool = False
    total_steps: int = 0
    gates_triggered: List["ExecutionGate"] = Field(default_factory=list)
    pending_question: Optional[Any] = None  # UserQuestion from user_question.py
    analysis_dump: Optional[str] = None
    compaction_summary: Optional[str] = None  # LLM-generated context summary
    
    def add_execution(self, tool_exec: ToolExecution):
        """Add a tool execution result."""
        self.tool_executions.append(tool_exec)
        self.total_steps += 1
    
    def format_for_analysis(self, context_manager=None) -> str:
        """
        Format all execution results for the analysis phase.
        
        Args:
            context_manager: Optional ContextManager for intelligent formatting.
                           If provided, uses tiered context and summarization.
                           If not provided, uses simple truncation.
        """
        sections = [
            f"## Investigation Goal\n{self.goal}",
            f"\n## Execution Plan\n{self.plan}" if self.plan else "",
            f"\n## Execution Results ({self.total_steps} steps)\n"
        ]
        
        total = len(self.tool_executions)
        
        for i, exec_result in enumerate(self.tool_executions, 1):
            sections.append(f"\n### Step {i}: {exec_result.tool_name}")
            sections.append(f"Parameters: {exec_result.parameters}")
            
            result_text = str(exec_result.result) if exec_result.result else "No result"
            
            if context_manager:
                # Use context manager for intelligent formatting
                display_content, cached = context_manager.process_result(
                    tool_name=exec_result.tool_name,
                    parameters=exec_result.parameters,
                    result=result_text,
                    goal=self.goal
                )
                sections.append(f"Result:\n{display_content}\n")
            else:
                # Fallback: simple truncation for very long results
                # Increased from 2000 to 8000 to preserve more context
                if len(result_text) > 8000:
                    result_text = result_text[:8000] + f"\n... [Truncated {len(result_text) - 8000} chars]"
                sections.append(f"Result:\n{result_text}\n")
        
        return "\n".join(sections)
    
    def get_summary(self) -> str:
        """Get a summary of execution results."""
        tool_counts = {}
        for exec_result in self.tool_executions:
            tool_counts[exec_result.tool_name] = tool_counts.get(exec_result.tool_name, 0) + 1

        summary_lines = [
            f"Total steps executed: {self.total_steps}",
            f"Tools used: {', '.join([f'{tool}({count}x)' for tool, count in tool_counts.items()])}"
        ]
        return "\n".join(summary_lines)


class KnowledgeArtifact(BaseModel):
    """A saved knowledge artifact ("sticky note") for the session."""
    key: str
    value: str
    category: str = "general"
    tags: List[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=datetime.now)

    def format_for_prompt(self) -> str:
        """Format artifact for prompt injection."""
        return f"- [{self.category}] {self.key}: {self.value}"


class RankedResult(BaseModel):
    """A tool execution result with relevance scoring for hybrid context management."""
    tool_name: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    result: str
    relevance_score: float = 0.0
    category: str = "other"  # 'decompilation', 'strings', 'imports', 'xrefs', etc.
    timestamp: datetime = Field(default_factory=datetime.now)
    
    def format_for_prompt(self, max_chars: int = 2000) -> str:
        """Format for prompt with optional truncation."""
        result_text = self.result
        if len(result_text) > max_chars:
            result_text = result_text[:max_chars] + f"\n... [Truncated {len(self.result) - max_chars} chars]"
        return f"### {self.tool_name} (score: {self.relevance_score:.2f})\n{result_text}"


class CorrelationHint(BaseModel):
    """Cross-tool correlation hint based on shared addresses or patterns."""
    address: str
    mentions: List[str] = Field(default_factory=list)  # ["strings: 'admin'", "xref: FUN_X"]
    significance: str = "MEDIUM"  # 'HIGH', 'MEDIUM', 'LOW'
    
    def format_for_prompt(self) -> str:
        """Format for prompt inclusion."""
        mentions_str = "; ".join(self.mentions[:5])  # Limit to 5 mentions
        return f"- **{self.address}** ({self.significance}): {mentions_str}"


class CycleConclusions(BaseModel):
    """
    Structured conclusions from an analysis phase.
    
    These conclusions are passed to the next planning phase to inform
    the updated investigation plan. This enables per-cycle isolation
    while maintaining continuity across the agentic loop.
    """
    cycle_number: int
    binary_purpose: str = ""
    key_findings: List[Dict[str, Any]] = Field(default_factory=list)
    # Format: [{"address": "0x...", "finding": "...", "confidence": "HIGH/MEDIUM/LOW"}]
    
    investigation_gaps: List[str] = Field(default_factory=list)
    # What still needs investigation
    
    recommended_next_steps: List[str] = Field(default_factory=list)
    # Specific tools/actions for next cycle
    
    correlation_insights: List[str] = Field(default_factory=list)
    # Cross-tool patterns discovered
    
    tools_executed: int = 0
    timestamp: datetime = Field(default_factory=datetime.now)
    
    def format_for_planning(self) -> str:
        """Format conclusions for next planning phase."""
        sections = [
            f"## Cycle {self.cycle_number} Conclusions",
            f"\n### Binary Purpose\n{self.binary_purpose}" if self.binary_purpose else "",
        ]
        
        if self.key_findings:
            findings_lines = ["### Key Findings"]
            for f in self.key_findings[:10]:  # Limit to 10
                conf = f.get('confidence', 'MEDIUM')
                findings_lines.append(f"- [{conf}] {f.get('address', '?')}: {f.get('finding', '')}")
            sections.append("\n".join(findings_lines))
        
        if self.correlation_insights:
            sections.append("### Correlation Insights\n" + "\n".join(f"- {i}" for i in self.correlation_insights[:5]))
        
        if self.investigation_gaps:
            sections.append("### Investigation Gaps\n" + "\n".join(f"- {g}" for g in self.investigation_gaps[:5]))
        
        if self.recommended_next_steps:
            sections.append("### Recommended Next Steps\n" + "\n".join(f"- {s}" for s in self.recommended_next_steps[:5]))
        
        return "\n\n".join(s for s in sections if s)


class ExecutionSignal(str, Enum):
    """Signals that control execution loop flow.
    
    Inspired by OpenCode's blocked/stop/continue return values
    from SessionProcessor.
    """
    CONTINUE = "continue"   # Keep executing
    PAUSE = "pause"         # Stop and surface to user for review
    ABORT = "abort"         # Kill the loop entirely


class ExecutionGate(BaseModel):
    """A gate event — records why the execution loop paused.
    
    Inspired by OpenCode's PermissionNext.ask() pattern where the
    system blocks until the user responds with once/always/reject.
    
    Triggers:
        artifact   — Critical finding detected in tool results
        repetition — Doom-loop: N identical tool calls in a row
        high_risk  — Destructive tool about to execute
        clarification — AI requested user guidance
    """
    reason: str
    signal: ExecutionSignal = ExecutionSignal.PAUSE
    trigger: str = "unknown"  # "artifact", "repetition", "high_risk", "clarification"
    context: Dict[str, Any] = Field(default_factory=dict)
    user_feedback: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.now)


# Resolve forward reference for ExecutionPhaseResults.gates_triggered
ExecutionPhaseResults.model_rebuild()


class SessionMemory(BaseModel):
    """Complete session memory including conversation and state."""
    messages: List[ConversationMessage] = Field(default_factory=list)
    tool_executions: List[ToolExecution] = Field(default_factory=list)
    analysis_state: AnalysisState = Field(default_factory=AnalysisState)
    start_time: datetime = Field(default_factory=datetime.now)
    knowledge_base: List[KnowledgeArtifact] = Field(default_factory=list)  # New Knowledge Base
    user_preferences: Dict[str, Any] = Field(default_factory=dict)
    
    def add_message(self, role: MessageRole, content: str, metadata: Dict[str, Any] = None):
        """Add a message to the conversation history."""
        self.messages.append(ConversationMessage(
            role=role,
            content=content,
            metadata=metadata or {}
        ))
    
    def add_tool_execution(self, tool_name: str, parameters: Dict[str, Any], result: str, success: bool, reasoning: str = None):
        """Record a tool execution."""
        self.tool_executions.append(ToolExecution(
            tool_name=tool_name,
            parameters=parameters,
            result=result,
            success=success,
            reasoning=reasoning
        ))
        
    def add_knowledge(self, key: str, value: str, category: str = "general", tags: List[str] = None):
        """Add a persistent knowledge artifact."""
        self.knowledge_base.append(KnowledgeArtifact(
            key=key,
            value=value,
            category=category,
            tags=tags or []
        ))

    def set_user_preference(self, key: str, value: Any) -> None:
        """Set a user preference (sticky note) for this session."""
        self.user_preferences[key] = value

    def get_user_preferences_summary(self) -> str:
        """Format user preferences for prompt injection."""
        if not self.user_preferences:
            return ""
        lines = ["## USER PREFERENCES (STICKY)"]
        for k in sorted(self.user_preferences.keys()):
            v = self.user_preferences[k]
            lines.append(f"- {k}: {v}")
        return "\n".join(lines)

    def get_knowledge_summary(self) -> str:
        """Get formatted summary of all knowledge artifacts."""
        if not self.knowledge_base:
            return ""
        
        section = "## 🧠 KNOWN KNOWLEDGE ARTIFACTS\n"
        items = [k.format_for_prompt() for k in self.knowledge_base]
        return section + "\n".join(items)
    
    def get_recent_messages(self, limit: int = 10, 
                           role_filter: Optional[List[MessageRole]] = None) -> List[ConversationMessage]:
        """Get recent messages, optionally filtered by role."""
        messages = self.messages
        if role_filter:
            messages = [m for m in messages if m.role in role_filter]
        return messages[-limit:]
    
    def get_recent_tool_executions(self, limit: int = 5) -> List[ToolExecution]:
        """Get recent tool executions."""
        return self.tool_executions[-limit:]
    
    def get_all_tool_executions(self) -> List[ToolExecution]:
        """Get all tool executions in the session."""
        return self.tool_executions

    
    def build_structured_prompt(self, goal: str, current_plan: Optional[str] = None,
                                cag_context: Optional[CAGContext] = None,
                                phase_instructions: Optional[str] = None) -> StructuredPrompt:
        """Build a structured prompt from the current session state."""
        return StructuredPrompt(
            goal=goal,
            analysis_state=self.analysis_state,
            current_plan=current_plan,
            cag_context=cag_context,
            tool_results=self.get_recent_tool_executions(),
            conversation_history=self.get_recent_messages(limit=10),
            phase_specific_instructions=phase_instructions
        )
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat(),
            set: lambda v: list(v)
        }
