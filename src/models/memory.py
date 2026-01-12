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
from pydantic import BaseModel, Field, validator
from datetime import datetime
from enum import Enum


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
    
    @validator('conversation_history')
    def validate_history_not_too_long(cls, v):
        """Warn if conversation history is getting very long."""
        if len(v) > 100:
            # Could log a warning here
            pass
        return v


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


class SessionMemory(BaseModel):
    """Complete session memory including conversation and state."""
    messages: List[ConversationMessage] = Field(default_factory=list)
    tool_executions: List[ToolExecution] = Field(default_factory=list)
    analysis_state: AnalysisState = Field(default_factory=AnalysisState)
    start_time: datetime = Field(default_factory=datetime.now)
    knowledge_base: List[KnowledgeArtifact] = Field(default_factory=list)  # New Knowledge Base
    
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

