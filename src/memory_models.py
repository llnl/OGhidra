"""
Data structures for session memory and tool call tracking.
"""

from pydantic import BaseModel, Field, validator
from typing import List, Dict, Any, Literal, Optional
import datetime
import uuid

class ToolCallRecord(BaseModel):
    """Represents a single tool call made during a session."""
    tool_name: str = Field(min_length=1, description="Tool name cannot be empty")
    parameters: Dict[str, Any]
    timestamp: datetime.datetime = Field(default_factory=datetime.datetime.utcnow)
    status: Optional[Literal["success", "error"]] = None
    result_preview: Optional[str] = Field(default=None, max_length=1000, description="Brief summary of the tool's output")
    
    @validator('tool_name')
    def validate_tool_name(cls, v):
        """Validate tool name format."""
        if not v.strip():
            raise ValueError('Tool name cannot be empty or whitespace')
        # Basic validation for tool names (should be valid identifiers)
        import re
        if not re.match(r'^[a-zA-Z][a-zA-Z0-9_]*$', v):
            raise ValueError('Tool name must be a valid identifier (letters, numbers, underscore, starting with letter)')
        return v.strip()

class SessionRecord(BaseModel):
    """Represents a single conversation session with the user."""
    session_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    start_time: datetime.datetime = Field(default_factory=datetime.datetime.utcnow)
    end_time: Optional[datetime.datetime] = None
    
    user_task_description: str = Field(min_length=1, max_length=2000, description="The core task, problem, or question from the user")
    
    tool_calls: List[ToolCallRecord] = Field(default_factory=list)
    
    outcome: Literal["success", "failure", "partial_success", "in_progress", "aborted"] = "in_progress"
    outcome_reason: Optional[str] = Field(default=None, max_length=500, description="Brief explanation for the outcome")
    
    session_summary: Optional[str] = Field(default=None, max_length=2000, description="LLM-generated summary of key findings or solution")
    
    @validator('user_task_description')
    def validate_task_description(cls, v):
        """Ensure task description is meaningful."""
        if not v.strip():
            raise ValueError('Task description cannot be empty or whitespace')
        return v.strip()
    
    @validator('end_time')
    def validate_end_time(cls, v, values):
        """Ensure end_time is after start_time."""
        if v and 'start_time' in values:
            start_time = values['start_time']
            if v < start_time:
                raise ValueError('end_time cannot be before start_time')
            # Reasonable session duration limit (24 hours)
            if (v - start_time).total_seconds() > 24 * 60 * 60:
                raise ValueError('Session duration cannot exceed 24 hours')
        return v
    
    @property
    def duration(self) -> Optional[datetime.timedelta]:
        """Calculate session duration."""
        if self.end_time and self.start_time:
            return self.end_time - self.start_time
        return None
    
    @property
    def is_active(self) -> bool:
        """Check if session is currently active."""
        return self.outcome == "in_progress" and self.end_time is None 