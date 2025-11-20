"""
Active session management for the Ollama-GhidraMCP Bridge.
"""

import datetime
from typing import Literal, Dict, Any, Optional, List

from .memory_models import SessionRecord, ToolCallRecord
from .session_store import SessionHistoryStore

class ActiveSessionManager:
    def __init__(self, store: SessionHistoryStore):
        self.store = store
        self.current_session: Optional[SessionRecord] = None

    def start_new_session(self, user_task_description: str) -> Optional[str]:
        """
        Starts a new session. If a previous one was in progress, it's saved as 'aborted'.
        
        Args:
            user_task_description: The user's initial query or task description.
            
        Returns:
            The session ID of the new session, or None if creation failed.
        """
        if self.current_session and self.current_session.outcome == "in_progress":
            self.end_current_session(
                outcome="aborted", 
                reason="New session started before explicit completion."
            )
        
        self.current_session = SessionRecord(user_task_description=user_task_description)
        return self.current_session.session_id

    def log_tool_call(self, 
                     tool_name: str, 
                     parameters: Dict[str, Any],
                     status: Optional[Literal["success", "error"]] = None,
                     result_preview: Optional[str] = None) -> bool:
        """
        Logs a tool call to the current active session.
        
        Args:
            tool_name: The name of the tool being called.
            parameters: The parameters passed to the tool.
            status: Optional status of the tool call (success/error).
            result_preview: Optional brief summary of the tool's output.
            
        Returns:
            True if the tool call was logged successfully, False otherwise.
        """
        if not self.current_session:
            return False
        
        tool_call = ToolCallRecord(
            tool_name=tool_name, 
            parameters=parameters,
            status=status,
            result_preview=result_preview
        )
        self.current_session.tool_calls.append(tool_call)
        return True

    def update_tool_call_status(self, 
                              index: int, 
                              status: Literal["success", "error"],
                              result_preview: Optional[str] = None) -> bool:
        """
        Updates the status of a previously logged tool call.
        
        Args:
            index: The index of the tool call in the current session's tool_calls list.
            status: The new status to set (success/error).
            result_preview: Optional brief summary of the tool's output.
            
        Returns:
            True if the status was updated successfully, False otherwise.
        """
        if not self.current_session or index >= len(self.current_session.tool_calls):
            return False
        
        tool_call = self.current_session.tool_calls[index]
        tool_call.status = status
        if result_preview is not None:
            tool_call.result_preview = result_preview
        return True

    def update_task_description(self, new_description: str) -> bool:
        """
        Updates the task description of the current active session.
        
        Args:
            new_description: The updated task description.
            
        Returns:
            True if the description was updated successfully, False otherwise.
        """
        if not self.current_session:
            return False
        
        self.current_session.user_task_description = new_description
        return True

    def end_current_session(self, 
                          outcome: Literal["success", "failure", "partial_success", "aborted"], 
                          reason: Optional[str] = None, 
                          summary: Optional[str] = None) -> bool:
        """
        Ends the current session, sets its outcome, and saves it.
        
        Args:
            outcome: The outcome of the session.
            reason: Optional reason for the outcome.
            summary: Optional summary of the session.
            
        Returns:
            True if the session was ended and saved successfully, False otherwise.
        """
        if not self.current_session:
            return False

        self.current_session.outcome = outcome
        self.current_session.outcome_reason = reason
        self.current_session.session_summary = summary
        self.current_session.end_time = datetime.datetime.utcnow()
        
        self.store.save_session(self.current_session)
        self.current_session = None
        return True

    def get_current_session_id(self) -> Optional[str]:
        """Returns the ID of the current session, if one exists."""
        return self.current_session.session_id if self.current_session else None

    def get_session_tools(self) -> List[ToolCallRecord]:
        """Returns the list of tool calls for the current session."""
        if not self.current_session:
            return []
        return self.current_session.tool_calls 