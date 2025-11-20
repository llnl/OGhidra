"""
Memory Manager for the Ollama-GhidraMCP Bridge.

This module integrates session storage, active session management,
and vector database for RAG capabilities.
"""

import logging
from typing import List, Dict, Any, Optional, Tuple

from .config import BridgeConfig, SessionHistoryConfig
from .memory_models import SessionRecord, ToolCallRecord
from .session_store import SessionHistoryStore
from .active_session import ActiveSessionManager
from .vector_store import SimpleVectorStore
from .session_utils import SessionEmbedder, SessionSummarizer

logger = logging.getLogger(__name__)

class MemoryManager:
    """
    Memory Manager for the Ollama-GhidraMCP Bridge.
    
    This class integrates session storage, active session management,
    and vector database for RAG capabilities.
    """
    
    def __init__(self, config: BridgeConfig, llm_client=None):
        """
        Initialize the Memory Manager.
        
        Args:
            config: The bridge configuration.
            llm_client: Optional LLM client for generating summaries.
        """
        self.config = config
        self.session_config = config.session_history
        
        # Initialize session storage
        self.session_store = SessionHistoryStore(
            storage_path=self.session_config.storage_path
        )
        
        # Initialize active session manager
        self.active_session_manager = ActiveSessionManager(self.session_store)
        
        # Initialize vector store if enabled
        self.vector_store = None
        if self.session_config.use_vector_embeddings:
            self.vector_store = SimpleVectorStore(
                storage_dir=self.session_config.vector_db_path
            )
        
        # Initialize embedder and summarizer – use embedding model, not generation model
        self.embedder = SessionEmbedder(
            embedding_model=config.ollama.embedding_model
        )
        self.summarizer = SessionSummarizer(llm_client=llm_client)
        
        # Load existing sessions
        self.sessions = self.session_store.load_all_sessions()
        logger.info(f"Loaded {len(self.sessions)} sessions from storage")
        
        # Set up indices for fast lookup
        self.session_index = {s.session_id: i for i, s in enumerate(self.sessions)}
    
    def start_session(self, user_task: str) -> str:
        """
        Start a new session.
        
        Args:
            user_task: The user's initial query or task description.
            
        Returns:
            The session ID of the new session.
        """
        session_id = self.active_session_manager.start_new_session(user_task_description=user_task)
        logger.info(f"Started new session {session_id} for task: '{user_task}'")
        return session_id
    
    def log_tool_call(self, 
                    tool_name: str, 
                    parameters: Dict[str, Any],
                    status: Optional[str] = None,
                    result_preview: Optional[str] = None) -> bool:
        """
        Log a tool call in the current session.
        
        Args:
            tool_name: The name of the tool being called.
            parameters: The parameters passed to the tool.
            status: Optional status of the tool call (success/error).
            result_preview: Optional brief summary of the tool's output.
            
        Returns:
            True if the tool call was logged successfully, False otherwise.
        """
        result = self.active_session_manager.log_tool_call(
            tool_name=tool_name,
            parameters=parameters,
            status=status,
            result_preview=result_preview
        )
        if result:
            logger.debug(f"Logged tool call '{tool_name}' to session {self.active_session_manager.get_current_session_id()}")
        return result
    
    def update_tool_status(self, 
                         index: int, 
                         status: str,
                         result_preview: Optional[str] = None) -> bool:
        """
        Update the status of a previously logged tool call.
        
        Args:
            index: The index of the tool call in the current session's tool_calls list.
            status: The new status to set (success/error).
            result_preview: Optional brief summary of the tool's output.
            
        Returns:
            True if the status was updated successfully, False otherwise.
        """
        return self.active_session_manager.update_tool_call_status(
            index=index,
            status=status,
            result_preview=result_preview
        )
    
    def end_session(self, 
                  outcome: str, 
                  reason: Optional[str] = None,
                  generate_summary: bool = None) -> Optional[str]:
        """
        End the current session and optionally generate a summary.
        
        Args:
            outcome: The outcome of the session ('success', 'failure', 'partial_success', 'aborted').
            reason: Optional reason for the outcome.
            generate_summary: Whether to generate a summary. If None, uses the config default.
            
        Returns:
            The session ID of the completed session, or None if no active session.
        """
        if not self.active_session_manager.current_session:
            return None
        
        session_id = self.active_session_manager.get_current_session_id()
        
        # Generate summary if enabled
        summary = None
        if generate_summary is None:
            generate_summary = self.session_config.auto_summarize
        
        if generate_summary:
            summary = self.summarizer.generate_summary(self.active_session_manager.current_session)
        
        # End the session
        result = self.active_session_manager.end_current_session(
            outcome=outcome,
            reason=reason,
            summary=summary
        )
        
        if result:
            logger.info(f"Ended session {session_id} with outcome '{outcome}'")
            
            # Reload sessions to include the newly completed one
            self.sessions = self.session_store.load_all_sessions()
            self.session_index = {s.session_id: i for i, s in enumerate(self.sessions)}
            
            # Add to vector store if enabled
            if self.vector_store is not None and self.session_config.use_vector_embeddings:
                session = self.session_store.get_session_by_id(session_id)
                if session:
                    embedding = self.embedder.embed_session(session)
                    self.vector_store.add_session(session, embedding)
                    logger.debug(f"Added session {session_id} to vector store")
        
        return session_id if result else None
    
    def get_similar_sessions(self, query: str, top_k: int = 3) -> List[Dict[str, Any]]:
        """
        Find sessions similar to the given query.
        
        Args:
            query: The query to find similar sessions for.
            top_k: The number of similar sessions to return.
            
        Returns:
            A list of similar sessions, with metadata and similarity scores.
        """
        if not self.vector_store or not self.session_config.use_vector_embeddings:
            logger.warning("Vector embeddings are not enabled. Cannot search for similar sessions.")
            return []
        
        # Create a dummy session for embedding
        dummy_session = SessionRecord(
            user_task_description=query,
            outcome="in_progress"
        )
        
        # Generate embedding for the query
        query_embedding = self.embedder.embed_session(dummy_session)
        
        # Search for similar sessions
        similar_sessions = self.vector_store.search(query_embedding, top_k=top_k)
        return similar_sessions
    
    def get_recent_sessions(self, limit: int = 5) -> List[SessionRecord]:
        """
        Get the most recent sessions.
        
        Args:
            limit: The maximum number of sessions to return.
            
        Returns:
            A list of the most recent sessions.
        """
        # Sort sessions by start_time in descending order
        sorted_sessions = sorted(
            self.sessions, 
            key=lambda s: s.start_time, 
            reverse=True
        )
        return sorted_sessions[:limit]
    
    def get_successful_sessions(self, limit: int = None) -> List[SessionRecord]:
        """
        Get sessions with 'success' outcome.
        
        Args:
            limit: Optional maximum number of sessions to return.
            
        Returns:
            A list of successful sessions.
        """
        successful = [s for s in self.sessions if s.outcome == "success"]
        # Sort by start_time in descending order
        successful.sort(key=lambda s: s.start_time, reverse=True)
        return successful[:limit] if limit is not None else successful
    
    def get_session_by_id(self, session_id: str) -> Optional[SessionRecord]:
        """
        Get a session by its ID.
        
        Args:
            session_id: The ID of the session to retrieve.
            
        Returns:
            The session with the specified ID, or None if not found.
        """
        if session_id in self.session_index:
            return self.sessions[self.session_index[session_id]]
        return self.session_store.get_session_by_id(session_id)
    
    def get_session_count(self) -> int:
        """
        Get the total number of stored sessions.
        
        Returns:
            The number of sessions in storage.
        """
        return len(self.sessions)
    
    def clear_all_sessions(self) -> bool:
        """
        Clear all session data (USE WITH CAUTION).
        
        Returns:
            True if successful, False otherwise.
        """
        try:
            # Close any active session
            if self.active_session_manager.current_session:
                self.active_session_manager.end_current_session(
                    outcome="aborted", 
                    reason="Cleared all sessions"
                )
            
            # Clear vector store if it exists
            if self.vector_store:
                self.vector_store.clear()
            
            # Delete session storage file and reload (empty)
            import os
            if os.path.exists(self.session_config.storage_path):
                os.remove(self.session_config.storage_path)
            
            # Reset in-memory sessions
            self.sessions = []
            self.session_index = {}
            
            logger.warning("Cleared all session data")
            return True
        except Exception as e:
            logger.error(f"Error clearing session data: {e}")
            return False 