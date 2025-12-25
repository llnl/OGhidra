"""
Utilities for working with session records, generating embeddings and summaries.
"""

import logging
import numpy as np
from typing import Optional, List, Dict, Any
import time

# Import your Ollama client or other LLM clients as needed
# For example, if you have an Ollama client in src/ollama_client.py
# from .ollama_client import OllamaClient

from .memory_models import SessionRecord, ToolCallRecord

logger = logging.getLogger(__name__)

class SessionEmbedder:
    """
    Utility class for generating embeddings from session records.
    
    This is a placeholder implementation. In a real implementation, you would use
    a proper embedding model, such as one from OpenAI, HuggingFace, or a locally hosted model.
    """
    
    def __init__(self, embedding_model: str = "nomic-embed-text"):
        """
        Initialize the SessionEmbedder.
        
        Args:
            embedding_model: The name of the embedding model to use.
        """
        self.embedding_model = embedding_model
        # In a real implementation, you would initialize your embedding model here
        logger.info(f"Initialized SessionEmbedder with model: {embedding_model}")
    
    def _create_session_text(self, session: SessionRecord) -> str:
        """
        Create a text representation of a session record for embedding.
        
        Args:
            session: The session record to convert to text.
            
        Returns:
            A text representation of the session record.
        """
        # Create a text representation that captures the important aspects of the session
        lines = [
            f"Task: {session.user_task_description}",
        ]
        
        # Add tool calls
        if session.tool_calls:
            lines.append("\nTools used:")
            for i, tool in enumerate(session.tool_calls):
                # Format parameters as a string
                params_str = ", ".join([f"{k}={v}" for k, v in tool.parameters.items()])
                lines.append(f"{i+1}. {tool.tool_name}({params_str})")
                if tool.status:
                    lines.append(f"   Status: {tool.status}")
                if tool.result_preview:
                    lines.append(f"   Result: {tool.result_preview}")
        
        # Add outcome and summary if available
        if session.outcome != "in_progress":
            lines.append(f"\nOutcome: {session.outcome}")
        if session.outcome_reason:
            lines.append(f"Reason: {session.outcome_reason}")
        if session.session_summary:
            lines.append(f"\nSummary: {session.session_summary}")
        
        return "\n".join(lines)
    
    def embed_session(self, session: SessionRecord) -> np.ndarray:
        """
        Generate an embedding for a session record using the configured Ollama embedding model.
        Falls back to the previous deterministic-random embedding if the Ollama client is
        unavailable or an error occurs.
        """
        # Create a text representation of the session
        session_text = self._create_session_text(session)
        
        # Try Ollama first for a real semantic embedding
        try:
            # Local import to avoid circular import at module load time
            from .bridge import Bridge  # pylint: disable=import-outside-toplevel

            ollama_embs = Bridge.get_ollama_embeddings([session_text], model=self.embedding_model)
            if ollama_embs:
                emb_vec = np.array(ollama_embs[0], dtype=np.float32)
                # Normalise to unit length for cosine similarity
                norm = np.linalg.norm(emb_vec)
                if norm != 0:
                    emb_vec = emb_vec / norm
                logger.debug("Generated Ollama embedding for session %s", session.session_id)
                return emb_vec
            logger.warning("Ollama returned no embedding – falling back to placeholder vector")
        except Exception as exc:  # pylint: disable=broad-except
            logger.error("Failed to generate Ollama embedding: %s – falling back to placeholder", exc)

        # ------------------------------------------------------------------
        # Fallback – previous deterministic random vector (ensures old flows
        # keep working even when Ollama is offline)
        # ------------------------------------------------------------------
        content_hash = hash(session_text) % 10000
        np.random.seed(content_hash)
        embedding = np.random.random(384)  # 384-D placeholder
        embedding = embedding / np.linalg.norm(embedding)
        return embedding

class SessionSummarizer:
    """
    Utility class for generating summaries from session records.
    
    This is a placeholder implementation. In a real implementation, you would use
    your LLM client to generate summaries.
    """
    
    def __init__(self, llm_client=None):
        """
        Initialize the SessionSummarizer.
        
        Args:
            llm_client: The LLM client to use for generating summaries.
        """
        self.llm_client = llm_client
        # In a real implementation, you would use this client to generate summaries
        logger.info("Initialized SessionSummarizer")
    
    def _create_summary_prompt(self, session: SessionRecord) -> str:
        """
        Create a prompt for generating a summary of a session.
        
        Args:
            session: The session record to summarize.
            
        Returns:
            A prompt for the LLM to generate a summary.
        """
        tool_calls_text = ""
        for i, tool in enumerate(session.tool_calls):
            params_str = ", ".join([f"{k}={v}" for k, v in tool.parameters.items()])
            tool_text = f"{i+1}. {tool.tool_name}({params_str})"
            if tool.status:
                tool_text += f" → {tool.status}"
            if tool.result_preview:
                tool_text += f"\n   Result: {tool.result_preview}"
            tool_calls_text += tool_text + "\n"
        
        prompt = f"""
Summarize the following reverse engineering session with Ghidra:

Task: {session.user_task_description}

Tools used:
{tool_calls_text}

Outcome: {session.outcome}
{f"Reason: {session.outcome_reason}" if session.outcome_reason else ""}

Please provide a concise summary (2-3 sentences) of what was accomplished or discovered during this session.
Focus on the key insights, findings, or conclusions that would be useful for future reference.
"""
        return prompt
    
    def generate_summary(self, session: SessionRecord) -> Optional[str]:
        """
        Generate a summary for a session record.
        
        Args:
            session: The session record to summarize.
            
        Returns:
            A summary of the session, or None if summarization failed.
        """
        # Create a prompt for the LLM
        prompt = self._create_summary_prompt(session)
        
        # In a real implementation, you would use your LLM client here
        # For now, we'll return a placeholder summary based on the outcome
        if self.llm_client is None:
            # Generate a placeholder summary based on the session data
            outcome_map = {
                "success": "Successfully completed the task",
                "failure": "Failed to complete the task",
                "partial_success": "Partially completed the task",
                "aborted": "The session was aborted before completion",
                "in_progress": "The session is still in progress"
            }
            
            outcome_text = outcome_map.get(session.outcome, "Session completed")
            tool_count = len(session.tool_calls)
            tools_used = ", ".join(set(tc.tool_name for tc in session.tool_calls[:3]))
            if len(set(tc.tool_name for tc in session.tool_calls)) > 3:
                tools_used += ", and others"
            
            summary = f"{outcome_text} using {tool_count} tool calls. Main tools used: {tools_used}. "
            summary += f"The task was to {session.user_task_description[:100]}{'...' if len(session.user_task_description) > 100 else ''}."
            
            logger.warning("Using placeholder summary - no LLM client provided")
            time.sleep(0.1)  # Small delay to simulate real processing
            return summary
        
        # In a real implementation with an LLM client:
        try:
            # response = self.llm_client.generate(prompt=prompt, max_tokens=150)
            # return response.text.strip()
            pass  # Replace with actual LLM call when available
        except Exception as e:
            logger.error(f"Error generating summary: {e}")
            return None 