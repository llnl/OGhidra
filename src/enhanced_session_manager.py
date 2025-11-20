"""
Enhanced Session Management System for OGhidra
Handles comprehensive session saving/loading including analyzed functions, RAG vectors, and UI state.
"""

import os
import json
import time
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple, Iterator, Callable
from dataclasses import dataclass, asdict
import hashlib

logger = logging.getLogger(__name__)

@dataclass
class FunctionAnalysis:
    """Represents an analyzed function with all its metadata."""
    address: str
    old_name: str
    new_name: str
    behavior_summary: str
    analysis_timestamp: float
    function_hash: Optional[str] = None  # For deduplication
    ai_confidence: Optional[float] = None
    processing_time: Optional[float] = None

@dataclass
class SessionMetadata:
    """Metadata for an analysis session."""
    session_name: str
    session_id: str
    binary_path: Optional[str]
    binary_hash: Optional[str]
    created_at: datetime
    last_modified: datetime
    total_functions: int
    analyzed_functions_count: int
    session_description: Optional[str] = None
    tags: Optional[List[str]] = None

@dataclass
class UIState:
    """UI state information."""
    analyzed_functions_panel_expanded: bool = True
    last_selected_function: Optional[str] = None
    filter_settings: Optional[Dict[str, Any]] = None
    
    def __post_init__(self):
        if self.filter_settings is None:
            self.filter_settings = {}

class EnhancedSessionManager:
    """
    Enhanced session manager that provides comprehensive session persistence.
    Handles analyzed functions, RAG vectors, UI state, and metadata.
    """
    
    def __init__(self, sessions_dir: str = "analysis_sessions"):
        """
        Initialize the enhanced session manager.
        
        Args:
            sessions_dir: Directory to store session data
        """
        self.sessions_dir = sessions_dir
        self.current_session_id: Optional[str] = None
        self.current_session_data: Optional[Dict[str, Any]] = None
        
        # Ensure sessions directory exists
        os.makedirs(sessions_dir, exist_ok=True)
        
        # Performance tracking
        self.load_stats = {
            'last_load_time': 0,
            'last_functions_loaded': 0,
            'streaming_enabled': True
        }
        
        logger.info(f"Enhanced Session Manager initialized with directory: {sessions_dir}")
    
    def create_session(self, session_name: str, binary_path: Optional[str] = None, 
                      description: Optional[str] = None) -> str:
        """
        Create a new analysis session.
        
        Args:
            session_name: User-provided name for the session
            binary_path: Path to the binary being analyzed
            description: Optional description of the analysis
            
        Returns:
            Session ID
        """
        # Generate unique session ID
        timestamp = int(time.time())
        session_id = f"session_{timestamp}_{hashlib.md5(session_name.encode()).hexdigest()[:8]}"
        
        # Create session directory
        session_dir = os.path.join(self.sessions_dir, session_id)
        os.makedirs(session_dir, exist_ok=True)
        
        # Calculate binary hash if path provided
        binary_hash = None
        if binary_path and os.path.exists(binary_path):
            try:
                with open(binary_path, 'rb') as f:
                    binary_hash = hashlib.sha256(f.read()).hexdigest()
            except Exception as e:
                logger.warning(f"Could not calculate binary hash: {e}")
        
        # Create session metadata
        metadata = SessionMetadata(
            session_name=session_name,
            session_id=session_id,
            binary_path=binary_path,
            binary_hash=binary_hash,
            created_at=datetime.now(),
            last_modified=datetime.now(),
            total_functions=0,
            analyzed_functions_count=0,
            session_description=description,
            tags=[]
        )
        
        # Initialize session data structure with proper datetime serialization
        session_data = {
            "metadata": {
                **asdict(metadata),
                "created_at": metadata.created_at.isoformat(),
                "last_modified": metadata.last_modified.isoformat()
            },
            "analyzed_functions": {},  # address -> FunctionAnalysis
            "rag_vectors": [],  # List of vector data
            "ui_state": asdict(UIState()),
            "analysis_log": [],  # Log of analysis operations
            "performance_stats": {
                "total_processing_time": 0.0,
                "average_function_time": 0.0,
                "rag_vector_count": 0
            }
        }
        
        # Save initial session
        self._save_session_data(session_id, session_data)
        
        self.current_session_id = session_id
        self.current_session_data = session_data
        
        logger.info(f"Created new session: {session_name} (ID: {session_id})")
        return session_id
    
    def save_current_session(self, analyzed_functions: Dict[str, Any], 
                           rag_vectors: Optional[List[Any]] = None, 
                           ui_state: Optional[Dict[str, Any]] = None,
                           performance_stats: Optional[Dict[str, Any]] = None) -> bool:
        """
        Save the current session with all analysis data.
        
        Args:
            analyzed_functions: Dictionary of analyzed functions from the UI panel
            rag_vectors: List of RAG vector data
            ui_state: Current UI state
            performance_stats: Performance statistics
            
        Returns:
            True if successful, False otherwise
        """
        if not self.current_session_id or not self.current_session_data:
            logger.error("No active session to save")
            return False
        
        try:
            # Update analyzed functions
            if analyzed_functions:
                for address, func_data in analyzed_functions.items():
                    # Convert to FunctionAnalysis if needed
                    if isinstance(func_data, dict):
                        func_analysis = FunctionAnalysis(
                            address=func_data.get('address', address),
                            old_name=func_data.get('old_name', 'Unknown'),
                            new_name=func_data.get('new_name', 'Unknown'),
                            behavior_summary=func_data.get('behavior_summary', func_data.get('summary', '')),
                            analysis_timestamp=func_data.get('timestamp', time.time()),
                            function_hash=func_data.get('hash'),
                            ai_confidence=func_data.get('confidence'),
                            processing_time=func_data.get('processing_time')
                        )
                    else:
                        func_analysis = func_data
                    
                    self.current_session_data["analyzed_functions"][address] = asdict(func_analysis)
            
            # Update RAG vectors
            if rag_vectors:
                self.current_session_data["rag_vectors"] = rag_vectors
            
            # Update UI state
            if ui_state and self.current_session_data["ui_state"] is not None:
                self.current_session_data["ui_state"].update(ui_state)
            
            # Update performance stats
            if performance_stats and self.current_session_data["performance_stats"] is not None:
                self.current_session_data["performance_stats"].update(performance_stats)
            
            # Update metadata
            self.current_session_data["metadata"]["last_modified"] = datetime.now().isoformat()
            self.current_session_data["metadata"]["analyzed_functions_count"] = len(
                self.current_session_data["analyzed_functions"]
            )
            
            # Add to analysis log
            self.current_session_data["analysis_log"].append({
                "timestamp": time.time(),
                "action": "session_saved",
                "functions_count": len(self.current_session_data["analyzed_functions"]),
                "rag_vectors_count": len(self.current_session_data.get("rag_vectors", []))
            })
            
            # Save to disk
            success = self._save_session_data(self.current_session_id, self.current_session_data)
            
            if success:
                logger.info(f"Successfully saved session {self.current_session_id}")
            else:
                logger.error(f"Failed to save session {self.current_session_id}")
            
            return success
            
        except Exception as e:
            logger.error(f"Error saving session: {e}")
            return False
    
    def load_session(self, session_identifier: str) -> Optional[Dict[str, Any]]:
        """
        Load a session by name or ID.
        
        Args:
            session_identifier: Session name or ID
            
        Returns:
            Session data dictionary or None if not found
        """
        try:
            # First try as session ID
            session_data = self._load_session_data(session_identifier)
            
            # If not found, try to find by name
            if not session_data:
                sessions = self.list_sessions()
                for session_info in sessions:
                    if session_info["name"] == session_identifier:
                        session_data = self._load_session_data(session_info["id"])
                        break
            
            if session_data:
                self.current_session_id = session_data["metadata"]["session_id"]
                self.current_session_data = session_data
                logger.info(f"Loaded session: {session_data['metadata']['session_name']}")
                return session_data
            else:
                logger.warning(f"Session not found: {session_identifier}")
                return None
                
        except Exception as e:
            logger.error(f"Error loading session {session_identifier}: {e}")
            return None
    
    def list_sessions(self) -> List[Dict[str, Any]]:
        """
        List all available sessions.
        
        Returns:
            List of session information dictionaries
        """
        sessions = []
        
        try:
            if not os.path.exists(self.sessions_dir):
                return sessions
            
            for session_id in os.listdir(self.sessions_dir):
                session_path = os.path.join(self.sessions_dir, session_id)
                if os.path.isdir(session_path):
                    metadata_file = os.path.join(session_path, "session.json")
                    if os.path.exists(metadata_file):
                        try:
                            with open(metadata_file, 'r', encoding='utf-8') as f:
                                session_data = json.load(f)
                                metadata = session_data.get("metadata", {})
                                
                                # Convert ISO format strings to timestamps for UI compatibility
                                created_at = metadata.get("created_at")
                                last_modified = metadata.get("last_modified")
                                
                                # Handle both timestamp and ISO format
                                try:
                                    if isinstance(created_at, str):
                                        created_timestamp = datetime.fromisoformat(created_at.replace('Z', '+00:00')).timestamp()
                                    else:
                                        created_timestamp = created_at or 0
                                except:
                                    created_timestamp = 0
                                
                                try:
                                    if isinstance(last_modified, str):
                                        modified_timestamp = datetime.fromisoformat(last_modified.replace('Z', '+00:00')).timestamp()
                                    else:
                                        modified_timestamp = last_modified or 0
                                except:
                                    modified_timestamp = 0
                                
                                sessions.append({
                                    "id": session_id,
                                    "name": metadata.get("session_name", "Unknown"),
                                    "created": created_timestamp,
                                    "last_modified": modified_timestamp,
                                    "analyzed_functions_count": metadata.get("analyzed_functions_count", 0),
                                    "binary_path": metadata.get("binary_path"),
                                    "description": metadata.get("session_description"),
                                    "tags": metadata.get("tags", [])
                                })
                        except Exception as e:
                            logger.warning(f"Error reading session {session_id}: {e}")
            
            # Sort by last modified (newest first)
            sessions.sort(key=lambda x: x.get("last_modified", 0), reverse=True)
            
        except Exception as e:
            logger.error(f"Error listing sessions: {e}")
        
        return sessions
    
    def delete_session(self, session_identifier: str) -> bool:
        """
        Delete a session.
        
        Args:
            session_identifier: Session name or ID
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Find session ID
            session_id = session_identifier
            if not os.path.exists(os.path.join(self.sessions_dir, session_id)):
                # Try to find by name
                sessions = self.list_sessions()
                for session_info in sessions:
                    if session_info["name"] == session_identifier:
                        session_id = session_info["id"]
                        break
                else:
                    logger.warning(f"Session not found: {session_identifier}")
                    return False
            
            # Delete session directory
            import shutil
            session_path = os.path.join(self.sessions_dir, session_id)
            shutil.rmtree(session_path)
            
            # Clear current session if it was the deleted one
            if self.current_session_id == session_id:
                self.current_session_id = None
                self.current_session_data = None
            
            logger.info(f"Deleted session: {session_identifier}")
            return True
            
        except Exception as e:
            logger.error(f"Error deleting session {session_identifier}: {e}")
            return False
    
    def export_session(self, session_identifier: str, export_path: str, 
                      include_vectors: bool = True) -> bool:
        """
        Export a session to a file.
        
        Args:
            session_identifier: Session name or ID
            export_path: Path to export file
            include_vectors: Whether to include RAG vectors
            
        Returns:
            True if successful, False otherwise
        """
        try:
            session_data = self.load_session(session_identifier)
            if not session_data:
                return False
            
            # Prepare export data
            export_data = {
                "export_version": "1.0",
                "export_timestamp": datetime.now().isoformat(),
                "session_data": session_data
            }
            
            # Optionally exclude vectors to reduce file size
            if not include_vectors:
                export_data["session_data"]["rag_vectors"] = []
            
            # Write to file
            with open(export_path, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, default=str)
            
            logger.info(f"Exported session {session_identifier} to {export_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error exporting session {session_identifier}: {e}")
            return False
    
    def import_session(self, import_path: str, new_session_name: Optional[str] = None) -> Optional[str]:
        """
        Import a session from a file.
        
        Args:
            import_path: Path to import file
            new_session_name: Optional new name for the session
            
        Returns:
            New session ID or None if failed
        """
        try:
            with open(import_path, 'r', encoding='utf-8') as f:
                import_data = json.load(f)
            
            session_data = import_data.get("session_data")
            if not session_data:
                logger.error("Invalid session export file")
                return None
            
            # Create new session with imported data
            original_name = session_data["metadata"]["session_name"]
            session_name = new_session_name or f"{original_name}_imported"
            
            session_id = self.create_session(session_name)
            
            # Update with imported data
            self.current_session_data.update(session_data)
            self.current_session_data["metadata"]["session_name"] = session_name
            self.current_session_data["metadata"]["session_id"] = session_id
            
            # Save imported session
            self._save_session_data(session_id, self.current_session_data)
            
            logger.info(f"Imported session as {session_name} (ID: {session_id})")
            return session_id
            
        except Exception as e:
            logger.error(f"Error importing session from {import_path}: {e}")
            return None
    
    def get_current_session_info(self) -> Optional[Dict[str, Any]]:
        """
        Get information about the current session.
        
        Returns:
            Current session info or None
        """
        if not self.current_session_data:
            return None
        
        return {
            "id": self.current_session_id,
            "name": self.current_session_data["metadata"]["session_name"],
            "functions_count": len(self.current_session_data["analyzed_functions"]),
            "rag_vectors_count": len(self.current_session_data.get("rag_vectors", [])),
            "last_modified": self.current_session_data["metadata"]["last_modified"]
        }
    
    def _save_session_data(self, session_id: str, session_data: Dict[str, Any]) -> bool:
        """Save session data to disk."""
        try:
            session_path = os.path.join(self.sessions_dir, session_id)
            os.makedirs(session_path, exist_ok=True)
            
            # Save main session file
            session_file = os.path.join(session_path, "session.json")
            with open(session_file, 'w', encoding='utf-8') as f:
                json.dump(session_data, f, indent=2, default=str)
            
            return True
            
        except Exception as e:
            logger.error(f"Error saving session data: {e}")
            return False
    
    def _load_session_data(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Load session data from disk."""
        try:
            session_file = os.path.join(self.sessions_dir, session_id, "session.json")
            if not os.path.exists(session_file):
                return None
            
            with open(session_file, 'r', encoding='utf-8') as f:
                return json.load(f)
                
        except Exception as e:
            logger.error(f"Error loading session data: {e}")
            return None
    
    def load_session_streaming(self, session_identifier: str, 
                             progress_callback: Optional[Callable] = None) -> Optional[Dict[str, Any]]:
        """
        Load session with streaming support for large files.
        
        Args:
            session_identifier: Session name or ID
            progress_callback: Optional callback for progress updates
            
        Returns:
            Session metadata and iterator for functions
        """
        try:
            # Check file size first
            session_file = self._get_session_file_path(session_identifier)
            if not os.path.exists(session_file):
                logger.error(f"Session file not found: {session_file}")
                return None
                
            file_size = os.path.getsize(session_file) / (1024 * 1024)  # MB
            
            if file_size > 10:  # Stream if > 10MB
                logger.info(f"Large session detected ({file_size:.1f}MB), attempting streaming loader")
                
                # Try to load metadata first (lightweight)
                session_data = self._load_session_metadata(session_identifier)
                if not session_data:
                    logger.warning("Failed to load metadata, falling back to regular loading")
                    return self.load_session(session_identifier)
                
                # Return metadata with streaming iterator
                return {
                    'metadata': session_data.get('metadata', {}),
                    'streaming': True,
                    'file_size_mb': file_size,
                    'function_iterator': self._stream_functions(session_identifier),
                    'rag_vectors_iterator': self._stream_rag_vectors(session_identifier)
                }
            else:
                # Load normally for small files
                logger.info(f"Small session ({file_size:.1f}MB), using regular loader")
                return self.load_session(session_identifier)
                
        except Exception as e:
            logger.error(f"Error in streaming load for {session_identifier}: {e}")
            logger.info("Falling back to regular session loading")
            try:
                return self.load_session(session_identifier)
            except Exception as e2:
                logger.error(f"Regular loading also failed: {e2}")
                return None

    def _stream_functions(self, session_identifier: str) -> Iterator[Tuple[str, Dict[str, Any]]]:
        """Stream functions from large session file."""
        try:
            # Use chunked loading as primary method (more reliable than ijson)
            logger.info("Using chunked loading for function streaming")
            yield from self._stream_functions_chunked(session_identifier)
                
        except Exception as e:
            logger.error(f"Error streaming functions: {e}")
            # No further fallback - chunked loading should always work

    def _stream_functions_chunked(self, session_identifier: str) -> Iterator[Tuple[str, Dict[str, Any]]]:
        """Fallback chunked loading for systems without ijson."""
        try:
            session_data = self._load_session_data(session_identifier)
            if not session_data:
                return
            
            functions = session_data.get('analyzed_functions', {})
            
            # Yield in chunks of 100 functions
            chunk_size = 100
            items = list(functions.items())
            
            for i in range(0, len(items), chunk_size):
                chunk = items[i:i + chunk_size]
                for address, func_data in chunk:
                    yield address, func_data
                
                # Small delay to prevent UI freezing
                time.sleep(0.001)
                
        except Exception as e:
            logger.error(f"Error in chunked loading: {e}")

    def _stream_rag_vectors(self, session_identifier: str) -> Iterator[Dict[str, Any]]:
        """Stream RAG vectors from large session file."""
        try:
            session_file = self._get_session_file_path(session_identifier)
            
            try:
                import ijson
                with open(session_file, 'rb') as f:
                    vectors = ijson.items(f, 'rag_vectors.item')
                    for vector_data in vectors:
                        yield vector_data
            except ImportError:
                # Fallback: load in chunks
                session_data = self._load_session_data(session_identifier)
                if session_data:
                    vectors = session_data.get('rag_vectors', [])
                    for vector_data in vectors:
                        yield vector_data
                        time.sleep(0.001)  # Prevent UI freezing
                        
        except Exception as e:
            logger.error(f"Error streaming RAG vectors: {e}")

    def _load_session_metadata(self, session_identifier: str) -> Optional[Dict[str, Any]]:
        """Load only session metadata without functions/vectors."""
        try:
            session_file = self._get_session_file_path(session_identifier)
            if not os.path.exists(session_file):
                return None
            
            # For reliability, just load the full file and extract metadata
            # This is safer than trying to parse with ijson
            logger.info("Loading session metadata using regular JSON loading")
            session_data = self._load_session_data(session_identifier)
            if session_data:
                return {
                    'metadata': session_data.get('metadata', {}),
                    'ui_state': session_data.get('ui_state', {}),
                    'performance_stats': session_data.get('performance_stats', {}),
                    'functions_count': len(session_data.get('analyzed_functions', {})),
                    'vectors_count': len(session_data.get('rag_vectors', []))
                }
            return None
                
        except Exception as e:
            logger.error(f"Error loading session metadata: {e}")
            return None

    def _get_session_file_path(self, session_identifier: str) -> str:
        """Get the full path to a session file."""
        # First try as session ID
        session_file = os.path.join(self.sessions_dir, session_identifier, "session.json")
        if os.path.exists(session_file):
            return session_file
        
        # Try to find by name
        sessions = self.list_sessions()
        for session_info in sessions:
            if session_info["name"] == session_identifier:
                return os.path.join(self.sessions_dir, session_info["id"], "session.json")
        
        # Return the original attempt if not found
        return session_file 