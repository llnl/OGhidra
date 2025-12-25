"""
CAG Manager for Ollama-GhidraMCP Bridge.

This module implements the main manager for Cache-Augmented Generation
that integrates with the Bridge class.
"""

import os
import logging
from typing import Dict, Any, Optional, List, Tuple

from .knowledge_cache import GhidraKnowledgeCache
from .session_cache import SessionCache
from .init_dirs import ensure_cag_directories
from .vector_store import create_vector_store_from_docs

logger = logging.getLogger("ollama-ghidra-bridge.cag.manager")

class CAGManager:
    """
    Manager for Cache-Augmented Generation in the Ollama-GhidraMCP Bridge.
    
    This class orchestrates the knowledge and session caches, and integrates
    with the Bridge to augment prompts with relevant cached information.
    """
    
    def __init__(self, config):
        """
        Initialize the CAG manager.
        
        Args:
            config: Configuration object
        """
        self.config = config
        
        # Knowledge base configuration
        self.enable_kb = getattr(config, 'enable_knowledge_base', True)
        self.kb_dir = getattr(config, 'knowledge_base_dir', 'knowledge_base')
        
        # Session cache for context-aware generation
        self.session_cache = SessionCache()
        
        # Memory manager for enhanced context
        self.memory_manager = None
        try:
            from src.memory_manager import MemoryManager
            self.memory_manager = MemoryManager(config)
        except ImportError:
            logging.warning("MemoryManager not available")
        
        # Flag to control vector store usage for prompts (can be disabled via UI)
        self.use_vector_store_for_prompts = True
        
        # Lazy initialization of vector store to prevent blocking during session load
        self._vector_store = None
        self._vector_store_initialized = False
        
        # Check Ollama availability before initializing vector store
        self._ollama_available = self._check_ollama_availability()
        
        # Bridge reference for cache stats (set by Bridge during initialization)
        self._bridge_ref = None
        
        if self._ollama_available:
            logging.info("CAG Manager initialized with Ollama embeddings available")
        else:
            logging.warning("CAG Manager initialized - Ollama embeddings not available. Vector features disabled.")
    
    @property
    def vector_store(self):
        """Get vector store with lazy initialization."""
        if not self._vector_store_initialized:
            if self._ollama_available:
                self._vector_store = self._initialize_vector_store()
            else:
                logging.debug("Skipping vector store initialization - Ollama not available")
                self._vector_store = None
            self._vector_store_initialized = True
        return self._vector_store
    
    def enhance_prompt(self, query: str, phase: str = None, token_limit: int = 2000) -> str:
        """
        Enhance a prompt with relevant cached information.
        
        Args:
            query: The current query
            phase: The current phase ("planning", "execution", "analysis")
            token_limit: Maximum number of tokens to include
            
        Returns:
            Enhanced context to include in the prompt
        """
        enhanced_sections = []
        total_tokens = 0
        
        # Add relevant knowledge if enabled, available, and RAG is not disabled
        if self._ollama_available and self.vector_store and self.use_vector_store_for_prompts:
            # Adjust token limit based on the phase
            phase_token_allocation = {
                "planning": 0.4,  # 40% of token limit for planning
                "execution": 0.3,  # 30% for execution
                "analysis": 0.5,   # 50% for analysis
                None: 0.4          # Default
            }
            
            knowledge_token_limit = int(token_limit * phase_token_allocation.get(phase, 0.4))
            
            knowledge_section = self.vector_store.get_relevant_knowledge(query, knowledge_token_limit)
            if knowledge_section:
                knowledge_tokens = len(knowledge_section) // 4  # Rough approximation
                enhanced_sections.append(knowledge_section)
                total_tokens += knowledge_tokens
                logger.debug(f"Added knowledge context ({knowledge_tokens} tokens)")
        
        # Add session cache if enabled
        if self.session_cache:
            # Adjust token limit based on remaining tokens
            session_token_limit = token_limit - total_tokens
            
            if session_token_limit > 200:  # Only if we have enough tokens left
                pruned_cache = self.session_cache.prune_cache_for_query(query, session_token_limit)
                session_section = self.session_cache.format_pruned_cache(pruned_cache)
                
                if session_section:
                    session_tokens = len(session_section) // 4  # Rough approximation
                    enhanced_sections.append(session_section)
                    total_tokens += session_tokens
                    logger.debug(f"Added session context ({session_tokens} tokens)")
        
        # Combine all sections
        if enhanced_sections:
            enhanced_prompt = "\n\n".join(enhanced_sections)
            logger.info(f"Enhanced prompt with {total_tokens} tokens of additional context")
            return enhanced_prompt
        
        return ""
    
    def update_session_from_bridge_context(self, context_history: List[Dict[str, Any]]) -> None:
        """
        Update the session cache from the Bridge's context history.
        
        Args:
            context_history: List of context items from the Bridge
        """
        if not self.session_cache:
            return
        
        # Context could be a list of dictionaries or a list
        if not isinstance(context_history, list):
            # Convert to list if it's not already
            logger.warning(f"Expected context_history to be a list, got {type(context_history)}")
            return
            
        for item in context_history:
            if isinstance(item, dict) and "role" in item and "content" in item:
                self.session_cache.add_context_item(item["role"], item["content"])
            else:
                logger.warning(f"Unexpected context item format: {item}")
                continue
    
    def update_from_function_decompile(self, address: str, name: str, decompiled_code: str) -> None:
        """
        Update the session cache with a decompiled function.
        
        Args:
            address: Function address
            name: Function name
            decompiled_code: Decompiled code
        """
        if not self.session_cache:
            return
            
        self.session_cache.add_decompiled_function(address, name, decompiled_code)
    
    def update_from_function_rename(self, old_name_or_address: str, new_name: str) -> None:
        """
        Update the session cache with a renamed function.
        
        Args:
            old_name_or_address: Old function name or address
            new_name: New function name
        """
        if not self.session_cache:
            return
            
        # Determine if this is an address or name (simple heuristic)
        entity_type = "function"
        if all(c in "0123456789abcdefABCDEF" for c in old_name_or_address.replace("0x", "")):
            entity_type = "function_address"
            
        self.session_cache.add_renamed_entity(old_name_or_address, new_name, entity_type)
    
    def update_from_analysis_result(self, query: str, context: str, result: str) -> None:
        """
        Update the session cache with an analysis result.
        
        Args:
            query: The query that triggered the analysis
            context: Context used for the analysis
            result: Analysis result
        """
        if not self.session_cache:
            return
            
        self.session_cache.add_analysis_result(query, context, result)
    
    def save_session(self) -> None:
        """Save the session cache to disk."""
        if self.session_cache:
            self.session_cache.save_to_disk()
            logger.info("Session cache saved to disk")
    
    def find_similar_analysis(self, query: str) -> Optional[str]:
        """
        Find a similar previous analysis result.
        
        Args:
            query: Query to find similar analysis for
            
        Returns:
            Similar analysis result or None
        """
        if not self.session_cache:
            return None
            
        return self.session_cache.find_similar_analysis(query)
    
    def get_available_sessions(self) -> List[str]:
        """
        Get a list of available session IDs.
        
        Returns:
            List of session IDs
        """
        return SessionCache.list_available_sessions()
    
    def load_session(self, session_id: str) -> bool:
        """
        Load a session from disk.
        
        Args:
            session_id: ID of the session to load
            
        Returns:
            True if successful, False otherwise
        """
        if not self.session_cache:
            return False
            
        return self.session_cache.load_from_disk(session_id)
    
    def get_debug_info(self) -> Dict[str, Any]:
        """
        Get debug information about the CAG manager.
        
        Returns:
            Dictionary with debug information
        """
        info = {
            "enable_kb": self.enable_kb,
            "session_cache": None
        }
        
        # Add cache statistics if bridge is available
        if hasattr(self, '_bridge_ref') and self._bridge_ref:
            try:
                cache_stats = self._bridge_ref.get_cache_stats()
                info["cache_stats"] = cache_stats
            except Exception as e:
                logging.debug(f"Could not get cache stats: {e}")
                info["cache_stats"] = "unavailable"
        
        # Report vector store info regardless of enable_kb setting
        if self.vector_store:
            # Check if we have the new combined vector store
            if (hasattr(self.vector_store, 'embeddings') and 
                self.vector_store.embeddings is not None and 
                len(self.vector_store.embeddings) > 0):
                try:
                    # Handle both numpy arrays and lists
                    first_embedding = self.vector_store.embeddings[0]
                    if hasattr(first_embedding, 'shape'):
                        dimensions = first_embedding.shape[0]
                    elif isinstance(first_embedding, (list, tuple)):
                        dimensions = len(first_embedding)
                    else:
                        dimensions = 'Unknown'
                    
                    info["vector_store"] = {
                        "document_count": len(self.vector_store.documents),
                        "vector_count": len(self.vector_store.embeddings),
                        "dimensions": dimensions
                    }
                except Exception as e:
                    logging.warning(f"Error getting vector store dimensions: {e}")
                    info["vector_store"] = {
                        "document_count": len(self.vector_store.documents) if hasattr(self.vector_store, 'documents') else 0,
                        "vector_count": len(self.vector_store.embeddings),
                        "dimensions": 'Error'
                    }
            else:
                # Fallback to old format for compatibility or empty vector store
                info["vector_store"] = {
                    "document_count": len(getattr(self.vector_store, 'documents', [])),
                    "vector_count": 0,
                    "dimensions": 'N/A',
                    "function_signatures": len(getattr(self.vector_store, 'function_signatures', [])),
                    "binary_patterns": len(getattr(self.vector_store, 'binary_patterns', [])),
                    "analysis_rules": len(getattr(self.vector_store, 'analysis_rules', [])),
                    "common_workflows": len(getattr(self.vector_store, 'common_workflows', []))
                }
            
        if self.session_cache:
            info["session_cache"] = {
                "session_id": self.session_cache.session_id,
                "context_history": len(self.session_cache.context_history),
                "decompiled_functions": len(self.session_cache.decompiled_functions),
                "renamed_entities": len(self.session_cache.renamed_entities),
                "analysis_results": len(self.session_cache.analysis_results)
            }
            
        return info

    def _initialize_vector_store(self):
        """Initialize the vector store with context documents."""
        try:
            # Load existing vector database and CAG-specific documents
            existing_docs, existing_vectors = self._load_existing_vector_db()
            cag_docs = self._load_cag_documents()
            
            # Combine all documents
            all_docs = existing_docs + cag_docs
            
            if not all_docs:
                logging.warning("No documents available for vector store")
                return None
            
            # If we have existing vectors, we need to create vectors for new CAG docs and combine
            if existing_vectors is not None and len(existing_vectors) > 0 and len(cag_docs) > 0:
                logging.info(f"Combining {len(existing_vectors)} existing vectors with {len(cag_docs)} CAG documents")
                return self._create_combined_vector_store(existing_docs, existing_vectors, cag_docs)
            elif existing_vectors is not None and len(existing_vectors) > 0:
                # Only existing vectors
                from .vector_store import SimpleVectorStore
                logging.info(f"Loaded vector store with {len(existing_vectors)} existing vectors")
                return SimpleVectorStore(existing_docs, existing_vectors)
            else:
                # Create new vectors for all documents
                vector_store = create_vector_store_from_docs(all_docs)
                logging.info(f"Created new vector store with {len(all_docs)} documents")
                return vector_store
            
        except Exception as e:
            logging.error(f"Error initializing vector store: {str(e)}")
            return None
    
    def _load_existing_vector_db(self):
        """Load existing vector database if available."""
        try:
            from pathlib import Path
            import json
            import numpy as np
            
            vector_db_path = Path("data/vector_db")
            vectors_file = vector_db_path / "vectors.npy"
            metadata_file = vector_db_path / "metadata.json"
            documents_file = vector_db_path / "documents.json"
            
            # Check if all required files exist
            if not all(f.exists() for f in [vectors_file, metadata_file, documents_file]):
                logging.debug("Vector database files not found")
                return [], None
            
            # Load the vector database
            vectors = np.load(vectors_file)
            
            with open(metadata_file, 'r') as f:
                metadata = json.load(f)
            
            with open(documents_file, 'r') as f:
                documents = json.load(f)
            
            logging.info(f"Successfully loaded vector database with {len(vectors)} vectors")
            return documents, vectors
            
        except Exception as e:
            logging.warning(f"Failed to load existing vector database: {e}")
            return [], None
    
    def _load_cag_documents(self):
        """Load CAG-specific documents (workplans, etc.)."""
        docs = []
        
        # Load workplans
        workplan_files = [
            "workplans/knowledge_capture.md", 
            "workplans/progressive_analysis.md",
            "workplans/ghidra_tasks.md",
            "workplans/malware_analysis_triage.md"
        ]
        
        for file_path in workplan_files:
            full_path = os.path.join(os.path.dirname(__file__), file_path)
            if os.path.exists(full_path):
                with open(full_path, 'r') as f:
                    content = f.read()
                    docs.append({"text": content, "type": "workplan", "name": os.path.basename(file_path)})
            else:
                logging.warning(f"Workplan file not found: {full_path}")

        # Load knowledge base if enabled and exists (and not already in main vector DB)
        if self.enable_kb:
            kb_path = os.path.join(self.kb_dir, "knowledge_base.md")
            if os.path.exists(kb_path):
                with open(kb_path, 'r') as f:
                    content = f.read()
                    docs.append({"text": content, "type": "knowledge_base", "name": "knowledge_base.md"})
            else:
                logging.warning(f"Knowledge base file not found: {kb_path}")
        
        logging.info(f"Loaded {len(docs)} CAG-specific documents")
        return docs
    
    def _create_combined_vector_store(self, existing_docs, existing_vectors, cag_docs):
        """Create a combined vector store from existing vectors and new CAG documents."""
        try:
            import numpy as np
            
            if not cag_docs:
                # No new docs to add, just use existing
                from .vector_store import SimpleVectorStore
                return SimpleVectorStore(existing_docs, existing_vectors)
            
            # Create vectors for CAG documents using Ollama
            try:
                # Use Ollama embeddings from Bridge class
                try:
                    from src.bridge import Bridge
                    
                    cag_texts = [doc["text"] for doc in cag_docs]
                    cag_embeddings_list = Bridge.get_ollama_embeddings(cag_texts)
                    
                    if not cag_embeddings_list:
                        logging.warning("No Ollama embedding model available. Using existing vectors only.")
                        from .vector_store import SimpleVectorStore
                        return SimpleVectorStore(existing_docs, existing_vectors)
                    
                    # Convert to numpy arrays
                    cag_vectors = [np.array(emb) for emb in cag_embeddings_list]
                    
                except ImportError:
                    logging.warning("Bridge not available for embeddings. Using existing vectors only.")
                    from .vector_store import SimpleVectorStore
                    return SimpleVectorStore(existing_docs, existing_vectors)
                
                # Combine documents and vectors
                all_docs = existing_docs + cag_docs
                all_vectors = existing_vectors + cag_vectors
                
                from .vector_store import SimpleVectorStore
                logging.info(f"Combined vector store: {len(existing_vectors)} existing + {len(cag_vectors)} CAG = {len(all_vectors)} total vectors")
                return SimpleVectorStore(all_docs, all_vectors)
                
            except ImportError:
                logging.warning("sentence_transformers not available, using existing vectors only")
                from .vector_store import SimpleVectorStore
                return SimpleVectorStore(existing_docs, existing_vectors)
                
        except Exception as e:
            logging.error(f"Error creating combined vector store: {e}")
            logging.error("This may be due to vector dimension mismatch between different embedding models.")
            logging.error("Ensure all vectors are created using the same embedding model (check OLLAMA_EMBEDDING_MODEL in .env).")
            # Fallback to existing vectors only
            from .vector_store import SimpleVectorStore
            return SimpleVectorStore(existing_docs, existing_vectors)
    
    def _check_ollama_availability(self) -> bool:
        """Check if Ollama server is available for embeddings."""
        try:
            import requests
            from src.config import get_config
            config = get_config()
            ollama_url = str(config.ollama.base_url)
            response = requests.get(f"{ollama_url}/api/tags", timeout=2)
            if response.status_code == 200:
                # Basic server check passed, assume embeddings will work
                # Don't test actual embeddings during init to avoid circular dependencies
                return True
            return False
        except Exception:
            return False
    
    def should_skip_command(self, command_name: str, params: Dict[str, Any], context_window: int = 10) -> Tuple[bool, str]:
        """
        Determine if a command should be skipped based on recent execution history.
        
        Args:
            command_name: The command to check
            params: Command parameters
            context_window: Number of recent context items to check
            
        Returns:
            Tuple of (should_skip, reason)
        """
        if not self.session_cache:
            return False, ""
        
        # Create command signature for comparison
        param_signature = sorted(params.items()) if params else []
        current_signature = f"{command_name}({param_signature})"
        
        # Check recent context history for identical commands
        recent_context = self.session_cache.context_history[-context_window:] if len(self.session_cache.context_history) > context_window else self.session_cache.context_history
        
        identical_count = 0
        similar_count = 0
        last_identical = None
        
        for item in reversed(recent_context):
            if item.role == "tool_call":
                if current_signature in item.content:
                    identical_count += 1
                    if not last_identical:
                        last_identical = item
                elif command_name in item.content:
                    similar_count += 1
        
        # Skip if we've seen this exact command recently
        if identical_count >= 1:
            return True, f"Identical command '{current_signature}' executed {identical_count} time(s) recently"
        
        # For get_current_function, be more lenient but still check for excessive calls
        if command_name == "get_current_function" and similar_count >= 3:
            return True, f"get_current_function called {similar_count} times recently - likely redundant"
        
        # For decompile_function, check if we already have this function cached
        if command_name == "decompile_function":
            func_identifier = params.get("name") or params.get("address", "current")
            if func_identifier in self.session_cache.decompiled_functions:
                return True, f"Function '{func_identifier}' already decompiled in this session"
        
        return False, ""
    
    def get_cached_command_result(self, command_name: str, params: Dict[str, Any]) -> Optional[str]:
        """
        Get a cached result for a command from the session cache.
        
        Args:
            command_name: The command name
            params: Command parameters
            
        Returns:
            Cached result or None if not found
        """
        if not self.session_cache:
            return None
        
        # For decompiled functions, check our cache
        if command_name == "decompile_function":
            func_identifier = params.get("name") or params.get("address", "current")
            if func_identifier in self.session_cache.decompiled_functions:
                func_data = self.session_cache.decompiled_functions[func_identifier]
                return func_data.decompiled_code
        
        # For analysis results, find similar queries
        if command_name == "analyze_function":
            func_identifier = params.get("name") or params.get("address", "current")
            # Look for analysis results related to this function
            for analysis in self.session_cache.analysis_results:
                if func_identifier in analysis.query or func_identifier in analysis.context:
                    return analysis.result
        
        return None
    
    def enhance_prompt_with_memory_context(self, query: str, command_name: str = None, params: Dict[str, Any] = None) -> str:
        """
        Enhance a prompt with relevant memory context to prevent redundant operations.
        
        Args:
            query: The original query
            command_name: Command being considered (optional)
            params: Command parameters (optional)
            
        Returns:
            Enhanced prompt with memory context
        """
        if not self.session_cache:
            return ""
        
        memory_context = []
        
        # Add context about recent operations
        if len(self.session_cache.context_history) > 0:
            recent_operations = []
            for item in self.session_cache.context_history[-5:]:  # Last 5 operations
                if item.role == "tool_call":
                    recent_operations.append(item.content)
            
            if recent_operations:
                memory_context.append("RECENT OPERATIONS COMPLETED:")
                memory_context.extend([f"- {op}" for op in recent_operations])
                memory_context.append("")
        
        # Add context about available cached data
        cache_info = []
        
        if self.session_cache.decompiled_functions:
            func_names = list(self.session_cache.decompiled_functions.keys())[:3]  # Show first 3
            cache_info.append(f"DECOMPILED FUNCTIONS AVAILABLE: {', '.join(func_names)}")
            if len(self.session_cache.decompiled_functions) > 3:
                cache_info.append(f"(and {len(self.session_cache.decompiled_functions) - 3} more)")
        
        if self.session_cache.renamed_entities:
            rename_count = len(self.session_cache.renamed_entities)
            cache_info.append(f"FUNCTIONS RENAMED: {rename_count}")
        
        if self.session_cache.analysis_results:
            analysis_count = len(self.session_cache.analysis_results)
            cache_info.append(f"ANALYSIS RESULTS CACHED: {analysis_count}")
        
        if cache_info:
            memory_context.append("CACHED DATA AVAILABLE:")
            memory_context.extend([f"- {info}" for info in cache_info])
            memory_context.append("")
        
        # Add specific guidance based on the command being considered
        if command_name:
            guidance = self._get_command_specific_guidance(command_name, params)
            if guidance:
                memory_context.append("MEMORY GUIDANCE:")
                memory_context.append(guidance)
                memory_context.append("")
        
        if memory_context:
            memory_context.insert(0, "=== MEMORY CONTEXT ===")
            memory_context.append("=== END MEMORY CONTEXT ===")
            return "\n".join(memory_context)
        
        return ""
    
    def _get_command_specific_guidance(self, command_name: str, params: Dict[str, Any]) -> str:
        """
        Get command-specific guidance based on memory state.
        
        Args:
            command_name: The command name
            params: Command parameters
            
        Returns:
            Guidance string
        """
        if not self.session_cache:
            return ""
        
        guidance = []
        
        if command_name == "get_current_function":
            recent_calls = sum(1 for item in self.session_cache.context_history[-10:] 
                             if item.role == "tool_call" and "get_current_function" in item.content)
            if recent_calls >= 2:
                guidance.append("⚠️  get_current_function has been called multiple times recently.")
                guidance.append("Consider using cached results or proceeding with analysis.")
        
        elif command_name == "decompile_function":
            func_identifier = params.get("name") or params.get("address", "current")
            if func_identifier in self.session_cache.decompiled_functions:
                guidance.append(f"✅ Function '{func_identifier}' is already decompiled and cached.")
                guidance.append("Use the cached result instead of decompiling again.")
        
        elif command_name == "analyze_function":
            # Check if we have similar analysis
            similar_analyses = [a for a in self.session_cache.analysis_results 
                              if any(word in a.query.lower() for word in ["analyze", "function", "behavior"])]
            if similar_analyses:
                guidance.append(f"📋 {len(similar_analyses)} similar analysis result(s) available in cache.")
                guidance.append("Consider if additional analysis is needed or if cached results suffice.")
        
        return "\n".join(guidance) if guidance else ""
    
    def update_command_execution(self, command_name: str, params: Dict[str, Any], result: str) -> None:
        """
        Update the session cache with a completed command execution.
        
        Args:
            command_name: The executed command
            params: Command parameters
            result: Command result
        """
        if not self.session_cache:
            return
        
        # Add the command execution to context
        param_str = ", ".join([f'{k}="{v}"' for k, v in params.items()]) if params else ""
        tool_call = f"EXECUTE: {command_name}({param_str})"
        self.session_cache.add_context_item("tool_call", tool_call)
        
        # Add the result
        self.session_cache.add_context_item("tool_result", result)
        
        # Update specific caches based on command type
        if command_name == "decompile_function":
            func_identifier = params.get("name") or params.get("address", "current")
            if func_identifier and func_identifier != "current":
                self.session_cache.add_decompiled_function(
                    address=params.get("address", "unknown"),
                    name=func_identifier,
                    decompiled_code=result
                )
        
        elif command_name == "rename_function":
            old_name = params.get("old_name", "")
            new_name = params.get("new_name", "")
            if old_name and new_name:
                self.session_cache.add_renamed_entity(old_name, new_name, "function")
        
        elif command_name == "analyze_function":
            func_identifier = params.get("name") or params.get("address", "current")
            query = f"analyze_function for {func_identifier}"
            self.session_cache.add_analysis_result(query, str(params), result) 