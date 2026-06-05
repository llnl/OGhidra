"""
CAG Manager for Ollama-GhidraMCP Bridge.

This module implements the main manager for Cache-Augmented Generation
that integrates with the Bridge class.
"""

import os
import logging
from typing import Dict, Any, Optional, List, Tuple

from .vector_store import create_vector_store_from_docs
from .malware_patterns import analyze_all_patterns, list_all_patterns

logger = logging.getLogger("ollama-ghidra-bridge.cag.manager")


class CAGManager:
    """
    Manager for Cache-Augmented Generation in the Ollama-GhidraMCP Bridge.

    This class orchestrates the knowledge and session caches, and integrates
    with the Bridge to augment prompts with relevant cached information.
    """

    def __init__(self, config, session=None):
        """
        Initialize the CAG manager.

        Args:
            config: Configuration object
            session: Optional SessionMemory object
        """
        self.config = config
        self.session = session

        # Knowledge base configuration
        self.enable_kb = getattr(config, "enable_knowledge_base", True)
        self.kb_dir = getattr(config, "knowledge_base_dir", "knowledge_base")

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

        # PRIORITY: Check if we have pattern detection results to inject
        # Pattern alerts get highest priority and are prepended
        if hasattr(self, "_last_pattern_check_result"):
            pattern_result = self._last_pattern_check_result
            if pattern_result.get("has_matches", False):
                pattern_alert = pattern_result.get("summary", "")
                if pattern_alert:
                    enhanced_sections.insert(0, pattern_alert)
                    pattern_tokens = len(pattern_alert) // 4
                    total_tokens += pattern_tokens
                    logger.debug(f"Injected malware pattern alert ({pattern_tokens} tokens)")
            # Clear after use to avoid duplicate injections
            delattr(self, "_last_pattern_check_result")

        # Add relevant knowledge if enabled, available, and RAG is not disabled
        if self._ollama_available and self.vector_store and self.use_vector_store_for_prompts:
            # Adjust token limit based on the phase
            phase_token_allocation = {
                "planning": 0.4,  # 40% of token limit for planning
                "execution": 0.3,  # 30% for execution
                "analysis": 0.5,  # 50% for analysis
                None: 0.4,  # Default
            }

            knowledge_token_limit = int(token_limit * phase_token_allocation.get(phase, 0.4))

            # If the user explicitly enabled Hybrid Search in the UI, prefer hybrid retrieval
            # (keyword + semantic) for selecting knowledge snippets.
            use_hybrid = False
            try:
                bridge_ref = getattr(self, "_bridge_ref", None)
                use_hybrid = bool(getattr(bridge_ref, "grep_layer_enabled", False))
            except Exception:
                use_hybrid = False

            knowledge_section = ""
            if use_hybrid and hasattr(self.vector_store, "search_hybrid"):
                try:
                    results = self.vector_store.search_hybrid(query, top_k=3, use_keywords=True)
                    if results:
                        char_limit = knowledge_token_limit * 4
                        relevant_docs = []
                        total_chars = 0

                        for result in results:
                            doc = result.get("document", {})
                            doc_text = doc.get("text", doc.get("content", ""))
                            doc_type = doc.get("type", "unknown")
                            doc_name = doc.get("name", doc.get("title", "Unnamed"))
                            header = f"## {doc_type.upper()}: {doc_name} (hybrid)\n"

                            if total_chars + len(header) + len(doc_text) > char_limit:
                                if not relevant_docs:
                                    truncated_text = doc_text[: max(0, char_limit - len(header) - 3)] + "..."
                                    relevant_docs.append(f"{header}\n{truncated_text}")
                                break

                            relevant_docs.append(f"{header}\n{doc_text}")
                            total_chars += len(header) + len(doc_text)

                        knowledge_section = "\n\n".join(relevant_docs)
                except Exception as e:
                    logger.debug(f"Hybrid knowledge retrieval failed, falling back to semantic: {e}")

            if not knowledge_section:
                knowledge_section = self.vector_store.get_relevant_knowledge(query, knowledge_token_limit)
            if knowledge_section:
                knowledge_tokens = len(knowledge_section) // 4  # Rough approximation
                enhanced_sections.append(knowledge_section)
                total_tokens += knowledge_tokens
                logger.debug(f"Added knowledge context ({knowledge_tokens} tokens)")

        # Add session context if enabled and session memory is available
        if self.session:
            # Adjust token limit based on remaining tokens
            session_token_limit = token_limit - total_tokens

            if session_token_limit > 200:  # Only if we have enough tokens left
                pruned_context = self._prune_session_for_query(query, session_token_limit)
                session_section = self._format_session_context(pruned_context)

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
        Update the session context from the Bridge's context history.

        Args:
            context_history: List of context items from the Bridge
        """
        if not self.session:
            return

        # Context could be a list of dictionaries or a list
        if not isinstance(context_history, list):
            # Convert to list if it's not already
            logger.warning(f"Expected context_history to be a list, got {type(context_history)}")
            return

        for item in context_history:
            if isinstance(item, dict) and "role" in item and "content" in item:
                self.session.add_message(item["role"], item["content"])
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
        if not self.session:
            return

        # Update session analysis state
        if hasattr(self.session, "analysis_state"):
            self.session.analysis_state.functions_decompiled.add(name)
            if address and address != "unknown":
                self.session.analysis_state.functions_decompiled.add(address)

        # Add to tool executions for retrieval
        self.session.add_tool_execution(
            tool_name="decompile_function", parameters={"name": name, "address": address}, result=decompiled_code, success=True
        )

    def update_from_function_rename(self, old_name_or_address: str, new_name: str) -> None:
        """
        Update the session cache with a renamed function.

        Args:
            old_name_or_address: Old function name or address
            new_name: New function name
        """
        if not self.session:
            return

        # Update session analysis state
        if hasattr(self.session, "analysis_state"):
            self.session.analysis_state.functions_renamed[old_name_or_address] = new_name

        # Add to tool executions
        self.session.add_tool_execution(
            tool_name="rename_function",
            parameters={"old_name": old_name_or_address, "new_name": new_name},
            result=f"Successfully renamed to {new_name}",
            success=True,
        )

    def update_from_analysis_result(self, query: str, context: str, result: str) -> None:
        """
        Update the session cache with an analysis result.

        Args:
            query: The query that triggered the analysis
            context: Context used for the analysis
            result: Analysis result
        """
        if not self.session:
            return

        # Update analysis state cache
        if hasattr(self.session, "analysis_state"):
            self.session.analysis_state.cached_results[query] = result

        # Add to tool executions
        self.session.add_tool_execution(
            tool_name="analyze_function", parameters={"query": query, "context": context}, result=result, success=True
        )

    def save_session(self) -> None:
        """Save the session memory (handled by Bridge/MemoryManager)."""
        pass

    def find_similar_analysis(self, query: str) -> Optional[str]:
        """
        Find a similar previous analysis result.

        Args:
            query: Query to find similar analysis for

        Returns:
            Similar analysis result or None
        """
        if not self.session:
            return None

        # Search in analysis_state cached results
        if hasattr(self.session, "analysis_state") and self.session.analysis_state.cached_results:
            query_words = set(query.lower().split())
            best_match = None
            best_score = 0

            for past_query, result in self.session.analysis_state.cached_results.items():
                past_words = set(past_query.lower().split())
                if not past_words:
                    continue

                score = len(query_words.intersection(past_words)) / len(query_words.union(past_words))
                if score > 0.5 and score > best_score:
                    best_score = score
                    best_match = result
            return best_match

        return None

    def get_available_sessions(self) -> List[str]:
        """
        Get a list of available session IDs (handled by MemoryManager).

        Returns:
            List of session IDs
        """
        if self.memory_manager:
            return [s.session_id for s in self.memory_manager.get_recent_sessions(100)]
        return []

    def load_session(self, session_id: str) -> bool:
        """
        Load a session from disk (handled by Bridge/MemoryManager).

        Args:
            session_id: ID of the session to load

        Returns:
            True if successful, False otherwise
        """
        return False

    def get_debug_info(self) -> Dict[str, Any]:
        """
        Get debug information about the CAG manager.

        Returns:
            Dictionary with debug information
        """
        info = {"enable_kb": self.enable_kb, "session": None}

        # Add cache statistics if bridge is available
        if hasattr(self, "_bridge_ref") and self._bridge_ref:
            try:
                cache_stats = self._bridge_ref.get_cache_stats()
                info["cache_stats"] = cache_stats
            except Exception as e:
                logging.debug(f"Could not get cache stats: {e}")
                info["cache_stats"] = "unavailable"

        # Report vector store info regardless of enable_kb setting
        if self.vector_store:
            # Check if we have the new combined vector store
            if (
                hasattr(self.vector_store, "embeddings")
                and self.vector_store.embeddings is not None
                and len(self.vector_store.embeddings) > 0
            ):
                try:
                    # Handle both numpy arrays and lists
                    first_embedding = self.vector_store.embeddings[0]
                    if hasattr(first_embedding, "shape"):
                        dimensions = first_embedding.shape[0]
                    elif isinstance(first_embedding, (list, tuple)):
                        dimensions = len(first_embedding)
                    else:
                        dimensions = "Unknown"

                    info["vector_store"] = {
                        "document_count": len(self.vector_store.documents),
                        "vector_count": len(self.vector_store.embeddings),
                        "dimensions": dimensions,
                    }
                except Exception as e:
                    logging.warning(f"Error getting vector store dimensions: {e}")
                    info["vector_store"] = {
                        "document_count": len(self.vector_store.documents) if hasattr(self.vector_store, "documents") else 0,
                        "vector_count": len(self.vector_store.embeddings),
                        "dimensions": "Error",
                    }
            else:
                # Fallback to old format for compatibility or empty vector store
                info["vector_store"] = {
                    "document_count": len(getattr(self.vector_store, "documents", [])),
                    "vector_count": 0,
                    "dimensions": "N/A",
                    "function_signatures": len(getattr(self.vector_store, "function_signatures", [])),
                    "binary_patterns": len(getattr(self.vector_store, "binary_patterns", [])),
                    "analysis_rules": len(getattr(self.vector_store, "analysis_rules", [])),
                    "common_workflows": len(getattr(self.vector_store, "common_workflows", [])),
                }

        if self.session:
            info["session"] = {
                "session_id": getattr(self.session, "session_id", "unknown"),
                "messages": len(self.session.messages),
                "tool_executions": len(self.session.tool_executions),
                "decompiled_functions": len(self.session.analysis_state.functions_decompiled)
                if hasattr(self.session, "analysis_state")
                else 0,
                "renamed_entities": len(self.session.analysis_state.functions_renamed)
                if hasattr(self.session, "analysis_state")
                else 0,
                "analysis_results": len(self.session.analysis_state.cached_results)
                if hasattr(self.session, "analysis_state")
                else 0,
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
            documents_file = vector_db_path / "documents.json"

            # Check if all required files exist
            if not all(f.exists() for f in [vectors_file, documents_file]):
                logging.debug("Vector database files not found")
                return [], None

            # Load the vector database
            vectors = np.load(vectors_file)

            with open(documents_file, "r") as f:
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
            "workplans/malware_analysis_triage.md",
        ]

        for file_path in workplan_files:
            full_path = os.path.join(os.path.dirname(__file__), file_path)
            if os.path.exists(full_path):
                with open(full_path, "r") as f:
                    content = f.read()
                    docs.append({"text": content, "type": "workplan", "name": os.path.basename(file_path)})
            else:
                logging.warning(f"Workplan file not found: {full_path}")

        # Load knowledge base if enabled and exists (and not already in main vector DB)
        if self.enable_kb:
            kb_path = os.path.join(self.kb_dir, "knowledge_base.md")
            if os.path.exists(kb_path):
                with open(kb_path, "r") as f:
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
                    cag_embeddings_list = Bridge.get_embeddings(cag_texts)

                    if not cag_embeddings_list:
                        logging.warning("No embedding model available. Using existing vectors only.")
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

                logging.info(
                    f"Combined vector store: {len(existing_vectors)} existing + {len(cag_vectors)} CAG = {len(all_vectors)} total vectors"
                )
                return SimpleVectorStore(all_docs, all_vectors)

            except ImportError:
                logging.warning("sentence_transformers not available, using existing vectors only")
                from .vector_store import SimpleVectorStore

                return SimpleVectorStore(existing_docs, existing_vectors)

        except Exception as e:
            logging.error(f"Error creating combined vector store: {e}")
            logging.error("This may be due to vector dimension mismatch between different embedding models.")
            logging.error(
                "Ensure all vectors are created using the same embedding model (check OLLAMA_EMBEDDING_MODEL in .env)."
            )
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
        if not self.session:
            return False, ""

        # Create command signature for comparison
        param_signature = sorted(params.items()) if params else []
        current_signature = f"{command_name}({param_signature})"

        # Check recent context history for identical commands
        recent_messages = (
            self.session.messages[-context_window:] if len(self.session.messages) > context_window else self.session.messages
        )

        identical_count = 0
        similar_count = 0
        last_identical = None

        for item in reversed(recent_messages):
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
            if hasattr(self.session, "analysis_state") and func_identifier in self.session.analysis_state.functions_decompiled:
                return True, f"Function '{func_identifier}' already decompiled in this session"

        return False, ""

    def get_cached_command_result(self, command_name: str, params: Dict[str, Any]) -> Optional[str]:
        """
        Get a cached result for a command from the session memory.

        Args:
            command_name: The command name
            params: Command parameters

        Returns:
            Cached result or None if not found
        """
        if not self.session:
            return None

        # For decompiled functions, search tool executions
        if command_name == "decompile_function":
            func_identifier = params.get("name") or params.get("address", "current")
            for tool_exec in reversed(self.session.tool_executions):
                if tool_exec.tool_name == "decompile_function" and (
                    tool_exec.parameters.get("name") == func_identifier
                    or tool_exec.parameters.get("address") == func_identifier
                ):
                    return tool_exec.result

        # For analysis results, search tool executions or cached results
        if command_name == "analyze_function":
            func_identifier = params.get("name") or params.get("address", "current")
            if hasattr(self.session, "analysis_state") and func_identifier in self.session.analysis_state.cached_results:
                return self.session.analysis_state.cached_results[func_identifier]

            for tool_exec in reversed(self.session.tool_executions):
                if tool_exec.tool_name == "analyze_function" and func_identifier in str(tool_exec.parameters):
                    return tool_exec.result

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
        if not self.session:
            return ""

        memory_context = []

        # Add context about recent operations
        if len(self.session.messages) > 0:
            recent_operations = []
            for item in self.session.messages[-5:]:  # Last 5 operations
                if item.role == "tool_call":
                    recent_operations.append(item.content)

            if recent_operations:
                memory_context.append("RECENT OPERATIONS COMPLETED:")
                memory_context.extend([f"- {op}" for op in recent_operations])
                memory_context.append("")

        # Add context about available cached data
        cache_info = []

        if hasattr(self.session, "analysis_state"):
            state = self.session.analysis_state
            if state.functions_decompiled:
                func_names = list(state.functions_decompiled)[:3]
                cache_info.append(f"DECOMPILED FUNCTIONS AVAILABLE: {', '.join(func_names)}")
                if len(state.functions_decompiled) > 3:
                    cache_info.append(f"(and {len(state.functions_decompiled) - 3} more)")

            if state.functions_renamed:
                cache_info.append(f"FUNCTIONS RENAMED: {len(state.functions_renamed)}")

            if state.cached_results:
                cache_info.append(f"ANALYSIS RESULTS CACHED: {len(state.cached_results)}")

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
        if not self.session:
            return ""

        guidance = []

        if command_name == "get_current_function":
            recent_calls = sum(
                1 for item in self.session.messages[-10:] if item.role == "tool_call" and "get_current_function" in item.content
            )
            if recent_calls >= 2:
                guidance.append("⚠️  get_current_function has been called multiple times recently.")
                guidance.append("Consider using cached results or proceeding with analysis.")

        elif command_name == "decompile_function":
            func_identifier = params.get("name") or params.get("address", "current")
            if hasattr(self.session, "analysis_state") and func_identifier in self.session.analysis_state.functions_decompiled:
                guidance.append(f"✅ Function '{func_identifier}' is already decompiled and cached.")
                guidance.append("Use the cached result instead of decompiling again.")

        elif command_name == "analyze_function":
            # Check if we have similar analysis
            similar_analyses = []
            if hasattr(self.session, "analysis_state"):
                similar_analyses = [
                    q
                    for q in self.session.analysis_state.cached_results.keys()
                    if any(word in q.lower() for word in ["analyze", "function", "behavior"])
                ]

            if similar_analyses:
                guidance.append(f"📋 {len(similar_analyses)} similar analysis result(s) available in cache.")
                guidance.append("Consider if additional analysis is needed or if cached results suffice.")

        return "\n".join(guidance) if guidance else ""

    def update_command_execution(self, command_name: str, params: Dict[str, Any], result: str) -> None:
        """
        Update the session context with a completed command execution.

        Args:
            command_name: The executed command
            params: Command parameters
            result: Command result
        """
        if not self.session:
            return

        # Add the command execution to context
        param_str = ", ".join([f'{k}="{v}"' for k, v in params.items()]) if params else ""
        tool_call = f"EXECUTE: {command_name}({param_str})"
        self.session.add_message("tool_call", tool_call)

        # Add the result
        self.session.add_message("tool_result", result)

        # Update specific caches based on command type
        if command_name == "decompile_function":
            self.update_from_function_decompile(
                address=params.get("address", "unknown"), name=params.get("name") or "current", decompiled_code=result
            )

        elif command_name == "rename_function":
            self.update_from_function_rename(
                old_name_or_address=params.get("old_name", ""), new_name=params.get("new_name", "")
            )

        elif command_name == "analyze_function":
            func_identifier = params.get("name") or params.get("address", "current")
            query = f"analyze_function for {func_identifier}"
            self.update_from_analysis_result(query, str(params), result)

    def _prune_session_for_query(self, query: str, token_limit: int = 4000) -> Dict[str, Any]:
        """
        Prune the session context to fit within token limits while retaining relevant information.
        """
        pruned_cache = {"messages": [], "decompiled_functions": {}, "renamed_entities": {}, "analysis_results": []}

        if not self.session:
            return pruned_cache

        # Start with recent messages
        total_tokens = 0
        for msg in reversed(self.session.messages[-10:]):
            msg_tokens = len(msg.content) // 4
            if total_tokens + msg_tokens <= token_limit:
                pruned_cache["messages"].insert(0, msg)
                total_tokens += msg_tokens
            else:
                break

        # Add analysis results similar to the query
        if hasattr(self.session, "analysis_state"):
            query_words = set(query.lower().split())
            for past_query, result in self.session.analysis_state.cached_results.items():
                past_words = set(past_query.lower().split())
                if not past_words:
                    continue

                score = len(query_words.intersection(past_words)) / len(query_words.union(past_words))
                if score > 0.4:
                    res_tokens = len(result) // 4
                    if total_tokens + res_tokens <= token_limit:
                        pruned_cache["analysis_results"].append({"query": past_query, "result": result})
                        total_tokens += res_tokens

            # Add decompiled functions mentioned in query or recent context
            for func_name in self.session.analysis_state.functions_decompiled:
                if func_name.lower() in query.lower():
                    # Find the code in tool_executions
                    for tool_exec in reversed(self.session.tool_executions):
                        if tool_exec.tool_name == "decompile_function" and (
                            tool_exec.parameters.get("name") == func_name or tool_exec.parameters.get("address") == func_name
                        ):
                            code_tokens = len(tool_exec.result) // 4
                            if total_tokens + code_tokens <= token_limit:
                                pruned_cache["decompiled_functions"][func_name] = tool_exec.result
                                total_tokens += code_tokens
                            break

            # Add renamed entities
            pruned_cache["renamed_entities"] = self.session.analysis_state.functions_renamed

        return pruned_cache

    def _format_session_context(self, pruned_cache: Dict[str, Any]) -> str:
        """
        Format the pruned session context as a string for prompt inclusion.
        """
        sections = []

        # Format messages
        if pruned_cache["messages"] and len(pruned_cache["messages"]) > 2:
            context_section = "## Prior Context:\n\n"
            items_to_show = pruned_cache["messages"][:-1]
            for item in items_to_show[-5:]:
                role_label = item.role.value.capitalize() if hasattr(item.role, "value") else str(item.role).capitalize()
                prefix = f"**{role_label}**: "
                content = item.content[:500] + "..." if len(item.content) > 500 else item.content
                content = content.replace("\n", "\n  ")
                context_section += f"{prefix}{content}\n\n"
            sections.append(context_section)

        # Format decompiled functions
        if pruned_cache["decompiled_functions"]:
            functions_section = "## Previously Decompiled Functions:\n\n"
            for name, code in pruned_cache["decompiled_functions"].items():
                functions_section += f"### Function: {name}\n\n"
                functions_section += "```c\n"
                max_lines = 30
                code_lines = code.split("\n")
                if len(code_lines) > max_lines:
                    trimmed_code = "\n".join(code_lines[:15]) + "\n// ... [trimmed] ...\n" + "\n".join(code_lines[-15:])
                    functions_section += trimmed_code
                else:
                    functions_section += code
                functions_section += "\n```\n\n"
            sections.append(functions_section)

        # Format renamed entities
        if pruned_cache["renamed_entities"]:
            rename_section = "## Entity Renames Performed:\n\n"
            for old_name, new_name in pruned_cache["renamed_entities"].items():
                rename_section += f"* Function: `{old_name}` → `{new_name}`\n"
            sections.append(rename_section)

        # Format analysis results
        if pruned_cache["analysis_results"]:
            analysis_section = "## Previous Analyses:\n\n"
            for analysis in pruned_cache["analysis_results"]:
                analysis_section += f"### Analysis: {analysis['query'][:50]}...\n\n"
                analysis_section += f"{analysis['result']}\n\n"
            sections.append(analysis_section)

        # Format pattern detections (if any HIGH severity patterns were found)
        if self.session and hasattr(self.session.analysis_state, "pattern_detections"):
            detections = self.session.analysis_state.pattern_detections
            if detections:
                pattern_section = "## Malware Patterns Detected (HIGH Severity):\n\n"
                for address, patterns in detections.items():
                    pattern_section += f"- **{address}**: {', '.join(patterns)}\n"
                sections.append(pattern_section)

        return "\n".join(sections)

    # ========================================================================
    # MALWARE PATTERN DETECTION
    # ========================================================================

    def check_function_for_malware_patterns(
        self, decompiled_code: str, assembly: Optional[str] = None, function_address: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Check decompiled code against malware pattern library.

        This method analyzes function code for known malware techniques including:
        - API evasion (PEB walking, API hashing)
        - Process injection (remote/local)
        - Anti-analysis (debugger/VM detection)
        - Persistence mechanisms
        - Obfuscation techniques

        Args:
            decompiled_code: Decompiled C code from Ghidra
            assembly: Optional assembly code for additional pattern matching
            function_address: Optional function address for logging/reporting

        Returns:
            Dictionary with:
            {
                "has_matches": bool,
                "matches": [
                    {
                        "pattern_name": str,
                        "severity": "HIGH" | "MEDIUM" | "LOW",
                        "confidence": float (0.0-1.0),
                        "intent": str,
                        "mitre": str,
                        "indicators_found": list
                    },
                    ...
                ],
                "summary": str (formatted alert text)
            }
        """
        try:
            # Run pattern analysis
            matches = analyze_all_patterns(decompiled_code, assembly)

            if not matches:
                return {"has_matches": False, "matches": [], "summary": ""}

            # Generate formatted summary
            high_severity = [m for m in matches if m["severity"] == "HIGH"]
            summary = self._format_pattern_alert(matches, high_severity, function_address)

            # Log detection
            if high_severity:
                logger.warning(f"HIGH severity malware patterns detected in function {function_address or 'unknown'}")
                for match in high_severity:
                    logger.warning(f"  - {match['pattern_name']} (confidence: {match['confidence']:.0%})")
            else:
                logger.info(f"Malware patterns detected in function {function_address or 'unknown'}")

            return {"has_matches": True, "matches": matches, "summary": summary}

        except Exception as e:
            logger.error(f"Error checking malware patterns: {e}", exc_info=True)
            return {"has_matches": False, "matches": [], "summary": ""}

    def _format_pattern_alert(self, all_matches: List[Dict], high_severity: List[Dict], address: Optional[str]) -> str:
        """
        Format pattern matches as alert text for prompt injection.

        Args:
            all_matches: All pattern matches
            high_severity: HIGH severity matches only
            address: Optional function address

        Returns:
            Formatted alert string
        """
        lines = ["\n" + "=" * 70]
        lines.append("🚨 MALWARE PATTERN DETECTION ALERT")
        lines.append("=" * 70 + "\n")

        if address:
            lines.append(f"Function Address: {address}\n")

        # Show HIGH severity patterns first
        if high_severity:
            lines.append("🔴 HIGH SEVERITY PATTERNS:\n")
            for match in high_severity:
                lines.append(f"⚠️  **{match['pattern_name']}**")
                lines.append(f"   Confidence: {match['confidence']:.0%}")
                lines.append(f"   Intent: {match['intent']}")
                lines.append(f"   MITRE ATT&CK: {match.get('mitre', 'N/A')}")

                # Show first 3 indicators
                if match["indicators_found"]:
                    indicators_preview = match["indicators_found"][:3]
                    lines.append(f"   Evidence: {', '.join(indicators_preview)}")
                    if len(match["indicators_found"]) > 3:
                        lines.append(f"   ... and {len(match['indicators_found']) - 3} more indicators")
                lines.append("")

        # Show MEDIUM/LOW severity patterns
        medium_low = [m for m in all_matches if m["severity"] != "HIGH"]
        if medium_low:
            lines.append(f"ℹ️  Additional {len(medium_low)} pattern(s) detected (MEDIUM/LOW severity):\n")
            for match in medium_low:
                lines.append(f"   • {match['pattern_name']} ({match['severity']}, {match['confidence']:.0%} confidence)")
            lines.append("")

        lines.append("=" * 70)
        lines.append("⚡ RECOMMENDATION: Investigate this function immediately!")
        lines.append("=" * 70 + "\n")

        return "\n".join(lines)

    def get_available_patterns(self) -> List[Dict[str, str]]:
        """
        Get list of all available malware patterns.

        Returns:
            List of pattern info dictionaries
        """
        return list_all_patterns()
