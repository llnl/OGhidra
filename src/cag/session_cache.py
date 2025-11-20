"""
Session Cache for Ghidra Bridge - Cache-Augmented Generation (CAG)

This module implements a session cache that persists relevant information across
a session, such as conversation history and previous analysis results.
"""

import os
import json
import time
import logging
from typing import Dict, List, Set, Optional, Any, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger("ollama-ghidra-bridge.cag.session")

@dataclass
class DecompiledFunction:
    """Information about a decompiled function."""
    address: str
    name: str
    decompiled_code: str
    timestamp: float = field(default_factory=time.time)
    token_count: int = 0

@dataclass
class RenamedEntity:
    """Information about a renamed entity."""
    old_address_or_name: str
    new_name: str
    entity_type: str  # "function", "variable", "structure", etc.
    timestamp: float = field(default_factory=time.time)

@dataclass
class AnalysisResult:
    """Information about an analysis result."""
    query: str
    context: str
    result: str
    timestamp: float = field(default_factory=time.time)
    token_count: int = 0

@dataclass
class ContextItem:
    """A single item in the conversation context."""
    role: str  # "user", "assistant", "tool_call", "tool_result"
    content: str
    timestamp: float = field(default_factory=time.time)
    token_count: int = 0

class SessionCache:
    """Cache that persists relevant information across a session."""
    
    def __init__(self, session_id: str = None, cache_dir: str = "ghidra_session_cache"):
        """
        Initialize the session cache.
        
        Args:
            session_id: Unique identifier for the session. If None, a timestamp-based ID is used.
            cache_dir: Directory to store cache files
        """
        self.session_id = session_id or f"session_{int(time.time())}"
        self.cache_dir = os.path.join(cache_dir, self.session_id)
        
        self.context_history: List[ContextItem] = []
        self.decompiled_functions: Dict[str, DecompiledFunction] = {}  # Keyed by address
        self.renamed_entities: Dict[str, RenamedEntity] = {}  # Keyed by old_address_or_name
        self.analysis_results: List[AnalysisResult] = []
        
        # Track seen addresses and names to avoid duplicates
        self.seen_addresses: Set[str] = set()
        self.seen_names: Set[str] = set()
        
        # Ensure cache directory exists
        os.makedirs(self.cache_dir, exist_ok=True)
        
        # Initialize logger
        self.logger = logging.getLogger("ollama-ghidra-bridge.cag.session")
        self.logger.info(f"Session cache initialized with ID: {self.session_id}")
    
    def add_context_item(self, role: str, content: str) -> None:
        """
        Add an item to the conversation context.
        
        Args:
            role: Role of the speaker ("user", "assistant", "tool_call", "tool_result")
            content: Content of the message
        """
        # Simple estimation of token count
        token_count = len(content) // 4  # Rough approximation: ~4 chars per token
        
        item = ContextItem(
            role=role,
            content=content,
            timestamp=time.time(),
            token_count=token_count
        )
        
        self.context_history.append(item)
        self.logger.debug(f"Added context item with role '{role}' ({token_count} tokens)")
    
    def add_decompiled_function(self, address: str, name: str, decompiled_code: str) -> None:
        """
        Add a decompiled function to the cache.
        
        Args:
            address: Function address
            name: Function name
            decompiled_code: Decompiled code
        """
        # Skip if we've already seen this address to avoid duplication
        if address in self.seen_addresses:
            self.logger.debug(f"Function at address {address} already in cache, updating")
        
        token_count = len(decompiled_code) // 4  # Rough approximation
        
        func = DecompiledFunction(
            address=address,
            name=name,
            decompiled_code=decompiled_code,
            timestamp=time.time(),
            token_count=token_count
        )
        
        self.decompiled_functions[address] = func
        self.seen_addresses.add(address)
        self.seen_names.add(name)
        
        self.logger.debug(f"Added decompiled function {name} at {address} ({token_count} tokens)")
    
    def add_renamed_entity(self, old_address_or_name: str, new_name: str, entity_type: str) -> None:
        """
        Add a renamed entity to the cache.
        
        Args:
            old_address_or_name: Old address or name
            new_name: New name
            entity_type: Type of entity ("function", "variable", "structure", etc.)
        """
        entity = RenamedEntity(
            old_address_or_name=old_address_or_name,
            new_name=new_name,
            entity_type=entity_type,
            timestamp=time.time()
        )
        
        self.renamed_entities[old_address_or_name] = entity
        self.seen_names.add(new_name)
        
        self.logger.debug(f"Added renamed {entity_type}: {old_address_or_name} -> {new_name}")
    
    def add_analysis_result(self, query: str, context: str, result: str) -> None:
        """
        Add an analysis result to the cache.
        
        Args:
            query: The query that triggered the analysis
            context: Context used for the analysis
            result: Analysis result
        """
        token_count = len(result) // 4  # Rough approximation
        
        analysis = AnalysisResult(
            query=query,
            context=context,
            result=result,
            timestamp=time.time(),
            token_count=token_count
        )
        
        self.analysis_results.append(analysis)
        self.logger.debug(f"Added analysis result for query: {query[:50]}... ({token_count} tokens)")
    
    def find_similar_analysis(self, query: str, threshold: float = 0.7) -> Optional[str]:
        """
        Find a similar previous analysis result.
        
        This is a simple implementation using word overlap. For production, consider
        using proper semantic search with embeddings.
        
        Args:
            query: Query to find similar analysis for
            threshold: Similarity threshold (0-1)
            
        Returns:
            Similar analysis result or None
        """
        if not self.analysis_results:
            return None
            
        query_words = set(query.lower().split())
        best_match = None
        best_score = 0
        
        for analysis in self.analysis_results:
            past_query_words = set(analysis.query.lower().split())
            
            # Word overlap score
            if not past_query_words:
                continue
                
            score = len(query_words.intersection(past_query_words)) / len(query_words.union(past_query_words))
            
            if score > threshold and score > best_score:
                best_score = score
                best_match = analysis
        
        if best_match:
            return best_match.result
            
        return None
    
    def get_function_by_name(self, function_name: str) -> Optional[DecompiledFunction]:
        """
        Get a function by name.
        
        Args:
            function_name: Name of the function
            
        Returns:
            DecompiledFunction object or None
        """
        for address, func in self.decompiled_functions.items():
            if func.name == function_name:
                return func
                
        return None
    
    def get_function_by_address(self, address: str) -> Optional[DecompiledFunction]:
        """
        Get a function by address.
        
        Args:
            address: Address of the function
            
        Returns:
            DecompiledFunction object or None
        """
        return self.decompiled_functions.get(address)
    
    def get_renamed_entity(self, old_address_or_name: str) -> Optional[RenamedEntity]:
        """
        Get a renamed entity by old address or name.
        
        Args:
            old_address_or_name: Old address or name
            
        Returns:
            RenamedEntity object or None
        """
        return self.renamed_entities.get(old_address_or_name)
    
    def get_context_history(self, limit: int = 5) -> List[ContextItem]:
        """
        Get recent context history.
        
        Args:
            limit: Maximum number of items to return
            
        Returns:
            List of recent context items
        """
        return self.context_history[-limit:] if self.context_history else []
    
    def prune_cache_for_query(self, query: str, token_limit: int = 4000) -> Dict[str, Any]:
        """
        Prune the cache to fit within token limits while retaining relevant information.
        
        Args:
            query: The current query
            token_limit: Maximum tokens to include
            
        Returns:
            Dictionary with pruned cache items
        """
        pruned_cache = {
            "context_history": [],
            "decompiled_functions": {},
            "renamed_entities": {},
            "analysis_results": []
        }
        
        # Start with recent context items
        total_tokens = 0
        for item in reversed(self.context_history[-10:]):  # Last 10 items
            if total_tokens + item.token_count <= token_limit:
                pruned_cache["context_history"].insert(0, item)  # Keep original order
                total_tokens += item.token_count
            else:
                break
                
        # Add analysis results semantically similar to the query
        query_words = set(query.lower().split())
        for analysis in sorted(self.analysis_results, key=lambda a: a.timestamp, reverse=True):
            # Calculate relevance score based on word overlap
            past_query_words = set(analysis.query.lower().split())
            if past_query_words:
                score = len(query_words.intersection(past_query_words)) / len(query_words.union(past_query_words))
                
                # Only include highly relevant items
                if score > 0.3 and total_tokens + analysis.token_count <= token_limit:
                    pruned_cache["analysis_results"].append(analysis)
                    total_tokens += analysis.token_count
        
        # Add recently decompiled functions mentioned in the query
        for address, func in sorted(self.decompiled_functions.items(), key=lambda x: x[1].timestamp, reverse=True):
            # Check if function name is mentioned in query
            if func.name.lower() in query.lower():
                # Prioritize mentioned functions
                if total_tokens + func.token_count <= token_limit:
                    pruned_cache["decompiled_functions"][address] = func
                    total_tokens += func.token_count
        
        # Add additional decompiled functions if space allows
        for address, func in sorted(self.decompiled_functions.items(), key=lambda x: x[1].timestamp, reverse=True):
            if address not in pruned_cache["decompiled_functions"]:
                if total_tokens + func.token_count <= token_limit:
                    pruned_cache["decompiled_functions"][address] = func
                    total_tokens += func.token_count
        
        # Add renamed entities (these are small, so include all if possible)
        for old_name, entity in self.renamed_entities.items():
            # Estimate token count (renamed entities are small)
            entity_tokens = 20
            if total_tokens + entity_tokens <= token_limit:
                pruned_cache["renamed_entities"][old_name] = entity
                total_tokens += entity_tokens
        
        self.logger.info(f"Pruned cache for query. Using {total_tokens}/{token_limit} tokens. "
                        f"Includes {len(pruned_cache['context_history'])} context items, "
                        f"{len(pruned_cache['decompiled_functions'])} functions, "
                        f"{len(pruned_cache['renamed_entities'])} renamed entities, "
                        f"{len(pruned_cache['analysis_results'])} analysis results.")
        
        return pruned_cache
    
    def format_pruned_cache(self, pruned_cache: Dict[str, Any]) -> str:
        """
        Format the pruned cache for inclusion in the prompt.
        
        Args:
            pruned_cache: Pruned cache dictionary from prune_cache_for_query
            
        Returns:
            Formatted string for prompt inclusion
        """
        sections = []
        
        # Format context history
        if pruned_cache["context_history"]:
            context_section = "## Recent Conversation:\n\n"
            for item in pruned_cache["context_history"]:
                prefix = f"**{item.role.capitalize()}**: "
                content = item.content.replace("\n", "\n  ")  # Indent for readability
                context_section += f"{prefix}{content}\n\n"
            sections.append(context_section)
        
        # Format decompiled functions
        if pruned_cache["decompiled_functions"]:
            functions_section = "## Previously Decompiled Functions:\n\n"
            for address, func in pruned_cache["decompiled_functions"].items():
                functions_section += f"### Function: {func.name} (address: {func.address})\n\n"
                functions_section += "```c\n"
                # Trim long decompilations to avoid bloating the context
                max_lines = 30
                code_lines = func.decompiled_code.split("\n")
                if len(code_lines) > max_lines:
                    top_lines = code_lines[:max_lines//2]
                    bottom_lines = code_lines[-max_lines//2:]
                    trimmed_code = "\n".join(top_lines) + "\n// ... [trimmed] ...\n" + "\n".join(bottom_lines)
                    functions_section += trimmed_code
                else:
                    functions_section += func.decompiled_code
                functions_section += "\n```\n\n"
            sections.append(functions_section)
        
        # Format renamed entities
        if pruned_cache["renamed_entities"]:
            rename_section = "## Entity Renames Performed:\n\n"
            for old_name, entity in pruned_cache["renamed_entities"].items():
                rename_section += f"* {entity.entity_type.capitalize()}: `{old_name}` → `{entity.new_name}`\n"
            sections.append(rename_section)
        
        # Format analysis results
        if pruned_cache["analysis_results"]:
            analysis_section = "## Previous Analyses:\n\n"
            for i, analysis in enumerate(pruned_cache["analysis_results"]):
                analysis_section += f"### Analysis {i+1}: {analysis.query[:50]}...\n\n"
                analysis_section += f"{analysis.result}\n\n"
            sections.append(analysis_section)
        
        return "\n".join(sections)
    
    def format_entire_cache(self) -> str:
        """
        Format the entire cache as a string (for debugging).
        
        Returns:
            Formatted string representation of the entire cache
        """
        output = []
        
        # Format session info
        output.append(f"# Session Cache (ID: {self.session_id})")
        output.append(f"Created at: {time.ctime()}")
        output.append(f"Cache directory: {self.cache_dir}")
        output.append("")
        
        # Format context history
        output.append(f"## Context History ({len(self.context_history)} items)")
        for i, item in enumerate(self.context_history):
            output.append(f"{i+1}. Role: {item.role}, Timestamp: {time.ctime(item.timestamp)}")
            output.append(f"   Content: {item.content[:50]}...")
        output.append("")
        
        # Format decompiled functions
        output.append(f"## Decompiled Functions ({len(self.decompiled_functions)} items)")
        for address, func in self.decompiled_functions.items():
            output.append(f"* {func.name} ({address}), Timestamp: {time.ctime(func.timestamp)}")
            code_preview = func.decompiled_code.replace("\n", " ")[:50]
            output.append(f"  Code: {code_preview}...")
        output.append("")
        
        # Format renamed entities
        output.append(f"## Renamed Entities ({len(self.renamed_entities)} items)")
        for old_name, entity in self.renamed_entities.items():
            output.append(f"* {entity.entity_type}: {old_name} -> {entity.new_name}, "
                        f"Timestamp: {time.ctime(entity.timestamp)}")
        output.append("")
        
        # Format analysis results
        output.append(f"## Analysis Results ({len(self.analysis_results)} items)")
        for i, analysis in enumerate(self.analysis_results):
            output.append(f"{i+1}. Query: {analysis.query[:50]}...")
            output.append(f"   Result: {analysis.result[:50]}...")
            output.append(f"   Timestamp: {time.ctime(analysis.timestamp)}")
        
        return "\n".join(output)
    
    def save_to_disk(self) -> None:
        """Save the session cache to disk."""
        try:
            # Save context history
            context_path = os.path.join(self.cache_dir, "context_history.json")
            with open(context_path, 'w', encoding='utf-8') as f:
                json.dump([vars(item) for item in self.context_history], f, indent=2)
            
            # Save decompiled functions
            functions_path = os.path.join(self.cache_dir, "decompiled_functions.json")
            with open(functions_path, 'w', encoding='utf-8') as f:
                json.dump({addr: vars(func) for addr, func in self.decompiled_functions.items()}, f, indent=2)
            
            # Save renamed entities
            entities_path = os.path.join(self.cache_dir, "renamed_entities.json")
            with open(entities_path, 'w', encoding='utf-8') as f:
                json.dump({old: vars(entity) for old, entity in self.renamed_entities.items()}, f, indent=2)
            
            # Save analysis results
            results_path = os.path.join(self.cache_dir, "analysis_results.json")
            with open(results_path, 'w', encoding='utf-8') as f:
                json.dump([vars(analysis) for analysis in self.analysis_results], f, indent=2)
            
            # Save metadata
            metadata_path = os.path.join(self.cache_dir, "metadata.json")
            with open(metadata_path, 'w', encoding='utf-8') as f:
                json.dump({
                    "session_id": self.session_id,
                    "saved_at": time.time(),
                    "item_counts": {
                        "context_history": len(self.context_history),
                        "decompiled_functions": len(self.decompiled_functions),
                        "renamed_entities": len(self.renamed_entities),
                        "analysis_results": len(self.analysis_results)
                    }
                }, f, indent=2)
                
            self.logger.info(f"Session cache saved to {self.cache_dir}")
        except Exception as e:
            self.logger.error(f"Error saving session cache to disk: {str(e)}")
    
    def load_from_disk(self, session_id: str) -> bool:
        """
        Load a session cache from disk.
        
        Args:
            session_id: ID of the session to load
            
        Returns:
            True if successful, False otherwise
        """
        try:
            self.session_id = session_id
            self.cache_dir = os.path.join(self.cache_dir.split(self.session_id)[0], self.session_id)
            
            if not os.path.exists(self.cache_dir):
                self.logger.warning(f"Session directory does not exist: {self.cache_dir}")
                return False
            
            # Load context history
            context_path = os.path.join(self.cache_dir, "context_history.json")
            if os.path.exists(context_path):
                with open(context_path, 'r', encoding='utf-8') as f:
                    self.context_history = [ContextItem(**item) for item in json.load(f)]
            
            # Load decompiled functions
            functions_path = os.path.join(self.cache_dir, "decompiled_functions.json")
            if os.path.exists(functions_path):
                with open(functions_path, 'r', encoding='utf-8') as f:
                    self.decompiled_functions = {addr: DecompiledFunction(**func) 
                                              for addr, func in json.load(f).items()}
                    self.seen_addresses = set(self.decompiled_functions.keys())
                    self.seen_names = set(func.name for func in self.decompiled_functions.values())
            
            # Load renamed entities
            entities_path = os.path.join(self.cache_dir, "renamed_entities.json")
            if os.path.exists(entities_path):
                with open(entities_path, 'r', encoding='utf-8') as f:
                    self.renamed_entities = {old: RenamedEntity(**entity) 
                                          for old, entity in json.load(f).items()}
                    # Add renamed entities to seen names
                    self.seen_names.update(entity.new_name for entity in self.renamed_entities.values())
            
            # Load analysis results
            results_path = os.path.join(self.cache_dir, "analysis_results.json")
            if os.path.exists(results_path):
                with open(results_path, 'r', encoding='utf-8') as f:
                    self.analysis_results = [AnalysisResult(**analysis) for analysis in json.load(f)]
            
            self.logger.info(f"Loaded session cache for {self.session_id} with "
                           f"{len(self.context_history)} context items, "
                           f"{len(self.decompiled_functions)} functions, "
                           f"{len(self.renamed_entities)} renamed entities, and "
                           f"{len(self.analysis_results)} analysis results")
            return True
        except Exception as e:
            self.logger.error(f"Error loading session cache: {str(e)}")
            return False
    
    def list_available_sessions() -> List[str]:
        """
        List available session IDs.
        
        Returns:
            List of available session IDs
        """
        sessions = []
        cache_dir = "ghidra_session_cache"
        
        if os.path.exists(cache_dir):
            for session_id in os.listdir(cache_dir):
                if os.path.isdir(os.path.join(cache_dir, session_id)):
                    sessions.append(session_id)
        
        return sessions 