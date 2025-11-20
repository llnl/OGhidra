"""
Knowledge Cache for Ghidra Bridge - Cache-Augmented Generation (CAG)

This module implements a persistent cache for domain knowledge related to Ghidra,
binary analysis, and common function patterns.
"""

import os
import json
import logging
import hashlib
from typing import Dict, List, Set, Optional, Any, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger("ollama-ghidra-bridge.cag.knowledge")

@dataclass
class FunctionSignature:
    """Information about a function signature."""
    name: str
    description: str
    parameters: Dict[str, str] = field(default_factory=dict)
    return_type: str = ""
    common_locations: List[str] = field(default_factory=list)
    related_functions: List[str] = field(default_factory=list)
    token_count: int = 0

@dataclass
class BinaryPattern:
    """Information about a common binary pattern."""
    name: str
    description: str
    byte_pattern: str
    architecture: str
    token_count: int = 0

@dataclass
class AnalysisRule:
    """Heuristic rules for analysis."""
    name: str
    description: str
    condition: str
    action: str
    examples: List[str] = field(default_factory=list)
    token_count: int = 0

class GhidraKnowledgeCache:
    """Persistent cache for Ghidra domain knowledge."""
    
    def __init__(self, cache_dir: str = "ghidra_knowledge_cache"):
        """
        Initialize the knowledge cache.
        
        Args:
            cache_dir: Directory to store cache files
        """
        self.cache_dir = cache_dir
        self.function_signatures: Dict[str, FunctionSignature] = {}
        self.binary_patterns: Dict[str, BinaryPattern] = {}
        self.analysis_rules: Dict[str, AnalysisRule] = {}
        self.common_workflows: Dict[str, str] = {}
        self.knowledge_initialized = False
        
        # Ensure cache directory exists
        os.makedirs(cache_dir, exist_ok=True)
        
        # Initialize logger
        self.logger = logging.getLogger("ollama-ghidra-bridge.cag.knowledge")
    
    def preload(self, knowledge_files: List[str] = None) -> None:
        """
        Preload domain knowledge from files.
        
        Args:
            knowledge_files: List of JSON files containing knowledge
        """
        if self.knowledge_initialized:
            self.logger.info("Knowledge cache already initialized, skipping preload")
            return
            
        if knowledge_files is None:
            # Use default knowledge files if none provided
            knowledge_dir = os.path.join(os.path.dirname(__file__), "knowledge")
            knowledge_files = [
                os.path.join(knowledge_dir, "function_signatures.json"),
                os.path.join(knowledge_dir, "binary_patterns.json"),
                os.path.join(knowledge_dir, "analysis_rules.json"),
                os.path.join(knowledge_dir, "common_workflows.json")
            ]
        
        loaded_files = 0
        for file_path in knowledge_files:
            if not os.path.exists(file_path):
                self.logger.warning(f"Knowledge file not found: {file_path}")
                continue
                
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    
                if "function_signatures" in data:
                    for name, info in data["function_signatures"].items():
                        self.function_signatures[name] = FunctionSignature(
                            name=name,
                            description=info.get("description", ""),
                            parameters=info.get("parameters", {}),
                            return_type=info.get("return_type", ""),
                            common_locations=info.get("common_locations", []),
                            related_functions=info.get("related_functions", []),
                            token_count=info.get("token_count", self._estimate_tokens(str(info)))
                        )
                        
                if "binary_patterns" in data:
                    for name, info in data["binary_patterns"].items():
                        self.binary_patterns[name] = BinaryPattern(
                            name=name,
                            description=info.get("description", ""),
                            byte_pattern=info.get("byte_pattern", ""),
                            architecture=info.get("architecture", ""),
                            token_count=info.get("token_count", self._estimate_tokens(str(info)))
                        )
                        
                if "analysis_rules" in data:
                    for name, info in data["analysis_rules"].items():
                        self.analysis_rules[name] = AnalysisRule(
                            name=name,
                            description=info.get("description", ""),
                            condition=info.get("condition", ""),
                            action=info.get("action", ""),
                            examples=info.get("examples", []),
                            token_count=info.get("token_count", self._estimate_tokens(str(info)))
                        )
                        
                if "common_workflows" in data:
                    self.common_workflows.update(data["common_workflows"])
                
                loaded_files += 1
                self.logger.info(f"Loaded knowledge from {file_path}")
            except Exception as e:
                self.logger.error(f"Error loading knowledge file {file_path}: {str(e)}")
        
        if loaded_files > 0:
            self.knowledge_initialized = True
            self.logger.info(f"Knowledge cache initialized with {len(self.function_signatures)} function signatures, "
                           f"{len(self.binary_patterns)} binary patterns, and {len(self.analysis_rules)} analysis rules")
        else:
            self.logger.warning("No knowledge files were successfully loaded")
    
    def get_relevant_function_info(self, function_name: str) -> str:
        """
        Get information about a specific function.
        
        Args:
            function_name: Name of the function
            
        Returns:
            Formatted string with function information
        """
        # Try exact match first
        if function_name in self.function_signatures:
            func = self.function_signatures[function_name]
            return self._format_function_info(func)
        
        # Try partial match
        matches = []
        for name, func in self.function_signatures.items():
            if function_name.lower() in name.lower():
                matches.append(func)
        
        if not matches:
            return f"No information available for function: {function_name}"
        
        # Format the matches
        result = f"## Information about function(s) related to '{function_name}':\n\n"
        for func in matches[:3]:  # Limit to top 3 matches to avoid context bloat
            result += self._format_function_info(func) + "\n\n"
        
        return result
    
    def get_relevant_binary_patterns(self, query: str) -> str:
        """
        Get binary patterns relevant to a query.
        
        Args:
            query: The query to match against
            
        Returns:
            Formatted string with relevant patterns
        """
        # Simple keyword matching for now
        matches = []
        for name, pattern in self.binary_patterns.items():
            # Check if any keywords from the query match the pattern name or description
            keywords = query.lower().split()
            if any(keyword in name.lower() or keyword in pattern.description.lower() for keyword in keywords):
                matches.append(pattern)
        
        if not matches:
            return ""
        
        # Format the matches
        result = "## Relevant Binary Patterns:\n\n"
        for pattern in matches[:3]:  # Limit to top 3 matches
            result += f"### {pattern.name}\n"
            result += f"Description: {pattern.description}\n"
            result += f"Architecture: {pattern.architecture}\n"
            result += f"Byte Pattern: `{pattern.byte_pattern}`\n\n"
        
        return result
    
    def get_workflow_for_task(self, task_type: str) -> str:
        """
        Get a common workflow for a specific task type.
        
        Args:
            task_type: Type of task to get workflow for
            
        Returns:
            Workflow instructions as a string
        """
        if task_type in self.common_workflows:
            return f"## Common Workflow for {task_type}:\n\n{self.common_workflows[task_type]}"
        
        # Try partial match
        for workflow_type, instructions in self.common_workflows.items():
            if task_type.lower() in workflow_type.lower():
                return f"## Common Workflow for {workflow_type}:\n\n{instructions}"
        
        return ""
    
    def get_relevant_knowledge(self, query: str, token_limit: int = 2000) -> str:
        """
        Get relevant knowledge for a query, optimized for token limit.
        
        Args:
            query: The query to match against
            token_limit: Maximum tokens to include
            
        Returns:
            Formatted string with relevant knowledge
        """
        knowledge_sections = []
        total_tokens = 0
        
        # Extract potential function names from query (simple heuristic)
        potential_functions = self._extract_potential_functions(query)
        
        # Include function information if specific functions are mentioned
        for func_name in potential_functions:
            if func_name in self.function_signatures:
                func_info = self._format_function_info(self.function_signatures[func_name])
                func_tokens = self._estimate_tokens(func_info)
                if total_tokens + func_tokens <= token_limit:
                    knowledge_sections.append(func_info)
                    total_tokens += func_tokens
        
        # Include task-specific workflow if detected
        task_types = ["decompilation", "function renaming", "structure creation", 
                     "patch creation", "scripting", "function analysis"]
        for task in task_types:
            if task.lower() in query.lower() and task in self.common_workflows:
                workflow = self.get_workflow_for_task(task)
                workflow_tokens = self._estimate_tokens(workflow)
                if total_tokens + workflow_tokens <= token_limit:
                    knowledge_sections.append(workflow)
                    total_tokens += workflow_tokens
                    break  # Only include one workflow for brevity
        
        # Include relevant binary patterns if tokens remain
        if total_tokens < token_limit:
            patterns = self.get_relevant_binary_patterns(query)
            patterns_tokens = self._estimate_tokens(patterns)
            if patterns and total_tokens + patterns_tokens <= token_limit:
                knowledge_sections.append(patterns)
                total_tokens += patterns_tokens
        
        # Combine all sections
        if knowledge_sections:
            return "\n\n".join(knowledge_sections)
        
        return ""
    
    def _format_function_info(self, func: FunctionSignature) -> str:
        """Format function information for inclusion in prompts."""
        params_str = ", ".join([f"{name}: {type_}" for name, type_ in func.parameters.items()])
        signature = f"{func.name}({params_str}) -> {func.return_type}"
        
        result = f"### Function: {signature}\n\n"
        result += f"{func.description}\n\n"
        
        if func.common_locations:
            result += f"Common locations: {', '.join(func.common_locations)}\n"
            
        if func.related_functions:
            result += f"Related functions: {', '.join(func.related_functions)}\n"
            
        return result
    
    def _extract_potential_functions(self, query: str) -> List[str]:
        """Extract potential function names from a query using simple heuristics."""
        # This is a simple implementation - could be enhanced with regex patterns
        potential_functions = []
        
        # Look for common function name patterns
        words = query.split()
        for word in words:
            # Check if word looks like a function name (alphanumeric with possible underscores)
            if word.isalnum() or '_' in word:
                # Check if it's in our function signatures
                if word in self.function_signatures:
                    potential_functions.append(word)
                # Check partial matches
                else:
                    for func_name in self.function_signatures.keys():
                        if word.lower() in func_name.lower():
                            potential_functions.append(func_name)
        
        return list(set(potential_functions))
    
    def _estimate_tokens(self, text: str) -> int:
        """Estimate the number of tokens in a text (very rough approximation)."""
        # Simple approximation: ~4 characters per token on average
        return len(text) // 4
        
    def save_to_disk(self) -> None:
        """Save the knowledge cache to disk."""
        # Function signatures
        signatures_path = os.path.join(self.cache_dir, "function_signatures.json")
        with open(signatures_path, 'w', encoding='utf-8') as f:
            json.dump({"function_signatures": {name: vars(sig) for name, sig in self.function_signatures.items()}}, 
                     f, indent=2)
        
        # Binary patterns
        patterns_path = os.path.join(self.cache_dir, "binary_patterns.json")
        with open(patterns_path, 'w', encoding='utf-8') as f:
            json.dump({"binary_patterns": {name: vars(pattern) for name, pattern in self.binary_patterns.items()}}, 
                     f, indent=2)
        
        # Analysis rules
        rules_path = os.path.join(self.cache_dir, "analysis_rules.json")
        with open(rules_path, 'w', encoding='utf-8') as f:
            json.dump({"analysis_rules": {name: vars(rule) for name, rule in self.analysis_rules.items()}}, 
                     f, indent=2)
        
        # Common workflows
        workflows_path = os.path.join(self.cache_dir, "common_workflows.json")
        with open(workflows_path, 'w', encoding='utf-8') as f:
            json.dump({"common_workflows": self.common_workflows}, f, indent=2)
            
        self.logger.info(f"Knowledge cache saved to {self.cache_dir}")
    
    def load_from_disk(self) -> bool:
        """
        Load the knowledge cache from disk.
        
        Returns:
            True if successful, False otherwise
        """
        try:
            # Function signatures
            signatures_path = os.path.join(self.cache_dir, "function_signatures.json")
            if os.path.exists(signatures_path):
                with open(signatures_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if "function_signatures" in data:
                        for name, info in data["function_signatures"].items():
                            self.function_signatures[name] = FunctionSignature(**info)
            
            # Binary patterns
            patterns_path = os.path.join(self.cache_dir, "binary_patterns.json")
            if os.path.exists(patterns_path):
                with open(patterns_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if "binary_patterns" in data:
                        for name, info in data["binary_patterns"].items():
                            self.binary_patterns[name] = BinaryPattern(**info)
            
            # Analysis rules
            rules_path = os.path.join(self.cache_dir, "analysis_rules.json")
            if os.path.exists(rules_path):
                with open(rules_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if "analysis_rules" in data:
                        for name, info in data["analysis_rules"].items():
                            self.analysis_rules[name] = AnalysisRule(**info)
            
            # Common workflows
            workflows_path = os.path.join(self.cache_dir, "common_workflows.json")
            if os.path.exists(workflows_path):
                with open(workflows_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if "common_workflows" in data:
                        self.common_workflows = data["common_workflows"]
            
            self.knowledge_initialized = True
            self.logger.info(f"Knowledge cache loaded from {self.cache_dir}")
            return True
        except Exception as e:
            self.logger.error(f"Error loading knowledge cache: {str(e)}")
            return False 