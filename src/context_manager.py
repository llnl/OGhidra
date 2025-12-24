"""
Context Management Module for OGhidra

This module provides intelligent context management for LLM interactions:
- Result caching with references
- Intelligent summarization of large results
- Tiered context (detailed recent, summarized older)
- Context budget tracking and enforcement
- Smart content prioritization
"""

import logging
import hashlib
import json
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

logger = logging.getLogger("ollama-ghidra-bridge.context")


class ResultPriority(Enum):
    """Priority levels for result content."""
    CRITICAL = 3  # Function names, addresses, errors
    HIGH = 2      # Decompiled code, key findings
    MEDIUM = 1    # Lists, cross-references
    LOW = 0       # Verbose output, raw data


@dataclass
class CachedResult:
    """A cached tool execution result with metadata."""
    result_id: str
    tool_name: str
    parameters: Dict[str, Any]
    full_result: str
    summary: Optional[str] = None
    excerpt: Optional[str] = None
    token_estimate: int = 0
    priority: ResultPriority = ResultPriority.MEDIUM
    timestamp: datetime = field(default_factory=datetime.now)
    is_summarized: bool = False
    
    def get_display_content(self, detail_level: str = "full") -> str:
        """Get content at specified detail level."""
        if detail_level == "full":
            return self.full_result
        elif detail_level == "summary" and self.summary:
            return f"[SUMMARIZED] {self.summary}\n[Full: {len(self.full_result)} chars, ref: {self.result_id}]"
        elif detail_level == "excerpt" and self.excerpt:
            return f"{self.excerpt}\n[Truncated, ref: {self.result_id}]"
        else:
            return self.full_result[:500] + f"...\n[Truncated, ref: {self.result_id}]"


class ResultCache:
    """
    Cache for tool execution results with intelligent retrieval.
    
    Stores full results and provides various levels of detail
    based on context budget and priority.
    """
    
    def __init__(self, max_cache_size: int = 100):
        self.cache: Dict[str, CachedResult] = {}
        self.max_cache_size = max_cache_size
        self.result_counter = 0
        
    def store(self, tool_name: str, parameters: Dict[str, Any], result: str, 
              custom_id: Optional[str] = None) -> CachedResult:
        """
        Store a result and return a CachedResult object.
        
        Args:
            tool_name: Name of the tool that produced this result
            parameters: Parameters used in the tool call
            result: The full result string
            custom_id: Optional custom ID (e.g., 'step_1') for easy retrieval
        """
        self.result_counter += 1
        
        # Use custom ID if provided, otherwise generate unique ID
        if custom_id:
            result_id = custom_id
        else:
            param_hash = hashlib.md5(json.dumps(parameters, sort_keys=True).encode()).hexdigest()[:8]
            result_id = f"r{self.result_counter}_{tool_name}_{param_hash}"
        
        # Estimate tokens (rough: ~4 chars per token)
        token_estimate = len(result) // 4
        
        # Determine priority based on tool type
        priority = self._determine_priority(tool_name, result)
        
        # Create excerpt (first meaningful portion)
        excerpt = self._create_excerpt(result, tool_name)
        
        cached = CachedResult(
            result_id=result_id,
            tool_name=tool_name,
            parameters=parameters,
            full_result=result,
            excerpt=excerpt,
            token_estimate=token_estimate,
            priority=priority
        )
        
        self.cache[result_id] = cached
        
        # Evict old entries if over limit
        if len(self.cache) > self.max_cache_size:
            self._evict_oldest()
        
        return cached
    
    def get(self, result_id: str) -> Optional[CachedResult]:
        """Retrieve a cached result by ID."""
        return self.cache.get(result_id)
    
    def get_full_result(self, result_id: str) -> Optional[str]:
        """Get the full result content for a cached result."""
        cached = self.cache.get(result_id)
        return cached.full_result if cached else None
    
    def _determine_priority(self, tool_name: str, result: str) -> ResultPriority:
        """Determine priority based on tool type and result content."""
        high_priority_tools = {'decompile_function', 'decompile_function_by_address', 
                               'get_current_function', 'analyze_function'}
        medium_priority_tools = {'disassemble_function', 'read_bytes', 
                                 'get_xrefs_to', 'get_xrefs_from'}
        low_priority_tools = {'list_functions', 'list_methods', 'list_strings',
                              'list_imports', 'list_exports'}
        
        if tool_name in high_priority_tools:
            return ResultPriority.HIGH
        elif tool_name in medium_priority_tools:
            return ResultPriority.MEDIUM
        elif tool_name in low_priority_tools:
            return ResultPriority.LOW
        
        # Check for error indicators
        if 'error' in result.lower()[:100]:
            return ResultPriority.CRITICAL
        
        return ResultPriority.MEDIUM
    
    def _create_excerpt(self, result: str, tool_name: str) -> str:
        """Create a meaningful excerpt from the result."""
        lines = result.split('\n')
        
        # For list results, show first few and count
        if tool_name.startswith('list_') and len(lines) > 10:
            excerpt_lines = lines[:8]
            excerpt_lines.append(f"... ({len(lines)} total items)")
            return '\n'.join(excerpt_lines)
        
        # For decompiled code, show signature and first lines
        if 'decompile' in tool_name:
            # Try to find function signature
            for i, line in enumerate(lines[:5]):
                if '(' in line and ')' in line:
                    return '\n'.join(lines[:min(15, len(lines))])
            return '\n'.join(lines[:15])
        
        # Default: first 500 chars
        return result[:500]
    
    def _evict_oldest(self):
        """Remove the oldest low-priority entries."""
        # Sort by priority (low first) then timestamp (old first)
        sorted_entries = sorted(
            self.cache.items(),
            key=lambda x: (x[1].priority.value, x[1].timestamp)
        )
        
        # Remove bottom 20%
        to_remove = len(self.cache) // 5
        for result_id, _ in sorted_entries[:to_remove]:
            del self.cache[result_id]
    
    def clear(self):
        """Clear the cache."""
        self.cache.clear()
        self.result_counter = 0


class ContextBudget:
    """
    Track and enforce context budget limits.
    
    Helps manage token usage across different prompt sections.
    """
    
    def __init__(self, total_budget: int = 80000, 
                 execution_fraction: float = 0.4,
                 chars_per_token: float = 4.0):
        self.total_budget = total_budget
        self.execution_fraction = execution_fraction
        self.chars_per_token = chars_per_token
        
        # Calculate section budgets
        self.system_budget = int(total_budget * 0.25)  # 25% for system prompt
        self.execution_budget = int(total_budget * execution_fraction)
        self.history_budget = int(total_budget * 0.15)  # 15% for history
        self.response_budget = int(total_budget * 0.20)  # 20% reserved for response
        
        # Current usage tracking
        self.current_usage = {
            'system': 0,
            'execution': 0,
            'history': 0,
            'other': 0
        }
    
    def estimate_tokens(self, text: str) -> int:
        """Estimate token count for text."""
        return int(len(text) / self.chars_per_token)
    
    def estimate_chars(self, tokens: int) -> int:
        """Estimate character count for tokens."""
        return int(tokens * self.chars_per_token)
    
    def get_remaining_execution_budget(self) -> int:
        """Get remaining tokens for execution results."""
        return self.execution_budget - self.current_usage['execution']
    
    def get_remaining_execution_chars(self) -> int:
        """Get remaining characters for execution results."""
        return self.estimate_chars(self.get_remaining_execution_budget())
    
    def add_usage(self, section: str, text: str) -> int:
        """Add usage and return tokens used."""
        tokens = self.estimate_tokens(text)
        self.current_usage[section] = self.current_usage.get(section, 0) + tokens
        return tokens
    
    def can_fit(self, text: str, section: str = 'execution') -> bool:
        """Check if text fits within section budget."""
        tokens = self.estimate_tokens(text)
        current = self.current_usage.get(section, 0)
        budget = getattr(self, f'{section}_budget', self.total_budget)
        return current + tokens <= budget
    
    def get_budget_for_result(self, priority: ResultPriority, 
                               remaining_results: int) -> int:
        """Calculate character budget for a single result based on priority."""
        remaining_chars = self.get_remaining_execution_chars()
        
        if remaining_results <= 0:
            return remaining_chars
        
        # Allocate more budget to high priority results
        priority_multipliers = {
            ResultPriority.CRITICAL: 2.0,
            ResultPriority.HIGH: 1.5,
            ResultPriority.MEDIUM: 1.0,
            ResultPriority.LOW: 0.5
        }
        
        base_budget = remaining_chars // remaining_results
        return int(base_budget * priority_multipliers.get(priority, 1.0))
    
    def reset(self):
        """Reset usage tracking."""
        self.current_usage = {
            'system': 0,
            'execution': 0,
            'history': 0,
            'other': 0
        }
    
    def get_usage_summary(self) -> str:
        """Get a summary of current usage."""
        total_used = sum(self.current_usage.values())
        return (f"Context Usage: {total_used}/{self.total_budget} tokens "
                f"({100*total_used/self.total_budget:.1f}%)\n"
                f"  System: {self.current_usage['system']}/{self.system_budget}\n"
                f"  Execution: {self.current_usage['execution']}/{self.execution_budget}\n"
                f"  History: {self.current_usage['history']}/{self.history_budget}")


class ContextManager:
    """
    Main context management class that coordinates all context operations.
    
    Features:
    - Intelligent result summarization
    - Tiered context (detailed recent, summarized older)
    - Context budget enforcement
    - Smart content prioritization
    - Result caching with references
    """
    
    def __init__(self, 
                 ollama_client=None,
                 context_budget: int = 80000,
                 execution_fraction: float = 0.5,
                 enable_summarization: bool = True,
                 enable_caching: bool = True,
                 enable_tiered_context: bool = True):
        
        self.ollama_client = ollama_client
        self.enable_summarization = enable_summarization
        self.enable_caching = enable_caching
        self.enable_tiered_context = enable_tiered_context
        
        # Initialize components
        self.result_cache = ResultCache() if enable_caching else None
        self.budget = ContextBudget(context_budget, execution_fraction)
        
        # Track recent results for tiered context
        self.recent_results: List[CachedResult] = []
        self.max_recent_detailed = 3  # Last 3 get full detail
        
        logger.info(f"ContextManager initialized with budget={context_budget}, "
                   f"summarization={enable_summarization}, caching={enable_caching}")
    
    def process_result(self, tool_name: str, parameters: Dict[str, Any], 
                       result: str, goal: str = "") -> Tuple[str, CachedResult]:
        """
        Process a tool execution result for context-aware inclusion.
        
        Returns:
            Tuple of (display_content, cached_result)
        """
        # Cache the result
        cached = None
        if self.result_cache:
            cached = self.result_cache.store(tool_name, parameters, result)
            self.recent_results.append(cached)
        else:
            # Create a minimal cached result for tracking
            cached = CachedResult(
                result_id=f"temp_{len(self.recent_results)}",
                tool_name=tool_name,
                parameters=parameters,
                full_result=result,
                token_estimate=len(result) // 4,
                priority=ResultPriority.MEDIUM
            )
            self.recent_results.append(cached)
        
        # Determine how much budget we have for this result
        char_budget = self.budget.get_budget_for_result(
            cached.priority,
            remaining_results=1  # Conservative estimate
        )
        
        # If result fits in budget, use full
        if len(result) <= char_budget:
            display_content = result
        # If summarization enabled and result is large, summarize
        elif self.enable_summarization and len(result) > 3000:
            summary = self._summarize_result(result, tool_name, goal)
            cached.summary = summary
            cached.is_summarized = True
            display_content = f"[SUMMARIZED]\n{summary}\n\n[Full result: {len(result)} chars, cached as {cached.result_id}]"
        # Otherwise, smart truncate
        else:
            display_content = self._smart_truncate(result, char_budget, tool_name)
        
        # Track budget usage
        self.budget.add_usage('execution', display_content)
        
        return display_content, cached
    
    def format_results_for_prompt(self, tool_executions: List[Any], 
                                   goal: str = "") -> str:
        """
        Format tool execution results for inclusion in prompt.
        
        Uses tiered context: recent results get full detail,
        older results get summaries or excerpts.
        """
        if not tool_executions:
            return ""
        
        sections = []
        total_results = len(tool_executions)
        
        for i, exec_result in enumerate(tool_executions):
            is_recent = i >= total_results - self.max_recent_detailed
            result_num = i + 1
            
            # Get tool info
            tool_name = getattr(exec_result, 'tool_name', str(exec_result))
            parameters = getattr(exec_result, 'parameters', {})
            result = getattr(exec_result, 'result', str(exec_result))
            
            # Determine detail level based on recency and budget
            if is_recent or not self.enable_tiered_context:
                detail_level = "full"
                remaining_budget = self.budget.get_remaining_execution_chars()
                
                if len(result) > remaining_budget:
                    if self.enable_summarization and len(result) > 3000:
                        detail_level = "summary"
                    else:
                        detail_level = "excerpt"
            else:
                # Older results get summarized
                detail_level = "summary" if self.enable_summarization else "excerpt"
            
            # Get display content
            display_content = self._get_result_content(
                result, tool_name, parameters, goal, detail_level
            )
            
            # Track budget
            self.budget.add_usage('execution', display_content)
            
            # Format section
            section = f"### Step {result_num}: {tool_name}\n"
            section += f"Parameters: {parameters}\n"
            section += f"Result:\n{display_content}\n"
            
            sections.append(section)
        
        return "\n".join(sections)
    
    def _get_result_content(self, result: str, tool_name: str, 
                            parameters: Dict, goal: str, 
                            detail_level: str) -> str:
        """Get result content at specified detail level."""
        if detail_level == "full":
            # Apply smart truncation if still too large
            max_chars = self.budget.get_remaining_execution_chars()
            if len(result) > max_chars:
                return self._smart_truncate(result, max_chars, tool_name)
            return result
        
        elif detail_level == "summary":
            if self.enable_summarization:
                summary = self._summarize_result(result, tool_name, goal)
                return f"[SUMMARIZED] {summary}\n[Full: {len(result)} chars]"
            else:
                return self._smart_truncate(result, 1000, tool_name)
        
        else:  # excerpt
            return self._smart_truncate(result, 500, tool_name)
    
    def _summarize_result(self, result: str, tool_name: str, goal: str = "") -> str:
        """Use LLM to summarize a large result."""
        if not self.ollama_client:
            logger.warning("No ollama_client available for summarization, using truncation")
            return self._smart_truncate(result, 800, tool_name)
        
        try:
            # Limit input to avoid token overflow
            input_text = result[:12000] if len(result) > 12000 else result
            
            prompt = f"""Concisely summarize this {tool_name} output in 2-4 sentences.
Preserve: function names, addresses, key patterns, errors, important values.

{input_text}

Summary:"""
            
            summary = self.ollama_client.generate(
                prompt=prompt,
                temperature=0.3,
                max_tokens=200
            )
            
            return summary.strip() if summary else self._smart_truncate(result, 800, tool_name)
            
        except Exception as e:
            logger.warning(f"Summarization failed: {e}, using truncation")
            return self._smart_truncate(result, 800, tool_name)
    
    def _smart_truncate(self, result: str, max_chars: int, tool_name: str) -> str:
        """
        Smart truncation that preserves important content.
        
        Strategy:
        - For list results: first N items + count
        - For code: signature + first lines
        - For hex dumps: first + last portions
        - Default: first + last with middle indicator
        """
        if len(result) <= max_chars:
            return result
        
        lines = result.split('\n')
        
        # List results: show first and count
        if tool_name.startswith('list_') or len(lines) > 50:
            # Calculate how many lines we can show
            avg_line_len = len(result) // max(len(lines), 1)
            lines_to_show = max(5, max_chars // max(avg_line_len, 50))
            
            if lines_to_show < len(lines):
                first_lines = lines[:lines_to_show - 2]
                return '\n'.join(first_lines) + f"\n... [{len(lines) - lines_to_show + 2} more lines, {len(result)} total chars]"
        
        # Hex dumps: show first and last
        if 'read_bytes' in tool_name or all(c in '0123456789ABCDEFabcdef: |\n' for c in result[:100]):
            portion = max_chars // 3
            first_part = result[:portion]
            last_part = result[-portion:]
            return f"{first_part}\n... [middle truncated] ...\n{last_part}"
        
        # Decompiled code: preserve signature
        if 'decompile' in tool_name:
            # Find function signature (first line with parentheses)
            sig_end = 0
            for i, line in enumerate(lines[:10]):
                if '(' in line and ')' in line:
                    sig_end = result.find('\n', result.find(line))
                    break
            
            if sig_end > 0:
                signature = result[:sig_end + 1]
                remaining = max_chars - len(signature) - 50
                body_preview = result[sig_end + 1:sig_end + 1 + remaining]
                return f"{signature}{body_preview}\n... [truncated, {len(result)} total chars]"
        
        # Default: first and last portions
        first_portion = int(max_chars * 0.7)
        last_portion = max_chars - first_portion - 50
        
        return (f"{result[:first_portion]}\n"
                f"... [truncated {len(result) - max_chars} chars] ...\n"
                f"{result[-last_portion:]}")
    
    def prioritize_results(self, results: List[Any], goal: str) -> List[Any]:
        """
        Prioritize results by relevance to goal.
        
        Higher priority results get more context budget.
        """
        scored = []
        goal_words = set(goal.lower().split())
        
        for exec_result in results:
            result_text = str(getattr(exec_result, 'result', exec_result)).lower()
            tool_name = getattr(exec_result, 'tool_name', '')
            
            score = 0
            
            # Score based on goal word matches
            for word in goal_words:
                if len(word) > 3 and word in result_text:
                    score += 2
            
            # Tool type scoring
            if 'decompile' in tool_name:
                score += 5
            elif 'analyze' in tool_name:
                score += 4
            elif 'get_current' in tool_name:
                score += 3
            elif 'xrefs' in tool_name:
                score += 2
            elif 'list_' in tool_name:
                score -= 1
            
            # Error penalty
            if 'error' in result_text[:200]:
                score -= 3
            
            scored.append((score, exec_result))
        
        # Sort by score descending
        scored.sort(key=lambda x: x[0], reverse=True)
        
        return [exec_result for _, exec_result in scored]
    
    def get_full_result(self, result_id: str) -> Optional[str]:
        """Retrieve the full cached result by ID."""
        if self.result_cache:
            return self.result_cache.get_full_result(result_id)
        return None
    
    def reset(self):
        """Reset context manager state for new query."""
        self.budget.reset()
        self.recent_results.clear()
    
    def get_status(self) -> str:
        """Get current status summary."""
        return (f"Context Manager Status:\n"
                f"  {self.budget.get_usage_summary()}\n"
                f"  Cached results: {len(self.result_cache.cache) if self.result_cache else 0}\n"
                f"  Recent results: {len(self.recent_results)}")

