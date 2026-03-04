"""
Intelligent Context Builder for Enhanced Knowledge Space

This module builds context dynamically based on query intent rather than
using fixed truncation rules, enabling more relevant context assembly.

Author: OGhidra Enhanced Knowledge System
Date: 2026-02-19
"""

import logging
from typing import Dict, List, Any, Optional, Set

logger = logging.getLogger("ollama-ghidra-bridge.intelligent_context")


class IntelligentContextBuilder:
    """
    Build context dynamically based on query intent.
    
    Capabilities:
    - Intent classification (data_flow, security, implementation, call_flow, general)
    - Context assembly with token budget management
    - Priority-based context inclusion
    """
    
    # Intent classification keywords
    INTENT_KEYWORDS = {
        'data_flow': [
            'input', 'output', 'parameter', 'return', 'data', 'flow',
            'argument', 'value', 'pass', 'receive', 'give', 'get'
        ],
        'security': [
            'security', 'vulnerability', 'risk', 'exploit', 'attack',
            'safe', 'unsafe', 'dangerous', 'protect', 'threat', 'breach'
        ],
        'implementation': [
            'how', 'implement', 'algorithm', 'logic', 'code', 'work',
            'does', 'perform', 'execute', 'calculate', 'process'
        ],
        'call_flow': [
            'call', 'invoke', 'execute', 'chain', 'path', 'sequence',
            'order', 'flow', 'step', 'dependency', 'uses', 'used by'
        ]
    }
    
    def __init__(self, bridge=None):
        """
        Initialize the intelligent context builder.
        
        Args:
            bridge: Optional Bridge instance for accessing function data
        """
        self.logger = logger
        self.bridge = bridge
    
    def build_context_for_query(self, function_addr: str, query: str,
                                max_tokens: int = 2000) -> str:
        """
        Build relevant context based on query intent.
        
        Args:
            function_addr: Address of the function to build context for
            query: User's query
            max_tokens: Maximum tokens to include in context
        
        Returns:
            Assembled context string
        """
        try:
            # Classify query intent
            intent = self._classify_intent(query)
            
            # Get function metadata if available
            func_data = self._get_function_data(function_addr)
            if not func_data:
                return self._build_fallback_context(function_addr)
            
            # Build context based on intent
            if intent == 'data_flow':
                return self._build_dataflow_context(func_data, max_tokens)
            elif intent == 'security':
                return self._build_security_context(func_data, max_tokens)
            elif intent == 'implementation':
                return self._build_implementation_context(func_data, max_tokens)
            elif intent == 'call_flow':
                return self._build_callflow_context(func_data, max_tokens)
            else:
                return self._build_general_context(func_data, max_tokens)
                
        except Exception as e:
            self.logger.error(f"Error building intelligent context: {e}")
            return f"Context for function at {function_addr}"
    
    def _classify_intent(self, query: str) -> str:
        """
        Classify what the user is asking about.
        
        Args:
            query: User's query string
        
        Returns:
            Intent category: 'data_flow', 'security', 'implementation', 'call_flow', or 'general'
        """
        query_lower = query.lower()
        
        # Calculate scores for each intent
        scores = {}
        for intent, keywords in self.INTENT_KEYWORDS.items():
            score = sum(1 for kw in keywords if kw in query_lower)
            scores[intent] = score
        
        # Return intent with highest score, or 'general' if no matches
        max_score = max(scores.values())
        if max_score > 0:
            return max(scores, key=scores.get)
        return 'general'
    
    def _get_function_data(self, function_addr: str) -> Optional[Dict[str, Any]]:
        """Get function metadata from bridge if available."""
        if not self.bridge:
            return None
        
        # Try to get from function_address_mapping
        if hasattr(self.bridge, 'function_address_mapping'):
            func_data = self.bridge.function_address_mapping.get(function_addr)
            if func_data:
                return func_data
        
        # Try to get from analysis_state
        if hasattr(self.bridge, 'analysis_state'):
            functions_renamed = self.bridge.analysis_state.get('functions_renamed', {})
            if function_addr in functions_renamed:
                return {
                    'address': function_addr,
                    'new_name': functions_renamed[function_addr],
                }
        
        return None
    
    # ========== Context Builders by Intent ==========
    
    def _build_dataflow_context(self, func_data: Dict, max_tokens: int) -> str:
        """Build data flow-focused context."""
        sections = []
        
        new_name = func_data.get('new_name', 'unknown')
        sections.append(f"## Data Flow Analysis: {new_name}")
        
        # Function signature
        signature = func_data.get('signature', {})
        if signature:
            sections.append(f"\n**Return Type:** `{signature.get('return_type', 'unknown')}`")
            
            params = signature.get('parameters', [])
            if params:
                sections.append("\n**Parameters:**")
                for param in params[:5]:
                    sections.append(f"- `{param.get('type', '?')} {param.get('name', '?')}`: {param.get('usage', 'input')}")
        
        # Data flow specifics
        data_flow = func_data.get('data_flow', {})
        if data_flow:
            side_effects = data_flow.get('side_effects', [])
            if side_effects:
                sections.append("\n**Side Effects:**")
                for effect in side_effects:
                    sections.append(f"- {effect.replace('_', ' ').title()}")
            
            globals_accessed = data_flow.get('globals_accessed', [])
            if globals_accessed:
                sections.append(f"\n**Global Variables:** {', '.join(globals_accessed[:5])}")
        
        # Behavior summary
        summary = func_data.get('summary', {})
        if isinstance(summary, dict):
            behavior = summary.get('behavior_summary', '')
            if behavior:
                sections.append(f"\n**Behavior:** {behavior}")
        
        return "\n".join(sections)[:max_tokens * 4]  # Rough token estimate
    
    def _build_security_context(self, func_data: Dict, max_tokens: int) -> str:
        """Build security-focused context."""
        sections = []
        
        new_name = func_data.get('new_name', 'unknown')
        sections.append(f"## Security Analysis: {new_name}")
        
        # Security details
        security = func_data.get('security', {})
        if security:
            criticality = security.get('criticality', 'low')
            sections.append(f"\n**Criticality Level:** {criticality.upper()}")
            
            indicators = security.get('indicators', [])
            if indicators:
                sections.append("\n**Security Indicators:**")
                for indicator in indicators:
                    sections.append(f"- {indicator.replace('_', ' ').title()}")
            
            risks = security.get('risks', [])
            if risks:
                sections.append("\n**Identified Risks:**")
                for risk in risks[:5]:
                    sections.append(f"- {risk}")
        
        # Operations
        categories = func_data.get('categories', {})
        operations = categories.get('operations', [])
        if operations:
            security_ops = [op for op in operations 
                          if any(s in op for s in ['crypto', 'network', 'auth', 'registry', 'process'])]
            if security_ops:
                sections.append(f"\n**Security-Relevant Operations:** {', '.join(security_ops)}")
        
        return "\n".join(sections)[:max_tokens * 4]
    
    def _build_implementation_context(self, func_data: Dict, max_tokens: int) -> str:
        """Build implementation-focused context."""
        sections = []
        
        new_name = func_data.get('new_name', 'unknown')
        sections.append(f"## Implementation Details: {new_name}")
        
        # Metrics
        metrics = func_data.get('metrics', {})
        if metrics:
            sections.append(f"\n**Complexity:** {metrics.get('complexity_tier', 'unknown').title()}")
            sections.append(f"**Cyclomatic Complexity:** {metrics.get('cyclomatic_complexity', 0)}")
            sections.append(f"**Lines of Code:** {metrics.get('code_lines', 0)}")
        
        # Patterns
        patterns = func_data.get('patterns', [])
        if patterns:
            sections.append("\n**Code Patterns:**")
            for pattern in patterns:
                sections.append(f"- {pattern.replace('_', ' ').title()}")
        
        # Operations
        categories = func_data.get('categories', {})
        operations = categories.get('operations', [])
        if operations:
            sections.append(f"\n**Operations:** {', '.join(operations)}")
        
        # Function analysis from AI
        summary = func_data.get('summary', {})
        if isinstance(summary, dict):
            analysis = summary.get('function_analysis', '')
            if analysis:
                # Extract first few sentences
                sentences = analysis.split('.')[:3]
                sections.append(f"\n**Analysis:** {'. '.join(sentences)}.")
        
        return "\n".join(sections)[:max_tokens * 4]
    
    def _build_callflow_context(self, func_data: Dict, max_tokens: int) -> str:
        """Build call flow-focused context."""
        sections = []
        
        new_name = func_data.get('new_name', 'unknown')
        sections.append(f"## Call Flow: {new_name}")
        
        # Dependencies
        dependencies = func_data.get('dependencies', {})
        if dependencies:
            calls = dependencies.get('calls', [])
            if calls:
                sections.append(f"\n**Calls {len(calls)} function(s):**")
                for call in calls[:8]:
                    addr = call.get('address', 'unknown')
                    importance = call.get('importance', 'medium')
                    sections.append(f"- {addr} ({importance} priority)")
            
            called_by = dependencies.get('called_by', [])
            if called_by:
                sections.append(f"\n**Called by {len(called_by)} function(s):**")
                for caller in called_by[:8]:
                    addr = caller.get('address', 'unknown')
                    context = caller.get('context', 'unknown context')
                    sections.append(f"- {addr} ({context})")
            
            call_depth = dependencies.get('call_depth', 0)
            sections.append(f"\n**Call Depth:** {call_depth}")
        
        # Domain context
        categories = func_data.get('categories', {})
        domain = categories.get('primary_domain', 'general')
        sections.append(f"\n**Functional Domain:** {domain.replace('_', ' ').title()}")
        
        return "\n".join(sections)[:max_tokens * 4]
    
    def _build_general_context(self, func_data: Dict, max_tokens: int) -> str:
        """Build general-purpose context."""
        sections = []
        
        new_name = func_data.get('new_name', 'unknown')
        old_name = func_data.get('old_name', 'unknown')
        address = func_data.get('address', 'unknown')
        
        sections.append(f"## Function: {new_name}")
        if old_name != new_name:
            sections.append(f"*Originally: {old_name}*")
        sections.append(f"**Address:** {address}")
        
        # Quick overview
        categories = func_data.get('categories', {})
        domain = categories.get('primary_domain', 'general')
        sections.append(f"\n**Domain:** {domain.replace('_', ' ').title()}")
        
        operations = categories.get('operations', [])
        if operations:
            sections.append(f"**Operations:** {', '.join(operations[:5])}")
        
        # Metrics
        metrics = func_data.get('metrics', {})
        if metrics:
            complexity = metrics.get('complexity_tier', 'unknown')
            sections.append(f"**Complexity:** {complexity.title()}")
        
        # Security
        security = func_data.get('security', {})
        if security:
            criticality = security.get('criticality', 'low')
            if criticality in ['high', 'critical']:
                sections.append(f"\n⚠️ **Security:** {criticality.upper()} criticality")
        
        # Behavior summary
        summary = func_data.get('summary', {})
        if isinstance(summary, dict):
            behavior = summary.get('behavior_summary', '')
            if behavior:
                sections.append(f"\n**Purpose:** {behavior}")
        elif isinstance(summary, str) and summary:
            # Legacy: just take first sentence
            first_sentence = summary.split('.')[0] + '.'
            sections.append(f"\n**Purpose:** {first_sentence}")
        
        return "\n".join(sections)[:max_tokens * 4]
    
    def _build_fallback_context(self, function_addr: str) -> str:
        """Build minimal fallback context when no metadata available."""
        return f"Function at address {function_addr} (metadata not yet available)"
