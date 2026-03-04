"""
RAG Document Builder for Enhanced Knowledge Space

This module builds information-dense, hierarchically structured documents
optimized for semantic search and LLM retrieval.

Author: OGhidra Enhanced Knowledge System
Date: 2026-02-19
"""

import logging
from typing import Dict, List, Any, Optional

logger = logging.getLogger("ollama-ghidra-bridge.rag_document_builder")


class RAGDocumentBuilder:
    """
    Build optimized RAG documents from function metadata.
    
    Capabilities:
    - Hierarchical content structure (Quick Ref → Details)
    - Information-dense formatting (no boilerplate)
    - Semantic tagging for filtered search
    - Multi-vector chunking support
    """
    
    def __init__(self):
        """Initialize the RAG document builder."""
        self.logger = logger
    
    def build_primary_document(self, func_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create the primary RAG document for a function.
        
        Args:
            func_data: Complete function metadata dict
        
        Returns:
            RAG document with title, content, metadata
        """
        try:
            # Extract key fields
            address = func_data.get('address', 'unknown')
            old_name = func_data.get('old_name', 'unknown')
            new_name = func_data.get('new_name', old_name)
            
            # Get metadata sections
            metrics = func_data.get('metrics', {})
            categories = func_data.get('categories', {})
            signature = func_data.get('signature', {})
            patterns = func_data.get('patterns', [])
            security = func_data.get('security', {})
            data_flow = func_data.get('data_flow', {})
            dependencies = func_data.get('dependencies', {})
            summary = func_data.get('summary', {})
            
            # Build hierarchical content
            content = self._format_hierarchical_content(
                new_name, address, old_name,
                metrics, categories, signature, patterns,
                security, data_flow, dependencies, summary
            )
            
            # Generate semantic tags
            semantic_tags = self._generate_semantic_tags(func_data)
            
            # Build document
            primary_domain = categories.get('primary_domain', 'general')
            security_level = security.get('criticality', 'low')
            complexity = metrics.get('complexity_tier', 'unknown')
            
            document = {
                'title': f"Function: {new_name} [{primary_domain}]",
                'content': content,
                'metadata': {
                    'type': 'function_analysis',
                    'address': address,
                    'old_name': old_name,
                    'new_name': new_name,
                    'domain': primary_domain,
                    'security_relevant': security_level in ['high', 'critical'],
                    'security_level': security_level,
                    'complexity': complexity,
                    'operations': categories.get('operations', []),
                    'patterns': patterns,
                    'semantic_tags': semantic_tags,
                    'chunk_type': 'primary',
                }
            }
            
            return document
            
        except Exception as e:
            self.logger.error(f"Error building RAG document: {e}")
            return self._build_fallback_document(func_data)
    
    def build_multi_vector_documents(self, func_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Create multiple focused vectors per function for semantic chunking.
        
        Args:
            func_data: Complete function metadata dict
        
        Returns:
            List of RAG documents (one per semantic chunk)
        """
        documents = []
        
        try:
            # Always include purpose vector
            documents.append(self._build_purpose_vector(func_data))
            
            # Always include implementation vector
            documents.append(self._build_implementation_vector(func_data))
            
            # Always include dependencies vector
            documents.append(self._build_dependencies_vector(func_data))
            
            # Conditional: Security vector (if security-relevant)
            security = func_data.get('security', {})
            if security.get('criticality') in ['high', 'critical']:
                documents.append(self._build_security_vector(func_data))
            
            # Conditional: Data flow vector (if complex)
            metrics = func_data.get('metrics', {})
            if metrics.get('cyclomatic_complexity', 0) > 5:
                documents.append(self._build_dataflow_vector(func_data))
            
            return documents
            
        except Exception as e:
            self.logger.error(f"Error building multi-vector documents: {e}")
            # Fallback to single primary document
            return [self.build_primary_document(func_data)]
    
    # ========== Private Methods: Content Formatting ==========
    
    def _format_hierarchical_content(self, new_name: str, address: str, old_name: str,
                                     metrics: Dict, categories: Dict, signature: Dict,
                                     patterns: List, security: Dict, data_flow: Dict,
                                     dependencies: Dict, summary: Dict) -> str:
        """Format content with clear hierarchy for LLM consumption."""
        
        sections = []
        
        # Header
        sections.append(f"# {new_name} @ {address}")
        if old_name != new_name:
            sections.append(f"*Originally: {old_name}*")
        sections.append("")
        
        # Quick Reference (scannable)
        sections.append(self._build_quick_reference(
            categories, security, metrics))
        
        # Key Operations (bullet points from AI summary)
        sections.append(self._build_key_operations(summary, categories))
        
        # Dependencies
        sections.append(self._build_dependencies_section(dependencies))
        
        # Technical Details
        sections.append(self._build_technical_details(
            signature, metrics, data_flow))
        
        # Context (behavior summary from AI)
        sections.append(self._build_context_section(summary))
        
        # Code Patterns
        if patterns:
            sections.append(self._build_patterns_section(patterns))
        
        # Security Details (if relevant)
        if security.get('criticality') in ['medium', 'high', 'critical']:
            sections.append(self._build_security_section(security))
        
        return "\n\n".join(filter(None, sections))
    
    def _build_quick_reference(self, categories: Dict, security: Dict, 
                               metrics: Dict) -> str:
        """Build scannable quick reference section."""
        domain = categories.get('primary_domain', 'unknown')
        complexity = metrics.get('complexity_tier', 'unknown')
        security_level = security.get('criticality', 'low')
        
        # Security indicator emoji
        security_emoji = {
            'critical': '🔴 CRITICAL',
            'high': '🔒 High Security',
            'medium': '⚠️ Medium Security',
            'low': '📝 Standard'
        }.get(security_level, '📝 Standard')
        
        lines = [
            "## Quick Reference",
            f"**Domain:** {domain.replace('_', ' ').title()}",
            f"**Complexity:** {complexity.title()}",
            f"**Security:** {security_emoji}",
        ]
        
        # Add operations if present
        operations = categories.get('operations', [])
        if operations:
            ops_display = ', '.join(op.replace('_', ' ').title() for op in operations[:5])
            if len(operations) > 5:
                ops_display += f" (+{len(operations)-5} more)"
            lines.append(f"**Operations:** {ops_display}")
        
        return "\n".join(lines)
    
    def _build_key_operations(self, summary: Dict, categories: Dict) -> str:
        """Build key operations section from AI summary."""
        lines = ["## Key Operations"]
        
        # Try to extract bullet points from function analysis
        if isinstance(summary, dict):
            analysis = summary.get('function_analysis', '')
            behavior = summary.get('behavior_summary', '')
        elif isinstance(summary, str):
            # Legacy: summary is just a string
            analysis = summary
            behavior = ''
        else:
            analysis = ''
            behavior = ''
        
        # Extract operations from AI analysis
        operations_found = []
        if analysis:
            # Look for bullet points or numbered lists
            for line in analysis.split('\n'):
                line = line.strip()
                if line.startswith(('- ', '* ', '• ', '1.', '2.', '3.')):
                    clean_line = line.lstrip('-*•0123456789. ')
                    if clean_line:
                        operations_found.append(clean_line)
        
        # If we found operations, use them
        if operations_found:
            for op in operations_found[:7]:  # Limit to 7 operations
                lines.append(f"- {op}")
        else:
            # Fallback: use behavior summary or categories
            if behavior:
                lines.append(f"- {behavior}")
            else:
                ops = categories.get('operations', [])
                if ops:
                    lines.append(f"- Performs {', '.join(ops[:3])} operations")
                else:
                    lines.append("- (Analysis pending)")
        
        return "\n".join(lines)
    
    def _build_dependencies_section(self, dependencies: Dict) -> str:
        """Build dependencies section."""
        lines = ["## Dependencies"]
        
        calls = dependencies.get('calls', [])
        called_by = dependencies.get('called_by', [])
        
        if calls:
            call_list = ', '.join(c.get('address', 'unknown')[:10] for c in calls[:5])
            if len(calls) > 5:
                call_list += f" (+{len(calls)-5} more)"
            lines.append(f"**Calls:** {call_list}")
        
        if called_by:
            caller_list = ', '.join(c.get('address', 'unknown')[:10] for c in called_by[:5])
            if len(called_by) > 5:
                caller_list += f" (+{len(called_by)-5} more)"
            lines.append(f"**Called By:** {caller_list}")
        
        if not calls and not called_by:
            lines.append("*(No cross-references found)*")
        
        return "\n".join(lines)
    
    def _build_technical_details(self, signature: Dict, metrics: Dict, 
                                 data_flow: Dict) -> str:
        """Build technical details section."""
        lines = ["## Technical Details"]
        
        # Signature
        return_type = signature.get('return_type', 'unknown')
        params = signature.get('parameters', [])
        lines.append(f"**Returns:** `{return_type}`")
        
        if params:
            param_str = ', '.join(f"{p.get('type', '?')} {p.get('name', '?')}" 
                                 for p in params[:4])
            if len(params) > 4:
                param_str += f" (+{len(params)-4} more)"
            lines.append(f"**Parameters:** `{param_str}`")
        else:
            lines.append("**Parameters:** *(none)*")
        
        # Metrics
        complexity = metrics.get('cyclomatic_complexity', 0)
        loc = metrics.get('code_lines', 0)
        lines.append(f"**Complexity:** {complexity} | **LOC:** {loc}")
        
        # Side effects
        side_effects = data_flow.get('side_effects', [])
        if side_effects:
            effects_display = ', '.join(e.replace('_', ' ') for e in side_effects[:3])
            lines.append(f"**Side Effects:** {effects_display}")
        
        # Globals
        globals_accessed = data_flow.get('globals_accessed', [])
        if globals_accessed:
            globals_display = ', '.join(globals_accessed[:5])
            lines.append(f"**Accesses Globals:** {globals_display}")
        
        return "\n".join(lines)
    
    def _build_context_section(self, summary: Dict) -> str:
        """Build context section with behavior summary."""
        lines = ["## Context"]
        
        if isinstance(summary, dict):
            behavior = summary.get('behavior_summary', '')
            if behavior:
                lines.append(behavior)
            else:
                lines.append("*(Detailed analysis in progress)*")
        elif isinstance(summary, str):
            # Extract first few sentences
            sentences = summary.split('.')[:3]
            lines.append('. '.join(sentences) + '.')
        else:
            lines.append("*(Analysis pending)*")
        
        return "\n".join(lines)
    
    def _build_patterns_section(self, patterns: List[str]) -> str:
        """Build code patterns section."""
        lines = ["## Code Patterns"]
        
        pattern_display = {
            'error_handling': '✓ Error Handling',
            'input_validation': '✓ Input Validation',
            'resource_management': '✓ Resource Management',
            'iterative_processing': '✓ Loops/Iteration',
            'state_machine': '✓ State Machine',
            'callback_usage': '✓ Callbacks',
            'conditional_return': '✓ Conditional Returns',
        }
        
        for pattern in patterns:
            display = pattern_display.get(pattern, f'✓ {pattern.replace("_", " ").title()}')
            lines.append(display)
        
        return "\n".join(lines)
    
    def _build_security_section(self, security: Dict) -> str:
        """Build security details section."""
        lines = ["## Security Analysis"]
        
        criticality = security.get('criticality', 'low')
        lines.append(f"**Level:** {criticality.upper()}")
        
        indicators = security.get('indicators', [])
        if indicators:
            lines.append("**Indicators:**")
            for indicator in indicators:
                lines.append(f"- {indicator.replace('_', ' ').title()}")
        
        risks = security.get('risks', [])
        if risks:
            lines.append("**Risks:**")
            for risk in risks[:3]:
                lines.append(f"- {risk}")
        
        return "\n".join(lines)
    
    # ========== Private Methods: Multi-Vector Documents ==========
    
    def _build_purpose_vector(self, func_data: Dict) -> Dict[str, Any]:
        """Build purpose-focused vector (for 'what does this do?' queries)."""
        new_name = func_data.get('new_name', 'unknown')
        address = func_data.get('address', 'unknown')
        categories = func_data.get('categories', {})
        summary = func_data.get('summary', {})
        
        domain = categories.get('primary_domain', 'general')
        
        # Extract behavior summary
        if isinstance(summary, dict):
            behavior = summary.get('behavior_summary', '')
        else:
            behavior = str(summary)[:200] if summary else ''
        
        content = f"""# Purpose: {new_name}

**Domain:** {domain.replace('_', ' ').title()}
**Address:** {address}

## What It Does
{behavior if behavior else 'Function purpose analysis in progress'}

**Operations:** {', '.join(categories.get('operations', ['general']))}
"""
        
        return {
            'title': f"Purpose: {new_name}",
            'content': content,
            'metadata': {
                **func_data.get('metadata', {}),
                'chunk_type': 'purpose',
                'address': address,
                'new_name': new_name,
            }
        }
    
    def _build_implementation_vector(self, func_data: Dict) -> Dict[str, Any]:
        """Build implementation-focused vector (for 'how is this implemented?' queries)."""
        new_name = func_data.get('new_name', 'unknown')
        address = func_data.get('address', 'unknown')
        patterns = func_data.get('patterns', [])
        metrics = func_data.get('metrics', {})
        signature = func_data.get('signature', {})
        
        content = f"""# Implementation: {new_name}

**Complexity:** {metrics.get('complexity_tier', 'unknown').title()} (CC: {metrics.get('cyclomatic_complexity', 0)})
**Size:** {metrics.get('code_lines', 0)} lines

## Signature
Returns: `{signature.get('return_type', 'unknown')}`
Parameters: {len(signature.get('parameters', []))} params

## Patterns Used
{chr(10).join(f'- {p.replace("_", " ").title()}' for p in patterns) if patterns else '- Standard implementation'}

## Technical Approach
Based on complexity and patterns, this function uses a {'complex' if metrics.get('cyclomatic_complexity', 0) > 10 else 'straightforward'} implementation approach.
"""
        
        return {
            'title': f"Implementation: {new_name}",
            'content': content,
            'metadata': {
                **func_data.get('metadata', {}),
                'chunk_type': 'implementation',
                'address': address,
                'new_name': new_name,
            }
        }
    
    def _build_dependencies_vector(self, func_data: Dict) -> Dict[str, Any]:
        """Build dependencies-focused vector (for 'what does this call?' queries)."""
        new_name = func_data.get('new_name', 'unknown')
        address = func_data.get('address', 'unknown')
        dependencies = func_data.get('dependencies', {})
        
        calls = dependencies.get('calls', [])
        called_by = dependencies.get('called_by', [])
        
        content = f"""# Dependencies: {new_name}

## Functions This Calls
{chr(10).join(f'- {c.get("address", "unknown")}' for c in calls[:10]) if calls else '- None (leaf function)'}
{f'... and {len(calls)-10} more' if len(calls) > 10 else ''}

## Functions That Call This
{chr(10).join(f'- {c.get("address", "unknown")}' for c in called_by[:10]) if called_by else '- None (possibly entry point or unused)'}
{f'... and {len(called_by)-10} more' if len(called_by) > 10 else ''}

**Call Depth:** {dependencies.get('call_depth', 0)}
"""
        
        return {
            'title': f"Dependencies: {new_name}",
            'content': content,
            'metadata': {
                **func_data.get('metadata', {}),
                'chunk_type': 'dependencies',
                'address': address,
                'new_name': new_name,
            }
        }
    
    def _build_security_vector(self, func_data: Dict) -> Dict[str, Any]:
        """Build security-focused vector (for security analysis queries)."""
        new_name = func_data.get('new_name', 'unknown')
        address = func_data.get('address', 'unknown')
        security = func_data.get('security', {})
        categories = func_data.get('categories', {})
        
        content = f"""# Security Analysis: {new_name}

**Criticality:** {security.get('criticality', 'low').upper()}
**Domain:** {categories.get('primary_domain', 'general')}

## Security Indicators
{chr(10).join(f'- {i.replace("_", " ").title()}' for i in security.get('indicators', [])) if security.get('indicators') else '- Standard function'}

## Identified Risks
{chr(10).join(f'- {r}' for r in security.get('risks', [])) if security.get('risks') else '- No specific risks identified'}

## Operations
{', '.join(op.replace('_', ' ').title() for op in categories.get('operations', []))}
"""
        
        return {
            'title': f"Security: {new_name}",
            'content': content,
            'metadata': {
                **func_data.get('metadata', {}),
                'chunk_type': 'security',
                'address': address,
                'new_name': new_name,
                'security_relevant': True,
            }
        }
    
    def _build_dataflow_vector(self, func_data: Dict) -> Dict[str, Any]:
        """Build data flow-focused vector (for 'what data does this process?' queries)."""
        new_name = func_data.get('new_name', 'unknown')
        address = func_data.get('address', 'unknown')
        data_flow = func_data.get('data_flow', {})
        signature = func_data.get('signature', {})
        
        params = signature.get('parameters', [])
        
        content = f"""# Data Flow: {new_name}

## Inputs
{chr(10).join(f'- {p.get("type", "?")} {p.get("name", "?")}' for p in params) if params else '- No parameters'}

## Outputs
Returns: `{signature.get('return_type', 'unknown')}`

## Side Effects
{chr(10).join(f'- {s.replace("_", " ").title()}' for s in data_flow.get('side_effects', [])) if data_flow.get('side_effects') else '- Pure function (no side effects)'}

## Global Access
{chr(10).join(f'- {g}' for g in data_flow.get('globals_accessed', [])) if data_flow.get('globals_accessed') else '- No global variables accessed'}

**Return Points:** {data_flow.get('return_points', 0)}
"""
        
        return {
            'title': f"Data Flow: {new_name}",
            'content': content,
            'metadata': {
                **func_data.get('metadata', {}),
                'chunk_type': 'dataflow',
                'address': address,
                'new_name': new_name,
            }
        }
    
    # ========== Helper Methods ==========
    
    def _generate_semantic_tags(self, func_data: Dict) -> List[str]:
        """Generate semantic tags for filtering and search."""
        tags = set()
        
        # Add domain tags
        categories = func_data.get('categories', {})
        domain = categories.get('primary_domain', 'general')
        tags.add(domain)
        
        # Add operation tags
        for op in categories.get('operations', []):
            tags.add(op)
        
        # Add security tags
        security = func_data.get('security', {})
        if security.get('criticality') in ['high', 'critical']:
            tags.add('security_critical')
        
        # Add complexity tags
        metrics = func_data.get('metrics', {})
        complexity = metrics.get('complexity_tier', 'unknown')
        tags.add(f'complexity_{complexity}')
        
        # Add pattern tags
        patterns = func_data.get('patterns', [])
        for pattern in patterns:
            tags.add(pattern)
        
        return sorted(list(tags))
    
    def _build_fallback_document(self, func_data: Dict) -> Dict[str, Any]:
        """Build a minimal fallback document if main build fails."""
        address = func_data.get('address', 'unknown')
        new_name = func_data.get('new_name', 'unknown')
        
        return {
            'title': f"Function: {new_name}",
            'content': f"# {new_name}\n\nAddress: {address}\n\n*(Metadata extraction in progress)*",
            'metadata': {
                'type': 'function_analysis',
                'address': address,
                'new_name': new_name,
                'domain': 'unknown',
                'security_relevant': False,
                'complexity': 'unknown',
                'operations': [],
                'semantic_tags': [],
                'chunk_type': 'primary',
            }
        }
