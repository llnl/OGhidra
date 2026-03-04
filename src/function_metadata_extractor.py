"""
Function Metadata Extractor for Enhanced Knowledge Space

This module extracts structured metadata from decompiled C code to create
rich, queryable function knowledge for the Smart Enumeration system.

Author: OGhidra Enhanced Knowledge System
Date: 2026-02-19
"""

import re
import logging
from typing import Dict, List, Any, Set, Optional

logger = logging.getLogger("ollama-ghidra-bridge.metadata_extractor")


class FunctionMetadataExtractor:
    """
    Extract structured metadata from decompiled function code.
    
    Capabilities:
    - Code metrics (LOC, complexity, instruction count)
    - Operation categorization (crypto, network, file I/O, etc.)
    - Function signature parsing
    - Code pattern detection
    - Security indicator analysis
    """
    
    # Operation detection patterns
    CRYPTO_PATTERNS = [
        r'\b(encrypt|decrypt|cipher|hash|md5|sha\d+|aes|des|rsa|crypto|random|nonce|iv)\b',
        r'\bCrypt\w+',
        r'\b(key|salt|hmac)\b'
    ]
    
    NETWORK_PATTERNS = [
        r'\b(socket|connect|send|recv|bind|listen|accept|http|tcp|udp|ip|dns)\b',
        r'\b(WSA|getaddrinfo|inet_|htons|ntohs)\b',
        r'\b(url|uri|request|response|packet)\b'
    ]
    
    FILE_IO_PATTERNS = [
        r'\b(fopen|fclose|fread|fwrite|fseek|ftell|file|FILE)\b',
        r'\b(open|close|read|write|lseek)\b',
        r'\b(CreateFile|ReadFile|WriteFile|CloseHandle)\b',
        r'\b(path|directory|folder)\b'
    ]
    
    MEMORY_PATTERNS = [
        r'\b(malloc|calloc|realloc|free|new|delete)\b',
        r'\b(memcpy|memset|memmove|memcmp)\b',
        r'\b(HeapAlloc|HeapFree|VirtualAlloc|VirtualFree)\b',
        r'\b(buffer|alloc)\b'
    ]
    
    STRING_PATTERNS = [
        r'\b(str(cpy|cat|cmp|len|chr|str|tok|dup|n\w+))\b',
        r'\b(sprintf|snprintf|printf|scanf)\b',
        r'\b(wcs\w+|_tcs\w+)\b',
        r'\b(string|text|char\s*\*)\b'
    ]
    
    VALIDATION_PATTERNS = [
        r'\bif\s*\([^)]*(<|>|==|!=|<=|>=)',
        r'\b(validate|check|verify|assert|ensure)\b',
        r'\breturn\s+(NULL|0|-1|FALSE)',
        r'\b(bounds|range|limit|max|min)\b'
    ]
    
    REGISTRY_PATTERNS = [
        r'\b(Reg(OpenKey|QueryValue|SetValue|CreateKey|DeleteKey|CloseKey))\b',
        r'\b(HKEY_|registry)\b'
    ]
    
    PROCESS_PATTERNS = [
        r'\b(CreateProcess|OpenProcess|TerminateProcess|process)\b',
        r'\b(thread|CreateThread|_beginthread)\b',
        r'\b(mutex|semaphore|event|critical_section)\b'
    ]
    
    def __init__(self):
        """Initialize the metadata extractor."""
        self.logger = logger
    
    def extract_all_metadata(self, decompiled_code: str, function_name: str,
                            context: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Extract all metadata from decompiled function code.
        
        Args:
            decompiled_code: Decompiled C code of the function
            function_name: Name of the function
            context: Optional context with caller/callee information
        
        Returns:
            Dictionary containing all extracted metadata
        """
        try:
            metadata = {
                'metrics': self.extract_metrics(decompiled_code),
                'categories': self.categorize_operations(decompiled_code, function_name),
                'signature': self.extract_function_signature(decompiled_code),
                'patterns': self.detect_patterns(decompiled_code),
                'security': None,  # Will be populated after categories
                'data_flow': self.extract_data_flow(decompiled_code),
                'dependencies': self.extract_dependencies(context) if context else {},
            }
            
            # Security analysis depends on categories
            metadata['security'] = self.analyze_security_indicators(
                decompiled_code, 
                metadata['categories']['operations']
            )
            
            return metadata
            
        except Exception as e:
            self.logger.error(f"Error extracting metadata: {e}")
            return self._get_default_metadata()
    
    def extract_metrics(self, decompiled_code: str) -> Dict[str, Any]:
        """
        Extract code complexity metrics.
        
        Returns:
            Dict with: size_bytes, code_lines, cyclomatic_complexity, complexity_tier
        """
        lines = decompiled_code.split('\n')
        
        # Count actual code lines (exclude comments, braces, empty)
        code_lines = [line.strip() for line in lines 
                     if line.strip() and 
                     not line.strip() in ['{', '}', ''] and
                     not line.strip().startswith('//') and
                     not line.strip().startswith('/*')]
        
        # Estimate cyclomatic complexity (count decision points)
        complexity = 1  # Base complexity
        complexity += len(re.findall(r'\bif\s*\(', decompiled_code))
        complexity += len(re.findall(r'\belse\s+if\s*\(', decompiled_code))
        complexity += len(re.findall(r'\bwhile\s*\(', decompiled_code))
        complexity += len(re.findall(r'\bfor\s*\(', decompiled_code))
        complexity += len(re.findall(r'\bcase\s+', decompiled_code))
        complexity += len(re.findall(r'\b(&&|\|\|)', decompiled_code))
        complexity += len(re.findall(r'\b\?\s*', decompiled_code))  # Ternary operators
        
        # Determine complexity tier
        if complexity <= 5:
            tier = 'simple'
        elif complexity <= 15:
            tier = 'medium'
        else:
            tier = 'complex'
        
        return {
            'size_bytes': len(decompiled_code),
            'code_lines': len(code_lines),
            'cyclomatic_complexity': complexity,
            'complexity_tier': tier,
            'estimated_instructions': len(code_lines) * 2,  # Rough estimate
        }
    
    def categorize_operations(self, decompiled_code: str, 
                             function_name: str) -> Dict[str, Any]:
        """
        Categorize the operations performed by the function.
        
        Returns:
            Dict with: primary_domain, operations list, patterns
        """
        operations = set()
        code_lower = decompiled_code.lower()
        name_lower = function_name.lower()
        
        # Check each operation category
        if self._matches_patterns(code_lower, self.CRYPTO_PATTERNS):
            operations.add('crypto')
        if self._matches_patterns(code_lower, self.NETWORK_PATTERNS):
            operations.add('network')
        if self._matches_patterns(code_lower, self.FILE_IO_PATTERNS):
            operations.add('file_io')
        if self._matches_patterns(code_lower, self.MEMORY_PATTERNS):
            operations.add('memory')
        if self._matches_patterns(code_lower, self.STRING_PATTERNS):
            operations.add('string_manipulation')
        if self._matches_patterns(code_lower, self.VALIDATION_PATTERNS):
            operations.add('validation')
        if self._matches_patterns(code_lower, self.REGISTRY_PATTERNS):
            operations.add('registry')
        if self._matches_patterns(code_lower, self.PROCESS_PATTERNS):
            operations.add('process_management')
        
        # Check for authentication/authorization
        if any(kw in name_lower for kw in ['auth', 'login', 'password', 'credential', 'token', 'session']):
            operations.add('authentication')
        
        # Check for parsing/serialization
        if any(kw in code_lower for kw in ['parse', 'serialize', 'deserialize', 'json', 'xml', 'format']):
            operations.add('parsing')
        
        # Determine primary domain
        primary_domain = self._determine_primary_domain(operations, name_lower)
        
        return {
            'primary_domain': primary_domain,
            'operations': sorted(list(operations)),
            'security_relevant': self._is_security_relevant(operations),
        }
    
    def extract_function_signature(self, decompiled_code: str) -> Dict[str, Any]:
        """
        Parse function signature from decompiled code.
        
        Returns:
            Dict with: return_type, parameters, calling_convention
        """
        # Try to find function definition (first non-comment line with parentheses)
        lines = decompiled_code.split('\n')
        signature_line = None
        
        for line in lines:
            stripped = line.strip()
            if stripped and not stripped.startswith('//') and '(' in stripped:
                signature_line = stripped
                break
        
        if not signature_line:
            return self._get_default_signature()
        
        # Parse return type
        return_type = 'unknown'
        if signature_line:
            parts = signature_line.split('(')[0].strip().split()
            if len(parts) >= 2:
                return_type = ' '.join(parts[:-1])  # Everything except function name
        
        # Parse parameters
        params = self._parse_parameters(signature_line)
        
        # Detect calling convention
        calling_convention = 'unknown'
        if '__cdecl' in signature_line:
            calling_convention = 'cdecl'
        elif '__stdcall' in signature_line:
            calling_convention = 'stdcall'
        elif '__fastcall' in signature_line:
            calling_convention = 'fastcall'
        elif '__thiscall' in signature_line:
            calling_convention = 'thiscall'
        
        return {
            'return_type': return_type,
            'parameters': params,
            'calling_convention': calling_convention,
            'param_count': len(params),
        }
    
    def detect_patterns(self, decompiled_code: str) -> List[str]:
        """
        Detect common code patterns.
        
        Returns:
            List of detected pattern names
        """
        patterns = []
        
        # Error handling pattern
        if re.search(r'if\s*\([^)]*==\s*(NULL|0|-1)\s*\)', decompiled_code):
            patterns.append('error_handling')
        
        # Loop pattern
        if 'for' in decompiled_code or 'while' in decompiled_code:
            patterns.append('iterative_processing')
        
        # Validation pattern (multiple checks)
        validation_checks = len(re.findall(r'if\s*\([^)]*(<|>|==|!=)', decompiled_code))
        if validation_checks >= 3:
            patterns.append('input_validation')
        
        # State machine pattern (switch with many cases)
        case_count = len(re.findall(r'\bcase\s+', decompiled_code))
        if case_count >= 5:
            patterns.append('state_machine')
        
        # Factory pattern (returns different types)
        if 'switch' in decompiled_code and 'return' in decompiled_code:
            patterns.append('conditional_return')
        
        # Resource management (alloc + free pairs)
        has_alloc = bool(re.search(r'\b(malloc|calloc|new|alloc)\b', decompiled_code, re.I))
        has_free = bool(re.search(r'\b(free|delete)\b', decompiled_code, re.I))
        if has_alloc and has_free:
            patterns.append('resource_management')
        
        # Callback pattern
        if re.search(r'\(\s*\*\s*\w+\s*\)', decompiled_code):
            patterns.append('callback_usage')
        
        return patterns
    
    def analyze_security_indicators(self, decompiled_code: str, 
                                   operations: List[str]) -> Dict[str, Any]:
        """
        Analyze security-relevant indicators.
        
        Returns:
            Dict with: indicators, risks, criticality
        """
        indicators = set()
        risks = []
        
        # Check operations for security relevance
        if 'crypto' in operations:
            indicators.add('uses_crypto')
        if 'network' in operations:
            indicators.add('network_communication')
        if 'authentication' in operations:
            indicators.add('handles_credentials')
        if 'file_io' in operations:
            indicators.add('file_access')
        if 'registry' in operations:
            indicators.add('registry_access')
        if 'process_management' in operations:
            indicators.add('process_manipulation')
        
        # Check for dangerous functions
        dangerous_funcs = [
            'strcpy', 'strcat', 'sprintf', 'gets', 'scanf',  # Buffer overflow risks
            'system', 'exec', 'popen',  # Command injection risks
            'eval',  # Code injection risks
        ]
        for func in dangerous_funcs:
            if re.search(rf'\b{func}\b', decompiled_code):
                indicators.add('uses_dangerous_function')
                risks.append(f"Uses potentially unsafe function: {func}")
        
        # Determine criticality
        criticality = 'low'
        if 'handles_credentials' in indicators or 'uses_crypto' in indicators:
            criticality = 'high'
        elif 'network_communication' in indicators or 'process_manipulation' in indicators:
            criticality = 'medium'
        elif len(indicators) >= 3:
            criticality = 'medium'
        
        return {
            'indicators': sorted(list(indicators)),
            'risks': risks,
            'criticality': criticality,
        }
    
    def extract_data_flow(self, decompiled_code: str) -> Dict[str, Any]:
        """
        Extract data flow information.
        
        Returns:
            Dict with: parameters, return_value, side_effects, globals_accessed
        """
        # Extract global variable accesses
        globals_accessed = []
        global_pattern = r'\bg_\w+|[A-Z_]{3,}'  # Common global naming patterns
        for match in re.finditer(global_pattern, decompiled_code):
            var_name = match.group(0)
            if var_name not in globals_accessed:
                globals_accessed.append(var_name)
        
        # Detect side effects
        side_effects = []
        if re.search(r'\b(fprintf|printf|log|write)\b', decompiled_code, re.I):
            side_effects.append('writes_to_output')
        if re.search(r'\b(fwrite|WriteFile|write)\b', decompiled_code):
            side_effects.append('writes_to_file')
        if globals_accessed:
            side_effects.append('modifies_globals')
        if re.search(r'\b(malloc|calloc|new)\b', decompiled_code):
            side_effects.append('allocates_memory')
        
        # Detect return behavior
        return_count = len(re.findall(r'\breturn\b', decompiled_code))
        has_void_return = 'void' in decompiled_code.split('\n')[0] if decompiled_code else False
        
        return {
            'globals_accessed': globals_accessed[:10],  # Limit to 10
            'side_effects': side_effects,
            'return_points': return_count,
            'has_void_return': has_void_return,
        }
    
    def extract_dependencies(self, context: Dict) -> Dict[str, Any]:
        """
        Extract function dependencies from context.
        
        Args:
            context: Context dict with callers_code and callees_code
        
        Returns:
            Dict with: calls, called_by, depth
        """
        calls = []
        called_by = []
        
        # Extract callees
        if context and 'callees_code' in context:
            for callee in context['callees_code']:
                calls.append({
                    'address': callee.get('address', 'unknown'),
                    'importance': 'medium',  # Could be enhanced with better heuristics
                })
        
        # Extract callers
        if context and 'callers_code' in context:
            for caller in context['callers_code']:
                called_by.append({
                    'address': caller.get('address', 'unknown'),
                    'context': 'unknown',  # Could be enhanced
                })
        
        return {
            'calls': calls,
            'called_by': called_by,
            'call_depth': len(calls),
        }
    
    # Helper methods
    
    def _matches_patterns(self, text: str, patterns: List[str]) -> bool:
        """Check if text matches any of the given regex patterns."""
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False
    
    def _determine_primary_domain(self, operations: Set[str], 
                                  function_name: str) -> str:
        """Determine the primary functional domain of the function."""
        # Priority order for domain assignment
        domain_priority = [
            ('authentication', ['authentication']),
            ('cryptography', ['crypto']),
            ('networking', ['network']),
            ('file_system', ['file_io']),
            ('process_management', ['process_management']),
            ('registry', ['registry']),
            ('memory_management', ['memory']),
            ('data_processing', ['parsing', 'string_manipulation', 'validation']),
        ]
        
        for domain, keywords in domain_priority:
            if any(kw in operations for kw in keywords):
                return domain
        
        # Fallback to name-based classification
        if any(kw in function_name for kw in ['init', 'setup', 'config']):
            return 'initialization'
        if any(kw in function_name for kw in ['cleanup', 'destroy', 'close']):
            return 'cleanup'
        
        return 'general'
    
    def _is_security_relevant(self, operations: Set[str]) -> bool:
        """Determine if operations are security-relevant."""
        security_ops = {'crypto', 'network', 'authentication', 'registry', 'process_management'}
        return bool(operations & security_ops)
    
    def _parse_parameters(self, signature_line: str) -> List[Dict[str, str]]:
        """Parse function parameters from signature."""
        params = []
        
        # Extract parameter list from signature
        match = re.search(r'\(([^)]*)\)', signature_line)
        if not match:
            return params
        
        param_string = match.group(1).strip()
        if not param_string or param_string == 'void':
            return params
        
        # Split parameters
        param_parts = param_string.split(',')
        for part in param_parts:
            part = part.strip()
            if not part:
                continue
            
            # Try to extract type and name
            tokens = part.split()
            if len(tokens) >= 2:
                param_type = ' '.join(tokens[:-1])
                param_name = tokens[-1].rstrip('*').rstrip('[').split('[')[0]
                params.append({
                    'name': param_name,
                    'type': param_type,
                    'usage': 'input',  # Default assumption
                })
            elif len(tokens) == 1:
                params.append({
                    'name': 'unknown',
                    'type': tokens[0],
                    'usage': 'input',
                })
        
        return params
    
    def _get_default_metadata(self) -> Dict[str, Any]:
        """Return default metadata structure when extraction fails."""
        return {
            'metrics': {
                'size_bytes': 0,
                'code_lines': 0,
                'cyclomatic_complexity': 1,
                'complexity_tier': 'unknown',
                'estimated_instructions': 0,
            },
            'categories': {
                'primary_domain': 'unknown',
                'operations': [],
                'security_relevant': False,
            },
            'signature': self._get_default_signature(),
            'patterns': [],
            'security': {
                'indicators': [],
                'risks': [],
                'criticality': 'low',
            },
            'data_flow': {
                'globals_accessed': [],
                'side_effects': [],
                'return_points': 0,
                'has_void_return': False,
            },
            'dependencies': {
                'calls': [],
                'called_by': [],
                'call_depth': 0,
            }
        }
    
    def _get_default_signature(self) -> Dict[str, Any]:
        """Return default function signature."""
        return {
            'return_type': 'unknown',
            'parameters': [],
            'calling_convention': 'unknown',
            'param_count': 0,
        }
