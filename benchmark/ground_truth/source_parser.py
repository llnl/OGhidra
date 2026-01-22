"""
Source Code Parser
===================

Parses C/C++ source files to extract function definitions, signatures,
and documentation comments.

Uses regex-based parsing for portability (no external dependencies like libclang).
For more accurate parsing, consider integrating with tree-sitter or clang.
"""

import re
import logging
from pathlib import Path
from typing import List, Optional, Tuple

from .extractor import FunctionGroundTruth

logger = logging.getLogger("oghidra.benchmark.ground_truth.parser")


class SourceCodeParser:
    """
    Parser for C/C++ source files.

    Extracts function definitions with their signatures, bodies, and
    preceding documentation comments (Doxygen-style or C-style).
    """

    # Regex patterns for C/C++ parsing
    PATTERNS = {
        # Doxygen-style comments: /** ... */ or /// ...
        'doxygen_block': re.compile(
            r'/\*\*\s*(.*?)\s*\*/',
            re.DOTALL
        ),
        'doxygen_line': re.compile(
            r'(?:^|\n)\s*///\s*(.+?)(?=\n(?!\s*///))',
            re.MULTILINE
        ),

        # C-style block comment: /* ... */
        'c_block_comment': re.compile(
            r'/\*\s*(.*?)\s*\*/',
            re.DOTALL
        ),

        # Function definition pattern (simplified)
        # Captures: return_type, function_name, parameters, body
        'function_def': re.compile(
            r'''
            # Optional static/inline/extern keywords
            (?:(?:static|inline|extern|__attribute__\s*\([^)]*\))\s+)*
            # Return type (including pointers)
            ([\w\s\*]+?)\s+
            # Function name
            (\w+)\s*
            # Parameters
            \(([^)]*)\)\s*
            # Function body
            (\{(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*\})
            ''',
            re.VERBOSE | re.MULTILINE
        ),

        # Simpler function signature (for declarations)
        'function_sig': re.compile(
            r'([\w\s\*]+?)\s+(\w+)\s*\(([^)]*)\)',
            re.MULTILINE
        ),
    }

    # Keywords that are not function names
    KEYWORDS = {
        'if', 'else', 'while', 'for', 'do', 'switch', 'case', 'default',
        'return', 'break', 'continue', 'goto', 'sizeof', 'typeof',
        'struct', 'union', 'enum', 'typedef', 'static', 'extern',
        'const', 'volatile', 'inline', 'register', 'auto',
    }

    def __init__(self):
        """Initialize the parser."""
        logger.info("SourceCodeParser initialized")

    def parse_file(
        self,
        file_path: str,
        base_path: str = "",
    ) -> List[FunctionGroundTruth]:
        """
        Parse a C/C++ source file and extract functions.

        Args:
            file_path: Path to source file
            base_path: Base path for relative file paths

        Returns:
            List of FunctionGroundTruth objects
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Source file not found: {file_path}")

        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()

        # Get relative path for cleaner reporting
        if base_path:
            try:
                rel_path = path.relative_to(base_path)
            except ValueError:
                rel_path = path
        else:
            rel_path = path

        functions = self._extract_functions(content, str(rel_path))
        logger.debug(f"Extracted {len(functions)} functions from {rel_path}")

        return functions

    def _extract_functions(
        self,
        content: str,
        source_file: str,
    ) -> List[FunctionGroundTruth]:
        """Extract all functions from source content."""
        functions = []

        # Find all function definitions
        for match in self.PATTERNS['function_def'].finditer(content):
            return_type = match.group(1).strip()
            func_name = match.group(2).strip()
            params = match.group(3).strip()
            body = match.group(4)

            # Skip keywords mistaken as function names
            if func_name in self.KEYWORDS:
                continue

            # Skip very short names (likely macros)
            if len(func_name) < 2:
                continue

            # Calculate line number
            line_number = content[:match.start()].count('\n') + 1

            # Build signature
            signature = f"{return_type} {func_name}({params})"

            # Find preceding comment (docstring)
            docstring = self._find_preceding_comment(content, match.start())

            # Generate unique ID
            func_id = f"{source_file}:{func_name}:{line_number}"

            # Estimate complexity (simple heuristic)
            complexity = self._estimate_complexity(body)

            # Extract tags from function characteristics
            tags = self._extract_tags(func_name, body, docstring)

            functions.append(FunctionGroundTruth(
                function_id=func_id,
                function_name=func_name,
                source_file=source_file,
                line_number=line_number,
                signature=signature,
                original_docstring=docstring,
                source_code=body,
                complexity_score=complexity,
                tags=tags,
            ))

        return functions

    def _find_preceding_comment(
        self,
        content: str,
        func_start: int,
    ) -> Optional[str]:
        """Find documentation comment immediately before function."""
        # Look at the 500 characters before the function
        search_start = max(0, func_start - 500)
        preceding = content[search_start:func_start]

        # Try Doxygen block comment first
        matches = list(self.PATTERNS['doxygen_block'].finditer(preceding))
        if matches:
            # Get the last (closest) match
            comment = matches[-1].group(1)
            # Check it's close to the function (within 50 chars of whitespace)
            after_comment = preceding[matches[-1].end():]
            if len(after_comment.strip()) < 50:
                return self._clean_comment(comment)

        # Try regular C block comment
        matches = list(self.PATTERNS['c_block_comment'].finditer(preceding))
        if matches:
            comment = matches[-1].group(1)
            after_comment = preceding[matches[-1].end():]
            if len(after_comment.strip()) < 50:
                return self._clean_comment(comment)

        return None

    def _clean_comment(self, comment: str) -> str:
        """Clean up comment text by removing asterisks and extra whitespace."""
        lines = comment.split('\n')
        cleaned = []
        for line in lines:
            # Remove leading asterisks and whitespace
            line = re.sub(r'^\s*\*\s?', '', line)
            cleaned.append(line)

        result = '\n'.join(cleaned).strip()

        # Remove Doxygen tags for cleaner text
        result = re.sub(r'@\w+\s*', '', result)
        result = re.sub(r'\\[a-z]+\s*', '', result)

        return result if result else None

    def _estimate_complexity(self, body: str) -> int:
        """
        Estimate cyclomatic complexity based on control flow keywords.

        This is a rough approximation - for accurate complexity,
        use proper static analysis tools.
        """
        complexity = 1  # Base complexity

        # Count control flow statements
        control_patterns = [
            r'\bif\s*\(',
            r'\belse\s+if\s*\(',
            r'\bwhile\s*\(',
            r'\bfor\s*\(',
            r'\bcase\s+',
            r'\bcatch\s*\(',
            r'\b\?\s*',  # Ternary operator
            r'\b&&\b',
            r'\b\|\|\b',
        ]

        for pattern in control_patterns:
            complexity += len(re.findall(pattern, body))

        return complexity

    def _extract_tags(
        self,
        func_name: str,
        body: str,
        docstring: Optional[str],
    ) -> List[str]:
        """Extract semantic tags based on function characteristics."""
        tags = []
        combined = f"{func_name} {body} {docstring or ''}"
        combined_lower = combined.lower()

        # Domain detection
        tag_patterns = {
            'crypto': ['encrypt', 'decrypt', 'aes', 'rsa', 'hash', 'sha', 'md5', 'cipher', 'key'],
            'network': ['socket', 'connect', 'send', 'recv', 'http', 'tcp', 'udp', 'port', 'host'],
            'file_io': ['fopen', 'fread', 'fwrite', 'fclose', 'read', 'write', 'file', 'path'],
            'memory': ['malloc', 'free', 'alloc', 'realloc', 'memcpy', 'memset', 'buffer'],
            'string': ['str', 'sprintf', 'printf', 'sscanf', 'parse', 'format', 'concat'],
            'error_handling': ['error', 'exception', 'fail', 'errno', 'perror'],
            'init': ['init', 'setup', 'create', 'new', 'construct'],
            'cleanup': ['cleanup', 'destroy', 'free', 'close', 'release', 'delete'],
            'validation': ['valid', 'check', 'verify', 'assert', 'sanity'],
        }

        for tag, keywords in tag_patterns.items():
            if any(kw in combined_lower for kw in keywords):
                tags.append(tag)

        return tags
