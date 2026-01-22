"""
OGhidra Runner
===============

Integrates with OGhidra to generate function summaries from decompiled code.
This is the "candidate" generator for benchmark evaluation.
"""

import logging
import time
import re
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

logger = logging.getLogger("oghidra.benchmark.runners.oghidra")


@dataclass
class OGhidraResult:
    """Result from OGhidra function analysis."""
    function_address: str
    function_name: str
    decompiled_code: str
    ai_summary: str
    suggested_name: Optional[str]
    analysis_time: float
    context_chars: int
    metadata: Dict[str, Any]


class OGhidraRunner:
    """
    Runner that uses OGhidra to analyze functions and generate summaries.

    This class wraps the OGhidra bridge to:
    1. Decompile functions from binary
    2. Gather caller/callee context
    3. Generate AI summaries
    4. Extract suggested function names
    """

    def __init__(
        self,
        bridge: Any,
        include_context: bool = True,
        max_context_chars: int = 6000,
    ):
        """
        Initialize the OGhidra runner.

        Args:
            bridge: OGhidra Bridge instance
            include_context: Whether to gather caller/callee context
            max_context_chars: Maximum characters for context
        """
        self.bridge = bridge
        self.include_context = include_context
        self.max_context_chars = max_context_chars

        logger.info(f"OGhidraRunner initialized (context: {include_context})")

    def analyze_function(
        self,
        address: str,
        function_name: Optional[str] = None,
    ) -> OGhidraResult:
        """
        Analyze a single function using OGhidra.

        Args:
            address: Function address in hex
            function_name: Known function name (optional)

        Returns:
            OGhidraResult with summary and metadata
        """
        start_time = time.time()

        # Decompile the function
        if function_name:
            decompiled = self.bridge.ghidra.decompile_function(name=function_name)
        else:
            decompiled = self.bridge.ghidra.decompile_function_by_address(address=address)

        if not decompiled or decompiled.lower().startswith("error"):
            raise ValueError(f"Failed to decompile function at {address}: {decompiled}")

        # Gather context if enabled
        context_info = ""
        context_chars = 0

        if self.include_context:
            context_info, context_chars = self._gather_context(address)

        # Build analysis prompt (matches OGhidra's enumerate-binary format)
        analysis_prompt = self._build_analysis_prompt(
            function_name or f"FUN_{address}",
            decompiled,
            context_info,
        )

        # Generate AI summary
        ai_response = self.bridge.ollama.generate(prompt=analysis_prompt)

        # Parse response
        summary, suggested_name = self._parse_response(ai_response)

        analysis_time = time.time() - start_time

        return OGhidraResult(
            function_address=address,
            function_name=function_name or f"FUN_{address}",
            decompiled_code=decompiled,
            ai_summary=summary,
            suggested_name=suggested_name,
            analysis_time=analysis_time,
            context_chars=context_chars,
            metadata={
                "include_context": self.include_context,
                "decompiled_length": len(decompiled),
            },
        )

    def _gather_context(self, address: str) -> tuple:
        """Gather caller/callee context for a function."""
        context_parts = []
        total_chars = 0

        try:
            # Get callers
            callers = self.bridge.ghidra.get_xrefs_to(address=address)
            if isinstance(callers, list) and callers:
                caller_addrs = self._extract_addresses(callers[:3])
                for caller_addr in caller_addrs:
                    if total_chars >= self.max_context_chars:
                        break
                    try:
                        caller_code = self.bridge.ghidra.decompile_function_by_address(address=caller_addr)
                        if caller_code and not caller_code.lower().startswith("error"):
                            truncated = caller_code[:1000] if len(caller_code) > 1000 else caller_code
                            context_parts.append(f"### Caller at {caller_addr}:\n```c\n{truncated}\n```")
                            total_chars += len(truncated)
                    except Exception:
                        pass

            # Get callees
            callees = self.bridge.ghidra.get_xrefs_from(address=address)
            if isinstance(callees, list) and callees:
                callee_addrs = self._extract_addresses(callees[:3])
                for callee_addr in callee_addrs:
                    if total_chars >= self.max_context_chars:
                        break
                    try:
                        callee_code = self.bridge.ghidra.decompile_function_by_address(address=callee_addr)
                        if callee_code and not callee_code.lower().startswith("error"):
                            truncated = callee_code[:1000] if len(callee_code) > 1000 else callee_code
                            context_parts.append(f"### Callee at {callee_addr}:\n```c\n{truncated}\n```")
                            total_chars += len(truncated)
                    except Exception:
                        pass

        except Exception as e:
            logger.warning(f"Failed to gather context for {address}: {e}")

        return "\n\n".join(context_parts), total_chars

    def _extract_addresses(self, xrefs: list) -> list:
        """Extract addresses from xref results."""
        addresses = []
        for xref in xrefs:
            if isinstance(xref, dict):
                addr = xref.get('from_address') or xref.get('to_address') or xref.get('address')
                if addr:
                    addresses.append(str(addr))
            elif isinstance(xref, str):
                match = re.search(r'([0-9a-fA-F]{6,})', xref)
                if match:
                    addresses.append(match.group(1))
        return addresses

    def _build_analysis_prompt(
        self,
        function_name: str,
        decompiled: str,
        context_info: str,
    ) -> str:
        """Build the analysis prompt matching OGhidra's format."""
        prompt = f"""Analyze the function '{function_name}' and provide a detailed summary.

## TARGET FUNCTION: {function_name}
```c
{decompiled}
```
"""
        if context_info:
            prompt += f"""
## CONTEXTUAL INFORMATION (Callers/Callees):
{context_info}
"""

        prompt += """
Based on the function's code and context, provide:

**Function Analysis:**
[What does this function do? Identify specific operations like memory allocation, string manipulation, network operations, file I/O, cryptographic operations, etc.]

**Behavior Summary:**
[1-4 sentence summary describing the function's primary behavior and purpose]

**Suggested Name:** [descriptiveFunctionName]
**Rationale:** [Why this name captures the function's purpose]
"""
        return prompt

    def _parse_response(self, response: str) -> tuple:
        """Parse AI response to extract summary and suggested name."""
        summary = response.strip()
        suggested_name = None

        # Extract suggested name
        lines = response.split('\n')
        for line in lines:
            if 'suggested name:' in line.lower():
                name_part = line.split(':', 1)[1].strip()
                name_part = name_part.replace('**', '').replace('*', '').strip()
                match = re.search(r'\b([a-z][a-zA-Z0-9_]*[a-zA-Z0-9])\b', name_part)
                if match:
                    suggested_name = match.group(1)
                    break

        return summary, suggested_name

    def batch_analyze(
        self,
        addresses: List[str],
        function_names: Optional[List[str]] = None,
        progress_callback: Optional[callable] = None,
    ) -> List[OGhidraResult]:
        """
        Analyze multiple functions.

        Args:
            addresses: List of function addresses
            function_names: Optional list of function names
            progress_callback: Optional callback(current, total) for progress

        Returns:
            List of OGhidraResult objects
        """
        if function_names is None:
            function_names = [None] * len(addresses)

        results = []
        total = len(addresses)

        for i, (addr, name) in enumerate(zip(addresses, function_names)):
            try:
                result = self.analyze_function(addr, name)
                results.append(result)
            except Exception as e:
                logger.warning(f"Failed to analyze {addr}: {e}")

            if progress_callback:
                progress_callback(i + 1, total)

        return results
