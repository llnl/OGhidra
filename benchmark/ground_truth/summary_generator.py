"""
Source Summary Generator
=========================

Generates AI summaries from source code to serve as ground truth.
These summaries represent what the AI "should" produce if it had
access to the original source code.
"""

import logging
from typing import Any, Optional

from .extractor import FunctionGroundTruth

logger = logging.getLogger("oghidra.benchmark.ground_truth.generator")


# Prompt template for generating source code summaries
SOURCE_SUMMARY_PROMPT = """You are analyzing source code to create a ground truth summary for benchmarking.

## Task
Analyze this C/C++ function and provide a clear, accurate summary of what it does.
This summary will be used as ground truth to evaluate how well AI can understand decompiled code.

## Function Information
**Name:** {function_name}
**Signature:** {signature}
**File:** {source_file}

## Documentation (if available):
{docstring}

## Source Code:
```c
{source_code}
```

## Instructions
Provide a summary that includes:
1. **Primary Purpose**: What is the main goal of this function? (1-2 sentences)
2. **Key Operations**: What are the important operations it performs?
3. **Inputs/Outputs**: What does it take as input and what does it return/modify?
4. **Side Effects**: Any notable side effects (memory allocation, file I/O, etc.)?

Write your summary in a clear, technical style that a reverse engineer would find useful.
Focus on behavioral description rather than implementation details.

## Summary:"""


class SourceSummaryGenerator:
    """
    Generates ground truth summaries from source code using an LLM.

    These summaries represent the "ideal" understanding that should be
    achievable from the source code, serving as the benchmark target.
    """

    def __init__(
        self,
        ollama_client: Any,
        model: Optional[str] = None,
        temperature: float = 0.3,
        max_source_chars: int = 4000,
    ):
        """
        Initialize the summary generator.

        Args:
            ollama_client: OllamaClient instance for generation
            model: Model to use (defaults to client's configured model)
            temperature: Temperature for generation (lower = more deterministic)
            max_source_chars: Maximum source code characters to include
        """
        self.ollama_client = ollama_client
        self.model = model
        self.temperature = temperature
        self.max_source_chars = max_source_chars

        logger.info(f"SourceSummaryGenerator initialized (model: {model or 'default'})")

    def generate_summary(
        self,
        func: FunctionGroundTruth,
    ) -> str:
        """
        Generate a ground truth summary for a function.

        Args:
            func: FunctionGroundTruth object with source code

        Returns:
            Generated summary string
        """
        # Truncate source if too long
        source_code = func.source_code
        if len(source_code) > self.max_source_chars:
            source_code = source_code[: self.max_source_chars] + "\n// ... [truncated]"

        # Format docstring
        docstring = func.original_docstring or "No documentation available."

        # Build prompt
        prompt = SOURCE_SUMMARY_PROMPT.format(
            function_name=func.function_name,
            signature=func.signature,
            source_file=func.source_file,
            docstring=docstring,
            source_code=source_code,
        )

        try:
            response = self.ollama_client.generate(
                prompt=prompt,
                model=self.model,
                temperature=self.temperature,
            )

            summary = self._clean_summary(response)
            logger.debug(f"Generated summary for {func.function_name}: {len(summary)} chars")

            return summary

        except Exception as e:
            logger.error(f"Failed to generate summary for {func.function_name}: {e}")
            raise

    def _clean_summary(self, response: str) -> str:
        """Clean up the generated summary."""
        # Remove common artifacts
        summary = response.strip()

        # Remove markdown headers if present
        lines = summary.split("\n")
        cleaned_lines = []
        for line in lines:
            # Skip lines that look like section headers from our prompt
            if line.strip().startswith("## Summary"):
                continue
            if line.strip().startswith("```"):
                continue
            cleaned_lines.append(line)

        return "\n".join(cleaned_lines).strip()

    def batch_generate(
        self,
        functions: list,
        progress_callback: Optional[callable] = None,
    ) -> list:
        """
        Generate summaries for multiple functions.

        Args:
            functions: List of FunctionGroundTruth objects
            progress_callback: Optional callback(current, total) for progress

        Returns:
            List of (function, summary) tuples
        """
        results = []
        total = len(functions)

        for i, func in enumerate(functions):
            try:
                summary = self.generate_summary(func)
                func.llm_source_summary = summary
                results.append((func, summary))
            except Exception as e:
                logger.warning(f"Skipping {func.function_name}: {e}")
                results.append((func, None))

            if progress_callback:
                progress_callback(i + 1, total)

        return results
