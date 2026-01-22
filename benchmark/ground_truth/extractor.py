"""
Ground Truth Extractor
=======================

Main orchestrator for extracting ground truth from source code projects.
Handles C/C++ parsing, docstring extraction, and LLM summary generation.

Usage:
    extractor = GroundTruthExtractor(ollama_client)
    ground_truth = extractor.extract_from_project(
        source_dir="path/to/source",
        binary_path="path/to/compiled.bin",
        output_path="benchmark/ground_truth/project_name.json"
    )
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field, asdict
from datetime import datetime

logger = logging.getLogger("oghidra.benchmark.ground_truth")


@dataclass
class FunctionGroundTruth:
    """Ground truth data for a single function."""

    # Identity
    function_id: str
    function_name: str
    source_file: str
    line_number: int

    # Source code artifacts
    signature: str
    original_docstring: Optional[str]
    source_code: str

    # Generated ground truth
    llm_source_summary: Optional[str] = None

    # Binary mapping (filled after compilation)
    binary_path: Optional[str] = None
    binary_address: Optional[str] = None
    optimization_level: Optional[str] = None

    # OGhidra generated (filled during benchmark)
    oghidra_summary: Optional[str] = None
    oghidra_suggested_name: Optional[str] = None

    # Metadata
    complexity_score: Optional[int] = None
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class GroundTruthDataset:
    """Complete ground truth dataset for a project."""

    # Dataset metadata
    name: str
    version: str
    created_at: str
    source_project: str

    # Configuration
    optimization_levels: List[str]
    compiler: str
    compiler_version: str

    # Functions
    functions: List[FunctionGroundTruth]

    # Statistics
    total_functions: int = 0
    functions_with_docstrings: int = 0
    functions_with_summaries: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "created_at": self.created_at,
            "source_project": self.source_project,
            "optimization_levels": self.optimization_levels,
            "compiler": self.compiler,
            "compiler_version": self.compiler_version,
            "total_functions": len(self.functions),
            "functions_with_docstrings": sum(1 for f in self.functions if f.original_docstring),
            "functions_with_summaries": sum(1 for f in self.functions if f.llm_source_summary),
            "functions": [f.to_dict() for f in self.functions],
        }

    def save(self, path: str):
        """Save dataset to JSON file."""
        with open(path, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)
        logger.info(f"Saved ground truth dataset to {path}")

    @classmethod
    def load(cls, path: str) -> "GroundTruthDataset":
        """Load dataset from JSON file."""
        with open(path, 'r') as f:
            data = json.load(f)

        functions = [FunctionGroundTruth(**f) for f in data.pop("functions")]
        return cls(functions=functions, **data)


class GroundTruthExtractor:
    """
    Extracts ground truth from source code for benchmark evaluation.

    This class:
    1. Parses C/C++ source files for function definitions
    2. Extracts existing docstrings/comments
    3. Generates LLM summaries from source code
    4. Maps functions to binary addresses after compilation
    """

    def __init__(
        self,
        ollama_client: Optional[Any] = None,
        generate_summaries: bool = True,
    ):
        """
        Initialize the extractor.

        Args:
            ollama_client: OllamaClient for generating summaries (optional)
            generate_summaries: Whether to generate LLM summaries from source
        """
        self.ollama_client = ollama_client
        self.generate_summaries = generate_summaries and ollama_client is not None

        logger.info(f"GroundTruthExtractor initialized (summaries: {self.generate_summaries})")

    def extract_from_project(
        self,
        source_dir: str,
        project_name: str,
        binary_path: Optional[str] = None,
        optimization_level: str = "O2",
        compiler: str = "gcc",
        compiler_version: str = "unknown",
        file_patterns: List[str] = None,
    ) -> GroundTruthDataset:
        """
        Extract ground truth from a source code project.

        Args:
            source_dir: Path to source code directory
            project_name: Name for this dataset
            binary_path: Path to compiled binary (optional)
            optimization_level: Compiler optimization level
            compiler: Compiler used
            compiler_version: Compiler version
            file_patterns: Glob patterns for source files (default: *.c, *.cpp)

        Returns:
            GroundTruthDataset with extracted functions
        """
        from .source_parser import SourceCodeParser
        from .summary_generator import SourceSummaryGenerator

        source_path = Path(source_dir)
        if not source_path.exists():
            raise ValueError(f"Source directory not found: {source_dir}")

        # Default patterns for C/C++
        if file_patterns is None:
            file_patterns = ["**/*.c", "**/*.cpp", "**/*.cc", "**/*.h", "**/*.hpp"]

        # Find all source files
        source_files = []
        for pattern in file_patterns:
            source_files.extend(source_path.glob(pattern))

        logger.info(f"Found {len(source_files)} source files in {source_dir}")

        # Parse source files
        parser = SourceCodeParser()
        all_functions: List[FunctionGroundTruth] = []

        for source_file in source_files:
            try:
                functions = parser.parse_file(str(source_file), str(source_path))
                all_functions.extend(functions)
            except Exception as e:
                logger.warning(f"Failed to parse {source_file}: {e}")

        logger.info(f"Extracted {len(all_functions)} functions from source")

        # Generate LLM summaries if enabled
        if self.generate_summaries and self.ollama_client:
            generator = SourceSummaryGenerator(self.ollama_client)
            for func in all_functions:
                try:
                    func.llm_source_summary = generator.generate_summary(func)
                except Exception as e:
                    logger.warning(f"Failed to generate summary for {func.function_name}: {e}")

        # Set binary info if provided
        if binary_path:
            for func in all_functions:
                func.binary_path = binary_path
                func.optimization_level = optimization_level

        # Create dataset
        dataset = GroundTruthDataset(
            name=project_name,
            version="1.0.0",
            created_at=datetime.now().isoformat(),
            source_project=str(source_path),
            optimization_levels=[optimization_level],
            compiler=compiler,
            compiler_version=compiler_version,
            functions=all_functions,
        )

        logger.info(f"Created ground truth dataset: {len(all_functions)} functions")
        return dataset

    def map_binary_addresses(
        self,
        dataset: GroundTruthDataset,
        ghidra_client: Any,
    ) -> GroundTruthDataset:
        """
        Map source functions to binary addresses using Ghidra.

        This requires the binary to have debug symbols or for function
        names to be preserved (non-stripped).

        Args:
            dataset: Ground truth dataset to update
            ghidra_client: GhidraMCPClient connected to Ghidra with binary loaded

        Returns:
            Updated dataset with binary addresses
        """
        # Get all functions from Ghidra
        ghidra_functions = ghidra_client.list_functions()

        # Build lookup by name
        ghidra_lookup = {}
        for func_line in ghidra_functions:
            if " at " in func_line:
                name, addr = func_line.split(" at ", 1)
                ghidra_lookup[name.strip()] = addr.strip()

        # Map functions
        mapped_count = 0
        for func in dataset.functions:
            if func.function_name in ghidra_lookup:
                func.binary_address = ghidra_lookup[func.function_name]
                mapped_count += 1

        logger.info(f"Mapped {mapped_count}/{len(dataset.functions)} functions to binary addresses")
        return dataset
