#!/usr/bin/env python3
"""
Report Generator
----------------
Extracted from Bridge to isolate the ~2,000-line report-generation subsystem.

The public entry point is ``ReportGenerator.generate_software_report()``.
"""

from __future__ import annotations

import glob
import json
import logging
import os
import re
from datetime import datetime
from typing import Any, Dict, List, Optional


class ReportGenerator:
    """Generates comprehensive software analysis reports from Ghidra binary data.

    Parameters
    ----------
    ghidra_client
        A ``GhidraMCPClient`` (or compatible) used to collect binary data
        (imports, exports, functions, strings, segments, etc.).
    llm_client
        An LLM client (``OllamaClient``, ``ExternalClient``, or ``CustomAPIClient``)
        that exposes a ``generate(prompt=...)`` method.
    session
        A ``SessionMemory`` instance.  The generator reads
        ``session.analysis_state`` for renamed / decompiled function tracking.
    cag_manager
        Optional ``CAGManager`` whose ``.vector_store`` is used for RAG
        retrieval when building prompts.
    enable_cag : bool
        Whether CAG / RAG is enabled.
    logger
        Optional ``logging.Logger``.  Falls back to ``__name__`` logger.
    logs_dir : str | None
        Directory where analysis dump markdown files live.  When *None* the
        generator falls back to ``"logs"``.
    html_report_prompt : str
        The prompt template used for AI-driven HTML report generation.  In the
        original Bridge code this came from ``config.ollama.html_report_generation_prompt``.
    function_summaries : dict | None
        A dict mapping function identifiers to summary strings.  In Bridge
        this lives at ``self.function_summaries``; it is passed through here
        so the generator does not need to reach back into Bridge.
    """

    def __init__(
        self,
        ghidra_client,
        llm_client,
        session,
        cag_manager=None,
        enable_cag: bool = False,
        logger: Optional[logging.Logger] = None,
        logs_dir: Optional[str] = None,
        html_report_prompt: str = "",
        function_summaries: Optional[Dict[str, str]] = None,
    ) -> None:
        self.ghidra = ghidra_client
        self.llm = llm_client
        self.session = session
        self.cag_manager = cag_manager
        self.enable_cag = enable_cag
        self.logger = logger or logging.getLogger(__name__)
        self.logs_dir = logs_dir or "logs"
        self.html_report_prompt = html_report_prompt
        self.function_summaries: Dict[str, str] = function_summaries if function_summaries is not None else {}

        # Build the legacy analysis_state dict from the session model so
        # existing code that reads ``self.analysis_state`` keeps working.
        self.analysis_state: Dict[str, Any] = {
            "functions_decompiled": session.analysis_state.functions_decompiled,
            "functions_renamed": session.analysis_state.functions_renamed,
            "comments_added": session.analysis_state.comments_added,
            "functions_analyzed": session.analysis_state.functions_analyzed,
            "cached_results": session.analysis_state.cached_results,
        }

    # ------------------------------------------------------------------
    #  Utility helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _get_current_timestamp() -> str:
        """Return the current timestamp as an ISO-8601 string."""
        return datetime.now().isoformat()

    # ------------------------------------------------------------------
    #  Public entry point
    # ------------------------------------------------------------------

    def generate_software_report(self, report_format: str = "markdown") -> str:
        """
        Generate a comprehensive software analysis report using AI-powered analysis.

        This method performs complete software behavior analysis including:
        - Software type classification and architecture analysis
        - Security risk assessment with detailed scoring
        - Function categorization and behavioral pattern analysis
        - Comprehensive findings summary with actionable insights

        Args:
            report_format: Output format ("markdown", "text", "json", "html")

        Returns:
            Comprehensive software analysis report string
        """
        try:
            self.logger.info("Starting comprehensive software report generation")

            # Phase 1: Data Collection - Gather all available binary information
            self.logger.info("Phase 1: Collecting binary data...")
            report_data = self._collect_comprehensive_binary_data()

            # Phase 2: AI Analysis - Analyze collected data with specialized prompts
            self.logger.info("Phase 2: Performing AI-powered analysis...")
            analysis_results = self._perform_comprehensive_ai_analysis(report_data)

            # Phase 3: Report Generation - Structure and format the final report
            self.logger.info("Phase 3: Generating structured report...")
            final_report = self._generate_structured_software_report(
                report_data, analysis_results, report_format
            )

            self.logger.info("Software report generation completed successfully")
            return final_report

        except Exception as e:
            self.logger.error(f"Error generating software report: {e}")
            return f"Error generating software report: {e}"

    # ------------------------------------------------------------------
    #  Phase 1 - Data collection
    # ------------------------------------------------------------------

    def _get_latest_agent_analysis_text(self) -> str:
        """Retrieve the text analysis from the latest agent dump or orchestrator log.

        Searches orchestrator logs first (prioritizing those with confirmed
        findings that match the current binary), then falls back to
        analysis_dump files.
        """
        try:
            if not os.path.exists(self.logs_dir):
                return ""

            # Search both analysis_dump and orchestrator log files
            dump_files = glob.glob(os.path.join(self.logs_dir, "analysis_dump_*.md"))
            orchestrator_files = glob.glob(
                os.path.join(self.logs_dir, "orchestrator_*.md")
            )

            # Try orchestrator logs first (newest first), looking for one
            # with real findings for the current binary
            binary_name = getattr(self, "_current_binary_name", None)
            orchestrator_files_sorted = sorted(
                orchestrator_files, key=os.path.getmtime, reverse=True
            )

            for orch_file in orchestrator_files_sorted:
                try:
                    with open(orch_file, "r", encoding="utf-8") as f:
                        content = f.read()

                    # Skip orchestrator logs with no real final report
                    if "## Final Report" not in content:
                        continue

                    # If we know the binary name, prefer logs that mention it
                    if binary_name and binary_name.lower() not in content.lower():
                        continue

                    report_section = content.split("## Final Report", 1)[1]
                    notebook_findings = self._extract_orchestrator_findings(content)

                    # Skip logs where the final report has no confirmed findings
                    if (
                        "Confirmed Findings\nNone" in report_section
                        and not notebook_findings
                    ):
                        continue

                    self.logger.info(
                        f"Using orchestrator log for report context: {orch_file}"
                    )
                    if notebook_findings:
                        return notebook_findings + "\n\n" + report_section.strip()
                    return report_section.strip()

                except Exception:
                    continue

            # If no binary-specific orchestrator log found, try any
            # orchestrator log with real findings (newest first)
            if binary_name:
                for orch_file in orchestrator_files_sorted:
                    try:
                        with open(orch_file, "r", encoding="utf-8") as f:
                            content = f.read()

                        if "## Final Report" not in content:
                            continue

                        report_section = content.split("## Final Report", 1)[1]
                        notebook_findings = self._extract_orchestrator_findings(
                            content
                        )

                        if (
                            "Confirmed Findings\nNone" in report_section
                            and not notebook_findings
                        ):
                            continue

                        self.logger.info(
                            f"Using orchestrator log (no binary match) for report: "
                            f"{orch_file}"
                        )
                        if notebook_findings:
                            return (
                                notebook_findings + "\n\n" + report_section.strip()
                            )
                        return report_section.strip()

                    except Exception:
                        continue

            # Fall back to analysis_dump files
            if dump_files:
                latest_file = max(dump_files, key=os.path.getmtime)
                self.logger.info(
                    f"Using analysis dump for report context: {latest_file}"
                )

                with open(latest_file, "r", encoding="utf-8") as f:
                    content = f.read()

                # Look for "AI AGENT RESPONSE" section
                parts = content.split("AI AGENT RESPONSE")
                if len(parts) > 1:
                    analysis_part = parts[-1]
                    analysis_part = analysis_part.split(
                        "============================================"
                        "================"
                    )[-1]
                    return analysis_part.strip()

                # Look for "Binary Analysis Report" header
                if "# Binary Analysis Report" in content:
                    return content.split("# Binary Analysis Report", 1)[1]

            return ""

        except Exception as e:
            self.logger.warning(f"Failed to read latest analysis log: {e}")
            return ""

    def _extract_orchestrator_findings(self, content: str) -> str:
        """Extract confirmed notebook findings from an orchestrator log.

        Parses the ``### Notebook Update`` sections to collect accepted
        findings with their severity levels and descriptions.
        """
        findings: list[str] = []
        for line in content.splitlines():
            line = line.strip()
            # Accepted findings look like: "- [HIGH] Description (confirmed)"
            if line.startswith("- [") and (
                "confirmed" in line.lower()
                or "suspected" in line.lower()
            ):
                findings.append(line)

        if not findings:
            return ""

        return "## Confirmed Investigation Findings\n" + "\n".join(findings)

    def _collect_comprehensive_binary_data(self) -> Dict[str, Any]:
        """Collect all available binary data for analysis."""
        data: Dict[str, Any] = {
            "functions": [],
            "renamed_functions": [],
            "function_summaries": {},
            "function_addresses": {},  # Map function names to addresses
            "imports": [],
            "exports": [],
            "strings": [],
            "segments": [],
            "classes": [],
            "namespaces": [],
            "data_items": [],
            "analysis_state": self.analysis_state.copy(),
            "metadata": {
                "total_functions": 0,
                "renamed_count": 0,
                "analyzed_count": 0,
            },
        }

        try:
            # Collect function information
            functions_result = self.ghidra.list_functions()
            if isinstance(functions_result, list):
                data["functions"] = functions_result
            elif isinstance(functions_result, str) and not functions_result.startswith(
                "ERROR:"
            ):
                data["functions"] = [
                    f.strip() for f in functions_result.split("\n") if f.strip()
                ]

            # Parse function addresses from function names
            for func in data["functions"]:
                match = re.match(r"^(0x[0-9a-fA-F]+)\s+(.+)$", func)
                if match:
                    addr, name = match.groups()
                    data["function_addresses"][name] = addr
                    data["function_addresses"][func] = addr
                else:
                    addr_match = re.search(r"(0x[0-9a-fA-F]+)", func)
                    if addr_match:
                        data["function_addresses"][func] = addr_match.group(1)

            data["metadata"]["total_functions"] = len(data["functions"])

            # Collect renamed functions from analysis state
            data["renamed_functions"] = list(
                self.analysis_state["functions_renamed"].items()
            )
            data["metadata"]["renamed_count"] = len(data["renamed_functions"])

            # Collect function summaries
            data["function_summaries"] = self.function_summaries.copy()
            data["metadata"]["analyzed_count"] = len(data["function_summaries"])

            # Collect imports
            imports_result = self.ghidra.list_imports()
            if isinstance(imports_result, (list, str)) and not str(
                imports_result
            ).startswith("ERROR:"):
                if isinstance(imports_result, str):
                    data["imports"] = [
                        i.strip() for i in imports_result.split("\n") if i.strip()
                    ]
                else:
                    data["imports"] = imports_result

            # Collect exports
            exports_result = self.ghidra.list_exports()
            if isinstance(exports_result, (list, str)) and not str(
                exports_result
            ).startswith("ERROR:"):
                if isinstance(exports_result, str):
                    data["exports"] = [
                        e.strip() for e in exports_result.split("\n") if e.strip()
                    ]
                else:
                    data["exports"] = exports_result

            # Collect memory segments
            segments_result = self.ghidra.list_segments()
            if isinstance(segments_result, (list, str)) and not str(
                segments_result
            ).startswith("ERROR:"):
                if isinstance(segments_result, str):
                    data["segments"] = [
                        s.strip() for s in segments_result.split("\n") if s.strip()
                    ]
                else:
                    data["segments"] = segments_result

            # Collect classes/namespaces
            classes_result = self.ghidra.list_classes()
            if isinstance(classes_result, (list, str)) and not str(
                classes_result
            ).startswith("ERROR:"):
                if isinstance(classes_result, str):
                    data["classes"] = [
                        c.strip() for c in classes_result.split("\n") if c.strip()
                    ]
                else:
                    data["classes"] = classes_result

            namespaces_result = self.ghidra.list_namespaces()
            if isinstance(namespaces_result, (list, str)) and not str(
                namespaces_result
            ).startswith("ERROR:"):
                if isinstance(namespaces_result, str):
                    data["namespaces"] = [
                        n.strip() for n in namespaces_result.split("\n") if n.strip()
                    ]
                else:
                    data["namespaces"] = namespaces_result

            # Collect data items
            data_items_result = self.ghidra.list_data_items()
            if isinstance(data_items_result, (list, str)) and not str(
                data_items_result
            ).startswith("ERROR:"):
                if isinstance(data_items_result, str):
                    data["data_items"] = [
                        d.strip()
                        for d in data_items_result.split("\n")
                        if d.strip()
                    ]
                else:
                    data["data_items"] = data_items_result

            # Collect strings with addresses for evidence
            try:
                strings_result = self.ghidra.list_strings(limit=500)
                if isinstance(strings_result, list):
                    data["strings"] = strings_result
                elif isinstance(strings_result, str) and not strings_result.startswith(
                    "ERROR:"
                ):
                    data["strings"] = [
                        s.strip() for s in strings_result.split("\n") if s.strip()
                    ]
            except Exception as string_err:
                self.logger.debug(f"Error collecting strings: {string_err}")

        except Exception as e:
            self.logger.warning(f"Error collecting some binary data: {e}")

        # Collect binary name and info (before agent analysis lookup so we
        # can match orchestrator logs to the current binary)
        try:
            program_info = self.ghidra.get_current_program_info()
            data["metadata"]["binary_name"] = program_info.get("name", "Unknown Binary")
            data["metadata"]["project_name"] = program_info.get(
                "project", "Unknown Project"
            )
            self.logger.info(
                f"Collected binary info: {data['metadata']['binary_name']}"
            )
        except Exception as e:
            self.logger.warning(f"Failed to collect binary info: {e}")
            data["metadata"]["binary_name"] = "Unknown Binary"

        # Store binary name for orchestrator log matching
        self._current_binary_name = data["metadata"]["binary_name"]

        # Collect previous agent/orchestrator analysis for correlation
        data["agent_analysis_history"] = self._get_latest_agent_analysis_text()

        return data

    # ------------------------------------------------------------------
    #  Phase 2 - AI analysis
    # ------------------------------------------------------------------

    def _perform_comprehensive_ai_analysis(
        self, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Perform AI-powered analysis of collected binary data."""
        analysis: Dict[str, Any] = {
            "software_classification": {},
            "security_assessment": {},
            "function_categorization": {},
            "behavioral_analysis": {},
            "architecture_analysis": {},
            "risk_assessment": {},
        }

        try:
            # Software Classification Analysis
            classification_prompt = self._build_classification_prompt(data)
            classification_response = self.llm.generate(prompt=classification_prompt)
            analysis["software_classification"] = self._parse_classification_response(
                classification_response
            )

            # Security Assessment Analysis
            security_prompt = self._build_security_assessment_prompt(data)
            security_response = self.llm.generate(prompt=security_prompt)
            analysis["security_assessment"] = self._parse_security_response(
                security_response
            )

            # Function Categorization Analysis
            function_prompt = self._build_function_categorization_prompt(data)
            function_response = self.llm.generate(prompt=function_prompt)
            analysis["function_categorization"] = self._parse_function_response(
                function_response
            )

            # Behavioral Pattern Analysis
            behavior_prompt = self._build_behavioral_analysis_prompt(data)
            behavior_response = self.llm.generate(prompt=behavior_prompt)
            analysis["behavioral_analysis"] = self._parse_behavioral_response(
                behavior_response
            )

            # Architecture Analysis
            architecture_prompt = self._build_architecture_prompt(data)
            architecture_response = self.llm.generate(prompt=architecture_prompt)
            analysis["architecture_analysis"] = self._parse_architecture_response(
                architecture_response
            )

            # Overall Risk Assessment
            risk_prompt = self._build_risk_assessment_prompt(data, analysis)
            risk_response = self.llm.generate(prompt=risk_prompt)
            analysis["risk_assessment"] = self._parse_risk_response(risk_response)

        except Exception as e:
            self.logger.error(f"Error during AI analysis: {e}")
            analysis["error"] = str(e)

        return analysis

    # ------------------------------------------------------------------
    #  Prompt context formatters
    # ------------------------------------------------------------------

    def _format_agent_analysis_context(
        self, data: Dict[str, Any], analysis_type: str = "analysis"
    ) -> str:
        """
        Format the agent analysis history section for prompts.

        Handles empty analysis gracefully by providing fallback content
        and explicit permission to speculate based on available data.
        """
        analysis_history = data.get("agent_analysis_history", "")

        if not analysis_history or not analysis_history.strip():
            return f"""No prior agent analysis available for this binary.

**IMPORTANT GUIDANCE:**
- You may SPECULATE based on the binary data provided above (imports, exports, function names, strings).
- Base your {analysis_type} on the concrete evidence available (function names, API imports, string references).
- Clearly indicate when you are inferring behavior vs. reporting confirmed findings.
- Do NOT refuse to analyze - provide your best assessment based on available data.
- If certain about something, state it confidently. If uncertain, use phrases like "likely", "appears to", "suggests"."""
        else:
            return analysis_history

    # ------------------------------------------------------------------
    #  Prompt builders
    # ------------------------------------------------------------------

    def _build_classification_prompt(self, data: Dict[str, Any]) -> str:
        """Build prompt for software classification analysis."""
        return f"""Analyze this binary and classify the software type and purpose.

**Binary Information:**
- Total Functions: {data['metadata']['total_functions']}
- Renamed Functions: {data['metadata']['renamed_count']}
- Analyzed Functions: {data['metadata']['analyzed_count']}
- Imports: {len(data['imports'])} ({', '.join(data['imports'][:10])}{'...' if len(data['imports']) > 10 else ''})
- Exports: {len(data['exports'])} ({', '.join(data['exports'][:10])}{'...' if len(data['exports']) > 10 else ''})
- Memory Segments: {len(data['segments'])}
- Classes/Namespaces: {len(data['classes']) + len(data['namespaces'])}

**Function Summaries:**
{self._format_summaries_for_prompt(data['function_summaries'])}

**Analysis Requirements:**
Provide a structured classification following this EXACT format:

**SOFTWARE_TYPE:** [Select ONE: Application, Library, Driver, Malware, System_Tool, Game, Utility, Service, Other]
**PRIMARY_PURPOSE:** [Brief description of main functionality]
**SECONDARY_FUNCTIONS:** [List of additional capabilities]
**TARGET_PLATFORM:** [Windows/Linux/macOS/Cross-platform/Embedded]
**ARCHITECTURE_STYLE:** [Monolithic/Modular/Service-oriented/Plugin-based/Other]
**COMPLEXITY_LEVEL:** [Low/Medium/High/Very_High]
**CLASSIFICATION_CONFIDENCE:** [0-100%]
**EVIDENCE:** [Key evidence supporting this classification - MUST include specific function addresses, function names, and string examples. Format: "Function at address 0x... named '...' does X", "String 'Y' found at Z"]

**PREVIOUS AGENT ANALYSIS:**
{self._format_agent_analysis_context(data, 'classification')}

**IMPORTANT:** If prior analysis exists, use it as the PRIMARY SOURCE of truth. Otherwise, base your classification on the Binary Information above."""

    def _build_security_assessment_prompt(self, data: Dict[str, Any]) -> str:
        """Build prompt for security risk assessment."""
        return f"""Perform a comprehensive security assessment of this binary.

**Binary Data for Analysis:**
- Functions: {data['metadata']['total_functions']} total, {data['metadata']['renamed_count']} renamed
- Key Imports: {', '.join(data['imports'][:15])}{'...' if len(data['imports']) > 15 else ''}
- Function Summaries: {len(data['function_summaries'])} available

**Renamed Functions and Behaviors:**
{self._format_function_behaviors_for_security(data)}

**Security Analysis Requirements:**
Analyze for security risks and provide assessment in this EXACT format:

**IMPORTANT:** For EACH suspicious indicator, security concern, or finding, you MUST provide:
1. The specific function address (e.g., 0x401000)
2. The function name
3. Actual string values, API calls, or code patterns found
4. Concrete examples from the binary

**OVERALL_RISK_LEVEL:** [CRITICAL/HIGH/MEDIUM/LOW]
**RISK_SCORE:** [0-100]
**SECURITY_CATEGORIES:**
- Network_Operations: [NONE/LOW/MEDIUM/HIGH/CRITICAL] - [description with specific addresses and functions]
- File_System_Access: [NONE/LOW/MEDIUM/HIGH/CRITICAL] - [description with specific addresses and functions]
- Registry_Manipulation: [NONE/LOW/MEDIUM/HIGH/CRITICAL] - [description with specific addresses and functions]
- Process_Manipulation: [NONE/LOW/MEDIUM/HIGH/CRITICAL] - [description with specific addresses and functions]
- Cryptographic_Operations: [NONE/LOW/MEDIUM/HIGH/CRITICAL] - [description with specific addresses and functions]
- Memory_Management: [NONE/LOW/MEDIUM/HIGH/CRITICAL] - [description with specific addresses and functions]
- Persistence_Mechanisms: [NONE/LOW/MEDIUM/HIGH/CRITICAL] - [description with specific addresses and functions]
**SUSPICIOUS_INDICATORS:** [List EACH concerning behavior with format: "Description at address 0x... in function '...' - Evidence: specific API/string/pattern"]
**MITIGATION_RECOMMENDATIONS:** [Security recommendations]
**IOCS:** [Potential Indicators of Compromise with specific addresses and strings found]

**PREVIOUS AGENT ANALYSIS:**
{self._format_agent_analysis_context(data, 'security assessment')}

**IMPORTANT:** If prior analysis exists, use it as the PRIMARY SOURCE of truth. Otherwise, assess security risks based on the imports, function names, and behaviors observable in the Binary Data above."""

    def _build_function_categorization_prompt(self, data: Dict[str, Any]) -> str:
        """Build prompt for function categorization analysis."""
        return f"""Categorize all functions in this binary by their primary purpose and behavior.

**Available Function Data:**
- Total Functions: {data['metadata']['total_functions']}
- Renamed Functions with Summaries: {data['metadata']['analyzed_count']}
- Sample Functions: {', '.join(data['functions'][:10])}{'...' if len(data['functions']) > 10 else ''}

**Function Summaries for Categorization:**
{self._format_summaries_for_categorization(data['function_summaries'])}

**Renamed Functions:**
{self._format_renamed_functions(data['renamed_functions'])}

**Categorization Requirements:**
Analyze and categorize functions into standard categories. Provide results in this EXACT format:

**IMPORTANT:** For each category with functions, list notable functions WITH their addresses in format: "function_name at 0x..."

**FUNCTION_CATEGORIES:**
**Network_Operations:** [count] - [function names WITH addresses (0x...) and brief descriptions]
**File_IO_Operations:** [count] - [function names WITH addresses (0x...) and brief descriptions]
**Memory_Management:** [count] - [function names WITH addresses (0x...) and brief descriptions]
**Cryptographic_Functions:** [count] - [function names WITH addresses (0x...) and brief descriptions]
**String_Processing:** [count] - [function names WITH addresses (0x...) and brief descriptions]
**UI_Interface:** [count] - [function names WITH addresses (0x...) and brief descriptions]
**Registry_Operations:** [count] - [function names WITH addresses (0x...) and brief descriptions]
**Process_Control:** [count] - [function names WITH addresses (0x...) and brief descriptions]
**Authentication:** [count] - [function names WITH addresses (0x...) and brief descriptions]
**Configuration:** [count] - [function names WITH addresses (0x...) and brief descriptions]
**Utility_Helper:** [count] - [function names WITH addresses (0x...) and brief descriptions]
**Error_Handling:** [count] - [function names WITH addresses (0x...) and brief descriptions]
**Main_Core:** [count] - [function names WITH addresses (0x...) and brief descriptions]
**Unknown_Other:** [count] - [function names WITH addresses (0x...) and brief descriptions]

**CATEGORY_INSIGHTS:** [Analysis of what the function distribution reveals about software purpose, cite specific address examples]

**PREVIOUS AGENT ANALYSIS:**
{self._format_agent_analysis_context(data, 'function categorization')}

**IMPORTANT:** If prior analysis exists, use it to guide categorization. Otherwise, categorize based on function names, import patterns, and observable code structure."""

    def _build_behavioral_analysis_prompt(self, data: Dict[str, Any]) -> str:
        """Build prompt for behavioral pattern analysis."""
        return f"""Analyze behavioral patterns and workflows in this binary.

**Behavioral Data:**
- Function Summaries: {len(data['function_summaries'])} detailed analyses
- Import Dependencies: {', '.join(data['imports'][:20])}
- Export Capabilities: {', '.join(data['exports'][:10])}

**Function Behavior Details:**
{self._format_behavioral_data(data)}

**Behavioral Analysis Requirements:**
Identify patterns, workflows, and behavioral characteristics. Format response as:

**IMPORTANT:** Cite specific function addresses demonstrating each behavioral pattern. Use format: "Behavior demonstrated by function at 0x..."

**PRIMARY_WORKFLOWS:** [Main execution flows and processes - cite specific function addresses]
**DATA_FLOW_PATTERNS:** [How data moves through the application - cite specific function addresses]
**INTERACTION_PATTERNS:** [User, network, file, system interactions - cite specific function addresses and strings]
**EXECUTION_MODELS:** [How the software operates - service, interactive, batch, etc. - cite specific function addresses]
**DEPENDENCY_ANALYSIS:** [Key dependencies and their purposes - cite specific import/export addresses]
**OPERATIONAL_MODES:** [Different modes of operation - cite specific function addresses]
**TRIGGER_MECHANISMS:** [What causes different behaviors - cite specific addresses and conditions]
**BEHAVIORAL_FINGERPRINT:** [Unique behavioral characteristics that identify this software - cite specific addresses and evidence]

**PREVIOUS AGENT ANALYSIS:**
{self._format_agent_analysis_context(data, 'behavioral analysis')}

**IMPORTANT:** If prior analysis exists, use it as the PRIMARY SOURCE. Otherwise, infer behavioral patterns from imports, exports, and function structures."""

    def _build_architecture_prompt(self, data: Dict[str, Any]) -> str:
        """Build prompt for software architecture analysis."""
        return f"""Analyze the software architecture and design patterns used in this binary.

**Architecture Data:**
- Code Organization: {len(data['classes'])} classes, {len(data['namespaces'])} namespaces
- Memory Layout: {len(data['segments'])} segments
- Function Structure: {data['metadata']['total_functions']} functions
- Data Structures: {len(data['data_items'])} data items

**Function Architecture:**
{self._format_architecture_data(data)}

**Architecture Analysis Requirements:**
Analyze the software architecture and provide results in this EXACT format:

**ARCHITECTURAL_PATTERN:** [Layered/MVC/Component-based/Microservices/Monolithic/Other]
**CODE_ORGANIZATION:** [How code is structured and organized]
**MODULE_STRUCTURE:** [How different modules/components are arranged]
**DESIGN_PATTERNS:** [Observable design patterns like Singleton, Factory, Observer, etc.]
**MEMORY_LAYOUT:** [How memory is organized and used]
**INTERFACE_DESIGN:** [How different components interface with each other]
**SCALABILITY_DESIGN:** [How the architecture supports scalability]
**ARCHITECTURE_QUALITY:** [Assessment of architectural quality and maintainability]
**COMPLEXITY_METRICS:** [Analysis of architectural complexity]

**PREVIOUS AGENT ANALYSIS:**
{self._format_agent_analysis_context(data, 'architecture analysis')}

**IMPORTANT:** If prior analysis exists, align your architecture analysis with it. Otherwise, derive architectural insights from code organization and structure."""

    def _build_risk_assessment_prompt(
        self, data: Dict[str, Any], analysis: Dict[str, Any]
    ) -> str:
        """Build prompt for overall risk assessment."""
        return f"""Provide a comprehensive risk assessment based on all analysis conducted.

**Analysis Summary:**
- Software Classification: {analysis.get('software_classification', {}).get('type', 'Unknown')}
- Security Assessment: {analysis.get('security_assessment', {}).get('risk_level', 'Unknown')}
- Function Categories: {len(analysis.get('function_categorization', {}))} categories analyzed
- Architecture: {analysis.get('architecture_analysis', {}).get('pattern', 'Unknown')}

**Risk Assessment Requirements:**
Provide final risk assessment in this EXACT format:

**IMPORTANT:** For EACH risk factor identified, cite the specific address where the risk was identified. Format: "Risk description at address 0x... in function '...'"

**OVERALL_RISK_RATING:** [CRITICAL/HIGH/MEDIUM/LOW]
**RISK_SCORE:** [0-100]
**PRIMARY_RISK_FACTORS:** [Top 3-5 risk factors WITH specific addresses and function names where identified]
**THREAT_LEVEL:** [IMMEDIATE/HIGH/MODERATE/LOW/MINIMAL]
**RECOMMENDED_ACTIONS:** [Specific actions to take, referencing specific addresses/functions if applicable]
**MONITORING_RECOMMENDATIONS:** [What to monitor if deployed, cite specific functions/addresses to watch]
**CONTAINMENT_STRATEGY:** [How to safely contain or isolate if needed]
**BUSINESS_IMPACT:** [Potential business/operational impact]
**TECHNICAL_RISK:** [Technical risks and implications with specific addresses]

**PREVIOUS AGENT ANALYSIS:**
{self._format_agent_analysis_context(data, 'risk assessment')}

**IMPORTANT:** If prior analysis exists, use it as the PRIMARY SOURCE for risk calculation. Otherwise, assess risks based on the analysis summary and observable indicators."""

    # ------------------------------------------------------------------
    #  Data formatters for prompts
    # ------------------------------------------------------------------

    def _format_summaries_for_prompt(self, summaries: Dict[str, str]) -> str:
        """Format function summaries for AI prompts with comprehensive RAG retrieval."""
        if not summaries:
            return "No function summaries available."

        formatted = []

        # Enhanced RAG approach: Use vector store to find ALL relevant functions
        if (
            self.enable_cag
            and self.cag_manager
            and hasattr(self.cag_manager, "vector_store")
            and self.cag_manager.vector_store
        ):
            enhanced_context = self._get_comprehensive_function_context(summaries)
            if enhanced_context:
                return enhanced_context

        # Fallback to basic formatting with limited functions
        for func, summary in list(summaries.items())[:10]:
            formatted.append(
                f"- {func}: {summary[:100]}{'...' if len(summary) > 100 else ''}"
            )

        if len(summaries) > 10:
            formatted.append(
                f"... and {len(summaries) - 10} more functions with summaries"
            )

        return "\n".join(formatted)

    def _get_comprehensive_function_context(
        self, summaries: Dict[str, str]
    ) -> Optional[str]:
        """Get comprehensive function context using multi-vector RAG retrieval."""
        try:
            vector_store = self.cag_manager.vector_store
            all_context: List[str] = []

            # Strategy 1: Search for different categories of functions
            search_queries = [
                "security cryptography authentication encryption",
                "network communication socket http tcp",
                "file system disk read write open",
                "memory allocation buffer management",
                "process thread execution control",
                "registry configuration system settings",
                "string parsing text processing",
                "user interface input output display",
                "database storage data management",
                "error handling exception logging",
                "main entry point initialization",
                "malware persistence backdoor",
            ]

            retrieved_functions: set = set()
            query_results: list = []

            # Perform multiple targeted searches
            for query in search_queries:
                results = vector_store.search(query, top_k=5)
                for result in results:
                    doc = result["document"]
                    if (
                        doc.get("type") == "function_analysis"
                        and doc.get("name") not in retrieved_functions
                    ):
                        query_results.append(
                            {
                                "name": doc.get("name"),
                                "content": doc.get("text", ""),
                                "score": result["score"],
                                "category": query.split()[0],
                            }
                        )
                        retrieved_functions.add(doc.get("name"))

            # Strategy 2: Include high-priority functions from summaries
            priority_keywords = [
                "main", "entry", "init", "start", "connect", "send", "receive",
                "read", "write", "create", "delete", "encrypt", "decrypt", "auth",
            ]

            for func_name, summary in summaries.items():
                if func_name not in retrieved_functions and any(
                    keyword.lower() in func_name.lower()
                    or keyword.lower() in summary.lower()
                    for keyword in priority_keywords
                ):
                    query_results.append(
                        {
                            "name": func_name,
                            "content": summary,
                            "score": 1.0,
                            "category": "priority",
                        }
                    )
                    retrieved_functions.add(func_name)

            # Strategy 3: Add remaining functions by relevance score
            remaining_functions = []
            for func_name, summary in summaries.items():
                if func_name not in retrieved_functions:
                    relevance_score = len(summary) / 500.0
                    if any(
                        keyword in summary.lower()
                        for keyword in [
                            "critical", "important", "key", "main", "core", "primary",
                        ]
                    ):
                        relevance_score += 0.5

                    remaining_functions.append(
                        {
                            "name": func_name,
                            "content": summary,
                            "score": relevance_score,
                            "category": "additional",
                        }
                    )

            remaining_functions.sort(key=lambda x: x["score"], reverse=True)
            query_results.extend(remaining_functions[:20])

            # Format comprehensive context
            if query_results:
                all_context.append("## COMPREHENSIVE FUNCTION ANALYSIS")
                all_context.append(
                    f"**Total Functions Analyzed: {len(query_results)} of {len(summaries)}**\n"
                )

                categories: Dict[str, list] = {}
                for result in query_results:
                    category = result["category"]
                    if category not in categories:
                        categories[category] = []
                    categories[category].append(result)

                for category, functions in categories.items():
                    if len(functions) > 0:
                        all_context.append(f"### {category.upper()} FUNCTIONS:")
                        for func in functions[:10]:
                            name = func["name"]
                            content = func["content"]
                            truncated_content = (
                                content[:300] + "..."
                                if len(content) > 300
                                else content
                            )
                            all_context.append(f"- **{name}**: {truncated_content}")

                        if len(functions) > 10:
                            all_context.append(
                                f"  *... and {len(functions) - 10} more {category} functions*"
                            )
                        all_context.append("")

                return "\n".join(all_context)

        except Exception as e:
            self.logger.warning(f"Error in comprehensive RAG retrieval: {e}")

        return None

    def _format_function_behaviors_for_security(self, data: Dict[str, Any]) -> str:
        """Format function behaviors specifically for security analysis with comprehensive RAG."""
        if (
            self.enable_cag
            and self.cag_manager
            and hasattr(self.cag_manager, "vector_store")
            and self.cag_manager.vector_store
        ):
            enhanced_security_context = self._get_comprehensive_security_context(data)
            if enhanced_security_context:
                return enhanced_security_context

        # Fallback to basic formatting
        formatted = []
        for old_name, new_name in data["renamed_functions"][:15]:
            summary = data["function_summaries"].get(old_name, "No summary available")
            formatted.append(
                f"- {old_name} → {new_name}: {summary[:150]}{'...' if len(summary) > 150 else ''}"
            )

        return (
            "\n".join(formatted)
            if formatted
            else "No renamed functions with behavioral data available."
        )

    def _get_comprehensive_security_context(self, data: Dict[str, Any]) -> Optional[str]:
        """Get comprehensive security-focused function context using RAG."""
        try:
            vector_store = self.cag_manager.vector_store
            all_context: List[str] = []

            security_queries = [
                "authentication login password credential verification",
                "encryption cryptography cipher hash algorithm",
                "network socket communication tcp udp http",
                "file access read write permission disk",
                "registry key value configuration system",
                "process execution spawn thread creation",
                "memory allocation buffer overflow protection",
                "privilege escalation administrator elevation",
                "persistence startup autorun service",
                "injection code dll payload shellcode",
                "obfuscation packing anti-analysis stealth",
                "communication c2 command control callback",
            ]

            retrieved_functions: set = set()
            security_results: list = []

            for query in security_queries:
                results = vector_store.search(query, top_k=8)
                for result in results:
                    doc = result["document"]
                    if (
                        doc.get("type") == "function_analysis"
                        and doc.get("name") not in retrieved_functions
                    ):
                        content = doc.get("text", "")
                        security_score = self._calculate_security_score(content)

                        security_results.append(
                            {
                                "old_name": doc.get("name", "unknown"),
                                "new_name": self._find_renamed_function(
                                    doc.get("name"), data
                                ),
                                "content": content,
                                "vector_score": result["score"],
                                "security_score": security_score,
                                "category": query.split()[0],
                            }
                        )
                        retrieved_functions.add(doc.get("name"))

            # Add high-risk functions from renamed functions
            for old_name, new_name in data["renamed_functions"]:
                if old_name not in retrieved_functions:
                    summary = data["function_summaries"].get(old_name, "")
                    security_score = self._calculate_security_score(summary)

                    if security_score > 0.3:
                        security_results.append(
                            {
                                "old_name": old_name,
                                "new_name": new_name,
                                "content": summary,
                                "vector_score": 0.8,
                                "security_score": security_score,
                                "category": "renamed",
                            }
                        )

            security_results.sort(
                key=lambda x: (x["security_score"] + x["vector_score"]) / 2,
                reverse=True,
            )

            if security_results:
                all_context.append("## COMPREHENSIVE SECURITY ANALYSIS")
                all_context.append(
                    f"**Security-Relevant Functions Analyzed: {len(security_results)}**\n"
                )

                high_risk = [r for r in security_results if r["security_score"] > 0.7]
                medium_risk = [
                    r
                    for r in security_results
                    if 0.4 <= r["security_score"] <= 0.7
                ]
                low_risk = [r for r in security_results if r["security_score"] < 0.4]

                if high_risk:
                    all_context.append("### 🔴 HIGH SECURITY RISK FUNCTIONS:")
                    for result in high_risk[:15]:
                        self._format_security_function(result, all_context)
                    all_context.append("")

                if medium_risk:
                    all_context.append("### 🟡 MEDIUM SECURITY RISK FUNCTIONS:")
                    for result in medium_risk[:10]:
                        self._format_security_function(result, all_context)
                    all_context.append("")

                if low_risk:
                    all_context.append("### 🟢 LOWER RISK / UTILITY FUNCTIONS:")
                    for result in low_risk[:5]:
                        self._format_security_function(result, all_context)
                    all_context.append("")

                return "\n".join(all_context)

        except Exception as e:
            self.logger.warning(
                f"Error in comprehensive security RAG retrieval: {e}"
            )

        return None

    def _calculate_security_score(self, content: str) -> float:
        """Calculate security relevance score for function content."""
        if not content:
            return 0.0

        content_lower = content.lower()
        score = 0.0

        high_risk_keywords = [
            "encrypt", "decrypt", "password", "credential", "authentication",
            "privilege", "administrator", "system", "registry", "service",
            "network", "socket", "http", "tcp", "udp", "connect", "send",
            "file", "read", "write", "delete", "create", "access",
            "process", "thread", "spawn", "execute", "injection",
            "memory", "allocation", "buffer", "overflow", "shellcode",
            "persistence", "startup", "autorun", "malware", "backdoor",
        ]

        medium_risk_keywords = [
            "string", "parse", "format", "validate", "check", "verify",
            "error", "exception", "log", "debug", "config", "setting",
        ]

        for keyword in high_risk_keywords:
            if keyword in content_lower:
                score += 0.15

        for keyword in medium_risk_keywords:
            if keyword in content_lower:
                score += 0.05

        if any(
            name in content_lower
            for name in ["auth", "crypt", "security", "protect", "verify"]
        ):
            score += 0.2

        return min(score, 1.0)

    def _find_renamed_function(self, old_name: str, data: Dict[str, Any]) -> str:
        """Find the new name for a renamed function."""
        for old, new in data["renamed_functions"]:
            if old == old_name:
                return new
        return old_name

    def _format_security_function(
        self, result: Dict[str, Any], context_list: List[str]
    ) -> None:
        """Format a security function result for the context."""
        old_name = result["old_name"]
        new_name = result["new_name"]
        content = result["content"]
        security_score = result["security_score"]

        truncated_content = (
            content[:400] + "..." if len(content) > 400 else content
        )

        if old_name != new_name:
            context_list.append(
                f"- **{old_name} → {new_name}** (Security Risk: {security_score:.2f}): {truncated_content}"
            )
        else:
            context_list.append(
                f"- **{old_name}** (Security Risk: {security_score:.2f}): {truncated_content}"
            )

    def _format_summaries_for_categorization(self, summaries: Dict[str, str]) -> str:
        """Format summaries for function categorization with comprehensive RAG."""
        return self._format_summaries_for_prompt(summaries)

    def _format_renamed_functions(self, renamed_functions: List[tuple]) -> str:
        """Format renamed functions list."""
        if not renamed_functions:
            return "No functions have been renamed yet."

        formatted = []
        for old_name, new_name in renamed_functions[:20]:
            formatted.append(f"- {old_name} → {new_name}")

        if len(renamed_functions) > 20:
            formatted.append(
                f"... and {len(renamed_functions) - 20} more renamed functions"
            )

        return "\n".join(formatted)

    def _format_behavioral_data(self, data: Dict[str, Any]) -> str:
        """Format behavioral data with comprehensive RAG analysis."""
        if (
            self.enable_cag
            and self.cag_manager
            and hasattr(self.cag_manager, "vector_store")
            and self.cag_manager.vector_store
        ):
            enhanced_behavioral_context = self._get_comprehensive_behavioral_context(
                data
            )
            if enhanced_behavioral_context:
                return enhanced_behavioral_context

        return self._format_summaries_for_prompt(data["function_summaries"])

    def _get_comprehensive_behavioral_context(
        self, data: Dict[str, Any]
    ) -> Optional[str]:
        """Get comprehensive behavioral context using RAG."""
        try:
            vector_store = self.cag_manager.vector_store
            all_context: List[str] = []

            behavioral_queries = [
                "initialization startup entry point main",
                "workflow process sequence execution flow",
                "data processing transformation parsing",
                "communication interaction interface api",
                "state management configuration settings",
                "event handling callback response trigger",
                "loop iteration recursive repetitive",
                "decision logic conditional branching",
                "cleanup finalization termination shutdown",
                "validation verification check constraint",
            ]

            retrieved_functions: set = set()
            behavioral_results: list = []

            for query in behavioral_queries:
                results = vector_store.search(query, top_k=6)
                for result in results:
                    doc = result["document"]
                    if (
                        doc.get("type") == "function_analysis"
                        and doc.get("name") not in retrieved_functions
                    ):
                        content = doc.get("text", "")
                        behavioral_score = self._calculate_behavioral_score(content)

                        behavioral_results.append(
                            {
                                "name": doc.get("name"),
                                "content": content,
                                "vector_score": result["score"],
                                "behavioral_score": behavioral_score,
                                "category": query.split()[0],
                            }
                        )
                        retrieved_functions.add(doc.get("name"))

            # Add important functions from summaries
            for func_name, summary in data["function_summaries"].items():
                if func_name not in retrieved_functions:
                    behavioral_score = self._calculate_behavioral_score(summary)
                    if behavioral_score > 0.4:
                        behavioral_results.append(
                            {
                                "name": func_name,
                                "content": summary,
                                "vector_score": 0.7,
                                "behavioral_score": behavioral_score,
                                "category": "identified",
                            }
                        )
                        retrieved_functions.add(func_name)

            behavioral_results.sort(
                key=lambda x: x["behavioral_score"], reverse=True
            )

            if behavioral_results:
                all_context.append("## COMPREHENSIVE BEHAVIORAL ANALYSIS")
                all_context.append(
                    f"**Behaviorally Significant Functions: {len(behavioral_results)}**\n"
                )

                core_behavior = [
                    r for r in behavioral_results if r["behavioral_score"] > 0.8
                ]
                supporting_behavior = [
                    r
                    for r in behavioral_results
                    if 0.5 <= r["behavioral_score"] <= 0.8
                ]
                utility_behavior = [
                    r for r in behavioral_results if r["behavioral_score"] < 0.5
                ]

                if core_behavior:
                    all_context.append("### 🎯 CORE BEHAVIORAL FUNCTIONS:")
                    for result in core_behavior[:12]:
                        self._format_behavioral_function(result, all_context)
                    all_context.append("")

                if supporting_behavior:
                    all_context.append("### 🔧 SUPPORTING BEHAVIORAL FUNCTIONS:")
                    for result in supporting_behavior[:15]:
                        self._format_behavioral_function(result, all_context)
                    all_context.append("")

                if utility_behavior:
                    all_context.append("### ⚙️ UTILITY / HELPER FUNCTIONS:")
                    for result in utility_behavior[:8]:
                        self._format_behavioral_function(result, all_context)
                    all_context.append("")

                return "\n".join(all_context)

        except Exception as e:
            self.logger.warning(
                f"Error in comprehensive behavioral RAG retrieval: {e}"
            )

        return None

    def _calculate_behavioral_score(self, content: str) -> float:
        """Calculate behavioral significance score for function content."""
        if not content:
            return 0.0

        content_lower = content.lower()
        score = 0.0

        core_indicators = [
            "main", "entry", "start", "initialize", "init", "setup",
            "process", "execute", "run", "handle", "manage", "control",
            "create", "generate", "build", "construct", "parse",
            "connect", "communicate", "send", "receive", "transfer",
            "validate", "verify", "check", "authenticate", "authorize",
        ]

        supporting_indicators = [
            "configure", "setup", "prepare", "cleanup", "finalize",
            "update", "modify", "change", "transform", "convert",
            "save", "load", "read", "write", "store", "retrieve",
            "format", "encode", "decode", "compress", "extract",
        ]

        flow_indicators = [
            "loop", "iterate", "repeat", "while", "for", "next",
            "if", "then", "else", "switch", "case", "condition",
            "callback", "event", "trigger", "signal", "notify",
            "wait", "sleep", "pause", "resume", "continue", "stop",
        ]

        for indicator in core_indicators:
            if indicator in content_lower:
                score += 0.25

        for indicator in supporting_indicators:
            if indicator in content_lower:
                score += 0.15

        for indicator in flow_indicators:
            if indicator in content_lower:
                score += 0.10

        behavioral_names = [
            "main", "entry", "process", "handle", "execute", "init",
        ]
        if any(name in content_lower for name in behavioral_names):
            score += 0.3

        return min(score, 1.0)

    def _format_behavioral_function(
        self, result: Dict[str, Any], context_list: List[str]
    ) -> None:
        """Format a behavioral function result for the context."""
        name = result["name"]
        content = result["content"]
        behavioral_score = result["behavioral_score"]

        truncated_content = (
            content[:350] + "..." if len(content) > 350 else content
        )

        context_list.append(
            f"- **{name}** (Behavioral Score: {behavioral_score:.2f}): {truncated_content}"
        )

    def _format_architecture_data(self, data: Dict[str, Any]) -> str:
        """Format architecture data with comprehensive analysis."""
        if (
            self.enable_cag
            and self.cag_manager
            and hasattr(self.cag_manager, "vector_store")
            and self.cag_manager.vector_store
        ):
            enhanced_architecture_context = (
                self._get_comprehensive_architecture_context(data)
            )
            if enhanced_architecture_context:
                return enhanced_architecture_context

        return self._format_summaries_for_prompt(data["function_summaries"])

    def _get_comprehensive_architecture_context(
        self, data: Dict[str, Any]
    ) -> Optional[str]:
        """Get comprehensive architecture context using RAG."""
        try:
            vector_store = self.cag_manager.vector_store
            all_context: List[str] = []

            architecture_queries = [
                "initialization setup configuration startup",
                "interface api public private function",
                "module component service layer structure",
                "dependency injection factory pattern",
                "data model structure class object",
                "controller handler manager coordinator",
                "utility helper common shared library",
                "persistence storage database file system",
                "logging debug error monitoring trace",
                "cleanup disposal finalize terminate",
            ]

            retrieved_functions: set = set()
            architecture_results: list = []

            for query in architecture_queries:
                results = vector_store.search(query, top_k=5)
                for result in results:
                    doc = result["document"]
                    if (
                        doc.get("type") == "function_analysis"
                        and doc.get("name") not in retrieved_functions
                    ):
                        content = doc.get("text", "")
                        architecture_score = self._calculate_architecture_score(
                            content
                        )

                        architecture_results.append(
                            {
                                "name": doc.get("name"),
                                "content": content,
                                "vector_score": result["score"],
                                "architecture_score": architecture_score,
                                "category": query.split()[0],
                            }
                        )
                        retrieved_functions.add(doc.get("name"))

            architecture_results.sort(
                key=lambda x: x["architecture_score"], reverse=True
            )

            if architecture_results:
                all_context.append("## COMPREHENSIVE ARCHITECTURE ANALYSIS")
                all_context.append(
                    f"**Architecturally Significant Functions: {len(architecture_results)}**\n"
                )

                categories: Dict[str, list] = {}
                for result in architecture_results:
                    category = result["category"]
                    if category not in categories:
                        categories[category] = []
                    categories[category].append(result)

                for category, functions in categories.items():
                    if len(functions) > 0:
                        all_context.append(f"### {category.upper()} LAYER:")
                        for func in functions[:8]:
                            self._format_architecture_function(func, all_context)
                        all_context.append("")

                return "\n".join(all_context)

        except Exception as e:
            self.logger.warning(
                f"Error in comprehensive architecture RAG retrieval: {e}"
            )

        return None

    def _calculate_architecture_score(self, content: str) -> float:
        """Calculate architectural significance score for function content."""
        if not content:
            return 0.0

        content_lower = content.lower()
        score = 0.0

        pattern_indicators = [
            "factory", "singleton", "observer", "strategy", "adapter",
            "facade", "proxy", "decorator", "builder", "command",
        ]

        layer_indicators = [
            "controller", "service", "repository", "model", "view",
            "handler", "manager", "coordinator", "processor", "engine",
        ]

        structure_indicators = [
            "interface", "abstract", "base", "parent", "child",
            "public", "private", "static", "dynamic", "virtual",
        ]

        for indicator in pattern_indicators:
            if indicator in content_lower:
                score += 0.3

        for indicator in layer_indicators:
            if indicator in content_lower:
                score += 0.2

        for indicator in structure_indicators:
            if indicator in content_lower:
                score += 0.1

        return min(score, 1.0)

    def _format_architecture_function(
        self, result: Dict[str, Any], context_list: List[str]
    ) -> None:
        """Format an architecture function result for the context."""
        name = result["name"]
        content = result["content"]
        architecture_score = result["architecture_score"]

        truncated_content = (
            content[:300] + "..." if len(content) > 300 else content
        )

        context_list.append(
            f"- **{name}** (Arch Score: {architecture_score:.2f}): {truncated_content}"
        )

    # ------------------------------------------------------------------
    #  Response parsers
    # ------------------------------------------------------------------

    def _parse_classification_response(self, response: str) -> Dict[str, str]:
        """Parse software classification response."""
        parsed: Dict[str, Any] = {}
        try:
            lines = response.split("\n")
            for line in lines:
                if "**SOFTWARE_TYPE:**" in line:
                    parsed["type"] = line.split("**SOFTWARE_TYPE:**")[1].strip()
                elif "**PRIMARY_PURPOSE:**" in line:
                    parsed["purpose"] = line.split("**PRIMARY_PURPOSE:**")[1].strip()
                elif "**CLASSIFICATION_CONFIDENCE:**" in line:
                    parsed["confidence"] = line.split(
                        "**CLASSIFICATION_CONFIDENCE:**"
                    )[1].strip()
                elif "**EVIDENCE:**" in line:
                    parsed["evidence"] = line.split("**EVIDENCE:**")[1].strip()

            parsed["addresses"] = self._extract_addresses_from_analysis(response)
        except Exception as e:
            self.logger.warning(f"Error parsing classification response: {e}")
            parsed["raw_response"] = response

        return parsed

    def _parse_security_response(self, response: str) -> Dict[str, str]:
        """Parse security assessment response."""
        parsed: Dict[str, Any] = {}
        try:
            lines = response.split("\n")
            indicators_section: List[str] = []
            capturing_indicators = False

            for line in lines:
                if "**OVERALL_RISK_LEVEL:**" in line:
                    parsed["risk_level"] = line.split("**OVERALL_RISK_LEVEL:**")[
                        1
                    ].strip()
                elif "**RISK_SCORE:**" in line:
                    parsed["risk_score"] = line.split("**RISK_SCORE:**")[1].strip()
                elif "**SUSPICIOUS_INDICATORS:**" in line:
                    capturing_indicators = True
                    remainder = line.split("**SUSPICIOUS_INDICATORS:**")[1].strip()
                    if remainder:
                        indicators_section.append(remainder)
                elif (
                    "**MITIGATION_RECOMMENDATIONS:**" in line
                    or "**IOCS:**" in line
                ):
                    capturing_indicators = False
                elif capturing_indicators and line.strip():
                    indicators_section.append(line.strip())

            if indicators_section:
                parsed["indicators"] = "\n".join(indicators_section)

            parsed["addresses"] = self._extract_addresses_from_analysis(response)

            if "**IOCS:**" in response:
                iocs_match = (
                    response.split("**IOCS:**")[1].split("**")[0]
                    if "**IOCS:**" in response
                    else ""
                )
                parsed["iocs"] = iocs_match.strip()

        except Exception as e:
            self.logger.warning(f"Error parsing security response: {e}")
            parsed["raw_response"] = response

        return parsed

    def _parse_function_response(self, response: str) -> Dict[str, str]:
        """Parse function categorization response."""
        parsed: Dict[str, Any] = {}
        try:
            categories = re.findall(
                r"\*\*([^:]+):\*\* \[(\d+)\] - ([^*]+)", response
            )
            for category, count, description in categories:
                parsed[category.lower().replace("_", " ")] = (
                    f"{count} functions: {description.strip()}"
                )

            parsed["addresses"] = self._extract_addresses_from_analysis(response)

            if "**CATEGORY_INSIGHTS:**" in response:
                insights_match = (
                    response.split("**CATEGORY_INSIGHTS:**")[1].split("**")[0]
                    if "**CATEGORY_INSIGHTS:**" in response
                    else ""
                )
                parsed["insights"] = insights_match.strip()

        except Exception as e:
            self.logger.warning(f"Error parsing function response: {e}")
            parsed["raw_response"] = response

        return parsed

    def _parse_behavioral_response(self, response: str) -> Dict[str, str]:
        """Parse behavioral analysis response."""
        parsed: Dict[str, Any] = {}
        try:
            lines = response.split("\n")
            for line in lines:
                if "**PRIMARY_WORKFLOWS:**" in line:
                    parsed["workflows"] = line.split("**PRIMARY_WORKFLOWS:**")[
                        1
                    ].strip()
                elif "**BEHAVIORAL_FINGERPRINT:**" in line:
                    parsed["fingerprint"] = line.split(
                        "**BEHAVIORAL_FINGERPRINT:**"
                    )[1].strip()

            parsed["addresses"] = self._extract_addresses_from_analysis(response)

        except Exception as e:
            self.logger.warning(f"Error parsing behavioral response: {e}")
            parsed["raw_response"] = response

        return parsed

    def _parse_architecture_response(self, response: str) -> Dict[str, str]:
        """Parse architecture analysis response."""
        parsed: Dict[str, Any] = {}
        try:
            lines = response.split("\n")
            for line in lines:
                if "**ARCHITECTURAL_PATTERN:**" in line:
                    parsed["pattern"] = line.split("**ARCHITECTURAL_PATTERN:**")[
                        1
                    ].strip()
                elif "**ARCHITECTURE_QUALITY:**" in line:
                    parsed["quality"] = line.split("**ARCHITECTURE_QUALITY:**")[
                        1
                    ].strip()
        except Exception as e:
            self.logger.warning(f"Error parsing architecture response: {e}")
            parsed["raw_response"] = response

        return parsed

    def _parse_risk_response(self, response: str) -> Dict[str, str]:
        """Parse risk assessment response."""
        parsed: Dict[str, Any] = {}
        try:
            lines = response.split("\n")
            risk_factors_section: List[str] = []
            capturing_factors = False

            for line in lines:
                if "**OVERALL_RISK_RATING:**" in line:
                    parsed["rating"] = line.split("**OVERALL_RISK_RATING:**")[
                        1
                    ].strip()
                elif "**THREAT_LEVEL:**" in line:
                    parsed["threat_level"] = line.split("**THREAT_LEVEL:**")[
                        1
                    ].strip()
                elif "**RECOMMENDED_ACTIONS:**" in line:
                    capturing_factors = False
                    parsed["recommendations"] = line.split(
                        "**RECOMMENDED_ACTIONS:**"
                    )[1].strip()
                elif "**PRIMARY_RISK_FACTORS:**" in line:
                    capturing_factors = True
                    remainder = line.split("**PRIMARY_RISK_FACTORS:**")[1].strip()
                    if remainder:
                        risk_factors_section.append(remainder)
                elif (
                    capturing_factors
                    and line.strip()
                    and not line.startswith("**")
                ):
                    risk_factors_section.append(line.strip())

            if risk_factors_section:
                parsed["risk_factors"] = "\n".join(risk_factors_section)

            parsed["addresses"] = self._extract_addresses_from_analysis(response)

        except Exception as e:
            self.logger.warning(f"Error parsing risk response: {e}")
            parsed["raw_response"] = response

        return parsed

    # ------------------------------------------------------------------
    #  Phase 3 - Report generation
    # ------------------------------------------------------------------

    def _generate_structured_software_report(
        self,
        data: Dict[str, Any],
        analysis: Dict[str, Any],
        format_type: str,
    ) -> str:
        """Generate the final structured software report."""
        if format_type.lower() == "json":
            return self._generate_json_report(data, analysis)
        elif format_type.lower() == "text":
            return self._generate_text_report(data, analysis)
        elif format_type.lower() == "html":
            return self._generate_html_report(data, analysis)
        else:  # Default to markdown
            return self._generate_markdown_report(data, analysis)

    def _generate_markdown_report(
        self, data: Dict[str, Any], analysis: Dict[str, Any]
    ) -> str:
        """Generate markdown-formatted software report."""
        timestamp = self._get_current_timestamp()

        report = f"""# Comprehensive Software Analysis Report

**Generated:** {timestamp}
**Analysis Tool:** OGhidra AI-Powered Reverse Engineering Platform

---

## 📊 Executive Summary

### Software Classification
- **Type:** {analysis.get('software_classification', {}).get('type', 'Unknown')}
- **Primary Purpose:** {analysis.get('software_classification', {}).get('purpose', 'Not determined')}
- **Classification Confidence:** {analysis.get('software_classification', {}).get('confidence', 'N/A')}

### Risk Assessment
- **Overall Risk Level:** {analysis.get('risk_assessment', {}).get('rating', 'Not assessed')}
- **Security Risk Score:** {analysis.get('security_assessment', {}).get('risk_score', 'N/A')}/100
- **Threat Level:** {analysis.get('risk_assessment', {}).get('threat_level', 'Unknown')}

---

## 🔍 Binary Overview

### Statistical Summary
- **Total Functions:** {data['metadata']['total_functions']}
- **Analyzed Functions:** {data['metadata']['analyzed_count']} ({(data['metadata']['analyzed_count']/data['metadata']['total_functions']*100) if data['metadata']['total_functions'] > 0 else 0:.1f}%)
- **Renamed Functions:** {data['metadata']['renamed_count']}
- **Imported Symbols:** {len(data['imports'])}
- **Exported Symbols:** {len(data['exports'])}
- **Memory Segments:** {len(data['segments'])}

### Key Imports
{self._format_imports_for_report(data['imports'])}

### Key Exports
{self._format_exports_for_report(data['exports'])}

---

## 🏗️ Architecture Analysis

### Design Pattern
**Pattern:** {analysis.get('architecture_analysis', {}).get('pattern', 'Not identified')}

### Architecture Quality
{analysis.get('architecture_analysis', {}).get('quality', 'Not assessed')}

---

## 🎯 Function Analysis

### Function Categories
{self._format_function_categories_for_report(analysis.get('function_categorization', {}))}

### Renamed Functions
{self._format_renamed_functions_for_report(data['renamed_functions'])}

---

## 🔒 Security Assessment

### Risk Breakdown
- **Overall Risk:** {analysis.get('security_assessment', {}).get('risk_level', 'Not assessed')}
- **Risk Score:** {analysis.get('security_assessment', {}).get('risk_score', 'N/A')}/100

### Suspicious Indicators
{analysis.get('security_assessment', {}).get('indicators', 'None identified')}

### Security Recommendations
{analysis.get('risk_assessment', {}).get('recommendations', 'No specific recommendations available')}

---

## 🔄 Behavioral Analysis

### Primary Workflows
{analysis.get('behavioral_analysis', {}).get('workflows', 'Not analyzed')}

### Behavioral Fingerprint
{analysis.get('behavioral_analysis', {}).get('fingerprint', 'Not identified')}

---

## 📋 Key Findings

### Evidence Supporting Classification
{analysis.get('software_classification', {}).get('evidence', 'No specific evidence documented')}

### Function Insights
{analysis.get('function_categorization', {}).get('insights', 'No insights available')}

---

## 🔬 Detailed Findings with Addresses

This section provides specific addresses and evidence for key findings identified during analysis.

### Security-Related Findings
{self._format_findings_with_addresses(analysis.get('security_assessment', {}).get('addresses', []), max_findings=15)}

### Classification Evidence with Addresses
{self._format_findings_with_addresses(analysis.get('software_classification', {}).get('addresses', []), max_findings=10)}

### Behavioral Patterns with Addresses
{self._format_findings_with_addresses(analysis.get('behavioral_analysis', {}).get('addresses', []), max_findings=10)}

### Risk Factors with Addresses
{self._format_findings_with_addresses(analysis.get('risk_assessment', {}).get('addresses', []), max_findings=10)}

---

## ⚠️ Risk Mitigation

### Recommended Actions
{analysis.get('risk_assessment', {}).get('recommendations', 'No specific recommendations')}

### Monitoring Recommendations
{analysis.get('risk_assessment', {}).get('monitoring', 'Standard monitoring protocols recommended')}

---

## 📈 Analysis Statistics

- **Analysis Completion:** {(sum(1 for a in analysis.values() if a)/len(analysis)*100):.1f}%
- **Data Quality:** {'High' if data['metadata']['analyzed_count'] > 10 else 'Medium' if data['metadata']['analyzed_count'] > 0 else 'Low'}
- **Confidence Level:** {analysis.get('software_classification', {}).get('confidence', 'Not determined')}

---

*Report generated by OGhidra AI-Powered Reverse Engineering Platform*
*For questions or additional analysis, consult the detailed function summaries and analysis logs.*
"""
        return report

    def _generate_html_report(
        self, data: Dict[str, Any], analysis: Dict[str, Any]
    ) -> str:
        """
        Generate HTML-formatted vulnerability report using AI.

        This method:
        1. Builds a context summary from analysis data
        2. Calls the LLM with html_report_generation_prompt to get structured JSON
        3. Parses the JSON response into sections
        4. Assembles final HTML using the report_template module
        """
        from src.report_template import (
            generate_html_report,
            ReportSection,
            ReportMetadata,
            build_stats_grid,
            build_attack_vectors,
            build_timeline,
            build_table,
            build_vulnerability_discovery,
            get_discovery_javascript,
        )

        # Build context for the AI
        context = self._build_html_report_context(data, analysis)

        # Get the HTML report generation prompt
        prompt = self.html_report_prompt

        # Build the full prompt with context
        full_prompt = f"""{prompt}

## ANALYSIS DATA TO REPORT:

### Binary Information:
- **Binary Name:** {data.get('metadata', {}).get('binary_name', 'Unknown Binary')}
- **Total Functions:** {data.get('metadata', {}).get('total_functions', 0)}
- **Analyzed Functions:** {data.get('metadata', {}).get('analyzed_count', 0)}
- **Renamed Functions:** {data.get('metadata', {}).get('renamed_count', 0)}
- **Imports:** {len(data.get('imports', []))}
- **Exports:** {len(data.get('exports', []))}

### INVESTIGATION FINDINGS (HIGHEST PRIORITY — use these as the primary source of truth):
{context}

### Security Assessment:
- **Risk Level:** {analysis.get('security_assessment', {}).get('risk_level', 'Not assessed')}
- **Risk Score:** {analysis.get('security_assessment', {}).get('risk_score', 'N/A')}/100
- **Indicators:** {analysis.get('security_assessment', {}).get('indicators', 'None')}

### Software Classification:
- **Type:** {analysis.get('software_classification', {}).get('type', 'Unknown')}
- **Purpose:** {analysis.get('software_classification', {}).get('purpose', 'Unknown')}
- **Confidence:** {analysis.get('software_classification', {}).get('confidence', 'N/A')}

### Risk Assessment:
- **Rating:** {analysis.get('risk_assessment', {}).get('rating', 'Not assessed')}
- **Threat Level:** {analysis.get('risk_assessment', {}).get('threat_level', 'Unknown')}
- **Recommendations:** {analysis.get('risk_assessment', {}).get('recommendations', 'None')}

### Key Imports (sample):
{self._format_imports_sample(data.get('imports', [])[:20])}

### Behavioral Analysis:
- **Workflows:** {analysis.get('behavioral_analysis', {}).get('workflows', 'Not analyzed')}
- **Fingerprint:** {analysis.get('behavioral_analysis', {}).get('fingerprint', 'Not identified')}

### Evidence with Addresses:
{self._format_address_evidence(analysis)}

IMPORTANT: If "INVESTIGATION FINDINGS" above contains confirmed vulnerability findings from a prior investigation (orchestrator notebook entries, final report), those findings MUST be the primary basis for the report. They take precedence over the generic security assessment. The report severity, findings, and discovery sections must reflect these confirmed results.

Now generate the JSON report based on this data.
"""

        try:
            # Call LLM to generate the structured report
            response = self._call_llm_for_html_report(full_prompt)

            # Parse the JSON response
            sections, ai_metadata = self._parse_html_report_response(response)

            # If no sections were generated, use the fallback report
            if not sections:
                self.logger.info(
                    "No sections generated from AI, using fallback report"
                )
                return self._generate_fallback_html_report(data, analysis)

            # Create metadata
            binary_name = data.get("metadata", {}).get(
                "binary_name", "Unknown Binary"
            )
            metadata = ReportMetadata(
                binary_name=binary_name,
                severity=ai_metadata.get("severity", "MEDIUM"),
                subtitle=ai_metadata.get(
                    "subtitle", "AI-Powered Binary Analysis Report"
                ),
                tool_name="OGhidra MCP",
            )

            # Generate the final HTML
            return generate_html_report(sections, metadata)

        except Exception as e:
            self.logger.error(f"Error generating HTML report: {e}")
            return self._generate_fallback_html_report(data, analysis)

    def _build_html_report_context(
        self, data: Dict[str, Any], analysis: Dict[str, Any]
    ) -> str:
        """Build context string for HTML report generation."""
        context_parts: List[str] = []

        # Include orchestrator/agent investigation findings (highest priority)
        agent_analysis = data.get("agent_analysis_history", "")
        if agent_analysis and agent_analysis.strip():
            context_parts.append("## Prior Investigation Findings (PRIMARY SOURCE):")
            context_parts.append(agent_analysis[:4000])

        summaries = data.get("function_summaries", {})
        if summaries:
            context_parts.append("## Key Function Summaries:")
            for name, summary in list(summaries.items())[:10]:
                context_parts.append(f"- **{name}:** {summary[:200]}...")

        return "\n".join(context_parts)

    def _format_imports_sample(self, imports: List[str]) -> str:
        """Format a sample of imports for the prompt."""
        if not imports:
            return "No imports available"
        return "\n".join(f"- {imp}" for imp in imports[:15])

    def _format_address_evidence(self, analysis: Dict[str, Any]) -> str:
        """Format address evidence from analysis for the prompt."""
        evidence: List[str] = []

        for section_name in [
            "security_assessment",
            "software_classification",
            "risk_assessment",
        ]:
            section = analysis.get(section_name, {})
            addresses = section.get("addresses", [])
            if addresses:
                for addr_info in addresses[:5]:
                    if isinstance(addr_info, dict):
                        evidence.append(
                            f"- {addr_info.get('address', 'N/A')}: {addr_info.get('context', 'No context')}"
                        )

        return (
            "\n".join(evidence)
            if evidence
            else "No specific address evidence available"
        )

    def _call_llm_for_html_report(self, prompt: str) -> str:
        """Call the LLM to generate the HTML report structure."""
        try:
            if self.llm:
                response = self.llm.generate(prompt=prompt)
                return response
            else:
                self.logger.warning(
                    "No LLM client available for HTML report generation"
                )
                return "{}"
        except Exception as e:
            self.logger.error(f"Error calling LLM for HTML report: {e}")
            return "{}"

    def _parse_html_report_response(self, response: str) -> tuple:
        """
        Parse the AI's JSON response into ReportSection objects.

        Returns:
            Tuple of (List[ReportSection], metadata_dict)
        """
        from src.report_template import (
            ReportSection,
            build_stats_grid,
            build_attack_vectors,
            build_timeline,
            build_table,
        )

        sections: list = []
        metadata = {"severity": "MEDIUM", "subtitle": "Binary Analysis Report"}

        try:
            # Try to extract JSON from the response
            json_match = re.search(
                r"```(?:json)?\s*(\{.*?\})\s*```", response, re.DOTALL
            )
            if json_match:
                json_str = json_match.group(1)
            else:
                json_start = response.find("{")
                json_end = response.rfind("}") + 1
                if json_start >= 0 and json_end > json_start:
                    json_str = response[json_start:json_end]
                else:
                    raise ValueError("No JSON found in response")

            report_data = json.loads(json_str)

            if "metadata" in report_data:
                metadata = report_data["metadata"]

            for section_data in report_data.get("sections", []):
                section_id = section_data.get("id", "unknown")
                title = section_data.get("title", "Section")
                icon = section_data.get("icon", "📄")
                content_type = section_data.get("content_type", "html")
                content = section_data.get("content", "")

                if content_type == "stats" and isinstance(content, (str, list)):
                    if isinstance(content, str):
                        try:
                            content = json.loads(content)
                        except Exception:
                            pass
                    if isinstance(content, list):
                        content = build_stats_grid(content)

                elif content_type == "attack_vectors" and isinstance(
                    content, (str, list)
                ):
                    if isinstance(content, str):
                        try:
                            content = json.loads(content)
                        except Exception:
                            pass
                    if isinstance(content, list):
                        content = build_attack_vectors(content)

                elif content_type == "timeline" and isinstance(
                    content, (str, list)
                ):
                    if isinstance(content, str):
                        try:
                            content = json.loads(content)
                        except Exception:
                            pass
                    if isinstance(content, list):
                        content = build_timeline(content)

                elif content_type == "table" and isinstance(
                    content, (str, dict)
                ):
                    if isinstance(content, str):
                        try:
                            content = json.loads(content)
                        except Exception:
                            pass
                    if isinstance(content, dict):
                        headers = content.get("headers", [])
                        rows = content.get("rows", [])
                        address_cols = (
                            [0]
                            if headers and "Address" in headers[0]
                            else []
                        )
                        content = build_table(headers, rows, address_cols)

                elif content_type == "discovery" and isinstance(
                    content, (str, list)
                ):
                    from src.report_template import build_vulnerability_discovery

                    if isinstance(content, str):
                        try:
                            content = json.loads(content)
                        except Exception:
                            pass
                    if isinstance(content, list):
                        content = build_vulnerability_discovery(content)

                elif content_type == "key_findings" and isinstance(
                    content, (str, list)
                ):
                    from src.report_template import build_key_findings

                    if isinstance(content, str):
                        try:
                            content = json.loads(content)
                        except Exception:
                            pass
                    if isinstance(content, list):
                        content = build_key_findings(content)

                elif content_type == "security_imports" and isinstance(
                    content, (str, list)
                ):
                    from src.report_template import build_security_imports

                    if isinstance(content, str):
                        try:
                            content = json.loads(content)
                        except Exception:
                            pass
                    if isinstance(content, list):
                        content = build_security_imports(content)

                sections.append(
                    ReportSection(
                        id=section_id,
                        title=title,
                        icon=icon,
                        content_type=content_type,
                        content=str(content),
                    )
                )

            if not sections:
                raise ValueError("No sections found in parsed response")

        except Exception as e:
            self.logger.warning(f"Error parsing HTML report response: {e}")
            if response and response.strip() and response != "{}":
                from src.report_template import ReportSection as _RS

                sections.append(
                    _RS(
                        id="raw_analysis",
                        title="Analysis Results",
                        icon="📋",
                        content_type="html",
                        content=f'<div class="summary-content"><pre>{response[:5000]}</pre></div>',
                    )
                )
            else:
                self.logger.warning(
                    "Empty or invalid LLM response, using fallback report"
                )

        return sections, metadata

    def _generate_fallback_html_report(
        self, data: Dict[str, Any], analysis: Dict[str, Any]
    ) -> str:
        """Generate a basic HTML report without AI, as fallback."""
        from src.report_template import (
            generate_html_report,
            ReportSection,
            ReportMetadata,
        )

        binary_name = data.get("metadata", {}).get("binary_name", "Unknown Binary")

        metadata = ReportMetadata(
            binary_name=binary_name,
            severity=analysis.get("security_assessment", {})
            .get("risk_level", "MEDIUM")
            .upper(),
            subtitle="Binary Analysis Report (Fallback)",
        )

        sections = []

        # Executive Summary
        exec_content = f'''
        <div class="summary-content">
            <p><strong>Software Type:</strong> {analysis.get('software_classification', {}).get('type', 'Unknown')}</p>
            <p><strong>Risk Level:</strong> {analysis.get('security_assessment', {}).get('risk_level', 'Unknown')}</p>
            <p><strong>Purpose:</strong> {analysis.get('software_classification', {}).get('purpose', 'Not determined')}</p>
        </div>
        '''
        sections.append(
            ReportSection(
                id="executive_summary",
                title="Executive Summary",
                icon="📋",
                content_type="html",
                content=exec_content,
            )
        )

        # Statistics
        stats_content = f'''
        <div class="grid">
            <div class="card">
                <div class="card-header">
                    <div class="card-icon">📦</div>
                    <h3>Functions</h3>
                </div>
                <div class="stat-value">{data.get('metadata', {}).get('total_functions', 0)}</div>
            </div>
            <div class="card">
                <div class="card-header">
                    <div class="card-icon">🔗</div>
                    <h3>Imports</h3>
                </div>
                <div class="stat-value">{len(data.get('imports', []))}</div>
            </div>
            <div class="card">
                <div class="card-header">
                    <div class="card-icon">📤</div>
                    <h3>Exports</h3>
                </div>
                <div class="stat-value">{len(data.get('exports', []))}</div>
            </div>
        </div>
        '''
        sections.append(
            ReportSection(
                id="statistics",
                title="Statistics",
                icon="📊",
                content_type="html",
                content=stats_content,
            )
        )

        return generate_html_report(sections, metadata)

    def _generate_json_report(
        self, data: Dict[str, Any], analysis: Dict[str, Any]
    ) -> str:
        """Generate JSON-formatted software report."""
        report_data = {
            "metadata": {
                "generated_timestamp": self._get_current_timestamp(),
                "tool": "OGhidra AI-Powered Reverse Engineering Platform",
                "version": "1.0",
            },
            "executive_summary": {
                "software_type": analysis.get("software_classification", {}).get(
                    "type", "Unknown"
                ),
                "primary_purpose": analysis.get(
                    "software_classification", {}
                ).get("purpose", "Not determined"),
                "risk_level": analysis.get("risk_assessment", {}).get(
                    "rating", "Not assessed"
                ),
                "risk_score": analysis.get("security_assessment", {}).get(
                    "risk_score", "N/A"
                ),
                "threat_level": analysis.get("risk_assessment", {}).get(
                    "threat_level", "Unknown"
                ),
            },
            "binary_overview": {
                "statistics": data["metadata"],
                "imports": data["imports"][:20],
                "exports": data["exports"][:20],
                "segments": data["segments"],
            },
            "analysis_results": {
                "classification": analysis.get("software_classification", {}),
                "security": analysis.get("security_assessment", {}),
                "functions": analysis.get("function_categorization", {}),
                "behavior": analysis.get("behavioral_analysis", {}),
                "architecture": analysis.get("architecture_analysis", {}),
                "risk": analysis.get("risk_assessment", {}),
            },
            "detailed_findings": {
                "security_findings": analysis.get(
                    "security_assessment", {}
                ).get("addresses", []),
                "classification_evidence": analysis.get(
                    "software_classification", {}
                ).get("addresses", []),
                "behavioral_patterns": analysis.get(
                    "behavioral_analysis", {}
                ).get("addresses", []),
                "risk_factors": analysis.get("risk_assessment", {}).get(
                    "addresses", []
                ),
                "function_addresses": analysis.get(
                    "function_categorization", {}
                ).get("addresses", []),
            },
            "function_data": {
                "renamed_functions": data["renamed_functions"],
                "summaries": data["function_summaries"],
            },
        }

        return json.dumps(report_data, indent=2, default=str)

    def _generate_text_report(
        self, data: Dict[str, Any], analysis: Dict[str, Any]
    ) -> str:
        """Generate plain text software report."""
        markdown_report = self._generate_markdown_report(data, analysis)

        text_report = markdown_report
        text_report = text_report.replace("#", "")
        text_report = text_report.replace("**", "")
        text_report = text_report.replace("*", "")
        text_report = text_report.replace("---", "=" * 50)

        return text_report

    # ------------------------------------------------------------------
    #  Report display formatters
    # ------------------------------------------------------------------

    def _format_imports_for_report(self, imports: List[str]) -> str:
        """Format imports for report display."""
        if not imports:
            return "- No imports detected"

        formatted = []
        for imp in imports[:15]:
            formatted.append(f"- {imp}")

        if len(imports) > 15:
            formatted.append(f"- ... and {len(imports) - 15} more imports")

        return "\n".join(formatted)

    def _format_exports_for_report(self, exports: List[str]) -> str:
        """Format exports for report display."""
        if not exports:
            return "- No exports detected"

        formatted = []
        for exp in exports[:10]:
            formatted.append(f"- {exp}")

        if len(exports) > 10:
            formatted.append(f"- ... and {len(exports) - 10} more exports")

        return "\n".join(formatted)

    def _format_function_categories_for_report(
        self, categories: Dict[str, str]
    ) -> str:
        """Format function categories for report display."""
        if not categories:
            return "- Function categorization not available"

        formatted = []
        for category, description in categories.items():
            if "raw_response" not in category:
                formatted.append(f"- **{category.title()}:** {description}")

        return (
            "\n".join(formatted)
            if formatted
            else "- No function categories identified"
        )

    def _format_renamed_functions_for_report(
        self, renamed_functions: List[tuple]
    ) -> str:
        """Format renamed functions for report display."""
        if not renamed_functions:
            return "- No functions have been renamed in this analysis"

        formatted = []
        for old_name, new_name in renamed_functions[:20]:
            formatted.append(f"- `{old_name}` → `{new_name}`")

        if len(renamed_functions) > 20:
            formatted.append(
                f"- ... and {len(renamed_functions) - 20} more renamed functions"
            )

        return "\n".join(formatted)

    # ------------------------------------------------------------------
    #  Address and evidence extraction helpers
    # ------------------------------------------------------------------

    def _extract_addresses_from_analysis(
        self, analysis_text: str
    ) -> List[Dict[str, str]]:
        """
        Extract addresses and their associated findings from AI analysis text.

        Returns:
            List of dictionaries with 'address', 'context', 'finding' keys
        """
        findings: List[Dict[str, str]] = []

        address_patterns = [
            r"(?:at|in|address)\s+(0x[0-9a-fA-F]{6,})\s+(?:in\s+)?(?:function\s+)?[\"']?([^\"'\n,.:]+)?",
            r"(0x[0-9a-fA-F]{6,})\s+[\"']([^\"'\n,.:]+)[\"']",
            r"function\s+[\"']?([^\"'\s]+)[\"']?\s+at\s+(0x[0-9a-fA-F]{6,})",
        ]

        lines = analysis_text.split("\n")
        for line in lines:
            for pattern in address_patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for match in matches:
                    groups = match.groups()
                    address = None
                    function = None

                    for group in groups:
                        if group and group.startswith("0x"):
                            address = group
                        elif group and not group.startswith("0x"):
                            function = group

                    if address:
                        findings.append(
                            {
                                "address": address,
                                "function": function or "unknown",
                                "context": line.strip(),
                                "finding": line.strip(),
                            }
                        )

        return findings

    def _format_findings_with_addresses(
        self, findings: List[Dict[str, str]], max_findings: int = 20
    ) -> str:
        """
        Format a list of findings with addresses for report display.
        """
        if not findings:
            return "No specific findings with addresses available."

        formatted: List[str] = []
        for i, finding in enumerate(findings[:max_findings], 1):
            addr = finding.get("address", "unknown")
            func = finding.get("function", "unknown")
            context = finding.get("context", "No details")

            formatted.append(f"{i}. **Address {addr}** (Function: `{func}`)")
            formatted.append(f"   {context}")
            formatted.append("")

        if len(findings) > max_findings:
            formatted.append(
                f"*... and {len(findings) - max_findings} more findings*"
            )

        return "\n".join(formatted)

    def _enrich_findings_with_locations(
        self, analysis: Dict[str, Any], data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Enrich analysis findings with specific location data.
        """
        enriched = analysis.copy()

        all_findings: List[Dict[str, str]] = []

        for section_key, section_value in analysis.items():
            if isinstance(section_value, dict):
                for key, value in section_value.items():
                    if isinstance(value, str):
                        findings = self._extract_addresses_from_analysis(value)
                        for finding in findings:
                            finding["section"] = section_key
                            finding["subsection"] = key
                            all_findings.append(finding)
            elif isinstance(section_value, str):
                findings = self._extract_addresses_from_analysis(section_value)
                for finding in findings:
                    finding["section"] = section_key
                    all_findings.append(finding)

        enriched["extracted_findings"] = all_findings

        return enriched
