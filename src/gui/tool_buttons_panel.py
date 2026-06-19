import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from ..bridge import Bridge
from .ai_response_panel import AIResponsePanel
from .workflow_diagram import WorkflowDiagram
import threading
import time
import json
import re
from typing import Dict, Any
from .daemon_thread_pool_executor import DaemonThreadPoolExecutor
from concurrent.futures import as_completed
import logging

logger = logging.getLogger(__name__)


class ToolButtonsPanel:
    """Panel with buttons for commonly used tools."""

    def __init__(
        self,
        parent,
        bridge: Bridge,
        response_panel: AIResponsePanel,
        workflow_diagram: WorkflowDiagram,
        renamed_functions_panel=None,
    ):
        self.frame = ttk.LabelFrame(parent, text="Smart Tools", padding=10)
        self.bridge = bridge
        self.response_panel = response_panel
        self.workflow_diagram = workflow_diagram
        self.renamed_functions_panel = renamed_functions_panel
        self.tool_running = False
        self.should_stop = False  # Flag to control stopping

        # DECOMPILATION CACHE: LRU cache for frequently accessed functions
        self._decompilation_cache = {}  # address -> decompiled_code
        self._cache_max_size = 1000  # Cache up to 1000 functions
        self._cache_hits = 0  # Track cache performance
        self._cache_misses = 0

        self._setup_widgets()

    def _setup_widgets(self):
        """Setup the tool button widgets."""
        # Smart tool buttons (use AI agent workflow)
        smart_tools = [
            ("analyze-current", "Analyze Current Function", self._analyze_current_function),
            ("rename-current", "Rename Current Function", self._rename_current_function),
            ("rename-all", "Rename All Functions", self._rename_all_functions),
            ("generate-report", "Generate Software Report", self._generate_software_report),
            ("analyze-imports", "Analyze Imports", self._analyze_imports),
            ("analyze-strings", "Analyze Strings", self._analyze_strings),
            ("analyze-exports", "Analyze Exports", self._analyze_exports),
            ("search-strings", "Search Strings", self._search_strings),
            ("scan-tables", "Scan Function Tables", self._scan_function_tables),
        ]

        for i, (tool_id, label, command) in enumerate(smart_tools):
            btn = ttk.Button(self.frame, text=label, command=command, width=25, state="normal")
            btn.grid(row=i // 2, column=i % 2, padx=5, pady=5, sticky="ew")

        # Calculate the next row after buttons (buttons use rows 0 to (len-1)//2)
        next_row = (len(smart_tools) + 1) // 2

        # Status indicator
        self.status_label = ttk.Label(self.frame, text="Ready", foreground="green")
        self.status_label.grid(row=next_row, column=0, columnspan=2, pady=(10, 0))

        # Progress bar and stop button frame
        progress_frame = ttk.Frame(self.frame)
        progress_frame.grid(row=next_row + 1, column=0, columnspan=2, sticky="ew", pady=(5, 0))
        progress_frame.grid_columnconfigure(0, weight=1)

        self.progress = ttk.Progressbar(progress_frame, mode="indeterminate")
        self.progress.grid(row=0, column=0, sticky="ew", padx=(0, 5))

        self.stop_button = ttk.Button(progress_frame, text="Stop", command=self._stop_tool, state="disabled", width=8)
        self.stop_button.grid(row=0, column=1)

        # Configure grid weights
        self.frame.grid_columnconfigure(0, weight=1)
        self.frame.grid_columnconfigure(1, weight=1)

    def _set_tool_running(self, running: bool, tool_name: str = ""):
        """Set the tool running state."""
        self.tool_running = running

        # Update all buttons
        state = "disabled" if running else "normal"
        for widget in self.frame.winfo_children():
            if isinstance(widget, ttk.Button) and widget not in [self.stop_button]:
                widget.config(state=state)

        # Update stop button state
        self.stop_button.config(state="normal" if running else "disabled")

        # Update status and progress
        if running:
            self.should_stop = False  # Reset stop flag for new tool
            self.status_label.config(text=f"Running {tool_name}...", foreground="orange")
            self.progress.start()
        else:
            self.status_label.config(text="Ready", foreground="green")
            self.progress.stop()

    def _run_ai_agent_query(self, query: str, tool_name: str):
        """Run a query through the AI agent workflow."""

        def worker():
            try:
                self._set_tool_running(True, tool_name)

                # Add query to response panel
                self.response_panel.add_response(f"Smart Tool: {tool_name}", f"Query: {query}")

                # Start monitoring workflow in a separate thread
                monitor_thread = threading.Thread(target=self._monitor_workflow_stage, daemon=True)
                monitor_thread.start()

                # Process query with full AI agent workflow
                result = self.bridge.process_query(query)

                # Add result to response panel
                self.response_panel.add_response("AI Agent Response", result)

                # Final stage update
                self.workflow_diagram.set_current_stage(None)

            except Exception as e:
                error_msg = f"Error running worker for '_run_ai_agent_query()': {e}"
                logger.error(error_msg)
                self.response_panel.add_response("Error", error_msg)
                self.workflow_diagram.set_current_stage(None)
            finally:
                # THREAD SAFETY: Clear batch operation flag to re-enable auto-refresh
                if self.renamed_functions_panel:
                    self.renamed_functions_panel.batch_operation_in_progress = False
                    # Trigger a final refresh to show all completed functions
                    try:
                        self.renamed_functions_panel._update_function_list()
                    except Exception as refresh_error:
                        logger.warning(f"Error refreshing function list after batch operation: {refresh_error}")

                self._set_tool_running(False)

        threading.Thread(target=worker, daemon=True).start()

    def _monitor_workflow_stage(self):
        """Monitor the bridge's workflow stage and update the diagram."""
        previous_stage = None
        while self.tool_running:
            try:
                current_stage = getattr(self.bridge, "current_workflow_stage", None)
                if current_stage != previous_stage:
                    self.workflow_diagram.set_current_stage(current_stage)
                    previous_stage = current_stage

                # Break if workflow is complete
                if current_stage is None and previous_stage is not None:
                    break

                time.sleep(0.1)  # Check every 100ms
            except Exception as e:
                logger.error(f"Error monitoring workflow stage: {e}")
                break

    def _run_hardcoded_workflow(self, tool_name: str, display_name: str, params: dict | None = None):
        """Run a hardcoded workflow: call *tool_name*(**params) then send results to AI for analysis."""

        def worker():
            try:
                self._set_tool_running(True, display_name)
                self.workflow_diagram.set_current_stage("execution")

                # Add initial message to response panel
                self.response_panel.add_response(
                    f"Smart Tool: {display_name}", f"Executing {tool_name}() and sending results to AI for analysis..."
                )

                # Step 1: Call the specific Ghidra tool (with pagination for list tools)
                if hasattr(self.bridge.ghidra, tool_name):
                    tool_method = getattr(self.bridge.ghidra, tool_name)

                    try:
                        # Check if this is a list tool that supports pagination
                        is_list_tool = tool_name in [
                            "list_imports",
                            "list_exports",
                            "list_strings",
                            "list_functions",
                            "list_methods",
                        ]

                        if is_list_tool:
                            self.response_panel.add_response(
                                "Progress", f"Retrieving all {tool_name.split('_')[1]} (paginated)..."
                            )
                            raw_tool_result = self.bridge._collect_all_paginated_list_results(
                                tool_method, **((params or {}).copy())
                            )
                            if isinstance(raw_tool_result, list):
                                self.response_panel.add_response("Progress", f"Collected {len(raw_tool_result)} items.")

                        else:
                            # Standard single call for non-list tools
                            raw_tool_result = tool_method(**(params or {}))

                    except TypeError as te:
                        self.response_panel.add_response("Error", f"Parameter mismatch: {te}")
                        return

                    # Check if we got an error
                    is_error = isinstance(raw_tool_result, str) and raw_tool_result.lower().startswith("error:")

                    if not is_error:
                        # Format the tool data
                        if isinstance(raw_tool_result, (dict, list)):
                            try:
                                formatted_tool_data = json.dumps(raw_tool_result, indent=2)
                            except TypeError:
                                formatted_tool_data = str(raw_tool_result)
                        else:
                            formatted_tool_data = str(raw_tool_result)

                        # Add raw output to response panel
                        self.response_panel.add_response(f"Raw Output from {tool_name}", formatted_tool_data)

                        # --------------------------------------------------
                        # EXTRA CONTEXT FOR STRING SEARCH
                        # --------------------------------------------------
                        extra_context = ""
                        if tool_name == "list_strings" and isinstance(raw_tool_result, list):
                            import re

                            # Extract addresses from list_strings lines
                            addr_pattern = re.compile(r"^([0-9a-fA-F]{6,})[: ]")
                            addresses = []
                            for line in raw_tool_result:
                                m = addr_pattern.match(line)
                                if m:
                                    addresses.append(m.group(1))

                            # Limit to first 5 addresses to keep prompt size sane
                            addresses = addresses[:5]

                            if addresses:
                                extra_context += "\n\n=== STRING USAGE CONTEXT (auto-collected) ===\n"

                            for addr in addresses:
                                # Get incoming xrefs (who references this string)
                                try:
                                    xrefs = self.bridge.ghidra.get_xrefs_to(addr)
                                except Exception as e:
                                    xrefs = [f"Error getting xrefs_to({addr}): {e}"]

                                # Normalise format to list of lines
                                if isinstance(xrefs, (str, bytes)):
                                    xref_lines = str(xrefs).splitlines()
                                else:
                                    xref_lines = [str(x) for x in xrefs]

                                extra_context += (
                                    f"\n-- String at {addr} references ({len(xref_lines)}):\n"
                                    + "\n".join(xref_lines[:10])
                                    + "\n"
                                )

                                # Decompile first 2 referencing functions (if any address found)
                                fn_addrs = []
                                for xl in xref_lines:
                                    mm = addr_pattern.match(xl)
                                    if mm:
                                        fn_addrs.append(mm.group(1))
                                    if len(fn_addrs) >= 2:
                                        break

                                for faddr in fn_addrs:
                                    try:
                                        code = self.bridge.ghidra.decompile_function_by_address(faddr)
                                        code_snippet = "\n".join(code.splitlines()[:60])  # cap lines
                                    except Exception as e:
                                        code_snippet = f"Error decompiling {faddr}: {e}"
                                    extra_context += f"\n--- Decompiled caller {faddr} ---\n{code_snippet}\n"

                        # Step 2: Send to AI for analysis
                        self.workflow_diagram.set_current_stage("analysis")
                        analysis_prompt = self._get_analysis_prompt(tool_name, formatted_tool_data + extra_context)

                        try:
                            ai_analysis = self.bridge.ollama.generate(prompt=analysis_prompt)

                            if ai_analysis and ai_analysis.strip():
                                self.response_panel.add_response("AI Analysis", ai_analysis)
                            else:
                                self.response_panel.add_response("Warning", "AI analysis returned empty response.")

                        except Exception as e:
                            error_msg = f"Error during AI analysis: {e}"
                            logger.error(error_msg)
                            self.response_panel.add_response("Error", error_msg)
                    else:
                        # Tool returned an error
                        self.response_panel.add_response("Tool Error", raw_tool_result)

                else:
                    error_msg = f"Tool {tool_name} not found in bridge.ghidra"
                    self.response_panel.add_response("Error", error_msg)

                # Final stage update
                self.workflow_diagram.set_current_stage(None)

            except Exception as e:
                error_msg = f"Error running {display_name}: {e}"
                logger.error(error_msg)
                self.response_panel.add_response("Error", error_msg)
                self.workflow_diagram.set_current_stage(None)
            finally:
                self._set_tool_running(False)

        threading.Thread(target=worker, daemon=True).start()

    def _run_hardcoded_rename_workflow(self, display_name: str):
        """Run a hardcoded rename workflow: get current function, analyze with AI agent, then rename based on AI analysis."""

        def worker():
            try:
                self._set_tool_running(True, display_name)
                self.workflow_diagram.set_current_stage("execution")

                # Add initial message to response panel
                self.response_panel.add_response(
                    f"Smart Tool: {display_name}",
                    "Starting 3-step rename workflow: get current function → AI analysis → rename",
                )

                # Step 1: Get current function
                try:
                    current_function_result = self.bridge.ghidra.get_current_function()
                    if isinstance(current_function_result, str) and current_function_result.lower().startswith("error:"):
                        self.response_panel.add_response("Error", f"Failed to get current function: {current_function_result}")
                        return

                    self.response_panel.add_response("Step 1: Current Function", str(current_function_result))

                    # Extract function name from the result
                    function_name = None
                    if isinstance(current_function_result, str):
                        # Parse function name from result like "Function: FUN_401000 at 401000"
                        import re

                        match = re.search(r"Function:\s*(\w+)", current_function_result)
                        if match:
                            function_name = match.group(1)

                    if not function_name:
                        self.response_panel.add_response(
                            "Error", "Could not extract function name from current function result"
                        )
                        return

                except Exception as e:
                    self.response_panel.add_response("Error", f"Error getting current function: {e}")
                    return

                # Step 2: Use AI agent to analyze the function and suggest a new name
                try:
                    self.workflow_diagram.set_current_stage("analysis")

                    # Create a detailed query for the AI agent to analyze and suggest rename
                    analysis_query = f"""Analyze the function '{function_name}' and provide a highly descriptive rename suggestion.

You MUST follow this EXACT format in your response:

**Function Analysis:**
[Provide comprehensive analysis: What does this function do? Identify specific operations like memory allocation, string manipulation, network operations, file I/O, cryptographic operations, data validation, etc. Examine parameters, return values, called functions, and code patterns. Look for domain-specific functionality.]

**Behavior Summary:**
[Write a precise 1-4 sentence summary describing the function's primary behavior, data flow, and purpose in the program architecture]

**Suggested Name:** [descriptiveSpecificFunctionName]
**Rationale:** [Explain in detail why this name accurately captures the function's specific purpose and distinguishes it from other functions]

ENHANCED NAMING REQUIREMENTS:
- Be HIGHLY SPECIFIC about the operation (e.g., "parseHttpHeaders" not "parseData", "validateEmailFormat" not "validateInput")
- Include data type/domain context (e.g., "processNetworkPacket", "decryptUserCredentials", "compressImageBuffer")
- Use action verbs that describe the EXACT operation: parse, validate, encrypt, decrypt, compress, decompress, serialize, deserialize, allocate, deallocate, transform, convert, extract, insert, remove, update, calculate, generate, verify, authenticate, etc.
- Use precise nouns: Buffer, Packet, Header, Payload, Token, Credential, Session, Connection, Registry, Configuration, Certificate, Signature, etc.
- Be domain-aware: If it's crypto operations use crypto terms, if it's network use network terms, if it's file system use file terms
- Use camelCase format
- Length: 2-5 words (prioritize clarity over brevity)
- Avoid generic terms: process, handle, manage, data, function, method, routine, etc.

EXAMPLES of good names:
- parseJsonConfiguration (not parseData)
- validateTlsCertificate (not validateInput)
- encryptAesPayload (not encryptData)
- allocateMemoryBuffer (not allocateMemory)
- extractRegistryKeys (not extractData)
- calculateChecksumValue (not calculateValue)

CRITICAL: You MUST include all four sections with the exact headers shown above. Focus on making the suggested name as specific and descriptive as possible."""

                    # Use direct ollama.generate instead of bridge.process_query to avoid infinite loops
                    # This follows the same fix pattern as the "Analyze Current Function" tool
                    ai_response = self.bridge.ollama.generate(prompt=analysis_query)

                    if ai_response and ai_response.strip():
                        self.response_panel.add_response("Step 2: AI Analysis & Name Suggestion", ai_response)

                        # USE THE ENTIRE AI RESPONSE as the behavior summary
                        function_summary = ai_response.strip()
                        self.response_panel.add_response(
                            "Debug", f"📝 Using full AI response as behavior summary (length: {len(function_summary)} chars)"
                        )

                        # Extract suggested name from AI response
                        suggested_name = None

                        # Split AI response into lines for parsing
                        lines = ai_response.split("\n")

                        # First, look for the "Suggested Name:" pattern
                        for line in lines:
                            line = line.strip()
                            if "Suggested Name:" in line:
                                # Extract everything after "Suggested Name:"
                                name_part = line.split("Suggested Name:", 1)[1].strip()
                                # Remove any markdown formatting
                                name_part = name_part.replace("**", "").replace("*", "").strip()
                                # Extract the actual function name (should be camelCase/snake_case)
                                import re

                                name_match = re.search(r"\b([a-z][a-zA-Z0-9_]*[a-zA-Z0-9]|[a-z][a-zA-Z0-9]*)\b", name_part)
                                if name_match:
                                    suggested_name = name_match.group(1)
                                    break

                        # Fallback: look for patterns in the response that might indicate function names
                        if not suggested_name:
                            # Look for camelCase patterns in the response
                            import re

                            # First, try to find words that look like function names (camelCase with at least one capital)
                            camel_case_matches = re.findall(r"\b([a-z][a-zA-Z0-9]*[A-Z][a-zA-Z0-9]*)\b", ai_response)

                            # Filter out common words
                            excluded_words = {
                                "function",
                                "name",
                                "suggest",
                                "analysis",
                                "code",
                                "parameter",
                                "value",
                                "data",
                                "result",
                                "return",
                                "call",
                                "method",
                                "functionName",
                                "newFunctionName",
                                "descriptiveFunctionName",
                            }

                            for match in camel_case_matches:
                                if (
                                    len(match) > 4
                                    and match.lower() not in excluded_words
                                    and not match.startswith("FUN_")
                                    and not any(word in match.lower() for word in ["function", "name", "example"])
                                ):
                                    suggested_name = match
                                    break

                            # If still no match, look for any reasonable identifier
                            if not suggested_name:
                                simple_matches = re.findall(r"\b([a-z][a-zA-Z0-9_]*)\b", ai_response)
                                for match in simple_matches:
                                    if (
                                        len(match) > 6
                                        and match.lower() not in excluded_words
                                        and not match.startswith("FUN_")
                                        and not any(
                                            word in match.lower()
                                            for word in ["function", "name", "example", "analysis", "response"]
                                        )
                                    ):
                                        suggested_name = match
                                        break

                        if suggested_name:
                            self.response_panel.add_response("Step 3a: Extracted Suggested Name", suggested_name)

                            # Step 3: Perform the actual rename using bridge.execute_command to ensure state tracking
                            try:
                                rename_result = self.bridge.execute_command(
                                    "rename_function", {"old_name": function_name, "new_name": suggested_name}
                                )
                                # rename_result is already the result string, not a dict

                                # STORE the captured summary for this function
                                if function_summary and hasattr(self.bridge, "function_summaries"):
                                    # Get the function address to use as identifier
                                    current_function_result = self.bridge.ghidra.get_current_function()
                                    if isinstance(current_function_result, str) and "at " in current_function_result:
                                        import re

                                        match = re.search(r"at\s+([0-9a-fA-F]+)", current_function_result)
                                        if match:
                                            address = match.group(1)
                                            self.bridge.function_summaries[address] = function_summary

                                            # Add to RAG and show the results with visual feedback
                                            old_vector_count = 0
                                            if (
                                                hasattr(self.bridge, "cag_manager")
                                                and self.bridge.cag_manager
                                                and hasattr(self.bridge.cag_manager, "vector_store")
                                                and self.bridge.cag_manager.vector_store
                                            ):
                                                old_vector_count = len(self.bridge.cag_manager.vector_store.documents)

                                            # Show RAG vector creation status
                                            self.workflow_diagram.set_rag_progress(0, 1, active=True)
                                            self.response_panel.add_response(
                                                "Step 3c: RAG Integration", "Adding function analysis to RAG vector space..."
                                            )

                                            # RAG integration removed - use "Load Vectors" button for vector operations
                                            # self.bridge._add_function_to_rag(address, function_summary)

                                            # Update progress and complete
                                            self.workflow_diagram.set_rag_progress(1, 1, active=True)
                                            import time

                                            time.sleep(0.2)  # Brief pause to show completion
                                            self.workflow_diagram.complete_rag_stage()

                                            new_vector_count = 0
                                            if (
                                                hasattr(self.bridge, "cag_manager")
                                                and self.bridge.cag_manager
                                                and hasattr(self.bridge.cag_manager, "vector_store")
                                                and self.bridge.cag_manager.vector_store
                                            ):
                                                new_vector_count = len(self.bridge.cag_manager.vector_store.documents)

                                            self.response_panel.add_response(
                                                "Step 3d: Summary & RAG Complete",
                                                f"📝 Function summary captured and added to RAG\n"
                                                f"📊 Vector count: {old_vector_count} -> {new_vector_count}\n"
                                                f"📄 Summary length: {len(function_summary)} characters\n"
                                                f"🔍 Preview: {function_summary[:150]}...",
                                            )
                                else:
                                    self.response_panel.add_response(
                                        "Debug",
                                        f"⚠️ No function summary extracted from AI response. Summary found: {function_summary is not None}",
                                    )

                            except Exception as e:
                                rename_result = f"Error: {str(e)}"

                            if isinstance(rename_result, str) and rename_result.lower().startswith("error:"):
                                self.response_panel.add_response("Error", f"Failed to rename function: {rename_result}")
                            else:
                                self.response_panel.add_response(
                                    "Step 3b: Rename Result", f"Successfully renamed '{function_name}' to '{suggested_name}'"
                                )
                                self.response_panel.add_response(
                                    "Success",
                                    f"✅ Rename workflow completed! Function '{function_name}' is now '{suggested_name}'",
                                )

                                # Add to UI renamed functions panel if available
                                if self.renamed_functions_panel and function_summary:
                                    try:
                                        # Get the address from current function result
                                        current_function_result = self.bridge.ghidra.get_current_function()
                                        address = "Unknown"
                                        if isinstance(current_function_result, str) and "at " in current_function_result:
                                            import re

                                            match = re.search(r"at\s+([0-9a-fA-F]+)", current_function_result)
                                            if match:
                                                address = match.group(1)

                                        self.renamed_functions_panel.add_function_with_summary(
                                            address=address,
                                            old_name=function_name,
                                            new_name=suggested_name,
                                            summary=function_summary,
                                        )
                                    except Exception as e:
                                        self.response_panel.add_response(
                                            "UI Warning", f"Could not update renamed functions panel: {e}"
                                        )
                        else:
                            self.response_panel.add_response(
                                "Debug",
                                f"⚠️ Could not extract function name from AI response. Response contained: {ai_response[:200]}...",
                            )
                            self.response_panel.add_response(
                                "Error",
                                "Could not extract a valid function name from AI response. Please try again or rename manually.",
                            )
                    else:
                        self.response_panel.add_response("Error", "AI agent returned empty response for analysis")

                except Exception as e:
                    self.response_panel.add_response("Error", f"Error during AI analysis step: {e}")
                    return

                # Final stage update
                self.workflow_diagram.set_current_stage(None)

            except Exception as e:
                error_msg = f"Error running {display_name}: {e}"
                logger.error(error_msg)
                self.response_panel.add_response("Error", error_msg)
                self.workflow_diagram.set_current_stage(None)
            finally:
                self._set_tool_running(False)

        threading.Thread(target=worker, daemon=True).start()

    def _process_single_function_for_bulk_rename(self, function_index, full_function_string, enumeration_mode, total_functions):
        """
        Process a single function for bulk rename (designed for parallel execution).

        Returns:
            dict with keys: 'success', 'result_type', 'function_data', 'error_msg'
        """
        import time

        result = {
            "success": False,
            "result_type": None,  # 'renamed', 'enumerated', 'skipped', 'failed'
            "function_data": None,
            "error_msg": None,
            "function_name": None,
            "address": None,
            "suggested_name": None,
            "summary": None,
        }

        try:
            # Extract function name and address
            if " at " in full_function_string:
                function_name = full_function_string.split(" at ")[0].strip()
                address = full_function_string.split(" at ")[1].strip()
            else:
                function_name = full_function_string.strip()
                name_address_match = re.search(r"([0-9a-fA-F]{8,})", function_name)
                address = name_address_match.group(1) if name_address_match else function_name

            result["function_name"] = function_name
            result["address"] = address

            # Determine if should process based on enumeration mode
            is_generic_name = function_name.startswith(("FUN_", "sub_", "loc_", "unk_", "j_"))
            should_process = False

            if enumeration_mode == "rename_only":
                should_process = is_generic_name
                if not should_process:
                    result["result_type"] = "skipped"
                    result["success"] = True
                    return result
            elif enumeration_mode == "full_enumeration":
                should_process = True
            elif enumeration_mode == "smart_enumeration":
                # ENHANCED SMART ENUMERATION FILTERS
                important_keywords = [
                    "main",
                    "init",
                    "crypto",
                    "encrypt",
                    "decrypt",
                    "hash",
                    "key",
                    "auth",
                    "login",
                    "password",
                    "network",
                    "socket",
                    "http",
                    "tcp",
                    "udp",
                    "file",
                    "read",
                    "write",
                    "open",
                    "close",
                    "connect",
                    "send",
                    "recv",
                    "malloc",
                    "free",
                    "alloc",
                    "buffer",
                    "parse",
                    "validate",
                    "check",
                    "verify",
                    "process",
                    "handle",
                    "execute",
                    "run",
                    "start",
                    "stop",
                    "config",
                    "setting",
                    "registry",
                    "service",
                    "thread",
                    "mutex",
                    "lock",
                    "sync",
                    "async",
                ]

                function_lower = function_name.lower()

                # FILTER 1: Skip thunk functions and wrappers
                skip_patterns = ["thunk", "stub", "wrapper"]
                if any(pattern in function_lower for pattern in skip_patterns):
                    result["result_type"] = "skipped"
                    result["success"] = True
                    return result

                # FILTER 2: Skip import/export wrappers
                if (
                    function_name.startswith("__imp_")
                    or function_name.startswith("__exp_")
                    or function_name.startswith("_imp_")
                ):
                    result["result_type"] = "skipped"
                    result["success"] = True
                    return result

                # FILTER 3: Skip simple accessor functions (get/set/is with short names)
                accessor_prefixes = ["get", "set", "is"]
                if any(function_lower.startswith(prefix) for prefix in accessor_prefixes) and len(function_name) < 15:
                    result["result_type"] = "skipped"
                    result["success"] = True
                    return result

                # FILTER 4: Skip C runtime library and standard library functions
                crt_patterns = ["_crt_", "__cxx_", "__std_", "__cxa_", "__gnu_", "__gxx_", "_runtim"]
                if any(pattern in function_lower for pattern in crt_patterns):
                    result["result_type"] = "skipped"
                    result["success"] = True
                    return result

                # FILTER 5: Check if function should be processed based on importance
                if is_generic_name:
                    # Always process generic names (FUN_*, sub_*, etc.)
                    should_process = True
                else:
                    # For renamed functions, check if they contain important keywords
                    should_process = any(keyword in function_lower for keyword in important_keywords)

                if not should_process:
                    result["result_type"] = "skipped"
                    result["success"] = True
                    return result

            # STEP 1: Decompile function. Use address-based decompilation so
            # this works reliably across backends (HTTP MCP and pyGhidra)
            # regardless of how auto-generated names are formatted.
            try:
                function_decompile_result = self.bridge.ghidra.decompile_function_by_address(address=address)
                if isinstance(function_decompile_result, str) and function_decompile_result.lower().startswith("error:"):
                    result["error_msg"] = f"Failed to decompile: {function_decompile_result}"
                    result["result_type"] = "failed"
                    return result

                # SMART ENUMERATION FILTER: Check decompiled code complexity
                # Skip trivial functions with very small code bodies
                if enumeration_mode == "smart_enumeration" and function_decompile_result:
                    # Count actual code lines (excluding braces, empty lines, simple returns)
                    code_lines = [
                        line.strip()
                        for line in function_decompile_result.split("\n")
                        if line.strip() and line.strip() not in ["{", "}", ""] and not line.strip().startswith("//")
                    ]

                    # Functions with <= 3 lines of actual code are typically trivial
                    # Examples: simple getters, setters, wrappers, return statements
                    if len(code_lines) <= 3:
                        result["result_type"] = "skipped"
                        result["success"] = True
                        return result

                    # Additional check: very short total code (< 50 chars) is likely trivial
                    if len(function_decompile_result.strip()) < 50:
                        result["result_type"] = "skipped"
                        result["success"] = True
                        return result

            except Exception as e:
                result["error_msg"] = f"Error decompiling: {e}"
                result["result_type"] = "failed"
                return result

            # STEP 1.5: Gather context
            try:
                context = self._gather_function_context(function_name, address, max_chars=8000)
            except Exception:
                context = {"callers_code": [], "callees_code": [], "truncated": False}

            # STEP 2: AI Analysis (with retry logic for LLM failures)
            max_retries = 2
            retry_count = 0
            ai_response = None

            while retry_count <= max_retries and not ai_response:
                contextual_info = self._format_context_for_prompt(context)
                analysis_query = f"""Analyze the function '{function_name}' and provide a highly descriptive rename suggestion.

## TARGET FUNCTION: {function_name}
```c
{function_decompile_result}
```
{contextual_info}

Based on the target function's code AND the contextual information about its callers and callees above, analyze the function thoroughly and provide a highly descriptive rename suggestion.

You MUST follow this EXACT format in your response:

**Function Analysis:**
[Provide comprehensive analysis: What does this function do? Identify specific operations like memory allocation, string manipulation, network operations, file I/O, cryptographic operations, data validation, etc. Examine parameters, return values, called functions, and code patterns. Look for domain-specific functionality.]

**Behavior Summary:**
[Write a precise 1-4 sentence summary describing the function's primary behavior, data flow, and purpose in the program architecture]

**Suggested Name:** [descriptiveSpecificFunctionName]
**Rationale:** [Explain in detail why this name accurately captures the function's specific purpose and distinguishes it from other functions]

ENHANCED NAMING REQUIREMENTS:
- Be HIGHLY SPECIFIC about the operation (e.g., "parseHttpHeaders" not "parseData", "validateEmailFormat" not "validateInput")
- Include data type/domain context (e.g., "processNetworkPacket", "decryptUserCredentials", "compressImageBuffer")
- Use action verbs that describe the EXACT operation: parse, validate, encrypt, decrypt, compress, decompress, serialize, deserialize, allocate, deallocate, transform, convert, extract, insert, remove, update, calculate, generate, verify, authenticate, etc.
- Use precise nouns: Buffer, Packet, Header, Payload, Token, Credential, Session, Connection, Registry, Configuration, Certificate, Signature, etc.
- Be domain-aware: If it's crypto operations use crypto terms, if it's network use network terms, if it's file system use file terms
- Use camelCase format
- Length: 2-5 words (prioritize clarity over brevity)
- Avoid generic terms: process, handle, manage, data, function, method, routine, etc.

EXAMPLES of good names:
- parseJsonConfiguration (not parseData)
- validateTlsCertificate (not validateInput)
- encryptAesPayload (not encryptData)
- allocateMemoryBuffer (not allocateMemory)
- extractRegistryKeys (not extractData)
- calculateChecksumValue (not calculateValue)

CRITICAL: You MUST include all four sections with the exact headers shown above. Focus on making the suggested name as specific and descriptive as possible."""

                ai_response = self.bridge.ollama.generate(prompt=analysis_query)

                if ai_response and ai_response.strip():
                    function_summary = ai_response.strip()
                    result["summary"] = function_summary

                    # Extract suggested name
                    suggested_name = None
                    lines = ai_response.split("\n")

                    for line in lines:
                        line = line.strip()
                        if "Suggested Name:" in line:
                            name_part = line.split("Suggested Name:", 1)[1].strip()
                            name_part = name_part.replace("**", "").replace("*", "").strip()
                            name_match = re.search(r"\b([a-z][a-zA-Z0-9_]*[a-zA-Z0-9]|[a-z][a-zA-Z0-9]*)\b", name_part)
                            if name_match:
                                suggested_name = name_match.group(1)
                                break

                    # Fallback extraction
                    if not suggested_name:
                        camel_case_matches = re.findall(r"\b([a-z][a-zA-Z0-9]*[A-Z][a-zA-Z0-9]*)\b", ai_response)
                        excluded_words = {
                            "function",
                            "name",
                            "suggest",
                            "analysis",
                            "code",
                            "parameter",
                            "value",
                            "data",
                            "result",
                            "return",
                            "call",
                            "method",
                            "functionName",
                            "newFunctionName",
                            "descriptiveFunctionName",
                        }

                        for match in camel_case_matches:
                            if (
                                len(match) > 4
                                and match.lower() not in excluded_words
                                and not match.startswith("FUN_")
                                and not any(word in match.lower() for word in ["function", "name", "example"])
                            ):
                                suggested_name = match
                                break

                        if not suggested_name:
                            simple_matches = re.findall(r"\b([a-z][a-zA-Z0-9_]*)\b", ai_response)
                            for match in simple_matches:
                                if (
                                    len(match) > 6
                                    and match.lower() not in excluded_words
                                    and not match.startswith("FUN_")
                                    and not any(
                                        word in match.lower()
                                        for word in ["function", "name", "example", "analysis", "response"]
                                    )
                                ):
                                    suggested_name = match
                                    break

                    # Handle enumeration vs renaming
                    # FIXED: Process renamed functions correctly in enumeration modes
                    if enumeration_mode in ["full_enumeration", "smart_enumeration"]:
                        # In enumeration modes, always process functions (generic or renamed)
                        if not is_generic_name:
                            # Already renamed function - just enumerate it
                            suggested_name = function_name
                            result["result_type"] = "enumerated"
                        elif suggested_name and is_generic_name:
                            # Generic function with AI-suggested name - rename it
                            try:
                                rename_result = self.bridge.execute_command(
                                    "rename_function", {"old_name": function_name, "new_name": suggested_name}
                                )
                                if isinstance(rename_result, str) and rename_result.lower().startswith("error:"):
                                    result["error_msg"] = f"Rename failed: {rename_result}"
                                    result["result_type"] = "failed"
                                    return result
                                result["result_type"] = "renamed"
                            except Exception as e:
                                result["error_msg"] = f"Exception during rename: {e}"
                                result["result_type"] = "failed"
                                return result
                        else:
                            # Generic function but AI didn't provide a name - still enumerate it
                            suggested_name = function_name
                            result["result_type"] = "enumerated"
                    else:
                        # rename_only mode - only process generic names
                        if suggested_name and is_generic_name:
                            # Perform rename
                            try:
                                rename_result = self.bridge.execute_command(
                                    "rename_function", {"old_name": function_name, "new_name": suggested_name}
                                )
                                if isinstance(rename_result, str) and rename_result.lower().startswith("error:"):
                                    result["error_msg"] = f"Rename failed: {rename_result}"
                                    result["result_type"] = "failed"
                                    return result
                                result["result_type"] = "renamed"
                            except Exception as e:
                                result["error_msg"] = f"Exception during rename: {e}"
                                result["result_type"] = "failed"
                                return result
                        else:
                            result["error_msg"] = "Could not extract function name from AI response"
                            result["result_type"] = "failed"
                            return result

                    result["suggested_name"] = suggested_name

                    # ============ ENHANCED METADATA EXTRACTION ============
                    # Extract structured metadata from decompiled code
                    try:
                        from src.function_metadata_extractor import FunctionMetadataExtractor

                        metadata_extractor = FunctionMetadataExtractor()

                        # Extract all metadata
                        metadata = metadata_extractor.extract_all_metadata(
                            function_decompile_result, suggested_name if suggested_name else function_name, context
                        )

                        # Parse AI response into structured sections
                        structured_summary = self._parse_ai_response_sections(ai_response)

                    except Exception as meta_error:
                        logger.warning(f"Metadata extraction failed: {meta_error}")
                        # Fallback to minimal metadata
                        metadata = {
                            "metrics": {},
                            "categories": {},
                            "signature": {},
                            "patterns": [],
                            "security": {},
                            "data_flow": {},
                            "dependencies": {},
                        }
                        structured_summary = {"raw": function_summary}

                    # Build enhanced function data
                    result["function_data"] = {
                        # Core Identity
                        "address": address,
                        "old_name": function_name,
                        "new_name": suggested_name if suggested_name else function_name,
                        # Enhanced Metadata (NEW)
                        "metrics": metadata.get("metrics", {}),
                        "categories": metadata.get("categories", {}),
                        "signature": metadata.get("signature", {}),
                        "patterns": metadata.get("patterns", []),
                        "security": metadata.get("security", {}),
                        "data_flow": metadata.get("data_flow", {}),
                        "dependencies": metadata.get("dependencies", {}),
                        # Structured Summary (NEW)
                        "summary": structured_summary,
                        # Legacy raw summary (for backward compat)
                        "raw_summary": function_summary,
                        "timestamp": time.time(),
                    }

                    # Store in bridge (both formats for compatibility)
                    # THREAD SAFETY: Acquire lock before writing to shared dictionaries
                    if self.renamed_functions_panel and hasattr(self.renamed_functions_panel, "dict_lock"):
                        with self.renamed_functions_panel.dict_lock:
                            if function_summary and hasattr(self.bridge, "function_summaries"):
                                self.bridge.function_summaries[address] = function_summary

                            # Store enhanced metadata in address mapping
                            if hasattr(self.bridge, "function_address_mapping"):
                                self.bridge.function_address_mapping[address] = result["function_data"]
                    else:
                        # Fallback if no lock available (shouldn't happen)
                        if function_summary and hasattr(self.bridge, "function_summaries"):
                            self.bridge.function_summaries[address] = function_summary

                        if hasattr(self.bridge, "function_address_mapping"):
                            self.bridge.function_address_mapping[address] = result["function_data"]

                    result["success"] = True
                    return result
                else:
                    # Empty response - retry if attempts remaining
                    retry_count += 1
                    if retry_count <= max_retries:
                        logger.warning(f"Empty AI response for {function_name}, retry {retry_count}/{max_retries}")
                        import time

                        time.sleep(1)  # Brief delay before retry
                    else:
                        result["error_msg"] = "AI returned empty response after retries"
                        result["result_type"] = "failed"
                        return result

            # If we get here, all retries failed
            result["error_msg"] = "All retry attempts failed"
            result["result_type"] = "failed"
            return result

        except Exception as e:
            result["error_msg"] = f"Exception processing function: {e}"
            result["result_type"] = "failed"
            return result

    def _create_batch_rag_vectors(self, processed_functions_data):
        """Create RAG vectors in batches for processed functions with visual progress feedback."""
        if not processed_functions_data:
            return 0

        total_functions = len(processed_functions_data)
        self.response_panel.add_response(
            "🔄 RAG Processing", f"Creating RAG vectors for {total_functions} processed functions..."
        )

        # Initialize RAG progress in workflow diagram
        self.workflow_diagram.set_rag_progress(0, total_functions, active=True)

        # Batch create RAG vectors for all processed functions
        rag_success_count = 0
        rag_batch_size = 25  # Process RAG vectors in smaller batches

        for batch_start in range(0, total_functions, rag_batch_size):
            batch_end = min(batch_start + rag_batch_size, total_functions)
            batch = processed_functions_data[batch_start:batch_end]

            self.response_panel.add_response(
                "📊 RAG Batch", f"Processing RAG vectors {batch_start + 1}-{batch_end} of {total_functions}"
            )

            for i, func_data in enumerate(batch):
                try:
                    # RAG integration removed - use "Load Vectors" button for vector operations
                    # if hasattr(self.bridge, '_add_function_to_rag'):
                    #     self.bridge._add_function_to_rag(
                    #         func_data['address'],
                    #         func_data['summary']
                    #     )
                    rag_success_count += 1

                    # Update progress bar for each vector created
                    current_progress = batch_start + i + 1
                    self.workflow_diagram.set_rag_progress(current_progress, total_functions, active=True)

                    # Small delay to make progress visible (can be removed for production)
                    import time

                    time.sleep(0.01)  # 10ms delay for visual feedback

                except Exception as e:
                    logger.warning(f"Could not add function {func_data['old_name']} to RAG: {e}")

            # Check for stop signal during RAG processing
            if hasattr(self, "should_stop") and self.should_stop:
                self.response_panel.add_response(
                    "🛑 RAG Cancelled", f"RAG vector creation stopped by user. Created {rag_success_count} vectors."
                )
                # Still mark RAG stage as complete even if cancelled
                self.workflow_diagram.complete_rag_stage()
                return rag_success_count

        # Mark RAG creation as complete
        self.workflow_diagram.complete_rag_stage()
        self.response_panel.add_response(
            "✅ RAG Complete", f"Successfully created {rag_success_count}/{total_functions} RAG vectors"
        )

        # Update memory panel to reflect new vector count
        if hasattr(self, "renamed_functions_panel") and hasattr(self.renamed_functions_panel, "bridge"):
            try:
                # Trigger memory panel refresh to show updated vector count
                if hasattr(self.renamed_functions_panel.bridge, "_ui_memory_panel_refresh"):
                    self.renamed_functions_panel.bridge._ui_memory_panel_refresh()
            except Exception as e:
                logger.debug(f"Could not refresh memory panel: {e}")

        return rag_success_count

    def _decompile_function_cached(self, address: str) -> str:
        """
        Decompile a function by address with LRU caching.

        This dramatically reduces redundant Ghidra calls when the same function
        is referenced as a caller/callee by multiple functions.

        Args:
            address: Function address to decompile

        Returns:
            Decompiled code string or error message
        """
        # Normalize address format (remove 0x prefix if present, convert to uppercase)
        normalized_addr = address.replace("0x", "").replace("0X", "").upper()

        # Check cache first
        if normalized_addr in self._decompilation_cache:
            self._cache_hits += 1
            return self._decompilation_cache[normalized_addr]

        # Cache miss - fetch from Ghidra
        self._cache_misses += 1
        try:
            code = self.bridge.ghidra.decompile_function_by_address(address=str(address))

            # Only cache successful results (not errors)
            if code and not code.lower().startswith("error"):
                # Implement LRU eviction if cache is full
                if len(self._decompilation_cache) >= self._cache_max_size:
                    # Remove oldest entry (simple FIFO for now, true LRU would need OrderedDict)
                    oldest_key = next(iter(self._decompilation_cache))
                    del self._decompilation_cache[oldest_key]

                self._decompilation_cache[normalized_addr] = code

            return code
        except Exception as e:
            return f"Error: {e}"

    def _get_cache_stats(self) -> dict:
        """Get decompilation cache statistics."""
        total_requests = self._cache_hits + self._cache_misses
        hit_rate = (self._cache_hits / total_requests * 100) if total_requests > 0 else 0

        return {
            "hits": self._cache_hits,
            "misses": self._cache_misses,
            "total_requests": total_requests,
            "hit_rate_pct": hit_rate,
            "cache_size": len(self._decompilation_cache),
            "max_size": self._cache_max_size,
        }

    def _clear_decompilation_cache(self):
        """Clear the decompilation cache and reset statistics."""
        self._decompilation_cache.clear()
        self._cache_hits = 0
        self._cache_misses = 0

    def _gather_function_context(self, function_name: str, address: str, max_chars: int = 8000) -> dict:
        """
        Gather contextual information about a function (callers and callees).

        Args:
            function_name: Name of the function
            address: Address of the function
            max_chars: Maximum total characters for context (truncate if exceeded)

        Returns:
            dict with keys: 'callers', 'callees', 'callers_code', 'callees_code', 'truncated'
        """
        context = {"callers": [], "callees": [], "callers_code": [], "callees_code": [], "truncated": False, "total_chars": 0}

        try:
            # Get callers (who calls this function?)
            try:
                callers_result = self.bridge.ghidra.get_xrefs_to(address=address)
                if isinstance(callers_result, list) and callers_result:
                    # Handle both dict format (JSON) and string format (text)
                    caller_addresses = []
                    for c in callers_result[:5]:  # Limit to 5 callers
                        if isinstance(c, dict):
                            # JSON format: extract from dictionary
                            addr = c.get("from_address") or c.get("from") or c.get("fromAddress")
                            if addr:
                                caller_addresses.append(addr)
                        elif isinstance(c, str):
                            # Text format: parse string like "FROM: 0x401000" or "0x401000"
                            import re

                            # Try to extract hex address from string
                            match = re.search(r"(?:from[:\s]+)?([0-9a-fA-F]{6,})", c, re.IGNORECASE)
                            if match:
                                caller_addresses.append(match.group(1))

                    context["callers"] = caller_addresses

                    # Try to get function names for caller addresses
                    for caller_addr in context["callers"][:3]:  # Only decompile top 3 callers
                        try:
                            # USE CACHE: This dramatically reduces redundant Ghidra calls
                            caller_code = self._decompile_function_cached(address=str(caller_addr))
                            if caller_code and not caller_code.lower().startswith("error"):
                                # Truncate individual caller code to 1000 chars
                                if len(caller_code) > 1000:
                                    caller_code = caller_code[:1000] + "...[truncated]"
                                context["callers_code"].append({"address": caller_addr, "code": caller_code})
                        except Exception as e:
                            logger.warning(f"Failed to decompile the caller {caller_addr}: {e}")
                            pass  # Skip if can't decompile caller
            except Exception as e:
                logger.warning(f"Failed to get the callers to function {function_name} at {address}: {e}")
                pass  # Skip if can't get callers

            # Get callees (what does this function call?)
            try:
                callees_result = self.bridge.ghidra.get_xrefs_from(address=address)
                if isinstance(callees_result, list) and callees_result:
                    # Handle both dict format (JSON) and string format (text)
                    callee_addresses = []
                    for c in callees_result[:5]:  # Limit to 5 callees
                        if isinstance(c, dict):
                            # JSON format: extract from dictionary
                            addr = c.get("to_address") or c.get("to") or c.get("toAddress")
                            if addr:
                                callee_addresses.append(addr)
                        elif isinstance(c, str):
                            # Text format: parse string like "TO: 0x401000" or "0x401000"
                            import re

                            # Try to extract hex address from string
                            match = re.search(r"(?:to[:\s]+)?([0-9a-fA-F]{6,})", c, re.IGNORECASE)
                            if match:
                                callee_addresses.append(match.group(1))

                    context["callees"] = callee_addresses

                    # Try to get function names for callee addresses
                    for callee_addr in context["callees"][:3]:  # Only decompile top 3 callees
                        try:
                            # USE CACHE: This dramatically reduces redundant Ghidra calls
                            callee_code = self._decompile_function_cached(address=str(callee_addr))
                            if callee_code and not callee_code.lower().startswith("error"):
                                # Truncate individual callee code to 1000 chars
                                if len(callee_code) > 1000:
                                    callee_code = callee_code[:1000] + "...[truncated]"
                                context["callees_code"].append({"address": callee_addr, "code": callee_code})
                        except Exception as e:
                            logger.warning(f"Failed to decompile the callee {callee_addr}: {e}")
                            pass  # Skip if can't decompile callee
            except Exception as e:
                logger.warning(f"Failed to get the callee to function {function_name} at {address}: {e}")
                pass  # Skip if can't get callees

            # Calculate total context size
            total_chars = sum(len(c["code"]) for c in context["callers_code"])
            total_chars += sum(len(c["code"]) for c in context["callees_code"])
            context["total_chars"] = total_chars

            # If total context exceeds max, truncate intelligently
            if total_chars > max_chars:
                context["truncated"] = True
                # Keep fewer callees to prioritize callers (callers are usually more important for understanding usage)
                if len(context["callees_code"]) > 1:
                    context["callees_code"] = context["callees_code"][:1]
                if len(context["callers_code"]) > 2:
                    context["callers_code"] = context["callers_code"][:2]

                # Recalculate
                total_chars = sum(len(c["code"]) for c in context["callers_code"])
                total_chars += sum(len(c["code"]) for c in context["callees_code"])
                context["total_chars"] = total_chars

        except Exception:
            # If any error, return empty context
            pass

        return context

    def _format_context_for_prompt(self, context: dict) -> str:
        """Format gathered context into a prompt-friendly string."""
        if not context["callers"] and not context["callees"]:
            return ""

        sections = []

        # Add callers section
        if context["callers_code"]:
            sections.append("\n## CALLER FUNCTIONS (Functions that call this function):")
            for i, caller in enumerate(context["callers_code"], 1):
                sections.append(f"\n### Caller {i} at address {caller['address']}:")
                sections.append(f"```c\n{caller['code']}\n```")

        # Add callees section
        if context["callees_code"]:
            sections.append("\n## CALLEE FUNCTIONS (Functions called by this function):")
            for i, callee in enumerate(context["callees_code"], 1):
                sections.append(f"\n### Callee {i} at address {callee['address']}:")
                sections.append(f"```c\n{callee['code']}\n```")

        if context["truncated"]:
            sections.append("\n*Note: Context truncated to fit character limits. Showing most relevant callers/callees.*")

        return "\n".join(sections)

    def _parse_ai_response_sections(self, ai_response: str) -> Dict[str, Any]:
        """
        Parse AI response into structured sections.

        Args:
            ai_response: Raw AI response text

        Returns:
            Dict with parsed sections
        """
        sections = {
            "function_analysis": "",
            "behavior_summary": "",
            "suggested_name": "",
            "rationale": "",
            "key_operations": [],
            "raw": ai_response,  # Keep raw for backward compat
        }

        try:
            # Split by common section markers
            lines = ai_response.split("\n")
            current_section = None
            current_content = []

            for line in lines:
                line_stripped = line.strip()

                # Detect section headers
                if "Function Analysis:" in line or "**Function Analysis:**" in line:
                    if current_section and current_content:
                        sections[current_section] = "\n".join(current_content).strip()
                    current_section = "function_analysis"
                    current_content = []
                elif "Behavior Summary:" in line or "**Behavior Summary:**" in line:
                    if current_section and current_content:
                        sections[current_section] = "\n".join(current_content).strip()
                    current_section = "behavior_summary"
                    current_content = []
                elif "Suggested Name:" in line or "**Suggested Name:**" in line:
                    if current_section and current_content:
                        sections[current_section] = "\n".join(current_content).strip()
                    current_section = "suggested_name"
                    # Extract name directly
                    name_part = line.split(":", 1)[1] if ":" in line else ""
                    sections["suggested_name"] = name_part.strip().replace("**", "").replace("*", "")
                    current_section = None
                elif "Rationale:" in line or "**Rationale:**" in line:
                    if current_section and current_content:
                        sections[current_section] = "\n".join(current_content).strip()
                    current_section = "rationale"
                    current_content = []
                elif current_section:
                    # Add to current section
                    # Extract bullet points for key operations
                    if current_section == "function_analysis":
                        if line_stripped.startswith(("- ", "* ", "• ", "1.", "2.", "3.")):
                            clean_line = line_stripped.lstrip("-*•0123456789. ")
                            if clean_line:
                                sections["key_operations"].append(clean_line)
                    current_content.append(line)

            # Save final section
            if current_section and current_content:
                sections[current_section] = "\n".join(current_content).strip()

        except Exception as e:
            logger.warning(f"Error parsing AI response sections: {e}")

        return sections

    def _run_bulk_rename_workflow(self, display_name: str, enumeration_mode: str = "rename_only"):
        """Optimized bulk function analysis workflow with deferred RAG vector creation and batch processing."""

        def worker():
            import time

            try:
                self._set_tool_running(True, display_name)
                self.workflow_diagram.set_current_stage("planning")

                # THREAD SAFETY: Set flag to prevent auto-refresh during batch operations
                if self.renamed_functions_panel:
                    self.renamed_functions_panel.batch_operation_in_progress = True

                # Performance tracking
                start_time = time.time()
                processed_functions_data = []  # Store all processed functions for batch RAG creation
                batch_size = 50  # Process functions in batches for better performance

                # Add initial message to response panel
                self.response_panel.add_response(
                    f"🚀 Smart Tool: {display_name}", f"Starting OPTIMIZED bulk function analysis with mode: {enumeration_mode}"
                )
                self.response_panel.add_response(
                    "⚡ Performance Enhancements",
                    f"• Batch processing (size: {batch_size})\n• Deferred RAG vector creation\n• Optimized AI prompts\n• Enhanced progress tracking",
                )

                # Step 1: Get all functions (with pagination)
                try:
                    self.response_panel.add_response("📋 Step 1", "Retrieving list of all functions (paginated)...")

                    all_functions = []
                    offset = 0
                    limit = 200  # Request 200 functions per page

                    while True:
                        batch_result = self.bridge.ghidra.list_functions(offset=offset, limit=limit)

                        if isinstance(batch_result, str) and batch_result.lower().startswith("error:"):
                            self.response_panel.add_response(
                                "Error", f"Failed to get function list at offset {offset}: {batch_result}"
                            )
                            break

                        # Parse the batch
                        if isinstance(batch_result, list):
                            raw_batch = batch_result
                        elif isinstance(batch_result, str):
                            raw_batch = [f.strip() for f in batch_result.split("\n") if f.strip()]
                        else:
                            self.response_panel.add_response("Error", f"Unexpected function list format: {type(batch_result)}")
                            break

                        # IMPROVED: Check for pagination metadata BEFORE filtering
                        # Look for [Next: offset=X] to determine if more data exists
                        has_more_data = any("[Next:" in line for line in raw_batch if isinstance(line, str))

                        # Extract total count from metadata if available
                        # Format: [Total: 3000] [Showing: 1-200] [Next: offset=200, limit=200]
                        total_count = None
                        for line in raw_batch:
                            if isinstance(line, str) and "[Total:" in line:
                                import re

                                match = re.search(r"\[Total:\s*(\d+)\]", line)
                                if match:
                                    total_count = int(match.group(1))
                                    break

                        # Filter out pagination metadata lines
                        # Remove lines like [Total: 655], [Showing: 1-20], [Next: offset=20]
                        batch = [f for f in raw_batch if f and not f.startswith("[") and not f.lower().startswith("error")]

                        if not batch:
                            # No more functions - we've reached the end
                            break

                        # Add to our collection
                        all_functions.extend(batch)

                        # Update progress with better information
                        if total_count:
                            progress_msg = f"Found {len(all_functions)} of {total_count} functions..."
                        else:
                            progress_msg = f"Found {len(all_functions)} functions so far..."
                        self.response_panel.add_response("Step 1 Progress", progress_msg)

                        # IMPROVED: Use server metadata to determine if more data exists
                        # This is more reliable than checking batch size
                        if not has_more_data:
                            # Server indicates no more data available
                            break

                        # Move to next page - use the requested limit, not actual batch size
                        # The server handles the offset correctly even if some items were filtered
                        offset += limit

                    functions = all_functions

                    # Filter out any invalid function names
                    valid_functions = [f for f in functions if f and not f.lower().startswith("error")]

                    if not valid_functions:
                        self.response_panel.add_response("Warning", "No valid functions found to rename.")
                        return

                    total_functions = len(valid_functions)
                    self.response_panel.add_response("Step 1 Complete", f"Found {total_functions} functions to process")
                    # PARALLEL PROCESSING CONFIGURATION
                    max_workers = 5  # Process 5 functions concurrently (configurable)
                    self.response_panel.add_response(
                        "⚡ Parallel Processing",
                        f"Using {max_workers} concurrent workers for faster processing",
                    )

                    # Step 2: Process functions in parallel using a daemon-based
                    # ThreadPoolExecutor so worker threads don't block process
                    # exit when the UI is closed.

                    successful_renames = 0
                    failed_renames = 0
                    skipped_functions = 0
                    enumerated_functions = 0  # Functions analyzed but not renamed (for enumeration)
                    completed_count = 0  # Track completion for progress updates

                    # PARALLEL PROCESSING: Submit all functions to thread pool
                    with DaemonThreadPoolExecutor(max_workers=max_workers) as executor:
                        # Submit all functions for processing
                        future_to_function = {
                            executor.submit(
                                self._process_single_function_for_bulk_rename,
                                i,
                                full_function_string,
                                enumeration_mode,
                                total_functions,
                            ): (i, full_function_string)
                            for i, full_function_string in enumerate(valid_functions, 1)
                        }

                        # Process results as they complete
                        for future in as_completed(future_to_function):
                            # Check for stop signal
                            if self.should_stop:
                                self.response_panel.add_response("Cancelled", "🛑 Operation cancelled by user")
                                # Cancel remaining futures
                                for remaining_future in future_to_function:
                                    remaining_future.cancel()
                                # Still create RAG vectors for completed functions
                                if processed_functions_data:
                                    self.response_panel.add_response(
                                        "🔄 RAG Processing",
                                        f"Creating RAG vectors for {len(processed_functions_data)} processed functions before stopping...",
                                    )
                                    rag_count = self._create_batch_rag_vectors(processed_functions_data)
                                    self.response_panel.add_response(
                                        "✅ Stop Complete",
                                        f"Operation stopped. Successfully created {rag_count} RAG vectors from processed functions.",
                                    )
                                break

                            i, full_function_string = future_to_function[future]
                            completed_count += 1

                            try:
                                result = future.result()

                                # Handle result based on type
                                if result["result_type"] == "skipped":
                                    skipped_functions += 1
                                    if completed_count % 10 == 0:  # Batch UI updates
                                        self.response_panel.add_response(
                                            "Progress", f"Processed {completed_count}/{total_functions} functions"
                                        )

                                elif result["result_type"] == "failed":
                                    failed_renames += 1
                                    self.response_panel.add_response(
                                        "Error", f"❌ {result['function_name']}: {result['error_msg']}"
                                    )

                                elif result["result_type"] == "renamed":
                                    successful_renames += 1
                                    self.response_panel.add_response(
                                        "Success", f"✅ {result['function_name']} → {result['suggested_name']}"
                                    )

                                    # Add function data
                                    if result["function_data"]:
                                        processed_functions_data.append(result["function_data"])

                                    # Add to UI panel
                                    if self.renamed_functions_panel and result["function_data"]:
                                        try:
                                            self.renamed_functions_panel.add_function_with_summary(
                                                address=result["address"],
                                                old_name=result["function_name"],
                                                new_name=result["suggested_name"],
                                                summary=result["summary"],
                                            )
                                        except Exception as e:
                                            logger.warning(f"Could not update UI panel: {e}")

                                elif result["result_type"] == "enumerated":
                                    enumerated_functions += 1
                                    self.response_panel.add_response("Success", f"✅ {result['function_name']} (analyzed)")

                                    # Add function data
                                    if result["function_data"]:
                                        processed_functions_data.append(result["function_data"])

                                    # Add to UI panel
                                    if self.renamed_functions_panel and result["function_data"]:
                                        try:
                                            self.renamed_functions_panel.add_function_with_summary(
                                                address=result["address"],
                                                old_name=result["function_name"],
                                                new_name=result["suggested_name"],
                                                summary=result["summary"],
                                            )
                                        except Exception as e:
                                            logger.warning(f"Could not update UI panel: {e}")

                                # Periodic progress updates (every 10 functions)
                                if completed_count % 10 == 0:
                                    progress_pct = (completed_count / total_functions) * 100
                                    self.response_panel.add_response(
                                        "Progress",
                                        f"⚡ Parallel Progress: {completed_count}/{total_functions} ({progress_pct:.1f}%) | "
                                        + f"✅ {successful_renames + enumerated_functions} processed | "
                                        + f"❌ {failed_renames} failed | "
                                        + f"⏭️ {skipped_functions} skipped",
                                    )

                            except Exception as e:
                                failed_renames += 1
                                self.response_panel.add_response("Process Error", f"Exception processing function: {e}")

                    # BATCH RAG VECTOR CREATION (Performance Optimization)
                    self.workflow_diagram.set_current_stage("analysis")
                    if processed_functions_data:
                        self.response_panel.add_response(
                            "📊 Vector Creation", "Starting RAG vector creation for all processed functions..."
                        )
                        rag_count = self._create_batch_rag_vectors(processed_functions_data)
                        self.response_panel.add_response(
                            "✅ Vector Success", f"All {rag_count} function analyses have been added to the RAG vector space."
                        )

                    # Performance summary
                    total_time = time.time() - start_time
                    avg_time_per_function = total_time / max(1, (successful_renames + enumerated_functions))

                    # SKIP REASON SUMMARY
                    if skipped_functions > 0:
                        skip_reason_msg = "\n📊 **Functions Skipped Breakdown:**\n"
                        if enumeration_mode == "smart_enumeration":
                            skip_reason_msg += "Smart Enumeration filters applied:\n"
                            skip_reason_msg += "• Thunk/stub/wrapper functions\n"
                            skip_reason_msg += "• Import/export wrappers (__imp_, __exp_)\n"
                            skip_reason_msg += "• Simple getters/setters (< 15 chars)\n"
                            skip_reason_msg += "• C runtime library functions\n"
                            skip_reason_msg += "• Trivial code (≤ 3 lines)\n"
                            skip_reason_msg += "• Non-security-relevant renamed functions\n"
                            skip_reason_msg += f"\n💡 **Tip:** Use 'Enumerate All Functions' to process ALL {total_functions} functions without filtering."
                        elif enumeration_mode == "rename_only":
                            skip_reason_msg += "Rename-only mode: Only generic function names (FUN_*, sub_*) were processed.\n"
                            skip_reason_msg += (
                                f"💡 **Tip:** {skipped_functions} functions were already renamed and were skipped."
                            )
                        self.response_panel.add_response("⏭️ Skip Summary", skip_reason_msg)

                    # AUTOMATIC SESSION SAVE
                    session_save_success = False
                    try:
                        self.response_panel.add_response("💾 Auto-Save", "Automatically saving session...")

                        # Define operation type for session description
                        operation_type = {
                            "rename_only": "BULK RENAME",
                            "full_enumeration": "FULL ENUMERATION",
                            "smart_enumeration": "SMART ENUMERATION",
                        }.get(enumeration_mode, "BULK RENAME")

                        # Initialize session manager if not exists
                        if not hasattr(self, "session_manager"):
                            from src.enhanced_session_manager import EnhancedSessionManager

                            self.session_manager = EnhancedSessionManager()

                        # Collect analyzed functions from the renamed functions panel
                        analyzed_functions = {}
                        if self.renamed_functions_panel and hasattr(self.renamed_functions_panel, "functions"):
                            for addr, func_data in self.renamed_functions_panel.functions.items():
                                analyzed_functions[addr] = {
                                    "address": addr,
                                    "old_name": func_data.get("old_name", "Unknown"),
                                    "new_name": func_data.get("new_name", "Unknown"),
                                    "behavior_summary": func_data.get("summary", ""),
                                    "timestamp": func_data.get("timestamp", time.time()),
                                }

                        # Collect RAG vectors
                        rag_vectors = []
                        if hasattr(self.bridge, "cag_manager") and self.bridge.cag_manager:
                            if hasattr(self.bridge.cag_manager, "vector_store") and self.bridge.cag_manager.vector_store:
                                if hasattr(self.bridge.cag_manager.vector_store, "documents"):
                                    rag_vectors = self.bridge.cag_manager.vector_store.documents or []

                        # Save session with auto-generated name
                        auto_session_name = f"BulkRename_{enumeration_mode}_{int(time.time())}"

                        # Always create a new session for bulk operations (don't reuse old sessions)
                        # This ensures clean state and proper data persistence
                        self.session_manager.create_session(
                            session_name=auto_session_name,
                            binary_path=getattr(self.bridge, "current_binary_path", "Unknown"),
                            description=f"Auto-saved after {operation_type} operation",
                        )

                        # Save the session data
                        session_save_success = self.session_manager.save_current_session(
                            analyzed_functions=analyzed_functions,
                            rag_vectors=rag_vectors,
                            performance_stats={
                                "total_functions": total_functions,
                                "successful_renames": successful_renames,
                                "enumerated_functions": enumerated_functions,
                                "failed_renames": failed_renames,
                                "skipped_functions": skipped_functions,
                                "total_time": total_time,
                                "avg_time_per_function": avg_time_per_function,
                                "rag_vectors_count": len(processed_functions_data),
                                "enumeration_mode": enumeration_mode,
                                "save_timestamp": time.time(),
                            },
                        )

                        if session_save_success:
                            self.response_panel.add_response(
                                "✅ Auto-Save Complete",
                                f"Session automatically saved as '{auto_session_name}'\n"
                                + f"• {len(analyzed_functions)} analyzed functions\n"
                                + f"• {len(rag_vectors)} RAG vectors",
                            )
                        else:
                            self.response_panel.add_response(
                                "⚠️ Auto-Save Warning", "Session save attempted but may have failed. Check logs for details."
                            )

                    except Exception as save_error:
                        self.response_panel.add_response(
                            "⚠️ Auto-Save Error",
                            f"Could not automatically save session: {save_error}\n"
                            + "You can manually save via File > Save Session",
                        )
                        logger.error(f"Auto-save error: {save_error}")
                        import traceback

                        logger.error(traceback.format_exc())

                    # Get cache statistics
                    cache_stats = self._get_cache_stats()

                    # Final summary with performance metrics
                    summary_msg = f"""
🎉 {operation_type} OPERATION COMPLETE 🎉

📊 Summary:
• Total functions found: {total_functions}
• Successfully renamed: {successful_renames}
• Successfully enumerated: {enumerated_functions}
• Failed to process: {failed_renames}
• Skipped: {skipped_functions}

⚡ Performance:
• Total processing time: {total_time:.1f} seconds
• Average time per function: {avg_time_per_function:.2f} seconds
• RAG vectors created: {len(processed_functions_data)}
• Parallel workers: {max_workers}

💾 Decompilation Cache Stats:
• Cache hits: {cache_stats["hits"]} ({cache_stats["hit_rate_pct"]:.1f}% hit rate)
• Cache misses: {cache_stats["misses"]}
• Total requests: {cache_stats["total_requests"]}
• Ghidra calls saved: {cache_stats["hits"]}

🎯 Mode: {enumeration_mode.replace("_", " ").title()}
💾 Session Auto-Saved: {"✅ Yes" if session_save_success else "⚠️ Failed (save manually)"}

All processed functions have been added to the 'Analyzed Functions' tab with behavior summaries.
Check the tab to see detailed analysis results and manage function information.
"""
                    self.response_panel.add_response("🏁 Final Summary", summary_msg)

                    # Clear cache after operation completes
                    self._clear_decompilation_cache()

                except Exception as e:
                    error_msg = f"Error during bulk rename: {e}"
                    self.response_panel.add_response("Error", error_msg)
                    import traceback

                    self.response_panel.add_response("Error Details", traceback.format_exc())

                # Final stage update
                self.workflow_diagram.set_current_stage(None)

            except Exception as e:
                error_msg = f"Error running {display_name}: {e}"
                logger.error(error_msg)
                self.response_panel.add_response("Error", error_msg)
                self.workflow_diagram.set_current_stage(None)
            finally:
                self._set_tool_running(False)

        threading.Thread(target=worker, daemon=True).start()

    def _analyze_current_function(self):
        """Analyze the current function using hardcoded workflow."""
        if self.tool_running:
            return

        self._run_hardcoded_analyze_current_function("Analyze Current Function")

    def _run_hardcoded_analyze_current_function(self, display_name: str):
        """Run a hardcoded analyze current function workflow: get current function → decompile → AI analysis."""

        def worker():
            try:
                self._set_tool_running(True, display_name)
                self.workflow_diagram.set_current_stage("execution")

                # Add initial message to response panel
                self.response_panel.add_response(
                    f"Smart Tool: {display_name}",
                    "Starting 3-step analysis workflow: get current function → decompile → AI analysis",
                )

                # Step 1: Get current function
                try:
                    current_function_result = self.bridge.ghidra.get_current_function()
                    if isinstance(current_function_result, str) and current_function_result.lower().startswith("error:"):
                        self.response_panel.add_response("Error", f"Failed to get current function: {current_function_result}")
                        return

                    self.response_panel.add_response("Step 1: Current Function", str(current_function_result))

                    # Extract function name from the result
                    function_name = None
                    if isinstance(current_function_result, str):
                        # Parse function name from result like "Function: FUN_401000 at 401000"
                        import re

                        match = re.search(r"Function:\s*(\w+)", current_function_result)
                        if match:
                            function_name = match.group(1)

                    if not function_name:
                        self.response_panel.add_response(
                            "Error", "Could not extract function name from current function result"
                        )
                        return

                except Exception as e:
                    self.response_panel.add_response("Error", f"Error getting current function: {e}")
                    return

                # Step 2: Decompile the function to get its code
                try:
                    decompile_result = self.bridge.ghidra.decompile_function(name=function_name)
                    if isinstance(decompile_result, str) and decompile_result.lower().startswith("error:"):
                        self.response_panel.add_response(
                            "Error", f"Failed to decompile function {function_name}: {decompile_result}"
                        )
                        return

                    self.response_panel.add_response(
                        "Step 2: Function Decompilation",
                        f"Successfully decompiled {function_name} (length: {len(decompile_result)} chars)",
                    )

                except Exception as e:
                    self.response_panel.add_response("Error", f"Error decompiling function {function_name}: {e}")
                    return

                # Step 3: AI Analysis of the function
                try:
                    self.workflow_diagram.set_current_stage("analysis")

                    # Build analysis prompt with function info first
                    analysis_prompt = (
                        f"Analyze the function '{function_name}' and provide comprehensive insights.\n\n"
                        f"FUNCTION INFORMATION:\n"
                        f"Function Name: {function_name}\n"
                        f"Decompiled Code:\n{decompile_result}\n"
                    )

                    # --------------------------------------------------
                    # Gather cross-reference context (incoming / outgoing)
                    # --------------------------------------------------
                    address = None
                    if isinstance(current_function_result, str):
                        addr_match = re.search(r"at\s+([0-9a-fA-F]+)", current_function_result)
                        if addr_match:
                            address = addr_match.group(1)

                    xref_to_text = "(unavailable)"
                    xref_from_text = "(unavailable)"

                    try:
                        if address:
                            xrefs_to = self.bridge.ghidra.get_xrefs_to(address=address)
                            xrefs_from = self.bridge.ghidra.get_xrefs_from(address=address)
                            # Ensure lists
                            xrefs_to = xrefs_to if isinstance(xrefs_to, list) else [str(xrefs_to)]
                            xrefs_from = xrefs_from if isinstance(xrefs_from, list) else [str(xrefs_from)]
                            xref_to_text = "\n".join(map(str, xrefs_to)) or "(none)"
                            xref_from_text = "\n".join(map(str, xrefs_from)) or "(none)"
                    except Exception as _xe:
                        logger.debug(f"Could not fetch xrefs for {function_name}: {_xe}")

                    # Append cross-reference context (callers/callees)
                    analysis_prompt += (
                        "\nCROSS-REFERENCE INFORMATION:\n"
                        "Incoming references (calls **to** this function):\n"
                        f"{xref_to_text}\n\n"
                        "Outgoing references (calls **from** this function):\n"
                        f"{xref_from_text}\n"
                    )

                    # Generate AI analysis
                    ai_analysis = self.bridge.ollama.generate(prompt=analysis_prompt)

                    if ai_analysis and ai_analysis.strip():
                        self.response_panel.add_response("Step 3: Comprehensive AI Analysis", ai_analysis)

                        # Store the function summary for future reference
                        if hasattr(self.bridge, "function_summaries"):
                            self.bridge.function_summaries[function_name] = ai_analysis.strip()

                        # Add to renamed functions panel for tracking (even if not renamed)
                        if hasattr(self, "renamed_functions_panel") and self.renamed_functions_panel:
                            # Extract address from current function result
                            address = "unknown"
                            if isinstance(current_function_result, str):
                                addr_match = re.search(r"at\s+([0-9a-fA-F]+)", current_function_result)
                                if addr_match:
                                    address = addr_match.group(1)

                            self.renamed_functions_panel.add_function_with_summary(
                                address=address,
                                old_name=function_name,
                                new_name=function_name,  # Keep same name since this is analysis only
                                summary=ai_analysis.strip(),
                            )

                        self.response_panel.add_response(
                            "✅ Analysis Complete",
                            f"Function {function_name} has been thoroughly analyzed and added to the function tracking system.",
                        )
                    else:
                        self.response_panel.add_response("Warning", "AI analysis returned empty response.")

                except Exception as e:
                    error_msg = f"Error during AI analysis: {e}"
                    logger.error(error_msg)
                    self.response_panel.add_response("Error", error_msg)

                # Final stage update
                self.workflow_diagram.set_current_stage(None)

            except Exception as e:
                error_msg = f"Error running {display_name}: {e}"
                logger.error(error_msg)
                self.response_panel.add_response("Error", error_msg)
                self.workflow_diagram.set_current_stage(None)
            finally:
                self._set_tool_running(False)

        threading.Thread(target=worker, daemon=True).start()

    def _rename_current_function(self):
        """Rename the current function using hardcoded workflow."""
        if self.tool_running:
            return

        self._run_hardcoded_rename_workflow("Rename Current Function")

    def _rename_all_functions(self):
        """Rename all functions using AI analysis with confirmation and enumeration options."""
        if self.tool_running:
            return

        # Single professional warning dialog
        warning_message = """⚠️ Rename All Functions - Confirmation Required

You are about to rename ALL functions in this binary using AI analysis.

Important considerations:
• This operation will process every function in the binary
• Each function will be analyzed individually and renamed based on AI suggestions
• This process may take considerable time depending on the number of functions
• Function names will be changed from generic names (FUN_*, sub_*, etc.) to descriptive names
• The operation cannot be easily undone - consider saving your current session first

Progress will be shown in the AI Response panel and results will appear in the Renamed Functions tab.

Do you want to proceed with renaming all functions?"""

        if not messagebox.askyesno("Rename All Functions", warning_message):
            return

        # Secondary dialog for enumeration option
        enumeration_dialog = tk.Toplevel(self.frame)
        enumeration_dialog.title("Function Enumeration Options")
        enumeration_dialog.geometry("800x650")
        enumeration_dialog.transient(self.frame.winfo_toplevel())
        enumeration_dialog.grab_set()

        # Center the dialog
        enumeration_dialog.update_idletasks()
        x = (enumeration_dialog.winfo_screenwidth() // 2) - (800 // 2)
        y = (enumeration_dialog.winfo_screenheight() // 2) - (650 // 2)
        enumeration_dialog.geometry(f"800x650+{x}+{y}")

        # Dialog content
        main_frame = ttk.Frame(enumeration_dialog, padding=20)
        main_frame.pack(fill="both", expand=True)

        # Title
        title_label = ttk.Label(main_frame, text="🔍 Function Enumeration Options", font=("TkDefaultFont", 14, "bold"))
        title_label.pack(pady=(0, 15))

        # Description
        desc_text = """Enhanced Enumeration Mode

The "Rename All Functions" tool can also serve as a comprehensive function enumeration tool.
This will ensure ALL functions (renamed and existing) are added to the Renamed Functions list
with high-quality behavior summaries for complete binary coverage.

Choose your enumeration strategy:"""

        desc_label = ttk.Label(main_frame, text=desc_text, font=("TkDefaultFont", 10), wraplength=750)
        desc_label.pack(pady=(0, 20))

        # Options frame
        options_frame = ttk.LabelFrame(main_frame, text="Enumeration Strategy", padding=15)
        options_frame.pack(fill="x", pady=(0, 20))

        enumeration_var = tk.StringVar(value="rename_only")

        # Option 1: Rename only (current behavior)
        ttk.Radiobutton(options_frame, text="Rename Only (Standard)", variable=enumeration_var, value="rename_only").pack(
            anchor="w", pady=5
        )
        desc1 = ttk.Label(
            options_frame,
            text="• Only rename functions with generic names (FUN_*, sub_*, etc.)\n• Skip functions that already have descriptive names\n• Faster execution, focused on renaming",
            font=("TkDefaultFont", 9),
            foreground="gray",
        )
        desc1.pack(anchor="w", padx=20, pady=(0, 10))

        # Option 2: Full enumeration (enhanced)
        ttk.Radiobutton(
            options_frame, text="Full Enumeration (Enhanced)", variable=enumeration_var, value="full_enumeration"
        ).pack(anchor="w", pady=5)
        desc2 = ttk.Label(
            options_frame,
            text="• Process ALL functions in the binary (renamed + existing)\n• Generate behavior summaries for every function\n• Add all functions to Renamed Functions list for complete coverage\n• Ideal for comprehensive binary analysis and documentation",
            font=("TkDefaultFont", 9),
            foreground="gray",
        )
        desc2.pack(anchor="w", padx=20, pady=(0, 10))

        # Option 3: Smart enumeration
        ttk.Radiobutton(
            options_frame, text="Smart Enumeration (Recommended)", variable=enumeration_var, value="smart_enumeration"
        ).pack(anchor="w", pady=5)
        desc3 = ttk.Label(
            options_frame,
            text="• Rename generic functions + analyze key descriptive functions\n• Focus on important functions (main, crypto, network, file ops)\n• Balance between speed and comprehensive coverage\n• Best for most analysis scenarios",
            font=("TkDefaultFont", 9),
            foreground="gray",
        )
        desc3.pack(anchor="w", padx=20)

        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill="x")

        selected_mode = None

        def confirm_enumeration():
            nonlocal selected_mode
            selected_mode = enumeration_var.get()
            enumeration_dialog.destroy()

        def cancel_enumeration():
            enumeration_dialog.destroy()

        ttk.Button(button_frame, text="Start Processing", command=confirm_enumeration).pack(side="right", padx=(10, 0))
        ttk.Button(button_frame, text="Cancel", command=cancel_enumeration).pack(side="right")

        # Wait for dialog to close
        enumeration_dialog.wait_window()

        if selected_mode is None:
            return  # User cancelled

        # Start the bulk rename workflow with selected enumeration mode
        self._run_bulk_rename_workflow("Rename All Functions", enumeration_mode=selected_mode)

    def _analyze_imports(self):
        """Analyze imports using hardcoded workflow."""
        if self.tool_running:
            return

        self._run_hardcoded_workflow("list_imports", "Analyze Imports")

    def _analyze_strings(self):
        """Analyze strings using hardcoded workflow."""
        if self.tool_running:
            return

        self._run_hardcoded_workflow("list_strings", "Analyze Strings")

    def _analyze_exports(self):
        """Analyze exports using hardcoded workflow."""
        if self.tool_running:
            return

        self._run_hardcoded_workflow("list_exports", "Analyze Exports")

    def _generate_software_report(self):
        """Generate comprehensive software report using AI analysis."""
        if self.tool_running:
            return

        # Professional confirmation dialog
        confirmation_message = """🔍 Generate Vulnerability Report - Confirmation Required

You are about to generate an AI-powered HTML vulnerability analysis report.

This report will include:
• Executive Summary with risk assessment
• Attack vectors and exploitation flow diagrams
• AI investigation steps timeline
• Critical imports and string artifacts
• Security recommendations

The analysis process will:
• Collect all available binary data (functions, imports, exports, segments, etc.)
• Analyze renamed functions and their behavioral summaries
• Perform AI-powered classification and risk assessment
• Generate a styled HTML report

This operation may take several minutes depending on the amount of analysis data available.

Do you want to proceed with generating the vulnerability report?"""

        if not messagebox.askyesno("Generate Vulnerability Report", confirmation_message):
            return

        # Start the software report generation workflow with HTML format
        self._run_software_report_workflow("Generate Vulnerability Report", "html")

    def _run_software_report_workflow(self, display_name: str, report_format: str):
        """Run the comprehensive software report generation workflow."""

        def worker():
            try:
                self._set_tool_running(True, display_name)
                self.workflow_diagram.set_current_stage("planning")

                # Add initial message to response panel
                self.response_panel.add_response(
                    f"Smart Tool: {display_name}",
                    f"Starting comprehensive software analysis and report generation (Format: {report_format.upper()})",
                )

                # Phase 1: Data Collection
                self.response_panel.add_response("Phase 1", "Collecting comprehensive binary data...")
                self.workflow_diagram.set_current_stage("execution")

                # Phase 2: AI Analysis
                self.response_panel.add_response(
                    "Phase 2", "Performing AI-powered analysis (classification, security, behavior, architecture)..."
                )
                self.workflow_diagram.set_current_stage("analysis")

                # Phase 3: Report Generation
                self.response_panel.add_response("Phase 3", "Generating structured software report...")
                self.workflow_diagram.set_current_stage("review")

                # Call the bridge method to generate the report
                try:
                    report_content = self.bridge.generate_software_report(report_format)

                    # Display success message
                    self.response_panel.add_response("Report Generated", "✅ Vulnerability report generated successfully!")

                    # Only show preview for non-HTML formats (HTML is not human-readable in text)
                    if report_format != "html":
                        preview = report_content[:1000] + ("..." if len(report_content) > 1000 else "")
                        self.response_panel.add_response("Report Preview", preview)
                    else:
                        self.response_panel.add_response(
                            "Report Info",
                            f"📄 HTML report generated ({len(report_content)} bytes). Open the saved file in a browser to view.",
                        )

                    # Offer to save the report
                    save_response = messagebox.askyesno(
                        "Save Report",
                        f"Vulnerability report generated successfully!\n\nWould you like to save the report to a file?\n\nReport size: {len(report_content)} bytes",
                    )

                    if save_response:
                        # Determine file extension
                        extension = ".md" if report_format == "markdown" else f".{report_format}"
                        default_filename = f"vulnerability_report_{self._get_timestamp_for_filename()}{extension}"

                        # Show save dialog
                        filename = filedialog.asksaveasfilename(
                            title="Save Vulnerability Report",
                            defaultextension=extension,
                            initialfile=default_filename,
                            filetypes=[(f"{report_format.upper()} files", f"*{extension}"), ("All files", "*.*")],
                        )

                        if filename:
                            try:
                                with open(filename, "w", encoding="utf-8") as f:
                                    f.write(report_content)
                                self.response_panel.add_response("File Saved", f"✅ Report saved to: {filename}")
                            except Exception as e:
                                self.response_panel.add_response("Save Error", f"❌ Error saving file: {e}")

                    # Only show full report in response panel for non-HTML formats
                    if report_format != "html":
                        self.response_panel.add_response("Full Report", report_content)

                except Exception as e:
                    error_msg = f"Error generating software report: {e}"
                    self.response_panel.add_response("Error", error_msg)
                    import traceback

                    self.response_panel.add_response("Error Details", traceback.format_exc())

                # Final stage update
                self.workflow_diagram.set_current_stage(None)

            except Exception as e:
                error_msg = f"Error running {display_name}: {e}"
                logger.error(error_msg)
                self.response_panel.add_response("Error", error_msg)
                self.workflow_diagram.set_current_stage(None)
            finally:
                self._set_tool_running(False)

        threading.Thread(target=worker, daemon=True).start()

    def _get_timestamp_for_filename(self) -> str:
        """Get a timestamp string suitable for filenames."""
        from datetime import datetime

        return datetime.now().strftime("%Y%m%d_%H%M%S")

    def _get_analysis_prompt(self, tool_name: str, tool_data: str) -> str:
        """Get the appropriate analysis prompt for the given tool."""
        if tool_name == "list_strings":
            return f"""
Examine the list of embedded strings below. Identify any hardcoded credentials, API keys, IP addresses, or domain names that could reveal server infrastructure or communication endpoints. Look for error messages, debug information, or file paths that might betray the program's original development environment or core functionality. Note any unusual or obfuscated strings that could be used for dynamic decryption or command-and-control (C2) communication.

STRINGS DATA:
{tool_data}

Please provide a detailed analysis focusing on:
1. Security-relevant strings (credentials, keys, IPs, domains)
2. Development environment clues (file paths, debug messages)
3. Functional indicators (error messages, configuration strings)
4. Suspicious or obfuscated content
5. Potential C2 or malware indicators
"""

        elif tool_name == "list_exports":
            return f"""
Review the exported functions below to determine the primary purpose of this library or executable. Identify function names that suggest significant capabilities, such as CreateUser, EncryptData, or ExecuteShellcode. Pay close attention to any non-standard or ambiguously named exports that might conceal malicious functionality. Cross-reference these exports with public documentation to spot any deviations or undocumented features.

EXPORTS DATA:
{tool_data}

Please provide a detailed analysis focusing on:
1. Primary purpose and functionality of the binary
2. Significant capability indicators (encryption, network, process manipulation)
3. Non-standard or suspicious export names
4. Comparison with expected/documented behavior
5. Potential security implications
"""

        elif tool_name == "list_imports":
            return f"""
Analyze the imported libraries and functions below to understand the binary's core dependencies and capabilities. Note which high-level libraries (e.g., ws2_32.dll for networking, crypt32.dll for cryptography) are being used to infer its main purpose. Scrutinize the specific functions imported; for instance, imports like VirtualAllocEx, WriteProcessMemory, and CreateRemoteThread are strong indicators of process injection or malware-like behavior. Flag any unusual or lesser-known library imports for deeper investigation.

IMPORTS DATA:
{tool_data}

Please provide a detailed analysis focusing on:
1. Core dependencies and their implications
2. High-level library purposes (networking, crypto, etc.)
3. Suspicious function combinations (process injection indicators)
4. Unusual or lesser-known library imports
5. Overall capability assessment and security implications
"""

        else:
            # Fallback for unknown tools
            return f"""
Analyze the following data from the {tool_name} tool and provide insights about what it reveals regarding the binary's functionality, purpose, and potential security implications.

TOOL DATA:
{tool_data}

Please provide a comprehensive analysis of this information.
"""

    def get_widget(self):
        """Return the frame widget."""
        return self.frame

    def _stop_tool(self):
        """Stop the currently running tool."""
        if self.tool_running:
            self.should_stop = True
            self.response_panel.add_response("User Action", "🛑 Tool cancellation requested...")
            self._set_tool_running(False)

    def _set_tool_running(self, running: bool, tool_name: str = ""):
        """Set the tool running state."""
        self.tool_running = running

        # Update all buttons
        state = "disabled" if running else "normal"
        for widget in self.frame.winfo_children():
            if isinstance(widget, ttk.Button) and widget not in [self.stop_button]:
                widget.config(state=state)

        # Update stop button state
        self.stop_button.config(state="normal" if running else "disabled")

        # Update status and progress
        if running:
            self.should_stop = False  # Reset stop flag for new tool
            self.status_label.config(text=f"Running {tool_name}...", foreground="orange")
            self.progress.start()
        else:
            self.status_label.config(text="Ready", foreground="green")
            self.progress.stop()

    def _search_strings(self):
        """Prompt the user for a substring and search defined strings."""
        if self.tool_running:
            return

        import tkinter.simpledialog as sd

        query = sd.askstring("String Search", "Enter substring to search in defined strings:")
        if query is None or query.strip() == "":
            return  # cancelled

        # list_strings supports optional 'filter' parameter (alias string_search)
        self._run_hardcoded_workflow("list_strings", f"Search Strings for '{query}'", params={"filter": query.strip()})

    def _scan_function_tables(self):
        """Scan for function pointer tables (vtables, dispatch tables) without LLM intervention."""
        if self.tool_running:
            return

        def worker():
            try:
                self._set_tool_running(True, "Scan Function Tables")
                self.workflow_diagram.set_current_stage("execution")

                # Add initial message
                self.response_panel.add_response(
                    "Smart Tool: Scan Function Tables",
                    "Scanning binary for function pointer tables (vtables, dispatch tables, jump tables)...\n"
                    "This runs algorithmically without LLM intervention.",
                )

                # Run the scan directly (no LLM needed)
                tables = self.bridge.ghidra.scan_function_pointer_tables(
                    min_table_entries=3, pointer_size=8, max_scan_size=65536
                )

                if tables:
                    # Format results
                    formatted = self.bridge.ghidra.format_table_scan_results(tables)
                    self.response_panel.add_response(f"Scan Complete: Found {len(tables)} Table(s)", formatted)

                    # Now send to AI for interpretation
                    self.workflow_diagram.set_current_stage("analysis")

                    # Build analysis prompt
                    analysis_prompt = f"""Analyze these detected function pointer tables:

{formatted}

Please provide:
1. What type of tables these likely are (vtables, dispatch tables, jump tables, etc.)
2. What the functions in each table might be doing based on their names
3. Any insights about the code structure or design patterns revealed
4. Which functions are reachable through these tables (indirect call targets)
"""

                    # Stream the AI analysis
                    self.response_panel.add_response("AI Analysis", "")

                    for chunk in self.bridge.ollama_client.stream_generate(
                        model=self.bridge.ollama_config.model, prompt=analysis_prompt, temperature=0.7
                    ):
                        if self.should_stop:
                            break
                        self.response_panel.append_to_last_response(chunk)
                else:
                    # Get segment info for context
                    try:
                        segments = self.bridge.ghidra.list_segments()
                        seg_info = "\n".join(f"  {s}" for s in segments[:8])
                    except Exception as e:
                        error_message = "  (Could not retrieve segment info)"
                        logger.warning(f"{error_message}: {e}")
                        seg_info = error_message

                    self.response_panel.add_response(
                        "Scan Complete: No Tables Found",
                        f"No function pointer tables were detected (require 3+ consecutive function pointers).\n\n"
                        f"**Scanned Segments:**\n{seg_info}\n\n"
                        f"**This could mean:**\n"
                        f"• The binary is written in C (no vtables) rather than C++\n"
                        f"• No dispatch tables or jump tables in data segments\n"
                        f"• Function pointers exist but aren't grouped into tables\n\n"
                        f"**Alternative approaches:**\n"
                        f"• Use read_bytes() to examine specific addresses manually\n"
                        f"• Search for xrefs to functions to find indirect calls\n"
                        f"• Look for DATA references using get_xrefs_to()",
                    )

                self.workflow_diagram.set_current_stage("complete")

            except Exception as e:
                import traceback

                self.response_panel.add_response("Error", f"Scan failed: {str(e)}\n\n{traceback.format_exc()}")
                self.workflow_diagram.set_current_stage("error")
            finally:
                self._set_tool_running(False, "")

        import threading

        threading.Thread(target=worker, daemon=True).start()
