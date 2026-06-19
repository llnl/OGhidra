#!/usr/bin/env python3
"""
OGhidra UI Module
-----------------
Comprehensive GUI interface for the Ollama-GhidraMCP Bridge application.
"""

import logging
import threading
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
from typing import Any, Dict

import ttkbootstrap as tb

from ..bridge import Bridge
from ..config import BridgeConfig
from .memory_info_panel import MemoryInfoPanel
from .ai_response_panel import AIResponsePanel
from .query_input_panel import QueryInputPanel
from .renamed_functions_panel import RenamedFunctionsPanel
from .server_config_dialog import ServerConfigDialog
from .tool_buttons_panel import ToolButtonsPanel
from .workflow_diagram import WorkflowDiagram

logger = logging.getLogger("ollama-ghidra-bridge.ui")


class OGhidraUI:
    """Main UI class for the OGhidra application."""

    def __init__(self, bridge: Bridge, config: BridgeConfig):
        self.bridge = bridge
        self.config = config

        # Allow Bridge to access UI state (e.g., analyzed functions tree) for prompt enrichment.
        try:
            setattr(self.bridge, "_ui_instance", self)
        except Exception:
            pass

        # Use ttkbootstrap Window for modern dark theme with rounded corners
        self.root = tb.Window(
            title="OGhidra - Ollama-GhidraMCP Bridge",
            themename="darkly",  # Dark gray theme with soft corners
            size=(1400, 900),
        )

        # Ensure closing the main window triggers a clean application shutdown
        # (save session, close Ghidra/pyGhidra client, exit mainloop).
        self.root.protocol("WM_DELETE_WINDOW", self._quit_application)

        self._setup_ui()
        self._setup_menu()

        # Start health monitoring
        self._start_health_monitoring()

        # Display startup configuration info
        self._show_startup_info()

    def _show_startup_info(self):
        """Display configuration info on startup."""
        provider = getattr(self.config, "llm_provider", "ollama")

        # Determine active configuration source
        if provider == "ollama":
            config_src = self.config.ollama
            provider_display = "Ollama"
        elif provider == "google":
            # Legacy google support (will be mapped to external effectively but kept distinct in config if needed)
            config_src = self.config.google
            provider_display = "Google (Legacy)"
        elif provider == "custom_api":
            config_src = self.config.custom_api
            provider_display = "Custom API"
        else:  # external or specific external provider name
            config_src = self.config.external
            # For external, show the sub-provider type if available
            sub_provider = getattr(config_src, "provider", "unknown")
            provider_display = f"External ({sub_provider})"

        # Safe attribute access with defaults
        timeout = getattr(config_src, "timeout", "N/A")
        request_delay = getattr(config_src, "request_delay", 0.0)
        model = getattr(config_src, "model", "unknown")
        embedding_model = getattr(config_src, "embedding_model", "unknown")

        # Build startup message with more details
        startup_msg = (
            f"═══════════════════════════════════════════════════════════\n"
            f"LLM Provider: {provider_display}\n"
            f"Chat Model: {model}\n"
            f"Embedding Model: {embedding_model}\n"
            f"Timeout: {timeout}s | Request Delay: {request_delay}s\n"
            f"═══════════════════════════════════════════════════════════\n"
            f"Ready for queries."
        )
        self.response_panel.add_response("System", startup_msg)

    def _setup_ui(self):
        """Setup the main UI layout."""
        # Main paned window
        main_paned = ttk.PanedWindow(self.root, orient="horizontal")
        main_paned.pack(fill="both", expand=True, padx=5, pady=5)

        # Left panel - Main focus: Query and AI Response (larger)
        main_frame = ttk.Frame(main_paned)
        main_paned.add(main_frame, weight=4)

        # Right panel - Analyzed Functions sidebar (slimmer)
        sidebar_frame = ttk.Frame(main_paned)
        main_paned.add(sidebar_frame, weight=1)

        # Setup main panel (query + AI response)
        self._setup_main_panel(main_frame)

        # Setup sidebar (analyzed functions)
        self._setup_sidebar_panel(sidebar_frame)

    def _setup_main_panel(self, parent):
        """Setup the main panel with query input and AI responses (primary focus)."""
        # Query input panel
        self.query_panel = QueryInputPanel(parent, self.bridge, None, None)  # workflow_diagram set later
        self.query_panel.get_widget().pack(fill="x", pady=(0, 10))

        # AI Response panel (main content area)
        # Pass the generate report callback from main UI
        self.response_panel = AIResponsePanel(parent, generate_callback=self._menu_generate_report)
        self.response_panel.get_widget().pack(fill="both", expand=True)

    def _setup_sidebar_panel(self, parent):
        """Setup the sidebar with analyzed functions (secondary, slimmer)."""
        # Workflow status tracker (above analyzed functions)
        workflow_frame = ttk.LabelFrame(parent, text="Workflow Status", padding=8)
        workflow_frame.pack(fill="x", pady=(0, 10))

        self.workflow_diagram = WorkflowDiagram(workflow_frame, width=500, height=100)
        self.workflow_diagram.get_widget().pack()

        # Analyzed Functions panel
        self.renamed_functions_panel = RenamedFunctionsPanel(parent, self.bridge)
        self.renamed_functions_panel.get_widget().pack(fill="both", expand=True)
        # Start auto-refresh for renamed functions
        self.renamed_functions_panel._start_auto_refresh()

        # Wire analyzed-functions panel into the query panel so Hybrid Search status can
        # accurately reflect whether summaries are available.
        try:
            if hasattr(self, "query_panel") and self.query_panel:
                setattr(self.query_panel, "renamed_functions_panel", self.renamed_functions_panel)
                if hasattr(self.query_panel, "_on_grep_layer_change"):
                    self.query_panel._on_grep_layer_change()
        except Exception:
            pass

        # Hidden components (memory panel - accessed via Tools > System Info menu)
        hidden_frame = ttk.Frame(parent)  # Don't pack this
        self.memory_panel = MemoryInfoPanel(hidden_frame, self.bridge)
        self.bridge._ui_memory_panel_refresh = self.memory_panel._update_memory_info

        # Set up chain of thought callback for live AI reasoning updates
        self.bridge._ui_cot_callback = self.response_panel.add_cot_update

        # Tool panel (hidden - accessed via Analysis menu)
        self.tool_panel = ToolButtonsPanel(parent, self.bridge, None, self.workflow_diagram, self.renamed_functions_panel)

        # Connect panels to response panel and each other
        self.tool_panel.response_panel = self.response_panel
        self.query_panel.response_panel = self.response_panel
        self.query_panel.workflow_diagram = self.workflow_diagram
        self.query_panel.tool_panel = self.tool_panel  # For quick action buttons

    def _setup_menu(self):
        """Setup the application menu."""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)

        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Save Session", command=self._save_session)
        file_menu.add_command(label="Load Session", command=self._load_session)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self._quit_application)

        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Health Check", command=self._health_check)
        tools_menu.add_command(label="System Info", command=self._show_system_info)
        tools_menu.add_command(label="Server Configuration", command=self._configure_servers)
        tools_menu.add_separator()
        tools_menu.add_command(label="Clear Session", command=self._clear_all_data)

        # Analysis menu (Smart Tools)
        analysis_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Analysis", menu=analysis_menu)

        # Current function operations
        analysis_menu.add_command(label="Analyze Current Function", command=self._menu_analyze_current)
        analysis_menu.add_command(label="Rename Current Function", command=self._menu_rename_current)
        analysis_menu.add_separator()

        # Batch operations
        analysis_menu.add_command(label="Rename All Functions", command=self._menu_rename_all)
        analysis_menu.add_command(label="Generate Software Report", command=self._menu_generate_report)
        analysis_menu.add_separator()

        # Analysis tools
        analysis_menu.add_command(label="Analyze Imports", command=self._menu_analyze_imports)
        analysis_menu.add_command(label="Analyze Exports", command=self._menu_analyze_exports)
        analysis_menu.add_command(label="Analyze Strings", command=self._menu_analyze_strings)
        analysis_menu.add_separator()

        # Search/Scan tools
        analysis_menu.add_command(label="Search Strings...", command=self._menu_search_strings)
        analysis_menu.add_command(label="Scan Function Tables", command=self._menu_scan_tables)

        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self._show_about)

    def _start_health_monitoring(self):
        """Start periodic health monitoring."""

        def monitor():
            try:
                # Update memory info every 30 seconds
                self.memory_panel._update_memory_info()
            except Exception as e:
                logger.error(f"Error in health monitoring: {e}")

            # Schedule next update
            self.root.after(30000, monitor)  # 30 seconds

        # Start monitoring
        self.root.after(5000, monitor)  # Start after 5 seconds

    def _save_session(self):
        """Save the current session with enhanced session management."""
        try:
            import time
            from datetime import datetime
            import tkinter.messagebox as messagebox

            # Import the enhanced session manager with absolute import
            try:
                from src.enhanced_session_manager import EnhancedSessionManager
            except ImportError as e:
                messagebox.showerror("Import Error", f"Could not import session manager: {e}")
                return

            # Initialize session manager if not exists
            if not hasattr(self, "session_manager"):
                try:
                    self.session_manager = EnhancedSessionManager()
                except Exception as e:
                    messagebox.showerror("Initialization Error", f"Could not initialize session manager: {e}")
                    return

            # Create session name dialog
            session_dialog = tk.Toplevel(self.root)
            session_dialog.title("Save Analysis Session")
            session_dialog.geometry("700x600")
            session_dialog.transient(self.root)
            session_dialog.grab_set()

            # Center dialog
            try:
                session_dialog.update_idletasks()
                x = (session_dialog.winfo_screenwidth() // 2) - (350)
                y = (session_dialog.winfo_screenheight() // 2) - (300)
                session_dialog.geometry(f"700x600+{x}+{y}")
            except Exception as e:
                logger.warning(f"Could not center dialog: {e}")

            main_frame = ttk.Frame(session_dialog, padding=20)
            main_frame.pack(fill="both", expand=True)

            # Title
            ttk.Label(main_frame, text="💾 Save Analysis Session", font=("TkDefaultFont", 14, "bold")).pack(pady=(0, 15))

            # Session name
            ttk.Label(main_frame, text="Session Name:").pack(anchor="w")
            session_name_var = tk.StringVar(value=f"Analysis_{int(time.time())}")
            session_name_entry = ttk.Entry(main_frame, textvariable=session_name_var, width=50)
            session_name_entry.pack(fill="x", pady=(5, 10))

            # Description
            ttk.Label(main_frame, text="Description (optional):").pack(anchor="w")

            desc_text = tk.Text(
                main_frame,
                height=4,
                width=50,
                font=("Segoe UI", 10),
                relief="flat",
                borderwidth=1,
                padx=6,
                pady=6,
            )
            desc_text.pack(fill="x", pady=(5, 10))

            # Current session info
            info_frame = ttk.LabelFrame(main_frame, text="Current Session Info", padding=10)
            info_frame.pack(fill="x", pady=(10, 0))

            # Get analyzed functions count
            functions_count = 0
            try:
                if hasattr(self, "renamed_functions_panel") and self.renamed_functions_panel:
                    # Count functions in the panel
                    if hasattr(self.renamed_functions_panel, "function_summaries"):
                        functions_count = len(self.renamed_functions_panel.function_summaries)
                    elif hasattr(self.bridge, "function_summaries"):
                        functions_count = len(self.bridge.function_summaries)
            except Exception as e:
                logger.warning(f"Could not get functions count: {e}")

            ttk.Label(info_frame, text=f"• Analyzed Functions: {functions_count}").pack(anchor="w")

            # RAG vectors count
            rag_count = 0
            try:
                if hasattr(self.bridge, "cag_manager") and self.bridge.cag_manager:
                    if hasattr(self.bridge.cag_manager, "vector_store") and self.bridge.cag_manager.vector_store:
                        if hasattr(self.bridge.cag_manager.vector_store, "embeddings"):
                            embeddings = self.bridge.cag_manager.vector_store.embeddings
                            if embeddings is not None:
                                # Handle numpy arrays properly
                                try:
                                    rag_count = len(embeddings)
                                except (TypeError, ValueError):
                                    # Handle case where embeddings might be a numpy array
                                    if hasattr(embeddings, "shape"):
                                        rag_count = embeddings.shape[0] if len(embeddings.shape) > 0 else 0
                else:
                    rag_count = 0
            except Exception as e:
                logger.warning(f"Could not get RAG count: {e}")
                rag_count = 0

            ttk.Label(info_frame, text=f"• RAG Vectors: {rag_count}").pack(anchor="w")
            ttk.Label(info_frame, text=f"• Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}").pack(anchor="w")

            # Buttons
            button_frame = ttk.Frame(main_frame)
            button_frame.pack(fill="x", pady=(20, 0))

            result = {"saved": False}

            def save_session():
                try:
                    session_name = session_name_var.get().strip()
                    if not session_name:
                        messagebox.showerror("Error", "Please enter a session name.")
                        return

                    description = desc_text.get(1.0, tk.END).strip()

                    # Create new session
                    try:
                        self.session_manager.create_session(
                            session_name=session_name, description=description if description else None
                        )
                    except Exception as e:
                        messagebox.showerror("Session Creation Error", f"Could not create session: {e}")
                        return

                    # Collect analyzed functions data
                    analyzed_functions = {}
                    try:
                        if hasattr(self.bridge, "function_summaries") and self.bridge.function_summaries:
                            for address, summary in self.bridge.function_summaries.items():
                                analyzed_functions[address] = {
                                    "address": address,
                                    "old_name": "Unknown",
                                    "new_name": "Unknown",
                                    "behavior_summary": summary,
                                    "timestamp": time.time(),
                                }

                        # Also try to get data from the renamed functions panel
                        if hasattr(self, "renamed_functions_panel") and self.renamed_functions_panel:
                            if hasattr(self.renamed_functions_panel, "function_summaries"):
                                for key, summary in self.renamed_functions_panel.function_summaries.items():
                                    if key not in analyzed_functions:
                                        analyzed_functions[key] = {
                                            "address": key,
                                            "old_name": "Unknown",
                                            "new_name": "Unknown",
                                            "behavior_summary": summary,
                                            "timestamp": time.time(),
                                        }
                    except Exception as e:
                        logger.warning(f"Could not collect analyzed functions: {e}")

                    # Refinement: rebuild analyzed_functions entries with accurate address/old/new names and standard key 'behavior_summary'
                    try:
                        mapping = getattr(self.bridge, "function_address_mapping", {})
                        summaries = getattr(self.bridge, "function_summaries", {})

                        for identifier, info in mapping.items():
                            summary_val = (
                                summaries.get(identifier)
                                or summaries.get(info.get("old_name", ""))
                                or summaries.get(info.get("new_name", ""))
                            )
                            if not summary_val:
                                continue
                            addr = (
                                identifier
                                if self.renamed_functions_panel._looks_like_address(identifier)
                                else info.get("address", identifier)
                            )
                            analyzed_functions[addr] = {
                                "address": addr,
                                "old_name": info.get("old_name", "Unknown"),
                                "new_name": info.get("new_name", "Unknown"),
                                "behavior_summary": summary_val,
                                "timestamp": time.time(),
                            }

                        # Convert legacy 'summary' field to 'behavior_summary'
                        for rec in analyzed_functions.values():
                            if "summary" in rec and "behavior_summary" not in rec:
                                rec["behavior_summary"] = rec.pop("summary")
                    except Exception as refine_err:
                        logger.warning(f"Analyzed functions refinement failed: {refine_err}")

                    # FINAL DEDUPLICATION: remove non-address keys when a canonical address entry exists for the same new_name
                    try:

                        def _looks_like_address(txt: str) -> bool:
                            if not isinstance(txt, str):
                                return False
                            if txt.startswith("0x"):
                                txt = txt[2:]
                            return (len(txt) >= 4 and all(c in "0123456789abcdefABCDEF" for c in txt)) or (
                                txt.isdigit() and len(txt) >= 8
                            )

                        # Collect new_names that have a real address entry
                        canonical_new_names = {
                            rec.get("new_name") for addr, rec in analyzed_functions.items() if _looks_like_address(addr)
                        }

                        # Remove duplicates whose key is not an address but share the same new_name
                        for key in list(analyzed_functions.keys()):
                            if _looks_like_address(key):
                                continue  # keep canonical
                            rec = analyzed_functions.get(key, {})
                            if rec.get("new_name") in canonical_new_names:
                                analyzed_functions.pop(key, None)
                    except Exception as dedup_err:
                        logger.debug(f"Final deduplication step failed: {dedup_err}")

                    # SAFETY FILTER: remove incomplete function records
                    try:
                        for addr in list(analyzed_functions.keys()):
                            rec = analyzed_functions.get(addr, {})
                            old_unknown = rec.get("old_name") in [None, "", "Unknown"]
                            new_unknown = rec.get("new_name") in [None, "", "Unknown"]
                            summary_empty = not rec.get("behavior_summary", "").strip()
                            if (old_unknown and new_unknown) or summary_empty:
                                analyzed_functions.pop(addr, None)
                    except Exception as filter_err:
                        logger.debug(f"Safety filter failed: {filter_err}")

                    # Collect RAG vectors
                    rag_vectors = []
                    try:
                        if hasattr(self.bridge, "cag_manager") and self.bridge.cag_manager:
                            if hasattr(self.bridge.cag_manager, "vector_store") and self.bridge.cag_manager.vector_store:
                                if hasattr(self.bridge.cag_manager.vector_store, "documents"):
                                    rag_vectors = self.bridge.cag_manager.vector_store.documents or []
                    except Exception as e:
                        logger.warning(f"Could not collect RAG vectors: {e}")

                    # Save session data
                    try:
                        success = self.session_manager.save_current_session(
                            analyzed_functions=analyzed_functions,
                            rag_vectors=rag_vectors,
                            performance_stats={
                                "functions_count": functions_count,
                                "rag_count": rag_count,
                                "save_timestamp": time.time(),
                            },
                        )

                        if success:
                            result["saved"] = True
                            session_dialog.destroy()
                            messagebox.showinfo(
                                "Success",
                                f"Session '{session_name}' saved successfully!\n\nSaved {len(analyzed_functions)} analyzed functions and {len(rag_vectors)} RAG vectors.",
                            )
                        else:
                            messagebox.showerror("Error", "Failed to save session. Check logs for details.")
                    except Exception as e:
                        messagebox.showerror("Save Error", f"Error saving session: {e}")

                except Exception as e:
                    messagebox.showerror("Error", f"Failed to save session: {e}")
                    import traceback

                    logger.error(f"Save session error: {e}\n{traceback.format_exc()}")

            def cancel_save():
                session_dialog.destroy()

            ttk.Button(button_frame, text="Save Session", command=save_session).pack(side="right", padx=(10, 0))
            ttk.Button(button_frame, text="Cancel", command=cancel_save).pack(side="right")

            # Wait for dialog
            session_dialog.wait_window()

        except Exception as e:
            messagebox.showerror("Error", f"Failed to open save dialog: {e}")
            import traceback

            logger.error(f"Save session dialog error: {e}\n{traceback.format_exc()}")

    def _load_session(self):
        """Load a session with enhanced session management."""
        try:
            from datetime import datetime
            import tkinter.messagebox as messagebox

            # Import the enhanced session manager with absolute import
            from src.enhanced_session_manager import EnhancedSessionManager

            # Initialize session manager if not exists
            if not hasattr(self, "session_manager"):
                self.session_manager = EnhancedSessionManager()

                # Get available sessions
            sessions = self.session_manager.list_sessions()
            if not sessions:
                messagebox.showinfo("Info", "No saved sessions found.")
                return

            # Create session selection dialog
            load_dialog = tk.Toplevel(self.root)
            load_dialog.title("Load Analysis Session")
            load_dialog.geometry("700x650")
            load_dialog.transient(self.root)
            load_dialog.grab_set()

            # Center dialog
            load_dialog.update_idletasks()
            x = (load_dialog.winfo_screenwidth() // 2) - (350)
            y = (load_dialog.winfo_screenheight() // 2) - (325)
            load_dialog.geometry(f"700x650+{x}+{y}")

            main_frame = ttk.Frame(load_dialog, padding=20)
            main_frame.pack(fill="both", expand=True)

            # Title
            ttk.Label(main_frame, text="📂 Load Analysis Session", font=("TkDefaultFont", 14, "bold")).pack(pady=(0, 15))

            # Sessions list
            list_frame = ttk.LabelFrame(main_frame, text="Available Sessions", padding=10)
            list_frame.pack(fill="both", expand=True, pady=(0, 10))

            # Create treeview for sessions
            columns = ("Name", "Functions", "Created", "Modified")
            session_tree = ttk.Treeview(list_frame, columns=columns, show="headings", height=12)

            # Configure columns
            session_tree.heading("Name", text="Session Name")
            session_tree.heading("Functions", text="Functions")
            session_tree.heading("Created", text="Created")
            session_tree.heading("Modified", text="Last Modified")

            session_tree.column("Name", width=200)
            session_tree.column("Functions", width=80)
            session_tree.column("Created", width=150)
            session_tree.column("Modified", width=150)

            # Add scrollbar
            scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=session_tree.yview)
            session_tree.configure(yscrollcommand=scrollbar.set)

            session_tree.pack(side="left", fill="both", expand=True)
            scrollbar.pack(side="right", fill="y")

            # Populate sessions
            session_items = {}
            for session in sessions:
                try:
                    created_str = datetime.fromtimestamp(session.get("created", 0)).strftime("%Y-%m-%d %H:%M")
                    modified_str = datetime.fromtimestamp(session.get("last_modified", 0)).strftime("%Y-%m-%d %H:%M")
                    functions_count = session.get("analyzed_functions_count", 0)

                    item_id = session_tree.insert(
                        "", "end", values=(session["name"], functions_count, created_str, modified_str)
                    )
                    session_items[item_id] = session
                except Exception as e:
                    logger.warning(f"Error displaying session {session.get('name', 'Unknown')}: {e}")
                    # Try with fallback values
                    try:
                        item_id = session_tree.insert(
                            "",
                            "end",
                            values=(
                                session.get("name", "Unknown Session"),
                                session.get("analyzed_functions_count", 0),
                                "Unknown",
                                "Unknown",
                            ),
                        )
                        session_items[item_id] = session
                    except Exception as e2:
                        logger.error(f"Failed to display session even with fallbacks: {e2}")

            # Show message if no sessions loaded
            if not session_items:
                session_tree.insert("", "end", values=("No sessions found", "", "", ""))

            # Buttons
            button_frame = ttk.Frame(main_frame)
            button_frame.pack(fill="x", pady=(10, 0))

            result = {"loaded": False}

            def load_selected_session():
                selection = session_tree.selection()
                if not selection:
                    messagebox.showerror("Error", "Please select a session to load.")
                    return

                if selection[0] not in session_items:
                    messagebox.showerror("Error", "Invalid session selection.")
                    return

                try:
                    session = session_items[selection[0]]

                    # Set session loading flag to prevent expensive operations
                    if hasattr(self, "memory_panel"):
                        self.memory_panel.set_session_loading(True)

                    # Try streaming load first for large sessions
                    session_data = self.session_manager.load_session_streaming(session["id"])

                    if session_data and session_data.get("streaming"):
                        # Handle streaming load
                        self._load_session_streaming(session_data, session)
                        return
                    elif not session_data:
                        # Fallback to regular load
                        session_data = self.session_manager.load_session(session["id"])

                    if session_data:
                        functions_loaded = 0

                        # Restore analyzed functions to UI (deduplicated)
                        if hasattr(self, "renamed_functions_panel") and self.renamed_functions_panel:
                            analyzed_functions = session_data.get("analyzed_functions", {})

                            # ----------------------
                            # Deduplicate by canonical address and merge related records
                            # ----------------------
                            unique_funcs = {}
                            processed_ids = set()  # canonical_id = address|new_name to avoid duplicates

                            for func_data in analyzed_functions.values():
                                # 1) Derive canonical address (prefer explicit address field that looks like an address)
                                addr = func_data.get("address")
                                if not addr or not self.renamed_functions_panel._looks_like_address(addr):
                                    # Address sometimes stored in name fields – pick whichever looks like an address
                                    for cand in (func_data.get("old_name"), func_data.get("new_name")):
                                        if cand and self.renamed_functions_panel._looks_like_address(cand):
                                            addr = cand
                                            break

                                # Fallback: use new_name / old_name if no real address (edge-case)
                                if not addr:
                                    addr = func_data.get("new_name") or func_data.get("old_name") or "Unknown"

                                canonical_id = f"{addr}|{func_data.get('new_name', 'Unknown')}"
                                if canonical_id in processed_ids:
                                    # Already captured this address/name pair
                                    continue
                                processed_ids.add(canonical_id)

                                if addr not in unique_funcs:
                                    unique_funcs[addr] = {
                                        "address": addr,
                                        "old_name": func_data.get("old_name", "Unknown"),
                                        "new_name": func_data.get("new_name", "Unknown"),
                                        "behavior_summary": func_data.get("behavior_summary") or func_data.get("summary", ""),
                                    }
                                else:
                                    existing = unique_funcs[addr]
                                    # Merge names preferring non-Unknown values
                                    if existing.get("old_name") in [None, "Unknown"] and func_data.get("old_name"):
                                        existing["old_name"] = func_data["old_name"]
                                    if existing.get("new_name") in [None, "Unknown"] and func_data.get("new_name"):
                                        existing["new_name"] = func_data["new_name"]
                                    # Merge summary if existing entry lacks one
                                    if not existing.get("behavior_summary"):
                                        existing["behavior_summary"] = func_data.get("behavior_summary") or func_data.get(
                                            "summary", ""
                                        )

                        for addr, fd in unique_funcs.items():
                            try:
                                summary_val = fd.get("behavior_summary") or fd.get("summary", "")
                                self.renamed_functions_panel.add_function_with_summary(
                                    address=addr,
                                    old_name=fd.get("old_name", "Unknown"),
                                    new_name=fd.get("new_name", "Unknown"),
                                    summary=summary_val,
                                )
                                functions_loaded += 1
                            except Exception as e:
                                logger.warning(f"Could not restore function {addr}: {e}")

                        # Skip RAG vector restoration during session loading to prevent HuggingFace API calls
                        # Vectors will be loaded on-demand via the "Load Vectors" button
                        rag_vectors = session_data.get("rag_vectors", [])

                        # Note: RAG vectors are available in session data but not loaded automatically
                        # Use "Load Vectors" button in Analyzed Functions panel to create embeddings

                        # Clear session loading flag and update memory panel
                        if hasattr(self, "memory_panel"):
                            self.memory_panel.set_session_loading(False)

                        # Task mode and custom notepad are persisted outside saved sessions (data/user_prefs.json).

                        result["loaded"] = True
                        result["session"] = session
                        load_dialog.destroy()

                        success_msg = f"Session '{session['name']}' loaded successfully!\n\n"
                        success_msg += f"• Restored {functions_loaded} analyzed functions\n"
                        if len(rag_vectors) > 0:
                            success_msg += f"• Found {len(rag_vectors)} RAG vectors in session (use 'Load Vectors' button to create embeddings)\n"
                        success_msg += "• Session loaded without creating embeddings (prevents HuggingFace rate limiting)"

                        messagebox.showinfo("Success", success_msg)
                    else:
                        # Clear session loading flag on error
                        if hasattr(self, "memory_panel"):
                            self.memory_panel.set_session_loading(False)
                        messagebox.showerror("Error", "Failed to load session data.")

                except Exception as e:
                    # Clear session loading flag on error
                    if hasattr(self, "memory_panel"):
                        self.memory_panel.set_session_loading(False)
                    messagebox.showerror("Error", f"Failed to load session: {e}")
                    import traceback

                    logger.error(f"Load session error: {e}\n{traceback.format_exc()}")

            def cancel_load():
                load_dialog.destroy()

            ttk.Button(button_frame, text="Load Session", command=load_selected_session).pack(side="right", padx=(10, 0))
            ttk.Button(button_frame, text="Cancel", command=cancel_load).pack(side="right")

            # Wait for dialog
            load_dialog.wait_window()

        except Exception as e:
            messagebox.showerror("Error", f"Failed to open load dialog: {e}")
            import traceback

            logger.error(f"Load session error: {e}\n{traceback.format_exc()}")

    def _load_session_streaming(self, session_data: Dict[str, Any], session_info: Dict[str, Any]):
        """Load a large session using streaming to prevent UI freezing."""
        try:
            import threading
            from tkinter import messagebox, Toplevel, Label, Button, ttk

            # Create progress dialog - larger size to accommodate all elements
            progress_dialog = Toplevel(self.root)
            progress_dialog.title("Loading Large Session")
            progress_dialog.geometry("500x300")
            progress_dialog.transient(self.root)
            progress_dialog.grab_set()
            progress_dialog.resizable(False, False)

            # Center the dialog
            progress_dialog.update_idletasks()
            x = (progress_dialog.winfo_screenwidth() // 2) - (500 // 2)
            y = (progress_dialog.winfo_screenheight() // 2) - (300 // 2)
            progress_dialog.geometry(f"500x300+{x}+{y}")

            # Main content frame
            content_frame = ttk.Frame(progress_dialog)
            content_frame.pack(fill="both", expand=True, padx=20, pady=20)

            # Title
            title_label = Label(content_frame, text="Loading Large Session", font=("Arial", 14, "bold"))
            title_label.pack(pady=(0, 10))

            # Session name
            session_label = Label(content_frame, text=f"Session: {session_info['name']}", font=("Arial", 11))
            session_label.pack(pady=2)

            # File size
            file_size = session_data.get("file_size_mb", 0)
            size_label = Label(content_frame, text=f"File size: {file_size:.1f} MB", font=("Arial", 10))
            size_label.pack(pady=2)

            # Progress status
            progress_var = tk.StringVar(value="Initializing...")
            progress_label = Label(content_frame, textvariable=progress_var, font=("Arial", 10))
            progress_label.pack(pady=(10, 5))

            # Progress bar
            progress_bar = ttk.Progressbar(content_frame, mode="indeterminate", length=400)
            progress_bar.pack(pady=10, fill="x")
            progress_bar.start()

            # Function count stats
            stats_var = tk.StringVar(value="Functions loaded: 0")
            stats_label = Label(content_frame, textvariable=stats_var, font=("Arial", 10, "bold"))
            stats_label.pack(pady=5)

            # Info text
            info_label = Label(
                content_frame,
                text="Large sessions are loaded progressively to prevent UI freezing.\nThis may take a few moments...",
                font=("Arial", 9),
                justify="center",
            )
            info_label.pack(pady=10)

            # Button frame to ensure cancel button is always visible
            button_frame = ttk.Frame(content_frame)
            button_frame.pack(side="bottom", fill="x", pady=(20, 0))

            # Cancel button - centered and prominent
            cancel_requested = threading.Event()

            def cancel_load():
                cancel_requested.set()
                progress_dialog.destroy()

            cancel_button = Button(
                button_frame,
                text="Cancel Loading",
                command=cancel_load,
                font=("Arial", 10),
                bg="#ff6b6b",
                fg="white",
                relief="raised",
                bd=2,
                padx=20,
                pady=5,
            )
            cancel_button.pack(side="bottom", pady=10)

            # Loading worker
            def load_worker():
                try:
                    functions_loaded = 0

                    # Load functions in chunks
                    if hasattr(self, "renamed_functions_panel") and self.renamed_functions_panel:
                        progress_var.set("Loading functions...")

                        # Enable streaming mode to prevent individual UI updates
                        self.renamed_functions_panel.set_streaming_mode(True)

                        function_iterator = session_data.get("function_iterator")
                        if function_iterator:
                            for address, func_data in function_iterator:
                                if cancel_requested.is_set():
                                    break

                                try:
                                    self.renamed_functions_panel.add_function_with_summary(
                                        address=address,
                                        old_name=func_data.get("old_name", "Unknown"),
                                        new_name=func_data.get("new_name", "Unknown"),
                                        summary=func_data.get("behavior_summary", func_data.get("summary", "")),
                                        update_state=False,
                                    )
                                    functions_loaded += 1

                                    # Update progress every 50 functions
                                    if functions_loaded % 50 == 0:
                                        stats_var.set(f"Functions loaded: {functions_loaded}")
                                        progress_dialog.update_idletasks()

                                except Exception as e:
                                    logger.debug(f"Could not restore function {address}: {e}")

                        # Disable streaming mode and do final UI update
                        self.renamed_functions_panel.set_streaming_mode(False)

                    # Don't load RAG vectors automatically - they're too large
                    # User can load them via "Load Vectors" button

                    # Clear session loading flag
                    if hasattr(self, "memory_panel"):
                        self.memory_panel.set_session_loading(False)

                    # Task mode and custom notepad are persisted outside saved sessions (data/user_prefs.json).

                    # Close progress dialog and show success
                    if not cancel_requested.is_set():
                        progress_dialog.destroy()

                        success_msg = f"Large session '{session_info['name']}' loaded successfully!\n\n"
                        success_msg += f"• Restored {functions_loaded} analyzed functions\n"
                        success_msg += f"• File size: {file_size:.1f} MB\n"
                        success_msg += "• RAG vectors available but not loaded (use 'Load Vectors' button)\n"
                        success_msg += "• Streaming load prevented UI freezing"

                        messagebox.showinfo("Success", success_msg)

                except Exception as e:
                    # Clear session loading flag on error
                    if hasattr(self, "memory_panel"):
                        self.memory_panel.set_session_loading(False)

                    progress_dialog.destroy()
                    messagebox.showerror("Error", f"Failed to load session: {e}")
                    import traceback

                    logger.error(f"Streaming load error: {e}\n{traceback.format_exc()}")

            # Start loading in background thread
            threading.Thread(target=load_worker, daemon=True).start()

        except Exception as e:
            # Clear session loading flag on error
            if hasattr(self, "memory_panel"):
                self.memory_panel.set_session_loading(False)
            messagebox.showerror("Error", f"Failed to setup streaming load: {e}")
            import traceback

            logger.error(f"Streaming setup error: {e}\n{traceback.format_exc()}")

    def _health_check(self):
        """Perform a health check."""

        def check():
            results = []

            # Check Ollama
            try:
                ollama_health = self.bridge.ollama.check_health()
                results.append(f"Ollama API: {'OK ✅' if ollama_health else 'NOT OK ❌'}")
            except Exception as e:
                results.append(f"Ollama API: ERROR - {e}")

            # Check Ghidra backend (HTTP MCP server or pyGhidra)
            try:
                ghidra_health = self.bridge.ghidra.check_health()
                # Decide label based on configured backend
                backend = getattr(self.config.ghidra, "backend", "http")
                if backend == "pyghidra":
                    label = "PyGhidra API"
                else:
                    label = "GhidraMCP API"

                results.append(f"{label}: {'OK ✅' if ghidra_health else 'NOT OK ❌'}")
            except Exception as e:
                backend = getattr(self.config.ghidra, "backend", "http")
                label = "PyGhidra API" if backend == "pyghidra" else "GhidraMCP API"
                results.append(f"{label}: ERROR - {e}")

            # Check CAG
            try:
                cag_enabled = getattr(self.bridge, "enable_cag", False)
                results.append(f"CAG System: {'Enabled ✅' if cag_enabled else 'Disabled ❌'}")
            except Exception as e:
                results.append(f"CAG System: ERROR - {e}")

            # Show results
            messagebox.showinfo("Health Check", "\n".join(results))

        threading.Thread(target=check, daemon=True).start()

    def _show_system_info(self):
        """Show system information dialog with CAG/RAG controls and memory stats."""
        dialog = tk.Toplevel(self.root)
        dialog.title("System Information")
        dialog.geometry("500x700")
        dialog.transient(self.root)
        dialog.grab_set()

        # Center the dialog
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() - 500) // 2
        y = (dialog.winfo_screenheight() - 700) // 2
        dialog.geometry(f"+{x}+{y}")

        main_frame = ttk.Frame(dialog, padding=15)
        main_frame.pack(fill="both", expand=True)

        # CAG System Controls
        cag_frame = ttk.LabelFrame(main_frame, text="Context-Augmented Generation (CAG)", padding=10)
        cag_frame.pack(fill="x", pady=(0, 10))

        cag_enabled = getattr(self.bridge, "enable_cag", False)
        cag_status = ttk.Label(
            cag_frame, text=f"Status: {'Enabled' if cag_enabled else 'Disabled'}", foreground="green" if cag_enabled else "gray"
        )
        cag_status.pack(anchor="w")

        cag_var = tk.BooleanVar(value=cag_enabled)

        def toggle_cag():
            self.bridge.enable_cag = cag_var.get()
            cag_status.config(
                text=f"Status: {'Enabled' if cag_var.get() else 'Disabled'}", foreground="green" if cag_var.get() else "gray"
            )

        cag_check = ttk.Checkbutton(cag_frame, text="Enable CAG", variable=cag_var, command=toggle_cag)
        cag_check.pack(anchor="w", pady=(5, 0))

        # RAG System Controls
        rag_frame = ttk.LabelFrame(main_frame, text="Retrieval-Augmented Generation (RAG)", padding=10)
        rag_frame.pack(fill="x", pady=(0, 10))

        # Helper function to get current vector count
        def get_vector_count():
            count = 0
            if hasattr(self.bridge, "cag_manager") and self.bridge.cag_manager:
                vector_store = self.bridge.cag_manager.vector_store
                if vector_store and hasattr(vector_store, "embeddings") and vector_store.embeddings is not None:
                    try:
                        count = len(vector_store.embeddings)
                    except Exception as e:
                        logger.warning(f"Failed to get the vector count from the vector store embeddings : {e}")
                        pass
            return count

        # Get initial values
        rag_enabled = False
        if hasattr(self.bridge, "cag_manager") and self.bridge.cag_manager:
            rag_enabled = getattr(self.bridge.cag_manager, "use_vector_store_for_prompts", True)

        rag_status = ttk.Label(
            rag_frame,
            text=f"Status: {'Enabled' if rag_enabled else 'Disabled'} ({get_vector_count()} vectors)",
            foreground="green" if rag_enabled else "gray",
        )
        rag_status.pack(anchor="w")

        rag_var = tk.BooleanVar(value=rag_enabled)

        def toggle_rag():
            if hasattr(self.bridge, "cag_manager") and self.bridge.cag_manager:
                self.bridge.cag_manager.use_vector_store_for_prompts = rag_var.get()
            # Refresh vector count when toggling
            current_count = get_vector_count()
            rag_status.config(
                text=f"Status: {'Enabled' if rag_var.get() else 'Disabled'} ({current_count} vectors)",
                foreground="green" if rag_var.get() else "gray",
            )

        rag_check = ttk.Checkbutton(rag_frame, text="Enable RAG", variable=rag_var, command=toggle_rag)
        rag_check.pack(anchor="w", pady=(5, 0))

        # Add refresh button for vector count
        def refresh_rag_status():
            current_count = get_vector_count()
            is_enabled = rag_var.get()
            rag_status.config(
                text=f"Status: {'Enabled' if is_enabled else 'Disabled'} ({current_count} vectors)",
                foreground="green" if is_enabled else "gray",
            )

        ttk.Button(rag_frame, text="Refresh Count", command=refresh_rag_status).pack(anchor="w", pady=(5, 0))

        # Memory Stats
        stats_frame = ttk.LabelFrame(main_frame, text="Memory Statistics", padding=10)
        stats_frame.pack(fill="both", expand=True, pady=(0, 10))

        stats_text = scrolledtext.ScrolledText(
            stats_frame,
            height=10,
            relief="flat",
            borderwidth=1,
            padx=6,
            pady=6,
        )
        stats_text.pack(fill="both", expand=True)

        # Populate memory stats
        def refresh_stats():
            stats_text.delete(1.0, tk.END)
            try:
                import psutil

                process = psutil.Process()
                mem_info = process.memory_info()

                stats = []
                stats.append(f"Process Memory: {mem_info.rss / 1024 / 1024:.1f} MB")
                stats.append(f"Virtual Memory: {mem_info.vms / 1024 / 1024:.1f} MB")
                stats.append("")

                # Bridge stats
                if hasattr(self.bridge, "function_summaries"):
                    stats.append(f"Analyzed Functions: {len(self.bridge.function_summaries)}")
                if hasattr(self.bridge, "function_address_mapping"):
                    stats.append(f"Function Mappings: {len(self.bridge.function_address_mapping)}")

                # Vector store stats
                if hasattr(self.bridge, "cag_manager") and self.bridge.cag_manager:
                    vs = self.bridge.cag_manager.vector_store
                    if vs:
                        doc_count = len(vs.documents) if hasattr(vs, "documents") and vs.documents else 0
                        emb_count = len(vs.embeddings) if hasattr(vs, "embeddings") and vs.embeddings else 0
                        stats.append(f"Vector Documents: {doc_count}")
                        stats.append(f"Vector Embeddings: {emb_count}")

                stats_text.insert(1.0, "\n".join(stats))
            except ImportError:
                stats_text.insert(1.0, "Install psutil for detailed memory stats:\npip install psutil")
            except Exception as e:
                stats_text.insert(1.0, f"Error getting stats: {e}")

        refresh_stats()

        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill="x")

        ttk.Button(button_frame, text="Refresh", command=refresh_stats).pack(side="left")
        ttk.Button(button_frame, text="Close", command=dialog.destroy).pack(side="right")

    def _configure_servers(self):
        """Open server configuration dialog."""
        try:
            dialog = ServerConfigDialog(self.root, self.config)
            if dialog.result:
                # Configuration was saved successfully

                # Dynamically reload the LLM client to reflect changes (e.g. switching providers)
                if hasattr(self.bridge, "reload_llm_client"):
                    self.bridge.reload_llm_client()
                else:
                    # Fallback for manual updates if method missing
                    self.bridge.ollama.base_url = str(self.config.ollama.base_url).rstrip("/")
                    self.bridge.ollama.default_model = self.config.ollama.model

                # Update Ghidra client configuration (always manual update as it's less complex)
                if hasattr(self.bridge, "ghidra_client") and self.bridge.ghidra_client:
                    self.bridge.ghidra_client.config.base_url = str(self.config.ghidra.base_url).rstrip("/")

                messagebox.showinfo(
                    "Configuration Updated",
                    "Server configuration has been updated and reloaded.\n\n"
                    "You can now use the new provider/settings immediately.",
                )
        except Exception as e:
            messagebox.showerror("Configuration Error", f"Failed to configure servers: {e}")

    def _clear_all_data(self):
        """Clear all data."""
        if messagebox.askyesno("Confirm", "Are you sure you want to clear all data? This action cannot be undone."):
            try:
                # Clear response panel
                self.response_panel._clear_responses()

                # Clear query input
                self.query_panel._clear_query()

                # Reset bridge state
                if hasattr(self.bridge, "analysis_state"):
                    self.bridge.analysis_state = {
                        "functions_decompiled": set(),
                        "functions_renamed": {},
                        "comments_added": {},
                        "functions_analyzed": set(),
                    }

                # Clear function address mapping and summaries
                if hasattr(self.bridge, "function_address_mapping"):
                    self.bridge.function_address_mapping = {}
                if hasattr(self.bridge, "function_summaries"):
                    self.bridge.function_summaries = {}

                # Clear renamed functions panel
                if hasattr(self, "renamed_functions_panel"):
                    self.renamed_functions_panel.function_summaries = {}
                    self.renamed_functions_panel._update_function_list()

                # Reset workflow
                self.workflow_diagram.set_current_stage(None)

                # Update memory info
                self.memory_panel._update_memory_info()

                messagebox.showinfo("Success", "All data cleared.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to clear data: {e}")

    # ========== Analysis Menu Handlers ==========

    def _menu_analyze_current(self):
        """Menu handler: Analyze Current Function."""
        if hasattr(self, "tool_panel"):
            self.tool_panel._analyze_current_function()

    def _menu_rename_current(self):
        """Menu handler: Rename Current Function."""
        if hasattr(self, "tool_panel"):
            self.tool_panel._rename_current_function()

    def _menu_rename_all(self):
        """Menu handler: Rename All Functions."""
        if hasattr(self, "tool_panel"):
            self.tool_panel._rename_all_functions()

    def _menu_generate_report(self):
        """Menu handler: Generate Software Report."""
        if hasattr(self, "tool_panel"):
            self.tool_panel._generate_software_report()

    def _menu_analyze_imports(self):
        """Menu handler: Analyze Imports."""
        if hasattr(self, "tool_panel"):
            self.tool_panel._analyze_imports()

    def _menu_analyze_exports(self):
        """Menu handler: Analyze Exports."""
        if hasattr(self, "tool_panel"):
            self.tool_panel._analyze_exports()

    def _menu_analyze_strings(self):
        """Menu handler: Analyze Strings."""
        if hasattr(self, "tool_panel"):
            self.tool_panel._analyze_strings()

    def _menu_search_strings(self):
        """Menu handler: Search Strings."""
        if hasattr(self, "tool_panel"):
            self.tool_panel._search_strings()

    def _menu_scan_tables(self):
        """Menu handler: Scan Function Tables."""
        if hasattr(self, "tool_panel"):
            self.tool_panel._scan_function_tables()

    def _show_about(self):
        """Show about dialog."""
        about_text = """OGhidra - Ollama-GhidraMCP Bridge
Version 1.0

An AI-powered reverse engineering toolkit that bridges
Ollama language models with Ghidra through MCP.

Features:
• Cache-Augmented Generation (CAG)
• Vector embeddings for knowledge retrieval
• Three-phase agentic workflow
• Interactive GUI interface
• Smart function analysis and renaming

© 2024 OGhidra Team"""

        messagebox.showinfo("About OGhidra", about_text)

    def _quit_application(self):
        """Quit the application."""
        if messagebox.askyesno("Quit", "Are you sure you want to quit?"):
            try:
                # Save session before quitting
                if hasattr(self.bridge, "cag_manager") and self.bridge.cag_manager:
                    self.bridge.cag_manager.save_session()
                # Best-effort: close any Ghidra client (including pyGhidra
                # backend) so projects/programs are released cleanly.
                if hasattr(self.bridge, "ghidra_client") and self.bridge.ghidra_client:
                    try:
                        self.bridge.ghidra_client.close()
                    except Exception as e:
                        logger.error(f"Error closing Ghidra client on quit: {e}")
            except Exception as e:
                logger.error(f"Error saving session on quit: {e}")

            self.root.quit()
            self.root.destroy()

    def run(self):
        """Run the UI main loop."""
        try:
            self.root.mainloop()
        except KeyboardInterrupt:
            self._quit_application()


def launch_ui(bridge: Bridge, config: BridgeConfig):
    """Launch the OGhidra UI."""
    try:
        ui = OGhidraUI(bridge, config)
        logger.info("Launching OGhidra UI...")
        ui.run()

    except ImportError as e:
        print(f"Error: Unable to import tkinter. GUI mode not available: {e}")
        return False
    except Exception as e:
        logger.error(f"Error launching UI: {e}")
        print(f"Error launching UI: {e}")
        return False

    return True
