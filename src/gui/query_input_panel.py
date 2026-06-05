import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time
from ..bridge import Bridge
from .ai_response_panel import AIResponsePanel
from .workflow_diagram import WorkflowDiagram
import logging

logger = logging.getLogger(__name__)


class QueryInputPanel:
    """Panel for AI agent query input."""

    def __init__(self, parent, bridge: Bridge, response_panel: AIResponsePanel, workflow_diagram: WorkflowDiagram):
        self.frame = ttk.LabelFrame(parent, text="AI Query", padding=10)
        self.bridge = bridge
        self.response_panel = response_panel
        self.workflow_diagram = workflow_diagram
        self.query_running = False
        self.should_stop = False  # Flag to control stopping
        self._setup_widgets()

    def _setup_widgets(self):
        """Setup the query input widgets."""
        # Query input
        ttk.Label(self.frame, text="Enter your query:", font=("Arial", 10, "bold")).grid(
            row=0, column=0, sticky="w", pady=(0, 5)
        )

        self.query_entry = tk.Text(
            self.frame,
            height=3,
            width=60,
            font=("Segoe UI", 11),
            wrap=tk.WORD,
            relief="flat",
            borderwidth=1,
            padx=6,
            pady=6,
        )
        self.query_entry.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(0, 10))

        # Task mode controls (simple UI toggle + mode selection)
        taskmode_frame = ttk.Frame(self.frame)
        taskmode_frame.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(0, 6))
        taskmode_frame.grid_columnconfigure(3, weight=1)

        self.task_mode_enabled_var = tk.BooleanVar(value=False)
        self.task_mode_var = tk.StringVar(value="purpose_id")

        # Initialize from Bridge if available (sticky across restarts)
        try:
            if hasattr(self.bridge, "get_task_mode_state"):
                st = self.bridge.get_task_mode_state()
                if isinstance(st, dict):
                    self.task_mode_enabled_var.set(bool(st.get("enabled", False)))
                    mode = str(st.get("mode", "off") or "off")
                    if mode in ("purpose_id", "malware", "vuln", "custom"):
                        self.task_mode_var.set(mode)
                    else:
                        self.task_mode_var.set("purpose_id")
        except Exception:
            pass

        self.task_mode_check = ttk.Checkbutton(
            taskmode_frame, text="Task Mode", variable=self.task_mode_enabled_var, command=self._on_task_mode_change
        )
        self.task_mode_check.grid(row=0, column=0, sticky="w")

        ttk.Label(taskmode_frame, text="Mode:").grid(row=0, column=1, sticky="w", padx=(10, 4))
        self.task_mode_combo = ttk.Combobox(
            taskmode_frame,
            textvariable=self.task_mode_var,
            values=["purpose_id", "malware", "vuln", "custom"],
            state="readonly",
            width=12,
        )
        self.task_mode_combo.grid(row=0, column=2, sticky="w")
        self.task_mode_combo.bind("<<ComboboxSelected>>", lambda e: self._on_task_mode_change())

        self.task_mode_status = ttk.Label(taskmode_frame, text="Off", foreground="gray")
        self.task_mode_status.grid(row=0, column=3, sticky="e")

        # Apply initial status
        self._on_task_mode_change()

        # Grep Layer Frame (NEW) - for hybrid search functionality
        # Note: This should be placed in the grid right after taskmode_frame (row 2, after row 2 which is taskmode)
        grep_container = ttk.Frame(self.frame)
        grep_container.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(0, 6))

        grep_frame = ttk.LabelFrame(grep_container, text="Function Search", padding=(10, 5))
        grep_frame.pack(fill="x", expand=True)

        # Initialize grep layer variable
        self.grep_enabled_var = tk.BooleanVar(value=False)

        # Try to restore previous grep state from bridge
        try:
            if hasattr(self.bridge, "grep_layer_enabled"):
                self.grep_enabled_var.set(bool(self.bridge.grep_layer_enabled))
        except Exception:
            pass

        self.grep_check = ttk.Checkbutton(
            grep_frame, text="Enable Hybrid Search", variable=self.grep_enabled_var, command=self._on_grep_layer_change
        )
        self.grep_check.grid(row=0, column=0, sticky="w")

        self.grep_status = ttk.Label(grep_frame, text="Off - No summaries loaded", foreground="gray")
        self.grep_status.grid(row=0, column=1, padx=(10, 0), sticky="w")

        # Info label
        info_label = ttk.Label(
            grep_frame,
            text="Combines keyword search + semantic embeddings for finding functions",
            font=("TkDefaultFont", 8),
            foreground="gray",
        )
        info_label.grid(row=1, column=0, columnspan=2, sticky="w", pady=(2, 0))

        grep_frame.columnconfigure(1, weight=1)

        # Call initial update
        self._on_grep_layer_change()

        # Buttons
        button_frame = ttk.Frame(self.frame)
        button_frame.grid(row=4, column=0, columnspan=2, sticky="ew")

        self.send_button = ttk.Button(button_frame, text="Send Query", command=self._send_query)
        self.send_button.pack(side="left", padx=(0, 5))

        ttk.Button(button_frame, text="Clear", command=self._clear_query).pack(side="left", padx=(0, 15))

        # Separator
        ttk.Separator(button_frame, orient="vertical").pack(side="left", fill="y", padx=(0, 15), pady=2)

        # Quick action buttons for common smart tools
        self.analyze_button = ttk.Button(button_frame, text="Analyze Function", command=self._analyze_current)
        self.analyze_button.pack(side="left", padx=(0, 5))

        self.rename_button = ttk.Button(button_frame, text="Rename Function", command=self._rename_current)
        self.rename_button.pack(side="left")

        # Status and progress
        self.status_label = ttk.Label(self.frame, text="Ready", foreground="green")
        self.status_label.grid(row=5, column=0, columnspan=2, pady=(10, 0))

        # Progress bar and stop button frame
        progress_frame = ttk.Frame(self.frame)
        progress_frame.grid(row=6, column=0, columnspan=2, sticky="ew", pady=(5, 0))
        progress_frame.grid_columnconfigure(0, weight=1)

        self.progress = ttk.Progressbar(progress_frame, mode="indeterminate")
        self.progress.grid(row=0, column=0, sticky="ew", padx=(0, 5))

        self.stop_button = ttk.Button(progress_frame, text="Stop", command=self._stop_query, state="disabled", width=8)
        self.stop_button.grid(row=0, column=1)

        # Configure grid weights
        self.frame.grid_columnconfigure(0, weight=1)

        # Bind Enter key (Ctrl+Enter to send)
        self.query_entry.bind("<Control-Return>", lambda e: self._send_query())

    def _send_query(self):
        """Send the query to the AI agent."""
        if self.query_running:
            return

        query = self.query_entry.get(1.0, tk.END).strip()
        if not query:
            messagebox.showwarning("Empty Query", "Please enter a query.")
            return

        def worker():
            try:
                self._set_query_running(True)

                # Add query to response panel
                self.response_panel.add_response("User Query", query)

                # Start monitoring workflow in a separate thread
                monitor_thread = threading.Thread(target=self._monitor_workflow_stage, daemon=True)
                monitor_thread.start()

                # Process query with full AI agent workflow
                # Apply task mode (if enabled) to bridge before processing
                try:
                    if hasattr(self.bridge, "set_task_mode"):
                        enabled = bool(self.task_mode_enabled_var.get())
                        mode = str(self.task_mode_var.get())
                        self.bridge.set_task_mode(enabled=enabled, mode=mode)
                except Exception:
                    pass

                result = self.bridge.process_query(query)

                # Add result to response panel
                self.response_panel.add_response("AI Agent Response", result)

                # Final stage update
                self.workflow_diagram.set_current_stage(None)

            except Exception as e:
                error_msg = f"Error processing query: {e}"
                logger.error(error_msg)
                self.response_panel.add_response("Error", error_msg)
                self.workflow_diagram.set_current_stage(None)
            finally:
                self._set_query_running(False)

        threading.Thread(target=worker, daemon=True).start()

    def _on_task_mode_change(self):
        """Update task mode status label and push state to bridge."""
        enabled = bool(self.task_mode_enabled_var.get())
        mode = str(self.task_mode_var.get())
        if enabled:
            self.task_mode_status.config(text=f"On ({mode})", foreground="green")
        else:
            self.task_mode_status.config(text="Off", foreground="gray")

        try:
            if hasattr(self.bridge, "set_task_mode"):
                self.bridge.set_task_mode(enabled=enabled, mode=mode)
        except Exception:
            pass

    def _on_grep_layer_change(self):
        """Handle grep layer checkbox changes."""
        enabled = bool(self.grep_enabled_var.get())

        # Check if we have function summaries available
        has_summaries = False
        summary_count = 0

        try:
            if hasattr(self, "renamed_functions_panel") and self.renamed_functions_panel:
                # RenamedFunctionsPanel stores entries in a Treeview; count rows.
                if hasattr(self.renamed_functions_panel, "tree"):
                    summary_count = len(self.renamed_functions_panel.tree.get_children())
                    has_summaries = summary_count > 0
                elif hasattr(self.renamed_functions_panel, "function_summaries"):
                    summary_count = len(self.renamed_functions_panel.function_summaries)
                    has_summaries = summary_count > 0
        except Exception:
            pass

        # Update status label
        if enabled:
            if has_summaries:
                self.grep_status.config(text=f"On - {summary_count} function(s) indexed", foreground="green")
            else:
                self.grep_status.config(text="On - Waiting for summaries", foreground="orange")
        else:
            if has_summaries:
                self.grep_status.config(text=f"Off - {summary_count} function(s) available", foreground="gray")
            else:
                self.grep_status.config(text="Off - No summaries loaded", foreground="gray")

        # Update bridge
        try:
            if hasattr(self.bridge, "set_grep_layer_enabled"):
                self.bridge.set_grep_layer_enabled(enabled)
            else:
                # Set attribute directly if method doesn't exist yet
                self.bridge.grep_layer_enabled = enabled

            logger.info(f"Grep layer {'enabled' if enabled else 'disabled'} ({summary_count} functions available)")
        except Exception as e:
            logger.error(f"Error setting grep layer: {e}")

    def _clear_query(self):
        """Clear the query input."""
        self.query_entry.delete(1.0, tk.END)

    def _analyze_current(self):
        """Analyze the current function in Ghidra."""
        if hasattr(self, "tool_panel") and self.tool_panel:
            self.tool_panel._analyze_current_function()
        else:
            messagebox.showwarning("Not Ready", "Tool panel not initialized yet.")

    def _rename_current(self):
        """Rename the current function in Ghidra based on AI analysis."""
        if hasattr(self, "tool_panel") and self.tool_panel:
            self.tool_panel._rename_current_function()
        else:
            messagebox.showwarning("Not Ready", "Tool panel not initialized yet.")

    def _stop_query(self):
        """Stop the currently running query."""
        if self.query_running:
            self.should_stop = True
            self.response_panel.add_response("User Action", "🛑 Query cancellation requested...")
            self._set_query_running(False)

    def _set_query_running(self, running: bool):
        """Set the query running state."""
        self.query_running = running

        # Update button states
        state = "disabled" if running else "normal"
        self.send_button.config(state=state)
        self.analyze_button.config(state=state)
        self.rename_button.config(state=state)
        self.stop_button.config(state="normal" if running else "disabled")

        # Update status and progress
        if running:
            self.should_stop = False  # Reset stop flag for new query
            self.status_label.config(text="Processing query...", foreground="orange")
            self.progress.start()
        else:
            self.status_label.config(text="Ready", foreground="green")
            self.progress.stop()

    def _monitor_workflow_stage(self):
        """Monitor the bridge's workflow stage and update the diagram."""
        previous_stage = None
        while self.query_running:
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

    def get_widget(self):
        """Return the frame widget."""
        return self.frame
