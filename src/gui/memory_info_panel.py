import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from ..bridge import Bridge

import logging

logger = logging.getLogger(__name__)


class MemoryInfoPanel:
    """Panel for displaying memory and system information."""

    def __init__(self, parent, bridge: Bridge):
        self.bridge = bridge
        self.frame = ttk.LabelFrame(parent, text="Memory & System Info", padding="10")
        self._setup_widgets()
        self._start_auto_refresh()

        # Flag to prevent initialization during session loading
        self._session_loading = False

    def _setup_widgets(self):
        """Setup the memory info widgets."""
        # CAG System Controls
        cag_frame = ttk.Frame(self.frame)
        cag_frame.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 5))

        ttk.Label(cag_frame, text="CAG System:", font=("Arial", 10, "bold")).pack(side="left")
        self.cag_status = ttk.Label(cag_frame, text="Unknown")
        self.cag_status.pack(side="left", padx=(10, 15))

        self.cag_var = tk.BooleanVar()
        self.cag_checkbox = ttk.Checkbutton(cag_frame, text="Enable CAG", variable=self.cag_var, command=self._toggle_cag)
        self.cag_checkbox.pack(side="left")

        # RAG/Vector Store Controls
        rag_frame = ttk.Frame(self.frame)
        rag_frame.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(0, 5))

        ttk.Label(rag_frame, text="RAG System:", font=("Arial", 10, "bold")).pack(side="left")
        self.vector_status = ttk.Label(rag_frame, text="Unknown")
        self.vector_status.pack(side="left", padx=(10, 15))

        self.rag_var = tk.BooleanVar()
        self.rag_checkbox = ttk.Checkbutton(rag_frame, text="Enable RAG", variable=self.rag_var, command=self._toggle_rag)
        self.rag_checkbox.pack(side="left")

        # Memory Stats
        ttk.Label(self.frame, text="Memory Stats:", font=("Arial", 10, "bold")).grid(row=2, column=0, sticky="nw", pady=(5, 0))

        self.memory_text = scrolledtext.ScrolledText(
            self.frame,
            height=8,
            width=60,
            relief="flat",
            borderwidth=1,
            padx=6,
            pady=6,
        )
        self.memory_text.grid(row=3, column=0, columnspan=2, sticky="nsew", pady=(5, 0))

        # Configure grid weights to make memory text expand
        self.frame.grid_rowconfigure(3, weight=1)
        self.frame.grid_columnconfigure(0, weight=1)

        # Refresh button
        ttk.Button(self.frame, text="Refresh", command=self._update_memory_info).grid(
            row=4, column=0, columnspan=2, pady=(10, 0)
        )

        # Start auto-refresh
        self._update_memory_info()
        self._start_auto_refresh()

    def _update_memory_info(self):
        """Update memory information display."""
        try:
            # Skip expensive operations during session loading
            if getattr(self, "_session_loading", False):
                self.memory_text.delete(1.0, tk.END)
                self.memory_text.insert(1.0, "Session loading... Memory info will update after loading completes.")
                return

            # CAG Status
            cag_enabled = getattr(self.bridge, "enable_cag", False)
            self.cag_status.config(text="Enabled ✅" if cag_enabled else "Disabled ❌")
            self.cag_var.set(cag_enabled)

            # RAG/Vector Store Status
            rag_enabled = False
            vector_count = 0

            # Check if session history has vector embeddings enabled
            if hasattr(self.bridge, "config") and hasattr(self.bridge.config, "session_history"):
                rag_enabled = getattr(self.bridge.config.session_history, "use_vector_embeddings", False)

            # Check for actual vector store data (only if not session loading)
            if hasattr(self.bridge, "memory_manager") and self.bridge.memory_manager:
                mm = self.bridge.memory_manager
                if hasattr(mm, "vector_store") and mm.vector_store:
                    if (
                        hasattr(mm.vector_store, "vectors")
                        and mm.vector_store.vectors is not None
                        and hasattr(mm.vector_store.vectors, "shape")
                    ):
                        vector_count = mm.vector_store.vectors.shape[0]

            # Also check CAG manager for vector store (only if already initialized)
            if hasattr(self.bridge, "cag_manager") and self.bridge.cag_manager:
                # Check if RAG is actually enabled (not just if vector store exists)
                rag_enabled = getattr(self.bridge.cag_manager, "use_vector_store_for_prompts", True)

                # Get vector store - this will trigger lazy initialization if Ollama is available
                vector_store = self.bridge.cag_manager.vector_store
                if vector_store and rag_enabled:
                    # Get vector count from CAG manager
                    if hasattr(vector_store, "embeddings") and vector_store.embeddings is not None:
                        try:
                            cag_vector_count = len(vector_store.embeddings)
                            vector_count = max(vector_count, cag_vector_count)
                        except (TypeError, AttributeError):
                            # Handle case where embeddings might be a numpy array or other format
                            if hasattr(vector_store.embeddings, "shape"):
                                cag_vector_count = (
                                    vector_store.embeddings.shape[0] if len(vector_store.embeddings.shape) > 0 else 0
                                )
                                vector_count = max(vector_count, cag_vector_count)
                    elif hasattr(vector_store, "documents") and vector_store.documents:
                        # Fallback: count documents if embeddings not available
                        cag_vector_count = len(vector_store.documents)
                        vector_count = max(vector_count, cag_vector_count)

            self.vector_status.config(text=f"{'Enabled' if rag_enabled else 'Disabled'} ({vector_count} vectors)")
            self.rag_var.set(rag_enabled)

            # Memory Stats
            stats_text = self._get_memory_stats()
            self.memory_text.delete(1.0, tk.END)
            self.memory_text.insert(1.0, stats_text)

        except Exception as e:
            logger.error(f"Error updating memory info: {e}")
            self.memory_text.delete(1.0, tk.END)
            self.memory_text.insert(1.0, f"Error updating memory info: {e}")

    def _toggle_cag(self):
        """Toggle CAG system on/off."""
        try:
            new_state = self.cag_var.get()

            # Update bridge configuration
            if hasattr(self.bridge, "config"):
                self.bridge.config.cag_enabled = new_state
                self.bridge.config.enable_cag = new_state

            self.bridge.enable_cag = new_state

            # If enabling CAG, try to reinitialize CAG manager
            if new_state and (not hasattr(self.bridge, "cag_manager") or not self.bridge.cag_manager):
                try:
                    from src.cag import CAGManager

                    self.bridge.cag_manager = CAGManager(self.bridge.config)
                    self.bridge.memory_manager = getattr(self.bridge.cag_manager, "memory_manager", None)
                    logger.info("CAG Manager reinitialized")
                except Exception as e:
                    logger.error(f"Failed to reinitialize CAG Manager: {e}")
                    messagebox.showerror(
                        "CAG Error",
                        f"Failed to enable CAG: {e}\n\nThis may be due to configuration issues. Check that your .env file is properly configured.",
                    )
                    self.cag_var.set(False)
                    return

            # If disabling CAG, clean up
            elif not new_state:
                if hasattr(self.bridge, "cag_manager") and self.bridge.cag_manager:
                    # Save session before disabling
                    try:
                        self.bridge.cag_manager.save_session()
                    except Exception as e:
                        logger.warning(f"Failed to save session for the CAG manager: {e}")
                        pass
                    self.bridge.cag_manager = None
                    self.bridge.memory_manager = None

            # Refresh display
            self._update_memory_info()

            status = "enabled" if new_state else "disabled"
            messagebox.showinfo("CAG System", f"Cache-Augmented Generation system has been {status}.")

        except Exception as e:
            logger.error(f"Error toggling CAG: {e}")
            messagebox.showerror("Error", f"Failed to toggle CAG system: {e}")
            # Revert checkbox
            self.cag_var.set(not self.cag_var.get())

    def _toggle_rag(self):
        """Toggle RAG system on/off."""
        try:
            new_state = self.rag_var.get()

            # Update session history configuration
            if hasattr(self.bridge, "config") and hasattr(self.bridge.config, "session_history"):
                self.bridge.config.session_history.use_vector_embeddings = new_state

            if new_state:
                # Enabling RAG - check if CAG is enabled (but don't force it)
                if not getattr(self.bridge, "enable_cag", False):
                    response = messagebox.askyesnocancel(
                        "CAG Required",
                        "RAG system works best with CAG enabled for enhanced context.\n\n"
                        "• Yes: Enable both CAG and RAG\n"
                        "• No: Enable RAG only (limited functionality)\n"
                        "• Cancel: Keep current settings",
                    )
                    if response is True:  # Yes - enable both
                        self.cag_var.set(True)
                        self._toggle_cag()
                    elif response is False:  # No - RAG only
                        messagebox.showwarning(
                            "Limited RAG", "RAG enabled without CAG. Functionality will be limited to basic vector embeddings."
                        )
                    else:  # Cancel
                        self.rag_var.set(False)
                        return
            else:
                # Disabling RAG - ask if user wants to disable CAG too
                if getattr(self.bridge, "enable_cag", False):
                    response = messagebox.askyesno(
                        "Disable CAG Too?",
                        "RAG is provided by the CAG system. Would you like to disable CAG entirely?\n\n"
                        "• Yes: Disable both CAG and RAG (saves memory)\n"
                        "• No: Keep CAG enabled (RAG will still be disabled)",
                    )
                    if response:  # Yes - disable CAG too
                        self.cag_var.set(False)
                        self._toggle_cag()

                # If CAG manager exists, disable vector store usage for prompts
                if hasattr(self.bridge, "cag_manager") and self.bridge.cag_manager:
                    # Set a flag to disable vector store usage in prompts
                    self.bridge.cag_manager.use_vector_store_for_prompts = False
                    logger.info("Disabled vector store usage for RAG prompts")

            # Re-enable vector store usage if enabling RAG
            if new_state and hasattr(self.bridge, "cag_manager") and self.bridge.cag_manager:
                self.bridge.cag_manager.use_vector_store_for_prompts = True
                logger.info("Enabled vector store usage for RAG prompts")

            # Refresh display
            self._update_memory_info()

            status = "enabled" if new_state else "disabled"
            if new_state and not getattr(self.bridge, "enable_cag", False):
                messagebox.showinfo(
                    "RAG System", f"RAG system {status} (basic mode - consider enabling CAG for full functionality)."
                )
            else:
                messagebox.showinfo("RAG System", f"RAG system {status}.")

        except Exception as e:
            logger.error(f"Error toggling RAG: {e}")
            messagebox.showerror("Error", f"Failed to toggle RAG system: {e}")
            # Revert checkbox
            self.rag_var.set(not self.rag_var.get())

    def _start_auto_refresh(self):
        """Start auto-refresh timer for memory info."""

        def refresh():
            try:
                self._update_memory_info()
            except Exception as e:
                logger.error(f"Error in auto-refresh: {e}")
            # Schedule next refresh in 30 seconds
            self.frame.after(30000, refresh)

        # Start the refresh cycle
        self.frame.after(30000, refresh)

    def _get_memory_stats(self) -> str:
        """Get formatted memory statistics."""
        stats = []

        try:
            # CAG Manager stats
            if hasattr(self.bridge, "cag_manager") and self.bridge.cag_manager:
                debug_info = self.bridge.cag_manager.get_debug_info()
                stats.append("=== CAG System ===")
                stats.append(f"Knowledge Base: {'Enabled' if debug_info.get('enable_kb', False) else 'Disabled'}")

                if "vector_store" in debug_info:
                    vs_info = debug_info["vector_store"]
                    if "vector_count" in vs_info:
                        # New combined vector store format
                        stats.append(f"Vector Count: {vs_info.get('vector_count', 0)}")
                        stats.append(f"Document Count: {vs_info.get('document_count', 0)}")
                        stats.append(f"Vector Dimensions: {vs_info.get('dimensions', 'N/A')}")
                    else:
                        # Current format - get actual counts from vector store
                        doc_count = vs_info.get("document_count", 0)
                        vector_count = vs_info.get("vector_count", 0)
                        dimensions = vs_info.get("dimensions", "N/A")

                        stats.append(f"Document Count: {doc_count}")
                        stats.append(f"Vector Count: {vector_count}")
                        stats.append(f"Vector Dimensions: {dimensions}")

                        # Show legacy components if they exist
                        legacy_count = (
                            vs_info.get("function_signatures", 0)
                            + vs_info.get("binary_patterns", 0)
                            + vs_info.get("analysis_rules", 0)
                            + vs_info.get("common_workflows", 0)
                        )
                        if legacy_count > 0:
                            stats.append(f"Legacy Vector Components: {legacy_count}")

                if "session" in debug_info:
                    s_info = debug_info["session"]
                    stats.append(f"Session ID: {s_info.get('session_id', 'unknown')}")
                    stats.append(f"Messages: {s_info.get('messages', 0)}")
                    stats.append(f"Tool Executions: {s_info.get('tool_executions', 0)}")
                    stats.append(f"Decompiled Functions: {s_info.get('decompiled_functions', 0)}")
                    stats.append(f"Analysis Results: {s_info.get('analysis_results', 0)}")

                # Add cache statistics
                if "cache_stats" in debug_info and debug_info["cache_stats"] != "unavailable":
                    cache_info = debug_info["cache_stats"]
                    stats.append("")
                    stats.append("=== Performance Cache ===")
                    stats.append(f"Cache Hits: {cache_info.get('hits', 0)}")
                    stats.append(f"Cache Misses: {cache_info.get('misses', 0)}")
                    stats.append(f"Hit Rate: {cache_info.get('hit_rate', '0.0%')}")
                    stats.append(f"Cached Items: {cache_info.get('cache_size', 0)}")
                    stats.append(f"Total Requests: {cache_info.get('total_requests', 0)}")
                elif hasattr(self.bridge, "get_cache_stats"):
                    # Direct access if CAG debug info fails
                    try:
                        cache_info = self.bridge.get_cache_stats()
                        stats.append("")
                        stats.append("=== Performance Cache ===")
                        stats.append(f"Cache Hits: {cache_info.get('hits', 0)}")
                        stats.append(f"Cache Misses: {cache_info.get('misses', 0)}")
                        stats.append(f"Hit Rate: {cache_info.get('hit_rate', '0.0%')}")
                        stats.append(f"Cached Items: {cache_info.get('cache_size', 0)}")
                        stats.append(f"Total Requests: {cache_info.get('total_requests', 0)}")
                    except Exception as e:
                        stats.append("")
                        stats.append("=== Performance Cache ===")
                        stats.append(f"Cache Stats Error: {e}")

            # Analysis State
            if hasattr(self.bridge, "analysis_state"):
                state = self.bridge.analysis_state
                stats.append("\n=== Analysis State ===")
                stats.append(f"Functions Decompiled: {len(state.get('functions_decompiled', set()))}")
                stats.append(f"Functions Renamed: {len(state.get('functions_renamed', {}))}")
                stats.append(f"Comments Added: {len(state.get('comments_added', {}))}")
                stats.append(f"Functions Analyzed: {len(state.get('functions_analyzed', set()))}")

            # Current Goal
            if hasattr(self.bridge, "current_goal") and self.bridge.current_goal:
                stats.append("\n=== Current Goal ===")
                stats.append(f"Goal: {self.bridge.current_goal}")
                stats.append(f"Steps Taken: {getattr(self.bridge, 'goal_steps_taken', 0)}")
                stats.append(f"Max Steps: {getattr(self.bridge, 'max_goal_steps', 0)}")
                stats.append(f"Achieved: {'Yes' if getattr(self.bridge, 'goal_achieved', False) else 'No'}")

        except Exception as e:
            stats.append(f"Error gathering stats: {e}")

        return "\n".join(stats) if stats else "No memory statistics available"

    def set_session_loading(self, loading: bool):
        """Set session loading flag to prevent expensive operations during session loading."""
        self._session_loading = loading
        if loading:
            # Show loading message immediately
            self.memory_text.delete(1.0, tk.END)
            self.memory_text.insert(1.0, "Session loading... Memory info will update after loading completes.")
        else:
            # Refresh memory info when loading is complete
            self._update_memory_info()

    def get_widget(self):
        """Get the main widget."""
        return self.frame
