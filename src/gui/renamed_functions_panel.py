import json
import logging
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, messagebox, scrolledtext, ttk

from ..bridge import Bridge
from .ui_thread import run_on_ui

logger = logging.getLogger(__name__)


class RenamedFunctionsPanel:
    """Panel displaying renamed functions with their addresses and behavior summaries."""

    # How often (ms) the main thread drains queued Tk mutations.
    _UI_POLL_INTERVAL_MS = 50

    def __init__(self, parent, bridge: Bridge):
        import queue
        import threading

        self.frame = ttk.LabelFrame(parent, text="Analyzed Functions", padding=10)
        self.bridge = bridge
        self.function_summaries = {}  # Store behavior summaries for functions
        self._streaming_load_active = False  # Flag to prevent updates during streaming
        self.batch_operation_in_progress = False  # Flag to prevent auto-refresh during batch operations
        self.dict_lock = threading.RLock()  # Thread-safe lock for dictionary access

        # THREAD SAFETY: Tkinter is not thread-safe. Background workers (bulk
        # rename, session load) must never touch widgets directly. They push a
        # zero-arg callable onto this queue; the main thread drains it via a
        # poller scheduled from _setup_widgets (i.e. registered on the main
        # thread), so every Treeview mutation runs on the Tk main loop.
        self._ui_queue = queue.Queue()
        self._ui_poller_active = True

        # Authoritative, thread-safe mirror of the displayed rows: iid -> values.
        # Updated synchronously (under dict_lock) the moment a row's data is
        # known, i.e. *before* the async Tk apply runs. Any thread can read a
        # consistent snapshot via get_rows_snapshot() without touching a widget.
        self._rows_model = {}

        self._setup_widgets()
        self._update_function_list()

    def _setup_widgets(self):
        """Setup the renamed functions widgets."""
        # Control buttons frame
        control_frame = ttk.Frame(self.frame)
        control_frame.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 10))

        ttk.Button(control_frame, text="Refresh", command=self._update_function_list).pack(side="left", padx=(0, 5))
        ttk.Button(control_frame, text="Export", command=self._export_function_list).pack(side="left", padx=(0, 5))
        ttk.Button(control_frame, text="Clear All", command=self._clear_all_functions).pack(side="left", padx=(0, 5))

        # Add Load Vectors button
        self.load_vectors_button = ttk.Button(control_frame, text="Load Vectors", command=self._load_vectors_from_functions)
        self.load_vectors_button.pack(side="left", padx=(0, 5))

        # Function count label
        self.count_label = ttk.Label(self.frame, text="Functions: 0", font=("Arial", 10, "bold"))
        self.count_label.grid(row=1, column=0, columnspan=2, sticky="w", pady=(0, 5))

        # Vector status label
        self.vector_status_label = ttk.Label(self.frame, text="Vectors: Not loaded", font=("Arial", 9), foreground="gray")
        self.vector_status_label.grid(row=1, column=0, columnspan=2, sticky="e", pady=(0, 5))

        # Treeview for function list
        self.tree_frame = ttk.Frame(self.frame)
        self.tree_frame.grid(row=2, column=0, columnspan=2, sticky="nsew", pady=(0, 10))

        # Configure grid weights
        self.frame.grid_rowconfigure(2, weight=1)
        self.frame.grid_columnconfigure(0, weight=1)
        self.tree_frame.grid_rowconfigure(0, weight=1)
        self.tree_frame.grid_columnconfigure(0, weight=1)

        # Create treeview with columns (including hidden summary_key column)
        columns = ("Address", "Old Name", "New Name", "Summary", "summary_key")
        self.tree = ttk.Treeview(self.tree_frame, columns=columns, show="headings", height=8)

        # Configure column headings
        self.tree.heading("Address", text="Address")
        self.tree.heading("Old Name", text="Old Name")
        self.tree.heading("New Name", text="New Name")
        self.tree.heading("Summary", text="Behavior Summary")

        # Configure column widths (compact for sidebar)
        self.tree.column("Address", width=80, minwidth=60)
        self.tree.column("Old Name", width=100, minwidth=70)
        self.tree.column("New Name", width=100, minwidth=70)
        self.tree.column("Summary", width=150, minwidth=100)

        # Hide the summary_key column (used for internal tracking)
        self.tree.column("summary_key", width=0, minwidth=0, stretch=False)
        self.tree.heading("summary_key", text="")

        # Add scrollbars
        v_scrollbar = ttk.Scrollbar(self.tree_frame, orient="vertical", command=self.tree.yview)
        h_scrollbar = ttk.Scrollbar(self.tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)

        # Grid the treeview and scrollbars
        self.tree.grid(row=0, column=0, sticky="nsew")
        v_scrollbar.grid(row=0, column=1, sticky="ns")
        h_scrollbar.grid(row=1, column=0, sticky="ew")

        # Bind double-click event
        self.tree.bind("<Double-1>", self._on_function_double_click)
        self.tree.bind("<Button-3>", self._on_right_click)  # Right-click context menu

        # Start the main-thread UI queue poller (registered on the main thread).
        self.frame.after(self._UI_POLL_INTERVAL_MS, self._drain_ui_queue)

        # Auto-refresh setup
        self._start_auto_refresh()

    def _enqueue_ui(self, callback):
        """Schedule `callback` to run on the Tk main thread.

        Safe to call from any thread: it only touches a thread-safe queue and
        never a widget. The main-thread poller (_drain_ui_queue) applies it.
        """
        self._ui_queue.put(callback)

    def _drain_ui_queue(self):
        """Main-thread poller: apply all queued Tk mutations, then reschedule.

        All ops pending at a given tick are applied in one batch and the count
        label is refreshed exactly once afterwards, so a burst of incremental
        upserts costs a single O(n) count scan rather than one per row.
        """
        import queue

        applied = False
        try:
            while True:
                try:
                    callback = self._ui_queue.get_nowait()
                except queue.Empty:
                    break
                try:
                    callback()
                    applied = True
                except tk.TclError as e:
                    logger.debug(f"Queued UI update skipped: {e}")
                except Exception as e:
                    logger.error(f"Error applying queued UI update: {e}")

            if applied:
                self._refresh_count_label()
        finally:
            # Reschedule unless the widget is gone (app shutting down).
            if self._ui_poller_active:
                try:
                    self.frame.after(self._UI_POLL_INTERVAL_MS, self._drain_ui_queue)
                except tk.TclError:
                    self._ui_poller_active = False

    def _refresh_count_label(self):
        """Update the 'Functions: N' label to the live row count. Main thread only."""
        try:
            self.count_label.config(text=f"Functions: {len(self.tree.get_children())}")
        except tk.TclError:
            pass

    def _load_vectors_from_functions(self):
        """Load all analyzed functions into the vector store for RAG enhancement."""
        import threading
        from tkinter import messagebox

        # Check if CAG/RAG is available
        if not (
            hasattr(self.bridge, "enable_cag")
            and self.bridge.enable_cag
            and hasattr(self.bridge, "cag_manager")
            and self.bridge.cag_manager
        ):
            messagebox.showwarning(
                "RAG Not Available",
                "RAG (Retrieval-Augmented Generation) system is not enabled.\n\n"
                "Please enable CAG system in the Memory panel to use vector loading.",
            )
            return

        # Get function count
        function_count = 0
        try:
            if hasattr(self.bridge, "analysis_state"):
                renamed_functions = self.bridge.analysis_state.get("functions_renamed", {})
                function_address_mapping = getattr(self.bridge, "function_address_mapping", {})
                function_count = len(set(list(renamed_functions.keys()) + list(function_address_mapping.keys())))
        except Exception as e:
            logger.warning(f"Failed to get the function_count: {e}")
            function_count = 0

        if function_count == 0:
            messagebox.showinfo("No Functions", "No analyzed functions found to load into vectors.")
            return

        # Confirm with user for large sessions
        if function_count > 50:
            response = messagebox.askyesno(
                "Large Session Warning",
                f"You are about to load {function_count} functions into vectors.\n\n"
                f"This may take several minutes and use significant memory.\n\n"
                f"Continue?",
            )
            if not response:
                return

        # Create progress dialog
        progress_dialog = tk.Toplevel(self.frame)
        progress_dialog.title("Loading Vectors")
        progress_dialog.geometry("450x200")
        progress_dialog.transient(self.frame.winfo_toplevel())
        progress_dialog.grab_set()
        progress_dialog.protocol("WM_DELETE_WINDOW", lambda: None)  # Prevent closing

        # Center dialog
        progress_dialog.update_idletasks()
        x = (progress_dialog.winfo_screenwidth() // 2) - 225
        y = (progress_dialog.winfo_screenheight() // 2) - 100
        progress_dialog.geometry(f"450x200+{x}+{y}")

        progress_frame = ttk.Frame(progress_dialog, padding=20)
        progress_frame.pack(fill="both", expand=True)

        progress_label = ttk.Label(progress_frame, text="Loading functions into vector store...", font=("Arial", 11, "bold"))
        progress_label.pack(pady=(0, 10))

        progress_status = ttk.Label(progress_frame, text="Initializing...", foreground="blue")
        progress_status.pack(pady=(0, 10))

        progress_bar = ttk.Progressbar(progress_frame, mode="determinate", maximum=function_count)
        progress_bar.pack(fill="x", pady=(0, 10))

        progress_detail = ttk.Label(progress_frame, text="", font=("Arial", 9), foreground="gray")
        progress_detail.pack(pady=(0, 10))

        # Results summary
        results_label = ttk.Label(progress_frame, text="", font=("Arial", 10))
        results_label.pack(pady=(10, 0))

        def load_vectors_worker():
            """Background worker to load vectors."""
            vectors_loaded = 0
            vectors_failed = 0

            # All widget writes below marshal onto the Tk main thread; the main
            # loop redraws, so no manual progress_dialog.update() is needed.
            def set_status(text):
                run_on_ui(lambda: progress_status.config(text=text))

            try:
                # Disable the button during loading
                run_on_ui(lambda: self.load_vectors_button.config(state="disabled", text="Loading..."))

                # Get all function data
                set_status("Collecting function data...")

                functions_to_process = []

                # PRIMARY SOURCE: the thread-safe row model (has ALL functions
                # with summaries). Read via snapshot rather than the Treeview so
                # this worker thread never touches a widget and never misses a
                # row whose insert is still queued.
                for values in self.get_rows_snapshot():
                    try:
                        if len(values) >= 4:
                            address = values[0]
                            old_name = values[1]
                            new_name = values[2]
                            summary = values[3]

                            if summary and summary.strip():  # Only process functions with summaries
                                functions_to_process.append(
                                    {"address": address, "old_name": old_name, "new_name": new_name, "summary": summary}
                                )
                    except Exception as e:
                        logger.warning(f"Error reading row snapshot: {e}")
                        continue

                # FALLBACK: If tree is empty, try bridge.function_address_mapping
                if not functions_to_process and hasattr(self.bridge, "function_address_mapping"):
                    function_address_mapping = self.bridge.function_address_mapping
                    bridge_summaries = getattr(self.bridge, "function_summaries", {})

                    for address, info in function_address_mapping.items():
                        old_name = info.get("old_name", "Unknown")
                        new_name = info.get("new_name", "Unknown")

                        # Get summary from bridge
                        summary = (
                            bridge_summaries.get(address, "")
                            or bridge_summaries.get(old_name, "")
                            or bridge_summaries.get(new_name, "")
                        )

                        if summary:  # Only process functions with summaries
                            functions_to_process.append(
                                {"address": address, "old_name": old_name, "new_name": new_name, "summary": summary}
                            )

                # SECONDARY FALLBACK: Try analysis_state
                if not functions_to_process and hasattr(self.bridge, "analysis_state"):
                    renamed_functions = self.bridge.analysis_state.get("functions_renamed", {})
                    bridge_summaries = getattr(self.bridge, "function_summaries", {})

                    for identifier, new_name in renamed_functions.items():
                        summary = bridge_summaries.get(identifier, "")
                        if summary:
                            functions_to_process.append(
                                {
                                    "address": identifier if self._looks_like_address(identifier) else "Unknown",
                                    "old_name": identifier if not self._looks_like_address(identifier) else "Unknown",
                                    "new_name": new_name,
                                    "summary": summary,
                                }
                            )

                total_functions = len(functions_to_process)
                run_on_ui(lambda: progress_bar.config(maximum=total_functions))

                set_status(f"Loading {total_functions} functions into vectors...")

                # **OPTIMIZED: Batch processing approach with embeddings**
                set_status("Initializing embedding service...")

                # ✅ FIXED: Use generic embeddings from Bridge
                try:
                    from src.bridge import Bridge

                    # Test embeddings availability
                    test_embeddings = Bridge.get_embeddings(["test"])
                    if not test_embeddings:
                        # Get the configured embedding model name
                        client_config = getattr(Bridge._ollama_client, "config", None)
                        emb_model = getattr(client_config, "embedding_model", "nomic-embed-text")
                        provider = getattr(Bridge._ollama_client, "provider", "LLM")
                        raise Exception(
                            f"{provider} embedding model ({emb_model}) not available.\n\nPlease ensure your configuration is correct."
                        )

                    client_config = getattr(Bridge._ollama_client, "config", None)
                    emb_model = getattr(client_config, "embedding_model", "nomic-embed-text")
                    provider = getattr(Bridge._ollama_client, "provider", "Ollama")
                    logger.info(f"✅ Using {provider} embeddings ({emb_model}) for vector creation")
                except Exception as e:
                    raise Exception(f"Embedding service not available: {e}")

                # Process in batches for better performance
                BATCH_SIZE = 50  # Process 50 functions at once
                num_batches = (total_functions + BATCH_SIZE - 1) // BATCH_SIZE

                for batch_num in range(num_batches):
                    batch_start = batch_num * BATCH_SIZE
                    batch_end = min(batch_start + BATCH_SIZE, total_functions)
                    batch = functions_to_process[batch_start:batch_end]

                    set_status(f"Processing batch {batch_num + 1} of {num_batches}")

                    # ✅ FIXED: Use generic batch embeddings
                    # Filter out empty summaries which cause 400 errors
                    batch_texts = []
                    valid_batch = []
                    for func in batch:
                        summary = func.get("summary", "").strip()
                        if summary and len(summary) > 0:
                            batch_texts.append(summary)
                            valid_batch.append(func)
                        else:
                            logger.warning(f"Skipping function {func.get('new_name', 'Unknown')} - empty summary")
                            vectors_failed += 1

                    if not batch_texts:
                        logger.warning(f"Batch {batch_num + 1} has no valid texts to embed")
                        continue

                    batch = valid_batch  # Use only valid functions
                    batch_embeddings_list = Bridge.get_embeddings(batch_texts)

                    if not batch_embeddings_list:
                        logger.error("Failed to generate embeddings")
                        continue

                    # Convert to numpy arrays for compatibility
                    import numpy as np

                    batch_embeddings = [np.array(emb) for emb in batch_embeddings_list]

                    # Add each function to vector store
                    for i, (func_data, embedding) in enumerate(zip(batch, batch_embeddings)):
                        try:
                            # Directly add to vector store (bypass individual model loading)
                            self._add_function_to_vector_store_direct(func_data, embedding)
                            vectors_loaded += 1

                            # Update progress (marshalled to the main thread)
                            overall_progress = batch_start + i + 1
                            new_name = func_data["new_name"]
                            run_on_ui(
                                lambda p=overall_progress, n=new_name: (
                                    progress_bar.config(value=p),
                                    progress_detail.config(text=f"Added: {n}"),
                                )
                            )

                        except Exception as e:
                            logger.warning(f"Failed to add {func_data['new_name']}: {e}")
                            vectors_failed += 1

                    # Small delay between batches
                    import time

                    time.sleep(0.1)

                # Update results
                set_status("Vector loading completed!")
                results_text = f"✅ Successfully loaded: {vectors_loaded} vectors\n"
                if vectors_failed > 0:
                    results_text += f"❌ Failed to load: {vectors_failed} vectors\n"
                results_text += f"📊 Total processed: {total_functions} functions"

                run_on_ui(lambda: results_label.config(text=results_text, foreground="green"))

                # Update vector status label
                run_on_ui(lambda: self.vector_status_label.config(text=f"Vectors: {vectors_loaded} loaded", foreground="green"))

                # Update memory panel if available
                if hasattr(self.bridge, "cag_manager") and self.bridge.cag_manager:
                    # Force refresh of vector store to ensure counts are updated
                    vector_store = self.bridge.cag_manager.vector_store
                    if vector_store:
                        logger.info(
                            f"Vector store after loading: {len(vector_store.embeddings) if vector_store.embeddings else 0} vectors"
                        )

                    # Trigger memory panel update by finding it in the UI hierarchy (on the main thread)
                    def refresh_memory_panel():
                        root = self.frame.winfo_toplevel()
                        for widget in root.winfo_children():
                            if hasattr(widget, "winfo_children"):
                                for child in widget.winfo_children():
                                    if hasattr(child, "_update_memory_info"):
                                        child._update_memory_info()
                                        break

                    run_on_ui(refresh_memory_panel)

                # Add close button (created + auto-close scheduled on the main thread)
                run_on_ui(lambda: self._add_vector_close_button(progress_dialog, progress_frame, vectors_failed == 0))

            except Exception as e:
                logger.error(f"Vector loading error: {e}")
                err = str(e)
                set_status("Error occurred during vector loading!")
                run_on_ui(lambda: results_label.config(text=f"❌ Error: {err}", foreground="red"))
                run_on_ui(lambda: self._add_vector_close_button(progress_dialog, progress_frame, False))

        # Start loading in background thread
        threading.Thread(target=load_vectors_worker, daemon=True).start()

    def _add_vector_close_button(self, progress_dialog, progress_frame, auto_close):
        """Add the Close button to the vector-load dialog. MUST run on the main thread."""

        def close_dialog():
            try:
                progress_dialog.destroy()
            except tk.TclError:
                pass
            self.load_vectors_button.config(state="normal", text="Load Vectors")

        ttk.Button(progress_frame, text="Close", command=close_dialog).pack(pady=(10, 0))

        # Auto-close shortly after a fully successful load.
        if auto_close:
            progress_dialog.after(3000, close_dialog)

    def _add_function_to_vector_store_direct(self, func_data, embedding):
        """Add function directly to vector store without reloading model."""
        import numpy as np

        # Create function document
        function_doc = {
            "text": f"Function: {func_data['new_name']}\nOriginal: {func_data['old_name']}\nAddress: {func_data['address']}\nBehavior: {func_data['summary']}",
            "type": "function_analysis",
            "name": func_data["new_name"],
            "metadata": {"address": func_data["address"], "old_name": func_data["old_name"], "new_name": func_data["new_name"]},
        }

        # Add to vector store
        if hasattr(self.bridge, "cag_manager") and self.bridge.cag_manager:
            cag_manager = self.bridge.cag_manager
            vector_store = cag_manager.vector_store

            # Create a new vector store if one doesn't exist
            if vector_store is None:
                try:
                    from src.cag.vector_store import SimpleVectorStore

                    # Create empty vector store
                    vector_store = SimpleVectorStore(documents=[], embeddings=[])
                    # Set it directly on the cag_manager
                    cag_manager._vector_store = vector_store
                    cag_manager._vector_store_initialized = True
                    logger.info("Created new empty vector store for function embeddings")
                except Exception as e:
                    raise Exception(f"Could not create vector store: {e}")

            # Now add the document and embedding
            vector_store.documents.append(function_doc)

            # Add embedding
            if isinstance(vector_store.embeddings, list):
                vector_store.embeddings.append(embedding)
            else:
                # Handle numpy array case
                if len(vector_store.embeddings) == 0:
                    vector_store.embeddings = [embedding]
                else:
                    vector_store.embeddings = np.vstack([vector_store.embeddings, embedding.reshape(1, -1)])
        else:
            raise Exception("CAG manager not available - cannot add to vector store")

    @staticmethod
    def _addr_iid(address: str) -> str:
        """Stable Treeview row id for an address-keyed function."""
        return f"addr::{address}"

    @staticmethod
    def _name_iid(identifier: str) -> str:
        """Stable Treeview row id for a function only known by name."""
        return f"name::{identifier}"

    def _compute_desired_rows(self):
        """Compute the ordered (iid, values) rows that should be displayed.

        Pure computation: reads bridge state but never mutates the Treeview.
        Uses precomputed lookup sets so deduplication is O(n) rather than the
        old O(n^2) nested scans.
        """
        rows = []
        seen_iids = set()

        if not hasattr(self.bridge, "analysis_state"):
            return rows

        renamed_functions = self.bridge.analysis_state.get("functions_renamed", {})
        function_address_mapping = getattr(self.bridge, "function_address_mapping", {})
        bridge_summaries = getattr(self.bridge, "function_summaries", {})

        # Precompute (identifier, new_name) pairs already covered by the address
        # mapping so the renamed_functions pass can skip duplicates in O(1).
        covered_pairs = set()
        for addr, info in function_address_mapping.items():
            nn = info.get("new_name")
            covered_pairs.add((addr, nn))
            covered_pairs.add((info.get("old_name"), nn))

        # Primary source: the address mapping (most complete data).
        for address, info in function_address_mapping.items():
            iid = self._addr_iid(address)
            if iid in seen_iids:
                continue
            seen_iids.add(iid)

            old_name = info.get("old_name", "Unknown")
            new_name = info.get("new_name", "Unknown")

            display_address = address.replace("name_", "") if address.startswith("name_") else address
            summary_key = f"{address}_{new_name}"
            summary = (
                bridge_summaries.get(address, "")
                or bridge_summaries.get(old_name, "")
                or bridge_summaries.get(new_name, "")
                or self.function_summaries.get(summary_key, "No summary available")
            )
            rows.append((iid, (display_address, old_name, new_name, summary, summary_key)))

        # Secondary source: renamed_functions not represented in the mapping.
        for identifier, new_name in renamed_functions.items():
            if (identifier, new_name) in covered_pairs:
                continue

            iid = self._name_iid(identifier)
            if iid in seen_iids:
                continue
            seen_iids.add(iid)

            is_address = self._looks_like_address(identifier)
            address = identifier if is_address else "Unknown"
            old_name = "Unknown" if is_address else identifier
            summary_key = f"{address}_{new_name}" if address != "Unknown" else f"{old_name}_{new_name}"
            summary = bridge_summaries.get(identifier, "") or self.function_summaries.get(summary_key, "No summary available")
            rows.append((iid, (address, old_name, new_name, summary, summary_key)))

        return rows

    def _reconcile_tree(self, rows):
        """Reconcile the Treeview to `rows` via upsert instead of rebuild.

        MUST run on the Tk main thread (invoked via the UI queue). Existing rows
        are updated in place (only when values actually change) and new rows are
        appended; rows no longer present are removed. Rows are never reordered,
        so scroll position, selection, expanded state, and any user-applied sort
        order are preserved. The tree is never fully cleared.
        """
        desired_ids = {iid for iid, _ in rows}

        # Remove only rows that have genuinely disappeared.
        for iid in list(self.tree.get_children()):
            if iid not in desired_ids:
                try:
                    self.tree.delete(iid)
                except tk.TclError:
                    pass

        # Upsert desired rows, keeping existing rows in their current position.
        for iid, values in rows:
            values = tuple(values)
            if self.tree.exists(iid):
                if tuple(self.tree.item(iid, "values")) != values:
                    self.tree.item(iid, values=values)
            else:
                self.tree.insert("", "end", iid=iid, values=values)

        self._refresh_count_label()

    def _update_function_list(self):
        """Refresh the function list incrementally (upsert, never full rebuild).

        Safe to call from any thread: the row set is computed under the data
        lock, then the Treeview mutation is marshalled onto the Tk main thread.
        The lock is released before any widget is touched.
        """
        # THREAD SAFETY: hold the lock only for the read-side snapshot and to
        # refresh the authoritative row model; the widget is touched later, on
        # the Tk main thread, via the queue.
        with self.dict_lock:
            try:
                rows = self._compute_desired_rows()
            except Exception as e:
                logger.error(f"Error computing function list: {e}")
                return
            self._rows_model = {iid: tuple(values) for iid, values in rows}

        logger.debug(f"Reconciling function list: {len(rows)} rows")
        self._enqueue_ui(lambda: self._reconcile_tree(rows))

    def _upsert_function_row(self, address: str, old_name: str, new_name: str, summary: str = ""):
        """Insert or update a single row without touching the rest of the tree.

        Stable row ids keyed on the function address let the incremental
        rename-all flow update one row per completed function in O(1), instead
        of rebuilding the entire Treeview on every success (which hung the UI
        past ~1000 functions and lost scroll/selection each time).

        Safe to call from any thread: values are snapshotted under the data
        lock, then the Treeview mutation is marshalled onto the Tk main thread.
        """
        # Snapshot the row values under the lock; touch no widgets here.
        with self.dict_lock:
            iid = self._addr_iid(address)
            display_address = address.replace("name_", "") if address.startswith("name_") else address
            summary_key = f"{address}_{new_name}"

            bridge_summaries = getattr(self.bridge, "function_summaries", {})
            resolved_summary = (
                bridge_summaries.get(address, "")
                or bridge_summaries.get(old_name, "")
                or bridge_summaries.get(new_name, "")
                or self.function_summaries.get(summary_key, "")
                or summary
                or "No summary available"
            )
            values = (display_address, old_name, new_name, resolved_summary, summary_key)
            # Update the authoritative model immediately so readers on any
            # thread see this row without waiting for the Tk apply to run.
            self._rows_model[iid] = values

        self._enqueue_ui(lambda: self._apply_row_upsert(iid, values, new_name))

    def get_rows_snapshot(self):
        """Return a consistent snapshot of all rows as a list of value-tuples.

        Thread-safe and lag-free: reflects every row whose data is known, even
        ones whose Treeview insert is still queued. Prefer this over reading
        tree.get_children() from any non-UI thread. Each tuple is
        (address, old_name, new_name, summary, summary_key).
        """
        with self.dict_lock:
            return list(self._rows_model.values())

    def _apply_row_upsert(self, iid, values, new_name):
        """Apply a single-row upsert to the Treeview. MUST run on the main thread."""
        try:
            if self.tree.exists(iid):
                if tuple(self.tree.item(iid, "values")) != values:
                    self.tree.item(iid, values=values)
            else:
                self.tree.insert("", "end", iid=iid, values=values)
        except tk.TclError as e:
            logger.debug(f"Tree upsert skipped for {new_name}: {e}")

    def _looks_like_address(self, text: str) -> bool:
        """Check if a string looks like a memory address."""
        if not isinstance(text, str):
            return False

        # Check for hex addresses (0x prefix or all hex digits)
        if text.startswith("0x") or (len(text) >= 4 and all(c in "0123456789abcdefABCDEF" for c in text)):
            return True

        # Check for decimal addresses (long numbers)
        if text.isdigit() and len(text) >= 8:
            return True

        return False

    def _on_function_double_click(self, event):
        """Handle double-click on function item - opens summary editor."""
        selection = self.tree.selection()
        if not selection:
            return

        item = selection[0]
        try:
            values = self.tree.item(item, "values")
            # Use the safer approach that doesn't rely on tree item references
            address, old_name, new_name = values[0], values[1], values[2]
            self._edit_summary_by_function_data(address, old_name, new_name)
        except tk.TclError:
            # Item was deleted, ignore
            messagebox.showwarning("Warning", "The selected function is no longer available. The list may have been refreshed.")
            return

    def _on_right_click(self, event):
        """Handle right-click context menu."""
        selection = self.tree.selection()
        if not selection:
            return

        item = selection[0]
        try:
            values = self.tree.item(item, "values")
        except tk.TclError:
            # Item was deleted, ignore this right-click
            return

        # Store the function data instead of relying on item reference
        address, old_name, new_name = values[0], values[1], values[2]

        # Create context menu with safer callbacks
        context_menu = tk.Menu(self.tree, tearoff=0)
        context_menu.add_command(
            label="Edit Summary", command=lambda: self._edit_summary_by_function_data(address, old_name, new_name)
        )
        context_menu.add_separator()
        context_menu.add_command(label="Copy Address", command=lambda: self._copy_to_clipboard(address))
        context_menu.add_command(label="Copy Name", command=lambda: self._copy_to_clipboard(new_name))
        context_menu.add_separator()
        context_menu.add_command(
            label="Remove Function", command=lambda: self._remove_function_by_data(address, old_name, new_name)
        )

        try:
            context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            context_menu.grab_release()

    def _edit_summary_for_item(self, item):
        """Edit summary for a specific item in a dedicated window."""
        try:
            values = self.tree.item(item, "values")
        except tk.TclError:
            # Item was deleted, ignore
            messagebox.showwarning("Warning", "The selected function is no longer available. The list may have been refreshed.")
            return

        # Get the summary key from the hidden column
        if len(values) > 4:
            summary_key = values[4]
        elif len(values) >= 3 and values[0] != "Unknown":
            summary_key = f"{values[0]}_{values[2]}"
        elif len(values) >= 3:
            summary_key = f"{values[1]}_{values[2]}"
        else:
            summary_key = "unknown_function"

        # Use the same summary that "View Details" shows - from the tree item directly
        address = values[0] if len(values) > 0 else "Unknown"
        old_name = values[1] if len(values) > 1 else "Unknown"
        new_name = values[2] if len(values) > 2 else "Unknown"
        current_summary = values[3] if len(values) > 3 else "No summary available"

        # Create a dedicated window for editing the summary
        self._open_summary_editor(address, old_name, new_name, current_summary, item, summary_key)

    def _edit_summary_by_function_data(self, address, old_name, new_name):
        """Edit summary by function data instead of tree item reference (safer approach)."""
        # Find the current summary for this function
        summary_key = f"{address}_{new_name}" if address != "Unknown" else f"{old_name}_{new_name}"

        # Get current summary from our storage or bridge
        current_summary = ""
        if hasattr(self.bridge, "function_summaries"):
            bridge_summaries = getattr(self.bridge, "function_summaries", {})
            current_summary = (
                bridge_summaries.get(address, "")
                or bridge_summaries.get(old_name, "")
                or bridge_summaries.get(new_name, "")
                or self.function_summaries.get(summary_key, "No summary available")
            )
        else:
            current_summary = self.function_summaries.get(summary_key, "No summary available")

        # Create a dedicated window for editing the summary (no tree_item dependency)
        self._open_summary_editor(address, old_name, new_name, current_summary, None, summary_key)

    def _open_summary_editor(self, address, old_name, new_name, current_summary, tree_item, summary_key):
        """Open a dedicated window for editing the behavior summary."""
        # Create a new window
        editor_window = tk.Toplevel(self.frame)
        editor_window.title(f"Edit Behavior Summary - {new_name}")
        editor_window.geometry("750x700")
        editor_window.transient(self.frame.winfo_toplevel())
        editor_window.grab_set()
        editor_window.minsize(600, 500)  # Ensure minimum size for buttons to be visible

        # Center the window
        editor_window.update_idletasks()
        x = (editor_window.winfo_screenwidth() // 2) - (750 // 2)
        y = (editor_window.winfo_screenheight() // 2) - (700 // 2)
        editor_window.geometry(f"750x700+{x}+{y}")

        # Create the UI
        main_frame = ttk.Frame(editor_window, padding=10)
        main_frame.pack(fill="both", expand=True)

        # Function info section
        info_frame = ttk.LabelFrame(main_frame, text="Function Information", padding=10)
        info_frame.pack(fill="x", pady=(0, 10))

        ttk.Label(info_frame, text=f"Address: {address}").pack(anchor="w")
        ttk.Label(info_frame, text=f"Original Name: {old_name}").pack(anchor="w")
        ttk.Label(info_frame, text=f"New Name: {new_name}").pack(anchor="w")

        # Summary editing section
        summary_frame = ttk.LabelFrame(main_frame, text="Behavior Summary", padding=10)
        summary_frame.pack(fill="both", expand=True, pady=(0, 10))

        # Instructions
        instructions = ttk.Label(
            summary_frame,
            text="Edit the behavior summary below. This will be used as context for future AI analysis:",
            font=("TkDefaultFont", 9),
        )
        instructions.pack(anchor="w", pady=(0, 5))

        # Text editor
        text_frame = ttk.Frame(summary_frame)
        text_frame.pack(fill="both", expand=True)

        summary_text = scrolledtext.ScrolledText(
            text_frame,
            height=12,
            width=80,
            wrap=tk.WORD,
            relief="flat",
            borderwidth=1,
            padx=6,
            pady=6,
        )
        summary_text.pack(fill="both", expand=True)
        summary_text.insert("1.0", current_summary)
        summary_text.focus()

        # Character count
        char_count_var = tk.StringVar()
        char_count_label = ttk.Label(summary_frame, textvariable=char_count_var, font=("TkDefaultFont", 8))
        char_count_label.pack(anchor="e")

        def update_char_count(event=None):
            content = summary_text.get("1.0", tk.END).strip()
            char_count_var.set(f"Characters: {len(content)}")

        summary_text.bind("<KeyRelease>", update_char_count)
        update_char_count()

        # Buttons - ensure they're always visible at the bottom
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill="x", pady=(10, 5))

        def save_and_close():
            new_summary = summary_text.get("1.0", tk.END).strip()

            try:
                # ROBUST FIX: Instead of relying on potentially stale tree_item reference,
                # find the correct tree item by matching the function data
                target_tree_item = None
                for item in self.tree.get_children():
                    try:
                        values = self.tree.item(item, "values")
                        if len(values) >= 3 and values[0] == address and values[1] == old_name and values[2] == new_name:
                            target_tree_item = item
                            break
                    except tk.TclError:
                        # Item was deleted, skip it
                        continue

                # Update the tree item if found
                if target_tree_item:
                    try:
                        values = self.tree.item(target_tree_item, "values")
                        self.tree.item(target_tree_item, values=(values[0], values[1], values[2], new_summary, summary_key))
                    except tk.TclError:
                        # Tree item was deleted during update, that's okay - we'll update storage anyway
                        logger.debug(
                            f"Tree item was deleted during summary update for {new_name}, but continuing with storage update"
                        )

                # Update our storage (this is the most important part)
                self.function_summaries[summary_key] = new_summary

                # Update in bridge function summaries
                if hasattr(self.bridge, "function_summaries"):
                    if address != "Unknown" and not address.startswith("name_"):
                        self.bridge.function_summaries[address] = new_summary
                    elif old_name != "Unknown":
                        self.bridge.function_summaries[old_name] = new_summary
                    else:
                        self.bridge.function_summaries[new_name] = new_summary

                # Update RAG vectors
                # RAG integration removed - use "Load Vectors" button for vector operations
                # if hasattr(self.bridge, '_add_function_to_rag'):
                #     identifier = address if address != "Unknown" else old_name
                #     self.bridge._add_function_to_rag(identifier, new_summary)

                # Trigger a refresh to ensure UI is up to date
                self._update_function_list()

                editor_window.destroy()
                messagebox.showinfo("Success", "Behavior summary updated successfully!")

            except Exception as e:
                logger.error(f"Error saving summary: {e}")
                # Even if tree update fails, we can still save the summary to storage
                try:
                    self.function_summaries[summary_key] = new_summary
                    if hasattr(self.bridge, "function_summaries"):
                        if address != "Unknown" and not address.startswith("name_"):
                            self.bridge.function_summaries[address] = new_summary
                        elif old_name != "Unknown":
                            self.bridge.function_summaries[old_name] = new_summary
                        else:
                            self.bridge.function_summaries[new_name] = new_summary

                    editor_window.destroy()
                    messagebox.showinfo("Success", "Behavior summary saved to storage (UI will update on next refresh)")
                except Exception as inner_e:
                    logger.error(f"Failed to save to storage as well: {inner_e}")
                    messagebox.showerror("Error", f"Failed to save summary: {e}")

        def cancel():
            editor_window.destroy()

        ttk.Button(button_frame, text="Save", command=save_and_close).pack(side="right", padx=(5, 0))
        ttk.Button(button_frame, text="Cancel", command=cancel).pack(side="right")

        # Handle window close
        editor_window.protocol("WM_DELETE_WINDOW", cancel)

    def _copy_to_clipboard(self, text):
        """Copy text to clipboard."""
        self.frame.clipboard_clear()
        self.frame.clipboard_append(text)
        messagebox.showinfo("Copied", f"Copied to clipboard: {text}")

    def _remove_function(self, item):
        """Remove a function from the renamed list."""
        try:
            values = self.tree.item(item, "values")
        except tk.TclError:
            # Item was deleted, ignore
            messagebox.showwarning("Warning", "The selected function is no longer available. The list may have been refreshed.")
            return

        if messagebox.askyesno("Confirm", "Remove this function from the renamed list?"):
            address, old_name, new_name, _ = values
            self._remove_function_by_data(address, old_name, new_name)

    def _remove_function_by_data(self, address, old_name, new_name):
        """Remove a function by its data (safer than tree item reference)."""
        if messagebox.askyesno("Confirm", f"Remove function '{new_name}' from the renamed list?"):
            # Remove from bridge analysis state
            if hasattr(self.bridge, "analysis_state"):
                renamed_functions = self.bridge.analysis_state.get("functions_renamed", {})

                # Try to find and remove the entry
                to_remove = None
                for key, value in renamed_functions.items():
                    if value == new_name and (key == address or key == old_name):
                        to_remove = key
                        break

                if to_remove:
                    del renamed_functions[to_remove]

            # Also remove from our local summaries
            summary_key = f"{address}_{new_name}" if address != "Unknown" else f"{old_name}_{new_name}"
            if summary_key in self.function_summaries:
                del self.function_summaries[summary_key]

            # Refresh the list
            self._update_function_list()

    def _export_function_list(self):
        """Export the function list to a file."""
        try:
            filename = filedialog.asksaveasfilename(
                title="Export Renamed Functions",
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("Text files", "*.txt"), ("All files", "*.*")],
            )

            if not filename:
                return

            export_data = []
            for item in self.tree.get_children():
                values = self.tree.item(item, "values")
                export_data.append(
                    {
                        "address": values[0],
                        "old_name": values[1],
                        "new_name": values[2],
                        "summary": values[3],
                        "timestamp": datetime.now().isoformat(),
                    }
                )

            if filename.endswith(".json"):
                with open(filename, "w", encoding="utf-8") as f:
                    json.dump(export_data, f, indent=2, ensure_ascii=False)
            else:
                with open(filename, "w", encoding="utf-8") as f:
                    f.write("Renamed Functions Export\n")
                    f.write("=" * 50 + "\n\n")
                    for func in export_data:
                        f.write(f"Address: {func['address']}\n")
                        f.write(f"Old Name: {func['old_name']}\n")
                        f.write(f"New Name: {func['new_name']}\n")
                        f.write(f"Summary: {func['summary']}\n")
                        f.write(f"Timestamp: {func['timestamp']}\n")
                        f.write("-" * 30 + "\n")

            messagebox.showinfo("Success", f"Function list exported to {filename}")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to export function list: {e}")

    def _clear_all_functions(self):
        """Clear all renamed functions."""
        if messagebox.askyesno(
            "Confirm", "Are you sure you want to clear all renamed functions? This action cannot be undone."
        ):
            try:
                # Clear from bridge analysis state
                if hasattr(self.bridge, "analysis_state"):
                    self.bridge.analysis_state["functions_renamed"] = {}

                # Clear our summaries
                self.function_summaries = {}

                # Update the display
                self._update_function_list()

                messagebox.showinfo("Success", "All renamed functions cleared.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to clear functions: {e}")

    def _start_auto_refresh(self):
        """Start auto-refresh of the function list."""

        def refresh():
            try:
                # THREAD SAFETY: Skip refresh during batch operations to prevent race conditions
                if self.batch_operation_in_progress:
                    logger.debug("Skipping auto-refresh during batch operation")
                else:
                    self._update_function_list()
            except Exception as e:
                logger.error(f"Error in auto-refresh: {e}")

            # Schedule next refresh
            self.frame.after(15000, refresh)  # Refresh every 15 seconds

        # Start refreshing after 5 seconds
        self.frame.after(5000, refresh)

    def add_function_with_summary(
        self, address: str, old_name: str, new_name: str, summary: str = "", *, update_state: bool = True
    ):
        """Add a function with a summary programmatically."""
        summary_key = f"{address}_{new_name}" if address != "Unknown" else f"{old_name}_{new_name}"

        # Store summary locally
        if summary:
            self.function_summaries[summary_key] = summary

        if update_state:
            # THREAD SAFETY: Acquire lock before writing to shared dictionaries
            with self.dict_lock:
                # CRITICAL FIX: Update bridge data structures that the UI actually reads from
                # Update bridge's function_address_mapping
                if not hasattr(self.bridge, "function_address_mapping"):
                    self.bridge.function_address_mapping = {}

                self.bridge.function_address_mapping[address] = {"old_name": old_name, "new_name": new_name}

                # Update bridge's function summaries
                if not hasattr(self.bridge, "function_summaries"):
                    self.bridge.function_summaries = {}

                if summary:
                    # Store summary using multiple keys for robust retrieval
                    self.bridge.function_summaries[address] = summary
                    if old_name != "Unknown":
                        self.bridge.function_summaries[old_name] = summary
                    if new_name != "Unknown":
                        self.bridge.function_summaries[new_name] = summary

                # Update bridge's analysis_state for legacy compatibility
                if not hasattr(self.bridge, "analysis_state"):
                    self.bridge.analysis_state = {}

                if "functions_renamed" not in self.bridge.analysis_state:
                    self.bridge.analysis_state["functions_renamed"] = {}

                # Store in analysis_state using only address as key to avoid duplicate name entries
                self.bridge.analysis_state["functions_renamed"][address] = new_name

                # Debug logging to verify data storage
                import logging

                logger = logging.getLogger("ollama-ghidra-bridge.ui")
                logger.info(f"Added function to session: {address} | {old_name} -> {new_name}")
                logger.info(f"Bridge function_address_mapping now has {len(self.bridge.function_address_mapping)} entries")
                logger.info(
                    f"Bridge analysis_state functions_renamed now has {len(self.bridge.analysis_state['functions_renamed'])} entries"
                )

        # Only refresh the UI list if not in streaming mode
        # During streaming, we'll do batch updates to prevent UI freezing.
        # Upsert just this one row instead of rebuilding the whole tree, so
        # bulk rename stays responsive and scroll/selection are preserved.
        if not self._streaming_load_active:
            self._upsert_function_row(address, old_name, new_name, summary)

    def set_streaming_mode(self, active: bool):
        """Enable or disable streaming mode to prevent UI updates during bulk loading."""
        self._streaming_load_active = active
        if not active:
            # When streaming ends, do a final update
            self._update_function_list()

    def get_widget(self):
        """Return the main frame widget."""
        return self.frame
