from queue import Queue
from tkinter import ttk
from typing import Any, Literal, Tuple, Union


class StatusPanel:
    """Panel for displaying system health status."""

    def __init__(self, parent):
        self.frame = ttk.LabelFrame(parent, text="System Health", padding=8)

        # Create queue for thread-safe UI updates
        self.ui_update_queue: Queue[Tuple[Literal["llm", "ghidra", "cag"], Any]] = Queue()

        # Status indicators - initialize with "Down" status
        self.llm_status = ttk.Label(
            self.frame,
            text="LLM API: NOT OK ✗",
            foreground="#FF0000",
            font=("Arial", 9),
        )
        self.llm_status.pack(fill="x", pady=2, anchor="w")

        self.ghidra_status = ttk.Label(
            self.frame,
            text="GhidraMCP API: NOT OK ✗",
            foreground="#FF0000",
            font=("Arial", 9),
        )
        self.ghidra_status.pack(fill="x", pady=2, anchor="w")

        self.cag_status = ttk.Label(
            self.frame,
            text="CAG System: Disabled",
            foreground="#FFA500",
            font=("Arial", 9),
        )
        self.cag_status.pack(fill="x", pady=2, anchor="w")

        # Start queue checking process on the main thread
        self._check_ui_update_queue()

    def update_llm_status(self, llm_status):
        """Update just the LLM status indicator."""
        # Add to queue for thread-safe UI update
        self.ui_update_queue.put(("llm", llm_status))

    def update_ghidra_status(self, ghidra_status):
        """Update just the Ghidra status indicator."""
        # Add to queue for thread-safe UI update
        self.ui_update_queue.put(("ghidra", ghidra_status))

    def update_cag_status(self, cag_status):
        """Update just the CAG status indicator."""
        # Add to queue for thread-safe UI update
        self.ui_update_queue.put(("cag", cag_status))

    def _check_ui_update_queue(self):
        """Process items from the UI update queue on the main thread."""
        try:
            # Process all current items in the queue
            while not self.ui_update_queue.empty():
                # Get the update from the queue
                status_type, status_value = self.ui_update_queue.get_nowait()

                # Handle different types of updates
                if status_type == "llm":
                    self._update_llm_status_main_thread(status_value)
                elif status_type == "ghidra":
                    self._update_ghidra_status_main_thread(status_value)
                elif status_type == "cag":
                    self._update_cag_status_main_thread(status_value)

                # Mark as done
                self.ui_update_queue.task_done()

        except Exception as e:
            print(f"Error processing status update queue: {e}")

        finally:
            # Schedule next check after 100ms
            if hasattr(self, "frame") and self.frame.winfo_exists():
                self.frame.after(100, self._check_ui_update_queue)

    def _update_llm_status_main_thread(self, llm_status):
        """Update the Llm status indicator on the main thread."""
        if isinstance(llm_status, Exception):
            self.llm_status.config(text=f"LLM API: ERROR", foreground="#FF0000")
        else:
            color = "#2BC72B" if llm_status else "#FF0000"
            text = "OK ✓" if llm_status else "NOT OK ✗"
            self.llm_status.config(text=f"Llm API: {text}", foreground=color)

    def _update_ghidra_status_main_thread(self, ghidra_status):
        """Update the Ghidra status indicator on the main thread."""
        if isinstance(ghidra_status, Exception):
            self.ghidra_status.config(text=f"GhidraMCP API: ERROR", foreground="#FF0000")
        else:
            color = "#2BC72B" if ghidra_status else "#FF0000"
            text = "OK ✓" if ghidra_status else "NOT OK ✗"
            self.ghidra_status.config(text=f"GhidraMCP API: {text}", foreground=color)

    def _update_cag_status_main_thread(self, cag_status):
        """Update the CAG status indicator on the main thread."""
        if isinstance(cag_status, Exception):
            self.cag_status.config(text=f"CAG System: ERROR", foreground="#FF0000")
        else:
            color = "#2BC72B" if cag_status else "#FFA500"
            text = "Enabled ✓" if cag_status else "Disabled"
            self.cag_status.config(text=f"CAG System: {text}", foreground=color)

    def get_widget(self):
        """Return the main widget."""
        return self.frame
