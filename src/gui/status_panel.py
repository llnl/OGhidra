from tkinter import ttk


class StatusPanel:
    """Panel for displaying system health status."""

    def __init__(self, parent):
        self.frame = ttk.LabelFrame(parent, text="System Health", padding=8)

        # Status indicators - initialize with "Down" status
        self.ollama_status = ttk.Label(
            self.frame,
            text="Ollama API: NOT OK ✗",
            foreground="#FF0000",
            font=("Arial", 9),
        )
        self.ollama_status.pack(fill="x", pady=2, anchor="w")

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

    def update_ollama_status(self, ollama_status):
        """Update just the Ollama status indicator."""
        if isinstance(ollama_status, Exception):
            self.ollama_status.after(
                0,
                lambda: self.ollama_status.config(text=f"Ollama API: ERROR", foreground="#FF0000"),
            )
        else:
            color = "#2BC72B" if ollama_status else "#FF0000"
            text = "OK ✓" if ollama_status else "NOT OK ✗"
            self.ollama_status.after(
                0,
                lambda: self.ollama_status.config(text=f"Ollama API: {text}", foreground=color),
            )

    def update_ghidra_status(self, ghidra_status):
        """Update just the Ghidra status indicator."""
        if isinstance(ghidra_status, Exception):
            self.ghidra_status.after(
                0,
                lambda: self.ghidra_status.config(text=f"GhidraMCP API: ERROR", foreground="#FF0000"),
            )
        else:
            color = "#2BC72B" if ghidra_status else "#FF0000"
            text = "OK ✓" if ghidra_status else "NOT OK ✗"
            self.ghidra_status.after(
                0,
                lambda: self.ghidra_status.config(text=f"GhidraMCP API: {text}", foreground=color),
            )

    def update_cag_status(self, cag_status):
        """Update just the CAG status indicator."""
        if isinstance(cag_status, Exception):
            self.cag_status.after(
                0,
                lambda: self.cag_status.config(text=f"CAG System: ERROR", foreground="#FF0000"),
            )
        else:
            color = "#2BC72B" if cag_status else "#FFA500"
            text = "Enabled ✓" if cag_status else "Disabled"
            self.cag_status.after(
                0,
                lambda: self.cag_status.config(text=f"CAG System: {text}", foreground=color),
            )

    def get_widget(self):
        """Return the main widget."""
        return self.frame
