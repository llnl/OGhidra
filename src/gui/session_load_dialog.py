import tkinter as tk
from tkinter import ttk


class SessionLoadDialog:
    """Improved session loading dialog with proper positioning."""

    def __init__(self, parent, sessions):
        self.sessions = sessions
        self.selected_session = None

        # Create the dialog window
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Load Session")
        self.dialog.geometry("700x600")
        self.dialog.transient(parent)
        self.dialog.grab_set()

        # Center the dialog on the parent window
        self.dialog.update_idletasks()
        parent_x = parent.winfo_rootx()
        parent_y = parent.winfo_rooty()
        parent_width = parent.winfo_width()
        parent_height = parent.winfo_height()

        dialog_width = 700
        dialog_height = 600

        x = parent_x + (parent_width - dialog_width) // 2
        y = parent_y + (parent_height - dialog_height) // 2

        self.dialog.geometry(f"{dialog_width}x{dialog_height}+{x}+{y}")

        self._setup_widgets()

        # Wait for dialog to close
        self.dialog.wait_window()

    def _setup_widgets(self):
        """Setup the dialog widgets."""
        main_frame = ttk.Frame(self.dialog, padding=20)
        main_frame.pack(fill="both", expand=True)

        # Title
        title_label = ttk.Label(main_frame, text="Load Session", font=("TkDefaultFont", 12, "bold"))
        title_label.pack(pady=(0, 10))

        # Instructions
        instructions = ttk.Label(main_frame, text="Select a session to load:")
        instructions.pack(anchor="w", pady=(0, 10))

        # Session list frame
        list_frame = ttk.Frame(main_frame)
        list_frame.pack(fill="both", expand=True, pady=(0, 20))

        # Create listbox with scrollbar
        scrollbar = ttk.Scrollbar(list_frame)
        scrollbar.pack(side="right", fill="y")

        self.session_listbox = tk.Listbox(
            list_frame,
            yscrollcommand=scrollbar.set,
            font=("Segoe UI", 10),
            relief="flat",
            borderwidth=1,
            highlightthickness=0,
        )
        self.session_listbox.pack(side="left", fill="both", expand=True)
        scrollbar.config(command=self.session_listbox.yview)

        # Populate sessions
        for session in self.sessions:
            self.session_listbox.insert(tk.END, session)

        # Double-click to select
        self.session_listbox.bind("<Double-Button-1>", self._on_double_click)

        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill="x")

        cancel_button = ttk.Button(button_frame, text="Cancel", command=self._cancel)
        cancel_button.pack(side="right", padx=(10, 0))

        load_button = ttk.Button(button_frame, text="Load", command=self._load)
        load_button.pack(side="right")

        # Default focus on listbox
        if self.sessions:
            self.session_listbox.selection_set(0)
            self.session_listbox.focus()

    def _on_double_click(self, event):
        """Handle double-click on session."""
        self._load()

    def _load(self):
        """Load the selected session."""
        selection = self.session_listbox.curselection()
        if selection:
            self.selected_session = self.sessions[selection[0]]
            self.dialog.destroy()

    def _cancel(self):
        """Cancel the dialog."""
        self.selected_session = None
        self.dialog.destroy()
