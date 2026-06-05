from typing import Optional
from ttkbootstrap import Style
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk, filedialog
import json
from datetime import datetime


class AIResponsePanel:
    """Panel for displaying AI agent responses."""

    def __init__(self, parent, generate_callback=None):
        self.frame = ttk.LabelFrame(parent, text="AI Agent Responses", padding=10)
        self.generate_callback = generate_callback
        self._setup_widgets()
        self._setup_text_tags()
        self.response_history = []

    def _setup_widgets(self):
        """Setup the AI response widgets."""
        self.response_text = scrolledtext.ScrolledText(
            self.frame,
            height=15,
            width=80,
            wrap=tk.WORD,
            relief="flat",
            borderwidth=1,
            padx=8,
            pady=8,
        )
        self.response_text.grid(row=0, column=0, columnspan=3, sticky="nsew", pady=(0, 10))

        # Control buttons
        ttk.Button(self.frame, text="Clear", command=self._clear_responses).grid(row=1, column=0, padx=(0, 5))
        # Converted "Save to File" to "Generate Report" per user request
        ttk.Button(self.frame, text="Generate Report", command=self._on_generate_report).grid(row=1, column=1, padx=5)
        ttk.Button(self.frame, text="Export JSON", command=self._export_json).grid(row=1, column=2, padx=(5, 0))

        # Configure grid weights
        self.frame.grid_rowconfigure(0, weight=1)
        self.frame.grid_columnconfigure(0, weight=1)

    def _setup_text_tags(self):
        """Setup text tags for syntax highlighting in responses."""
        colors = Style().colors

        # Header/separator styling
        self.response_text.tag_config("header", foreground=colors.info, font=("Consolas", 11, "bold"))
        self.response_text.tag_config("separator", foreground=colors.secondary)
        # Status colors
        self.response_text.tag_config("success", foreground=colors.success)
        self.response_text.tag_config("warning", foreground=colors.warning)
        self.response_text.tag_config("error", foreground=colors.danger)
        self.response_text.tag_config("info", foreground=colors.info)
        # Tool/action styling
        self.response_text.tag_config("tool", foreground=colors.warning, font=("Consolas", 11, "italic"))
        self.response_text.tag_config("reasoning", foreground="#a0a0a0")  # Subtle gray for reasoning

    def add_response(self, response_type: str, content: str, timestamp: Optional[datetime] = None):
        """Add a new AI response to the display."""
        if timestamp is None:
            timestamp = datetime.now()

        # Store in history
        response_entry = {"type": response_type, "content": content, "timestamp": timestamp.isoformat()}
        self.response_history.append(response_entry)

        # Display in text widget
        formatted_response = f"\n{'=' * 60}\n"
        formatted_response += f"[{timestamp.strftime('%H:%M:%S')}] {response_type.upper()}\n"
        formatted_response += f"{'=' * 60}\n"
        formatted_response += f"{content}\n"

        self.response_text.insert(tk.END, formatted_response)
        self.response_text.see(tk.END)

    def add_cot_update(self, update_type: str, content: str, timestamp: Optional[datetime] = None):
        """Add a chain of thought update to the display (streaming during agentic loop).

        This method displays the AI's reasoning and progress during query processing,
        mirroring what is printed to the terminal.

        Args:
            update_type: Type of update (e.g., 'Cycle', 'Phase', 'Reasoning', 'Tool')
            content: The update content
            timestamp: Optional timestamp (defaults to now)
        """
        if timestamp is None:
            timestamp = datetime.now()

        # Store in history with cot prefix
        response_entry = {"type": f"cot_{update_type.lower()}", "content": content, "timestamp": timestamp.isoformat()}
        self.response_history.append(response_entry)

        # Format based on update type for visual distinction
        time_str = timestamp.strftime("%H:%M:%S")

        if update_type.upper() == "CYCLE":
            # Major cycle separator
            formatted = f"\n{'=' * 60}\n"
            formatted += f"[{time_str}] {content}\n"
            formatted += f"{'=' * 60}\n"
        elif update_type.upper() == "PHASE":
            # Phase indicator
            formatted = f"[{time_str}] {content}\n"
        elif update_type.upper() == "REASONING":
            # AI reasoning - highlight this
            formatted = f"[{time_str}] {content}\n"
        elif update_type.upper() == "TOOL":
            # Tool execution
            formatted = f"[{time_str}]   -> {content}\n"
        elif update_type.upper() == "STATUS":
            # Status update
            formatted = f"[{time_str}] {content}\n"
        else:
            # Default format
            formatted = f"[{time_str}] [{update_type}] {content}\n"

        self.response_text.insert(tk.END, formatted)
        self.response_text.see(tk.END)

    def _clear_responses(self):
        """Clear all responses."""
        self.response_text.delete(1.0, tk.END)
        self.response_history.clear()

    def _save_responses(self):
        """Save responses to a text file."""
        if not self.response_history:
            messagebox.showwarning("No Data", "No responses to save.")
            return

        filename = filedialog.asksaveasfilename(
            title="Save AI Responses", defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )

        if filename:
            try:
                with open(filename, "w", encoding="utf-8") as f:
                    for entry in self.response_history:
                        f.write(f"[{entry['timestamp']}] {entry['type'].upper()}\n")
                        f.write("=" * 60 + "\n")
                        f.write(f"{entry['content']}\n\n")
                messagebox.showinfo("Success", f"Responses saved to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save file: {e}")

    def _export_json(self):
        """Export responses as JSON."""
        if not self.response_history:
            messagebox.showwarning("No Data", "No responses to export.")
            return

        filename = filedialog.asksaveasfilename(
            title="Export AI Responses as JSON",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )

        if filename:
            try:
                with open(filename, "w", encoding="utf-8") as f:
                    json.dump(self.response_history, f, indent=2, ensure_ascii=False)
                messagebox.showinfo("Success", f"Responses exported to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export file: {e}")

    def _on_generate_report(self):
        """Handle Generate Report button click."""
        if self.generate_callback:
            self.generate_callback()
        else:
            messagebox.showinfo("Info", "Report generation callback not linked.")

    def get_widget(self):
        """Return the frame widget."""
        return self.frame
