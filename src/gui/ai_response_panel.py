import json
import tkinter as tk
from datetime import datetime
from queue import Queue
from tkinter import filedialog, messagebox, scrolledtext, ttk
from typing import Literal, Optional, Tuple, Union

from .theme_colors import ThemeColors


class AIResponsePanel:
    """Panel for displaying AI agent responses."""

    def __init__(self, parent, theme_colors: ThemeColors, generate_callback=None):
        self.frame = ttk.LabelFrame(parent, text="AI Agent Responses", padding=10)
        self.generate_callback = generate_callback
        self._theme_colors = theme_colors
        self.response_history: list[dict[str, str]] = []

        # Queues for the asynchronous workers to post results
        self.response_queue: Queue[Union[Tuple[Literal["regular"], str], Tuple[Literal["cot"], str, str]]] = Queue()

        # Setup the GUI
        self._setup_widgets()
        self._setup_text_tags()

        # Start UI callback loops for displaying the results from asynchronous workers.
        self._check_queue()

    def _setup_widgets(self):
        """Setup the AI response widgets."""
        # Get theme colors (fallback to sensible defaults if not initialized)

        if self._theme_colors:
            bg = self._theme_colors.inputbg
            fg = self._theme_colors.inputfg
            selectbg = self._theme_colors.selectbg
            selectfg = self._theme_colors.selectfg
            insertbg = self._theme_colors.fg
            font = self._theme_colors.text_font
        else:
            bg = "#303030"
            fg = "#e0e0e0"
            selectbg = "#505050"
            selectfg = "#ffffff"
            insertbg = "#ffffff"
            font = ("Consolas", 11)

        # Response display with dark theme and better font
        self.response_text = scrolledtext.ScrolledText(
            self.frame,
            height=15,
            width=80,
            font=font,
            wrap=tk.WORD,
            bg=bg,
            fg=fg,
            insertbackground=insertbg,
            selectbackground=selectbg,
            selectforeground=selectfg,
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
        colors = self._theme_colors
        if colors:
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
        else:
            # Fallback colors
            self.response_text.tag_config("header", foreground="#5bc0de", font=("Consolas", 11, "bold"))
            self.response_text.tag_config("separator", foreground="#6c757d")
            self.response_text.tag_config("success", foreground="#5cb85c")
            self.response_text.tag_config("warning", foreground="#f0ad4e")
            self.response_text.tag_config("error", foreground="#d9534f")
            self.response_text.tag_config("info", foreground="#5bc0de")
            self.response_text.tag_config("tool", foreground="#f0ad4e")
            self.response_text.tag_config("reasoning", foreground="#a0a0a0")

    def add_response(self, response_type: str, content: str, timestamp: Optional[datetime] = None):
        """Add a new AI response to the display via queue for thread safety."""
        if timestamp is None:
            timestamp = datetime.now()

        # Store in history
        response_entry = {
            "type": response_type,
            "content": content,
            "timestamp": timestamp.isoformat(),
        }
        self.response_history.append(response_entry)

        # Format the response
        formatted_response = f"\n{'='*60}\n"
        formatted_response += f"[{timestamp.strftime('%H:%M:%S')}] {response_type.upper()}\n"
        formatted_response += f"{'='*60}\n"
        formatted_response += f"{content}\n"

        # Add to queue instead of updating UI directly
        self.response_queue.put(("regular", formatted_response))

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
        response_entry = {
            "type": f"cot_{update_type.lower()}",
            "content": content,
            "timestamp": timestamp.isoformat(),
        }
        self.response_history.append(response_entry)

        # Format based on update type for visual distinction
        time_str = timestamp.strftime("%H:%M:%S")

        if update_type.upper() == "CYCLE":
            # Major cycle separator
            formatted = f"\n{'='*60}\n"
            formatted += f"[{time_str}] {content}\n"
            formatted += f"{'='*60}\n"
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

        # Add to queue with update type for potential tag application
        self.response_queue.put(("cot", formatted, update_type.upper()))

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
            title="Save AI Responses",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
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

    def _check_queue(self):
        """Process items from the response queue on the main thread."""
        try:
            # Process all current items in the queue
            while not self.response_queue.empty():
                item = self.response_queue.get_nowait()

                # Handle regular responses
                if item[0] == "regular":
                    self.response_text.insert(tk.END, item[1])
                    self.response_text.see(tk.END)

                # Handle chain of thought updates
                elif item[0] == "cot":
                    formatted, update_type = item[1], item[2]
                    self.response_text.insert(tk.END, formatted)

                    # Apply appropriate tag based on update type
                    if update_type == "REASONING":
                        last_line_start = self.response_text.index(f"{tk.END} linestart-1c")
                        self.response_text.tag_add("reasoning", last_line_start, tk.END)
                    elif update_type == "TOOL":
                        last_line_start = self.response_text.index(f"{tk.END} linestart-1c")
                        self.response_text.tag_add("tool", last_line_start, tk.END)

                    self.response_text.see(tk.END)

                # Mark as done
                self.response_queue.task_done()

        except Exception as e:
            print(f"Error processing response queue: {e}")

        finally:
            # Schedule next check after 100ms
            self.response_text.after(100, self._check_queue)

    def get_widget(self):
        """Return the frame widget."""
        return self.frame
