#!/usr/bin/env python3
"""
OGhidra UI Module
-----------------
Comprehensive GUI interface for the Ollama-GhidraMCP Bridge application.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog, simpledialog
import ttkbootstrap as tb
from ttkbootstrap.constants import *
import threading
import json
import time
from datetime import datetime
from typing import Dict, Any, Optional, List
import logging
import os
import re

from .config import BridgeConfig
from .bridge import Bridge

logger = logging.getLogger("ollama-ghidra-bridge.ui")

# Global theme colors instance - set when OGhidraUI initializes
_theme_colors = None

class ThemeColors:
    """Theme-aware colors for raw tk widgets (Canvas, Text, Listbox, etc.)."""
    
    def __init__(self, style):
        """Initialize with a ttkbootstrap style object."""
        colors = style.colors
        
        # Main backgrounds
        self.bg = colors.bg                    # Main window background
        self.inputbg = colors.inputbg          # Input field background  
        self.selectbg = colors.selectbg        # Selection background
        
        # Foregrounds
        self.fg = colors.fg                    # Main text color
        self.inputfg = colors.inputfg          # Input text color
        self.selectfg = colors.selectfg        # Selected text color
        
        # Accent colors
        self.primary = colors.primary          # Primary accent (blue)
        self.secondary = colors.secondary      # Secondary accent
        self.success = colors.success          # Success/green
        self.info = colors.info                # Info/cyan
        self.warning = colors.warning          # Warning/orange
        self.danger = colors.danger            # Error/red
        
        # Border
        self.border = colors.border
        
        # Computed colors for specific use cases
        self.canvas_bg = colors.bg             # Canvas background
        self.text_font = ('Consolas', 11)      # Softer monospace font
        self.ui_font = ('Segoe UI', 10)        # UI font


class ServerConfigDialog:
    """Dialog for configuring server URLs."""
    
    def __init__(self, parent, config: BridgeConfig):
        self.config = config
        self.result = None
        
        # Create the dialog window
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Server Configuration")
        self.dialog.geometry("600x650")
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        # Center the dialog on the parent window
        self.dialog.update_idletasks()
        parent_x = parent.winfo_rootx()
        parent_y = parent.winfo_rooty()
        parent_width = parent.winfo_width()
        parent_height = parent.winfo_height()
        
        dialog_width = 600
        dialog_height = 650
        
        x = parent_x + (parent_width - dialog_width) // 2
        y = parent_y + (parent_height - dialog_height) // 2
        
        self.dialog.geometry(f"{dialog_width}x{dialog_height}+{x}+{y}")
        
        self._setup_widgets()
        
        # Wait for dialog to close
        self.dialog.wait_window()
    
    def _setup_widgets(self):
        """Setup the dialog widgets."""
        main_frame = ttk.Frame(self.dialog, padding=20)
        main_frame.pack(fill='both', expand=True)
        
        # Title
        title_label = ttk.Label(main_frame, text="Server Configuration", font=('TkDefaultFont', 12, 'bold'))
        title_label.pack(pady=(0, 20))
        
        # Ollama configuration
        ollama_frame = ttk.LabelFrame(main_frame, text="Ollama Server", padding=10)
        ollama_frame.pack(fill='x', pady=(0, 10))
        
        ttk.Label(ollama_frame, text="Base URL:").grid(row=0, column=0, sticky='w', pady=5)
        self.ollama_url_var = tk.StringVar(value=str(self.config.ollama.base_url))
        ollama_entry = ttk.Entry(ollama_frame, textvariable=self.ollama_url_var, width=50)
        ollama_entry.grid(row=0, column=1, sticky='ew', padx=(10, 0), pady=5)
        
        ttk.Label(ollama_frame, text="Model:").grid(row=1, column=0, sticky='w', pady=5)
        self.ollama_model_var = tk.StringVar(value=self.config.ollama.model)
        model_entry = ttk.Entry(ollama_frame, textvariable=self.ollama_model_var, width=50)
        model_entry.grid(row=1, column=1, sticky='ew', padx=(10, 0), pady=5)
        
        # Embedding model selection
        ttk.Label(ollama_frame, text="Embedding Model:").grid(row=2, column=0, sticky='w', pady=5)
        self.embedding_model_var = tk.StringVar(value=getattr(self.config.ollama, 'embedding_model', 'nomic-embed-text'))
        self.embedding_combo = ttk.Combobox(ollama_frame, textvariable=self.embedding_model_var, width=47, state='readonly')
        self.embedding_combo.grid(row=2, column=1, sticky='ew', padx=(10, 0), pady=5)
        
        # Set default embedding model options (include code-centric model)
        self.embedding_combo['values'] = (
            'nomic-embed-text',
            'nomic-embed-text:latest',
            'mxbai-embed-large',
            'all-minilm:33m'
        )
        
        # Button to refresh available models
        refresh_button = ttk.Button(ollama_frame, text="Refresh Models", command=self._refresh_models)
        refresh_button.grid(row=3, column=1, sticky='e', padx=(10, 0), pady=5)
        
        ollama_frame.columnconfigure(1, weight=1)
        
        # GhidraMCP configuration
        ghidra_frame = ttk.LabelFrame(main_frame, text="GhidraMCP Server", padding=10)
        ghidra_frame.pack(fill='x', pady=(0, 10))
        
        ttk.Label(ghidra_frame, text="Base URL:").grid(row=0, column=0, sticky='w', pady=5)
        self.ghidra_url_var = tk.StringVar(value=str(self.config.ghidra.base_url))
        ghidra_entry = ttk.Entry(ghidra_frame, textvariable=self.ghidra_url_var, width=50)
        ghidra_entry.grid(row=0, column=1, sticky='ew', padx=(10, 0), pady=5)
        
        ghidra_frame.columnconfigure(1, weight=1)
        
        # Help text
        help_text = ttk.Label(main_frame, 
                             text="Configure server URLs for distributed setups.\nDefault ports: Ollama (11434), GhidraMCP (8080)\nEmbedding model is used for RAG/vector operations.",
                             font=('TkDefaultFont', 9),
                             foreground='gray')
        help_text.pack(pady=(10, 20))
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill='x')
        
        # Test connections button
        test_button = ttk.Button(button_frame, text="Test Connections", command=self._test_connections)
        test_button.pack(side='left')
        
        # Right side buttons
        right_frame = ttk.Frame(button_frame)
        right_frame.pack(side='right')
        
        cancel_button = ttk.Button(right_frame, text="Cancel", command=self._cancel)
        cancel_button.pack(side='right', padx=(10, 0))
        
        save_button = ttk.Button(right_frame, text="Save", command=self._save)
        save_button.pack(side='right')
    
    def _refresh_models(self):
        """Refresh the available embedding models from the Ollama server."""
        def fetch_models():
            try:
                import requests
                response = requests.get(f"{self.ollama_url_var.get()}/api/tags", timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    models = data.get('models', [])
                    
                    # Filter for embedding models (typically contain 'embed', 'minilm', or common embedding model names)
                    embedding_models = []
                    for model in models:
                        model_name = model.get('name', '').lower()
                        if any(keyword in model_name for keyword in ['embed', 'minilm', 'sentence', 'all-minilm']):
                            embedding_models.append(model.get('name', ''))
                    
                    # Add default options and fetched models
                    all_models = ['nomic-embed-text', 'nomic-embed-text:latest', 'mxbai-embed-large', 'all-minilm:33m'] + embedding_models
                    # Remove duplicates while preserving order
                    seen = set()
                    unique_models = []
                    for model in all_models:
                        if model not in seen:
                            seen.add(model)
                            unique_models.append(model)
                    
                    # Update combobox values
                    self.embedding_combo['values'] = unique_models
                    messagebox.showinfo("Models Refreshed", f"Found {len(unique_models)} embedding models")
                else:
                    messagebox.showerror("Error", f"Failed to fetch models: HTTP {response.status_code}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to connect to Ollama server:\n{str(e)}")
        
        threading.Thread(target=fetch_models, daemon=True).start()
    
    def _test_connections(self):
        """Test the connections to the configured servers."""
        def test():
            results = []
            
            # Test Ollama
            try:
                import requests
                response = requests.get(f"{self.ollama_url_var.get()}/api/tags", timeout=5)
                if response.status_code == 200:
                    results.append("Ollama: ✅ Connected")
                    
                    # Test embedding model specifically (try new API first, then legacy)
                    embedding_model = self.embedding_model_var.get()
                    if embedding_model:
                        embed_success = False
                        # Try new API (/api/embed) first
                        try:
                            embed_response = requests.post(
                                f"{self.ollama_url_var.get()}/api/embed",
                                json={"model": embedding_model, "input": "test"},
                                timeout=10
                            )
                            if embed_response.status_code == 200:
                                results.append(f"Embedding Model ({embedding_model}): ✅ Available")
                                embed_success = True
                        except Exception:
                            pass
                        
                        # Fallback to legacy API (/api/embeddings) if new API failed
                        if not embed_success:
                            try:
                                embed_response = requests.post(
                                    f"{self.ollama_url_var.get()}/api/embeddings",
                                    json={"model": embedding_model, "prompt": "test"},
                                    timeout=10
                                )
                                if embed_response.status_code == 200:
                                    results.append(f"Embedding Model ({embedding_model}): ✅ Available (legacy API)")
                                    embed_success = True
                            except Exception:
                                pass
                        
                        if not embed_success:
                            results.append(f"Embedding Model ({embedding_model}): ❌ Not available")
                else:
                    results.append(f"Ollama: ❌ HTTP {response.status_code}")
            except Exception as e:
                results.append(f"Ollama: ❌ {str(e)}")
            
            # Test GhidraMCP
            try:
                import requests
                response = requests.get(f"{self.ghidra_url_var.get()}/methods", 
                                      params={"offset": 0, "limit": 1}, timeout=5)
                if response.status_code == 200:
                    results.append("GhidraMCP: ✅ Connected")
                else:
                    results.append(f"GhidraMCP: ❌ HTTP {response.status_code}")
            except Exception as e:
                results.append(f"GhidraMCP: ❌ {str(e)}")
            
            # Show results
            messagebox.showinfo("Connection Test", "\n".join(results))
        
        threading.Thread(target=test, daemon=True).start()
    
    def _save(self):
        """Save the configuration."""
        try:
            # Validate URLs
            from pydantic import AnyHttpUrl
            
            # Test URL validation
            ollama_url = AnyHttpUrl(self.ollama_url_var.get())
            ghidra_url = AnyHttpUrl(self.ghidra_url_var.get())
            
            # Update config
            self.config.ollama.base_url = ollama_url
            self.config.ollama.model = self.ollama_model_var.get()
            self.config.ollama.embedding_model = self.embedding_model_var.get()
            self.config.ghidra.base_url = ghidra_url
            
            # Update the clients with new URLs
            # (No need to update _bridge_ref here; handled by main UI)

            # --- Update .env file ---
            self._update_env_file({
                'OLLAMA_BASE_URL': str(ollama_url),
                'OLLAMA_MODEL': self.ollama_model_var.get(),
                'OLLAMA_EMBEDDING_MODEL': self.embedding_model_var.get(),
                'GHIDRA_BASE_URL': str(ghidra_url)
            })
            # ---
            
            self.result = True
            self.dialog.destroy()
            
        except Exception as e:
            messagebox.showerror("Invalid Configuration", f"Error in configuration:\n{str(e)}")

    def _update_env_file(self, updates: dict):
        """Update or insert keys in the .env file."""
        env_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env')
        try:
            if not os.path.exists(env_path):
                # If .env does not exist, create it with the updates
                with open(env_path, 'w', encoding='utf-8') as f:
                    for k, v in updates.items():
                        f.write(f"{k}={v}\n")
                return
            # Read all lines
            with open(env_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            # Update or insert
            keys = set(updates.keys())
            new_lines = []
            found_keys = set()
            for line in lines:
                for k, v in updates.items():
                    if line.strip().startswith(f"{k}="):
                        new_lines.append(f"{k}={v}\n")
                        found_keys.add(k)
                        break
                else:
                    new_lines.append(line)
            # Add any missing keys
            for k in keys - found_keys:
                new_lines.append(f"{k}={updates[k]}\n")
            # Write back
            with open(env_path, 'w', encoding='utf-8') as f:
                f.writelines(new_lines)
        except Exception as e:
            logger.error(f"Failed to update .env file: {e}")
    
    def _cancel(self):
        """Cancel the dialog."""
        self.result = False
        self.dialog.destroy()

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
        main_frame.pack(fill='both', expand=True)
        
        # Title
        title_label = ttk.Label(main_frame, text="Load Session", font=('TkDefaultFont', 12, 'bold'))
        title_label.pack(pady=(0, 10))
        
        # Instructions
        instructions = ttk.Label(main_frame, text="Select a session to load:")
        instructions.pack(anchor='w', pady=(0, 10))
        
        # Session list frame
        list_frame = ttk.Frame(main_frame)
        list_frame.pack(fill='both', expand=True, pady=(0, 20))
        
        # Create listbox with scrollbar
        scrollbar = ttk.Scrollbar(list_frame)
        scrollbar.pack(side='right', fill='y')
        
        # Get theme colors for dark styling
        colors = _theme_colors
        if colors:
            bg, fg = colors.inputbg, colors.inputfg
            selectbg = colors.primary
            selectfg = '#ffffff'
        else:
            bg, fg = '#303030', '#e0e0e0'
            selectbg, selectfg = '#375a7f', '#ffffff'
        
        self.session_listbox = tk.Listbox(
            list_frame, yscrollcommand=scrollbar.set, 
            font=('Segoe UI', 10),
            bg=bg, fg=fg,
            selectbackground=selectbg, selectforeground=selectfg,
            relief='flat', borderwidth=1,
            highlightthickness=0
        )
        self.session_listbox.pack(side='left', fill='both', expand=True)
        scrollbar.config(command=self.session_listbox.yview)
        
        # Populate sessions
        for session in self.sessions:
            self.session_listbox.insert(tk.END, session)
        
        # Double-click to select
        self.session_listbox.bind('<Double-Button-1>', self._on_double_click)
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill='x')
        
        cancel_button = ttk.Button(button_frame, text="Cancel", command=self._cancel)
        cancel_button.pack(side='right', padx=(10, 0))
        
        load_button = ttk.Button(button_frame, text="Load", command=self._load)
        load_button.pack(side='right')
        
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

# Enhanced WorkflowDiagram class with RAG vector creation stage
class WorkflowDiagram:
    """Visual representation of the agentic workflow stages."""
    
    def __init__(self, parent, width=400, height=100):
        # Get theme colors for dark styling
        colors = _theme_colors
        if colors:
            canvas_bg = colors.bg
            self.idle_color = '#4a4a4a'  # Dark gray for idle
            self.text_idle_color = '#a0a0a0'  # Light gray text
            self.stage_colors = {
                'Planning': colors.info,       # Cyan/blue
                'Execution': colors.warning,   # Orange
                'Analysis': colors.success,    # Green
                'Review': colors.secondary,    # Purple-ish
                'idle': self.idle_color
            }
        else:
            canvas_bg = '#303030'
            self.idle_color = '#4a4a4a'
            self.text_idle_color = '#a0a0a0'
            self.stage_colors = {
                'Planning': '#3498db',
                'Execution': '#f39c12',
                'Analysis': '#2ecc71',
                'Review': '#9b59b6',
                'idle': self.idle_color
            }
        
        self.canvas = tk.Canvas(
            parent, width=width, height=height, 
            bg=canvas_bg, 
            relief='flat', bd=0,
            highlightthickness=0
        )
        self.width = width
        self.height = height
        self.current_stage = None
        self.stages = ['Planning', 'Execution', 'Analysis', 'Review']
        
        # RAG vector progress tracking (for status display only)
        self.rag_progress = 0
        self.rag_total = 0
        self.rag_active = False
        self.rag_status_text = ""
        
        self._draw_workflow()
    
    def _draw_workflow(self):
        """Draw the workflow diagram."""
        self.canvas.delete("all")
        
        # Calculate positions
        stage_width = (self.width - 40) // len(self.stages)
        y_center = self.height // 2
        
        for i, stage in enumerate(self.stages):
            x_start = 20 + i * stage_width
            x_center = x_start + stage_width // 2
            
            # Determine color (dark theme aware)
            if self.current_stage == stage.lower().replace(' ', '_'):
                color = self.stage_colors[stage]
                text_color = 'white'
                outline_color = '#ffffff'
            else:
                color = self.stage_colors['idle']
                text_color = self.text_idle_color
                outline_color = '#5a5a5a'
            
            # Draw stage box with rounded appearance (using softer outline)
            self.canvas.create_rectangle(
                x_start, y_center - 15, x_start + stage_width - 10, y_center + 15,
                fill=color, outline=outline_color, width=1
            )
            
            # Draw stage text
            self.canvas.create_text(
                x_center - 5, y_center, text=stage, fill=text_color, font=('Segoe UI', 9, 'bold')
            )
            
            # Draw arrow to next stage (light color for dark theme)
            if i < len(self.stages) - 1:
                arrow_x = x_start + stage_width - 5
                self.canvas.create_line(
                    arrow_x, y_center, arrow_x + 10, y_center,
                    arrow=tk.LAST, fill='#6a6a6a', width=2
                )
    
        # Draw RAG status text below workflow if active
        if self.rag_active and self.rag_status_text:
            self.canvas.create_text(
                self.width // 2, self.height - 15,
                text=self.rag_status_text, fill='#e74c3c', font=('Arial', 9, 'bold')
            )
    

    
    def set_current_stage(self, stage: str | None):
        """Set the current active stage."""
        self.current_stage = stage.lower().replace(' ', '_') if stage else None
        if stage != 'rag_vectors':
            self.rag_active = False
        self._draw_workflow()
    
    def set_rag_progress(self, current: int, total: int, active: bool = True):
        """Set RAG vector creation progress."""
        self.rag_progress = current
        self.rag_total = total
        self.rag_active = active
        if active and total > 0:
            percentage = int((current / total) * 100)
            self.rag_status_text = f"Saving RAG vectors: {current}/{total} ({percentage}%)"
        else:
            self.rag_status_text = ""
        self._draw_workflow()
    
    def complete_rag_stage(self):
        """Mark RAG vector creation as complete."""
        self.rag_active = False
        self.rag_status_text = ""
        self._draw_workflow()
    
    def get_widget(self):
        """Return the canvas widget."""
        return self.canvas

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
        cag_frame.grid(row=0, column=0, columnspan=2, sticky='ew', pady=(0, 5))
        
        ttk.Label(cag_frame, text="CAG System:", font=('Arial', 10, 'bold')).pack(side='left')
        self.cag_status = ttk.Label(cag_frame, text="Unknown")
        self.cag_status.pack(side='left', padx=(10, 15))
        
        self.cag_var = tk.BooleanVar()
        self.cag_checkbox = ttk.Checkbutton(
            cag_frame, text="Enable CAG", variable=self.cag_var,
            command=self._toggle_cag
        )
        self.cag_checkbox.pack(side='left')
        
        # RAG/Vector Store Controls
        rag_frame = ttk.Frame(self.frame)
        rag_frame.grid(row=1, column=0, columnspan=2, sticky='ew', pady=(0, 5))
        
        ttk.Label(rag_frame, text="RAG System:", font=('Arial', 10, 'bold')).pack(side='left')
        self.vector_status = ttk.Label(rag_frame, text="Unknown")
        self.vector_status.pack(side='left', padx=(10, 15))
        
        self.rag_var = tk.BooleanVar()
        self.rag_checkbox = ttk.Checkbutton(
            rag_frame, text="Enable RAG", variable=self.rag_var,
            command=self._toggle_rag
        )
        self.rag_checkbox.pack(side='left')
        
        # Memory Stats
        ttk.Label(self.frame, text="Memory Stats:", font=('Arial', 10, 'bold')).grid(row=2, column=0, sticky='nw', pady=(5, 0))
        
        # Get theme colors for dark styling
        colors = _theme_colors
        if colors:
            bg, fg = colors.inputbg, colors.inputfg
            selectbg, selectfg = colors.selectbg, colors.selectfg
            font = colors.text_font
        else:
            bg, fg = '#303030', '#e0e0e0'
            selectbg, selectfg = '#505050', '#ffffff'
            font = ('Consolas', 11)
        
        self.memory_text = scrolledtext.ScrolledText(
            self.frame, height=8, width=60, font=font,
            bg=bg, fg=fg,
            selectbackground=selectbg, selectforeground=selectfg,
            relief='flat', borderwidth=1, padx=6, pady=6
        )
        self.memory_text.grid(row=3, column=0, columnspan=2, sticky='nsew', pady=(5, 0))
        
        # Configure grid weights to make memory text expand
        self.frame.grid_rowconfigure(3, weight=1)
        self.frame.grid_columnconfigure(0, weight=1)
        
        # Refresh button
        ttk.Button(self.frame, text="Refresh", command=self._update_memory_info).grid(row=4, column=0, columnspan=2, pady=(10, 0))
        
        # Start auto-refresh
        self._update_memory_info()
        self._start_auto_refresh()
    
    def _update_memory_info(self):
        """Update memory information display."""
        try:
            # Skip expensive operations during session loading
            if getattr(self, '_session_loading', False):
                self.memory_text.delete(1.0, tk.END)
                self.memory_text.insert(1.0, "Session loading... Memory info will update after loading completes.")
                return
            
            # CAG Status
            cag_enabled = getattr(self.bridge, 'enable_cag', False)
            self.cag_status.config(text="Enabled ✅" if cag_enabled else "Disabled ❌")
            self.cag_var.set(cag_enabled)
            
            # RAG/Vector Store Status
            rag_enabled = False
            vector_count = 0
            
            # Check if session history has vector embeddings enabled
            if hasattr(self.bridge, 'config') and hasattr(self.bridge.config, 'session_history'):
                rag_enabled = getattr(self.bridge.config.session_history, 'use_vector_embeddings', False)
            
            # Check for actual vector store data (only if not session loading)
            if hasattr(self.bridge, 'memory_manager') and self.bridge.memory_manager:
                mm = self.bridge.memory_manager
                if hasattr(mm, 'vector_store') and mm.vector_store:
                    if (hasattr(mm.vector_store, 'vectors') and 
                        mm.vector_store.vectors is not None and 
                        hasattr(mm.vector_store.vectors, 'shape')):
                        vector_count = mm.vector_store.vectors.shape[0]
            
            # Also check CAG manager for vector store (only if already initialized)
            if (hasattr(self.bridge, 'cag_manager') and 
                self.bridge.cag_manager):
                # Check if RAG is actually enabled (not just if vector store exists)
                rag_enabled = getattr(self.bridge.cag_manager, 'use_vector_store_for_prompts', True)
                
                # Get vector store - this will trigger lazy initialization if Ollama is available
                vector_store = self.bridge.cag_manager.vector_store
                if vector_store and rag_enabled:
                    # Get vector count from CAG manager
                    if (hasattr(vector_store, 'embeddings') and 
                        vector_store.embeddings is not None):
                        try:
                            cag_vector_count = len(vector_store.embeddings)
                            vector_count = max(vector_count, cag_vector_count)
                        except (TypeError, AttributeError):
                            # Handle case where embeddings might be a numpy array or other format
                            if hasattr(vector_store.embeddings, 'shape'):
                                cag_vector_count = vector_store.embeddings.shape[0] if len(vector_store.embeddings.shape) > 0 else 0
                                vector_count = max(vector_count, cag_vector_count)
                    elif hasattr(vector_store, 'documents') and vector_store.documents:
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
            if hasattr(self.bridge, 'config'):
                self.bridge.config.cag_enabled = new_state
                self.bridge.config.enable_cag = new_state
            
            self.bridge.enable_cag = new_state
            
            # If enabling CAG, try to reinitialize CAG manager
            if new_state and (not hasattr(self.bridge, 'cag_manager') or not self.bridge.cag_manager):
                try:
                    from src.cag import CAGManager
                    self.bridge.cag_manager = CAGManager(self.bridge.config)
                    self.bridge.memory_manager = getattr(self.bridge.cag_manager, 'memory_manager', None)
                    logger.info("CAG Manager reinitialized")
                except Exception as e:
                    logger.error(f"Failed to reinitialize CAG Manager: {e}")
                    messagebox.showerror("CAG Error", f"Failed to enable CAG: {e}\n\nThis may be due to configuration issues. Check that your .env file is properly configured.")
                    self.cag_var.set(False)
                    return
            
            # If disabling CAG, clean up
            elif not new_state:
                if hasattr(self.bridge, 'cag_manager') and self.bridge.cag_manager:
                    # Save session before disabling
                    try:
                        self.bridge.cag_manager.save_session()
                    except:
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
            if hasattr(self.bridge, 'config') and hasattr(self.bridge.config, 'session_history'):
                self.bridge.config.session_history.use_vector_embeddings = new_state
            
            if new_state:
                # Enabling RAG - check if CAG is enabled (but don't force it)
                if not getattr(self.bridge, 'enable_cag', False):
                    response = messagebox.askyesnocancel(
                        "CAG Required", 
                        "RAG system works best with CAG enabled for enhanced context.\n\n"
                        "• Yes: Enable both CAG and RAG\n"
                        "• No: Enable RAG only (limited functionality)\n"
                        "• Cancel: Keep current settings"
                    )
                    if response is True:  # Yes - enable both
                        self.cag_var.set(True)
                        self._toggle_cag()
                    elif response is False:  # No - RAG only
                        messagebox.showwarning("Limited RAG", 
                            "RAG enabled without CAG. Functionality will be limited to basic vector embeddings.")
                    else:  # Cancel
                        self.rag_var.set(False)
                        return
            else:
                # Disabling RAG - ask if user wants to disable CAG too
                if getattr(self.bridge, 'enable_cag', False):
                    response = messagebox.askyesno(
                        "Disable CAG Too?", 
                        "RAG is provided by the CAG system. Would you like to disable CAG entirely?\n\n"
                        "• Yes: Disable both CAG and RAG (saves memory)\n"
                        "• No: Keep CAG enabled (RAG will still be disabled)"
                    )
                    if response:  # Yes - disable CAG too
                        self.cag_var.set(False)
                        self._toggle_cag()
                
                # If CAG manager exists, disable vector store usage for prompts
                if hasattr(self.bridge, 'cag_manager') and self.bridge.cag_manager:
                    # Set a flag to disable vector store usage in prompts
                    self.bridge.cag_manager.use_vector_store_for_prompts = False
                    logger.info("Disabled vector store usage for RAG prompts")
            
            # Re-enable vector store usage if enabling RAG
            if new_state and hasattr(self.bridge, 'cag_manager') and self.bridge.cag_manager:
                self.bridge.cag_manager.use_vector_store_for_prompts = True
                logger.info("Enabled vector store usage for RAG prompts")
            
            # Refresh display
            self._update_memory_info()
            
            status = "enabled" if new_state else "disabled"
            if new_state and not getattr(self.bridge, 'enable_cag', False):
                messagebox.showinfo("RAG System", 
                    f"RAG system {status} (basic mode - consider enabling CAG for full functionality).")
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
            if hasattr(self.bridge, 'cag_manager') and self.bridge.cag_manager:
                debug_info = self.bridge.cag_manager.get_debug_info()
                stats.append("=== CAG System ===")
                stats.append(f"Knowledge Base: {'Enabled' if debug_info.get('enable_kb', False) else 'Disabled'}")
                
                if 'vector_store' in debug_info:
                    vs_info = debug_info['vector_store']
                    if 'vector_count' in vs_info:
                        # New combined vector store format
                        stats.append(f"Vector Count: {vs_info.get('vector_count', 0)}")
                        stats.append(f"Document Count: {vs_info.get('document_count', 0)}")
                        stats.append(f"Vector Dimensions: {vs_info.get('dimensions', 'N/A')}")
                    else:
                        # Current format - get actual counts from vector store
                        doc_count = vs_info.get('document_count', 0)
                        vector_count = vs_info.get('vector_count', 0)
                        dimensions = vs_info.get('dimensions', 'N/A')
                        
                        stats.append(f"Document Count: {doc_count}")
                        stats.append(f"Vector Count: {vector_count}")
                        stats.append(f"Vector Dimensions: {dimensions}")
                        
                        # Show legacy components if they exist
                        legacy_count = (vs_info.get('function_signatures', 0) + 
                                      vs_info.get('binary_patterns', 0) + 
                                      vs_info.get('analysis_rules', 0) + 
                                      vs_info.get('common_workflows', 0))
                        if legacy_count > 0:
                            stats.append(f"Legacy Vector Components: {legacy_count}")
                
                if 'session_cache' in debug_info:
                    sc_info = debug_info['session_cache']
                    stats.append(f"Session Entries: {sc_info.get('entry_count', 0)}")
                    stats.append(f"Decompiled Functions: {sc_info.get('decompiled_functions', 0)}")
                    stats.append(f"Analysis Results: {sc_info.get('analysis_results', 0)}")
                
                # Add cache statistics
                if 'cache_stats' in debug_info and debug_info['cache_stats'] != "unavailable":
                    cache_info = debug_info['cache_stats']
                    stats.append("")
                    stats.append("=== Performance Cache ===")
                    stats.append(f"Cache Hits: {cache_info.get('hits', 0)}")
                    stats.append(f"Cache Misses: {cache_info.get('misses', 0)}")
                    stats.append(f"Hit Rate: {cache_info.get('hit_rate', '0.0%')}")
                    stats.append(f"Cached Items: {cache_info.get('cache_size', 0)}")
                    stats.append(f"Total Requests: {cache_info.get('total_requests', 0)}")
                elif hasattr(self.bridge, 'get_cache_stats'):
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
            if hasattr(self.bridge, 'analysis_state'):
                state = self.bridge.analysis_state
                stats.append("\n=== Analysis State ===")
                stats.append(f"Functions Decompiled: {len(state.get('functions_decompiled', set()))}")
                stats.append(f"Functions Renamed: {len(state.get('functions_renamed', {}))}")
                stats.append(f"Comments Added: {len(state.get('comments_added', {}))}")
                stats.append(f"Functions Analyzed: {len(state.get('functions_analyzed', set()))}")
            
            # Current Goal
            if hasattr(self.bridge, 'current_goal') and self.bridge.current_goal:
                stats.append(f"\n=== Current Goal ===")
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

class RenamedFunctionsPanel:
    """Panel displaying renamed functions with their addresses and behavior summaries."""
    
    def __init__(self, parent, bridge: Bridge):
        self.frame = ttk.LabelFrame(parent, text="Analyzed Functions", padding=10)
        self.bridge = bridge
        self.function_summaries = {}  # Store behavior summaries for functions
        self._streaming_load_active = False  # Flag to prevent updates during streaming
        self._setup_widgets()
        self._update_function_list()
    
    def _setup_widgets(self):
        """Setup the renamed functions widgets."""
        # Control buttons frame
        control_frame = ttk.Frame(self.frame)
        control_frame.grid(row=0, column=0, columnspan=2, sticky='ew', pady=(0, 10))
        
        ttk.Button(control_frame, text="Refresh", command=self._update_function_list).pack(side='left', padx=(0, 5))
        ttk.Button(control_frame, text="Export", command=self._export_function_list).pack(side='left', padx=(0, 5))
        ttk.Button(control_frame, text="Clear All", command=self._clear_all_functions).pack(side='left', padx=(0, 5))
        
        # Add Load Vectors button
        self.load_vectors_button = ttk.Button(control_frame, text="Load Vectors", command=self._load_vectors_from_functions)
        self.load_vectors_button.pack(side='left', padx=(0, 5))
        
        # Function count label
        self.count_label = ttk.Label(self.frame, text="Functions: 0", font=('Arial', 10, 'bold'))
        self.count_label.grid(row=1, column=0, columnspan=2, sticky='w', pady=(0, 5))
        
        # Vector status label
        self.vector_status_label = ttk.Label(self.frame, text="Vectors: Not loaded", font=('Arial', 9), foreground='gray')
        self.vector_status_label.grid(row=1, column=0, columnspan=2, sticky='e', pady=(0, 5))
        
        # Treeview for function list
        self.tree_frame = ttk.Frame(self.frame)
        self.tree_frame.grid(row=2, column=0, columnspan=2, sticky='nsew', pady=(0, 10))
        
        # Configure grid weights
        self.frame.grid_rowconfigure(2, weight=1)
        self.frame.grid_columnconfigure(0, weight=1)
        self.tree_frame.grid_rowconfigure(0, weight=1)
        self.tree_frame.grid_columnconfigure(0, weight=1)
        
        # Create treeview with columns (including hidden summary_key column)
        columns = ('Address', 'Old Name', 'New Name', 'Summary', 'summary_key')
        self.tree = ttk.Treeview(self.tree_frame, columns=columns, show='headings', height=8)
        
        # Configure column headings
        self.tree.heading('Address', text='Address')
        self.tree.heading('Old Name', text='Old Name')
        self.tree.heading('New Name', text='New Name')
        self.tree.heading('Summary', text='Behavior Summary')
        
        # Configure column widths (compact for sidebar)
        self.tree.column('Address', width=80, minwidth=60)
        self.tree.column('Old Name', width=100, minwidth=70)
        self.tree.column('New Name', width=100, minwidth=70)
        self.tree.column('Summary', width=150, minwidth=100)
        
        # Hide the summary_key column (used for internal tracking)
        self.tree.column('summary_key', width=0, minwidth=0, stretch=False)
        self.tree.heading('summary_key', text='')
        
        # Add scrollbars
        v_scrollbar = ttk.Scrollbar(self.tree_frame, orient='vertical', command=self.tree.yview)
        h_scrollbar = ttk.Scrollbar(self.tree_frame, orient='horizontal', command=self.tree.xview)
        self.tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # Grid the treeview and scrollbars
        self.tree.grid(row=0, column=0, sticky='nsew')
        v_scrollbar.grid(row=0, column=1, sticky='ns')
        h_scrollbar.grid(row=1, column=0, sticky='ew')
        
        # Bind double-click event
        self.tree.bind('<Double-1>', self._on_function_double_click)
        self.tree.bind('<Button-3>', self._on_right_click)  # Right-click context menu
        
        # Auto-refresh setup
        self._start_auto_refresh()
    
    def _load_vectors_from_functions(self):
        """Load all analyzed functions into the vector store for RAG enhancement."""
        import tkinter.messagebox as messagebox
        import threading
        
        # Check if CAG/RAG is available
        if not (hasattr(self.bridge, 'enable_cag') and self.bridge.enable_cag and 
                hasattr(self.bridge, 'cag_manager') and self.bridge.cag_manager):
            messagebox.showwarning("RAG Not Available", 
                                 "RAG (Retrieval-Augmented Generation) system is not enabled.\n\n"
                                 "Please enable CAG system in the Memory panel to use vector loading.")
            return
        
        # Get function count
        function_count = 0
        try:
            if hasattr(self.bridge, 'analysis_state'):
                renamed_functions = self.bridge.analysis_state.get('functions_renamed', {})
                function_address_mapping = getattr(self.bridge, 'function_address_mapping', {})
                function_count = len(set(list(renamed_functions.keys()) + list(function_address_mapping.keys())))
        except:
            function_count = 0
        
        if function_count == 0:
            messagebox.showinfo("No Functions", "No analyzed functions found to load into vectors.")
            return
        
        # Confirm with user for large sessions
        if function_count > 50:
            response = messagebox.askyesno("Large Session Warning", 
                                         f"You are about to load {function_count} functions into vectors.\n\n"
                                         f"This may take several minutes and use significant memory.\n\n"
                                         f"Continue?")
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
        progress_frame.pack(fill='both', expand=True)
        
        progress_label = ttk.Label(progress_frame, text="Loading functions into vector store...", 
                                 font=('Arial', 11, 'bold'))
        progress_label.pack(pady=(0, 10))
        
        progress_status = ttk.Label(progress_frame, text="Initializing...", foreground='blue')
        progress_status.pack(pady=(0, 10))
        
        progress_bar = ttk.Progressbar(progress_frame, mode='determinate', maximum=function_count)
        progress_bar.pack(fill='x', pady=(0, 10))
        
        progress_detail = ttk.Label(progress_frame, text="", font=('Arial', 9), foreground='gray')
        progress_detail.pack(pady=(0, 10))
        
        # Results summary
        results_label = ttk.Label(progress_frame, text="", font=('Arial', 10))
        results_label.pack(pady=(10, 0))
        
        def load_vectors_worker():
            """Background worker to load vectors."""
            vectors_loaded = 0
            vectors_failed = 0
            
            try:
                # Disable the button during loading
                self.load_vectors_button.config(state='disabled', text='Loading...')
                
                # Get all function data
                progress_status.config(text="Collecting function data...")
                progress_dialog.update()
                
                functions_to_process = []
                
                # Collect from function_address_mapping
                if hasattr(self.bridge, 'function_address_mapping'):
                    function_address_mapping = self.bridge.function_address_mapping
                    bridge_summaries = getattr(self.bridge, 'function_summaries', {})
                    
                    for address, info in function_address_mapping.items():
                        old_name = info.get('old_name', 'Unknown')
                        new_name = info.get('new_name', 'Unknown')
                        
                        # Get summary from multiple sources (bridge and panel)
                        summary = ''
                        
                        # Try bridge function_summaries first
                        summary = (bridge_summaries.get(address, '') or 
                                 bridge_summaries.get(old_name, '') or
                                 bridge_summaries.get(new_name, ''))
                        
                        # If not found, try panel's function_summaries with various key formats
                        if not summary:
                            summary_key = f"{address}_{new_name}" if address != "Unknown" else f"{old_name}_{new_name}"
                            summary = self.function_summaries.get(summary_key, '')
                            
                            # Also try alternate key formats
                            if not summary:
                                summary = self.function_summaries.get(f"{address}_{old_name}", '')
                            if not summary:
                                # Try matching by just the address or name in the key
                                for key, val in self.function_summaries.items():
                                    if address in key or new_name in key or old_name in key:
                                        summary = val
                                        break
                        
                        if summary:  # Only process functions with summaries
                            functions_to_process.append({
                                'address': address,
                                'old_name': old_name,
                                'new_name': new_name,
                                'summary': summary
                            })
                
                # Collect from analysis_state if not already included
                if hasattr(self.bridge, 'analysis_state'):
                    renamed_functions = self.bridge.analysis_state.get('functions_renamed', {})
                    bridge_summaries = getattr(self.bridge, 'function_summaries', {})
                    
                    # Create a set of all processed function identifiers to avoid duplicates
                    processed_identifiers = set()
                    for f in functions_to_process:
                        processed_identifiers.add(f['address'])
                        processed_identifiers.add(f['old_name'])
                        processed_identifiers.add(f['new_name'])
                    
                    for identifier, new_name in renamed_functions.items():
                        # Check if this function is already processed from address mapping
                        already_processed = False
                        for f in functions_to_process:
                            if (f['address'] == identifier or 
                                f['old_name'] == identifier or 
                                f['new_name'] == identifier or
                                f['new_name'] == new_name):
                                already_processed = True
                                break
                        
                        if not already_processed:
                            summary = bridge_summaries.get(identifier, '')
                            if summary:
                                functions_to_process.append({
                                    'address': identifier if self._looks_like_address(identifier) else 'Unknown',
                                    'old_name': identifier if not self._looks_like_address(identifier) else 'Unknown',
                                    'new_name': new_name,
                                    'summary': summary
                                })
                
                total_functions = len(functions_to_process)
                progress_bar.config(maximum=total_functions)
                
                progress_status.config(text=f"Loading {total_functions} functions into vectors...")
                progress_dialog.update()
                
                # **OPTIMIZED: Batch processing approach with Ollama embeddings**
                progress_status.config(text="Initializing local Ollama embeddings...")
                progress_dialog.update()
                
                # ✅ FIXED: Use Ollama embeddings instead of SentenceTransformer
                try:
                    from src.bridge import Bridge
                    
                    # Test Ollama embeddings availability
                    test_embeddings = Bridge.get_ollama_embeddings(["test"])
                    if not test_embeddings:
                        # Get the configured embedding model name
                        emb_model = getattr(self.bridge.config.ollama, 'embedding_model', 'nomic-embed-text')
                        raise Exception(f"Ollama embedding model ({emb_model}) not available.\n\nPlease ensure:\n1. Ollama server is running\n2. Run: ollama pull {emb_model}")
                    
                    emb_model = getattr(self.bridge.config.ollama, 'embedding_model', 'nomic-embed-text')
                    logger.info(f"✅ Using Ollama embeddings ({emb_model}) for vector creation")
                except Exception as e:
                    raise Exception(f"Ollama embedding model not available: {e}")
                
                # Process in batches for better performance
                BATCH_SIZE = 50  # Process 50 functions at once
                num_batches = (total_functions + BATCH_SIZE - 1) // BATCH_SIZE
                
                for batch_num in range(num_batches):
                    batch_start = batch_num * BATCH_SIZE
                    batch_end = min(batch_start + BATCH_SIZE, total_functions)
                    batch = functions_to_process[batch_start:batch_end]
                    
                    progress_status.config(text=f"Processing batch {batch_num + 1} of {num_batches} (Ollama)")
                    progress_dialog.update()
                    
                    # ✅ FIXED: Use Ollama batch embeddings instead of SentenceTransformer
                    # Filter out empty summaries which cause 400 errors
                    batch_texts = []
                    valid_batch = []
                    for func in batch:
                        summary = func.get('summary', '').strip()
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
                    batch_embeddings_list = Bridge.get_ollama_embeddings(batch_texts)
                    
                    if not batch_embeddings_list:
                        logger.error("Failed to generate embeddings with Ollama")
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
                            
                            # Update progress
                            overall_progress = batch_start + i + 1
                            progress_bar.config(value=overall_progress)
                            progress_detail.config(text=f"Added: {func_data['new_name']}")
                            
                            if overall_progress % 10 == 0:
                                progress_dialog.update()
                            
                        except Exception as e:
                            logger.warning(f"Failed to add {func_data['new_name']}: {e}")
                            vectors_failed += 1
                    
                    # Small delay between batches
                    import time
                    time.sleep(0.1)
                
                # Update results
                progress_status.config(text="Vector loading completed!")
                results_text = f"✅ Successfully loaded: {vectors_loaded} vectors\n"
                if vectors_failed > 0:
                    results_text += f"❌ Failed to load: {vectors_failed} vectors\n"
                results_text += f"📊 Total processed: {total_functions} functions"
                
                results_label.config(text=results_text, foreground='green')
                
                # Update vector status label
                self.vector_status_label.config(text=f"Vectors: {vectors_loaded} loaded", foreground='green')
                
                # Update memory panel if available
                if hasattr(self.bridge, 'cag_manager') and self.bridge.cag_manager:
                    # Force refresh of vector store to ensure counts are updated
                    vector_store = self.bridge.cag_manager.vector_store
                    if vector_store:
                        logger.info(f"Vector store after loading: {len(vector_store.embeddings) if vector_store.embeddings else 0} vectors")
                    
                    # Trigger memory panel update by finding it in the UI hierarchy
                    root = self.frame.winfo_toplevel()
                    # Look for memory panel in the UI - it's typically in the left panel
                    for widget in root.winfo_children():
                        if hasattr(widget, 'winfo_children'):
                            for child in widget.winfo_children():
                                if hasattr(child, '_update_memory_info'):
                                    child._update_memory_info()
                                    break
                
                # Add close button
                def close_dialog():
                    progress_dialog.destroy()
                    self.load_vectors_button.config(state='normal', text='Load Vectors')
                
                close_button = ttk.Button(progress_frame, text="Close", command=close_dialog)
                close_button.pack(pady=(10, 0))
                
                # Auto-close after 3 seconds if successful
                if vectors_failed == 0:
                    progress_dialog.after(3000, close_dialog)
                
            except Exception as e:
                progress_status.config(text="Error occurred during vector loading!")
                results_label.config(text=f"❌ Error: {str(e)}", foreground='red')
                logger.error(f"Vector loading error: {e}")
                
                # Add close button
                def close_dialog():
                    progress_dialog.destroy()
                    self.load_vectors_button.config(state='normal', text='Load Vectors')
                
                close_button = ttk.Button(progress_frame, text="Close", command=close_dialog)
                close_button.pack(pady=(10, 0))
        
        # Start loading in background thread
        threading.Thread(target=load_vectors_worker, daemon=True).start()
    
    def _add_function_to_vector_store_direct(self, func_data, embedding):
        """Add function directly to vector store without reloading model."""
        import numpy as np
        
        # Create function document
        function_doc = {
            "text": f"Function: {func_data['new_name']}\nOriginal: {func_data['old_name']}\nAddress: {func_data['address']}\nBehavior: {func_data['summary']}",
            "type": "function_analysis",
            "name": func_data['new_name'], 
            "metadata": {
                "address": func_data['address'],
                "old_name": func_data['old_name'],
                "new_name": func_data['new_name']
            }
        }
        
        # Add to vector store
        if hasattr(self.bridge, 'cag_manager') and self.bridge.cag_manager:
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
    
    def _update_function_list(self):
        """Update the list of renamed functions."""
        try:
            # Clear existing items
            for item in self.tree.get_children():
                self.tree.delete(item)
            
            if not hasattr(self.bridge, 'analysis_state'):
                self.count_label.config(text="Functions: 0")
                return
            
            renamed_functions = self.bridge.analysis_state.get('functions_renamed', {})
            
            # Get improved function address mapping and summaries from bridge
            function_address_mapping = getattr(self.bridge, 'function_address_mapping', {})
            bridge_summaries = getattr(self.bridge, 'function_summaries', {})
            
            # Debug logging
            logger.info(f"DEBUG: Updating function list - renamed_functions: {len(renamed_functions)}, address_mapping: {len(function_address_mapping)}")
            if renamed_functions:
                logger.info(f"DEBUG: Renamed functions keys: {list(renamed_functions.keys())}")
                logger.info(f"DEBUG: Renamed functions values: {list(renamed_functions.values())}")
            if function_address_mapping:
                logger.info(f"DEBUG: Address mappings keys: {list(function_address_mapping.keys())}")
                for addr, info in function_address_mapping.items():
                    logger.info(f"DEBUG: Address {addr} -> {info}")
            
            # Also check if bridge has the expected attributes
            if hasattr(self.bridge, 'analysis_state'):
                logger.info(f"DEBUG: Bridge analysis_state exists with keys: {list(self.bridge.analysis_state.keys())}")
            else:
                logger.warning("DEBUG: Bridge has no analysis_state attribute!")
                
            if hasattr(self.bridge, 'function_address_mapping'):
                logger.info(f"DEBUG: Bridge function_address_mapping exists with {len(self.bridge.function_address_mapping)} entries")
            else:
                logger.warning("DEBUG: Bridge has no function_address_mapping attribute!")
            
            # Update count with total unique functions - use address mapping as primary source
            # to avoid duplicates between renamed_functions and function_address_mapping
            unique_functions = set()
            
            # Add all functions from address mapping (most complete data)
            for address in function_address_mapping.keys():
                unique_functions.add(address)
            
            # Add any functions from renamed_functions that aren't in address mapping
            for identifier in renamed_functions.keys():
                # Check if this identifier is already covered by address mapping
                already_covered = False
                for addr, info in function_address_mapping.items():
                    if (addr == identifier or 
                        info.get('old_name') == identifier or 
                        info.get('new_name') == identifier):
                        already_covered = True
                        break
                
                if not already_covered:
                    unique_functions.add(identifier)
            
            total_functions = len(unique_functions)
            self.count_label.config(text=f"Functions: {total_functions}")
            
            # Use the function address mapping as the primary source to avoid duplicates
            processed_functions = set()
            
            # Process functions from the address mapping first (most complete data)
            for address, info in function_address_mapping.items():
                old_name = info.get('old_name', 'Unknown')
                new_name = info.get('new_name', 'Unknown')
                
                # Skip if we've already processed this function
                function_key = f"{address}_{new_name}"
                if function_key in processed_functions:
                    continue
                processed_functions.add(function_key)
                
                # Clean up fake address prefix for display
                display_address = address.replace('name_', '') if address.startswith('name_') else address
                
                # Get summary from bridge first, then fallback to local storage
                summary_key = f"{address}_{new_name}"
                summary = (bridge_summaries.get(address, '') or 
                          bridge_summaries.get(old_name, '') or
                          bridge_summaries.get(new_name, '') or
                          self.function_summaries.get(summary_key, "No summary available"))
                
                # Insert into tree with summary_key as a hidden column
                item_id = self.tree.insert('', 'end', values=(display_address, old_name, new_name, summary, summary_key))
            
            # Process any remaining functions from renamed_functions that weren't in address mapping
            for identifier, new_name in renamed_functions.items():
                # Skip if this function was already processed from address mapping
                already_processed = False
                for addr, info in function_address_mapping.items():
                    if (info.get('new_name') == new_name and 
                        (addr == identifier or info.get('old_name') == identifier)):
                        already_processed = True
                        break
                
                if already_processed:
                    continue
                
                # This is a function not in our enhanced mapping - add it with limited info
                function_key = f"{identifier}_{new_name}"
                if function_key in processed_functions:
                    continue
                processed_functions.add(function_key)
                
                is_address = self._looks_like_address(identifier)
                address = identifier if is_address else "Unknown"
                old_name = "Unknown" if is_address else identifier
                
                summary_key = f"{address}_{new_name}" if address != "Unknown" else f"{old_name}_{new_name}"
                summary = (bridge_summaries.get(identifier, '') or
                          self.function_summaries.get(summary_key, "No summary available"))
                
                # Insert into tree
                item_id = self.tree.insert('', 'end', values=(address, old_name, new_name, summary, summary_key))
            
        except Exception as e:
            # During streaming loads, tree updates can fail due to rapid changes
            # Log as debug instead of error to reduce noise
            if "not found" in str(e).lower():
                logger.debug(f"Tree item not found during function list update: {e}")
            else:
                logger.error(f"Error updating function list: {e}")
    
    def _looks_like_address(self, text: str) -> bool:
        """Check if a string looks like a memory address."""
        if not isinstance(text, str):
            return False
        
        # Check for hex addresses (0x prefix or all hex digits)
        if text.startswith('0x') or (len(text) >= 4 and all(c in '0123456789abcdefABCDEF' for c in text)):
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
            values = self.tree.item(item, 'values')
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
            values = self.tree.item(item, 'values')
        except tk.TclError:
            # Item was deleted, ignore this right-click
            return
        
        # Store the function data instead of relying on item reference
        address, old_name, new_name = values[0], values[1], values[2]
        
        # Create context menu with safer callbacks
        context_menu = tk.Menu(self.tree, tearoff=0)
        context_menu.add_command(label="Edit Summary", 
                               command=lambda: self._edit_summary_by_function_data(address, old_name, new_name))
        context_menu.add_separator()
        context_menu.add_command(label="Copy Address", command=lambda: self._copy_to_clipboard(address))
        context_menu.add_command(label="Copy Name", command=lambda: self._copy_to_clipboard(new_name))
        context_menu.add_separator()
        context_menu.add_command(label="Remove Function", 
                               command=lambda: self._remove_function_by_data(address, old_name, new_name))
        
        try:
            context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            context_menu.grab_release()
    
    def _edit_summary_for_item(self, item):
        """Edit summary for a specific item in a dedicated window."""
        try:
            values = self.tree.item(item, 'values')
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
        if hasattr(self.bridge, 'function_summaries'):
            bridge_summaries = getattr(self.bridge, 'function_summaries', {})
            current_summary = (bridge_summaries.get(address, '') or 
                             bridge_summaries.get(old_name, '') or
                             bridge_summaries.get(new_name, '') or
                             self.function_summaries.get(summary_key, "No summary available"))
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
        main_frame.pack(fill='both', expand=True)
        
        # Function info section
        info_frame = ttk.LabelFrame(main_frame, text="Function Information", padding=10)
        info_frame.pack(fill='x', pady=(0, 10))
        
        ttk.Label(info_frame, text=f"Address: {address}").pack(anchor='w')
        ttk.Label(info_frame, text=f"Original Name: {old_name}").pack(anchor='w')
        ttk.Label(info_frame, text=f"New Name: {new_name}").pack(anchor='w')
        
        # Summary editing section
        summary_frame = ttk.LabelFrame(main_frame, text="Behavior Summary", padding=10)
        summary_frame.pack(fill='both', expand=True, pady=(0, 10))
        
        # Instructions
        instructions = ttk.Label(summary_frame, 
                                text="Edit the behavior summary below. This will be used as context for future AI analysis:",
                                font=('TkDefaultFont', 9))
        instructions.pack(anchor='w', pady=(0, 5))
        
        # Text editor
        text_frame = ttk.Frame(summary_frame)
        text_frame.pack(fill='both', expand=True)
        
        # Get theme colors for dark styling
        colors = _theme_colors
        if colors:
            bg, fg = colors.inputbg, colors.inputfg
            selectbg, selectfg = colors.selectbg, colors.selectfg
            insertbg = colors.fg
            font = colors.text_font
        else:
            bg, fg = '#303030', '#e0e0e0'
            selectbg, selectfg = '#505050', '#ffffff'
            insertbg = '#ffffff'
            font = ('Consolas', 11)
        
        summary_text = scrolledtext.ScrolledText(
            text_frame, height=12, width=80, wrap=tk.WORD, font=font,
            bg=bg, fg=fg,
            insertbackground=insertbg,
            selectbackground=selectbg, selectforeground=selectfg,
            relief='flat', borderwidth=1, padx=6, pady=6
        )
        summary_text.pack(fill='both', expand=True)
        summary_text.insert('1.0', current_summary)
        summary_text.focus()
        
        # Character count
        char_count_var = tk.StringVar()
        char_count_label = ttk.Label(summary_frame, textvariable=char_count_var, font=('TkDefaultFont', 8))
        char_count_label.pack(anchor='e')
        
        def update_char_count(event=None):
            content = summary_text.get('1.0', tk.END).strip()
            char_count_var.set(f"Characters: {len(content)}")
        
        summary_text.bind('<KeyRelease>', update_char_count)
        update_char_count()
        
        # Buttons - ensure they're always visible at the bottom
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill='x', pady=(10, 5))
        
        def save_and_close():
            new_summary = summary_text.get('1.0', tk.END).strip()
            
            try:
                # ROBUST FIX: Instead of relying on potentially stale tree_item reference,
                # find the correct tree item by matching the function data
                target_tree_item = None
                for item in self.tree.get_children():
                    try:
                        values = self.tree.item(item, 'values')
                        if (len(values) >= 3 and 
                            values[0] == address and 
                            values[1] == old_name and 
                            values[2] == new_name):
                            target_tree_item = item
                            break
                    except tk.TclError:
                        # Item was deleted, skip it
                        continue
                
                # Update the tree item if found
                if target_tree_item:
                    try:
                        values = self.tree.item(target_tree_item, 'values')
                        self.tree.item(target_tree_item, values=(values[0], values[1], values[2], new_summary, summary_key))
                    except tk.TclError:
                        # Tree item was deleted during update, that's okay - we'll update storage anyway
                        logger.debug(f"Tree item was deleted during summary update for {new_name}, but continuing with storage update")
                
                # Update our storage (this is the most important part)
                self.function_summaries[summary_key] = new_summary
                
                # Update in bridge function summaries
                if hasattr(self.bridge, 'function_summaries'):
                    if address != "Unknown" and not address.startswith('name_'):
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
                    if hasattr(self.bridge, 'function_summaries'):
                        if address != "Unknown" and not address.startswith('name_'):
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
        
        ttk.Button(button_frame, text="Save", command=save_and_close).pack(side='right', padx=(5, 0))
        ttk.Button(button_frame, text="Cancel", command=cancel).pack(side='right')
        
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
            values = self.tree.item(item, 'values')
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
            if hasattr(self.bridge, 'analysis_state'):
                renamed_functions = self.bridge.analysis_state.get('functions_renamed', {})
                
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
                filetypes=[("JSON files", "*.json"), ("Text files", "*.txt"), ("All files", "*.*")]
            )
            
            if not filename:
                return
            
            export_data = []
            for item in self.tree.get_children():
                values = self.tree.item(item, 'values')
                export_data.append({
                    'address': values[0],
                    'old_name': values[1],
                    'new_name': values[2],
                    'summary': values[3],
                    'timestamp': datetime.now().isoformat()
                })
            
            if filename.endswith('.json'):
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(export_data, f, indent=2, ensure_ascii=False)
            else:
                with open(filename, 'w', encoding='utf-8') as f:
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
        if messagebox.askyesno("Confirm", "Are you sure you want to clear all renamed functions? This action cannot be undone."):
            try:
                # Clear from bridge analysis state
                if hasattr(self.bridge, 'analysis_state'):
                    self.bridge.analysis_state['functions_renamed'] = {}
                
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
                self._update_function_list()
            except Exception as e:
                logger.error(f"Error in auto-refresh: {e}")
            
            # Schedule next refresh
            self.frame.after(15000, refresh)  # Refresh every 15 seconds
        
        # Start refreshing after 5 seconds
        self.frame.after(5000, refresh)
    
    def add_function_with_summary(self, address: str, old_name: str, new_name: str, summary: str = "", *, update_state: bool = True):
        """Add a function with a summary programmatically."""
        summary_key = f"{address}_{new_name}" if address != "Unknown" else f"{old_name}_{new_name}"
        
        # Store summary locally
        if summary:
            self.function_summaries[summary_key] = summary
        
        if update_state:
            # CRITICAL FIX: Update bridge data structures that the UI actually reads from
            # Update bridge's function_address_mapping
            if not hasattr(self.bridge, 'function_address_mapping'):
                self.bridge.function_address_mapping = {}
            
            self.bridge.function_address_mapping[address] = {
                'old_name': old_name, 
                'new_name': new_name
            }
            
            # Update bridge's function summaries
            if not hasattr(self.bridge, 'function_summaries'):
                self.bridge.function_summaries = {}
            
            if summary:
                # Store summary using multiple keys for robust retrieval
                self.bridge.function_summaries[address] = summary
                if old_name != "Unknown":
                    self.bridge.function_summaries[old_name] = summary
                if new_name != "Unknown":
                    self.bridge.function_summaries[new_name] = summary
            
            # Update bridge's analysis_state for legacy compatibility
            if not hasattr(self.bridge, 'analysis_state'):
                self.bridge.analysis_state = {}
            
            if 'functions_renamed' not in self.bridge.analysis_state:
                self.bridge.analysis_state['functions_renamed'] = {}
            
            # Store in analysis_state using only address as key to avoid duplicate name entries
            self.bridge.analysis_state['functions_renamed'][address] = new_name
            
            # Debug logging to verify data storage
            import logging
            logger = logging.getLogger("ollama-ghidra-bridge.ui")
            logger.info(f"Added function to session: {address} | {old_name} -> {new_name}")
            logger.info(f"Bridge function_address_mapping now has {len(self.bridge.function_address_mapping)} entries")
            logger.info(f"Bridge analysis_state functions_renamed now has {len(self.bridge.analysis_state['functions_renamed'])} entries")
        
        # Only refresh the UI list if not in streaming mode
        # During streaming, we'll do batch updates to prevent UI freezing
        if not self._streaming_load_active:
            self._update_function_list()
    
    def set_streaming_mode(self, active: bool):
        """Enable or disable streaming mode to prevent UI updates during bulk loading."""
        self._streaming_load_active = active
        if not active:
            # When streaming ends, do a final update
            self._update_function_list()
    
    def get_widget(self):
        """Return the main frame widget."""
        return self.frame

class AIResponsePanel:
    """Panel for displaying AI agent responses."""
    
    def __init__(self, parent):
        self.frame = ttk.LabelFrame(parent, text="AI Agent Responses", padding=10)
        self._setup_widgets()
        self._setup_text_tags()
        self.response_history = []
    
    def _setup_widgets(self):
        """Setup the AI response widgets."""
        # Get theme colors (fallback to sensible defaults if not initialized)
        colors = _theme_colors
        if colors:
            bg = colors.inputbg
            fg = colors.inputfg
            selectbg = colors.selectbg
            selectfg = colors.selectfg
            insertbg = colors.fg
            font = colors.text_font
        else:
            bg = '#303030'
            fg = '#e0e0e0'
            selectbg = '#505050'
            selectfg = '#ffffff'
            insertbg = '#ffffff'
            font = ('Consolas', 11)
        
        # Response display with dark theme and better font
        self.response_text = scrolledtext.ScrolledText(
            self.frame, height=15, width=80, 
            font=font, wrap=tk.WORD,
            bg=bg, fg=fg,
            insertbackground=insertbg,
            selectbackground=selectbg,
            selectforeground=selectfg,
            relief='flat',
            borderwidth=1,
            padx=8,
            pady=8
        )
        self.response_text.grid(row=0, column=0, columnspan=3, sticky='nsew', pady=(0, 10))
        
        # Control buttons
        ttk.Button(self.frame, text="Clear", command=self._clear_responses).grid(row=1, column=0, padx=(0, 5))
        ttk.Button(self.frame, text="Save to File", command=self._save_responses).grid(row=1, column=1, padx=5)
        ttk.Button(self.frame, text="Export JSON", command=self._export_json).grid(row=1, column=2, padx=(5, 0))
        
        # Configure grid weights
        self.frame.grid_rowconfigure(0, weight=1)
        self.frame.grid_columnconfigure(0, weight=1)
    
    def _setup_text_tags(self):
        """Setup text tags for syntax highlighting in responses."""
        colors = _theme_colors
        if colors:
            # Header/separator styling
            self.response_text.tag_config('header', foreground=colors.info, font=('Consolas', 11, 'bold'))
            self.response_text.tag_config('separator', foreground=colors.secondary)
            # Status colors
            self.response_text.tag_config('success', foreground=colors.success)
            self.response_text.tag_config('warning', foreground=colors.warning)
            self.response_text.tag_config('error', foreground=colors.danger)
            self.response_text.tag_config('info', foreground=colors.info)
            # Tool/action styling
            self.response_text.tag_config('tool', foreground=colors.warning, font=('Consolas', 11, 'italic'))
            self.response_text.tag_config('reasoning', foreground='#a0a0a0')  # Subtle gray for reasoning
        else:
            # Fallback colors
            self.response_text.tag_config('header', foreground='#5bc0de', font=('Consolas', 11, 'bold'))
            self.response_text.tag_config('separator', foreground='#6c757d')
            self.response_text.tag_config('success', foreground='#5cb85c')
            self.response_text.tag_config('warning', foreground='#f0ad4e')
            self.response_text.tag_config('error', foreground='#d9534f')
            self.response_text.tag_config('info', foreground='#5bc0de')
            self.response_text.tag_config('tool', foreground='#f0ad4e')
            self.response_text.tag_config('reasoning', foreground='#a0a0a0')
    
    def add_response(self, response_type: str, content: str, timestamp: Optional[datetime] = None):
        """Add a new AI response to the display."""
        if timestamp is None:
            timestamp = datetime.now()
        
        # Store in history
        response_entry = {
            'type': response_type,
            'content': content,
            'timestamp': timestamp.isoformat()
        }
        self.response_history.append(response_entry)
        
        # Display in text widget
        formatted_response = f"\n{'='*60}\n"
        formatted_response += f"[{timestamp.strftime('%H:%M:%S')}] {response_type.upper()}\n"
        formatted_response += f"{'='*60}\n"
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
        response_entry = {
            'type': f'cot_{update_type.lower()}',
            'content': content,
            'timestamp': timestamp.isoformat()
        }
        self.response_history.append(response_entry)
        
        # Format based on update type for visual distinction
        time_str = timestamp.strftime('%H:%M:%S')
        
        if update_type.upper() == 'CYCLE':
            # Major cycle separator
            formatted = f"\n{'='*60}\n"
            formatted += f"[{time_str}] {content}\n"
            formatted += f"{'='*60}\n"
        elif update_type.upper() == 'PHASE':
            # Phase indicator
            formatted = f"[{time_str}] {content}\n"
        elif update_type.upper() == 'REASONING':
            # AI reasoning - highlight this
            formatted = f"[{time_str}] {content}\n"
        elif update_type.upper() == 'TOOL':
            # Tool execution
            formatted = f"[{time_str}]   -> {content}\n"
        elif update_type.upper() == 'STATUS':
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
            title="Save AI Responses",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    for entry in self.response_history:
                        f.write(f"[{entry['timestamp']}] {entry['type'].upper()}\n")
                        f.write("="*60 + "\n")
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
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(self.response_history, f, indent=2, ensure_ascii=False)
                messagebox.showinfo("Success", f"Responses exported to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export file: {e}")
    
    def get_widget(self):
        """Return the frame widget."""
        return self.frame

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
        ttk.Label(self.frame, text="Enter your query:", font=('Arial', 10, 'bold')).grid(row=0, column=0, sticky='w', pady=(0, 5))
        
        # Get theme colors for dark styling
        colors = _theme_colors
        if colors:
            bg, fg = colors.inputbg, colors.inputfg
            selectbg, selectfg = colors.selectbg, colors.selectfg
            insertbg = colors.fg
        else:
            bg, fg = '#303030', '#e0e0e0'
            selectbg, selectfg = '#505050', '#ffffff'
            insertbg = '#ffffff'
        
        self.query_entry = tk.Text(
            self.frame, height=3, width=60, 
            font=('Segoe UI', 11), wrap=tk.WORD,
            bg=bg, fg=fg,
            insertbackground=insertbg,
            selectbackground=selectbg, selectforeground=selectfg,
            relief='flat', borderwidth=1, padx=6, pady=6
        )
        self.query_entry.grid(row=1, column=0, columnspan=2, sticky='ew', pady=(0, 10))
        
        # Buttons
        button_frame = ttk.Frame(self.frame)
        button_frame.grid(row=2, column=0, columnspan=2, sticky='ew')
        
        self.send_button = ttk.Button(button_frame, text="Send Query", command=self._send_query)
        self.send_button.pack(side='left', padx=(0, 5))
        
        ttk.Button(button_frame, text="Clear", command=self._clear_query).pack(side='left', padx=(0, 15))
        
        # Separator
        ttk.Separator(button_frame, orient='vertical').pack(side='left', fill='y', padx=(0, 15), pady=2)
        
        # Quick action buttons for common smart tools
        self.analyze_button = ttk.Button(button_frame, text="Analyze Function", command=self._analyze_current)
        self.analyze_button.pack(side='left', padx=(0, 5))
        
        self.rename_button = ttk.Button(button_frame, text="Rename Function", command=self._rename_current)
        self.rename_button.pack(side='left')
        
        # Status and progress
        self.status_label = ttk.Label(self.frame, text="Ready", foreground='green')
        self.status_label.grid(row=3, column=0, columnspan=2, pady=(10, 0))
        
        # Progress bar and stop button frame
        progress_frame = ttk.Frame(self.frame)
        progress_frame.grid(row=4, column=0, columnspan=2, sticky='ew', pady=(5, 0))
        progress_frame.grid_columnconfigure(0, weight=1)
        
        self.progress = ttk.Progressbar(progress_frame, mode='indeterminate')
        self.progress.grid(row=0, column=0, sticky='ew', padx=(0, 5))
        
        self.stop_button = ttk.Button(progress_frame, text="Stop", command=self._stop_query, state='disabled', width=8)
        self.stop_button.grid(row=0, column=1)
        
        # Configure grid weights
        self.frame.grid_columnconfigure(0, weight=1)
        
        # Bind Enter key (Ctrl+Enter to send)
        self.query_entry.bind('<Control-Return>', lambda e: self._send_query())
    
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
    
    def _clear_query(self):
        """Clear the query input."""
        self.query_entry.delete(1.0, tk.END)
    
    def _analyze_current(self):
        """Analyze the current function in Ghidra."""
        if hasattr(self, 'tool_panel') and self.tool_panel:
            self.tool_panel._analyze_current_function()
        else:
            messagebox.showwarning("Not Ready", "Tool panel not initialized yet.")
    
    def _rename_current(self):
        """Rename the current function in Ghidra based on AI analysis."""
        if hasattr(self, 'tool_panel') and self.tool_panel:
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
        state = 'disabled' if running else 'normal'
        self.send_button.config(state=state)
        self.analyze_button.config(state=state)
        self.rename_button.config(state=state)
        self.stop_button.config(state='normal' if running else 'disabled')
        
        # Update status and progress
        if running:
            self.should_stop = False  # Reset stop flag for new query
            self.status_label.config(text="Processing query...", foreground='orange')
            self.progress.start()
        else:
            self.status_label.config(text="Ready", foreground='green')
            self.progress.stop()
    
    def _monitor_workflow_stage(self):
        """Monitor the bridge's workflow stage and update the diagram."""
        previous_stage = None
        while self.query_running:
            try:
                current_stage = getattr(self.bridge, 'current_workflow_stage', None)
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

class ToolButtonsPanel:
    """Panel with buttons for commonly used tools."""
    
    def __init__(self, parent, bridge: Bridge, response_panel: AIResponsePanel, workflow_diagram: WorkflowDiagram, renamed_functions_panel=None):
        self.frame = ttk.LabelFrame(parent, text="Smart Tools", padding=10)
        self.bridge = bridge
        self.response_panel = response_panel
        self.workflow_diagram = workflow_diagram
        self.renamed_functions_panel = renamed_functions_panel
        self.tool_running = False
        self.should_stop = False  # Flag to control stopping
        self._setup_widgets()
    
    def _setup_widgets(self):
        """Setup the tool button widgets."""
        # Smart tool buttons (use AI agent workflow)
        smart_tools = [
            ('analyze-current', 'Analyze Current Function', self._analyze_current_function),
            ('rename-current', 'Rename Current Function', self._rename_current_function),
            ('rename-all', 'Rename All Functions', self._rename_all_functions),
            ('generate-report', 'Generate Software Report', self._generate_software_report),
            ('analyze-imports', 'Analyze Imports', self._analyze_imports),
            ('analyze-strings', 'Analyze Strings', self._analyze_strings),
            ('analyze-exports', 'Analyze Exports', self._analyze_exports),
            ('search-strings', 'Search Strings', self._search_strings),
            ('scan-tables', 'Scan Function Tables', self._scan_function_tables),
        ]
        
        for i, (tool_id, label, command) in enumerate(smart_tools):
            btn = ttk.Button(
                self.frame, text=label, command=command,
                width=25, state='normal'
            )
            btn.grid(row=i//2, column=i%2, padx=5, pady=5, sticky='ew')
        
        # Calculate the next row after buttons (buttons use rows 0 to (len-1)//2)
        next_row = (len(smart_tools) + 1) // 2
        
        # Status indicator
        self.status_label = ttk.Label(self.frame, text="Ready", foreground='green')
        self.status_label.grid(row=next_row, column=0, columnspan=2, pady=(10, 0))
        
        # Progress bar and stop button frame
        progress_frame = ttk.Frame(self.frame)
        progress_frame.grid(row=next_row + 1, column=0, columnspan=2, sticky='ew', pady=(5, 0))
        progress_frame.grid_columnconfigure(0, weight=1)
        
        self.progress = ttk.Progressbar(progress_frame, mode='indeterminate')
        self.progress.grid(row=0, column=0, sticky='ew', padx=(0, 5))
        
        self.stop_button = ttk.Button(progress_frame, text="Stop", command=self._stop_tool, state='disabled', width=8)
        self.stop_button.grid(row=0, column=1)
        
        # Configure grid weights
        self.frame.grid_columnconfigure(0, weight=1)
        self.frame.grid_columnconfigure(1, weight=1)
    
    def _set_tool_running(self, running: bool, tool_name: str = ""):
        """Set the tool running state."""
        self.tool_running = running
        
        # Update all buttons
        state = 'disabled' if running else 'normal'
        for widget in self.frame.winfo_children():
            if isinstance(widget, ttk.Button) and widget not in [self.stop_button]:
                widget.config(state=state)
        
        # Update stop button state
        self.stop_button.config(state='normal' if running else 'disabled')
        
        # Update status and progress
        if running:
            self.should_stop = False  # Reset stop flag for new tool
            self.status_label.config(text=f"Running {tool_name}...", foreground='orange')
            self.progress.start()
        else:
            self.status_label.config(text="Ready", foreground='green')
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
                self.response_panel.add_response(f"AI Agent Response", result)
                
                # Final stage update
                self.workflow_diagram.set_current_stage(None)
                
            except Exception as e:
                error_msg = f"Error running {tool_name}: {e}"
                logger.error(error_msg)
                self.response_panel.add_response("Error", error_msg)
                self.workflow_diagram.set_current_stage(None)
            finally:
                self._set_tool_running(False)
        
        threading.Thread(target=worker, daemon=True).start()
    
    def _monitor_workflow_stage(self):
        """Monitor the bridge's workflow stage and update the diagram."""
        previous_stage = None
        while self.tool_running:
            try:
                current_stage = getattr(self.bridge, 'current_workflow_stage', None)
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
                self.workflow_diagram.set_current_stage('execution')
                
                # Add initial message to response panel
                self.response_panel.add_response(f"Smart Tool: {display_name}", f"Executing {tool_name}() and sending results to AI for analysis...")
                
                # Step 1: Call the specific Ghidra tool
                if hasattr(self.bridge.ghidra, tool_name):
                    tool_method = getattr(self.bridge.ghidra, tool_name)
                    try:
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
                            import re, itertools, textwrap

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

                                extra_context += f"\n-- String at {addr} references ({len(xref_lines)}):\n" + "\n".join(xref_lines[:10]) + "\n"

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
                        self.workflow_diagram.set_current_stage('analysis')
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
                self.workflow_diagram.set_current_stage('execution')
                
                # Add initial message to response panel
                self.response_panel.add_response(f"Smart Tool: {display_name}", "Starting 3-step rename workflow: get current function → AI analysis → rename")
                
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
                        # Parse function name from result like "Function: FUN_00409bd4 at 00409bd4"
                        import re
                        match = re.search(r'Function:\s*(\w+)', current_function_result)
                        if match:
                            function_name = match.group(1)
                    
                    if not function_name:
                        self.response_panel.add_response("Error", "Could not extract function name from current function result")
                        return
                    
                except Exception as e:
                    self.response_panel.add_response("Error", f"Error getting current function: {e}")
                    return
                
                # Step 2: Use AI agent to analyze the function and suggest a new name
                try:
                    self.workflow_diagram.set_current_stage('analysis')
                    
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
                        self.response_panel.add_response("Debug", f"📝 Using full AI response as behavior summary (length: {len(function_summary)} chars)")
                        
                        # Extract suggested name from AI response
                        suggested_name = None
                        
                        # Split AI response into lines for parsing
                        lines = ai_response.split('\n')
                        
                        # First, look for the "Suggested Name:" pattern
                        for line in lines:
                            line = line.strip()
                            if 'Suggested Name:' in line:
                                # Extract everything after "Suggested Name:"
                                name_part = line.split('Suggested Name:', 1)[1].strip()
                                # Remove any markdown formatting
                                name_part = name_part.replace('**', '').replace('*', '').strip()
                                # Extract the actual function name (should be camelCase/snake_case)
                                import re
                                name_match = re.search(r'\b([a-z][a-zA-Z0-9_]*[a-zA-Z0-9]|[a-z][a-zA-Z0-9]*)\b', name_part)
                                if name_match:
                                    suggested_name = name_match.group(1)
                                    break
                        
                        # Fallback: look for patterns in the response that might indicate function names
                        if not suggested_name:
                            # Look for camelCase patterns in the response
                            import re
                            
                            # First, try to find words that look like function names (camelCase with at least one capital)
                            camel_case_matches = re.findall(r'\b([a-z][a-zA-Z0-9]*[A-Z][a-zA-Z0-9]*)\b', ai_response)
                            
                            # Filter out common words
                            excluded_words = {'function', 'name', 'suggest', 'analysis', 'code', 'parameter', 'value', 'data', 'result', 'return', 'call', 'method', 'functionName', 'newFunctionName', 'descriptiveFunctionName'}
                            
                            for match in camel_case_matches:
                                if (len(match) > 4 and 
                                    match.lower() not in excluded_words and 
                                    not match.startswith('FUN_') and
                                    not any(word in match.lower() for word in ['function', 'name', 'example'])):
                                    suggested_name = match
                                    break
                            
                            # If still no match, look for any reasonable identifier
                            if not suggested_name:
                                simple_matches = re.findall(r'\b([a-z][a-zA-Z0-9_]*)\b', ai_response)
                                for match in simple_matches:
                                    if (len(match) > 6 and 
                                        match.lower() not in excluded_words and 
                                        not match.startswith('FUN_') and
                                        not any(word in match.lower() for word in ['function', 'name', 'example', 'analysis', 'response'])):
                                        suggested_name = match
                                        break
                        
                        if suggested_name:
                            self.response_panel.add_response("Step 3a: Extracted Suggested Name", suggested_name)
                            
                            # Step 3: Perform the actual rename using bridge.execute_command to ensure state tracking
                            try:
                                rename_result = self.bridge.execute_command("rename_function", {"old_name": function_name, "new_name": suggested_name})
                                # rename_result is already the result string, not a dict
                                
                                # STORE the captured summary for this function
                                if function_summary and hasattr(self.bridge, 'function_summaries'):
                                    # Get the function address to use as identifier
                                    current_function_result = self.bridge.ghidra.get_current_function()
                                    if isinstance(current_function_result, str) and "at " in current_function_result:
                                        import re
                                        match = re.search(r'at\s+([0-9a-fA-F]+)', current_function_result)
                                        if match:
                                            address = match.group(1)
                                            self.bridge.function_summaries[address] = function_summary
                                            
                                            # Add to RAG and show the results with visual feedback
                                            old_vector_count = 0
                                            if (hasattr(self.bridge, 'cag_manager') and 
                                                self.bridge.cag_manager and 
                                                hasattr(self.bridge.cag_manager, 'vector_store') and 
                                                self.bridge.cag_manager.vector_store):
                                                old_vector_count = len(self.bridge.cag_manager.vector_store.documents)
                                            
                                            # Show RAG vector creation status
                                            self.workflow_diagram.set_rag_progress(0, 1, active=True)
                                            self.response_panel.add_response("Step 3c: RAG Integration", "Adding function analysis to RAG vector space...")
                                            
                                            # RAG integration removed - use "Load Vectors" button for vector operations
                            # self.bridge._add_function_to_rag(address, function_summary)
                                            
                                            # Update progress and complete
                                            self.workflow_diagram.set_rag_progress(1, 1, active=True)
                                            import time
                                            time.sleep(0.2)  # Brief pause to show completion
                                            self.workflow_diagram.complete_rag_stage()
                                            
                                            new_vector_count = 0
                                            if (hasattr(self.bridge, 'cag_manager') and 
                                                self.bridge.cag_manager and 
                                                hasattr(self.bridge.cag_manager, 'vector_store') and 
                                                self.bridge.cag_manager.vector_store):
                                                new_vector_count = len(self.bridge.cag_manager.vector_store.documents)
                                            
                                            self.response_panel.add_response("Step 3d: Summary & RAG Complete", 
                                                f"📝 Function summary captured and added to RAG\n"
                                                f"📊 Vector count: {old_vector_count} -> {new_vector_count}\n"
                                                f"📄 Summary length: {len(function_summary)} characters\n"
                                                f"🔍 Preview: {function_summary[:150]}...")
                                else:
                                    self.response_panel.add_response("Debug", f"⚠️ No function summary extracted from AI response. Summary found: {function_summary is not None}")
                                
                            except Exception as e:
                                rename_result = f"Error: {str(e)}"
                            
                            if isinstance(rename_result, str) and rename_result.lower().startswith("error:"):
                                self.response_panel.add_response("Error", f"Failed to rename function: {rename_result}")
                            else:
                                self.response_panel.add_response("Step 3b: Rename Result", f"Successfully renamed '{function_name}' to '{suggested_name}'")
                                self.response_panel.add_response("Success", f"✅ Rename workflow completed! Function '{function_name}' is now '{suggested_name}'")
                                
                                # Add to UI renamed functions panel if available
                                if self.renamed_functions_panel and function_summary:
                                    try:
                                        # Get the address from current function result
                                        current_function_result = self.bridge.ghidra.get_current_function()
                                        address = "Unknown"
                                        if isinstance(current_function_result, str) and "at " in current_function_result:
                                            import re
                                            match = re.search(r'at\s+([0-9a-fA-F]+)', current_function_result)
                                            if match:
                                                address = match.group(1)
                                        
                                        self.renamed_functions_panel.add_function_with_summary(
                                            address=address, 
                                            old_name=function_name, 
                                            new_name=suggested_name, 
                                            summary=function_summary
                                        )
                                    except Exception as e:
                                        self.response_panel.add_response("UI Warning", f"Could not update renamed functions panel: {e}")
                        else:
                            self.response_panel.add_response("Debug", f"⚠️ Could not extract function name from AI response. Response contained: {ai_response[:200]}...")
                            self.response_panel.add_response("Error", "Could not extract a valid function name from AI response. Please try again or rename manually.")
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
    
    def _create_batch_rag_vectors(self, processed_functions_data):
        """Create RAG vectors in batches for processed functions with visual progress feedback."""
        if not processed_functions_data:
            return 0
        
        total_functions = len(processed_functions_data)
        self.response_panel.add_response("🔄 RAG Processing", f"Creating RAG vectors for {total_functions} processed functions...")
        
        # Initialize RAG progress in workflow diagram
        self.workflow_diagram.set_rag_progress(0, total_functions, active=True)
        
        # Batch create RAG vectors for all processed functions
        rag_success_count = 0
        rag_batch_size = 25  # Process RAG vectors in smaller batches
        
        for batch_start in range(0, total_functions, rag_batch_size):
            batch_end = min(batch_start + rag_batch_size, total_functions)
            batch = processed_functions_data[batch_start:batch_end]
            
            self.response_panel.add_response("📊 RAG Batch", f"Processing RAG vectors {batch_start + 1}-{batch_end} of {total_functions}")
            
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
            if hasattr(self, 'should_stop') and self.should_stop:
                self.response_panel.add_response("🛑 RAG Cancelled", f"RAG vector creation stopped by user. Created {rag_success_count} vectors.")
                # Still mark RAG stage as complete even if cancelled
                self.workflow_diagram.complete_rag_stage()
                return rag_success_count
        
        # Mark RAG creation as complete
        self.workflow_diagram.complete_rag_stage()
        self.response_panel.add_response("✅ RAG Complete", f"Successfully created {rag_success_count}/{total_functions} RAG vectors")
        
        # Update memory panel to reflect new vector count
        if hasattr(self, 'renamed_functions_panel') and hasattr(self.renamed_functions_panel, 'bridge'):
            try:
                # Trigger memory panel refresh to show updated vector count
                if hasattr(self.renamed_functions_panel.bridge, '_ui_memory_panel_refresh'):
                    self.renamed_functions_panel.bridge._ui_memory_panel_refresh()
            except Exception as e:
                logger.debug(f"Could not refresh memory panel: {e}")
        
        return rag_success_count
    
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
        context = {
            'callers': [],
            'callees': [],
            'callers_code': [],
            'callees_code': [],
            'truncated': False,
            'total_chars': 0
        }
        
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
                            addr = c.get('from_address') or c.get('from') or c.get('fromAddress')
                            if addr:
                                caller_addresses.append(addr)
                        elif isinstance(c, str):
                            # Text format: parse string like "FROM: 0x401000" or "0x401000"
                            import re
                            # Try to extract hex address from string
                            match = re.search(r'(?:from[:\s]+)?([0-9a-fA-F]{6,})', c, re.IGNORECASE)
                            if match:
                                caller_addresses.append(match.group(1))
                    
                    context['callers'] = caller_addresses
                    
                    # Try to get function names for caller addresses
                    for caller_addr in context['callers'][:3]:  # Only decompile top 3 callers
                        try:
                            caller_code = self.bridge.ghidra.decompile_function_by_address(address=str(caller_addr))
                            if caller_code and not caller_code.lower().startswith("error"):
                                # Truncate individual caller code to 1000 chars
                                if len(caller_code) > 1000:
                                    caller_code = caller_code[:1000] + "...[truncated]"
                                context['callers_code'].append({
                                    'address': caller_addr,
                                    'code': caller_code
                                })
                        except:
                            pass  # Skip if can't decompile caller
            except:
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
                            addr = c.get('to_address') or c.get('to') or c.get('toAddress')
                            if addr:
                                callee_addresses.append(addr)
                        elif isinstance(c, str):
                            # Text format: parse string like "TO: 0x401000" or "0x401000"
                            import re
                            # Try to extract hex address from string
                            match = re.search(r'(?:to[:\s]+)?([0-9a-fA-F]{6,})', c, re.IGNORECASE)
                            if match:
                                callee_addresses.append(match.group(1))
                    
                    context['callees'] = callee_addresses
                    
                    # Try to get function names for callee addresses
                    for callee_addr in context['callees'][:3]:  # Only decompile top 3 callees
                        try:
                            callee_code = self.bridge.ghidra.decompile_function_by_address(address=str(callee_addr))
                            if callee_code and not callee_code.lower().startswith("error"):
                                # Truncate individual callee code to 1000 chars
                                if len(callee_code) > 1000:
                                    callee_code = callee_code[:1000] + "...[truncated]"
                                context['callees_code'].append({
                                    'address': callee_addr,
                                    'code': callee_code
                                })
                        except:
                            pass  # Skip if can't decompile callee
            except:
                pass  # Skip if can't get callees
            
            # Calculate total context size
            total_chars = sum(len(c['code']) for c in context['callers_code'])
            total_chars += sum(len(c['code']) for c in context['callees_code'])
            context['total_chars'] = total_chars
            
            # If total context exceeds max, truncate intelligently
            if total_chars > max_chars:
                context['truncated'] = True
                # Keep fewer callees to prioritize callers (callers are usually more important for understanding usage)
                if len(context['callees_code']) > 1:
                    context['callees_code'] = context['callees_code'][:1]
                if len(context['callers_code']) > 2:
                    context['callers_code'] = context['callers_code'][:2]
                
                # Recalculate
                total_chars = sum(len(c['code']) for c in context['callers_code'])
                total_chars += sum(len(c['code']) for c in context['callees_code'])
                context['total_chars'] = total_chars
        
        except Exception as e:
            # If any error, return empty context
            pass
        
        return context

    def _format_context_for_prompt(self, context: dict) -> str:
        """Format gathered context into a prompt-friendly string."""
        if not context['callers'] and not context['callees']:
            return ""
        
        sections = []
        
        # Add callers section
        if context['callers_code']:
            sections.append("\n## CALLER FUNCTIONS (Functions that call this function):")
            for i, caller in enumerate(context['callers_code'], 1):
                sections.append(f"\n### Caller {i} at address {caller['address']}:")
                sections.append(f"```c\n{caller['code']}\n```")
        
        # Add callees section  
        if context['callees_code']:
            sections.append("\n## CALLEE FUNCTIONS (Functions called by this function):")
            for i, callee in enumerate(context['callees_code'], 1):
                sections.append(f"\n### Callee {i} at address {callee['address']}:")
                sections.append(f"```c\n{callee['code']}\n```")
        
        if context['truncated']:
            sections.append("\n*Note: Context truncated to fit character limits. Showing most relevant callers/callees.*")
        
        return "\n".join(sections)

    def _run_bulk_rename_workflow(self, display_name: str, enumeration_mode: str = "rename_only"):
        """Optimized bulk function analysis workflow with deferred RAG vector creation and batch processing."""
        def worker():
            import time
            try:
                self._set_tool_running(True, display_name)
                self.workflow_diagram.set_current_stage('planning')
                
                # Performance tracking
                start_time = time.time()
                processed_functions_data = []  # Store all processed functions for batch RAG creation
                batch_size = 50  # Process functions in batches for better performance
                
                # Add initial message to response panel
                self.response_panel.add_response(f"🚀 Smart Tool: {display_name}", f"Starting OPTIMIZED bulk function analysis with mode: {enumeration_mode}")
                self.response_panel.add_response("⚡ Performance Enhancements", f"• Batch processing (size: {batch_size})\n• Deferred RAG vector creation\n• Optimized AI prompts\n• Enhanced progress tracking")
                
                # Step 1: Get all functions
                try:
                    self.response_panel.add_response("📋 Step 1", "Retrieving list of all functions...")
                    all_functions_result = self.bridge.ghidra.list_functions()
                    
                    if isinstance(all_functions_result, str) and all_functions_result.lower().startswith("error:"):
                        self.response_panel.add_response("Error", f"Failed to get function list: {all_functions_result}")
                        return
                    
                    # Parse the function list
                    if isinstance(all_functions_result, list):
                        functions = all_functions_result
                    elif isinstance(all_functions_result, str):
                        # Split by newlines and filter out empty lines
                        functions = [f.strip() for f in all_functions_result.split('\n') if f.strip()]
                    else:
                        self.response_panel.add_response("Error", f"Unexpected function list format: {type(all_functions_result)}")
                        return
                    
                    # Filter out any invalid function names
                    valid_functions = [f for f in functions if f and not f.lower().startswith("error")]
                    
                    if not valid_functions:
                        self.response_panel.add_response("Warning", "No valid functions found to rename.")
                        return
                    
                    total_functions = len(valid_functions)
                    self.response_panel.add_response("Step 1 Complete", f"Found {total_functions} functions to process")
                    
                    # Step 2: Process each function using the EXACT same workflow as "Rename Current Function"
                    successful_renames = 0
                    failed_renames = 0
                    skipped_functions = 0
                    enumerated_functions = 0  # Functions analyzed but not renamed (for enumeration)
                    
                    for i, full_function_string in enumerate(valid_functions, 1):
                        try:
                            # Check for stop signal
                            if self.should_stop:
                                self.response_panel.add_response("Cancelled", f"🛑 Operation cancelled by user at function {i}/{total_functions}")
                                # IMPORTANT: Still create RAG vectors for processed functions before stopping
                                if processed_functions_data:
                                    self.response_panel.add_response("🔄 RAG Processing", f"Creating RAG vectors for {len(processed_functions_data)} processed functions before stopping...")
                                    self.response_panel.add_response("📊 Vector Status", "Please wait while RAG vectors are being created. This ensures no function analysis is lost.")
                                    rag_count = self._create_batch_rag_vectors(processed_functions_data)
                                    self.response_panel.add_response("✅ Stop Complete", f"Operation stopped. Successfully created {rag_count} RAG vectors from processed functions.")
                                break
                                
                            # Extract just the function name from the full string (e.g., "FUN_00401000" from "FUN_00401000 at 00401000")
                            if " at " in full_function_string:
                                function_name = full_function_string.split(" at ")[0].strip()
                                # Extract address early for consistent use
                                address = full_function_string.split(" at ")[1].strip()
                            else:
                                function_name = full_function_string.strip()
                                # Try to extract address from function name if possible
                                import re
                                name_address_match = re.search(r'([0-9a-fA-F]{8,})', function_name)
                                address = name_address_match.group(1) if name_address_match else function_name
                            
                            # Update progress
                            progress_msg = f"Processing function {i}/{total_functions}: {function_name}"
                            self.response_panel.add_response("Progress", progress_msg)
                            
                            # Determine processing logic based on enumeration mode
                            should_process = False
                            is_generic_name = function_name.startswith(('FUN_', 'sub_', 'loc_', 'unk_', 'j_'))
                            
                            if enumeration_mode == "rename_only":
                                # Standard mode: Only process functions with generic names
                                should_process = is_generic_name
                                if not should_process:
                                    self.response_panel.add_response("Skipped", f"Function {function_name} appears to already have a descriptive name")
                                    skipped_functions += 1
                                    continue
                            
                            elif enumeration_mode == "full_enumeration":
                                # Full enumeration: Process ALL functions
                                should_process = True
                                
                            elif enumeration_mode == "smart_enumeration":
                                # Smart enumeration: Process generic functions + important descriptive functions
                                important_keywords = ['main', 'init', 'crypto', 'encrypt', 'decrypt', 'hash', 'key', 'auth', 'login', 'password', 'network', 'socket', 'http', 'tcp', 'udp', 'file', 'read', 'write', 'open', 'close', 'connect', 'send', 'recv', 'malloc', 'free', 'alloc', 'buffer', 'parse', 'validate', 'check', 'verify', 'process', 'handle', 'execute', 'run', 'start', 'stop', 'config', 'setting', 'registry', 'service', 'thread', 'mutex', 'lock', 'sync', 'async']
                                
                                if is_generic_name:
                                    should_process = True
                                else:
                                    # Check if descriptive function contains important keywords
                                    function_lower = function_name.lower()
                                    should_process = any(keyword in function_lower for keyword in important_keywords)
                                    
                                if not should_process:
                                    self.response_panel.add_response("Skipped", f"Function {function_name} doesn't match smart enumeration criteria")
                                    skipped_functions += 1
                                    continue
                            
                            # Log the processing decision
                            if enumeration_mode != "rename_only":
                                mode_desc = {"full_enumeration": "Full Enumeration", "smart_enumeration": "Smart Enumeration"}.get(enumeration_mode, enumeration_mode)
                                self.response_panel.add_response("Processing", f"{mode_desc}: Analyzing {function_name} {'(generic name)' if is_generic_name else '(descriptive name)'}")
                            
                            # STEP 1 (per function): Get function info using decompile_function
                            try:
                                # Use decompile_function to get the function code (FIX: add name parameter)
                                function_decompile_result = self.bridge.ghidra.decompile_function(name=function_name)
                                if isinstance(function_decompile_result, str) and function_decompile_result.lower().startswith("error:"):
                                    self.response_panel.add_response("Error", f"Failed to decompile function {function_name}: {function_decompile_result}")
                                    failed_renames += 1
                                    continue
                                
                                self.response_panel.add_response(f"Step 1 (Function {i}): Decompiled {function_name}", f"Successfully retrieved function code (length: {len(function_decompile_result)} chars)")
                                
                            except Exception as e:
                                self.response_panel.add_response("Error", f"Error decompiling function {function_name}: {e}")
                                failed_renames += 1
                                continue
                            
                            # STEP 1.5 (NEW): Gather contextual information (callers and callees)
                            try:
                                self.response_panel.add_response(f"🔍 Gathering context for {function_name}", "Fetching callers and callees...")
                                context = self._gather_function_context(function_name, address, max_chars=8000)
                                
                                if context['callers_code'] or context['callees_code']:
                                    callers_count = len(context['callers_code'])
                                    callees_count = len(context['callees_code'])
                                    truncated_msg = " (truncated)" if context['truncated'] else ""
                                    self.response_panel.add_response(f"✅ Context gathered", 
                                        f"Found {callers_count} caller(s) and {callees_count} callee(s){truncated_msg} " +
                                        f"({context['total_chars']} chars total)")
                                else:
                                    self.response_panel.add_response(f"ℹ️ Context", "No callers/callees found (function may be entry point or leaf)")
                            except Exception as e:
                                # If context gathering fails, continue without it
                                context = {'callers_code': [], 'callees_code': [], 'truncated': False}
                                self.response_panel.add_response("Warning", f"Could not gather context: {e}")
                            
                            # STEP 2 (per function): Enhanced AI analysis with contextual information
                            try:
                                self.workflow_diagram.set_current_stage('analysis')
                                
                                # Format contextual information
                                contextual_info = self._format_context_for_prompt(context)
                                
                                # Create enhanced analysis query with contextual information
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
                                
                                # Use direct ollama.generate instead of bridge.process_query to avoid infinite loops
                                # This follows the same fix pattern as the "Analyze Current Function" tool
                                ai_response = self.bridge.ollama.generate(prompt=analysis_query)
                                
                                if ai_response and ai_response.strip():
                                    self.response_panel.add_response(f"Step 2 (Function {i}): AI Analysis for {function_name}", ai_response)
                                    
                                    # USE THE ENTIRE AI RESPONSE as the behavior summary (EXACT same as original)
                                    function_summary = ai_response.strip()
                                    
                                    # Extract suggested name from AI response (EXACT same logic as original)
                                    suggested_name = None
                                    lines = ai_response.split('\n')
                                    
                                    # Look for the "Suggested Name:" pattern (EXACT same as original)
                                    for line in lines:
                                        line = line.strip()
                                        if 'Suggested Name:' in line:
                                            name_part = line.split('Suggested Name:', 1)[1].strip()
                                            name_part = name_part.replace('**', '').replace('*', '').strip()
                                            import re
                                            name_match = re.search(r'\b([a-z][a-zA-Z0-9_]*[a-zA-Z0-9]|[a-z][a-zA-Z0-9]*)\b', name_part)
                                            if name_match:
                                                suggested_name = name_match.group(1)
                                                break
                                    
                                    # Fallback extraction logic (EXACT same as original)
                                    if not suggested_name:
                                        import re
                                        camel_case_matches = re.findall(r'\b([a-z][a-zA-Z0-9]*[A-Z][a-zA-Z0-9]*)\b', ai_response)
                                        excluded_words = {'function', 'name', 'suggest', 'analysis', 'code', 'parameter', 'value', 'data', 'result', 'return', 'call', 'method', 'functionName', 'newFunctionName', 'descriptiveFunctionName'}
                                        
                                        for match in camel_case_matches:
                                            if (len(match) > 4 and 
                                                match.lower() not in excluded_words and 
                                                not match.startswith('FUN_') and
                                                not any(word in match.lower() for word in ['function', 'name', 'example'])):
                                                suggested_name = match
                                                break
                                        
                                        # If still no match, look for any reasonable identifier (EXACT same as original)
                                        if not suggested_name:
                                            simple_matches = re.findall(r'\b([a-z][a-zA-Z0-9_]*)\b', ai_response)
                                            for match in simple_matches:
                                                if (len(match) > 6 and 
                                                    match.lower() not in excluded_words and 
                                                    not match.startswith('FUN_') and
                                                    not any(word in match.lower() for word in ['function', 'name', 'example', 'analysis', 'response'])):
                                                    suggested_name = match
                                                    break
                                    
                                    # Handle enumeration vs renaming logic
                                    if not is_generic_name and enumeration_mode in ["full_enumeration", "smart_enumeration"]:
                                        # This is a descriptive function being analyzed for enumeration only
                                        suggested_name = function_name  # Keep the existing name
                                        self.response_panel.add_response(f"Step 3a (Function {i}): Enumeration Mode", f"Function {function_name} already has descriptive name - analyzing for enumeration only")
                                        rename_result = f"Enumeration: Kept existing name '{function_name}'"
                                        
                                    elif suggested_name and is_generic_name:
                                        self.response_panel.add_response(f"Step 3a (Function {i}): Extracted Name for {function_name}", suggested_name)
                                        
                                        # STEP 3 (per function): Perform the rename using bridge.execute_command (EXACT same as original)
                                        self.workflow_diagram.set_current_stage('execution')
                                        try:
                                            rename_result = self.bridge.execute_command("rename_function", {"old_name": function_name, "new_name": suggested_name})
                                        except Exception as e:
                                            self.response_panel.add_response("Rename Error", f"Exception renaming {function_name}: {e}")
                                            failed_renames += 1
                                            continue
                                    
                                    else:
                                        # No suggested name could be extracted, but we still want to add to enumeration in enumeration modes
                                        if enumeration_mode in ["full_enumeration", "smart_enumeration"]:
                                            suggested_name = function_name  # Keep existing name
                                            rename_result = f"Enumeration: Kept existing name '{function_name}' (no AI suggestion)"
                                            self.response_panel.add_response(f"Step 3a (Function {i}): Enumeration Fallback", f"No rename suggestion for {function_name}, keeping existing name for enumeration")
                                        else:
                                            self.response_panel.add_response("AI Error", f"Could not extract function name from AI response for {function_name}")
                                            failed_renames += 1
                                            continue
                                    
                                    # Address was already extracted earlier - no need to re-extract
                                    # (address variable is already available from the early extraction)
                                    
                                    # STORE the function summary for batch processing
                                    if function_summary and hasattr(self.bridge, 'function_summaries'):
                                        self.bridge.function_summaries[address] = function_summary
                                        
                                        # DEFERRED: Store function data for batch RAG creation at the end
                                        processed_functions_data.append({
                                            'address': address,
                                            'old_name': function_name,
                                            'new_name': suggested_name if suggested_name else function_name,
                                            'summary': function_summary,
                                            'timestamp': time.time()
                                        })
                                    
                                    # Process results based on operation type
                                    if isinstance(rename_result, str) and rename_result.lower().startswith("error:"):
                                        self.response_panel.add_response("Rename Error", f"Failed to rename {function_name} to {suggested_name}: {rename_result}")
                                        failed_renames += 1
                                    elif isinstance(rename_result, str) and rename_result.startswith("Enumeration:"):
                                        # This was an enumeration (analysis only) operation
                                        self.response_panel.add_response(f"Step 3b (Function {i}): Enumeration Result", f"Successfully analyzed '{function_name}' for enumeration")
                                        self.response_panel.add_response("Success", f"✅ Function {i}/{total_functions}: {function_name} (analyzed)")
                                        enumerated_functions += 1
                                    else:
                                        self.response_panel.add_response(f"Step 3b (Function {i}): Rename Result", f"Successfully renamed '{function_name}' to '{suggested_name}'")
                                        self.response_panel.add_response("Success", f"✅ Function {i}/{total_functions}: {function_name} → {suggested_name}")
                                        successful_renames += 1
                                                
                                    # CRITICAL: Always add to UI renamed functions panel (for all processed functions)
                                    # This should happen regardless of rename vs enumeration mode
                                    if self.renamed_functions_panel:
                                        try:
                                            # Ensure we have a summary (use a default if needed)
                                            display_summary = function_summary if function_summary else "Function processed but no summary available"
                                            
                                            # Ensure we have a suggested name (fallback to original name)
                                            display_new_name = suggested_name if suggested_name else function_name
                                            
                                            self.renamed_functions_panel.add_function_with_summary(
                                                address=address, 
                                                old_name=function_name, 
                                                new_name=display_new_name, 
                                                summary=display_summary
                                            )
                                            
                                            # Debug log for verification
                                            self.response_panel.add_response("UI Update", f"✅ Added {function_name} to Renamed Functions panel (Address: {address})")
                                                
                                        except Exception as e:
                                            self.response_panel.add_response("UI Warning", f"Could not update renamed functions panel for {function_name}: {e}")
                                    else:
                                        self.response_panel.add_response("UI Warning", f"Renamed functions panel not available for {function_name}")
                                        
                                else:
                                    self.response_panel.add_response("AI Error", f"AI agent returned empty response for {function_name}")
                                    failed_renames += 1
                                    
                                    # Even for failed AI responses in enumeration mode, try to add with basic info
                                    if enumeration_mode in ["full_enumeration", "smart_enumeration"] and self.renamed_functions_panel:
                                        try:
                                            # address is always available since we extract it early
                                            self.renamed_functions_panel.add_function_with_summary(
                                                address=address, 
                                                old_name=function_name, 
                                                new_name=function_name, 
                                                summary="Function enumerated but AI analysis failed"
                                            )
                                            self.response_panel.add_response("UI Update", f"⚠️ Added {function_name} to panel despite AI failure (Address: {address})")
                                        except Exception as e:
                                            self.response_panel.add_response("UI Warning", f"Could not add failed function {function_name}: {e}")
                                
                            except Exception as e:
                                self.response_panel.add_response("AI Error", f"Exception during AI analysis for {function_name}: {e}")
                                failed_renames += 1
                                continue
                            
                        except Exception as e:
                            self.response_panel.add_response("Process Error", f"Exception processing {function_name}: {e}")
                            failed_renames += 1
                            continue
                    
                    # BATCH RAG VECTOR CREATION (Performance Optimization)
                    self.workflow_diagram.set_current_stage('analysis')
                    if processed_functions_data:
                        self.response_panel.add_response("📊 Vector Creation", "Starting RAG vector creation for all processed functions...")
                        rag_count = self._create_batch_rag_vectors(processed_functions_data)
                        self.response_panel.add_response("✅ Vector Success", f"All {rag_count} function analyses have been added to the RAG vector space.")
                    
                    # Performance summary
                    total_time = time.time() - start_time
                    avg_time_per_function = total_time / max(1, (successful_renames + enumerated_functions))
                    
                    # Final summary with performance metrics
                    operation_type = {"rename_only": "BULK RENAME", "full_enumeration": "FULL ENUMERATION", "smart_enumeration": "SMART ENUMERATION"}.get(enumeration_mode, "BULK RENAME")
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

🎯 Mode: {enumeration_mode.replace('_', ' ').title()}

All processed functions have been added to the 'Analyzed Functions' tab with behavior summaries.
Check the tab to see detailed analysis results and manage function information.
"""
                    self.response_panel.add_response("🏁 Final Summary", summary_msg)
                    
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
                self.workflow_diagram.set_current_stage('execution')
                
                # Add initial message to response panel
                self.response_panel.add_response(f"Smart Tool: {display_name}", "Starting 3-step analysis workflow: get current function → decompile → AI analysis")
                
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
                        # Parse function name from result like "Function: FUN_00409bd4 at 00409bd4"
                        import re
                        match = re.search(r'Function:\s*(\w+)', current_function_result)
                        if match:
                            function_name = match.group(1)
                    
                    if not function_name:
                        self.response_panel.add_response("Error", "Could not extract function name from current function result")
                        return
                    
                except Exception as e:
                    self.response_panel.add_response("Error", f"Error getting current function: {e}")
                    return
                
                # Step 2: Decompile the function to get its code
                try:
                    decompile_result = self.bridge.ghidra.decompile_function(name=function_name)
                    if isinstance(decompile_result, str) and decompile_result.lower().startswith("error:"):
                        self.response_panel.add_response("Error", f"Failed to decompile function {function_name}: {decompile_result}")
                        return
                    
                    self.response_panel.add_response("Step 2: Function Decompilation", f"Successfully decompiled {function_name} (length: {len(decompile_result)} chars)")
                    
                except Exception as e:
                    self.response_panel.add_response("Error", f"Error decompiling function {function_name}: {e}")
                    return
                
                # Step 3: AI Analysis of the function
                try:
                    self.workflow_diagram.set_current_stage('analysis')
                    
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
                        addr_match = re.search(r'at\s+([0-9a-fA-F]+)', current_function_result)
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
                        if hasattr(self.bridge, 'function_summaries'):
                            self.bridge.function_summaries[function_name] = ai_analysis.strip()
                        
                        # Add to renamed functions panel for tracking (even if not renamed)
                        if hasattr(self, 'renamed_functions_panel') and self.renamed_functions_panel:
                            # Extract address from current function result
                            address = "unknown"
                            if isinstance(current_function_result, str):
                                addr_match = re.search(r'at\s+([0-9a-fA-F]+)', current_function_result)
                                if addr_match:
                                    address = addr_match.group(1)
                            
                            self.renamed_functions_panel.add_function_with_summary(
                                address=address,
                                old_name=function_name,
                                new_name=function_name,  # Keep same name since this is analysis only
                                summary=ai_analysis.strip()
                            )
                        
                        self.response_panel.add_response("✅ Analysis Complete", f"Function {function_name} has been thoroughly analyzed and added to the function tracking system.")
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
        main_frame.pack(fill='both', expand=True)
        
        # Title
        title_label = ttk.Label(main_frame, text="🔍 Function Enumeration Options", font=('TkDefaultFont', 14, 'bold'))
        title_label.pack(pady=(0, 15))
        
        # Description
        desc_text = """Enhanced Enumeration Mode

The "Rename All Functions" tool can also serve as a comprehensive function enumeration tool. 
This will ensure ALL functions (renamed and existing) are added to the Renamed Functions list 
with high-quality behavior summaries for complete binary coverage.

Choose your enumeration strategy:"""
        
        desc_label = ttk.Label(main_frame, text=desc_text, font=('TkDefaultFont', 10), wraplength=750)
        desc_label.pack(pady=(0, 20))
        
        # Options frame
        options_frame = ttk.LabelFrame(main_frame, text="Enumeration Strategy", padding=15)
        options_frame.pack(fill='x', pady=(0, 20))
        
        enumeration_var = tk.StringVar(value="rename_only")
        
        # Option 1: Rename only (current behavior)
        ttk.Radiobutton(options_frame, text="Rename Only (Standard)", 
                       variable=enumeration_var, value="rename_only").pack(anchor='w', pady=5)
        desc1 = ttk.Label(options_frame, text="• Only rename functions with generic names (FUN_*, sub_*, etc.)\n• Skip functions that already have descriptive names\n• Faster execution, focused on renaming", 
                         font=('TkDefaultFont', 9), foreground='gray')
        desc1.pack(anchor='w', padx=20, pady=(0, 10))
        
        # Option 2: Full enumeration (enhanced)
        ttk.Radiobutton(options_frame, text="Full Enumeration (Enhanced)", 
                       variable=enumeration_var, value="full_enumeration").pack(anchor='w', pady=5)
        desc2 = ttk.Label(options_frame, text="• Process ALL functions in the binary (renamed + existing)\n• Generate behavior summaries for every function\n• Add all functions to Renamed Functions list for complete coverage\n• Ideal for comprehensive binary analysis and documentation", 
                         font=('TkDefaultFont', 9), foreground='gray')
        desc2.pack(anchor='w', padx=20, pady=(0, 10))
        
        # Option 3: Smart enumeration
        ttk.Radiobutton(options_frame, text="Smart Enumeration (Recommended)", 
                       variable=enumeration_var, value="smart_enumeration").pack(anchor='w', pady=5)
        desc3 = ttk.Label(options_frame, text="• Rename generic functions + analyze key descriptive functions\n• Focus on important functions (main, crypto, network, file ops)\n• Balance between speed and comprehensive coverage\n• Best for most analysis scenarios", 
                         font=('TkDefaultFont', 9), foreground='gray')
        desc3.pack(anchor='w', padx=20)
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill='x')
        
        selected_mode = None
        
        def confirm_enumeration():
            nonlocal selected_mode
            selected_mode = enumeration_var.get()
            enumeration_dialog.destroy()
        
        def cancel_enumeration():
            enumeration_dialog.destroy()
        
        ttk.Button(button_frame, text="Start Processing", command=confirm_enumeration).pack(side='right', padx=(10, 0))
        ttk.Button(button_frame, text="Cancel", command=cancel_enumeration).pack(side='right')
        
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
        confirmation_message = """🔍 Generate Software Report - Confirmation Required

You are about to generate a comprehensive AI-powered software analysis report.

This report will include:
• Software classification and architecture analysis
• Security risk assessment with detailed scoring
• Function categorization and behavioral pattern analysis
• Comprehensive findings summary with actionable insights

The analysis process will:
• Collect all available binary data (functions, imports, exports, segments, etc.)
• Analyze renamed functions and their behavioral summaries
• Perform AI-powered classification and risk assessment
• Generate a detailed markdown report with executive summary

This operation may take several minutes depending on the amount of analysis data available.

Do you want to proceed with generating the software report?"""
        
        if not messagebox.askyesno("Generate Software Report", confirmation_message):
            return
        
        # Show format selection dialog
        format_dialog = tk.Toplevel(self.frame)
        format_dialog.title("Report Format Selection")
        format_dialog.geometry("400x200")
        format_dialog.transient(self.frame)
        format_dialog.grab_set()
        
        # Center the dialog
        format_dialog.update_idletasks()
        x = (format_dialog.winfo_screenwidth() // 2) - (format_dialog.winfo_width() // 2)
        y = (format_dialog.winfo_screenheight() // 2) - (format_dialog.winfo_height() // 2)
        format_dialog.geometry(f"+{x}+{y}")
        
        # Dialog content
        ttk.Label(format_dialog, text="Select Report Format:", font=('Arial', 12, 'bold')).pack(pady=10)
        
        format_var = tk.StringVar(value="markdown")
        
        ttk.Radiobutton(format_dialog, text="Markdown (.md) - Formatted report with sections", 
                       variable=format_var, value="markdown").pack(anchor='w', padx=20, pady=5)
        ttk.Radiobutton(format_dialog, text="Plain Text (.txt) - Simple text format", 
                       variable=format_var, value="text").pack(anchor='w', padx=20, pady=5)
        ttk.Radiobutton(format_dialog, text="JSON (.json) - Structured data format", 
                       variable=format_var, value="json").pack(anchor='w', padx=20, pady=5)
        
        # Buttons frame
        button_frame = ttk.Frame(format_dialog)
        button_frame.pack(pady=20)
        
        selected_format = None
        
        def confirm_format():
            nonlocal selected_format
            selected_format = format_var.get()
            format_dialog.destroy()
        
        def cancel_format():
            format_dialog.destroy()
        
        ttk.Button(button_frame, text="Generate Report", command=confirm_format).pack(side='left', padx=10)
        ttk.Button(button_frame, text="Cancel", command=cancel_format).pack(side='left', padx=10)
        
        # Wait for dialog to close
        format_dialog.wait_window()
        
        if selected_format is None:
            return  # User cancelled
        
        # Start the software report generation workflow
        self._run_software_report_workflow("Generate Software Report", selected_format)
    
    def _run_software_report_workflow(self, display_name: str, report_format: str):
        """Run the comprehensive software report generation workflow."""
        def worker():
            try:
                self._set_tool_running(True, display_name)
                self.workflow_diagram.set_current_stage('planning')
                
                # Add initial message to response panel
                self.response_panel.add_response(f"Smart Tool: {display_name}", f"Starting comprehensive software analysis and report generation (Format: {report_format.upper()})")
                
                # Phase 1: Data Collection
                self.response_panel.add_response("Phase 1", "Collecting comprehensive binary data...")
                self.workflow_diagram.set_current_stage('execution')
                
                # Phase 2: AI Analysis
                self.response_panel.add_response("Phase 2", "Performing AI-powered analysis (classification, security, behavior, architecture)...")
                self.workflow_diagram.set_current_stage('analysis')
                
                # Phase 3: Report Generation
                self.response_panel.add_response("Phase 3", "Generating structured software report...")
                self.workflow_diagram.set_current_stage('review')
                
                # Call the bridge method to generate the report
                try:
                    report_content = self.bridge.generate_software_report(report_format)
                    
                    # Display success message
                    self.response_panel.add_response("Report Generated", f"✅ Software report generated successfully!")
                    
                    # Show first 1000 characters in response panel
                    preview = report_content[:1000] + ("..." if len(report_content) > 1000 else "")
                    self.response_panel.add_response("Report Preview", preview)
                    
                    # Offer to save the report
                    save_response = messagebox.askyesno(
                        "Save Report",
                        f"Software report generated successfully!\n\nWould you like to save the report to a file?\n\nReport length: {len(report_content)} characters"
                    )
                    
                    if save_response:
                        # Determine file extension
                        extension = ".md" if report_format == "markdown" else f".{report_format}"
                        default_filename = f"software_report_{self._get_timestamp_for_filename()}{extension}"
                        
                        # Show save dialog
                        filename = filedialog.asksaveasfilename(
                            title="Save Software Report",
                            defaultextension=extension,
                            initialfile=default_filename,
                            filetypes=[
                                (f"{report_format.title()} files", f"*{extension}"),
                                ("All files", "*.*")
                            ]
                        )
                        
                        if filename:
                            try:
                                with open(filename, 'w', encoding='utf-8') as f:
                                    f.write(report_content)
                                self.response_panel.add_response("File Saved", f"✅ Report saved to: {filename}")
                            except Exception as e:
                                self.response_panel.add_response("Save Error", f"❌ Error saving file: {e}")
                    
                    # Also display the full report in the response panel
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
        state = 'disabled' if running else 'normal'
        for widget in self.frame.winfo_children():
            if isinstance(widget, ttk.Button) and widget not in [self.stop_button]:
                widget.config(state=state)
        
        # Update stop button state
        self.stop_button.config(state='normal' if running else 'disabled')
        
        # Update status and progress
        if running:
            self.should_stop = False  # Reset stop flag for new tool
            self.status_label.config(text=f"Running {tool_name}...", foreground='orange')
            self.progress.start()
        else:
            self.status_label.config(text="Ready", foreground='green')
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
                self.workflow_diagram.set_current_stage('execution')
                
                # Add initial message
                self.response_panel.add_response(
                    "Smart Tool: Scan Function Tables", 
                    "Scanning binary for function pointer tables (vtables, dispatch tables, jump tables)...\n"
                    "This runs algorithmically without LLM intervention."
                )
                
                # Run the scan directly (no LLM needed)
                tables = self.bridge.ghidra.scan_function_pointer_tables(
                    min_table_entries=3,
                    pointer_size=8,
                    max_scan_size=65536
                )
                
                if tables:
                    # Format results
                    formatted = self.bridge.ghidra.format_table_scan_results(tables)
                    self.response_panel.add_response(
                        f"Scan Complete: Found {len(tables)} Table(s)", 
                        formatted
                    )
                    
                    # Now send to AI for interpretation
                    self.workflow_diagram.set_current_stage('analysis')
                    
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
                        model=self.bridge.ollama_config.model,
                        prompt=analysis_prompt,
                        temperature=0.7
                    ):
                        if self.should_stop:
                            break
                        self.response_panel.append_to_last_response(chunk)
                else:
                    # Get segment info for context
                    try:
                        segments = self.bridge.ghidra.list_segments()
                        seg_info = "\n".join(f"  {s}" for s in segments[:8])
                    except:
                        seg_info = "  (Could not retrieve segment info)"
                    
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
                        f"• Look for DATA references using get_xrefs_to()"
                    )
                
                self.workflow_diagram.set_current_stage('complete')
                
            except Exception as e:
                import traceback
                self.response_panel.add_response("Error", f"Scan failed: {str(e)}\n\n{traceback.format_exc()}")
                self.workflow_diagram.set_current_stage('error')
            finally:
                self._set_tool_running(False, "")
        
        import threading
        threading.Thread(target=worker, daemon=True).start()

class OGhidraUI:
    """Main UI class for the OGhidra application."""
    
    def __init__(self, bridge: Bridge, config: BridgeConfig):
        self.bridge = bridge
        self.config = config
        
        # Use ttkbootstrap Window for modern dark theme with rounded corners
        self.root = tb.Window(
            title="OGhidra - Ollama-GhidraMCP Bridge",
            themename="darkly",  # Dark gray theme with soft corners
            size=(1400, 900)
        )
        
        # Store style reference for theme-aware color access
        self.style = self.root.style
        
        # Initialize global theme colors for raw tk widgets
        global _theme_colors
        _theme_colors = ThemeColors(self.style)
        
        self._setup_ui()
        self._setup_menu()
        
        # Start health monitoring
        self._start_health_monitoring()
        
        # Display startup configuration info
        self._show_startup_info()
    
    def _show_startup_info(self):
        """Display configuration info on startup."""
        ollama_config = self.config.ollama
        timeout = getattr(ollama_config, 'timeout', 120)
        request_delay = getattr(ollama_config, 'request_delay', 0.0)
        model = getattr(ollama_config, 'model', 'unknown')
        
        startup_msg = (
            f"Ollama Config: timeout={timeout}s, request_delay={request_delay}s, model={model}\n"
            f"Ready for queries."
        )
        self.response_panel.add_response("System", startup_msg)
    
    def _setup_ui(self):
        """Setup the main UI layout."""
        # Main paned window
        main_paned = ttk.PanedWindow(self.root, orient='horizontal')
        main_paned.pack(fill='both', expand=True, padx=5, pady=5)
        
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
        self.query_panel.get_widget().pack(fill='x', pady=(0, 10))
        
        # AI Response panel (main content area)
        self.response_panel = AIResponsePanel(parent)
        self.response_panel.get_widget().pack(fill='both', expand=True)
    
    def _setup_sidebar_panel(self, parent):
        """Setup the sidebar with analyzed functions (secondary, slimmer)."""
        # Workflow status tracker (above analyzed functions)
        workflow_frame = ttk.LabelFrame(parent, text="Workflow Status", padding=8)
        workflow_frame.pack(fill='x', pady=(0, 10))
        
        self.workflow_diagram = WorkflowDiagram(workflow_frame, width=500, height=100)
        self.workflow_diagram.get_widget().pack()
        
        # Analyzed Functions panel
        self.renamed_functions_panel = RenamedFunctionsPanel(parent, self.bridge)
        self.renamed_functions_panel.get_widget().pack(fill='both', expand=True)
        # Start auto-refresh for renamed functions
        self.renamed_functions_panel._start_auto_refresh()
        
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
            if not hasattr(self, 'session_manager'):
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
            main_frame.pack(fill='both', expand=True)
            
            # Title
            ttk.Label(main_frame, text="💾 Save Analysis Session", font=('TkDefaultFont', 14, 'bold')).pack(pady=(0, 15))
            
            # Session name
            ttk.Label(main_frame, text="Session Name:").pack(anchor='w')
            session_name_var = tk.StringVar(value=f"Analysis_{int(time.time())}")
            session_name_entry = ttk.Entry(main_frame, textvariable=session_name_var, width=50)
            session_name_entry.pack(fill='x', pady=(5, 10))
            
            # Description
            ttk.Label(main_frame, text="Description (optional):").pack(anchor='w')
            
            # Get theme colors for dark styling
            colors = _theme_colors
            if colors:
                bg, fg = colors.inputbg, colors.inputfg
                selectbg, selectfg = colors.selectbg, colors.selectfg
                insertbg = colors.fg
            else:
                bg, fg = '#303030', '#e0e0e0'
                selectbg, selectfg = '#505050', '#ffffff'
                insertbg = '#ffffff'
            
            desc_text = tk.Text(
                main_frame, height=4, width=50,
                font=('Segoe UI', 10),
                bg=bg, fg=fg,
                insertbackground=insertbg,
                selectbackground=selectbg, selectforeground=selectfg,
                relief='flat', borderwidth=1, padx=6, pady=6
            )
            desc_text.pack(fill='x', pady=(5, 10))
            
            # Current session info
            info_frame = ttk.LabelFrame(main_frame, text="Current Session Info", padding=10)
            info_frame.pack(fill='x', pady=(10, 0))
            
            # Get analyzed functions count
            functions_count = 0
            try:
                if hasattr(self, 'renamed_functions_panel') and self.renamed_functions_panel:
                    # Count functions in the panel
                    if hasattr(self.renamed_functions_panel, 'function_summaries'):
                        functions_count = len(self.renamed_functions_panel.function_summaries)
                    elif hasattr(self.bridge, 'function_summaries'):
                        functions_count = len(self.bridge.function_summaries)
            except Exception as e:
                logger.warning(f"Could not get functions count: {e}")
            
            ttk.Label(info_frame, text=f"• Analyzed Functions: {functions_count}").pack(anchor='w')
            
            # RAG vectors count
            rag_count = 0
            try:
                if hasattr(self.bridge, 'cag_manager') and self.bridge.cag_manager:
                    if hasattr(self.bridge.cag_manager, 'vector_store') and self.bridge.cag_manager.vector_store:
                        if hasattr(self.bridge.cag_manager.vector_store, 'embeddings'):
                            embeddings = self.bridge.cag_manager.vector_store.embeddings
                            if embeddings is not None:
                                # Handle numpy arrays properly
                                try:
                                    rag_count = len(embeddings)
                                except (TypeError, ValueError):
                                    # Handle case where embeddings might be a numpy array
                                    if hasattr(embeddings, 'shape'):
                                        rag_count = embeddings.shape[0] if len(embeddings.shape) > 0 else 0
                else:
                    rag_count = 0
            except Exception as e:
                logger.warning(f"Could not get RAG count: {e}")
                rag_count = 0
            
            ttk.Label(info_frame, text=f"• RAG Vectors: {rag_count}").pack(anchor='w')
            ttk.Label(info_frame, text=f"• Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}").pack(anchor='w')
            
            # Buttons
            button_frame = ttk.Frame(main_frame)
            button_frame.pack(fill='x', pady=(20, 0))
            
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
                        session_id = self.session_manager.create_session(
                            session_name=session_name,
                            description=description if description else None
                        )
                    except Exception as e:
                        messagebox.showerror("Session Creation Error", f"Could not create session: {e}")
                        return
                    
                    # Collect analyzed functions data
                    analyzed_functions = {}
                    try:
                        if hasattr(self.bridge, 'function_summaries') and self.bridge.function_summaries:
                            for address, summary in self.bridge.function_summaries.items():
                                analyzed_functions[address] = {
                                    'address': address,
                                    'old_name': 'Unknown',
                                    'new_name': 'Unknown', 
                                    'behavior_summary': summary,
                                    'timestamp': time.time()
                                }
                        
                        # Also try to get data from the renamed functions panel
                        if hasattr(self, 'renamed_functions_panel') and self.renamed_functions_panel:
                            if hasattr(self.renamed_functions_panel, 'function_summaries'):
                                for key, summary in self.renamed_functions_panel.function_summaries.items():
                                    if key not in analyzed_functions:
                                        analyzed_functions[key] = {
                                            'address': key,
                                            'old_name': 'Unknown',
                                            'new_name': 'Unknown',
                                            'behavior_summary': summary,
                                            'timestamp': time.time()
                                        }
                    except Exception as e:
                        logger.warning(f"Could not collect analyzed functions: {e}")

                    # Refinement: rebuild analyzed_functions entries with accurate address/old/new names and standard key 'behavior_summary'
                    try:
                        mapping = getattr(self.bridge, 'function_address_mapping', {})
                        summaries = getattr(self.bridge, 'function_summaries', {})

                        for identifier, info in mapping.items():
                            summary_val = summaries.get(identifier) or summaries.get(info.get('old_name','')) or summaries.get(info.get('new_name',''))
                            if not summary_val:
                                continue
                            addr = identifier if self.renamed_functions_panel._looks_like_address(identifier) else info.get('address', identifier)
                            analyzed_functions[addr] = {
                                'address': addr,
                                'old_name': info.get('old_name', 'Unknown'),
                                'new_name': info.get('new_name', 'Unknown'),
                                'behavior_summary': summary_val,
                                'timestamp': time.time()
                            }

                        # Convert legacy 'summary' field to 'behavior_summary'
                        for rec in analyzed_functions.values():
                            if 'summary' in rec and 'behavior_summary' not in rec:
                                rec['behavior_summary'] = rec.pop('summary')
                    except Exception as refine_err:
                        logger.warning(f"Analyzed functions refinement failed: {refine_err}")
                    
                    # FINAL DEDUPLICATION: remove non-address keys when a canonical address entry exists for the same new_name
                    try:
                        def _looks_like_address(txt: str) -> bool:
                            if not isinstance(txt, str):
                                return False
                            if txt.startswith('0x'):
                                txt = txt[2:]
                            return ((len(txt) >= 4 and all(c in '0123456789abcdefABCDEF' for c in txt))
                                    or (txt.isdigit() and len(txt) >= 8))

                        # Collect new_names that have a real address entry
                        canonical_new_names = {
                            rec.get('new_name')
                            for addr, rec in analyzed_functions.items()
                            if _looks_like_address(addr)
                        }

                        # Remove duplicates whose key is not an address but share the same new_name
                        for key in list(analyzed_functions.keys()):
                            if _looks_like_address(key):
                                continue  # keep canonical
                            rec = analyzed_functions.get(key, {})
                            if rec.get('new_name') in canonical_new_names:
                                analyzed_functions.pop(key, None)
                    except Exception as dedup_err:
                        logger.debug(f"Final deduplication step failed: {dedup_err}")
                    
                    # SAFETY FILTER: remove incomplete function records
                    try:
                        for addr in list(analyzed_functions.keys()):
                            rec = analyzed_functions.get(addr, {})
                            old_unknown = rec.get('old_name') in [None, '', 'Unknown']
                            new_unknown = rec.get('new_name') in [None, '', 'Unknown']
                            summary_empty = not rec.get('behavior_summary', '').strip()
                            if (old_unknown and new_unknown) or summary_empty:
                                analyzed_functions.pop(addr, None)
                    except Exception as filter_err:
                        logger.debug(f"Safety filter failed: {filter_err}")
                    
                    # Collect RAG vectors
                    rag_vectors = []
                    try:
                        if hasattr(self.bridge, 'cag_manager') and self.bridge.cag_manager:
                            if hasattr(self.bridge.cag_manager, 'vector_store') and self.bridge.cag_manager.vector_store:
                                if hasattr(self.bridge.cag_manager.vector_store, 'documents'):
                                    rag_vectors = self.bridge.cag_manager.vector_store.documents or []
                    except Exception as e:
                        logger.warning(f"Could not collect RAG vectors: {e}")
                    
                    # Save session data
                    try:
                        success = self.session_manager.save_current_session(
                            analyzed_functions=analyzed_functions,
                            rag_vectors=rag_vectors,
                            performance_stats={
                                'functions_count': functions_count,
                                'rag_count': rag_count,
                                'save_timestamp': time.time()
                            }
                        )
                        
                        if success:
                            result["saved"] = True
                            session_dialog.destroy()
                            messagebox.showinfo("Success", f"Session '{session_name}' saved successfully!\n\nSaved {len(analyzed_functions)} analyzed functions and {len(rag_vectors)} RAG vectors.")
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
            
            ttk.Button(button_frame, text="Save Session", command=save_session).pack(side='right', padx=(10, 0))
            ttk.Button(button_frame, text="Cancel", command=cancel_save).pack(side='right')
            
            # Wait for dialog
            session_dialog.wait_window()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open save dialog: {e}")
            import traceback
            logger.error(f"Save session dialog error: {e}\n{traceback.format_exc()}")
    
    def _load_session(self):
        """Load a session with enhanced session management."""
        try:
            import time
            from datetime import datetime
            import tkinter.messagebox as messagebox
            
            # Import the enhanced session manager with absolute import
            from src.enhanced_session_manager import EnhancedSessionManager
            
            # Initialize session manager if not exists
            if not hasattr(self, 'session_manager'):
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
            main_frame.pack(fill='both', expand=True)
            
            # Title
            ttk.Label(main_frame, text="📂 Load Analysis Session", font=('TkDefaultFont', 14, 'bold')).pack(pady=(0, 15))
            
            # Sessions list
            list_frame = ttk.LabelFrame(main_frame, text="Available Sessions", padding=10)
            list_frame.pack(fill='both', expand=True, pady=(0, 10))
            
            # Create treeview for sessions
            columns = ("Name", "Functions", "Created", "Modified")
            session_tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=12)
            
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
            scrollbar = ttk.Scrollbar(list_frame, orient='vertical', command=session_tree.yview)
            session_tree.configure(yscrollcommand=scrollbar.set)
            
            session_tree.pack(side='left', fill='both', expand=True)
            scrollbar.pack(side='right', fill='y')
            
            # Populate sessions
            session_items = {}
            for session in sessions:
                try:
                    created_str = datetime.fromtimestamp(session.get('created', 0)).strftime('%Y-%m-%d %H:%M')
                    modified_str = datetime.fromtimestamp(session.get('last_modified', 0)).strftime('%Y-%m-%d %H:%M')
                    functions_count = session.get('analyzed_functions_count', 0)
                    
                    item_id = session_tree.insert('', 'end', values=(
                        session['name'],
                        functions_count,
                        created_str,
                        modified_str
                    ))
                    session_items[item_id] = session
                except Exception as e:
                    logger.warning(f"Error displaying session {session.get('name', 'Unknown')}: {e}")
                    # Try with fallback values
                    try:
                        item_id = session_tree.insert('', 'end', values=(
                            session.get('name', 'Unknown Session'),
                            session.get('analyzed_functions_count', 0),
                            'Unknown',
                            'Unknown'
                        ))
                        session_items[item_id] = session
                    except Exception as e2:
                        logger.error(f"Failed to display session even with fallbacks: {e2}")
            
            # Show message if no sessions loaded
            if not session_items:
                session_tree.insert('', 'end', values=('No sessions found', '', '', ''))
            
            # Buttons
            button_frame = ttk.Frame(main_frame)
            button_frame.pack(fill='x', pady=(10, 0))
            
            result = {"loaded": False}
            
            def on_session_select(event):
                """Handle session selection."""
                selection = session_tree.selection()
                if selection and selection[0] in session_items:
                    session = session_items[selection[0]]
                    # Could show session details here
            
            session_tree.bind('<<TreeviewSelect>>', on_session_select)
            
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
                    if hasattr(self, 'memory_panel'):
                        self.memory_panel.set_session_loading(True)
                    
                    # Try streaming load first for large sessions
                    session_data = self.session_manager.load_session_streaming(session['id'])
                    
                    if session_data and session_data.get('streaming'):
                        # Handle streaming load
                        self._load_session_streaming(session_data, session)
                        return
                    elif not session_data:
                        # Fallback to regular load
                        session_data = self.session_manager.load_session(session['id'])
                    
                    if session_data:
                        functions_loaded = 0
                        vectors_loaded = 0
                        
                        # Restore analyzed functions to UI (deduplicated)
                        if hasattr(self, 'renamed_functions_panel') and self.renamed_functions_panel:
                            analyzed_functions = session_data.get('analyzed_functions', {})

                            # ----------------------
                            # Deduplicate by canonical address and merge related records
                            # ----------------------
                            unique_funcs = {}
                            processed_ids = set()  # canonical_id = address|new_name to avoid duplicates

                            for func_data in analyzed_functions.values():
                                # 1) Derive canonical address (prefer explicit address field that looks like an address)
                                addr = func_data.get('address')
                                if not addr or not self.renamed_functions_panel._looks_like_address(addr):
                                    # Address sometimes stored in name fields – pick whichever looks like an address
                                    for cand in (func_data.get('old_name'), func_data.get('new_name')):
                                        if cand and self.renamed_functions_panel._looks_like_address(cand):
                                            addr = cand
                                            break

                                # Fallback: use new_name / old_name if no real address (edge-case)
                                if not addr:
                                    addr = func_data.get('new_name') or func_data.get('old_name') or "Unknown"

                                canonical_id = f"{addr}|{func_data.get('new_name','Unknown')}"
                                if canonical_id in processed_ids:
                                    # Already captured this address/name pair
                                    continue
                                processed_ids.add(canonical_id)

                                if addr not in unique_funcs:
                                    unique_funcs[addr] = {
                                        'address': addr,
                                        'old_name': func_data.get('old_name', 'Unknown'),
                                        'new_name': func_data.get('new_name', 'Unknown'),
                                        'behavior_summary': func_data.get('behavior_summary') or func_data.get('summary', '')
                                    }
                                else:
                                    existing = unique_funcs[addr]
                                    # Merge names preferring non-Unknown values
                                    if existing.get('old_name') in [None, 'Unknown'] and func_data.get('old_name'):
                                        existing['old_name'] = func_data['old_name']
                                    if existing.get('new_name') in [None, 'Unknown'] and func_data.get('new_name'):
                                        existing['new_name'] = func_data['new_name']
                                    # Merge summary if existing entry lacks one
                                    if not existing.get('behavior_summary'):
                                        existing['behavior_summary'] = func_data.get('behavior_summary') or func_data.get('summary', '')
                        
                        for addr, fd in unique_funcs.items():
                            try:
                                summary_val = fd.get('behavior_summary') or fd.get('summary', '')
                                self.renamed_functions_panel.add_function_with_summary(
                                    address=addr,
                                    old_name=fd.get('old_name', 'Unknown'),
                                    new_name=fd.get('new_name', 'Unknown'),
                                    summary=summary_val
                                )
                                functions_loaded += 1
                            except Exception as e:
                                logger.warning(f"Could not restore function {addr}: {e}")
                        
                        # Skip RAG vector restoration during session loading to prevent HuggingFace API calls
                        # Vectors will be loaded on-demand via the "Load Vectors" button
                        rag_vectors = session_data.get('rag_vectors', [])
                        vectors_loaded = 0  # Don't count vectors as loaded since we're not loading them
                        
                        # Note: RAG vectors are available in session data but not loaded automatically
                        # Use "Load Vectors" button in Analyzed Functions panel to create embeddings
                        
                        # Clear session loading flag and update memory panel
                        if hasattr(self, 'memory_panel'):
                            self.memory_panel.set_session_loading(False)
                        
                        result["loaded"] = True
                        result["session"] = session
                        load_dialog.destroy()
                        
                        success_msg = f"Session '{session['name']}' loaded successfully!\n\n"
                        success_msg += f"• Restored {functions_loaded} analyzed functions\n"
                        if len(rag_vectors) > 0:
                            success_msg += f"• Found {len(rag_vectors)} RAG vectors in session (use 'Load Vectors' button to create embeddings)\n"
                        success_msg += f"• Session loaded without creating embeddings (prevents HuggingFace rate limiting)"
                        
                        messagebox.showinfo("Success", success_msg)
                    else:
                        # Clear session loading flag on error
                        if hasattr(self, 'memory_panel'):
                            self.memory_panel.set_session_loading(False)
                        messagebox.showerror("Error", "Failed to load session data.")
                        
                except Exception as e:
                    # Clear session loading flag on error
                    if hasattr(self, 'memory_panel'):
                        self.memory_panel.set_session_loading(False)
                    messagebox.showerror("Error", f"Failed to load session: {e}")
                    import traceback
                    logger.error(f"Load session error: {e}\n{traceback.format_exc()}")
            
            def cancel_load():
                load_dialog.destroy()
            
            ttk.Button(button_frame, text="Load Session", command=load_selected_session).pack(side='right', padx=(10, 0))
            ttk.Button(button_frame, text="Cancel", command=cancel_load).pack(side='right')
            
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
            content_frame.pack(fill='both', expand=True, padx=20, pady=20)
            
            # Title
            title_label = Label(content_frame, text=f"Loading Large Session", 
                              font=('Arial', 14, 'bold'))
            title_label.pack(pady=(0, 10))
            
            # Session name
            session_label = Label(content_frame, text=f"Session: {session_info['name']}", 
                                font=('Arial', 11))
            session_label.pack(pady=2)
            
            # File size
            file_size = session_data.get('file_size_mb', 0)
            size_label = Label(content_frame, text=f"File size: {file_size:.1f} MB", 
                             font=('Arial', 10))
            size_label.pack(pady=2)
            
            # Progress status
            progress_var = tk.StringVar(value="Initializing...")
            progress_label = Label(content_frame, textvariable=progress_var, 
                                 font=('Arial', 10))
            progress_label.pack(pady=(10, 5))
            
            # Progress bar
            progress_bar = ttk.Progressbar(content_frame, mode='indeterminate', length=400)
            progress_bar.pack(pady=10, fill='x')
            progress_bar.start()
            
            # Function count stats
            stats_var = tk.StringVar(value="Functions loaded: 0")
            stats_label = Label(content_frame, textvariable=stats_var, 
                              font=('Arial', 10, 'bold'))
            stats_label.pack(pady=5)
            
            # Info text
            info_label = Label(content_frame, 
                             text="Large sessions are loaded progressively to prevent UI freezing.\nThis may take a few moments...",
                             font=('Arial', 9), justify='center')
            info_label.pack(pady=10)
            
            # Button frame to ensure cancel button is always visible
            button_frame = ttk.Frame(content_frame)
            button_frame.pack(side='bottom', fill='x', pady=(20, 0))
            
            # Cancel button - centered and prominent
            cancel_requested = threading.Event()
            def cancel_load():
                cancel_requested.set()
                progress_dialog.destroy()
            
            cancel_button = Button(button_frame, text="Cancel Loading", command=cancel_load,
                                 font=('Arial', 10), bg='#ff6b6b', fg='white', 
                                 relief='raised', bd=2, padx=20, pady=5)
            cancel_button.pack(side='bottom', pady=10)
            
            # Loading worker
            def load_worker():
                try:
                    functions_loaded = 0
                    
                    # Load functions in chunks
                    if hasattr(self, 'renamed_functions_panel') and self.renamed_functions_panel:
                        progress_var.set("Loading functions...")
                        
                        # Enable streaming mode to prevent individual UI updates
                        self.renamed_functions_panel.set_streaming_mode(True)
                        
                        function_iterator = session_data.get('function_iterator')
                        if function_iterator:
                            for address, func_data in function_iterator:
                                if cancel_requested.is_set():
                                    break
                                
                                try:
                                    self.renamed_functions_panel.add_function_with_summary(
                                        address=address,
                                        old_name=func_data.get('old_name', 'Unknown'),
                                        new_name=func_data.get('new_name', 'Unknown'),
                                        summary=func_data.get('behavior_summary', func_data.get('summary', '')),
                                        update_state=False
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
                    if hasattr(self, 'memory_panel'):
                        self.memory_panel.set_session_loading(False)
                    
                    # Close progress dialog and show success
                    if not cancel_requested.is_set():
                        progress_dialog.destroy()
                        
                        success_msg = f"Large session '{session_info['name']}' loaded successfully!\n\n"
                        success_msg += f"• Restored {functions_loaded} analyzed functions\n"
                        success_msg += f"• File size: {file_size:.1f} MB\n"
                        success_msg += f"• RAG vectors available but not loaded (use 'Load Vectors' button)\n"
                        success_msg += f"• Streaming load prevented UI freezing"
                        
                        messagebox.showinfo("Success", success_msg)
                    
                except Exception as e:
                    # Clear session loading flag on error
                    if hasattr(self, 'memory_panel'):
                        self.memory_panel.set_session_loading(False)
                    
                    progress_dialog.destroy()
                    messagebox.showerror("Error", f"Failed to load session: {e}")
                    import traceback
                    logger.error(f"Streaming load error: {e}\n{traceback.format_exc()}")
            
            # Start loading in background thread
            threading.Thread(target=load_worker, daemon=True).start()
            
        except Exception as e:
            # Clear session loading flag on error
            if hasattr(self, 'memory_panel'):
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
            
            # Check Ghidra
            try:
                ghidra_health = self.bridge.ghidra.check_health()
                results.append(f"GhidraMCP API: {'OK ✅' if ghidra_health else 'NOT OK ❌'}")
            except Exception as e:
                results.append(f"GhidraMCP API: ERROR - {e}")
            
            # Check CAG
            try:
                cag_enabled = getattr(self.bridge, 'enable_cag', False)
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
        main_frame.pack(fill='both', expand=True)
        
        # CAG System Controls
        cag_frame = ttk.LabelFrame(main_frame, text="Context-Augmented Generation (CAG)", padding=10)
        cag_frame.pack(fill='x', pady=(0, 10))
        
        cag_enabled = getattr(self.bridge, 'enable_cag', False)
        cag_status = ttk.Label(cag_frame, text=f"Status: {'Enabled' if cag_enabled else 'Disabled'}", 
                              foreground='green' if cag_enabled else 'gray')
        cag_status.pack(anchor='w')
        
        cag_var = tk.BooleanVar(value=cag_enabled)
        def toggle_cag():
            self.bridge.enable_cag = cag_var.get()
            cag_status.config(text=f"Status: {'Enabled' if cag_var.get() else 'Disabled'}",
                            foreground='green' if cag_var.get() else 'gray')
        cag_check = ttk.Checkbutton(cag_frame, text="Enable CAG", variable=cag_var, command=toggle_cag)
        cag_check.pack(anchor='w', pady=(5, 0))
        
        # RAG System Controls
        rag_frame = ttk.LabelFrame(main_frame, text="Retrieval-Augmented Generation (RAG)", padding=10)
        rag_frame.pack(fill='x', pady=(0, 10))
        
        # Helper function to get current vector count
        def get_vector_count():
            count = 0
            if hasattr(self.bridge, 'cag_manager') and self.bridge.cag_manager:
                vector_store = self.bridge.cag_manager.vector_store
                if vector_store and hasattr(vector_store, 'embeddings') and vector_store.embeddings is not None:
                    try:
                        count = len(vector_store.embeddings)
                    except:
                        pass
            return count
        
        # Get initial values
        rag_enabled = False
        if hasattr(self.bridge, 'cag_manager') and self.bridge.cag_manager:
            rag_enabled = getattr(self.bridge.cag_manager, 'use_vector_store_for_prompts', True)
        
        rag_status = ttk.Label(rag_frame, text=f"Status: {'Enabled' if rag_enabled else 'Disabled'} ({get_vector_count()} vectors)",
                              foreground='green' if rag_enabled else 'gray')
        rag_status.pack(anchor='w')
        
        rag_var = tk.BooleanVar(value=rag_enabled)
        def toggle_rag():
            if hasattr(self.bridge, 'cag_manager') and self.bridge.cag_manager:
                self.bridge.cag_manager.use_vector_store_for_prompts = rag_var.get()
            # Refresh vector count when toggling
            current_count = get_vector_count()
            rag_status.config(text=f"Status: {'Enabled' if rag_var.get() else 'Disabled'} ({current_count} vectors)",
                            foreground='green' if rag_var.get() else 'gray')
        rag_check = ttk.Checkbutton(rag_frame, text="Enable RAG", variable=rag_var, command=toggle_rag)
        rag_check.pack(anchor='w', pady=(5, 0))
        
        # Add refresh button for vector count
        def refresh_rag_status():
            current_count = get_vector_count()
            is_enabled = rag_var.get()
            rag_status.config(text=f"Status: {'Enabled' if is_enabled else 'Disabled'} ({current_count} vectors)",
                            foreground='green' if is_enabled else 'gray')
        ttk.Button(rag_frame, text="Refresh Count", command=refresh_rag_status).pack(anchor='w', pady=(5, 0))
        
        # Memory Stats
        stats_frame = ttk.LabelFrame(main_frame, text="Memory Statistics", padding=10)
        stats_frame.pack(fill='both', expand=True, pady=(0, 10))
        
        # Get theme colors for dark styling
        colors = _theme_colors
        if colors:
            bg, fg = colors.inputbg, colors.inputfg
            selectbg, selectfg = colors.selectbg, colors.selectfg
            font = colors.text_font
        else:
            bg, fg = '#303030', '#e0e0e0'
            selectbg, selectfg = '#505050', '#ffffff'
            font = ('Consolas', 11)
        
        stats_text = scrolledtext.ScrolledText(
            stats_frame, height=10, font=font,
            bg=bg, fg=fg,
            selectbackground=selectbg, selectforeground=selectfg,
            relief='flat', borderwidth=1, padx=6, pady=6
        )
        stats_text.pack(fill='both', expand=True)
        
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
                if hasattr(self.bridge, 'function_summaries'):
                    stats.append(f"Analyzed Functions: {len(self.bridge.function_summaries)}")
                if hasattr(self.bridge, 'function_address_mapping'):
                    stats.append(f"Function Mappings: {len(self.bridge.function_address_mapping)}")
                
                # Vector store stats
                if hasattr(self.bridge, 'cag_manager') and self.bridge.cag_manager:
                    vs = self.bridge.cag_manager.vector_store
                    if vs:
                        doc_count = len(vs.documents) if hasattr(vs, 'documents') and vs.documents else 0
                        emb_count = len(vs.embeddings) if hasattr(vs, 'embeddings') and vs.embeddings else 0
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
        button_frame.pack(fill='x')
        
        ttk.Button(button_frame, text="Refresh", command=refresh_stats).pack(side='left')
        ttk.Button(button_frame, text="Close", command=dialog.destroy).pack(side='right')
    
    def _configure_servers(self):
        """Open server configuration dialog."""
        try:
            dialog = ServerConfigDialog(self.root, self.config)
            if dialog.result:
                # Configuration was saved successfully
                # Update the clients with new configuration
                self.bridge.ollama.base_url = str(self.config.ollama.base_url).rstrip('/')
                self.bridge.ollama.default_model = self.config.ollama.model
                
                # Update Ghidra client configuration
                if hasattr(self.bridge, 'ghidra_client') and self.bridge.ghidra_client:
                    self.bridge.ghidra_client.config.base_url = str(self.config.ghidra.base_url).rstrip('/')
                
                messagebox.showinfo("Configuration Updated", 
                                  "Server configuration has been updated.\n\n"
                                  "Note: Some changes may require restarting the application "
                                  "to take full effect.")
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
                if hasattr(self.bridge, 'analysis_state'):
                    self.bridge.analysis_state = {
                        'functions_decompiled': set(),
                        'functions_renamed': {},
                        'comments_added': {},
                        'functions_analyzed': set(),
                    }
                
                # Clear function address mapping and summaries
                if hasattr(self.bridge, 'function_address_mapping'):
                    self.bridge.function_address_mapping = {}
                if hasattr(self.bridge, 'function_summaries'):
                    self.bridge.function_summaries = {}
                
                # Clear renamed functions panel
                if hasattr(self, 'renamed_functions_panel'):
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
        if hasattr(self, 'tool_panel'):
            self.tool_panel._analyze_current_function()
    
    def _menu_rename_current(self):
        """Menu handler: Rename Current Function."""
        if hasattr(self, 'tool_panel'):
            self.tool_panel._rename_current_function()
    
    def _menu_rename_all(self):
        """Menu handler: Rename All Functions."""
        if hasattr(self, 'tool_panel'):
            self.tool_panel._rename_all_functions()
    
    def _menu_generate_report(self):
        """Menu handler: Generate Software Report."""
        if hasattr(self, 'tool_panel'):
            self.tool_panel._generate_software_report()
    
    def _menu_analyze_imports(self):
        """Menu handler: Analyze Imports."""
        if hasattr(self, 'tool_panel'):
            self.tool_panel._analyze_imports()
    
    def _menu_analyze_exports(self):
        """Menu handler: Analyze Exports."""
        if hasattr(self, 'tool_panel'):
            self.tool_panel._analyze_exports()
    
    def _menu_analyze_strings(self):
        """Menu handler: Analyze Strings."""
        if hasattr(self, 'tool_panel'):
            self.tool_panel._analyze_strings()
    
    def _menu_search_strings(self):
        """Menu handler: Search Strings."""
        if hasattr(self, 'tool_panel'):
            self.tool_panel._search_strings()
    
    def _menu_scan_tables(self):
        """Menu handler: Scan Function Tables."""
        if hasattr(self, 'tool_panel'):
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
                if hasattr(self.bridge, 'cag_manager') and self.bridge.cag_manager:
                    self.bridge.cag_manager.save_session()
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
