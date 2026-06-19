import tkinter as tk
from tkinter import ttk, messagebox
import os
from ..config import BridgeConfig
import threading

import logging

logger = logging.getLogger(__name__)


class ServerConfigDialog:
    """Dialog for configuring server URLs."""

    def __init__(self, parent, config: BridgeConfig):
        self.config = config
        self.result = None

        # Create the dialog window
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Server Configuration")
        self.dialog.geometry("600x750")
        self.dialog.transient(parent)
        self.dialog.grab_set()

        # Center the dialog on the parent window
        self.dialog.update_idletasks()
        parent_x = parent.winfo_rootx()
        parent_y = parent.winfo_rooty()
        parent_width = parent.winfo_width()
        parent_height = parent.winfo_height()

        dialog_width = 600
        dialog_height = 750

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
        title_label = ttk.Label(main_frame, text="Server Configuration", font=("TkDefaultFont", 12, "bold"))
        title_label.pack(pady=(0, 20))

        # --- Provider Selection ---
        provider_frame = ttk.Frame(main_frame)
        provider_frame.pack(fill="x", pady=(0, 10))

        ttk.Label(provider_frame, text="LLM Provider:").pack(side="left", padx=(0, 10))

        # Determine current provider
        current_provider = getattr(self.config, "llm_provider", "ollama")
        self.provider_var = tk.StringVar(value=current_provider)

        self.provider_combo = ttk.Combobox(
            provider_frame,
            textvariable=self.provider_var,
            values=["ollama", "google", "custom_api"],
            state="readonly",
            width=20,
        )
        self.provider_combo.pack(side="left")
        self.provider_combo.bind("<<ComboboxSelected>>", self._on_provider_changed)

        # --- External (Generic) Configuration ---
        self.external_frame = ttk.LabelFrame(main_frame, text="External Provider Configuration", padding=10)

        # Provider Type
        ttk.Label(self.external_frame, text="Provider Type:").grid(row=0, column=0, sticky="w", pady=5)
        self.ext_provider_var = tk.StringVar(value=getattr(self.config.external, "provider", "google"))
        self.ext_provider_combo = ttk.Combobox(
            self.external_frame, textvariable=self.ext_provider_var, values=["google"], state="readonly", width=47
        )
        self.ext_provider_combo.grid(row=0, column=1, sticky="ew", padx=(10, 0), pady=5)

        ttk.Label(self.external_frame, text="API Key:").grid(row=1, column=0, sticky="w", pady=5)
        self.ext_key_var = tk.StringVar(value=getattr(self.config.external, "api_key", ""))
        ext_key_entry = ttk.Entry(self.external_frame, textvariable=self.ext_key_var, width=50, show="*")
        ext_key_entry.grid(row=1, column=1, sticky="ew", padx=(10, 0), pady=5)

        ttk.Label(self.external_frame, text="Model:").grid(row=2, column=0, sticky="w", pady=5)
        self.ext_model_var = tk.StringVar(value=getattr(self.config.external, "model", "gemini-1.5-flash"))
        ext_model_entry = ttk.Entry(self.external_frame, textvariable=self.ext_model_var, width=50)
        ext_model_entry.grid(row=2, column=1, sticky="ew", padx=(10, 0), pady=5)

        ttk.Label(self.external_frame, text="Embedding Model:").grid(row=3, column=0, sticky="w", pady=5)
        self.ext_embed_var = tk.StringVar(value=getattr(self.config.external, "embedding_model", "text-embedding-004"))
        ext_embed_entry = ttk.Entry(self.external_frame, textvariable=self.ext_embed_var, width=50)
        ext_embed_entry.grid(row=3, column=1, sticky="ew", padx=(10, 0), pady=5)

        self.external_frame.columnconfigure(1, weight=1)

        # --- Custom API Configuration ---
        self.custom_api_frame = ttk.LabelFrame(main_frame, text="Custom API Configuration (OpenAI-compatible)", padding=10)

        ttk.Label(self.custom_api_frame, text="API URL:").grid(row=0, column=0, sticky="w", pady=5)
        self.custom_api_url_var = tk.StringVar(
            value=str(getattr(self.config.custom_api, "api_url", "https://api.example.com/v1/chat/completions"))
        )
        custom_url_entry = ttk.Entry(self.custom_api_frame, textvariable=self.custom_api_url_var, width=50)
        custom_url_entry.grid(row=0, column=1, sticky="ew", padx=(10, 0), pady=5)

        ttk.Label(self.custom_api_frame, text="API Key:").grid(row=1, column=0, sticky="w", pady=5)
        self.custom_api_key_var = tk.StringVar(value=getattr(self.config.custom_api, "api_key", ""))
        custom_key_entry = ttk.Entry(self.custom_api_frame, textvariable=self.custom_api_key_var, width=50, show="*")
        custom_key_entry.grid(row=1, column=1, sticky="ew", padx=(10, 0), pady=5)

        ttk.Label(self.custom_api_frame, text="Model:").grid(row=2, column=0, sticky="w", pady=5)
        self.custom_api_model_var = tk.StringVar(value=getattr(self.config.custom_api, "model", "gpt-4"))
        custom_model_entry = ttk.Entry(self.custom_api_frame, textvariable=self.custom_api_model_var, width=50)
        custom_model_entry.grid(row=2, column=1, sticky="ew", padx=(10, 0), pady=5)

        ttk.Label(self.custom_api_frame, text="Embedding Model:").grid(row=3, column=0, sticky="w", pady=5)
        self.custom_api_embed_var = tk.StringVar(
            value=getattr(self.config.custom_api, "embedding_model", "text-embedding-ada-002")
        )
        custom_embed_entry = ttk.Entry(self.custom_api_frame, textvariable=self.custom_api_embed_var, width=50)
        custom_embed_entry.grid(row=3, column=1, sticky="ew", padx=(10, 0), pady=5)

        ttk.Label(self.custom_api_frame, text="Max Tokens:").grid(row=4, column=0, sticky="w", pady=5)
        self.custom_api_max_tokens_var = tk.StringVar(value=str(getattr(self.config.custom_api, "max_tokens", 4096)))
        custom_tokens_entry = ttk.Entry(self.custom_api_frame, textvariable=self.custom_api_max_tokens_var, width=50)
        custom_tokens_entry.grid(row=4, column=1, sticky="ew", padx=(10, 0), pady=5)

        self.custom_api_frame.columnconfigure(1, weight=1)

        # --- Ollama Configuration ---
        self.ollama_frame = ttk.LabelFrame(main_frame, text="Ollama Server", padding=10)

        ttk.Label(self.ollama_frame, text="Base URL:").grid(row=0, column=0, sticky="w", pady=5)
        self.ollama_url_var = tk.StringVar(value=str(self.config.ollama.base_url))
        ollama_entry = ttk.Entry(self.ollama_frame, textvariable=self.ollama_url_var, width=50)
        ollama_entry.grid(row=0, column=1, sticky="ew", padx=(10, 0), pady=5)

        ttk.Label(self.ollama_frame, text="Model:").grid(row=1, column=0, sticky="w", pady=5)
        self.ollama_model_var = tk.StringVar(value=self.config.ollama.model)
        model_entry = ttk.Entry(self.ollama_frame, textvariable=self.ollama_model_var, width=50)
        model_entry.grid(row=1, column=1, sticky="ew", padx=(10, 0), pady=5)

        # Embedding model selection
        ttk.Label(self.ollama_frame, text="Embedding Model:").grid(row=2, column=0, sticky="w", pady=5)
        self.embedding_model_var = tk.StringVar(value=getattr(self.config.ollama, "embedding_model", "nomic-embed-text"))
        embedding_entry = ttk.Entry(self.ollama_frame, textvariable=self.embedding_model_var, width=50)
        embedding_entry.grid(row=2, column=1, sticky="ew", padx=(10, 0), pady=5)

        self.ollama_frame.columnconfigure(1, weight=1)

        # GhidraMCP configuration
        ghidra_frame = ttk.LabelFrame(main_frame, text="GhidraMCP Server", padding=10)
        ghidra_frame.pack(fill="x", pady=(0, 10))

        ttk.Label(ghidra_frame, text="Base URL:").grid(row=0, column=0, sticky="w", pady=5)
        self.ghidra_url_var = tk.StringVar(value=str(self.config.ghidra.base_url))
        ghidra_entry = ttk.Entry(ghidra_frame, textvariable=self.ghidra_url_var, width=50)
        ghidra_entry.grid(row=0, column=1, sticky="ew", padx=(10, 0), pady=5)

        ghidra_frame.columnconfigure(1, weight=1)

        # Initial visibility toggle
        self._toggle_provider()

        # Help text
        help_text = ttk.Label(
            main_frame,
            text="Configure connections to LLM and Ghidra backend.\nSelect provider from the dropdown.",
            font=("TkDefaultFont", 9),
            foreground="gray",
        )
        help_text.pack(pady=(10, 20))

        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill="x")

        # Test connections button
        test_button = ttk.Button(button_frame, text="Test Connections", command=self._test_connections)
        test_button.pack(side="left")

        # Right side buttons
        right_frame = ttk.Frame(button_frame)
        right_frame.pack(side="right")

        cancel_button = ttk.Button(right_frame, text="Cancel", command=self._cancel)
        cancel_button.pack(side="right", padx=(10, 0))

        save_button = ttk.Button(right_frame, text="Save", command=self._save)
        save_button.pack(side="right")

    def _on_provider_changed(self, event):
        """Handle provider selection change."""
        self._toggle_provider()

    def _toggle_provider(self):
        """Toggle visibility of provider frames."""
        provider = self.provider_var.get()
        if provider == "google":  # Alias for 'external' in UI logic
            provider = "external"

        # Hide all provider frames first
        self.ollama_frame.pack_forget()
        self.external_frame.pack_forget()
        self.custom_api_frame.pack_forget()

        # Show the selected provider frame
        if provider == "external":
            # External API selected
            self.external_frame.pack(fill="x", pady=(0, 10), after=self.dialog.winfo_children()[0].winfo_children()[1])
        elif provider == "custom_api":
            # Custom API selected
            self.custom_api_frame.pack(fill="x", pady=(0, 10), after=self.dialog.winfo_children()[0].winfo_children()[1])
        else:
            # Ollama selected
            self.ollama_frame.pack(fill="x", pady=(0, 10), after=self.dialog.winfo_children()[0].winfo_children()[1])

    def _test_connections(self):
        """Test the connections to the configured servers."""

        def test():
            results = []

            # Test LLM Provider
            provider = self.provider_var.get()
            if provider == "google" or provider == "external":
                # Test External / Google
                try:
                    import requests

                    api_key = self.ext_key_var.get()
                    if not api_key:
                        results.append("External API: ❌ API Key is missing")
                    else:
                        # Simple test for Google (since it's the only supported one currently)
                        url = f"https://generativelanguage.googleapis.com/v1beta/models?key={api_key}"
                        response = requests.get(url, timeout=5)
                        if response.status_code == 200:
                            results.append("External API (Google): ✅ Connected")
                            # Verify model exists
                            models = response.json().get("models", [])
                            target_model = self.ext_model_var.get()
                            model_found = any(target_model in m.get("name", "") for m in models)
                            if model_found:
                                results.append(f"Model ({target_model}): ✅ Available")
                            else:
                                results.append(f"Model ({target_model}): ⚠️ Not found in list (might still work)")
                        else:
                            results.append(f"External API: ❌ HTTP {response.status_code}")
                except Exception as e:
                    results.append(f"External API: ❌ {str(e)}")
            elif provider == "custom_api":
                # Test Custom API
                try:
                    import requests

                    api_url = self.custom_api_url_var.get()
                    api_key = self.custom_api_key_var.get()

                    if not api_key:
                        results.append("Custom API: ❌ API Key is missing")
                    elif not api_url:
                        results.append("Custom API: ❌ API URL is missing")
                    else:
                        # Test with a minimal request
                        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
                        test_payload = {
                            "model": self.custom_api_model_var.get(),
                            "messages": [{"role": "user", "content": "test"}],
                            "max_tokens": 1,
                        }

                        response = requests.post(api_url, headers=headers, json=test_payload, timeout=10, verify=False)
                        if response.status_code == 200:
                            results.append("Custom API: ✅ Connected")
                            results.append(f"Model ({self.custom_api_model_var.get()}): ✅ Available")
                        else:
                            results.append(f"Custom API: ❌ HTTP {response.status_code}")
                            try:
                                error_detail = response.json()
                                results.append(f"Error: {error_detail}")
                            except Exception as e:
                                logger.warning(f"Failed to extract the error response body: {e}")
                                pass
                except Exception as e:
                    results.append(f"Custom API: ❌ {str(e)}")
            else:
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
                                    timeout=10,
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
                                        timeout=10,
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

            backend = getattr(self.config.ghidra, "backend", "http")

            if backend == "pyghidra":
                try:
                    from .ghidra_client import PyGhidraClient

                    client = PyGhidraClient(self.config.ghidra)
                    try:
                        if client.check_health():
                            results.append("pyGhidra: ✅ Connected")
                        else:
                            results.append("pyGhidra: ❌ Health check failed")
                    finally:
                        client.close()
                except Exception as e:
                    results.append(f"pyGhidra: ❌ {str(e)}")
            else:
                try:
                    import requests

                    response = requests.get(
                        f"{self.ghidra_url_var.get()}/methods",
                        params={"offset": 0, "limit": 1},
                        timeout=5,
                    )
                    if response.status_code == 200:
                        results.append("GhidraMCP: ✅ Connected")
                    else:
                        results.append(f"GhidraMCP: ❌ HTTP {response.status_code}")
                except Exception as e:
                    results.append(f"GhidraMCP: ❌ {str(e)}")

            # Test GhidraMCP
            try:
                import requests

                response = requests.get(f"{self.ghidra_url_var.get()}/methods", params={"offset": 0, "limit": 1}, timeout=5)
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
            # Update config
            self.config.ollama.base_url = ollama_url
            self.config.ollama.model = self.ollama_model_var.get()
            self.config.ollama.embedding_model = self.embedding_model_var.get()
            self.config.ghidra.base_url = ghidra_url

            # Google / External Config
            self.config.external.provider = self.ext_provider_var.get()
            self.config.external.api_key = self.ext_key_var.get()
            self.config.external.model = self.ext_model_var.get()
            self.config.external.embedding_model = self.ext_embed_var.get()

            # Custom API Config
            from pydantic import AnyHttpUrl

            custom_api_url = AnyHttpUrl(self.custom_api_url_var.get())
            self.config.custom_api.api_url = custom_api_url
            self.config.custom_api.api_key = self.custom_api_key_var.get()
            self.config.custom_api.model = self.custom_api_model_var.get()
            self.config.custom_api.embedding_model = self.custom_api_embed_var.get()
            try:
                self.config.custom_api.max_tokens = int(self.custom_api_max_tokens_var.get())
            except ValueError:
                pass  # Keep default if invalid

            # Provider
            provider = self.provider_var.get()
            # If user selected 'google' in dropdown, map to 'external' internally or keep alias if preferred
            # We'll stick to 'external' internally mostly
            if provider == "google":
                self.config.llm_provider = "external"
            else:
                self.config.llm_provider = provider

            # Update the clients with new URLs
            # (No need to update _bridge_ref here; handled by main UI)

            # --- Update .env file ---
            env_updates = {
                "OLLAMA_BASE_URL": str(ollama_url),
                "OLLAMA_MODEL": self.ollama_model_var.get(),
                "OLLAMA_EMBEDDING_MODEL": self.embedding_model_var.get(),
                "GHIDRA_BASE_URL": str(ghidra_url),
                # External Configs
                "EXTERNAL_PROVIDER": self.ext_provider_var.get(),
                "EXTERNAL_API_KEY": self.ext_key_var.get(),
                "EXTERNAL_MODEL": self.ext_model_var.get(),
                "EXTERNAL_EMBEDDING_MODEL": self.ext_embed_var.get(),
                # Custom API Configs
                "CUSTOM_API_URL": self.custom_api_url_var.get(),
                "CUSTOM_API_KEY": self.custom_api_key_var.get(),
                "CUSTOM_API_MODEL": self.custom_api_model_var.get(),
                "CUSTOM_API_EMBEDDING_MODEL": self.custom_api_embed_var.get(),
                "CUSTOM_API_MAX_TOKENS": self.custom_api_max_tokens_var.get(),
                # Provider
                "LLM_PROVIDER": "external" if provider == "google" else provider,
            }
            self._update_env_file(env_updates)
            # ---

            self.result = True
            self.dialog.destroy()

        except Exception as e:
            messagebox.showerror("Invalid Configuration", f"Error in configuration:\n{str(e)}")

    def _update_env_file(self, updates: dict):
        """Update or insert keys in the .env file."""
        env_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env")
        try:
            if not os.path.exists(env_path):
                # If .env does not exist, create it with the updates
                with open(env_path, "w", encoding="utf-8") as f:
                    for k, v in updates.items():
                        f.write(f"{k}={v}\n")
                return
            # Read all lines
            with open(env_path, "r", encoding="utf-8") as f:
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
            with open(env_path, "w", encoding="utf-8") as f:
                f.writelines(new_lines)
        except Exception as e:
            logger.error(f"Failed to update .env file: {e}")

    def _cancel(self):
        """Cancel the dialog."""
        self.result = False
        self.dialog.destroy()
