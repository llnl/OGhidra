#!/usr/bin/env python3
"""
External Generic Client for OGhidra
-----------------------------------
Handles communication with external LLM APIs (Google Gemini, OpenAI, etc.).
Currently implements Google Gemini v1beta interface.
"""

import json
import logging
import requests
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Union, Tuple
from tenacity import Retrying, stop_after_attempt, wait_exponential, retry_if_exception

# Reuse text chunking utilities from ollama_client
from src.ollama_client import chunk_text_for_embedding, average_embeddings


def is_retryable_exception(e):
    """Check if an exception is retryable (429, 500, 503, or connection/timeout)."""
    if isinstance(e, requests.exceptions.HTTPError):
        # Retry on 429 (Rate Limit), 500 (Server Error), and 503 (Service Unavailable)
        return e.response is not None and e.response.status_code in [429, 500, 503]
    # Also retry on connection and timeout errors
    return isinstance(e, (requests.exceptions.ConnectionError, requests.exceptions.Timeout))


class ExternalClient:
    """Generic Client for interacting with External LLM APIs."""

    def __init__(self, config):
        """
        Initialize the External client.

        Args:
            config: ExternalConfig object with attributes:
                - provider: 'google', 'openai', etc.
                - api_key: API Key
                - model: Default model to use
                - ...
        """
        self.config = config
        self.provider = getattr(config, "provider", "google").lower()
        self.api_key = config.api_key
        self.default_model = config.model
        self.embedding_model = config.embedding_model

        # Generation Config
        self.temperature = getattr(config, "temperature", 0.7)
        self.max_tokens = getattr(config, "max_tokens", 8192)
        self.top_p = getattr(config, "top_p", 0.95)
        self.top_k = getattr(config, "top_k", 40)

        # Use default system prompt from config if available, else empty
        self.default_system_prompt = getattr(config, "default_system_prompt", "")

        self.timeout = getattr(config, "timeout", 120)
        self.logger = logging.getLogger("external-client")
        self.model_map = config.model_map

        # LLM Logging setup
        self.llm_logging_enabled = getattr(config, "llm_logging_enabled", False)
        # We'll use a generic log file name unless specified
        self.llm_log_file = getattr(config, "llm_log_file", "logs/llm_interactions_external.log")
        self.llm_log_prompts = getattr(config, "llm_log_prompts", True)
        self.llm_log_responses = getattr(config, "llm_log_responses", True)
        self.llm_log_tokens = getattr(config, "llm_log_tokens", True)
        self.llm_log_timing = getattr(config, "llm_log_timing", True)
        self.llm_log_format = getattr(config, "llm_log_format", "json")
        self.llm_logger = None

        # Retry and Delay Config
        self.request_delay = getattr(config, "request_delay", 0.0)
        self.max_retries = getattr(config, "max_retries", 3)

        print(f"[ExternalClient] Initialized: provider={self.provider} model={self.default_model} delay={self.request_delay}s")

        if self.llm_logging_enabled:
            self._setup_llm_logger()

    def _setup_llm_logger(self):
        """Setup dedicated logger for LLM interactions."""
        # Create logs directory if it doesn't exist
        log_dir = Path(self.llm_log_file).parent
        log_dir.mkdir(parents=True, exist_ok=True)

        # Create dedicated LLM logger
        self.llm_logger = logging.getLogger("llm-interactions-external")
        self.llm_logger.setLevel(logging.INFO)
        self.llm_logger.propagate = False

        # Remove any existing handlers
        self.llm_logger.handlers.clear()

        # Add file handler
        file_handler = logging.FileHandler(self.llm_log_file, encoding="utf-8")
        file_handler.setLevel(logging.INFO)

        # Format depends on log format setting
        if self.llm_log_format == "json":
            formatter = logging.Formatter("%(message)s")
        else:
            formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S")

        file_handler.setFormatter(formatter)
        self.llm_logger.addHandler(file_handler)

        self.logger.info(f"External LLM logging initialized. Log file: {self.llm_log_file}")

    def _log_llm_interaction(self, interaction_type: str, data: Dict[str, Any]):
        """Log LLM interaction to dedicated log file."""
        if not self.llm_logging_enabled or not self.llm_logger:
            return

        log_entry = {"timestamp": datetime.now().isoformat(), "interaction_type": interaction_type, "provider": self.provider}

        if self.llm_log_format == "json":
            log_entry.update(data)
            self.llm_logger.info(json.dumps(log_entry))
        else:
            # Simple text logging
            lines = [f"Type: {interaction_type}"]
            for key, value in data.items():
                lines.append(f"{key}: {value}")
            self.llm_logger.info("\n".join(lines))

    def query(self, prompt: Union[str, Tuple[str, str]], phase: Optional[str] = None) -> str:
        """
        High-level query interface compatible with Bridge.
        Handles both string prompts and (system, user) tuples.

        Args:
            prompt: String prompt or (system_prompt, user_prompt) tuple
            phase: Optional phase name for model selection

        Returns:
            Generated response string
        """
        system_prompt = None
        user_prompt = prompt

        # Handle tuple prompt (system, user)
        if isinstance(prompt, tuple) and len(prompt) == 2:
            system_prompt, user_prompt = prompt

        return self.generate(prompt=user_prompt, system_prompt=system_prompt, phase=phase)

    def generate(
        self,
        prompt: str,
        model: Optional[str] = None,
        system_prompt: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        phase: Optional[str] = None,
    ) -> str:
        """
        Generate a response from the External API.
        Currently supports: Google (Gemini)
        """
        start_time = time.time() if self.llm_log_timing else None

        # Request Delay
        if self.request_delay > 0:
            self.logger.debug(f"Sleeping for {self.request_delay}s before request")
            time.sleep(self.request_delay)

        used_model = model or self.default_model
        used_system = system_prompt or self.default_system_prompt

        # --- Provider: Google ---
        if self.provider == "google":
            return self._generate_google(prompt, used_model, used_system, temperature, max_tokens, start_time, phase)
        else:
            self.logger.error(f"Provider '{self.provider}' not implemented yet.")
            return ""

    def _generate_google(self, prompt, model, system_prompt, temperature, max_tokens, start_time, phase=None):
        """Google Gemini Implementation"""

        # URL Construction
        # Ensure we don't double-prefix 'models/'
        clean_model = model.replace("models/", "")
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{clean_model}:generateContent"

        # Headers
        headers = {"Content-Type": "application/json", "X-goog-api-key": self.api_key}

        # Payload Construction
        # 1. System Instruction
        payload = {}
        if system_prompt:
            payload["system_instruction"] = {"parts": [{"text": system_prompt}]}

        # 2. Contents (User Prompt)
        payload["contents"] = [{"parts": [{"text": prompt}]}]

        # 3. Generation Config
        gen_config = {
            "temperature": temperature if temperature is not None else self.temperature,
            "maxOutputTokens": max_tokens if max_tokens is not None else self.max_tokens,
            "topP": self.top_p,
            "topK": self.top_k,
        }
        payload["generationConfig"] = gen_config

        # 4. Safety Settings (Disable strict filtering for security research)
        payload["safetySettings"] = [
            {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
        ]

        try:
            # Setup retryer
            retryer = Retrying(
                stop=stop_after_attempt(self.max_retries + 1),
                wait=wait_exponential(multiplier=1, min=2, max=10),
                retry=retry_if_exception(is_retryable_exception),
                reraise=True,
            )

            # Execute request with retries
            def do_post():
                print(f"[ExternalClient] Sending request to Google (timeout={self.timeout}s)...")
                try:
                    resp = requests.post(url, headers=headers, json=payload, timeout=self.timeout)
                    print(f"[ExternalClient] Received response: {resp.status_code}")
                    resp.raise_for_status()
                    return resp
                except Exception as e:
                    print(f"[ExternalClient] Request failed: {e}")
                    raise

            response = retryer(do_post)
            data = response.json()

            # Response Parsing
            candidates = data.get("candidates", [])
            response_text = ""
            finish_reason = "UNKNOWN"
            if candidates:
                content = candidates[0].get("content", {})
                parts = content.get("parts", [])
                if parts:
                    response_text = parts[0].get("text", "")
                finish_reason = candidates[0].get("finishReason", "UNKNOWN")

            # Retry-on-empty: If model returned empty with STOP, retry once with a hint
            if not response_text.strip() and finish_reason == "STOP":
                self.logger.warning("Empty response received with STOP. Retrying with hint...")

                # Append a hint to the prompt
                retry_prompt = (
                    prompt
                    + "\n\n[SYSTEM NOTE: Your previous response was empty. If you cannot determine the next step, explain why. If the investigation is complete, respond with 'INVESTIGATION COMPLETE'.]"
                )

                # Make a single retry
                retry_payload = dict(payload)
                retry_payload["contents"] = [{"parts": [{"text": retry_prompt}]}]

                retry_resp = requests.post(url, headers=headers, json=retry_payload, timeout=self.timeout)
                if retry_resp.ok:
                    retry_data = retry_resp.json()
                    retry_candidates = retry_data.get("candidates", [])
                    if retry_candidates:
                        retry_content = retry_candidates[0].get("content", {})
                        retry_parts = retry_content.get("parts", [])
                        if retry_parts:
                            response_text = retry_parts[0].get("text", "")
                            finish_reason = retry_candidates[0].get("finishReason", "UNKNOWN")
                            data = retry_data  # Update for logging
                            self.logger.info(f"Retry successful, got {len(response_text)} chars")

            # Log interaction
            if self.llm_logging_enabled:
                log_data = {"model": clean_model, "method": "generate", "status": "success", "phase": phase}
                if self.llm_log_prompts:
                    log_data["prompt"] = prompt
                    log_data["system_prompt"] = system_prompt
                if self.llm_log_responses:
                    log_data["response"] = response_text

                # Token usage metadata
                usage = data.get("usageMetadata", {})

                log_data["finish_reason"] = finish_reason

                if self.llm_log_tokens:
                    log_data["tokens"] = {
                        "prompt_token_count": usage.get("promptTokenCount", 0),
                        "candidates_token_count": usage.get("candidatesTokenCount", 0),
                        "total_token_count": usage.get("totalTokenCount", 0),
                    }

                if self.llm_log_timing and start_time:
                    log_data["timing"] = {"total_duration_seconds": time.time() - start_time}

                self._log_llm_interaction("generate", log_data)

            return response_text

        except requests.exceptions.RequestException as e:
            # Extract detailed error info from response body if available
            error_detail = str(e)
            prompt_size = len(prompt) if prompt else 0
            system_size = len(system_prompt) if system_prompt else 0

            if hasattr(e, "response") and e.response is not None:
                try:
                    error_body = e.response.text
                    error_detail = f"{str(e)} | Response: {error_body[:1000]}"
                except Exception as inner_exception:
                    self.logger.warning(f"Failed to get the error detail while parsing exception {e}: {inner_exception}")
                    pass

            self.logger.error(f"Error calling External API (Google): {error_detail}")
            self.logger.error(
                f"Request sizes - prompt: {prompt_size:,} chars, system: {system_size:,} chars, total: {prompt_size + system_size:,} chars"
            )

            if self.llm_logging_enabled:
                self._log_llm_interaction(
                    "generate",
                    {
                        "model": model,
                        "status": "error",
                        "error": error_detail,
                        "prompt_chars": prompt_size,
                        "system_chars": system_size,
                    },
                )
            raise

    def generate_with_phase(self, prompt: str, phase: Optional[str] = None, system_prompt: Optional[str] = None) -> str:
        """Generate using phase-specific model configuration."""
        model = self.model_map.get(phase) if phase else None

        # Defensive Check: Validate model against provider
        if self.provider == "google":
            if model and not (model.lower().startswith("gemini") or model.lower().startswith("learnlm")):
                self.logger.warning(f"Ignoring invalid model '{model}' for Google provider. Using default.")
                model = None

        return self.generate(prompt=prompt, model=model, system_prompt=system_prompt, phase=phase)

    def embed(self, text: str, model: str = None) -> List[float]:
        """
        Generate embeddings.
        """
        start_time = time.time() if self.llm_log_timing else None

        # Request Delay
        if self.request_delay > 0:
            self.logger.debug(f"Sleeping for {self.request_delay}s before request")
            time.sleep(self.request_delay)

        used_model = model or self.embedding_model

        if self.provider == "google":
            # Use chunking strategy
            if len(text) > 8000:
                return self._embed_chunked(text, used_model, start_time)
            return self._embed_single_google(text, used_model, start_time)
        else:
            self.logger.error("Embeddings not implemented for this provider yet.")
            return []

    def _embed_chunked(self, text: str, embedding_model: str, start_time: Optional[float]) -> List[float]:
        chunks = chunk_text_for_embedding(text, max_chars=8000)
        chunk_embeddings = []
        for chunk in chunks:
            try:
                # Dispatch based on provider
                if self.provider == "google":
                    emb = self._embed_single_google(chunk, embedding_model, None)
                else:
                    emb = []

                if emb:
                    chunk_embeddings.append(emb)
            except Exception as e:
                self.logger.error(f"Failed to embed chunk: {e}")

        if not chunk_embeddings:
            return []

        return average_embeddings(chunk_embeddings)

    def _embed_single_google(self, text: str, embedding_model: str, start_time: Optional[float]) -> List[float]:
        if not text.strip():
            return []

        clean_model = embedding_model.replace("models/", "")
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{clean_model}:embedContent"

        headers = {"Content-Type": "application/json", "X-goog-api-key": self.api_key}

        payload = {
            "content": {"parts": [{"text": text}]},
            "model": f"models/{clean_model}",  # Redundant but safe
        }

        try:
            # Setup retryer
            retryer = Retrying(
                stop=stop_after_attempt(self.max_retries + 1),
                wait=wait_exponential(multiplier=1, min=2, max=10),
                retry=retry_if_exception(is_retryable_exception),
                reraise=True,
            )

            # Execute request with retries
            def do_post():
                resp = requests.post(url, headers=headers, json=payload, timeout=self.timeout)
                resp.raise_for_status()
                return resp

            response = retryer(do_post)

            data = response.json()
            embedding = data.get("embedding", {}).get("values", [])

            if self.llm_logging_enabled:
                self._log_llm_interaction(
                    "embed", {"model": embedding_model, "status": "success", "embedding_dim": len(embedding)}
                )

            return embedding
        except Exception as e:
            self.logger.error(f"Error calling External Embed API: {e}")
            raise

    def check_health(self) -> bool:
        try:
            # Simple check - list models if possible, or just assume true if instantiated
            if self.provider == "google":
                # Try a lightweight call or just return True if API key valid format
                return bool(self.api_key)
            return True
        except Exception as e:
            self.logger.warning(f"Failed external client health check: {e}")
            return False
