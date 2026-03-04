#!/usr/bin/env python3
"""
Custom API Client for OGhidra
-----------------------------
Handles communication with OpenAI-compatible APIs (GPT-5, custom endpoints, etc.).
"""

import json
import logging
import requests
import time
import uuid
import warnings
import threading
import email.utils
import random
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Union, Tuple
from tenacity import Retrying, stop_after_attempt, wait_exponential, retry_if_exception
import urllib3

# Suppress SSL warnings when verification is disabled
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Also suppress requests warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

def is_retryable_exception(e):
    """Check if an exception is retryable (429, 500, 503, or connection/timeout)."""
    if isinstance(e, requests.exceptions.HTTPError):
        return e.response is not None and e.response.status_code in [429, 500, 503]
    return isinstance(e, (requests.exceptions.ConnectionError, requests.exceptions.Timeout))


class CustomAPIClient:
    """Client for interacting with OpenAI-compatible Custom APIs."""
    
    def __init__(self, config):
        """
        Initialize the Custom API client.
        
        Args:
            config: CustomAPIConfig object with attributes:
                - api_url: Base URL for the API
                - api_key: API key for authentication
                - model: Default model to use
                - timeout: Request timeout
        """
        self.config = config
        self.base_url = str(config.api_url).rstrip('/')
        self.api_key = config.api_key
        self.default_model = config.model
        
        # Generation Config
        self.temperature = getattr(config, 'temperature', 0.7)
        self.max_tokens = getattr(config, 'max_tokens', 4096)
        
        # Use default system prompt from config if available
        self.default_system_prompt = getattr(config, 'default_system_prompt', '')
        
        self.timeout = getattr(config, 'timeout', 300)
        self.logger = logging.getLogger("custom-api-client")
        # Optional UI callback for surfacing retries without digging through logs
        # Signature: (event_type: str, payload: Dict[str, Any]) -> None
        self._ui_event_callback = getattr(config, 'ui_event_callback', None)
        self.model_map = getattr(config, 'model_map', {})
        
        # LLM Logging setup (reuse from config if available)
        self.llm_logging_enabled = getattr(config, 'llm_logging_enabled', False)
        self.llm_log_file = getattr(config, 'llm_log_file', 'logs/llm_interactions_custom.log')
        self.llm_log_prompts = getattr(config, 'llm_log_prompts', True)
        self.llm_log_responses = getattr(config, 'llm_log_responses', True)
        self.llm_log_tokens = getattr(config, 'llm_log_tokens', True)
        self.llm_log_timing = getattr(config, 'llm_log_timing', True)
        self.llm_log_format = getattr(config, 'llm_log_format', 'json')
        self.llm_logger = None
        
        # Retry and Delay Config
        self.request_delay = getattr(config, 'request_delay', 0.0)
        self.max_retries = getattr(config, 'max_retries', 3)

        # Global throttling / concurrency control
        self.max_concurrency = int(getattr(config, 'max_concurrency', 1) or 1)
        self.global_min_interval = float(getattr(config, 'global_min_interval', 0.0) or 0.0)
        self.respect_retry_after = bool(getattr(config, 'respect_retry_after', True))
        self.retry_after_max_seconds = int(getattr(config, 'retry_after_max_seconds', 60) or 60)

        # Adaptive throttling
        # Automatically increases pacing after rate-limits, slowly relaxes after sustained success.
        self.adaptive_throttle_enabled = bool(getattr(config, 'adaptive_throttle_enabled', True))
        self.adaptive_max_interval = float(getattr(config, 'adaptive_max_interval', 10.0) or 10.0)
        self.adaptive_increase_factor = float(getattr(config, 'adaptive_increase_factor', 1.5) or 1.5)
        self.adaptive_decrease_factor = float(getattr(config, 'adaptive_decrease_factor', 0.9) or 0.9)
        self.adaptive_success_streak_threshold = int(getattr(config, 'adaptive_success_streak_threshold', 10) or 10)
        self.adaptive_jitter_seconds = float(getattr(config, 'adaptive_jitter_seconds', 0.25) or 0.25)

        self._request_semaphore = threading.Semaphore(self.max_concurrency)
        self._throttle_lock = threading.Lock()
        self._last_request_start = 0.0

        self._adaptive_lock = threading.Lock()
        self._adaptive_interval = max(0.0, self.global_min_interval)
        self._adaptive_success_streak = 0
        
        # SSL verification (disabled by default for custom APIs with cert issues)
        self.verify_ssl = getattr(config, 'verify_ssl', False)
        
        print(f"[Custom API] Initialized: url={self.base_url} model={self.default_model} delay={self.request_delay}s")
        
        if self.llm_logging_enabled:
            self._setup_llm_logger()

        self._log_throttle_state()

    def _log_throttle_state(self) -> None:
        state = {
            'base_url': self.base_url,
            'default_model': self.default_model,
            'request_delay_seconds': self.request_delay,
            'max_concurrency': self.max_concurrency,
            'global_min_interval_seconds': self.global_min_interval,
            'respect_retry_after': self.respect_retry_after,
            'retry_after_max_seconds': self.retry_after_max_seconds,
            'adaptive_throttle_enabled': self.adaptive_throttle_enabled,
            'adaptive_max_interval_seconds': self.adaptive_max_interval,
            'adaptive_increase_factor': self.adaptive_increase_factor,
            'adaptive_decrease_factor': self.adaptive_decrease_factor,
            'adaptive_success_streak_threshold': self.adaptive_success_streak_threshold,
            'adaptive_jitter_seconds': self.adaptive_jitter_seconds,
        }

        if self.adaptive_throttle_enabled:
            with self._adaptive_lock:
                state['adaptive_current_interval_seconds'] = self._adaptive_interval
                state['adaptive_success_streak'] = self._adaptive_success_streak

        self.logger.info(f"[Custom API] Throttle state: {state}")
        self._log_llm_interaction('throttle_state', state)
    
    def _setup_llm_logger(self):
        """Setup dedicated logger for LLM interactions."""
        log_dir = Path(self.llm_log_file).parent
        log_dir.mkdir(parents=True, exist_ok=True)
        
        self.llm_logger = logging.getLogger("llm-interactions-custom")
        self.llm_logger.setLevel(logging.INFO)
        self.llm_logger.propagate = False
        self.llm_logger.handlers.clear()
        
        file_handler = logging.FileHandler(self.llm_log_file, encoding='utf-8')
        file_handler.setLevel(logging.INFO)
        
        if self.llm_log_format == 'json':
            formatter = logging.Formatter('%(message)s')
        else:
            formatter = logging.Formatter(
                '%(asctime)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
        
        file_handler.setFormatter(formatter)
        self.llm_logger.addHandler(file_handler)
        
        self.logger.info(f"Custom API LLM logging initialized. Log file: {self.llm_log_file}")
    
    def _log_llm_interaction(self, interaction_type: str, data: Dict[str, Any]):
        """Log LLM interaction to dedicated log file."""
        if not self.llm_logging_enabled or not self.llm_logger:
            return
        
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'interaction_type': interaction_type,
            'provider': 'custom_api'
        }
        
        if self.llm_log_format == 'json':
            log_entry.update(data)
            self.llm_logger.info(json.dumps(log_entry))
        else:
            lines = [f"Type: {interaction_type}"]
            for key, value in data.items():
                lines.append(f"{key}: {value}")
            self.llm_logger.info('\n'.join(lines))

    def _emit_ui_event(self, event_type: str, payload: Dict[str, Any]) -> None:
        cb = self._ui_event_callback
        if not cb:
            return
        try:
            cb(event_type, payload)
        except Exception:
            pass

    def _apply_global_throttle(self) -> None:
        """Enforce a global minimum interval between request starts."""
        effective_interval = self.global_min_interval
        if self.adaptive_throttle_enabled:
            with self._adaptive_lock:
                effective_interval = max(effective_interval, self._adaptive_interval)

        if effective_interval <= 0:
            return

        with self._throttle_lock:
            now = time.monotonic()
            elapsed = now - self._last_request_start
            if elapsed < effective_interval:
                time.sleep(effective_interval - elapsed)
            self._last_request_start = time.monotonic()

    def _adaptive_on_success(self, call_type: str = 'generate') -> None:
        if not self.adaptive_throttle_enabled:
            return

        with self._adaptive_lock:
            base = max(0.0, self.global_min_interval)

            # If we're already elevated above baseline, only count generate successes.
            # This avoids embeddings causing premature relaxation during mixed workloads.
            if base > 0 and self._adaptive_interval > base * 1.5 and call_type != 'generate':
                return

            self._adaptive_success_streak += 1
            if self._adaptive_success_streak >= self.adaptive_success_streak_threshold:
                new_interval = max(base, self._adaptive_interval * self.adaptive_decrease_factor)
                if new_interval != self._adaptive_interval:
                    self.logger.debug(
                        f"[AdaptiveThrottle] success_streak={self._adaptive_success_streak} interval {self._adaptive_interval:.2f}s -> {new_interval:.2f}s"
                    )
                    self._adaptive_interval = new_interval
                self._adaptive_success_streak = 0

    def _adaptive_on_rate_limit(self, retry_after_s: float = 0.0) -> None:
        if not self.adaptive_throttle_enabled:
            return
        with self._adaptive_lock:
            self._adaptive_success_streak = 0

            base = max(0.0, self.global_min_interval)
            cur = max(base, self._adaptive_interval)
            if retry_after_s > 0:
                target = max(cur, float(retry_after_s))
            else:
                seed = cur if cur > 0 else 1.0
                target = seed * self.adaptive_increase_factor

            jitter = 0.0
            if self.adaptive_jitter_seconds > 0:
                jitter = random.random() * self.adaptive_jitter_seconds

            new_interval = min(max(base, target + jitter), self.adaptive_max_interval)
            if new_interval > self._adaptive_interval:
                self.logger.debug(
                    f"[AdaptiveThrottle] rate_limit interval {self._adaptive_interval:.2f}s -> {new_interval:.2f}s"
                )
                self._adaptive_interval = new_interval

    def _parse_retry_after_seconds(self, resp: requests.Response) -> float:
        """Parse Retry-After header into seconds (0 if missing/invalid)."""
        if not self.respect_retry_after:
            return 0.0

        raw = resp.headers.get('Retry-After')
        if not raw:
            return 0.0

        raw = raw.strip()
        try:
            secs = float(raw)
            if secs < 0:
                return 0.0
            return min(secs, float(self.retry_after_max_seconds))
        except ValueError:
            pass

        # Retry-After can also be an HTTP date
        try:
            dt = email.utils.parsedate_to_datetime(raw)
            if dt is None:
                return 0.0
            now = datetime.now(dt.tzinfo) if dt.tzinfo else datetime.utcnow()
            delta = (dt - now).total_seconds()
            if delta <= 0:
                return 0.0
            return min(delta, float(self.retry_after_max_seconds))
        except Exception:
            return 0.0

    def _make_before_sleep(self,
                           interaction_type: str,
                           request_id: str,
                           model: str,
                           phase: Optional[str]):
        """Create a tenacity before_sleep callback that logs retries and adapts throttle."""

        def before_sleep(retry_state):
            exc = None
            try:
                if retry_state and retry_state.outcome:
                    exc = retry_state.outcome.exception()
            except Exception:
                exc = None

            status_code = None
            retry_after_s = 0.0
            if isinstance(exc, requests.exceptions.HTTPError) and getattr(exc, 'response', None) is not None:
                try:
                    status_code = exc.response.status_code
                    retry_after_s = self._parse_retry_after_seconds(exc.response)
                except Exception:
                    status_code = None
                    retry_after_s = 0.0

            # Let Retry-After override/extend the next sleep duration.
            try:
                if retry_state.next_action is not None:
                    sleep_s = float(retry_state.next_action.sleep)
                    if retry_after_s > 0:
                        sleep_s = max(sleep_s, float(retry_after_s))

                    # Ensure retries are also paced by the adaptive interval.
                    if self.adaptive_throttle_enabled:
                        with self._adaptive_lock:
                            sleep_s = max(sleep_s, float(self._adaptive_interval))

                    retry_state.next_action.sleep = sleep_s
            except Exception:
                pass

            if status_code in (429, 503):
                self._adaptive_on_rate_limit(retry_after_s=retry_after_s)

            try:
                sleep_s = float(retry_state.next_action.sleep) if retry_state.next_action is not None else None
            except Exception:
                sleep_s = None

            adaptive_interval = None
            if self.adaptive_throttle_enabled:
                with self._adaptive_lock:
                    adaptive_interval = self._adaptive_interval

            self._log_llm_interaction(f"{interaction_type}_retry", {
                'request_id': request_id,
                'model': model,
                'phase': phase,
                'attempt_number': getattr(retry_state, 'attempt_number', None),
                'sleep_seconds': sleep_s,
                'status_code': status_code,
                'retry_after_seconds': retry_after_s if retry_after_s > 0 else None,
                'adaptive_interval_seconds': adaptive_interval,
                'error': str(exc) if exc else None,
            })

            # Surface retry state to UI (do not spam llm_interactions log)
            self._emit_ui_event('llm_retry', {
                'provider': 'custom_api',
                'interaction': interaction_type,
                'request_id': request_id,
                'model': model,
                'phase': phase,
                'attempt_number': getattr(retry_state, 'attempt_number', None),
                'sleep_seconds': sleep_s,
                'status_code': status_code,
                'retry_after_seconds': retry_after_s if retry_after_s > 0 else None,
                'adaptive_interval_seconds': adaptive_interval,
                'error': str(exc) if exc else None,
            })

        return before_sleep
    
    def query(self, prompt: Union[str, Tuple[str, str]], phase: Optional[str] = None) -> str:
        """
        High-level query interface compatible with Bridge.
        Handles both string prompts and (system, user) tuples.
        """
        system_prompt: Optional[str] = None
        user_prompt: str
        
        if isinstance(prompt, tuple) and len(prompt) == 2:
            system_prompt, user_prompt = prompt
        else:
            user_prompt = str(prompt)
        
        return self.generate(
            prompt=user_prompt,
            system_prompt=system_prompt,
            phase=phase
        )
    
    def generate(self, 
                prompt: str, 
                model: Optional[str] = None,
                system_prompt: Optional[str] = None,
                temperature: Optional[float] = None,
                max_tokens: Optional[int] = None,
                phase: Optional[str] = None) -> str:
        """
        Generate a response from the Custom API.
        Supports OpenAI-compatible chat completions format.
        """
        start_time = time.time() if self.llm_log_timing else None
        
        # Request Delay
        if self.request_delay > 0:
            self.logger.debug(f"Sleeping for {self.request_delay}s before request")
            time.sleep(self.request_delay)
        
        # Determine effective parameters
        effective_model = model or self.default_model
        effective_system = system_prompt or self.default_system_prompt
        effective_temperature = temperature if temperature is not None else self.temperature
        effective_max_tokens = max_tokens if max_tokens is not None else self.max_tokens
        
        # Build messages array
        messages = []
        if effective_system:
            messages.append({"role": "system", "content": effective_system})
        messages.append({"role": "user", "content": prompt})
        
        # Headers
        headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json'
        }
        
        # Model-specific detection and adjustments
        model_lower = effective_model.lower()
        
        # Detect Claude models (Anthropic/Bedrock)
        is_claude_model = any(x in model_lower for x in ['claude', 'anthropic'])
        
        # Detect reasoning models (OpenAI GPT-5, o1-series)
        is_reasoning_model = any(x in model_lower for x in ['gpt-5', 'o1-', 'o1mini', 'o1preview'])
        
        # Detect other models with known limits
        is_gpt4 = 'gpt-4' in model_lower and 'gpt-5' not in model_lower
        
        # Adjust temperature for reasoning models
        if is_reasoning_model and effective_temperature != 1.0:
            self.logger.warning(f"⚙️  Adjusting temperature from {effective_temperature} to 1.0 for {effective_model}")
            effective_temperature = 1.0
        
        # Build payload
        payload = {
            "model": effective_model,
            "messages": messages,
            "temperature": effective_temperature,
        }
        
        # Intelligent token limit adjustment based on model type
        if is_claude_model:
            # Claude models via Bedrock have 64K output limit but 200K input
            # Be conservative to avoid hitting limits
            max_output_tokens = min(effective_max_tokens, 32000)  # Cap at 32K for safety
            payload["max_tokens"] = max_output_tokens
            
            # Log adjustment if we reduced the limit
            if effective_max_tokens > max_output_tokens:
                self.logger.info(f"⚙️  Adjusted max_tokens from {effective_max_tokens} to {max_output_tokens} for Claude model (64K limit)")
                
        elif is_reasoning_model:
            # Reasoning models use max_completion_tokens with higher limits (128K for GPT-5)
            reasoning_default = min(effective_max_tokens, 32000)
            payload["max_completion_tokens"] = reasoning_default
            self.logger.debug(f"Using max_completion_tokens={reasoning_default} for reasoning model")
            
        elif is_gpt4:
            # GPT-4 has various context windows, be conservative
            max_output_tokens = min(effective_max_tokens, 16000)
            payload["max_tokens"] = max_output_tokens
            
        else:
            # Generic OpenAI-compatible API - use standard max_tokens
            payload["max_tokens"] = effective_max_tokens
        
        # Construct API endpoint URL
        if self.base_url.endswith('/chat/completions') or self.base_url.endswith('/v1/chat/completions'):
            api_url = self.base_url
        else:
            api_url = f"{self.base_url}/v1/chat/completions"
        
        # Log request
        request_id = str(uuid.uuid4())
        if self.llm_logging_enabled:
            self._log_llm_interaction('generate_request', {
                'request_id': request_id,
                'model': effective_model,
                'phase': phase,
                'temperature': effective_temperature,
                'max_tokens': payload.get('max_tokens') or payload.get('max_completion_tokens'),
                'prompt': prompt if self.llm_log_prompts else '[REDACTED]',
                'system_prompt': effective_system if self.llm_log_prompts else '[REDACTED]'
            })
        
        # Print what we're doing
        print(f"[Custom API] Generating response using model: {effective_model}")
        
        # Retry logic
        response_text = ""
        error_msg = None
        
        try:
            # Concurrency + global throttling
            self._request_semaphore.acquire()
            self._apply_global_throttle()

            retryer = Retrying(
                stop=stop_after_attempt(self.max_retries + 1),
                wait=wait_exponential(multiplier=1, min=2, max=10),
                retry=retry_if_exception(is_retryable_exception),
                before_sleep=self._make_before_sleep('generate', request_id, effective_model, phase),
                reraise=True
            )
            
            def do_post():
                resp = requests.post(api_url, headers=headers, json=payload,
                                     timeout=self.timeout, verify=self.verify_ssl)
                resp.raise_for_status()
                return resp
            
            response = retryer(do_post)
            data = response.json()
            
            # Extract response
            if 'choices' in data and len(data['choices']) > 0:
                response_text = data['choices'][0].get('message', {}).get('content', '')
            else:
                self.logger.warning("Unexpected Custom API response format")
                response_text = ''
            
            # Log success
            if self.llm_logging_enabled:
                duration_ms = (time.time() - start_time) * 1000 if start_time else 0
                usage = data.get('usage', {})
                self._log_llm_interaction('generate_response', {
                    'request_id': request_id,
                    'model': effective_model,
                    'phase': phase,
                    'status': 'success',
                    'response': response_text if self.llm_log_responses else '[REDACTED]',
                    'tokens': usage if self.llm_log_tokens else None,
                    'duration_ms': duration_ms if self.llm_log_timing else None
                })

            self._adaptive_on_success('generate')
            return response_text
        
        except Exception as e:
            error_msg = str(e)
            self.logger.error(f"Error calling Custom API: {error_msg}")
            
            # Enhanced error logging (HTTP errors)
            if isinstance(e, requests.exceptions.HTTPError) and getattr(e, 'response', None) is not None:
                try:
                    http_resp = e.response
                    error_body = http_resp.text
                    self.logger.error(f"Response Status: {http_resp.status_code}")
                    self.logger.error(f"Response Body: {error_body[:1000]}")
                except Exception:
                    pass
            
            # Log request sizes for debugging
            prompt_size = len(prompt) if prompt else 0
            system_size = len(system_prompt) if system_prompt else 0
            self.logger.error(f"Request sizes - prompt: {prompt_size:,} chars, system: {system_size:,} chars, total: {prompt_size + system_size:,} chars")
            
            # Log error
            if self.llm_logging_enabled:
                duration_ms = (time.time() - start_time) * 1000 if start_time else 0
                self._log_llm_interaction('generate_error', {
                    'request_id': request_id,
                    'model': effective_model,
                    'phase': phase,
                    'status': 'error',
                    'error': error_msg,
                    'duration_ms': duration_ms if self.llm_log_timing else None
                })
            
            raise

        finally:
            # Ensure we always release semaphore
            try:
                self._request_semaphore.release()
            except Exception:
                pass
    
    def generate_with_phase(self,
                           prompt: str,
                           phase: Optional[str] = None,
                           system_prompt: Optional[str] = None) -> str:
        """Generate using phase-specific model configuration."""
        model_override = self.model_map.get(phase) if phase else None
        if model_override:
            return self.generate(prompt=prompt, model=model_override, system_prompt=system_prompt, phase=phase)
        return self.generate(prompt=prompt, system_prompt=system_prompt, phase=phase)
    
    def embed(self, text: str, model: Optional[str] = None) -> List[float]:
        """
        Generate embeddings using Custom API (OpenAI-compatible).
        Supports text-embedding-ada-002 and similar models.
        
        Args:
            text: Text to embed
            model: Embedding model to use (defaults to configured embedding_model)
            
        Returns:
            List of embedding values
        """
        if not text.strip():
            return []
        
        start_time = time.time() if self.llm_log_timing else None
        
        # Request Delay
        if self.request_delay > 0:
            self.logger.debug(f"Sleeping for {self.request_delay}s before embedding request")
            time.sleep(self.request_delay)
        
        embedding_model = model if model is not None else getattr(self.config, 'embedding_model', 'text-embedding-ada-002')
        
        # Construct embeddings endpoint URL
        if self.base_url.endswith('/embeddings') or self.base_url.endswith('/v1/embeddings'):
            api_url = self.base_url
        else:
            # Standard OpenAI embeddings endpoint
            # Remove the chat completions path if present
            base = self.base_url
            if base.endswith('/v1/chat/completions'):
                base = base[:-len('/v1/chat/completions')]
            elif base.endswith('/chat/completions'):
                base = base[:-len('/chat/completions')]
            api_url = f"{base.rstrip('/')}/v1/embeddings"
        
        headers = {
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json'
        }
        
        payload = {
            "model": embedding_model,
            "input": text
        }
        
        request_id = str(uuid.uuid4())
        
        # Print what we're doing
        print(f"[Custom API] Generating embeddings using model: {embedding_model}")
        
        try:
            # Concurrency + global throttling
            self._request_semaphore.acquire()
            self._apply_global_throttle()

            # Setup retryer
            retryer = Retrying(
                stop=stop_after_attempt(self.max_retries + 1),
                wait=wait_exponential(multiplier=1, min=2, max=10),
                retry=retry_if_exception(is_retryable_exception),
                before_sleep=self._make_before_sleep('embed', request_id, embedding_model, phase=None),
                reraise=True
            )
            
            def do_post():
                resp = requests.post(api_url, headers=headers, json=payload,
                                    timeout=self.timeout, verify=self.verify_ssl)
                resp.raise_for_status()
                return resp
            
            response = retryer(do_post)
            data = response.json()
            
            # Extract embedding from response
            if 'data' in data and len(data['data']) > 0:
                embedding = data['data'][0].get('embedding', [])
            else:
                self.logger.warning("Unexpected Custom API embeddings response format")
                embedding = []
            
            # Log success
            if self.llm_logging_enabled:
                duration_ms = (time.time() - start_time) * 1000 if start_time else 0
                usage = data.get('usage', {})
                self._log_llm_interaction('embed', {
                    'request_id': request_id,
                    'model': embedding_model,
                    'status': 'success',
                    'embedding_dim': len(embedding),
                    'text_length': len(text),
                    'tokens': usage if self.llm_log_tokens else None,
                    'duration_ms': duration_ms if self.llm_log_timing else None
                })

            self._adaptive_on_success('embed')
            return embedding
        
        except Exception as e:
            error_msg = str(e)
            self.logger.error(f"Error calling Custom API embeddings: {error_msg}")
            
            # Log error
            if self.llm_logging_enabled:
                duration_ms = (time.time() - start_time) * 1000 if start_time else 0
                self._log_llm_interaction('embed_error', {
                    'request_id': request_id,
                    'model': embedding_model,
                    'status': 'error',
                    'error': error_msg,
                    'text_length': len(text),
                    'duration_ms': duration_ms if self.llm_log_timing else None
                })
            
            raise

        finally:
            try:
                self._request_semaphore.release()
            except Exception:
                pass
    
    def check_health(self) -> bool:
        """Check if the Custom API endpoint is reachable."""
        try:
            headers = {'Authorization': f'Bearer {self.api_key}', 'Content-Type': 'application/json'}
            test_payload = {
                "model": self.default_model,
                "messages": [{"role": "user", "content": "test"}],
                "max_tokens": 1
            }
            
            if self.base_url.endswith('/chat/completions') or self.base_url.endswith('/v1/chat/completions'):
                api_url = self.base_url
            else:
                api_url = f"{self.base_url}/v1/chat/completions"
            
            response = requests.post(api_url, headers=headers, json=test_payload, 
                                    timeout=5, verify=self.verify_ssl)
            return response.status_code == 200
        except Exception as e:
            self.logger.error(f"Custom API health check failed: {e}")
            return False
