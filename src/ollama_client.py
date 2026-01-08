#!/usr/bin/env python3
"""
Ollama Client for OGhidra
-------------------------
Handles communication with the Ollama API for AI model interactions.
"""

import json
import logging
import requests
import time
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple


# =============================================================================
# Text Chunking Utilities for Embedding Context Limits
# =============================================================================

# nomic-embed-text and most embedding models have 8192 token limit
# Using ~4 chars per token as rough estimate
MAX_EMBEDDING_TOKENS = 8192
CHARS_PER_TOKEN = 4
MAX_EMBEDDING_CHARS = MAX_EMBEDDING_TOKENS * CHARS_PER_TOKEN  # ~32,768 chars
SAFE_EMBEDDING_CHARS = int(MAX_EMBEDDING_CHARS * 0.95)  # 95% to be safe (~31,129 chars)


def chunk_text_for_embedding(
    text: str, 
    max_chars: int = SAFE_EMBEDDING_CHARS, 
    overlap_chars: int = 500
) -> List[str]:
    """
    Split text into chunks that fit within embedding model context window.
    
    Only chunks if text exceeds max_chars. Attempts to break at natural
    boundaries (newlines, periods) to preserve semantic meaning.
    
    Args:
        text: The text to potentially chunk
        max_chars: Maximum characters per chunk (default: ~31K for 8192 tokens)
        overlap_chars: Character overlap between chunks for context continuity
        
    Returns:
        List of text chunks (single-element list if no chunking needed)
    """
    if not text:
        return [""]
    
    # If text fits, return as single chunk
    if len(text) <= max_chars:
        return [text]
    
    chunks = []
    start = 0
    text_length = len(text)
    
    while start < text_length:
        end = min(start + max_chars, text_length)
        
        # If not at the end, try to break at a natural boundary
        if end < text_length:
            # Search window: last 2000 chars of the chunk
            search_start = max(start, end - 2000)
            
            # Priority 1: Double newline (paragraph break)
            double_newline = text.rfind('\n\n', search_start, end)
            if double_newline > start + (max_chars // 2):  # Must be past halfway
                end = double_newline + 2
            else:
                # Priority 2: Single newline
                single_newline = text.rfind('\n', search_start, end)
                if single_newline > start + (max_chars // 2):
                    end = single_newline + 1
                else:
                    # Priority 3: End of sentence
                    sentence_end = max(
                        text.rfind('. ', search_start, end),
                        text.rfind('.\n', search_start, end),
                        text.rfind(';\n', search_start, end),
                        text.rfind('}\n', search_start, end),  # Code block end
                    )
                    if sentence_end > start + (max_chars // 2):
                        end = sentence_end + 2
        
        chunk = text[start:end].strip()
        if chunk:  # Only add non-empty chunks
            chunks.append(chunk)
        
        # Move start, accounting for overlap
        if end >= text_length:
            break
        start = max(start + 1, end - overlap_chars)
    
    return chunks if chunks else [text[:max_chars]]


def average_embeddings(embeddings: List[List[float]]) -> List[float]:
    """
    Average multiple embeddings into a single embedding vector.
    
    Used when text is chunked - each chunk's embedding is averaged
    to produce a single representative embedding.
    
    Args:
        embeddings: List of embedding vectors (all same dimension)
        
    Returns:
        Averaged embedding vector
    """
    if not embeddings:
        return []
    
    if len(embeddings) == 1:
        return embeddings[0]
    
    # Get embedding dimension from first embedding
    dim = len(embeddings[0])
    
    # Sum all embeddings
    averaged = [0.0] * dim
    for emb in embeddings:
        for i, val in enumerate(emb):
            averaged[i] += val
    
    # Divide by count
    count = len(embeddings)
    averaged = [val / count for val in averaged]
    
    return averaged

class OllamaClient:
    """Client for interacting with Ollama API."""
    
    def __init__(self, config):
        """
        Initialize the Ollama client.
        
        Args:
            config: OllamaConfig object or similar with attributes:
                - base_url: Base URL for Ollama API
                - model: Default model to use
                - embedding_model: Default embedding model to use
                - system_prompt: Default system prompt
                - temperature: Temperature for generation
                - max_tokens: Maximum tokens to generate
        """
        self.config = config  # Store config reference
        self.base_url = str(config.base_url).rstrip('/')  # Remove trailing slash
        self.default_model = config.model
        self.embedding_model = getattr(config, 'embedding_model', 'nomic-embed-text')
        self.default_system_prompt = getattr(config, 'default_system_prompt', '')
        self.temperature = getattr(config, 'temperature', 0.7)
        self.max_tokens = getattr(config, 'max_tokens', 2000)
        self.timeout = getattr(config, 'timeout', 120)  # Default 120 seconds for LLM requests
        self.logger = logging.getLogger("ollama-client")
        self.model_map = config.model_map
        
        # LLM Logging setup
        self.llm_logging_enabled = getattr(config, 'llm_logging_enabled', False)
        self.llm_log_file = getattr(config, 'llm_log_file', 'logs/llm_interactions.log')
        self.llm_log_prompts = getattr(config, 'llm_log_prompts', True)
        self.llm_log_responses = getattr(config, 'llm_log_responses', True)
        self.llm_log_tokens = getattr(config, 'llm_log_tokens', True)
        self.llm_log_timing = getattr(config, 'llm_log_timing', True)
        self.llm_log_format = getattr(config, 'llm_log_format', 'json')
        self.llm_logger = None
        
        # Embedding API version: None = auto-detect, 'new' = /api/embed, 'old' = /api/embeddings
        self._embedding_api_version = None
        
        # Print loaded configuration values for verification (always visible)
        request_delay = getattr(config, 'request_delay', 0.0)
        print(f"[OllamaClient] Initialized: timeout={self.timeout}s, request_delay={request_delay}s, model={self.default_model}")
        
        if self.llm_logging_enabled:
            self._setup_llm_logger()
    
    def _setup_llm_logger(self):
        """Setup dedicated logger for LLM interactions."""
        # Create logs directory if it doesn't exist
        log_dir = Path(self.llm_log_file).parent
        log_dir.mkdir(parents=True, exist_ok=True)
        
        # Create dedicated LLM logger
        self.llm_logger = logging.getLogger("llm-interactions")
        self.llm_logger.setLevel(logging.INFO)
        self.llm_logger.propagate = False  # Don't propagate to root logger
        
        # Remove any existing handlers
        self.llm_logger.handlers.clear()
        
        # Add file handler
        file_handler = logging.FileHandler(self.llm_log_file, encoding='utf-8')
        file_handler.setLevel(logging.INFO)
        
        # Format depends on log format setting
        if self.llm_log_format == 'json':
            formatter = logging.Formatter('%(message)s')
        else:
            formatter = logging.Formatter(
                '%(asctime)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
        
        file_handler.setFormatter(formatter)
        self.llm_logger.addHandler(file_handler)
        
        self.logger.info(f"LLM logging initialized. Log file: {self.llm_log_file}")
    
    def _log_llm_interaction(self, interaction_type: str, data: Dict[str, Any]):
        """
        Log LLM interaction to dedicated log file.
        
        Args:
            interaction_type: Type of interaction ('generate', 'embed', 'chat')
            data: Dictionary containing interaction data
        """
        if not self.llm_logging_enabled or not self.llm_logger:
            return
        
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'interaction_type': interaction_type,
        }
        
        # Add data based on logging preferences
        if self.llm_log_format == 'json':
            log_entry.update(data)
            self.llm_logger.info(json.dumps(log_entry, indent=2))
        else:
            # Text format
            lines = [
                f"{'='*80}",
                f"Timestamp: {log_entry['timestamp']}",
                f"Type: {interaction_type}",
            ]
            
            for key, value in data.items():
                if isinstance(value, str) and len(value) > 500:
                    lines.append(f"{key}: {value[:500]}... [truncated]")
                else:
                    lines.append(f"{key}: {value}")
            
            lines.append(f"{'='*80}")
            self.llm_logger.info('\n'.join(lines))
        
    def generate(self, 
                prompt: str, 
                model: Optional[str] = None,
                system_prompt: Optional[str] = None,
                temperature: Optional[float] = None,
                max_tokens: Optional[int] = None) -> str:
        """
        Generate a response from the Ollama model.
        
        Args:
            prompt: The input prompt
            model: Optional model override
            system_prompt: Optional system prompt override
            temperature: Optional temperature override
            max_tokens: Optional max tokens override
            
        Returns:
            Generated response text
        """
        start_time = time.time() if self.llm_log_timing else None
        
        # Request Delay
        request_delay = getattr(self.config, 'request_delay', 0.0)
        if request_delay > 0:
            self.logger.debug(f"Sleeping for {request_delay}s before request")
            time.sleep(request_delay)
            
        url = f"{self.base_url}/api/generate"
        
        used_model = model or self.default_model
        used_system = system_prompt or self.default_system_prompt
        used_temp = temperature or self.temperature
        
        payload = {
            "model": used_model,
            "prompt": prompt,
            "system": used_system,
            "temperature": used_temp,
            "stream": False  # Disable streaming to get a single response
        }
        
        try:
            response = requests.post(url, json=payload, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
            response_text = data.get('response', '')
            
            # Log LLM interaction
            if self.llm_logging_enabled:
                log_data = {
                    'model': used_model,
                    'method': 'generate',
                }
                
                if self.llm_log_prompts:
                    log_data['prompt'] = prompt
                    log_data['system_prompt'] = used_system
                    log_data['temperature'] = used_temp
                
                if self.llm_log_responses:
                    log_data['response'] = response_text
                    log_data['response_length'] = len(response_text)
                
                if self.llm_log_tokens and 'eval_count' in data:
                    log_data['tokens'] = {
                        'prompt_eval_count': data.get('prompt_eval_count', 0),
                        'eval_count': data.get('eval_count', 0),
                        'total_count': data.get('prompt_eval_count', 0) + data.get('eval_count', 0)
                    }
                
                if self.llm_log_timing and start_time:
                    elapsed = time.time() - start_time
                    log_data['timing'] = {
                        'total_duration_seconds': elapsed,
                        'total_duration_ms': data.get('total_duration', 0) / 1_000_000,
                        'load_duration_ms': data.get('load_duration', 0) / 1_000_000,
                        'prompt_eval_duration_ms': data.get('prompt_eval_duration', 0) / 1_000_000,
                        'eval_duration_ms': data.get('eval_duration', 0) / 1_000_000
                    }
                
                log_data['status'] = 'success'
                self._log_llm_interaction('generate', log_data)
            
            return response_text
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error calling Ollama API: {str(e)}")
            
            # Log failed interaction
            if self.llm_logging_enabled:
                log_data = {
                    'model': used_model,
                    'method': 'generate',
                    'status': 'error',
                    'error': str(e)
                }
                if self.llm_log_prompts:
                    log_data['prompt'] = prompt
                if self.llm_log_timing and start_time:
                    log_data['timing'] = {'total_duration_seconds': time.time() - start_time}
                self._log_llm_interaction('generate', log_data)
            
            raise
        except json.JSONDecodeError as e:
            self.logger.error(f"Error parsing Ollama API response: {str(e)}")
            raise
            
    def generate_with_phase(self,
                          prompt: str,
                          phase: Optional[str] = None,
                          system_prompt: Optional[str] = None) -> str:
        """
        Generate a response using a phase-specific model if configured.
        
        Args:
            prompt: The input prompt
            phase: Optional phase name ('planning', 'execution', 'analysis')
            system_prompt: Optional system prompt override
            
        Returns:
            Generated response text
        """
        # Get the model for this phase if configured
        model = self.model_map.get(phase) if phase else None
        
        # Generate the response using the phase-specific model or default
        return self.generate(
            prompt=prompt,
            model=model,
            system_prompt=system_prompt
        )
            
    def list_models(self) -> List[str]:
        """
        List available models from Ollama.
        
        Returns:
            List of model names
        """
        url = f"{self.base_url}/api/tags"
        
        try:
            response = requests.get(url, timeout=self.timeout)
            response.raise_for_status()
            return [model['name'] for model in response.json()['models']]
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error listing Ollama models: {str(e)}")
            raise

    def embed(self, text: str, model: str = None) -> List[float]:
        """
        Generate embeddings using Ollama embedding model.
        
        Supports both new (/api/embed) and legacy (/api/embeddings) Ollama API versions.
        Auto-detects which version works and caches the result for future calls.
        
        If text exceeds the model's context limit (8192 tokens), it will be
        automatically chunked and the resulting embeddings averaged.
        
        Args:
            text: Text to embed
            model: Embedding model to use (defaults to configured embedding_model)
            
        Returns:
            List of embedding values
        """
        start_time = time.time() if self.llm_log_timing else None
        
        # Request Delay
        request_delay = getattr(self.config, 'request_delay', 0.0)
        if request_delay > 0:
            self.logger.debug(f"Sleeping for {request_delay}s before request")
            time.sleep(request_delay)
            
        # Use provided model or default embedding model
        embedding_model = model or self.embedding_model
        
        # Check if text needs chunking (exceeds ~8192 tokens)
        if text and len(text) > SAFE_EMBEDDING_CHARS:
            return self._embed_chunked(text, embedding_model, start_time)
        
        # Normal embedding for text within context limit
        return self._embed_single(text, embedding_model, start_time)
    
    def _embed_chunked(self, text: str, embedding_model: str, start_time: Optional[float]) -> List[float]:
        """
        Handle embedding for text that exceeds context limit by chunking.
        
        Splits text into chunks, embeds each chunk, then averages the embeddings.
        """
        chunks = chunk_text_for_embedding(text)
        
        self.logger.info(
            f"Text length ({len(text)} chars, ~{len(text)//CHARS_PER_TOKEN} tokens) "
            f"exceeds embedding limit. Chunking into {len(chunks)} pieces."
        )
        
        # Embed each chunk
        chunk_embeddings = []
        for i, chunk in enumerate(chunks):
            self.logger.debug(f"Embedding chunk {i+1}/{len(chunks)} ({len(chunk)} chars)")
            try:
                emb = self._embed_single(chunk, embedding_model, None)  # Don't log timing per chunk
                if emb:
                    chunk_embeddings.append(emb)
                else:
                    self.logger.warning(f"Chunk {i+1} returned empty embedding")
            except Exception as e:
                self.logger.error(f"Failed to embed chunk {i+1}: {e}")
                # Continue with other chunks rather than failing completely
        
        if not chunk_embeddings:
            self.logger.error("All chunks failed to embed")
            return []
        
        # Average the chunk embeddings
        averaged = average_embeddings(chunk_embeddings)
        
        self.logger.info(
            f"Successfully embedded {len(chunk_embeddings)}/{len(chunks)} chunks, "
            f"averaged to single {len(averaged)}-dim vector"
        )
        
        # Log the overall operation
        if self.llm_logging_enabled and start_time:
            self._log_llm_interaction('embed_chunked', {
                'model': embedding_model,
                'method': 'embed_chunked',
                'original_length': len(text),
                'num_chunks': len(chunks),
                'successful_chunks': len(chunk_embeddings),
                'embedding_dimension': len(averaged),
                'timing': {'total_duration_seconds': time.time() - start_time},
                'status': 'success'
            })
        
        return averaged
    
    def _embed_single(self, text: str, embedding_model: str, start_time: Optional[float]) -> List[float]:
        """
        Embed a single text chunk (must be within context limit).
        """
        # Determine which API version to try based on cached result
        if self._embedding_api_version == 'new':
            return self._embed_new_api(text, embedding_model, start_time)
        elif self._embedding_api_version == 'old':
            return self._embed_old_api(text, embedding_model, start_time)
        else:
            # Auto-detect: try new API first, fall back to old
            try:
                result = self._embed_new_api(text, embedding_model, start_time)
                self._embedding_api_version = 'new'
                self.logger.debug("Using new Ollama embedding API (/api/embed)")
                return result
            except requests.exceptions.RequestException as e:
                # Check if it's a 404 (endpoint not found) - indicates old Ollama version
                if hasattr(e, 'response') and e.response is not None and e.response.status_code == 404:
                    self.logger.debug("New embedding API not available, falling back to legacy /api/embeddings")
                    try:
                        result = self._embed_old_api(text, embedding_model, start_time)
                        self._embedding_api_version = 'old'
                        self.logger.debug("Using legacy Ollama embedding API (/api/embeddings)")
                        return result
                    except Exception as fallback_error:
                        self.logger.error(f"Both embedding APIs failed. New API: {e}, Legacy API: {fallback_error}")
                        raise fallback_error
                else:
                    # Other error (500, connection error, etc.) - don't fallback, just raise
                    raise
    
    def _embed_new_api(self, text: str, embedding_model: str, start_time: Optional[float]) -> List[float]:
        """
        Generate embeddings using the new Ollama API (/api/embed).
        Introduced in Ollama 0.1.26+.
        """
        # Validate input - empty or None text causes 400 errors
        if not text or not text.strip():
            self.logger.warning("Empty text provided to embed API, using placeholder")
            text = "empty"
        
        url = f"{self.base_url}/api/embed"
        payload = {
            "model": embedding_model,
            "input": text
        }
        
        try:
            response = requests.post(url, json=payload, timeout=self.timeout)
            if response.status_code == 400:
                # Log the actual error response for debugging
                try:
                    error_detail = response.json()
                    self.logger.error(f"Ollama embed 400 error: {error_detail}")
                except:
                    self.logger.error(f"Ollama embed 400 error: {response.text[:500]}")
            response.raise_for_status()
            data = response.json()
            # New API returns "embeddings" (array) for batch input
            embeddings_data = data.get('embeddings', [])
            embedding = embeddings_data[0] if embeddings_data else data.get('embedding', [])
            
            self._log_embed_success(embedding_model, text, embedding, start_time)
            return embedding
        except requests.exceptions.RequestException as e:
            self._log_embed_error(embedding_model, text, e, start_time)
            raise
        except json.JSONDecodeError as e:
            self.logger.error(f"Error parsing Ollama embed response: {str(e)}")
            raise
    
    def _embed_old_api(self, text: str, embedding_model: str, start_time: Optional[float]) -> List[float]:
        """
        Generate embeddings using the legacy Ollama API (/api/embeddings).
        For Ollama versions prior to 0.1.26.
        """
        # Validate input - empty or None text causes errors
        if not text or not text.strip():
            self.logger.warning("Empty text provided to embed API, using placeholder")
            text = "empty"
        
        url = f"{self.base_url}/api/embeddings"
        payload = {
            "model": embedding_model,
            "prompt": text
        }
        
        try:
            response = requests.post(url, json=payload, timeout=self.timeout)
            if response.status_code == 400:
                # Log the actual error response for debugging
                try:
                    error_detail = response.json()
                    self.logger.error(f"Ollama embeddings 400 error: {error_detail}")
                except:
                    self.logger.error(f"Ollama embeddings 400 error: {response.text[:500]}")
            response.raise_for_status()
            data = response.json()
            embedding = data.get('embedding', [])
            
            self._log_embed_success(embedding_model, text, embedding, start_time)
            return embedding
        except requests.exceptions.RequestException as e:
            self._log_embed_error(embedding_model, text, e, start_time)
            raise
        except json.JSONDecodeError as e:
            self.logger.error(f"Error parsing Ollama embeddings response: {str(e)}")
            raise
    
    def _log_embed_success(self, embedding_model: str, text: str, embedding: List[float], start_time: Optional[float]):
        """Log successful embedding generation."""
        if self.llm_logging_enabled:
            log_data = {
                'model': embedding_model,
                'method': 'embed',
                'embedding_dimension': len(embedding)
            }
            
            if self.llm_log_prompts:
                log_data['text'] = text[:500] + ('...' if len(text) > 500 else '')
                log_data['text_length'] = len(text)
            
            if self.llm_log_timing and start_time:
                log_data['timing'] = {'total_duration_seconds': time.time() - start_time}
            
            log_data['status'] = 'success'
            self._log_llm_interaction('embed', log_data)
    
    def _log_embed_error(self, embedding_model: str, text: str, error: Exception, start_time: Optional[float]):
        """Log failed embedding generation."""
        self.logger.error(f"Error calling Ollama embed API: {str(error)}")
        
        if self.llm_logging_enabled:
            log_data = {
                'model': embedding_model,
                'method': 'embed',
                'status': 'error',
                'error': str(error)
            }
            if self.llm_log_timing and start_time:
                log_data['timing'] = {'total_duration_seconds': time.time() - start_time}
            self._log_llm_interaction('embed', log_data)

    def check_health(self) -> bool:
        """
        Check if the Ollama server is reachable and healthy.
        Returns True if healthy, False otherwise.
        """
        try:
            response = requests.get(f"{self.base_url}/api/tags", timeout=5)
            return response.status_code == 200
        except Exception as e:
            self.logger.error(f"Ollama health check failed: {e}")
            return False
    
    def list_models(self) -> list:
        """
        List available models on the Ollama server.
        Returns list of model names.
        """
        try:
            response = requests.get(f"{self.base_url}/api/tags", timeout=5)
            if response.status_code == 200:
                data = response.json()
                models = data.get('models', [])
                return [model.get('name', '') for model in models]
            return []
        except Exception as e:
            self.logger.error(f"Failed to list models: {e}")
            return []