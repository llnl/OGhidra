#!/usr/bin/env python3
"""
Ollama-GhidraMCP Bridge
-----------------------
This application acts as a bridge between a locally hosted Ollama AI model
and GhidraMCP, enabling AI-assisted reverse engineering tasks within Ghidra.
"""

import argparse
import json
import logging
import sys
import os
import re  # Added for pattern matching in enhanced error feedback
import time
from typing import Dict, Any, List, Optional, Tuple, Union
import threading
import os, json, logging, textwrap, inspect, sys, functools, itertools, math, random, hashlib, base64, tempfile, shutil, subprocess

from src.config import BridgeConfig
from src.ollama_client import OllamaClient
from src.ghidra_client import GhidraMCPClient
from src.command_parser import CommandParser
from src.cag.manager import CAGManager
from src import config
from src.models.memory import (
    SessionMemory,
    MessageRole,
    CAGContext,
    StructuredPrompt,
    AnalysisState,
    ExecutionPhaseResults,
    ToolExecution
)
from src.context_manager import ContextManager
from datetime import datetime

# Configure logging
def setup_logging(config):
    """Set up logging configuration."""
    handlers = []
    
    if config.log_console:
        handlers.append(logging.StreamHandler(sys.stdout))
        
    if config.log_file_enabled:
        handlers.append(logging.FileHandler(config.log_file))
        
    logging.basicConfig(
        level=getattr(logging, config.log_level),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=handlers
    )
    
    return logging.getLogger("ollama-ghidra-bridge")

class Bridge:
    """Main bridge class that connects Ollama with GhidraMCP."""
    
    # Class-level singleton for SentenceTransformer model
    _sentence_transformer_model = None
    _model_load_lock = None
    _ollama_client = None
    
    def __init__(self, config: BridgeConfig, include_capabilities: bool = False, max_agent_steps: int = 5,
                enable_cag: bool = True):
        """Initialize the bridge with configuration."""
        self.config = config
        self.logger = logging.getLogger("ollama-ghidra-bridge")
        
        # Initialize threading lock for model loading
        if Bridge._model_load_lock is None:
            Bridge._model_load_lock = threading.Lock()
        
        # Initialize clients
        self.ollama = OllamaClient(config=config.ollama)
        self.ghidra_client = GhidraMCPClient(config=config.ghidra, ollama_client=self.ollama)
        
        # Set Ollama client for embeddings
        Bridge.set_ollama_client(self.ollama)
        
        # Command parser for extracting tool calls
        self.command_parser = CommandParser()
        
        # Session memory (Pydantic-based structured storage)
        session_id = f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.session = SessionMemory(session_id=session_id)
        
        # Legacy context support (for backward compatibility during transition)
        self.context = []  # Will be deprecated in favor of self.session
        
        # Tool capabilities
        self.include_capabilities = include_capabilities
        self.capabilities_text = None
        if include_capabilities:
            self.capabilities_text = self._load_capabilities_text()
        
        # CAG Configuration
        self.enable_cag = enable_cag
        self.cag_manager = None
        
        # Memory/knowledge manager
        self.memory_manager = None
        
        # Context manager for intelligent result handling
        self.context_manager = ContextManager(
            ollama_client=self.ollama,
            context_budget=self.config.ollama.context_budget,
            execution_fraction=self.config.ollama.context_budget_execution,
            enable_summarization=self.config.ollama.enable_result_summarization,
            enable_caching=self.config.ollama.result_cache_enabled,
            enable_tiered_context=self.config.ollama.tiered_context_enabled
        )
        
        if self.enable_cag:
            try:
                from .cag import CAGManager
                self.cag_manager = CAGManager(config)
                # Set bridge reference for cache stats
                self.cag_manager._bridge_ref = self
                # Memory manager is part of CAG manager
                self.memory_manager = self.cag_manager.memory_manager if hasattr(self.cag_manager, 'memory_manager') else None
            except ImportError as e:
                self.logger.warning(f"CAG dependencies not available: {e}. Running without CAG.")
                self.enable_cag = False
        
        # Analysis state tracking (legacy dict - now points to session's Pydantic model)
        # The actual state is stored in self.session.analysis_state (AnalysisState model)
        # This dict is maintained for backward compatibility
        self.analysis_state = {
            'functions_decompiled': self.session.analysis_state.functions_decompiled,
            'functions_renamed': self.session.analysis_state.functions_renamed,
            'comments_added': self.session.analysis_state.comments_added,
            'functions_analyzed': self.session.analysis_state.functions_analyzed,
            'cached_results': self.session.analysis_state.cached_results,
        }
        
        # Enhanced function tracking with address mapping
        self.function_address_mapping = {}
        
        # Store function analysis summaries
        self.function_summaries = {}
        
        # Initialize caches and statistics
        self._init_caches()
        
        # Agentic workflow settings
        self.max_goal_steps = max_agent_steps
        self.goal_steps_taken = 0
        self.current_goal = None
        self.goal_achieved = False
        self.current_plan = ""
        self.current_plan_tools = []
        self.executed_tools = set()  # Track (cmd_name:params_signature) to avoid duplicates
        self.step_result_map = {}  # Map cmd_signature -> (loop_step_id, result_excerpt)
        self.tool_repetition_limit = 2  # Maximum repetitions allowed for tool calls
        self.current_loop_number = 1  # Track current agentic loop/cycle number
        
        # Workflow stage tracking for UI integration
        self.current_workflow_stage = None  # Can be: 'planning', 'execution', 'analysis', 'review', None
        
        # Partial outputs storage
        self.partial_outputs = []
        
        # UI callback for chain of thought updates (set by UI if present)
        self._ui_cot_callback = None
        
        self.logger.info("Bridge initialized successfully")
        
    @classmethod
    def get_sentence_transformer(cls):
        """DEPRECATED: Use get_ollama_embeddings instead for local embedding generation."""
        import logging
        logger = logging.getLogger("ollama-ghidra-bridge")
        logger.warning("get_sentence_transformer is DEPRECATED. Use get_ollama_embeddings for local embeddings.")
        logger.warning("To ensure no HuggingFace API calls, this method now returns None.")
        
        # Return None to force usage of Ollama embeddings
        return None
    
    @classmethod
    def get_ollama_embeddings(cls, texts: List[str], model: str = None) -> List[List[float]]:
        """Get embeddings using local Ollama embedding model."""
        logger = logging.getLogger("ollama-ghidra-bridge")
        
        if not hasattr(cls, '_ollama_client') or cls._ollama_client is None:
            logger.debug("Ollama client not initialized. Embeddings unavailable.")
            return []
        
        # Filter out empty/None texts which cause 400 errors
        valid_texts = []
        for text in texts:
            if text and isinstance(text, str) and text.strip():
                valid_texts.append(text.strip())
            else:
                logger.warning(f"Skipping invalid text for embedding: {repr(text)[:50]}")
        
        if not valid_texts:
            logger.warning("No valid texts to embed after filtering")
            return []
        
        # Use provided model or default from config
        embedding_model = model or getattr(cls._ollama_client.config, 'embedding_model', 'nomic-embed-text')
            
        try:
            embeddings = []
            for text in valid_texts:
                embedding = cls._ollama_client.embed(text, model=embedding_model)
                if embedding:
                    embeddings.append(embedding)
                else:
                    logger.debug(f"Failed to generate embedding for text: {text[:50]}...")
                    return []  # Return empty if any embedding fails
            
            logger.debug(f"✅ Generated {len(embeddings)} embeddings using Ollama {embedding_model}")
            return embeddings
        except Exception as e:
            logger.error(f"Failed to generate Ollama embeddings: {e}")
            return []

    @classmethod
    def set_ollama_client(cls, ollama_client):
        """Set the Ollama client for embeddings."""
        cls._ollama_client = ollama_client
    
    def _init_caches(self):
        """Initialize decompilation and function caches."""
        # Enhanced decompilation cache with multiple cache keys
        self.decompilation_cache = {}  # function_name -> result
        self.function_cache = {}       # address -> function_data
        self.cache_stats = {
            'hits': 0,
            'misses': 0,
            'cache_size': 0
        }
    
    def _emit_cot(self, update_type: str, content: str, also_print: bool = True):
        """Emit a chain of thought update to both terminal and UI.
        
        This method provides live visibility into the AI agent's reasoning
        during the agentic loop, mirroring output to both console and UI.
        
        Args:
            update_type: Type of update ('Cycle', 'Phase', 'Reasoning', 'Tool', 'Status')
            content: The update content to display
            also_print: Whether to also print to terminal (default True)
        """
        if also_print:
            if update_type.upper() == 'REASONING':
                pass # Don't double print reasoning as it's often long
            else:
                print(f"[{update_type}] {content}")
                
        # Send to UI callback if registered
        if self._ui_cot_callback:
            self._ui_cot_callback(update_type, content)

    def _parse_and_save_artifacts(self, response: str):
        """
        Parse text-based artifacts from LLM response.
        Format: ARTIFACT: [category] key = value
        """
        import re
        # Regex to capture: ARTIFACT: [cat] key = value
        # Tolerates missing brackets or whitespace variations
        pattern = r"ARTIFACT:\s*(?:\[(\w+)\])?\s*([^=]+)\s*=\s*(.+)"
        
        matches = re.finditer(pattern, response, re.IGNORECASE)
        count = 0
        for match in matches:
            category = match.group(1) or "general"
            key = match.group(2).strip()
            value = match.group(3).strip()
            
            self.session.add_knowledge(key, value, category)
            self.logger.info(f"💾 Parsed Artifact: [{category}] {key} = {value}")
            count += 1
            
        if count > 0:
            self._emit_cot("Memory", f"Saved {count} knowledge artifacts")
    
    def _load_capabilities_text(self) -> Optional[str]:
        """Load the capabilities text from the file if the flag is set."""
        if not self.include_capabilities:
            return None
            
        capabilities_file = "ai_ghidra_capabilities.txt"
        try:
            # Assuming the script is run from the project root
            file_path = os.path.join(os.path.dirname(__file__), '..', capabilities_file) 
            if os.path.exists(file_path):
                with open(file_path, 'r', encoding='utf-8') as f:
                    return f.read()
            else:
                # Try reading from the current working directory as a fallback
                if os.path.exists(capabilities_file):
                    with open(capabilities_file, 'r', encoding='utf-8') as f:
                        return f.read()
                else:
                    self.logger.warning(f"Capabilities file '{capabilities_file}' not found.")
                    return None
        except Exception as e:
            self.logger.error(f"Error reading capabilities file '{capabilities_file}': {str(e)}")
            return None

    def _build_structured_prompt(self, phase: str = None) -> tuple:
        """
        Build structured prompts with proper separation between system and user prompts.
        
        SYSTEM PROMPT contains:
        - Role definition
        - Available tools and their syntax
        - Formatting rules and best practices
        - Phase-specific instructions (planning/execution/analysis)
        
        USER PROMPT contains:
        - User's goal and query
        - Current execution state
        - Tool execution results and history
        - Dynamic context from CAG
        
        Args:
            phase: Optional phase name to customize the prompt
            
        Returns:
            Tuple of (system_prompt, user_prompt)
        """
        # ========== SYSTEM PROMPT SECTIONS (Static Instructions) ==========
        system_sections = []
        
        # 1. Role and expertise definition
        role_definition = """You are an AI assistant specialized in reverse engineering with Ghidra.
You can help analyze binary files by executing commands through GhidraMCP."""
        system_sections.append(role_definition)
        
        # 2. Available tools section (static)
        if self.include_capabilities and self.capabilities_text:
            tools_section = (
                f"## Available Tools\n"
                f"You have access to the following Ghidra interaction tools.\n\n"
                f"{self.capabilities_text}\n\n"
                f"## Tool Execution Format\n"
                f"To call a tool, use this EXACT format:\n"
                f"EXECUTE: tool_name(param1=\"value1\", param2=\"value2\")\n\n"
                f"Rules:\n"
                f"- Output ONLY the EXECUTE line, no extra text\n"
                f"- String values MUST be in double quotes\n"
                f"- Numerical values should NOT be quoted\n"
                f"- Use exact tool and parameter names from the list above\n\n"
                f"Examples:\n"
                f"EXECUTE: decompile_function(name=\"main\")\n"
                f"EXECUTE: rename_function(old_name=\"FUN_140011a8\", new_name=\"process_data\")\n"
                f"EXECUTE: list_imports(offset=0, limit=50)\n"
            )
            system_sections.append(tools_section)
        
        # 3. Phase-specific instructions (static rules)
        if phase == "planning":
            phase_instructions = self.config.ollama.planning_system_prompt.replace(
                "{user_task_description}", "[User's goal will be provided in the user message]"
            )
            system_sections.append(phase_instructions)
        elif phase == "execution":
            phase_instructions = self.config.ollama.execution_system_prompt.format(
                user_task_description="[User's goal will be provided in the user message]",
                FUNCTION_CALL_BEST_PRACTICES=self.config.ollama.FUNCTION_CALL_BEST_PRACTICES
            )
            system_sections.append(phase_instructions)
        elif phase == "evaluation":
            phase_instructions = self.config.ollama.evaluation_system_prompt.replace(
                "{user_task_description}", "[User's goal will be provided in the user message]"
            )
            system_sections.append(phase_instructions)
        elif phase == "analysis":
            phase_instructions = self.config.ollama.analysis_system_prompt.replace(
                "{user_task_description}", "[User's goal will be provided in the user message]"
            )
            system_sections.append(phase_instructions)
        elif phase == "review":
            # Review phase uses execution instructions + emphasis on quality
            phase_instructions = self.config.ollama.execution_system_prompt.format(
                user_task_description="[User's goal will be provided in the user message]",
                FUNCTION_CALL_BEST_PRACTICES=self.config.ollama.FUNCTION_CALL_BEST_PRACTICES
            )
            # Add review-specific guidance
            review_guidance = """
    
    CRITICAL FOR REVIEW PHASE:
    - You MUST use the EXECUTE: format to call tools
    - Do NOT use markdown code blocks like ```tool_code``` or ```tool_execution```
    - CORRECT FORMAT: EXECUTE: tool_name(param1="value1", param2="value2")
    - INCORRECT FORMATS: ```tool_code\ntool_name()```, tool_execution tool_name(), etc.
    
    If you want to call a tool, output ONLY:
    EXECUTE: tool_name(param1="value1")
    
    No code blocks, no extra formatting, just the EXECUTE line.
            """
            system_sections.append(phase_instructions + review_guidance)
        
        # Combine all system sections
        system_prompt = "\n\n".join(system_sections)
        
        # ========== USER PROMPT SECTIONS (Dynamic Context) ==========
        # Use Pydantic StructuredPrompt for clean separation and ordering
        
        # Build CAG context if enabled
        cag_context_obj = None
        if self.enable_cag and self.cag_manager:
            latest_user_query = None
            
            # Get latest user query from session
            recent_user_msgs = self.session.get_recent_messages(limit=1, role_filter=[MessageRole.USER])
            if recent_user_msgs:
                latest_user_query = recent_user_msgs[0].content
            
            if latest_user_query:
                self.cag_manager.update_session_from_bridge_context(
                    self.context if isinstance(self.context, list) else self.context.get('history', [])
                )
                cag_text = self.cag_manager.enhance_prompt(latest_user_query, phase)
                if cag_text:
                    # Create CAGContext object
                    cag_context_obj = CAGContext(workplans=[cag_text])
        
        # Build phase-specific instructions
        phase_instructions = None
        latest_user_role = None
        if isinstance(self.context, list) and self.context:
            latest_user_role = self.context[-1].get("role")
        elif isinstance(self.context, dict) and self.context.get('history', []):
            latest_user_role = self.context['history'][-1].get("role")
        
        if latest_user_role == "user":
            if phase == "planning" or not self.current_plan:
                phase_instructions = "## Current Task\nCreate a plan to address the goal above. Do not execute any commands yet."
            elif phase == "execution":
                phase_instructions = "## Current Task\nExecute the necessary tools to gather information for the goal above."
            elif phase == "analysis":
                phase_instructions = "## Current Task\nAnalyze the gathered information and provide a comprehensive answer to the goal above."
            else:
                phase_instructions = "## Current Task\nAddress the goal above using the available tools."
        
        # Build structured prompt using Pydantic model
        structured_prompt = StructuredPrompt(
            goal=self.current_goal,
            analysis_state=self.session.analysis_state,
            current_plan=self.current_plan,
            cag_context=cag_context_obj,
            tool_results=self.session.get_recent_tool_executions(limit=5),
            conversation_history=self.session.get_recent_messages(limit=self.config.context_limit),
            phase_specific_instructions=phase_instructions
        )
        
        # Generate user prompt with conversation history ALWAYS at the end
        user_prompt = structured_prompt.build_user_prompt(max_history_items=self.config.context_limit)

        # --- INJECT KNOWLEDGE ARTIFACTS ---
        knowledge_summary = self.session.get_knowledge_summary()
        if knowledge_summary:
            user_prompt = knowledge_summary + "\n\n" + user_prompt
        # ----------------------------------
        
        # --- INJECT COMPLETED STEPS SUMMARY ---
        # Get all unique executed tools from session for this goal
        executed_tools = self.session.get_all_tool_executions() 
        if executed_tools:
            # Create a compact summary of what has been done
            completed_summary = ["\n## COMPLETED STEPS (DO NOT REPEAT):"]
            
            # Group by tool name for cleaner display
            tools_by_name = {}
            for tool in executed_tools:
                name = tool.tool_name
                # Skip pagination tools from the summary to avoid clutter
                if name in ["list_functions", "list_imports", "list_exports", "list_strings"]:
                    params_str = f"offset={tool.parameters.get('offset', '?')}"
                else:
                    # Format parameters compactly
                    params_str = ", ".join([f"{k}={v}" for k,v in tool.parameters.items()])
                
                if name not in tools_by_name:
                    tools_by_name[name] = []
                tools_by_name[name].append(params_str)
            
            for name, params_list in tools_by_name.items():
                # Limit to last 3 calls per tool to save context
                params_display = "; ".join(params_list[-3:] if len(params_list) > 3 else params_list)
                completed_summary.append(f"- {name}: {params_display}")
                
            user_prompt += "\n".join(completed_summary) + "\n"
        # -------------------------------------
        
        return (system_prompt, user_prompt)
    
    def _check_final_response_quality(self, response: str) -> bool:
        """
        Check if the final response is of good quality and doesn't indicate tool limitations.
        Also verifies that all critical planned tools have been executed.
        
        Args:
            response: The potential final response text
            
        Returns:
            True if the response is complete and satisfactory, False if it indicates incomplete analysis
        """
        # Look for phrases that indicate the model couldn't complete the task
        limitation_phrases = [
            "i cannot", "cannot directly", "i'm unable to", "unable to", 
            "doesn't include", "not available", "no way to", "would need",
            "don't have access", "no access to", "not possible with",
            "not able to", "couldn't find", "missing", "not found",
            "not supported", "no tool", "no command", "doesn't exist",
            "the current toolset doesn't"
        ]
        
        # Check if the response contains any of these limitation phrases
        response_lower = response.lower()
        for phrase in limitation_phrases:
            if phrase in response_lower:
                self.logger.info(f"Final response indicates limitation: '{phrase}'")
                return False
                
        # Check if response is too short
        if len(response.strip()) < 150:
            self.logger.info(f"Final response is too short ({len(response.strip())} chars)")
            return False
            
        # Check if final response has error messages
        if "ERROR:" in response or "Failed" in response:
            self.logger.info("Final response contains error messages")
            return False
            
        # Check if all critical planned tools have been executed
        # Update the pending_critical list based on current execution status
        pending_critical = [
            tool for tool in self.planned_tools_tracker['planned'] 
            if tool['is_critical'] and tool['execution_status'] == 'pending'
        ]
        
        if pending_critical:
            tool_names = ", ".join([tool['tool'] for tool in pending_critical])
            self.logger.info(f"Critical planned tools not executed: {tool_names}")
            
            # Check if the response falsely claims actions that weren't performed
            for tool in pending_critical:
                tool_name = tool['tool']
                # Check for phrases that indicate the tool was used when it actually wasn't
                false_claim_patterns = [
                    f"renamed to", f"renamed the function", f"function is now named",
                    f"have renamed", f"renamed", f"new name", f"changed the name",
                    f"added comment", f"commented", f"set a comment",
                    f"decompiled"
                ]
                
                for pattern in false_claim_patterns:
                    if pattern in response_lower and any(rename_tool in tool_name for rename_tool in ["rename", "comment"]):
                        self.logger.warning(f"Response falsely claims an action was performed: '{pattern}' but {tool_name} was not executed")
                        return False
            
            # If the response doesn't falsely claim completion but critical tools are missing, still return False
            return False
            
        return True

    def _normalize_command_name(self, command_name: str) -> str:
        """
        Normalize a command name (e.g., convert camelCase to snake_case).
        
        Args:
            command_name: The command name to normalize
            
        Returns:
            The normalized command name or empty string if not found
        """
        # First check if the command name already exists
        if hasattr(self.ghidra_client, command_name):
            return command_name
            
        # Try converting camelCase to snake_case
        snake_case = re.sub(r'(?<!^)(?=[A-Z])', '_', command_name).lower()
        
        # Only return the snake_case version if it exists
        if hasattr(self.ghidra_client, snake_case):
            logging.info(f"Normalized command name from '{command_name}' to '{snake_case}'")
            return snake_case
        
        return ""

    def _check_command_exists(self, command_name: str) -> Tuple[bool, str, List[str], List[str]]:
        """
        Check if a command exists and provide suggestions if it doesn't.
        
        Args:
            command_name: The command name to check
            
        Returns:
            Tuple of (exists, error_message, similar_commands, all_available_commands)
        """
        normalized_command = self._normalize_command_name(command_name)
        available_commands = [
            name for name in dir(self.ghidra_client) 
            if not name.startswith('_') and callable(getattr(self.ghidra_client, name))
        ]
        
        if normalized_command:
            return True, "", [], available_commands # Return all commands even if found
            
        # Command not found, provide helpful suggestions
        # available_commands already computed above
        
        # Find similar commands
        similar_commands = []
        for cmd in available_commands:
            # Simple similarity check - could be improved
            if command_name.lower() in cmd.lower() or cmd.lower() in command_name.lower():
                similar_commands.append(cmd)
        
        suggestion_msg = ""
        if similar_commands:
            suggestion_msg = f"\nDid you mean one of these? {', '.join(similar_commands)}"
            
        if command_name == "decompile":
            suggestion_msg = "\nDid you mean 'decompile_function(name=\"function_name\")' or 'decompile_function_by_address(address=\"1400011a8\")'?"
        elif command_name == "disassemble":
            suggestion_msg = "\nThere is no 'disassemble' command. Try 'decompile_function_by_address(address=\"1400011a8\")' instead."
            
        error_message = f"Unknown command: {command_name}{suggestion_msg}"
        return False, error_message, similar_commands, available_commands

    def _normalize_command_params(self, command_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalize command parameters based on command requirements.
        
        Args:
            command_name: The normalized command name
            params: The original parameters
            
        Returns:
            Normalized parameters
        """
        normalized_params = {}
        
        # Common parameter name mappings
        param_mappings = {
            "functionAddress": "address",
            "function_address": "address",
            "functionName": "name",
            "function_name": "name",
            "oldName": "old_name",
            "newName": "new_name"
        }
        
        # Special case normalizations for specific commands
        command_specific_mappings = {
            "rename_function_by_address": {
                "address": "function_address"
            },
            "decompile_function_by_address": {
                "function_address": "address"
            }
        }
        
        # Apply command-specific normalizations first
        if command_name in command_specific_mappings:
            for orig_key, new_key in command_specific_mappings[command_name].items():
                if orig_key in params:
                    normalized_params[new_key] = params[orig_key]
                    logging.info(f"Normalized parameter '{orig_key}' to '{new_key}' for command '{command_name}'")
        
        # Then apply general normalizations
        for key, value in params.items():
            if key in normalized_params:
                continue  # Skip if already processed by command-specific normalization
                
            # Apply general parameter name mapping
            norm_key = param_mappings.get(key, key)
            if norm_key != key:
                logging.info(f"Normalized parameter '{key}' to '{norm_key}' for command '{command_name}'")
                
            normalized_params[norm_key] = value
            
        return normalized_params

    def get_cached_result(self, result_id: str) -> str:
        """
        Retrieve the full content of a cached result by its ID.
        
        This allows the AI to request the full content of results that
        were previously summarized or truncated due to context budget limits.
        
        Args:
            result_id: The cached result ID (e.g., "r5_decompile_function_abc123")
            
        Returns:
            Full result content, or error message if not found
        """
        if not self.context_manager or not self.context_manager.result_cache:
            return "Error: Result caching is not enabled"
        
        full_result = self.context_manager.get_full_result(result_id)
        
        if full_result:
            self.logger.info(f"Retrieved cached result: {result_id} ({len(full_result)} chars)")
            return full_result
        else:
            return f"Error: Cached result '{result_id}' not found. Available IDs: {list(self.context_manager.result_cache.cache.keys())[:5]}"

    def execute_command(self, command_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute a command with parameters.
        
        Args:
            command_name: The name of the command to execute
            params: The parameters to pass to the command
            
        Returns:
            The result of the command execution
        """
        try:
            # Handle bridge-level commands FIRST (before Ghidra client validation)
            bridge_commands = {"get_cached_result", "scan_function_pointer_tables"}
            normalized_bridge_cmd = command_name.lower().replace("-", "_").replace(" ", "_")
            
            if normalized_bridge_cmd == "get_cached_result":
                result_id = params.get("result_id", "")
                result = self.get_cached_result(result_id)
                return {"result": result, "source": "context_cache"}
            
            if normalized_bridge_cmd == "scan_function_pointer_tables":
                # This is handled by ghidra_client, so let it pass through
                pass
            
            # Normalize command name and parameters for Ghidra client commands
            normalized_command = self._normalize_command_name(command_name)
            if not normalized_command:
                exists, error_message, similar_commands, all_available_commands = self._check_command_exists(command_name)
                if not exists:
                    # Construct the enhanced error message with the list of all tools
                    tools_list_str = "\nAvailable Ghidra Tools:\n"
                    if all_available_commands:
                        for i, tool in enumerate(sorted(all_available_commands)):
                            tools_list_str += f"  - {tool}\n"
                    else:
                        tools_list_str += "  (Could not fetch tool list or no tools available via client introspection).\n"
                    
                    # Also mention bridge-level commands
                    tools_list_str += "\nBridge-level commands:\n"
                    tools_list_str += "  - get_cached_result(result_id): Retrieve full cached result\n"
                    tools_list_str += "  - scan_function_pointer_tables(): Scan for vtables/dispatch tables\n"
                    
                    enhanced_unknown_command_error = f"{error_message}\n\nTo help you choose a valid tool, here is a list of available Ghidra tools:\n{tools_list_str}"
                    raise ValueError(enhanced_unknown_command_error)
                
            # Check for required parameters
            is_valid, error_message = self.command_parser.validate_command_parameters(
                normalized_command, params
            )
            if not is_valid:
                enhanced_error = self.command_parser.get_enhanced_error_message(
                    command_name, params, error_message
                )
                raise ValueError(enhanced_error)
                
            # Enhanced CAG memory-based duplicate detection
            if self.enable_cag and self.cag_manager:
                # Check if CAG memory suggests skipping this command
                should_skip, skip_reason = self.cag_manager.should_skip_command(normalized_command, params)
                if should_skip:
                    self.logger.warning(f"🧠 CAG Memory suggests skipping: {skip_reason}")
                    
                    # Try to get cached result from CAG memory
                    cached_result = self.cag_manager.get_cached_command_result(normalized_command, params)
                    if cached_result:
                        self.logger.info(f"🎯 Using CAG cached result for {normalized_command}")
                        return {"result": cached_result, "source": "cag_cache"}
                    else:
                        # Return a guidance message instead of executing
                        guidance_msg = f"Command '{normalized_command}' skipped due to recent execution. {skip_reason}"
                        return {"result": guidance_msg, "source": "cag_skip", "skipped": True}
                
            # Find the command in the Ghidra client
            command_func = getattr(self.ghidra_client, normalized_command)
            
            # Enhanced caching for multiple command types
            cache_key = self._generate_cache_key(normalized_command, params)
            cached_result = self._get_cached_result(normalized_command, cache_key, params)
            
            if cached_result is not None:
                self.cache_stats['hits'] += 1
                self.logger.info(f"🎯 Cache HIT for {normalized_command} (key: {cache_key}) - Stats: {self.cache_stats['hits']} hits, {self.cache_stats['misses']} misses")
                return cached_result
            
            # Cache miss - execute the command
            self.cache_stats['misses'] += 1
            self.logger.info(f"💫 Cache MISS for {normalized_command} (key: {cache_key}) - Executing...")
            
            result = command_func(**params)
            
            # Cache the result for future use
            self._cache_result(normalized_command, cache_key, params, result)
            
            # Update CAG memory with the executed command and result
            if self.enable_cag and self.cag_manager:
                self.cag_manager.update_command_execution(normalized_command, params, str(result))
            
            # Update analysis state to track the command execution
            command_dict = {
                'name': normalized_command,
                'params': params
            }
            self._update_analysis_state(command_dict, str(result))
            
            return result
        except Exception as e:
            error_message = str(e)
            enhanced_error = self.command_parser.get_enhanced_error_message(
                command_name, params, error_message
            )
            raise ValueError(enhanced_error) from e

    def _generate_cache_key(self, command_name: str, params: Dict[str, Any]) -> str:
        """
        Generate a cache key for a command and its parameters.
        
        Args:
            command_name: The command name
            params: The command parameters
            
        Returns:
            A unique cache key string
        """
        # For functions, use name if available, otherwise use current function
        if command_name in ["decompile_function", "analyze_function"]:
            if "name" in params and params["name"]:
                return f"{command_name}:{params['name']}"
            elif "address" in params and params["address"]:
                return f"{command_name}:{params['address']}"
            else:
                # For current function, we need to get the current function name/address
                try:
                    current_func = self.ghidra_client.get_current_function()
                    if isinstance(current_func, str) and "Function:" in current_func:
                        # Extract function name from "Function: FUN_12345 at 12345"
                        import re
                        match = re.search(r'Function:\s*(\w+)', current_func)
                        if match:
                            func_name = match.group(1)
                            return f"{command_name}:current:{func_name}"
                except:
                    pass
                return f"{command_name}:current"
        
        elif command_name == "get_current_function":
            # For get_current_function, cache per session but allow invalidation
            return f"{command_name}:session"
            
        else:
            # For other commands, create key from sorted params
            param_str = ":".join([f"{k}={v}" for k, v in sorted(params.items())])
            return f"{command_name}:{param_str}" if param_str else command_name

    def _get_cached_result(self, command_name: str, cache_key: str, params: Dict[str, Any]):
        """
        Get a cached result if available.
        
        Args:
            command_name: The command name
            cache_key: The cache key
            params: The command parameters
            
        Returns:
            Cached result or None if not found
        """
        # Commands that should NOT be cached (real-time or state-dependent)
        NO_CACHE_COMMANDS = [
            "list_imports",      # May change with binary state
            "list_exports",      # May change with binary state
            "list_strings",      # Large results, may change
            "list_segments",     # Binary structure
            "get_current_address",  # Dynamic state
            "check_health",      # Real-time check
            "health_check"       # Real-time check
        ]
        
        # Don't use cache for these commands
        if command_name in NO_CACHE_COMMANDS:
            return None
        
        # Check different cache stores based on command type
        if command_name in ["decompile_function", "analyze_function"]:
            return self.decompilation_cache.get(cache_key)
        elif command_name == "get_current_function":
            return self.function_cache.get(cache_key)
        else:
            # Generic cache for other commands
            return self.decompilation_cache.get(cache_key)

    def _cache_result(self, command_name: str, cache_key: str, params: Dict[str, Any], result: Any):
        """
        Cache a command result.
        
        Args:
            command_name: The command name
            cache_key: The cache key
            params: The command parameters
            result: The result to cache
        """
        # Commands that should NOT be cached (real-time or state-dependent)
        NO_CACHE_COMMANDS = [
            "list_imports",      # May change with binary state
            "list_exports",      # May change with binary state
            "list_strings",      # Large results, may change
            "list_segments",     # Binary structure
            "get_current_address",  # Dynamic state
            "check_health",      # Real-time check
            "health_check"       # Real-time check
        ]
        
        # Don't cache these commands
        if command_name in NO_CACHE_COMMANDS:
            return
        
        # Check if result is an error - don't cache errors
        if isinstance(result, str) and result.startswith("ERROR:"):
            self.logger.debug(f"⚠️ Not caching error result for {command_name}")
            return
        
        # Check if result is empty or indicates failure - don't cache
        if isinstance(result, (list, dict)) and not result:
            self.logger.debug(f"⚠️ Not caching empty result for {command_name}")
            return
        
        # Cache in appropriate store
        if command_name in ["decompile_function", "analyze_function"]:
            self.decompilation_cache[cache_key] = result
            self.cache_stats['cache_size'] = len(self.decompilation_cache)
            self.logger.debug(f"📦 Cached {command_name} result for key: {cache_key}")
        elif command_name == "get_current_function":
            self.function_cache[cache_key] = result
            self.logger.debug(f"📦 Cached {command_name} result for key: {cache_key}")
        else:
            # Generic cache for other commands (but only cacheable ones)
            self.decompilation_cache[cache_key] = result
            self.cache_stats['cache_size'] = len(self.decompilation_cache)

    def clear_cache(self):
        """Clear all caches."""
        self.decompilation_cache.clear()
        self.function_cache.clear()
        self.cache_stats = {'hits': 0, 'misses': 0, 'cache_size': 0}
        self.logger.info("🧹 All caches cleared")

    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        total_requests = self.cache_stats['hits'] + self.cache_stats['misses']
        hit_rate = (self.cache_stats['hits'] / total_requests * 100) if total_requests > 0 else 0
        
        return {
            'hits': self.cache_stats['hits'],
            'misses': self.cache_stats['misses'],
            'hit_rate': f"{hit_rate:.1f}%",
            'cache_size': self.cache_stats['cache_size'],
            'total_requests': total_requests
        }

    def process_query_with_agentic_loop(self, query: str) -> str:
        """
        Process a query with multi-cycle agentic loop.
        
        Loops through Planning → Execution → Analysis → Evaluation
        until goal is achieved or max cycles reached.
        
        Args:
            query: Natural language query from the user
            
        Returns:
            Final analysis response
        """
        try:
            self.logger.info(f"🚀 Starting agentic query processing: '{query}'")
            self.logger.info(f"📊 Config: max_agentic_cycles={self.config.ollama.max_agentic_cycles}, max_execution_steps={self.config.ollama.max_execution_steps}")
            
            # Store the query as our current goal
            self.current_goal = query
            self.goal_achieved = False
            self.goal_steps_taken = 0
            self.executed_tools = set()  # Reset tool tracking for new query
            self.step_result_map = {}  # Reset step result map for new query
            
            # Ensure context is initialized
            if not isinstance(self.context, list):
                if isinstance(self.context, dict) and 'history' in self.context:
                    self.context = self.context['history']
                else:
                    self.context = []
            
            # Add user query to context
            self.add_to_context("user", query)
            
            # Get configuration
            max_cycles = self.config.ollama.max_agentic_cycles
            max_exec_steps = self.config.ollama.max_execution_steps
            
            best_response = ""
            all_cycle_results = []
            
            # OUTER LOOP: Agentic cycles
            for cycle in range(1, max_cycles + 1):
                self.logger.info(f"{'='*70}")
                self.logger.info(f"AGENTIC CYCLE {cycle}/{max_cycles}")
                self.logger.info(f"{'='*70}")
                
                # Emit cycle start to UI
                self._emit_cot("Cycle", f"AGENTIC CYCLE {cycle}/{max_cycles}")
                
                # Track current loop number for step ID generation
                self.current_loop_number = cycle
                
                # PHASE 1: Planning
                self.logger.info(f"📋 Cycle {cycle} - Phase 1: Planning")
                self._emit_cot("Phase", f"Phase 1: Planning")
                self.current_workflow_stage = 'planning'
                
                # For cycles after the first, add context about what we learned
                if cycle > 1:
                    cycle_context = f"\n\n## Previous Cycle Results\n"
                    cycle_context += f"Cycles completed: {cycle - 1}\n"
                    cycle_context += f"Previous evaluation: {all_cycle_results[-1]['reason']}\n"
                    
                    # Build summary of tools already executed to prevent redundant calls
                    cycle_context += "\n### Already Executed Tools (DO NOT repeat these exact calls):\n"
                    for cmd_sig, (step_id, excerpt) in self.step_result_map.items():
                        # Parse the command signature to show a readable format
                        cmd_parts = cmd_sig.split(":", 1)
                        cmd_name = cmd_parts[0] if cmd_parts else cmd_sig
                        cycle_context += f"- {step_id}: {cmd_name} -> {excerpt[:80]}...\n"
                    
                    cycle_context += "\nContinue investigating based on the gaps identified above. "
                    cycle_context += "Use get_cached_result(result_id=\"step_L{loop}_{N}\") to retrieve any previous result.\n"
                    plan_response = self._generate_plan(query + cycle_context)
                else:
                    plan_response = self._generate_plan(query)
                
                self.logger.info(f"✅ Planning completed: {len(plan_response)} chars")
                self._emit_cot("Status", f"Planning completed ({len(plan_response)} chars)")
                
                # PHASE 2: Execution Loop (INNER LOOP)
                self.logger.info(f"🔧 Cycle {cycle} - Phase 2: Execution Loop (max {max_exec_steps} steps)")
                self._emit_cot("Phase", f"Phase 2: Execution Loop (max {max_exec_steps} steps)")
                self.current_workflow_stage = 'execution'
                exec_results = self._execution_loop(plan_response, max_steps=max_exec_steps)
                self.logger.info(f"✅ Execution loop completed: {exec_results.total_steps} steps executed")
                self._emit_cot("Status", f"Execution completed: {exec_results.total_steps} tools executed")
                
                # PHASE 3: Analysis
                self.logger.info(f"🧠 Cycle {cycle} - Phase 3: Analysis")
                self._emit_cot("Phase", f"Phase 3: Analysis")
                self.current_workflow_stage = 'analysis'
                response = self._analyze_execution_results(exec_results)
                self.logger.info(f"✅ Analysis completed: {len(response)} chars")
                self._emit_cot("Status", f"Analysis completed ({len(response)} chars)")
                
                # Store best response so far
                best_response = response
                
                # PHASE 4: Evaluation
                self.logger.info(f"🔍 Cycle {cycle} - Phase 4: Goal Evaluation")
                self._emit_cot("Phase", f"Phase 4: Goal Evaluation")
                self.current_workflow_stage = 'evaluation'
                goal_achieved, reason = self._evaluate_goal_achievement(
                    goal=query,
                    analysis=response,
                    exec_results=exec_results
                )
                
                # Store cycle results
                all_cycle_results.append({
                    'cycle': cycle,
                    'goal_achieved': goal_achieved,
                    'reason': reason,
                    'tools_executed': exec_results.total_steps
                })
                
                if goal_achieved:
                    self.logger.info(f"✅ Goal achieved in cycle {cycle}!")
                    self.logger.info(f"   Total cycles used: {cycle}/{max_cycles}")
                    self.logger.info(f"   Total tools executed: {sum(r['tools_executed'] for r in all_cycle_results)}")
                    self._emit_cot("Status", f"Goal achieved in cycle {cycle}! Total tools: {sum(r['tools_executed'] for r in all_cycle_results)}")
                    self.goal_achieved = True
                    break
                else:
                    self.logger.warning(f"⚠️ Goal not achieved in cycle {cycle}")
                    self.logger.warning(f"   Reason: {reason}")
                    self._emit_cot("Status", f"Goal not yet achieved: {reason[:100]}...")
                    
                    if cycle < max_cycles:
                        self.logger.info(f"🔄 Looping back to planning for cycle {cycle + 1}")
                        self._emit_cot("Status", f"Looping back to planning for cycle {cycle + 1}")
                        # Add evaluation result to context for next planning
                        eval_context = f"Cycle {cycle} evaluation: Goal not yet achieved. {reason}"
                        self.add_to_context("evaluation", eval_context)
                    else:
                        self.logger.warning(f"⚠️ Max cycles ({max_cycles}) reached")
                        self.logger.warning(f"   Returning best effort response from {len(all_cycle_results)} cycles")
                        self._emit_cot("Status", f"Max cycles ({max_cycles}) reached - returning best effort response")
            
            # Add final summary to response if multiple cycles were used
            if len(all_cycle_results) > 1:
                cycle_summary = f"\n\n---\n**Investigation Summary**: Completed {len(all_cycle_results)} investigation cycle(s) with {sum(r['tools_executed'] for r in all_cycle_results)} total tool executions."
                best_response += cycle_summary
            
            # Add assistant response to context
            self.add_to_context("assistant", best_response)
            
            # Workflow complete
            self.current_workflow_stage = None
            self.logger.info("🎯 Agentic query processing completed successfully")
            
            return best_response
            
        except Exception as e:
            # Log the exception with full traceback
            import traceback
            self.logger.error(f"❌ Error in agentic query processing: {str(e)}")
            self.logger.error(f"Full traceback: {traceback.format_exc()}")
            
            # Reset workflow stage on error
            self.current_workflow_stage = None
            
            # Return error message
            return f"Error in query processing: {str(e)}"

    def process_query_single_pass(self, query: str) -> str:
        """
        Process a natural language query with a single Planning→Execution→Analysis pass.
        
        This is the original behavior - one cycle only, no goal evaluation or re-planning.
        
        Args:
            query: Natural language query from the user
            
        Returns:
            Result of processing the query
        """
        try:
            self.logger.info(f"🚀 Starting query processing: '{query}'")
            
            # Store the query as our current goal
            self.current_goal = query
            self.goal_achieved = False
            self.goal_steps_taken = 0
            self.executed_tools = set()  # Reset tool tracking for new query
            self.step_result_map = {}  # Reset step result map for new query
            
            # Ensure context is initialized as a list if it's not already
            if not isinstance(self.context, list):
                if isinstance(self.context, dict) and 'history' in self.context:
                    self.context = self.context['history']
                else:
                    self.context = []
            
            # Add user query to context
            self.add_to_context("user", query)
            
            # PHASE 1: Planning - determine what tools need to be called
            self.logger.info("📋 Phase 1: Starting planning phase")
            self.current_workflow_stage = 'planning'
            plan_response = self._generate_plan(query)
            self.logger.info(f"✅ Planning completed: {len(plan_response)} chars")
            
            # Check if execution loop is enabled
            use_execution_loop = self.config.ollama.execution_loop_enabled
            
            if use_execution_loop:
                # NEW: Multi-tool execution loop
                self.logger.info("🔄 Phase 2: Starting execution loop (multi-tool mode)")
                self.current_workflow_stage = 'execution'
                max_steps = self.config.ollama.max_execution_steps
                exec_results = self._execution_loop(plan_response, max_steps=max_steps)
                self.logger.info(f"✅ Execution loop completed: {exec_results.total_steps} steps")
                
                # PHASE 3: Analysis - analyze accumulated results
                self.logger.info("🧠 Phase 3: Starting analysis phase with accumulated results")
                self.current_workflow_stage = 'analysis'
                response = self._analyze_execution_results(exec_results)
                self.logger.info(f"✅ Analysis completed: {len(response)} chars")
            else:
                # LEGACY: Single-shot execution (original behavior)
                self.logger.info("🔧 Phase 2: Starting execution phase (legacy single-shot mode)")
                self.current_workflow_stage = 'execution'
                result = self._execute_plan()
                self.logger.info(f"✅ Execution completed: {len(result)} chars")
                
                # PHASE 3: Analysis - analyze results and generate final response
                self.logger.info("🧠 Phase 3: Starting analysis phase")
                self.current_workflow_stage = 'analysis'
                response = self._generate_analysis(query, result)
                self.logger.info(f"✅ Analysis completed: {len(response)} chars")
            
            # Add assistant response to context
            self.add_to_context("assistant", response)
            
            # Workflow complete
            self.current_workflow_stage = None
            self.logger.info("🎯 Query processing completed successfully")
            
            return response
        except Exception as e:
            # Log the exception with full traceback
            import traceback
            self.logger.error(f"❌ Error in query processing: {str(e)}")
            self.logger.error(f"Full traceback: {traceback.format_exc()}")
            
            # Reset workflow stage on error
            self.current_workflow_stage = None
            
            # Return error message
            return f"Error in query processing: {str(e)}"

    def process_query(self, query: str) -> str:
        """
        Main entry point for query processing.
        
        Routes to appropriate processing method based on configuration:
        - Agentic loop: Multiple Planning→Execution→Analysis cycles with goal evaluation
        - Single-pass: One Planning→Execution→Analysis cycle (original behavior)
        
        Args:
            query: Natural language query from the user
            
        Returns:
            Result of processing the query
        """
        # Check if agentic loop is enabled
        if self.config.ollama.agentic_loop_enabled:
            self.logger.info("🔄 Using multi-cycle agentic loop mode")
            return self.process_query_with_agentic_loop(query)
        else:
            self.logger.info("➡️ Using single-pass mode (legacy)")
            return self.process_query_single_pass(query)

    def _generate_plan(self, query: str) -> str:
        """
        Generate a plan for addressing the query using Ollama.
        
        Args:
            query: Natural language query from the user
            
        Returns:
            Plan response
        """
        # Use CAG manager to enhance context with knowledge and session data
        if self.enable_cag and self.cag_manager:
            # Update session cache with current context
            self.cag_manager.update_session_from_bridge_context(self.context)
        
        logging.info("Starting planning phase")
        
        # Build prompts (system and user)
        system_prompt, user_prompt = self._build_structured_prompt(phase="planning")
        user_prompt += f"\n\nUser Query: {query}"
        
        # Generate planning response with properly separated prompts
        response = self.ollama.generate_with_phase(user_prompt, phase="planning", system_prompt=system_prompt)
        
        # Extract plan
        self.current_plan = response
        logging.info(f"Received planning response: {response[:100]}...")
        
        # Parse the planned tools
        self.current_plan_tools = self._parse_plan_tools(response)
        logging.info(f"Extracted {len(self.current_plan_tools)} planned tools from plan")
        
        # Add plan to context
        self.add_to_context("plan", response)
        
        logging.info("Planning phase completed")
        return response

    def _display_tool_result(self, cmd_name: str, result: Any) -> None:
        """
        Display a tool result to the user in a clear, formatted way.
        
        Args:
            cmd_name: The name of the command executed
            result: The result from the command execution
        """
        # List of "verbose" commands that should display their full results
        verbose_commands = ["list_functions", "list_methods", "list_imports", "list_exports", 
                           "search_functions_by_name", "decompile_function", "decompile_function_by_address"]
        
        # Special handling based on command type
        if cmd_name in verbose_commands:
            print("\n" + "="*60)
            print(f"Results from {cmd_name}:")
            print("="*60)
            
            # Format based on result type
            if isinstance(result, list):
                # For lists like function lists, show with numbering
                for i, item in enumerate(result, 1):
                    if isinstance(item, dict) and "name" in item and "address" in item:
                        print(f"{i:3d}. {item['name']} @ {item['address']}")
                    elif isinstance(item, dict):
                        print(f"{i:3d}. {item}")
                    else:
                        print(f"{i:3d}. {item}")
                print(f"\nTotal: {len(result)} items")
            elif isinstance(result, dict):
                # For dictionary results
                for key, value in result.items():
                    print(f"{key}: {value}")
            elif isinstance(result, str) and len(result) > 500:
                # For long string results (like decompiled code)
                print(f"{result[:500]}...\n[Showing first 500 characters of {len(result)} total]")
            else:
                # For other results
                print(result)
            
            print("="*60 + "\n")
        else:
            # For non-verbose commands, just show a success message
            print(f"✓ Successfully executed {cmd_name}")
            
    def _execute_plan(self) -> str:
        """
        Execute the generated plan.
        Returns:
            A string representing all tool results or errors.
        """
        # --- Duplicate-detection helpers ---
        READ_ONLY_PAGINATED = {"list_strings", "list_imports", "list_exports", "list_segments"}

        def _canonical_params(cmd, params):
            """Strip default offset/limit values for read-only tools so signatures match."""
            defaults = {"offset": 0, "limit": 100}
            if cmd in READ_ONLY_PAGINATED:
                cleaned = {k: v for k, v in params.items() if defaults.get(k) != v}
            else:
                cleaned = params
            return tuple(sorted(cleaned.items()))
        
        logging.info("Starting execution phase")
        
        all_results = []
        self.goal_steps_taken = 0
        step_count = 0
        goal_statement = f"Goal: {self.current_goal}"
        
        executed_commands = {}  # cmd_name+params -> count
        
        # Loop until we hit max steps or goal is achieved
        while step_count < self.max_goal_steps and not self.goal_achieved:
            step_count += 1
            self.goal_steps_taken = step_count
            
            logging.info(f"Step {step_count}/{self.max_goal_steps}: Sending query to Ollama")
            
            # Build prompts for tool execution
            system_prompt, user_prompt = self._build_structured_prompt(phase="execution")
            user_prompt += f"\n\n{goal_statement}\n\nStep {step_count}: Determine the next tool to call or mark the goal as completed."
            
            # Use CAG to enhance context with knowledge and session data
            if self.enable_cag and self.cag_manager:
                # Update session cache with current context
                self.cag_manager.update_session_from_bridge_context(self.context)
                
                # Get memory-enhanced prompt context to prevent redundant operations
                memory_context = self.cag_manager.enhance_prompt_with_memory_context(goal_statement)
                if memory_context:
                    user_prompt = f"{memory_context}\n\n{user_prompt}"
            
            # Generate execution step with properly separated prompts
            response = self.ollama.generate_with_phase(user_prompt, phase="execution", system_prompt=system_prompt)
            logging.info(f"Received response from Ollama: {response[:100]}...")
            
            # --- PARSE ARTIFACTS (Text-Based) ---
            self._parse_and_save_artifacts(response)
            # ------------------------------------
            
            # Extract commands to execute
            commands = self.command_parser.extract_commands(response)
            
            # Enhanced duplicate detection using CAG memory system
            if commands:
                cmd_name, cmd_params = commands[0]  # Get first command
                
                # Create signature for this exact command
                cmd_signature = f"{cmd_name}({_canonical_params(cmd_name, cmd_params)})"
                
                # First check CAG memory for intelligent duplicate detection
                skip_due_to_memory = False
                if self.enable_cag and self.cag_manager:
                    should_skip, skip_reason = self.cag_manager.should_skip_command(cmd_name, cmd_params)
                    if should_skip:
                        self.logger.warning(f"🧠 CAG Memory: {skip_reason}")
                        
                        # Get memory-enhanced guidance
                        memory_guidance = self.cag_manager.enhance_prompt_with_memory_context(
                            self.current_goal or "analysis", cmd_name, cmd_params
                        )
                        
                        guidance_msg = f"CAG Memory Guidance: {skip_reason}\n\n{memory_guidance}"
                        self.add_to_context("system", guidance_msg)
                        skip_due_to_memory = True
                
                # Fallback to original duplicate detection if CAG didn't catch it
                if not skip_due_to_memory and executed_commands.get(cmd_signature, 0) >= 1:
                    self.logger.warning(f"🚫 Skipping duplicate command: {cmd_signature}")
                    self.add_to_context("assistant", f"ERROR: Duplicate command `{cmd_name}` was skipped. Please choose a different tool or change parameters.")
                    skip_due_to_memory = True
                
                if skip_due_to_memory:
                    continue
                
                executed_commands[cmd_signature] = executed_commands.get(cmd_signature, 0) + 1
                
                # Track tool usage
                tool_signature = f"{cmd_name}({cmd_params})"
                tool_count = self.executed_tools.count(cmd_name)
                
                # Special validation for rename_function to prevent context mismatches
                if cmd_name == "rename_function" and "old_name" in cmd_params:
                    old_name = cmd_params["old_name"]
                    new_name = cmd_params.get("new_name", "")
                    rename_count = self.executed_tools.count("rename_function")
                    
                    # Check for same-name rename (useless operation)
                    if old_name == new_name:
                        logging.warning(f"Detected same-name rename: '{old_name}' -> '{new_name}'. This is a useless operation.")
                        same_name_guidance = f"""
                        ATTENTION: You're trying to rename '{old_name}' to '{new_name}' - this is the SAME NAME!
                        
                        This is a useless operation. The function is already named '{old_name}'.
                        
                        If the function is already properly named, respond with "GOAL ACHIEVED".
                        If you need to rename it, choose a DIFFERENT, more descriptive name based on the function's purpose.
                        """
                        self.add_to_context("system", same_name_guidance)
                        continue  # Skip this command and get a new one
                    
                    if rename_count >= 2:  # After 2 rename attempts, provide guidance
                        logging.warning(f"Multiple rename_function calls detected. Checking for context mismatch.")
                        context_guidance = f"""
                        ATTENTION: You've called 'rename_function' {rename_count} times. 
                        
                        You're trying to rename '{old_name}'. Please verify this is the CURRENT function:
                        1. Call get_current_function() to see which function is currently selected in Ghidra
                        2. Only rename the function that is currently selected
                        3. If you've already renamed the correct function, respond with "GOAL ACHIEVED"
                        
                        Do NOT rename functions from previous contexts or conversations.
                        """
                        self.add_to_context("system", context_guidance)
                
                if tool_count >= self.tool_repetition_limit:
                    logging.warning(f"Tool '{cmd_name}' has been called {tool_count} times. Possible repetitive behavior detected.")
                    
                    # Inject a guidance prompt to help the AI break out of the loop
                    guidance_prompt = f"""
                    ATTENTION: You've called '{cmd_name}' {tool_count} times already. This suggests you may be stuck in a loop.
                    
                    Based on the goal: "{self.current_goal}"
                    
                    Please review what you've accomplished so far and either:
                    1. If you have enough information, proceed to the ACTION step (e.g., rename_function)
                    2. If the goal is complete, respond with "GOAL ACHIEVED"
                    3. If you need different information, use a different tool
                    
                    Do NOT repeat the same tool call again.
                    """
                    self.add_to_context("system", guidance_prompt)
            
            # If no commands but the response indicates goal completion, mark as achieved
            if not commands and ("GOAL ACHIEVED" in response.upper() or "GOAL COMPLETE" in response.upper()):
                logging.info("AI indicates the goal has been achieved")
                self.goal_achieved = True
                all_results.append(f"Step {step_count} - Goal achievement indicated: {response}")
                break
                
            # Execute commands
            execution_result = ""
            for cmd_name, cmd_params in commands:
                try:
                    # Add tool call to context
                    tool_call = f"EXECUTE: {cmd_name}({', '.join([f'{k}=\"{v}\"' for k, v in cmd_params.items()])})"
                    self.add_to_context("tool_call", tool_call)
                    
                    # Execute command with parameter normalization
                    logging.info(f"Executing GhidraMCP command: {cmd_name} with params: {cmd_params}")
                    result = self.execute_command(cmd_name, cmd_params)
                    
                    # Display the result to the user
                    self._display_tool_result(cmd_name, result)
                    
                    # Format the result for context and logging
                    if isinstance(result, dict) or isinstance(result, list):
                        execution_result = json.dumps(result, indent=2)
                    else:
                        execution_result = str(result)
                    
                    # Dynamic truncation based on context budget
                    # Default: 15,000 chars (~3,750 tokens) - increased from previous 6,000
                    max_result_chars = 15000
                    if self.context_manager and hasattr(self.context_manager, 'budget'):
                        remaining = self.context_manager.budget.get_remaining_execution_chars()
                        # Allow up to 25% of remaining budget or default, whichever is larger
                        max_result_chars = max(15000, remaining // 4)
                    
                    context_result = execution_result
                    if len(execution_result) > max_result_chars:
                        # For list-like results, show a summary instead of full output
                        lines = execution_result.split('\n')
                        if len(lines) > 50:
                            # Show first 30 and last 15 lines with a summary (increased from 20/10)
                            first_lines = '\n'.join(lines[:30])
                            last_lines = '\n'.join(lines[-15:])
                            truncation_msg = f"\n... [Truncated {len(lines) - 45} lines for context efficiency] ...\n"
                            context_result = f"{first_lines}{truncation_msg}{last_lines}\n\nSummary: {len(lines)} total items returned"
                            logging.info(f"Truncated large result ({len(execution_result)} chars -> {len(context_result)} chars)")
                        else:
                            # Simple truncation for non-list results
                            context_result = execution_result[:max_result_chars] + f"\n... [Truncated {len(execution_result) - max_result_chars} chars]"
                    
                    # Add to Pydantic session (structured storage)
                    self.session.add_tool_execution(
                        tool_name=cmd_name,
                        parameters=cmd_params,
                        result=context_result,
                        success=True
                    )
                    
                    # Add command result to context (legacy - for backward compatibility)
                    self.add_to_context("tool_result", context_result)
                    # Cache signature for duplicate detection intelligence
                    sig_exec = f"{cmd_name}({_canonical_params(cmd_name, cmd_params)})"
                    self.analysis_state.setdefault('cached_results', {})[sig_exec] = True
                    
                    # Update analysis state
                    command = {"name": cmd_name, "params": cmd_params}
                    self._update_analysis_state(command, execution_result)
                    
                    # Add to all results
                    all_results.append(f"Command: {cmd_name}\nResult: {execution_result}\n")
                
                except Exception as e:
                    error_msg = f"ERROR: {str(e)}"
                    logging.error(f"Error executing {cmd_name}: {error_msg}")
                    execution_result = error_msg
                    self.add_to_context("tool_error", error_msg)
                    all_results.append(f"Command: {cmd_name}\nError: {error_msg}\n")
                    print(f"❌ Error executing {cmd_name}: {error_msg}")
            
            # If no commands were found, note this and end loop if it's the second consecutive time
            if not commands:
                logging.info("No commands found in AI response, ending tool execution loop")
                all_results.append(f"Step {step_count} - No tool calls: {response}")
                break
        
        if step_count >= self.max_goal_steps:
            logging.info(f"Reached maximum steps ({self.max_goal_steps}), ending tool execution loop")
            
        logging.info("Execution phase completed")
        return "\n".join(all_results)

    def _evaluate_goal_completion(self, query: str, execution_results: str) -> bool:
        """
        Ask the AI to evaluate if the goal has been completed.
        
        Args:
            query: The original user query.
            execution_results: A summary of the execution phase.
            
        Returns:
            True if the goal is considered complete, False otherwise.
        """
        self.logger.info("Evaluating goal completion...")
        
        # Format the evaluation prompt with the user's task description
        prompt = self.config.ollama.evaluation_system_prompt.format(
            user_task_description=query
        )
        
        # Add the execution results for context
        full_prompt = f"{prompt}\n\nExecution Summary:\n{execution_results}"
        
        response = self.ollama.generate(full_prompt)
        self.logger.info(f"Received evaluation response: {response.strip()}")
        
        return "goal achieved" in response.strip().lower()

    def _clean_final_response(self, response: str) -> str:
        """
        Clean up the final response for display by removing markers and formatting.
        
        Args:
            response: The raw final response
            
        Returns:
            Cleaned response text
        """
        # Remove "FINAL RESPONSE:" marker if present
        cleaned = re.sub(r'^FINAL RESPONSE:\s*', '', response, flags=re.IGNORECASE)
        
        # Remove any trailing instructions or markers
        cleaned = re.sub(r'\n+\s*EXECUTE:.*$', '', cleaned, flags=re.MULTILINE)
        
        # Remove any markdown formatting intended for the AI but not for display
        cleaned = re.sub(r'^\s*```.*?```\s*$', '', cleaned, flags=re.MULTILINE | re.DOTALL)
        
        return cleaned.strip()

    def _generate_analysis(self, query: str, execution_results: str) -> str:
        """
        Analyze the results of tool executions and generate a final response.
        
        Args:
            query: The original query
            execution_results: Results from tool executions
            
        Returns:
            Final analysis response
        """
        logging.info("Starting review and reasoning phase")
        
        # Update workflow stage to review
        self.current_workflow_stage = 'review'
        
        self.goal_achieved = False
        review_steps = 0
        max_review_steps = self.max_goal_steps
        final_response = ""
        review_results = []
        
        # Phase to iteratively review and refine our understanding
        while not self.goal_achieved and review_steps < max_review_steps:
            review_steps += 1
            logging.info(f"Review step {review_steps}/{max_review_steps}: Sending query to Ollama")
            
            # Build prompts for review
            system_prompt, user_prompt = self._build_structured_prompt(phase="review")
            user_prompt += f"\n\nGoal: {self.current_goal}\n\nExecution Results:\n{execution_results}\n\n"
            
            # Add directive based on whether we have execution results
            if execution_results and len(execution_results.strip()) > 50:
                user_prompt += """Review the execution results above carefully.

INVESTIGATION CRITERIA - Did you:
✓ Examine ALL error messages and strings in the code?
✓ Identify the protocol/technology (HTTP/2, TLS, etc.)?
✓ Understand the function's primary purpose from error messages?
✓ Extract semantic meaning from string literals?
✓ Use the AI analysis summary if available?

NAMING QUALITY CHECK:
❌ AVOID generic names like: "data_processing", "handle_something", "process_data"
✅ USE specific names based on: error messages, protocol operations, actual behavior
   Examples: "handle_http2_stream_close", "validate_tls_handshake", "parse_certificate_data"

If you can derive a MORE SPECIFIC name from the analysis (especially from error messages or AI summary), you MUST call rename_function again with the better name.

Only provide FINAL RESPONSE when:
1. The function name is SPECIFIC and DESCRIPTIVE (not generic)
2. You've investigated all available information (strings, errors, AI analysis)
3. No further investigation would improve the result

If investigation is incomplete or name is too generic, use EXECUTE to call tools."""
            else:
                user_prompt += "No tool execution results are available yet. You MUST use the EXECUTE format to call the necessary tools to accomplish the goal. Do NOT provide a FINAL RESPONSE until tools have been executed and results obtained."
            
            # Use CAG to enhance context
            if self.enable_cag and self.cag_manager:
                self.cag_manager.update_session_from_bridge_context(self.context)
            
            # Generate review response with properly separated prompts
            review_response = self.ollama.generate_with_phase(user_prompt, phase="analysis", system_prompt=system_prompt)
            logging.info(f"Received review response: {review_response[:100]}...")
            
            # Check for the final response marker
            final_response_match = re.search(r'FINAL RESPONSE:\s*(.*?)(?:\n\s*$|\Z)', 
                                             review_response, re.DOTALL)
            if final_response_match:
                final_response = final_response_match.group(1).strip()
                
                # Check if the "final response" actually contains instructions to execute tools
                # Common patterns: "should rename", "need to call", "must execute", "will rename", etc.
                instruction_patterns = [
                    r'\b(should|must|need to|will|let\'s)\s+(call|execute|rename|analyze|use)',
                    r'\brename\s+.*\s+to\s+',
                    r'\bcall\s+the\s+\w+\s+(function|tool|command)',
                    r'\bexecute\s+.*\s+with\s+',
                ]
                contains_instructions = any(re.search(pattern, final_response, re.IGNORECASE) 
                                           for pattern in instruction_patterns)
                
                if contains_instructions:
                    logging.warning("FINAL RESPONSE contains instructions instead of results - AI is describing actions rather than executing them")
                    logging.warning(f"Problematic response preview: {final_response[:200]}")
                    # Don't treat this as a valid final response, continue review loop
                    final_response = None
                    review_results.append(f"⚠️ Review step {review_steps}: AI provided instructions instead of executing tools. Response ignored.")
                    continue
                
                # Validate that the final response is reasonable
                if final_response and len(final_response) > 100:
                    logging.info("Found high-quality 'FINAL RESPONSE' marker in review, ending review loop")
                    self.goal_achieved = True
                    break
                elif final_response:
                    if "unable" in final_response.lower() or "limit" in final_response.lower():
                        logging.info(f"Final response is too short ({len(final_response)} chars)")
                        logging.info("Found 'FINAL RESPONSE' marker but response indicates limitations, continuing review")
                else:
                    logging.info("'FINAL RESPONSE' marker found but unable to extract response")
            
            # Check for additional tool calls in the review
            commands = self.command_parser.extract_commands(review_response)
            if commands:
                new_execution_results = []
                for cmd_name, cmd_params in commands:
                    try:
                        # Execute command
                        result = self.execute_command(cmd_name, cmd_params)
                        
                        # Format result for display
                        formatted_result = self.command_parser.format_command_results(cmd_name, cmd_params, result)
                        logging.info(f"Review command executed: {cmd_name}")
                        
                        # Add result to context
                        self.add_to_context("tool_result", formatted_result)
                        
                        # Store for injection back into execution_results
                        tool_result_entry = f"Tool Call: {cmd_name}\nParameters: {cmd_params}\nTool Result: {formatted_result}\n"
                        review_results.append(tool_result_entry)
                        new_execution_results.append(tool_result_entry)
                    except Exception as e:
                        error_msg = f"ERROR: {str(e)}"
                        logging.error(f"Error executing review command {cmd_name}: {error_msg}")
                        self.add_to_context("tool_error", error_msg)
                        error_entry = f"Error executing {cmd_name}: {error_msg}"
                        review_results.append(error_entry)
                        new_execution_results.append(error_entry)
                
                # Inject new results back into execution_results for next iteration
                if new_execution_results:
                    execution_results += "\n" + "\n".join(new_execution_results)
                    logging.info(f"Injected {len(new_execution_results)} new tool results into execution context")
            
            # If no commands and no final response yet, continue
            if not commands and not final_response:
                review_results.append(f"Review step {review_steps}: {review_response}")
        
        # If we have a final response, add it to the results
        if final_response:
            # Clean up the response for display
            display_response = self._clean_final_response(final_response)
            review_results.append(f"FINAL RESPONSE:\n{display_response}")
        else:
            review_results.append("No final response generated during review")
            
        return "\n".join(review_results)

    def _execution_loop(self, plan: str, max_steps: int = 10) -> ExecutionPhaseResults:
        """
        Execute tools in a loop until investigation is complete.
        
        This implements the multi-tool execution loop that allows the AI to:
        1. Execute multiple tools sequentially (Batching)
        2. Accumulate results for comprehensive analysis
        3. Decide when investigation is complete
        4. Capture reasoning for Chain of Thought
        
        Args:
            plan: The execution plan from planning phase
            max_steps: Maximum number of tool executions allowed
            
        Returns:
            ExecutionPhaseResults with all accumulated tool executions
        """
        # Initialize execution results
        exec_results = ExecutionPhaseResults(
            goal=self.current_goal or "Investigation",
            plan=plan
        )
        
        self.logger.info(f"🔄 Starting execution loop (max {max_steps} steps)")
        
        for step in range(1, max_steps + 1):
            self.logger.info(f"📍 Execution loop step {step}/{max_steps}")
            
            # Build prompt for next tool execution
            system_prompt, user_prompt = self._build_execution_loop_prompt(exec_results, step)
            
            # Ask AI: "What's the next tool to execute?"
            response = self.ollama.generate_with_phase(
                user_prompt,
                phase="execution",
                system_prompt=system_prompt
            )
            
            self.logger.info(f"Received execution loop response: {response[:100]}...")
            
            # Check if investigation is complete
            if "INVESTIGATION COMPLETE" in response.upper() or "GOAL ACHIEVED" in response.upper():
                self.logger.info("✅ AI indicates investigation is complete")
                exec_results.investigation_complete = True
                exec_results.completed_at = datetime.now()
                break
            
            # Extract reasoning
            reasoning = None
            reasoning_match = re.search(r'REASONING:\s*(.*?)(?:\nEXECUTE:|$)', response, re.DOTALL)
            if reasoning_match:
                reasoning = reasoning_match.group(1).strip()
                self.logger.info(f"🤔 Reasoning: {reasoning}")
                
                # Live CoT View - emit to both terminal and UI
                if getattr(self.config.ollama, 'show_reasoning', True):
                    self._emit_cot("Reasoning", f"REASONING: {reasoning}")
            
            # Parse tool calls from response
            commands = self.command_parser.extract_commands(response)
            
            if not commands:
                self.logger.warning(f"⚠️ No tool call found in response at step {step}")
                # Give AI one more chance
                if step < max_steps:
                    continue
                else:
                    break
            
            # Execute tools (Batching Support)
            for cmd_name, cmd_params in commands:
                try:
                    # Generate signature for duplicate detection
                    param_sig = str(sorted(cmd_params.items())) if cmd_params else ""
                    cmd_signature = f"{cmd_name}:{param_sig}"
                    
                    # Check for duplicate tool execution
                    if cmd_signature in self.executed_tools:
                        self.logger.warning(f"Skipping duplicate tool call: {cmd_name}({cmd_params})")
                        
                        # Get original step info for helpful message (now includes loop prefix)
                        original_step_id, result_excerpt = self.step_result_map.get(cmd_signature, (None, None))
                        
                        if original_step_id and result_excerpt:
                            # Include loop-prefixed step reference so AI clearly knows which loop it came from
                            skip_note = (
                                f"[Already executed in {original_step_id}. "
                                f"Result excerpt: {result_excerpt[:150]}... "
                                f"Use get_cached_result(result_id=\"{original_step_id}\") for full content]"
                            )
                        else:
                            skip_note = f"[Skipped - already executed with same parameters]"
                        
                        tool_exec = ToolExecution(
                            tool_name=cmd_name,
                            parameters=cmd_params,
                            result=skip_note,
                            success=True,
                            reasoning=f"Duplicate call skipped: {reasoning}"
                        )
                        exec_results.add_execution(tool_exec)
                        continue
                    
                    # Track this execution
                    self.executed_tools.add(cmd_signature)
                    
                    self.logger.info(f"🔧 Executing: {cmd_name}({cmd_params})")
                    
                    # Emit tool execution to UI
                    params_str = ", ".join(f"{k}={v}" for k, v in cmd_params.items()) if cmd_params else ""
                    self._emit_cot("Tool", f"Executing: {cmd_name}({params_str})")
                    
                    # Execute the tool
                    result = self.execute_command(cmd_name, cmd_params)
                    
                    # Display the result to the user
                    self._display_tool_result(cmd_name, result)
                    
                    # Format result
                    if isinstance(result, (dict, list)):
                        result_str = json.dumps(result, indent=2)
                    else:
                        result_str = str(result)
                    
                    # Store the full result for caching before truncation
                    full_result_str = result_str
                    
                    # Generate step ID early so we can reference it in truncation message
                    # Use loop-prefixed ID: step_L{loop}_{step} for unambiguous cross-loop references
                    current_step = exec_results.total_steps + 1
                    loop_step_id = f"step_L{self.current_loop_number}_{current_step}"
                    
                    # Dynamic truncation based on context budget
                    # Default: 15,000 chars (~3,750 tokens) - much larger than previous 6,000
                    max_result_chars = 15000
                    if self.context_manager and hasattr(self.context_manager, 'budget'):
                        remaining = self.context_manager.budget.get_remaining_execution_chars()
                        # Allow up to 25% of remaining budget or default, whichever is larger
                        max_result_chars = max(15000, remaining // 4)
                    
                    if len(result_str) > max_result_chars:
                        result_str = result_str[:max_result_chars] + (
                            f"\n... [Truncated {len(result_str) - max_result_chars} chars. "
                            f"Use get_cached_result(result_id=\"{loop_step_id}\") for full content]"
                        )
                    
                    # Add to execution results
                    tool_exec = ToolExecution(
                        tool_name=cmd_name,
                        parameters=cmd_params,
                        result=result_str,
                        success=True,
                        reasoning=reasoning
                    )
                    exec_results.add_execution(tool_exec)
                    
                    # Store step result for duplicate reference and caching
                    result_excerpt = result_str[:200].replace('\n', ' ').strip()
                    self.step_result_map[cmd_signature] = (loop_step_id, result_excerpt)
                    
                    # Cache FULL result with loop-prefixed ID for retrieval via get_cached_result
                    if self.context_manager and self.context_manager.result_cache:
                        self.context_manager.result_cache.store(
                            tool_name=cmd_name,
                            parameters=cmd_params,
                            result=full_result_str,  # Store full result, not truncated
                            custom_id=loop_step_id
                        )
                    
                    # Also add to session for tracking
                    self.session.add_tool_execution(
                        tool_name=cmd_name,
                        parameters=cmd_params,
                        result=result_str,
                        success=True,
                        reasoning=reasoning
                    )
                    
                    # Update analysis state
                    self._update_analysis_state({"name": cmd_name, "params": cmd_params}, result_str)
                    
                    self.logger.info(f"Step {step} complete: {cmd_name}")
                    
                except Exception as e:
                    error_msg = f"ERROR: {str(e)}"
                    self.logger.error(f"❌ Error in execution loop step {step}: {error_msg}")
                    
                    # Add error to execution results
                    tool_exec = ToolExecution(
                        tool_name=cmd_name,
                        parameters=cmd_params,
                        result=error_msg,
                        success=False,
                        error=error_msg,
                        reasoning=reasoning
                    )
                    exec_results.add_execution(tool_exec)
                    
                    # Continue to next command in batch
                    continue
        
        # Mark as complete
        if not exec_results.investigation_complete:
            exec_results.completed_at = datetime.now()
            self.logger.warning(f"⚠️ Execution loop ended after {step} steps (max reached)")
        
        self.logger.info(f"✅ Execution loop complete: {exec_results.total_steps} steps executed")
        return exec_results

    def _build_execution_loop_prompt(self, exec_results: ExecutionPhaseResults, 
                                     current_step: int) -> Tuple[str, str]:
        """
        Build prompt for execution loop iteration.
        
        Shows AI the goal, plan, and results so far, asks for next tool.
        
        Args:
            exec_results: Accumulated execution results so far
            current_step: Current step number
            
        Returns:
            Tuple of (system_prompt, user_prompt)
        """
        # Build base structured prompt for execution phase
        system_prompt, _ = self._build_structured_prompt(phase="execution")
        
        # Build custom user prompt (dynamic - shows progress)
        loop_num = self.current_loop_number
        user_sections = [
            f"## Investigation Goal\n{exec_results.goal}",
            f"\n## Execution Plan\n{exec_results.plan}",
            f"\n## Progress: Loop {loop_num}, Step {current_step} (completed {exec_results.total_steps} steps in this loop)"
        ]
        
        # Show previous loop results if this is cycle 2+
        if loop_num > 1 and self.step_result_map:
            prev_loop_results = [(sid, exc) for sid, exc in self.step_result_map.values() 
                                 if not sid.startswith(f"step_L{loop_num}_")]
            if prev_loop_results:
                user_sections.append(f"\n## Results from Previous Loop(s) (available via get_cached_result):")
                for step_id, excerpt in prev_loop_results[:5]:  # Limit to 5 to avoid bloat
                    user_sections.append(f"- {step_id}: {excerpt[:100]}...")
                if len(prev_loop_results) > 5:
                    user_sections.append(f"  ... and {len(prev_loop_results) - 5} more results")
        
        # Show execution results so far in current loop
        if exec_results.tool_executions:
            user_sections.append(f"\n## Execution Results (Loop {loop_num}):")
            for i, tool_exec in enumerate(exec_results.tool_executions, 1):
                step_id = f"step_L{loop_num}_{i}"
                result_preview = str(tool_exec.result)[:500]  # Truncate for context
                if len(str(tool_exec.result)) > 500:
                    result_preview += "..."
                user_sections.append(f"\n{step_id}: {tool_exec.tool_name}({tool_exec.parameters})")
                user_sections.append(f"Result: {result_preview}")
        
        # Instructions for next step
        user_sections.append("""
## Your Task

Based on the plan and results so far, determine the NEXT step(s).

1. **Reasoning**: Explain WHY you are choosing the specific tool(s). What do you hope to learn?
2. **Execution**: Execute one or more tools to gather information.

If the investigation is complete and you have enough information, respond with:
INVESTIGATION COMPLETE

Otherwise, provide your reasoning and then execute the tool(s) using the standard EXECUTE format:

REASONING: [Your reasoning here]
EXECUTE: tool_name(param1="value1", param2="value2")
EXECUTE: another_tool(param1="value1")

Output the REASONING line followed by one or more EXECUTE lines.
If you are done, output ONLY "INVESTIGATION COMPLETE".
""")
        
        user_prompt = "\n".join(user_sections)
        
        return (system_prompt, user_prompt)

    def _analyze_execution_results(self, exec_results: ExecutionPhaseResults) -> str:
        """
        Analysis phase: Review all execution results and provide comprehensive analysis.
        
        Uses context manager for intelligent result formatting with:
        - Tiered context (recent results get more detail)
        - Large result summarization
        - Context budget enforcement
        
        Args:
            exec_results: Accumulated results from execution loop
            
        Returns:
            Final analysis response
        """
        self.logger.info("📊 Starting analysis phase with accumulated results")
        
        # Reset context manager for fresh budget tracking
        self.context_manager.reset()
        
        # Format results with context-aware truncation and summarization
        formatted_results = self._format_results_with_context(exec_results)
        
        # Build prompt with context-managed execution results
        system_prompt, _ = self._build_structured_prompt(phase="analysis")
        
        user_prompt = f"""
## Investigation Goal
{exec_results.goal}

## Execution Summary
{exec_results.get_summary()}

## Execution Results ({exec_results.total_steps} steps)
{formatted_results}

## Your Task

Review ALL the execution results above and provide a comprehensive analysis that addresses the investigation goal.

Focus on:
1. What the target function/code does
2. How it's used (callers/references)
3. What it uses (callees/dependencies)
4. Overall behavior and purpose
5. Key findings and insights

Provide a clear, detailed analysis. Start your response with "FINAL RESPONSE:" to mark it as the final output.
"""
        
        # Log context budget usage
        self.logger.debug(self.context_manager.get_status())
        
        response = self.ollama.generate_with_phase(
            user_prompt,
            phase="analysis",
            system_prompt=system_prompt
        )
        
        # Clean up the response
        final_response = self._clean_final_response(response)
        
        self.logger.info("✅ Analysis phase complete")
        return final_response
    
    def _format_results_with_context(self, exec_results: ExecutionPhaseResults) -> str:
        """
        Format execution results with context-aware truncation and summarization.
        
        Uses the context manager to:
        - Give recent results more detail (tiered context)
        - Summarize or truncate large results
        - Stay within context budget
        
        Args:
            exec_results: Accumulated tool execution results
            
        Returns:
            Formatted string suitable for prompt inclusion
        """
        if not exec_results.tool_executions:
            return "No tool executions recorded."
        
        sections = []
        total = len(exec_results.tool_executions)
        
        for i, tool_exec in enumerate(exec_results.tool_executions, 1):
            # Determine detail level based on recency
            is_recent = i > total - self.context_manager.max_recent_detailed
            
            # Process result through context manager
            result_text = str(tool_exec.result) if tool_exec.result else "No result"
            display_content, cached = self.context_manager.process_result(
                tool_name=tool_exec.tool_name,
                parameters=tool_exec.parameters,
                result=result_text,
                goal=exec_results.goal
            )
            
            # Build section with loop-prefixed step ID
            step_id = f"step_L{self.current_loop_number}_{i}"
            section_lines = [f"\n### {step_id}: {tool_exec.tool_name}"]
            
            # Add reasoning if present
            if tool_exec.reasoning:
                section_lines.append(f"Reasoning: {tool_exec.reasoning}")
            
            # Add parameters
            param_str = ", ".join([f'{k}="{v}"' for k, v in tool_exec.parameters.items()])
            section_lines.append(f"Parameters: {param_str}")
            
            # Add result
            section_lines.append(f"Result:\n{display_content}")
            
            # Note if result was summarized
            if cached and cached.is_summarized:
                section_lines.append(f"[Full result cached as {cached.result_id}]")
            
            sections.append("\n".join(section_lines))
        
        return "\n".join(sections)

    def _evaluate_goal_achievement(
        self, 
        goal: str, 
        analysis: str, 
        exec_results: ExecutionPhaseResults
    ) -> Tuple[bool, str]:
        """
        Evaluate if the investigation goal has been achieved.
        
        This is used in the agentic loop to determine if another
        Planning→Execution→Analysis cycle is needed.
        
        Args:
            goal: The original user goal/query
            analysis: The analysis response from current cycle
            exec_results: All execution results from current cycle
            
        Returns:
            Tuple of (goal_achieved: bool, reason: str)
        """
        self.logger.info("🔍 Evaluating goal achievement...")
        
        # Build evaluation prompt
        system_prompt, _ = self._build_structured_prompt(phase="evaluation")
        
        user_prompt = f"""
## Original User Goal
{goal}

## Investigation Summary (Current Cycle)
- Total tools executed: {exec_results.total_steps}
- Investigation marked complete by AI: {exec_results.investigation_complete}
- Tools used: {', '.join([te.tool_name for te in exec_results.tool_executions])}

## Analysis Provided
{analysis[:1500]}...

## Your Task

Evaluate if the original goal has been **completely and thoroughly** achieved based on the analysis above.

Consider:
1. Does the analysis directly answer the user's question?
2. Is the information comprehensive and complete?
3. Are there obvious gaps or missing details?
4. Would the user be satisfied with this response?

Respond with EXACTLY ONE of these formats:

**If goal is fully achieved:**
GOAL ACHIEVED

**If more investigation needed:**
GOAL NOT ACHIEVED: [one sentence explaining what's missing]

Examples:
- "GOAL ACHIEVED"
- "GOAL NOT ACHIEVED: Need to investigate callers to understand usage"
- "GOAL NOT ACHIEVED: Missing information about error handling"

Be strict: Only mark as GOAL ACHIEVED if the goal is FULLY and COMPLETELY satisfied.
"""
        
        response = self.ollama.generate_with_phase(
            user_prompt,
            phase="evaluation",
            system_prompt=system_prompt
        )
        
        # Parse response
        response_clean = response.strip()
        goal_achieved = "GOAL ACHIEVED" in response_clean.upper() and "NOT ACHIEVED" not in response_clean.upper()
        
        if goal_achieved:
            reason = "Goal fully satisfied based on analysis"
        else:
            # Extract reason after "GOAL NOT ACHIEVED:"
            if "GOAL NOT ACHIEVED:" in response_clean:
                reason = response_clean.split("GOAL NOT ACHIEVED:", 1)[1].strip()
            else:
                reason = response_clean
        
        self.logger.info(f"{'✅' if goal_achieved else '⚠️'} Evaluation: {'Achieved' if goal_achieved else 'Not achieved'}")
        if not goal_achieved:
            self.logger.info(f"   Reason: {reason}")
        
        return goal_achieved, reason

    def _capture_function_summary(self, function_identifier: str, analysis_text: str) -> None:
        """
        Capture and store a function summary from AI analysis text.
        
        Args:
            function_identifier: Function address or name identifier
            analysis_text: The AI analysis text to extract summary from
        """
        self.logger.info(f"DEBUG: _capture_function_summary called for {function_identifier}, text length: {len(analysis_text)}")
        summary = self._extract_function_summary(analysis_text)
        self.logger.info(f"DEBUG: _extract_function_summary returned: '{summary}'")
        
        if summary and summary != "No clear summary found":
            # Store in bridge summaries
            if not hasattr(self, 'function_summaries'):
                self.function_summaries = {}
            self.function_summaries[function_identifier] = summary
            self.logger.info(f"DEBUG: Captured summary for {function_identifier}: {summary[:100]}...")
            
            # RAG integration removed - use "Load Vectors" button for vector operations
            # self._add_function_to_rag(function_identifier, summary)

            # ------------------------------------------------------------------
            #  NEW: Attempt to gather caller x-refs for this function
           # ------------------------------------------------------------------
            addr = self._normalize_address(str(function_identifier))
            if addr:
                try:
                    self._collect_xref_context(addr)
                except Exception as e:
                    self.logger.debug(f"Xref context collection failed for {function_identifier}: {e}")
        else:
            self.logger.warning(f"DEBUG: No valid summary extracted for {function_identifier}")

    def _add_function_to_rag(self, function_identifier: str, summary: str) -> None:
        """
        Add a renamed function and its summary as a RAG vector for enhanced context.
        
        Args:
            function_identifier: Function address or name identifier
            summary: Function behavior summary
        """
        try:
            self.logger.info(f"DEBUG: _add_function_to_rag called for {function_identifier} with summary: {summary[:50]}...")
            
            # Check if CAG manager is available and RAG is enabled
            has_cag = hasattr(self, 'cag_manager') and self.cag_manager
            rag_enabled = getattr(self.cag_manager, 'use_vector_store_for_prompts', True) if has_cag else False
            
            self.logger.info(f"DEBUG: has_cag_manager: {has_cag}, rag_enabled: {rag_enabled}")
            
            if not (has_cag and rag_enabled):
                self.logger.warning(f"DEBUG: Skipping RAG integration - has_cag: {has_cag}, rag_enabled: {rag_enabled}")
                return
            
            # Get function details from address mapping
            function_info = self.function_address_mapping.get(function_identifier, {})
            old_name = function_info.get('old_name', 'Unknown')
            new_name = function_info.get('new_name', function_identifier)
            
            # Create a comprehensive document for the vector store
            function_doc = {
                'title': f"Renamed Function: {new_name}",
                'content': f"""Function Analysis Result:

Address: {function_identifier}
Original Name: {old_name}
Renamed To: {new_name}
Analysis Summary: {summary}

This function was analyzed and renamed during reverse engineering. The summary provides insights into its behavior and purpose, which can help with understanding similar functions or related code patterns.

Keywords: function analysis, reverse engineering, {old_name}, {new_name}, behavior analysis""",
                'metadata': {
                    'type': 'function_analysis',
                    'address': function_identifier,
                    'old_name': old_name,
                    'new_name': new_name,
                    'summary': summary,
                    'timestamp': self._get_current_timestamp()
                }
            }
            
            # Add to vector store using CAG manager  
            if hasattr(self.cag_manager, 'vector_store') and self.cag_manager.vector_store:
                try:
                    # Generate embedding via Ollama
                    content_text = function_doc['content']
                    embeddings = Bridge.get_ollama_embeddings([content_text])
                    if not embeddings:
                        self.logger.warning("Ollama embedding unavailable – skipping RAG integration for function")
                        return
                    import numpy as np
                    embedding = np.array(embeddings[0], dtype=np.float32)
                    
                    # Convert our function_doc to the expected SimpleVectorStore format
                    vector_doc = {
                        "text": content_text,
                        "type": "function_analysis", 
                        "name": new_name,
                        "metadata": function_doc['metadata']
                    }
                    
                    # Get current counts for debugging
                    old_doc_count = len(self.cag_manager.vector_store.documents)
                    old_embedding_count = len(self.cag_manager.vector_store.embeddings)
                    
                    # Add document to documents list
                    self.cag_manager.vector_store.documents.append(vector_doc)
                    
                    # Add embedding to embeddings list
                    if isinstance(self.cag_manager.vector_store.embeddings, list) and len(self.cag_manager.vector_store.embeddings) > 0:
                        # Check if embeddings are stored as numpy arrays or lists
                        if isinstance(self.cag_manager.vector_store.embeddings[0], np.ndarray):
                            self.cag_manager.vector_store.embeddings.append(embedding)
                        else:
                            # Convert to numpy array first
                            embeddings_array = np.array(self.cag_manager.vector_store.embeddings)
                            new_embeddings = np.vstack([embeddings_array, embedding.reshape(1, -1)])
                            self.cag_manager.vector_store.embeddings = [new_embeddings[i] for i in range(len(new_embeddings))]
                    else:
                        # First embedding or empty list
                        self.cag_manager.vector_store.embeddings = [embedding]
                    
                    new_doc_count = len(self.cag_manager.vector_store.documents)
                    new_embedding_count = len(self.cag_manager.vector_store.embeddings)
                    
                    self.logger.info(f"✅ Successfully added function '{new_name}' to RAG vectors")
                    self.logger.info(f"📊 Documents: {old_doc_count} -> {new_doc_count}")
                    self.logger.info(f"🔢 Embeddings: {old_embedding_count} -> {new_embedding_count}")
                    
                    # Trigger memory panel refresh if UI is available
                    try:
                        if hasattr(self, '_ui_memory_panel_refresh'):
                            self._ui_memory_panel_refresh()
                    except Exception as e:
                        self.logger.debug(f"Could not refresh memory panel: {e}")
                    
                except Exception as e:
                    self.logger.error(f"Error adding function to RAG: {e}")
                except Exception as e:
                    self.logger.error(f"Failed to add function to RAG vectors: {e}")
                    import traceback
                    self.logger.error(f"Full traceback: {traceback.format_exc()}")
            
        except Exception as e:
            self.logger.warning(f"Failed to add function to RAG vectors: {e}")

    def _get_current_timestamp(self) -> str:
        """Get current timestamp as string."""
        from datetime import datetime
        return datetime.now().isoformat()

    def _extract_function_summary(self, analysis_text: str) -> str:
        """Extract a concise function summary from AI analysis text."""
        if not analysis_text:
            return ""
        
        # Look for key phrases that indicate function purpose
        lines = analysis_text.split('\n')
        summary_indicators = [
            'this function', 'the function', 'it appears to', 'appears to be',
            'responsible for', 'purpose is', 'main purpose', 'primary function',
            'function does', 'function is', 'seems to', 'likely', 'probably'
        ]
        
        best_summary = ""
        for line in lines:
            line = line.strip()
            if len(line) > 20 and len(line) < 200:  # Reasonable length
                line_lower = line.lower()
                if any(indicator in line_lower for indicator in summary_indicators):
                    # Clean up the line
                    if line.endswith('.'):
                        line = line[:-1]
                    # Remove common prefixes
                    for prefix in ['Based on the analysis, ', 'It appears that ', 'The function ']:
                        if line.startswith(prefix):
                            line = line[len(prefix):]
                    
                    if len(line) > len(best_summary) and len(line) < 150:
                        best_summary = line
        
        # Fallback: look for any descriptive sentence
        if not best_summary:
            for line in lines:
                line = line.strip()
                if (len(line) > 30 and len(line) < 150 and 
                    ('.' in line or ',' in line) and
                    not line.startswith('EXECUTE:') and
                    not line.startswith('Step ') and
                    'function' in line.lower()):
                    best_summary = line
                    break
        
        return best_summary[:150] if best_summary else "Analysis performed"

    def _update_analysis_state(self, command: Dict[str, Any], result: str) -> None:
        """
        Update the internal analysis state based on the executed command and result.
        
        Args:
            command: The executed command
            result: The result of the command
        """
        # Only update state if command was successful
        if "ERROR" in result or "Failed" in result:
            return
            
        # Track decompiled functions and capture summaries
        if command['name'] == "decompile_function" and "name" in command['params']:
            function_name = command['params']['name']
            # Don't add to functions_analyzed - decompilation is not the same as analysis
            # Only actual analysis commands should increment the analyzed count
            
            # Capture summary from the most recent AI response
            if hasattr(self, 'partial_outputs') and self.partial_outputs:
                for output in reversed(self.partial_outputs):
                    if output.get('type') in ['reasoning', 'review'] and output.get('content'):
                        self._capture_function_summary(function_name, output['content'])
                        break
            
        elif command['name'] == "decompile_function_by_address" and "address" in command['params']:
            address = command['params']['address']
            self.analysis_state['functions_decompiled'].add(address)
            # Don't add to functions_analyzed - decompilation is not the same as analysis
            # Only actual analysis commands should increment the analyzed count
            
        elif command['name'] == "analyze_function":
            # This is the actual analysis command that should increment the analyzed count
            address = command['params'].get('address')
            if address:
                # Only add to functions_analyzed if not already in functions_renamed
                # to avoid double-counting the same function
                if address not in self.analysis_state.get('functions_renamed', {}):
                    self.analysis_state['functions_analyzed'].add(address)
            else:
                # If no address provided, analyze_function uses current function
                # We'll add it when we capture the summary with the actual address
                pass
            
            # Capture summary from the most recent AI response
            if hasattr(self, 'partial_outputs') and self.partial_outputs:
                for output in reversed(self.partial_outputs):
                    if output.get('type') in ['reasoning', 'review'] and output.get('content'):
                        # Use address if provided, otherwise we'll need to extract it from the result
                        identifier = address if address else "current_function"
                        self._capture_function_summary(identifier, output['content'])
                        break
            
        # Track renamed functions
        elif command['name'] == "rename_function" and "old_name" in command['params'] and "new_name" in command['params']:
            old_name = command['params']['old_name']
            new_name = command['params']['new_name']
            self.logger.info(f"DEBUG: Processing rename_function command: {old_name} -> {new_name}")
            
            # Smart address extraction - try multiple methods to get the correct address
            address = None
            
            # Method 1: Extract address from old_name if it contains hex pattern
            import re
            address_match = re.search(r'([0-9a-fA-F]{8,})', old_name)
            if address_match:
                address = address_match.group(1)
                self.logger.info(f"DEBUG: Extracted address from old_name: {address}")
            
            # Method 2: If no address in old_name, try get_current_function (single function rename scenario)
            if not address:
                try:
                    current_function_result = self.ghidra.get_current_function()
                    if isinstance(current_function_result, str) and "at " in current_function_result:
                        # Extract address from result like "Function: FUN_00409bd4 at 00409bd4"
                        match = re.search(r'at\s+([0-9a-fA-F]+)', current_function_result)
                        if match:
                            address = match.group(1)
                            self.logger.info(f"DEBUG: Extracted address from current_function: {address}")
                except Exception as e:
                    self.logger.warning(f"DEBUG: Failed to get current function: {e}")
            
            # Method 3: If still no address, try to get it from decompiling the function by name
            if not address:
                try:
                    decompile_result = self.ghidra.decompile_function(old_name)
                    if isinstance(decompile_result, str):
                        addr_match = re.search(r'([0-9a-fA-F]{8,})', decompile_result)
                        if addr_match:
                            address = addr_match.group(1)
                            self.logger.info(f"DEBUG: Extracted address from decompile_function: {address}")
                except Exception as e:
                    self.logger.warning(f"DEBUG: Failed to decompile function {old_name}: {e}")
            
            # Store the function rename information
            if address:
                # Use the real address as the key
                self.analysis_state['functions_renamed'][address] = new_name
                self.function_address_mapping[address] = {'old_name': old_name, 'new_name': new_name}
                self.logger.info(f"DEBUG: Stored function mapping at address {address}: {old_name} -> {new_name}")
                
                # Capture summary from the most recent AI response for rename workflow
                self.logger.info(f"DEBUG: Checking partial_outputs for summary extraction, has partial_outputs: {hasattr(self, 'partial_outputs')}")
                if hasattr(self, 'partial_outputs'):
                    self.logger.info(f"DEBUG: partial_outputs length: {len(self.partial_outputs)}")
                    
                    for output in reversed(self.partial_outputs):
                        if output.get('type') in ['reasoning', 'review'] and output.get('content'):
                            self.logger.info(f"DEBUG: Found suitable partial_output for summary extraction")
                            self._capture_function_summary(address, output['content'])
                            break
                    else:
                        self.logger.warning(f"DEBUG: No suitable partial_outputs found for summary extraction")
                else:
                    self.logger.warning(f"DEBUG: No partial_outputs attribute found")
            else:
                # Fallback: no address found, use old_name as identifier
                self.analysis_state['functions_renamed'][old_name] = new_name
                fake_addr = f"name_{old_name}"
                self.function_address_mapping[fake_addr] = {'old_name': old_name, 'new_name': new_name}
                self.logger.info(f"DEBUG: No address found, using fallback storage with fake_addr: {fake_addr}")
            
            self.logger.info(f"DEBUG: Total functions in analysis_state: {len(self.analysis_state['functions_renamed'])}")
            self.logger.info(f"DEBUG: Total functions in address_mapping: {len(self.function_address_mapping)}")
            
        elif command['name'] == "rename_function_by_address" and "function_address" in command['params'] and "new_name" in command['params']:
            address = command['params']['function_address']
            new_name = command['params']['new_name']
            self.analysis_state['functions_renamed'][address] = new_name
            
            # Store complete function information
            self.function_address_mapping[address] = {'old_name': 'Unknown', 'new_name': new_name}
            
        # Track comments added
        elif command['name'] in ["set_decompiler_comment", "set_disassembly_comment"] and "address" in command['params'] and "comment" in command['params']:
            self.analysis_state['comments_added'][command['params']['address']] = command['params']['comment']
        
        # Clean up any duplicates between functions_analyzed and functions_renamed
        self._cleanup_duplicate_function_tracking()
    
    def _cleanup_duplicate_function_tracking(self) -> None:
        """
        Clean up duplicate function tracking between functions_analyzed and functions_renamed.
        If a function is in both sets, prefer functions_renamed as it has more complete data.
        """
        if not hasattr(self, 'analysis_state'):
            return
            
        functions_renamed = self.analysis_state.get('functions_renamed', {})
        functions_analyzed = self.analysis_state.get('functions_analyzed', set())
        
        # Remove any functions from functions_analyzed that are already in functions_renamed
        duplicates_to_remove = set()
        for analyzed_func in functions_analyzed:
            if analyzed_func in functions_renamed:
                duplicates_to_remove.add(analyzed_func)
        
        # Remove duplicates
        for duplicate in duplicates_to_remove:
            functions_analyzed.discard(duplicate)
            self.logger.debug(f"Removed duplicate function tracking: {duplicate} (kept in functions_renamed)")
    
    def _check_for_clarification_request(self, response: str) -> bool:
        """
        Check if the AI's response is a request for clarification from the user.
        
        Args:
            response: The AI's response text
            
        Returns:
            True if the response is a clarification request, False otherwise
        """
        # Simple heuristic: look for question marks near the end of the response
        # and check if the response doesn't contain any tool calls
        if "EXECUTE:" not in response and "?" in response:
            last_paragraph = response.split("\n\n")[-1].strip()
            # If the last paragraph ends with a question mark, it's likely a clarification request
            if last_paragraph.endswith("?"):
                # Additional check: make sure it's not just showing code examples with question marks
                if not ("`" in last_paragraph or "```" in last_paragraph):
                    return True
        return False
        
    def _extract_suggestions(self, response: str) -> Tuple[str, List[str]]:
        """
        Extract tool improvement suggestions from the AI's response.
        
        Args:
            response: The AI's response text
            
        Returns:
            Tuple of (cleaned_response, list_of_suggestions)
        """
        suggestions = []
        cleaned_lines = []
        
        # Simple parsing: look for lines starting with "SUGGESTION:"
        for line in response.split("\n"):
            if line.strip().startswith("SUGGESTION:"):
                suggestion = line.strip()[len("SUGGESTION:"):].strip()
                suggestions.append(suggestion)
            else:
                cleaned_lines.append(line)
                
        # If suggestions were found, log them
        if suggestions:
            self.logger.info(f"Found {len(suggestions)} tool improvement suggestions")
            for suggestion in suggestions:
                self.logger.info(f"Tool suggestion: {suggestion}")
                
        return "\n".join(cleaned_lines), suggestions

    def _generate_cohesive_report(self) -> str:
        """
        Generate a cohesive report from various data gathered during the analysis.
        
        Returns:
            A comprehensive report as a string
        """
        if not self.partial_outputs:
            return "No analysis was performed or captured."
            
        # Organize our partial outputs into sections for the report
        report_sections = {
            "plan": [],              # Added section for the initial plan
            "findings": [],
            "insights": [],
            "analysis": [],
            "tools": [],
            "errors": [],            # Added section for errors
            "conclusions": []
        }
        
        # First, process the raw responses to capture information that might be truncated in cleaned responses
        raw_responses = []
        for output in self.partial_outputs:
            if output["type"] in ["raw_response", "raw_review"]:
                raw_responses.append(output["content"])
        
        # Process partial outputs to populate sections
        for output in self.partial_outputs:
            content = output.get("content", "")
            output_type = output.get("type", "")
            
            # --- Capture Initial Plan ---
            if output_type == "planning":
                report_sections["plan"].append(content)
                continue # Skip further processing for plan content
                
            # --- Process Reasoning (Cleaned & Raw) ---
            if output_type in ["reasoning", "review"]:
                # Use the cleaned reasoning/review content for keyword/structure matching
                
                # Extract numbered insights
                numbered_insights = []
                in_numbered_list = False
                current_insight = ""
                for line in content.split('\n'):
                    if re.match(r'^\s*\d+\.\s', line):
                        if in_numbered_list and current_insight.strip(): numbered_insights.append(current_insight.strip())
                        in_numbered_list = True
                        current_insight = line.strip()
                    elif in_numbered_list and line.strip(): current_insight += " " + line.strip()
                    elif in_numbered_list: # End of item
                        if current_insight.strip(): numbered_insights.append(current_insight.strip())
                        in_numbered_list = False
                        current_insight = ""
                if in_numbered_list and current_insight.strip(): numbered_insights.append(current_insight.strip())
                if numbered_insights: report_sections["insights"].extend(numbered_insights)
                
                # Extract bulleted findings
                findings_section = False
                for line in content.split('\n'):
                    if any(marker in line.lower() for marker in ["i found:", "findings:", "key observations:", "key finding"]):
                        findings_section = True
                    elif findings_section and not line.strip(): findings_section = False
                    if findings_section or line.strip().startswith('- ') or line.strip().startswith('* '):
                        if line.strip(): report_sections["findings"].append(line.strip())
                        
                # Extract conclusions
                if any(marker in content.lower() for marker in ["in conclusion", "to summarize", "in summary", "conclusion:", "final analysis"]):
                    conclusion_text = ""
                    in_conclusion = False
                    for line in content.split('\n'):
                        if any(marker in line.lower() for marker in ["in conclusion", "to summarize", "in summary", "conclusion:", "final analysis"]):
                            in_conclusion = True
                        if in_conclusion and line.strip(): conclusion_text += line + "\n"
                    if conclusion_text: report_sections["conclusions"].append(conclusion_text.strip())
                
                # Extract general analysis (exclude already captured parts)
                analysis_content = content
                for category in ["findings", "insights", "conclusions"]:
                    for item in report_sections[category]:
                        analysis_content = analysis_content.replace(item, "")
                if analysis_content.strip():
                    # Only add if it contains relevant technical terms
                    if any(term in analysis_content.lower() for term in ["function", "address", "import", "export", "binary", "assembly", "code", "decompile", "call", "pointer", "struct"]):
                        report_sections["analysis"].append(analysis_content.strip())
        
        # --- Process Raw Responses for Additional Detail (before EXECUTE) ---
        for raw_response in raw_responses:
            # Extract text before the first EXECUTE block
            pre_execute_text = raw_response.split("EXECUTE:", 1)[0].strip()
            if not pre_execute_text:
                continue
            
            # Extract numbered insights from raw text
            numbered_insights_raw = []
            in_numbered_list_raw = False
            current_insight_raw = ""
            for line in pre_execute_text.split('\n'):
                if re.match(r'^\s*\d+\.\s', line):
                    if in_numbered_list_raw and current_insight_raw.strip(): numbered_insights_raw.append(current_insight_raw.strip())
                    in_numbered_list_raw = True
                    current_insight_raw = line.strip()
                elif in_numbered_list_raw and line.strip(): current_insight_raw += " " + line.strip()
                elif in_numbered_list_raw:
                    if current_insight_raw.strip(): numbered_insights_raw.append(current_insight_raw.strip())
                    in_numbered_list_raw = False
                    current_insight_raw = ""
            if in_numbered_list_raw and current_insight_raw.strip(): numbered_insights_raw.append(current_insight_raw.strip())
            if numbered_insights_raw: report_sections["insights"].extend(numbered_insights_raw)
            
            # Extract bulleted findings from raw text
            for line in pre_execute_text.split('\n'):
                 if (line.strip().startswith('- ') or line.strip().startswith('* ')):
                     if line.strip(): report_sections["findings"].append(line.strip())
                     
            # Extract general analysis from raw text (exclude already captured parts)
            analysis_content_raw = pre_execute_text
            for category in ["findings", "insights"]:
                for item in report_sections[category]:
                    analysis_content_raw = analysis_content_raw.replace(item, "")
            if analysis_content_raw.strip():
                 if any(term in analysis_content_raw.lower() for term in ["function", "address", "import", "export", "binary", "assembly", "code", "decompile", "call", "pointer", "struct"]):
                     report_sections["analysis"].append(analysis_content_raw.strip())
        
        # --- Process Tool Results & Errors ---
        tool_results = []
        for output in self.partial_outputs:
            if output["type"] in ["tool_result", "review_tool_result"]:
                result_text = output.get("result", "")
                step_info = f"Step {output.get('step', output.get('review_step', '?'))}"
                tool_info = f"{output.get('tool', 'unknown')}({', '.join([f'{k}={v}' for k, v in output.get('params', {}).items()])})"
                
                # Check for errors
                if "ERROR:" in result_text or "Failed" in result_text:
                    report_sections["errors"].append(f"{step_info}: {tool_info} -> {result_text}")
                else:
                    # Successful result - summarize and add to tools list
                    result_lines = result_text.split('\n')
                    # Remove the RESULT: prefix if present
                    result_content = '\n'.join([l.replace("RESULT: ", "", 1) for l in result_lines if l.strip()])
                    result_summary = result_content[:150] + ("..." if len(result_content) > 150 else "")
                    tool_results.append(f"{step_info}: {tool_info} -> {result_summary}")
        
        report_sections["tools"] = tool_results
        
        # --- Deduplicate Sections --- 
        for section in report_sections:
            if isinstance(report_sections[section], list):
                seen = set()
                # Keep order, filter duplicates (case-insensitive for strings)
                report_sections[section] = [x for x in report_sections[section] if not ( (x.lower() if isinstance(x, str) else x) in seen or seen.add( (x.lower() if isinstance(x, str) else x) ) )]
        
        # Option 1: Build a structured report manually
        report = self._build_structured_report(report_sections)
        
        # Return the manually structured report
        return report
        
    def _build_structured_report(self, report_sections):
        """
        Build a structured report from the collected sections.
        
        Args:
            report_sections: Dict of report sections
            
        Returns:
            A formatted report string
        """
        report = "# Analysis Report\n\n"
        
        if report_sections["plan"]:
            report += "## Initial Plan\n"
            report += "\n".join(report_sections["plan"]) + "\n\n"
        
        if report_sections["insights"]:
            report += "## Key Insights\n"
            report += "\n".join(report_sections["insights"]) + "\n\n"
        
        if report_sections["findings"]:
            report += "## Findings\n"
            report += "\n".join(report_sections["findings"]) + "\n\n"
        
        if report_sections["analysis"]:
            report += "## Analysis Details\n"
            report += "\n\n".join(report_sections["analysis"]) + "\n\n"
        
        if report_sections["tools"]:
            report += "## Tools Used (Successful)\n"
            report += "\n".join([f"- {tool}" for tool in report_sections["tools"]]) + "\n\n"
            
        if report_sections["errors"]:
            report += "## Errors Encountered\n"
            report += "\n".join([f"- {error}" for error in report_sections["errors"]]) + "\n\n"
        
        if report_sections["conclusions"]:
            report += "## Conclusions\n"
            report += "\n".join(report_sections["conclusions"]) + "\n"
        
        return report.strip()
    
    def _parse_plan_tools(self, plan: str) -> List[Dict[str, Any]]:
        """Parses the PLAN section from the AI's response."""
        tools = []
        # Regex to find all TOOL: lines
        tool_lines = re.findall(r"TOOL:\s*(.*)", plan)
        
        for line in tool_lines:
            try:
                # Split the line into the tool name and its parameters part
                parts = line.split(" PARAMS: ", 1)
                command_name = parts[0].strip()
                params_str = parts[1].strip() if len(parts) > 1 else ""

                params = {}
                if params_str:
                    # Use a more robust regex to parse key-value pairs
                    # This handles quoted strings and unquoted numbers
                    param_pairs = re.findall(r'(\w+)\s*=\s*(".*?"|\S+)', params_str)
                    for key, value in param_pairs:
                        # Strip quotes from string values
                        if value.startswith('"') and value.endswith('"'):
                            params[key] = value[1:-1]
                        else:
                            # Attempt to convert to int/float, otherwise keep as string
                            try:
                                if '.' in value:
                                    params[key] = float(value)
                                else:
                                    params[key] = int(value)
                            except ValueError:
                                params[key] = value
                
                tools.append({'tool': command_name, 'params': params})

            except Exception as e:
                self.logger.error(f"Error parsing tool line '{line}': {e}")

        self.logger.info(f"Extracted {len(tools)} planned tools from plan")
        return tools

    def _mark_tool_as_executed(self, command_name: str, params: Dict[str, Any]) -> None:
        """
        Mark a tool as executed in the planned tools tracker.
        
        Args:
            command_name: The name of the executed command
            params: The parameters used for the command
        """
        for tool_entry in self.planned_tools_tracker['planned']:
            if tool_entry['tool'] == command_name:
                tool_entry['execution_status'] = 'executed'
                break

    def _get_pending_critical_tools_prompt(self) -> str:
        """
        Generate a prompt section about pending critical tools.
        
        Returns:
            A string to be included in the review prompt if there are pending critical tools
        """
        # Update the pending_critical list based on current execution status
        self.planned_tools_tracker['pending_critical'] = [
            tool for tool in self.planned_tools_tracker['planned'] 
            if tool['is_critical'] and tool['execution_status'] == 'pending'
        ]
        
        if not self.planned_tools_tracker['pending_critical']:
            return ""
            
        # Generate the prompt
        pending_tools_prompt = "\n\nThere are pending critical tool calls that appear necessary but have not been executed:\n"
        
        for tool in self.planned_tools_tracker['pending_critical']:
            pending_tools_prompt += f"- {tool['tool']}: Mentioned in context \"{tool['context']}\"\n"
            
        pending_tools_prompt += "\nPlease ensure these critical tool calls are explicitly executed before concluding the task."
        
        return pending_tools_prompt

    def _check_implied_actions_without_commands(self, response_text: str) -> str:
        """
        Check if the response text implies actions that should be taken but doesn't include 
        the actual EXECUTE commands to perform those actions.
        
        Args:
            response_text: The AI's response text
            
        Returns:
            A prompt string asking for explicit commands if needed, otherwise empty string
        """
        # Skip if there are already commands in the response
        if "EXECUTE:" in response_text:
            return ""
            
        # Check if this is a review prompt we generated - if so, don't re-analyze it
        if "Your response implies certain actions should be taken" in response_text:
            return ""
            
        # Patterns that indicate implied actions without explicit commands
        implied_action_patterns = [
            (r"(should|will|going to|let's) rename", "rename_function"),
            (r"(should|will|going to|let's) add comment", "set_decompiler_comment"),
            (r"(suggest|proposed|recommend) (naming|naming it|renaming)", "rename_function"),
            (r"(suggest|proposed|recommend) (to|that) name", "rename_function"),
            (r"(appropriate|suitable|better|good|descriptive) name would be", "rename_function"),
            (r"function (should|could|would) be (named|called)", "rename_function"),
            (r"rename (the|this) function (to|as)", "rename_function"),
            (r"naming it ['\"]([\w_]+)['\"]", "rename_function")
        ]
        
        response_lower = response_text.lower()
        
        # Check for implied actions
        implied_actions = []
        for pattern, related_tool in implied_action_patterns:
            if re.search(pattern, response_lower):
                implied_actions.append((pattern, related_tool))
                
        if not implied_actions:
            return ""
            
        # Generate a prompt asking for explicit commands
        action_prompt = "\n\nYour response implies certain actions should be taken, but you didn't include explicit EXECUTE commands:\n"
        
        for pattern, tool in implied_actions:
            matches = re.findall(pattern, response_lower)
            if matches:
                action_prompt += f"- You mentioned: '{pattern.replace('|', ' or ')}'\n"
                
        action_prompt += "\nPlease provide explicit EXECUTE commands to perform these actions."
        return action_prompt

    def add_to_context(self, role: str, content: str) -> None:
        """
        Add an entry to the context history.
        
        This method now uses the Pydantic SessionMemory for structured storage
        while maintaining backward compatibility with the legacy context list.
        
        Args:
            role: The role of the entry ('user', 'assistant', 'tool_call', 'tool_result', etc.)
            content: The content of the entry
        """
        # Add to new Pydantic session (primary storage)
        try:
            message_role = MessageRole(role.lower())
            self.session.add_message(message_role, content)
        except ValueError:
            # If role is not in MessageRole enum, default to SYSTEM
            self.logger.warning(f"Unknown role '{role}', defaulting to SYSTEM")
            self.session.add_message(MessageRole.SYSTEM, content)
        
        # Maintain legacy context for backward compatibility
        if isinstance(self.context, list):
            self.context.append({"role": role, "content": content})
        elif isinstance(self.context, dict):
            if not 'history' in self.context:
                self.context['history'] = []
            self.context['history'].append({"role": role, "content": content})
        else:
            # Create a new list if neither
            self.context = [{"role": role, "content": content}]

    @property
    def ghidra(self):
        """Property for backward compatibility with code referencing bridge.ghidra."""
        return self.ghidra_client

    def execute_goal(self, goal: str) -> Tuple[bool, List[str]]:
        """
        Execute a goal by breaking it down into steps and executing each step.
        
        Args:
            goal: The goal to execute
            
        Returns:
            Tuple of (success, results)
        """
        logging.info(f"Executing goal: {goal}")
        self.context["goal"] = goal
        self.current_goal = goal
        self.executed_tools = set()  # Reset tool tracking for new goal
        self.step_result_map = {}  # Reset step result map for new goal
        all_results = []
        step_count = 0
        self.goal_achieved = False

        # Use CAG manager to enhance context with knowledge and session data
        if self.enable_cag and self.cag_manager:
            # Update session cache with current context
            self.cag_manager.update_session_from_bridge_context(self.context)
        
        logging.info("Starting planning phase")
        planning_prompt = self._build_planning_prompt(goal)
        planning_response = self.chat_engine.query(planning_prompt)
        logging.info(f"Received planning response: {planning_response[:100]}...")
        
        # Extract tools from the plan
        planned_tools = self._extract_planned_tools(planning_response)
        logging.info(f"Extracted {len(planned_tools)} planned tools from plan")
        
        # Add the plan to context
        self.add_to_context("plan", planning_response)
        
        logging.info("Planning phase completed")
        logging.info("Starting execution phase")
        
        while step_count < self.max_goal_steps and not self.goal_achieved:
            step_count += 1
            logging.info(f"Step {step_count}/{self.max_goal_steps}: Sending query to Ollama")
            
            # Generate prompt based on current context
            prompt = self._build_execution_prompt()
            
            # Get response from Ollama
            response = self.chat_engine.query(prompt)
            logging.info(f"Received response from Ollama: {response[:100]}...")
            
            # Update context with the response
            self.add_to_context("execution_response", response)
            
            # Process commands in the response
            commands = self.command_parser.extract_commands(response)
            
            if self._is_goal_achieved(response):
                logging.info("Goal achievement indicated in response")
                self.goal_achieved = True
                all_results.append(f"Step {step_count} - Goal achievement indicated: {response}")
                break
                
            # Execute commands
            execution_result = ""
            for cmd_name, cmd_params in commands:
                try:
                    # Add tool call to context
                    tool_call = f"EXECUTE: {cmd_name}({', '.join([f'{k}=\"{v}\"' for k, v in cmd_params.items()])})"
                    self.add_to_context("tool_call", tool_call)
                    
                    # Track executed tools with full signature for duplicate detection
                    param_sig = str(sorted(cmd_params.items())) if cmd_params else ""
                    cmd_signature = f"{cmd_name}:{param_sig}"
                    
                    # Skip if already executed with same params
                    if cmd_signature in self.executed_tools:
                        self.logger.warning(f"Skipping duplicate: {cmd_name}")
                        continue
                    
                    self.executed_tools.add(cmd_signature)
                    
                    # Execute command
                    result = self.execute_command(cmd_name, cmd_params)
                    
                    # Format result for display
                    formatted_result = self.command_parser.format_command_results(cmd_name, cmd_params, result)
                    logging.info(f"Command executed: {cmd_name}")
                    logging.info(f"Result: {formatted_result[:100]}...")
                    
                    # Add result to context
                    self.add_to_context("tool_result", formatted_result)
                    
                    # Cache signature for duplicate detection intelligence
                    sig = f"{cmd_name}({_canonical_params(cmd_name, cmd_params)})"
                    self.analysis_state['cached_results'][sig] = True
                    
                    # Special logic to re-orient the agent after analysis
                    if cmd_name == "analyze_function":
                        # This prompt is a direct instruction, framed as a user follow-up, to force the next action.
                        reminder_prompt = f"""
                        Excellent, the analysis is complete. Now, using that analysis, complete the original task: '{self.current_goal}'.
                        Your final step is to call the `rename_function` tool.
                        - Find the CURRENT function name from the most recent `get_current_function` output in the history.
                        - Create a descriptive new name based on the analysis you just performed.
                        - Then, call the `rename_function` tool with the CURRENT function's old and new names.
                        - IMPORTANT: Only rename the function that is currently selected in Ghidra, not any other function.
                        """
                        self.add_to_context("user", reminder_prompt) # Use "user" role for higher salience
                        self.logger.info("Injecting user follow-up prompt to refocus agent on the final rename step.")
                    
                    # Check for context mismatches in rename operations
                    if cmd_name == "rename_function" and "old_name" in cmd_params:
                        old_name = cmd_params["old_name"]
                        # Check if this rename operation might be working on the wrong function
                        if "✓ Successfully executed" in execution_result and old_name.startswith("FUN_"):
                            context_check_prompt = f"""
                            ATTENTION: You just renamed '{old_name}' successfully, but please verify this is the correct function.
                            
                            If your goal is to rename the CURRENT function (the one selected in Ghidra), you should:
                            1. Use `get_current_function()` to confirm which function is currently selected
                            2. Only rename that specific function
                            
                            If you've already completed the task successfully, respond with "GOAL ACHIEVED".
                            """
                            self.add_to_context("system", context_check_prompt)
                    
                    execution_result = formatted_result
                    all_results.append(f"Command: {cmd_name}\nResult: {execution_result}\n")
                
                except Exception as e:
                    error_msg = f"ERROR: {str(e)}"
                    logging.error(f"Error executing {cmd_name}: {error_msg}")
                    execution_result = error_msg
                    self.add_to_context("tool_error", error_msg)
                    all_results.append(f"Error executing {cmd_name}: {error_msg}")
            
            # If no commands found, end the execution phase
            if not commands:
                logging.info("No commands found in AI response, ending tool execution loop")
                all_results.append(f"Step {step_count} - No tool calls: {response}")
                break
        
        if step_count >= self.max_goal_steps:
            logging.info(f"Reached maximum steps ({self.max_goal_steps}), ending tool execution loop")
            all_results.append(f"Reached maximum steps ({self.max_goal_steps})")
            
        logging.info("Execution phase completed")
        
        # Only do review if requested
        if self.enable_review:
            all_results.append("\n=== REVIEW PHASE ===\n")
            all_results.extend(self._perform_review_phase())
            
        return self.goal_achieved, all_results

    def _is_goal_achieved(self, response: str) -> bool:
        """
        Check if the response indicates that the goal has been achieved.
        
        Args:
            response: The AI response to check
            
        Returns:
            True if the goal is achieved, False otherwise
        """
        response_upper = response.upper()
        goal_indicators = [
            "GOAL ACHIEVED",
            "GOAL COMPLETE",
            "TASK COMPLETED",
            "SUCCESSFULLY COMPLETED",
            "OBJECTIVE ACCOMPLISHED"
        ]
        
        return any(indicator in response_upper for indicator in goal_indicators)

    def _build_execution_prompt(self) -> str:
        """
        Build a prompt for the execution phase.
        
        Returns:
            The prompt string
        """
        # Include context, goal, and any previous interactions
        system_prompt, user_prompt = self._build_structured_prompt(phase="execution") 
        
        # Add function call best practices to system prompt
        if hasattr(config, 'FUNCTION_CALL_BEST_PRACTICES') and config.FUNCTION_CALL_BEST_PRACTICES:
            system_prompt += f"\n\nFunction call best practices:\n{config.FUNCTION_CALL_BEST_PRACTICES}\n"
            
        # Return both prompts as a tuple
        return (system_prompt, user_prompt)

    def _build_planning_prompt(self, goal: str) -> str:
        """
        Build a prompt for the planning phase.
        
        Args:
            goal: The goal to plan for
            
        Returns:
            The prompt string
        """
        # Get system and user prompts
        system_prompt, user_prompt = self._build_structured_prompt(phase="planning")
        user_prompt += f"\n\nGoal: {goal}\n"
        
        # Add function call best practices to system prompt
        if hasattr(config, 'FUNCTION_CALL_BEST_PRACTICES') and config.FUNCTION_CALL_BEST_PRACTICES:
            system_prompt += f"\n\nFunction call best practices:\n{config.FUNCTION_CALL_BEST_PRACTICES}\n"
            
        # Return both prompts as a tuple
        return (system_prompt, user_prompt)
        
    def _build_review_prompt(self) -> str:
        """
        Build a prompt for the review phase.
        
        Returns:
            The prompt string
        """
        system_prompt, user_prompt = self._build_structured_prompt(phase="review")
        
        # Add function call best practices to system prompt
        if hasattr(config, 'FUNCTION_CALL_BEST_PRACTICES') and config.FUNCTION_CALL_BEST_PRACTICES:
            system_prompt += f"\n\nFunction call best practices:\n{config.FUNCTION_CALL_BEST_PRACTICES}\n"
            
        # Return both prompts as a tuple
        return (system_prompt, user_prompt)

    def _run_hardcoded_rename_workflow(self, display_name: str):
        # Instead of: ai_response = self.bridge.process_query(analysis_query)
        # Do direct calls:
        
        # 1. Get current function (already done)
        # 2. Decompile ONCE
        decompiled_code = self.bridge.execute_command("decompile_function", {"name": function_name})
        
        # 3. Create analysis prompt with the decompiled code
        analysis_prompt = f"Analyze this decompiled function and suggest a name:\n{decompiled_code}"
        
        # 4. Use Ollama directly (no multi-phase workflow)
        ai_response = self.bridge.ollama.generate(analysis_prompt)
        
        # 5. Extract name and rename

    def generate_software_report(self, report_format: str = "markdown") -> str:
        """
        Generate a comprehensive software analysis report using AI-powered analysis.
        
        This method performs complete software behavior analysis including:
        - Software type classification and architecture analysis
        - Security risk assessment with detailed scoring
        - Function categorization and behavioral pattern analysis
        - Comprehensive findings summary with actionable insights
        
        Args:
            report_format: Output format ("markdown", "text", "json")
            
        Returns:
            Comprehensive software analysis report string
        """
        try:
            self.logger.info("Starting comprehensive software report generation")
            
            # Set workflow stage for UI integration
            self.current_workflow_stage = 'planning'
            
            # Phase 1: Data Collection - Gather all available binary information
            self.logger.info("Phase 1: Collecting binary data...")
            report_data = self._collect_comprehensive_binary_data()
            
            # Phase 2: AI Analysis - Analyze collected data with specialized prompts
            self.current_workflow_stage = 'analysis'
            self.logger.info("Phase 2: Performing AI-powered analysis...")
            analysis_results = self._perform_comprehensive_ai_analysis(report_data)
            
            # Phase 3: Report Generation - Structure and format the final report
            self.current_workflow_stage = 'review'
            self.logger.info("Phase 3: Generating structured report...")
            final_report = self._generate_structured_software_report(report_data, analysis_results, report_format)
            
            # Clear workflow stage
            self.current_workflow_stage = None
            
            self.logger.info("Software report generation completed successfully")
            return final_report
            
        except Exception as e:
            self.logger.error(f"Error generating software report: {e}")
            self.current_workflow_stage = None
            return f"Error generating software report: {e}"
    
    def _collect_comprehensive_binary_data(self) -> Dict[str, Any]:
        """Collect all available binary data for analysis."""
        data = {
            'functions': [],
            'renamed_functions': [],
            'function_summaries': {},
            'function_addresses': {},  # Map function names to addresses
            'imports': [],
            'exports': [],
            'strings': [],
            'segments': [],
            'classes': [],
            'namespaces': [],
            'data_items': [],
            'analysis_state': self.analysis_state.copy(),
            'metadata': {
                'total_functions': 0,
                'renamed_count': 0,
                'analyzed_count': 0
            }
        }
        
        try:
            # Collect function information
            functions_result = self.ghidra.list_functions()
            if isinstance(functions_result, list):
                data['functions'] = functions_result
            elif isinstance(functions_result, str) and not functions_result.startswith("ERROR:"):
                data['functions'] = [f.strip() for f in functions_result.split('\n') if f.strip()]
            
            # Parse function addresses from function names
            # Format is typically "address functionName" or just "functionName"
            import re
            for func in data['functions']:
                # Try to extract address and name
                match = re.match(r'^(0x[0-9a-fA-F]+)\s+(.+)$', func)
                if match:
                    addr, name = match.groups()
                    data['function_addresses'][name] = addr
                    data['function_addresses'][func] = addr  # Also store by full string
                else:
                    # Try alternate formats: just address, or name@address
                    addr_match = re.search(r'(0x[0-9a-fA-F]+)', func)
                    if addr_match:
                        data['function_addresses'][func] = addr_match.group(1)
            
            data['metadata']['total_functions'] = len(data['functions'])
            
            # Collect renamed functions from analysis state
            data['renamed_functions'] = list(self.analysis_state['functions_renamed'].items())
            data['metadata']['renamed_count'] = len(data['renamed_functions'])
            
            # Collect function summaries
            data['function_summaries'] = self.function_summaries.copy()
            data['metadata']['analyzed_count'] = len(data['function_summaries'])
            
            # Collect imports
            imports_result = self.ghidra.list_imports()
            if isinstance(imports_result, (list, str)) and not str(imports_result).startswith("ERROR:"):
                if isinstance(imports_result, str):
                    data['imports'] = [i.strip() for i in imports_result.split('\n') if i.strip()]
                else:
                    data['imports'] = imports_result
            
            # Collect exports
            exports_result = self.ghidra.list_exports()
            if isinstance(exports_result, (list, str)) and not str(exports_result).startswith("ERROR:"):
                if isinstance(exports_result, str):
                    data['exports'] = [e.strip() for e in exports_result.split('\n') if e.strip()]
                else:
                    data['exports'] = exports_result
            
            # Collect memory segments
            segments_result = self.ghidra.list_segments()
            if isinstance(segments_result, (list, str)) and not str(segments_result).startswith("ERROR:"):
                if isinstance(segments_result, str):
                    data['segments'] = [s.strip() for s in segments_result.split('\n') if s.strip()]
                else:
                    data['segments'] = segments_result
            
            # Collect classes/namespaces
            classes_result = self.ghidra.list_classes()
            if isinstance(classes_result, (list, str)) and not str(classes_result).startswith("ERROR:"):
                if isinstance(classes_result, str):
                    data['classes'] = [c.strip() for c in classes_result.split('\n') if c.strip()]
                else:
                    data['classes'] = classes_result
            
            namespaces_result = self.ghidra.list_namespaces()
            if isinstance(namespaces_result, (list, str)) and not str(namespaces_result).startswith("ERROR:"):
                if isinstance(namespaces_result, str):
                    data['namespaces'] = [n.strip() for n in namespaces_result.split('\n') if n.strip()]
                else:
                    data['namespaces'] = namespaces_result
            
            # Collect data items
            data_items_result = self.ghidra.list_data_items()
            if isinstance(data_items_result, (list, str)) and not str(data_items_result).startswith("ERROR:"):
                if isinstance(data_items_result, str):
                    data['data_items'] = [d.strip() for d in data_items_result.split('\n') if d.strip()]
                else:
                    data['data_items'] = data_items_result
            
            # Collect strings with addresses for evidence
            try:
                strings_result = self.ghidra.list_strings(limit=500)  # Get top 500 strings
                if isinstance(strings_result, list):
                    data['strings'] = strings_result  # JSON format likely includes addresses
                elif isinstance(strings_result, str) and not strings_result.startswith("ERROR:"):
                    data['strings'] = [s.strip() for s in strings_result.split('\n') if s.strip()]
            except Exception as string_err:
                self.logger.debug(f"Error collecting strings: {string_err}")
            
        except Exception as e:
            self.logger.warning(f"Error collecting some binary data: {e}")
        
        return data
    
    def _perform_comprehensive_ai_analysis(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Perform AI-powered analysis of collected binary data."""
        analysis = {
            'software_classification': {},
            'security_assessment': {},
            'function_categorization': {},
            'behavioral_analysis': {},
            'architecture_analysis': {},
            'risk_assessment': {}
        }
        
        try:
            # Software Classification Analysis
            classification_prompt = self._build_classification_prompt(data)
            classification_response = self.ollama.generate(prompt=classification_prompt)
            analysis['software_classification'] = self._parse_classification_response(classification_response)
            
            # Security Assessment Analysis
            security_prompt = self._build_security_assessment_prompt(data)
            security_response = self.ollama.generate(prompt=security_prompt)
            analysis['security_assessment'] = self._parse_security_response(security_response)
            
            # Function Categorization Analysis
            function_prompt = self._build_function_categorization_prompt(data)
            function_response = self.ollama.generate(prompt=function_prompt)
            analysis['function_categorization'] = self._parse_function_response(function_response)
            
            # Behavioral Pattern Analysis
            behavior_prompt = self._build_behavioral_analysis_prompt(data)
            behavior_response = self.ollama.generate(prompt=behavior_prompt)
            analysis['behavioral_analysis'] = self._parse_behavioral_response(behavior_response)
            
            # Architecture Analysis
            architecture_prompt = self._build_architecture_prompt(data)
            architecture_response = self.ollama.generate(prompt=architecture_prompt)
            analysis['architecture_analysis'] = self._parse_architecture_response(architecture_response)
            
            # Overall Risk Assessment
            risk_prompt = self._build_risk_assessment_prompt(data, analysis)
            risk_response = self.ollama.generate(prompt=risk_prompt)
            analysis['risk_assessment'] = self._parse_risk_response(risk_response)
            
        except Exception as e:
            self.logger.error(f"Error during AI analysis: {e}")
            # Return partial analysis with error noted
            analysis['error'] = str(e)
        
        return analysis
    
    def _build_classification_prompt(self, data: Dict[str, Any]) -> str:
        """Build prompt for software classification analysis."""
        return f"""Analyze this binary and classify the software type and purpose.

**Binary Information:**
- Total Functions: {data['metadata']['total_functions']}
- Renamed Functions: {data['metadata']['renamed_count']}
- Analyzed Functions: {data['metadata']['analyzed_count']}
- Imports: {len(data['imports'])} ({', '.join(data['imports'][:10])}{'...' if len(data['imports']) > 10 else ''})
- Exports: {len(data['exports'])} ({', '.join(data['exports'][:10])}{'...' if len(data['exports']) > 10 else ''})
- Memory Segments: {len(data['segments'])}
- Classes/Namespaces: {len(data['classes']) + len(data['namespaces'])}

**Function Summaries:**
{self._format_summaries_for_prompt(data['function_summaries'])}

**Analysis Requirements:**
Provide a structured classification following this EXACT format:

**SOFTWARE_TYPE:** [Select ONE: Application, Library, Driver, Malware, System_Tool, Game, Utility, Service, Other]
**PRIMARY_PURPOSE:** [Brief description of main functionality]
**SECONDARY_FUNCTIONS:** [List of additional capabilities]
**TARGET_PLATFORM:** [Windows/Linux/macOS/Cross-platform/Embedded]
**ARCHITECTURE_STYLE:** [Monolithic/Modular/Service-oriented/Plugin-based/Other]
**COMPLEXITY_LEVEL:** [Low/Medium/High/Very_High]
**CLASSIFICATION_CONFIDENCE:** [0-100%]
**EVIDENCE:** [Key evidence supporting this classification - MUST include specific function addresses, function names, and string examples. Format: "Function at address 0x... named '...' does X", "String 'Y' found at Z"]"""

    def _build_security_assessment_prompt(self, data: Dict[str, Any]) -> str:
        """Build prompt for security risk assessment."""
        return f"""Perform a comprehensive security assessment of this binary.

**Binary Data for Analysis:**
- Functions: {data['metadata']['total_functions']} total, {data['metadata']['renamed_count']} renamed
- Key Imports: {', '.join(data['imports'][:15])}{'...' if len(data['imports']) > 15 else ''}
- Function Summaries: {len(data['function_summaries'])} available

**Renamed Functions and Behaviors:**
{self._format_function_behaviors_for_security(data)}

**Security Analysis Requirements:**
Analyze for security risks and provide assessment in this EXACT format:

**IMPORTANT:** For EACH suspicious indicator, security concern, or finding, you MUST provide:
1. The specific function address (e.g., 0x401000)
2. The function name
3. Actual string values, API calls, or code patterns found
4. Concrete examples from the binary

**OVERALL_RISK_LEVEL:** [CRITICAL/HIGH/MEDIUM/LOW]
**RISK_SCORE:** [0-100]
**SECURITY_CATEGORIES:**
- Network_Operations: [NONE/LOW/MEDIUM/HIGH/CRITICAL] - [description with specific addresses and functions]
- File_System_Access: [NONE/LOW/MEDIUM/HIGH/CRITICAL] - [description with specific addresses and functions]
- Registry_Manipulation: [NONE/LOW/MEDIUM/HIGH/CRITICAL] - [description with specific addresses and functions]
- Process_Manipulation: [NONE/LOW/MEDIUM/HIGH/CRITICAL] - [description with specific addresses and functions]
- Cryptographic_Operations: [NONE/LOW/MEDIUM/HIGH/CRITICAL] - [description with specific addresses and functions]
- Memory_Management: [NONE/LOW/MEDIUM/HIGH/CRITICAL] - [description with specific addresses and functions]
- Persistence_Mechanisms: [NONE/LOW/MEDIUM/HIGH/CRITICAL] - [description with specific addresses and functions]
**SUSPICIOUS_INDICATORS:** [List EACH concerning behavior with format: "Description at address 0x... in function '...' - Evidence: specific API/string/pattern"]
**MITIGATION_RECOMMENDATIONS:** [Security recommendations]
**IOCS:** [Potential Indicators of Compromise with specific addresses and strings found]"""

    def _build_function_categorization_prompt(self, data: Dict[str, Any]) -> str:
        """Build prompt for function categorization analysis."""
        return f"""Categorize all functions in this binary by their primary purpose and behavior.

**Available Function Data:**
- Total Functions: {data['metadata']['total_functions']}
- Renamed Functions with Summaries: {data['metadata']['analyzed_count']}
- Sample Functions: {', '.join(data['functions'][:10])}{'...' if len(data['functions']) > 10 else ''}

**Function Summaries for Categorization:**
{self._format_summaries_for_categorization(data['function_summaries'])}

**Renamed Functions:**
{self._format_renamed_functions(data['renamed_functions'])}

**Categorization Requirements:**
Analyze and categorize functions into standard categories. Provide results in this EXACT format:

**IMPORTANT:** For each category with functions, list notable functions WITH their addresses in format: "function_name at 0x..."

**FUNCTION_CATEGORIES:**
**Network_Operations:** [count] - [function names WITH addresses (0x...) and brief descriptions]
**File_IO_Operations:** [count] - [function names WITH addresses (0x...) and brief descriptions]
**Memory_Management:** [count] - [function names WITH addresses (0x...) and brief descriptions]
**Cryptographic_Functions:** [count] - [function names WITH addresses (0x...) and brief descriptions]
**String_Processing:** [count] - [function names WITH addresses (0x...) and brief descriptions]
**UI_Interface:** [count] - [function names WITH addresses (0x...) and brief descriptions]
**Registry_Operations:** [count] - [function names WITH addresses (0x...) and brief descriptions]
**Process_Control:** [count] - [function names WITH addresses (0x...) and brief descriptions]
**Authentication:** [count] - [function names WITH addresses (0x...) and brief descriptions]
**Configuration:** [count] - [function names WITH addresses (0x...) and brief descriptions]
**Utility_Helper:** [count] - [function names WITH addresses (0x...) and brief descriptions]
**Error_Handling:** [count] - [function names WITH addresses (0x...) and brief descriptions]
**Main_Core:** [count] - [function names WITH addresses (0x...) and brief descriptions]
**Unknown_Other:** [count] - [function names WITH addresses (0x...) and brief descriptions]

**CATEGORY_INSIGHTS:** [Analysis of what the function distribution reveals about software purpose, cite specific address examples]"""

    def _build_behavioral_analysis_prompt(self, data: Dict[str, Any]) -> str:
        """Build prompt for behavioral pattern analysis."""
        return f"""Analyze behavioral patterns and workflows in this binary.

**Behavioral Data:**
- Function Summaries: {len(data['function_summaries'])} detailed analyses
- Import Dependencies: {', '.join(data['imports'][:20])}
- Export Capabilities: {', '.join(data['exports'][:10])}

**Function Behavior Details:**
{self._format_behavioral_data(data)}

**Behavioral Analysis Requirements:**
Identify patterns, workflows, and behavioral characteristics. Format response as:

**IMPORTANT:** Cite specific function addresses demonstrating each behavioral pattern. Use format: "Behavior demonstrated by function at 0x..."

**PRIMARY_WORKFLOWS:** [Main execution flows and processes - cite specific function addresses]
**DATA_FLOW_PATTERNS:** [How data moves through the application - cite specific function addresses]
**INTERACTION_PATTERNS:** [User, network, file, system interactions - cite specific function addresses and strings]
**EXECUTION_MODELS:** [How the software operates - service, interactive, batch, etc. - cite specific function addresses]
**DEPENDENCY_ANALYSIS:** [Key dependencies and their purposes - cite specific import/export addresses]
**OPERATIONAL_MODES:** [Different modes of operation - cite specific function addresses]
**TRIGGER_MECHANISMS:** [What causes different behaviors - cite specific addresses and conditions]
**BEHAVIORAL_FINGERPRINT:** [Unique behavioral characteristics that identify this software - cite specific addresses and evidence]"""

    def _build_architecture_prompt(self, data: Dict[str, Any]) -> str:
        """Build prompt for software architecture analysis."""
        return f"""Analyze the software architecture and design patterns used in this binary.

**Architecture Data:**
- Code Organization: {len(data['classes'])} classes, {len(data['namespaces'])} namespaces
- Memory Layout: {len(data['segments'])} segments
- Function Structure: {data['metadata']['total_functions']} functions
- Data Structures: {len(data['data_items'])} data items

**Function Architecture:**
{self._format_architecture_data(data)}

**Architecture Analysis Requirements:**
Analyze the software architecture and provide results in this EXACT format:

**ARCHITECTURAL_PATTERN:** [Layered/MVC/Component-based/Microservices/Monolithic/Other]
**CODE_ORGANIZATION:** [How code is structured and organized]
**MODULE_STRUCTURE:** [How different modules/components are arranged]
**DESIGN_PATTERNS:** [Observable design patterns like Singleton, Factory, Observer, etc.]
**MEMORY_LAYOUT:** [How memory is organized and used]
**INTERFACE_DESIGN:** [How different components interface with each other]
**SCALABILITY_DESIGN:** [How the architecture supports scalability]
**ARCHITECTURE_QUALITY:** [Assessment of architectural quality and maintainability]
**COMPLEXITY_METRICS:** [Analysis of architectural complexity]"""

    def _build_risk_assessment_prompt(self, data: Dict[str, Any], analysis: Dict[str, Any]) -> str:
        """Build prompt for overall risk assessment."""
        return f"""Provide a comprehensive risk assessment based on all analysis conducted.

**Analysis Summary:**
- Software Classification: {analysis.get('software_classification', {}).get('type', 'Unknown')}
- Security Assessment: {analysis.get('security_assessment', {}).get('risk_level', 'Unknown')}
- Function Categories: {len(analysis.get('function_categorization', {}))} categories analyzed
- Architecture: {analysis.get('architecture_analysis', {}).get('pattern', 'Unknown')}

**Risk Assessment Requirements:**
Provide final risk assessment in this EXACT format:

**IMPORTANT:** For EACH risk factor identified, cite the specific address where the risk was identified. Format: "Risk description at address 0x... in function '...'"

**OVERALL_RISK_RATING:** [CRITICAL/HIGH/MEDIUM/LOW]
**RISK_SCORE:** [0-100]
**PRIMARY_RISK_FACTORS:** [Top 3-5 risk factors WITH specific addresses and function names where identified]
**THREAT_LEVEL:** [IMMEDIATE/HIGH/MODERATE/LOW/MINIMAL]
**RECOMMENDED_ACTIONS:** [Specific actions to take, referencing specific addresses/functions if applicable]
**MONITORING_RECOMMENDATIONS:** [What to monitor if deployed, cite specific functions/addresses to watch]
**CONTAINMENT_STRATEGY:** [How to safely contain or isolate if needed]
**BUSINESS_IMPACT:** [Potential business/operational impact]
**TECHNICAL_RISK:** [Technical risks and implications with specific examples from addresses]"""

    def _format_summaries_for_prompt(self, summaries: Dict[str, str]) -> str:
        """Format function summaries for AI prompts with comprehensive RAG retrieval."""
        if not summaries:
            return "No function summaries available."
        
        formatted = []
        
        # Enhanced RAG approach: Use vector store to find ALL relevant functions
        if (hasattr(self, 'enable_cag') and self.enable_cag and 
            hasattr(self, 'cag_manager') and self.cag_manager and 
            hasattr(self.cag_manager, 'vector_store') and self.cag_manager.vector_store):
            
            # Use comprehensive multi-vector retrieval
            enhanced_context = self._get_comprehensive_function_context(summaries)
            if enhanced_context:
                return enhanced_context
        
        # Fallback to basic formatting with limited functions
        for func, summary in list(summaries.items())[:10]:  # Limit for prompt size
            formatted.append(f"- {func}: {summary[:100]}{'...' if len(summary) > 100 else ''}")
        
        if len(summaries) > 10:
            formatted.append(f"... and {len(summaries) - 10} more functions with summaries")
        
        return '\n'.join(formatted)

    def _get_comprehensive_function_context(self, summaries: Dict[str, str]) -> str:
        """Get comprehensive function context using multi-vector RAG retrieval."""
        try:
            vector_store = self.cag_manager.vector_store
            all_context = []
            
            # Strategy 1: Search for different categories of functions
            search_queries = [
                "security cryptography authentication encryption",
                "network communication socket http tcp",
                "file system disk read write open",
                "memory allocation buffer management",
                "process thread execution control",
                "registry configuration system settings",
                "string parsing text processing",
                "user interface input output display",
                "database storage data management",
                "error handling exception logging",
                "main entry point initialization",
                "malware persistence backdoor"
            ]
            
            retrieved_functions = set()
            query_results = []
            
            # Perform multiple targeted searches
            for query in search_queries:
                results = vector_store.search(query, top_k=5)
                for result in results:
                    doc = result["document"]
                    if (doc.get("type") == "function_analysis" and 
                        doc.get("name") not in retrieved_functions):
                        query_results.append({
                            "name": doc.get("name"),
                            "content": doc.get("text", ""),
                            "score": result["score"],
                            "category": query.split()[0]  # First word as category
                        })
                        retrieved_functions.add(doc.get("name"))
            
            # Strategy 2: Include high-priority functions from summaries
            priority_keywords = ["main", "entry", "init", "start", "connect", "send", "receive", 
                               "read", "write", "create", "delete", "encrypt", "decrypt", "auth"]
            
            for func_name, summary in summaries.items():
                if (func_name not in retrieved_functions and 
                    any(keyword.lower() in func_name.lower() or keyword.lower() in summary.lower() 
                        for keyword in priority_keywords)):
                    query_results.append({
                        "name": func_name,
                        "content": summary,
                        "score": 1.0,
                        "category": "priority"
                    })
                    retrieved_functions.add(func_name)
            
            # Strategy 3: Add remaining functions by relevance score
            remaining_functions = []
            for func_name, summary in summaries.items():
                if func_name not in retrieved_functions:
                    # Simple relevance scoring based on summary length and keywords
                    relevance_score = len(summary) / 500.0  # Longer summaries get higher scores
                    if any(keyword in summary.lower() for keyword in 
                          ["critical", "important", "key", "main", "core", "primary"]):
                        relevance_score += 0.5
                    
                    remaining_functions.append({
                        "name": func_name,
                        "content": summary,
                        "score": relevance_score,
                        "category": "additional"
                    })
            
            # Sort by score and add top remaining functions
            remaining_functions.sort(key=lambda x: x["score"], reverse=True)
            query_results.extend(remaining_functions[:20])  # Add top 20 remaining
            
            # Format comprehensive context
            if query_results:
                all_context.append("## COMPREHENSIVE FUNCTION ANALYSIS")
                all_context.append(f"**Total Functions Analyzed: {len(query_results)} of {len(summaries)}**\n")
                
                # Group by category for better organization
                categories = {}
                for result in query_results:
                    category = result["category"]
                    if category not in categories:
                        categories[category] = []
                    categories[category].append(result)
                
                # Format each category
                for category, functions in categories.items():
                    if len(functions) > 0:
                        all_context.append(f"### {category.upper()} FUNCTIONS:")
                        for func in functions[:10]:  # Limit per category for readability
                            name = func["name"]
                            content = func["content"]
                            # Truncate very long content but be more generous
                            truncated_content = content[:300] + "..." if len(content) > 300 else content
                            all_context.append(f"- **{name}**: {truncated_content}")
                        
                        if len(functions) > 10:
                            all_context.append(f"  *... and {len(functions) - 10} more {category} functions*")
                        all_context.append("")
                
                return '\n'.join(all_context)
            
        except Exception as e:
            self.logger.warning(f"Error in comprehensive RAG retrieval: {e}")
        
        return None

    def _format_function_behaviors_for_security(self, data: Dict[str, Any]) -> str:
        """Format function behaviors specifically for security analysis with comprehensive RAG."""
        # Enhanced RAG approach for security analysis
        if (hasattr(self, 'enable_cag') and self.enable_cag and 
            hasattr(self, 'cag_manager') and self.cag_manager and 
            hasattr(self.cag_manager, 'vector_store') and self.cag_manager.vector_store):
            
            enhanced_security_context = self._get_comprehensive_security_context(data)
            if enhanced_security_context:
                return enhanced_security_context
        
        # Fallback to basic formatting
        formatted = []
        
        # Add renamed functions with their behaviors
        for old_name, new_name in data['renamed_functions'][:15]:
            summary = data['function_summaries'].get(old_name, "No summary available")
            formatted.append(f"- {old_name} → {new_name}: {summary[:150]}{'...' if len(summary) > 150 else ''}")
        
        return '\n'.join(formatted) if formatted else "No renamed functions with behavioral data available."

    def _get_comprehensive_security_context(self, data: Dict[str, Any]) -> str:
        """Get comprehensive security-focused function context using RAG."""
        try:
            vector_store = self.cag_manager.vector_store
            all_context = []
            
            # Security-focused search queries
            security_queries = [
                "authentication login password credential verification",
                "encryption cryptography cipher hash algorithm",
                "network socket communication tcp udp http",
                "file access read write permission disk",
                "registry key value configuration system",
                "process execution spawn thread creation",
                "memory allocation buffer overflow protection",
                "privilege escalation administrator elevation",
                "persistence startup autorun service",
                "injection code dll payload shellcode",
                "obfuscation packing anti-analysis stealth",
                "communication c2 command control callback"
            ]
            
            retrieved_functions = set()
            security_results = []
            
            # Perform security-focused searches
            for query in security_queries:
                results = vector_store.search(query, top_k=8)  # More results for security
                for result in results:
                    doc = result["document"]
                    if (doc.get("type") == "function_analysis" and 
                        doc.get("name") not in retrieved_functions):
                        
                        # Calculate security relevance score
                        content = doc.get("text", "")
                        security_score = self._calculate_security_score(content)
                        
                        security_results.append({
                            "old_name": doc.get("name", "unknown"),
                            "new_name": self._find_renamed_function(doc.get("name"), data),
                            "content": content,
                            "vector_score": result["score"],
                            "security_score": security_score,
                            "category": query.split()[0]
                        })
                        retrieved_functions.add(doc.get("name"))
            
            # Add high-risk functions from renamed functions
            for old_name, new_name in data['renamed_functions']:
                if old_name not in retrieved_functions:
                    summary = data['function_summaries'].get(old_name, "")
                    security_score = self._calculate_security_score(summary)
                    
                    if security_score > 0.3:  # Only include if security-relevant
                        security_results.append({
                            "old_name": old_name,
                            "new_name": new_name,
                            "content": summary,
                            "vector_score": 0.8,
                            "security_score": security_score,
                            "category": "renamed"
                        })
            
            # Sort by combined security and vector scores
            security_results.sort(key=lambda x: (x["security_score"] + x["vector_score"]) / 2, reverse=True)
            
            if security_results:
                all_context.append("## COMPREHENSIVE SECURITY ANALYSIS")
                all_context.append(f"**Security-Relevant Functions Analyzed: {len(security_results)}**\n")
                
                # Group by security risk level
                high_risk = [r for r in security_results if r["security_score"] > 0.7]
                medium_risk = [r for r in security_results if 0.4 <= r["security_score"] <= 0.7]
                low_risk = [r for r in security_results if r["security_score"] < 0.4]
                
                if high_risk:
                    all_context.append("### 🔴 HIGH SECURITY RISK FUNCTIONS:")
                    for result in high_risk[:15]:  # Top 15 high-risk
                        self._format_security_function(result, all_context)
                    all_context.append("")
                
                if medium_risk:
                    all_context.append("### 🟡 MEDIUM SECURITY RISK FUNCTIONS:")
                    for result in medium_risk[:10]:  # Top 10 medium-risk
                        self._format_security_function(result, all_context)
                    all_context.append("")
                
                if low_risk:
                    all_context.append("### 🟢 LOWER RISK / UTILITY FUNCTIONS:")
                    for result in low_risk[:5]:  # Top 5 low-risk for completeness
                        self._format_security_function(result, all_context)
                    all_context.append("")
                
                return '\n'.join(all_context)
            
        except Exception as e:
            self.logger.warning(f"Error in comprehensive security RAG retrieval: {e}")
        
        return None

    def _calculate_security_score(self, content: str) -> float:
        """Calculate security relevance score for function content."""
        if not content:
            return 0.0
        
        content_lower = content.lower()
        score = 0.0
        
        # High-risk indicators
        high_risk_keywords = [
            "encrypt", "decrypt", "password", "credential", "authentication",
            "privilege", "administrator", "system", "registry", "service",
            "network", "socket", "http", "tcp", "udp", "connect", "send",
            "file", "read", "write", "delete", "create", "access",
            "process", "thread", "spawn", "execute", "injection",
            "memory", "allocation", "buffer", "overflow", "shellcode",
            "persistence", "startup", "autorun", "malware", "backdoor"
        ]
        
        # Medium-risk indicators  
        medium_risk_keywords = [
            "string", "parse", "format", "validate", "check", "verify",
            "error", "exception", "log", "debug", "config", "setting"
        ]
        
        # Count occurrences
        for keyword in high_risk_keywords:
            if keyword in content_lower:
                score += 0.15
        
        for keyword in medium_risk_keywords:
            if keyword in content_lower:
                score += 0.05
        
        # Bonus for function names that indicate security functions
        if any(name in content_lower for name in ["auth", "crypt", "security", "protect", "verify"]):
            score += 0.2
        
        return min(score, 1.0)  # Cap at 1.0

    def _find_renamed_function(self, old_name: str, data: Dict[str, Any]) -> str:
        """Find the new name for a renamed function."""
        for old, new in data['renamed_functions']:
            if old == old_name:
                return new
        return old_name  # Return original if not renamed

    def _format_security_function(self, result: Dict[str, Any], context_list: List[str]) -> None:
        """Format a security function result for the context."""
        old_name = result["old_name"]
        new_name = result["new_name"]
        content = result["content"]
        security_score = result["security_score"]
        
        # Truncate content but be more generous for security analysis
        truncated_content = content[:400] + "..." if len(content) > 400 else content
        
        if old_name != new_name:
            context_list.append(f"- **{old_name} → {new_name}** (Security Risk: {security_score:.2f}): {truncated_content}")
        else:
            context_list.append(f"- **{old_name}** (Security Risk: {security_score:.2f}): {truncated_content}")

    def _format_summaries_for_categorization(self, summaries: Dict[str, str]) -> str:
        """Format summaries for function categorization with comprehensive RAG."""
        # Use the same comprehensive approach as the main formatter
        return self._format_summaries_for_prompt(summaries)

    def _format_renamed_functions(self, renamed_functions: List[tuple]) -> str:
        """Format renamed functions list."""
        if not renamed_functions:
            return "No functions have been renamed yet."
        
        formatted = []
        for old_name, new_name in renamed_functions[:20]:
            formatted.append(f"- {old_name} → {new_name}")
        
        if len(renamed_functions) > 20:
            formatted.append(f"... and {len(renamed_functions) - 20} more renamed functions")
        
        return '\n'.join(formatted)

    def _format_behavioral_data(self, data: Dict[str, Any]) -> str:
        """Format behavioral data with comprehensive RAG analysis."""
        # Enhanced RAG approach for behavioral analysis
        if (hasattr(self, 'enable_cag') and self.enable_cag and 
            hasattr(self, 'cag_manager') and self.cag_manager and 
            hasattr(self.cag_manager, 'vector_store') and self.cag_manager.vector_store):
            
            enhanced_behavioral_context = self._get_comprehensive_behavioral_context(data)
            if enhanced_behavioral_context:
                return enhanced_behavioral_context
        
        # Fallback to basic behavioral data
        return self._format_summaries_for_prompt(data['function_summaries'])

    def _get_comprehensive_behavioral_context(self, data: Dict[str, Any]) -> str:
        """Get comprehensive behavioral context using RAG."""
        try:
            vector_store = self.cag_manager.vector_store
            all_context = []
            
            # Behavioral analysis search queries
            behavioral_queries = [
                "initialization startup entry point main",
                "workflow process sequence execution flow",
                "data processing transformation parsing",
                "communication interaction interface api",
                "state management configuration settings",
                "event handling callback response trigger",
                "loop iteration recursive repetitive",
                "decision logic conditional branching",
                "cleanup finalization termination shutdown",
                "validation verification check constraint"
            ]
            
            retrieved_functions = set()
            behavioral_results = []
            
            # Perform behavioral-focused searches
            for query in behavioral_queries:
                results = vector_store.search(query, top_k=6)
                for result in results:
                    doc = result["document"]
                    if (doc.get("type") == "function_analysis" and 
                        doc.get("name") not in retrieved_functions):
                        
                        content = doc.get("text", "")
                        behavioral_score = self._calculate_behavioral_score(content)
                        
                        behavioral_results.append({
                            "name": doc.get("name"),
                            "content": content,
                            "vector_score": result["score"],
                            "behavioral_score": behavioral_score,
                            "category": query.split()[0]
                        })
                        retrieved_functions.add(doc.get("name"))
            
            # Add important functions from summaries
            for func_name, summary in data['function_summaries'].items():
                if func_name not in retrieved_functions:
                    behavioral_score = self._calculate_behavioral_score(summary)
                    if behavioral_score > 0.4:  # Only include behaviorally significant functions
                        behavioral_results.append({
                            "name": func_name,
                            "content": summary,
                            "vector_score": 0.7,
                            "behavioral_score": behavioral_score,
                            "category": "identified"
                        })
                        retrieved_functions.add(func_name)
            
            # Sort by behavioral relevance
            behavioral_results.sort(key=lambda x: x["behavioral_score"], reverse=True)
            
            if behavioral_results:
                all_context.append("## COMPREHENSIVE BEHAVIORAL ANALYSIS")
                all_context.append(f"**Behaviorally Significant Functions: {len(behavioral_results)}**\n")
                
                # Group by behavioral significance
                core_behavior = [r for r in behavioral_results if r["behavioral_score"] > 0.8]
                supporting_behavior = [r for r in behavioral_results if 0.5 <= r["behavioral_score"] <= 0.8]
                utility_behavior = [r for r in behavioral_results if r["behavioral_score"] < 0.5]
                
                if core_behavior:
                    all_context.append("### 🎯 CORE BEHAVIORAL FUNCTIONS:")
                    for result in core_behavior[:12]:
                        self._format_behavioral_function(result, all_context)
                    all_context.append("")
                
                if supporting_behavior:
                    all_context.append("### 🔧 SUPPORTING BEHAVIORAL FUNCTIONS:")
                    for result in supporting_behavior[:15]:
                        self._format_behavioral_function(result, all_context)
                    all_context.append("")
                
                if utility_behavior:
                    all_context.append("### ⚙️ UTILITY / HELPER FUNCTIONS:")
                    for result in utility_behavior[:8]:
                        self._format_behavioral_function(result, all_context)
                    all_context.append("")
                
                return '\n'.join(all_context)
            
        except Exception as e:
            self.logger.warning(f"Error in comprehensive behavioral RAG retrieval: {e}")
        
        return None

    def _calculate_behavioral_score(self, content: str) -> float:
        """Calculate behavioral significance score for function content."""
        if not content:
            return 0.0
        
        content_lower = content.lower()
        score = 0.0
        
        # Core behavioral indicators
        core_indicators = [
            "main", "entry", "start", "initialize", "init", "setup",
            "process", "execute", "run", "handle", "manage", "control",
            "create", "generate", "build", "construct", "parse",
            "connect", "communicate", "send", "receive", "transfer",
            "validate", "verify", "check", "authenticate", "authorize"
        ]
        
        # Supporting behavioral indicators
        supporting_indicators = [
            "configure", "setup", "prepare", "cleanup", "finalize",
            "update", "modify", "change", "transform", "convert",
            "save", "load", "read", "write", "store", "retrieve",
            "format", "encode", "decode", "compress", "extract"
        ]
        
        # State and flow indicators
        flow_indicators = [
            "loop", "iterate", "repeat", "while", "for", "next",
            "if", "then", "else", "switch", "case", "condition",
            "callback", "event", "trigger", "signal", "notify",
            "wait", "sleep", "pause", "resume", "continue", "stop"
        ]
        
        # Count occurrences with different weights
        for indicator in core_indicators:
            if indicator in content_lower:
                score += 0.25
        
        for indicator in supporting_indicators:
            if indicator in content_lower:
                score += 0.15
        
        for indicator in flow_indicators:
            if indicator in content_lower:
                score += 0.10
        
        # Bonus for function names that suggest behavioral significance
        behavioral_names = ["main", "entry", "process", "handle", "execute", "init"]
        if any(name in content_lower for name in behavioral_names):
            score += 0.3
        
        return min(score, 1.0)  # Cap at 1.0

    def _format_behavioral_function(self, result: Dict[str, Any], context_list: List[str]) -> None:
        """Format a behavioral function result for the context."""
        name = result["name"]
        content = result["content"]
        behavioral_score = result["behavioral_score"]
        
        # Truncate content but preserve behavioral details
        truncated_content = content[:350] + "..." if len(content) > 350 else content
        
        context_list.append(f"- **{name}** (Behavioral Score: {behavioral_score:.2f}): {truncated_content}")

    def _format_architecture_data(self, data: Dict[str, Any]) -> str:
        """Format architecture data with comprehensive analysis."""
        # Enhanced RAG approach for architecture analysis  
        if (hasattr(self, 'enable_cag') and self.enable_cag and 
            hasattr(self, 'cag_manager') and self.cag_manager and 
            hasattr(self.cag_manager, 'vector_store') and self.cag_manager.vector_store):
            
            enhanced_architecture_context = self._get_comprehensive_architecture_context(data)
            if enhanced_architecture_context:
                return enhanced_architecture_context
        
        # Fallback to basic architecture data
        return self._format_summaries_for_prompt(data['function_summaries'])

    def _get_comprehensive_architecture_context(self, data: Dict[str, Any]) -> str:
        """Get comprehensive architecture context using RAG."""
        try:
            vector_store = self.cag_manager.vector_store
            all_context = []
            
            # Architecture-focused search queries
            architecture_queries = [
                "initialization setup configuration startup",
                "interface api public private function",
                "module component service layer structure",
                "dependency injection factory pattern",
                "data model structure class object",
                "controller handler manager coordinator",
                "utility helper common shared library",
                "persistence storage database file system",
                "logging debug error monitoring trace",
                "cleanup disposal finalize terminate"
            ]
            
            retrieved_functions = set()
            architecture_results = []
            
            # Perform architecture-focused searches
            for query in architecture_queries:
                results = vector_store.search(query, top_k=5)
                for result in results:
                    doc = result["document"]
                    if (doc.get("type") == "function_analysis" and 
                        doc.get("name") not in retrieved_functions):
                        
                        content = doc.get("text", "")
                        architecture_score = self._calculate_architecture_score(content)
                        
                        architecture_results.append({
                            "name": doc.get("name"),
                            "content": content,
                            "vector_score": result["score"],
                            "architecture_score": architecture_score,
                            "category": query.split()[0]
                        })
                        retrieved_functions.add(doc.get("name"))
            
            # Sort by architectural significance
            architecture_results.sort(key=lambda x: x["architecture_score"], reverse=True)
            
            if architecture_results:
                all_context.append("## COMPREHENSIVE ARCHITECTURE ANALYSIS")
                all_context.append(f"**Architecturally Significant Functions: {len(architecture_results)}**\n")
                
                # Group by architectural layer/role
                categories = {}
                for result in architecture_results:
                    category = result["category"]
                    if category not in categories:
                        categories[category] = []
                    categories[category].append(result)
                
                # Format each architectural category
                for category, functions in categories.items():
                    if len(functions) > 0:
                        all_context.append(f"### {category.upper()} LAYER:")
                        for func in functions[:8]:  # Limit per category
                            self._format_architecture_function(func, all_context)
                        all_context.append("")
                
                return '\n'.join(all_context)
            
        except Exception as e:
            self.logger.warning(f"Error in comprehensive architecture RAG retrieval: {e}")
        
        return None

    def _calculate_architecture_score(self, content: str) -> float:
        """Calculate architectural significance score for function content."""
        if not content:
            return 0.0
        
        content_lower = content.lower()
        score = 0.0
        
        # Architecture pattern indicators
        pattern_indicators = [
            "factory", "singleton", "observer", "strategy", "adapter",
            "facade", "proxy", "decorator", "builder", "command"
        ]
        
        # Component/layer indicators
        layer_indicators = [
            "controller", "service", "repository", "model", "view",
            "handler", "manager", "coordinator", "processor", "engine"
        ]
        
        # Structure indicators
        structure_indicators = [
            "interface", "abstract", "base", "parent", "child",
            "public", "private", "static", "dynamic", "virtual"
        ]
        
        # Count architectural significance
        for indicator in pattern_indicators:
            if indicator in content_lower:
                score += 0.3
        
        for indicator in layer_indicators:
            if indicator in content_lower:
                score += 0.2
        
        for indicator in structure_indicators:
            if indicator in content_lower:
                score += 0.1
        
        return min(score, 1.0)  # Cap at 1.0

    def _format_architecture_function(self, result: Dict[str, Any], context_list: List[str]) -> None:
        """Format an architecture function result for the context."""
        name = result["name"]
        content = result["content"]
        architecture_score = result["architecture_score"]
        
        # Truncate content for architecture analysis
        truncated_content = content[:300] + "..." if len(content) > 300 else content
        
        context_list.append(f"- **{name}** (Arch Score: {architecture_score:.2f}): {truncated_content}")

    def _format_summaries_for_categorization(self, summaries: Dict[str, str]) -> str:
        """Format summaries for function categorization with comprehensive RAG."""
        # Use the same comprehensive approach as the main formatter
        return self._format_summaries_for_prompt(summaries)

    def _format_renamed_functions(self, renamed_functions: List[tuple]) -> str:
        """Format renamed functions list."""
        if not renamed_functions:
            return "No functions have been renamed yet."
        
        formatted = []
        for old_name, new_name in renamed_functions[:20]:
            formatted.append(f"- {old_name} → {new_name}")
        
        if len(renamed_functions) > 20:
            formatted.append(f"... and {len(renamed_functions) - 20} more renamed functions")
        
        return '\n'.join(formatted)

    def _format_behavioral_data(self, data: Dict[str, Any]) -> str:
        """Format data for behavioral analysis."""
        return self._format_summaries_for_prompt(data['function_summaries'])

    def _format_architecture_data(self, data: Dict[str, Any]) -> str:
        """Format data for architecture analysis."""
        formatted = []
        if data['classes']:
            formatted.append(f"Classes: {', '.join(data['classes'][:10])}")
        if data['namespaces']:
            formatted.append(f"Namespaces: {', '.join(data['namespaces'][:10])}")
        if data['segments']:
            formatted.append(f"Memory Segments: {', '.join(data['segments'][:5])}")
        
        return '\n'.join(formatted) if formatted else "Limited architecture data available."

    # Response parsing methods
    def _parse_classification_response(self, response: str) -> Dict[str, str]:
        """Parse software classification response."""
        parsed = {}
        try:
            lines = response.split('\n')
            for line in lines:
                if '**SOFTWARE_TYPE:**' in line:
                    parsed['type'] = line.split('**SOFTWARE_TYPE:**')[1].strip()
                elif '**PRIMARY_PURPOSE:**' in line:
                    parsed['purpose'] = line.split('**PRIMARY_PURPOSE:**')[1].strip()
                elif '**CLASSIFICATION_CONFIDENCE:**' in line:
                    parsed['confidence'] = line.split('**CLASSIFICATION_CONFIDENCE:**')[1].strip()
                elif '**EVIDENCE:**' in line:
                    parsed['evidence'] = line.split('**EVIDENCE:**')[1].strip()
            
            # Extract addresses from the evidence section
            parsed['addresses'] = self._extract_addresses_from_analysis(response)
        except Exception as e:
            self.logger.warning(f"Error parsing classification response: {e}")
            parsed['raw_response'] = response
        
        return parsed

    def _parse_security_response(self, response: str) -> Dict[str, str]:
        """Parse security assessment response."""
        parsed = {}
        try:
            lines = response.split('\n')
            indicators_section = []
            capturing_indicators = False
            
            for line in lines:
                if '**OVERALL_RISK_LEVEL:**' in line:
                    parsed['risk_level'] = line.split('**OVERALL_RISK_LEVEL:**')[1].strip()
                elif '**RISK_SCORE:**' in line:
                    parsed['risk_score'] = line.split('**RISK_SCORE:**')[1].strip()
                elif '**SUSPICIOUS_INDICATORS:**' in line:
                    capturing_indicators = True
                    # Get initial content after the header
                    remainder = line.split('**SUSPICIOUS_INDICATORS:**')[1].strip()
                    if remainder:
                        indicators_section.append(remainder)
                elif '**MITIGATION_RECOMMENDATIONS:**' in line or '**IOCS:**' in line:
                    capturing_indicators = False
                elif capturing_indicators and line.strip():
                    indicators_section.append(line.strip())
            
            if indicators_section:
                parsed['indicators'] = '\n'.join(indicators_section)
            
            # Extract addresses from suspicious indicators and entire response
            parsed['addresses'] = self._extract_addresses_from_analysis(response)
            
            # Extract IOCs section if present
            if '**IOCS:**' in response:
                iocs_match = response.split('**IOCS:**')[1].split('**')[0] if '**IOCS:**' in response else ""
                parsed['iocs'] = iocs_match.strip()
                
        except Exception as e:
            self.logger.warning(f"Error parsing security response: {e}")
            parsed['raw_response'] = response
        
        return parsed

    def _parse_function_response(self, response: str) -> Dict[str, str]:
        """Parse function categorization response."""
        parsed = {}
        try:
            # Extract function categories with addresses preserved
            import re
            categories = re.findall(r'\*\*([^:]+):\*\* \[(\d+)\] - ([^*]+)', response)
            for category, count, description in categories:
                # Keep the full description which should now include addresses
                parsed[category.lower().replace('_', ' ')] = f"{count} functions: {description.strip()}"
            
            # Extract all addresses from function categorization
            parsed['addresses'] = self._extract_addresses_from_analysis(response)
            
            # Also capture insights if present
            if '**CATEGORY_INSIGHTS:**' in response:
                insights_match = response.split('**CATEGORY_INSIGHTS:**')[1].split('**')[0] if '**CATEGORY_INSIGHTS:**' in response else ""
                parsed['insights'] = insights_match.strip()
                
        except Exception as e:
            self.logger.warning(f"Error parsing function response: {e}")
            parsed['raw_response'] = response
        
        return parsed

    def _parse_behavioral_response(self, response: str) -> Dict[str, str]:
        """Parse behavioral analysis response."""
        parsed = {}
        try:
            lines = response.split('\n')
            for line in lines:
                if '**PRIMARY_WORKFLOWS:**' in line:
                    parsed['workflows'] = line.split('**PRIMARY_WORKFLOWS:**')[1].strip()
                elif '**BEHAVIORAL_FINGERPRINT:**' in line:
                    parsed['fingerprint'] = line.split('**BEHAVIORAL_FINGERPRINT:**')[1].strip()
            
            # Extract addresses from behavioral analysis
            parsed['addresses'] = self._extract_addresses_from_analysis(response)
            
        except Exception as e:
            self.logger.warning(f"Error parsing behavioral response: {e}")
            parsed['raw_response'] = response
        
        return parsed

    def _parse_architecture_response(self, response: str) -> Dict[str, str]:
        """Parse architecture analysis response."""
        parsed = {}
        try:
            lines = response.split('\n')
            for line in lines:
                if '**ARCHITECTURAL_PATTERN:**' in line:
                    parsed['pattern'] = line.split('**ARCHITECTURAL_PATTERN:**')[1].strip()
                elif '**ARCHITECTURE_QUALITY:**' in line:
                    parsed['quality'] = line.split('**ARCHITECTURE_QUALITY:**')[1].strip()
        except Exception as e:
            self.logger.warning(f"Error parsing architecture response: {e}")
            parsed['raw_response'] = response
        
        return parsed

    def _parse_risk_response(self, response: str) -> Dict[str, str]:
        """Parse risk assessment response."""
        parsed = {}
        try:
            lines = response.split('\n')
            risk_factors_section = []
            capturing_factors = False
            
            for line in lines:
                if '**OVERALL_RISK_RATING:**' in line:
                    parsed['rating'] = line.split('**OVERALL_RISK_RATING:**')[1].strip()
                elif '**THREAT_LEVEL:**' in line:
                    parsed['threat_level'] = line.split('**THREAT_LEVEL:**')[1].strip()
                elif '**RECOMMENDED_ACTIONS:**' in line:
                    capturing_factors = False
                    parsed['recommendations'] = line.split('**RECOMMENDED_ACTIONS:**')[1].strip()
                elif '**PRIMARY_RISK_FACTORS:**' in line:
                    capturing_factors = True
                    remainder = line.split('**PRIMARY_RISK_FACTORS:**')[1].strip()
                    if remainder:
                        risk_factors_section.append(remainder)
                elif capturing_factors and line.strip() and not line.startswith('**'):
                    risk_factors_section.append(line.strip())
            
            if risk_factors_section:
                parsed['risk_factors'] = '\n'.join(risk_factors_section)
            
            # Extract addresses from risk assessment
            parsed['addresses'] = self._extract_addresses_from_analysis(response)
            
        except Exception as e:
            self.logger.warning(f"Error parsing risk response: {e}")
            parsed['raw_response'] = response
        
        return parsed

    def _generate_structured_software_report(self, data: Dict[str, Any], analysis: Dict[str, Any], format_type: str) -> str:
        """Generate the final structured software report."""
        if format_type.lower() == "json":
            return self._generate_json_report(data, analysis)
        elif format_type.lower() == "text":
            return self._generate_text_report(data, analysis)
        else:  # Default to markdown
            return self._generate_markdown_report(data, analysis)

    def _generate_markdown_report(self, data: Dict[str, Any], analysis: Dict[str, Any]) -> str:
        """Generate markdown-formatted software report."""
        timestamp = self._get_current_timestamp()
        
        report = f"""# Comprehensive Software Analysis Report

**Generated:** {timestamp}  
**Analysis Tool:** OGhidra AI-Powered Reverse Engineering Platform

---

## 📊 Executive Summary

### Software Classification
- **Type:** {analysis.get('software_classification', {}).get('type', 'Unknown')}
- **Primary Purpose:** {analysis.get('software_classification', {}).get('purpose', 'Not determined')}
- **Classification Confidence:** {analysis.get('software_classification', {}).get('confidence', 'N/A')}

### Risk Assessment
- **Overall Risk Level:** {analysis.get('risk_assessment', {}).get('rating', 'Not assessed')}
- **Security Risk Score:** {analysis.get('security_assessment', {}).get('risk_score', 'N/A')}/100
- **Threat Level:** {analysis.get('risk_assessment', {}).get('threat_level', 'Unknown')}

---

## 🔍 Binary Overview

### Statistical Summary
- **Total Functions:** {data['metadata']['total_functions']}
- **Analyzed Functions:** {data['metadata']['analyzed_count']} ({(data['metadata']['analyzed_count']/data['metadata']['total_functions']*100) if data['metadata']['total_functions'] > 0 else 0:.1f}%)
- **Renamed Functions:** {data['metadata']['renamed_count']}
- **Imported Symbols:** {len(data['imports'])}
- **Exported Symbols:** {len(data['exports'])}
- **Memory Segments:** {len(data['segments'])}

### Key Imports
{self._format_imports_for_report(data['imports'])}

### Key Exports  
{self._format_exports_for_report(data['exports'])}

---

## 🏗️ Architecture Analysis

### Design Pattern
**Pattern:** {analysis.get('architecture_analysis', {}).get('pattern', 'Not identified')}

### Architecture Quality
{analysis.get('architecture_analysis', {}).get('quality', 'Not assessed')}

---

## 🎯 Function Analysis

### Function Categories
{self._format_function_categories_for_report(analysis.get('function_categorization', {}))}

### Renamed Functions
{self._format_renamed_functions_for_report(data['renamed_functions'])}

---

## 🔒 Security Assessment

### Risk Breakdown
- **Overall Risk:** {analysis.get('security_assessment', {}).get('risk_level', 'Not assessed')}
- **Risk Score:** {analysis.get('security_assessment', {}).get('risk_score', 'N/A')}/100

### Suspicious Indicators
{analysis.get('security_assessment', {}).get('indicators', 'None identified')}

### Security Recommendations
{analysis.get('risk_assessment', {}).get('recommendations', 'No specific recommendations available')}

---

## 🔄 Behavioral Analysis

### Primary Workflows
{analysis.get('behavioral_analysis', {}).get('workflows', 'Not analyzed')}

### Behavioral Fingerprint
{analysis.get('behavioral_analysis', {}).get('fingerprint', 'Not identified')}

---

## 📋 Key Findings

### Evidence Supporting Classification
{analysis.get('software_classification', {}).get('evidence', 'No specific evidence documented')}

### Function Insights
{analysis.get('function_categorization', {}).get('insights', 'No insights available')}

---

## 🔬 Detailed Findings with Addresses

This section provides specific addresses and evidence for key findings identified during analysis.

### Security-Related Findings
{self._format_findings_with_addresses(analysis.get('security_assessment', {}).get('addresses', []), max_findings=15)}

### Classification Evidence with Addresses
{self._format_findings_with_addresses(analysis.get('software_classification', {}).get('addresses', []), max_findings=10)}

### Behavioral Patterns with Addresses
{self._format_findings_with_addresses(analysis.get('behavioral_analysis', {}).get('addresses', []), max_findings=10)}

### Risk Factors with Addresses
{self._format_findings_with_addresses(analysis.get('risk_assessment', {}).get('addresses', []), max_findings=10)}

---

## ⚠️ Risk Mitigation

### Recommended Actions
{analysis.get('risk_assessment', {}).get('recommendations', 'No specific recommendations')}

### Monitoring Recommendations
{analysis.get('risk_assessment', {}).get('monitoring', 'Standard monitoring protocols recommended')}

---

## 📈 Analysis Statistics

- **Analysis Completion:** {(sum(1 for a in analysis.values() if a)/len(analysis)*100):.1f}%
- **Data Quality:** {'High' if data['metadata']['analyzed_count'] > 10 else 'Medium' if data['metadata']['analyzed_count'] > 0 else 'Low'}
- **Confidence Level:** {analysis.get('software_classification', {}).get('confidence', 'Not determined')}

---

*Report generated by OGhidra AI-Powered Reverse Engineering Platform*  
*For questions or additional analysis, consult the detailed function summaries and analysis logs.*
"""
        return report

    def _generate_json_report(self, data: Dict[str, Any], analysis: Dict[str, Any]) -> str:
        """Generate JSON-formatted software report."""
        report_data = {
            "metadata": {
                "generated_timestamp": self._get_current_timestamp(),
                "tool": "OGhidra AI-Powered Reverse Engineering Platform",
                "version": "1.0"
            },
            "executive_summary": {
                "software_type": analysis.get('software_classification', {}).get('type', 'Unknown'),
                "primary_purpose": analysis.get('software_classification', {}).get('purpose', 'Not determined'),
                "risk_level": analysis.get('risk_assessment', {}).get('rating', 'Not assessed'),
                "risk_score": analysis.get('security_assessment', {}).get('risk_score', 'N/A'),
                "threat_level": analysis.get('risk_assessment', {}).get('threat_level', 'Unknown')
            },
            "binary_overview": {
                "statistics": data['metadata'],
                "imports": data['imports'][:20],  # Limit for size
                "exports": data['exports'][:20],
                "segments": data['segments']
            },
            "analysis_results": {
                "classification": analysis.get('software_classification', {}),
                "security": analysis.get('security_assessment', {}),
                "functions": analysis.get('function_categorization', {}),
                "behavior": analysis.get('behavioral_analysis', {}),
                "architecture": analysis.get('architecture_analysis', {}),
                "risk": analysis.get('risk_assessment', {})
            },
            "detailed_findings": {
                "security_findings": analysis.get('security_assessment', {}).get('addresses', []),
                "classification_evidence": analysis.get('software_classification', {}).get('addresses', []),
                "behavioral_patterns": analysis.get('behavioral_analysis', {}).get('addresses', []),
                "risk_factors": analysis.get('risk_assessment', {}).get('addresses', []),
                "function_addresses": analysis.get('function_categorization', {}).get('addresses', [])
            },
            "function_data": {
                "renamed_functions": data['renamed_functions'],
                "summaries": data['function_summaries']
            }
        }
        
        import json
        return json.dumps(report_data, indent=2, default=str)

    def _generate_text_report(self, data: Dict[str, Any], analysis: Dict[str, Any]) -> str:
        """Generate plain text software report."""
        # Convert markdown to plain text by removing markdown formatting
        markdown_report = self._generate_markdown_report(data, analysis)
        
        # Simple markdown to text conversion
        text_report = markdown_report
        text_report = text_report.replace('#', '')  # Remove headers
        text_report = text_report.replace('**', '')  # Remove bold
        text_report = text_report.replace('*', '')   # Remove italics
        text_report = text_report.replace('---', '=' * 50)  # Replace separators
        
        return text_report

    def _format_imports_for_report(self, imports: List[str]) -> str:
        """Format imports for report display."""
        if not imports:
            return "- No imports detected"
        
        formatted = []
        for imp in imports[:15]:  # Show top 15
            formatted.append(f"- {imp}")
        
        if len(imports) > 15:
            formatted.append(f"- ... and {len(imports) - 15} more imports")
        
        return '\n'.join(formatted)

    def _format_exports_for_report(self, exports: List[str]) -> str:
        """Format exports for report display."""
        if not exports:
            return "- No exports detected"
        
        formatted = []
        for exp in exports[:10]:  # Show top 10
            formatted.append(f"- {exp}")
        
        if len(exports) > 10:
            formatted.append(f"- ... and {len(exports) - 10} more exports")
        
        return '\n'.join(formatted)

    def _format_function_categories_for_report(self, categories: Dict[str, str]) -> str:
        """Format function categories for report display."""
        if not categories:
            return "- Function categorization not available"
        
        formatted = []
        for category, description in categories.items():
            if 'raw_response' not in category:
                formatted.append(f"- **{category.title()}:** {description}")
        
        return '\n'.join(formatted) if formatted else "- No function categories identified"

    def _format_renamed_functions_for_report(self, renamed_functions: List[tuple]) -> str:
        """Format renamed functions for report display."""
        if not renamed_functions:
            return "- No functions have been renamed in this analysis"
        
        formatted = []
        for old_name, new_name in renamed_functions[:20]:  # Show top 20
            formatted.append(f"- `{old_name}` → `{new_name}`")
        
        if len(renamed_functions) > 20:
            formatted.append(f"- ... and {len(renamed_functions) - 20} more renamed functions")
        
        return '\n'.join(formatted)

    # ------------------------------------------------------------------
    # Address and Evidence Extraction Helpers
    # ------------------------------------------------------------------

    def _extract_addresses_from_analysis(self, analysis_text: str) -> List[Dict[str, str]]:
        """
        Extract addresses and their associated findings from AI analysis text.
        
        Args:
            analysis_text: The AI-generated analysis text
            
        Returns:
            List of dictionaries with 'address', 'context', 'finding' keys
        """
        import re
        findings = []
        
        # Pattern to match addresses with context
        # Matches patterns like: "at address 0x401000", "0x401000 in function", etc.
        address_patterns = [
            r'(?:at|in|address)\s+(0x[0-9a-fA-F]{6,})\s+(?:in\s+)?(?:function\s+)?["\']?([^"\'\n,.:]+)?',
            r'(0x[0-9a-fA-F]{6,})\s+["\']([^"\'\n,.:]+)["\']',
            r'function\s+["\']?([^"\'\s]+)["\']?\s+at\s+(0x[0-9a-fA-F]{6,})',
        ]
        
        lines = analysis_text.split('\n')
        for line in lines:
            for pattern in address_patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for match in matches:
                    groups = match.groups()
                    # Handle different capture group orders
                    address = None
                    function = None
                    
                    for group in groups:
                        if group and group.startswith('0x'):
                            address = group
                        elif group and not group.startswith('0x'):
                            function = group
                    
                    if address:
                        findings.append({
                            'address': address,
                            'function': function or 'unknown',
                            'context': line.strip(),
                            'finding': line.strip()
                        })
        
        return findings

    def _format_findings_with_addresses(self, findings: List[Dict[str, str]], max_findings: int = 20) -> str:
        """
        Format a list of findings with addresses for report display.
        
        Args:
            findings: List of finding dictionaries with address info
            max_findings: Maximum number of findings to include
            
        Returns:
            Formatted string for report
        """
        if not findings:
            return "No specific findings with addresses available."
        
        formatted = []
        for i, finding in enumerate(findings[:max_findings], 1):
            addr = finding.get('address', 'unknown')
            func = finding.get('function', 'unknown')
            context = finding.get('context', 'No details')
            
            formatted.append(f"{i}. **Address {addr}** (Function: `{func}`)")
            formatted.append(f"   {context}")
            formatted.append("")
        
        if len(findings) > max_findings:
            formatted.append(f"*... and {len(findings) - max_findings} more findings*")
        
        return '\n'.join(formatted)

    def _enrich_findings_with_locations(self, analysis: Dict[str, Any], data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich analysis findings with specific location data.
        
        Args:
            analysis: The analysis dictionary from AI
            data: The collected binary data
            
        Returns:
            Enriched analysis with location data
        """
        enriched = analysis.copy()
        
        # Extract addresses from all analysis sections
        all_findings = []
        
        for section_key, section_value in analysis.items():
            if isinstance(section_value, dict):
                for key, value in section_value.items():
                    if isinstance(value, str):
                        findings = self._extract_addresses_from_analysis(value)
                        for finding in findings:
                            finding['section'] = section_key
                            finding['subsection'] = key
                            all_findings.append(finding)
            elif isinstance(section_value, str):
                findings = self._extract_addresses_from_analysis(section_value)
                for finding in findings:
                    finding['section'] = section_key
                    all_findings.append(finding)
        
        # Add extracted findings to enriched analysis
        enriched['extracted_findings'] = all_findings
        
        return enriched

    # ------------------------------------------------------------------
    # X-ref context helper
    # ------------------------------------------------------------------

    def _collect_xref_context(self, address: str, max_funcs: int = 10) -> None:
        """Fetch functions that reference *address* and capture quick summaries.

        Stores results in self.function_xrefs[address] = [caller_addrs].
        Also decompiles and extracts summaries for new callers (up to *max_funcs*).
        """
        if not hasattr(self, 'function_xrefs'):
            self.function_xrefs = {}

        if address in self.function_xrefs:
            # Already collected
            return

        # Call MCP client
        xrefs = []
        try:
            xrefs = self.ghidra.get_xrefs_to(address, limit=max_funcs)  # type: ignore
        except Exception as e:
            self.logger.debug(f"get_xrefs_to failed for {address}: {e}")
            return

        # Normalise list to raw addresses
        caller_addrs = []
        for ref in xrefs[:max_funcs]:
            if isinstance(ref, dict):
                addr = ref.get('from') or ref.get('address') or ''
            else:
                addr = str(ref)
            if addr and re.fullmatch(r"[0-9a-fA-F]{6,}", addr):
                caller_addrs.append(addr)

        self.function_xrefs[address] = caller_addrs

        # Capture summaries for each caller if not already known
        for caller in caller_addrs:
            if hasattr(self, 'function_summaries') and caller in self.function_summaries:
                continue
            try:
                decomp = self.ghidra.decompile_function_by_address(caller)  # type: ignore
                if isinstance(decomp, str):
                    caller_summary = self._extract_function_summary(decomp)
                    if caller_summary:
                        if not hasattr(self, 'function_summaries'):
                            self.function_summaries = {}
                        self.function_summaries[caller] = caller_summary
            except Exception as e:
                self.logger.debug(f"Failed to decompile caller {caller}: {e}")

    # ------------------------------------------------------------------
    #  Address normalisation helpers
    # ------------------------------------------------------------------

    def _normalize_address(self, identifier: str) -> Optional[str]:
        """Try to extract a pure hexadecimal address from various identifier
        forms (e.g. 'FUN_004057c0', 'thunk_FUN_004057c0', '0x004057c0',
        'Function: FUN_004057c0 at 004057c0').

        Returns the hex string (lower-case, no '0x' prefix) or ``None`` if
        no valid address can be found.
        """
        if not identifier:
            return None

        # Strip common 0x prefix if present
        if identifier.startswith(("0x", "0X")):
            identifier = identifier[2:]

        # Already a bare hex value?
        if re.fullmatch(r"[0-9a-fA-F]{6,}", identifier):
            return identifier.lower()

        # Search for a hex substring of length ≥6 anywhere in the string
        match = re.search(r"([0-9a-fA-F]{6,})", identifier)
        if match:
            return match.group(1).lower()

        return None

def main():
    """Main entry point for the bridge application."""
    parser = argparse.ArgumentParser(description="Ollama-GhidraMCP Bridge")
    parser.add_argument("--ollama-url", help="Ollama server URL")
    parser.add_argument("--ghidra-url", help="GhidraMCP server URL")
    parser.add_argument("--model", help="Ollama model to use")
    
    # Add model arguments for each phase
    parser.add_argument("--planning-model", help="Model to use for the planning phase")
    parser.add_argument("--execution-model", help="Model to use for the execution phase")
    parser.add_argument("--analysis-model", help="Model to use for the analysis phase")
    
    parser.add_argument("--interactive", action="store_true", help="Run in interactive mode")
    parser.add_argument("--list-models", action="store_true", help="List available models")
    parser.add_argument("--list-context", action="store_true", help="List current conversation context")
    parser.add_argument("--mock", action="store_true", help="Run in mock mode (simulated GhidraMCP)")
    parser.add_argument("--log-level", help="Set log level (DEBUG, INFO, WARNING, ERROR)")
    parser.add_argument("--include-capabilities", action="store_true", help="Include capabilities.txt content in prompts")
    parser.add_argument("--max-steps", type=int, default=5, help="Maximum number of steps for agentic execution loop")
    
    args = parser.parse_args()
    
    # Set log level from arguments or environment
    if args.log_level:
        os.environ["LOG_LEVEL"] = args.log_level
        
    # Configure based on arguments and environment variables
    config = BridgeConfig()
    
    # Override with command line arguments
    if args.ollama_url:
        config.ollama.base_url = args.ollama_url
    if args.ghidra_url:
        config.ghidra.base_url = args.ghidra_url
    if args.model:
        config.ollama.model = args.model
    if args.mock:
        config.ghidra.mock_mode = True
        
    # Handle model switching - update the model map
    if args.planning_model:
        config.ollama.model_map["planning"] = args.planning_model
    if args.execution_model:
        config.ollama.model_map["execution"] = args.execution_model
    if args.analysis_model:
        config.ollama.model_map["analysis"] = args.analysis_model
        
    # Initialize clients
    ollama_client = OllamaClient(config.ollama)
    ghidra_client = GhidraMCPClient(config.ghidra)
    
    # List models if requested
    if args.list_models:
        models = ollama_client.list_models()
        if models:
            print("Available Ollama models:")
            for model in models:
                print(f"  - {model}")
        else:
            print("No models found or error connecting to Ollama")
        return 0
    
    # Initialize the bridge
    bridge = Bridge(
        config=config,
        include_capabilities=args.include_capabilities,
        max_agent_steps=args.max_steps
    )
    
    # Health check for Ollama and GhidraMCP
    ollama_health = "OK" if ollama_client.check_health() else "FAIL"
    ghidra_health = "OK" if ghidra_client.check_health() else "FAIL"
    
    # List context if requested
    if args.list_context:
        print("\nCurrent conversation context:")
        for i, item in enumerate(bridge.context):
            print(f"{i}: {item.get('role', 'unknown')}: {item.get('content', '')[:50]}...")
        return 0
    
    # Interactive mode
    if args.interactive:
        # Display banner
        print(
            "╔══════════════════════════════════════════════════════════════════╗\n"
            "║                                                                  ║\n"
            "║  OGhidra - Simplified Three-Phase Architecture                   ║\n"
            "║  ------------------------------------------                      ║\n"
            "║                                                                  ║\n"
            "║  1. Planning Phase: Create a plan for addressing the query       ║\n"
            "║  2. Tool Calling Phase: Execute tools to gather information      ║\n"
            "║  3. Analysis Phase: Analyze results and provide answers          ║\n"
            "║                                                                  ║\n"
            "║  For more information, see README-ARCHITECTURE.md                ║\n"
            "║                                                                  ║\n"
            "╚══════════════════════════════════════════════════════════════════╝"
        )
        
        print(f"Ollama-GhidraMCP Bridge (Interactive Mode)")
        print(f"Default model: {config.ollama.model}")
        
        # Show health status
        if ollama_health != "OK" or ghidra_health != "OK":
            print(f"Health check: Ollama: {ollama_health}, GhidraMCP: {ghidra_health}")
        
        # Main interaction loop
        while True:
            try:
                prompt = input("\nQuery (or 'exit', 'quit', 'health', 'models'): ")
                
                if prompt.lower() in ["exit", "quit"]:
                    break
                    
                elif prompt.lower() == "health":
                    ollama_health = "OK" if ollama_client.check_health() else "FAIL"
                    ghidra_health = "OK" if ghidra_client.check_health() else "FAIL"
                    print(f"Health check: Ollama: {ollama_health}, GhidraMCP: {ghidra_health}")
                    
                elif prompt.lower() == "models":
                    models = ollama_client.list_models()
                    if models:
                        print("Available Ollama models:")
                        for model in models:
                            print(f"  - {model}")
                    else:
                        print("No models found or error connecting to Ollama")
                        
                elif prompt.strip():  # Only process non-empty prompts
                    response = bridge.process_query(prompt)
                    print(f"\n{response}")
                    
            except KeyboardInterrupt:
                print("\nExiting...")
                break
                
            except Exception as e:
                print(f"Error: {str(e)}")
                
        return 0
        
    # Non-interactive mode - process input from stdin
    else:
        user_input = ""
        for line in sys.stdin:
            user_input += line
            
        if user_input.strip():
            response = bridge.process_query(user_input)
            print(response)
            
        return 0

if __name__ == "__main__":
    main() 