"""
Configuration module for the Ollama-GhidraMCP Bridge.
"""

import os
from pydantic import BaseModel, Field, validator, AnyHttpUrl
from pydantic_settings import BaseSettings
from typing import Optional, Dict, Any, List, ClassVar
import re

class ToolParameters(BaseModel):
    type: str = "object"
    properties: Dict[str, Any]
    required: List[str] = []

class Function(BaseModel):
    name: str
    description: str
    parameters: ToolParameters

class Tool(BaseModel):
    type: str = "function"
    function: Function

class OllamaConfig(BaseModel):
    """Configuration for the Ollama client."""
    base_url: AnyHttpUrl = Field(default="http://localhost:11434", env="OLLAMA_BASE_URL")
    # Default model. This is primarily set by the OLLAMA_MODEL environment variable.
    # llama3.1 is recommended for features like tool calling.
    model: str = Field(default="gemma3:27b", min_length=1, description="Model name cannot be empty", env="OLLAMA_MODEL")
    # Embedding model for vector operations
    embedding_model: str = Field(default="nomic-embed-text", min_length=1, description="Embedding model name cannot be empty", env="OLLAMA_EMBEDDING_MODEL")
    timeout: int = Field(ge=1, le=600, default=120, description="Timeout for requests in seconds (1-600)", env="OLLAMA_TIMEOUT")
    
    # Execution loop settings (INNER LOOP - tools per execution phase)
    max_execution_steps: int = Field(
        default=10,
        ge=1,
        le=50,
        description="Maximum tool executions per investigation (1-50)",
        env="MAX_EXECUTION_STEPS"
    )
    
    execution_loop_enabled: bool = Field(
        default=True,
        description="Enable multi-tool execution loop for comprehensive investigations",
        env="EXECUTION_LOOP_ENABLED"
    )
    
    # Agentic loop settings (OUTER LOOP - full planning→execution→analysis cycles)
    max_agentic_cycles: int = Field(
        default=3,
        ge=1,
        le=10,
        description="Maximum Planning→Execution→Analysis cycles per query (1-10)",
        env="MAX_AGENTIC_CYCLES"
    )
    
    agentic_loop_enabled: bool = Field(
        default=True,
        description="Enable multi-cycle agentic loop with goal evaluation and re-planning",
        env="AGENTIC_LOOP_ENABLED"
    )
    
    # LLM Logging Configuration
    llm_logging_enabled: bool = Field(default=False, env="LLM_LOGGING_ENABLED")
    llm_log_file: str = Field(default="logs/llm_interactions.log", env="LLM_LOG_FILE")
    llm_log_prompts: bool = Field(default=True, env="LLM_LOG_PROMPTS")
    llm_log_responses: bool = Field(default=True, env="LLM_LOG_RESPONSES")
    llm_log_tokens: bool = Field(default=True, env="LLM_LOG_TOKENS")
    llm_log_timing: bool = Field(default=True, env="LLM_LOG_TIMING")
    llm_log_format: str = Field(default="json", env="LLM_LOG_FORMAT")  # "json" or "text"
    
    # Live CoT View
    show_reasoning: bool = Field(default=True, description="Print Chain of Thought reasoning to stdout", env="OLLAMA_SHOW_REASONING")
    
    # Request Delay
    request_delay: float = Field(default=0.0, ge=0.0, description="Delay in seconds before each request", env="OLLAMA_REQUEST_DELAY")
    
    # Context Budget Management
    context_budget: int = Field(
        default=80000,
        ge=4000,
        le=200000,
        description="Maximum context tokens for prompts (4000-200000)",
        env="CONTEXT_BUDGET"
    )
    
    context_budget_execution: float = Field(
        default=0.5,
        ge=0.1,
        le=0.8,
        description="Fraction of context budget for execution results (0.1-0.8)",
        env="CONTEXT_BUDGET_EXECUTION"
    )
    
    enable_result_summarization: bool = Field(
        default=True,
        description="Use LLM to summarize large results instead of truncating",
        env="ENABLE_RESULT_SUMMARIZATION"
    )
    
    result_cache_enabled: bool = Field(
        default=True,
        description="Cache full results and pass references to AI",
        env="RESULT_CACHE_ENABLED"
    )
    
    tiered_context_enabled: bool = Field(
        default=True,
        description="Use tiered context (detailed recent, summarized older)",
        env="TIERED_CONTEXT_ENABLED"
    )
    
    @validator('model')
    def validate_model_name(cls, v):
        """Ensure model name follows expected patterns."""
        if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9_\-:.]*$', v):
            raise ValueError('Model name contains invalid characters. Use only alphanumeric, underscore, dash, colon, and dot.')
        return v
    
    @validator('model_map')
    def validate_model_phases(cls, v):
        """Validate that model_map contains valid phase names."""
        valid_phases = {'planning', 'execution', 'analysis', 'evaluation', 'review'}
        invalid_phases = set(v.keys()) - valid_phases
        if invalid_phases:
            raise ValueError(f'Invalid phases in model_map: {invalid_phases}. Valid phases are: {valid_phases}')
        return v
    
    # Model map for different phases of the simplified agentic loop
    # If a phase is not in the map or the value is empty, the default model will be used
    model_map: Dict[str, str] = Field(default_factory=lambda: {
        "planning": "",       # Model for planning phase 
        "execution": "",      # Model for tool execution phase
        "analysis": ""        # Model for final analysis phase
    })
    
    # Simplified system prompt
    default_system_prompt: str = """
    You are an AI assistant specialized in reverse engineering with Ghidra.
    You can help analyze binary files by executing commands through GhidraMCP.
    """
    
    # Define tools for Ollama's tool calling API
    tools: List[Tool] = Field(default_factory=lambda: [
        {
            "type": "function",
            "function": {
                "name": "list_methods",
                "description": "List all function names with pagination",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "offset": {"type": "integer", "description": "Offset to start from"},
                        "limit": {"type": "integer", "description": "Maximum number of results"}
                    }
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "list_classes",
                "description": "List all namespace/class names with pagination",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "offset": {"type": "integer", "description": "Offset to start from"},
                        "limit": {"type": "integer", "description": "Maximum number of results"}
                    }
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "decompile_function",
                "description": "Decompile a specific function by name",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "description": "Function name"}
                    },
                    "required": ["name"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "rename_function",
                "description": "Rename a function",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "old_name": {"type": "string", "description": "Current function name"},
                        "new_name": {"type": "string", "description": "New function name"}
                    },
                    "required": ["old_name", "new_name"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "rename_function_by_address",
                "description": "Rename function by address (IMPORTANT: Use numerical addresses only, not function names)",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "function_address": {"type": "string", "description": "Function address (numerical only, like '1800011a8')"},
                        "new_name": {"type": "string", "description": "New function name"}
                    },
                    "required": ["function_address", "new_name"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "list_functions",
                "description": "List all functions in the database with pagination. Returns function names and addresses. Use offset and limit to navigate through results. Returns pagination metadata showing total count and next page info.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "offset": {
                            "type": "integer",
                            "description": "Offset to start from (default: 0)"
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Maximum number of results (default: 100, recommended: 50-100)"
                        }
                    }
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "decompile_function_by_address",
                "description": "Decompile function at address",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "address": {"type": "string", "description": "Function address"}
                    },
                    "required": ["address"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "disassemble_function",
                "description": "Get assembly code (address: instruction; comment) for a function. IMPORTANT: Use numerical addresses only (e.g., '140003e50'), not function names.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "address": {"type": "string", "description": "Function address (numerical only, like '140003e50')"}
                    },
                    "required": ["address"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "analyze_function",
                "description": "Analyze a function including its code and all functions it calls",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "address": {"type": "string", "description": "Function address (optional)"}
                    }
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "list_imports",
                "description": "List imported symbols in the program",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "offset": {"type": "integer", "description": "Offset to start from"},
                        "limit": {"type": "integer", "description": "Maximum number of results"}
                    }
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "list_exports", 
                "description": "List exported functions/symbols in the program",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "offset": {"type": "integer", "description": "Offset to start from"},
                        "limit": {"type": "integer", "description": "Maximum number of results"}
                    }
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "list_segments",
                "description": "List all memory segments in the program",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "offset": {"type": "integer", "description": "Offset to start from"},
                        "limit": {"type": "integer", "description": "Maximum number of results"}
                    }
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "list_strings",
                "description": "List defined strings or search by substring (alias: string_search)",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "offset": {"type": "integer", "description": "Pagination offset"},
                        "limit": {"type": "integer", "description": "Maximum number of results"},
                        "filter": {"type": "string", "description": "Substring to filter results"}
                    }
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "search_functions_by_name",
                "description": "Search for functions by name substring",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Search query string"},
                        "offset": {"type": "integer", "description": "Offset to start from"},
                        "limit": {"type": "integer", "description": "Maximum number of results"}
                    },
                    "required": ["query"]
                }
            }
        },
        # --- Cross-reference helpers (new) ---
        {
            "type": "function",
            "function": {
                "name": "get_xrefs_to",
                "description": "List incoming cross-references (callers / data refs TO the given address)",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "address": {"type": "string", "description": "Target address in hexadecimal or numeric format"},
                        "offset": {"type": "integer", "description": "Pagination offset"},
                        "limit": {"type": "integer", "description": "Maximum number of results"}
                    },
                    "required": ["address"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "get_xrefs_from",
                "description": "List outgoing cross-references (callees / data refs FROM the given address)",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "address": {"type": "string", "description": "Source address in hexadecimal or numeric format"},
                        "offset": {"type": "integer", "description": "Pagination offset"},
                        "limit": {"type": "integer", "description": "Maximum number of results"}
                    },
                    "required": ["address"]
                }
            }
        },
        {
            "type": "function",
            "function": {
                "name": "get_function_xrefs",
                "description": "List cross-references to a function by its name",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "description": "Function name (e.g., 'FUN_00401234')"},
                        "offset": {"type": "integer", "description": "Pagination offset"},
                        "limit": {"type": "integer", "description": "Maximum number of results"}
                    },
                    "required": ["name"]
                }
            }
        },
        # --- Raw memory access (new) ---
        {
            "type": "function",
            "function": {
                "name": "read_bytes",
                "description": "Read raw bytes from memory at the specified address. Returns hex dump with ASCII representation or base64 encoded data. Useful for examining encrypted data, magic bytes, shellcode, or structure layouts.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "address": {"type": "string", "description": "Starting address in hex format (e.g., '10040fae0')"},
                        "length": {"type": "integer", "description": "Number of bytes to read (1-4096, default: 16)"},
                        "format": {"type": "string", "description": "Output format: 'hex' for hex dump (default), 'raw' for base64 encoded"}
                    },
                    "required": ["address"]
                }
            }
        },
        # --- Smart Analysis Tools (algorithmic, no LLM in loop) ---
        {
            "type": "function",
            "function": {
                "name": "scan_function_pointer_tables",
                "description": "Scan the binary for function pointer tables (vtables, dispatch tables, jump tables). Returns structured list of detected tables with addresses and function entries. Runs algorithmically without LLM intervention - useful for reachability analysis.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "min_table_entries": {"type": "integer", "description": "Minimum consecutive function pointers to qualify as a table (default: 3)"},
                        "pointer_size": {"type": "integer", "description": "Size of pointers in bytes: 8 for x64, 4 for x86 (default: 8)"},
                        "max_scan_size": {"type": "integer", "description": "Maximum bytes to scan per segment (default: 65536)"}
                    },
                    "required": []
                }
            }
        },
        # --- Context Management Tools ---
        {
            "type": "function",
            "function": {
                "name": "get_cached_result",
                "description": "Retrieve the full content of a previously summarized or truncated result. When large tool results are summarized due to context limits, they are cached with an ID like 'r5_decompile_function_abc123'. Use this to get the complete original content when the summary is not sufficient.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "result_id": {"type": "string", "description": "The cached result ID (e.g., 'r5_decompile_function_abc123')"}
                    },
                    "required": ["result_id"]
                }
            }
        }
    ])
    
    # System prompts for different model phases
    planning_system_prompt: str = """
    You are an expert Reverse Engineering Planning Agent.
    Your goal is to create a logical, step-by-step plan to investigate a binary using Ghidra.
    
    CRITICAL INSTRUCTION:
    - If you discover specific constants, keys, or IPs, output them as ARTIFACTS (see below).
    - Always batch discovery tools (list_imports, list_exports) in the first step.
    """
    
    execution_system_prompt: str = """
    You are a Tool Execution Assistant for Ghidra reverse engineering tasks.
    Your primary goal is to solve the user's task.
    
    ⚡ KNOWLEDGE MANAGEMENT:
    When you find a hardcoded string, encryption key, IP address, or important function address,
    output it on a separate line in this format:
    
    ARTIFACT: [category] key = value
    
    Examples:
    ARTIFACT: [network] C2_IP = 192.168.1.50
    ARTIFACT: [crypto] AES_KEY = 0xDEADBEEF
    ARTIFACT: [function] Decryptor = 0x180045000
    
    This saves the fact permanently (it will appear in "KNOWN ARTIFACTS" in future steps).
    
    ⚡ BATCHING & EFFICIENCY:
    - EXECUTE MULTIPLE TOOLS IN ONE RESPONSE.
    - Batch: list_imports, list_exports, list_strings.
    
    PROGRESSIVE EXECUTION PATTERN:
    1. **Capability Mapping**: (list_imports, list_segments) - Understand potential behavior.
    2. **Target Acquisition**: (list_strings filter="...", get_xrefs_to) - Find interesting entry points.
    3. **Deep Analysis**: (decompile_function, analyze_function) - Verify logic.
    4. **Action**: (rename_function) - Document findings.
    5. **Goal Completion**: (GOAL ACHIEVED)
    
    CRITICAL GUIDANCE:
    - **Capability First**: Don't assume malware; prove functionality.
    - **Batch Read-Only**: ALWAYS batch `list_*` and `get_*` calls together.
    - **Naming**: NEVER rename a function to the SAME NAME.
    - **Duplicates**: If a tool was just run, use `get_cached_result` or move to the next step.

    COMPLETION:
    - If the goal is met or no suitable tool exists, output "GOAL ACHIEVED"
    - Otherwise, execute the next appropriate tool(s).

    {{FUNCTION_CALL_BEST_PRACTICES}}
"""
    
    # Best practices for function calls
    FUNCTION_CALL_BEST_PRACTICES: ClassVar[str] = """# COMMON ERRORS TO AVOID:
# - DO use snake_case for function names.
# - DO batch read-only commands (list_*, get_*) together in a single response.
# - Parameter 'address' for tools like decompile_function_by_address refers to the numerical memory address.
# - DO NOT use the "FUN_" prefix for numerical addresses.
# - DO NOT use the "0x" prefix for numerical addresses.
# - DUPLICATE TOOL CALLS: Use get_cached_result(result_id=...) if a result is already available.
"""
    
    evaluation_system_prompt: str = """
    You are a Goal Evaluation Assistant for Ghidra reverse engineering tasks.
    Your task is to determine if the stated user goal has been achieved based on the tools executed and their results.

    The user's original goal was: **{{user_task_description}}**

    Review the full conversation history and ask yourself:
    1. Was the original goal fully and explicitly completed? For example, if the goal was to rename a function, was the `rename_function` or `rename_function_by_address` tool successfully executed?
    2. Merely analyzing a function or gathering information is not enough if the goal was to perform an action.
    3. Are there any errors that prevented the final step of goal completion?

    If the goal has been successfully and completely achieved, respond ONLY with "GOAL ACHIEVED".
    If the final action has not been taken or more steps are clearly needed to satisfy the user's request, respond ONLY with "GOAL NOT ACHIEVED".
    """
    
    analysis_system_prompt: str = """
    You are an analysis assistant specialized in reverse engineering with Ghidra.
    USER GOAL: **{user_task_description}**
    Your task is to analyze the results of the tool executions and provide a comprehensive
    answer to the user's query. Focus on clear explanations and actionable insights.
    
    When presenting results:
    1. For function listings, show at least some sample entries, not just totals
    2. For decompiled code, include the relevant portions with explanations
    3. Always include specific details from the tool results, not just summaries
    4. Format your output for readability using proper spacing, headers, and bullet points
    
    Prefix your final answer with "FINAL RESPONSE:" to mark the conclusion of your analysis.
    """
    
    # System prompts for different phases
    phase_system_prompts: Dict[str, str] = Field(default_factory=lambda: {
        "planning": "",    # If empty, use planning_system_prompt
        "execution": "",   # If empty, use execution_system_prompt
        "analysis": "",    # If empty, use analysis_system_prompt
        "evaluation": "",  # If empty, use evaluation_system_prompt
        "review": ""       # If empty, use analysis_system_prompt for review
    })

class GhidraMCPConfig(BaseModel):
    """Configuration for the GhidraMCP client."""
    base_url: AnyHttpUrl = Field(default="http://localhost:8080", env="GHIDRA_BASE_URL")
    timeout: int = Field(ge=1, le=300, default=30, description="Timeout in seconds (1-300)", env="GHIDRA_TIMEOUT")
    mock_mode: bool = Field(default=False, env="GHIDRA_MOCK_MODE")
    api_path: str = Field(default="", description="API path for GhidraMCP", env="GHIDRA_API_PATH")
    
    @validator('api_path')
    def validate_api_path(cls, v):
        """Validate API path format."""
        if v and not v.startswith('/'):
            raise ValueError('API path must start with "/" or be empty')
        return v

class SessionHistoryConfig(BaseModel):
    """Configuration for session history."""
    enabled: bool = True
    storage_path: str = Field(default="data/ollama_ghidra_session_history.jsonl", description="Path to session history file")
    max_sessions: int = Field(ge=1, le=100000, default=1000, description="Maximum number of sessions to store (1-100000)")
    auto_summarize: bool = True
    use_vector_embeddings: bool = False
    vector_db_path: str = Field(default="data/vector_db", description="Path to vector database directory")
    
    @validator('storage_path')
    def validate_storage_path(cls, v):
        """Validate storage path format."""
        if not v.strip():
            raise ValueError('Storage path cannot be empty')
        if not v.endswith('.jsonl'):
            raise ValueError('Storage path must end with .jsonl extension')
        return v.strip()
    
    @validator('vector_db_path')
    def validate_vector_db_path(cls, v):
        """Validate vector database path."""
        if not v.strip():
            raise ValueError('Vector database path cannot be empty')
        return v.strip()

class BridgeConfig(BaseSettings):
    """Root configuration model, loading from environment variables."""
    ollama: OllamaConfig = Field(default_factory=OllamaConfig)
    ghidra: GhidraMCPConfig = Field(default_factory=GhidraMCPConfig)
    session_history: SessionHistoryConfig = Field(default_factory=SessionHistoryConfig)
    
    log_level: str = Field(default="INFO", description="Logging level")
    log_file: str = Field(default="bridge.log", description="Log file path")
    log_console: bool = True
    log_file_enabled: bool = True
    context_limit: int = Field(ge=1, le=50, default=25, description="Context limit for conversations (1-50)")
    max_steps: int = Field(ge=1, le=100, default=5, description="Maximum steps for task execution (1-100)")
    
    # CAG Configuration
    cag_enabled: bool = True
    cag_knowledge_cache_enabled: bool = True
    cag_session_cache_enabled: bool = True
    cag_token_limit: int = Field(ge=100, le=50000, default=2000, description="CAG token limit (100-50000)")

    # Enable or disable Context-Augmented Generation
    enable_cag: bool = True
    
    # Enable or disable Knowledge Base
    enable_knowledge_base: bool = True
    
    # Knowledge Base directory
    knowledge_base_dir: str = Field(default="knowledge_base", description="Knowledge base directory path")
    
    # Enable or disable review phase
    enable_review: bool = True
    
    @validator('log_level')
    def validate_log_level(cls, v):
        """Validate log level."""
        valid_levels = {'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'}
        v_upper = v.upper()
        if v_upper not in valid_levels:
            raise ValueError(f'log_level must be one of {valid_levels}')
        return v_upper
    
    @validator('log_file')
    def validate_log_file(cls, v):
        """Validate log file path."""
        if not v.strip():
            raise ValueError('Log file path cannot be empty')
        if not v.endswith('.log'):
            raise ValueError('Log file must have .log extension')
        return v.strip()
    
    @validator('knowledge_base_dir')
    def validate_knowledge_base_dir(cls, v):
        """Validate knowledge base directory."""
        if not v.strip():
            raise ValueError('Knowledge base directory cannot be empty')
        return v.strip()

    model_config = {
        'env_prefix': '', # No prefix for env vars
        'case_sensitive': False,
        # Nested models will also be populated from env vars
        # e.g. OLLAMA_BASE_URL will populate ollama.base_url
        'env_nested_delimiter': '_',
        'env_file': '.env',
        'env_file_encoding': 'utf-8',
        'extra': 'ignore'
    }

# Helper function to get the config instance
_config_instance: Optional[BridgeConfig] = None

def get_config() -> BridgeConfig:
    """Returns a singleton instance of the BridgeConfig."""
    global _config_instance
    if _config_instance is None:
        # Explicitly load .env file before creating config
        try:
            from dotenv import load_dotenv
            load_dotenv('.env')
        except ImportError:
            # python-dotenv not available, try to continue without it
            pass
        
        # Create config with explicit environment loading
        import os
        config_data = {}
        
        # Manually map environment variables to config structure
        if os.getenv('OLLAMA_BASE_URL'):
            # Ensure base URL doesn't have trailing slash
            base_url = os.getenv('OLLAMA_BASE_URL').rstrip('/')
            config_data['ollama'] = {'base_url': base_url}
        if os.getenv('OLLAMA_MODEL'):
            if 'ollama' not in config_data:
                config_data['ollama'] = {}
            config_data['ollama']['model'] = os.getenv('OLLAMA_MODEL')
        
        # Load LLM logging configuration
        if os.getenv('LLM_LOGGING_ENABLED'):
            if 'ollama' not in config_data:
                config_data['ollama'] = {}
            config_data['ollama']['llm_logging_enabled'] = os.getenv('LLM_LOGGING_ENABLED').lower() == 'true'
        if os.getenv('LLM_LOG_FILE'):
            if 'ollama' not in config_data:
                config_data['ollama'] = {}
            config_data['ollama']['llm_log_file'] = os.getenv('LLM_LOG_FILE')
        if os.getenv('LLM_LOG_FORMAT'):
            if 'ollama' not in config_data:
                config_data['ollama'] = {}
            config_data['ollama']['llm_log_format'] = os.getenv('LLM_LOG_FORMAT')
        if os.getenv('LLM_LOG_PROMPTS'):
            if 'ollama' not in config_data:
                config_data['ollama'] = {}
            config_data['ollama']['llm_log_prompts'] = os.getenv('LLM_LOG_PROMPTS').lower() == 'true'
        if os.getenv('LLM_LOG_RESPONSES'):
            if 'ollama' not in config_data:
                config_data['ollama'] = {}
            config_data['ollama']['llm_log_responses'] = os.getenv('LLM_LOG_RESPONSES').lower() == 'true'
        if os.getenv('LLM_LOG_TOKENS'):
            if 'ollama' not in config_data:
                config_data['ollama'] = {}
            config_data['ollama']['llm_log_tokens'] = os.getenv('LLM_LOG_TOKENS').lower() == 'true'
        if os.getenv('LLM_LOG_TIMING'):
            if 'ollama' not in config_data:
                config_data['ollama'] = {}
            config_data['ollama']['llm_log_timing'] = os.getenv('LLM_LOG_TIMING').lower() == 'true'
        
        # Load phase-specific models into model_map
        model_map = {}
        if os.getenv('OLLAMA_MODEL_PLANNING'):
            model_map['planning'] = os.getenv('OLLAMA_MODEL_PLANNING')
        if os.getenv('OLLAMA_MODEL_EXECUTION'):
            model_map['execution'] = os.getenv('OLLAMA_MODEL_EXECUTION')
        if os.getenv('OLLAMA_MODEL_ANALYSIS'):
            model_map['analysis'] = os.getenv('OLLAMA_MODEL_ANALYSIS')
        if os.getenv('OLLAMA_MODEL_EVALUATION'):
            model_map['evaluation'] = os.getenv('OLLAMA_MODEL_EVALUATION')
        if os.getenv('OLLAMA_MODEL_REVIEW'):
            model_map['review'] = os.getenv('OLLAMA_MODEL_REVIEW')
            
        if model_map:
            if 'ollama' not in config_data:
                config_data['ollama'] = {}
            config_data['ollama']['model_map'] = model_map
        
        # Load execution loop settings
        if os.getenv('MAX_EXECUTION_STEPS'):
            if 'ollama' not in config_data:
                config_data['ollama'] = {}
            try:
                config_data['ollama']['max_execution_steps'] = int(os.getenv('MAX_EXECUTION_STEPS'))
            except ValueError:
                pass  # Use default if invalid value
        
        if os.getenv('EXECUTION_LOOP_ENABLED'):
            if 'ollama' not in config_data:
                config_data['ollama'] = {}
            config_data['ollama']['execution_loop_enabled'] = os.getenv('EXECUTION_LOOP_ENABLED').lower() == 'true'
        
        # Load agentic loop settings
        if os.getenv('MAX_AGENTIC_CYCLES'):
            if 'ollama' not in config_data:
                config_data['ollama'] = {}
            try:
                config_data['ollama']['max_agentic_cycles'] = int(os.getenv('MAX_AGENTIC_CYCLES'))
            except ValueError:
                pass  # Use default if invalid value
        
        if os.getenv('AGENTIC_LOOP_ENABLED'):
            if 'ollama' not in config_data:
                config_data['ollama'] = {}
            config_data['ollama']['agentic_loop_enabled'] = os.getenv('AGENTIC_LOOP_ENABLED').lower() == 'true'
        
        # Load Ollama timeout setting
        if os.getenv('OLLAMA_TIMEOUT'):
            if 'ollama' not in config_data:
                config_data['ollama'] = {}
            try:
                config_data['ollama']['timeout'] = int(os.getenv('OLLAMA_TIMEOUT'))
            except ValueError:
                pass  # Use default if invalid value
        
        # Load Ollama request delay setting
        if os.getenv('OLLAMA_REQUEST_DELAY'):
            if 'ollama' not in config_data:
                config_data['ollama'] = {}
            try:
                config_data['ollama']['request_delay'] = float(os.getenv('OLLAMA_REQUEST_DELAY'))
            except ValueError:
                pass  # Use default if invalid value
        
        # Load Ollama embedding model
        if os.getenv('OLLAMA_EMBEDDING_MODEL'):
            if 'ollama' not in config_data:
                config_data['ollama'] = {}
            config_data['ollama']['embedding_model'] = os.getenv('OLLAMA_EMBEDDING_MODEL')
        
        # Load show reasoning setting
        if os.getenv('OLLAMA_SHOW_REASONING'):
            if 'ollama' not in config_data:
                config_data['ollama'] = {}
            config_data['ollama']['show_reasoning'] = os.getenv('OLLAMA_SHOW_REASONING').lower() == 'true'
        
        # Load context budget settings
        if os.getenv('CONTEXT_BUDGET'):
            if 'ollama' not in config_data:
                config_data['ollama'] = {}
            try:
                config_data['ollama']['context_budget'] = int(os.getenv('CONTEXT_BUDGET'))
            except ValueError:
                pass  # Use default if invalid value
        
        if os.getenv('CONTEXT_BUDGET_EXECUTION'):
            if 'ollama' not in config_data:
                config_data['ollama'] = {}
            try:
                config_data['ollama']['context_budget_execution'] = float(os.getenv('CONTEXT_BUDGET_EXECUTION'))
            except ValueError:
                pass  # Use default if invalid value
        
        # Load result handling settings
        if os.getenv('ENABLE_RESULT_SUMMARIZATION'):
            if 'ollama' not in config_data:
                config_data['ollama'] = {}
            config_data['ollama']['enable_result_summarization'] = os.getenv('ENABLE_RESULT_SUMMARIZATION').lower() == 'true'
        
        if os.getenv('RESULT_CACHE_ENABLED'):
            if 'ollama' not in config_data:
                config_data['ollama'] = {}
            config_data['ollama']['result_cache_enabled'] = os.getenv('RESULT_CACHE_ENABLED').lower() == 'true'
        
        if os.getenv('TIERED_CONTEXT_ENABLED'):
            if 'ollama' not in config_data:
                config_data['ollama'] = {}
            config_data['ollama']['tiered_context_enabled'] = os.getenv('TIERED_CONTEXT_ENABLED').lower() == 'true'
            
        # Load Ghidra configuration
        if os.getenv('GHIDRA_BASE_URL'):
            config_data['ghidra'] = {'base_url': os.getenv('GHIDRA_BASE_URL')}
        
        if os.getenv('GHIDRA_TIMEOUT'):
            if 'ghidra' not in config_data:
                config_data['ghidra'] = {}
            try:
                config_data['ghidra']['timeout'] = int(os.getenv('GHIDRA_TIMEOUT'))
            except ValueError:
                pass  # Use default if invalid value
        
        if os.getenv('GHIDRA_MOCK_MODE'):
            if 'ghidra' not in config_data:
                config_data['ghidra'] = {}
            config_data['ghidra']['mock_mode'] = os.getenv('GHIDRA_MOCK_MODE').lower() == 'true'
        
        if os.getenv('GHIDRA_API_PATH'):
            if 'ghidra' not in config_data:
                config_data['ghidra'] = {}
            config_data['ghidra']['api_path'] = os.getenv('GHIDRA_API_PATH')
            
        _config_instance = BridgeConfig(**config_data)
    return _config_instance 