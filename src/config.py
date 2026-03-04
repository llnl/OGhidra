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
    llm_logging_enabled: bool = Field(default=True, env="LLM_LOGGING_ENABLED")
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
    
    # Request Retries
    max_retries: int = Field(default=3, ge=0, description="Maximum number of retries for transient errors", env="OLLAMA_MAX_RETRIES")
    
    # Context Budget Management
    context_budget: int = Field(
        default=80000,
        ge=4000,
        le=2000000,
        description="Maximum context tokens for prompts (4000-2000000)",
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
    
    # Sliding Window & Tiered Context Limits
    # These scale proportionally to CONTEXT_BUDGET (chars ≈ tokens × 4)
    max_detailed_steps: int = Field(
        default=10,
        ge=1,
        le=50,
        description="Maximum execution steps to keep in full detail (sliding window)",
        env="MAX_DETAILED_STEPS"
    )
    
    current_loop_max_chars: int = Field(
        default=4000,
        ge=100,
        le=50000,
        description="Max chars for current loop results (full details)",
        env="CURRENT_LOOP_MAX_CHARS"
    )
    
    prev_loop_max_chars: int = Field(
        default=800,
        ge=50,
        le=10000,
        description="Max chars for previous loop results (bullet summaries)",
        env="PREV_LOOP_MAX_CHARS"
    )
    
    older_loop_max_chars: int = Field(
        default=200,
        ge=20,
        le=2000,
        description="Max chars for older loop results (one-line refs)",
        env="OLDER_LOOP_MAX_CHARS"
    )
    
    # Hybrid Context Management Settings
    top_n_per_category: int = Field(
        default=10,
        ge=1,
        le=50,
        description="Maximum items per result category in ranked results",
        env="TOP_N_PER_CATEGORY"
    )
    
    enable_correlation_hints: bool = Field(
        default=True,
        description="Build cross-tool address correlations for analysis",
        env="ENABLE_CORRELATION_HINTS"
    )
    
    min_correlation_mentions: int = Field(
        default=2,
        ge=2,
        le=5,
        description="Minimum tool mentions to surface a correlation",
        env="MIN_CORRELATION_MENTIONS"
    )
    
    # Interactive Execution Gate (OpenCode-inspired)
    execution_gate_enabled: bool = Field(
        default=True,
        description="Enable interactive execution gate for pause/review during loops",
        env="EXECUTION_GATE_ENABLED"
    )
    
    gate_on_artifact: bool = Field(
        default=True,
        description="Pause when critical artifact found in tool results",
        env="GATE_ON_ARTIFACT"
    )
    
    gate_on_repetition: bool = Field(
        default=True,
        description="Pause on N identical tool calls (doom-loop detection)",
        env="GATE_ON_REPETITION"
    )
    
    gate_repetition_threshold: int = Field(
        default=3,
        ge=2,
        le=10,
        description="How many identical calls before triggering repetition gate",
        env="GATE_REPETITION_THRESHOLD"
    )
    
    gate_on_high_risk_tool: bool = Field(
        default=False,
        description="Pause before destructive tools (rename_function, etc.)",
        env="GATE_ON_HIGH_RISK_TOOL"
    )
    
    gate_auto_resume_timeout: int = Field(
        default=0,
        ge=0,
        description="Seconds before auto-resuming after gate (0 = wait forever)",
        env="GATE_AUTO_RESUME_TIMEOUT"
    )
    
    # Session Compaction (OpenCode-inspired)
    compaction_enabled: bool = Field(
        default=True,
        description="Enable smart context pruning to prevent overflow",
        env="COMPACTION_ENABLED"
    )
    
    compaction_threshold: float = Field(
        default=0.75,
        ge=0.3,
        le=0.95,
        description="Context usage fraction that triggers compaction (0.3-0.95)",
        env="COMPACTION_THRESHOLD"
    )
    
    compaction_auto: bool = Field(
        default=True,
        description="Auto-compact between agentic cycles when threshold exceeded",
        env="COMPACTION_AUTO"
    )
    
    # Enable or disable Context-Augmented Generation
    enable_cag: bool = True
    
    # Review Phase Configuration
    review_thoroughness: str = Field(
        default="standard",
        description="Review depth: 'basic', 'standard', or 'thorough'",
        env="REVIEW_THOROUGHNESS"
    )
    
    @validator('review_thoroughness')
    def validate_review_thoroughness(cls, v):
        """Validate review thoroughness level."""
        valid_levels = {'basic', 'standard', 'thorough'}
        v_lower = v.lower()
        if v_lower not in valid_levels:
            raise ValueError(f'review_thoroughness must be one of {valid_levels}')
        return v_lower
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
                "description": "Decompile a specific function by name. Returns lines of code with pagination.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string", "description": "Function name"},
                        "offset": {
                            "type": "integer",
                            "description": "Line number offset to start reading from (default: 0)",
                            "default": 0
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Maximum number of lines to return (default: 500)",
                            "default": 500
                        }
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
                "description": "Decompile function at address. Returns lines of code with pagination.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "address": {"type": "string", "description": "Function address"},
                        "offset": {
                            "type": "integer",
                            "description": "Line number offset to start reading from (default: 0)",
                            "default": 0
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Maximum number of lines to return (default: 500)",
                            "default": 500
                        }
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
                "description": "List imported symbols in the program. Returns name, address, reference count, and caller names.",
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
                        "name": {"type": "string", "description": "Function name (e.g., 'FUN_401000')"},
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
                        "address": {"type": "string", "description": "Starting address in hex format (e.g., '401000')"},
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
        },
        {
            "type": "function",
            "function": {
                "name": "search_function_summaries",
                "description": "🔍 PRIMARY DISCOVERY TOOL when Hybrid Search enabled. Search through analyzed function summaries using hybrid keyword + semantic search. USE THIS FIRST for function discovery before list_functions, decompile, or other tools. STRATEGY: Run 2-3 related queries with different keyword combinations. Use top_k=15-20 to get comprehensive results. Focus on top-5 results, scan remaining for relevant keywords. Available when function summaries loaded and 'Hybrid Search' checkbox enabled in UI.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Search query with keywords or concepts. Use multiple related terms for better results. Examples: 'network socket connection', 'file read write operation', 'string decode transform', 'memory allocation buffer'"},
                        "search_type": {"type": "string", "enum": ["hybrid", "keyword", "semantic", "name"], "description": "Search mode: 'hybrid' (keyword+semantic, default), 'keyword' (grep-style), 'semantic' (RAG only), 'name' (exact function name)", "default": "hybrid"},
                        "top_k": {"type": "integer", "description": "Number of results to return. Use 5-10 for focused searches, 15-20 for comprehensive discovery. Default: 5", "default": 5}
                    },
                    "required": ["query"]
                }
            }
        }
    ])
    
    # System prompts for different model phases
    # NOTE: Deployment vulnerability guidance is intentionally excluded from the default
    # planning prompt and should only be enabled when task_mode is vuln-focused.
    planning_system_prompt: str = """
    You are an expert Reverse Engineering Planning Agent.
    Your goal is to create a logical, step-by-step plan to investigate a binary using Ghidra.

    ## Planning Rules
    1. **Structure**: Break down the goal into logical, sequential steps.
    2. **Tools**: Explicitly state which tool(s) will be used for each step.
    3. **Conditionals**: If a step depends on findings from a previous step, note that.
       (e.g. "If imports show network activity, then list network-related strings")
    4. **Completeness**: Ensure the plan covers all aspects needed to achieve the goal.
    5. **Verification**: Include a final step to verify findings if possible.

    CRITICAL INSTRUCTION:
    - If you discover specific constants, keys, or IPs, output them as ARTIFACTS.
    - Always batch discovery tools (list_imports, list_exports) in the first step.

    User Goal: {user_task_description}
    """

    # Vuln-focused planning prompt (includes deployment vulnerability checks).
    planning_system_prompt_vuln: str = """
    You are an expert Reverse Engineering Planning Agent.
    Your goal is to create a logical, step-by-step plan to investigate a binary using Ghidra.
    
    ## CRITICAL: Deployment Vulnerability Awareness
    
    Your vulnerability search must cover BOTH layers:
    
    **Layer 1: Code Vulnerabilities**
    - Memory: buffer overflow, use-after-free, integer overflow
    - Injection: SQL, command, format string
    - Logic: authentication bypass, race conditions
    
    **Layer 2: Deployment Vulnerabilities**
    - Service Issues: unquoted paths, weak permissions, privilege escalation
    - Executable Loading: DLL hijacking, PATH manipulation
    - Registry: weak ACLs, auto-run persistence
    
    MANDATORY DEPLOYMENT CHECKS:
    
    1. Is this a Windows service?
       - Search imports for: StartServiceCtrlDispatcher
       - If YES → Add service security analysis to plan
    
    2. Does it load executables/DLLs?
       - Search imports for: LoadLibrary, CreateProcess, ShellExecute
       - If YES → Plan to analyze what/where it loads
    
    3. Are there hardcoded paths?
       - Search strings for: "C:\\Program Files", ".exe", ".dll"
       - If YES → Check for proper validation and quoting
    
    ## Planning Rules
    1. **Structure**: Break down the goal into logical, sequential steps.
    2. **Tools**: Explicitly state which tool(s) will be used for each step.
    3. **Conditionals**: If a step depends on findings from a previous step, note that.
       (e.g. "If imports show network activity, then list network-related strings")
    4. **Completeness**: Ensure the plan covers all aspects needed to achieve the goal.
    5. **Verification**: Include a final step to verify findings if possible.
    
    CRITICAL INSTRUCTION:
    - If you discover specific constants, keys, or IPs, output them as ARTIFACTS.
    - Always batch discovery tools (list_imports, list_exports) in the first step.
    
    User Goal: {user_task_description}
    """
    
    # Execution system prompt for TASK MODE ON (vulnerability/malware analysis)
    execution_system_prompt_task_mode: str = """
    You are a Tool Execution Assistant for Ghidra reverse engineering tasks.
    Your primary goal is to solve the user's task through systematic threat hunting.
    
    🔥 HYBRID SEARCH STRATEGY (When Enabled - CHECK USER PROMPT)
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    
    When hybrid search is available, you MUST use search_function_summaries with 
    BEHAVIORAL/SEMANTIC queries as your PRIMARY discovery method.
    
    ✅ CORRECT Query Construction (Describe behavior, not keywords):
    
    **Security File Access Patterns:**
    • "Find code that resolves system/security file paths dynamically to evade static analysis"
    • "Locate functions accessing protected resources with obfuscated path construction"
    • "Identify code reading sensitive data stores using misleading function names"
    
    **String Obfuscation Patterns:**
    • "Find functionality that decodes or deobfuscates strings at runtime"
    • "Locate code that builds strings character-by-character or via XOR/encoding"
    • "Identify stack-based string construction to hide literal values"
    
    **Network/C2 Patterns:**
    • "Find code establishing network connections with dynamically resolved endpoints"
    • "Locate functions performing data exfiltration disguised as legitimate traffic"
    • "Identify callback mechanisms using encoded URLs or IP addresses"
    
    **Persistence/Execution Patterns:**
    • "Find code that modifies system configuration for persistence"
    • "Locate functions injecting into processes or loading code dynamically"
    • "Identify privilege escalation attempts through token manipulation or API abuse"
    
    **Evasion Patterns:**
    • "Find anti-analysis techniques: debugger detection, VM detection, timing checks"
    • "Locate code that patches or hooks security APIs"
    • "Identify sandbox evasion through environment fingerprinting"
    
    ❌ WRONG Query Construction (Keyword lists without context):
    • "string concatenate build construct path"
    • "shadow password authentication credential"
    • "decode decrypt xor encode"
    • "file open fopen access check"
    
    🎯 Query Construction Rules:
    1. **Describe BEHAVIOR** - What does the code do? (not just keywords)
    2. **Include intent/context** - Why would it do this? (obfuscation, theft, evasion, persistence)
    3. **Add concrete examples** - "such as credential files", "e.g., C2 communication"
    4. **Mention evasion techniques** - "misleading names", "obfuscated", "dynamic construction"
    5. **Stay general enough** - Don't match exact strings, describe patterns
    
    📊 Usage Strategy:
    • Run 2-3 related behavioral queries with different framings
    • Use top_k=15-20 for comprehensive discovery
    • Focus on top-5 results, scan remaining for relevant patterns
    • Always decompile top candidates to verify behavior
    • Cross-validate with get_xrefs_to, list_strings for confirmation
    
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    
    🔍 MANDATORY INVESTIGATION METHODOLOGY
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    
    For EVERY suspicious finding, you MUST complete all 4 steps before moving on:
    
    1️⃣  DISCOVER → Search with targeted filters (limit ≤20)
       ✅ CORRECT: list_strings(filter="keyword", limit=15)
       ❌ WRONG:   list_strings(filter="", limit=5000)
       
       Use targeted searches with filters. Bulk dumps overwhelm context.
    
    2️⃣  LOCATE → Find cross-references
       Example: get_xrefs_to(address="0x12345", limit=10)
       
       Don't just discover - find which functions use it.
    
    3️⃣  TRACE → Decompile the calling function (MANDATORY)
       Example: decompile_function_by_address(address="0x12346")
       
       This is REQUIRED. Never report findings without decompilation.
    
    4️⃣  VERIFY → Prove malicious intent from decompiled code
       Example: "Function at 0x12346 reads environment variable, 
                concatenates with user-controlled path, executes via system()"
       
       Provide: addresses, API calls, data flows, concrete evidence.
    
    ⚠️  CRITICAL RULES:
    • NEVER use limit>20 for bulk operations (list_imports, list_strings, etc.)
    • NEVER skip decompilation (step 3) - required for verification
    • NEVER report findings without code evidence (step 4)
    • ALWAYS provide addresses and code snippets from decompiled functions
    • NEVER claim "GOAL ACHIEVED" without completing all 4 steps for each finding
    
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    
    🎯 MULTI-LAYER THREAT DETECTION
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    
    Your analysis must cover BOTH layers:
    
    **Layer 1: Code-Level Threats**
    - Memory corruption: buffer overflow, use-after-free, integer overflow
    - Injection flaws: command injection, SQL injection, format strings
    - Logic bugs: authentication bypass, race conditions, validation errors
    
    **Layer 2: Deployment/Configuration Threats**
    - Unsafe file operations: unvalidated paths, insecure permissions
    - Dynamic loading risks: DLL/SO hijacking, LD_PRELOAD abuse, unsafe search paths
    - Service/daemon issues: weak permissions, unquoted paths, misconfiguration
    - Startup/persistence: auto-run mechanisms without validation
    
    **Investigation Coverage Areas:**
    
    1. **System Resource Access**
       - Config files: /etc/*, registry keys, .ini/.conf files, app settings
       - Credential stores: password files, token caches, keychain access
       - Critical paths: system directories, application data folders
    
    2. **Network Operations**
       - Connection APIs: socket, connect, WSAConnect, URLDownload, WinHTTP/libcurl
       - DNS operations: gethostbyname, getaddrinfo, DnsQuery, resolver functions
       - Protocol indicators: HTTP headers, user-agents, custom protocols
    
    3. **Execution & Persistence**
       - Process creation: fork/exec, CreateProcess, system(), popen()
       - Code loading: dlopen, LoadLibrary, mmap+exec, VirtualAlloc patterns
       - Persistence: startup folders, scheduled tasks, cron, service registration
    
    4. **Privilege & Access**
       - Elevation: sudo, UAC bypass, token manipulation, setuid patterns
       - Access control: chmod, ACL modification, privilege APIs
       - Impersonation: setuid, ImpersonateLoggedOnUser, credential delegation
    
    5. **Evasion & Anti-Analysis**
       - Debugger detection: ptrace, IsDebuggerPresent, timing checks
       - VM detection: CPUID, registry artifacts, process/file indicators
       - Obfuscation: packed sections, encrypted strings, indirect calls
    
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    
    ⚡ BATCHING & EFFICIENCY:
    - EXECUTE MULTIPLE TOOLS IN ONE RESPONSE
    - Batch read-only operations: list_imports, list_exports, list_strings
    - ALWAYS batch `list_*` and `get_*` calls together

    ⚡ VERIFY FINDINGS:
    - CAUTION: Do not assume an API is malicious just because it exists
    - PROVE IT: Verify arguments, contexts, and behavioral patterns
    
    🎯 RESPONSE FORMAT & TOOL EXECUTION
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    
    When executing tools, use this format:
    
    REASONING: [Brief explanation of WHY you're executing these tools]
    EXECUTE: tool_name(param1="value1", param2="value2")
    EXECUTE: another_tool(param1="value1")
    
    Rules:
    - Explain your reasoning FIRST (what are you trying to discover?)
    - Execute tools using exact format above
    - String values MUST be in double quotes
    - Numerical values should NOT be quoted
    - Can execute multiple tools in one response (batch related operations)
    
    Completion signals:
    - When goal is achieved: "INVESTIGATION COMPLETE"
    
    ⚠️  CRITICAL: NEVER output "INVESTIGATION COMPLETE" or "GOAL ACHIEVED" 
        in the SAME response as EXECUTE commands. Wait for results first.
    
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    
    CRITICAL GUIDANCE:
    - **Evidence-Based**: Report what you observe, not what you assume
    - **Naming**: NEVER rename a function to the SAME NAME
    - **Duplicates**: If a tool was just run, use `get_cached_result` or move to next step

    ⚠️ NEVER RETURN AN EMPTY RESPONSE:
    - If you cannot determine the next step, explain WHY you are stuck
    - If investigation hit a dead end, explain what was tried and why it failed
    - If goal is complete, say "INVESTIGATION COMPLETE" with summary

    {{FUNCTION_CALL_BEST_PRACTICES}}
"""
    
    # Execution system prompt for TASK MODE OFF (simple queries, direct answers)
    execution_system_prompt: str = """
    You are a Tool Execution Assistant for Ghidra reverse engineering tasks.
    Your goal is to answer the user's question clearly and efficiently.
    
    ⚡ SIMPLE & DIRECT APPROACH:
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    
    1. **Understand the Question**: What specific information does the user need?
    2. **Execute Relevant Tools**: Use only the tools needed to answer the question
    3. **Provide Clear Answer**: Explain what you found in simple terms
    
    KEY PRINCIPLES:
    • Focus ONLY on what the user asked
    • Don't over-investigate or search for vulnerabilities unless asked
    • Use minimal tool calls to get the answer
    • Keep limits reasonable (10-20 for discovery, more if needed for specific analysis)
    • Batch related tools together (list_imports + list_exports + list_strings)

    🔍 FUNCTION SUMMARY SEARCH - PRIMARY DISCOVERY TOOL
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    
    When Hybrid Search is enabled (vectors loaded), use search_function_summaries 
    as your PRIMARY tool for function discovery BEFORE list_functions, decompile, etc.
    
    USAGE STRATEGY:
    
    1. USE MULTIPLE RELATED QUERIES - Cast a wide net with different keyword combinations:
       EXECUTE: search_function_summaries(query="primary concept keywords", search_type="hybrid", top_k=20)
       EXECUTE: search_function_summaries(query="related concept keywords", search_type="hybrid", top_k=20)
       EXECUTE: search_function_summaries(query="alternative terminology", search_type="hybrid", top_k=20)
    
    2. CHOOSE APPROPRIATE top_k:
       • Focused searches: top_k=5-10
       • Comprehensive discovery: top_k=15-20 (to get broader coverage)
    
    3. SELECT SEARCH TYPE:
       • hybrid (default): Keyword + semantic - best for most cases
       • keyword: Exact term matching - use when you know specific strings
       • semantic: Behavior-based - use for conceptual searches
       • name: Function name matching
    
    INTERPRETING RESULTS:
    • Focus on top-5 results for detailed investigation
    • Scan remaining results for relevant keywords related to your goal
    • Decompile promising candidates for verification
    • Cross-validate with get_xrefs_to, list_strings, and other tools
    
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    
    EXAMPLES:
    
    Q: "What does function FUN_401000 do?"
    A: EXECUTE: decompile_function_by_address(address="401000")
       Then explain the function's behavior based on the code.
    
    Q: "Find the main function"
    A: EXECUTE: search_functions_by_name(query="main", offset=0, limit=10)
       Then identify which one is the entry point.
    
    Q: "What imports does this binary use?"
    A: EXECUTE: list_imports(offset=0, limit=50)
       Then summarize the key imports and their purpose.
    
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    
    ⚡ BATCHING:
    Execute multiple related tools in one response when possible.
    
    COMPLETION:
    - When you have enough information to answer the user's question, say "INVESTIGATION COMPLETE"
    - Otherwise, execute the next tool(s) you need
    
    COMPLETION RULES:
    - NEVER output "INVESTIGATION COMPLETE" in the same response as EXECUTE commands
    - NEVER output "GOAL ACHIEVED" in the same response as EXECUTE commands
    - After executing tools, WAIT for results, analyze them, THEN decide
    - Pattern:
      ✅ CORRECT: EXECUTE tools → (wait for results) → analyze → answer or continue
      ❌ WRONG:   EXECUTE tools + "INVESTIGATION COMPLETE" in same response

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
    
    # HTML Report Generation Prompt
    html_report_generation_prompt: str = """
You are generating an HTML vulnerability report based on binary analysis findings.

## OUTPUT FORMAT
You MUST output ONLY valid JSON (no markdown, no explanation) with this structure:
```json
{
  "metadata": {
    "severity": "CRITICAL|HIGH|MEDIUM|LOW",
    "subtitle": "Short description of the analysis type"
  },
  "sections": [
    {
      "id": "section_id",
      "title": "Section Title",
      "icon": "📋",
      "content_type": "html",
      "content": "<div>HTML content here</div>"
    }
  ]
}
```

## REQUIRED SECTIONS (include all that apply based on findings):

1. **executive_summary** - Overview with impact assessment
   - icon: 📋
   - Summarize key findings, risk level, and recommendations

2. **statistics** - Key metrics as JSON for stat cards
   - icon: 📊
   - content_type: "stats"
   - content: JSON array like [{"icon":"📦","value":"150","label":"API Imports"},{"icon":"ƒ","value":"490","label":"Functions"}]

3. **key_findings** - Security findings with severity (REPLACES attack_vectors)
   - icon: 🔥
   - content_type: "key_findings"
   - content: JSON array like [{"title":"DLL Hijacking Risk","severity":"high","description":"LoadLibraryW called without path validation","apis":["LoadLibraryW","GetProcAddress"]}]

4. **attack_vectors** - Brief attack vector cards (legacy, use key_findings instead)
   - icon: ⚡
   - content_type: "attack_vectors"
   - content: JSON array like [{"title":"Token Manipulation","severity":"critical","description":"...","apis":["OpenProcessToken"]}]

5. **vulnerability_discovery** - DETAILED investigation paths with evidence
   - icon: 🔬
   - content_type: "discovery"
   - content: JSON array of discovery objects:
   ```json
   [{
     "title": "DLL Hijacking via LoadLibraryW",
     "subtitle": "EXTERNAL:0000000d",
     "severity": "high",
     "investigation_path": [
       {"tool": "list_imports", "time": "07:36:13", "params": "{\\"offset\\": 0}", "result": "Discovered <code>LoadLibraryW</code> at <code>EXTERNAL:0000000d</code>"},
       {"tool": "get_xrefs_to", "time": "07:51:42", "params": "{\\"address\\": \\"LoadLibraryW\\"}", "result": "Found <strong>3 call sites</strong>"}
     ],
      "evidence": [
        {"type": "Import API", "value": "LoadLibraryW", "address": "EXTERNAL:0000000d"},
        {"type": "String Reference", "value": "mscoree.dll", "address": "0x401000"}
      ],
      "code": {
        "filename": "FUN_402000",
        "address": "0x402000",
        "content": "<span class=\\"fn\\">LoadLibraryW</span>(<span class=\\"str\\">L\\"mscoree.dll\\"</span>)"
      },
     "impact": {
       "title": "Privilege Escalation Risk",
       "description": "If the binary runs elevated, an attacker could place a malicious <code>mscoree.dll</code> to execute code."
     }
   }]
   ```

6. **security_imports** - Security-relevant API imports table
   - icon: 🔗
   - content_type: "security_imports"
   - content: JSON array like [{"address":"0x401000","api":"VirtualAlloc","category":"Memory","risk":"high"}]

7. **investigation_steps** - Timeline of AI analysis
   - icon: 🔍
   - content_type: "timeline"
   - content: JSON array like [{"step":"STEP 1","title":"Import Analysis","content":"...","reasoning":"..."}]

8. **string_artifacts** - Interesting strings with addresses
   - icon: 📝
   - content_type: "table"
   - content: JSON like {"headers":["Address","String","Significance"],"rows":[["0x401000","api.example.com","C2 Server"]]}

9. **recommendations** - Mitigation steps
   - icon: ✅
   - HTML list with actionable recommendations

## DYNAMIC SECTIONS (add based on findings):
- **encryption_analysis** - If crypto APIs found (CryptEncrypt, etc.)
- **network_behavior** - If network APIs found (socket, WinHTTP, etc.)
- **persistence_mechanisms** - If registry/service APIs found
- **anti_analysis** - If debugging/VM detection found

## CSS CLASSES AVAILABLE:
- Tags: tag-critical, tag-high, tag-medium, tag-low, tag-info
- Stats: stats-grid, stat-card, stat-icon, stat-value, stat-label
- Findings: findings-grid, finding-card, finding-header, finding-title, finding-badge, finding-desc, finding-apis, finding-api
- Code: code-block, address, api-tag, kw, fn, str, cmt, typ, num, hl
- Layout: grid, container, section, section-header, section-line
- Discovery: discovery-section, discovery-card, inv-path, inv-step, evidence-grid, evidence-item, impact-box
- Risk: risk-meter, risk-circle, risk-inner, risk-score, risk-label

## IMPORTANT RULES:
1. Include memory addresses where relevant (e.g., "String at 0x401000")
2. Use HTML tags in results (code, strong) for highlighting
3. Be evidence-based - cite specific findings from the analysis
4. Use proper severity levels based on actual risk (critical, high, medium, low)
5. Output ONLY the JSON, no other text
6. For vulnerability_discovery, show the ACTUAL investigation steps that led to finding the vulnerability
7. ALWAYS include statistics section with function count, imports, exports, and security issues count
8. Include key_findings section if ANY security-relevant APIs or patterns were found
"""

    
    # System prompts for different phases
    phase_system_prompts: Dict[str, str] = Field(default_factory=lambda: {
        "planning": "",    # If empty, use planning_system_prompt
        "execution": "",   # If empty, use execution_system_prompt
        "analysis": "",    # If empty, use analysis_system_prompt
        "evaluation": "",  # If empty, use evaluation_system_prompt
        "review": ""       # If empty, use analysis_system_prompt for review
    })

class GoogleConfig(BaseModel):
    """Configuration for the Google Gemini client."""
    api_key: str = Field(default="", description="Google API Key", env="GOOGLE_API_KEY")
    # Default model (e.g., gemini-2.0-flash, gemini-3-flash)
    model: str = Field(default="gemini-3-flash", description="Default Gemini model", env="GOOGLE_MODEL")
    # Embedding model
    embedding_model: str = Field(default="gemini-embedding-1.0", description="Embedding model name", env="GOOGLE_EMBEDDING_MODEL")
    timeout: int = Field(ge=1, le=600, default=120, description="Timeout for requests in seconds (1-600)", env="GOOGLE_TIMEOUT")
    
    # Request Delay
    request_delay: float = Field(default=0.0, ge=0.0, description="Delay in seconds before each request", env="GOOGLE_REQUEST_DELAY")
    
    # Request Retries
    max_retries: int = Field(default=3, ge=0, description="Maximum number of retries for transient errors", env="GOOGLE_MAX_RETRIES")
    
    # Model map for phases
    model_map: Dict[str, str] = Field(default_factory=lambda: {
        "planning": "",
        "execution": "",
        "analysis": ""
    })
    
    # Defaults handled by the client if empty, but good to have fields
    default_system_prompt: str = """
    You are an AI assistant specialized in reverse engineering with Ghidra.
    You can help analyze binary files by executing commands through GhidraMCP.
    """
    
    # Reuse Ollama tool definitions for now as the internal structure is likely similar for the bridge
    # The client will translate them to Google's format
    tools: List[Tool] = Field(default_factory=lambda: OllamaConfig().tools)

    # Context Budget (reused logic)
    context_budget: int = Field(default=80000, ge=4000, le=2000000, env="CONTEXT_BUDGET")
    context_budget_execution: float = Field(default=0.5, ge=0.1, le=0.8, env="CONTEXT_BUDGET_EXECUTION")
    enable_result_summarization: bool = Field(default=True, env="ENABLE_RESULT_SUMMARIZATION")
    result_cache_enabled: bool = Field(default=True, env="RESULT_CACHE_ENABLED")
    tiered_context_enabled: bool = Field(default=True, env="TIERED_CONTEXT_ENABLED")

    # Logging
    llm_logging_enabled: bool = Field(default=False, env="LLM_LOGGING_ENABLED")
    llm_log_file: str = Field(default="logs/llm_interactions.log", env="LLM_LOG_FILE")
    llm_log_prompts: bool = Field(default=True, env="LLM_LOG_PROMPTS")
    llm_log_responses: bool = Field(default=True, env="LLM_LOG_RESPONSES")
    llm_log_tokens: bool = Field(default=True, env="LLM_LOG_TOKENS")
    llm_log_timing: bool = Field(default=True, env="LLM_LOG_TIMING")
    llm_log_format: str = Field(default="json", env="LLM_LOG_FORMAT")

class ExternalConfig(BaseModel):
    """Configuration for Generic External LLM Providers (Google, OpenAI, etc.)."""
    provider: str = Field(default="google", description="Provider type: 'google', 'openai', etc.", env="EXTERNAL_PROVIDER") 
    api_key: str = Field(default="", description="API Key", env="EXTERNAL_API_KEY")
    base_url: str = Field(default="", description="Base URL for API", env="EXTERNAL_BASE_URL")
    model: str = Field(default="gemini-1.5-flash", description="Default Model Name", env="EXTERNAL_MODEL")
    embedding_model: str = Field(default="", description="Embedding model name", env="EXTERNAL_EMBEDDING_MODEL")
    timeout: int = Field(ge=1, le=600, default=120, description="Timeout in seconds", env="EXTERNAL_TIMEOUT")
    
    # Request Delay
    request_delay: float = Field(default=0.0, ge=0.0, description="Delay in seconds before each request", env="EXTERNAL_REQUEST_DELAY")
    
    # Request Retries
    max_retries: int = Field(default=5, ge=0, description="Maximum number of retries for transient errors", env="EXTERNAL_MAX_RETRIES")
    
    # Generation Config
    temperature: float = Field(default=0.7, ge=0.0, le=2.0, env="EXTERNAL_TEMPERATURE")
    max_tokens: int = Field(default=8192, ge=1, env="EXTERNAL_MAX_TOKENS")
    top_p: float = Field(default=0.95, ge=0.0, le=1.0, env="EXTERNAL_TOP_P")
    top_k: int = Field(default=40, ge=1, env="EXTERNAL_TOP_K")
    
    # Model map for phases
    model_map: Dict[str, str] = Field(default_factory=lambda: {
        "planning": "",
        "execution": "",
        "analysis": ""
    })
    
    # Defaults
    default_system_prompt: str = """
    You are an AI assistant specialized in reverse engineering with Ghidra.
    You can help analyze binary files by executing commands through GhidraMCP.
    """
    
    # Tools logic reused from OllamaConfig
    tools: List[Tool] = Field(default_factory=lambda: OllamaConfig().tools)

    # Context Budget (reused logic)
    context_budget: int = Field(default=20000, ge=4000, le=2000000, env="CONTEXT_BUDGET")
    context_budget_execution: float = Field(default=0.5, ge=0.1, le=0.8, env="CONTEXT_BUDGET_EXECUTION")
    enable_result_summarization: bool = Field(default=True, env="ENABLE_RESULT_SUMMARIZATION")
    result_cache_enabled: bool = Field(default=True, env="RESULT_CACHE_ENABLED")
    tiered_context_enabled: bool = Field(default=True, env="TIERED_CONTEXT_ENABLED")
    
    # Sliding Window & Tiered Context Limits
    max_detailed_steps: int = Field(default=5, ge=1, le=50, env="MAX_DETAILED_STEPS")
    current_loop_max_chars: int = Field(default=2000, ge=100, le=50000, env="CURRENT_LOOP_MAX_CHARS")

    prev_loop_max_chars: int = Field(default=800, ge=50, le=10000, env="PREV_LOOP_MAX_CHARS")
    older_loop_max_chars: int = Field(default=200, ge=20, le=2000, env="OLDER_LOOP_MAX_CHARS")
    
    # Logging
    llm_logging_enabled: bool = Field(default=False, env="LLM_LOGGING_ENABLED")
    llm_log_file: str = Field(default="logs/llm_interactions.log", env="LLM_LOG_FILE")
    llm_log_prompts: bool = Field(default=True, env="LLM_LOG_PROMPTS")
    llm_log_responses: bool = Field(default=True, env="LLM_LOG_RESPONSES")
    llm_log_tokens: bool = Field(default=True, env="LLM_LOG_TOKENS")
    llm_log_timing: bool = Field(default=True, env="LLM_LOG_TIMING")
    llm_log_format: str = Field(default="json", env="LLM_LOG_FORMAT")


    # Execution/Agentic loop settings (reused)
    max_execution_steps: int = Field(default=10, ge=1, le=50, env="MAX_EXECUTION_STEPS")
    execution_loop_enabled: bool = Field(default=True, env="EXECUTION_LOOP_ENABLED")
    max_agentic_cycles: int = Field(default=3, ge=1, le=10, env="MAX_AGENTIC_CYCLES")
    agentic_loop_enabled: bool = Field(default=True, env="AGENTIC_LOOP_ENABLED")
    
    # System prompts (reused from OllamaConfig default factories usually, but we need to define them here)
    # We can copy them from OllamaConfig to ensure consistency
    planning_system_prompt: str = OllamaConfig().planning_system_prompt
    execution_system_prompt: str = OllamaConfig().execution_system_prompt
    evaluation_system_prompt: str = OllamaConfig().evaluation_system_prompt
    analysis_system_prompt: str = OllamaConfig().analysis_system_prompt
    FUNCTION_CALL_BEST_PRACTICES: ClassVar[str] = OllamaConfig.FUNCTION_CALL_BEST_PRACTICES


class CustomAPIConfig(BaseModel):
    """Configuration for Custom API (OpenAI-compatible) client."""
    api_url: AnyHttpUrl = Field(
        default="https://api.example.com/v1/chat/completions",
        env="CUSTOM_API_URL"
    )
    api_key: str = Field(default="", env="CUSTOM_API_KEY")
    model: str = Field(
        default="gpt-4",
        min_length=1,
        description="Model name for Custom API",
        env="CUSTOM_API_MODEL"
    )
    embedding_model: str = Field(
        default="text-embedding-ada-002",
        min_length=1,
        description="Embedding model for Custom API",
        env="CUSTOM_API_EMBEDDING_MODEL"
    )
    timeout: int = Field(
        ge=1,
        le=600,
        default=300,
        description="Timeout for requests in seconds (1-600)",
        env="CUSTOM_API_TIMEOUT"
    )
    
    # Generation parameters
    temperature: float = Field(default=0.7, ge=0.0, le=2.0, env="CUSTOM_API_TEMPERATURE")
    max_tokens: int = Field(default=4096, ge=1, env="CUSTOM_API_MAX_TOKENS")
    
    # SSL verification (may need to disable for custom certs)
    verify_ssl: bool = Field(default=False, env="CUSTOM_API_VERIFY_SSL")
    
    # Default system prompt
    default_system_prompt: str = Field(default="", env="CUSTOM_API_SYSTEM_PROMPT")
    
    # Model map for different phases
    model_map: Dict[str, str] = Field(default_factory=lambda: {
        "planning": "",
        "execution": "",
        "analysis": ""
    })
    
    # LLM Logging (inherited from main config)
    llm_logging_enabled: bool = Field(default=True, env="LLM_LOGGING_ENABLED")
    llm_log_file: str = Field(default="logs/llm_interactions_custom.log", env="CUSTOM_API_LOG_FILE")
    llm_log_prompts: bool = Field(default=True, env="LLM_LOG_PROMPTS")
    llm_log_responses: bool = Field(default=True, env="LLM_LOG_RESPONSES")
    llm_log_tokens: bool = Field(default=True, env="LLM_LOG_TOKENS")
    llm_log_timing: bool = Field(default=True, env="LLM_LOG_TIMING")
    llm_log_format: str = Field(default="json", env="LLM_LOG_FORMAT")
    
    # Request settings
    request_delay: float = Field(default=0.0, ge=0.0, env="CUSTOM_API_REQUEST_DELAY")
    max_retries: int = Field(default=3, ge=0, env="CUSTOM_API_MAX_RETRIES")

    # Global throttling / concurrency control (advanced)
    max_concurrency: int = Field(default=1, ge=1, env="CUSTOM_API_MAX_CONCURRENCY")
    global_min_interval: float = Field(default=0.0, ge=0.0, env="CUSTOM_API_GLOBAL_MIN_INTERVAL")
    respect_retry_after: bool = Field(default=True, env="CUSTOM_API_RESPECT_RETRY_AFTER")
    retry_after_max_seconds: int = Field(default=60, ge=0, env="CUSTOM_API_RETRY_AFTER_MAX_SECONDS")

    # Adaptive throttling (advanced)
    adaptive_throttle_enabled: bool = Field(default=True, env="CUSTOM_API_ADAPTIVE_THROTTLE_ENABLED")
    adaptive_max_interval: float = Field(default=10.0, ge=0.0, env="CUSTOM_API_ADAPTIVE_MAX_INTERVAL")
    adaptive_increase_factor: float = Field(default=1.5, ge=1.0, env="CUSTOM_API_ADAPTIVE_INCREASE_FACTOR")
    adaptive_decrease_factor: float = Field(default=0.9, gt=0.0, le=1.0, env="CUSTOM_API_ADAPTIVE_DECREASE_FACTOR")
    adaptive_success_streak_threshold: int = Field(default=10, ge=1, env="CUSTOM_API_ADAPTIVE_SUCCESS_STREAK_THRESHOLD")
    adaptive_jitter_seconds: float = Field(default=0.25, ge=0.0, env="CUSTOM_API_ADAPTIVE_JITTER_SECONDS")
    
    # Context Budget (reused logic)
    context_budget: int = Field(default=20000, ge=4000, le=2000000, env="CONTEXT_BUDGET")
    context_budget_execution: float = Field(default=0.5, ge=0.1, le=0.8, env="CONTEXT_BUDGET_EXECUTION")
    enable_result_summarization: bool = Field(default=True, env="ENABLE_RESULT_SUMMARIZATION")
    result_cache_enabled: bool = Field(default=True, env="RESULT_CACHE_ENABLED")
    tiered_context_enabled: bool = Field(default=True, env="TIERED_CONTEXT_ENABLED")
    
    # Sliding Window & Tiered Context Limits
    max_detailed_steps: int = Field(default=5, ge=1, le=50, env="MAX_DETAILED_STEPS")
    current_loop_max_chars: int = Field(default=2000, ge=100, le=50000, env="CURRENT_LOOP_MAX_CHARS")
    prev_loop_max_chars: int = Field(default=800, ge=50, le=10000, env="PREV_LOOP_MAX_CHARS")
    older_loop_max_chars: int = Field(default=200, ge=20, le=2000, env="OLDER_LOOP_MAX_CHARS")
    
    # Execution/Agentic loop settings (reused)
    max_execution_steps: int = Field(default=10, ge=1, le=50, env="MAX_EXECUTION_STEPS")
    execution_loop_enabled: bool = Field(default=True, env="EXECUTION_LOOP_ENABLED")
    max_agentic_cycles: int = Field(default=3, ge=1, le=10, env="MAX_AGENTIC_CYCLES")
    agentic_loop_enabled: bool = Field(default=True, env="AGENTIC_LOOP_ENABLED")
    
    # Reuse tools and system prompts from OllamaConfig
    tools: List[Tool] = Field(default_factory=lambda: OllamaConfig().tools)
    planning_system_prompt: str = OllamaConfig().planning_system_prompt
    execution_system_prompt: str = OllamaConfig().execution_system_prompt
    evaluation_system_prompt: str = OllamaConfig().evaluation_system_prompt
    analysis_system_prompt: str = OllamaConfig().analysis_system_prompt
    FUNCTION_CALL_BEST_PRACTICES: ClassVar[str] = OllamaConfig.FUNCTION_CALL_BEST_PRACTICES


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
    google: GoogleConfig = Field(default_factory=GoogleConfig) # Deprecated, keep for compat
    external: ExternalConfig = Field(default_factory=ExternalConfig)
    custom_api: CustomAPIConfig = Field(default_factory=CustomAPIConfig)
    llm_provider: str = Field(default="ollama", description="LLM provider: 'ollama', 'google' (legacy), 'external', or 'custom_api'", env="LLM_PROVIDER")
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
            load_dotenv('.env', override=True)
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
            # Also apply to external config
            if 'external' not in config_data:
                config_data['external'] = {}
            config_data['external']['agentic_loop_enabled'] = os.getenv('AGENTIC_LOOP_ENABLED').lower() == 'true'
        
        # Apply MAX_AGENTIC_CYCLES to external config as well
        if os.getenv('MAX_AGENTIC_CYCLES'):
            if 'external' not in config_data:
                config_data['external'] = {}
            try:
                config_data['external']['max_agentic_cycles'] = int(os.getenv('MAX_AGENTIC_CYCLES'))
            except ValueError:
                pass
        
        # Apply MAX_EXECUTION_STEPS to external config
        if os.getenv('MAX_EXECUTION_STEPS'):
            if 'external' not in config_data:
                config_data['external'] = {}
            try:
                config_data['external']['max_execution_steps'] = int(os.getenv('MAX_EXECUTION_STEPS'))
            except ValueError:
                pass
        
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

        # Load Ollama retry setting
        if os.getenv('OLLAMA_MAX_RETRIES'):
            if 'ollama' not in config_data:
                config_data['ollama'] = {}
            try:
                config_data['ollama']['max_retries'] = int(os.getenv('OLLAMA_MAX_RETRIES'))
            except ValueError:
                pass
        
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

        # Load LLM Provider
        if os.getenv('LLM_PROVIDER'):
            config_data['llm_provider'] = os.getenv('LLM_PROVIDER').lower()

        # Load Google Configuration
        if os.getenv('GOOGLE_API_KEY'):
            if 'google' not in config_data:
                config_data['google'] = {}
            config_data['google']['api_key'] = os.getenv('GOOGLE_API_KEY')
        
        if os.getenv('GOOGLE_MODEL'):
            if 'google' not in config_data:
                config_data['google'] = {}
            config_data['google']['model'] = os.getenv('GOOGLE_MODEL')

        if os.getenv('GOOGLE_EMBEDDING_MODEL'):
            if 'google' not in config_data:
                config_data['google'] = {}
            config_data['google']['embedding_model'] = os.getenv('GOOGLE_EMBEDDING_MODEL')

        if os.getenv('GOOGLE_TIMEOUT'):
            if 'google' not in config_data:
                config_data['google'] = {}
            try:
                config_data['google']['timeout'] = int(os.getenv('GOOGLE_TIMEOUT'))
            except ValueError:
                pass

        if os.getenv('GOOGLE_REQUEST_DELAY'):
            if 'google' not in config_data:
                config_data['google'] = {}
            try:
                config_data['google']['request_delay'] = float(os.getenv('GOOGLE_REQUEST_DELAY'))
            except ValueError:
                pass

        if os.getenv('GOOGLE_MAX_RETRIES'):
            if 'google' not in config_data:
                config_data['google'] = {}
            try:
                config_data['google']['max_retries'] = int(os.getenv('GOOGLE_MAX_RETRIES'))
            except ValueError:
                pass

        # Load External Configuration
        if 'external' not in config_data:
            config_data['external'] = {}
            
        if os.getenv('EXTERNAL_PROVIDER'):
            config_data['external']['provider'] = os.getenv('EXTERNAL_PROVIDER')
        if os.getenv('EXTERNAL_API_KEY'):
            config_data['external']['api_key'] = os.getenv('EXTERNAL_API_KEY')
        if os.getenv('EXTERNAL_MODEL'):
            config_data['external']['model'] = os.getenv('EXTERNAL_MODEL')
        if os.getenv('EXTERNAL_EMBEDDING_MODEL'):
            config_data['external']['embedding_model'] = os.getenv('EXTERNAL_EMBEDDING_MODEL')
        if os.getenv('EXTERNAL_TIMEOUT'):
            try:
                config_data['external']['timeout'] = int(os.getenv('EXTERNAL_TIMEOUT'))
            except ValueError:
                pass
        if os.getenv('EXTERNAL_TEMPERATURE'):
            try:
                config_data['external']['temperature'] = float(os.getenv('EXTERNAL_TEMPERATURE'))
            except ValueError:
                pass
        if os.getenv('EXTERNAL_MAX_TOKENS'):
            try:
                config_data['external']['max_tokens'] = int(os.getenv('EXTERNAL_MAX_TOKENS'))
            except ValueError:
                pass

        if os.getenv('EXTERNAL_REQUEST_DELAY'):
            try:
                config_data['external']['request_delay'] = float(os.getenv('EXTERNAL_REQUEST_DELAY'))
            except ValueError:
                pass

        if os.getenv('EXTERNAL_MAX_RETRIES'):
            try:
                config_data['external']['max_retries'] = int(os.getenv('EXTERNAL_MAX_RETRIES'))
            except ValueError:
                pass
        
        # Load Shared Fields for External (Context, Logging)
        if os.getenv('CONTEXT_BUDGET'):
            try:
                config_data['external']['context_budget'] = int(os.getenv('CONTEXT_BUDGET'))
            except ValueError:
                pass
                
        # Logging settings
        if os.getenv('LLM_LOGGING_ENABLED'):
            config_data['external']['llm_logging_enabled'] = os.getenv('LLM_LOGGING_ENABLED').lower() == 'true'
        if os.getenv('LLM_LOG_FILE'):
            config_data['external']['llm_log_file'] = os.getenv('LLM_LOG_FILE')
        
        # Ensure model_map is explicitly empty to prevent pollution from Ollama models
        config_data['external']['model_map'] = {}
        
        # DEBUG: Print final config structure for external to verify isolation
        # print(f"DEBUG: External Config Loaded: {config_data.get('external')}")
        
        # Ensure model_map is clean
        config_data['external']['model_map'] = {}


        # Ensure model_map for Google is initialized but empty to prevent pollution
        if 'google' in config_data:
            # We explicitly don't want to copy Ollama's model_map to Google
            # unless we implement GOOGLE_MODEL_PLANNING etc. later.
            config_data['google']['model_map'] = {}

        # Load Custom API Configuration
        if 'custom_api' not in config_data:
            config_data['custom_api'] = {}
            
        if os.getenv('CUSTOM_API_URL'):
            config_data['custom_api']['api_url'] = os.getenv('CUSTOM_API_URL')
        if os.getenv('CUSTOM_API_KEY'):
            config_data['custom_api']['api_key'] = os.getenv('CUSTOM_API_KEY')
        if os.getenv('CUSTOM_API_MODEL'):
            config_data['custom_api']['model'] = os.getenv('CUSTOM_API_MODEL')
        if os.getenv('CUSTOM_API_EMBEDDING_MODEL'):
            config_data['custom_api']['embedding_model'] = os.getenv('CUSTOM_API_EMBEDDING_MODEL')
        if os.getenv('CUSTOM_API_TIMEOUT'):
            try:
                config_data['custom_api']['timeout'] = int(os.getenv('CUSTOM_API_TIMEOUT'))
            except ValueError:
                pass
        if os.getenv('CUSTOM_API_TEMPERATURE'):
            try:
                config_data['custom_api']['temperature'] = float(os.getenv('CUSTOM_API_TEMPERATURE'))
            except ValueError:
                pass
        if os.getenv('CUSTOM_API_MAX_TOKENS'):
            try:
                config_data['custom_api']['max_tokens'] = int(os.getenv('CUSTOM_API_MAX_TOKENS'))
            except ValueError:
                pass
        if os.getenv('CUSTOM_API_VERIFY_SSL'):
            config_data['custom_api']['verify_ssl'] = os.getenv('CUSTOM_API_VERIFY_SSL').lower() == 'true'
        if os.getenv('CUSTOM_API_REQUEST_DELAY'):
            try:
                config_data['custom_api']['request_delay'] = float(os.getenv('CUSTOM_API_REQUEST_DELAY'))
            except ValueError:
                pass
        if os.getenv('CUSTOM_API_MAX_RETRIES'):
            try:
                config_data['custom_api']['max_retries'] = int(os.getenv('CUSTOM_API_MAX_RETRIES'))
            except ValueError:
                pass
        
        # Advanced throttling settings
        if os.getenv('CUSTOM_API_MAX_CONCURRENCY'):
            try:
                config_data['custom_api']['max_concurrency'] = int(os.getenv('CUSTOM_API_MAX_CONCURRENCY'))
            except ValueError:
                pass
        if os.getenv('CUSTOM_API_GLOBAL_MIN_INTERVAL'):
            try:
                config_data['custom_api']['global_min_interval'] = float(os.getenv('CUSTOM_API_GLOBAL_MIN_INTERVAL'))
            except ValueError:
                pass
        if os.getenv('CUSTOM_API_RESPECT_RETRY_AFTER'):
            config_data['custom_api']['respect_retry_after'] = os.getenv('CUSTOM_API_RESPECT_RETRY_AFTER').lower() == 'true'
        if os.getenv('CUSTOM_API_RETRY_AFTER_MAX_SECONDS'):
            try:
                config_data['custom_api']['retry_after_max_seconds'] = int(os.getenv('CUSTOM_API_RETRY_AFTER_MAX_SECONDS'))
            except ValueError:
                pass
        
        # Adaptive throttling
        if os.getenv('CUSTOM_API_ADAPTIVE_THROTTLE_ENABLED'):
            config_data['custom_api']['adaptive_throttle_enabled'] = os.getenv('CUSTOM_API_ADAPTIVE_THROTTLE_ENABLED').lower() == 'true'
        if os.getenv('CUSTOM_API_ADAPTIVE_MAX_INTERVAL'):
            try:
                config_data['custom_api']['adaptive_max_interval'] = float(os.getenv('CUSTOM_API_ADAPTIVE_MAX_INTERVAL'))
            except ValueError:
                pass
        if os.getenv('CUSTOM_API_ADAPTIVE_INCREASE_FACTOR'):
            try:
                config_data['custom_api']['adaptive_increase_factor'] = float(os.getenv('CUSTOM_API_ADAPTIVE_INCREASE_FACTOR'))
            except ValueError:
                pass
        if os.getenv('CUSTOM_API_ADAPTIVE_DECREASE_FACTOR'):
            try:
                config_data['custom_api']['adaptive_decrease_factor'] = float(os.getenv('CUSTOM_API_ADAPTIVE_DECREASE_FACTOR'))
            except ValueError:
                pass
        if os.getenv('CUSTOM_API_ADAPTIVE_SUCCESS_STREAK_THRESHOLD'):
            try:
                config_data['custom_api']['adaptive_success_streak_threshold'] = int(os.getenv('CUSTOM_API_ADAPTIVE_SUCCESS_STREAK_THRESHOLD'))
            except ValueError:
                pass
        if os.getenv('CUSTOM_API_ADAPTIVE_JITTER_SECONDS'):
            try:
                config_data['custom_api']['adaptive_jitter_seconds'] = float(os.getenv('CUSTOM_API_ADAPTIVE_JITTER_SECONDS'))
            except ValueError:
                pass
        
        # Context budget and execution loop settings
        if os.getenv('CONTEXT_BUDGET'):
            try:
                config_data['custom_api']['context_budget'] = int(os.getenv('CONTEXT_BUDGET'))
            except ValueError:
                pass
        if os.getenv('MAX_EXECUTION_STEPS'):
            try:
                config_data['custom_api']['max_execution_steps'] = int(os.getenv('MAX_EXECUTION_STEPS'))
            except ValueError:
                pass
        if os.getenv('MAX_AGENTIC_CYCLES'):
            try:
                config_data['custom_api']['max_agentic_cycles'] = int(os.getenv('MAX_AGENTIC_CYCLES'))
            except ValueError:
                pass
        if os.getenv('AGENTIC_LOOP_ENABLED'):
            config_data['custom_api']['agentic_loop_enabled'] = os.getenv('AGENTIC_LOOP_ENABLED').lower() == 'true'
        
        # Logging settings
        if os.getenv('LLM_LOGGING_ENABLED'):
            config_data['custom_api']['llm_logging_enabled'] = os.getenv('LLM_LOGGING_ENABLED').lower() == 'true'
        if os.getenv('LLM_LOG_FILE'):
            config_data['custom_api']['llm_log_file'] = os.getenv('LLM_LOG_FILE')
        
        # Ensure model_map is explicitly empty to prevent pollution
        config_data['custom_api']['model_map'] = {}

        _config_instance = BridgeConfig(**config_data)
    return _config_instance 
