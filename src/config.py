"""Configuration models for OGhidra."""

import re
from typing import ClassVar

from pydantic import AnyHttpUrl, BaseModel, Field, validator
from pydantic_settings import BaseSettings

DEFAULT_SYSTEM_PROMPT = """You are an AI assistant specialized in reverse engineering with Ghidra.
You can analyze binary files using the available Ghidra tools."""
class OllamaConfig(BaseModel):
    """Configuration for the Ollama client."""

    base_url: AnyHttpUrl = Field(default="http://localhost:11434", env="OLLAMA_BASE_URL")
    # Default model. This is primarily set by the OLLAMA_MODEL environment variable.
    # llama3.1 is recommended for features like tool calling.
    model: str = Field(default="gemma3:27b", min_length=1, description="Model name cannot be empty", env="OLLAMA_MODEL")
    # Embedding model for vector operations
    embedding_model: str = Field(
        default="nomic-embed-text",
        min_length=1,
        description="Embedding model name cannot be empty",
        env="OLLAMA_EMBEDDING_MODEL",
    )
    timeout: int = Field(ge=1, le=600, default=120, description="Timeout for requests in seconds (1-600)", env="OLLAMA_TIMEOUT")
    username: str = Field(default=None, env="OLLAMA_USERNAME")
    password: str = Field(default=None, env="OLLAMA_PASSWORD")

    # Execution loop settings (INNER LOOP - tools per execution phase)
    max_execution_steps: int = Field(
        default=10, ge=1, le=50, description="Maximum tool executions per investigation (1-50)", env="MAX_EXECUTION_STEPS"
    )

    # Agentic loop settings (OUTER LOOP - full planning→execution→analysis cycles)
    max_agentic_cycles: int = Field(
        default=3,
        ge=1,
        le=10,
        description="Maximum Planning→Execution→Analysis cycles per query (1-10)",
        env="MAX_AGENTIC_CYCLES",
    )

    agentic_loop_enabled: bool = Field(
        default=True,
        description="Enable multi-cycle agentic loop with goal evaluation and re-planning",
        env="AGENTIC_LOOP_ENABLED",
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
    show_reasoning: bool = Field(
        default=True, description="Print Chain of Thought reasoning to stdout", env="OLLAMA_SHOW_REASONING"
    )

    # Request Delay
    request_delay: float = Field(
        default=0.0, ge=0.0, description="Delay in seconds before each request", env="OLLAMA_REQUEST_DELAY"
    )

    # Request Retries
    max_retries: int = Field(
        default=3, ge=0, description="Maximum number of retries for transient errors", env="OLLAMA_MAX_RETRIES"
    )

    # Context Budget Management
    context_budget: int = Field(
        default=80000,
        ge=4000,
        le=2000000,
        description="Maximum context tokens for prompts (4000-2000000)",
        env="CONTEXT_BUDGET",
    )

    context_budget_execution: float = Field(
        default=0.5,
        ge=0.1,
        le=0.8,
        description="Fraction of context budget for execution results (0.1-0.8)",
        env="CONTEXT_BUDGET_EXECUTION",
    )

    enable_result_summarization: bool = Field(
        default=True, description="Use LLM to summarize large results instead of truncating", env="ENABLE_RESULT_SUMMARIZATION"
    )

    result_cache_enabled: bool = Field(
        default=True, description="Cache full results and pass references to AI", env="RESULT_CACHE_ENABLED"
    )

    tiered_context_enabled: bool = Field(
        default=True, description="Use tiered context (detailed recent, summarized older)", env="TIERED_CONTEXT_ENABLED"
    )

    # Sliding Window & Tiered Context Limits
    # These scale proportionally to CONTEXT_BUDGET (chars ≈ tokens × 4)
    max_detailed_steps: int = Field(
        default=10,
        ge=1,
        le=50,
        description="Maximum execution steps to keep in full detail (sliding window)",
        env="MAX_DETAILED_STEPS",
    )

    current_loop_max_chars: int = Field(
        default=4000,
        ge=100,
        le=50000,
        description="Max chars for current loop results (full details)",
        env="CURRENT_LOOP_MAX_CHARS",
    )

    prev_loop_max_chars: int = Field(
        default=800,
        ge=50,
        le=10000,
        description="Max chars for previous loop results (bullet summaries)",
        env="PREV_LOOP_MAX_CHARS",
    )

    older_loop_max_chars: int = Field(
        default=200, ge=20, le=2000, description="Max chars for older loop results (one-line refs)", env="OLDER_LOOP_MAX_CHARS"
    )

    # Hybrid Context Management Settings
    top_n_per_category: int = Field(
        default=10, ge=1, le=50, description="Maximum items per result category in ranked results", env="TOP_N_PER_CATEGORY"
    )

    enable_correlation_hints: bool = Field(
        default=True, description="Build cross-tool address correlations for analysis", env="ENABLE_CORRELATION_HINTS"
    )

    min_correlation_mentions: int = Field(
        default=2, ge=2, le=5, description="Minimum tool mentions to surface a correlation", env="MIN_CORRELATION_MENTIONS"
    )

    # Interactive Execution Gate (OpenCode-inspired)
    execution_gate_enabled: bool = Field(
        default=True,
        description="Enable interactive execution gate for pause/review during loops",
        env="EXECUTION_GATE_ENABLED",
    )

    gate_on_artifact: bool = Field(
        default=True, description="Pause when critical artifact found in tool results", env="GATE_ON_ARTIFACT"
    )

    gate_on_repetition: bool = Field(
        default=True, description="Pause on N identical tool calls (doom-loop detection)", env="GATE_ON_REPETITION"
    )

    gate_repetition_threshold: int = Field(
        default=3,
        ge=2,
        le=10,
        description="How many identical calls before triggering repetition gate",
        env="GATE_REPETITION_THRESHOLD",
    )

    gate_on_high_risk_tool: bool = Field(
        default=False, description="Pause before destructive tools (rename_function, etc.)", env="GATE_ON_HIGH_RISK_TOOL"
    )

    gate_auto_resume_timeout: int = Field(
        default=0,
        ge=0,
        description="Seconds before auto-resuming after gate (0 = wait forever)",
        env="GATE_AUTO_RESUME_TIMEOUT",
    )

    # Session Compaction (OpenCode-inspired)
    compaction_enabled: bool = Field(
        default=True, description="Enable smart context pruning to prevent overflow", env="COMPACTION_ENABLED"
    )

    compaction_threshold: float = Field(
        default=0.75,
        ge=0.3,
        le=0.95,
        description="Context usage fraction that triggers compaction (0.3-0.95)",
        env="COMPACTION_THRESHOLD",
    )

    compaction_auto: bool = Field(
        default=True, description="Auto-compact between agentic cycles when threshold exceeded", env="COMPACTION_AUTO"
    )

    # Enable or disable Context-Augmented Generation
    enable_cag: bool = True

    @validator("model")
    def validate_model_name(cls, v):
        """Ensure model name follows expected patterns."""
        if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9_\-:.]*$", v):
            raise ValueError("Model name contains invalid characters. Use only alphanumeric, underscore, dash, colon, and dot.")
        return v

    @validator("model_map")
    def validate_model_phases(cls, v):
        """Validate that model_map contains valid phase names."""
        valid_phases = {"planning", "execution", "analysis", "evaluation", "review"}
        invalid_phases = set(v.keys()) - valid_phases
        if invalid_phases:
            raise ValueError(f"Invalid phases in model_map: {invalid_phases}. Valid phases are: {valid_phases}")
        return v

    # Model map for different phases of the simplified agentic loop
    # If a phase is not in the map or the value is empty, the default model will be used
    model_map: dict[str, str] = Field(
        default_factory=lambda: {
            "planning": "",  # Model for planning phase
            "execution": "",  # Model for tool execution phase
            "analysis": "",  # Model for final analysis phase
        }
    )

    default_system_prompt: str = DEFAULT_SYSTEM_PROMPT

    # Phase guidance is deliberately compact. DSPy signatures define each
    # phase's role and output contract; these strings contain only runtime
    # policy that operators may reasonably customize.
    planning_system_prompt: str = """
Create an ordered investigation plan. Select only relevant Ghidra tools, make
conditional follow-ups explicit, and include verification for uncertain claims.
Plan only; do not issue tool calls.
"""

    planning_system_prompt_vuln: str = """
Plan an evidence-driven vulnerability investigation. Cover code-level flaws and,
when relevant, deployment risks such as unsafe loading, service configuration,
permissions, persistence, and unvalidated paths. Require decompiled-code evidence
before treating a suspected issue as confirmed. Plan only; do not issue tool calls.
"""

    execution_system_prompt_task_mode: str = """
Investigate systematically: discover a lead, locate its references, decompile the
relevant caller, and verify the data flow. Cite addresses and distinguish observed
evidence from hypotheses. Batch safe read-only calls and avoid repeating completed
calls. Use the typed action fields and set `complete` only when no further actions
are required.

{FUNCTION_CALL_BEST_PRACTICES}
"""

    execution_system_prompt: str = """
Use the minimum Ghidra tools needed to answer the user's question. Prefer targeted
queries, batch related read-only calls, and verify conclusions against tool output.
Use the typed action fields and set `complete` only when no further actions are required.

{FUNCTION_CALL_BEST_PRACTICES}
"""

    FUNCTION_CALL_BEST_PRACTICES: ClassVar[str] = """Use snake_case tool names and exact parameter names.
Use bare hexadecimal addresses without `FUN_` or `0x` where a tool expects a numerical address.
Retrieve cached results instead of repeating an identical call."""



class GoogleConfig(BaseModel):
    """Configuration for the Google Gemini client."""

    api_key: str = Field(default="", description="Google API Key", env="GOOGLE_API_KEY")
    # Default model (e.g., gemini-2.0-flash, gemini-3-flash)
    model: str = Field(default="gemini-3-flash", description="Default Gemini model", env="GOOGLE_MODEL")
    # Embedding model
    embedding_model: str = Field(
        default="gemini-embedding-1.0", description="Embedding model name", env="GOOGLE_EMBEDDING_MODEL"
    )
    timeout: int = Field(ge=1, le=600, default=120, description="Timeout for requests in seconds (1-600)", env="GOOGLE_TIMEOUT")

    # Request Delay
    request_delay: float = Field(
        default=0.0, ge=0.0, description="Delay in seconds before each request", env="GOOGLE_REQUEST_DELAY"
    )

    # Request Retries
    max_retries: int = Field(
        default=3, ge=0, description="Maximum number of retries for transient errors", env="GOOGLE_MAX_RETRIES"
    )

    # Model map for phases
    model_map: dict[str, str] = Field(default_factory=lambda: {"planning": "", "execution": "", "analysis": ""})

    default_system_prompt: str = DEFAULT_SYSTEM_PROMPT

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
    request_delay: float = Field(
        default=0.0, ge=0.0, description="Delay in seconds before each request", env="EXTERNAL_REQUEST_DELAY"
    )

    # Request Retries
    max_retries: int = Field(
        default=5, ge=0, description="Maximum number of retries for transient errors", env="EXTERNAL_MAX_RETRIES"
    )

    # Generation Config
    temperature: float = Field(default=0.7, ge=0.0, le=2.0, env="EXTERNAL_TEMPERATURE")
    max_tokens: int = Field(default=8192, ge=1, env="EXTERNAL_MAX_TOKENS")
    top_p: float = Field(default=0.95, ge=0.0, le=1.0, env="EXTERNAL_TOP_P")
    top_k: int = Field(default=40, ge=1, env="EXTERNAL_TOP_K")

    # Model map for phases
    model_map: dict[str, str] = Field(default_factory=lambda: {"planning": "", "execution": "", "analysis": ""})

    default_system_prompt: str = DEFAULT_SYSTEM_PROMPT

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
    max_agentic_cycles: int = Field(default=3, ge=1, le=10, env="MAX_AGENTIC_CYCLES")
    agentic_loop_enabled: bool = Field(default=True, env="AGENTIC_LOOP_ENABLED")

    # System prompts (reused from OllamaConfig default factories usually, but we need to define them here)
    # We can copy them from OllamaConfig to ensure consistency
    planning_system_prompt: str = OllamaConfig().planning_system_prompt
    execution_system_prompt: str = OllamaConfig().execution_system_prompt
    FUNCTION_CALL_BEST_PRACTICES: ClassVar[str] = OllamaConfig.FUNCTION_CALL_BEST_PRACTICES


class CustomAPIConfig(BaseModel):
    """Configuration for Custom API (OpenAI-compatible) client."""

    api_url: AnyHttpUrl = Field(default="https://api.example.com/v1/chat/completions", env="CUSTOM_API_URL")
    api_key: str = Field(default="", env="CUSTOM_API_KEY")
    model: str = Field(default="gpt-4", min_length=1, description="Model name for Custom API", env="CUSTOM_API_MODEL")
    embedding_model: str = Field(
        default="text-embedding-ada-002",
        min_length=1,
        description="Embedding model for Custom API",
        env="CUSTOM_API_EMBEDDING_MODEL",
    )
    timeout: int = Field(
        ge=1, le=600, default=300, description="Timeout for requests in seconds (1-600)", env="CUSTOM_API_TIMEOUT"
    )

    # Generation parameters
    temperature: float = Field(default=0.7, ge=0.0, le=2.0, env="CUSTOM_API_TEMPERATURE")
    max_tokens: int = Field(default=4096, ge=1, env="CUSTOM_API_MAX_TOKENS")

    # SSL verification (may need to disable for custom certs)
    verify_ssl: bool = Field(default=False, env="CUSTOM_API_VERIFY_SSL")

    # Default system prompt
    default_system_prompt: str = Field(default="", env="CUSTOM_API_SYSTEM_PROMPT")

    # Model map for different phases
    model_map: dict[str, str] = Field(default_factory=lambda: {"planning": "", "execution": "", "analysis": ""})

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
    max_agentic_cycles: int = Field(default=3, ge=1, le=10, env="MAX_AGENTIC_CYCLES")
    agentic_loop_enabled: bool = Field(default=True, env="AGENTIC_LOOP_ENABLED")

    # Reuse phase guidance from the default provider.
    planning_system_prompt: str = OllamaConfig().planning_system_prompt
    execution_system_prompt: str = OllamaConfig().execution_system_prompt
    FUNCTION_CALL_BEST_PRACTICES: ClassVar[str] = OllamaConfig.FUNCTION_CALL_BEST_PRACTICES


class GhidraMCPConfig(BaseModel):
    """Configuration for the GhidraMCP client."""

    base_url: AnyHttpUrl = Field(default="http://localhost:8080", env="GHIDRA_BASE_URL")
    timeout: int = Field(ge=1, le=300, default=30, description="Timeout in seconds (1-300)", env="GHIDRA_TIMEOUT")
    mock_mode: bool = Field(default=False, env="GHIDRA_MOCK_MODE")
    api_path: str = Field(default="", description="API path for GhidraMCP", env="GHIDRA_API_PATH")
    # Backend selection: "http" uses the GhidraMCP HTTP server, "pyghidra"
    # uses the in-process pyGhidra integration.
    backend: str = Field(
        default="http",
        description="Ghidra backend: 'http' (GhidraMCP server) or 'pyghidra' (in-process)",
        env="GHIDRA_BACKEND",
    )

    # Optional pyGhidra settings. These are only used when backend == "pyghidra".
    # They are intentionally loose strings so users can adapt them to however
    # they open projects/programs via pyGhidra.
    pyghidra_project_path: str | None = Field(
        default=None,
        description="Path to Ghidra project (directory or .gpr) for pyGhidra backend",
        env="PYGHIDRA_PROJECT_PATH",
    )
    pyghidra_program: str | None = Field(
        default=None,
        description=(
            "Program name or path within the project for pyGhidra backend. "
            "If omitted and the project contains exactly one program, that program "
            "will be opened automatically; if multiple programs exist, you must "
            "specify this value."
        ),
        env="PYGHIDRA_PROGRAM",
    )
    pyghidra_binary: str | None = Field(
        default=None,
        description=(
            "Path to a binary to open with pyGhidra. When set and no project is provided, "
            "OGhidra will create a new Ghidra project and import this binary."
        ),
        env="PYGHIDRA_BINARY",
    )

    @validator("api_path")
    def validate_api_path(cls, v):
        """Validate API path format."""
        if v and not v.startswith("/"):
            raise ValueError('API path must start with "/" or be empty')
        return v

    @validator("backend")
    def validate_backend(cls, v):
        """Validate Ghidra backend selection."""
        normalized = v.strip().lower()
        valid_backends = {"http", "pyghidra"}
        if normalized not in valid_backends:
            raise ValueError(f"backend must be one of {sorted(valid_backends)}")
        return normalized


class SessionHistoryConfig(BaseModel):
    """Configuration for session history."""

    enabled: bool = True
    storage_path: str = Field(default="data/ollama_ghidra_session_history.jsonl", description="Path to session history file")
    max_sessions: int = Field(ge=1, le=100000, default=1000, description="Maximum number of sessions to store (1-100000)")
    auto_summarize: bool = True
    use_vector_embeddings: bool = False
    vector_db_path: str = Field(default="data/vector_db", description="Path to vector database directory")

    @validator("storage_path")
    def validate_storage_path(cls, v):
        """Validate storage path format."""
        if not v.strip():
            raise ValueError("Storage path cannot be empty")
        if not v.endswith(".jsonl"):
            raise ValueError("Storage path must end with .jsonl extension")
        return v.strip()

    @validator("vector_db_path")
    def validate_vector_db_path(cls, v):
        """Validate vector database path."""
        if not v.strip():
            raise ValueError("Vector database path cannot be empty")
        return v.strip()


class BridgeConfig(BaseSettings):
    """Root configuration model, loading from environment variables."""

    ollama: OllamaConfig = Field(default_factory=OllamaConfig)
    google: GoogleConfig = Field(default_factory=GoogleConfig)  # Deprecated, keep for compat
    external: ExternalConfig = Field(default_factory=ExternalConfig)
    custom_api: CustomAPIConfig = Field(default_factory=CustomAPIConfig)
    llm_provider: str = Field(
        default="ollama",
        description="LLM provider: 'ollama', 'google' (legacy), 'external', or 'custom_api'",
        env="LLM_PROVIDER",
    )
    ghidra: GhidraMCPConfig = Field(default_factory=GhidraMCPConfig)
    session_history: SessionHistoryConfig = Field(default_factory=SessionHistoryConfig)

    log_level: str = Field(default="INFO", description="Logging level")
    log_file: str = Field(default="bridge.log", description="Log file path")
    log_console: bool = True
    log_file_enabled: bool = True
    context_limit: int = Field(ge=1, le=50, default=25, description="Context limit for conversations (1-50)")

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

    @validator("log_level")
    def validate_log_level(cls, v):
        """Validate log level."""
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        v_upper = v.upper()
        if v_upper not in valid_levels:
            raise ValueError(f"log_level must be one of {valid_levels}")
        return v_upper

    @validator("log_file")
    def validate_log_file(cls, v):
        """Validate log file path."""
        if not v.strip():
            raise ValueError("Log file path cannot be empty")
        if not v.endswith(".log"):
            raise ValueError("Log file must have .log extension")
        return v.strip()

    @validator("knowledge_base_dir")
    def validate_knowledge_base_dir(cls, v):
        """Validate knowledge base directory."""
        if not v.strip():
            raise ValueError("Knowledge base directory cannot be empty")
        return v.strip()

    model_config = {
        "env_prefix": "",  # No prefix for env vars
        "case_sensitive": False,
        # Nested models will also be populated from env vars
        # e.g. OLLAMA_BASE_URL will populate ollama.base_url
        "env_nested_delimiter": "_",
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "extra": "ignore",
    }


# Helper function to get the config instance
_config_instance: BridgeConfig | None = None


def get_config() -> BridgeConfig:
    """Returns a singleton instance of the BridgeConfig."""
    global _config_instance
    if _config_instance is None:
        # Explicitly load .env file before creating config
        try:
            from dotenv import load_dotenv

            load_dotenv(".env", override=True)
        except ImportError:
            # python-dotenv not available, try to continue without it
            pass

        # Create config with explicit environment loading
        import os

        config_data = {}

        # Manually map environment variables to config structure
        if os.getenv("OLLAMA_BASE_URL"):
            # Ensure base URL doesn't have trailing slash
            base_url = os.getenv("OLLAMA_BASE_URL").rstrip("/")
            config_data["ollama"] = {"base_url": base_url}
        if os.getenv("OLLAMA_MODEL"):
            if "ollama" not in config_data:
                config_data["ollama"] = {}
            config_data["ollama"]["model"] = os.getenv("OLLAMA_MODEL")

        # Load LLM logging configuration
        if os.getenv("LLM_LOGGING_ENABLED"):
            if "ollama" not in config_data:
                config_data["ollama"] = {}
            config_data["ollama"]["llm_logging_enabled"] = os.getenv("LLM_LOGGING_ENABLED").lower() == "true"
        if os.getenv("LLM_LOG_FILE"):
            if "ollama" not in config_data:
                config_data["ollama"] = {}
            config_data["ollama"]["llm_log_file"] = os.getenv("LLM_LOG_FILE")
        if os.getenv("LLM_LOG_FORMAT"):
            if "ollama" not in config_data:
                config_data["ollama"] = {}
            config_data["ollama"]["llm_log_format"] = os.getenv("LLM_LOG_FORMAT")
        if os.getenv("LLM_LOG_PROMPTS"):
            if "ollama" not in config_data:
                config_data["ollama"] = {}
            config_data["ollama"]["llm_log_prompts"] = os.getenv("LLM_LOG_PROMPTS").lower() == "true"
        if os.getenv("LLM_LOG_RESPONSES"):
            if "ollama" not in config_data:
                config_data["ollama"] = {}
            config_data["ollama"]["llm_log_responses"] = os.getenv("LLM_LOG_RESPONSES").lower() == "true"
        if os.getenv("LLM_LOG_TOKENS"):
            if "ollama" not in config_data:
                config_data["ollama"] = {}
            config_data["ollama"]["llm_log_tokens"] = os.getenv("LLM_LOG_TOKENS").lower() == "true"
        if os.getenv("LLM_LOG_TIMING"):
            if "ollama" not in config_data:
                config_data["ollama"] = {}
            config_data["ollama"]["llm_log_timing"] = os.getenv("LLM_LOG_TIMING").lower() == "true"

        # Load phase-specific models into model_map
        model_map = {}
        if os.getenv("OLLAMA_MODEL_PLANNING"):
            model_map["planning"] = os.getenv("OLLAMA_MODEL_PLANNING")
        if os.getenv("OLLAMA_MODEL_EXECUTION"):
            model_map["execution"] = os.getenv("OLLAMA_MODEL_EXECUTION")
        if os.getenv("OLLAMA_MODEL_ANALYSIS"):
            model_map["analysis"] = os.getenv("OLLAMA_MODEL_ANALYSIS")
        if os.getenv("OLLAMA_MODEL_EVALUATION"):
            model_map["evaluation"] = os.getenv("OLLAMA_MODEL_EVALUATION")
        if os.getenv("OLLAMA_MODEL_REVIEW"):
            model_map["review"] = os.getenv("OLLAMA_MODEL_REVIEW")

        if model_map:
            if "ollama" not in config_data:
                config_data["ollama"] = {}
            config_data["ollama"]["model_map"] = model_map

        # Load execution loop settings
        if os.getenv("MAX_EXECUTION_STEPS"):
            if "ollama" not in config_data:
                config_data["ollama"] = {}
            try:
                config_data["ollama"]["max_execution_steps"] = int(os.getenv("MAX_EXECUTION_STEPS"))
            except ValueError:
                pass  # Use default if invalid value

        # Load agentic loop settings
        if os.getenv("MAX_AGENTIC_CYCLES"):
            if "ollama" not in config_data:
                config_data["ollama"] = {}
            try:
                config_data["ollama"]["max_agentic_cycles"] = int(os.getenv("MAX_AGENTIC_CYCLES"))
            except ValueError:
                pass  # Use default if invalid value

        if os.getenv("AGENTIC_LOOP_ENABLED"):
            if "ollama" not in config_data:
                config_data["ollama"] = {}
            config_data["ollama"]["agentic_loop_enabled"] = os.getenv("AGENTIC_LOOP_ENABLED").lower() == "true"
            # Also apply to external config
            if "external" not in config_data:
                config_data["external"] = {}
            config_data["external"]["agentic_loop_enabled"] = os.getenv("AGENTIC_LOOP_ENABLED").lower() == "true"

        # Apply MAX_AGENTIC_CYCLES to external config as well
        if os.getenv("MAX_AGENTIC_CYCLES"):
            if "external" not in config_data:
                config_data["external"] = {}
            try:
                config_data["external"]["max_agentic_cycles"] = int(os.getenv("MAX_AGENTIC_CYCLES"))
            except ValueError:
                pass

        # Apply MAX_EXECUTION_STEPS to external config
        if os.getenv("MAX_EXECUTION_STEPS"):
            if "external" not in config_data:
                config_data["external"] = {}
            try:
                config_data["external"]["max_execution_steps"] = int(os.getenv("MAX_EXECUTION_STEPS"))
            except ValueError:
                pass

        # Load Ollama timeout setting
        if os.getenv("OLLAMA_TIMEOUT"):
            if "ollama" not in config_data:
                config_data["ollama"] = {}
            try:
                config_data["ollama"]["timeout"] = int(os.getenv("OLLAMA_TIMEOUT"))
            except ValueError:
                pass  # Use default if invalid value

        # Load Ollama request delay setting
        if os.getenv("OLLAMA_REQUEST_DELAY"):
            if "ollama" not in config_data:
                config_data["ollama"] = {}
            try:
                config_data["ollama"]["request_delay"] = float(os.getenv("OLLAMA_REQUEST_DELAY"))
            except ValueError:
                pass  # Use default if invalid value

        # Load Ollama embedding model
        if os.getenv("OLLAMA_EMBEDDING_MODEL"):
            if "ollama" not in config_data:
                config_data["ollama"] = {}
            config_data["ollama"]["embedding_model"] = os.getenv("OLLAMA_EMBEDDING_MODEL")

        # Load Ollama retry setting
        if os.getenv("OLLAMA_MAX_RETRIES"):
            if "ollama" not in config_data:
                config_data["ollama"] = {}
            try:
                config_data["ollama"]["max_retries"] = int(os.getenv("OLLAMA_MAX_RETRIES"))
            except ValueError:
                pass

        # Load show reasoning setting
        if os.getenv("OLLAMA_SHOW_REASONING"):
            if "ollama" not in config_data:
                config_data["ollama"] = {}
            config_data["ollama"]["show_reasoning"] = os.getenv("OLLAMA_SHOW_REASONING").lower() == "true"

        # Load context budget settings
        if os.getenv("CONTEXT_BUDGET"):
            if "ollama" not in config_data:
                config_data["ollama"] = {}
            try:
                config_data["ollama"]["context_budget"] = int(os.getenv("CONTEXT_BUDGET"))
            except ValueError:
                pass  # Use default if invalid value

        if os.getenv("CONTEXT_BUDGET_EXECUTION"):
            if "ollama" not in config_data:
                config_data["ollama"] = {}
            try:
                config_data["ollama"]["context_budget_execution"] = float(os.getenv("CONTEXT_BUDGET_EXECUTION"))
            except ValueError:
                pass  # Use default if invalid value

        # Load result handling settings
        if os.getenv("ENABLE_RESULT_SUMMARIZATION"):
            if "ollama" not in config_data:
                config_data["ollama"] = {}
            config_data["ollama"]["enable_result_summarization"] = os.getenv("ENABLE_RESULT_SUMMARIZATION").lower() == "true"

        if os.getenv("RESULT_CACHE_ENABLED"):
            if "ollama" not in config_data:
                config_data["ollama"] = {}
            config_data["ollama"]["result_cache_enabled"] = os.getenv("RESULT_CACHE_ENABLED").lower() == "true"

        if os.getenv("TIERED_CONTEXT_ENABLED"):
            if "ollama" not in config_data:
                config_data["ollama"] = {}
            config_data["ollama"]["tiered_context_enabled"] = os.getenv("TIERED_CONTEXT_ENABLED").lower() == "true"

        # Load Ghidra configuration
        if os.getenv("GHIDRA_BASE_URL"):
            config_data["ghidra"] = {"base_url": os.getenv("GHIDRA_BASE_URL")}

        if os.getenv("GHIDRA_TIMEOUT"):
            if "ghidra" not in config_data:
                config_data["ghidra"] = {}
            try:
                config_data["ghidra"]["timeout"] = int(os.getenv("GHIDRA_TIMEOUT"))
            except ValueError:
                pass  # Use default if invalid value

        if os.getenv("GHIDRA_MOCK_MODE"):
            if "ghidra" not in config_data:
                config_data["ghidra"] = {}
            config_data["ghidra"]["mock_mode"] = os.getenv("GHIDRA_MOCK_MODE").lower() == "true"

        if os.getenv("GHIDRA_API_PATH"):
            if "ghidra" not in config_data:
                config_data["ghidra"] = {}
            config_data["ghidra"]["api_path"] = os.getenv("GHIDRA_API_PATH")

        if os.getenv("GHIDRA_BACKEND"):
            if "ghidra" not in config_data:
                config_data["ghidra"] = {}
            config_data["ghidra"]["backend"] = os.getenv("GHIDRA_BACKEND")

        if os.getenv("PYGHIDRA_PROJECT_PATH"):
            if "ghidra" not in config_data:
                config_data["ghidra"] = {}
            config_data["ghidra"]["pyghidra_project_path"] = os.getenv("PYGHIDRA_PROJECT_PATH")

        if os.getenv("PYGHIDRA_PROGRAM"):
            if "ghidra" not in config_data:
                config_data["ghidra"] = {}
            config_data["ghidra"]["pyghidra_program"] = os.getenv("PYGHIDRA_PROGRAM")

        if os.getenv("PYGHIDRA_BINARY"):
            if "ghidra" not in config_data:
                config_data["ghidra"] = {}
            config_data["ghidra"]["pyghidra_binary"] = os.getenv("PYGHIDRA_BINARY")

        # Load LLM Provider
        if os.getenv("LLM_PROVIDER"):
            config_data["llm_provider"] = os.getenv("LLM_PROVIDER").lower()

        # Load Google Configuration
        if os.getenv("GOOGLE_API_KEY"):
            if "google" not in config_data:
                config_data["google"] = {}
            config_data["google"]["api_key"] = os.getenv("GOOGLE_API_KEY")

        if os.getenv("GOOGLE_MODEL"):
            if "google" not in config_data:
                config_data["google"] = {}
            config_data["google"]["model"] = os.getenv("GOOGLE_MODEL")

        if os.getenv("GOOGLE_EMBEDDING_MODEL"):
            if "google" not in config_data:
                config_data["google"] = {}
            config_data["google"]["embedding_model"] = os.getenv("GOOGLE_EMBEDDING_MODEL")

        if os.getenv("GOOGLE_TIMEOUT"):
            if "google" not in config_data:
                config_data["google"] = {}
            try:
                config_data["google"]["timeout"] = int(os.getenv("GOOGLE_TIMEOUT"))
            except ValueError:
                pass

        if os.getenv("GOOGLE_REQUEST_DELAY"):
            if "google" not in config_data:
                config_data["google"] = {}
            try:
                config_data["google"]["request_delay"] = float(os.getenv("GOOGLE_REQUEST_DELAY"))
            except ValueError:
                pass

        if os.getenv("GOOGLE_MAX_RETRIES"):
            if "google" not in config_data:
                config_data["google"] = {}
            try:
                config_data["google"]["max_retries"] = int(os.getenv("GOOGLE_MAX_RETRIES"))
            except ValueError:
                pass

        # Load External Configuration
        if "external" not in config_data:
            config_data["external"] = {}

        if os.getenv("EXTERNAL_PROVIDER"):
            config_data["external"]["provider"] = os.getenv("EXTERNAL_PROVIDER")
        if os.getenv("EXTERNAL_API_KEY"):
            config_data["external"]["api_key"] = os.getenv("EXTERNAL_API_KEY")
        if os.getenv("EXTERNAL_MODEL"):
            config_data["external"]["model"] = os.getenv("EXTERNAL_MODEL")
        if os.getenv("EXTERNAL_EMBEDDING_MODEL"):
            config_data["external"]["embedding_model"] = os.getenv("EXTERNAL_EMBEDDING_MODEL")
        if os.getenv("EXTERNAL_TIMEOUT"):
            try:
                config_data["external"]["timeout"] = int(os.getenv("EXTERNAL_TIMEOUT"))
            except ValueError:
                pass
        if os.getenv("EXTERNAL_TEMPERATURE"):
            try:
                config_data["external"]["temperature"] = float(os.getenv("EXTERNAL_TEMPERATURE"))
            except ValueError:
                pass
        if os.getenv("EXTERNAL_MAX_TOKENS"):
            try:
                config_data["external"]["max_tokens"] = int(os.getenv("EXTERNAL_MAX_TOKENS"))
            except ValueError:
                pass

        if os.getenv("EXTERNAL_REQUEST_DELAY"):
            try:
                config_data["external"]["request_delay"] = float(os.getenv("EXTERNAL_REQUEST_DELAY"))
            except ValueError:
                pass

        if os.getenv("EXTERNAL_MAX_RETRIES"):
            try:
                config_data["external"]["max_retries"] = int(os.getenv("EXTERNAL_MAX_RETRIES"))
            except ValueError:
                pass

        # Load Shared Fields for External (Context, Logging)
        if os.getenv("CONTEXT_BUDGET"):
            try:
                config_data["external"]["context_budget"] = int(os.getenv("CONTEXT_BUDGET"))
            except ValueError:
                pass

        # Logging settings
        if os.getenv("LLM_LOGGING_ENABLED"):
            config_data["external"]["llm_logging_enabled"] = os.getenv("LLM_LOGGING_ENABLED").lower() == "true"
        if os.getenv("LLM_LOG_FILE"):
            config_data["external"]["llm_log_file"] = os.getenv("LLM_LOG_FILE")

        # Ensure model_map is explicitly empty to prevent pollution from Ollama models
        config_data["external"]["model_map"] = {}

        # DEBUG: Print final config structure for external to verify isolation
        # print(f"DEBUG: External Config Loaded: {config_data.get('external')}")

        # Ensure model_map is clean
        config_data["external"]["model_map"] = {}

        # Ensure model_map for Google is initialized but empty to prevent pollution
        if "google" in config_data:
            # We explicitly don't want to copy Ollama's model_map to Google
            # unless we implement GOOGLE_MODEL_PLANNING etc. later.
            config_data["google"]["model_map"] = {}

        # Load Custom API Configuration
        if "custom_api" not in config_data:
            config_data["custom_api"] = {}

        if os.getenv("CUSTOM_API_URL"):
            config_data["custom_api"]["api_url"] = os.getenv("CUSTOM_API_URL")
        if os.getenv("CUSTOM_API_KEY"):
            config_data["custom_api"]["api_key"] = os.getenv("CUSTOM_API_KEY")
        if os.getenv("CUSTOM_API_MODEL"):
            config_data["custom_api"]["model"] = os.getenv("CUSTOM_API_MODEL")
        if os.getenv("CUSTOM_API_EMBEDDING_MODEL"):
            config_data["custom_api"]["embedding_model"] = os.getenv("CUSTOM_API_EMBEDDING_MODEL")
        if os.getenv("CUSTOM_API_TIMEOUT"):
            try:
                config_data["custom_api"]["timeout"] = int(os.getenv("CUSTOM_API_TIMEOUT"))
            except ValueError:
                pass
        if os.getenv("CUSTOM_API_TEMPERATURE"):
            try:
                config_data["custom_api"]["temperature"] = float(os.getenv("CUSTOM_API_TEMPERATURE"))
            except ValueError:
                pass
        if os.getenv("CUSTOM_API_MAX_TOKENS"):
            try:
                config_data["custom_api"]["max_tokens"] = int(os.getenv("CUSTOM_API_MAX_TOKENS"))
            except ValueError:
                pass
        if os.getenv("CUSTOM_API_VERIFY_SSL"):
            config_data["custom_api"]["verify_ssl"] = os.getenv("CUSTOM_API_VERIFY_SSL").lower() == "true"
        if os.getenv("CUSTOM_API_REQUEST_DELAY"):
            try:
                config_data["custom_api"]["request_delay"] = float(os.getenv("CUSTOM_API_REQUEST_DELAY"))
            except ValueError:
                pass
        if os.getenv("CUSTOM_API_MAX_RETRIES"):
            try:
                config_data["custom_api"]["max_retries"] = int(os.getenv("CUSTOM_API_MAX_RETRIES"))
            except ValueError:
                pass

        # Advanced throttling settings
        if os.getenv("CUSTOM_API_MAX_CONCURRENCY"):
            try:
                config_data["custom_api"]["max_concurrency"] = int(os.getenv("CUSTOM_API_MAX_CONCURRENCY"))
            except ValueError:
                pass
        if os.getenv("CUSTOM_API_GLOBAL_MIN_INTERVAL"):
            try:
                config_data["custom_api"]["global_min_interval"] = float(os.getenv("CUSTOM_API_GLOBAL_MIN_INTERVAL"))
            except ValueError:
                pass
        if os.getenv("CUSTOM_API_RESPECT_RETRY_AFTER"):
            config_data["custom_api"]["respect_retry_after"] = os.getenv("CUSTOM_API_RESPECT_RETRY_AFTER").lower() == "true"
        if os.getenv("CUSTOM_API_RETRY_AFTER_MAX_SECONDS"):
            try:
                config_data["custom_api"]["retry_after_max_seconds"] = int(os.getenv("CUSTOM_API_RETRY_AFTER_MAX_SECONDS"))
            except ValueError:
                pass

        # Adaptive throttling
        if os.getenv("CUSTOM_API_ADAPTIVE_THROTTLE_ENABLED"):
            config_data["custom_api"]["adaptive_throttle_enabled"] = (
                os.getenv("CUSTOM_API_ADAPTIVE_THROTTLE_ENABLED").lower() == "true"
            )
        if os.getenv("CUSTOM_API_ADAPTIVE_MAX_INTERVAL"):
            try:
                config_data["custom_api"]["adaptive_max_interval"] = float(os.getenv("CUSTOM_API_ADAPTIVE_MAX_INTERVAL"))
            except ValueError:
                pass
        if os.getenv("CUSTOM_API_ADAPTIVE_INCREASE_FACTOR"):
            try:
                config_data["custom_api"]["adaptive_increase_factor"] = float(os.getenv("CUSTOM_API_ADAPTIVE_INCREASE_FACTOR"))
            except ValueError:
                pass
        if os.getenv("CUSTOM_API_ADAPTIVE_DECREASE_FACTOR"):
            try:
                config_data["custom_api"]["adaptive_decrease_factor"] = float(os.getenv("CUSTOM_API_ADAPTIVE_DECREASE_FACTOR"))
            except ValueError:
                pass
        if os.getenv("CUSTOM_API_ADAPTIVE_SUCCESS_STREAK_THRESHOLD"):
            try:
                config_data["custom_api"]["adaptive_success_streak_threshold"] = int(
                    os.getenv("CUSTOM_API_ADAPTIVE_SUCCESS_STREAK_THRESHOLD")
                )
            except ValueError:
                pass
        if os.getenv("CUSTOM_API_ADAPTIVE_JITTER_SECONDS"):
            try:
                config_data["custom_api"]["adaptive_jitter_seconds"] = float(os.getenv("CUSTOM_API_ADAPTIVE_JITTER_SECONDS"))
            except ValueError:
                pass

        # Context budget and execution loop settings
        if os.getenv("CONTEXT_BUDGET"):
            try:
                config_data["custom_api"]["context_budget"] = int(os.getenv("CONTEXT_BUDGET"))
            except ValueError:
                pass
        if os.getenv("MAX_EXECUTION_STEPS"):
            try:
                config_data["custom_api"]["max_execution_steps"] = int(os.getenv("MAX_EXECUTION_STEPS"))
            except ValueError:
                pass
        if os.getenv("MAX_AGENTIC_CYCLES"):
            try:
                config_data["custom_api"]["max_agentic_cycles"] = int(os.getenv("MAX_AGENTIC_CYCLES"))
            except ValueError:
                pass
        if os.getenv("AGENTIC_LOOP_ENABLED"):
            config_data["custom_api"]["agentic_loop_enabled"] = os.getenv("AGENTIC_LOOP_ENABLED").lower() == "true"

        # Logging settings
        if os.getenv("LLM_LOGGING_ENABLED"):
            config_data["custom_api"]["llm_logging_enabled"] = os.getenv("LLM_LOGGING_ENABLED").lower() == "true"
        if os.getenv("LLM_LOG_FILE"):
            config_data["custom_api"]["llm_log_file"] = os.getenv("LLM_LOG_FILE")

        # Ensure model_map is explicitly empty to prevent pollution
        config_data["custom_api"]["model_map"] = {}

        _config_instance = BridgeConfig(**config_data)
    return _config_instance
