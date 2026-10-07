"""Validate external YAML/JSON once; pass typed models through the application."""

from pathlib import Path
from typing import Annotated, Literal, Self

import yaml
from pydantic import AnyHttpUrl, BaseModel, ConfigDict, Field, model_validator

NonemptyString = Annotated[str, Field(min_length=1)]
ServerName = Annotated[str, Field(pattern=r"^[A-Za-z][A-Za-z0-9_]*$")]


class ConfigModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
        allow_inf_nan=False,
        hide_input_in_errors=True,
    )


class LMConfig(ConfigModel):
    """DSPy/LiteLLM settings"""

    model: NonemptyString = Field(
        description=(
            "DSPy/LiteLLM identifier: <provider>/<exact model ID>. The first "
            "prefix selects the API integration; the remaining ID may contain "
            "slashes. This is not a URL. No aliases or prefix rewriting are "
            "applied. For a server ID openai/gpt-oss-120b, use "
            "hosted_vllm/openai/gpt-oss-120b or openai/openai/gpt-oss-120b."
        ),
        examples=[
            "openai/gpt-4o",
            "anthropic/claude-sonnet-4-5-20250929",
            "ollama_chat/llama3.2",
            "hosted_vllm/openai/gpt-oss-120b",
            "openai/openai/gpt-oss-120b",
        ],
    )
    api_base: AnyHttpUrl | None = Field(
        default=None,
        description=(
            "API base URL, separate from model. For an OpenAI-compatible "
            "server, typically http://127.0.0.1:8000/v1; for native Ollama, "
            "http://127.0.0.1:11434. Do not append /models or "
            "/chat/completions. Omit to use the provider's default endpoint."
        ),
    )
    api_key_env: NonemptyString | None = Field(
        default=None,
        description=(
            "Name of the environment variable containing this LM endpoint's "
            "API key, not the key itself. It must be available to the MCP "
            "server process. Omit for an endpoint that needs no key."
        ),
    )
    cache: bool = False
    max_tokens: int = Field(default=4096, gt=0)
    temperature: float | None = Field(default=None, ge=0)
    timeout: float = Field(default=120.0, gt=0)
    num_retries: int = Field(default=3, ge=0)
    ssl_verify: bool = Field(
        default=True,
        description=(
            "Verify HTTPS server certificates. Keep true for internal servers "
            "too; certificate trust is configured by application startup "
            "(for example, truststore), not by this configuration model."
        ),
    )


class StdioServerConfig(ConfigModel):
    transport: Literal["stdio"] = "stdio"
    command: NonemptyString
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)
    evidence_tools: list[NonemptyString] = Field(default_factory=list)


class HttpServerConfig(ConfigModel):
    transport: Literal["sse", "streamable-http"]
    url: AnyHttpUrl
    evidence_tools: list[NonemptyString] = Field(default_factory=list)


MCPServerConfig = Annotated[
    StdioServerConfig | HttpServerConfig, Field(discriminator="transport")
]


class AppConfig(ConfigModel):
    lm: LMConfig
    mcp_servers: dict[ServerName, MCPServerConfig] = Field(
        json_schema_extra={"required": ["ghidra"]},
    )
    max_iters: int = Field(default=6, gt=0)
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(
        default="INFO"
    )
    log_file: NonemptyString | None = "logs/oghidra-{pid}.jsonl"
    log_max_bytes: int = Field(default=5_000_000, gt=0)
    log_backup_count: int = Field(default=3, ge=1)
    compiled_predictor: NonemptyString | None = None

    @model_validator(mode="after")
    def require_ghidra(self) -> Self:
        if "ghidra" not in self.mcp_servers:
            raise ValueError("mcp_servers must include a 'ghidra' server")
        return self


def load_config(path: Path) -> AppConfig:
    """Load YAML (JSON is also valid YAML); resolve predictor relative to this file.

    Syntax errors and Pydantic ValidationErrors propagate with useful locations.
    No model connections or MCP subprocesses are started here.
    """
    config = AppConfig.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))
    if config.compiled_predictor is not None:
        config = config.model_copy(
            update={
                "compiled_predictor": str(
                    (path.parent / config.compiled_predictor).resolve()
                ),
            }
        )
    return config
