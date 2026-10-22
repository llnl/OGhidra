# Model and MCP host setup

## Model identifiers

The `lm` section configures DSPy's model connection; it does not inherit the
model used by the MCP host. Construct `lm.model` as:

```text
lm.model = <LiteLLM integration> + "/" + <exact endpoint model ID>
```

Only the first slash separates LiteLLM's integration name from the model ID.
Everything after it must exactly match the identifier reported by the endpoint,
including any provider-like prefix or additional slashes. `model` is not a URL;
`api_base` is the separate base URL.

| Connection | Exact ID reported by endpoint | LiteLLM integration | `lm.model` | `lm.api_base` |
| --- | --- | --- | --- | --- |
| OpenAI | `gpt-4o` | `openai` | `openai/gpt-4o` | Omit |
| Anthropic | `claude-sonnet-4-5-20250929` | `anthropic` | `anthropic/claude-sonnet-4-5-20250929` | Omit |
| Native Ollama chat | `llama3.2` | `ollama_chat` | `ollama_chat/llama3.2` | `http://127.0.0.1:11434` |
| Hosted vLLM | `openai/gpt-oss-120b` | `hosted_vllm` | `hosted_vllm/openai/gpt-oss-120b` | `http://127.0.0.1:8000/v1` |
| Generic OpenAI-compatible API | `openai/gpt-oss-120b` | `openai` | `openai/openai/gpt-oss-120b` | `http://127.0.0.1:8000/v1` |

Replace every example with a model available to your installation or account.
For OpenAI-compatible services, `api_base` normally ends in `/v1`; do not
append `/models` or `/chat/completions`. Native Ollama uses its base URL without
`/v1`.

For a server that reports the literal ID `openai/gpt-oss-120b`, the doubled
form `openai/openai/gpt-oss-120b` is intentional with LiteLLM's generic OpenAI
integration. The first `openai/` selects the integration; the second is part of
the exact endpoint ID. Conversely, `openai/gpt-oss-120b` is correct only if the
endpoint reports the literal ID `gpt-oss-120b`.

`api_key_env` is the name of an environment variable, not a secret value. The
variable must be visible to the Codex process that launches OGhidra. Keep
`ssl_verify: true`.

Supported LM fields are `model`, `api_base`, `api_key_env`, `cache`,
`max_tokens`, `temperature`, `timeout`, `num_retries`, and `ssl_verify`.
Configuration validation checks types and local requirements, not whether a
remote model exists or accepts the selected parameters. By default doctor does
not query `/models`, perform inference, or make a billable model request. Run
`oghidra-doctor --check-model` to make a small, uncached inference request that
can detect an exact-ID mismatch and other provider, authentication, transport,
or TLS failures. This optional request can incur a provider charge.

## Codex configuration scope

`codex mcp add` writes the normal shared Codex configuration. Codex CLI, the
IDE extension, and the ChatGPT desktop app use that configuration for the same
local Codex host.

Codex also supports project-scoped `.codex/config.toml` in trusted projects.
This is useful when the registration should apply only to this checkout, but
machine-specific absolute paths should not be committed. See the
[official Codex MCP documentation](https://developers.openai.com/codex/mcp/)
for the current configuration schema.

## Other MCP hosts

[`mcp.example.json`](../mcp.example.json) is a strict-JSON template for clients
that explicitly load MCP configuration files. Copy it to the ignored local
`mcp.json`, then replace every `/absolute/path/to/OGhidra` placeholder with the
repository's absolute path:

```bash
cp mcp.example.json mcp.json
```

On Windows, use `.venv\Scripts\oghidra-workflows.exe`. Keep secrets out of
both files; configure only the environment-variable name in `config.yaml`.

A compatible Claude CLI installation can, for example, be started with:

```bash
claude --mcp-config /absolute/path/to/OGhidra/mcp.json
```

Other hosts must use their own MCP settings. In every case, `pyghidra` is the
Streamable HTTP server at `http://127.0.0.1:8001/mcp`, while `oghidra` is the
stdio executable `.venv/bin/oghidra-workflows --config config.yaml`. Starting
the executable manually leaves it waiting for stdio MCP input; it does not open
another HTTP port.
