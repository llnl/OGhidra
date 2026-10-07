# OGhidra workflows — PyGhidra backend

## Diagnostics and crash logs


```yaml
log_level: DEBUG
log_file: logs/oghidra-{pid}.jsonl
log_max_bytes: 5000000
log_backup_count: 3
```

Paths are relative to the directory containing `config.yaml`, regardless of the
client's working directory. `{pid}` expands to the workflow process ID, avoiding
rotation conflicts between separate client-launched processes. Each process's
file rotates at 5 MB with three backups by default. Files from older processes
remain until removed; rotation is per process, not global retention. Set
`log_file: null` for stderr only. Malformed/unreadable configuration gets a
fallback startup error log at `logs/oghidra-PID.jsonl` if that folder is writable.
If a requested log file cannot be opened, startup fails visibly on stderr.

Normal logging never writes to stdout: stdout belongs to the stdio MCP protocol.
Human-readable stderr logs appear in the launching client's server logs and in
the terminal when run directly. JSON files include UTC timestamp, process,
logger, request ID, stage, timing, and event-specific metadata. Each workflow
request has its own correlation ID, also returned in tool errors and uncertain
rename results.

At INFO, look for `server.starting`, `server.ready`, `workflow.started`,
`mcp.initialized`, `workflow.target_selected`, and `workflow.completed`. At DEBUG,
`stage.started` / `stage.completed` identify connect, initialize, discovery,
decompile, DSPy evidence/naming, pre-write checks, rename, verification, and
cleanup. DSPy's native callbacks record LM/tool call IDs and durations; tool
errors are logged even when ReAct handles them and continues. `stage.failed`
records the original traceback, including chained exceptions and nested
ExceptionGroup causes. An error from the rename phase that becomes
`verification_failed` is also logged with its traceback.

To diagnose a failure:

1. Find the `request_id` in the client's tool error.
2. Open the newest `logs/oghidra-*.jsonl` file beside the configuration.
3. Find that request ID and inspect the first `stage.failed` or
   `dspy.*.failed` event and its `exc_info`. Later session cleanup failures may
   repeat or wrap the same cause.
4. If the client cannot launch the process, inspect its stderr log. Import
   failures before configured logging initializes appear there. The root
   `main.py` launcher retains a bootstrap traceback.

PowerShell tail:

```powershell
$log = Get-ChildItem .\logs\oghidra-*.jsonl | Sort-Object LastWriteTime -Descending | Select-Object -First 1
Get-Content $log.FullName -Tail 40 -Wait
```

The startup event records the interpreter, Python/library versions, CWD, absolute
config path, and log path. This helps distinguish the VSCode environment from the
one the agent client launches. `server.exited` indicates that the stdio transport
returned (for example, the client closed stdin), rather than a recorded Python
exception. `server.failed`, `process.uncaught`, `thread.uncaught`, and
`async.unhandled` preserve corresponding unhandled exception tracebacks.

Prompts, decompiled code, complete model responses, tool arguments/results,
subprocess arguments, and environment dictionaries are not deliberately logged.
Known credential environment values and common credential patterns are redacted;
endpoint metadata excludes URL userinfo, query parameters, and fragments.
Pydantic errors omit input-value representations. Provider/HTTP payload debug
logging stays disabled even at OGhidra DEBUG level. Exceptions still contain
upstream error messages, which may contain sensitive application data not covered
by redaction; review logs before sharing them.

Native faults handled by Python's `faulthandler` write thread stacks to stderr,
not the rotating JSON file. A forced kill, power loss, or a crash in the separate
PyGhidra-MCP process cannot be given an in-process Python traceback here; use the
upstream process's logs alongside the last OGhidra stage. This implementation
uses standard `logging`, `RotatingFileHandler`, `python-json-logger`, and DSPy's
callback API, with no external logging service.

A client-side configuration error can prevent OGhidra from being launched at all;
in that case there will be no new OGhidra log. For model identifier and endpoint
configuration, see the model connection instructions below.


One product: `rename_current_function(apply=True)`, implemented with DSPy and exposed through MCP. This version uses **clearbluejar/pyghidra-mcp 0.2.7** to launch the Ghidra GUI and serve MCP over Streamable HTTP. LaurieWired's extension and Python bridge are not used.

PyGhidra supplies Python access to Ghidra APIs. The separate upstream **pyghidra-mcp** project supplies the MCP tools and GUI lifecycle. OGhidra contains neither a copied backend nor its own Ghidra API wrapper.

## Start Ghidra and its MCP server

Use a separate environment for the upstream server so its dependencies and the workflow's dependencies can evolve independently. Install Ghidra and the JDK required by your Ghidra release first.

Windows PowerShell (paths are examples):

```powershell
python -m venv .venv-ghidra
.\.venv-ghidra\Scripts\python.exe -m pip install uv
.\.venv-ghidra\Scripts\python.exe -m uv pip "pyghidra-mcp==0.2.7"
$env:GHIDRA_INSTALL_DIR = 'C:\path\to\ghidra\installation'
.\.venv-ghidra\Scripts\pyghidra-mcp.exe --gui --transport streamable-http --host 127.0.0.1 --port 8001 --project-path 'C:\path\to\your\project.gpr'
```

On Linux/macOS, activate the backend environment, set `GHIDRA_INSTALL_DIR`, and launch Ghidra GUI with pyghidra MCP enabled with something like this:

```bash
pyghidra-mcp --gui --transport streamable-http --host 127.0.0.1 --port 8001 --project-path /absolute/path/to/research.gpr
```

This launches Ghidra. Open the desired program in its CodeBrowser, wait for analysis to finish, and select a location within a function. Keep this process running. Save/close any other Ghidra instance using the same project before starting this one; the backend cannot attach to an independently launched GUI. Ghidra/MCP run in the same JVM here, so changes are live in that GUI.

The MCP endpoint is `http://127.0.0.1:8001/mcp`. This is actual MCP over Streamable HTTP, with no intermediate REST bridge. Port 8001 avoids the example LM service on port 8000.

## Configure OGhidra

Python 3.12 or later, from this project's root:

```bash
python -m venv .venv
# Activate .venv using the command for your shell.
python -m pip install uv
uv pip install -e '.[test]'
```

Copy `config.example.yaml` to `config.yaml` and set the actual model name/endpoint. Keep this backend entry:

```yaml
mcp_servers:
  ghidra:
    transport: streamable-http
    url: http://127.0.0.1:8001/mcp
    evidence_tools:
      - decompile_function
      - list_xrefs
```

### Model connection: provider prefix, model ID, and URL

The `lm` section configures DSPy's own model connection; it does not inherit the
host client's model. OGhidra passes `lm.model` directly to `dspy.LM` without
aliases, automatic prefix insertion/removal, or provider-specific parsing.
There is no separate `provider` configuration field.

Use DSPy/LiteLLM's format:

```text
<LiteLLM provider>/<exact model identifier>
```

The first prefix selects the API integration, not necessarily the model's
publisher. The remainder is the model ID and can itself contain slashes.
`model` is not a URL; `api_base` is the separate API base URL. An ID returned by
`/v1/models` is not necessarily a complete DSPy model string.

For example, if your server returns `"id": "openai/gpt-oss-120b"`, configure:

```yaml
lm:
  model: hosted_vllm/openai/gpt-oss-120b
  api_base: https://your-model-server.example/v1
  ssl_verify: true
  # Uncomment when the endpoint requires authentication:
  # api_key_env: OGHIDRA_MODEL_API_KEY
```

`hosted_vllm/` selects LiteLLM's hosted vLLM integration. Use this prefix for
hosted vLLM; `vllm/` is the deprecated local SDK integration. The generic
OpenAI-compatible integration also works with this server: set
`model: openai/openai/gpt-oss-120b`. The first `openai/` selects the integration;
the second is part of the server's literal ID. Do not deduplicate them.

| API integration | Exact model ID (example) | `lm.model` | `lm.api_base` |
| --- | --- | --- | --- |
| OpenAI directly | `gpt-4o` | `openai/gpt-4o` | Omit |
| Anthropic directly | `claude-sonnet-4-5-20250929` | `anthropic/claude-sonnet-4-5-20250929` | Omit |
| Native Ollama chat | `llama3.2` | `ollama_chat/llama3.2` | `http://127.0.0.1:11434` |
| Hosted vLLM | `openai/gpt-oss-120b` | `hosted_vllm/openai/gpt-oss-120b` | `http://127.0.0.1:8000/v1` |
| Generic OpenAI-compatible API | `openai/gpt-oss-120b` | `openai/openai/gpt-oss-120b` | `http://127.0.0.1:8000/v1` |
| Generic OpenAI-compatible API | `mistralai/Devstral-2-123B-Instruct-2512` | `openai/mistralai/Devstral-2-123B-Instruct-2512` | Your server's API base |

Model IDs above are examples, not availability guarantees. Use the exact ID
provided by your service. Other LiteLLM integrations use their documented
prefixes and endpoint settings; no OGhidra alias list is needed. Keep all parts
of the server model ID, including organization names and tags.

For OpenAI-compatible services, `api_base` typically ends in `/v1`. Do not
append `/models` or `/chat/completions`; the client adds the request endpoint.
For native Ollama, use its base URL without `/v1` as shown above.

`api_key_env` is an environment variable **name**, not the secret value. For
an authenticated endpoint, set it explicitly and make sure that variable is
available to the MCP server launched by your client. For example, use
`api_key_env: ANTHROPIC_API_KEY` for a direct Anthropic connection. Omit it for
an endpoint that needs no key. When comparing curl with OGhidra, use the same
base URL and credentials. Restart the workflow MCP server after config changes.

Keep `ssl_verify: true`, including on internal HTTPS endpoints. When the server
entry point initializes `truststore` before importing DSPy and HTTP clients,
verification uses system trust on Windows and Linux. Setting this flag alone
does not initialize truststore. Certificates must be trusted in the account
and environment running the process; WSL and containers have separate trust
configuration from the Windows host.

If a request fails with "Invalid model name", compare the model ID in the
server's error with the exact `/v1/models` ID. For the example above, an error
showing only `gpt-oss-120b` means the model namespace was consumed as the routing
prefix: use `hosted_vllm/openai/gpt-oss-120b` or
`openai/openai/gpt-oss-120b`. A successful `/models` request alone does not test
chat completion access.

Supported LM fields: `model`, `api_base`, `api_key_env`, `cache`, `max_tokens`,
`temperature`, `timeout`, `num_retries`, and `ssl_verify`. Add explicit typed
fields when more settings are needed; arbitrary options are rejected. Config
validation checks field types, not whether a remote model exists or accepts
the selected generation parameters.

## Connect Your Client

Claude (or any host) launches the OGhidra workflow server over stdio. Both your client and OGhidra connects to the existing PyGhidra-MCP HTTP endpoint.

```json
{
  "mcpServers": {
    "pyghidra": {
      "command": "cmd",
      "args": [
        "/c",
        "npx",
        "-y",
        "mcp-remote",
        "http://127.0.0.1:8001/mcp",
        "--transport",
        "http-only",
        "--allow-http"
      ]
    },
    "oghidra-workflows": {
      "command": "C:/path/to/oghidra-workflows/.venv/Scripts/python.exe",
      "args": [
        "C:/path/to/oghidra-workflows/main.py",
        "--config",
        "C:/path/to/oghidra-workflows/config.yaml"
      ],
      "env": {
        "OGHIDRA_MODEL_API_KEY": "your-model-api-key"
      }
    }
  }
}
```

Omit `env` if the process already inherits the needed key or no key is configured. Restart the host after editing its configuration. Starting `main.py` manually with no check flag leaves it waiting for stdio MCP input; it does not expose another HTTP port.

For ease of use, a copy of this configuration for your claude client is found in `dsp.json` and can be loaded with a command such as `claude --mcp-config ./mcp.json`.

## What the workflow does

1. Calls upstream `get_gui_context()` and captures the active program path, cursor address, and function name.
2. Calls upstream `decompile_function(binary_name, name_or_address)` with the captured program and address. Addresses within functions are supported by upstream's containing-function lookup.
3. Uses typed DSPy prediction for a name, analysis, behavioral summary, and rationale. Optional `dspy.ReAct` gathers additional evidence through `dspy.Tool.from_mcp_tool`, using the program/address in its task context.
4. Rechecks the active program, cursor, and old name before writing.
5. Calls upstream `rename_function(binary_name, name_or_address, new_name)` exactly once.
6. Validates the structured rename receipt and reads the GUI context again. Only matching receipt and read-back return `status="renamed"`.

The result includes the captured `binary_name` and `address` (cursor address, not necessarily the entry point). After a rename receipt, `function_entry_address` contains the entry point reported by upstream. Structured response models validate the required fields. There is no parsing of old `Function: NAME at ADDRESS` text, no invented function identity, and no compatibility layer for LaurieWired tools.

Return statuses are `proposed`, `unchanged`, `renamed`, and `verification_failed`. Pre-write errors are MCP tool errors. An uncertain write is never retried automatically. Keep the cursor on the selected function until the call finishes: moving after a successful write can prevent GUI read-back verification and therefore returns `verification_failed`. Inspect Ghidra before retrying. This is a live program edit; save the program through Ghidra as usual.

The upstream tools do not offer an atomic compare-and-rename operation. Pre-write checks detect observed selection changes, but cannot prevent another client editing or replacing a program between calls. The program path is now explicitly part of every decompile/write request. Calls in one workflow process are serialized.

## Typed configuration and tool extensibility

`load_config(Path(...)) -> AppConfig` accepts YAML and JSON. Nested Pydantic models use `strict=True` and `extra="forbid"`; unknown fields and stringified numbers/booleans fail at startup. `config.lm.model` and `config.max_iters` are typed attributes. Transport is a discriminated union of stdio and HTTP settings. Models block field reassignment, but nested containers are not deeply immutable; treat config as read-only.

```bash
python main.py --schema > config.schema.json
```

The YAML example links this generated schema for editor validation. The Python models remain the single source of truth. Static types help Python callers; validation of external YAML values still happens at load time.

Additional MCP servers can be added to `mcp_servers`. `evidence_tools` lists their trusted read-only tools available to the DSPy investigation; upstream discovery supplies descriptions and parameter schemas. Internal DSPy names are `server__tool` to avoid collisions. The list is not a sandbox: tools have the effects their upstream implementation provides. Workflow writes are deterministic, outside ReAct.

## DSPy optimization

`examples/optimize.py` compiles the naming predictor using `BootstrapFewShot` and analyst-reviewed JSONL. Each row contains `function_name`, `decompiled_code`, `related_context`, and a `proposal` object with `suggested_name`, `analysis`, `behavior_summary`, and `rationale`. Use held-out binaries to avoid duplicate leakage:

```bash
python examples/optimize.py config.yaml train.jsonl heldout.jsonl predictor.json
```

Set `compiled_predictor` to the saved JSON path, relative to the config file. The script evaluates exact accepted-name matches; extend the metric for multiple acceptable names. This trains naming from supplied evidence, not evidence gathering. No trained artifact or naming-quality claim is bundled.

## Scope, dependencies, and validation

Runtime source consists of typed configuration, standard MCP connections, the DSPy workflow, and MCP entry points. There is no GUI implementation, provider wrapper, custom agent loop, RAG, or Ghidra backend in this repository. Upstream pyghidra-mcp itself includes ChromaDB/indexing dependencies; using this backend does not eliminate those third-party dependencies. Keep it in its own environment. For enclaves, stage approved dependencies and upstream model/indexing assets and configure internal endpoints; the workflow is not a claim that all third-party dependencies are network-free.

The backend contract was inspected in the published **pyghidra-mcp 0.2.7 wheel**, specifically `mcp_tools.py`, `models.py`, `tools.py`, and `gui_context.py`. The README's abbreviated API listing can lag the code (for example, `get_gui_context`). The decompiler's `name` field is a filename-like label, so the workflow uses GUI context for the real function name; it also rejects code/error responses lacking a successful signature.

```bash
pytest -q
```

Tests cover strict config, typed DSPy outputs, MCP discovery, native ReAct tool calls, and both stdio and Streamable HTTP backend sessions. The full host → workflow stdio → simulated PyGhidra-MCP HTTP path is tested. Ghidra behavior and LM responses are fixtures. Actual JVM/GUI integration and naming quality still require a live test in your environment. DSPy 3.3.1 and MCP Python SDK 1.30.0 are pinned; `constraints-tested.txt` records the workflow test environment, not the separately installed backend.

## Sources and license

- PyGhidra-MCP: https://github.com/clearbluejar/pyghidra-mcp
- Inspected release: https://pypi.org/project/pyghidra-mcp/0.2.7/
- DSPy MCP: https://dspy.ai/learn/programming/mcp/
- DSPy language models: https://dspy.ai/learn/programming/language_models/
- LiteLLM hosted vLLM: https://docs.litellm.ai/docs/providers/vllm
- LiteLLM OpenAI-compatible endpoints: https://docs.litellm.ai/docs/providers/openai_compatible
- Official MCP Python SDK v1: https://github.com/modelcontextprotocol/python-sdk/tree/v1.x

The rename product derives from the supplied OGhidra archive's GUI rename workflow and typed `AnalyzeFunction` signature. `LICENSE` is retained verbatim from that archive, including its commercial-use terms. No upstream backend source is bundled.
