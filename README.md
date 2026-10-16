# OGhidra — AI-powered reverse engineering with Ghidra

OGhidra connects language models to Ghidra through MCP, giving an AI agent
grounded access to the program and project state in your live Ghidra session.
It can support workflows that:

- inspect and search decompiled code, disassembly, symbols, strings, imports,
  exports, cross-references, raw bytes, and call graphs;
- improve a program by renaming functions and variables, setting types and
  function prototypes, and adding comments;
- work with Ghidra projects and the GUI by importing or opening programs,
  navigating to analysis targets, and saving changes; and
- combine those primitives with DSPy to build repeatable, model-driven reverse
  engineering workflows.

`rename_current_function` is one packaged DSPy workflow: it gathers evidence
about the function selected in Ghidra, proposes a descriptive name, and can
apply that name after revalidating the target. It is an example of what OGhidra
can automate, not the limit of the underlying Ghidra toolset.

OGhidra does not launch a separate GUI or replace Ghidra. The upstream
`pyghidra-mcp` process launches Ghidra and exposes its analysis and editing
tools; this repository adds higher-level workflows that an MCP host can invoke.

## Architecture

```mermaid
flowchart LR
    Host["Codex / MCP host"] -->|"stdio: workflow tools"| OG["OGhidra workflows"]
    OG -->|"Ghidra evidence and actions"| Py["pyghidra-mcp"]
    Host -->|"direct Ghidra tools"| Py
    Py <--> GUI["Ghidra GUI / CodeBrowser"]
```

Both MCP servers are passive. Opening a project or program does not
automatically run an OGhidra workflow; the host decides which direct tools or
higher-level workflows to invoke.

## Quick start with Codex

### Prerequisites

- Python 3.12 or later.
- Ghidra and the JDK required by that Ghidra release. This repository does not
  pin or install either one.
- Codex CLI, the Codex IDE extension, or the ChatGPT desktop app using the same
  local Codex configuration.
- A model endpoint, plus an API key when that endpoint requires one.

### One-time setup

#### 1. Install the two Python environments

From the repository root, create one environment for the Ghidra backend and a
separate environment for the workflow:

```bash
python3.12 -m venv .venv-ghidra
source .venv-ghidra/bin/activate
python -m pip install uv
python -m uv pip install "pyghidra-mcp==0.2.7"
deactivate

python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install uv
uv pip install -e '.[test]'
cp config.example.yaml config.yaml
deactivate
```

<details>
<summary>Windows PowerShell</summary>

```powershell
py -3.12 -m venv .venv-ghidra
.\.venv-ghidra\Scripts\Activate.ps1
python -m pip install uv
python -m uv pip install "pyghidra-mcp==0.2.7"
deactivate

py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install uv
uv pip install -e '.[test]'
Copy-Item config.example.yaml config.yaml
deactivate
```

</details>

#### 2. Configure the model

Edit `config.yaml` and replace the example `lm` settings with the model and
endpoint you actually use. Keep the Ghidra endpoint at
`http://127.0.0.1:8001/mcp` unless you deliberately choose another port.

`api_key_env` is the name of an environment variable, not the secret itself.
When it is set, that variable must be available to the Codex process that
launches the `oghidra` stdio server. Keep `ssl_verify: true`.

See [Model connection](#model-connection) for provider-specific examples.

#### 3. Register both MCP servers with Codex

Replace `/absolute/path/to/OGhidra` with this repository's absolute path:

```bash
codex mcp add pyghidra --url http://127.0.0.1:8001/mcp

codex mcp add oghidra -- \
  /absolute/path/to/OGhidra/.venv/bin/python \
  /absolute/path/to/OGhidra/main.py \
  --config /absolute/path/to/OGhidra/config.yaml

codex mcp list
```

Codex stores these registrations in its shared configuration, so they work
regardless of the directory from which you start a later Codex session. Codex
does **not** automatically discover this repository's `mcp.json`.

<details>
<summary>Windows PowerShell</summary>

```powershell
codex mcp add pyghidra --url http://127.0.0.1:8001/mcp

codex mcp add oghidra -- `
  'C:\absolute\path\to\OGhidra\.venv\Scripts\python.exe' `
  'C:\absolute\path\to\OGhidra\main.py' `
  --config 'C:\absolute\path\to\OGhidra\config.yaml'

codex mcp list
```

</details>

### Every analysis session

#### 1. Launch Ghidra through PyGhidra-MCP

Do not independently launch Ghidra first. From the repository root:

```bash
source .venv-ghidra/bin/activate
export GHIDRA_INSTALL_DIR=/absolute/path/to/ghidra
pyghidra-mcp --gui --transport streamable-http --host 127.0.0.1 --port 8001 \
  --project-path /absolute/path/to/your-project.gpr
```

For a new project, provide a project directory and name instead:

```bash
pyghidra-mcp --gui --transport streamable-http --host 127.0.0.1 --port 8001 \
  --project-path /absolute/path/to/projects --project-name research
```

<details>
<summary>Windows PowerShell</summary>

```powershell
.\.venv-ghidra\Scripts\Activate.ps1
$env:GHIDRA_INSTALL_DIR = 'C:\absolute\path\to\ghidra'
pyghidra-mcp --gui --transport streamable-http --host 127.0.0.1 --port 8001 --project-path 'C:\absolute\path\to\project.gpr'
```

</details>

Keep this terminal and the launched Ghidra GUI running. A successful backend
startup includes:

```text
GUI-backed server initialized
Uvicorn running on http://127.0.0.1:8001
```

#### 2. Select the function in Ghidra

Open the actual program in CodeBrowser, wait for Ghidra analysis to finish, and
place the cursor inside the target function. Opening only the project is not
enough. Do not open the same project in another Ghidra instance.

#### 3. Start a new Codex session and invoke the workflow

Start or restart Codex after registering or changing an MCP server. In the
Codex TUI, use `/mcp` to confirm that `pyghidra` and `oghidra` are active.

`rename_current_function` is an MCP tool, not a slash command. Ask Codex in
normal language:

```text
Use the oghidra MCP server's rename_current_function tool with apply set to
false for the function currently selected in Ghidra.
```

`apply: false` returns a proposal without modifying the program. When ready,
ask for `apply: true`; that performs a fresh analysis and a live rename rather
than committing the earlier proposal. Keep the same program and function
selected until the request completes, then save the program through Ghidra.

## Other MCP hosts

[`mcp.example.json`](mcp.example.json) is the portable strict-JSON template for
clients that explicitly load MCP configuration files. Copy it to `mcp.json`,
then replace every `/absolute/path/to/OGhidra` placeholder with this
repository's absolute path. Windows users must use the corresponding
`.venv\Scripts\python.exe` path. Keep secrets out of both files; configure only
the environment-variable name in `config.yaml`.

```bash
cp mcp.example.json mcp.json
```

<details>
<summary>Windows PowerShell</summary>

```powershell
Copy-Item mcp.example.json mcp.json
```

</details>

For example, a compatible Claude CLI installation can be started with:

```bash
claude --mcp-config /absolute/path/to/OGhidra/mcp.json
```

Other hosts must be configured through their own MCP settings. In every case,
`pyghidra` is the Streamable HTTP server at
`http://127.0.0.1:8001/mcp`, while `oghidra` is the stdio process launched with
the workflow environment's Python, `main.py`, and the absolute `config.yaml`
path. Starting `main.py` manually leaves it waiting for stdio MCP input; it does
not expose another HTTP port.

## Troubleshooting first run

| Observation | Meaning and next action |
| --- | --- |
| `Uvicorn running on http://127.0.0.1:8001` | PyGhidra-MCP is ready. Keep that terminal running. |
| `GET / HTTP/1.1` returns `404` | Expected: the MCP endpoint is `/mcp`, not `/`. |
| `Module.manifest` warnings or a Ghidra MCP server on port 8080 | An obsolete Ghidra extension is installed. It is not used by this backend; disable it through Ghidra's extension manager to remove the noise. |
| Opening a program appears to do nothing | Expected: the servers wait for the host to invoke a tool. Check `/mcp`, then ask Codex to use `rename_current_function`. |
| The project is open but the workflow cannot find a function | Open a program in CodeBrowser and put the cursor inside a function. |
| No new `logs/oghidra-*.jsonl` file appears | The host did not launch the `oghidra` stdio server. Check the absolute registration paths and restart Codex. |
| `server.stopped`, `server.exited`, or `MCP resources released` appears | The host connection or Ghidra process ended. Relaunch the relevant process and start a new host session. |
| `/rename_current_function` is unknown | Only `/mcp` is a Codex slash command here. Request the MCP tool in normal language. |

## Model connection

The `lm` section configures DSPy's own model connection; it does not inherit the
model used by the MCP host. OGhidra passes `lm.model` directly to `dspy.LM`.
Use DSPy/LiteLLM's format:

```text
<LiteLLM provider>/<exact model identifier>
```

The first prefix selects the API integration. The remainder is the exact model
ID and may itself contain slashes. `model` is not a URL; `api_base` is the
separate API base URL.

For example, if a hosted vLLM server reports the ID
`openai/gpt-oss-120b`, configure:

```yaml
lm:
  model: hosted_vllm/openai/gpt-oss-120b
  api_base: https://your-model-server.example/v1
  ssl_verify: true
  # api_key_env: OGHIDRA_MODEL_API_KEY
```

| API integration | Exact model ID (example) | `lm.model` | `lm.api_base` |
| --- | --- | --- | --- |
| OpenAI directly | `gpt-4o` | `openai/gpt-4o` | Omit |
| Anthropic directly | `claude-sonnet-4-5-20250929` | `anthropic/claude-sonnet-4-5-20250929` | Omit |
| Native Ollama chat | `llama3.2` | `ollama_chat/llama3.2` | `http://127.0.0.1:11434` |
| Hosted vLLM | `openai/gpt-oss-120b` | `hosted_vllm/openai/gpt-oss-120b` | `http://127.0.0.1:8000/v1` |
| Generic OpenAI-compatible API | `openai/gpt-oss-120b` | `openai/openai/gpt-oss-120b` | `http://127.0.0.1:8000/v1` |

For OpenAI-compatible services, `api_base` typically ends in `/v1`; do not
append `/models` or `/chat/completions`. Native Ollama uses its base URL without
`/v1`. Use the exact model ID provided by the service. A successful `/models`
request does not prove chat-completion access.

`hosted_vllm/` selects LiteLLM's hosted vLLM integration. For a generic
OpenAI-compatible server whose literal model ID already starts with `openai/`,
the doubled form `openai/openai/...` is intentional: the first prefix selects
the integration and the second belongs to the model ID.

Supported LM fields are `model`, `api_base`, `api_key_env`, `cache`,
`max_tokens`, `temperature`, `timeout`, `num_retries`, and `ssl_verify`.
Configuration validation checks field types, not whether a remote model exists
or accepts the selected parameters.

## Diagnostics and crash logs

The example configuration enables rotating JSON logs:

```yaml
log_level: DEBUG
log_file: logs/oghidra-{pid}.jsonl
log_max_bytes: 5000000
log_backup_count: 3
```

Paths are relative to the directory containing `config.yaml`, regardless of the
host's working directory. `{pid}` prevents rotation conflicts between separate
host-launched processes. Set `log_file: null` for stderr only. A malformed or
unreadable configuration gets a fallback startup log at
`logs/oghidra-PID.jsonl` when that directory is writable.

Normal logging never writes to stdout because stdout carries the stdio MCP
protocol. Human-readable logs go to stderr and JSON logs include timestamps,
process information, request IDs, stages, and timing.

At INFO, look for `server.starting`, `server.ready`, `workflow.started`,
`mcp.initialized`, `workflow.target_selected`, and `workflow.completed`. At
DEBUG, `stage.started` and `stage.completed` identify connection, discovery,
decompilation, DSPy, rename, verification, and cleanup work. `stage.failed`
records the original traceback.

To diagnose a request failure:

1. Find the `request_id` in the host's tool error.
2. Open the newest `logs/oghidra-*.jsonl` file beside `config.yaml`.
3. Find that request ID and inspect the first `stage.failed` or
   `dspy.*.failed` entry.
4. If no new log exists, inspect the host's MCP stderr log because the workflow
   process may never have started.

<details>
<summary>Tail the newest log in PowerShell</summary>

```powershell
$log = Get-ChildItem .\logs\oghidra-*.jsonl | Sort-Object LastWriteTime -Descending | Select-Object -First 1
Get-Content $log.FullName -Tail 40 -Wait
```

</details>

The startup event records the interpreter, library versions, working directory,
absolute config path, and log path. `server.exited` means the stdio transport
returned, commonly because the host closed stdin. Native faults write thread
stacks to stderr; a forced kill or a crash in the separate PyGhidra-MCP process
cannot produce an OGhidra traceback.

Prompts, decompiled code, complete model responses, tool arguments/results,
subprocess arguments, and environment dictionaries are not deliberately logged.
Known credential environment values and common credential patterns are
redacted. Endpoint metadata excludes URL userinfo, query parameters, and
fragments. Exceptions can still contain upstream application data, so review
logs before sharing them.

## Workflow behavior and safety

The workflow:

1. Captures the active program, cursor address, and function name through
   `get_gui_context()`.
2. Decompiles the selected function and optionally gathers trusted read-only
   evidence through DSPy ReAct tools.
3. Produces a typed name, analysis, behavioral summary, and rationale.
4. Rechecks the active program, cursor, and old name before any write.
5. Calls `rename_function` exactly once when `apply: true`.
6. Validates the rename receipt and reads the GUI state back.

Statuses are `proposed`, `unchanged`, `renamed`, and `verification_failed`.
Pre-write errors are MCP tool errors. An uncertain write is never retried
automatically. Moving the cursor after a successful write can prevent read-back
verification, so inspect Ghidra before retrying a `verification_failed` result.

The upstream tools do not provide an atomic compare-and-rename operation.
Pre-write checks detect observed selection changes but cannot prevent another
client from editing or replacing the program between calls. Calls within one
workflow process are serialized.

## Configuration and extensibility

`load_config(Path(...)) -> AppConfig` accepts YAML or JSON. Pydantic models use
strict types, reject unknown fields, and block field reassignment. The checked-in
`config.schema.json` is intended to mirror those models; the test suite compares
them and reports schema drift.

Additional MCP servers can be added to `mcp_servers`. `evidence_tools` lists
the trusted read-only tools made available to DSPy. This list is not a sandbox:
tools retain the effects of their upstream implementations. Workflow writes are
deterministic and remain outside ReAct.

## Development and scope

Runtime source consists of typed configuration, MCP connections, the DSPy
workflow, and MCP entry points. This repository does not contain its own GUI,
provider wrapper, custom agent loop, RAG implementation, or Ghidra backend.
PyGhidra-MCP includes its own indexing dependencies and should remain in its
separate environment.

Run the established tests from the workflow environment:

```bash
source .venv/bin/activate
pytest -q
```

Tests cover strict configuration, typed DSPy outputs, MCP discovery, native
ReAct tool calls, and both stdio and Streamable HTTP sessions. Ghidra behavior
and model responses are fixtures; actual JVM/GUI integration and naming quality
still require a live test.

## Sources and license

- [Codex MCP configuration](https://developers.openai.com/codex/mcp/)
- [PyGhidra-MCP](https://github.com/clearbluejar/pyghidra-mcp)
- [Inspected PyGhidra-MCP 0.2.7 release](https://pypi.org/project/pyghidra-mcp/0.2.7/)
- [DSPy MCP](https://dspy.ai/learn/programming/mcp/)
- [DSPy language models](https://dspy.ai/learn/programming/language_models/)
- [LiteLLM hosted vLLM](https://docs.litellm.ai/docs/providers/vllm)
- [LiteLLM OpenAI-compatible endpoints](https://docs.litellm.ai/docs/providers/openai_compatible)
- [Official MCP Python SDK v1](https://github.com/modelcontextprotocol/python-sdk/tree/v1.x)

The workflow derives from the supplied OGhidra archive's GUI rename workflow
and typed `AnalyzeFunction` signature. `LICENSE` is retained verbatim from that
archive, including its commercial-use terms. No upstream backend source is
bundled.
