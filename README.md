# OGhidra workflows — PyGhidra backend

One product: `rename_current_function(apply=True)`, implemented with DSPy and exposed through MCP. This version uses **clearbluejar/pyghidra-mcp 0.2.7** to launch the Ghidra GUI and serve MCP over Streamable HTTP. LaurieWired's extension and Python bridge are not used.

PyGhidra supplies Python access to Ghidra APIs. The separate upstream **pyghidra-mcp** project supplies the MCP tools and GUI lifecycle. OGhidra contains neither a copied backend nor its own Ghidra API wrapper.

## Start Ghidra and its MCP server

Use a separate environment for the upstream server so its dependencies and the workflow's dependencies can evolve independently. Install Ghidra and the JDK required by your Ghidra release first.

Windows PowerShell (paths are examples):

```powershell
python -m venv .venv-ghidra
.\.venv-ghidra\Scripts\python.exe -m pip install "pyghidra-mcp==0.2.7"
$env:GHIDRA_INSTALL_DIR = 'C:\tools\ghidra'
.\.venv-ghidra\Scripts\pyghidra-mcp.exe --gui --transport streamable-http --host 127.0.0.1 --port 8001 --project-path 'C:\projects\research.gpr'
```

On Linux/macOS, activate the backend environment, set `GHIDRA_INSTALL_DIR`, and run:

```bash
pyghidra-mcp --gui --transport streamable-http --host 127.0.0.1 --port 8001 --project-path /absolute/path/to/research.gpr
```

This launches Ghidra. Open the desired program in its CodeBrowser, wait for analysis to finish, and select a location within a function. Keep this process running. Save/close any other Ghidra instance using the same project before starting this one; the backend cannot attach to an independently launched GUI. Ghidra/MCP run in the same JVM here, so changes are live in that GUI.

The MCP endpoint is `http://127.0.0.1:8001/mcp`. This is actual MCP over Streamable HTTP, with no intermediate REST bridge. Port 8001 avoids the example LM service on port 8000.

## Configure the workflow

Python 3.12 or later, from this project's root:

```bash
python -m venv .venv
# Activate .venv using the command for your shell.
python -m pip install -e '.[test]'
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

The `lm` section configures DSPy's own model connection; it does not inherit the host client's model. `api_key_env` names an environment variable; remove it for a service that needs no explicit key. All model access goes through `dspy.LM`, without provider-specific code.

| Service | `lm.model` | `lm.api_base` |
| --- | --- | --- |
| OpenAI | `openai/YOUR_MODEL` | Omit |
| Ollama | `ollama_chat/YOUR_MODEL` | `http://127.0.0.1:11434` |
| vLLM / compatible local endpoint | `openai/YOUR_SERVED_MODEL` | `http://127.0.0.1:8000/v1` |

Supported LM fields: `model`, `api_base`, `api_key_env`, `cache`, `max_tokens`, `temperature`, `timeout`, and `num_retries`. Add explicit typed fields when more settings are needed; arbitrary options are rejected.

## Connect your client

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

First invoke `rename_current_function` with `{"apply": false}`. Then use `{"apply": true}` to perform a fresh analysis and rename. Applying is not a commit of the previous preview. Your host can separately connect directly to pyghidra-mcp and any other MCP services; those connections are not automatically lent to this workflow server.

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
- Official MCP Python SDK v1: https://github.com/modelcontextprotocol/python-sdk/tree/v1.x

The rename product derives from the supplied OGhidra archive's GUI rename workflow and typed `AnalyzeFunction` signature. `LICENSE` is retained verbatim from that archive, including its commercial-use terms. No upstream backend source is bundled.
