# OGhidra — AI-powered reverse engineering with Ghidra

OGhidra connects language models to a live Ghidra session through MCP. It adds
repeatable DSPy workflows to the inspection and editing tools exposed by
[PyGhidra-MCP](https://github.com/clearbluejar/pyghidra-mcp).

## Quick start

This path uses the Bash helpers on Linux or macOS. Windows users can follow the
[manual PowerShell commands](#windows-powershell) below.

### Prerequisites

- Python 3.12 or later.
- [Ghidra](https://ghidra-sre.org/) and the JDK required by that Ghidra release.
- [Codex CLI or another local Codex client](https://developers.openai.com/codex/mcp/).
- Access to a hosted model API, Ollama, or a vLLM-compatible endpoint.

OGhidra does not install Ghidra, a JDK, or a model.

### 1. Clone and set up

```bash
git clone https://github.com/llnl/OGhidra.git
cd OGhidra
./scripts/setup.sh --register-codex
```

The setup script creates two intentionally separate environments:

- `.venv-ghidra` contains PyGhidra-MCP and its Ghidra/JVM dependencies.
- `.venv` contains the OGhidra workflow server.

It also creates `config.yaml` from the example when that file is missing. It
never overwrites an existing configuration. With `--register-codex`, it adds
the `pyghidra` and `oghidra` MCP servers; registrations that already exist are
reported and left unchanged. Omit the flag if you use another MCP host or want
to register Codex manually.

### 2. Configure the model

Edit the `lm` section of `config.yaml` and replace
`replace/provider-and-model-id`. Build the value as:

```text
<LiteLLM integration>/<exact endpoint model ID>
```

For example, use `openai/gpt-4o` for the literal OpenAI model ID `gpt-4o`, or
`ollama_chat/llama3.2` with `api_base: http://127.0.0.1:11434` for a local
Ollama model. Preserve any slashes that are part of the endpoint's exact model
ID.

If authentication is required, set `api_key_env` to an environment-variable
name and expose that variable to the Codex process. Never put the secret itself
in `config.yaml`. See [Model and host setup](docs/model-and-host-setup.md) for
provider examples, model-ID details, and non-Codex MCP hosts.

### 3. Start Ghidra and PyGhidra-MCP

#### New Ghidra Project
In terminal 1, set `GHIDRA_INSTALL_DIR` to the Ghidra installation directory,
then provide the native PyGhidra-MCP project arguments:

- `--project-path` is the directory that will contain the project. It is
  created if it does not exist.
- `--project-name` is the project name and the base name of its `.gpr` and
  `.rep` files. For example, `research` creates `research.gpr` and
  `research.rep` under the project path.
- The final program path is optional. When present, it must name an existing
  binary and PyGhidra-MCP imports it into the project. Quote paths containing
  spaces. You can provide more than one program path.

Create the project and import a program immediately:

```bash
export GHIDRA_INSTALL_DIR=/absolute/path/to/ghidra
./scripts/run-ghidra.sh \
  --project-path /absolute/path/to/projects \
  --project-name research \
  /absolute/path/to/program
```

To start with an empty project, omit the final program path:

```bash
export GHIDRA_INSTALL_DIR=/absolute/path/to/ghidra
./scripts/run-ghidra.sh \
  --project-path /absolute/path/to/projects \
  --project-name research
```

This still creates or opens the `research` project and launches Ghidra. It
does not import or analyze a program until you import one later through Ghidra
or PyGhidra-MCP.

#### Existing Ghidra Project
For an existing project, pass its `.gpr` file as `--project-path`. The project
name is derived from the filename, so omit `--project-name`. Omit the program
path unless you also want to import another program:

```bash
export GHIDRA_INSTALL_DIR=/absolute/path/to/ghidra
./scripts/run-ghidra.sh --project-path /absolute/path/to/project.gpr
```

The run script launches PyGhidra-MCP and the Ghidra GUI on the required local
MCP endpoint. It does not launch Codex, doctor, or a workflow. Codex launches
the separate OGhidra stdio server when a client session starts.

Keep terminal 1 and the Ghidra GUI open. In CodeBrowser, wait for analysis to
finish and place the cursor inside the target function.

### 4. Check the session

In terminal 2, run the read-only doctor:

```bash
.venv/bin/oghidra-doctor --config config.yaml
```

`oghidra-doctor` is a launcher generated inside `.venv/bin` by the
`pip install -e .` step. Calling it by that path does not require activating
the environment. If `.venv` is activated, the shorter equivalent is
`oghidra-doctor --config config.yaml`.

Doctor validates local configuration, credentials, MCP connectivity, required
tools, and the current Ghidra selection. By default it does not contact the
model, decompile code, or modify Ghidra. Add `--check-model` to make a small,
uncached inference request; this can incur a provider charge. A ready session
reports `PASS` for both model connectivity and the Ghidra selection when that
option is used.

### 5. Example: Request a rename proposal

Start a new Codex session after registering or changing MCP configuration. Use
`/mcp` to confirm that `pyghidra` and `oghidra` are active, then ask:

```text
Use the oghidra MCP server's rename_current_function tool with apply set to
false for the function currently selected in Ghidra.
```

The result should include:

```text
status: proposed
```

`apply: false` never writes. If `apply` is omitted, the tool defaults to `true`
and may rename the selected function. To apply a rename deliberately, request
`apply: true`; OGhidra performs a fresh analysis and revalidates the live target
before writing. Save the program in Ghidra when finished.

## Manual setup and launch

These commands perform the same setup and launch steps without the Bash
helpers.

<details>
<summary>Linux and macOS</summary>

<a id="linux-and-macos"></a>

Clone the repository, create both environments, and initialize the
configuration:

```bash
git clone https://github.com/llnl/OGhidra.git
cd OGhidra
OGHIDRA_ROOT="$(pwd -P)"

python3.12 -m venv .venv-ghidra
.venv-ghidra/bin/python -m pip install "pyghidra-mcp==0.2.7"

python3.12 -m venv .venv
.venv/bin/python -m pip install -e .
test -e config.yaml || cp config.example.yaml config.yaml
```

After editing `config.yaml`, register both MCP servers:

```bash
OGHIDRA_ROOT="$(pwd -P)"
codex mcp add pyghidra --url http://127.0.0.1:8001/mcp
codex mcp add oghidra -- \
  "$OGHIDRA_ROOT/.venv/bin/oghidra-workflows" \
  --config "$OGHIDRA_ROOT/config.yaml"
codex mcp list
```

Launch a new project and program in terminal 1:

```bash
export GHIDRA_INSTALL_DIR=/absolute/path/to/ghidra
.venv-ghidra/bin/pyghidra-mcp \
  --gui --transport streamable-http --host 127.0.0.1 --port 8001 \
  --project-path /absolute/path/to/projects --project-name research \
  /absolute/path/to/program
```

Or launch an existing project:

```bash
export GHIDRA_INSTALL_DIR=/absolute/path/to/ghidra
.venv-ghidra/bin/pyghidra-mcp \
  --gui --transport streamable-http --host 127.0.0.1 --port 8001 \
  --project-path /absolute/path/to/project.gpr
```

Then run doctor in terminal 2:

```bash
.venv/bin/oghidra-doctor --config config.yaml
```

</details>

<details>
<summary>Windows PowerShell</summary>

<a id="windows-powershell"></a>

Clone the repository, create both environments, and initialize the
configuration:

```powershell
git clone https://github.com/llnl/OGhidra.git
Set-Location OGhidra
$OghidraRoot = (Resolve-Path .).Path

py -3.12 -m venv .venv-ghidra
.\.venv-ghidra\Scripts\python.exe -m pip install 'pyghidra-mcp==0.2.7'

py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
if (-not (Test-Path config.yaml)) {
  Copy-Item config.example.yaml config.yaml
}
```

After editing `config.yaml`, register both MCP servers:

For ease of use, a copy of this configuration for your claude client is found in `dsp.json` and can be loaded with a command such as `claude --mcp-config ./mcp.json`.

## Obsidian Vault Integration

OGhidra can integrate with an Obsidian vault to provide persistent, human-editable function analysis. When configured, the workflow:

1. **Reads existing notes** from the vault before analysis, providing context from previous work
2. **Writes comprehensive analysis** back to the vault after successful renames
3. **Preserves human annotations** by merging automated updates with user notes
4. **Links functions together** using Obsidian wikilinks for natural navigation

### Setting up the Vault

1. **Create a vault directory** for your Ghidra project:
   ```bash
   mkdir -p /path/to/ghidra-vault/functions
   ```

2. **Install the Local REST API plugin in Obsidian**:
   - Open Obsidian Settings → Community plugins
   - Browse for "Local REST API with MCP"
   - Click Install, then Enable
   - Go to Settings → Local REST API and note your API key
   - Enable HTTP server: Settings → Local REST API → Enable HTTP server

3. **Configure in config.yaml**:
   ```yaml
   mcp_servers:
     obsidian:
       transport: streamable-http
       url: http://127.0.0.1:27123/mcp
       headers:
         Authorization: "Bearer your-api-key-from-settings"
       vault_path: "/path/to/ghidra-vault"
       evidence_tools:
         - search_notes
         - read_note
   ```

   Get your API key from Settings → Local REST API in Obsidian. The API key authenticates via the `Authorization: Bearer` header.

   **Important**: The current MCP Python SDK (v1.30.0) does not support passing custom HTTP headers for streamable-http or SSE transports. The `headers` field is included in the config for documentation purposes and future SDK support. For now, OGhidra stores the configuration but cannot authenticate to the Obsidian MCP server. Your Claude client (mcp.json) can connect successfully using headers.

   **Note**: The HTTP endpoint (port 27123) avoids certificate validation issues. If you prefer HTTPS (port 27124), download and trust the certificate from `https://127.0.0.1:27124/obsidian-local-rest-api.crt`.

4. **Configure your Claude client** (optional, for direct vault access):

   In your `mcp.json` or Claude client config:
   ```json
   {
     "mcpServers": {
       "obsidian": {
         "type": "http",
         "url": "http://127.0.0.1:27123/mcp",
         "headers": {
           "Authorization": "Bearer your-api-key-from-settings"
         }
       }
     }
   }
   ```

5. **Open the vault in Obsidian** to view and edit notes with full Obsidian features (graph view, search, tags, etc.)

### Workflow with Obsidian

The DSPy ReAct agent can:
- **Search for similar functions** using `search_notes`
- **Read prior analysis** to learn from past work
- **Reference existing patterns** discovered in other functions

This creates a **knowledge-building loop**: each analysis improves future analyses by contributing to the shared vault.

## What the workflow does

1. Calls upstream `get_gui_context()` and captures the active program path, cursor address, and function name.
2. **[If Obsidian configured]** Searches vault for existing analysis of this function.
3. Calls upstream `decompile_function(binary_name, name_or_address)` with the captured program and address. Addresses within functions are supported by upstream's containing-function lookup.
4. Uses typed DSPy prediction for a name, analysis, behavioral summary, and rationale. Optional `dspy.ReAct` gathers additional evidence through `dspy.Tool.from_mcp_tool`, including Obsidian search tools if configured.
5. Rechecks the active program, cursor, and old name before writing.
6. Calls upstream `rename_function(binary_name, name_or_address, new_name)` exactly once.
7. Validates the structured rename receipt and reads the GUI context again. Only matching receipt and read-back return `status="renamed"`.
8. **[If Obsidian configured]** Writes comprehensive analysis note to vault, preserving user annotations.

The result includes the captured `binary_name` and `address` (cursor address, not necessarily the entry point). After a rename receipt, `function_entry_address` contains the entry point reported by upstream. Structured response models validate the required fields. There is no parsing of old `Function: NAME at ADDRESS` text, no invented function identity, and no compatibility layer for LaurieWired tools.

Return statuses are `proposed`, `unchanged`, `renamed`, and `verification_failed`. Pre-write errors are MCP tool errors. An uncertain write is never retried automatically. Keep the cursor on the selected function until the call finishes: moving after a successful write can prevent GUI read-back verification and therefore returns `verification_failed`. Inspect Ghidra before retrying. This is a live program edit; save the program through Ghidra as usual.

The upstream tools do not offer an atomic compare-and-rename operation. Pre-write checks detect observed selection changes, but cannot prevent another client editing or replacing a program between calls. The program path is now explicitly part of every decompile/write request. Calls in one workflow process are serialized.

## Typed configuration and tool extensibility

`load_config(Path(...)) -> AppConfig` accepts YAML and JSON. Nested Pydantic models use `strict=True` and `extra="forbid"`; unknown fields and stringified numbers/booleans fail at startup. `config.lm.model` and `config.max_iters` are typed attributes. Transport is a discriminated union of stdio and HTTP settings. Models block field reassignment, but nested containers are not deeply immutable; treat config as read-only.

```bash
python main.py --schema > config.schema.json
```powershell
$OghidraRoot = (Resolve-Path .).Path
codex mcp add pyghidra --url http://127.0.0.1:8001/mcp
codex mcp add oghidra -- `
  "$OghidraRoot\.venv\Scripts\oghidra-workflows.exe" `
  --config "$OghidraRoot\config.yaml"
codex mcp list
```

Launch a new project and program in terminal 1:

```powershell
$env:GHIDRA_INSTALL_DIR = 'C:\absolute\path\to\ghidra'
.\.venv-ghidra\Scripts\pyghidra-mcp.exe --gui --transport streamable-http --host 127.0.0.1 --port 8001 --project-path 'C:\absolute\path\to\projects' --project-name research 'C:\absolute\path\to\program.exe'
```

Or launch an existing project:

```powershell
$env:GHIDRA_INSTALL_DIR = 'C:\absolute\path\to\ghidra'
.\.venv-ghidra\Scripts\pyghidra-mcp.exe --gui --transport streamable-http --host 127.0.0.1 --port 8001 --project-path 'C:\absolute\path\to\project.gpr'
```

Then run doctor in terminal 2:

```powershell
.\.venv\Scripts\oghidra-doctor.exe --config config.yaml
```

Codex CLI, the IDE extension, and the ChatGPT desktop app share the same local
Codex MCP configuration. Start a new Codex session after changing it.

</details>

## Troubleshooting first run

| Observation | Meaning and next action |
| --- | --- |
| Doctor cannot connect to `http://127.0.0.1:8001/mcp` | Start PyGhidra-MCP in terminal 1 and keep it running. |
| Doctor reports a missing model placeholder or credential | Finish the `lm` section and expose the named credential to the Codex process. |
| Doctor cannot find a function | Open a program in CodeBrowser and place the cursor inside a function. |
| `/mcp` does not show both servers | Check `codex mcp list`, verify the captured repository path, and start a new Codex session. |
| No `logs/oghidra-*.jsonl` appears | The host did not launch the OGhidra stdio process; recheck registration paths. |
| `/rename_current_function` is unknown | It is an MCP tool, not a slash command. Request it in normal language. |

See [Operations and diagnostics](docs/operations.md) for logs, failure modes,
and workflow safety details.

## Architecture

```mermaid
flowchart LR
    Host["Codex / MCP host"] -->|"stdio: workflow tools"| OG["OGhidra workflows"]
    OG -->|"Ghidra evidence and actions"| Py["PyGhidra-MCP"]
    Host -->|"direct Ghidra tools"| Py
    Py <--> GUI["Ghidra GUI / CodeBrowser"]
```

Both MCP servers are passive. PyGhidra-MCP owns the Ghidra process and GUI;
OGhidra adds higher-level workflows. Opening a project or program does not run
a workflow automatically.

## Development and license

See [Development](docs/development.md) for tests, optional UV usage,
configuration extension points, and repository scope.

The workflow derives from the supplied OGhidra archive's GUI rename workflow
and typed `AnalyzeFunction` signature. [`LICENSE`](LICENSE) is retained from
that archive, including its commercial-use terms. No upstream backend source
is bundled.
