# Operations and diagnostics

## Doctor

Run doctor after PyGhidra-MCP is listening and a function is selected:

```bash
.venv/bin/oghidra-doctor --config config.yaml
```

`--timeout` defaults to 10 seconds and applies independently to each requested
model and MCP connectivity check. Doctor validates the config,
credential-variable presence, compiled predictor path, MCP initialization,
required tools, and GUI selection. It calls only `get_gui_context`; it never
decompiles a function or invokes `rename_function`.

Pass `--check-model` to make a small, uncached inference request through the
configured DSPy/LiteLLM provider. The request can incur a provider charge. A
successful provider response is sufficient; doctor does not require a
particular response body.

Model failures include a sanitized provider error and a troubleshooting hint.
For certificate verification failures, OGhidra reports that Python is using the
operating-system trust store through `truststore`; check the endpoint hostname,
system clock, proxy or private CA installation, and operating-system trust
configuration. Keep `ssl_verify: true`.

Doctor returns exit status 0 when no checks fail, 1 when a check fails, and 2
for invalid command arguments. Without `--check-model`, a warning that model
connectivity was not tested is expected.

## First-run failures

| Observation | Meaning and next action |
| --- | --- |
| `Uvicorn running on http://127.0.0.1:8001` | PyGhidra-MCP is ready. Keep that terminal running. |
| `GET / HTTP/1.1` returns `404` | Expected: the MCP endpoint is `/mcp`, not `/`. |
| `Module.manifest` warnings or a Ghidra MCP server on port 8080 | An obsolete Ghidra extension is installed. Disable it through Ghidra's extension manager. |
| `ProgramManagerPlugin` restore fails with `Unknown protocol: ghidra` | The JVM did not register Ghidra's URL handler before reopening saved programs. Launch through `scripts/run-ghidra.sh`, which supplies the required JVM option. |
| Opening a program appears to do nothing | Expected: both servers wait for the host to invoke a tool. Run doctor, check `/mcp`, then request the workflow. |
| The project is open but no function is found | Open a program in CodeBrowser and place the cursor inside a function. |
| No new `logs/oghidra-*.jsonl` appears | The host did not launch OGhidra. Check its absolute registration path and restart the host session. |
| `server.stopped`, `server.exited`, or `MCP resources released` appears | The host connection or Ghidra process ended. Relaunch it and start a new host session. |

## Diagnostics and crash logs

Configure diagnostics with top-level keys in the same `config.yaml` passed to
`oghidra-workflows --config`. Do not put them under `lm` or `mcp_servers`.
There is no separate crash-log setting: OGhidra records normal diagnostic
events and uncaught failures in the same destination.

```yaml
log_level: DEBUG
log_file: logs/oghidra-{pid}.jsonl
log_max_bytes: 5000000
log_backup_count: 3
```

| Setting | Meaning | Default |
| --- | --- | --- |
| `log_level` | Minimum severity: `DEBUG`, `INFO`, `WARNING`, `ERROR`, or `CRITICAL` | `INFO` |
| `log_file` | JSON log path; use `{pid}` per process, or `null` for stderr only | `logs/oghidra-{pid}.jsonl` |
| `log_max_bytes` | Approximate active-file rotation size | `5000000` |
| `log_backup_count` | Rotated backups retained for each resolved file | `3` |

Relative paths are resolved from the directory containing `config.yaml`, not
the host's working directory. A process can have an active file plus backups
named `.1`, `.2`, and `.3`. Restart the MCP server after changing settings.

Even with `log_file: null`, human-readable logs go to stderr. A malformed or
unreadable configuration cannot apply its logging settings, so OGhidra tries to
write a fallback `logs/oghidra-PID.jsonl` beside the configuration when that
directory is writable.

Normal logging never writes to stdout because stdout carries the stdio MCP
protocol. At INFO, look for `server.starting`, `server.ready`,
`workflow.started`, `mcp.initialized`, `workflow.target_selected`, and
`workflow.completed`. At DEBUG, stage events identify connection, discovery,
decompilation, DSPy, rename, verification, and cleanup work.

To diagnose a workflow failure:

1. Find the `request_id` in the host's tool error.
2. Open the newest `logs/oghidra-*.jsonl` file beside `config.yaml`.
3. Find that request ID and inspect the first `stage.failed` or
   `dspy.*.failed` event.
4. If no new log exists, inspect the MCP host's stderr log; the process may not
   have started.

The startup event records interpreter and library versions, the working
directory, absolute config path, and log path. `server.exited` commonly means
the host closed stdin. A forced kill or failure in the separate PyGhidra-MCP
process cannot produce an OGhidra traceback.

Prompts, decompiled code, complete model responses, tool arguments/results,
subprocess arguments, and environment dictionaries are not deliberately
logged. Known credential values and common credential patterns are redacted.
Endpoint metadata excludes URL userinfo, queries, and fragments. Exceptions can
still contain upstream application data, so review logs before sharing them.

## Workflow behavior and safety

The workflow:

1. Captures the active program, cursor address, and function name.
2. Decompiles the selected function and gathers configured read-only evidence.
3. Produces a typed name, analysis, behavioral summary, and rationale.
4. Rechecks the live program, cursor, and old name before a requested write.
5. Calls `rename_function` once when `apply: true`.
6. Validates the receipt and reads GUI state back.

Statuses are `proposed`, `unchanged`, `renamed`, and `verification_failed`.
Pre-write errors are MCP tool errors. An uncertain write is never retried
automatically. Moving the cursor after a successful write can prevent read-back
verification; inspect Ghidra before retrying a `verification_failed` result.

The upstream tools do not provide an atomic compare-and-rename operation.
Pre-write checks detect observed selection changes but cannot prevent another
client from editing or replacing the program between calls. Calls within one
workflow process are serialized.

## Bulk function rename

`rename_all_functions(apply=false, limit=5, cursor=null)` processes one batch
of generic functions in the active Ghidra program. `limit` accepts 1–25. Only
internal, non-thunk functions with `FUN_`, `sub_`, `loc_`, `unk_`, or `j_` names
are eligible; user-defined names are preserved even if they have one of those
prefixes. The GUI cursor does not need to be inside a function.

The default call previews names without writing. Set `apply=true` to analyze
and rename each function in the batch. Copy `next_cursor` into the next call's
`cursor` to continue in address order. A cursor is tied to the active program;
switching programs requires starting again without a cursor. To apply after a
preview, start without that preview's cursor so the first batch is included.

Each item reports its address, old name, proposal, status, and any error detail.
`counts` summarizes the batch. Function-specific failures do not stop later
functions. A stale target is skipped before writing; an uncertain write is
marked `verification_failed` and is never retried automatically. If the active
program changes, the batch aborts before the next write. A subsequent run from
the beginning can revisit still-generic functions that failed earlier.
