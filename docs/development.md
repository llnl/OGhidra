# Development

Runtime source contains typed configuration, MCP connections, diagnostics, the
DSPy workflow, and MCP entry points. The repository does not contain its own
GUI, provider wrapper, custom agent loop, RAG implementation, or Ghidra
backend.

PyGhidra-MCP runs separately and is not a workflow-package dependency. Its
indexing and JVM dependencies belong in `.venv-ghidra`.

## Environment and tests

Install development extras in the workflow environment:

```bash
.venv/bin/python -m pip install -e '.[test]'
.venv/bin/pytest -q
.venv/bin/ruff check .
.venv/bin/ruff format --check .
```

UV remains an optional development convenience. If it is already installed,
the equivalent editable install is:

```bash
uv pip install --python .venv/bin/python -e '.[test]'
```

Tests cover strict configuration, typed DSPy outputs, MCP discovery, native
ReAct tool calls, doctor behavior, diagnostics, and both stdio and Streamable
HTTP sessions. Ghidra behavior and model responses are fixtures; actual
JVM/GUI integration and naming quality require a live test.

## Configuration and extension points

`load_config(Path(...)) -> AppConfig` accepts YAML or JSON. Pydantic models use
strict types, reject unknown fields, and block field reassignment. The checked-
in `config.schema.json` mirrors those models; tests detect schema drift.

Additional MCP servers can be added to `mcp_servers`. `evidence_tools` lists
the trusted read-only tools made available to DSPy. This list is not a sandbox:
tools retain the effects of their upstream implementations. Deterministic
workflow writes remain outside ReAct.

## References

- [Codex MCP configuration](https://developers.openai.com/codex/mcp/)
- [PyGhidra-MCP 0.2.7](https://pypi.org/project/pyghidra-mcp/0.2.7/)
- [DSPy MCP](https://dspy.ai/learn/programming/mcp/)
- [DSPy language models](https://dspy.ai/learn/programming/language_models/)
- [LiteLLM hosted vLLM](https://docs.litellm.ai/docs/providers/vllm)
- [LiteLLM OpenAI-compatible endpoints](https://docs.litellm.ai/docs/providers/openai_compatible)
- [Official MCP Python SDK v1](https://github.com/modelcontextprotocol/python-sdk/tree/v1.x)
