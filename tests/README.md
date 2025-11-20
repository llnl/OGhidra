# Ghidra MCP Tool Call Testing

This directory contains test scripts for verifying the Ghidra MCP API and understanding how tool calls work with the AI agent.

## Key Findings

1. **API Structure**: The API is based on direct HTTP endpoints rather than a unified `/api/v1/function` endpoint. Each tool in `GhidraMCPClient` calls an appropriate endpoint directly.

2. **Working Endpoints**: All tools available in `GhidraMCPClient` (currently 27, including the new `list_strings`) are working correctly through their respective HTTP endpoints. These include:
   - Basic functions: `list_methods`, `get_current_function`, `list_functions`, `list_strings`, etc.
   - Analysis: `decompile_function`, `decompile_function_by_address`, `analyze_function`, etc.
   - Modifications: `rename_function`, `set_decompiler_comment`, `set_function_prototype`, etc.

3. **AI Agent Integration**: The AI agent uses the `EXECUTE: tool_name(param1="value1", param2="value2")` format to trigger tool calls, which are then processed by the `CommandParser` and executed through the `GhidraMCPClient`.

4. **Tool Call Pattern**: When the AI mentions a tool call in the form of `EXECUTE: tool_name(params)`, the bridge:
   - Extracts the command using regex
   - Validates the parameters
   - Calls the appropriate method in `GhidraMCPClient`
   - Returns the result to the AI

5. **No Mock Support**: The client no longer supports a mock mode; all calls are directed to the live Ghidra server specified in the configuration.

## Test Scripts

- **test_extended_api.py**: This script was previously used for broader API exploration but has been superseded by `test_tool_calls.py` for comprehensive tool testing
- **test_tool_calls.py**: Comprehensive tests for all available tools in `GhidraMCPClient`. It validates parameters, calls the tools, and can generate API documentation

## Generated Documentation

The `test_tool_calls.py` script can generate a comprehensive markdown file documenting all available tools, their parameters, return types, and sample results. Run it with:

```bash
python tests/test_tool_calls.py
```

This will create `tool_capabilities.md` with detailed API documentation.

## Using Tools in AI Conversations

To use the tools when interacting with the AI agent, use the following format:

```
EXECUTE: tool_name(param_name="param_value")
```

For example:

```
EXECUTE: list_strings(offset=0, limit=10)
EXECUTE: decompile_function(name="main")
```

The AI's response will be augmented with the result of the tool call. 