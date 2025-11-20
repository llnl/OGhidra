# Enabled Ghidra MCP Tools

This document provides an overview of the currently enabled tools in the Ghidra MCP API.

## Core Analysis Tools

These are the most important tools for analyzing code in Ghidra:

### `analyze_function(address=None)`
Provides comprehensive analysis of a function, including its decompiled code and all functions it calls.
If no address is provided, automatically uses the currently selected function in Ghidra.

### `decompile_function(name)`
Decompiles a specific function by name and returns the C code.

### `decompile_function_by_address(address)`
Decompiles a function at the specified address.

### `disassemble_function(address)`
Returns assembly code (with address, instruction, and comments) for a function.

## Navigation & Information Tools

### `get_current_function()`
Returns the function currently selected by the user in Ghidra.

### `get_current_address()`
Returns the address currently selected by the user in Ghidra.

### `get_function_by_address(address)`
Gets information about a function at the specified address.

### `list_functions()`
Lists all functions in the database.

## Search & Discovery Tools

### `list_methods(offset=0, limit=100)`
Lists all function names in the program with pagination.

### `list_classes(offset=0, limit=100)`
Lists all namespace/class names in the program.

### `list_strings(offset=0, limit=2000, filter=None)`
Lists all defined strings in the binary.  If `filter` is provided the list is restricted to strings containing that substring – this effectively performs a fast string search.

### `search_functions_by_name(query, offset=0, limit=100)`
Searches for functions whose name contains the given substring.

### `list_imports(offset=0, limit=100)`
Lists imported symbols in the program.

### `list_exports(offset=0, limit=100)`
Lists exported functions/symbols.

### `list_segments(offset=0, limit=100)`
Lists all memory segments in the program.

### `list_data_items(offset=0, limit=100)`
Lists defined data labels and their values.

### `list_namespaces(offset=0, limit=100)`
Lists all non-global namespaces in the program.

### `get_xrefs_to(address, offset=0, limit=100)`
Returns all cross-references *to* the specified code address.  Useful for finding every location that calls or references a given function/data.

### `get_xrefs_from(address, offset=0, limit=100)`
Returns all cross-references *from* the specified code address (i.e. outgoing references).

### `get_function_xrefs(name, offset=0, limit=100)`
Returns all references to a function by its current name.

## Modification Tools

### `rename_function(old_name, new_name)`
Renames a function by its current name to a new user-defined name.

### `rename_function_by_address(function_address, new_name)`
Renames a function by its address.

### `rename_data(address, new_name)`
Renames a data label at the specified address.

## System Tools

### `health_check()`
Checks if the GhidraMCP server is available.

### `check_health()`
Checks if the GhidraMCP server is reachable and responding.

## Disabled Tools

The following tools have been disabled to focus on the most useful analysis functionality:

- `rename_variable`
- `safe_get`
- `safe_post`
- `set_decompiler_comment`
- `set_disassembly_comment`
- `set_function_prototype`
- `set_local_variable_type`

## Tool Usage

To use these tools from the AI agent, use the following format:

```
EXECUTE: tool_name(param1="value1", param2="value2")
```

For example:

```
EXECUTE: analyze_function()
EXECUTE: decompile_function(name="main")
EXECUTE: list_strings(limit=10)
```

---

## Friendly aliases (CLI / agent)
For convenience the command parser recognises two high-level aliases and converts them to the underlying tools:

* `xref_lookup(...)` – maps to `get_xrefs_to`, `get_xrefs_from`, or `get_function_xrefs` depending on parameters (see below).
* `string_search(filter="<text>")` – maps to `list_strings(filter="<text>")`.

Alias usage examples:

```
# All refs *to* address 0x401000
EXECUTE: xref_lookup(address="401000", direction="to")

# All refs *from* address (defaults to direction="from")
EXECUTE: xref_lookup(address="401000", direction="from")

# Refs to function by name
EXECUTE: xref_lookup(name="CreateFileW")

# Find all strings that mention "passwd"
EXECUTE: string_search(filter="passwd")
``` 