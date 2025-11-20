# Knowledge Capture Workplan

This workplan outlines how to capture and organize knowledge about a binary during reverse engineering.

## Workplan: Capture Binary Overview

### Goal: Create a high-level understanding of the binary

1. **Identify binary type and architecture**:
   ```
   EXECUTE: get_program_info()
   ```

2. **List all imports to understand external dependencies**:
   ```
   EXECUTE: list_imports()
   ```

3. **List all exports to identify key functionality**:
   ```
   EXECUTE: list_exports()
   ```

4. **Identify potential string clues**:
   (Note: A direct `list_strings()` tool is not currently available. Analyze decompiled functions known to handle or reference string data. Look for calls to string manipulation library functions or direct memory references to string-like data segments.)

5. **Summarize findings** into a structured overview:
   - Binary type (executable, DLL, etc.)
   - Architecture and compiler information
   - Key imports grouped by functionality (networking, crypto, etc.)
   - Key exports and their potential purposes
   - Interesting strings and their context

### Common Errors and Solutions:
- If `get_program_info` returns incomplete data, check if the binary is packed or obfuscated
- When analyzing strings, filter out common library strings to focus on application-specific content

## Workplan: Function Purpose Identification

### Goal: Determine the purpose of unknown functions

1. **Decompile the target function**:
   ```
   EXECUTE: decompile_function(name="FUN_14000A000")
   ```
   Note: Replace with actual function name.

2. **Identify key characteristics**:
   - Parameters and return type
   - API calls made by the function
   - Data structures accessed
   - Error handling patterns

3. **Understand function context (callers and callees)**:
   (Note: A direct `find_references_to()` or specific caller/callee listing tool is not currently available. To understand context, decompile functions that appear to call this function, or functions that this function calls, based on analysis of the current function's decompiled code and any identifiable function names.)

4. **Examine calling functions for context**:
   ```
   EXECUTE: decompile_function(name="CALLING_FUNCTION")
   ```
   Note: Replace with actual calling function name.

5. **Propose a descriptive name** based on analysis:
   ```
   EXECUTE: rename_function(old_name="FUN_14000A000", new_name="descriptive_name")
   ```

### Common Errors and Solutions:
- If function purpose is unclear, examine both callers and callees for additional context
- Use string references within the function to provide clues about functionality
- Check if the function matches common library function signatures

## Workplan: Data Structure Analysis

### Goal: Identify and document key data structures

1. **Locate structure usage in functions**:
   ```
   EXECUTE: decompile_function(name="FUN_14000A000")
   ```
   Note: Look for pointer dereferences and field accesses.

2. **Identify structure fields and types**:
   - Note field offsets and access patterns
   - Determine field types based on usage
   - Look for arrays and nested structures

3. **Create a structure definition**:
   - Document field names, types, and purposes
   - Note relationships between structures
   - Map to known structures when possible

4. **Rename variables using the structure**:
   - Suggest meaningful variable names based on usage
   - Document the structure's role in the program

### Common Errors and Solutions:
- If structure fields are unclear, trace data flow through multiple functions
- Look for initialization functions that populate structure fields
- Compare against common library structures (e.g., Windows API structures)

## Workplan: Recursive Function Analysis

### Goal: Understand a function and all its dependencies

1. **Start with the target function**:
   ```
   EXECUTE: decompile_function(name="TARGET_FUNCTION")
   ```

2. **Identify all function calls within the target**:
   - Create a list of all called functions
   - Prioritize functions based on importance to control flow

3. **For each called function, recursively analyze**:
   ```
   EXECUTE: decompile_function(name="CALLED_FUNCTION")
   ```
   - Understand its purpose
   - Rename it appropriately
   - Document its behavior

4. **Map the call hierarchy**:
   - Create a tree of function calls
   - Identify critical paths in the execution flow
   - Note loops and recursive calls

5. **Summarize the overall functionality**:
   - Describe how the functions work together
   - Identify the main purpose of the target function
   - Document any security implications or interesting behaviors

### Common Errors and Solutions:
- Set a reasonable depth limit for recursive analysis to avoid getting overwhelmed
- Focus on unique or custom functions rather than standard library functions
- Use a breadth-first approach for large function sets to gain broader understanding first