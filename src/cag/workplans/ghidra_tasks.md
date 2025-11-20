# Ghidra Task Workplans

This document contains step-by-step workplans for common Ghidra tasks. These workplans should be followed precisely to ensure successful execution.

## Workplan: Analyze a Function's Calls

### Goal: Find all functions called by a specified function

1. **First, check if the function exists**:
   ```
   EXECUTE: list_functions()
   ```

2. **Decompile the function**:
   ```
   EXECUTE: decompile_function(name="FUN_14024DA90")
   ```
   Note: Replace "FUN_14024DA90" with the actual function name.

3. **Analyze the decompiled code**:
   - Look for direct function calls in the decompiled C-like code
   - These will appear as function calls like `FUN_14024B250()` or similar
   - Record all unique function names that are called

4. **Create a list of called functions**:
   - Present the list to the user in a clear format
   - Use bullet points for readability

### Common Errors and Solutions:
- If `decompile_function` fails with "Function not found", check the function name is correct and exists in the list from step 1
- Don't use the 'address' parameter with `decompile_function`, only use the 'name' parameter
- If the function name is unknown but you have an address, use `decompile_function_by_address` instead

## Workplan: Rename a Function

### Goal: Rename a function based on its purpose

1. **First, check if the function exists**:
   ```
   EXECUTE: list_functions()
   ```

2. **Decompile the function to understand its purpose**:
   ```
   EXECUTE: decompile_function(name="FUN_14024DA90")
   ```
   Note: Replace "FUN_14024DA90" with the actual function name.

3. **Analyze the code to determine an appropriate name**:
   - Look for key operations, data being processed, and return values
   - Consider function parameters and how they're used
   - Choose a descriptive name following common naming conventions

4. **Rename the function**:
   ```
   EXECUTE: rename_function(old_name="FUN_14024DA90", new_name="descriptive_name")
   ```

### Common Errors and Solutions:
- Always check that the function exists before attempting to rename it
- Use snake_case for new function names for consistency
- If renaming by address is needed, use `rename_function_by_address` with just the numeric part of the address

## Workplan: Find Functions by Pattern

### Goal: Locate functions containing specific patterns or functionality

1. **Search for functions by name pattern**:
   ```
   EXECUTE: search_functions_by_name(query="pattern")
   ```
   Note: Replace "pattern" with the search term.

2. **For each potential match, decompile and analyze**:
   ```
   EXECUTE: decompile_function(name="FUN_14024DA90")
   ```
   Note: Replace "FUN_14024DA90" with each function name from step 1.

3. **Evaluate the decompiled code** for the specific functionality you're seeking

4. **Present findings** to the user in a clear format with explanations

### Common Errors and Solutions:
- If no matches are found, try alternative search terms or patterns
- Break down complex searches into multiple simpler searches
- Consider function size, imports, or reference counts as additional filters 