# Executable Loading Security Analysis

## Goal
Identify all functions that load executables or libraries dynamically.

### Step 1: Discover Loading Functions

Execute simultaneously to find all dynamic loading:

```
EXECUTE: search_functions_by_name(query="LoadLibrary", offset=0, limit=50)
EXECUTE: search_functions_by_name(query="CreateProcess", offset=0, limit=50)
EXECUTE: search_functions_by_name(query="ShellExecute", offset=0, limit=30)
EXECUTE: search_functions_by_name(query="WinExec", offset=0, limit=20)
```

**Target APIs**:
- `LoadLibrary` / `LoadLibraryEx` / `LoadLibraryA` / `LoadLibraryW` - DLL loading
- `CreateProcess` / `CreateProcessA` / `CreateProcessW` - Process creation
- `ShellExecute` / `ShellExecuteEx` / `ShellExecuteA` / `ShellExecuteW` - Shell operations
- `WinExec` - Legacy process execution
- `GetModuleHandle` - May indicate dynamic dependency resolution

**If NO results found**:
- Binary doesn't load external code dynamically
- Low risk for this vulnerability class
- Can skip to other analyses

**If results found**:
- Proceed to Step 2 for EACH function
- Prioritize by API type (CreateProcess > LoadLibrary > ShellExecute)
