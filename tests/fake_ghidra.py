"""Protocol fixture only: never imported by production code."""

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Fixture Ghidra")
name = "FUN_00401000"


@mcp.tool()
def get_current_function() -> str:
    return f"Function: {name} at 00401000"


@mcp.tool()
def get_function_by_address(address: str) -> str:
    return f"Function: {name} at 00401000\nSignature: int {name}(void)"


@mcp.tool()
def decompile_function_by_address(address: str) -> str:
    return "int FUN_00401000(int x) { return x + 1; }"


@mcp.tool()
def rename_function_by_address(address: str, name: str) -> str:
    globals()["name"] = name
    return "Function renamed successfully"


@mcp.tool()
def get_xrefs_to(address: str) -> str:
    return "No callers"


if __name__ == "__main__":
    mcp.run()
