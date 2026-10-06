"""pyghidra-mcp 0.2.7 protocol fixture; no JVM or Ghidra emulation."""

import argparse

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel

parser = argparse.ArgumentParser()
parser.add_argument("--port", type=int)
args = parser.parse_args()
mcp = FastMCP("Fixture PyGhidra", host="127.0.0.1", port=args.port or 8001)
name = "FUN_00401000"


class GuiContextResponse(BaseModel):
    active_program: str | None = "/app.exe"
    active_provider: str | None = "Listing"
    active_address: str | None = "00401008"
    active_function: str | None = None
    selection: str | None = None
    location_type: str | None = "ProgramLocation"


class DecompiledFunction(BaseModel):
    name: str
    code: str
    signature: str | None = None
    error: str | None = None


class RenameResponse(BaseModel):
    binary_name: str
    address: str
    old_name: str
    new_name: str


@mcp.tool()
def get_gui_context() -> GuiContextResponse:
    return GuiContextResponse(active_function=name)


@mcp.tool()
def decompile_function(
    binary_name: str,
    name_or_address: str | list[str],
    include_callees: bool = False,
    include_strings: bool = False,
    include_xrefs: bool = False,
    timeout_sec: int = 30,
) -> list[DecompiledFunction]:
    assert binary_name == "/app.exe"
    assert name_or_address == "00401008"
    return [
        DecompiledFunction(
            name=f"{name}-00401000",
            code=f"int {name}(int x) {{ return x + 1; }}",
            signature=f"int {name}(int x)",
        )
    ]


@mcp.tool()
def rename_function(
    binary_name: str, name_or_address: str, new_name: str
) -> RenameResponse:
    global name
    assert binary_name == "/app.exe"
    assert name_or_address == "00401008"
    old_name, name = name, new_name
    return RenameResponse(
        binary_name=binary_name, address="00401000", old_name=old_name, new_name=name
    )


@mcp.tool()
def list_xrefs(binary_name: str, name_or_address: str) -> dict:
    return {"target": name_or_address, "cross_references": [], "error": None}


if __name__ == "__main__":
    mcp.run(transport="streamable-http" if args.port else "stdio")
