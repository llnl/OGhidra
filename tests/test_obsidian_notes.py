from mcp.types import CallToolResult, TextContent

from oghidra_workflows.obsidian import read_function_note, write_function_note


def reply(text="", *, error=False):
    return CallToolResult(content=[TextContent(type="text", text=text)], isError=error)


async def test_existing_note_is_moved_and_updated_with_human_notes():
    calls = []

    class Session:
        async def call_tool(self, name, arguments):
            calls.append((name, arguments))
            if name == "vault_read":
                return reply("file not found", error=True)
            return reply("ok")

    existing = (
        '---\nbinary_name: "/app.exe"\naddress: "0x1"\n---\n'
        "## Human Notes\nKeep this observation: \\g<0>.\n"
    )
    await write_function_note(
        Session(),
        "/vault",
        "/app.exe",
        "00000001",
        "FUN_1",
        "incrementOne",
        "new analysis\n---\n*Last analyzed: now*\n",
        "functions/FUN_1.md",
        existing,
    )

    assert [name for name, _ in calls] == ["vault_read", "vault_move", "vault_write"]
    assert calls[1][1]["allowOverwrite"] is False
    assert calls[2][1]["path"] == "functions/incrementOne.md"
    assert "Keep this observation: \\g<0>." in calls[2][1]["content"]


async def test_note_write_error_is_reported_to_workflow():
    class Session:
        async def call_tool(self, name, arguments):
            if name == "vault_read":
                return reply("file not found", error=True)
            if name == "vault_write":
                return reply("permission denied", error=True)
            return reply("ok")

    import pytest

    with pytest.raises(RuntimeError, match="stub write failed"):
        await write_function_note(
            Session(),
            "/vault",
            "/app.exe",
            "00000001",
            "FUN_1",
            "incrementOne",
            "analysis",
        )


async def test_note_read_permission_error_is_not_treated_as_missing():
    class Session:
        async def call_tool(self, name, arguments):
            return reply("permission denied", error=True)

    import pytest

    with pytest.raises(RuntimeError, match="note read failed"):
        await read_function_note(Session(), "/vault", "/app.exe", "FUN_1", "00000001")
