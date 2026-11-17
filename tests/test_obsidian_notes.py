import json

import pytest
from mcp.types import CallToolResult, TextContent

from oghidra_workflows.obsidian import (
    NoteCollisionError,
    format_address,
    make_disambiguated_note_filename,
    read_function_note,
    write_function_note,
)


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

    with pytest.raises(RuntimeError, match="note read failed"):
        await read_function_note(Session(), "/vault", "/app.exe", "FUN_1", "00000001")


async def test_same_name_functions_get_distinct_notes_and_can_be_read_back():
    class VaultSession:
        def __init__(self):
            self.notes = {}

        async def call_tool(self, name, arguments):
            if name == "vault_read":
                content = self.notes.get(arguments["path"])
                if content is None:
                    return reply("file not found", error=True)
                return CallToolResult(
                    content=[], structuredContent={"content": content}
                )
            if name == "search_simple":
                matches = [
                    {"filename": path}
                    for path, content in self.notes.items()
                    if arguments["query"] in content
                ]
                return reply(json.dumps(matches))
            if name == "vault_write":
                self.notes[arguments["path"]] = arguments["content"]
                return reply("ok")
            if name == "vault_move":
                source, destination = arguments["path"], arguments["destination"]
                if destination in self.notes or source not in self.notes:
                    return reply("path conflict", error=True)
                self.notes[destination] = self.notes.pop(source)
                return reply("ok")
            raise AssertionError(name)

    def note(program, address):
        return (
            f'---\nbinary_name: "{program}"\n'
            f'address: "{format_address(address)}"\n---\n'
        )

    session = VaultSession()
    cases = [
        ("/app.exe", "00000001", "FUN_1"),
        ("/app.exe", "00000002", "FUN_2"),
        ("/other.exe", "00000002", "FUN_2"),
    ]
    for program, address, old_name in cases:
        await write_function_note(
            session,
            "/vault",
            program,
            address,
            old_name,
            "sharedName",
            note(program, address),
        )

    assert len(session.notes) == 3
    assert "functions/sharedName.md" in session.notes
    for program, address, _ in cases:
        content, path = await read_function_note(
            session, "/vault", program, "sharedName", address
        )
        assert content == session.notes[path]
        assert path.startswith("functions/sharedName")

    content, path = await read_function_note(
        session, "/vault", "/app.exe", "sharedName", "00000002"
    )
    session.notes[path] += "\n## Human Notes\nKeep the second function distinct.\n"
    await write_function_note(
        session,
        "/vault",
        "/app.exe",
        "00000002",
        "FUN_2",
        "sharedName",
        note("/app.exe", "00000002") + "updated analysis\n---\n*Last analyzed: now*\n",
        path,
        session.notes[path],
    )
    assert "Keep the second function distinct." in session.notes[path]
    assert len(session.notes) == 3


async def test_existing_note_moves_to_distinct_name_without_losing_human_notes():
    program, address = "/app.exe", "00000002"
    old_path = "functions/FUN_2.md"
    new_path = "functions/" + make_disambiguated_note_filename(
        "sharedName", program, address
    )
    notes = {
        "functions/sharedName.md": (
            '---\nbinary_name: "/app.exe"\naddress: "0x1"\n---\n'
        ),
        old_path: (
            '---\nbinary_name: "/app.exe"\naddress: "0x2"\n---\n'
            "## Human Notes\nKeep this observation.\n"
        ),
    }

    class Session:
        async def call_tool(self, tool, arguments):
            if tool == "vault_read":
                content = notes.get(arguments["path"])
                if content is None:
                    return reply("file not found", error=True)
                return CallToolResult(
                    content=[], structuredContent={"content": content}
                )
            if tool == "vault_move":
                source, destination = arguments["path"], arguments["destination"]
                assert arguments["allowOverwrite"] is False
                assert destination not in notes
                notes[destination] = notes.pop(source)
                return reply("ok")
            if tool == "vault_write":
                notes[arguments["path"]] = arguments["content"]
                return reply("ok")
            raise AssertionError(tool)

    await write_function_note(
        Session(),
        "/vault",
        program,
        address,
        "FUN_2",
        "sharedName",
        '---\nbinary_name: "/app.exe"\naddress: "0x2"\n---\n'
        "Updated analysis\n---\n*Last analyzed: now*\n",
        old_path,
        notes[old_path],
    )

    assert old_path not in notes
    assert "Keep this observation." in notes[new_path]
    assert "Updated analysis" in notes[new_path]
    assert notes["functions/sharedName.md"].endswith('address: "0x1"\n---\n')


async def test_occupied_disambiguated_path_is_never_overwritten():
    program, address, name = "/app.exe", "00000002", "sharedName"
    other_note = '---\nbinary_name: "/other.exe"\naddress: "0x9"\n---\n'
    paths = {
        "functions/sharedName.md": other_note,
        "functions/"
        + make_disambiguated_note_filename(name, program, address): other_note,
    }

    class Session:
        async def call_tool(self, tool, arguments):
            if tool != "vault_read":
                pytest.fail("occupied note path must not be written")
            return CallToolResult(
                content=[], structuredContent={"content": paths[arguments["path"]]}
            )

    with pytest.raises(NoteCollisionError, match="Destination note"):
        await write_function_note(
            Session(),
            "/vault",
            program,
            address,
            "FUN_2",
            name,
            f'---\nbinary_name: "{program}"\naddress: "0x2"\n---\n',
        )
    assert len(paths) == 2
