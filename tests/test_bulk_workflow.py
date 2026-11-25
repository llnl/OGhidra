import json
import re
from types import SimpleNamespace

import pytest
from mcp.types import CallToolResult, TextContent, Tool

import oghidra_workflows.obsidian as obsidian_module
import oghidra_workflows.workflow as workflow_module
from oghidra_workflows.workflow import rename_all

PROPOSAL = {
    "suggested_name": "incrementValue",
    "analysis": "Adds one.",
    "behavior_summary": "Returns the input plus one.",
    "rationale": "Describes the observed arithmetic.",
}
CATALOG = {
    name: Tool(name=name, inputSchema={"type": "object"})
    for name in (
        "get_gui_context",
        "search_symbols_by_name",
        "decompile_function",
        "rename_function",
    )
}


def symbol(address, name, *, source="DEFAULT", external=False, is_thunk=False):
    return {
        "address": address,
        "name": name,
        "source": source,
        "external": external,
        "is_thunk": is_thunk,
        "type": "Function",
        "namespace": "Global",
        "refcount": 0,
    }


class Session:
    def __init__(self, symbols):
        self.symbols = {item["address"]: item for item in symbols}
        self.calls = []
        self.program = "/app.exe"
        self.change_before_write = None
        self.rename_error = False
        self.bad_receipt = False
        self.decompile_fail = set()
        self.reject_duplicate = False
        self.disconnect_on_decompile = False
        self.disconnected = False

    async def call_tool(self, name, arguments):
        self.calls.append((name, arguments))
        if self.disconnected:
            raise ConnectionError("MCP connection closed")
        if name == "get_gui_context":
            data = {
                "active_program": self.program,
                "active_address": None,
                "active_function": None,
            }
        elif name == "search_symbols_by_name":
            matches = [
                item
                for item in self.symbols.values()
                if re.search(arguments["query"], item["name"], re.IGNORECASE)
            ]
            matches.sort(key=lambda item: (item["name"].lower(), item["address"]))
            data = {
                "symbols": matches[
                    arguments["offset"] : arguments["offset"] + arguments["limit"]
                ]
            }
        elif name == "decompile_function":
            if self.disconnect_on_decompile:
                self.disconnected = True
                raise ConnectionError("MCP connection closed")
            address = arguments["name_or_address"]
            item = self.symbols[address]
            data = {
                "result": [
                    {
                        "name": f"{item['name']}-{address}",
                        "code": ""
                        if address in self.decompile_fail
                        else "int f(int x) { return x + 1; }",
                        "signature": None
                        if address in self.decompile_fail
                        else "int f(int x)",
                        "error": None,
                    }
                ]
            }
        elif name == "rename_function":
            if self.rename_error:
                raise TimeoutError("reply lost")
            address = arguments["name_or_address"]
            if self.reject_duplicate and any(
                item["name"] == arguments["new_name"] and item["address"] != address
                for item in self.symbols.values()
            ):
                raise ValueError("duplicate function name")
            item = self.symbols[address]
            old_name = item["name"]
            item["name"] = arguments["new_name"]
            item["source"] = "USER_DEFINED"
            data = {
                "binary_name": arguments["binary_name"],
                "address": "BAD" if self.bad_receipt else address,
                "old_name": old_name,
                "new_name": item["name"],
            }
        else:
            raise AssertionError(name)
        if self.change_before_write and name == "decompile_function":
            self.symbols[arguments["name_or_address"]]["name"] = (
                self.change_before_write
            )
        return CallToolResult(
            content=[TextContent(type="text", text=json.dumps(data))],
            structuredContent=data,
        )


class Program:
    def __init__(self, names=None):
        self.names = names or {}

    async def acall(self, **kwargs):
        return SimpleNamespace(
            proposal={
                **PROPOSAL,
                "suggested_name": self.names.get(
                    kwargs["address"], "increment" + kwargs["address"]
                ),
            }
        )


async def test_preview_filters_and_paginates_without_writing():
    items = [symbol(f"{i:08X}", f"FUN_{i:08X}") for i in range(105)]
    items += [
        symbol("00001000", "meaningfulName"),
        symbol("00001001", "FUN_00001001", source="USER_DEFINED"),
        symbol("00001002", "FUN_00001002", external=True),
        symbol("00001003", "FUN_00001003", is_thunk=True),
    ]
    session = Session(items)
    result = await rename_all(session, CATALOG, Program(), limit=5)
    assert result.status == "previewed"
    assert [item.address for item in result.items] == [f"{i:08X}" for i in range(5)]
    assert result.next_cursor
    assert sum(name == "search_symbols_by_name" for name, _ in session.calls) >= 2
    assert not any(name == "rename_function" for name, _ in session.calls)


async def test_apply_uses_addresses_and_continues_after_renames():
    session = Session([symbol(f"{i:08X}", f"FUN_{i:08X}") for i in range(4)])
    first = await rename_all(session, CATALOG, Program(), apply=True, limit=2)
    second = await rename_all(
        session, CATALOG, Program(), apply=True, limit=2, cursor=first.next_cursor
    )
    assert [item.status for item in first.items + second.items] == ["renamed"] * 4
    assert second.next_cursor is None
    assert [
        args["name_or_address"]
        for name, args in session.calls
        if name == "rename_function"
    ] == [f"{i:08X}" for i in range(4)]


async def test_verified_bulk_rename_creates_note_and_reports_outcome(monkeypatch):
    writes = []

    async def read_note(*args):
        return None, None

    async def write_note(*args):
        writes.append(args)

    async def confidence(**kwargs):
        return "high"

    monkeypatch.setattr(obsidian_module, "read_function_note", read_note)
    monkeypatch.setattr(obsidian_module, "write_function_note", write_note)
    monkeypatch.setattr(workflow_module, "calculate_confidence", confidence)
    session = Session([symbol("00000001", "FUN_1")])

    result = await rename_all(
        session,
        CATALOG,
        Program(),
        apply=True,
        obsidian_session=object(),
        vault_path="/vault",
    )

    assert result.items[0].status == "renamed"
    assert result.items[0].note_status == "written"
    assert writes and writes[0][4:6] == ("FUN_1", "increment00000001")


async def test_note_failure_does_not_change_verified_bulk_rename(monkeypatch):
    async def read_note(*args):
        return None, None

    async def write_note(*args):
        raise TimeoutError("reply lost")

    async def confidence(**kwargs):
        return "high"

    monkeypatch.setattr(obsidian_module, "read_function_note", read_note)
    monkeypatch.setattr(obsidian_module, "write_function_note", write_note)
    monkeypatch.setattr(workflow_module, "calculate_confidence", confidence)
    session = Session([symbol("00000001", "FUN_1")])
    result = await rename_all(
        session,
        CATALOG,
        Program(),
        apply=True,
        obsidian_session=object(),
        vault_path="/vault",
    )

    assert result.status == "completed"
    assert result.counts == {"renamed": 1}
    assert result.items[0].note_status == "failed"
    assert "reply lost" in result.items[0].note_detail


async def test_note_collision_skips_vault_write_but_keeps_rename(monkeypatch):
    async def read_note(*args):
        raise obsidian_module.NoteCollisionError("another function owns note")

    async def write_note(*args):
        pytest.fail("collision must not write a note")

    monkeypatch.setattr(obsidian_module, "read_function_note", read_note)
    monkeypatch.setattr(obsidian_module, "write_function_note", write_note)
    result = await rename_all(
        Session([symbol("00000001", "FUN_1")]),
        CATALOG,
        Program(),
        apply=True,
        obsidian_session=object(),
        vault_path="/vault",
    )

    assert result.items[0].status == "renamed"
    assert result.items[0].note_status == "failed"
    assert "another function" in result.items[0].note_detail


async def test_unavailable_obsidian_reports_note_status_on_verified_rename():
    result = await rename_all(
        Session([symbol("00000001", "FUN_1")]),
        CATALOG,
        Program(),
        apply=True,
        vault_path="/vault",
    )
    assert result.items[0].status == "renamed"
    assert result.items[0].note_status == "unavailable"


async def test_bulk_preview_uses_existing_note_context_without_vault_write(monkeypatch):
    seen = []

    async def read_note(*args):
        return "Prior analysis with a human observation", "functions/FUN_1.md"

    async def write_note(*args):
        pytest.fail("preview must not write a note")

    class RecordingProgram(Program):
        async def acall(self, **kwargs):
            seen.append(kwargs["existing_analysis"])
            return await super().acall(**kwargs)

    monkeypatch.setattr(obsidian_module, "read_function_note", read_note)
    monkeypatch.setattr(obsidian_module, "write_function_note", write_note)
    result = await rename_all(
        Session([symbol("00000001", "FUN_1")]),
        CATALOG,
        RecordingProgram(),
        obsidian_session=object(),
        vault_path="/vault",
    )

    assert result.items[0].status == "proposed"
    assert result.items[0].note_status == "not_attempted"
    assert "Prior analysis" in seen[0]


async def test_bulk_same_name_renames_write_distinct_notes(monkeypatch):
    class VaultSession:
        def __init__(self):
            self.notes = {}

        async def call_tool(self, name, arguments):
            if name == "vault_read":
                content = self.notes.get(arguments["path"])
                if content is None:
                    return CallToolResult(
                        content=[TextContent(type="text", text="file not found")],
                        isError=True,
                    )
                return CallToolResult(
                    content=[], structuredContent={"content": content}
                )
            if name == "search_simple":
                matches = [
                    {"filename": path}
                    for path, content in self.notes.items()
                    if arguments["query"] in content
                ]
                return CallToolResult(
                    content=[TextContent(type="text", text=json.dumps(matches))]
                )
            if name == "vault_write":
                self.notes[arguments["path"]] = arguments["content"]
            elif name == "vault_move":
                source, destination = arguments["path"], arguments["destination"]
                if destination in self.notes:
                    raise AssertionError("destination was overwritten")
                self.notes[destination] = self.notes.pop(source)
            else:
                raise AssertionError(name)
            return CallToolResult(content=[TextContent(type="text", text="ok")])

    async def confidence(**kwargs):
        return "high"

    monkeypatch.setattr(workflow_module, "calculate_confidence", confidence)
    ghidra = Session([symbol("00000001", "FUN_1"), symbol("00000002", "FUN_2")])
    vault = VaultSession()
    program = Program({"00000001": "sharedName", "00000002": "sharedName"})

    result = await rename_all(
        ghidra,
        CATALOG,
        program,
        apply=True,
        obsidian_session=vault,
        vault_path="/vault",
    )

    assert result.counts == {"renamed": 2}
    assert [item.note_status for item in result.items] == ["written", "written"]
    assert len(vault.notes) == 2
    assert "functions/sharedName.md" in vault.notes


async def test_stale_name_is_not_written_and_next_target_continues():
    session = Session([symbol("00000001", "FUN_1"), symbol("00000002", "FUN_2")])
    session.change_before_write = "changedByUser"
    result = await rename_all(session, CATALOG, Program(), apply=True)
    assert [item.status for item in result.items] == ["stale", "stale"]
    assert not any(name == "rename_function" for name, _ in session.calls)


async def test_uncertain_write_is_reported_once_and_processing_continues():
    session = Session([symbol("00000001", "FUN_1"), symbol("00000002", "FUN_2")])
    session.bad_receipt = True
    result = await rename_all(session, CATALOG, Program(), apply=True)
    assert [item.status for item in result.items] == ["verification_failed"] * 2
    assert sum(name == "rename_function" for name, _ in session.calls) == 2


async def test_invalid_proposal_and_decompile_failure_do_not_stop_batch():
    session = Session([symbol(f"{i:08X}", f"FUN_{i}") for i in range(3)])
    session.decompile_fail.add("00000001")
    program = Program({"00000000": "invalid name", "00000002": "incrementTwo"})
    result = await rename_all(session, CATALOG, program, apply=True)
    assert [item.status for item in result.items] == ["failed", "failed", "renamed"]
    assert result.status == "partial"
    assert result.counts == {"failed": 2, "renamed": 1}
    assert [
        args["name_or_address"]
        for name, args in session.calls
        if name == "rename_function"
    ] == ["00000002"]


async def test_duplicate_name_rejection_is_reported_and_other_target_continues():
    session = Session([symbol(f"{i:08X}", f"FUN_{i}") for i in range(3)])
    session.reject_duplicate = True
    program = Program(
        {"00000000": "sharedName", "00000001": "sharedName", "00000002": "uniqueName"}
    )
    result = await rename_all(session, CATALOG, program, apply=True)
    assert [item.status for item in result.items] == [
        "renamed",
        "verification_failed",
        "renamed",
    ]
    assert session.symbols["00000001"]["name"] == "FUN_1"


async def test_program_switch_aborts_before_next_write():
    class SwitchingProgram(Program):
        async def acall(self, **kwargs):
            session.program = "/other.exe"
            return await super().acall(**kwargs)

    session = Session([symbol("00000001", "FUN_1")])
    result = await rename_all(session, CATALOG, SwitchingProgram(), apply=True)
    assert result.status == "aborted"
    assert not any(name == "rename_function" for name, _ in session.calls)


async def test_connection_loss_stops_batch_and_preserves_partial_result():
    session = Session([symbol("00000001", "FUN_1"), symbol("00000002", "FUN_2")])
    session.disconnect_on_decompile = True
    result = await rename_all(session, CATALOG, Program(), apply=True)
    assert result.status == "aborted"
    assert [item.status for item in result.items] == ["failed"]
    assert result.next_cursor
    assert not any(name == "rename_function" for name, _ in session.calls)


async def test_provider_secret_is_redacted_from_per_function_error():
    class FailingProgram:
        async def acall(self, **kwargs):
            raise RuntimeError("api_key=fixture-secret")

    session = Session([symbol("00000001", "FUN_1")])
    result = await rename_all(session, CATALOG, FailingProgram())
    assert result.items[0].status == "failed"
    assert "fixture-secret" not in result.items[0].detail
    assert "[REDACTED]" in result.items[0].detail


async def test_bad_cursor_and_cross_program_cursor_are_rejected():
    session = Session([symbol("00000001", "FUN_1"), symbol("00000002", "FUN_2")])
    with pytest.raises(ValueError, match="cursor"):
        await rename_all(session, CATALOG, Program(), cursor="not-a-cursor")
    first = await rename_all(session, CATALOG, Program(), limit=1)
    session.program = "/other.exe"
    with pytest.raises(ValueError, match="program"):
        await rename_all(session, CATALOG, Program(), cursor=first.next_cursor)


@pytest.mark.parametrize("limit", [0, 26, True])
async def test_limit_is_bounded(limit):
    with pytest.raises(ValueError, match="limit"):
        await rename_all(Session([]), CATALOG, Program(), limit=limit)
