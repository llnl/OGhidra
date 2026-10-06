import json
from types import SimpleNamespace

import dspy
import pytest
from dspy.utils import DummyLM
from mcp.types import CallToolResult, TextContent, Tool
from pydantic import ValidationError

from oghidra_workflows.workflow import RenameProgram, rename_current, result_data

PROPOSAL = dict(
    suggested_name="incrementValue",
    analysis="Adds one to its input.",
    behavior_summary="Returns the input plus one.",
    rationale="Names the observed arithmetic.",
)


class Session:
    def __init__(
        self,
        changed=None,
        write_error=False,
        verify_wrong=False,
        empty=False,
        no_function=False,
        decompile_error=False,
        text_only=False,
        move_after_write=False,
    ):
        self.name = "FUN_00401000"
        self.calls = []
        self.changed, self.write_error = changed, write_error
        self.verify_wrong, self.empty = verify_wrong, empty
        self.no_function, self.decompile_error = no_function, decompile_error
        self.text_only, self.move_after_write = text_only, move_after_write
        self.wrote = False

    async def call_tool(self, name, arguments):
        self.calls.append((name, arguments))
        if name == "rename_function":
            self.wrote = True
            if self.write_error:
                raise TimeoutError("lost reply")
            old_name = self.name
            if not self.verify_wrong:
                self.name = arguments["new_name"]
            data = dict(
                binary_name=arguments["binary_name"],
                address="00401000",
                old_name=old_name,
                new_name=arguments["new_name"],
            )
        elif name == "decompile_function":
            data = {
                "result": [
                    dict(
                        name="FUN_00401000-00401000",
                        code="" if self.empty else "int f(int x) { return x + 1; }",
                        signature=None if self.decompile_error else "int f(int x)",
                        error=None,
                    )
                ]
            }
        else:
            data = dict(
                active_program="/app.exe",
                active_address="00401008",
                active_function=self.name,
            )
            if self.no_function:
                data["active_function"] = None
            if self.changed and len(self.calls) > 2:
                data.update(self.changed)
            if self.wrote and self.move_after_write:
                data["active_address"] = "00402000"
        return CallToolResult(
            content=[TextContent(type="text", text=json.dumps(data))],
            structuredContent=None if self.text_only else data,
        )


CATALOG = {
    name: Tool(name=name, inputSchema={"type": "object"})
    for name in ("get_gui_context", "decompile_function", "rename_function")
}


async def run(session, apply=True, proposal=None):
    with dspy.context(lm=DummyLM([{"proposal": proposal or PROPOSAL}])):
        return await rename_current(session, CATALOG, RenameProgram(), apply)


@pytest.mark.parametrize("text_only", [False, True])
async def test_rename_with_real_dspy_typed_prediction(text_only):
    session = Session(text_only=text_only)
    result = await run(session)
    assert result.status == "renamed"
    assert result.binary_name == "/app.exe"
    assert result.address == "00401008"  # captured cursor, not assumed to be entry
    assert result.function_entry_address == "00401000"
    assert result.observed_name == "incrementValue"
    assert session.calls[-2] == (
        "rename_function",
        {
            "binary_name": "/app.exe",
            "name_or_address": "00401008",
            "new_name": "incrementValue",
        },
    )


async def test_preview_does_not_write():
    session = Session()
    assert (await run(session, False)).status == "proposed"
    assert not session.wrote


async def test_no_improvement_does_not_write():
    session = Session()
    assert (
        await run(session, proposal={**PROPOSAL, "suggested_name": session.name})
    ).status == "unchanged"
    assert not session.wrote


@pytest.mark.parametrize(
    "changed",
    [
        {"active_address": "00402000"},
        {"active_program": "/different.exe"},
        {"active_function": "renamedByUser"},
    ],
)
async def test_changed_target_aborts(changed):
    session = Session(changed=changed)
    with pytest.raises(RuntimeError, match="changed"):
        await run(session)
    assert not session.wrote


@pytest.mark.parametrize(
    "options",
    [{"write_error": True}, {"verify_wrong": True}, {"move_after_write": True}],
)
async def test_uncertain_mutation_is_not_success_or_retried(options):
    session = Session(**options)
    assert (await run(session)).status == "verification_failed"
    assert sum(name == "rename_function" for name, _ in session.calls) == 1


@pytest.mark.parametrize("options", [{"empty": True}, {"decompile_error": True}])
async def test_failed_decompilation_aborts(options):
    session = Session(**options)
    with pytest.raises(RuntimeError, match="Decompilation failed"):
        await run(session)
    assert not session.wrote


async def test_no_selected_function():
    session = Session(no_function=True)
    with pytest.raises(ValueError, match="Select a function"):
        await run(session)
    assert len(session.calls) == 1


async def test_invalid_name_never_reaches_write():
    class BadProgram:
        async def acall(self, **kwargs):
            return SimpleNamespace(
                proposal={**PROPOSAL, "suggested_name": "bad name();"}
            )

    session = Session()
    with pytest.raises(ValidationError):
        await rename_current(session, CATALOG, BadProgram())
    assert not session.wrote


async def test_missing_gui_capability_fails_before_model():
    with pytest.raises(ValueError, match="--gui"):
        await rename_current(Session(), {}, RenameProgram())


def test_mcp_error_flag_is_respected():
    with pytest.raises(RuntimeError, match="Unavailable"):
        result_data(
            CallToolResult(
                isError=True, content=[TextContent(type="text", text="Unavailable")]
            )
        )
