from types import SimpleNamespace

import dspy
import pytest
from dspy.utils import DummyLM
from mcp.types import CallToolResult, TextContent, Tool
from pydantic import ValidationError

from oghidra_workflows.workflow import RenameProgram, function_identity, rename_current

PROPOSAL = dict(
    suggested_name="incrementValue",
    analysis="Adds one to its input.",
    behavior_summary="Returns the input plus one.",
    rationale="Names the observed arithmetic.",
)


class Session:
    def __init__(
        self, changed=False, write_error=False, verify_wrong=False, empty=False
    ):
        self.name = "FUN_00401000"
        self.calls = []
        self.changed, self.write_error = changed, write_error
        self.verify_wrong, self.empty = verify_wrong, empty

    async def call_tool(self, name, arguments):
        self.calls.append((name, arguments))
        if name == "rename_function_by_address":
            if self.write_error:
                raise TimeoutError("lost reply")
            if not self.verify_wrong:
                self.name = arguments["name"]
            text = "Renamed"
        elif name == "decompile_function_by_address":
            text = "" if self.empty else "int f(int x) { return x + 1; }"
        else:
            address = "00402000" if self.changed and len(self.calls) > 2 else "00401000"
            text = f"Function: {self.name} at {address}"
        return CallToolResult(content=[TextContent(type="text", text=text)])


CATALOG = {
    name: Tool(
        name=name,
        inputSchema={
            "type": "object",
            "properties": {"address": {"type": "string"}, "name": {"type": "string"}},
        },
    )
    for name in (
        "get_current_function",
        "get_function_by_address",
        "decompile_function_by_address",
        "rename_function_by_address",
    )
}


async def run(session, apply=True, proposal=None):
    with dspy.context(lm=DummyLM([{"proposal": proposal or PROPOSAL}])):
        return await rename_current(session, CATALOG, RenameProgram(), apply)


async def test_rename_with_real_dspy_typed_prediction():
    session = Session()
    result = await run(session)
    assert result.status == "renamed"
    assert result.observed_name == "incrementValue"
    assert session.calls[-2] == (
        "rename_function_by_address",
        {"address": "401000", "name": "incrementValue"},
    )


async def test_preview_does_not_write():
    session = Session()
    assert (await run(session, False)).status == "proposed"
    assert not any(name.startswith("rename") for name, _ in session.calls)


async def test_no_improvement_does_not_write():
    session = Session()
    assert (
        await run(session, proposal={**PROPOSAL, "suggested_name": session.name})
    ).status == "unchanged"
    assert len(session.calls) == 2


async def test_moved_selection_aborts():
    session = Session(changed=True)
    with pytest.raises(RuntimeError, match="changed"):
        await run(session)
    assert not any(name.startswith("rename") for name, _ in session.calls)


@pytest.mark.parametrize("options", [{"write_error": True}, {"verify_wrong": True}])
async def test_uncertain_mutation_is_not_success_or_retried(options):
    session = Session(**options)
    assert (await run(session)).status == "verification_failed"
    assert sum(name.startswith("rename") for name, _ in session.calls) == 1


async def test_no_decompilation_aborts():
    session = Session(empty=True)
    with pytest.raises(RuntimeError, match="empty"):
        await run(session)
    assert len(session.calls) == 2


async def test_invalid_name_never_reaches_write():
    class BadProgram:
        async def acall(self, **kwargs):
            return SimpleNamespace(
                proposal={**PROPOSAL, "suggested_name": "bad name();"}
            )

    session = Session()
    with pytest.raises(ValidationError):
        await rename_current(session, CATALOG, BadProgram())
    assert len(session.calls) == 2


@pytest.mark.parametrize(
    "text",
    ["No function at current location: 00401000", "Error: unavailable", "garbage"],
)
def test_invalid_selection(text):
    with pytest.raises(ValueError):
        function_identity(text)


async def test_missing_capability_fails_before_model():
    with pytest.raises(ValueError, match="missing required"):
        await rename_current(Session(), {}, RenameProgram())


def test_archive_fork_rename_schema():
    from oghidra_workflows.workflow import rename_arguments

    assert rename_arguments(
        {"properties": {"function_address": {}, "new_name": {}}},
        "401000",
        "incrementValue",
    ) == {"function_address": "401000", "new_name": "incrementValue"}


def test_mcp_error_flag_is_respected():
    from oghidra_workflows.workflow import result_text

    with pytest.raises(RuntimeError):
        result_text(
            CallToolResult(
                isError=True, content=[TextContent(type="text", text="Unavailable")]
            )
        )


def test_namespaced_function_identity():
    assert function_identity(
        "Function: ns::FUN_00401000 at 0x00401000\nSignature: int f()"
    ) == ("ns::FUN_00401000", "401000")
