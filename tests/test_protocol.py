import sys
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace

import dspy
from dspy.utils import DummyLM

import oghidra_workflows.server as server_module
from oghidra_workflows.config import AppConfig
from oghidra_workflows.connections import connect
from oghidra_workflows.workflow import GatherEvidence, rename_all


async def test_mcp_apply_contract_preserves_existing_defaults(monkeypatch):
    observed = []

    @asynccontextmanager
    async def fake_connect(servers):
        yield {"ghidra": object()}, {"ghidra": {}}, []

    async def fake_rename_current(session, catalog, program, apply):
        observed.append(apply)
        return SimpleNamespace(status="renamed" if apply else "proposed", detail="")

    monkeypatch.setattr(server_module, "connect", fake_connect)
    monkeypatch.setattr(server_module, "rename_current", fake_rename_current)
    monkeypatch.setattr(dspy, "LM", lambda **kwargs: DummyLM([]))
    config = AppConfig.model_validate(
        {
            "lm": {"model": "fixture"},
            "mcp_servers": {
                "ghidra": {"transport": "stdio", "command": sys.executable}
            },
        }
    )
    tool = server_module.build_server(config)._tool_manager._tools[
        "rename_current_function"
    ]

    await tool.run({})
    await tool.run({"apply": False})

    assert tool.parameters["properties"]["apply"]["default"] is True
    assert observed == [True, False]


async def test_bulk_mcp_contract_defaults_to_preview_and_exposes_cursor(monkeypatch):
    observed = []

    @asynccontextmanager
    async def fake_connect(servers):
        yield {"ghidra": object()}, {"ghidra": {}}, []

    async def fake_rename_all(session, catalog, program, apply, limit, cursor):
        observed.append((apply, limit, cursor))
        return SimpleNamespace(
            status="previewed", detail="", counts={}, next_cursor="next"
        )

    monkeypatch.setattr(server_module, "connect", fake_connect)
    monkeypatch.setattr(server_module, "rename_all", fake_rename_all)
    monkeypatch.setattr(dspy, "LM", lambda **kwargs: DummyLM([]))
    config = AppConfig.model_validate(
        {
            "lm": {"model": "fixture"},
            "mcp_servers": {
                "ghidra": {"transport": "stdio", "command": sys.executable}
            },
        }
    )
    tool = server_module.build_server(config)._tool_manager._tools[
        "rename_all_functions"
    ]

    await tool.run({})
    await tool.run({"apply": True, "limit": 2, "cursor": "previous"})

    properties = tool.parameters["properties"]
    assert properties["apply"]["default"] is False
    assert properties["limit"]["default"] == 5
    assert properties["limit"]["minimum"] == 1
    assert properties["limit"]["maximum"] == 25
    assert observed == [(False, 5, None), (True, 2, "previous")]


async def test_dspy_react_calls_native_mcp_tool():
    config = {
        "ghidra": {
            "transport": "stdio",
            "command": sys.executable,
            "args": [str(Path(__file__).with_name("fake_ghidra.py"))],
            "evidence_tools": ["list_xrefs"],
        }
    }
    config = AppConfig.model_validate(
        {"lm": {"model": "fixture"}, "mcp_servers": config}
    )
    async with connect(config.mcp_servers) as (_, _, tools):
        lm = DummyLM(
            [
                {
                    "next_thought": "Inspect callers",
                    "next_tool_name": "ghidra__list_xrefs",
                    "next_tool_args": {
                        "binary_name": "/app.exe",
                        "name_or_address": "00401008",
                    },
                },
                {
                    "next_thought": "Enough evidence",
                    "next_tool_name": "finish",
                    "next_tool_args": {},
                },
                {"reasoning": "No callers found", "evidence": "No callers"},
            ]
        )
        with dspy.context(lm=lm):
            result = await dspy.ReAct(GatherEvidence, tools=tools).acall(
                target="FUN_00401000 at 401000", decompiled_code="return x+1;"
            )
        assert "cross_references" in str(result.trajectory)
        assert result.evidence == "No callers"


async def test_bulk_rename_uses_native_mcp_function_search_and_write():
    config = AppConfig.model_validate(
        {
            "lm": {"model": "fixture"},
            "mcp_servers": {
                "ghidra": {
                    "transport": "stdio",
                    "command": sys.executable,
                    "args": [str(Path(__file__).with_name("fake_ghidra.py"))],
                }
            },
        }
    )

    class Program:
        async def acall(self, **kwargs):
            return SimpleNamespace(
                proposal={
                    "suggested_name": "incrementValue",
                    "analysis": "Adds one.",
                    "behavior_summary": "Returns input plus one.",
                    "rationale": "Matches arithmetic.",
                }
            )

    async with connect(config.mcp_servers) as (sessions, catalogs, _):
        result = await rename_all(
            sessions["ghidra"], catalogs["ghidra"], Program(), apply=True
        )
    assert result.status == "completed"
    assert [item.status for item in result.items] == ["renamed"]
    assert result.items[0].observed_name == "incrementValue"
