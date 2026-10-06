import sys
from pathlib import Path

import dspy
from dspy.utils import DummyLM
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from oghidra_workflows.config import AppConfig
from oghidra_workflows.connections import connect
from oghidra_workflows.workflow import GatherEvidence


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
