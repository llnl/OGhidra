"""Real workflow MCP server with a deterministic LM for protocol tests."""

import sys
from pathlib import Path

import dspy
from dspy.utils import DummyLM
from oghidra_workflows.server import build_server
from oghidra_workflows.config import AppConfig

proposal = dict(
    suggested_name="incrementValue",
    analysis="Adds one.",
    behavior_summary="Returns input plus one.",
    rationale="Observed operation.",
)
dspy.LM = lambda **kwargs: DummyLM([{"proposal": proposal}])
build_server(
    AppConfig.model_validate(
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
).run()
