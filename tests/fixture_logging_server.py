"""Real MCP workflow with a deliberately failing model; never production code."""

import sys
from pathlib import Path

import dspy
from dspy.utils import DummyLM

from oghidra_workflows.config import AppConfig
from oghidra_workflows.diagnostics import configure_logging
from oghidra_workflows.server import build_server

configure_logging("DEBUG", Path(sys.argv[1]))
dspy.LM = lambda **kwargs: DummyLM([])


async def fail(self, **kwargs):
    raise RuntimeError("Simulated provider failure")


dspy.Predict.acall = fail

build_server(
    AppConfig.model_validate(
        {
            "lm": {"model": "openai/fixture"},
            "log_level": "DEBUG",
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
