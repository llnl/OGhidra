"""MCP entry point. No provider-specific clients or Ghidra proxy endpoints."""

import argparse
import asyncio
import json
import os
from pathlib import Path

import dspy
import yaml
from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from .config import AppConfig, LMConfig, load_config
from .connections import connect
from .workflow import (
    GuiContext,
    RenameProgram,
    RenameResult,
    rename_current,
    result_data,
)


def make_lm(config: LMConfig) -> dspy.LM:
    # Dictionary conversion occurs only at the external SDK boundary.
    kwargs = config.model_dump(mode="json", exclude={"api_key_env"}, exclude_none=True)
    if config.api_key_env is not None:
        kwargs["api_key"] = os.environ[config.api_key_env]
    return dspy.LM(**kwargs)


def build_server(config: AppConfig) -> FastMCP:
    lm = make_lm(config.lm)
    server = FastMCP("OGhidra Workflows", log_level=config.log_level)
    lock = asyncio.Lock()

    @server.tool(
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=True,
            idempotentHint=False,
            openWorldHint=True,
        )
    )
    async def rename_current_function(apply: bool = True) -> RenameResult:
        """Analyze the function selected in Ghidra and rename it using DSPy.

        apply=False returns a proposal without writing. apply=True runs a fresh
        analysis and applies its result; it does not commit a previous proposal.
        Requires the configured Ghidra GUI to remain on the same program.
        """
        async with lock:
            async with connect(config.mcp_servers) as (sessions, catalogs, tools):
                program = RenameProgram(tools, max_iters=config.max_iters)
                if artifact := config.compiled_predictor:
                    program.analyze.load(artifact)
                with dspy.context(lm=lm):
                    return await rename_current(
                        sessions["ghidra"], catalogs["ghidra"], program, apply
                    )

    return server


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=Path("./config.yaml"), type=Path)
    args = parser.parse_args()
    if args.config is None:
        parser.error("--config is required unless --schema is supplied")
    try:
        config = load_config(args.config)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        parser.error(str(exc))

    build_server(config).run(transport="stdio")


if __name__ == "__main__":
    main()
