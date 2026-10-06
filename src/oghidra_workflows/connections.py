"""Standard MCP sessions and DSPy's native tool conversion, for any MCP server."""

import os
from contextlib import AsyncExitStack, asynccontextmanager
from collections.abc import AsyncIterator, Mapping

import dspy
from mcp import ClientSession, StdioServerParameters
from mcp.types import Tool
from mcp.client.sse import sse_client
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamablehttp_client


from .config import MCPServerConfig, StdioServerConfig


@asynccontextmanager
async def connect(
    servers: Mapping[str, MCPServerConfig],
) -> AsyncIterator[
    tuple[dict[str, ClientSession], dict[str, dict[str, Tool]], list[dspy.Tool]]
]:
    async with AsyncExitStack() as stack:
        sessions: dict[str, ClientSession] = {}
        catalogs: dict[str, dict[str, Tool]] = {}
        evidence_tools: list[dspy.Tool] = []
        for name, config in servers.items():
            if isinstance(config, StdioServerConfig):
                streams = await stack.enter_async_context(
                    stdio_client(
                        StdioServerParameters(
                            command=config.command,
                            args=config.args,
                            env={**os.environ, **config.env},
                        )
                    )
                )
            else:
                factory = (
                    sse_client if config.transport == "sse" else streamablehttp_client
                )
                streams = await stack.enter_async_context(factory(str(config.url)))
            session = await stack.enter_async_context(
                ClientSession(streams[0], streams[1])
            )
            await session.initialize()
            catalog, cursor = {}, None
            while True:
                page = await session.list_tools(cursor=cursor)
                catalog.update({tool.name: tool for tool in page.tools})
                cursor = page.nextCursor
                if not cursor:
                    break
            sessions[name], catalogs[name] = session, catalog
            # Explicit configuration controls the evidence agent's tools. It does
            # not restrict tools independently available to the host client.
            for tool_name in config.evidence_tools:
                if tool_name not in catalog:
                    raise ValueError(f"{name} does not advertise {tool_name}")
                tool = dspy.Tool.from_mcp_tool(session, catalog[tool_name])
                tool.name = f"{name}__{tool_name}"
                evidence_tools.append(tool)
        yield sessions, catalogs, evidence_tools
