"""Standard MCP sessions and DSPy's native tool conversion, for any MCP server."""

import os
from collections.abc import AsyncIterator, Mapping
from contextlib import AsyncExitStack, asynccontextmanager

import dspy
from mcp import ClientSession, StdioServerParameters
from mcp.client.sse import sse_client
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamablehttp_client
from mcp.types import Tool

from .config import MCPServerConfig, StdioServerConfig
from .diagnostics import endpoint, logger, operation, register_secret


@asynccontextmanager
async def connect(
    servers: Mapping[str, MCPServerConfig],
) -> AsyncIterator[
    tuple[dict[str, ClientSession], dict[str, dict[str, Tool]], list[dspy.Tool]]
]:
    # The outer scope also captures ExceptionGroups raised by SDK cleanup.
    with operation("mcp.session_lifecycle"):
        async with AsyncExitStack() as stack:
            sessions: dict[str, ClientSession] = {}
            catalogs: dict[str, dict[str, Tool]] = {}
            evidence_tools: list[dspy.Tool] = []
            for name, config in servers.items():
                fields = {"mcp_server": name, "transport": config.transport}
                if isinstance(config, StdioServerConfig):
                    fields["command"] = config.command  # never log args or env values
                    for key, value in config.env.items():
                        if any(
                            word in key.lower()
                            for word in ("key", "token", "secret", "password")
                        ):
                            register_secret(value)
                    with operation("mcp.connect", **fields):
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
                    fields["endpoint"] = endpoint(config.url)
                    factory = (
                        sse_client
                        if config.transport == "sse"
                        else streamablehttp_client
                    )
                    with operation("mcp.connect", **fields):
                        streams = await stack.enter_async_context(
                            factory(str(config.url))
                        )
                with operation("mcp.initialize", **fields):
                    session = await stack.enter_async_context(
                        ClientSession(streams[0], streams[1])
                    )
                    initialized = await session.initialize()
                    logger.info(
                        "mcp.initialized",
                        extra={
                            **fields,
                            "server_name": initialized.serverInfo.name,
                            "server_version": initialized.serverInfo.version,
                            "protocol_version": initialized.protocolVersion,
                        },
                    )
                with operation("mcp.discover_tools", **fields):
                    catalog, cursor = {}, None
                    while True:
                        page = await session.list_tools(cursor=cursor)
                        catalog.update({tool.name: tool for tool in page.tools})
                        cursor = page.nextCursor
                        if not cursor:
                            break
                    logger.debug(
                        "mcp.tools_discovered",
                        extra={**fields, "tools": sorted(catalog)},
                    )
                    sessions[name], catalogs[name] = session, catalog
                    for tool_name in config.evidence_tools:
                        if tool_name not in catalog:
                            raise ValueError(
                                f"{name} does not advertise {tool_name}; available tools: {sorted(catalog)}"
                            )
                        tool = dspy.Tool.from_mcp_tool(session, catalog[tool_name])
                        tool.name = f"{name}__{tool_name}"
                        evidence_tools.append(tool)
            logger.debug("mcp.connections_ready")
            try:
                yield sessions, catalogs, evidence_tools
            finally:
                logger.debug("mcp.connections_closing")
        logger.debug("mcp.connections_closed")
