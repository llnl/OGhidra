"""Standard MCP sessions and DSPy's native tool conversion, for any MCP server."""

import asyncio
import os
from collections.abc import AsyncIterator, Mapping
from contextlib import AsyncExitStack, asynccontextmanager

import dspy
from mcp import ClientSession, StdioServerParameters
from mcp.client.sse import sse_client
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamablehttp_client
from mcp.types import PaginatedRequestParams, Tool

from .config import MCPServerConfig, StdioServerConfig
from .diagnostics import endpoint, logger, operation, redact, register_secret


async def _close_optional(stack: AsyncExitStack, name: str) -> None:
    """Keep an optional peer's cleanup failure from hiding a Ghidra result."""
    try:
        await stack.aclose()
    except Exception as exc:  # noqa: BLE001 - optional transport cleanup.
        logger.warning(
            "mcp.optional_cleanup_failed",
            extra={"mcp_server": name, "error": redact(str(exc))},
        )


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
                optional = name == "obsidian"
                peer_stack = AsyncExitStack() if optional else stack
                try:
                    fields = {"mcp_server": name, "transport": config.transport}
                    if isinstance(config, StdioServerConfig):
                        fields["command"] = (
                            config.command
                        )  # never log args or env values
                        for key, value in config.env.items():
                            if any(
                                word in key.lower()
                                for word in ("key", "token", "secret", "password")
                            ):
                                register_secret(value)
                        with operation("mcp.connect", **fields):
                            streams = await peer_stack.enter_async_context(
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
                        for key, value in config.headers.items():
                            if any(
                                word in key.lower()
                                for word in (
                                    "authorization",
                                    "key",
                                    "token",
                                    "secret",
                                    "password",
                                )
                            ):
                                register_secret(value)
                        factory = (
                            sse_client
                            if config.transport == "sse"
                            else streamablehttp_client
                        )
                        with operation("mcp.connect", **fields):
                            streams = await peer_stack.enter_async_context(
                                factory(str(config.url), headers=config.headers or None)
                            )
                    with operation("mcp.initialize", **fields):
                        session = await peer_stack.enter_async_context(
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
                        catalog = {}
                        params = None
                        while True:
                            page = await session.list_tools(params=params)
                            catalog.update({tool.name: tool for tool in page.tools})
                            if not page.nextCursor:
                                break
                            params = PaginatedRequestParams(cursor=page.nextCursor)
                        logger.debug(
                            "mcp.tools_discovered",
                            extra={**fields, "tools": sorted(catalog)},
                        )
                        peer_tools = []
                        for tool_name in config.evidence_tools:
                            if tool_name not in catalog:
                                raise ValueError(
                                    f"{name} does not advertise {tool_name}; available tools: {sorted(catalog)}"
                                )
                            tool = dspy.Tool.from_mcp_tool(session, catalog[tool_name])
                            tool.name = f"{name}__{tool_name}"
                            peer_tools.append(tool)
                    if optional:
                        stack.push_async_callback(_close_optional, peer_stack, name)
                    sessions[name], catalogs[name] = session, catalog
                    evidence_tools.extend(peer_tools)
                except (Exception, asyncio.CancelledError) as exc:
                    if not optional:
                        raise
                    await _close_optional(peer_stack, name)
                    # MCP can cancel this task on connection failure; preserve
                    # cancellation only when the caller still has one pending.
                    if (
                        isinstance(exc, asyncio.CancelledError)
                        and asyncio.current_task().cancelling()
                    ):
                        raise
                    logger.warning(
                        "mcp.optional_unavailable",
                        extra={"mcp_server": name, "error": redact(str(exc))},
                    )
            logger.debug("mcp.connections_ready")
            try:
                yield sessions, catalogs, evidence_tools
            finally:
                logger.debug("mcp.connections_closing")
        logger.debug("mcp.connections_closed")
