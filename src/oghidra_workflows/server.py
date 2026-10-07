"""MCP entry point. No provider-specific clients or Ghidra proxy endpoints."""

import truststore

# Use the operating system's certificate trust configuration.
# Must run before importing DSPy, LiteLLM, or other HTTP clients.
truststore.inject_into_ssl()

import argparse
import asyncio
import logging
import os
import platform
import sys
from contextlib import asynccontextmanager
from importlib.metadata import version
from pathlib import Path

import dspy
from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from .config import AppConfig, LMConfig, load_config
from .connections import connect
from .diagnostics import (
    DSPyLoggingCallback,
    configure_logging,
    endpoint,
    install_async_exception_handler,
    install_exception_hooks,
    logger,
    operation,
    register_secret,
    request_context,
    resolve_log_file,
)
from .workflow import RenameProgram, RenameResult, rename_current


def make_lm(config: LMConfig) -> dspy.LM:
    kwargs = config.model_dump(
        mode="json",
        exclude={"api_key_env"},
        exclude_none=True,
    )

    # Remove trailing slash from api_base to avoid double-slash issues with litellm
    if "api_base" in kwargs and kwargs["api_base"] is not None:
        api_base_str = str(kwargs["api_base"])
        if api_base_str.endswith("/"):
            kwargs["api_base"] = api_base_str.rstrip("/")
    if config.api_key_env is not None:
        key = os.environ.get(config.api_key_env)
        if not key:
            raise ValueError(
                f"Required model credential environment variable is missing or empty: {config.api_key_env}"
            )
        register_secret(key)
        kwargs["api_key"] = key
    else:
        # For self-hosted VLLM servers or other endpoints that don't require authentication,
        # provide a dummy key that satisfies OpenAI client validation (must start with 'sk-').
        # The server will ignore this key if authentication is not configured.
        kwargs["api_key"] = "sk-no-key-required"
    if "/" not in config.model:
        logger.warning(
            "model.provider_prefix_missing",
            extra={
                "model": config.model,
                "hint": "DSPy/LiteLLM may require a provider prefix, e.g. ollama_chat/MODEL or openai/MODEL",
            },
        )
    # Pass ssl_verify to LiteLLM via DSPy LM kwargs
    # Default to verification when omitted; preserve an explicit setting.
    kwargs.setdefault("ssl_verify", True)
    with operation(
        "model.initialize",
        model=config.model,
        api_base=endpoint(config.api_base) if config.api_base else None,
    ):
        return dspy.LM(**kwargs)


@asynccontextmanager
async def server_lifespan(server):
    install_async_exception_handler()
    logger.info("server.ready", extra={"transport": "stdio"})
    try:
        yield {}
    finally:
        logger.info("server.stopped")


def build_server(config: AppConfig) -> FastMCP:
    lm = make_lm(config.lm)
    server = FastMCP(
        "OGhidra Workflows", log_level=config.log_level, lifespan=server_lifespan
    )
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
        with request_context() as request_id:
            logger.info(
                "workflow.started",
                extra={"tool": "rename_current_function", "apply": apply},
            )
            try:
                with operation("workflow.rename", apply=apply):
                    with operation("workflow.wait_for_lock"):
                        await lock.acquire()
                    try:
                        async with connect(config.mcp_servers) as (
                            sessions,
                            catalogs,
                            tools,
                        ):
                            program = RenameProgram(tools, max_iters=config.max_iters)
                            if artifact := config.compiled_predictor:
                                with operation("predictor.load", artifact=artifact):
                                    program.analyze.load(artifact)
                            with dspy.context(lm=lm, callbacks=[DSPyLoggingCallback()]):
                                result = await rename_current(
                                    sessions["ghidra"],
                                    catalogs["ghidra"],
                                    program,
                                    apply,
                                )
                    finally:
                        lock.release()
                if result.status == "verification_failed":
                    result.detail += f" [request_id={request_id}]"
                logger.log(
                    (
                        logging.WARNING
                        if result.status == "verification_failed"
                        else logging.INFO
                    ),
                    "workflow.completed",
                    extra={"status": result.status},
                )
                return result
            except Exception as exc:
                # The operation scope recorded the traceback before FastMCP turns
                # this exception into an MCP error. Return its correlation ID too.
                raise RuntimeError(
                    f"OGhidra workflow failed [request_id={request_id}]: {exc}"
                ) from exc

    return server


def main():
    configure_logging()  # stderr still works if config/file setup fails
    install_exception_hooks()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=Path("./config.yaml"), type=Path)
    args = parser.parse_args()
    config_path = args.config.resolve()
    config = None
    try:
        with operation(
            "config.load", config_path=str(config_path), cwd=str(Path.cwd())
        ):
            config = load_config(config_path)
        log_file = resolve_log_file(config_path, config.log_file)
        configure_logging(
            config.log_level, log_file, config.log_max_bytes, config.log_backup_count
        )
        logger.info(
            "server.starting",
            extra={
                "config_path": str(config_path),
                "cwd": str(Path.cwd()),
                "executable": sys.executable,
                "python": platform.python_version(),
                "log_file": str(log_file) if log_file else None,
                "versions": {
                    p: version(p)
                    for p in ("dspy", "mcp", "pydantic", "python-json-logger")
                },
            },
        )
        build_server(config).run(transport="stdio")
        logger.info(
            "server.exited",
            extra={
                "reason": "MCP stdio transport returned; host may have closed stdin"
            },
        )
    except KeyboardInterrupt:
        logger.info("server.interrupted")
    except Exception:
        if config is None:
            try:
                configure_logging(
                    log_file=resolve_log_file(config_path, "logs/oghidra-{pid}.jsonl")
                )
            except OSError:
                logger.exception("logging.bootstrap_file_unavailable")
        logger.critical("server.failed", exc_info=True)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
