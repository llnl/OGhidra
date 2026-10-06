import asyncio
import json
import logging
import os
import subprocess
import sys
from pathlib import Path

import pytest

from oghidra_workflows.diagnostics import (
    configure_logging,
    endpoint,
    logger,
    operation,
    request_context,
)


@pytest.fixture(autouse=True)
def restore_logging():
    root = logging.getLogger()
    old_handlers, old_level = root.handlers[:], root.level
    root.handlers = []  # keep pytest's handlers open while exercising force=True
    old_loggers = {
        name: logging.getLogger(name).level
        for name in (
            "oghidra_workflows",
            "dspy",
            "litellm",
            "LiteLLM",
            "openai",
            "httpx",
            "httpcore",
            "mcp",
        )
    }
    yield
    for handler in root.handlers:
        handler.close()
    root.handlers = old_handlers
    root.setLevel(old_level)
    for name, level in old_loggers.items():
        logging.getLogger(name).setLevel(level)


def records(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_structured_exception_group_is_redacted_and_stdout_empty(
    tmp_path, capsys, monkeypatch
):
    monkeypatch.setenv("EXAMPLE_API_KEY", "secret-for-test-123")
    path = tmp_path / "events.jsonl"
    configure_logging("DEBUG", path)
    with request_context() as request_id:
        with pytest.raises(ExceptionGroup):
            with operation(
                "mcp.initialize",
                endpoint=endpoint(
                    "http://user:password@localhost:8001/mcp?key=private"
                ),
            ):
                raise ExceptionGroup(
                    "connection errors",
                    [
                        ConnectionRefusedError("upstream refused connection"),
                        ValueError("api_key=secret-for-test-123"),
                    ],
                )
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "secret-for-test-123" not in captured.err + path.read_text()
    failure = next(r for r in records(path) if r["message"] == "stage.failed")
    assert failure["request_id"] == request_id
    assert failure["stage"] == "mcp.initialize"
    assert failure["endpoint"] == "http://localhost:8001/mcp"
    assert "ConnectionRefusedError" in failure["exc_info"]
    assert "ValueError" in failure["exc_info"]
    assert failure["duration_ms"] >= 0
    assert failure["timestamp"]


def test_level_and_reconfiguration_do_not_duplicate_records(tmp_path):
    path = tmp_path / "events.jsonl"
    configure_logging("WARNING", path)
    configure_logging("WARNING", path)
    logger.debug("hidden")
    logger.info("hidden")
    logger.warning("one_warning")
    assert [r["message"] for r in records(path)] == ["one_warning"]


def test_file_rotation(tmp_path):
    path = tmp_path / "events.jsonl"
    configure_logging("INFO", path, max_bytes=350, backup_count=2)
    for _ in range(15):
        logger.info("long-event" * 10)
    assert (tmp_path / "events.jsonl.1").exists()
    assert (tmp_path / "events.jsonl.2").exists()
    assert not (tmp_path / "events.jsonl.3").exists()


async def test_request_context_isolated_across_async_tasks(tmp_path):
    path = tmp_path / "events.jsonl"
    configure_logging("DEBUG", path)

    async def task(label):
        with request_context() as request_id:
            with operation(label):
                await asyncio.sleep(0)
                logger.info(label)
                return request_id

    first, second = await asyncio.gather(task("first"), task("second"))
    assert first != second
    selected = {
        r["message"]: r["request_id"]
        for r in records(path)
        if r["message"] in {"first", "second"}
    }
    assert selected == {"first": first, "second": second}
    logger.info("outside")
    assert records(path)[-1]["request_id"] == "-"


def test_invalid_config_has_durable_startup_traceback(tmp_path):
    config = tmp_path / "invalid.yaml"
    config.write_text("lm: [unterminated\n")
    main = Path(__file__).resolve().parents[1] / "main.py"
    result = subprocess.run(
        [sys.executable, str(main), "--config", str(config)],
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 1
    assert result.stdout == ""
    paths = list((tmp_path / "logs").glob("oghidra-*.jsonl"))
    assert len(paths) == 1
    record = records(paths[0])[-1]
    assert record["message"] == "server.failed"
    assert "ParserError" in record["exc_info"]


async def test_model_failure_logged_before_mcp_converts_error(tmp_path):
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    params = StdioServerParameters(
        command=sys.executable,
        args=[
            str(Path(__file__).with_name("fixture_logging_server.py")),
            str(tmp_path / "failure.jsonl"),
        ],
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            response = await session.call_tool(
                "rename_current_function", {"apply": False}
            )
            assert response.isError
            assert "request_id=" in response.content[0].text
    entries = records(tmp_path / "failure.jsonl")
    failure = next(
        r
        for r in entries
        if r["message"] == "stage.failed" and r["stage"] == "dspy.propose_name"
    )
    assert "Simulated provider failure" in failure["exc_info"]
    assert failure["request_id"] in response.content[0].text
    assert any(r["message"] == "mcp.initialized" for r in entries)
    assert any(r["message"] == "server.stopped" for r in entries)


async def test_native_dspy_callback_reports_errors_even_when_caller_handles_them(
    tmp_path,
):
    import dspy
    from oghidra_workflows.diagnostics import DSPyLoggingCallback

    path = tmp_path / "callbacks.jsonl"
    configure_logging("DEBUG", path)

    def fail():
        raise RuntimeError("tool unavailable")

    with request_context():
        with dspy.context(callbacks=[DSPyLoggingCallback()]):
            with pytest.raises(RuntimeError):
                await dspy.Tool(fail).acall()
    assert any(
        r["message"] == "dspy.tool.failed" and "tool unavailable" in r["exc_info"]
        for r in records(path)
    )
