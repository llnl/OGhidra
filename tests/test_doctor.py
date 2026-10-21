import asyncio
import sys
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from mcp.types import CallToolResult, TextContent

import oghidra_workflows.doctor as doctor_module
from oghidra_workflows.doctor import Check, main, run_checks


def write_config(path: Path, server: dict, **overrides) -> None:
    import yaml

    config = {
        "lm": {"model": "openai/fixture"},
        "mcp_servers": {"ghidra": server},
    }
    config.update(overrides)
    path.write_text(yaml.safe_dump(config), encoding="utf-8")


def configured_server() -> dict:
    return {
        "transport": "stdio",
        "command": sys.executable,
        "evidence_tools": ["list_xrefs"],
    }


def fake_connection(catalog=None, calls=None):
    class Session:
        async def call_tool(self, name, arguments):
            calls.append((name, arguments))
            data = {
                "active_program": "/fixture/program.exe",
                "active_address": "00401008",
                "active_function": "FUN_00401000",
            }
            return CallToolResult(
                content=[TextContent(type="text", text="fixture")],
                structuredContent=data,
            )

    @asynccontextmanager
    async def connect(servers):
        yield {"ghidra": Session()}, {"ghidra": catalog}, []

    return connect


async def test_doctor_connects_and_only_reads_gui_context(tmp_path, monkeypatch):
    calls = []
    catalog = {
        name: object()
        for name in (
            "get_gui_context",
            "decompile_function",
            "rename_function",
            "list_xrefs",
        )
    }
    monkeypatch.setattr(
        doctor_module, "connect", fake_connection(catalog=catalog, calls=calls)
    )
    config = tmp_path / "config.yaml"
    write_config(config, configured_server())

    checks = await run_checks(config, timeout=5)

    assert all(check.status != "FAIL" for check in checks)
    assert calls == [("get_gui_context", {})]
    assert any(
        check.label == "Ghidra selection" and "FUN_00401000" in check.detail
        for check in checks
    )


@pytest.mark.parametrize(
    ("lm", "overrides", "expected"),
    [
        ({"model": "replace/provider-and-model-id"}, {}, "model placeholder"),
        (
            {"model": "openai/fixture", "api_key_env": "MISSING_DOCTOR_KEY"},
            {},
            "MISSING_DOCTOR_KEY",
        ),
        (
            {"model": "openai/fixture"},
            {"compiled_predictor": "missing.json"},
            "compiled predictor",
        ),
    ],
)
async def test_doctor_reports_local_configuration_failures(
    tmp_path, monkeypatch, lm, overrides, expected
):
    monkeypatch.delenv("MISSING_DOCTOR_KEY", raising=False)
    config = tmp_path / "config.yaml"
    write_config(
        config,
        {"transport": "stdio", "command": sys.executable},
        **overrides,
    )
    import yaml

    data = yaml.safe_load(config.read_text(encoding="utf-8"))
    data["lm"] = lm
    config.write_text(yaml.safe_dump(data), encoding="utf-8")

    checks = await run_checks(config, timeout=0.1)

    assert any(check.status == "FAIL" and expected in check.detail for check in checks)


async def test_doctor_reports_missing_required_tool(tmp_path, monkeypatch):
    calls = []
    catalog = {
        name: object()
        for name in ("get_gui_context", "decompile_function", "list_xrefs")
    }
    monkeypatch.setattr(
        doctor_module, "connect", fake_connection(catalog=catalog, calls=calls)
    )
    config = tmp_path / "config.yaml"
    write_config(config, configured_server())

    checks = await run_checks(config, timeout=5)

    assert any(
        check.status == "FAIL"
        and check.label == "Ghidra tools"
        and "rename_function" in check.detail
        for check in checks
    )
    assert calls == []


async def test_doctor_timeout_is_bounded(tmp_path, monkeypatch):
    @asynccontextmanager
    async def slow_connection(servers):
        await asyncio.sleep(5)
        yield {}, {}, []

    monkeypatch.setattr(doctor_module, "connect", slow_connection)
    config = tmp_path / "config.yaml"
    write_config(config, configured_server())

    checks = await run_checks(config, timeout=0.05)

    assert (
        Check(
            "FAIL",
            "MCP connectivity",
            f"timed out after 0.05 seconds while checking ghidra={sys.executable}",
        )
        in checks
    )


def test_doctor_cli_redacts_credentials_and_endpoint_details(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.setenv("DOCTOR_SECRET", "secret-value-for-doctor")
    config = tmp_path / "config.yaml"
    write_config(
        config,
        {
            "transport": "streamable-http",
            "url": "http://user:password@127.0.0.1:1/mcp?token=query-secret",
        },
    )
    import yaml

    data = yaml.safe_load(config.read_text(encoding="utf-8"))
    data["lm"]["api_key_env"] = "DOCTOR_SECRET"
    config.write_text(yaml.safe_dump(data), encoding="utf-8")

    assert main(["--config", str(config), "--timeout", "0.1"]) == 1

    output = capsys.readouterr().out
    assert "secret-value-for-doctor" not in output
    assert "password" not in output
    assert "query-secret" not in output
    assert "http://127.0.0.1:1/mcp" in output


def test_doctor_cli_rejects_nonpositive_timeout():
    with pytest.raises(SystemExit) as exc:
        main(["--timeout", "0"])
    assert exc.value.code == 2
