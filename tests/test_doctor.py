import asyncio
import ssl
import sys
from contextlib import asynccontextmanager
from pathlib import Path

import dspy
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


def required_catalog() -> dict:
    return {
        name: object()
        for name in (
            "get_gui_context",
            "decompile_function",
            "rename_function",
            "list_xrefs",
        )
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
    catalog = required_catalog()
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


async def test_doctor_checks_model_only_when_requested(tmp_path, monkeypatch):
    mcp_calls = []
    model_calls = []

    class Model:
        async def acall(self, *, prompt, cache):
            model_calls.append((prompt, cache))
            return ["anything"]

    monkeypatch.setattr(doctor_module, "make_lm", lambda config: Model(), raising=False)
    monkeypatch.setattr(
        doctor_module,
        "connect",
        fake_connection(catalog=required_catalog(), calls=mcp_calls),
    )
    config = tmp_path / "config.yaml"
    write_config(config, configured_server())

    unchecked = await run_checks(config, timeout=5)
    checked = await run_checks(config, timeout=5, check_model=True)

    assert model_calls == [("Reply with OK.", False)]
    assert (
        Check(
            "WARN",
            "Model connectivity",
            "not tested; pass --check-model to make a small inference request",
        )
        in unchecked
    )
    assert Check("PASS", "Model connectivity", "inference request completed") in checked


async def test_doctor_skips_model_when_local_prerequisite_fails(tmp_path, monkeypatch):
    monkeypatch.setattr(
        doctor_module,
        "make_lm",
        lambda config: pytest.fail("model must not be constructed"),
        raising=False,
    )
    monkeypatch.setattr(
        doctor_module,
        "connect",
        fake_connection(catalog=required_catalog(), calls=[]),
    )
    config = tmp_path / "config.yaml"
    write_config(config, configured_server())
    import yaml

    data = yaml.safe_load(config.read_text(encoding="utf-8"))
    data["lm"]["model"] = "replace/provider-and-model-id"
    config.write_text(yaml.safe_dump(data), encoding="utf-8")

    checks = await run_checks(config, timeout=5, check_model=True)

    assert (
        Check(
            "WARN",
            "Model connectivity",
            "not attempted because model configuration or credentials failed",
        )
        in checks
    )


async def test_model_timeout_does_not_prevent_mcp_check(tmp_path, monkeypatch):
    class Model:
        async def acall(self, **kwargs):
            await asyncio.sleep(5)

    mcp_calls = []
    monkeypatch.setattr(doctor_module, "make_lm", lambda config: Model(), raising=False)
    monkeypatch.setattr(
        doctor_module,
        "connect",
        fake_connection(catalog=required_catalog(), calls=mcp_calls),
    )
    config = tmp_path / "config.yaml"
    write_config(config, configured_server())

    checks = await run_checks(config, timeout=0.01, check_model=True)

    assert Check("FAIL", "Model connectivity", "timed out after 0.01 seconds") in checks
    assert any(
        check.label == "MCP connectivity" and check.status == "PASS" for check in checks
    )
    assert mcp_calls == [("get_gui_context", {})]


@pytest.mark.parametrize(
    ("error", "expected_hint"),
    [
        (dspy.LMAuthError("rejected"), "api_key_env"),
        (dspy.LMUnsupportedModelError("missing"), "exact lm.model"),
        (dspy.LMRateLimitError("slow down"), "rate limit"),
        (dspy.LMBillingError("quota"), "billing and quota"),
        (dspy.LMInvalidRequestError("bad parameter"), "LM parameters"),
        (dspy.LMTransportError("connection refused"), "api_base, DNS, proxy"),
        (dspy.LMServerError("unavailable"), "provider service health"),
    ],
)
async def test_doctor_adds_model_error_troubleshooting(
    tmp_path, monkeypatch, error, expected_hint
):
    class Model:
        async def acall(self, **kwargs):
            raise error

    monkeypatch.setattr(doctor_module, "make_lm", lambda config: Model(), raising=False)
    monkeypatch.setattr(
        doctor_module,
        "connect",
        fake_connection(catalog=required_catalog(), calls=[]),
    )
    config = tmp_path / "config.yaml"
    write_config(config, configured_server())

    checks = await run_checks(config, timeout=5, check_model=True)

    failure = next(check for check in checks if check.label == "Model connectivity")
    assert failure.status == "FAIL"
    assert expected_hint in failure.detail


async def test_doctor_reports_tls_hint_and_redacts_model_endpoint(
    tmp_path, monkeypatch
):
    secret = "secret-model-key"
    raw_endpoint = "https://user:password@example.test/v1?token=query-secret"

    class Model:
        async def acall(self, **kwargs):
            try:
                raise ssl.SSLCertVerificationError(
                    1, "certificate verify failed for secret-model-key"
                )
            except ssl.SSLCertVerificationError as exc:
                raise dspy.LMTransportError("TLS request failed") from exc

    monkeypatch.setenv("DOCTOR_MODEL_KEY", secret)
    monkeypatch.setattr(doctor_module, "make_lm", lambda config: Model(), raising=False)
    monkeypatch.setattr(
        doctor_module,
        "connect",
        fake_connection(catalog=required_catalog(), calls=[]),
    )
    config = tmp_path / "config.yaml"
    write_config(
        config,
        configured_server(),
        lm={
            "model": "openai/fixture",
            "api_base": raw_endpoint,
            "api_key_env": "DOCTOR_MODEL_KEY",
        },
    )

    checks = await run_checks(config, timeout=5, check_model=True)

    detail = next(
        check.detail for check in checks if check.label == "Model connectivity"
    )
    assert "certificate verification failed" in detail
    assert "operating-system trust store" in detail
    assert "hostname, system clock, proxy/private CA" in detail
    assert "https://example.test/v1" in detail
    assert secret not in detail
    assert "password" not in detail
    assert "query-secret" not in detail
    assert "ssl_verify" not in detail


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
    @asynccontextmanager
    async def failing_connection(servers):
        raise ExceptionGroup("connection failed", [ConnectionError("refused")])
        yield  # pragma: no cover - makes this an async context manager fixture

    monkeypatch.setenv("DOCTOR_SECRET", "secret-value-for-doctor")
    monkeypatch.setattr(doctor_module, "connect", failing_connection)
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

    assert main(["--config", str(config)]) == 1

    output = capsys.readouterr().out
    assert "secret-value-for-doctor" not in output
    assert "password" not in output
    assert "query-secret" not in output
    assert "http://127.0.0.1:1/mcp" in output


def test_doctor_cli_model_failure_returns_one(tmp_path, monkeypatch, capsys):
    class Model:
        async def acall(self, **kwargs):
            raise dspy.LMAuthError("credential rejected")

    monkeypatch.setattr(doctor_module, "make_lm", lambda config: Model())
    monkeypatch.setattr(
        doctor_module,
        "connect",
        fake_connection(catalog=required_catalog(), calls=[]),
    )
    config = tmp_path / "config.yaml"
    write_config(config, configured_server())

    assert main(["--config", str(config), "--check-model"]) == 1

    output = capsys.readouterr().out
    assert "[FAIL] Model connectivity" in output
    assert "api_key_env" in output


def test_doctor_cli_rejects_nonpositive_timeout():
    with pytest.raises(SystemExit) as exc:
        main(["--timeout", "0"])
    assert exc.value.code == 2
