"""Read-only preflight checks for an OGhidra workflow configuration."""

# Import ordering below intentionally initializes the system trust store first.

from __future__ import annotations

import argparse
import asyncio
import math
import os
import ssl
from dataclasses import dataclass
from pathlib import Path

import truststore
import yaml
from pydantic import ValidationError

# Match the workflow server's operating-system trust configuration.
truststore.inject_into_ssl()

import dspy

from .config import AppConfig, HttpServerConfig, StdioServerConfig, load_config
from .connections import connect
from .diagnostics import configure_logging, endpoint, redact, register_secret
from .server import make_lm
from .workflow import REQUIRED_GHIDRA_TOOLS, GuiContext, result_data

MODEL_PLACEHOLDER = "replace/provider-and-model-id"


@dataclass(frozen=True)
class Check:
    status: str
    label: str
    detail: str


def _positive_timeout(value: str) -> float:
    try:
        timeout = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timeout must be a number") from exc
    if not math.isfinite(timeout) or not 0 < timeout <= 300:
        raise argparse.ArgumentTypeError(
            "timeout must be greater than 0 and at most 300"
        )
    return timeout


def _register_config_secrets(config: AppConfig) -> None:
    if config.lm.api_key_env:
        register_secret(os.environ.get(config.lm.api_key_env))
    for server in config.mcp_servers.values():
        if isinstance(server, StdioServerConfig):
            for value in server.env.values():
                register_secret(value)


def _safe_error(exc: Exception, config: AppConfig | None = None) -> str:
    detail = str(exc).replace("\n", " ")
    if config is not None:
        if config.lm.api_base is not None:
            raw_url = str(config.lm.api_base)
            detail = detail.replace(raw_url, endpoint(raw_url))
        for server in config.mcp_servers.values():
            if isinstance(server, HttpServerConfig):
                raw_url = str(server.url)
                detail = detail.replace(raw_url, endpoint(raw_url))
            else:
                for argument in sorted(server.args, key=len, reverse=True):
                    if argument:
                        detail = detail.replace(argument, "[ARG]")
    return f"{type(exc).__name__}: {redact(detail)}"


def _exception_chain(exc: Exception):
    """Yield a bounded, cycle-safe exception cause chain for diagnostics."""
    seen: set[int] = set()
    current: BaseException | None = exc
    while current is not None and id(current) not in seen and len(seen) < 8:
        seen.add(id(current))
        yield current
        current = current.__cause__ or current.__context__


def _tls_hint(exc: Exception) -> str | None:
    chain = list(_exception_chain(exc))
    messages = " ".join(str(item).lower() for item in chain)
    if any(isinstance(item, ssl.SSLCertVerificationError) for item in chain) or any(
        phrase in messages
        for phrase in ("certificate verify failed", "certificate_verify_failed")
    ):
        return (
            "certificate verification failed; OGhidra uses the operating-system "
            "trust store through truststore; check the endpoint hostname, system "
            "clock, proxy/private CA installation, and OS trust configuration"
        )
    if any(isinstance(item, ssl.SSLError) for item in chain) or any(
        phrase in messages for phrase in ("ssl error", "tls handshake")
    ):
        return (
            "TLS negotiation failed; check the endpoint hostname, protocol support, "
            "proxy, and operating-system trust configuration"
        )
    return None


def _model_error_hint(exc: Exception) -> str:
    """Map structured DSPy failures to concise operator actions."""
    if hint := _tls_hint(exc):
        return hint
    if isinstance(exc, (dspy.LMAuthError, dspy.LMNotConfiguredError)):
        return (
            "check that api_key_env names a populated, valid credential and that "
            "the account can access this model"
        )
    if isinstance(exc, dspy.LMUnsupportedModelError):
        return "verify the provider prefix and exact lm.model identifier"
    if isinstance(exc, dspy.LMBillingError):
        return "check provider billing and quota"
    if isinstance(exc, dspy.LMRateLimitError):
        return "the provider rate limit was reached; wait or check account limits"
    if isinstance(exc, dspy.LMTimeoutError):
        return "check endpoint availability and the configured model timeout"
    if isinstance(exc, (dspy.LMInvalidRequestError, dspy.LMUnsupportedFeatureError)):
        return "verify that the configured LM parameters are supported by the model"
    if isinstance(exc, dspy.LMTransportError):
        return "check lm.api_base, DNS, proxy, firewall, and endpoint availability"
    if isinstance(exc, dspy.LMServerError):
        return "check provider service health and retry later"
    if isinstance(exc, dspy.LMProviderError):
        return "check the provider response, service status, and account access"
    return "check the model identifier, endpoint, credentials, and provider logs"


def _model_failure_detail(exc: Exception, config: AppConfig) -> str:
    """Format model failures with safe cause details and an actionable hint."""
    causes = "; caused by ".join(
        _safe_error(item, config) for item in _exception_chain(exc)
    )
    target = (
        f"; endpoint={endpoint(config.lm.api_base)}"
        if config.lm.api_base is not None
        else ""
    )
    return f"{causes}{target}; hint: {_model_error_hint(exc)}"


def _configuration_error(exc: Exception) -> str:
    if isinstance(exc, yaml.MarkedYAMLError):
        location = ""
        if exc.problem_mark is not None:
            location = (
                f" at line {exc.problem_mark.line + 1}, "
                f"column {exc.problem_mark.column + 1}"
            )
        return f"{exc.problem or type(exc).__name__}{location}"
    if isinstance(exc, ValidationError):
        return redact(str(exc).replace("\n", " "))
    return _safe_error(exc)


def _configured_targets(config: AppConfig) -> str:
    targets = []
    for name, server in config.mcp_servers.items():
        target = (
            endpoint(server.url)
            if isinstance(server, HttpServerConfig)
            else server.command
        )
        targets.append(f"{name}={target}")
    return ", ".join(targets)


async def run_checks(
    config_path: Path, timeout: float = 10.0, check_model: bool = False
) -> list[Check]:
    """Validate local settings and the read-only MCP/Ghidra preflight contract."""
    checks: list[Check] = []
    try:
        config = load_config(config_path.resolve())
    except (OSError, TypeError, UnicodeError, ValidationError, yaml.YAMLError) as exc:
        return [Check("FAIL", "Configuration", _configuration_error(exc))]

    _register_config_secrets(config)
    checks.append(Check("PASS", "Configuration", str(config_path.resolve())))

    model_ready = True
    if config.lm.model == MODEL_PLACEHOLDER:
        model_ready = False
        checks.append(
            Check(
                "FAIL",
                "Model configuration",
                "replace the model placeholder with a provider and exact model ID",
            )
        )
    elif "/" not in config.lm.model:
        checks.append(
            Check(
                "WARN",
                "Model configuration",
                "model has no LiteLLM provider prefix",
            )
        )
    else:
        checks.append(Check("PASS", "Model configuration", config.lm.model))

    if config.lm.api_key_env is None:
        checks.append(Check("PASS", "Model credential", "not configured"))
    elif os.environ.get(config.lm.api_key_env):
        checks.append(
            Check(
                "PASS",
                "Model credential",
                f"{config.lm.api_key_env} is available",
            )
        )
    else:
        model_ready = False
        checks.append(
            Check(
                "FAIL",
                "Model credential",
                f"{config.lm.api_key_env} is missing or empty",
            )
        )

    if config.compiled_predictor is None:
        checks.append(Check("PASS", "Compiled predictor", "not configured"))
    elif Path(config.compiled_predictor).is_file():
        checks.append(Check("PASS", "Compiled predictor", config.compiled_predictor))
    else:
        checks.append(
            Check(
                "FAIL",
                "Compiled predictor",
                f"compiled predictor not found: {config.compiled_predictor}",
            )
        )

    if not check_model:
        checks.append(
            Check(
                "WARN",
                "Model connectivity",
                "not tested; pass --check-model to make a small inference request",
            )
        )
    elif not model_ready:
        checks.append(
            Check(
                "WARN",
                "Model connectivity",
                "not attempted because model configuration or credentials failed",
            )
        )
    else:
        try:
            async with asyncio.timeout(timeout):
                lm = make_lm(config.lm)
                await lm.acall(prompt="Reply with OK.", cache=False)
            checks.append(
                Check("PASS", "Model connectivity", "inference request completed")
            )
        except TimeoutError:
            checks.append(
                Check(
                    "FAIL",
                    "Model connectivity",
                    f"timed out after {timeout:g} seconds",
                )
            )
        except Exception as exc:  # noqa: BLE001 - every LM failure is a doctor result
            checks.append(
                Check("FAIL", "Model connectivity", _model_failure_detail(exc, config))
            )

    try:
        async with asyncio.timeout(timeout):
            async with connect(config.mcp_servers) as (sessions, catalogs, _):
                checks.append(
                    Check(
                        "PASS",
                        "MCP connectivity",
                        f"connected to {len(sessions)} configured server(s)",
                    )
                )
                ghidra_catalog = catalogs["ghidra"]
                missing = REQUIRED_GHIDRA_TOOLS - ghidra_catalog.keys()
                if missing:
                    checks.append(
                        Check(
                            "FAIL",
                            "Ghidra tools",
                            f"missing required tools: {', '.join(sorted(missing))}",
                        )
                    )
                else:
                    checks.append(
                        Check(
                            "PASS",
                            "Ghidra tools",
                            "required workflow tools are available",
                        )
                    )
                    context = GuiContext.model_validate(
                        result_data(
                            await sessions["ghidra"].call_tool("get_gui_context", {})
                        )
                    )
                    checks.append(
                        Check(
                            "PASS",
                            "Ghidra selection",
                            f"{context.active_program}: {context.active_function}",
                        )
                    )
    except TimeoutError:
        checks.append(
            Check(
                "FAIL",
                "MCP connectivity",
                (
                    f"timed out after {timeout:g} seconds while checking "
                    f"{_configured_targets(config)}"
                ),
            )
        )
    except Exception as exc:  # noqa: BLE001 - every MCP failure is a doctor result
        checks.append(
            Check(
                "FAIL",
                "MCP connectivity",
                (
                    f"{_safe_error(exc, config)} while checking "
                    f"{_configured_targets(config)}"
                ),
            )
        )

    return checks


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path("./config.yaml"))
    parser.add_argument("--timeout", type=_positive_timeout, default=10.0)
    parser.add_argument(
        "--check-model",
        action="store_true",
        help="make a small, uncached model inference request",
    )
    args = parser.parse_args(argv)

    # Suppress connection tracebacks while retaining redaction for unexpected logs.
    configure_logging("CRITICAL")
    checks = asyncio.run(run_checks(args.config, args.timeout, args.check_model))
    for check in checks:
        print(f"[{check.status}] {check.label}: {check.detail}")
    return 1 if any(check.status == "FAIL" for check in checks) else 0


if __name__ == "__main__":
    raise SystemExit(main())
