"""Standard logging + JSON files, scoped context, and native DSPy callbacks."""

from __future__ import annotations

import asyncio
import contextvars
import faulthandler
import logging
import os
import re
import sys
import threading
import time
import traceback
from contextlib import contextmanager
from logging.handlers import RotatingFileHandler
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
from uuid import uuid4

from dspy.utils.callback import BaseCallback
from pythonjsonlogger.json import JsonFormatter

logger = logging.getLogger("oghidra_workflows")
_context: contextvars.ContextVar[dict] = contextvars.ContextVar(
    "log_context", default={}
)
_secrets: set[str] = set()


def register_secret(value: str | None) -> None:
    if value:
        _secrets.add(value)


def redact(text: str) -> str:
    for secret in sorted(_secrets, key=len, reverse=True):
        text = text.replace(secret, "[REDACTED]")
    text = re.sub(
        r"(?i)(authorization[\s\"':=]+(?:bearer|basic)\s+)[^\s\"',}]+",
        r"\1[REDACTED]",
        text,
    )
    text = re.sub(
        r"(?i)((?:api[_-]?key|access_token|password|secret)[\s\"':=]+)[^\s\"',}&]+",
        r"\1[REDACTED]",
        text,
    )
    text = re.sub(r"(https?://)[^/\s@]+@", r"\1[REDACTED]@", text)
    return text


def endpoint(url: object) -> str:
    """URLs are useful for diagnosis; userinfo, query parameters, and fragments aren't."""
    parsed = urlsplit(str(url))
    return urlunsplit(
        (parsed.scheme, parsed.netloc.rsplit("@", 1)[-1], parsed.path, "", "")
    )


class ContextFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        for key, value in _context.get().items():
            if not hasattr(record, key):
                setattr(record, key, value)
        record.request_id = getattr(record, "request_id", "-")
        record.stage = getattr(record, "stage", "-")
        return True


def exception_text(exc_info):
    return "".join(
        traceback.TracebackException(
            *exc_info,
            capture_locals=False,
            max_group_width=10000,
            max_group_depth=10000,
        ).format()
    )


class JsonLogFormatter(JsonFormatter):
    def formatException(self, exc_info):
        return exception_text(exc_info)

    def process_log_record(self, log_data):
        def clean(value):
            if isinstance(value, str):
                return redact(value)
            if isinstance(value, dict):
                return {k: clean(v) for k, v in value.items()}
            if isinstance(value, (list, tuple)):
                return [clean(v) for v in value]
            return value

        return clean(log_data)


class ConsoleFormatter(logging.Formatter):
    converter = time.gmtime

    def formatException(self, exc_info):
        return exception_text(exc_info)

    def format(self, record):
        return redact(super().format(record))


def configure_logging(
    level="INFO", log_file: Path | None = None, max_bytes=5_000_000, backup_count=3
) -> None:
    for key, value in os.environ.items():
        if re.search(r"(?i)(api.?key|token|secret|password|credential)", key):
            register_secret(value)
    console = logging.StreamHandler(sys.stderr)
    console.setFormatter(
        ConsoleFormatter(
            "%(asctime)sZ %(levelname)s %(name)s [%(request_id)s %(stage)s] %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        )
    )
    handlers: list[logging.Handler] = [console]
    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(
            log_file, maxBytes=max_bytes, backupCount=backup_count, encoding="utf-8"
        )
        file_handler.setFormatter(
            JsonLogFormatter(
                "%(levelname)s %(name)s %(message)s %(process)d %(threadName)s %(request_id)s %(stage)s",
                timestamp=True,
            )
        )
        handlers.append(file_handler)
    for handler in handlers:
        handler.setLevel(level)
        handler.addFilter(ContextFilter())
    logging.basicConfig(level=level, handlers=handlers, force=True)
    logger.setLevel(level)
    # Never turn provider/HTTP payload logging on just to debug the workflow.
    for name in ("dspy", "litellm", "LiteLLM", "openai", "httpx", "httpcore", "mcp"):
        logging.getLogger(name).setLevel(
            max(logging.WARNING, logging.getLevelName(level))
        )
    logging.captureWarnings(True)


def resolve_log_file(config_path: Path, template: str | None) -> Path | None:
    if template is None:
        return None
    path = Path(template.replace("{pid}", str(os.getpid())))
    return (config_path.parent / path).resolve()


@contextmanager
def log_context(**fields):
    token = _context.set({**_context.get(), **fields})
    try:
        yield
    finally:
        _context.reset(token)


@contextmanager
def operation(stage: str, **fields):
    """Timed diagnostic scope; exceptions and cancellation propagate unchanged."""
    with log_context(stage=stage, **fields):
        started = time.perf_counter()
        logger.debug("stage.started")
        try:
            yield
        except asyncio.CancelledError:
            logger.warning(
                "stage.cancelled",
                extra={"duration_ms": round((time.perf_counter() - started) * 1000, 2)},
            )
            raise
        except Exception:
            logger.exception(
                "stage.failed",
                extra={"duration_ms": round((time.perf_counter() - started) * 1000, 2)},
            )
            raise
        else:
            logger.debug(
                "stage.completed",
                extra={"duration_ms": round((time.perf_counter() - started) * 1000, 2)},
            )


@contextmanager
def request_context():
    with log_context(request_id=uuid4().hex):
        yield _context.get()["request_id"]


def install_exception_hooks() -> None:
    try:
        faulthandler.enable(file=sys.stderr, all_threads=True)
    except (OSError, ValueError, RuntimeError):
        pass

    def uncaught(exc_type, exc, tb):
        if issubclass(exc_type, KeyboardInterrupt):
            return sys.__excepthook__(exc_type, exc, tb)
        logger.critical("process.uncaught", exc_info=(exc_type, exc, tb))

    sys.excepthook = uncaught
    threading.excepthook = lambda args: logger.critical(
        "thread.uncaught",
        extra={"failed_thread": args.thread.name if args.thread else None},
        exc_info=(args.exc_type, args.exc_value, args.exc_traceback),
    )


def install_async_exception_handler() -> None:
    def handler(loop, context):
        exc = context.get("exception")
        logger.error(
            "async.unhandled",
            extra={"detail": context.get("message")},
            exc_info=(type(exc), exc, exc.__traceback__) if exc else None,
        )

    asyncio.get_running_loop().set_exception_handler(handler)


class DSPyLoggingCallback(BaseCallback):
    """Observe DSPy without logging prompts, completions, or tool payloads."""

    def __init__(self):
        self._calls = {}
        self._lock = threading.Lock()

    def _start(self, kind, call_id, name):
        with self._lock:
            self._calls[call_id] = (time.perf_counter(), name)
        logger.debug(
            f"dspy.{kind}.started", extra={"call_id": call_id, "component": name}
        )

    def _end(self, kind, call_id, exception):
        with self._lock:
            started, name = self._calls.pop(call_id, (time.perf_counter(), "unknown"))
        fields = {
            "call_id": call_id,
            "component": name,
            "duration_ms": round((time.perf_counter() - started) * 1000, 2),
        }
        if exception is not None:
            logger.error(
                f"dspy.{kind}.failed",
                extra=fields,
                exc_info=(type(exception), exception, exception.__traceback__),
            )
        else:
            logger.debug(f"dspy.{kind}.completed", extra=fields)

    def on_lm_start(self, call_id, instance, inputs):
        self._start("lm", call_id, getattr(instance, "model", type(instance).__name__))

    def on_lm_end(self, call_id, outputs, exception=None):
        self._end("lm", call_id, exception)

    def on_tool_start(self, call_id, instance, inputs):
        self._start("tool", call_id, getattr(instance, "name", type(instance).__name__))

    def on_tool_end(self, call_id, outputs, exception=None):
        self._end("tool", call_id, exception)

    def on_adapter_parse_end(self, call_id, outputs, exception=None):
        if exception is not None:
            logger.error(
                "dspy.parse.failed",
                extra={"call_id": call_id},
                exc_info=(type(exception), exception, exception.__traceback__),
            )
