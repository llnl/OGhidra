"""Adapters from OGhidra's existing workflows to the versioned extension runtime.

The built-in operations keep the existing analysis and rename implementations.
Plugins see typed work items instead of Tk widgets or a mutable Bridge object.
"""

from __future__ import annotations

import functools
import inspect
import json
import logging
import re
import threading
from collections.abc import Callable, Iterator
from concurrent.futures import Future
from contextlib import closing
from typing import Any
from uuid import uuid4

from src.workflow import RunContext, WorkflowRuntime, WorkItem, WorkPlan, WorkResult, get_current_work_context

logger = logging.getLogger(__name__)

BRIDGE_OPERATIONS = {
    "agent.query": "process_query",
    "agent.plan": "_generate_plan",
    "agent.execute_plan": "_execute_plan",
    "agent.review": "_generate_analysis",
    "agent.execute": "_execution_loop",
    "agent.analyze": "_analyze_execution_results",
    "agent.evaluate": "_evaluate_goal_achievement",
    "report.generate": "generate_software_report",
    "tool.execute": "execute_command",
}


def canonical_address(value: Any) -> str:
    """Canonicalize hex addresses without confusing names with addresses."""
    text = str("" if value is None else value).strip()
    if re.fullmatch(r"(?:0x)?[0-9a-f]+", text, re.IGNORECASE):
        return format(int(text, 16), "x")
    return text


def function_identity(function: str) -> tuple[str, str]:
    name, separator, address = function.rpartition(" at ")
    if separator:
        return name.strip(), canonical_address(address)
    return function.strip(), ""


def workflow_operation(operation: str, workflow: str = "agent.default"):
    """Expose an existing Bridge method as a normal, transformable operation."""

    def decorate(function):
        signature = inspect.signature(function)

        @functools.wraps(function)
        def wrapped(bridge, *args, **kwargs):
            bound = signature.bind(bridge, *args, **kwargs)
            inputs = dict(bound.arguments)
            inputs.pop("self", None)
            return get_workflow_host(bridge).invoke(
                operation, inputs, lambda values: function(bridge, **values), workflow=workflow
            )

        return wrapped

    return decorate


def get_workflow_host(bridge) -> WorkflowHost:
    """Also supports headless adapters and tests that construct Bridge via __new__."""
    host = bridge.__dict__.get("workflow_host")
    if host is None:
        host = WorkflowHost(bridge)
        bridge.workflow_host = host
    return host


class WorkflowModelClient:
    """Model gateway: context plugins run after the final prompt is assembled.

    Both existing generation APIs pass through here once. Embeddings, health
    checks, configuration, and other client attributes retain their old behavior.
    """

    def __init__(self, client, host: WorkflowHost):
        object.__setattr__(self, "_client", client)
        object.__setattr__(self, "_host", host)

    def __getattr__(self, name):
        return getattr(self._client, name)

    def __setattr__(self, name, value):
        if name in {"_client", "_host"}:
            object.__setattr__(self, name, value)
        else:
            setattr(self._client, name, value)

    def _generate(self, method: str, args: tuple, kwargs: dict):
        # Binding against the public signatures keeps positional calls supported
        # and avoids passing plugin metadata into provider clients.
        names = (
            ("prompt", "phase", "system_prompt")
            if method == "generate_with_phase"
            else ("prompt", "model", "system_prompt", "temperature", "max_tokens", "phase")
        )
        if len(args) > len(names):
            raise TypeError("Too many positional model arguments")
        inputs = dict(zip(names, args))
        if inputs.keys() & kwargs.keys():
            raise TypeError("Multiple values for a model argument")
        inputs.update(kwargs)
        if "prompt" not in inputs:
            raise TypeError("A model prompt is required")

        def execute(values):
            if method == "generate_with_phase" and values.keys() & {"model", "temperature", "max_tokens"}:
                # Plugins use one generation contract even when a legacy caller
                # chose the narrower phase API. Keep its configured model choice.
                values = dict(values)
                if "model" not in values:
                    phase = values.get("phase")
                    model_map = getattr(self._client, "model_map", {})
                    model = model_map.get(phase) if phase and isinstance(model_map, dict) else None
                    if (
                        getattr(self._client, "provider", None) == "google"
                        and model
                        and not model.lower().startswith(("gemini", "learnlm"))
                    ):
                        model = None
                    values["model"] = model
                return self._client.generate(**values)
            return getattr(self._client, method)(**values)

        return self._host.invoke("llm.generate", inputs, execute, workflow="model.request")

    def generate(self, *args, **kwargs):
        return self._generate("generate", args, kwargs)

    def generate_with_phase(self, *args, **kwargs):
        return self._generate("generate_with_phase", args, kwargs)


class InlineExecutor:
    """Preserve the caller thread for the default sequential workflow."""

    def __init__(self, max_workers=1):
        if max_workers != 1:
            raise ValueError("InlineExecutor requires one worker")

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def submit(self, function, *args, **kwargs):
        future = Future()
        try:
            future.set_result(function(*args, **kwargs))
        except Exception as error:  # noqa: BLE001 - Match executor future exception semantics.
            future.set_exception(error)
        return future


class WorkflowHost:
    """Built-in operation registration, program scope, and function work plans."""

    def __init__(self, bridge):
        from src.plugins import PluginManager

        self.bridge = bridge
        self.runtime = WorkflowRuntime()
        self._lock = threading.RLock()
        self._registered: set[str] = set()
        self._session_key = str(uuid4())
        self._last_program_key = ""
        self.last_results = {}
        self._register("llm.generate", self._invoke)
        self._register("function.analyze", self._analyze_function)
        for operation in BRIDGE_OPERATIONS:
            self._register(operation, self._invoke)
        self.plugins = PluginManager(self.runtime)
        config = getattr(bridge, "config", None)
        paths = getattr(config, "plugin_paths", []) if config is not None else []
        settings = getattr(config, "plugin_settings", {}) if config is not None else {}
        self.plugins.load(paths if isinstance(paths, list) else [], settings=settings if isinstance(settings, dict) else {})
        self._plugins_configured = bool(paths)

    def _register(self, name: str, handler: Callable) -> None:
        with self._lock:
            if name not in self._registered:
                self.runtime.register_operation(name, handler)
                self._registered.add(name)

    def _invoke(self, item, context):
        # A plugin may insert a different built-in operation into a plan. Resolve
        # that operation by name instead of reusing the original request callback.
        if (
            context.services.get("invocation_operation") == item.operation
            and context.services.get("invocation_item_id") == item.id
        ):
            return context.services["invoke"](item.input)
        if item.operation == "llm.generate":
            return self._model_client.generate(**item.input)
        method_name = BRIDGE_OPERATIONS.get(item.operation)
        if method_name:
            method = getattr(self.bridge, method_name)
            original = getattr(method, "__wrapped__", None)
            return original(self.bridge, **item.input) if original else method(**item.input)
        raise ValueError(f"No host invocation is available for {item.operation}")

    def wrap_model(self, client):
        if isinstance(client, WorkflowModelClient):
            if client._host is self:
                self._model_client = client._client
                return client
            client = client._client
        self._model_client = client
        return WorkflowModelClient(client, self)

    def program_key(self) -> str:
        client = getattr(self.bridge, "ghidra_client", None)
        info = {}
        # Do not introduce new Ghidra requests in the plugin-free baseline.
        if self._plugins_configured and client is not None:
            try:
                candidate = client.get_current_program_info()
                if isinstance(candidate, dict):
                    info = {
                        key: candidate[key]
                        for key in ("program_id", "program_path", "name", "project", "port", "url", "backend")
                        if candidate.get(key)
                    }
            except Exception:
                logger.debug("Program identity unavailable; using session scope", exc_info=True)
        if not info:
            info = {
                "session": self._session_key,
                "client": id(client),
                "instance": str(getattr(client, "current_instance_port", "")),
                "program": id(getattr(client, "_program", None)),
            }
        return json.dumps(info, sort_keys=True)

    def _context(self, workflow: str, *, cancelled=None, services=None, state=None) -> RunContext:
        parent = get_current_work_context()
        if parent is not None:
            key = parent.run.program_key
            shared_state = parent.run.state
        else:
            key = self.program_key()
            shared_state = {"analysis_records": {}}
        if state:
            shared_state.update(state)
        config = getattr(self.bridge, "config", None)
        budget = getattr(config, "plugin_context_budget", 2000)
        if not isinstance(budget, int):
            budget = 2000
        host_services = {
            "validate_program": lambda context: self.program_key() == context.program_key,
            "log": logger,
        }
        if parent is not None:
            host_services["upstream_results"] = {
                **parent.results,
                **parent.run.state.get("workflow_results", {}),
            }
        if services:
            host_services.update(services)
        context = RunContext(
            workflow=workflow,
            program_key=key,
            services=host_services,
            state=shared_state,
            context_budget=budget,
            cancelled=cancelled or (parent.run.cancelled if parent else lambda: False),
        )
        with self._lock:
            if key != self._last_program_key:
                previous = self._last_program_key
                self._last_program_key = key
                self.runtime.emit("program.changed", {"previous": previous, "current": key}, context)
        return context

    def invoke(self, operation: str, inputs: dict, execute: Callable, *, workflow="agent.default"):
        """Execute one built-in operation without replaying failed side effects."""
        self._register(operation, self._invoke)
        parent = get_current_work_context()
        annotations = dict(parent.item.annotations) if parent else {}
        # Completion aliases belong to the owning analysis, not every nested call.
        annotations.pop("completion_event", None)
        if parent:
            annotations["parent_item_id"] = parent.item.id
        item = WorkItem(id=str(uuid4()), operation=operation, input=inputs, annotations=annotations)
        failures = []

        def execute_once(values):
            try:
                return execute(values)
            except Exception as error:
                failures.append(error)
                raise

        context = self._context(
            workflow,
            services={
                "invoke": execute_once,
                "invocation_operation": operation,
                "invocation_item_id": item.id,
                "executor_factory": InlineExecutor,
            },
        )
        results = self.runtime.run(WorkPlan(items=[item], workflow=workflow), context)
        result = results.get(item.id)
        with self._lock:
            self.last_results = results
        if result is None:
            raise RuntimeError(f"Workflow {workflow} removed its required result item {item.id}")
        if result.status != "completed":
            if result.status == "failed" and failures:
                raise failures[0]
            raise RuntimeError(result.error or f"Operation {operation} {result.status}")
        return result.value

    @staticmethod
    def _analyze_function(item, context):
        value = context.services["analyze_function"](item, context)
        if isinstance(value, dict):
            if value.get("result_type") == "skipped":
                return WorkResult(item.id, item.operation, "skipped", value=value)
            if value.get("success") is False or value.get("result_type") == "failed":
                return WorkResult(
                    item.id, item.operation, "failed", value=value, error=value.get("error_msg", "Analysis failed")
                )
        return value

    def _record_analysis(self, item, result, run):
        """Record the accepted result before observers or dependent work run."""
        value = result.value
        if item.operation != "function.analyze" or result.status != "completed" or not isinstance(value, dict):
            return
        if not value.get("success", value.get("result_type") in {"renamed", "enumerated"}):
            return
        record = dict(value.get("function_data") or value)
        record.update(
            address=item.input.get("address", record.get("address", "")),
            status="completed",
            strategic_category=item.annotations.get("strategic_category", ""),
        )
        record.setdefault("summary", value.get("summary", ""))
        record.setdefault("new_name", value.get("suggested_name") or item.input.get("name", ""))
        if self.program_key() == run.program_key:
            with self._lock:
                run.state["analysis_records"][record["address"] or item.id] = record

    def function_plan(self, functions: list[str], enumeration_mode: str) -> WorkPlan:
        items = []
        seen = set()
        for function in functions:
            name, address = function_identity(function)
            identity = address or function
            if identity in seen:
                continue
            seen.add(identity)
            items.append(
                WorkItem(
                    id=f"function:address:{address}" if address else f"function:index:{len(items)}",
                    operation="function.analyze",
                    input={"function": function, "name": name, "address": address, "enumeration_mode": enumeration_mode},
                    annotations={"completion_event": "analysis.completed", "function_address": address},
                )
            )
        for index, item in enumerate(items, 1):
            item.input.update(index=index, total=len(items))
        return WorkPlan(items=items, workflow="functions.analyze")

    def iter_functions(
        self,
        functions: list[str],
        enumeration_mode: str,
        analyze: Callable,
        *,
        max_workers: int = 1,
        cancelled: Callable[[], bool] | None = None,
        executor_factory=None,
    ) -> Iterator[tuple[WorkItem, Any]]:
        plan = self.function_plan(functions, enumeration_mode)
        snapshot = None

        def function_snapshot():
            nonlocal snapshot
            if snapshot is None:
                snapshot = self.collect_function_snapshot(plan.items, cancelled)
            return snapshot

        services = {"analyze_function": analyze, "function_snapshot": function_snapshot, "record_result": self._record_analysis}
        if executor_factory or max_workers == 1:
            services["executor_factory"] = executor_factory or InlineExecutor
        context = self._context("functions.analyze", cancelled=cancelled, services=services)
        with closing(self.runtime.iter_results(plan, context, max_workers=max_workers)) as results:
            for item, result in results:
                if item.operation == "function.analyze":
                    yield item, result

    def collect_function_snapshot(self, items: list[WorkItem], cancelled=None) -> dict:
        """Collect incoming CALL references; derive both directions from them.

        xrefs_from(entry) is instruction-specific, so it cannot describe all
        calls in a function. Incoming references include the caller name on both
        current backends. Resolve only unambiguous names; preserve unknown graph
        coverage on errors, truncation, or unresolved call sites.
        """
        client = getattr(self.bridge, "ghidra_client", None)
        snapshot = {
            item.input["address"]: {
                "address": item.input["address"],
                "name": item.input["name"],
                "callers": set(),
                "callees": set(),
                "relationships_known": False,
            }
            for item in items
            if item.input.get("address")
        }
        # The work list may exclude already analyzed functions. Include them in
        # the graph so omitted callees cannot turn a hub into an isolated node.
        complete = True
        if client is None:
            return snapshot
        previous = None
        for page in range(100):
            if cancelled and cancelled():
                complete = False
                break
            try:
                lines = client.list_functions(offset=page * 100, limit=100)
            except Exception:  # noqa: BLE001 - Backend failures make graph coverage unknown.
                complete = False
                break
            if not isinstance(lines, list) or (lines and repr(lines) == previous):
                complete = False
                break
            previous = repr(lines)
            count, has_next = 0, False
            for line in lines:
                if not isinstance(line, str) or line.lower().startswith("error"):
                    complete = False
                    continue
                if line.startswith("["):
                    has_next |= "next:" in line.lower()
                    continue
                name, address = function_identity(line)
                if not address:
                    complete = False
                    continue
                count += 1
                snapshot.setdefault(
                    address,
                    {
                        "address": address,
                        "name": name,
                        "callers": set(),
                        "callees": set(),
                        "relationships_known": False,
                    },
                )
            if not has_next and count < 100:
                break
        else:
            complete = False
        names = {}
        for address, record in snapshot.items():
            names.setdefault(record["name"], []).append(address)
        for target, record in snapshot.items():
            if cancelled and cancelled():
                complete = False
                break
            offset, previous = 0, None
            for _page in range(100):
                try:
                    lines = client.get_xrefs_to(address=target, offset=offset, limit=100)
                except Exception:  # noqa: BLE001 - Backend failures make graph coverage unknown.
                    complete = False
                    break
                if not isinstance(lines, list):
                    complete = False
                    break
                fingerprint = repr(lines)
                if fingerprint == previous and lines:
                    complete = False
                    break
                previous = fingerprint
                references = []
                has_next = False
                for line in lines:
                    if isinstance(line, str):
                        if line.lower().startswith("error"):
                            complete = False
                            continue
                        if line.startswith("["):
                            has_next |= "next:" in line.lower()
                            continue
                        # Format: From <instruction> in <function name> [CALL]
                        match = re.match(r"From\s+(\S+)\s+in\s+(.+?)\s+\[([^]]+)\]", line, re.IGNORECASE)
                        if match:
                            references.append((match[2], match[3], None))
                        else:
                            complete = False
                    elif isinstance(line, dict):
                        if not (line.get("type") or line.get("reference_type")):
                            complete = False
                        references.append(
                            (
                                line.get("from_function") or line.get("function") or line.get("caller"),
                                line.get("type") or line.get("reference_type") or "",
                                line.get("from_function_address") or line.get("caller_address"),
                            )
                        )
                    else:
                        complete = False
                for name, reference_type, caller_start in references:
                    if "CALL" not in str(reference_type).upper():
                        continue
                    candidates = [canonical_address(caller_start)] if caller_start else names.get(str(name), [])
                    if len(candidates) != 1 or candidates[0] not in snapshot:
                        complete = False
                        continue
                    caller = candidates[0]
                    record["callers"].add(caller)
                    snapshot[caller]["callees"].add(target)
                if not has_next and len(references) < 100:
                    break
                offset += 100
            else:
                complete = False
        for record in snapshot.values():
            record["callers"] = tuple(sorted(record["callers"]))
            record["callees"] = tuple(sorted(record["callees"]))
            record["relationships_known"] = complete
        return snapshot
