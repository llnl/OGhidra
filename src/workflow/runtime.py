"""Generic workflow transforms, context contributions and bounded execution.

Plugins transform copies of requests/plans. A failed optional transform cannot
mutate the accepted version. Operations run at most once; observer failures do
not cause retries. This runtime is an extension boundary, not a Python sandbox.
"""

import logging
from collections.abc import Callable, Iterator
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from contextvars import ContextVar, copy_context
from copy import deepcopy
from dataclasses import dataclass, replace
from threading import RLock
from types import MappingProxyType
from typing import Any

from .models import ContextBlock, RunContext, WorkContext, WorkflowEvent, WorkItem, WorkPlan, WorkResult

WORKFLOW_STAGES = frozenset({"workflow.plan", "request.prepare", "context.collect", "prompt.transform", "result.transform"})
SUPPORTED_STAGES = WORKFLOW_STAGES
_CURRENT_WORK: ContextVar[WorkContext | None] = ContextVar("oghidra_current_work", default=None)
_STATUSES = frozenset({"completed", "failed", "cancelled", "skipped"})
logger = logging.getLogger(__name__)


def get_current_work_context() -> WorkContext | None:
    """Return the active item, including inside nested host/model operations."""
    return _CURRENT_WORK.get()


@dataclass(frozen=True)
class _Hook:
    callback: Callable
    plugin_id: str
    priority: int
    sequence: int


@dataclass(frozen=True)
class _Registrations:
    operations: dict[str, Callable]
    hooks: dict[str, tuple[_Hook, ...]]
    sequence: int


class WorkflowRuntime:
    def __init__(self) -> None:
        self._operations: dict[str, Callable] = {"workflow.barrier": lambda item, context: None}
        self._hooks: dict[str, list[_Hook]] = {}
        self._lock = RLock()
        self._sequence = 0

    def snapshot_registrations(self) -> _Registrations:
        """Take a startup registration checkpoint for atomic plugin activation."""
        with self._lock:
            return _Registrations(
                dict(self._operations), {name: tuple(hooks) for name, hooks in self._hooks.items()}, self._sequence
            )

    def restore_registrations(self, snapshot: _Registrations) -> None:
        """Roll back a failed activation; callers must serialize plugin loading."""
        if not isinstance(snapshot, _Registrations):
            raise TypeError("Expected a registration snapshot from this runtime API")
        with self._lock:
            self._operations = dict(snapshot.operations)
            self._hooks = {name: list(hooks) for name, hooks in snapshot.hooks.items()}
            self._sequence = snapshot.sequence

    def register_operation(self, name: str, handler: Callable) -> None:
        if not isinstance(name, str) or not name.strip() or not callable(handler):
            raise ValueError("An operation needs a nonempty name and callable handler")
        with self._lock:
            if name in self._operations:
                raise ValueError(f"Operation already registered: {name}")
            self._operations[name] = handler

    def add_hook(self, stage: str, callback: Callable, plugin_id: str = "", priority: int = 0) -> None:
        """Register a transform or an observer for any named event.

        Higher priorities run first. Equal priorities retain registration order,
        allowing a loader to establish dependency order deterministically.
        """
        if not isinstance(stage, str) or not stage.strip() or not callable(callback):
            raise ValueError("A hook needs a nonempty stage and callable callback")
        if not isinstance(priority, int) or isinstance(priority, bool):
            raise TypeError("Hook priority must be an integer")
        with self._lock:
            self._sequence += 1
            hooks = self._hooks.setdefault(stage, [])
            hooks.append(_Hook(callback, plugin_id, priority, self._sequence))
            hooks.sort(key=lambda hook: (-hook.priority, hook.sequence))

    def subscribe(self, event: str, callback: Callable, plugin_id: str = "", priority: int = 0) -> None:
        if event in WORKFLOW_STAGES:
            raise ValueError(f"{event} is a transform stage, not an event")
        self.add_hook(event, callback, plugin_id, priority)

    def _registered_hooks(self, stage: str) -> tuple[_Hook, ...]:
        with self._lock:
            return tuple(self._hooks.get(stage, ()))

    def _hook_failed(self, stage: str, hook: _Hook, context: RunContext, error: Exception) -> None:
        diagnostic = {"stage": stage, "plugin_id": hook.plugin_id, "error": str(error)}
        with self._lock:
            context.state.setdefault("hook_errors", []).append(diagnostic)
        logger.warning("Extension %s failed at %s: %s", hook.plugin_id or "<anonymous>", stage, error)

    def emit(self, name: str, data: dict[str, Any] | None, context: RunContext) -> None:
        """Notify observers after committed state is visible; isolate each observer."""
        if name in WORKFLOW_STAGES:
            raise ValueError(f"Cannot emit transform stage {name}")
        payload = data or {}
        for hook in (*self._registered_hooks(name), *self._registered_hooks("*")):
            try:
                event = WorkflowEvent(name=name, item_id=payload.get("item_id"), data=deepcopy(payload))
                hook.callback(event, context)
            except Exception as error:  # noqa: BLE001 - Extension/operation failures must not trigger retries.
                self._hook_failed(name, hook, context, error)

    def _validate_item(self, item: WorkItem) -> None:
        if not isinstance(item, WorkItem):
            raise TypeError("Plan entries must be WorkItem objects")
        if not isinstance(item.id, str) or not item.id.strip():
            raise ValueError("Work item id must be a nonempty string")
        if not isinstance(item.operation, str) or item.operation not in self._operations:
            raise ValueError(f"Unknown operation: {item.operation}")
        if not isinstance(item.input, dict) or not isinstance(item.annotations, dict):
            raise TypeError(f"Input and annotations must be dictionaries: {item.id}")
        if not isinstance(item.priority, int) or isinstance(item.priority, bool):
            raise TypeError(f"Priority must be an integer: {item.id}")
        if not isinstance(item.depends_on, (tuple, list)) or any(not isinstance(dep, str) for dep in item.depends_on):
            raise ValueError(f"Dependencies must be a sequence of item ids: {item.id}")
        if len(item.depends_on) != len(set(item.depends_on)):
            raise ValueError(f"Duplicate dependency: {item.id}")

    def validate_plan(self, plan: WorkPlan) -> WorkPlan:
        if not isinstance(plan, WorkPlan) or not isinstance(plan.items, list):
            raise TypeError("Expected a WorkPlan with a list of items")
        if not isinstance(plan.workflow, str) or not plan.workflow.strip() or not isinstance(plan.annotations, dict):
            raise ValueError("A plan requires a workflow name and dictionary annotations")
        by_id: dict[str, WorkItem] = {}
        for item in plan.items:
            self._validate_item(item)
            if item.id in by_id:
                raise ValueError(f"Duplicate work item id: {item.id}")
            by_id[item.id] = item
        indegrees = {item.id: len(item.depends_on) for item in plan.items}
        dependents: dict[str, list[str]] = {item_id: [] for item_id in by_id}
        for item in plan.items:
            for dependency in item.depends_on:
                if dependency not in by_id:
                    raise ValueError(f"Unknown dependency {dependency} for {item.id}")
                dependents[dependency].append(item.id)
        ready = [item_id for item_id, degree in indegrees.items() if degree == 0]
        visited = 0
        while ready:
            item_id = ready.pop()
            visited += 1
            for dependent in dependents[item_id]:
                indegrees[dependent] -= 1
                if indegrees[dependent] == 0:
                    ready.append(dependent)
        if visited != len(by_id):
            raise ValueError("Work plan contains a dependency cycle")
        return plan

    def prepare_plan(self, plan: WorkPlan, context: RunContext) -> WorkPlan:
        self.validate_plan(plan)
        accepted = deepcopy(plan)
        for hook in self._registered_hooks("workflow.plan"):
            try:
                candidate = hook.callback(deepcopy(accepted), context)
                self.validate_plan(candidate)
                accepted = deepcopy(candidate)
            except Exception as error:  # noqa: BLE001 - Extension/operation failures must not trigger retries.
                self._hook_failed("workflow.plan", hook, context, error)
        return accepted

    def _transform_item(self, stage: str, item: WorkItem, context: WorkContext) -> WorkItem:
        accepted = item
        for hook in self._registered_hooks(stage):
            try:
                candidate_input = deepcopy(accepted)
                candidate = hook.callback(candidate_input, replace(context, item=candidate_input))
                self._validate_item(candidate)
                if candidate.id != item.id or tuple(candidate.depends_on) != tuple(item.depends_on):
                    raise ValueError("Request transforms cannot change item identity or dependencies")
                accepted = deepcopy(candidate)
            except Exception as error:  # noqa: BLE001 - Extension/operation failures must not trigger retries.
                self._hook_failed(stage, hook, context.run, error)
        return accepted

    def _collect_context(self, item: WorkItem, context: WorkContext) -> list[ContextBlock]:
        blocks: list[ContextBlock] = []
        for hook in self._registered_hooks("context.collect"):
            try:
                candidate = deepcopy(item)
                contribution = hook.callback(candidate, replace(context, item=candidate))
                addition = list(contribution) if contribution is not None else []
                for block in addition:
                    if not isinstance(block, ContextBlock) or not isinstance(block.text, str):
                        raise TypeError("Context contributors must return ContextBlock objects")
                    if block.kind not in {"evidence", "instruction", "instructions"}:
                        raise ValueError("Context kind must be evidence or instruction")
                    if not isinstance(block.source, str) or not isinstance(block.priority, int):
                        raise TypeError("Context source/priority has an invalid type")
                blocks.extend(deepcopy(addition))
            except Exception as error:  # noqa: BLE001 - Extension/operation failures must not trigger retries.
                self._hook_failed("context.collect", hook, context.run, error)
        return blocks

    @staticmethod
    def _context_text(blocks: list[ContextBlock], budget: int) -> str:
        """Use a conservative character cap (four chars per estimated token)."""
        remaining = max(0, int(budget)) * 4
        seen: set[str] = set()
        parts: list[str] = []
        for block in sorted(blocks, key=lambda block: -block.priority):
            text = block.text.strip()
            if not text or text in seen:
                continue
            seen.add(text)
            source = " ".join(block.source.splitlines()).strip()
            header = f"[{block.kind.title()}{': ' + source if source else ''}]\n"
            separator = "\n\n" if parts else ""
            available = remaining - len(separator) - len(header)
            if available <= 0:
                continue
            snippet = text if len(text) <= available else text[: max(0, available - 1)] + "…"
            part = separator + header + snippet
            parts.append(part)
            remaining -= len(part)
            if remaining <= 0:
                break
        return "".join(parts)

    def _enrich_context(self, item: WorkItem, context: WorkContext) -> WorkItem:
        blocks = self._collect_context(item, context)
        composer = context.services.get("compose_context")
        if composer is not None:
            try:
                candidate_input = deepcopy(item)
                candidate = composer(candidate_input, replace(context, item=candidate_input), blocks)
                self._validate_item(candidate)
                if candidate.id != item.id or tuple(candidate.depends_on) != tuple(item.depends_on):
                    raise ValueError("Context composition cannot change item identity or dependencies")
                return deepcopy(candidate)
            except Exception as error:  # noqa: BLE001 - Extension/operation failures must not trigger retries.
                self._hook_failed("context.compose", _Hook(composer, "host", 0, 0), context.run, error)
                return item
        if item.operation != "llm.generate" or not blocks:
            return item
        prompt = item.input.get("prompt")
        if not isinstance(prompt, str):
            return item
        text = self._context_text(blocks, context.run.context_budget)
        if not text:
            return item
        enriched = deepcopy(item)
        enriched.input["prompt"] = prompt + "\n\n" + text
        return enriched

    def _validate_result(self, result: WorkResult, item: WorkItem) -> None:
        if not isinstance(result, WorkResult) or result.item_id != item.id or result.operation != item.operation:
            raise ValueError("Result must preserve work item identity and operation")
        if result.status not in _STATUSES:
            raise ValueError(f"Invalid result status: {result.status}")

    def _transform_result(self, result: WorkResult, context: WorkContext) -> WorkResult:
        accepted = result
        for hook in self._registered_hooks("result.transform"):
            try:
                candidate = hook.callback(deepcopy(accepted), context)
                self._validate_result(candidate, context.item)
                if candidate.status != result.status:
                    raise ValueError("Result transforms cannot change execution status")
                accepted = deepcopy(candidate)
            except Exception as error:  # noqa: BLE001 - Extension/operation failures must not trigger retries.
                self._hook_failed("result.transform", hook, context.run, error)
        return accepted

    @staticmethod
    def _program_valid(context: RunContext) -> bool:
        validator = context.services.get("validate_program")
        if validator is None:
            return True
        try:
            return bool(validator(context))
        except Exception:
            logger.exception("Program validation failed")
            return False

    def _execute(self, item: WorkItem, context: WorkContext) -> WorkResult:
        token = _CURRENT_WORK.set(context)
        try:
            if context.run.cancelled() or not self._program_valid(context.run):
                return WorkResult(item.id, item.operation, "cancelled", error="Run cancelled or program changed")
            active = self._transform_item("request.prepare", item, context)
            context = replace(context, item=active)
            _CURRENT_WORK.set(context)
            active = self._enrich_context(active, context)
            context = replace(context, item=active)
            active = self._transform_item("prompt.transform", active, context)
            context = replace(context, item=active)
            _CURRENT_WORK.set(context)
            if context.run.cancelled() or not self._program_valid(context.run):
                return WorkResult(item.id, active.operation, "cancelled", error="Run cancelled or program changed")
            self.emit("operation.started", {"item_id": active.id, "item": active}, context.run)
            if context.run.cancelled() or not self._program_valid(context.run):
                return WorkResult(item.id, active.operation, "cancelled", error="Run cancelled or program changed")
            value = self._operations[active.operation](active, context)
            result = (
                value if isinstance(value, WorkResult) else WorkResult(active.id, active.operation, "completed", value=value)
            )
            self._validate_result(result, active)
            if not self._program_valid(context.run):
                return WorkResult(active.id, active.operation, "cancelled", error="Program changed during operation")
            return self._transform_result(result, context)
        except Exception as error:  # noqa: BLE001 - Extension/operation failures must not trigger retries.
            return WorkResult(item.id, context.item.operation, "failed", error=str(error))
        finally:
            _CURRENT_WORK.reset(token)

    def _record(self, item: WorkItem, result: WorkResult, results: dict[str, WorkResult], context: RunContext) -> None:
        results[item.id] = result
        with self._lock:
            context.state.setdefault("workflow_results", {})[item.id] = result
        recorder = context.services.get("record_result")
        if recorder is not None:
            try:
                recorder(item, result, context)
            except Exception as error:  # noqa: BLE001 - Record failure must not repeat an operation.
                self._hook_failed("result.record", _Hook(recorder, "host", 0, 0), context, error)
        payload = {"item_id": item.id, "item": item, "result": result}
        self.emit(f"operation.{result.status}", payload, context)
        alias = item.annotations.get("completion_event")
        if result.status == "completed" and isinstance(alias, str) and alias and alias != "operation.completed":
            if alias in WORKFLOW_STAGES:
                logger.warning("Ignoring completion event matching a transform stage: %s", alias)
            else:
                self.emit(alias, payload, context)

    def iter_results(self, plan: WorkPlan, context: RunContext, max_workers: int = 1) -> Iterator[tuple[WorkItem, WorkResult]]:
        """Yield committed results while keeping only max_workers items in flight.

        Dependencies require successful completion. Cancellation prevents new
        dispatch; operations already running are allowed to finish and recorded.
        Closing the generator stops submission and waits for in-flight work.
        """
        if not isinstance(max_workers, int) or isinstance(max_workers, bool) or max_workers < 1:
            raise ValueError("max_workers must be a positive integer")
        accepted = self.prepare_plan(plan, context)
        if not isinstance(context.context_budget, int) or context.context_budget < 0:
            raise ValueError("context_budget must be a nonnegative integer")
        pending = {item.id: item for item in accepted.items}
        positions = {item.id: index for index, item in enumerate(accepted.items)}
        results: dict[str, WorkResult] = {}
        inherited = get_current_work_context()
        inherited_results = (
            dict(inherited.results) if inherited is not None and inherited.run.program_key == context.program_key else {}
        )
        inherited_results.update(context.services.get("upstream_results", {}))
        self.emit("workflow.started", {"plan": accepted}, context)
        futures = {}
        try:
            executor_factory = context.services.get("executor_factory", ThreadPoolExecutor)
            with executor_factory(max_workers=max_workers) as executor:
                while pending or futures:
                    cancelled = context.cancelled() or not self._program_valid(context)
                    for item_id, item in list(pending.items()):
                        settled_barrier = (
                            item.operation == "workflow.barrier" and item.annotations.get("dependency_policy") == "settled"
                        )
                        failed_dependencies = (
                            []
                            if settled_barrier
                            else [dep for dep in item.depends_on if dep in results and results[dep].status != "completed"]
                        )
                        if cancelled or failed_dependencies:
                            status = "cancelled" if cancelled else "skipped"
                            error = (
                                "Run cancelled or program changed"
                                if cancelled
                                else f"Unsuccessful dependencies: {', '.join(failed_dependencies)}"
                            )
                            result = WorkResult(item_id, item.operation, status, error=error)
                            del pending[item_id]
                            self._record(item, result, results, context)
                            yield item, result
                    ready = sorted(
                        (
                            item
                            for item in pending.values()
                            if all(
                                dep in results
                                and (
                                    results[dep].status == "completed"
                                    or (
                                        item.operation == "workflow.barrier"
                                        and item.annotations.get("dependency_policy") == "settled"
                                    )
                                )
                                for dep in item.depends_on
                            )
                        ),
                        key=lambda item: (-item.priority, positions[item.id]),
                    )
                    for item in ready[: max(0, max_workers - len(futures))]:
                        if context.cancelled() or not self._program_valid(context):
                            break
                        snapshot = MappingProxyType(
                            {key: replace(value) for key, value in {**inherited_results, **results}.items()}
                        )
                        work_context = WorkContext(context, item, snapshot)
                        future = executor.submit(copy_context().run, self._execute, item, work_context)
                        futures[future] = item
                        del pending[item.id]
                    if futures:
                        done, _ = wait(futures, timeout=0.05, return_when=FIRST_COMPLETED)
                        for future in sorted(done, key=lambda future: positions[futures[future].id]):
                            item = futures.pop(future)
                            result = future.result()
                            self._record(item, result, results, context)
                            yield item, result
                    elif pending and not ready and not cancelled:
                        # A failed dependency may have been skipped later in the
                        # previous pass. Another pass propagates that status.
                        if not any(
                            any(dep in results and results[dep].status != "completed" for dep in item.depends_on)
                            for item in pending.values()
                        ):
                            raise RuntimeError("Validated work plan cannot make progress")
        finally:
            # Generator close or consumer failure must not lose completed writes.
            for future, item in list(futures.items()):
                if future.done() and not future.cancelled():
                    self._record(item, future.result(), results, context)
            payload = {"results": results, "pending_item_ids": list(pending)}
            if pending or any(result.status == "cancelled" for result in results.values()):
                status = "cancelled"
            elif any(result.status != "completed" for result in results.values()):
                status = "failed"
            else:
                status = "completed"
            self.emit(f"workflow.{status}", payload, context)
            self.emit("workflow.finished", payload, context)

    def run(
        self, plan: WorkPlan, context: RunContext, max_workers: int = 1, on_result: Callable | None = None
    ) -> dict[str, WorkResult]:
        results = {}
        iterator = self.iter_results(plan, context, max_workers=max_workers)
        try:
            for item, result in iterator:
                results[item.id] = result
                if on_result is not None:
                    on_result(item, result)
        finally:
            iterator.close()
        return results
