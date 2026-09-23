"""Plugin lifecycle for query and whole-program function analysis.

Third-party packages can expose an ``AnalysisPlugin`` instance, class, or
zero-argument factory through the ``oghidra.plugins`` entry-point group.  A
plugin may add ordered lifecycle phases and/or reorder functions before a bulk
analysis begins.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable, Iterable, Mapping, MutableMapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from importlib import metadata
from typing import Any


class PluginHook(str, Enum):
    QUERY_START = "query_start"
    BEFORE_PLANNING = "before_planning"
    AFTER_PLANNING = "after_planning"
    BEFORE_EXECUTION = "before_execution"
    AFTER_EXECUTION = "after_execution"
    BEFORE_ANALYSIS = "before_analysis"
    AFTER_ANALYSIS = "after_analysis"
    BEFORE_EVALUATION = "before_evaluation"
    AFTER_EVALUATION = "after_evaluation"
    BEFORE_FUNCTION_ANALYSIS = "before_function_analysis"
    AFTER_FUNCTION_ANALYSIS = "after_function_analysis"
    QUERY_END = "query_end"


@dataclass
class PluginContext:
    """Mutable data shared with plugin phases.

    ``data`` is intentionally open-ended so plugins can exchange artifacts
    without OGhidra taking a dependency on their concrete types.
    """

    bridge: Any
    query: str = ""
    hook: PluginHook | None = None
    cycle: int = 0
    plan: str = ""
    response: str = ""
    functions: list[Any] = field(default_factory=list)
    function_results: list[Mapping[str, Any]] = field(default_factory=list)
    data: MutableMapping[str, Any] = field(default_factory=dict)


PhaseHandler = Callable[[PluginContext], None]


@dataclass(frozen=True)
class PluginPhase:
    """One named, orderable phase attached to an OGhidra lifecycle hook."""

    name: str
    hook: PluginHook
    handler: PhaseHandler
    priority: int = 100
    before: tuple[str, ...] = ()
    after: tuple[str, ...] = ()


class AnalysisPlugin:
    """Base class for OGhidra analysis plugins."""

    name = "plugin"
    priority = 100

    def phases(self) -> Iterable[PluginPhase]:
        return ()

    def order_functions(self, functions: Sequence[Any], context: PluginContext) -> Sequence[Any]:
        return functions


class PluginManager:
    """Discovers plugins and executes their deterministic lifecycle."""

    ENTRY_POINT_GROUP = "oghidra.plugins"

    def __init__(self, plugins: Iterable[AnalysisPlugin] | None = None, logger: logging.Logger | None = None):
        self.logger = logger or logging.getLogger("ollama-ghidra-bridge.plugins")
        self._plugins: list[AnalysisPlugin] = []
        for plugin in plugins or ():
            self.register(plugin)

    @property
    def plugins(self) -> tuple[AnalysisPlugin, ...]:
        return tuple(self._plugins)

    def register(self, plugin: AnalysisPlugin) -> AnalysisPlugin:
        if not isinstance(plugin, AnalysisPlugin):
            raise TypeError("OGhidra plugins must inherit AnalysisPlugin")
        if any(existing.name == plugin.name for existing in self._plugins):
            raise ValueError(f"A plugin named '{plugin.name}' is already registered")
        self._plugins.append(plugin)
        self._plugins.sort(key=lambda item: (item.priority, item.name))
        return plugin

    def discover(self) -> list[AnalysisPlugin]:
        """Load plugins registered by installed Python distributions."""

        loaded: list[AnalysisPlugin] = []
        try:
            entry_points = metadata.entry_points()
            selected = entry_points.select(group=self.ENTRY_POINT_GROUP)
        except (AttributeError, TypeError):  # Python/importlib compatibility
            selected = metadata.entry_points().get(self.ENTRY_POINT_GROUP, ())

        for entry_point in selected:
            try:
                candidate = entry_point.load()
                plugin = candidate() if isinstance(candidate, type) or not isinstance(candidate, AnalysisPlugin) else candidate
                loaded.append(self.register(plugin))
                self.logger.info("Loaded OGhidra plugin '%s' from %s", plugin.name, entry_point.name)
            except Exception as exc:  # noqa: BLE001 - isolate untrusted entry points
                self.logger.warning("Could not load OGhidra plugin '%s': %s", entry_point.name, exc)
        return loaded

    def run(self, hook: PluginHook, context: PluginContext) -> PluginContext:
        context.hook = hook
        for phase in self._ordered_phases(hook):
            self.logger.debug("Running plugin phase '%s' at %s", phase.name, hook.value)
            phase.handler(context)
        return context

    def order_functions(self, functions: Sequence[Any], context: PluginContext) -> list[Any]:
        ordered = list(functions)
        context.functions = ordered
        for plugin in self._plugins:
            result = plugin.order_functions(tuple(ordered), context)
            if result is None:
                raise TypeError(f"Plugin '{plugin.name}' returned None from order_functions")
            ordered = list(result)
            context.functions = ordered
        return ordered

    def _ordered_phases(self, hook: PluginHook) -> list[PluginPhase]:
        phases: list[PluginPhase] = []
        for plugin in self._plugins:
            phases.extend(phase for phase in plugin.phases() if phase.hook == hook)

        names = [phase.name for phase in phases]
        if len(names) != len(set(names)):
            raise ValueError(f"Duplicate plugin phase name at {hook.value}")

        by_name = {phase.name: phase for phase in phases}
        edges: dict[str, set[str]] = {name: set() for name in names}
        indegree = {name: 0 for name in names}

        def add_edge(source: str, target: str) -> None:
            if source not in by_name or target not in by_name or target in edges[source]:
                return
            edges[source].add(target)
            indegree[target] += 1

        for phase in phases:
            for target in phase.before:
                add_edge(phase.name, target)
            for source in phase.after:
                add_edge(source, phase.name)

        ready = sorted(
            (by_name[name] for name, degree in indegree.items() if degree == 0),
            key=lambda phase: (phase.priority, phase.name),
        )
        ordered: list[PluginPhase] = []
        while ready:
            phase = ready.pop(0)
            ordered.append(phase)
            for target in sorted(edges[phase.name]):
                indegree[target] -= 1
                if indegree[target] == 0:
                    ready.append(by_name[target])
                    ready.sort(key=lambda item: (item.priority, item.name))

        if len(ordered) != len(phases):
            cyclic = sorted(name for name, degree in indegree.items() if degree)
            raise ValueError(f"Plugin phase dependency cycle at {hook.value}: {', '.join(cyclic)}")
        return ordered


class AddressOrderPlugin(AnalysisPlugin):
    """Example plugin that analyzes functions in address order."""

    name = "address_order"

    def __init__(self, reverse: bool = False, priority: int = 100):
        self.reverse = reverse
        self.priority = priority

    @staticmethod
    def _address(function: Any) -> int:
        if isinstance(function, Mapping):
            value = function.get("address", "")
        else:
            match = re.search(r"(?:0x)?([0-9a-fA-F]{6,})", str(function))
            value = match.group(1) if match else ""
        try:
            return int(str(value).removeprefix("0x"), 16)
        except (TypeError, ValueError):
            return 2**64 - 1

    def order_functions(self, functions: Sequence[Any], context: PluginContext) -> Sequence[Any]:
        return sorted(functions, key=self._address, reverse=self.reverse)


class FunctionRAGPlugin(AnalysisPlugin):
    """Indexes every completed function analysis through OGhidra's RAG builder."""

    name = "function_rag"

    def __init__(self, priority: int = 100):
        self.priority = priority

    def phases(self) -> Iterable[PluginPhase]:
        return (
            PluginPhase(
                name="build_function_rag",
                hook=PluginHook.AFTER_FUNCTION_ANALYSIS,
                handler=self._build,
                priority=self.priority,
            ),
        )

    def _build(self, context: PluginContext) -> None:
        indexed = 0
        failures: list[str] = []
        for item in context.function_results:
            if not item:
                continue
            function_data = item.get("function_data", item)
            if not isinstance(function_data, Mapping):
                continue
            address = str(function_data.get("address") or item.get("address") or "unknown")
            try:
                added = context.bridge._add_function_to_rag(address, dict(function_data))
                if added is None or int(added) > 0:
                    indexed += 1
                else:
                    failures.append(f"{address}: embedding service or RAG store unavailable")
            except Exception as exc:  # noqa: BLE001 - one failed document must not abort the batch
                failures.append(f"{address}: {exc}")
        context.data["function_rag"] = {"indexed": indexed, "failures": failures}
