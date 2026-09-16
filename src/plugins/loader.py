"""Manifest-driven, opt-in workflow extensions.

Only supplied manifest paths are loaded. Python plugins are trusted executable
code, not a sandbox. Each plugin gets a private package namespace; helper imports
must be package-relative. Registration is transactional, arbitrary Python side
effects are not. Host API constraints support comma-separated numeric comparison
clauses (==, !=, <, <=, >, >=), for example ``>=1.0,<2``.
"""

import hashlib
import importlib
import importlib.machinery
import inspect
import logging
import re
import sys
import tomllib
from collections.abc import Callable, Iterable
from copy import deepcopy
from dataclasses import asdict, dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Any

from .resources import PluginResources, contained_path

API_VERSION = "1.0"
HOOK_STAGES = frozenset({
    "workflow.plan", "request.prepare", "context.collect", "prompt.transform", "result.transform", "observer",
})
LIFECYCLE_EVENTS = frozenset({
    "workflow.started", "workflow.completed", "workflow.failed", "workflow.cancelled", "workflow.finished",
    "operation.started", "operation.completed", "operation.failed", "operation.cancelled", "operation.skipped",
    "analysis.completed", "program.changed",
})
_IDENTIFIER = re.compile(r"[a-zA-Z][a-zA-Z0-9_.-]*\Z")
_EVENT = re.compile(r"[a-zA-Z][a-zA-Z0-9_.-]*\Z")
_logger = logging.getLogger(__name__)
MAX_MANIFEST_BYTES = 64 * 1024


class PluginError(ValueError):
    """An extension cannot be safely registered with this host."""


def _version(value: str) -> tuple[int, int, int]:
    if not re.fullmatch(r"\d+(?:\.\d+){0,2}", value):
        raise PluginError(f"Unsupported numeric version: {value!r}")
    parts = [int(part) for part in value.split(".")]
    return tuple(parts + [0] * (3 - len(parts)))


def compatible_api(constraint: str) -> bool:
    if not isinstance(constraint, str) or not constraint.strip():
        raise PluginError("host_api must specify numeric version comparisons, such as >=1,<2")
    current = _version(API_VERSION)
    compatible = True
    for clause in constraint.split(","):
        match = re.fullmatch(r"\s*(==|!=|>=|<=|>|<)\s*(\d+(?:\.\d+){0,2})\s*", clause)
        if not match:
            raise PluginError(f"Unsupported host_api clause: {clause!r}")
        operator, requested = match.groups()
        target = _version(requested)
        compatible &= {
            "==": current == target, "!=": current != target, ">=": current >= target,
            "<=": current <= target, ">": current > target, "<": current < target,
        }[operator]
    return compatible


def _string_list(data: dict, key: str) -> tuple[str, ...]:
    value = data.get(key, [])
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise PluginError(f"{key} must be a list of nonempty strings")
    if len(value) != len(set(value)):
        raise PluginError(f"{key} contains duplicate entries")
    return tuple(value)


@dataclass(frozen=True)
class _Manifest:
    id: str
    version: str
    path: Path
    entrypoint: str | None
    contributions: tuple[str, ...]
    resources: tuple[str, ...]
    dependencies: tuple[str, ...]
    before: tuple[str, ...]
    after: tuple[str, ...]


@dataclass
class PluginStatus:
    id: str
    path: str
    version: str = ""
    status: str = "pending"
    error: str = ""
    contributions: list[str] = field(default_factory=list)
    resources: list[dict] = field(default_factory=list)
    active_skills: list[str] = field(default_factory=list)


def _manifest(path: Path) -> _Manifest:
    if path.name != "plugin.toml":
        raise PluginError("Plugin paths must point to an explicit plugin.toml file")
    with path.open("rb") as handle:
        raw = handle.read(MAX_MANIFEST_BYTES + 1)
    if len(raw) > MAX_MANIFEST_BYTES:
        raise PluginError("Manifest exceeds 64 KiB")
    data = tomllib.loads(raw.decode("utf-8-sig"))
    plugin_id = data.get("id")
    if not isinstance(plugin_id, str) or not _IDENTIFIER.fullmatch(plugin_id):
        raise PluginError("id must begin with a letter and contain only letters, digits, _, . or -")
    version = data.get("version")
    if not isinstance(version, str) or not version.strip():
        raise PluginError("version must be a nonempty string")
    if not compatible_api(data.get("host_api")):
        raise PluginError(f"Plugin {plugin_id} requires host API {data['host_api']}; host provides {API_VERSION}")
    entrypoint = data.get("entrypoint")
    if entrypoint is not None and (not isinstance(entrypoint, str) or not re.fullmatch(
        r"[a-zA-Z_]\w*(?:\.[a-zA-Z_]\w*)*:[a-zA-Z_]\w*", entrypoint,
    )):
        raise PluginError("entrypoint must be a package-relative module:callable")
    contributions = _string_list(data, "contributions")
    for contribution in contributions:
        if contribution in HOOK_STAGES or contribution in LIFECYCLE_EVENTS or contribution == "operations":
            continue
        if (contribution.startswith("event:") and _EVENT.fullmatch(contribution[6:])
                and contribution[6:] not in HOOK_STAGES):
            continue
        raise PluginError(f"Unknown contribution: {contribution}")
    dependencies, before, after = (_string_list(data, key) for key in ("dependencies", "before", "after"))
    for target in (*dependencies, *before, *after):
        if not _IDENTIFIER.fullmatch(target) or target == plugin_id:
            raise PluginError(f"Invalid ordering/dependency id: {target}")
    resources = _string_list(data, "resources")
    if resources and "context.collect" not in contributions:
        raise PluginError("Resources require the context.collect contribution")
    return _Manifest(plugin_id, version, path, entrypoint, contributions, resources, dependencies, before, after)


class PluginAPI:
    """The activation surface; registrations are staged until activation succeeds."""

    api_version = API_VERSION

    def __init__(self, manifest: _Manifest, config: dict[str, Any], resources: PluginResources):
        self.plugin_id = manifest.id
        self.config = deepcopy(config)
        self.resources = resources
        self._allowed = set(manifest.contributions)
        self._pending: list[tuple] = []
        self._open = True

    def _check(self, contribution: str, callback: Callable) -> None:
        if not self._open:
            raise PluginError("Plugin registration is only allowed during activate(api)")
        if contribution not in self._allowed:
            raise PluginError(f"Plugin {self.plugin_id} did not declare {contribution}")
        if not callable(callback):
            raise PluginError("Plugin callbacks must be callable")
        if inspect.iscoroutinefunction(callback):
            raise PluginError("Plugin callbacks must be synchronous")

    def register_operation(self, name: str, handler: Callable) -> None:
        self._check("operations", handler)
        if not isinstance(name, str) or not name.strip():
            raise PluginError("Operation name must be nonempty")
        self._pending.append(("operation", name, handler, 0))

    def add_hook(self, stage: str, callback: Callable, priority: int = 0) -> None:
        if stage not in HOOK_STAGES:
            raise PluginError(f"Unknown hook stage: {stage}")
        self._check(stage, callback)
        if not isinstance(priority, int) or isinstance(priority, bool):
            raise PluginError("Hook priority must be an integer")
        self._pending.append(("hook", "*" if stage == "observer" else stage, callback, priority))

    def subscribe(self, event: str, callback: Callable) -> None:
        if not isinstance(event, str) or not _EVENT.fullmatch(event) or event in HOOK_STAGES:
            raise PluginError(f"Invalid event name: {event!r}")
        declared = "observer" if "observer" in self._allowed else event if event in self._allowed else f"event:{event}"
        self._check(declared, callback)
        self._pending.append(("event", event, callback, 0))


class PluginManager:
    """Load explicit manifests once, in deterministic dependency order.

    Per-plugin settings: ``enabled`` (default true), ``active_skills`` (default
    empty), ``include_resources`` (default true). Other keys are plugin-defined.
    Errors disable only the affected plugin and its dependents. Re-loading an
    active id is rejected; create a new runtime/manager to reload extensions.
    """

    def __init__(self, runtime):
        self.runtime = runtime
        self._statuses: list[PluginStatus] = []
        self._active: dict[str, PluginAPI] = {}
        self._load_sequence = 0

    def inventory(self) -> list[dict]:
        return [asdict(status) for status in self._statuses]

    def load(self, paths: Iterable[str | Path], settings: dict[str, dict] | None = None) -> list[PluginStatus]:
        if isinstance(paths, (str, Path)):
            raise PluginError("paths must be a list of explicit plugin.toml paths")
        settings = {} if settings is None else settings
        if not isinstance(settings, dict):
            raise PluginError("Plugin settings must be a dictionary keyed by plugin id")
        records: dict[str, tuple[_Manifest, PluginStatus, dict]] = {}
        batch: list[PluginStatus] = []
        for supplied in paths:
            status = PluginStatus(id="", path=str(supplied))
            batch.append(status)
            self._statuses.append(status)
            try:
                manifest = _manifest(Path(supplied).expanduser().resolve())
                status.id, status.version = manifest.id, manifest.version
                status.path = str(manifest.path)
                status.contributions = list(manifest.contributions)
                config = settings.get(manifest.id, {})
                if not isinstance(config, dict):
                    raise PluginError(f"Settings for {manifest.id} must be a dictionary")
                if not isinstance(config.get("enabled", True), bool):
                    raise PluginError("enabled must be true or false")
                if manifest.id in self._active or manifest.id in records:
                    # Do not choose a winner between two conflicting manifests.
                    if manifest.id in records:
                        self._fail(records[manifest.id][1], f"Duplicate plugin id: {manifest.id}")
                    raise PluginError(f"Duplicate plugin id: {manifest.id}")
                records[manifest.id] = (manifest, status, config)
                if not config.get("enabled", True):
                    status.status = "disabled"
            except (OSError, ValueError, TypeError) as error:
                self._fail(status, str(error))

        pending = {plugin_id for plugin_id, (_, status, _) in records.items() if status.status == "pending"}
        predecessors: dict[str, set[str]] = {plugin_id: set() for plugin_id in pending}
        for plugin_id in pending:
            manifest = records[plugin_id][0]
            predecessors[plugin_id].update(target for target in (*manifest.dependencies, *manifest.after) if target in pending)
            for target in manifest.before:
                if target in pending:
                    predecessors[target].add(plugin_id)
        while pending:
            ready = sorted(plugin_id for plugin_id in pending if not (predecessors[plugin_id] & pending))
            if not ready:
                for plugin_id in sorted(pending):
                    self._fail(records[plugin_id][1], "Plugin ordering contains a cycle")
                break
            for plugin_id in ready:
                pending.remove(plugin_id)
                manifest, status, config = records[plugin_id]
                missing = [dependency for dependency in manifest.dependencies if dependency not in self._active]
                if missing:
                    self._fail(status, f"Required plugins are not active: {', '.join(missing)}")
                    continue
                self._activate(manifest, status, config)
        return batch

    @staticmethod
    def _fail(status: PluginStatus, error: str) -> None:
        status.status, status.error = "error", error
        _logger.warning("Plugin %s (%s) disabled: %s", status.id or "<unknown>", status.path, error)

    def _activate(self, manifest: _Manifest, status: PluginStatus, config: dict) -> None:
        namespace = ""
        api = None
        snapshot = None
        try:
            active_skills = config.get("active_skills", [])
            if not isinstance(active_skills, list) or any(not isinstance(value, str) for value in active_skills):
                raise PluginError("active_skills must be a list of skill names or resource paths")
            include_resources = config.get("include_resources", True)
            if not isinstance(include_resources, bool):
                raise PluginError("include_resources must be true or false")
            resources = PluginResources(manifest.path.parent, manifest.resources)
            selected = resources.selected(active_skills, include_resources)
            status.resources = resources.inventory()
            status.active_skills = [resource.name for resource in selected if resource.kind == "skill"]
            api = PluginAPI(manifest, config, resources)
            if selected:
                from src.workflow import ContextBlock

                blocks = tuple(ContextBlock(
                    text=resources.read(resource.path), source=f"plugin:{manifest.id}/{resource.path}",
                    priority=0, kind="instruction" if resource.kind == "skill" else "evidence",
                ) for resource in selected)
                api.add_hook("context.collect", lambda item, context: list(blocks))
            if manifest.entrypoint:
                self._load_sequence += 1
                digest = hashlib.sha256(str(manifest.path).encode()).hexdigest()[:16]
                namespace = f"_oghidra_plugin_{digest}_{id(self):x}_{self._load_sequence}"
                package = ModuleType(namespace)
                package.__path__ = [str(manifest.path.parent)]
                package.__package__ = namespace
                package.__spec__ = importlib.machinery.ModuleSpec(namespace, loader=None, is_package=True)
                sys.modules[namespace] = package
                module_name, callable_name = manifest.entrypoint.split(":")
                relative = module_name.replace(".", "/")
                module_path = contained_path(manifest.path.parent, f"{relative}.py")
                package_path = contained_path(manifest.path.parent, f"{relative}/__init__.py")
                if not module_path.is_file() and not package_path.is_file():
                    raise PluginError(f"Entrypoint module does not exist: {module_name}")
                module = importlib.import_module(f"{namespace}.{module_name}")
                activate = getattr(module, callable_name, None)
                if not callable(activate):
                    raise PluginError(f"Entrypoint is not callable: {manifest.entrypoint}")
                activation_result = activate(api)
                if inspect.isawaitable(activation_result):
                    if inspect.iscoroutine(activation_result):
                        activation_result.close()
                    raise PluginError("activate(api) must be synchronous")
            api._open = False
            snapshot = self.runtime.snapshot_registrations()
            for kind, name, callback, priority in api._pending:
                if kind == "operation":
                    self.runtime.register_operation(name, callback)
                elif kind == "event":
                    self.runtime.subscribe(name, callback, plugin_id=manifest.id)
                else:
                    self.runtime.add_hook(name, callback, plugin_id=manifest.id, priority=priority)
            self._active[manifest.id] = api
            status.status = "active"
        except (Exception, SystemExit) as error:  # noqa: BLE001 - isolate arbitrary plugin activation failures
            if snapshot is not None:
                self.runtime.restore_registrations(snapshot)
            if api is not None:
                api._open = False
            if namespace:
                for name in list(sys.modules):
                    if name == namespace or name.startswith(f"{namespace}."):
                        del sys.modules[name]
            self._fail(status, f"{type(error).__name__}: {error}")
