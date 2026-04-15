"""Extensible hook-based correlation rule system.

Replaces the hardcoded ``VulnCorrelationRule`` dataclass with an abstract
``CorrelationHook`` base and a ``CorrelationHookRegistry`` that accepts
both built-in and user-defined hooks.

Custom hook files should define a class inheriting from ``CorrelationHook``
with ``name``, ``description``, and ``check()`` implemented.
"""

import importlib.util
import logging
import os
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Set

from src.agents.base import WorkerTask

logger = logging.getLogger(__name__)


class CorrelationHook(ABC):
    """Abstract base for vulnerability correlation hooks.

    Each hook inspects the accumulated API set, coverage state, and
    function registry to decide whether a targeted investigation task
    should be injected.
    """

    def __init__(self):
        self.fired: bool = False

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique hook identifier."""

    @property
    @abstractmethod
    def description(self) -> str:
        """One-line description for logging."""

    @abstractmethod
    def check(
        self,
        all_apis: Set[str],
        coverage,
        function_registry,
        discovery_cache,
    ) -> Optional[WorkerTask]:
        """Evaluate the hook against current investigation state.

        Args:
            all_apis: Lowercased set of all API names seen so far.
            coverage: ``CoverageTracker`` instance.
            function_registry: ``FunctionRegistry`` instance.
            discovery_cache: ``DiscoveryCache`` instance.

        Returns:
            A ``WorkerTask`` to inject, or ``None`` if the hook does not fire.
        """


class CorrelationHookRegistry:
    """Central registry of correlation hooks.

    Iterates unfired hooks after each worker cycle.  First match wins
    (returns a single ``WorkerTask``).
    """

    def __init__(self):
        self._hooks: List[CorrelationHook] = []

    # ── Registration ─────────────────────────────────────────────────

    def register(self, hook: CorrelationHook) -> None:
        self._hooks.append(hook)

    def register_builtin_hooks(
        self,
        worker_max_steps: int = 20,
        worker_soft_limit: int = 8,
    ) -> None:
        """Register the 5 built-in vulnerability correlation hooks."""
        from src.correlation_hooks_builtin import get_builtin_hooks

        for hook in get_builtin_hooks(worker_max_steps, worker_soft_limit):
            self.register(hook)
        logger.info(
            "[CorrelationHookRegistry] Registered %d built-in hooks",
            len(self._hooks),
        )

    def load_custom_hooks(self, directory: str) -> int:
        """Scan *directory* for ``.py`` files with ``CorrelationHook`` subclasses.

        Returns the number of hooks loaded.
        """
        if not directory or not os.path.isdir(directory):
            return 0

        loaded = 0
        for filename in sorted(os.listdir(directory)):
            if not filename.endswith(".py") or filename.startswith("_"):
                continue
            filepath = os.path.join(directory, filename)
            try:
                spec = importlib.util.spec_from_file_location(
                    f"custom_hook_{filename[:-3]}", filepath
                )
                if spec is None or spec.loader is None:
                    continue
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (
                        isinstance(attr, type)
                        and issubclass(attr, CorrelationHook)
                        and attr is not CorrelationHook
                    ):
                        instance = attr()
                        self.register(instance)
                        loaded += 1
            except Exception as exc:
                logger.warning(
                    "[CorrelationHookRegistry] Failed to load hook from %s: %s",
                    filepath,
                    exc,
                )
        if loaded:
            logger.info(
                "[CorrelationHookRegistry] Loaded %d custom hook(s) from %s",
                loaded,
                directory,
            )
        return loaded

    # ── Evaluation ───────────────────────────────────────────────────

    def check_all(
        self,
        all_apis: Set[str],
        coverage,
        function_registry,
        discovery_cache,
    ) -> Optional[WorkerTask]:
        """Iterate unfired hooks; return the first fired task or ``None``."""
        for hook in self._hooks:
            if hook.fired:
                continue
            try:
                task = hook.check(
                    all_apis, coverage, function_registry, discovery_cache
                )
                if task is not None:
                    hook.fired = True
                    return task
            except Exception as exc:
                logger.warning(
                    "Correlation hook '%s' check failed: %s", hook.name, exc
                )
        return None

    def check_all_batch(
        self,
        all_apis: Set[str],
        coverage,
        function_registry,
        discovery_cache,
    ) -> List[WorkerTask]:
        """Fire ALL matching unfired hooks at once and return their tasks.

        Unlike ``check_all`` (first-match-wins), this fires every hook
        whose predicate matches.  Used after the recon phase to batch
        all correlation-driven tasks into a single burst instead of
        consuming one orchestrator cycle per hook.
        """
        tasks = []
        for hook in self._hooks:
            if hook.fired:
                continue
            try:
                task = hook.check(
                    all_apis, coverage, function_registry, discovery_cache
                )
                if task is not None:
                    hook.fired = True
                    tasks.append(task)
            except Exception as exc:
                logger.warning(
                    "Correlation hook '%s' check failed: %s", hook.name, exc
                )
        return tasks

    # ── Utilities ────────────────────────────────────────────────────

    def reset(self) -> None:
        """Reset all ``fired`` flags (call at investigation start)."""
        for hook in self._hooks:
            hook.fired = False

    @property
    def hook_names(self) -> List[str]:
        return [h.name for h in self._hooks]
