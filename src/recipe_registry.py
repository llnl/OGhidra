"""Plugin-style recipe registry.

Allows built-in recipes (registered programmatically) and custom recipes
(loaded from a directory of Python files) to coexist under a single
lookup mechanism.

Custom recipe files should define a class inheriting from ``BaseRecipe``
with ``name``, ``description``, and ``execute()`` implemented.
"""

import importlib.util
import logging
import os
from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, FrozenSet, List, Optional

logger = logging.getLogger(__name__)


class BaseRecipe(ABC):
    """Abstract base for custom recipes loaded from external files."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique recipe identifier (e.g. 'trace_import_callers')."""

    @property
    @abstractmethod
    def description(self) -> str:
        """One-line description shown in diagnostics."""

    @abstractmethod
    def execute(self, executor, params: Dict[str, Any]):
        """Run the recipe and return a ``RecipeResult``.

        Args:
            executor: The ``RecipeExecutor`` instance (provides helper
                      methods like ``_decompile_function``, tool access, etc.).
            params: Recipe-specific parameters dict.

        Returns:
            A ``RecipeResult`` dataclass.
        """


class RecipeRegistry:
    """Central registry of built-in and custom recipes.

    Usage::

        registry = RecipeRegistry()
        registry.register_builtin(
            "trace_import_callers",
            lambda executor, params: executor.trace_import_callers(...),
            "Trace callers of imported APIs",
        )
        registry.load_custom_recipes("./custom_recipes/")

        result = registry.execute("trace_import_callers", executor, params)
    """

    def __init__(self):
        self._builtins: Dict[str, Dict[str, Any]] = {}
        self._custom: Dict[str, BaseRecipe] = {}

    # ── Registration ─────────────────────────────────────────────────

    def register_builtin(
        self,
        name: str,
        callable_fn: Callable,
        description: str = "",
    ) -> None:
        """Register a built-in recipe as a callable."""
        self._builtins[name] = {
            "callable": callable_fn,
            "description": description,
        }

    def register_custom(self, recipe: BaseRecipe) -> None:
        """Register a custom recipe instance.

        Warns if it shadows a built-in with the same name.
        """
        if recipe.name in self._builtins:
            logger.warning(
                "[RecipeRegistry] Custom recipe '%s' shadows built-in recipe",
                recipe.name,
            )
        self._custom[recipe.name] = recipe
        logger.info(
            "[RecipeRegistry] Registered custom recipe: %s", recipe.name
        )

    # ── Discovery ────────────────────────────────────────────────────

    def load_custom_recipes(self, directory: str) -> int:
        """Scan *directory* for ``.py`` files and register any ``BaseRecipe`` subclasses.

        Returns the number of recipes loaded.
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
                    f"custom_recipe_{filename[:-3]}", filepath
                )
                if spec is None or spec.loader is None:
                    continue
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (
                        isinstance(attr, type)
                        and issubclass(attr, BaseRecipe)
                        and attr is not BaseRecipe
                    ):
                        instance = attr()
                        self.register_custom(instance)
                        loaded += 1
            except Exception as exc:
                logger.warning(
                    "[RecipeRegistry] Failed to load custom recipe from %s: %s",
                    filepath,
                    exc,
                )
        if loaded:
            logger.info(
                "[RecipeRegistry] Loaded %d custom recipe(s) from %s",
                loaded,
                directory,
            )
        return loaded

    # ── Queries ──────────────────────────────────────────────────────

    @property
    def available_recipes(self) -> FrozenSet[str]:
        """Names of all registered recipes (built-in + custom)."""
        return frozenset(self._builtins.keys() | self._custom.keys())

    def has_recipe(self, name: str) -> bool:
        return name in self._builtins or name in self._custom

    def get_description(self, name: str) -> str:
        if name in self._custom:
            return self._custom[name].description
        if name in self._builtins:
            return self._builtins[name].get("description", "")
        return ""

    # ── Execution ────────────────────────────────────────────────────

    def execute(self, name: str, executor, params: Dict[str, Any]):
        """Execute a recipe by name.

        Custom recipes take priority over built-ins with the same name.
        """
        if name in self._custom:
            return self._custom[name].execute(executor, params)
        if name in self._builtins:
            return self._builtins[name]["callable"](executor, params)
        raise ValueError(
            f"Unknown recipe: {name!r}. "
            f"Available: {sorted(self.available_recipes)}"
        )
