"""Multi-level configuration loader.

Discovers and deep-merges config files from:
  1. User-level:    ~/.oghidra/config.json
  2. Project-level: .oghidra/config.json  (relative to CWD)

Env vars (handled by pydantic-settings) remain highest priority and are
not touched here — this module only produces a merged dict of overrides
that is passed as **kwargs to the config model constructor.
"""

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively merge *override* into *base* (non-destructive copy).

    Strategy:
      - dicts → recursive merge
      - lists → append override items to base list
      - scalars → override wins
    """
    merged = dict(base)
    for key, val in override.items():
        if key in merged:
            base_val = merged[key]
            if isinstance(base_val, dict) and isinstance(val, dict):
                merged[key] = _deep_merge(base_val, val)
            elif isinstance(base_val, list) and isinstance(val, list):
                merged[key] = base_val + val
            else:
                merged[key] = val
        else:
            merged[key] = val
    return merged


class ConfigLoader:
    """Discovers and merges JSON config files.

    Usage::

        loader = ConfigLoader()
        overrides = loader.load_merged_overrides()
        # Pass overrides into BridgeConfig(**overrides)
    """

    DEFAULT_USER_PATH = os.path.join(
        os.path.expanduser("~"), ".oghidra", "config.json"
    )
    DEFAULT_PROJECT_PATH = os.path.join(".oghidra", "config.json")

    def __init__(
        self,
        user_config_path: Optional[str] = None,
        project_config_path: Optional[str] = None,
    ):
        self.user_path = user_config_path or self.DEFAULT_USER_PATH
        self.project_path = project_config_path or self.DEFAULT_PROJECT_PATH

    # ── Public API ───────────────────────────────────────────────────

    def load_merged_overrides(self) -> Dict[str, Any]:
        """Load and deep-merge user → project configs.

        Returns an empty dict if no config files exist.
        """
        merged: Dict[str, Any] = {}

        user_cfg = self._load_json_file(self.user_path, "user")
        if user_cfg:
            merged = _deep_merge(merged, user_cfg)

        project_cfg = self._load_json_file(self.project_path, "project")
        if project_cfg:
            merged = _deep_merge(merged, project_cfg)

        if merged:
            logger.info(
                "[ConfigLoader] Loaded overrides from config files: %s",
                list(merged.keys()),
            )

        return merged

    # ── Internals ────────────────────────────────────────────────────

    @staticmethod
    def _load_json_file(
        path: str, label: str
    ) -> Optional[Dict[str, Any]]:
        """Safely load a JSON file. Returns ``None`` if missing or invalid."""
        try:
            resolved = Path(path).resolve()
            if not resolved.is_file():
                return None
            with open(resolved, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                logger.warning(
                    "[ConfigLoader] %s config at %s is not a JSON object — ignoring",
                    label,
                    resolved,
                )
                return None
            logger.info("[ConfigLoader] Loaded %s config from %s", label, resolved)
            return data
        except json.JSONDecodeError as exc:
            logger.warning(
                "[ConfigLoader] %s config at %s has invalid JSON: %s — ignoring",
                label,
                path,
                exc,
            )
            return None
        except Exception as exc:
            logger.debug(
                "[ConfigLoader] Could not load %s config at %s: %s",
                label,
                path,
                exc,
            )
            return None
