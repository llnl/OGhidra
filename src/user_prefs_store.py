"""Small persistence layer for user preferences.

These preferences are intended to be sticky across application restarts even if the
user does not explicitly save/load an analysis session.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict


DEFAULT_PREFS_PATH = os.path.join("data", "user_prefs.json")


def load_user_prefs(path: str = DEFAULT_PREFS_PATH) -> Dict[str, Any]:
    try:
        if not os.path.exists(path):
            return {}
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_user_prefs(prefs: Dict[str, Any], path: str = DEFAULT_PREFS_PATH) -> None:
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(prefs, f, indent=2, ensure_ascii=False)
    except Exception:
        return
