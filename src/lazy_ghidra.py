"""Lazy-initializing proxy for GhidraMCPClient.

Defers the actual Ghidra connection (HTTP health-check, API detection,
instance listing) until the first real attribute access.  This lets the
Bridge start up even when Ghidra is not yet running.
"""

import logging
import threading

logger = logging.getLogger(__name__)

# Attributes that belong to the proxy itself — never forwarded.
_PROXY_ATTRS = frozenset({
    "_ghidra_cls",
    "_init_kwargs",
    "_real_client",
    "_init_lock",
    "_initialized",
})


class LazyGhidraClient:
    """Transparent proxy that creates the real GhidraMCPClient on first use.

    Usage::

        from src.ghidra_client import GhidraMCPClient

        client = LazyGhidraClient(
            GhidraMCPClient,
            config=ghidra_config,
            ollama_client=ollama,
        )
        # No connection yet — safe even if Ghidra is offline.

        client.list_functions()  # ← connection established HERE
    """

    def __init__(self, ghidra_cls, **kwargs):
        object.__setattr__(self, "_ghidra_cls", ghidra_cls)
        object.__setattr__(self, "_init_kwargs", kwargs)
        object.__setattr__(self, "_real_client", None)
        object.__setattr__(self, "_init_lock", threading.Lock())
        object.__setattr__(self, "_initialized", False)

    # ── Connection lifecycle ─────────────────────────────────────────

    def _ensure_connected(self):
        """Double-checked locking: instantiate the real client once."""
        if self._initialized:
            return
        with self._init_lock:
            if self._initialized:
                return
            logger.info("[LazyGhidraClient] First access — connecting to Ghidra …")
            try:
                real = self._ghidra_cls(**self._init_kwargs)
                object.__setattr__(self, "_real_client", real)
                object.__setattr__(self, "_initialized", True)
                logger.info("[LazyGhidraClient] Connection established.")
            except Exception as exc:
                logger.error(
                    "[LazyGhidraClient] Failed to connect to Ghidra: %s", exc
                )
                raise ConnectionError(
                    f"Ghidra connection failed on first use: {exc}"
                ) from exc

    @property
    def is_connected(self) -> bool:
        """Check whether the real client has been created (no side effect)."""
        return self._initialized

    # ── Transparent forwarding ───────────────────────────────────────

    def __getattr__(self, name):
        # Only reached for attributes NOT in _PROXY_ATTRS (those are set
        # via object.__setattr__ and resolved by normal lookup).
        self._ensure_connected()
        return getattr(self._real_client, name)

    def __setattr__(self, name, value):
        if name in _PROXY_ATTRS:
            object.__setattr__(self, name, value)
        else:
            self._ensure_connected()
            setattr(self._real_client, name, value)

    def __repr__(self):
        if self._initialized:
            return f"<LazyGhidraClient connected={True} client={self._real_client!r}>"
        return f"<LazyGhidraClient connected={False} pending>"
