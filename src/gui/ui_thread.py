"""One shared primitive for Tk thread-safety.

Tkinter is single-threaded: widgets may only be touched on the thread that runs
the main loop. Background workers all over this GUI mutate widgets directly,
which is undefined behavior. Instead of hand-marshalling at every call site,
route through the ``@ui_safe`` decorator (or ``run_on_ui``): the method runs
directly on the main thread and is queued (fire-and-forget) when called from
any other thread. A single pump, scheduled on the root at startup, drains the
queue on the main loop.

Usage:
    # once, right after creating the root window:
    from .ui_thread import install
    install(root)

    # on any widget-touching method (fire-and-forget; returns None off-thread):
    from .ui_thread import ui_safe
    @ui_safe
    def add_response(self, ...): self.text.insert(...)

Note: ``@ui_safe`` is for *mutations*. Cross-thread *reads* of widget state
(get_children, var.get) can't be fire-and-forget — expose a thread-safe data
snapshot instead.
"""

import functools
import queue
import threading

_queue: "queue.Queue | None" = None
_main_ident: "int | None" = None


def install(root, interval_ms: int = 30):
    """Call once, on the main thread, right after creating the Tk root."""
    global _queue, _main_ident
    _queue = queue.Queue()
    _main_ident = threading.get_ident()

    def _pump():
        while True:
            try:
                fn = _queue.get_nowait()
            except queue.Empty:
                break
            try:
                fn()
            except Exception:  # never let one bad callback kill the pump  # noqa: BLE001, S110 intentional defensive recovery boundary
                pass
        try:
            root.after(interval_ms, _pump)
        except Exception:  # noqa: BLE001, S110 intentional defensive recovery boundary
            pass  # root gone (shutdown)

    root.after(interval_ms, _pump)


def run_on_ui(fn):
    """Run ``fn`` on the Tk main thread (direct if already there, else queued)."""
    if _queue is None or threading.get_ident() == _main_ident:
        return fn()
    _queue.put(fn)


def ui_safe(method):
    """Decorator: run a widget-mutating method on the Tk main thread."""

    @functools.wraps(method)
    def wrapper(*args, **kwargs):
        if _queue is None or threading.get_ident() == _main_ident:
            return method(*args, **kwargs)
        _queue.put(lambda: method(*args, **kwargs))

    return wrapper
