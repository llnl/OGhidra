import weakref
import concurrent.futures.thread as thread_executor
from concurrent.futures import ThreadPoolExecutor
import threading


class DaemonThreadPoolExecutor(ThreadPoolExecutor):
    """ThreadPoolExecutor whose worker threads are daemons.

    This ensures background workers (e.g. bulk rename) do not prevent the
    Python process from exiting when the UI is closed.
    """

    def _adjust_thread_count(self):  # type: ignore[override]
        """Mirror CPython's executor logic, but spawn daemon workers."""
        if self._idle_semaphore.acquire(timeout=0):  # type: ignore[attr-defined]
            return

        def weakref_cb(_, q=self._work_queue):  # type: ignore[attr-defined]
            q.put(None)

        num_threads = len(self._threads)  # type: ignore[attr-defined]
        if num_threads < self._max_workers:  # type: ignore[attr-defined]
            thread_name = "%s_%d" % (
                self._thread_name_prefix or self,  # type: ignore[attr-defined]
                num_threads,
            )
            t = threading.Thread(
                name=thread_name,
                target=thread_executor._worker,
                args=(
                    weakref.ref(self, weakref_cb),
                    self._work_queue,  # type: ignore[attr-defined]
                    self._initializer,  # type: ignore[attr-defined]
                    self._initargs,  # type: ignore[attr-defined]
                ),
            )
            t.daemon = True
            t.start()
            self._threads.add(t)  # type: ignore[attr-defined]
            thread_executor._threads_queues[t] = self._work_queue  # type: ignore[attr-defined]
