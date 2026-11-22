"""
NEXUS Engine - Asynchronous Background Task Dispatcher
======================================================
Architecture Role: Thread-safe, non-blocking asynchronous execution manager
for long-running operations (Pandas ETL transformations, LangChain LLM inferences,
SQLite queries). Eliminates UI thread lockups in CustomTkinter.

Author: Senior Systems Engineer
Platform: Windows (Python 3.13) / CustomTkinter
"""

from __future__ import annotations

import concurrent.futures
import dataclasses
import enum
import inspect
import queue
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Set, Union

# Resilient logging initialization
try:
    from loguru import logger
except ImportError:
    import logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )
    logger = logging.getLogger("NEXUS-AsyncWorker")  # type: ignore


# ==============================================================================
# WORKER EVENT DEFINITIONS
# ==============================================================================

class WorkerEventType(enum.Enum):
    """Event classification emitted by background worker threads to the main queue."""
    PROGRESS = "PROGRESS"
    SUCCESS = "SUCCESS"
    ERROR = "ERROR"


@dataclasses.dataclass(frozen=True)
class WorkerEvent:
    """Immutable event payload pushed across thread boundaries into the UI queue."""
    task_id: str
    task_name: str
    event_type: WorkerEventType
    payload: Any  # Progress message (str), return value (Any), or Exception
    callback: Optional[Callable[..., None]]
    timestamp: float = dataclasses.field(default_factory=time.time)


# ==============================================================================
# ASYNC WORKER MANAGER
# ==============================================================================

class AsyncWorkerManager:
    """
    Thread-safe task scheduler and event-dispatcher for the NEXUS GUI.

    Architectural Invariants:
    1. Zero UI Thread Blocking: Heavy computation (I/O, LLM calls, ETL) runs
       strictly inside a ThreadPoolExecutor.
    2. Main-Thread Callback Execution: All callbacks (on_success, on_error, on_progress)
       are strictly dispatched on the main UI thread via process_queue().
    3. Exception Isolation: Uncaught exceptions inside callbacks are captured and logged
       without crashing the CustomTkinter .after() event loop.
    4. Clean Lifecycle Termination: shutdown() cancels pending futures and frees thread
       resources, preventing zombie processes on desktop exit.
    5. Headless Compatibility: Can be run and asserted in standard unittests without
       requiring a GUI display or an active Tkinter mainloop.
    """

    def __init__(self, max_workers: int = 4) -> None:
        self.max_workers = max_workers
        self._executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="NexusWorker"
        )
        self._event_queue: queue.Queue[WorkerEvent] = queue.Queue()
        self._task_counter: int = 0
        self._lock = threading.Lock()
        self._active_tasks: Dict[str, concurrent.futures.Future[Any]] = {}
        self._progress_callbacks: Dict[str, Callable[[str], None]] = {}
        self._is_shutdown: bool = False
        logger.info(f"AsyncWorkerManager initialized with {max_workers} worker threads.")

    @property
    def is_shutdown(self) -> bool:
        """Returns True if the worker pool has been shut down."""
        with self._lock:
            return self._is_shutdown

    def active_task_count(self) -> int:
        """Returns the number of tasks currently executing in the background."""
        with self._lock:
            return len(self._active_tasks)

    def is_busy(self) -> bool:
        """Returns True if any background tasks are actively running."""
        with self._lock:
            return len(self._active_tasks) > 0

    def pending_events_count(self) -> int:
        """Returns the number of events waiting in the queue to be processed."""
        return self._event_queue.qsize()

    # --------------------------------------------------------------------------
    # TASK SUBMISSION PIPELINE
    # --------------------------------------------------------------------------

    def submit_task(
        self,
        task_fn: Callable[..., Any],
        *args: Any,
        on_success: Optional[Callable[[Any], None]] = None,
        on_error: Optional[Callable[[Exception], None]] = None,
        on_progress: Optional[Callable[[str], None]] = None,
        task_name: str = "BackgroundTask",
        **kwargs: Any
    ) -> str:
        """
        Dispatches a callable to execute asynchronously inside the worker thread pool.

        Parameters:
            task_fn: Callable executing in the background thread.
            *args: Positional arguments forwarded to task_fn.
            on_success: Main-thread callback invoked with the return value of task_fn.
            on_error: Main-thread callback invoked with the Exception if task_fn fails.
            on_progress: Main-thread callback invoked whenever task reports progress.
            task_name: Descriptive label for logging and telemetry.
            **kwargs: Keyword arguments forwarded to task_fn.

        Returns:
            task_id: Unique string identifier for tracking and progress reporting.
        """
        with self._lock:
            if self._is_shutdown:
                raise RuntimeError(
                    f"Cannot submit task '{task_name}'. AsyncWorkerManager has already been shut down."
                )

            self._task_counter += 1
            task_id = f"TASK-{self._task_counter:05d}"
            if on_progress:
                self._progress_callbacks[task_id] = on_progress

        logger.debug(f"[SUBMIT] Task '{task_name}' [{task_id}] submitted to background pool.")

        # Reporter helper available for progress reporting
        def report_progress(message: str) -> None:
            self._queue_progress(task_id, task_name, message, on_progress)

        # Inject progress_callback into task_fn kwargs if accepted and not provided
        try:
            sig = inspect.signature(task_fn)
            if "progress_callback" in sig.parameters and "progress_callback" not in kwargs:
                kwargs["progress_callback"] = report_progress
        except (ValueError, TypeError):
            pass

        # Submit worker wrapper to thread pool
        future = self._executor.submit(
            self._execute_worker_job,
            task_id,
            task_name,
            task_fn,
            on_success,
            on_error,
            args,
            kwargs
        )

        with self._lock:
            self._active_tasks[task_id] = future

        return task_id

    def report_progress(self, task_id: str, message: str) -> bool:
        """
        Public progress reporting helper. Can be invoked from within background tasks
        or external managers to push a progress message for a specific task.
        """
        with self._lock:
            cb = self._progress_callbacks.get(task_id)

        self._queue_progress(task_id, "ExternalProgress", message, cb)
        return cb is not None

    def _queue_progress(
        self,
        task_id: str,
        task_name: str,
        message: str,
        callback: Optional[Callable[[str], None]]
    ) -> None:
        """Enqueues a progress notification event."""
        if self._is_shutdown:
            return

        self._event_queue.put(
            WorkerEvent(
                task_id=task_id,
                task_name=task_name,
                event_type=WorkerEventType.PROGRESS,
                payload=str(message),
                callback=callback
            )
        )

    def _execute_worker_job(
        self,
        task_id: str,
        task_name: str,
        task_fn: Callable[..., Any],
        on_success: Optional[Callable[[Any], None]],
        on_error: Optional[Callable[[Exception], None]],
        args: tuple[Any, ...],
        kwargs: dict[str, Any]
    ) -> None:
        """Internal execution wrapper running inside the background worker thread."""
        start_time = time.perf_counter()
        try:
            result = task_fn(*args, **kwargs)
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            logger.debug(f"[SUCCESS] Task '{task_name}' [{task_id}] completed in {duration_ms:.2f}ms.")

            if not self._is_shutdown:
                self._event_queue.put(
                    WorkerEvent(
                        task_id=task_id,
                        task_name=task_name,
                        event_type=WorkerEventType.SUCCESS,
                        payload=result,
                        callback=on_success
                    )
                )

        except Exception as exc:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            logger.error(f"[ERROR] Task '{task_name}' [{task_id}] failed after {duration_ms:.2f}ms: {exc}")

            if not self._is_shutdown:
                self._event_queue.put(
                    WorkerEvent(
                        task_id=task_id,
                        task_name=task_name,
                        event_type=WorkerEventType.ERROR,
                        payload=exc,
                        callback=on_error
                    )
                )

        finally:
            with self._lock:
                self._active_tasks.pop(task_id, None)
                self._progress_callbacks.pop(task_id, None)

    # --------------------------------------------------------------------------
    # MAIN-THREAD EVENT DISPATCHER
    # --------------------------------------------------------------------------

    def process_queue(self) -> int:
        """
        Drains all pending events from the internal queue and executes their
        associated callbacks on the caller thread (CustomTkinter UI main thread).

        Designed to be registered in a recurring CustomTkinter poll loop:
            self.after(30, self._poll_worker_events)

        Guarantees Exception Isolation: If a callback raises an error, it is
        logged with a traceback without interrupting the main loop or aborting
        the processing of subsequent queued events.

        Returns:
            int: The number of events processed during this iteration.
        """
        processed_count = 0

        while True:
            try:
                event = self._event_queue.get_nowait()
            except queue.Empty:
                break

            processed_count += 1
            if event.callback is not None:
                try:
                    event.callback(event.payload)
                except Exception as callback_exc:
                    # Isolate callback crashes so UI event loop stays alive
                    logger.error(
                        f"Exception in UI callback for task '{event.task_name}' "
                        f"[{event.task_id}] ({event.event_type.value}): {callback_exc}",
                        exc_info=True
                    )

        return processed_count

    # --------------------------------------------------------------------------
    # LIFECYCLE & SHUTDOWN MANAGEMENT
    # --------------------------------------------------------------------------

    def shutdown(self, wait: bool = False) -> None:
        """
        Cleanly terminates the worker thread pool and halts event queueing.
        Prevents zombie background threads when the user exits the GUI.

        Parameters:
            wait: If True, waits for active tasks to complete. If False (default),
                  cancels pending futures and exits immediately.
        """
        with self._lock:
            if self._is_shutdown:
                return
            self._is_shutdown = True

        logger.info(f"Shutting down AsyncWorkerManager (wait={wait})...")
        try:
            # cancel_futures is natively supported in Python 3.9+ (running Python 3.13)
            self._executor.shutdown(wait=wait, cancel_futures=True)
        except Exception as exc:
            logger.warning(f"Exception during ThreadPoolExecutor shutdown: {exc}")

        # Clear remaining queue items
        drained = 0
        while not self._event_queue.empty():
            try:
                self._event_queue.get_nowait()
                drained += 1
            except queue.Empty:
                break

        if drained > 0:
            logger.debug(f"Drained {drained} pending events from worker queue during shutdown.")

        logger.info("AsyncWorkerManager shutdown complete.")
