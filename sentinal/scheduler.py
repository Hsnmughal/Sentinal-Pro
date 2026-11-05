from __future__ import annotations

import threading
import os
import time
import sqlite3
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from .core.http import RequestDeferred
from .service import SentinalService


class PollScheduler:
    """Single-process durable scheduler backed by the poll_jobs table.

    All execution goes through the service's job runner, so scheduled and manual
    checks share one code path — and therefore the same request budgets and
    cooldowns. A request cooldown defers one job without stalling other sources.
    """

    def __init__(self, service: SentinalService):
        self.service = service
        self.tick_seconds = service.config.scheduler_tick_seconds
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None
        self._run_lock = threading.Lock()
        self._status_lock = threading.RLock()
        self._executor: ThreadPoolExecutor | None = None
        self._state: dict[str, Any] = {}
        self._last_idle_at: str | None = None
        if hasattr(service.client, "cancel_event"):
            service.client.cancel_event = self._stop

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def start(self) -> None:
        with self._status_lock:
            if self.running:
                return
            self.service.initialize()
            self._stop.clear()
            self._thread = threading.Thread(target=self._loop, name='sentinal-scheduler', daemon=True)
            self._publish_state({'state': 'running', 'started_at': _now(), 'tick_seconds': self.tick_seconds})
            self._thread.start()
            threading.Thread(target=self._record_exit, args=(self._thread,), name='sentinal-scheduler-exit', daemon=True).start()

    def _record_exit(self, thread: threading.Thread) -> None:
        thread.join()
        with self._status_lock:
            if self._thread is thread:
                if self._state.get('state') != 'failed':
                    self._publish_state({**self._state, 'state': 'stopped', 'stopped_at': _now()})

    def stop(self, timeout: float = 10) -> None:
        with self._status_lock:
            self._stop.set()
            self._wake.set()
            thread = self._thread
        if thread:
            thread.join(timeout=timeout)
        with self._status_lock:
            if self._thread is not thread:
                return
            state = 'stopping' if thread and thread.is_alive() else 'stopped'
            if self._state.get('state') != 'failed':
                self._publish_state({**self._state, 'state': state, 'stopped_at' if state == 'stopped' else 'stop_requested_at': _now()})

    def _publish_state(self, state: dict[str, Any]) -> None:
        with self._status_lock:
            self._state = dict(state)
            try:
                self.service.store.set_runtime_status('scheduler', state)
            except sqlite3.Error:
                pass  # The live status must remain available while persistence is unavailable.

    def force(self, source_type: str | None = None) -> int:
        count = self.service.store.force_jobs(source_type)
        self._wake.set()
        return count

    def force_job(self, job_key: str) -> bool:
        queued = self.service.store.force_job(job_key)
        self._wake.set()
        return queued

    def run_due_once(self) -> dict[str, int]:
        if not self._run_lock.acquire(blocking=False):
            return {"completed": 0, "failed": 0, "deferred": 0, "skipped": 1}
        try:
            jobs = self.service.store.due_jobs(limit=self.service.config.scheduler_batch_size)
            if not jobs:
                return {"completed": 0, "failed": 0, "deferred": 0, "skipped": 0}
            def progress(summary):
                summary.pop("errors", None)
                self.service.store.set_runtime_status("last_scheduler_pass", summary)
            return self.service.run_jobs(
                jobs,
                should_stop=self._stop.is_set, on_progress=progress, executor=self._executor,
            )
        finally:
            self._run_lock.release()

    def status(self, *, detailed: bool = True) -> dict[str, Any]:
        payload = {
            "running": self.running,
            "http_metrics": self.service.client.budget.metrics() if getattr(self.service.client, "budget", None) else {},
            "github_auth": {"configured": bool(os.getenv("GITHUB_TOKEN"))},
            "tick_seconds": self.tick_seconds,
            "configured_target_count": self.service.store.configured_target_count(),
            "sweep": self.service.store.sweep_summary(),
            "failed": self.service.store.list_failed_jobs(),
            "runtime": self.service.store.runtime_status(),
        }
        if self._state:
            payload['runtime']['scheduler'] = {'value': dict(self._state)}
        if detailed:
            payload['jobs'] = self.service.store.list_jobs()
        return payload

    def _loop(self) -> None:
        with ThreadPoolExecutor(max_workers=self.service.config.scheduler_max_workers) as executor:
            with self._run_lock:
                self._executor = executor
            try:
                self._drain_loop()
            except Exception as error:
                self._publish_state({'state': 'failed', 'error': f'{type(error).__name__}: {error}', 'failed_at': _now()})
            finally:
                with self._run_lock:
                    self._executor = None
                    close = getattr(self.service.client, 'close', None)
                    if callable(close):
                        close()

    def _drain_loop(self) -> None:
        next_maintenance = time.monotonic() + 86400
        failures = 0
        while not self._stop.is_set():
            self._wake.clear()
            try:
                recover = getattr(self.service, 'recover_unfinished_jobs', None)
                if callable(recover):
                    recover()
                while not self._stop.is_set():
                    if time.monotonic() >= next_maintenance:
                        self.service.store.run_maintenance()
                        next_maintenance = time.monotonic() + 86400
                    result = self.run_due_once()
                    if not sum(result.get(key, 0) for key in ("completed", "failed", "deferred")):
                        break
                if self._stop.is_set():
                    break
                delay = self.service.store.next_job_delay(self.tick_seconds)
                if failures:
                    failures = 0
                    self._publish_state({'state': 'running', 'recovered_at': _now(), 'tick_seconds': self.tick_seconds})
                # Reaching the wait is liveness evidence: health reads this
                # alongside the last completed pass, so an idle loop stays healthy.
                self._last_idle_at = _now()
                self._wake.wait(delay)
            except sqlite3.Error as error:
                code = getattr(error, 'sqlite_errorcode', None)
                transient = (code is not None and code & 255 in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED, sqlite3.SQLITE_IOERR))
                if code is None:
                    transient = isinstance(error, sqlite3.OperationalError) and any(
                        word in str(error).lower() for word in ('locked', 'busy', 'temporarily unavailable', 'disk i/o'))
                if not transient:
                    raise
                failures += 1
                delay = min(60, 2 ** min(failures - 1, 6))
                self._publish_state({'state': 'retrying', 'error': str(error),
                    'failed_at': _now(), 'retry_in_seconds': delay})
                self._stop.wait(delay)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
