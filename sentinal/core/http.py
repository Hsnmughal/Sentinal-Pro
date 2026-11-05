from __future__ import annotations

import json
import random
import threading
import time
from dataclasses import dataclass
from contextlib import contextmanager
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request

from .http_transport import NetworkResponseTooLarge, NetworkTransport, NetworkDeadline, NetworkCancelled, NetworkBusy


def header(headers: dict[str, str], name: str) -> str | None:
    """Case-insensitive header lookup — the single helper every caller uses."""
    return next((value for key, value in headers.items() if key.lower() == name.lower()), None)


@dataclass(frozen=True, slots=True)
class JsonResponse:
    status: int
    payload: Any
    headers: dict[str, str]


@dataclass(frozen=True, slots=True)
class TextResponse:
    status: int
    text: str | None
    headers: dict[str, str]


class RequestDeferred(RuntimeError):
    """A check must wait because of a budget, cooldown, deadline or shutdown.

    Raised instead of sleeping for a long time so one blocked platform can never
    stall other sources. Carries ``retry_at`` (epoch seconds) for rescheduling.
    A timed-out request may already have reached the remote server.
    """

    def __init__(self, origin: str, retry_at: float, reason: str):
        super().__init__(f"requests to {origin} deferred until {retry_at:.0f}: {reason}")
        self.origin = origin
        self.retry_at = retry_at
        self.reason = reason


class HttpStatusError(RuntimeError):
    """An HTTP failure with resource identity, independent of response wording."""
    def __init__(self, status: int, url: str, detail: str = ''):
        self.status, self.url = status, url
        super().__init__(f'HTTP {status} from {url}: {detail}')


def http_status(error: Exception) -> int | None:
    if isinstance(error, HttpStatusError):
        return error.status
    # Compatibility with existing third-party adapters and fake clients.
    import re
    match = re.match(r'^HTTP (\d{3}) from ', str(error))
    return int(match[1]) if match else None


class CooldownStore(Protocol):
    """Persistence surface for cooldowns (duck-typed over the SQLite store)."""

    def get_runtime_status(self, key: str) -> Any | None: ...

    def set_runtime_status(self, key: str, value: Any) -> None: ...

    def runtime_status(self) -> dict[str, Any]: ...


DEFAULT_BUDGET_SETTINGS: dict[str, Any] = {
    "min_spacing_seconds": 0.25,
    "jitter_seconds": 0.25,
    "max_requests": 120,
    "window_seconds": 60.0,
    "max_concurrent": 4,
    "max_response_bytes": 16 * 1024 * 1024,
    "backoff_base_seconds": 60,
    "backoff_max_seconds": 3600,
}

_COOLDOWN_PREFIX = "http_cooldown:"


class RequestBudget:
    """Shared request budgets by origin/credential.

    Enforces minimum spacing with jitter between requests, a sliding-window
    request cap, bounded concurrency and persisted cooldowns driven by
    ``Retry-After`` and rate-limit reset headers. Cooldowns live in the store, so
    a restart never resets them. Manual refreshes run through the same budget as
    scheduled polls because they share one client.
    """

    def __init__(self, persist: CooldownStore | None = None, settings: dict[str, Any] | None = None):
        self.persist = persist
        merged = dict(DEFAULT_BUDGET_SETTINGS)
        merged.update(settings or {})
        self.request_timeout_seconds = max(1.0, min(30.0, float(merged.get("request_timeout_seconds", 15))))
        self.min_spacing_seconds = max(0.0, float(merged["min_spacing_seconds"]))
        self.jitter_seconds = max(0.0, float(merged["jitter_seconds"]))
        self.max_requests = max(1, int(merged["max_requests"]))
        self.window_seconds = max(1.0, float(merged["window_seconds"]))
        self.max_concurrent = max(1, int(merged["max_concurrent"]))
        self.max_response_bytes = int(merged["max_response_bytes"])
        self._settings = merged
        self._sources = {}
        for host, values in (merged.get("sources") or {}).items():
            self._sources.setdefault(host.lower(), {}).update(values)
        self._active: dict[str, int] = {}
        self._held = threading.local()
        self._strikes: dict[str, int] = {}
        self._metrics: dict[str, dict[str, int]] = {}
        self._semaphore = threading.BoundedSemaphore(self.max_concurrent)
        self._lock = threading.Lock()
        self._persist_lock = threading.Lock()
        self._last_request: dict[str, float] = {}
        self._windows: dict[str, list[float]] = {}
        self._cooldowns: dict[str, tuple[float, str]] = {}
        self._load_persisted()

    def _load_persisted(self) -> None:
        if self.persist is None:
            return
        path = getattr(self.persist, "path", None)
        if path is not None and not Path(path).exists():
            return
        try:
            for key, record in (self.persist.runtime_status() or {}).items():
                if not key.startswith(_COOLDOWN_PREFIX):
                    continue
                value = record.get("value") if isinstance(record, dict) else None
                if isinstance(value, dict) and value.get("until"):
                    self._strikes[key[len(_COOLDOWN_PREFIX) :]] = int(value.get("strikes", 0))
                    self._cooldowns[key[len(_COOLDOWN_PREFIX) :]] = (
                        float(value["until"]),
                        str(value.get("reason", "")),
                    )
        except Exception as error:
            # The client can be constructed before a new database is initialized.
            if "no such table: runtime_status" not in str(error):
                raise

    def cooldown_until(self, origin: str) -> float | None:
        with self._lock:
            entry = self._cooldowns.get(origin)
        return entry[0] if entry else None

    def settings_for(self, url: str) -> dict[str, Any]:
        return {**self._settings, **self._sources.get((urlparse(url).hostname or "").lower(), {})}

    def metrics(self) -> dict[str, Any]:
        """Process-lifetime counters; never include credential keys."""
        with self._lock:
            return {origin: {**counts, "active": self._active.get(origin, 0),
                             "cooldown_until": self._cooldowns.get(origin, (None, ""))[0]}
                    for origin, counts in self._metrics.items()}

    def acquire(self, url: str, headers: dict[str, str] | None = None) -> None:
        """Wait for budget room or raise :class:`RequestDeferred` when waiting is long."""
        origin, credential = _origin_credential(url, headers)
        key = f"{origin}|{credential}"
        settings = self.settings_for(url)
        source_held = False
        if not self._semaphore.acquire(blocking=False):
            raise RequestDeferred(origin, time.time() + 1.0, "concurrency limit")
        try:
            with self._lock:
                now = time.time()
                cooldown = self._cooldowns.get(origin)
                if cooldown and cooldown[0] > now:
                    raise RequestDeferred(origin, cooldown[0], cooldown[1] or "cooldown")
                if self._active.get(origin, 0) >= max(1, int(settings["max_concurrent"])):
                    raise RequestDeferred(origin, now + 3.0, "source concurrency limit")
                spacing = max(0.0, float(settings["min_spacing_seconds"])) + random.uniform(0, max(0.0, float(settings["jitter_seconds"])))
                scheduled = max(now, self._last_request.get(key, 0.0) + spacing)
                window = self._windows.setdefault(key, [])
                window[:] = [stamp for stamp in window if stamp > now - max(1.0, float(settings["window_seconds"]))]
                if len(window) >= max(1, int(settings["max_requests"])):
                    raise RequestDeferred(origin, window[0] + max(1.0, float(settings["window_seconds"])), "request budget exhausted")
                if scheduled - now > 5.0:
                    raise RequestDeferred(origin, scheduled, "spacing")
                # Reserve under the lock: concurrent callers cannot take the same slot.
                self._last_request[key] = scheduled
                window.append(scheduled)
                counts = self._metrics.setdefault(origin, {})
                counts["requests"] = counts.get("requests", 0) + 1
                self._active[origin] = self._active.get(origin, 0) + 1
                source_held = True
            if scheduled > now:
                time.sleep(scheduled - now)
            with self._lock:
                cooldown = self._cooldowns.get(origin)
                if cooldown and cooldown[0] > time.time():
                    raise RequestDeferred(origin, cooldown[0], cooldown[1])
            self._held.origin = origin
        except BaseException:
            if source_held:
                with self._lock:
                    self._active[origin] -= 1
            self._semaphore.release()
            raise

    def release(self) -> None:
        origin = getattr(self._held, "origin", None)
        if origin is not None:
            with self._lock:
                self._active[origin] -= 1
            self._held.origin = None
        try:
            self._semaphore.release()
        except ValueError:
            pass

    def observe(self, url: str, status: int, response_headers: dict[str, str] | None, body: bytes = b"") -> None:
        """Record rate-limit state; persist a shared cooldown when told to back off."""
        origin, _credential = _origin_credential(url, None)
        headers = {str(k).lower(): str(v) for k, v in (response_headers or {}).items()}
        now = time.time()
        if not body:
            with self._lock:
                counts = self._metrics.setdefault(origin, {})
                name = f"http_{status}"
                counts[name] = counts.get(name, 0) + 1
        retry_at: float | None = None
        reason = ""
        retry_after = headers.get("retry-after")
        if retry_after:
            retry_at = _parse_retry_after(retry_after)
            reason = "Retry-After"
        remaining = headers.get("x-ratelimit-remaining")
        reset = headers.get("x-ratelimit-reset")
        if remaining is not None and reset is not None:
            try:
                if int(remaining) <= 0:
                    retry_at = max(retry_at or now, float(reset) + 1.0)
                    reason = "rate-limit reset"
            except ValueError:
                pass
        limited = status in (429, 503) or (status == 403 and any(
            term in body.decode("utf-8", errors="replace").lower()
            for term in ("secondary rate limit", "abuse detection")
        ))
        if limited:
            settings = self.settings_for(url)
            with self._lock:
                # Headers and the 403 body can report the same response twice.
                current = self._cooldowns.get(origin)
                if current is None or current[0] <= now:
                    self._strikes[origin] = min(self._strikes.get(origin, 0) + 1, 16)
                strikes = max(1, self._strikes.get(origin, 1))
            delay = min(float(settings["backoff_max_seconds"]),
                        float(settings["backoff_base_seconds"]) * 2 ** (strikes - 1))
            retry_at = max(retry_at or now, now + delay)
            reason = reason or f"HTTP {status}"
        elif 200 <= status < 400 and retry_at is None:
            with self._lock:
                current = self._cooldowns.get(origin)
                had_strikes = bool(self._strikes.get(origin)) and (current is None or current[0] <= now)
                if had_strikes:
                    self._strikes[origin] = 0
            if had_strikes:
                self._set_cooldown(origin, now, "recovered", status)
        if retry_at is None or retry_at <= now:
            return
        self._set_cooldown(origin, retry_at, reason, status)

    def transport_failure(self, url: str) -> None:
        """Pause this origin after connection failures; other origins keep running."""
        origin, _ = _origin_credential(url, None)
        self._set_cooldown(origin, time.time() + 60.0, "temporary connection failure", 0)

    def _set_cooldown(self, origin: str, retry_at: float, reason: str, status: int) -> None:
        with self._lock:
            current = self._cooldowns.get(origin)
            if current and current[0] > retry_at:
                retry_at, reason = current
            self._cooldowns[origin] = (retry_at, reason)
        # Publish in memory immediately, even if another writer is blocked on
        # storage. Serialize persistence and re-read the latest snapshot so an
        # older writer cannot overwrite a newer, longer cooldown.
        with self._persist_lock:
            with self._lock:
                retry_at, reason = self._cooldowns[origin]
            if self.persist is not None:
                # Persistence failure is an error, never a silent loss on restart.
                self.persist.set_runtime_status(
                    f"{_COOLDOWN_PREFIX}{origin}",
                    {"until": retry_at, "reason": reason, "status": status, "strikes": self._strikes.get(origin, 0)},
                )


def _origin_credential(url: str, headers: dict[str, str] | None) -> tuple[str, str]:
    parsed = urlparse(url)
    origin = f"{parsed.scheme}://{parsed.netloc}".lower()
    authorization = header(headers or {}, "authorization") or ""
    return origin, authorization


def _parse_retry_after(value: str) -> float | None:
    value = value.strip()
    try:
        return time.time() + float(value)
    except ValueError:
        pass
    try:
        parsed = parsedate_to_datetime(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    except (TypeError, ValueError):
        return None


class HttpClient:
    def __init__(self, user_agent: str = "Sentinal-Pro/0.1", budget: RequestBudget | None = None):
        self.user_agent = user_agent
        self.budget = budget
        self.cancel_event = None
        self._request_scope = threading.local()
        self.timeout = budget.request_timeout_seconds if budget else 15.0
        self.max_response_bytes = budget.max_response_bytes if budget else 16 * 1024 * 1024
        self._transport = None
        self._transport_lock = threading.Lock()

    def get_json(self, url: str, headers: dict[str, str] | None = None) -> JsonResponse:
        request_headers = {"Accept": "application/json", "User-Agent": self.user_agent}
        request_headers.update(headers or {})
        return self._request_json(url, request_headers)

    def get_text(self, url: str, headers: dict[str, str] | None = None) -> TextResponse:
        request_headers = {"Accept": "text/html", "User-Agent": self.user_agent}
        request_headers.update(headers or {})
        request = Request(url, headers=request_headers, method="GET")
        self._acquire(url, request_headers)
        try:
            with self._open(request) as response:
                charset = response.headers.get_content_charset() or "utf-8"
                return TextResponse(
                    response.status,
                    self._read_body(response, url).decode(charset, errors="replace"),
                    dict(response.headers.items()),
                )
        except HTTPError as error:
            body = self._read_body(error, url)
            if error.code == 403:
                self._observe(url, error.code, dict(error.headers.items()), body)
            if error.code == 304:
                return TextResponse(304, None, dict(error.headers.items()))
            self._maybe_defer(url)
            detail = body.decode("utf-8", errors="replace")[:500]
            raise HttpStatusError(error.code, url, detail) from error
        except URLError as error:
            if self.budget is not None:
                self.budget.transport_failure(url)
            raise RuntimeError(f"Unable to reach {url}: {error.reason}") from error
        finally:
            self._release()

    def post_json(self, url: str, payload: Any, headers: dict[str, str] | None = None) -> JsonResponse:
        request_headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": self.user_agent,
        }
        request_headers.update(headers or {})
        request = Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers=request_headers,
            method="POST",
        )
        self._acquire(url, request_headers)
        try:
            with self._open(request) as response:
                body = self._read_body(response, url).decode("utf-8")
                return JsonResponse(response.status, json.loads(body), dict(response.headers.items()))
        except HTTPError as error:
            body = self._read_body(error, url)
            if error.code == 403:
                self._observe(url, error.code, dict(error.headers.items()), body)
            self._maybe_defer(url)
            raise RuntimeError(f"JSON-RPC request failed for {url}: {error}") from error
        except URLError as error:
            if self.budget is not None:
                self.budget.transport_failure(url)
            raise RuntimeError(f"JSON-RPC request failed for {url}: {error}") from error
        finally:
            self._release()

    def _request_json(self, url: str, request_headers: dict[str, str]) -> JsonResponse:
        request = Request(url, headers=request_headers, method="GET")
        self._acquire(url, request_headers)
        try:
            with self._open(request) as response:
                body = self._read_body(response, url).decode("utf-8")
                return JsonResponse(response.status, json.loads(body), dict(response.headers.items()))
        except HTTPError as error:
            body = self._read_body(error, url)
            if error.code == 403:
                self._observe(url, error.code, dict(error.headers.items()), body)
            if error.code == 304:
                return JsonResponse(304, None, dict(error.headers.items()))
            self._maybe_defer(url)
            detail = body.decode("utf-8", errors="replace")[:500]
            raise HttpStatusError(error.code, url, detail) from error
        except URLError as error:
            if self.budget is not None:
                self.budget.transport_failure(url)
            raise RuntimeError(f"Unable to reach {url}: {error.reason}") from error
        finally:
            self._release()

    def close(self) -> None:
        with self._transport_lock:
            if self._transport is not None:
                self._transport.close()
                self._transport = None

    def _open(self, request: Request):
        # Only network schemes may reach the transport; file/data/ftp would read
        # local resources instead of the remote API a caller believes it uses.
        if request.type not in ("http", "https"):
            raise ValueError(f"Unsupported URL scheme: {request.type or '(none)'}")
        self._check_scope(request.full_url)
        deadline = time.monotonic() + self.timeout
        scope_deadline = getattr(self._request_scope, 'deadline', None)
        if scope_deadline is not None:
            deadline = min(deadline, scope_deadline)
        with self._transport_lock:
            if self._transport is None:
                self._transport = NetworkTransport(self.budget.max_concurrent if self.budget else 4)
            transport = self._transport
        try:
            return transport.request(request, deadline, self.cancel_event,
                on_headers=lambda status, headers: self._observe(request.full_url, status, headers),
                max_response_bytes=self.max_response_bytes)
        except NetworkBusy as error:
            raise RequestDeferred(_origin_credential(request.full_url, None)[0], time.time()+1, 'network concurrency limit') from error
        except NetworkCancelled as error:
            raise RequestDeferred(_origin_credential(request.full_url, None)[0], time.time()+60, 'scheduler stopping') from error
        except NetworkDeadline as error:
            if scope_deadline is not None and scope_deadline <= deadline:
                reason = 'check time budget'
            else:
                reason = 'request time budget'
                if self.budget is not None:
                    self.budget.transport_failure(request.full_url)
            raise RequestDeferred(_origin_credential(request.full_url, None)[0], time.time()+60, reason) from error

    def _read_body(self, response: Any, url: str) -> bytes:
        chunks = []
        total_bytes = 0
        read = getattr(response, 'read1', None)
        if not callable(read):
            stream = getattr(response, 'fp', None)
            read = getattr(stream, 'read1', None)
        if not callable(read):
            read = response.read
        while True:
            timeout = self._remaining_timeout(url)
            # urllib's HTTPResponse owns a buffered socket. Refresh its timeout
            # after headers and between chunks, rather than granting each read
            # the timeout that was calculated before opening the response.
            stream = getattr(response, 'fp', None)
            if not hasattr(stream, 'raw'):
                stream = getattr(stream, 'fp', None)
            transport = getattr(getattr(stream, 'raw', None), '_sock', None)
            if transport is not None:
                transport.settimeout(timeout)
            try:
                chunk = read(65536)
            except TimeoutError:
                self._check_scope(url)
                raise
            self._check_scope(url)
            if not chunk:
                return b''.join(chunks)
            total_bytes += len(chunk)
            if total_bytes > self.max_response_bytes:
                raise NetworkResponseTooLarge(f'response exceeds {self.max_response_bytes} byte limit')
            chunks.append(chunk)

    def _remaining_timeout(self, url: str) -> float:
        self._check_scope(url)
        deadline = getattr(self._request_scope, 'deadline', None)
        if deadline is None:
            return self.timeout
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RequestDeferred(_origin_credential(url, None)[0], time.time() + 60, 'check time budget')
        return min(self.timeout, remaining)

    def _check_scope(self, url: str) -> None:
        deadline = getattr(self._request_scope, 'deadline', None)
        if deadline is not None and time.monotonic() >= deadline:
            raise RequestDeferred(_origin_credential(url, None)[0], time.time() + 60, 'check time budget')
        if self.cancel_event is not None and self.cancel_event.is_set():
            raise RequestDeferred(_origin_credential(url, None)[0], time.time() + 60, 'scheduler stopping')

    @contextmanager
    def request_scope(self, seconds: float = 45.0):
        previous = getattr(self._request_scope, "deadline", None)
        deadline = time.monotonic() + seconds
        self._request_scope.deadline = min(previous, deadline) if previous is not None else deadline
        try:
            yield
        finally:
            self._request_scope.deadline = previous

    def _acquire(self, url: str, headers: dict[str, str]) -> None:
        self._check_scope(url)
        if self.budget is not None:
            self.budget.acquire(url, headers)

    def _release(self) -> None:
        if self.budget is not None:
            self.budget.release()

    def _observe(self, url: str, status: int, headers: dict[str, str], body: bytes = b"") -> None:
        if self.budget is not None:
            self.budget.observe(url, status, headers, body)

    def _maybe_defer(self, url: str) -> None:
        """After a response that imposed a cooldown, fail as a deferral (carrying
        the retry time) instead of a plain error — the request budget governs."""
        if self.budget is None:
            return
        origin, _credential = _origin_credential(url, None)
        until = self.budget.cooldown_until(origin)
        if until is not None and until > time.time():
            raise RequestDeferred(origin, until, "rate limited")
