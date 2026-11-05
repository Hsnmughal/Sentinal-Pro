from __future__ import annotations



import html

import hashlib

import json

import sqlite3

import socket
import shutil
import socketserver
import tempfile
import threading
import time

from datetime import datetime, timezone
from http import HTTPStatus

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from importlib import resources

from typing import Any, Callable

from urllib.parse import parse_qs, urlparse



from .core.models import ReviewStatus

from .core.registry import Registry


from .scheduler import PollScheduler

from .store import Store

from .research import dossiers, profile, save_evidence, write_package, remove_patch_bodies, review_investigation, change_type





#: Fallback rendering for a kind no adapter declared. Declared kinds always win.

_FALLBACK_KIND = ("CHANGE", "CHANGED", "")



#: A scheduler that has published no drain pass inside this window is wedged.

HEALTH_LAST_PASS_STALE_SECONDS = 1800



#: A stalled ZIP reader must release its bounded request slot instead of pinning it.

ZIP_EXPORT_TIMEOUT_SECONDS = 60



#: Baseline headers for every body this server writes.

_SECURITY_HEADERS = (

    ("X-Content-Type-Options", "nosniff"),

    ("X-Frame-Options", "DENY"),

    ("Referrer-Policy", "no-referrer"),

    ("Content-Security-Policy",

     "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "

     "script-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"),

)



_ASSET_TYPES = {

    "dashboard.css": "text/css; charset=utf-8",

    "theme-header.css": "text/css; charset=utf-8",

    "theme-overview.css": "text/css; charset=utf-8",

    "theme-controls.css": "text/css; charset=utf-8",

    "theme-failures.css": "text/css; charset=utf-8",

    "theme-research.css": "text/css; charset=utf-8",

    "theme-dossier.css": "text/css; charset=utf-8",

    "theme-diff.css": "text/css; charset=utf-8",

    "theme-motion.css": "text/css; charset=utf-8",

    "dashboard.js": "application/javascript; charset=utf-8",

    "research.js": "application/javascript; charset=utf-8",

}





class LocalHTTPServer(ThreadingHTTPServer):

    # Local server still faces untrusted clients, even when bound to loopback.
    # Bound the number of live request threads and terminate stalled sockets.
    max_request_threads = 16
    request_timeout_seconds = 10

    def __init__(self, *args, **kwargs):
        self._request_slots = threading.BoundedSemaphore(self.max_request_threads)
        super().__init__(*args, **kwargs)

    def get_request(self):
        request, address = super().get_request()
        request.settimeout(self.request_timeout_seconds)
        return request, address

    def process_request(self, request, client_address):
        if not self._request_slots.acquire(blocking=False):
            try:
                request.sendall(
                    b"HTTP/1.1 503 Service Unavailable\r\n"
                    b"Content-Length: 0\r\nConnection: close\r\n"
                    b"Retry-After: 1\r\n\r\n"
                )
            except OSError:
                pass
            finally:
                self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._request_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._request_slots.release()

    allow_reuse_address = not hasattr(socket, "SO_EXCLUSIVEADDRUSE")



    def server_bind(self):

        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):

            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)

        # HTTPServer.server_bind resolves socket.getfqdn(host), a reverse DNS lookup
        # that runs after listen(). On hosts with a slow or unreachable resolver it
        # blocks for as long as the lookup takes, so the socket accepts nothing and
        # loopback clients time out. This server is loopback-only, so the bound host
        # is already the correct server name.
        socketserver.TCPServer.server_bind(self)

        host, port = self.server_address[:2]

        self.server_name = host

        self.server_port = port





def serve(store: Store, host: str, port: int, scheduler: PollScheduler | None = None,

          *, on_start: Callable[[], None] | None = None, onchain=None) -> None:

    handler = _handler(store, scheduler, onchain)

    server = LocalHTTPServer((host, port), handler)

    try:

        if on_start:

            on_start()

        print(f"Sentinal Pro listening on http://{host}:{server.server_port}")

        server.serve_forever()

    except KeyboardInterrupt:

        pass

    finally:

        server.server_close()





def _kind_labels(registry: Registry) -> dict[str, tuple[str, str, str]]:

    return {

        kind: (spec.ui_group, spec.ui_chip, spec.phrase)

        for kind, spec in registry.kind_specs().items()

    }





def _actions(registry: Registry) -> dict[str, str | None]:

    """Every dashboard action, derived from the adapters so buttons and routing cannot drift."""

    actions: dict[str, str | None] = {"poll-all": None}

    for source_type in registry.source_types():
        if registry[source_type].manifest.polling.manual_only:
            continue
        actions[f"poll-{source_type}"] = source_type

    for _adapter, job in registry.global_jobs():

        actions[f"sync-{job.key}"] = job.key

    return actions





def _static_asset(name: str) -> bytes:

    return resources.files("sentinal").joinpath("static", name).read_bytes()





def _loopback_host(host_header: str | None) -> bool:
    """Only loopback names reach this server, so DNS rebinding cannot read it."""
    try:
        hostname = urlparse(f"//{host_header or ''}").hostname
    except ValueError:
        hostname = None
    return hostname in ("127.0.0.1", "localhost", "::1")



def _handler(store: Store, scheduler: PollScheduler | None = None, onchain=None) -> type[BaseHTTPRequestHandler]:

    registry = store.adapters

    # Multiple request threads share one projection. Keeping full dossier data
    # only in the transient calculation avoids serving expensive patch payloads
    # or retaining them in memory between dashboard refreshes.
    program_cache_lock = threading.Lock()
    program_cache = {'revision': None, 'expires': 0.0, 'rows': None}
    summary_fields = (
        'id', 'name', 'platform', 'lifecycle', 'change_count',
        'open_change_count', 'scoped_change_count', 'latest_change',
        'priority', 'fit', 'unknowns', 'lead_count', 'activity_count',
        'unreviewed_investigation_count', 'signal_count',
        'code_change_count', 'program_change_count',
    )

    def program_summaries():
        # Version checks catch updates from the scheduler and from other Store
        # instances. The TTL also refreshes time-dependent priority heuristics.
        with program_cache_lock:
            version = store.programs_revision()
            now = time.monotonic()
            if (program_cache['rows'] is not None
                    and version == program_cache['revision']
                    and now < program_cache['expires']):
                return program_cache['rows']
            rows = dossiers(store)
            summaries = [
                {**{key: row[key] for key in summary_fields},
                 'max_bounty': row['policy'].get('max_bounty')}
                for row in rows
            ]
            # A concurrent write may have happened during the dossier read.
            # In that case do not cache a possibly inconsistent snapshot.
            current_version = store.programs_revision()
            if current_version == version:
                program_cache.update(revision=version,
                                     expires=time.monotonic() + 60,
                                     rows=summaries)
            else:
                program_cache.update(revision=None, expires=0.0, rows=None)
            return summaries

    class Handler(BaseHTTPRequestHandler):



        def do_GET(self) -> None:  # noqa: N802

            self._dispatch(self._get)



        def do_POST(self) -> None:  # noqa: N802

            self._dispatch(self._post)



        def _dispatch(self, action) -> None:

            try:

                if not _loopback_host(self.headers.get("Host")):

                    self.send_error(HTTPStatus.FORBIDDEN, "Requests must target this server by a loopback host name")

                    return

                action()

            except (BrokenPipeError, ConnectionResetError):

                return

            except (ValueError, TypeError, KeyError, json.JSONDecodeError) as error:

                self._json({"error": str(error)}, status=HTTPStatus.BAD_REQUEST)

            except sqlite3.Error:

                self.log_error("database request failed")

                self._json({"error": "Database temporarily unavailable; retry shortly"}, status=HTTPStatus.SERVICE_UNAVAILABLE)

            except Exception as error:

                self.log_error("request failed: %s", type(error).__name__)

                self._json({"error": "Request failed; check local server logs"}, status=HTTPStatus.INTERNAL_SERVER_ERROR)



        def send_error(self, code, message=None, explain=None):

            if urlparse(self.path).path.startswith("/api/"):

                self._json({"error": message or HTTPStatus(code).phrase}, status=code)

            else:

                super().send_error(code, message, explain)



        def _read_json(self) -> dict[str, Any]:

            length = int(self.headers.get("Content-Length", "0"))

            if length < 0 or length > 65536:

                raise ValueError("Request body must be at most 64 KiB")

            body = json.loads(self.rfile.read(length) or b"{}")

            if not isinstance(body, dict):

                raise ValueError("Request body must be a JSON object")

            return body



        def _get(self) -> None:

            parsed = urlparse(self.path)

            if parsed.path == "/favicon.ico":

                self._bytes(b"", "image/x-icon", HTTPStatus.NO_CONTENT)

                return

            if parsed.path == "/api/research/profile":

                self._json(profile(store))

                return

            if parsed.path == "/api/programs":

                rows = program_summaries()

                self._json({"programs": rows, "revision": store.programs_revision(), "stats": store.stats(), "change_stats": {"code": sum(row["code_change_count"] for row in rows if row["lifecycle"] == "active"), "program": sum(row["program_change_count"] for row in rows if row["lifecycle"] == "active")}, "investigation_stats": {"leads": sum(row["lead_count"] for row in rows if row["lifecycle"] == "active"), "signals": sum(row["signal_count"] for row in rows if row["lifecycle"] == "active")}})

                return

            research_path = [piece for piece in parsed.path.split("/") if piece]

            if len(research_path) in (3, 4) and research_path[:2] == ["api", "programs"]:

                pid = _event_id(research_path[2])

                if len(research_path) == 4 and research_path[3] != "package":

                    self.send_error(HTTPStatus.NOT_FOUND)

                    return

                rows = dossiers(store, pid)

                if not rows:

                    self.send_error(HTTPStatus.NOT_FOUND)

                    return

                if len(research_path) == 4:
                    self._zip_export(rows[0], f"file-diffs-{pid}.zip")
                else:
                    for event in rows[0]['changes']:
                        remove_patch_bodies(event)
                    self._json(rows[0])

                return

            if parsed.path == "/api/events":

                query = parse_qs(parsed.query)

                view = _first(query, "view")

                if view not in (None, "all", "lead", "signal", "baseline"):

                    raise ValueError("view must be all, lead, signal, or baseline")

                status = _first(query, "status")

                if status is not None:

                    status = ReviewStatus(status).value

                tab_name = _first(query, "tab")

                if tab_name not in (None, "to_review", "reviewed", "dismissed"):

                    raise ValueError("Unknown review tab")

                limit = int(_first(query, "limit") or "200")

                if not 1 <= limit <= 1000:

                    raise ValueError("limit must be between 1 and 1000")

                queue_revision = store.get_runtime_status('queue_revision') or 0

                events = store.list_events(status=status, protocol_id=_first(query, "protocol"),

                                          tab=tab_name, category=view, limit=limit,

                                          queue_only=_first(query, "projection") == "queue")

                self._json({"events": [{**remove_patch_bodies(event), "change_type": change_type(event, store.adapters.kind_specs())} for event in events], "stats": store.stats(), "queue_revision": queue_revision})

                return

            if parsed.path == "/api/health":

                # Scheduler failures cannot be masked by a responsive web thread.
                scheduler_running = scheduler.running if scheduler is not None else None
                scheduler_state = (scheduler._state.get("state", "unknown")
                                   if scheduler is not None else "not_configured")
                last_pass = store.get_runtime_status("last_scheduler_pass")
                checked_at = last_pass.get("checked_at") if isinstance(last_pass, dict) else None
                checked_at = checked_at if isinstance(checked_at, str) else None
                last_pass_age = _age_seconds(checked_at)
                healthy = scheduler is None or (scheduler_running and scheduler_state == "running")
                if healthy and scheduler is not None:
                    # A wedged drain loop keeps republishing 'running'. Fresh evidence
                    # is a completed pass or an idle loop that reached its wait, so a
                    # genuinely idle scheduler is not reported as stale.
                    idle_age = _age_seconds(getattr(scheduler, "_last_idle_at", None))
                    ages = [age for age in (last_pass_age, idle_age) if age is not None]
                    elapsed = min(ages) if ages else _age_seconds(scheduler._state.get("started_at"))
                    healthy = elapsed is None or elapsed <= HEALTH_LAST_PASS_STALE_SECONDS
                self._json({"status": "ok" if healthy else "degraded",
                            "scheduler": {"running": scheduler_running, "state": scheduler_state},
                            "last_pass_checked_at": checked_at,
                            "last_pass_age_seconds": last_pass_age,
                            "stats": store.stats()},
                           status=HTTPStatus.OK if healthy else HTTPStatus.SERVICE_UNAVAILABLE)

                return

            if parsed.path == "/api/status":

                self._json(_status_payload(store, scheduler, detailed=_first(parse_qs(parsed.query), "details") == "1"))

                return

            if parsed.path == "/api/catalog":

                self._json({"programs": store.list_catalog(_first(parse_qs(parsed.query), "platform"))})

                return

            if parsed.path == "/":

                self._html(_dashboard(store, scheduler))

                return

            pieces = [piece for piece in parsed.path.split("/") if piece]

            if len(pieces) == 2 and pieces[0] == "static" and pieces[1] in _ASSET_TYPES:

                try:

                    body = _static_asset(pieces[1])

                except (FileNotFoundError, ModuleNotFoundError):

                    self.send_error(HTTPStatus.NOT_FOUND)

                    return

                self._bytes(body, _ASSET_TYPES[pieces[1]])

                return

            if len(pieces) == 4 and pieces[:2] == ["api", "events"] and pieces[3] == "diffs":
                detail = store.get_event(_event_id(pieces[2]))
                if detail is None or change_type(detail, store.adapters.kind_specs()) != "code":
                    self.send_error(HTTPStatus.NOT_FOUND)
                    return
                self._zip_export(
                    {"name": detail.get("protocol_name") or detail["protocol_id"], "changes": [detail]},
                    f"change-{detail['id']}-diffs.zip",
                )
                return

            if (len(pieces) == 6 and pieces[:2] == ["api", "events"]
                    and pieces[3] == "files" and pieces[5] == "patch"):
                event_id = _event_id(pieces[2])
                file_index = _file_index(pieces[4])
                patch = store.event_file_patch(event_id, file_index)
                if patch is None:
                    self.send_error(HTTPStatus.NOT_FOUND)
                    return
                self._json({"patch": patch})
                return

            if len(pieces) == 3 and pieces[:2] == ["api", "events"]:

                try:

                    event_id = _event_id(pieces[2])

                except ValueError:

                    self.send_error(HTTPStatus.NOT_FOUND)

                    return

                detail = store.get_event(event_id)

                if detail is None:

                    self.send_error(HTTPStatus.NOT_FOUND)

                    return

                program = detail.pop("program", {})

                self._json({"event": {**remove_patch_bodies(detail), "change_type": change_type(detail, store.adapters.kind_specs())}, "program": program})

                return

            self.send_error(HTTPStatus.NOT_FOUND)



        def _post(self) -> None:

            origin = self.headers.get("Origin")

            if origin and urlparse(origin).netloc != self.headers.get("Host"):

                self._json({"error": "Cross-origin writes are not allowed"}, status=HTTPStatus.FORBIDDEN)

                return

            parsed = urlparse(self.path)

            pieces = [piece for piece in parsed.path.split("/") if piece]

            if len(pieces) == 4 and pieces[:2] == ['api', 'programs'] and pieces[3] == 'onchain':
                pid = _event_id(pieces[2])
                if store.get_program(pid) is None:
                    self.send_error(HTTPStatus.NOT_FOUND)
                    return
                if onchain is None:
                    self._json({'error': 'Manual checks are not available in this server.'}, status=HTTPStatus.CONFLICT)
                    return
                self._json({'queued': onchain.queue(pid), 'program_id': pid}, status=HTTPStatus.ACCEPTED)
                return



            if parsed.path == "/api/research/profile":

                self._json(profile(store, self._read_json()))

                return

            if len(pieces) == 5 and pieces[:2] == ["api", "programs"] and pieces[3] == "investigations":
                pid = _event_id(pieces[2])
                if store.get_program(pid) is None:
                    self.send_error(HTTPStatus.NOT_FOUND)
                    return
                try:
                    self._json({"review": review_investigation(store, pid, pieces[4], self._read_json())})
                except KeyError:
                    self.send_error(HTTPStatus.NOT_FOUND)
                return
            if len(pieces) == 4 and pieces[:2] == ["api", "programs"] and pieces[3] == "evidence":

                pid = _event_id(pieces[2])

                if store.get_program(pid) is None:

                    self.send_error(HTTPStatus.NOT_FOUND)

                    return

                save_evidence(store, pid, self._read_json())

                self._json({"saved": True})

                return

            if pieces[:2] == ["api", "actions"] and len(pieces) == 3:

                if scheduler is None:

                    self._json({"error": "automatic scheduler is not running"}, status=HTTPStatus.CONFLICT)

                    return

                if pieces[2] == "retry":

                    body = self._read_json()

                    job_key = body.get("job_key")

                    if not isinstance(job_key, str) or not job_key.strip():

                        raise ValueError("job_key is required")

                    queued = scheduler.force_job(job_key) if job_key else False

                    self._json(

                        {"queued": 1 if queued else 0, "action": "retry", "job_key": job_key,

                         **({} if queued else {"error": "Check is already running or no longer scheduled"})},

                        status=HTTPStatus.ACCEPTED if queued else HTTPStatus.CONFLICT

                        if any(job["job_key"] == job_key for job in store.list_jobs()) else HTTPStatus.NOT_FOUND,

                    )

                    return

                sources = _actions(registry)

                if pieces[2] not in sources:

                    self.send_error(HTTPStatus.NOT_FOUND)

                    return

                queued = scheduler.force(sources[pieces[2]])

                self._json({"queued": queued, "action": pieces[2]}, status=HTTPStatus.ACCEPTED)

                return

            if (len(pieces) == 6 and pieces[:2] == ["api", "events"]
                    and pieces[3] == "files" and pieces[5] == "patch"):
                event_id = _event_id(pieces[2])
                file_index = _file_index(pieces[4])
                event = store.get_event(event_id)
                if event is None:
                    self.send_error(HTTPStatus.NOT_FOUND)
                    return
                files = (event.get('metadata') or {}).get('changed_files') or []
                if file_index >= len(files) or not isinstance(files[file_index], dict):
                    self.send_error(HTTPStatus.NOT_FOUND)
                    return
                patch = files[file_index].get('patch')
                if not isinstance(patch, str) or not patch.strip():
                    self.send_error(HTTPStatus.NOT_FOUND)
                    return
                self._json({"patch": patch})
                return

            if len(pieces) == 3 and pieces[:2] == ["api", "events"]:

                try:

                    event_id = _event_id(pieces[2])

                    body = self._read_json()

                    status = ReviewStatus(body["status"]) if "status" in body else None

                    note = body.get("note")

                    if note is not None and (not isinstance(note, str) or len(note) > 20000):

                        raise ValueError("note must be a string of at most 20000 characters")

                    if status is None and note is None:

                        raise KeyError("status")

                    updated = store.update_event(

                        event_id,

                        status=status,

                        note=note,

                    )

                    if not updated:

                        self.send_error(HTTPStatus.NOT_FOUND)

                    else:

                        current = store.get_event(event_id) or {}

                        self._json(

                            {

                                "updated": True,

                                "id": event_id,

                                "status": current.get("status"),

                            }

                        )

                except (ValueError, KeyError, json.JSONDecodeError) as error:

                    self._json({"error": str(error)}, status=HTTPStatus.BAD_REQUEST)

                return

            self.send_error(HTTPStatus.NOT_FOUND)



        def log_message(self, format: str, *args: Any) -> None:

            print(f"{self.address_string()} - {format % args}")



        def _zip_export(self, dossier: dict, filename: str) -> None:
            # BytesIO previously retained the entire compressed export in RAM.
            # Under concurrent downloads this grew with each archive. Spooling
            # keeps only 1 MiB per request before switching to a temporary file.
            with tempfile.SpooledTemporaryFile(max_size=1024 * 1024, mode='w+b') as output:
                write_package(dossier, output, store.adapters.kind_specs())
                length = output.tell()
                output.seek(0)
                timeout = self.connection.gettimeout()
                self.connection.settimeout(ZIP_EXPORT_TIMEOUT_SECONDS)
                try:
                    self.send_response(HTTPStatus.OK)
                    self.send_header("Content-Type", "application/zip")
                    self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
                    self.send_header("Content-Length", str(length))
                    self.send_header("Cache-Control", "no-store")
                    self._security_headers()
                    self.end_headers()
                    shutil.copyfileobj(output, self.wfile, length=64 * 1024)
                except (TimeoutError, BrokenPipeError, ConnectionResetError):
                    # A reader that stops consuming must not hold a request slot
                    # or receive a second error page after the ZIP headers.
                    self.close_connection = True
                finally:
                    try:
                        self.connection.settimeout(timeout)
                    except OSError:
                        pass

        def _json(self, value: Any, status: HTTPStatus = HTTPStatus.OK) -> None:

            self._bytes(json.dumps(value, default=str).encode("utf-8"), "application/json; charset=utf-8", status)



        def _html(self, value: str) -> None:

            self._bytes(value.encode("utf-8"), "text/html; charset=utf-8")



        def _security_headers(self) -> None:

            for name, value in _SECURITY_HEADERS:

                self.send_header(name, value)



        def _bytes(

            self, data: bytes, content_type: str, status: HTTPStatus = HTTPStatus.OK

        ) -> None:

            self.send_response(status)

            self.send_header("Content-Type", content_type)

            self.send_header("Content-Length", str(len(data)))

            self.send_header("Cache-Control", "no-store")

            self._security_headers()

            self.end_headers()

            self.wfile.write(data)



    return Handler





def _status_payload(store: Store, scheduler: PollScheduler | None, *, detailed: bool = False) -> dict[str, Any]:

    payload = (

        scheduler.status(detailed=detailed)

        if scheduler

        else {

            "running": False,

            **({"jobs": store.list_jobs()} if detailed else {}),

            "configured_target_count": store.configured_target_count(),

            "runtime": store.runtime_status(),

        }

    )

    payload.setdefault("configured_target_count", sum(job.get("target_key") is not None for job in payload.get("jobs", [])))

    if 'sweep' not in payload:

        payload['sweep'] = store.sweep_summary()

    if 'failed' not in payload:

        payload['failed'] = store.list_failed_jobs()

    if not detailed:
        
        payload.pop("jobs", None)
        
        # The summary payload keeps only actionable rows (error/blocked, capped);
        # deferred checks wait automatically and remain represented by counts so
        # the 15 s poll does not ship hundreds of waiting rows. ?details=1 keeps
        # the only full list.
        failures = payload.get("failed") or []
        
        payload["failed_total"] = len(failures)
        
        payload["deferred_total"] = sum(1 for job in failures if job.get("last_status") == "deferred")
        
        payload["failed"] = [job for job in failures if job.get("last_status") in ("error", "blocked")][:50]
        
        keys = {"scheduler", "last_scheduler_pass", "github_rate_limit", "immunefi_catalog", "export_error", "reconcile_error", "queue_revision"}
        
        payload["runtime"] = {key: value for key, value in payload.get("runtime", {}).items() if key in keys}
        
    return payload





def _toolbar(registry: Registry, store: Store | None = None) -> str:

    """Polling controls. Rendered from the adapters, so a new platform gains its button

    without any change here."""

    enabled = {job["source_type"] for job in store.list_jobs()} if store else set(registry.source_types()) | {job.key for _, job in registry.global_jobs()}
    if store:
        enabled.update(row['source_type'] for row in store.blocked_targets())

    buttons = [

        f"""<button {"" if source_type in enabled else "disabled title='No configured targets'"} onclick="runAction('poll-{source_type}',this)">Poll {html.escape(registry[source_type].manifest.label)}</button>"""

        for source_type in registry.source_types() if not registry[source_type].manifest.polling.manual_only

    ]

    buttons.extend(

        f"""<button {"" if job.key in enabled else "disabled title='Job disabled in config'"} onclick="runAction('sync-{job.key}',this)">{html.escape(job.label)}</button>"""

        for _adapter, job in registry.global_jobs()

    )

    buttons.append("""<button class="primary" onclick="runAction('poll-all',this)">Poll all</button>""")

    return "".join(buttons)





def _stats_cards(stats: dict[str, Any], registry: Registry) -> str:

    cards = [_stat("Active programs", stats.get("programs_by_lifecycle", {}).get("active", 0), "active")]

    catalog_by_platform = stats.get("catalog_by_platform", {})

    for adapter in registry.catalog_adapters():

        cards.append(

            _stat(f"{adapter.manifest.label} catalogue", catalog_by_platform.get(adapter.manifest.platform, 0), f"catalog:{adapter.manifest.platform}")

        )

    cards.append(_stat("Code changes", "—", "code"))

    cards.append(_stat("Program changes", "—", "program"))

    return "".join(cards)





def _dashboard(store: Store, scheduler: PollScheduler | None = None) -> str:

    registry = store.adapters

    queue_revision = store.get_runtime_status('queue_revision') or 0

    stats = store.stats()

    kind_labels = _kind_labels(registry)

    manual_controls = f'<details class="manual-checks"><summary>Refresh sources</summary><div class="poll-actions">{_toolbar(registry, store)}</div></details>' if scheduler else ""

    kinds = json.dumps(kind_labels, separators=(",", ":"))

    theme_sheets = ("theme-header.css", "theme-overview.css", "theme-controls.css",
                    "theme-failures.css", "theme-research.css", "theme-dossier.css",
                    "theme-diff.css", "theme-motion.css")
    theme_links = "".join(
        '<link rel="stylesheet" href="/static/' + name + '?v='
        + hashlib.sha256(_static_asset(name)).hexdigest()[:12] + '">'
        for name in theme_sheets)

    return f"""<!doctype html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="theme-color" content="#0a0a0a">
<meta name="description" content="Sentinal Pro — local security program and source change monitoring workbench">
<title>Sentinal Pro | Research workbench</title>
<link rel="stylesheet" href="/static/dashboard.css?v={hashlib.sha256(_static_asset('dashboard.css')).hexdigest()[:12]}">
{theme_links}
</head>
<body>
<div class="app-shell">
<header class="app-header">
  <div class="brand">
    <span class="brand-mark" aria-hidden="true">S</span>
    <div class="brand-copy"><h1>Sentinal <b>PRO</b></h1><p>Security change intelligence</p></div>
  </div>
  <div class="header-aside">
    <div id="health" class="health" role="status" aria-live="polite"><i aria-hidden="true"></i> LOCAL MONITOR</div>
    <div class="theme-segmented" role="group" aria-label="Appearance">
      <button type="button" class="theme-btn" data-set-theme="dark" aria-pressed="true">Dark</button>
      <button type="button" class="theme-btn" data-set-theme="light" aria-pressed="false">Light</button>
    </div>
  </div>
</header>
<main id="main-content">
  <section class="overview" aria-label="Monitoring overview">
    <div class="overview-title">
      <p class="eyebrow">Research / Overview</p>
      <h2>Monitor what changes.<br>Investigate what matters.</h2>
      <p>Track code, deployments, and bounty policy changes in one evidence-led workspace.</p>
    </div>
    <section class="stats" aria-label="Program telemetry">{_stats_cards(stats, registry)}</section>
  </section>
  <section class="controls" aria-label="Monitoring controls">
    <div class="monitor-summary"><h2>Monitoring activity</h2><p id="scheduler-status" role="status">Loading scheduler status…</p><p id="scheduler-detail" class="scheduler-detail"></p></div>
    <div id="sweep" class="sweep" aria-label="Scheduled checks">Loading sweep summary…</div>
    {manual_controls}
  </section>
  <p id="action-status" role="status" aria-live="polite"></p>
  <div id="failures" class="drawer" aria-label="Check failures"></div>
  <section id="program-research" class="queue" aria-label="Program research">
    <div class="toolbar">
      <div><h2>Choose a program</h2><p class="section-desc">Browse monitored programs and review recorded evidence.</p></div>
      <div class="filter-footer"><p id="program-count" role="status">Loading programs…</p><button type="button" id="reset-program-filters">Reset filters</button></div>
    </div>
    <div class="research-filters" role="search" aria-label="Filter monitored programs">
      <input id="program-search" type="search" class="search" placeholder="Search programs… (⌘K or /)" aria-label="Find a program" autocomplete="off">
      <div class="filter-field"><label for="filter-chain">Chain</label><select id="filter-chain"><option value="">All chains</option></select></div>
      <div class="filter-field"><label for="filter-language">Language</label><select id="filter-language"><option value="">All languages</option></select></div>
      <div class="filter-field"><label for="filter-type">Protocol type</label><select id="filter-type"><option value="">All protocol types</option></select></div>
      <div class="filter-field"><label for="filter-investigation">Change type</label><select id="filter-investigation"><option value="">All changes</option><option value="code">Code changes</option><option value="program">Program changes</option></select></div>
      <div class="filter-field"><label for="filter-lifecycle">Program status</label><select id="filter-lifecycle"><option value="active">Active programs</option><option value="">All statuses</option></select></div>
      <label class="filter-toggle"><input id="filter-open" type="checkbox" checked><span>With changes</span></label>
      <label class="filter-toggle"><input id="filter-scoped" type="checkbox"><span>Scoped changes only</span></label>
      <div class="filter-field"><label for="program-sort">Sort programs</label><select id="program-sort"><option value="recent">Latest change</option><option value="count">Most changes</option><option value="reward">Reward ceiling</option></select></div>
    </div>
    <div class="panes" data-mobile-view="list">
      <div id="program-list" class="leads" aria-label="Programs"><p class="load-state" role="status">Loading programs…</p></div>
      <aside id="program-dossier" class="detail" tabindex="-1" aria-label="Program evidence">
        <div class="empty-dossier"><p>Select a program to inspect its evidence.</p><span>Use ↑/↓ or J/K to navigate, / to search, and T to switch theme.</span></div>
      </aside>
    </div>
  </section>
</main>
</div>
<script>window.KIND_LABELS={kinds};window.QUEUE_REVISION={queue_revision};</script>
<script src="/static/dashboard.js?v={hashlib.sha256(_static_asset('dashboard.js')).hexdigest()[:12]}"></script>
<script src="/static/research.js?v={hashlib.sha256(_static_asset('research.js')).hexdigest()[:12]}"></script>
</body>
</html>"""



def _stat(label: str, value: int, key: str = "") -> str:

    return f'<article data-stat="{html.escape(key)}"><span>{html.escape(label)}</span><strong>{value}</strong></article>'





def _first(query: dict[str, list[str]], key: str) -> str | None:

    values = query.get(key)

    return values[0] if values else None





def _int(value: str | None, default: int) -> int:

    try:

        return int(value) if value is not None else default

    except ValueError:

        return default





def _age_seconds(value: Any) -> int | None:
    """Age of a published ISO-8601 timestamp, or None when it cannot be read."""
    if not isinstance(value, str):
        return None
    try:
        moment = datetime.fromisoformat(value)
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return int(time.time() - moment.timestamp())



def _file_index(raw: str) -> int:
    if not raw.isascii() or not raw.isdecimal() or len(raw) > 6:
        raise ValueError("Invalid file index")
    value = int(raw)
    if value > 100000:
        raise ValueError("Invalid file index")
    return value


def _event_id(raw: str) -> int:

    value = int(raw)

    if value <= 0:

        raise ValueError("event id must be positive")

    return value
