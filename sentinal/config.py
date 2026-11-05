from __future__ import annotations

import os
import math
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


DEFAULT_HTTP_SOURCES = {
    "immunefi.com": {"min_spacing_seconds": 3.0, "jitter_seconds": 1.0,
                     "max_requests": 15, "window_seconds": 60, "max_concurrent": 1},
    "api.github.com": {},
}


DEFAULT_PRIORITY_INTERVALS = {"high": 600, "normal": 1800, "dormant": 10_800}


def positive_interval(value: Any, name: str = 'interval_seconds') -> int:
    try:
        interval = int(value)
    except (TypeError, ValueError, OverflowError) as error:
        raise ValueError(f'{name} must be a positive number of seconds') from error
    if isinstance(value, bool) or interval < 1:
        raise ValueError(f'{name} must be at least 1 second')
    return interval


def validate_intervals(value: Any, path: str = 'config') -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            name = f'{path}.{key}'
            if key == 'interval_seconds':
                positive_interval(item, name)
            else:
                validate_intervals(item, name)
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            validate_intervals(item, f'{path}[{index}]')


@dataclass(frozen=True, slots=True)
class AppConfig:
    path: Path
    database: Path
    server_host: str
    server_port: int
    correlation_window_hours: int
    scheduler_tick_seconds: int
    scheduler_max_retry_seconds: int
    priority_intervals: dict[str, int]
    global_jobs: dict[str, dict[str, Any]]
    protocols: tuple[dict[str, Any], ...]
    http_settings: dict[str, Any] = field(default_factory=dict)
    paused_interval_factor: int = 4
    release_interval_factor: int = 6
    export_directory: Path | None = None
    scheduler_batch_size: int = 12
    scheduler_max_workers: int = 3

    def __post_init__(self) -> None:
        sources = {host: dict(values) for host, values in DEFAULT_HTTP_SOURCES.items()}
        for host, values in (self.http_settings.get("sources") or {}).items():
            sources.setdefault(host.lower(), {}).update(values)
        object.__setattr__(self, "http_settings", {**self.http_settings, "sources": sources})
        for label, settings in [("polling.http", self.http_settings), *[(f"polling.http.sources.{host}", values) for host, values in sources.items()]]:
            for key in ("min_spacing_seconds", "jitter_seconds", "max_requests", "window_seconds", "max_concurrent", "backoff_base_seconds", "backoff_max_seconds"):
                if key not in settings:
                    continue
                try:
                    number = float(settings[key])
                except (TypeError, ValueError) as error:
                    raise ValueError(f"{label}.{key} must be numeric") from error
                minimum = 0 if key in ("min_spacing_seconds", "jitter_seconds") else 1
                if isinstance(settings[key], bool) or not math.isfinite(number) or number < minimum:
                    raise ValueError(f"{label}.{key} must be finite and at least {minimum}")
                if key in ("max_requests", "max_concurrent") and not number.is_integer():
                    raise ValueError(f"{label}.{key} must be an integer")
        # A large or malformed response must not exhaust network worker memory.
        limit = self.http_settings.get("max_response_bytes", 16 * 1024 * 1024)
        if (isinstance(limit, bool) or not isinstance(limit, int)
                or not 65536 <= limit <= 64 * 1024 * 1024):
            raise ValueError("polling.http.max_response_bytes must be an integer between 65536 and 67108864")
        for name, value in self.priority_intervals.items():
            positive_interval(value, f'priority_intervals.{name}')
        validate_intervals(self.global_jobs, 'global_jobs')
        validate_intervals(self.protocols, 'protocols')
        for protocol in self.protocols:
            if not isinstance(protocol, dict):
                continue
            priority = str(protocol.get('priority', 'normal')).lower()
            if priority not in self.priority_intervals:
                raise ValueError(
                    f"protocol {protocol.get('id')!r} uses unknown priority {priority!r}; "
                    f"expected one of {sorted(self.priority_intervals)}"
                )


def load_config(path: str | os.PathLike[str]) -> AppConfig:
    config_path = Path(path).resolve()
    _load_dotenv(config_path.parent / ".env")
    with config_path.open("rb") as handle:
        raw = tomllib.load(handle)
    validate_intervals(raw)

    protocols = tuple(raw.get("protocols", ()))
    seen: set[str] = set()
    for protocol in protocols:
        protocol_id = str(protocol.get("id", "")).strip()
        if not protocol_id:
            raise ValueError("Every [[protocols]] entry requires a non-empty id")
        if protocol_id in seen:
            raise ValueError(f"Duplicate protocol id: {protocol_id}")
        seen.add(protocol_id)

    database_value = Path(raw.get("database", "sentinal.db"))
    if not database_value.is_absolute():
        database_value = config_path.parent / database_value

    server = raw.get("server", {})
    polling = raw.get("polling", {})
    scheduler = raw.get("scheduler", {})
    priority_intervals = scheduler.get("priority_intervals", {})
    export = raw.get("export", {})
    export_directory = export.get("directory", "platforms")
    if export_directory:
        export_directory = Path(export_directory)
        if not export_directory.is_absolute():
            export_directory = config_path.parent / export_directory
    return AppConfig(
        path=config_path,
        database=database_value.resolve(),
        server_host=str(server.get("host", "127.0.0.1")),
        server_port=int(server.get("port", 8080)),
        correlation_window_hours=int(polling.get("correlation_window_hours", 168)),
        scheduler_tick_seconds=max(5, int(scheduler.get("tick_seconds", 60))),
        scheduler_max_retry_seconds=max(60, int(scheduler.get("max_retry_seconds", 900))),
        priority_intervals={
            name: int(priority_intervals.get(name, seconds))
            for name, seconds in DEFAULT_PRIORITY_INTERVALS.items()
        },
        global_jobs={
            str(key): dict(value) for key, value in (raw.get("global_jobs") or {}).items()
        },
        protocols=protocols,
        http_settings=dict(polling.get("http") or {}),
        paused_interval_factor=max(1, int(polling.get("paused_interval_factor", 4))),
        release_interval_factor=max(1, int(polling.get("release_interval_factor", 6))),
        export_directory=export_directory.resolve() if export_directory else None,
        scheduler_batch_size=max(1, min(100, int(scheduler.get("batch_size", 12)))),
        scheduler_max_workers=max(1, min(4, int(scheduler.get("max_workers", 3)))),
    )


def _load_dotenv(path: Path) -> None:
    """Load simple KEY=VALUE entries without overriding the process environment."""
    if not path.is_file():
        return
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            raise ValueError(f"Invalid .env entry at line {line_number}")
        key, value = line.split("=", 1)
        key = key.strip()
        if not key or not key.replace("_", "a").isalnum() or key[0].isdigit():
            raise ValueError(f"Invalid .env variable name at line {line_number}")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        os.environ.setdefault(key, value)
