"""Adapter discovery and routing.

One lookup binds a platform to its behaviour, after which nothing in core branches on
the platform's name. Adding a platform means adding a package under
``sentinal.adapters`` — this module never changes.
"""

from __future__ import annotations

import importlib
import pkgutil
import tomllib
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from functools import lru_cache
from importlib import resources
from types import MappingProxyType
from typing import Any
from urllib.parse import urlparse

from .contract import (
    ContractError,
    EventKindSpec,
    GlobalFunction,
    GlobalJobSpec,
    Manifest,
    PollFunction,
    PollingSpec,
    TargetDeriver,
    TargetDiscoverer,
    validate_manifest,
)
from .kinds import SHARED_KIND_GROUPS


DEFAULT_PACKAGE = "sentinal.adapters"
MANIFEST_FILE = "adapter.toml"
BEHAVIOUR_MODULE = "adapter"

#: Target config key used when an adapter config yields exactly one target and the
#: adapter declares no ``derive_targets`` hook.
DEFAULT_TARGET_KEY = "default"

_SHARED_KIND_NAMES = frozenset(name for group in SHARED_KIND_GROUPS.values() for name in group)


class UnknownSourceError(LookupError):
    """No adapter provides the requested source type.

    Raised rather than silently falling back to another platform's behaviour, so a
    missing adapter is identified instead of being papered over.
    """


@dataclass(frozen=True, slots=True)
class Adapter:
    manifest: Manifest
    poll: PollFunction
    poll_global: GlobalFunction | None = None
    kinds: Mapping[str, EventKindSpec] = field(default_factory=dict)
    derive_targets: TargetDeriver | None = None
    discover_targets: TargetDiscoverer | None = None

    def split_targets(self, config: Any) -> list[tuple[str, Any]]:
        """One program's source config as individually pollable targets.

        Uses the adapter's ``derive_targets`` hook when declared; without it a list
        config yields one target per entry and any other config yields one target.
        """
        if self.derive_targets is not None:
            return list(self.derive_targets(config))
        if isinstance(config, list):
            return [(DEFAULT_TARGET_KEY, item) for item in config]
        return [(DEFAULT_TARGET_KEY, config)]


class Registry(Mapping[str, Adapter]):
    """All discovered adapters, keyed by ``manifest.source_type``."""

    def __init__(self, adapters: Iterable[Adapter]):
        by_type: dict[str, Adapter] = {}
        by_global_key: dict[str, Adapter] = {}
        by_host: dict[str, Adapter] = {}
        inline_owner: dict[str, str] = {}
        kinds: dict[str, EventKindSpec] = {}
        for adapter in adapters:
            manifest = adapter.manifest
            if manifest.source_type in by_type:
                raise ContractError(f"duplicate adapter source_type {manifest.source_type!r}")
            by_type[manifest.source_type] = adapter
            if manifest.global_job is not None:
                key = manifest.global_job.key
                if key in by_global_key:
                    other = by_global_key[key].manifest
                    raise ContractError(
                        f"global_job.key {key!r} is claimed by both {other.source_type!r} "
                        f"and {manifest.source_type!r}; global job keys must be unique"
                    )
                by_global_key[key] = adapter
            for host in manifest.url_hosts:
                host = host.lower()
                if host in by_host and by_host[host].manifest.source_type != manifest.source_type:
                    raise ContractError(f"url host {host!r} is claimed by two adapters")
                by_host[host] = adapter
            for name in manifest.event_kinds:
                owner = inline_owner.get(name)
                if owner is not None:
                    raise ContractError(
                        f"event kind {name!r} is declared inline by both {owner!r} and "
                        f"{manifest.source_type!r}; move it to a shared group in sentinal.core.kinds"
                    )
                inline_owner[name] = manifest.source_type
            for name, spec in adapter.kinds.items():
                existing = kinds.get(name)
                if existing is not None and existing != spec:
                    raise ContractError(
                        f"event kind {name!r} is declared differently by two adapters; "
                        f"move it to a shared group in sentinal.core.kinds"
                    )
                kinds[name] = spec
        for key, adapter in by_global_key.items():
            if key in by_type:
                raise ContractError(
                    f"global_job.key {key!r} (adapter {adapter.manifest.source_type!r}) collides with "
                    f"an adapter source_type; poll_jobs.source_type must stay unique"
                )
        self._by_type = by_type
        self._by_global_key = by_global_key
        self._by_host = by_host
        self._kinds = MappingProxyType(kinds)

    def __getitem__(self, source_type: str) -> Adapter:
        try:
            return self._by_type[source_type]
        except KeyError:
            raise UnknownSourceError(
                f"no adapter named {source_type!r}; known adapters: {sorted(self._by_type)}. "
                f"Add sentinal/adapters/{source_type}/ rather than reusing another platform's rules."
            ) from None

    def __iter__(self) -> Iterator[str]:
        return iter(self._by_type)

    def __len__(self) -> int:
        return len(self._by_type)

    def source_types(self) -> tuple[str, ...]:
        return tuple(sorted(self._by_type))

    def kind_specs(self) -> Mapping[str, EventKindSpec]:
        return self._kinds

    def resolve_host(self, url: str) -> Adapter | None:
        """Route a program URL to its platform by registered URL host."""
        host = (urlparse(url).hostname or "").lower()
        if not host:
            return None
        for candidate in (host, host.removeprefix("www.")):
            if candidate in self._by_host:
                return self._by_host[candidate]
        return None

    def policy_adapters(self) -> tuple[Adapter, ...]:
        return tuple(adapter for adapter in self._by_type.values() if adapter.manifest.policy_payload)

    def policy_adapter_for_platform(self, platform: str) -> Adapter | None:
        """The policy adapter that publishes a platform's program pages, if any."""
        for adapter in self.policy_adapters():
            if adapter.manifest.platform == platform and adapter.manifest.catalog_source:
                return adapter
        for adapter in self.policy_adapters():
            if adapter.manifest.platform == platform:
                return adapter
        return None

    def catalog_adapters(self) -> tuple[Adapter, ...]:
        return tuple(adapter for adapter in self._by_type.values() if adapter.manifest.catalog_source)

    def global_jobs(self) -> tuple[tuple[Adapter, GlobalJobSpec], ...]:
        return tuple(
            (adapter, adapter.manifest.global_job)
            for adapter in self._by_type.values()
            if adapter.manifest.global_job is not None
        )

    def global_adapter(self, key: str) -> Adapter | None:
        return self._by_global_key.get(key)

    def policy_source_types(self) -> tuple[str, ...]:
        return tuple(adapter.manifest.source_type for adapter in self.policy_adapters())

    def policy_config_keys(self) -> tuple[str, ...]:
        return tuple(adapter.manifest.config_key for adapter in self.policy_adapters())

    def catalog_platforms(self) -> tuple[str, ...]:
        return tuple(adapter.manifest.platform for adapter in self.catalog_adapters())


def discover(package: str = DEFAULT_PACKAGE) -> Registry:
    """Load every adapter package under ``package`` and validate the set as a whole.

    ``pkgutil.iter_modules`` enumerates the package's subpackages, so every adapter is a
    regular package (``__init__.py``) carrying ``adapter.toml`` and ``adapter.py``.
    """
    namespace = importlib.import_module(package)
    paths = getattr(namespace, "__path__", None)
    if paths is None:
        raise ContractError(f"{package!r} is not a package of adapters")
    loaded = [
        _load_adapter(f"{package}.{info.name}")
        for info in sorted(pkgutil.iter_modules(paths), key=lambda info: info.name)
        if not info.name.startswith("_")
    ]
    return Registry(loaded)


@lru_cache(maxsize=1)
def default_registry() -> Registry:
    return discover()


def resolve_kinds(manifest: Manifest) -> Mapping[str, EventKindSpec]:
    """Merge the manifest's shared kind groups with its own event kinds."""
    kinds: dict[str, EventKindSpec] = {}
    for group_name in manifest.shared_kinds:
        group = SHARED_KIND_GROUPS.get(group_name)
        if group is None:
            raise ContractError(
                f"adapter {manifest.source_type!r} references unknown shared kind group "
                f"{group_name!r}; core defines {sorted(SHARED_KIND_GROUPS)}"
            )
        for name, spec in group.items():
            if name in kinds and kinds[name] != spec:
                raise ContractError(
                    f"adapter {manifest.source_type!r} shared groups disagree on kind {name!r}"
                )
            kinds[name] = spec
    for name, spec in manifest.event_kinds.items():
        if name in kinds:
            raise ContractError(
                f"adapter {manifest.source_type!r} redeclares shared kind {name!r} inline"
            )
        if name in _SHARED_KIND_NAMES:
            raise ContractError(
                f"adapter {manifest.source_type!r} declares inline kind {name!r}, which collides "
                f"with a shared kind group in sentinal.core.kinds; pull the group in with shared_kinds "
                f"instead of shadowing the shared vocabulary"
            )
        kinds[name] = spec
    return MappingProxyType(kinds)


def manifest_from_toml(data: dict[str, Any]) -> Manifest:
    raw_polling = data.get("polling") or {}
    raw_global = data.get("global_job") or None
    kinds: dict[str, EventKindSpec] = {}
    for name, raw in (data.get("event_kinds") or {}).items():
        kinds[str(name)] = EventKindSpec(
            score=int(raw["score"]),
            label=str(raw.get("label", "")),
            ui_group=str(raw["ui_group"]),
            ui_chip=str(raw["ui_chip"]),
            tags=tuple(str(tag) for tag in raw.get("tags", ())),
            reason=str(raw.get("reason", "")),
            phrase=str(raw.get("phrase", "")),
        )
    return Manifest(
        schema_version=str(data.get("schema_version", "")),
        platform=str(data.get("platform", "")),
        source_type=str(data.get("source_type", "")),
        config_key=str(data.get("config_key", data.get("source_type", ""))),
        label=str(data.get("label", "")),
        url_hosts=tuple(str(host).lower() for host in data.get("url_hosts", ())),
        polling=PollingSpec(
            mode=str(raw_polling.get("mode", "priority")),
            fixed_interval_seconds=int(raw_polling.get("fixed_interval_seconds", 3600)),
            config_is_list=bool(raw_polling.get("config_is_list", False)),
            release_checks=bool(raw_polling.get("release_checks", False)),
            manual_only=bool(raw_polling.get("manual_only", False)),
        ),
        policy_payload=bool(data.get("policy_payload", False)),
        catalog_source=bool(data.get("catalog_source", False)),
        global_job=(
            GlobalJobSpec(
                key=str(raw_global["key"]),
                label=str(raw_global["label"]),
                interval_seconds=int(raw_global["interval_seconds"]),
                enabled_by_default=bool(raw_global.get("enabled_by_default", True)),
            )
            if raw_global
            else None
        ),
        shared_kinds=tuple(str(name) for name in data.get("shared_kinds", ())),
        event_kinds=MappingProxyType(kinds),
    )


def _load_adapter(module_path: str) -> Adapter:
    package = importlib.import_module(module_path)
    try:
        raw = resources.files(package).joinpath(MANIFEST_FILE).read_text(encoding="utf-8")
    except FileNotFoundError:
        raise ContractError(f"{module_path} has no {MANIFEST_FILE}") from None
    manifest = manifest_from_toml(tomllib.loads(raw))
    validate_manifest(manifest)
    if manifest.source_type != module_path.rsplit(".", 1)[-1]:
        raise ContractError(
            f"{module_path} declares source_type {manifest.source_type!r}; "
            f"rename the package or the manifest so they agree"
        )
    behaviour = importlib.import_module(f"{module_path}.{BEHAVIOUR_MODULE}")
    poll = getattr(behaviour, "poll", None)
    if not callable(poll):
        raise ContractError(f"{module_path}.{BEHAVIOUR_MODULE} must define poll(context)")
    if manifest.global_job is not None and not callable(getattr(behaviour, "poll_global", None)):
        raise ContractError(
            f"{module_path} declares a global_job but {BEHAVIOUR_MODULE}.poll_global(context) is missing"
        )
    return Adapter(
        manifest=manifest,
        poll=poll,
        poll_global=getattr(behaviour, "poll_global", None),
        kinds=resolve_kinds(manifest),
        derive_targets=getattr(behaviour, "derive_targets", None),
        discover_targets=getattr(behaviour, "discover_targets", None),
    )
