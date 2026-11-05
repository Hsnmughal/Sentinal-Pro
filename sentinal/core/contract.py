from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

from .models import EventCandidate


SCHEMA_VERSION = "1.0"

#: Shared vocabulary every adapter's event kinds are tagged with. Correlation rules in
#: :mod:`sentinal.core.scoring` match on these tags rather than on platform kind names,
#: so a new platform participates in correlation by declaring tags alone.
TAGS: frozenset[str] = frozenset(
    {
        "repository_activity",
        "release_boundary",
        "production_diff",
        "implementation_upgrade",
        "program_lifecycle",
        "scope",
        "impact",
        "reward_ceiling",
        "reward_tier",
        "fee",
        "policy",
    }
)

PRIORITY = "priority"
FIXED = "fixed"
_POLLING_MODES = frozenset({PRIORITY, FIXED})


class ContractError(ValueError):
    """An adapter violates the platform contract."""


@dataclass(frozen=True, slots=True)
class EventKindSpec:
    """What core needs to know about one event kind an adapter can emit.

    ``label`` is the contract field: the kind's human text. ``reason`` and ``phrase``
    optionally refine the wording shown in "why it scores" and in the review queue;
    each falls back to ``label``.
    """

    score: int
    label: str
    ui_group: str
    ui_chip: str
    tags: tuple[str, ...] = ()
    reason: str = ""
    phrase: str = ""

    def __post_init__(self) -> None:
        if not self.reason:
            object.__setattr__(self, "reason", self.label)
        if not self.phrase:
            object.__setattr__(self, "phrase", self.label)


@dataclass(frozen=True, slots=True)
class PollingSpec:
    """How often this source is polled and how its per-protocol config is shaped.

    ``release_checks`` asks orchestration to schedule a second, slower job per
    target (``job_kind="release"``) so release boundary checks run at their own
    cadence instead of on every code poll.
    """

    mode: str = PRIORITY
    fixed_interval_seconds: int = 3600
    config_is_list: bool = False
    release_checks: bool = False
    manual_only: bool = False

    def interval_for(
        self,
        priority_intervals: Mapping[str, int],
        priority: str,
        override: int | None = None,
    ) -> int:
        from ..config import positive_interval
        if override is not None:
            return positive_interval(override)
        if self.mode == FIXED:
            return positive_interval(self.fixed_interval_seconds)
        return positive_interval(priority_intervals[priority])


@dataclass(frozen=True, slots=True)
class GlobalJobSpec:
    """An optional platform-wide job (such as a catalogue sync) with no protocol."""

    key: str
    label: str
    interval_seconds: int
    enabled_by_default: bool = True


@dataclass(frozen=True, slots=True)
class Manifest:
    """Declarative platform description, loaded from ``adapters/<name>/adapter.toml``."""

    schema_version: str
    platform: str
    source_type: str
    config_key: str
    label: str
    url_hosts: tuple[str, ...]
    polling: PollingSpec = field(default_factory=PollingSpec)
    policy_payload: bool = False
    catalog_source: bool = False
    global_job: GlobalJobSpec | None = None
    shared_kinds: tuple[str, ...] = ()
    event_kinds: Mapping[str, EventKindSpec] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class PollContext:
    """Everything a poll may depend on. Nothing else is in scope.

    ``target`` is the one monitoring target this poll covers
    (``{"target_key": ..., "config": ...}``) and ``programs`` are the watched
    programs that currently need it: one poll of a shared target distributes its
    observations to every associated program. ``job_kind`` is ``"poll"`` for the
    regular check and ``"release"`` for the slower release-boundary check.
    ``protocol``/``config`` describe the primary program and remain the simple
    single-program entry point for adapters that never see shared targets.
    """

    store: Any
    protocol: Mapping[str, Any]
    config: Any
    client: Any
    source_type: str
    source_key: str
    target: Mapping[str, Any] | None = None
    programs: tuple[Mapping[str, Any], ...] = ()
    job_kind: str = "poll"


@dataclass(frozen=True, slots=True)
class GlobalContext:
    """Everything a platform-wide poll may depend on."""

    store: Any
    client: Any
    settings: Mapping[str, Any]


PollFunction = Callable[[PollContext], list[EventCandidate]]
GlobalFunction = Callable[[GlobalContext], tuple[dict[str, int], list[EventCandidate]]]

#: Optional adapter behaviour: split one per-program source config into individually
#: pollable monitoring targets. Each entry is ``(target_key, target_config)`` where
#: ``target_key`` identifies the target across programs (so a repository shared by
#: several programs stays polled while any of them is active) and ``target_config``
#: is a config value the adapter's ``poll`` accepts on its own. Without this hook a
#: list config yields one target per entry and any other config yields one target.
TargetDeriver = Callable[[Any], list[tuple[str, Any]]]

#: Optional adapter behaviour: given a normalised policy payload this adapter just
#: observed, suggest additional monitoring targets as
#: ``(source_type, target_key, target_config)`` triples. Suggested targets whose
#: ``source_type`` has no adapter are ignored, so a platform only ever creates
#: targets that something can actually poll.
TargetDiscoverer = Callable[[dict[str, Any]], list[tuple[str, str, dict[str, Any]]]]


def validate_manifest(manifest: Manifest) -> None:
    """Reject a manifest that breaks the contract. Fail loud at load, never at poll time."""
    if manifest.schema_version != SCHEMA_VERSION:
        raise ContractError(
            f"adapter {manifest.source_type!r} declares schema_version "
            f"{manifest.schema_version!r}; this core understands {SCHEMA_VERSION!r}"
        )
    for field_name in ("platform", "source_type", "config_key", "label"):
        if not str(getattr(manifest, field_name)).strip():
            raise ContractError(f"adapter manifest field {field_name!r} must not be empty")
    if manifest.polling.mode not in _POLLING_MODES:
        raise ContractError(
            f"adapter {manifest.source_type!r} polling.mode must be one of "
            f"{sorted(_POLLING_MODES)}, got {manifest.polling.mode!r}"
        )
    if manifest.polling.mode == FIXED and manifest.polling.fixed_interval_seconds <= 0:
        raise ContractError(
            f"adapter {manifest.source_type!r} polling.fixed_interval_seconds must be positive"
        )
    if not manifest.shared_kinds and not manifest.event_kinds:
        raise ContractError(
            f"adapter {manifest.source_type!r} declares no event kinds and no shared kind groups"
        )
    for name, spec in manifest.event_kinds.items():
        _validate_kind_spec(manifest.source_type, name, spec)
    if manifest.global_job is not None:
        if not manifest.global_job.key.strip():
            raise ContractError(f"adapter {manifest.source_type!r} global_job.key must not be empty")
        if manifest.global_job.interval_seconds <= 0:
            raise ContractError(
                f"adapter {manifest.source_type!r} global_job.interval_seconds must be positive"
            )


def _validate_kind_spec(source_type: str, name: str, spec: EventKindSpec) -> None:
    if not 0 <= spec.score <= 100:
        raise ContractError(f"{source_type}: kind {name!r} score must be 0..100, got {spec.score}")
    for field_name in ("label", "reason", "phrase", "ui_group", "ui_chip"):
        if not str(getattr(spec, field_name)).strip():
            raise ContractError(f"{source_type}: kind {name!r} field {field_name!r} must not be empty")
    unknown = [tag for tag in spec.tags if tag not in TAGS]
    if unknown:
        raise ContractError(
            f"{source_type}: kind {name!r} uses unknown tags {sorted(unknown)}; core knows {sorted(TAGS)}"
        )


def validate_kind(kind: str, kind_specs: Mapping[str, EventKindSpec]) -> EventKindSpec:
    """Return the spec for ``kind``, or fail loud if no adapter declared it."""
    spec = kind_specs.get(kind)
    if spec is None:
        raise ContractError(
            f"unknown event kind {kind!r}; event kinds must be declared by an adapter "
            f"(adapters/<platform>/adapter.toml) or a shared group in sentinal.core.kinds. "
            f"Declared kinds: {sorted(kind_specs)}"
        )
    return spec
