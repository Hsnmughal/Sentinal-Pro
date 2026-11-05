from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class ReviewStatus(StrEnum):
    NEW = "new"
    WATCHING = "watching"
    AUDITING = "auditing"
    DISMISSED = "dismissed"
    RESOLVED = "resolved"


class ProgramLifecycle(StrEnum):
    """Monitoring lifecycle of a watched bounty program.

    ``relisted`` is deliberately not a state: relisting is the transition
    ``delisted``/``dismissed`` -> ``active`` (recorded in the program's transition
    history and signalled with a fresh event), after which the program is simply
    active again.
    """

    ACTIVE = "active"
    PAUSED = "paused"
    DELISTED = "delisted"
    DISMISSED = "dismissed"


@dataclass(frozen=True, slots=True)
class EventCandidate:
    """A change an adapter noticed.

    ``kind`` is a plain string rather than an enum member so that adding a platform
    never requires editing core. It is validated against the registry's declared
    kinds at insertion time by :func:`sentinal.core.contract.validate_kind`.
    """

    protocol_id: str
    source_key: str
    kind: str
    entity: str
    before: Any
    after: Any
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ScoredEvent:
    candidate: EventCandidate
    score: int
    reasons: tuple[str, ...]
    detected_at: str = field(default_factory=utc_now)
    #: "lead" (code/deployment/release movement) or "signal" (bounty change).
    category: str = ""
    #: Eligibility confidence classification, kept strictly separate from ``score``
    #: (which is research priority): one of ``confirmed_scoped``,
    #: ``potential_primacy``, ``unlisted_code``, ``unresolved_mapping`` or "".
    eligibility: str = ""
    #: Concrete evidence rows supporting ``eligibility`` (assets, paths, rules).
    evidence: tuple[Any, ...] = ()
    # The journal assigns a durable identity to each occurrence of a transition.
    observation_fingerprint: str | None = None


@dataclass(frozen=True, slots=True)
class SourceState:
    source_key: str
    protocol_id: str
    source_type: str
    cursor: str | None
    etag: str | None
    payload: Any
    updated_at: str
    program_id: int | None = None
