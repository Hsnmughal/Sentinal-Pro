"""Shared event-kind groups.

Kinds emitted by platform-agnostic domain logic live here. A platform pulls a group
in with ``shared_kinds`` in its ``adapter.toml`` instead of forking the definitions,
so two platforms that share the same domain speak the same event vocabulary.

Kinds unique to one platform stay in that platform's ``adapter.toml``.
"""

from __future__ import annotations

from .contract import EventKindSpec, _validate_kind_spec


#: Emitted by :mod:`sentinal.core.bounty_policy` whenever a normalised bounty policy
#: diff produces a change. Any platform that publishes a bounty policy shares this.
BOUNTY_POLICY_KINDS: dict[str, EventKindSpec] = {
    "BOUNTY_SCOPE_ADDED": EventKindSpec(
        score=45,
        label="asset entered published bounty scope",
        ui_group="SCOPE CHANGE",
        ui_chip="ADDED",
        tags=("scope",),
    ),
    "BOUNTY_SCOPE_REMOVED": EventKindSpec(
        score=30,
        label="asset left published bounty scope",
        ui_group="SCOPE CHANGE",
        ui_chip="REMOVED",
        tags=("scope",),
    ),
    "BOUNTY_SCOPE_UPDATED": EventKindSpec(
        score=35,
        label="scoped asset redefined in published bounty scope",
        ui_group="SCOPE CHANGE",
        ui_chip="UPDATED",
        tags=("scope",),
    ),
    "BOUNTY_IMPACT_ADDED": EventKindSpec(
        score=30,
        label="new eligible security impact",
        ui_group="IMPACT CHANGE",
        ui_chip="ADDED",
        tags=("impact",),
    ),
    "BOUNTY_IMPACT_REMOVED": EventKindSpec(
        score=25,
        label="eligible security impact removed",
        ui_group="IMPACT CHANGE",
        ui_chip="REMOVED",
        tags=("impact",),
    ),
    "BOUNTY_IMPACT_UPDATED": EventKindSpec(
        score=20,
        label="eligible security impact redefined",
        ui_group="IMPACT CHANGE",
        ui_chip="UPDATED",
        tags=("impact",),
    ),
    "BOUNTY_MAX_INCREASED": EventKindSpec(
        score=25,
        label="maximum bounty increased",
        ui_group="REWARD CHANGE",
        ui_chip="RAISED",
        tags=("reward_ceiling",),
    ),
    "BOUNTY_MAX_DECREASED": EventKindSpec(
        score=20,
        label="maximum bounty decreased",
        ui_group="REWARD CHANGE",
        ui_chip="LOWERED",
        tags=("reward_ceiling",),
    ),
    "BOUNTY_REWARD_INCREASED": EventKindSpec(
        score=20,
        label="reward increased",
        ui_group="REWARD CHANGE",
        ui_chip="RAISED",
        tags=("reward_tier",),
    ),
    "BOUNTY_REWARD_DECREASED": EventKindSpec(
        score=15,
        label="reward decreased",
        ui_group="REWARD CHANGE",
        ui_chip="LOWERED",
        tags=("reward_tier",),
    ),
    "BOUNTY_FEE_CHANGED": EventKindSpec(
        score=15,
        label="submission fee changed",
        ui_group="FEE CHANGE",
        ui_chip="CHANGED",
        tags=("fee",),
    ),
    "BOUNTY_PROGRAM_PAUSED": EventKindSpec(
        score=35,
        label="bug-bounty program paused",
        reason="bounty program paused",
        ui_group="PROGRAM STATUS",
        ui_chip="PAUSED",
        tags=("program_lifecycle",),
    ),
    "BOUNTY_PROGRAM_RESUMED": EventKindSpec(
        score=25,
        label="bug-bounty program resumed",
        reason="bounty program resumed",
        ui_group="PROGRAM STATUS",
        ui_chip="RESUMED",
        tags=("program_lifecycle",),
    ),
    "BOUNTY_POLICY_CHANGED": EventKindSpec(
        score=10,
        label="bounty policy changed",
        ui_group="PROGRAM STATUS",
        ui_chip="POLICY",
        tags=("policy",),
    ),
}

#: Emitted when a platform's published catalogue of programs gains, loses or restores
#: an entry. Any platform that publishes a catalogue shares this.
PROGRAM_LIFECYCLE_KINDS: dict[str, EventKindSpec] = {
    "BOUNTY_PROGRAM_CREATED": EventKindSpec(
        score=20,
        label="bug-bounty program listed",
        reason="bounty program first observed",
        ui_group="PROGRAM STATUS",
        ui_chip="ADDED",
        tags=("program_lifecycle",),
    ),
    "BOUNTY_PROGRAM_DELISTED": EventKindSpec(
        score=30,
        label="program delisted",
        reason="bounty program delisted",
        ui_group="PROGRAM STATUS",
        ui_chip="REMOVED",
        tags=("program_lifecycle",),
    ),
    "BOUNTY_PROGRAM_RELISTED": EventKindSpec(
        score=25,
        label="program relisted",
        reason="bounty program relisted",
        ui_group="PROGRAM STATUS",
        ui_chip="RELISTED",
        tags=("program_lifecycle",),
    ),
}

SHARED_KIND_GROUPS: dict[str, dict[str, EventKindSpec]] = {
    "bounty_policy": BOUNTY_POLICY_KINDS,
    "program_lifecycle": PROGRAM_LIFECYCLE_KINDS,
}

#: Tags that make an event a research *lead* (code, deployment or release movement).
#: Every other kind — bounty scope, impact, fee, reward, rule and lifecycle change —
#: is a *signal*. Categories follow from tags alone, so a new platform's kinds land
#: in the right view without editing this table.
LEAD_TAGS: frozenset[str] = frozenset(
    {
        "repository_activity",
        "release_boundary",
        "production_diff",
        "implementation_upgrade",
    }
)

LEAD = "lead"
SIGNAL = "signal"


def category_for_tags(tags: tuple[str, ...] | frozenset[str]) -> str:
    return LEAD if LEAD_TAGS.intersection(tags) else SIGNAL

#: Which program-lifecycle state a committed event implies, keyed by shared event
#: kind. Storage applies these while committing the event, so the queue item and the
#: watched-program state can never drift apart. Kinds absent from this map have no
#: lifecycle meaning (code-change leads, reward tiers, ...).
LIFECYCLE_STATE_BY_KIND: dict[str, str] = {
    "BOUNTY_PROGRAM_CREATED": "active",
    "BOUNTY_PROGRAM_RELISTED": "active",
    "BOUNTY_PROGRAM_DELISTED": "delisted",
    "BOUNTY_PROGRAM_PAUSED": "paused",
    "BOUNTY_PROGRAM_RESUMED": "active",
}

#: Kinds that leave a "removal item" in the review queue. The item stays until it is
#: dismissed; dismissing it retires the program from the generated watchlist views
#: while its internal record (and history) is retained.
REMOVAL_KINDS: frozenset[str] = frozenset({"BOUNTY_PROGRAM_DELISTED"})

for _group_name, _group in SHARED_KIND_GROUPS.items():
    for _kind, _spec in _group.items():
        _validate_kind_spec(f"core.kinds.{_group_name}", _kind, _spec)
