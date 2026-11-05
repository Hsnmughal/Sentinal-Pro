from __future__ import annotations

from ...core.contract import GlobalContext, PollContext
from ...core.models import EventCandidate


def poll(context: PollContext) -> list[EventCandidate]:
    """Poll one monitoring target. Return only changes since the stored snapshot.

    ``context.target`` is the target this check covers
    (``{"target_key": ..., "config": ...}``) and ``context.programs`` lists the
    watched programs that need it — emit one candidate per program (share one
    observation across them) with ``protocol_id`` taken from each program.
    ``context.job_kind`` is ``"poll"`` or the slower ``"release"``.
    Establish a baseline silently on the first poll (return []) and only emit
    events afterwards. Commit the snapshot and its derived observations in one
    step with ``context.store.save_state(..., events=candidates)`` so a change can
    never be lost between the two.
    """
    config = (context.target or {}).get("config") or context.config
    if not config:
        return []
    previous = context.store.get_state(context.source_key)
    # ... fetch and normalise, reusing sentinal.core.bounty_policy when applicable ...
    # context.store.save_state(source_key=context.source_key, protocol_id=..., ..., events=candidates)
    return []


def poll_global(context: GlobalContext) -> tuple[dict[str, int], list[EventCandidate]]:
    """Poll platform-wide state. Required only when adapter.toml declares a global_job."""
    return {"total": 0, "added": 0, "removed": 0, "reactivated": 0}, []
