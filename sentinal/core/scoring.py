from __future__ import annotations

from collections.abc import Iterable, Mapping

from .contract import EventKindSpec, validate_kind
from .models import EventCandidate


def score_event(
    candidate: EventCandidate,
    related_kinds: Iterable[str] = (),
    kind_specs: Mapping[str, EventKindSpec] | None = None,
) -> tuple[int, tuple[str, ...]]:
    if kind_specs is None:
        from .registry import default_registry

        kind_specs = default_registry().kind_specs()
    spec = validate_kind(candidate.kind, kind_specs)
    score, base_reason = spec.score, spec.reason
    reasons = [base_reason]

    # Names and protocol-wide temporal proximity are hints, not evidence.
    from .investigation import significance
    findings = significance(candidate.metadata.get("changed_files") or [])
    areas = sorted({row["area"] for row in findings if row.get("strength") == "behavior"})
    if areas:
        score += min(25, len(areas) * 8)
        reasons.append("security-relevant changed lines: " + ", ".join(areas) + " (heuristic)")
    if candidate.metadata.get("truncated") or candidate.metadata.get("history_rewritten"):
        score = max(0, score - 20)
        reasons.append("incomplete change evidence reduces confidence")
    return min(score, 100), tuple(reasons)


def severity(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"
