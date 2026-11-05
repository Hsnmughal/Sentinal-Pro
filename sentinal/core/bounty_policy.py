"""Normalised bounty-policy domain logic.
Platform-agnostic shared vocabulary: every platform that publishes a bounty policy
routes its extracted data through :func:`normalize` and its changes through
:func:`detect_changes`, so all of them emit the same ``BOUNTY_*`` event vocabulary
declared in :mod:`sentinal.core.kinds`.
Structured identity is preserved end to end: scope and impact entries keep their
identity, category, severity, URLs/addresses and original wording, so a redefinition
of one asset is detected as an update rather than a removal plus an addition.
Presentation noise (HTML markup, entities, whitespace runs) is stripped before
storage so that meaning-bearing terms changes surface without markup churn.
"""
from __future__ import annotations
import html
import re
from typing import Any
from urllib.parse import urlparse
from .diffing import Difference, deep_diff
from .models import EventCandidate

_SEVERITIES = ("critical", "high", "medium", "low", "informational")
_TAG_RE = re.compile(r"<[^>]*>")
_WS_RE = re.compile(r"\s+")
_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
#: Path segments that separate the repository part of a code-host URL from a ref
#: and a file path (``.../owner/repo/<sep>/<ref>/<path>``). Host-agnostic on
#: purpose: core must not learn platform URL schemes.
_REF_SEPARATORS = frozenset({"blob", "tree", "raw", "src", "commit", "commits", "edit", "blame"})
#: File suffixes that make a changed file a contract-level ("runtime") asset.
CONTRACT_SUFFIXES = frozenset({".sol", ".vy", ".cairo", ".move", ".circom"})
#: Best-effort bounty category of a changed file. ``None`` means unknown — callers
#: must then treat applicability questions as unresolved rather than guessing.
_SUFFIX_CATEGORY = {
    ".sol": "smart_contract",
    ".vy": "smart_contract",
    ".cairo": "smart_contract",
    ".move": "smart_contract",
    ".circom": "smart_contract",
    ".ts": "web_app",
    ".tsx": "web_app",
    ".js": "web_app",
    ".jsx": "web_app",
}
#: Eligibility confidence classes, strongest first. These are confidence about
#: bounty eligibility — never research priority (that is the event score).
ELIGIBILITY_CONFIRMED = "confirmed_scoped"
ELIGIBILITY_PRIMACY = "potential_primacy"
ELIGIBILITY_UNLISTED = "unlisted_code"
ELIGIBILITY_UNRESOLVED = "unresolved_mapping"
_ELIGIBILITY_RANK = {
    ELIGIBILITY_CONFIRMED: 4,
    ELIGIBILITY_PRIMACY: 3,
    ELIGIBILITY_UNRESOLVED: 2,
    ELIGIBILITY_UNLISTED: 1,
    "": 0,
}

def clean_text(value: Any) -> str:
    """Strip presentation noise (markup, entities, whitespace runs) from free text."""
    if value is None:
        return ""
    text = html.unescape(str(value))
    text = _TAG_RE.sub(" ", text)
    return _WS_RE.sub(" ", text).strip()

def code_location(value: Any) -> dict[str, Any] | None:
    """Parse ``value`` into a code location, or None when none can be identified.
    Accepts ``owner/repo`` references (optionally ``owner/repo#ref``) and code-host
    URLs of the form ``https://host/owner/repo[/<sep>]/<ref>/<path>`` where
    ``<sep>`` is a ref separator such as ``blob``. URLs that do not carry a
    recognisable repository shape return None so callers can mark the mapping
    unresolved instead of guessing.
    """
    if not isinstance(value, str):
        return None
    raw = value.strip()
    if not raw:
        return None
    if "://" not in raw and not raw.startswith("/"):
        repo, sep, ref = raw.partition("#")
        pieces = [piece for piece in repo.strip("/").split("/") if piece]
        if len(pieces) != 2:
            return None
        return {
            "repo": f"{pieces[0]}/{pieces[1]}",
            "ref": ref.strip() or None,
            "path": None,
        }
    parsed = urlparse(raw)
    pieces = [piece for piece in parsed.path.split("/") if piece]
    if len(pieces) < 2:
        return None
    owner, repo = pieces[0], pieces[1]
    rest = pieces[2:]
    while rest and rest[0] == "-":
        rest = rest[1:]
    if not rest:
        return {"repo": f"{owner}/{repo}", "ref": None, "path": None}
    if rest[0] in _REF_SEPARATORS and len(rest) >= 3:
        return {
            "repo": f"{owner}/{repo}",
            "ref": rest[1],
            "path": "/".join(rest[2:]) or None,
            "directory": rest[0] == "tree",
        }
    return None

def normalize(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("Bounty source must return a JSON object")
    scope = _normalized_entries(payload.get("scope", []))
    repositories = _normalized_list(payload.get("repositories", []))
    for repo in sorted(_repositories_from_entries(scope)):
        if repo not in repositories:
            repositories.append(repo)
    return {
        "status": str(payload.get("status", "active")).lower(),
        "max_bounty": _number(payload.get("max_bounty")),
        "submission_cost": _number(payload.get("submission_cost")),
        "rewards": _normalized_mapping(payload.get("rewards", {})),
        "scope": scope,
        "impacts": _normalized_entries(payload.get("impacts", [])),
        "out_of_scope": _normalized_entries(payload.get("out_of_scope", [])),
        "policy": _normalized_mapping(payload.get("policy", {})),
        # Watchlist plumbing, not eligibility data: the repositories a program's
        # published scope points at (collected from asset locations plus any
        # explicit links a platform adapter publishes). Changes never emit events.
        "repositories": repositories,
    }


def validate_source_payload(payload: Any, previous: Any = None) -> list[str]:
    """Validate custom sources without treating omitted fields as removals."""
    if not isinstance(payload, dict):
        raise ValueError('Bounty source must return a JSON object')
    fields = {'status', 'max_bounty', 'submission_cost', 'scope', 'impacts',
              'out_of_scope', 'rewards', 'policy', 'repositories'}
    present = fields & payload.keys()
    if not present:
        raise ValueError('Bounty response contains no policy fields')
    previous = previous or {}
    required = set(previous.get('_source_fields', ()))
    if not required:
        required = {key for key in fields - {'status'} if previous.get(key) not in (None, [], {}, '')}
        if previous.get('status') == 'paused':
            required.add('status')
    if required - present:
        raise ValueError('Incomplete bounty response; missing ' + ', '.join(sorted(required - present)))
    for key in ('scope', 'impacts', 'out_of_scope', 'repositories'):
        if key in payload and (not isinstance(payload[key], list) or
                any(not isinstance(item, (str, dict)) for item in payload[key])):
            raise ValueError(f'{key} must be a list of entries')
    for key in ('rewards', 'policy'):
        if key in payload and not isinstance(payload[key], dict):
            raise ValueError(f'{key} must be an object')
    if 'status' in payload and payload['status'] not in ('active', 'paused', 'inactive'):
        raise ValueError('Bounty status must be active, paused, or inactive')
    import math
    for key in ('max_bounty', 'submission_cost'):
        if key in payload and payload[key] is not None:
            number = _number(payload[key])
            if isinstance(payload[key], bool) or number is None or not math.isfinite(number) or number < 0:
                raise ValueError(f'{key} must be a finite nonnegative amount or null')
    for entry in payload.get('scope', []):
        if isinstance(entry, dict) and entry.get('url'):
            try:
                parsed = urlparse(entry['url'])
                valid = parsed.scheme in ('http', 'https') and parsed.hostname and not parsed.username and not parsed.password
            except (ValueError, TypeError, AttributeError):
                valid = False
            if not valid:
                raise ValueError('Bounty scope URL is malformed')
    return sorted(present)

def detect_changes(
    protocol_id: str,
    source_key: str,
    previous: Any,
    current: dict[str, Any],
    platform: str,
    url: str,
) -> list[EventCandidate]:
    previous, current = policy_comparison(previous, current)
    events = []
    for difference in deep_diff(previous, current):
        if _is_watchlist_field(difference.path):
            continue
        candidate = _classify(protocol_id, source_key, difference, platform, url)
        if difference.path.startswith("scope["):
            for field, snapshot in (("asset_before", previous), ("asset_after", current)):
                entry = next((entry for entry in snapshot.get("scope", [])
                              if isinstance(entry, dict) and difference.path.startswith(f"scope[{entry.get('identity')}]") ), None)
                candidate.metadata[field] = entry
        events.append(candidate)
    return events


def policy_comparison(previous: Any, current: dict[str, Any]) -> tuple[Any, dict[str, Any]]:
    """Compare published content, not legacy formatting or derived code locations."""
    if not isinstance(previous, dict):
        return previous, current
    before, after = dict(previous), dict(current)
    before.pop('_source_fields', None)
    after.pop('_source_fields', None)
    before.pop('_source_url', None)
    after.pop('_source_url', None)
    if "submission_cost" in after and after.get("submission_cost") is None:
        before.setdefault("submission_cost", None)
    for field, kind in (("scope", "asset"), ("impacts", "impact")):
        old, new = before.get(field, []), after.get(field, [])
        if old and all(isinstance(entry, str) for entry in old) and all(isinstance(entry, dict) for entry in new):
            available = list(new)
            upgraded = []
            for entry in structured_entries(kind, old):
                matches = [item for item in available if
                           (entry.get("url") and item.get("url") == entry.get("url"))
                           or item.get("label") == entry.get("label")]
                if matches:
                    match = max(matches, key=lambda item: (
                        bool(entry.get("url") and item.get("url") == entry.get("url")),
                        item.get("identity") == entry.get("label"),
                        item.get("label") == entry.get("label") and item.get("severity") == entry.get("severity"),
                        item.get("category") == entry.get("category"),
                    ))
                    available.remove(match)
                    value = dict(match)
                    for key in ("label", "wording", "url", "severity", "category", "address"):
                        if entry.get(key) is not None:
                            if key in ("label", "wording") and entry.get("label") == match.get("identity") and match.get("label") == match.get("url"):
                                continue
                            value[key] = entry[key]
                    upgraded.append(value)
                else:
                    upgraded.append({key: value for key, value in entry.items() if key != 'kind'})
            old = upgraded
        # Location is inferred from URL. Its representation can evolve silently.
        before[field] = [{k: v for k, v in entry.items() if k != 'location'} if isinstance(entry, dict) else entry for entry in old]
        after[field] = [{k: v for k, v in entry.items() if k != 'location'} if isinstance(entry, dict) else entry for entry in new]
    return before, after

def _is_watchlist_field(path: str) -> bool:
    return path == "repositories" or path.startswith("repositories.") or path.startswith("repositories[")

def _classify(
    protocol_id: str,
    source_key: str,
    difference: Difference,
    platform: str,
    url: str,
) -> EventCandidate:
    path = difference.path
    lower = path.lower()
    if lower == "status":
        kind = "BOUNTY_PROGRAM_PAUSED" if difference.after in {"paused", "inactive"} else "BOUNTY_PROGRAM_RESUMED"
    elif lower == "max_bounty":
        kind = _directional(difference, "BOUNTY_MAX_INCREASED", "BOUNTY_MAX_DECREASED")
    elif lower == "submission_cost":
        kind = "BOUNTY_FEE_CHANGED"
    elif lower.startswith("rewards"):
        if difference.before is None:
            kind = "BOUNTY_REWARD_INCREASED"
        elif difference.after is None:
            kind = "BOUNTY_REWARD_DECREASED"
        else:
            kind = _directional(difference, "BOUNTY_REWARD_INCREASED", "BOUNTY_REWARD_DECREASED")
    elif lower.startswith("scope"):
        kind = _entry_kind("scope", difference, "BOUNTY_SCOPE_ADDED", "BOUNTY_SCOPE_REMOVED", "BOUNTY_SCOPE_UPDATED")
    elif lower.startswith("impacts"):
        kind = _entry_kind("impacts", difference, "BOUNTY_IMPACT_ADDED", "BOUNTY_IMPACT_REMOVED", "BOUNTY_IMPACT_UPDATED")
    else:
        kind = "BOUNTY_POLICY_CHANGED"
    return EventCandidate(
        protocol_id=protocol_id,
        source_key=source_key,
        kind=kind,
        entity=path,
        before=difference.before,
        after=difference.after,
        metadata={"platform": platform, "url": url},
    )

def _entry_kind(
    base: str,
    difference: Difference,
    added: str,
    removed: str,
    updated: str,
) -> str:
    """Classify one entry-list difference: a whole-entry addition/removal, or the
    redefinition of an existing entry (field-level change inside ``base[identity]``
    or a whole-list replacement)."""
    inner = difference.path[len(base) :]
    if inner == "":
        return updated
    if inner.startswith("[]"):
        return added if difference.before is None else removed
    if inner.startswith("["):
        if "]." in inner:
            return updated
        return added if difference.before is None else removed
    return updated

def _directional(difference: Difference, increase: str, decrease: str) -> str:
    try:
        return increase if float(difference.after) > float(difference.before) else decrease
    except (TypeError, ValueError):
        return "BOUNTY_POLICY_CHANGED"

# ----------------------------------------------------------------- normalization

def _normalized_mapping(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    return {str(key).strip().lower(): _normalize_value(item) for key, item in sorted(value.items())}

def _normalized_list(value: Any) -> list[Any]:
    if not isinstance(value, list):
        return []
    normalized = [_normalize_value(item) for item in value]
    return sorted(normalized, key=_entry_sort_key)

def _entry_sort_key(value: Any) -> str:
    return entry_identity(value) if isinstance(value, dict) else str(value)

def _normalized_entries(value: Any) -> list[Any]:
    if not isinstance(value, list):
        return []
    normalized = [
        normalize_entry(item) if isinstance(item, dict) else clean_text(item) for item in value
    ]
    normalized = [item for item in normalized if item != "" and item != {}]
    return sorted(normalized, key=_entry_sort_key)

def normalize_entry(entry: dict[str, Any]) -> dict[str, Any]:
    """Canonical structured form of one scope/impact/terms entry.
    Identity, category, severity, URLs/addresses and the original wording are all
    preserved; ``location`` is the parsed code location of ``url`` when one exists.
    """
    label = clean_text(_first(entry, "label", "title", "description", "name"))
    wording = clean_text(_first(entry, "wording", "description", "text", "title", "label"))
    url = clean_text(_first(entry, "url", "link"))
    address = clean_text(_first(entry, "address", "contract_address"))
    if not address:
        candidate = label or wording
        if _ADDRESS_RE.match(candidate or ""):
            address = candidate
    severity = clean_text(_first(entry, "severity")).lower() or None
    if severity not in _SEVERITIES:
        severity = severity or None
    category = clean_text(_first(entry, "category", "type", "asset_type")).lower() or None
    identity = clean_text(_first(entry, "identity", "id"))
    if not identity:
        identity = url or label or wording
    location = code_location(url) or code_location(_first(entry, "repository", "repo") or "")
    return {
        "identity": identity,
        "label": label or wording or identity,
        "wording": wording or label,
        "category": category,
        "severity": severity,
        "url": url or None,
        "address": address or None,
        "location": location,
        **({"chain_id": entry["chain_id"]} if "chain_id" in entry else {}),
    }

def entry_identity(entry: Any) -> str:
    if isinstance(entry, dict):
        return str(entry.get("identity") or entry.get("label") or "")
    return str(entry)

def _first(entry: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in entry and entry[key] not in (None, ""):
            return entry[key]
    return None

def _normalize_value(value: Any) -> Any:
    if isinstance(value, dict):
        return normalize_entry(value) if _looks_like_entry(value) else _normalized_mapping(value)
    if isinstance(value, list):
        return _normalized_list(value)
    if isinstance(value, str):
        return clean_text(value)
    return value

def _looks_like_entry(value: dict[str, Any]) -> bool:
    return any(key in value for key in ("identity", "id", "label", "title", "description", "url", "address"))

def _repositories_from_entries(entries: list[Any]) -> set[str]:
    repos: set[str] = set()
    for entry in entries:
        if isinstance(entry, dict):
            location = entry.get("location")
            if isinstance(location, dict) and location.get("repo"):
                repos.add(str(location["repo"]))
    return repos

def _number(value: Any) -> int | float | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return value
    cleaned = str(value).replace("$", "").replace(",", "").strip()
    try:
        number = float(cleaned)
        return int(number) if number.is_integer() else number
    except ValueError:
        return None

# ------------------------------------------------------------- structured tables

def structured_entries(kind: str, entries: list[Any]) -> list[dict[str, Any]]:
    """Structured form of normalised scope/impact/terms entries.
    Structured entries carry their identity, category, severity, URL/address and
    original wording straight through. Plain-string entries (legacy payloads) keep
    the best-effort ``"<severity>: <title>"`` and ``"<label> · <category> · <url>"``
    parsing and degrade to a single ``label`` when the shape is not recognised.
    Used to populate the structured program-scope tables, never for scoring.
    """
    rows: list[dict[str, Any]] = []
    for entry in entries:
        if isinstance(entry, dict):
            rows.append(
                {
                    "kind": kind,
                    "identity": entry.get("identity") or entry.get("label"),
                    "label": entry.get("label") or entry.get("wording") or "",
                    "category": entry.get("category"),
                    "severity": entry.get("severity"),
                    "url": entry.get("url"),
                    "address": entry.get("address"),
                    "wording": entry.get("wording"),
                    "location": entry.get("location"),
                }
            )
            continue
        label = str(entry)
        severity = None
        category = None
        url = None
        prefix, sep, rest = label.partition(":")
        if sep and prefix.strip().lower() in _SEVERITIES:
            severity = prefix.strip().lower()
            label = rest.strip()
        pieces = [piece.strip() for piece in label.split("·")]
        if len(pieces) >= 2:
            category = pieces[1] or None
            if len(pieces) >= 3 and pieces[2]:
                url = pieces[2]
            label = pieces[0] or label
        rows.append(
            {
                "kind": kind,
                "identity": label,
                "label": label,
                "category": category,
                "severity": severity,
                "url": url,
                "address": label if _ADDRESS_RE.match(label or "") else None,
                "wording": label,
                "location": code_location(url) if url else None,
            }
        )
    return rows

# --------------------------------------------------------- eligibility confidence

def asset_match_evidence(asset: dict[str, Any], changed: dict[str, Any]) -> dict[str, Any] | None:
    """Evidence row when ``changed`` (a file movement) matches a scoped ``asset``.
    Matches require repository + exact path or an explicit directory scope.
    """
    location = asset.get("location") or {}
    asset_repo = str(location.get("repo") or "").lower()
    changed_repo = str(changed.get("repo") or "").lower()
    asset_path = str(location.get("path") or "").strip("/")
    changed_path = str(changed.get("path") or "").strip("/")
    if not asset_repo or not changed_repo or asset_repo != changed_repo or not asset_path or not changed_path:
        return None
    match = None
    if asset_path == changed_path:
        match = "exact_path"
    elif location.get("directory") and changed_path.startswith(asset_path + "/"):
        match = "path_prefix"
    if match is None:
        return None
    return {
        "match": match,
        "asset": asset.get("label"),
        "asset_identity": asset.get("identity"),
        "asset_path": f"{asset_repo}:{asset_path}",
        "changed_path": f"{changed_repo}:{changed_path}",
        "status": changed.get("status"),
    }

def changed_file_category(changed: dict[str, Any]) -> str | None:
    path = str(changed.get("path") or "").lower()
    suffix = "." + path.rsplit(".", 1)[-1] if "." in path else ""
    return _SUFFIX_CATEGORY.get(suffix)

def classify_code_change(
    changed: dict[str, Any],
    assets: list[dict[str, Any]],
    primacy_rule: dict[str, Any] | None,
) -> tuple[str, list[dict[str, Any]]]:
    """Classify one changed file against published scope and primacy applicability.
    Returns ``(eligibility, evidence)``. Confirmed eligibility requires scoped
    asset path evidence; repository ownership alone never grants it, and a raw
    primacy value never becomes blanket eligibility — it can only raise
    ``potential_primacy`` when the published applicability covers this change.
    """
    repo = str(changed.get("repo") or "")
    changed_path = str(changed.get("path") or "")
    repo_assets = [
        asset
        for asset in assets
        if str((asset.get("location") or {}).get("repo") or "").lower() == repo.lower()
    ]
    evidence: list[dict[str, Any]] = []
    for asset in repo_assets:
        match = asset_match_evidence(asset, changed)
        if match is not None:
            evidence.append(match)
    if evidence:
        return ELIGIBILITY_CONFIRMED, evidence
    assets_without_paths = [
        asset.get("label")
        for asset in repo_assets
        if not (asset.get("location") or {}).get("path")
    ]
    if repo_assets and assets_without_paths and not any(
        (asset.get("location") or {}).get("path") for asset in repo_assets
    ):
        return ELIGIBILITY_UNRESOLVED, [
            {
                "match": "none",
                "reason": "program lists assets for this repository but none carry resolvable path evidence",
                "assets": assets_without_paths,
                "changed_path": f"{repo}:{changed_path}",
            }
        ]
    category = changed_file_category(changed)
    covered, note = _primacy_coverage(primacy_rule, category)
    if covered:
        return ELIGIBILITY_PRIMACY, [
            {
                "match": "primacy",
                "reason": note,
                "category": category,
                "changed_path": f"{repo}:{changed_path}",
                "rule": {
                    "mode": (primacy_rule or {}).get("mode"),
                    "categories": (primacy_rule or {}).get("categories"),
                },
            }
        ]
    if note.endswith("unresolved"):
        return ELIGIBILITY_UNRESOLVED, [
            {
                "match": "none",
                "reason": note,
                "changed_path": f"{repo}:{changed_path}",
                "rule": {"mode": (primacy_rule or {}).get("mode")},
            }
        ]
    evidence = [
        {
            "match": "none",
            "reason": "runtime code outside published bounty scope",
            "changed_path": f"{changed_path}",
            "status": changed.get("status"),
        }
    ]
    if changed.get("status") in {"added", "renamed", "copied"} and _is_contract_path(changed_path):
        evidence.append(
            {
                "match": "none",
                "reason": "new contract-level code: potential future scope",
                "changed_path": changed_path,
            }
        )
    return ELIGIBILITY_UNLISTED, evidence

def strongest_eligibility(classifications: list[str]) -> str:
    best = ""
    for eligibility in classifications:
        if _ELIGIBILITY_RANK.get(eligibility, 0) > _ELIGIBILITY_RANK.get(best, 0):
            best = eligibility
    return best

def _is_contract_path(path: str) -> bool:
    suffix = "." + path.rsplit(".", 1)[-1] if "." in path else ""
    return suffix in CONTRACT_SUFFIXES

def _primacy_may_apply(rule: dict[str, Any] | None) -> bool:
    return bool(rule) and "impact" in str(rule.get("mode") or "")

def _primacy_coverage(rule: dict[str, Any] | None, category: str | None) -> tuple[bool, str]:
    """Whether Primacy of Impact applicability covers this change category.
    A raw primacy value is never blanket coverage: it only ever yields *potential*
    coverage, and only when the published applicability does not exclude this
    change. When the applicability lists categories but the change's category is
    unknown, the mapping is explicitly unresolved. Notes ending in ``unresolved``
    mark exactly that case.
    """
    if not _primacy_may_apply(rule):
        return False, "no Primacy of Impact applicability published"
    exclusions = rule.get("exclusions") or {}
    excluded = {str(item).lower() for item in exclusions.get("categories") or []}
    if category and category in excluded:
        return False, "published primacy exclusions cover this category"
    categories = {str(item).lower() for item in rule.get("categories") or []}
    if categories:
        if category is None:
            return False, "primacy applicability lists categories but this change category is unknown; mapping unresolved"
        if category not in categories:
            return False, "published primacy applicability does not cover this category"
    return (
        True,
        "Primacy of Impact applicability published for this category; "
        "impact eligibility must be confirmed by review",
    )
