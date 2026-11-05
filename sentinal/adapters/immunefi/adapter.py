from __future__ import annotations

import json
import re
from dataclasses import replace
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlparse

from ...core.bounty_policy import detect_changes, normalize, structured_entries, code_location
from ...core.contract import GlobalContext, PollContext
from ...core.http import header, RequestDeferred, http_status
from ...core.models import EventCandidate


PLATFORM = "immunefi"
CATALOG_PLATFORM = "immunefi"
GLOBAL_JOB_KEY = "catalog"
CATALOG_SOURCE_KEY = f"{GLOBAL_JOB_KEY}:{CATALOG_PLATFORM}"
CATALOG_RUNTIME_KEY = f"{CATALOG_PLATFORM}_catalog"
DEFAULT_CATALOG_URL = "https://immunefi.com/bug-bounty/"



def derive_targets(config: Any) -> list[tuple[str, Any]]:
    """One detail target per program page URL."""
    if not isinstance(config, dict) or not config.get("url"):
        return []
    return [(str(config["url"]), dict(config))]


def discover_targets(payload: dict[str, Any]) -> list[tuple[str, str, dict[str, Any]]]:
    """Discover repositories and scoped addresses without making RPC requests.

    Block-explorer paths like address/<contract> are never repository evidence.
    """
    from ...core.registry import default_registry
    registry = default_registry()
    targets = {}
    for entry in structured_entries("asset", payload.get("scope", [])):
        url = entry.get("url")
        if not url:
            continue
        adapter = registry.resolve_host(str(url))
        if adapter is None or not any("repository_activity" in spec.tags for spec in adapter.kinds.values()):
            continue
        location = code_location(url)
        if location is None:
            continue
        for key, config in adapter.split_targets({"repository": location["repo"]}):
            targets[(adapter.manifest.source_type, str(key))] = config
    from ..evm.adapter import discover_assets
    for asset in discover_assets(payload):
        targets[("evm", f'{asset["chain_id"]}:proxy:{asset["proxy"]}')] = asset
    return [(source, key, config) for (source, key), config in sorted(targets.items())]


def poll(context: PollContext) -> list[EventCandidate]:
    config = (context.target or {}).get("config") or context.config or {}
    url = str(config.get("url") or "")
    if not url:
        return []
    store = context.store
    client = context.client
    programs = tuple(context.programs) or (context.protocol,)
    records = []
    for program in programs:
        protocol_id = str(program['id'])
        platform = str(program.get('platform') or PLATFORM)
        key = store.policy_source_key(f'{PLATFORM}:{protocol_id}', protocol_id, context.source_type,
                                      platform, program.get('program_id'))
        records.append((program, platform, key, store.get_state(key)))
    previous = records[0][3]
    headers = ({"If-None-Match": previous.etag} if previous and previous.etag
               and previous.payload.get('_source_url') == url else {})
    response = client.get_text(url, headers)
    if response.status == 304:
        if previous is None:
            raise ValueError('Source returned unchanged without a policy baseline')
        if previous.payload.get('_source_url', url) != url:
            raise ValueError('Source returned unchanged for a different policy URL')
        normalized = previous.payload
        current_fields = set(normalized.get('_source_fields', ()))
        for _, _, _, prior in records:
            if prior and set(prior.payload.get('_source_fields', ())) - current_fields:
                raise ValueError('Cached program response is missing previously supplied rule fields')
    else:
        expected_slug = _program_slug(url) or str(programs[0].get('external_id') or programs[0]['id'])
        requirements = {'_source_fields':sorted({field for _, _, _, prior in records if prior
                         for field in prior.payload.get('_source_fields', ())}),
                        'out_of_scope':any(prior and prior.payload.get('out_of_scope') for _, _, _, prior in records)}
        detail = extract_program_detail(response.text or '', expected_slug=expected_slug, previous=requirements)
        normalized = {**normalize(detail), '_source_fields': detail['_source_fields'], '_source_url':url}
    etag = header(response.headers, 'etag') or (previous.etag if response.status == 304 else None)
    events = []
    with store.connect():
        for program, platform, key, prior in records:
            changes = detect_changes(str(program['id']), key, prior.payload, normalized, platform, url) if prior else []
            if program.get('program_id') is not None:
                changes = [replace(event, metadata={**event.metadata, 'program_id': program['program_id']}) for event in changes]
            store.save_state(source_key=key, protocol_id=str(program['id']), source_type=context.source_type,
                payload=normalized, etag=etag, events=changes, platform=platform, program_id=program.get('program_id'))
            events.extend(changes)
    return events


def poll_global(context: GlobalContext) -> tuple[dict[str, int], list[EventCandidate]]:
    """Sync the public catalogue. The catalogue mirror, the watched-program list
    and the derived observations commit in one transaction; destructive
    reconciliation (delisting) only runs on a response verified complete."""
    store = context.store
    client = context.client
    url = str(context.settings.get("url") or DEFAULT_CATALOG_URL)
    previous = store.get_runtime_status(CATALOG_RUNTIME_KEY) or {}
    headers = {"If-None-Match": previous["etag"]} if previous.get("etag") else {}
    response = client.get_text(url, headers)
    if response.status == 304:
        return {"total": len(store.list_catalog(CATALOG_PLATFORM)), "added": 0, "removed": 0, "reactivated": 0}, []
    programs = extract_catalog(response.text or "", url)
    if not programs:
        raise RuntimeError(
            f"{PLATFORM} catalogue page returned no program links; refusing to replace the catalogue"
        )
    before = {program["external_id"]: program for program in store.list_catalog(CATALOG_PLATFORM)}
    complete, reason = _completeness(programs, before)
    incoming = {item["external_id"]: item for item in programs}
    missing = sorted(key for key, value in before.items() if value.get("active") and key not in incoming)
    confirmed = set()
    # Absence from an HTML extraction alone never proves removal. Verify missing
    # program pages; retain every missing record that could not be confirmed.
    limit = max(0, int(context.settings.get("removal_verification_limit", 10)))
    cursor = int(previous.get("verification_cursor", 0))
    if missing:
        ordered = missing[cursor % len(missing):] + missing[:cursor % len(missing)]
        for external_id in ordered[:limit]:
            record = before[external_id]
            if not record.get("url"):
                continue
            if store.is_target_blocked(PLATFORM, str(record['url'])):
                continue
            try:
                client.get_text(str(record["url"]), {})
            except RequestDeferred:
                break
            except RuntimeError as error:
                if http_status(error) in (404, 410):
                    confirmed.add(external_id)
        cursor = (cursor + limit) % len(missing)
    effective = list(programs) + [record for key, record in before.items()
                                 if record.get("active") and key not in incoming and key not in confirmed]
    events = _catalog_changes(store, before, effective, True) if before else []
    result = store.sync_catalog(CATALOG_PLATFORM, effective, events=events, complete=True)
    if missing:
        reason = f"{len(missing)} absent from extraction; {len(confirmed)} removals verified by program HTTP 404/410; remaining records retained"
        complete = len(confirmed) == len(missing)
    store.set_runtime_status(
        CATALOG_RUNTIME_KEY,
        {
            "program_count": result["total"],
            "etag": header(response.headers, "etag") if complete else None,
            "verification_cursor": cursor,
            "complete": complete,
            "completeness_reason": reason,
            "synced_at": result.get("synced_at"),
        },
    )
    return result, events


def _completeness(
    programs: list[dict[str, Any]], before: dict[str, dict[str, Any]]
) -> tuple[bool, str]:
    """Decide whether this catalogue response is complete enough to delist from."""
    incoming = {record["external_id"] for record in programs}
    missing = {key for key, record in before.items() if record.get("active") and key not in incoming}
    if missing:
        return False, "missing program pages require independent removal verification"
    return True, "no previously active program is missing"


def _catalog_changes(
    store: Any,
    before: dict[str, dict[str, Any]],
    incoming_programs: list[dict[str, Any]],
    complete: bool,
) -> list[EventCandidate]:
    incoming = {program["external_id"]: program for program in incoming_programs}
    events: list[EventCandidate] = []
    for external_id in sorted(set(before) | set(incoming)):
        previous = before.get(external_id)
        current = incoming.get(external_id)
        if previous is None:
            kind = "BOUNTY_PROGRAM_CREATED"
        elif not previous["active"] and current is not None:
            kind = "BOUNTY_PROGRAM_RELISTED"
        elif previous["active"] and current is None:
            if not complete:
                continue
            kind = "BOUNTY_PROGRAM_DELISTED"
        else:
            continue
        record = current or previous
        after = _catalog_summary(current)
        if after is None:
            after = {**_catalog_summary(previous), "active": False}
        store.ensure_protocol(external_id, record.get("name") or external_id)
        events.append(
            EventCandidate(
                protocol_id=external_id,
                source_key=CATALOG_SOURCE_KEY,
                kind=kind,
                entity=record.get("name") or external_id,
                before=_catalog_summary(previous),
                after=after,
                metadata={"platform": PLATFORM, "url": record.get("url")},
            )
        )
    return events


def _catalog_summary(record: dict[str, Any] | None) -> dict[str, Any] | None:
    if record is None:
        return None
    return {
        "name": record.get("name"),
        "url": record.get("url"),
        "max_bounty": record.get("max_bounty"),
        "active": bool(record.get("active")),
    }


class _CatalogueParser(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.links: dict[str, dict[str, str]] = {}
        self._slug: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "a":
            return
        href = dict(attrs).get("href") or ""
        slug = _program_slug(href)
        if slug:
            self._slug = slug
            self._text = []

    def handle_data(self, data: str) -> None:
        if self._slug:
            self._text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag != "a" or not self._slug:
            return
        name = " ".join(" ".join(self._text).split()) or _title(self._slug)
        self.links[self._slug] = {
            "external_id": self._slug,
            "name": name,
            "url": urljoin(self.base_url, f"/bug-bounty/{self._slug}/information/"),
        }
        self._slug = None
        self._text = []

    def programs(self) -> list[dict[str, str]]:
        return [self.links[key] for key in sorted(self.links)]


def _catalog_objects(document: str):
    """Decode Flight JSON and walk objects without depending on field order."""
    stream = _flight_stream(document)
    if not stream:
        try:
            stream = _decode(document)
        except json.JSONDecodeError:
            stream = document
    decoder = json.JSONDecoder()
    def walk(value):
        if isinstance(value, dict):
            yield value
            for child in value.values():
                yield from walk(child)
        elif isinstance(value, list):
            for child in value:
                yield from walk(child)
    consumed = 0
    for match in re.finditer(r'\{\s*"', stream):
        if match.start() < consumed:
            continue
        try:
            value, length = decoder.raw_decode(stream[match.start():])
        except json.JSONDecodeError:
            continue
        consumed = match.start() + length
        yield from walk(value)


def extract_catalog(document: str, base_url: str = DEFAULT_CATALOG_URL) -> list[dict[str, Any]]:
    embedded = {}
    for item in _catalog_objects(document):
        if not all(isinstance(item.get(key), str) and item[key] for key in ('slug','project','url')):
            continue
        slug = item['slug'].lower()
        if _program_slug(item['url']) != slug:
            continue
        bounty = item.get('maxBounty')
        if isinstance(bounty, bool) or not isinstance(bounty, (int, float)) or bounty < 0:
            continue
        embedded[slug] = {
            'external_id': slug,
            'name': item['project'],
            'url': _catalog_url(base_url, slug, item['url']),
            'max_bounty': bounty,
            'source_updated_at': item.get('updatedDate') if isinstance(item.get('updatedDate'), str) else None,
            'metadata': {
                'contentful_id': item.get('contentfulId'),
                'launch_date': item.get('launchDate'),
                'kyc': item.get('kyc') is True,
            },
        }
    if embedded:
        return [embedded[key] for key in sorted(embedded)]

    parser = _CatalogueParser(base_url)
    parser.feed(document)
    return parser.programs()


def _catalog_url(base_url: str, slug: str, candidate: str) -> str:
    """Pin catalogue links to the configured host; a hostile payload cannot
    redirect checks at loopback, private or non-HTTP origins."""
    base = urlparse(base_url)
    try:
        parsed = urlparse(candidate)
        trusted = (parsed.scheme == 'https' and parsed.hostname == base.hostname
                   and base.hostname is not None and not parsed.username and not parsed.password)
    except ValueError:
        trusted = False
    if trusted:
        return candidate
    return urljoin(base_url, f"/bug-bounty/{slug}/information/")


def extract_program_detail(document: str, *, expected_slug: str | None = None, previous=None) -> dict[str, Any]:
    """Return the bounty-normalized program shape parsed from a programme page.

    Reads the Next.js flight payload rather than the rendered tables: the tables are
    client-paginated (12 rows server-side) and omit fields such as ``isPayToSubmit``.
    Assets and impacts keep their structured identity, category, severity, URL or
    address and original wording.
    """
    stream = _flight_stream(document)
    bounty = _embedded_bounty(stream)
    if bounty is None:
        raise RuntimeError(
            f"{PLATFORM} program page yielded no embedded program data; refusing to replace the snapshot"
        )
    _validate_bounty(bounty, stream, expected_slug, previous or {})
    return {
        "status": "paused" if bounty.get("pausedAt") else "active",
        "max_bounty": bounty.get("maxBounty"),
        "submission_cost": _submission_cost(bounty),
        "rewards": _rewards(bounty.get("programRewards") or []),
        "scope": _assets(bounty.get("assets") or []),
        "impacts": _impacts(bounty.get("impacts") or []),
        "out_of_scope": _out_of_scope(bounty, _text_records(stream)),
        "policy": _policy(bounty),
        '_source_fields': sorted(key for key in bounty if key.startswith(_OUT_OF_SCOPE_PREFIX) or key in {
            'outOfScopeAndRules', 'customOutOfScopeInformation', 'submissionCost', 'submissionFee',
            'payToSubmitAmount', 'primacyAppliesTo', 'primacy_applies_to', 'primacyExclusions', 'primacy_exclusions'}),
    }


def _validate_bounty(bounty, stream, expected_slug, previous):
    """Reject partial hydration records before they can replace a good snapshot."""
    required = {'slug', 'project', 'maxBounty', 'pausedAt', 'assets', 'impacts', 'programRewards',
                'kyc', 'inviteOnly', 'isPayToSubmit', 'immunefiStandard',
                'responsiblePublicationCategory', 'proofOfConceptType', 'primacy', 'rewardsToken'}
    required.update(previous.get('_source_fields', ()))
    missing = required - bounty.keys()
    if missing:
        raise ValueError('Incomplete program data; missing ' + ', '.join(sorted(missing)))
    if not all(isinstance(bounty[key], str) and bounty[key].strip() for key in ('slug', 'project')):
        raise ValueError('Program identity is missing or malformed')
    if expected_slug is not None and bounty['slug'].lower() != expected_slug.lower():
        raise ValueError('Program response identity does not match the monitored URL')
    import math
    amount = bounty['maxBounty']
    if isinstance(amount, bool) or not isinstance(amount, (int, float)) or not math.isfinite(amount) or amount < 0:
        raise ValueError('Program reward ceiling must be a finite nonnegative number')
    if bounty['pausedAt'] is not None and not isinstance(bounty['pausedAt'], str):
        raise ValueError('Program pause status is malformed')
    for key in ('kyc', 'inviteOnly', 'isPayToSubmit', 'immunefiStandard'):
        if not isinstance(bounty[key], bool):
            raise ValueError(f'Program {key} must be boolean')
    for key in ('assets', 'impacts', 'programRewards'):
        if not isinstance(bounty[key], list) or any(not isinstance(row, dict) for row in bounty[key]):
            raise ValueError(f'Program {key} must be a complete list of objects')
    for row in bounty['assets']:
        if not {'url', 'description', 'type'} <= row.keys():
            raise ValueError('Program asset is incomplete')
        if not any(isinstance(row.get(key), str) and row[key].strip() for key in ('id', 'url', 'description', 'address')):
            raise ValueError('Program asset has no identity or location')
        for key in ('url', 'address', 'description', 'type'):
            if row.get(key) is not None and not isinstance(row[key], str):
                raise ValueError(f'Program asset {key} must be text')
        if row.get('url'):
            try:
                parsed = urlparse(row['url'])
                valid = parsed.scheme in ('http', 'https') and parsed.hostname and not parsed.username and not parsed.password
            except ValueError:
                valid = False
            if not valid:
                raise ValueError('Program asset URL is malformed')
    for row in bounty['impacts']:
        if not {'title', 'severity', 'type'} <= row.keys() or not all(
                isinstance(row[key], str) and row[key].strip() for key in ('title', 'severity', 'type')):
            raise ValueError('Program impact is incomplete or malformed')
    for row in bounty['programRewards']:
        if not all(isinstance(row.get(key), str) and row[key].strip()
                   for key in ('severity', 'assetType', 'rewardModel')):
            raise ValueError('Program reward tier is incomplete')
        keys = ('fixedReward',) if row['rewardModel'] == 'fixed' else ('minReward', 'maxReward')
        if any(key not in row for key in keys):
            raise ValueError('Program reward amounts are incomplete')
        for key in keys:
            value = row[key]
            if value is not None and (isinstance(value, bool) or not isinstance(value, (int, float))
                                      or not math.isfinite(value) or value < 0):
                raise ValueError('Program reward amount is malformed')
    if previous.get('out_of_scope') and not any(key.startswith(_OUT_OF_SCOPE_PREFIX) or key in
            ('outOfScopeAndRules', 'customOutOfScopeInformation') for key in bounty):
        raise ValueError('Program out-of-scope rules are missing')
    records = _text_records(stream)
    for key, value in bounty.items():
        if key.startswith(_OUT_OF_SCOPE_PREFIX) or key in ('outOfScopeAndRules', 'customOutOfScopeInformation'):
            if isinstance(value, str) and re.fullmatch(r'\$[0-9a-zA-Z]+', value) and value[1:] not in records:
                raise ValueError('Program rules reference a missing text record')


def _submission_cost(bounty: dict[str, Any]) -> Any:
    for key in ("submissionCost", "submissionFee", "payToSubmitAmount"):
        if bounty.get(key) is not None:
            return bounty.get(key)
    return None


def _rewards(entries: list[Any]) -> dict[str, Any]:
    rewards: dict[str, Any] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        asset_type = str(entry.get("assetType") or "general")
        severity = str(entry.get("severity") or "unknown")
        if entry.get("rewardModel") == "fixed":
            tier = {"flat": entry.get("fixedReward")}
        else:
            tier = {"min": entry.get("minReward"), "max": entry.get("maxReward")}
        rewards.setdefault(asset_type, {})[severity] = {
            key: value for key, value in tier.items() if value is not None
        }
    return rewards


def _assets(entries: list[Any]) -> list[dict[str, Any]]:
    assets: list[dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        description = " ".join(str(entry.get("description") or "").split())
        url = str(entry.get("url") or "").strip()
        identity = str(entry.get("id") or "").strip() or url or description
        assets.append(
            {
                "identity": identity,
                "label": description or url or identity,
                "wording": description,
                "category": str(entry.get("type") or "").strip() or None,
                "severity": None,
                "url": url or None,
                "address": str(entry.get("address") or "").strip() or None,
                **({"chain_id": entry.get("chain_id", entry.get("chainId"))} if "chain_id" in entry or "chainId" in entry else {}),
            }
        )
    return assets


def _impacts(entries: list[Any]) -> list[dict[str, Any]]:
    impacts: list[dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        severity = str(entry.get("severity") or "").strip()
        title = " ".join(str(entry.get("title") or "").split())
        if not title and not entry.get("id"):
            continue
        identity = str(entry.get("id") or "").strip() or f"{severity}:{title}"
        impacts.append(
            {
                "identity": identity,
                "label": title or identity,
                "wording": title,
                "category": str(entry.get("type") or "").strip() or None,
                "severity": severity or None,
                "url": None,
                "address": None,
            }
        )
    return impacts


def _policy(bounty: dict[str, Any]) -> dict[str, Any]:
    policy: dict[str, Any] = {
        "kyc": bool(bounty.get("kyc")),
        "invite_only": bool(bounty.get("inviteOnly")),
        "pay_to_submit": bool(bounty.get("isPayToSubmit")),
        "immunefi_standard": bool(bounty.get("immunefiStandard")),
        "responsible_publication": bounty.get("responsiblePublicationCategory"),
        "proof_of_concept": bounty.get("proofOfConceptType"),
        "primacy": bounty.get("primacy"),
        "rewards_token": bounty.get("rewardsToken"),
    }
    applies = bounty.get("primacyAppliesTo") or bounty.get("primacy_applies_to")
    exclusions = bounty.get("primacyExclusions") or bounty.get("primacy_exclusions")
    if isinstance(applies, dict):
        policy["primacy_applies_to"] = applies
    if isinstance(exclusions, dict):
        policy["primacy_exclusions"] = exclusions
    return policy


def _out_of_scope(bounty: dict[str, Any], records: dict[str, str]) -> list[str]:
    items: list[str] = []
    for key in sorted(bounty):
        if not key.startswith(_OUT_OF_SCOPE_PREFIX):
            continue
        label = key[len(_OUT_OF_SCOPE_PREFIX) :] or "General"
        items.extend(f"{label}: {line}" for line in _lines(_resolve(records, bounty[key])))
    for key in ("outOfScopeAndRules", "customOutOfScopeInformation"):
        items.extend(_lines(_resolve(records, bounty.get(key))))
    return items


def _lines(value: Any) -> list[str]:
    if value is None:
        return []
    raw = [line.strip() for line in str(value).splitlines()]
    bullets = [
        re.sub(r"^(?:[-*+]|\d+[.)])\s+", "", line)
        for line in raw
        if re.match(r"^(?:[-*+]|\d+[.)])\s+", line)
    ]
    return bullets or [line for line in raw if line]


def _resolve(records: dict[str, str], value: Any) -> str:
    if not isinstance(value, str):
        return "" if value is None else str(value)
    if value.startswith("$") and value[1:].isalnum():
        return records.get(value[1:], "")
    return value


def _text_records(stream: str) -> dict[str, str]:
    """Return the flight stream's text records keyed by record id.

    Rows are ``<id>:<value>`` where ``<id>`` may be empty (resource hints such as
    ``:HL[...]``). A text row is ``<id>:T<hexbytes>,<payload>`` whose hex length counts
    UTF-8 BYTES and whose payload is followed immediately by the next row with no
    separator; every other row is terminated by a newline.
    """
    data = stream.encode("utf-8")
    row = re.compile(rb"([0-9a-zA-Z]*):(T([0-9a-fA-F]+),)?")
    records: dict[str, str] = {}
    index = 0
    total = len(data)
    while index < total:
        match = row.match(data, index)
        if not match:
            newline = data.find(b"\n", index)
            if newline < 0:
                break
            index = newline + 1
            continue
        token = match.group(1).decode("ascii")
        start = match.end()
        if match.group(2):
            size = int(match.group(3), 16)
            if size > total - start:
                raise ValueError('Incomplete program text record; retaining the last good snapshot')
            try:
                value = data[start : start + size].decode('utf-8')
            except UnicodeDecodeError as error:
                raise ValueError('Malformed program text record byte length') from error
            if token:
                records[token] = value
            index = start + size
        else:
            end = data.find(b"\n", start)
            if end < 0:
                end = total
            if token:
                records[token] = data[start:end].decode("utf-8", "replace")
            index = end + 1
    return records


_OUT_OF_SCOPE_PREFIX = "defaultOutOfScope"

_FLIGHT_PUSH = re.compile(r"self\.__next_f\.push\(")


def _flight_stream(document: str) -> str:
    parts: list[str] = []
    for match in _FLIGHT_PUSH.finditer(document):
        literal = _balanced(document, match.end(), "[", "]")
        if literal is None:
            continue
        try:
            payload = json.loads(literal)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, list) and len(payload) > 1 and isinstance(payload[1], str):
            parts.append(payload[1])
    return "".join(parts)


def _embedded_bounty(stream: str) -> dict[str, Any] | None:
    marker = '"bounty":{'
    index = stream.find(marker)
    if index < 0:
        return None
    literal = _balanced(stream, index + len(marker) - 1, "{", "}")
    if literal is None:
        return None
    try:
        parsed = json.loads(literal)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _balanced(text: str, start: int, opening: str, closing: str) -> str | None:
    if start >= len(text) or text[start] != opening:
        return None
    depth = 0
    in_string = False
    escaped = False
    for index in range(start, len(text)):
        char = text[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == opening:
            depth += 1
        elif char == closing:
            depth -= 1
            if depth == 0:
                return text[start : index + 1]
    return None


def _decode(value: str) -> str:
    return json.loads(f'"{value}"')


def _program_slug(href: str) -> str | None:
    path = urlparse(href).path.strip("/").split("/")
    if len(path) < 2 or path[0] != "bug-bounty":
        return None
    slug = path[1].strip().lower()
    if not slug or slug in {"create", "submit"}:
        return None
    return slug


def _title(slug: str) -> str:
    return " ".join(piece.capitalize() for piece in slug.replace("-", " ").split())
