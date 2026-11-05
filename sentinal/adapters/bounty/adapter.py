from __future__ import annotations

from typing import Any
from dataclasses import replace

from ...core.bounty_policy import detect_changes, normalize, validate_source_payload
from ...core.contract import PollContext
from ...core.http import header
from ...core.models import EventCandidate


def derive_targets(config: Any) -> list[tuple[str, Any]]:
    """One detail target per policy URL."""
    if not isinstance(config, dict) or not config.get("url"):
        return []
    return [(str(config["url"]), dict(config))]


def discover_targets(payload: dict[str, Any]) -> list[tuple[str, str, dict[str, Any]]]:
    """Repository evidence published in the program's own scope becomes GitHub
    monitoring targets — only when the payload actually points at them."""
    from ..evm.adapter import discover_assets
    return [
        ("github", repo, {"repository": repo})
        for repo in payload.get("repositories", [])
        if isinstance(repo, str) and "/" in repo
    ] + [("evm", f'{asset["chain_id"]}:proxy:{asset["proxy"]}', asset) for asset in discover_assets(payload)]


def poll(context: PollContext) -> list[EventCandidate]:
    config = (context.target or {}).get("config") or context.config
    if not config:
        return []
    store = context.store
    client = context.client
    programs = tuple(context.programs) or (context.protocol,)
    url = str(config["url"])
    records = []
    for program in programs:
        protocol_id = str(program['id'])
        platform = str(program.get('platform') or (program.get('target_config') or config).get('platform', 'custom'))
        key = store.policy_source_key(f'{context.source_type}:{platform}:{protocol_id}',
            protocol_id, context.source_type, platform, program.get('program_id'))
        records.append((program, platform, key, store.get_state(key)))
    previous = records[0][3]
    headers = ({"If-None-Match": previous.etag} if previous and previous.etag
               and previous.payload.get('_source_url') == url else {})
    response = client.get_json(url, headers)
    if response.status == 304:
        if previous is None:
            raise ValueError('Source returned unchanged without a policy baseline')
        if previous.payload.get('_source_url', url) != url:
            raise ValueError('Source returned unchanged for a different policy URL')
        normalized = previous.payload
        current_fields = set(normalized.get('_source_fields', ()))
        for _, _, _, prior in records:
            if prior and set(prior.payload.get('_source_fields', ())) - current_fields:
                raise ValueError('Cached policy response is missing previously supplied fields')
    else:
        for _, _, _, prior in records:
            validate_source_payload(response.payload, prior.payload if prior else None)
        source_fields = validate_source_payload(response.payload)
        normalized = {**normalize(response.payload), '_source_fields': source_fields, '_source_url':url}
        if normalized['status'] == 'inactive':
            normalized['status'] = 'paused'
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
