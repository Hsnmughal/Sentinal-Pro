"""Minimal, local stdio MCP interface over Sentinal's existing SQLite store.

Implements the interoperable MCP 2025-11-25 JSON-RPC stdio subset for
initialize, ping, tools/list and tools/call. No network listener, dependency,
LLM, background scheduler, credentials or source polling is started here.
Standard input is a trusted local MCP host; this server must not be exposed
through an unauthenticated remote bridge.
"""
from __future__ import annotations

import json
import sys
import threading
import time
from typing import Any, TextIO

from .store import Store
from .research import safe_url

PROTOCOL_VERSION = '2025-11-25'
MAX_REQUEST_BYTES = 65_536
MAX_RESPONSE_BYTES = 96_000
MAX_PATCH_CHARS = 16_000
#: Characters of one recorded before/after value that get_change returns exactly.
#: A longer value is delivered as a bounded prefix of its recorded JSON text, and
#: the record says so instead of presenting part of a value as the whole one.
MAX_EVIDENCE_CHARS = 2_000
#: Most file summaries one get_change call returns; larger records are paged.
MAX_CHANGE_FILES = 100
#: Bytes reserved inside MAX_RESPONSE_BYTES for the JSON-RPC wrapper around the id.
ENVELOPE_RESERVE = 512
SERVER_NAME = 'sentinal-pro'


def _schema(properties: dict[str, dict[str, Any]] | None = None,
            required: tuple[str, ...] = ()) -> dict[str, Any]:
    return {'type': 'object', 'properties': properties or {},
            'required': list(required), 'additionalProperties': False}


def _int(default: int, minimum: int, maximum: int) -> dict[str, Any]:
    return {'type': 'integer', 'minimum': minimum, 'maximum': maximum, 'default': default}


def _text(limit: int = 150) -> dict[str, Any]:
    return {'type': 'string', 'maxLength': limit}


class ToolInputError(ValueError):
    """A tool argument is invalid; return an MCP tool error, not an exception trace."""


def _integer(value: Any, name: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ToolInputError(f'{name} must be an integer between {minimum} and {maximum}')
    return value


def _short(value: Any, *, maximum: int = 400) -> str | None:
    if value is None:
        return None
    if not isinstance(value, (str, int, float, bool)):
        return None
    return str(value)[:maximum]


def _url(value: Any) -> str | None:
    value = safe_url(value)
    return value[:500] if value else None


def _scope(value: Any) -> str:
    """Recorded patch scope, with the comparison default used everywhere else.

    ``comparison``, ``commit`` and ``legacy_unverified`` are the scopes the
    GitHub adapter and the schema migration record. A file stored without one is
    read as ``comparison`` by the adapter's projection, the export manifest and
    the dashboard, so an unrecorded scope is reported as that same value rather
    than as a second, empty state.
    """
    return _short(value, maximum=40) or 'comparison'


def _evidence(text: Any, recorded_chars: Any) -> tuple[Any, int | None]:
    """One recorded event before/after value, at its recorded JSON type.

    ``text`` is the stored JSON text of the value and ``recorded_chars`` its
    recorded character count, both read through ``substr``/``length`` so a large
    value never crosses IPC whole. A value inside ``MAX_EVIDENCE_CHARS`` is parsed
    and returned as recorded, so numbers, booleans, null, strings, arrays and
    objects keep their types exactly as the dashboard and the export manifest
    present them. A longer value is returned as the deterministic prefix of its
    stored text together with its recorded length, because a prefix is not valid
    JSON and a partial document must not be read as the complete one. Returns
    ``(value, recorded length or None when the value is complete)``. Absent and
    recorded-null columns both read as ``None``, the rule the store already uses.
    """
    if not text:
        return None, None
    if recorded_chars is not None and len(text) < int(recorded_chars):
        return text, int(recorded_chars)
    return json.loads(text), None


def _encode(data: Any) -> str:
    """One serializer for tool payloads, response envelopes and their size checks."""
    return json.dumps(data, ensure_ascii=False, separators=(',', ':'), default=str, allow_nan=False)


def _tool_result(data: dict[str, Any]) -> dict[str, Any]:
    """The tools/call result for one payload, exactly as the transport writes it.

    The payload crosses the wire twice - escaped a second time inside
    ``content[].text`` and duplicated as ``structuredContent`` - so a size check
    that measures only the payload understates the real response.
    """
    return {'content': [{'type': 'text', 'text': _encode(data)}],
            'structuredContent': data, 'isError': False}


def _response_sizes(data: dict[str, Any], request_id: Any = 0) -> tuple[int, int]:
    """(tool payload bytes, complete JSON-RPC envelope bytes) of a tool result.

    ``request_id`` is the id the envelope will actually carry, because it is part of
    the serialized response and has to be charged to the same cap the payload is. The
    default measures the placeholder the previous budget used when no request is in
    flight, such as a direct ``MonitoringTools`` call.
    """
    envelope = {'jsonrpc': '2.0', 'id': request_id, 'result': _tool_result(data)}
    return (len(_encode(data).encode('utf-8')),
            len(_encode(envelope).encode('utf-8')))


def _fits_transport(data: dict[str, Any], request_id: Any = 0) -> bool:
    """True when both existing response caps accept this tool payload and envelope.

    The envelope is measured with the request's own id, so a long or escaped id
    consumes the budget it really uses; ``ENVELOPE_RESERVE`` stays as the wrapper's
    margin. Escaping and non-ASCII content are measured as UTF-8 bytes for the same
    reason.
    """
    payload_bytes, envelope_bytes = _response_sizes(data, request_id)
    return (payload_bytes <= MAX_RESPONSE_BYTES // 2
            and envelope_bytes <= MAX_RESPONSE_BYTES - ENVELOPE_RESERVE)


def _fit_response(record: dict[str, Any], key: str, *, total: int, offset: int,
                  request_id: Any) -> dict[str, Any]:
    """Shorten ``record[key]`` to the longest prefix whose complete response fits.

    ``key`` names the one value a budgeted tool may shorten - the ``files`` of a
    change page or the ``text`` of a patch slice - and ``total`` the number of units
    the whole record holds, so ``has_more`` and ``next_offset`` describe exactly what
    is delivered. The serialized size grows with every unit, because the payload is
    duplicated as ``structuredContent`` and escaped again inside ``content[].text``
    and the envelope carries this request's own id; the count is therefore bisected,
    which costs log2(n) measurements instead of one per dropped unit, and the result
    is measured once more before it is returned. Units are dropped whole and never
    re-escaped, reordered or stripped of provenance.

    Raises ``ToolInputError`` when no unit can be delivered: a page that cannot make
    progress is a bounded error instead of an unanswerable or endless one.
    """
    values = record[key]
    low, high = 0, len(values)
    while low < high:
        middle = (low + high + 1) // 2
        record[key] = values[:middle]
        record['has_more'] = offset + middle < total
        record['next_offset'] = min(total, offset + middle)
        if _fits_transport(record, request_id):
            low = middle
        else:
            high = middle - 1
    record[key] = values[:low]
    record['has_more'] = offset + low < total
    record['next_offset'] = min(total, offset + low)
    if (low == 0 and values) or not _fits_transport(record, request_id):
        raise ToolInputError('Response cannot fit the transport cap with this request id')
    return record


def _tool(name: str, description: str, schema: dict[str, Any], *, read_only: bool = True) -> dict[str, Any]:
    return {'name': name, 'description': description, 'inputSchema': schema,
            'annotations': {'readOnlyHint': read_only, 'destructiveHint': False,
                            'openWorldHint': not read_only}}


class MonitoringTools:
    """Small and explicitly allowlisted boundary around locally stored evidence."""

    def __init__(self, store: Store, *, enable_queue: bool = False):
        self.store = store
        self.enable_queue = enable_queue
        self._queue_lock = threading.Lock()
        self._last_queue = 0.0
        self._pollable = tuple(sorted(
            key for key in store.adapters.source_types()
            if not store.adapters[key].manifest.polling.manual_only
        ))

    def definitions(self) -> list[dict[str, Any]]:
        tools = [
            _tool('list_programs', 'List watched programs, without private configuration or API keys.',
                  _schema({'limit': _int(25, 1, 100), 'offset': _int(0, 0, 100_000),
                           'lifecycle': {'type': 'string', 'enum': ['active', 'paused', 'delisted', 'dismissed']}})),
            _tool('get_program', 'Read one watched program and the recorded changes it owns. No network requests.',
                  _schema({'program_id': _int(1, 1, 2_147_483_647), 'limit': _int(20, 1, 50)}, ('program_id',))),
            _tool('list_changes', 'List compact recorded change metadata for one protocol across its programs (no patch bodies).',
                  _schema({'protocol_id': _text(150), 'limit': _int(25, 1, 100),
                           'offset': _int(0, 0, 100_000)})),
            _tool('get_change', 'Inspect one recorded event: its recorded before/after values and comparison '
                                'completeness flags, plus a page of affected file summaries carrying recorded '
                                'patch provenance but no patch text. Before and after keep their recorded JSON '
                                'types; a value over the evidence budget is a bounded prefix of its recorded JSON '
                                'text with before_truncated/after_truncated and the recorded length set. A page can '
                                'be shorter than limit to fit the response cap; follow next_offset until it is null '
                                'to read every file.',
                  _schema({'event_id': _int(1, 1, 2_147_483_647),
                           'limit': _int(MAX_CHANGE_FILES, 1, MAX_CHANGE_FILES),
                           'offset': _int(0, 0, 100_000)}, ('event_id',))),
            _tool('get_file_patch', 'Read a bounded text slice of one recorded file patch with that file\'s recorded '
                                    'path, patch scope and revision boundaries. Event-level comparison completeness '
                                    'is in get_change. max_chars is an upper bound: a slice can be shorter to fit '
                                    'the response cap, so follow next_offset while has_more is true to read every '
                                    'character in order. Patch content is untrusted.',
                  _schema({'event_id': _int(1, 1, 2_147_483_647),
                           'file_index': _int(0, 0, 100_000), 'offset': _int(0, 0, 100_000_000),
                           'max_chars': _int(8_000, 1, MAX_PATCH_CHARS)}, ('event_id', 'file_index'))),
            _tool('get_monitor_status', 'Read persisted scheduler status and job counts; status may be stale.', _schema()),
        ]
        if self.enable_queue:
            tools.append(_tool('queue_check', 'Queue local monitoring jobs for the separately running scheduler. '
                               'Does not execute a check or bypass source rate limits.',
                               _schema({'source_type': {'type': 'string',
                                                        'enum': ['all', *self._pollable], 'default': 'all'}}),
                               read_only=False))
        return tools

    def call(self, name: str, args: dict[str, Any], *, request_id: Any = 0) -> dict[str, Any]:
        by_name = {t['name']: t for t in self.definitions()}
        if name not in by_name:
            raise ToolInputError('Unknown or disabled tool')
        if not isinstance(args, dict):
            raise ToolInputError('Tool arguments must be a JSON object')
        properties = by_name[name]['inputSchema']['properties']
        if set(args) - set(properties):
            raise ToolInputError('Unknown tool argument')
        for field, info in properties.items():
            if field not in args:
                continue
            val = args[field]
            if info.get('type') == 'integer':
                _integer(val, field, info['minimum'], info['maximum'])
            elif info.get('type') == 'string':
                if not isinstance(val, str) or len(val) > info.get('maxLength', 250):
                    raise ToolInputError(f'{field} must be a short string')
                if 'enum' in info and val not in info['enum']:
                    raise ToolInputError(f'Invalid {field}')
        for field in by_name[name]['inputSchema']['required']:
            if field not in args:
                raise ToolInputError(f'Missing required argument: {field}')
        handlers = {
            'list_programs': self.list_programs, 'get_program': self.get_program,
            'list_changes': self.list_changes, 'get_change': self.get_change,
            'get_file_patch': self.get_file_patch, 'get_monitor_status': self.get_monitor_status,
            'queue_check': self.queue_check,
        }
        if name in ('get_change', 'get_file_patch'):
            # These two shorten their own payload to the transport budget, so they need
            # the id the envelope will carry. It is not a tool argument and never
            # appears in the advertised schema, so it cannot be supplied by the caller.
            return handlers[name](request_id=request_id, **args)
        return handlers[name](**args)

    def list_programs(self, *, limit: int = 25, offset: int = 0,
                      lifecycle: str | None = None) -> dict[str, Any]:
        # SQL paging avoids building every program and unpacking metadata/config.
        where = 'WHERE lifecycle = ?' if lifecycle else ''
        params: tuple[Any, ...] = (lifecycle,) if lifecycle else ()
        with self.store.connect() as db:
            count = db.execute(f'SELECT count(*) FROM programs {where}', params).fetchone()[0]
            rows = db.execute(f'''SELECT id, protocol_id, name, platform, lifecycle, url, max_bounty
                                  FROM programs {where} ORDER BY platform, external_id
                                  LIMIT ? OFFSET ?''', (*params, limit, offset)).fetchall()
        return {'programs': [{**{k: row[k] for k in ('id', 'platform', 'lifecycle', 'max_bounty')},
                              'protocol_id': _short(row['protocol_id'], maximum=150),
                              'name': _short(row['name'], maximum=200),
                              'url': _url(row['url'])} for row in rows],
                'total': count, 'limit': limit, 'offset': offset}

    def get_program(self, *, program_id: int, limit: int = 20) -> dict[str, Any]:
        with self.store.connect() as db:
            program = db.execute('''SELECT id, protocol_id, name, platform, lifecycle, url, max_bounty
                                    FROM programs WHERE id = ?''', (program_id,)).fetchone()
        if program is None:
            raise ToolInputError('Program not found')
        # The store applies the dossier ownership rules and pages afterwards, so a
        # shared protocol cannot let another program's events fill this program's page.
        changes = self.store.list_program_events(program_id, limit=limit)
        return {'program': {**{k: program[k] for k in ('id', 'platform', 'lifecycle', 'max_bounty')},
                            'protocol_id': _short(program['protocol_id'], maximum=150),
                            'name': _short(program['name'], maximum=200),
                            'url': _url(program['url'])},
                'recent_changes': [self._change_record(row) for row in changes]}

    def list_changes(self, *, protocol_id: str | None = None, limit: int = 25,
                     offset: int = 0) -> dict[str, Any]:
        where = "WHERE category != 'baseline'"
        params: tuple[Any, ...] = ()
        if protocol_id is not None:
            if not protocol_id.strip():
                raise ToolInputError('protocol_id cannot be empty')
            where += ' AND protocol_id = ?'
            params = (protocol_id,)
        with self.store.connect() as db:
            rows = db.execute(f'''SELECT id, protocol_id, kind, category, entity, status,
                                         detected_at, score, eligibility,
                                         json_extract(metadata_json, '$.repository') AS repository,
                                         json_array_length(json_extract(metadata_json, '$.changed_files')) AS file_count
                                  FROM events {where} ORDER BY detected_at DESC, id DESC
                                  LIMIT ? OFFSET ?''', (*params, limit, offset)).fetchall()
        return {'changes': [self._change_record(row) for row in rows], 'limit': limit, 'offset': offset,
                'has_more': len(rows) == limit}

    @staticmethod
    def _change_record(row: Any) -> dict[str, Any]:
        """One compact change row, shared by the protocol page and program reads.

        Accepts the SQLite row or the store's projected mapping; both are read by
        column name only.
        """
        return {
            'id': row['id'], 'protocol_id': _short(row['protocol_id'], maximum=150),
            'kind': _short(row['kind'], maximum=100),
            'category': _short(row['category'], maximum=80), 'entity': _short(row['entity'], maximum=250),
            'status': _short(row['status'], maximum=80), 'detected_at': row['detected_at'], 'score': row['score'],
            'eligibility': row['eligibility'], 'repository': _short(row['repository'], maximum=250),
            'file_count': row['file_count'] or 0,
        }

    def get_change(self, *, event_id: int, limit: int = MAX_CHANGE_FILES,
                   offset: int = 0, request_id: Any = 0) -> dict[str, Any]:
        """One event plus one page of recorded file provenance, without patch bodies.

        ``before`` and ``after`` are the values the event recorded, kept at their
        JSON types: a bounty amount stays a number, a revision or implementation
        address stays a string, a policy entry stays an object. A value that fits
        ``MAX_EVIDENCE_CHARS`` is returned exactly as the dashboard and the export
        manifest present it. A larger one is returned as the deterministic prefix
        of its recorded JSON text with ``before_truncated`` / ``after_truncated``
        set and ``before_chars`` / ``after_chars`` holding its recorded length, so
        a bounded answer is never read as the whole value; event evidence itself is
        not paged, unlike the per-file patches ``get_file_patch`` addresses.
        Absent and recorded-null columns both read as ``null``, the store's rule.

        Completeness is reported as separate recorded facts, matching the export
        manifest and the dashboard rather than one summary boolean:
        ``comparison_truncated`` is the comparison's own truncation flag,
        ``history_rewritten`` is a diverged/behind comparison, and
        ``comparison_incomplete`` is their union. ``patch_coverage_unverified``
        marks historical patches whose revision coverage is unverified, and
        ``patch_range_unavailable`` with ``patch_unavailable_reason`` explains an
        absent file comparison. Event-level facts are repeated on every page.

        Each file carries its own ``patch_scope`` (``comparison``, ``commit`` or
        ``legacy_unverified``), recorded ``patch_before`` / ``patch_after``
        boundaries and ``patch_truncated``. A null boundary is simply not
        recorded: under ``commit`` scope a null ``patch_before`` is an empty-tree
        parent only when the recorded patch is present and no
        ``patch_unavailable_reason`` was recorded; with that reason the parent is
        unknown, which is not a root commit. A null ``patch_after`` is never a
        known empty-tree destination.

        ``files`` is a page of at most ``limit`` summaries from the stable
        original index ``offset``, and each entry keeps its absolute
        ``file_index`` so ``get_file_patch`` addresses the stored file. A page is
        shortened only by dropping whole trailing entries when the complete
        serialized JSON-RPC response - the request's own id, the escaped copy inside
        ``content[].text`` and the ``structuredContent`` duplicate included - would
        otherwise exceed the transport cap; ``has_more`` and ``next_offset`` then say
        exactly where to resume, and no provenance field or warning is removed to make
        a page fit.
        """
        with self.store.connect() as db:
            # Recorded before/after evidence crosses IPC only as a bounded prefix;
            # length() reports the recorded size of the value that prefix belongs to.
            row = db.execute('''SELECT id, protocol_id, kind, category, entity, status,
                                       detected_at, score, eligibility,
                                       length(before_json) AS before_chars,
                                       substr(before_json, 1, ?) AS before_text,
                                       length(after_json) AS after_chars,
                                       substr(after_json, 1, ?) AS after_text
                                FROM events WHERE id = ?''',
                             (MAX_EVIDENCE_CHARS, MAX_EVIDENCE_CHARS, event_id)).fetchone()
            if row is None:
                raise ToolInputError('Event not found')
            # SQLite JSON extraction keeps patch bodies out of the Python process.
            # Paging runs in SQL too; json_each.key is the stable original index.
            page = db.execute('''SELECT
                json_each.key AS file_index,
                json_extract(value, '$.path') AS path,
                json_extract(value, '$.filename') AS filename,
                json_extract(value, '$.status') AS status,
                json_extract(value, '$.patch_truncated') AS patch_truncated,
                json_extract(value, '$.patch_scope') AS patch_scope,
                json_extract(value, '$.patch_before') AS patch_before,
                json_extract(value, '$.patch_after') AS patch_after,
                json_extract(value, '$.patch_unavailable_reason') AS patch_unavailable_reason,
                CASE WHEN length(json_extract(value, '$.patch')) > 0 THEN 1 ELSE 0 END AS has_patch
                FROM json_each((SELECT json_extract(metadata_json, '$.changed_files')
                                FROM events WHERE id = ?)) LIMIT ? OFFSET ?''',
                             (event_id, limit, offset)).fetchall()
            # Only small, allowlisted scalar metadata. Never return raw metadata_json.
            meta = db.execute('''SELECT json_extract(metadata_json, '$.repository') AS repository,
                        json_extract(metadata_json, '$.compare_url') AS compare_url,
                        json_extract(metadata_json, '$.truncated') AS truncated,
                        json_extract(metadata_json, '$.history_rewritten') AS history_rewritten,
                        json_extract(metadata_json, '$.patch_coverage_unverified') AS patch_coverage_unverified,
                        json_extract(metadata_json, '$.patch_range_unavailable') AS patch_range_unavailable,
                        json_extract(metadata_json, '$.patch_unavailable_reason') AS patch_unavailable_reason,
                        json_array_length(json_extract(metadata_json, '$.changed_files')) AS file_count
                        FROM events WHERE id = ?''', (event_id,)).fetchone()
        total = int(meta['file_count'] or 0)
        truncated = bool(meta['truncated'])
        rewritten = bool(meta['history_rewritten'])
        before, before_chars = _evidence(row['before_text'], row['before_chars'])
        after, after_chars = _evidence(row['after_text'], row['after_chars'])
        record = {'id': row['id'], 'protocol_id': _short(row['protocol_id'], maximum=150),
                  'kind': _short(row['kind'], maximum=100), 'category': _short(row['category'], maximum=80),
                  'entity': _short(row['entity'], maximum=250), 'status': row['status'],
                  'detected_at': row['detected_at'], 'score': row['score'],
                  'eligibility': row['eligibility'],
                  'repository': _short(meta['repository'], maximum=250),
                  'compare_url': _url(meta['compare_url']),
                  'before': before, 'after': after,
                  'evidence_truncated': before_chars is not None or after_chars is not None,
                  'comparison_truncated': truncated,
                  'history_rewritten': rewritten,
                  'comparison_incomplete': truncated or rewritten,
                  'patch_coverage_unverified': bool(meta['patch_coverage_unverified']),
                  'patch_range_unavailable': bool(meta['patch_range_unavailable']),
                  'file_count': total,
                  'offset': offset, 'limit': limit,
                  'files_truncated': total > MAX_CHANGE_FILES,
                  'files': [{'file_index': file['file_index'],
                             'path': _short(file['path'] or file['filename'], maximum=350),
                             'status': _short(file['status'], maximum=40),
                             'has_patch': bool(file['has_patch']),
                             'patch_truncated': bool(file['patch_truncated']),
                             'patch_scope': _scope(file['patch_scope']),
                             'patch_before': _short(file['patch_before'], maximum=200),
                             'patch_after': _short(file['patch_after'], maximum=200),
                             **({'patch_unavailable_reason': _short(file['patch_unavailable_reason'], maximum=400)}
                                if file['patch_unavailable_reason'] else {})}
                            for file in page]}
        if before_chars is not None:
            record['before_truncated'] = True
            record['before_chars'] = before_chars
        if after_chars is not None:
            record['after_truncated'] = True
            record['after_chars'] = after_chars
        if meta['patch_unavailable_reason']:
            record['patch_unavailable_reason'] = _short(meta['patch_unavailable_reason'], maximum=400)
        # Fit the real wire budget - the envelope's own request id, the escaped copy
        # inside content[].text and the structuredContent duplicate - by dropping whole
        # trailing entries, never by removing a provenance field or a warning.
        _fit_response(record, 'files', total=total, offset=offset, request_id=request_id)
        if not record['has_more']:
            # A completed list keeps reporting its end as an explicit null.
            record['next_offset'] = None
        return record

    def get_file_patch(self, *, event_id: int, file_index: int,
                       offset: int = 0, max_chars: int = 8_000,
                       request_id: Any = 0) -> dict[str, Any]:
        """One bounded patch slice with the provenance recorded for that file.

        The slice can be interpreted on its own: it names the file, its
        ``patch_scope`` and the revision boundaries that patch was recorded
        against, so an individual commit patch is not mistaken for the full
        observed comparison. Comparison-level completeness lives in
        ``get_change`` for the same ``event_id``.

        ``max_chars`` is an upper bound. Control characters and non-ASCII text cost
        more than one byte per character once the slice is escaped inside
        ``content[].text`` and duplicated as ``structuredContent``, so a slice that
        would not fit the transport cap - together with the request's own id - is
        shortened from its end at a character boundary. ``total_chars`` still reports
        the recorded length of the whole patch and ``next_offset`` the position after
        the text actually returned, so following ``next_offset`` while ``has_more`` is
        true reads the patch exactly once, in order.
        """
        # substr() returns only a bounded slice across IPC. Offsets are 0-based.
        prefix = f'$.changed_files[{file_index}]'
        with self.store.connect() as db:
            row = db.execute('''SELECT length(json_extract(metadata_json, ?)) AS total_chars,
                                substr(json_extract(metadata_json, ?), ?, ?) AS patch,
                                json_extract(metadata_json, ?, ?, ?, ?, ?, ?) AS provenance
                                FROM events WHERE id = ?''',
                             (f'{prefix}.patch', f'{prefix}.patch', offset + 1, max_chars,
                              f'{prefix}.path', f'{prefix}.filename', f'{prefix}.patch_scope',
                              f'{prefix}.patch_before', f'{prefix}.patch_after',
                              f'{prefix}.patch_truncated', event_id)).fetchone()
        if row is None or row['total_chars'] is None:
            raise ToolInputError('File patch not found')
        count = row['total_chars'] or 0
        if count == 0:
            raise ToolInputError('File patch not recorded')
        path, filename, scope, before, after, patch_truncated = json.loads(row['provenance'])
        text = row['patch'] or ''
        record = {'event_id': event_id, 'file_index': file_index,
                  'path': _short(path or filename, maximum=350),
                  'patch_scope': _scope(scope),
                  'patch_before': _short(before, maximum=200),
                  'patch_after': _short(after, maximum=200),
                  'patch_truncated': bool(patch_truncated),
                  'offset': offset, 'text': text, 'total_chars': count,
                  'next_offset': min(count, offset + len(text)),
                  'has_more': offset + len(text) < count,
                  'untrusted_content': True}
        # The recorded characters are returned as they are; only the length of the
        # slice is reduced, to the largest prefix whose whole response fits.
        return _fit_response(record, 'text', total=count, offset=offset, request_id=request_id)

    def get_monitor_status(self) -> dict[str, Any]:
        with self.store.connect() as db:
            jobs = db.execute('''SELECT COALESCE(last_status, 'unknown') AS state,
                                       COUNT(*) AS amount FROM poll_jobs GROUP BY last_status''').fetchall()
            queued = db.execute('SELECT COUNT(*) FROM poll_jobs WHERE manually_queued = 1').fetchone()[0]
        value = self.store.get_runtime_status('scheduler')
        if isinstance(value, dict):
            scheduler = {key: value.get(key) for key in ('state', 'started_at', 'stopped_at', 'failed_at', 'tick_seconds')
                         if key in value}
        else:
            scheduler = {'state': 'unknown'}
        return {'scheduler_last_recorded': scheduler, 'status_is_live': False,
                'job_counts': {row['state']: row['amount'] for row in jobs},
                'manually_queued_jobs': queued,
                'note': 'Run sentinal run separately for automatic monitoring. Stored status may be stale.'}

    def queue_check(self, *, source_type: str = 'all') -> dict[str, Any]:
        if not self.enable_queue or source_type not in ('all', *self._pollable):
            raise ToolInputError('Queueing disabled or source unavailable')
        with self._queue_lock:
            now = time.monotonic()
            if now - self._last_queue < 60:
                raise ToolInputError('Manual check already queued recently; retry after 60 seconds')
            count = self.store.force_jobs(None if source_type == 'all' else source_type)
            self._last_queue = now
        return {'queued_jobs': count, 'source_type': source_type,
                'message': 'Jobs queued in SQLite. A separately running scheduler executes them subject to source limits.'}


def _echoable_id(value: Any) -> bool:
    """True when a request id can be echoed inside a UTF-8 JSON-RPC response.

    ``json.loads`` accepts ``\\udXXX`` escapes and yields a lone surrogate for one that
    is not a valid pair, so a request line of pure ASCII can decode to a string this
    transport cannot encode. Only U+D800-U+DFFF are affected: Python strings hold an
    astral character, including the decoded form of a valid pair, as one code point.
    A surrogate-bearing id is refused rather than rewritten or escaped, because
    answering with a different id would answer a different request.
    """
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        return False
    return not isinstance(value, str) or not any('\ud800' <= character <= '\udfff'
                                                 for character in value)


def _utf8_stream(stream: TextIO, *, errors: str) -> TextIO:
    """Bind an inherited process stream to UTF-8 without wrapping or closing it.

    A Windows pipe inherits the legacy ANSI code page, so under cp1252 a
    non-ASCII program name raised UnicodeEncodeError on stdout, or was written as
    bytes that are not valid UTF-8, and incoming UTF-8 was mis-decoded. Rebinding
    the codec of the existing text wrapper keeps one buffer, one encoder and one
    close path for the stream; streams without reconfigure support pass through.
    """
    reconfigure = getattr(stream, 'reconfigure', None)
    if callable(reconfigure):
        reconfigure(encoding='utf-8', errors=errors)
    return stream


class MCPStdioServer:
    """Newline-delimited JSON-RPC over stdin/stdout; stdout is protocol only."""

    def __init__(self, tools: MonitoringTools, *, input_stream: TextIO | None = None,
                 output_stream: TextIO | None = None):
        self.tools = tools
        # Invalid UTF-8 is preserved as surrogates (PEP 383) so run() can reject the line:
        # errors='replace' would rewrite the bytes as U+FFFD and let a corrupted request run.
        self.stdin = input_stream if input_stream is not None else _utf8_stream(sys.stdin, errors='surrogateescape')
        self.stdout = output_stream if output_stream is not None else _utf8_stream(sys.stdout, errors='strict')
        self.initialized = False

    def _send(self, data: dict[str, Any]) -> None:
        try:
            encoded = _encode(data)
        except ValueError:
            # A bare NaN/Infinity is not JSON; answer with a valid error line instead
            # of writing an unparseable one or letting the encoder end the session.
            encoded = _encode(self._error(data.get('id'), -32603, 'Response contains a non-finite number'))
        if len(encoded.encode('utf-8')) > MAX_RESPONSE_BYTES:
            raise RuntimeError('MCP response exceeded size limit')
        self.stdout.write(encoded + '\n')
        self.stdout.flush()

    @staticmethod
    def _error(request_id: Any, code: int, message: str) -> dict[str, Any]:
        return {'jsonrpc': '2.0', 'id': request_id,
                'error': {'code': code, 'message': message}}

    def handle(self, message: Any) -> dict[str, Any] | None:
        if not isinstance(message, dict) or message.get('jsonrpc') != '2.0':
            return self._error(None, -32600, 'Invalid JSON-RPC request')
        request_id = message.get('id')
        if request_id is not None and not _echoable_id(request_id):
            # A lone surrogate decoded from an escape cannot be written back as UTF-8.
            # The error carries a null id instead, so rejecting one request cannot
            # take the session's following requests down with it.
            return self._error(None, -32600, 'Invalid JSON-RPC id')
        method = message.get('method')
        if not isinstance(method, str):
            return self._error(request_id, -32600, 'Invalid method')
        if method == 'notifications/initialized':
            return None
        if request_id is None:
            return None  # Notifications are one-way.
        params = message.get('params', {})
        if not isinstance(params, dict):
            return self._error(request_id, -32602, 'Params must be an object')
        if method == 'initialize':
            # MCP 2025-11-25; v2 SDK clients negotiate legacy fallback.
            self.initialized = True
            result = {'protocolVersion': PROTOCOL_VERSION,
                      'capabilities': {'tools': {'listChanged': False}},
                      'serverInfo': {'name': SERVER_NAME, 'version': '0.1.5'}}
        elif method == 'ping':
            result = {}
        elif not self.initialized:
            return self._error(request_id, -32002, 'Initialize MCP session before calling tools')
        elif method == 'tools/list':
            result = {'tools': self.tools.definitions()}
        elif method == 'tools/call':
            name = params.get('name')
            if not isinstance(name, str):
                return self._error(request_id, -32602, 'Tool name is required')
            args = params.get('arguments', {})
            try:
                data = self.tools.call(name, args, request_id=request_id)
                if len(_encode(data).encode('utf-8')) > MAX_RESPONSE_BYTES // 2:
                    raise ToolInputError('Tool result too large; reduce limit or request a smaller patch slice')
                result = _tool_result(data)
            except (ToolInputError, ValueError) as error:
                result = {'content': [{'type': 'text', 'text': str(error)}], 'isError': True}
            except Exception as error:
                # No raw SQLite exception details, credentials, stack traces to the agent.
                print(f'MCP tool {name!r} failed: {type(error).__name__}', file=sys.stderr)
                result = {'content': [{'type': 'text', 'text': 'Local data operation failed; see application logs'}],
                          'isError': True}
        else:
            return self._error(request_id, -32601, 'Method not found')
        return {'jsonrpc': '2.0', 'id': request_id, 'result': result}

    @staticmethod
    def _malformed_utf8(raw: str) -> bool:
        """True when the line still holds surrogate-escaped bytes, so it was not valid UTF-8."""
        return any('\udc80' <= character <= '\udcff' for character in raw)

    def run(self) -> None:
        while True:
            raw = self.stdin.readline(MAX_REQUEST_BYTES + 1)
            if not raw:
                return
            # Surrogate-escaped bytes encode back to their original length, so limits stay exact
            # and cannot raise; the line was fully consumed, so a bad line cannot disturb the next.
            size = len(raw.encode('utf-8', errors='surrogateescape'))
            if size > MAX_REQUEST_BYTES:
                # Drain overlong line in bounded chunks before resuming.
                while raw and not raw.endswith('\n'):
                    raw = self.stdin.readline(MAX_REQUEST_BYTES + 1)
                self._send(self._error(None, -32700, 'MCP request exceeds 64 KiB'))
                continue
            if not raw.endswith('\n'):
                # readline() stops without a newline only at end of input, so this is a final frame
                # the host never terminated. It is rejected as an incomplete line rather than being
                # answered as a whole request, and the next read sees the empty string and returns.
                # Size keeps its precedence above: an overlong line is reported as one.
                self._send(self._error(None, -32700, 'MCP request line is incomplete'))
                continue
            if self._malformed_utf8(raw):
                # json.loads accepts surrogates, so reject before parsing instead of dispatching.
                self._send(self._error(None, -32700, 'MCP request is not valid UTF-8'))
                continue
            try:
                message = json.loads(raw)
            except (ValueError, UnicodeError, RecursionError):
                self._send(self._error(None, -32700, 'Invalid JSON'))
                continue
            response = self.handle(message)
            if response is not None:
                try:
                    self._send(response)
                except RuntimeError:
                    self._send(self._error(response.get('id'), -32603, 'Response size limit exceeded'))


def serve_mcp(store: Store, *, enable_queue: bool = False) -> None:
    MCPStdioServer(MonitoringTools(store, enable_queue=enable_queue)).run()
