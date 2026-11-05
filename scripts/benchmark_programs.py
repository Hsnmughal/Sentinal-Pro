"""Offline, synthetic benchmark for cold dossiers and warm program-card requests.

Run `python -m scripts.benchmark_programs --events 10000 --programs 40`.
No credentials or network sources are used. Results depend on the machine.
"""
from __future__ import annotations

import argparse
import http.client
import json
import tempfile
import threading
import time
from http.server import ThreadingHTTPServer
from pathlib import Path

from sentinal.research import dossiers
from sentinal.store import Store
from sentinal.web import _handler


def populate(store: Store, program_count: int, event_count: int) -> list[int]:
    store.import_program_defs([
        {'platform': 'manual', 'external_id': f'p{i}', 'protocol_id': f'p{i}',
         'name': f'Protocol {i}', 'targets': [
             {'source_type': 'github', 'target_key': f'team/p{i}',
              'config': {'repository': f'team/p{i}'}}
         ]}
        for i in range(program_count)
    ])
    pids = [p['id'] for p in store.list_programs()]
    when = '2026-10-17T12:00:00+00:00'
    patch = '@@ -1 +1 @@\n-old\n+new\n'
    rows = []
    for n in range(event_count):
        protocol_id = f'p{n % program_count}'
        rows.append((f'fingerprint-{n}', protocol_id, f'github:team/{protocol_id}',
                     'GITHUB_HEAD_CHANGED', f'team/{protocol_id}', '"old"', '"new"',
                     json.dumps({'repository': f'team/{protocol_id}',
                                 'changed_files': [{'path': 'src/Contract.sol', 'patch': patch}]}),
                     50, '["changed"]', 'lead', 'unresolved_mapping', '[]', 'new', when, when))
    with store.connect() as db:
        db.executemany('''INSERT INTO events(fingerprint,protocol_id,source_key,kind,entity,
            before_json,after_json,metadata_json,score,reasons_json,category,eligibility,
            evidence_json,status,detected_at,updated_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''', rows)
    return pids


def timed(action):
    start = time.perf_counter()
    value = action()
    return round((time.perf_counter() - start) * 1000, 2), value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--events', type=int, default=10000)
    parser.add_argument('--programs', type=int, default=40)
    args = parser.parse_args()
    if not (0 <= args.events <= 100000 and 1 <= args.programs <= 1000):
        parser.error('events must be 0..100000 and programs 1..1000')
    with tempfile.TemporaryDirectory() as temp:
        store = Store(Path(temp) / 'benchmark.db')
        store.initialize()
        ids = populate(store, args.programs, args.events)
        cold_all, _ = timed(lambda: dossiers(store))
        single, _ = timed(lambda: dossiers(store, ids[0]))
        server = ThreadingHTTPServer(('127.0.0.1', 0), _handler(store))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        def get():
            conn = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=60)
            try:
                conn.request('GET', '/api/programs')
                response = conn.getresponse()
                result = response.read()
                if response.status != 200:
                    raise RuntimeError(f'HTTP {response.status}')
                return len(result)
            finally:
                conn.close()
        try:
            cold_http, payload_bytes = timed(get)
            warm_http, _ = timed(get)
            warm_http2, _ = timed(get)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(5)
        print(json.dumps({
            'programs': args.programs, 'events': args.events,
            'cold_full_dossiers_ms': cold_all,
            'single_program_dossier_ms': single,
            'first_program_cards_http_ms': cold_http,
            'cached_program_cards_http_ms': [warm_http, warm_http2],
            'program_cards_response_bytes': payload_bytes,
        }, indent=2))


if __name__ == '__main__':
    main()
