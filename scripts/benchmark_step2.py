"""Offline payload benchmark for Step 2's lazy recorded-diff API.

Run `python -m scripts.benchmark_step2 --events 12 --patch-kib 128`.

Numbers are synthetic, local, and not a claim about production latency.
"""
from __future__ import annotations

import argparse
import http.client
import json
import random
import string
import tempfile
import threading
import time
from http.server import ThreadingHTTPServer
from pathlib import Path

from sentinal.research import dossiers
from sentinal.store import Store
from sentinal.web import _handler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--events', type=int, default=12)
    parser.add_argument('--patch-kib', type=int, default=128)
    args = parser.parse_args()
    if not (1 <= args.events <= 100 and 1 <= args.patch_kib <= 512):
        parser.error('events must be 1..100 and patch-kib 1..512')
    with tempfile.TemporaryDirectory() as directory:
        store = Store(Path(directory) / 'benchmark.db')
        store.initialize()
        store.import_program_defs([{
            'platform': 'manual', 'external_id': 'demo', 'protocol_id': 'demo',
            'name': 'Demo', 'targets': [{'source_type': 'github', 'target_key': 'demo/core',
                                        'config': {'repository': 'demo/core'}}],
        }])
        pid = store.list_programs()[0]['id']
        chars = string.ascii_letters + string.digits
        rng = random.Random(99)
        patch = '@@ -1 +1 @@\n+' + ''.join(rng.choices(chars, k=args.patch_kib * 1024)) + '\n'
        rows = [(
            f'event-{n}', 'demo', 'github:demo/core', 'GITHUB_HEAD_CHANGED', 'demo/core',
            '"prev"', '"next"',
            json.dumps({'repository': 'demo/core', 'changed_files': [
                {'path': f'src/Contract{n}.sol', 'patch': patch}]}),
            50, '["changed"]', 'lead', 'unresolved_mapping', '[]', 'new',
            '2026-10-19T00:00:00+00:00', '2026-10-19T00:00:00+00:00',
        ) for n in range(args.events)]
        with store.connect() as db:
            db.executemany('''INSERT INTO events(fingerprint,protocol_id,source_key,kind,entity,
                before_json,after_json,metadata_json,score,reasons_json,category,eligibility,
                evidence_json,status,detected_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''', rows)
        dossier = dossiers(store, pid)[0]
        legacy_size = len(json.dumps(dossier, default=str).encode())
        server = ThreadingHTTPServer(('127.0.0.1', 0), _handler(store))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        def get(endpoint):
            client = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=30)
            try:
                before = time.perf_counter()
                client.request('GET', endpoint)
                response = client.getresponse()
                payload = response.read()
                if response.status != 200:
                    raise RuntimeError(f'HTTP {response.status}: {endpoint}')
                return len(payload), round((time.perf_counter() - before) * 1000, 2)
            finally:
                client.close()
        try:
            summary_size, summary_ms = get(f'/api/programs/{pid}')
            patch_size, patch_ms = get('/api/events/1/files/0/patch')
            zip_size, zip_ms = get(f'/api/programs/{pid}/package')
        finally:
            server.shutdown()
            server.server_close()
            thread.join(5)
        print(json.dumps({
            'events': args.events, 'patch_kib': args.patch_kib,
            'previous_full_dossier_bytes_estimate': legacy_size,
            'optimized_detail_bytes': summary_size,
            'response_reduction_percent': round((1 - summary_size / legacy_size) * 100, 2),
            'detail_request_ms': summary_ms,
            'single_patch_response_bytes': patch_size, 'single_patch_request_ms': patch_ms,
            'complete_zip_bytes': zip_size, 'zip_request_ms': zip_ms,
        }, indent=2))


if __name__ == '__main__':
    main()
