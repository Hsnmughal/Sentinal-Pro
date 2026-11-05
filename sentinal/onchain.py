"""Program-specific, user-triggered checks of scoped contract addresses."""
from __future__ import annotations

import os
import threading
from copy import deepcopy
from uuid import uuid4
from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext
from datetime import datetime, timezone

from .adapters.evm.adapter import discover_assets, inspect_asset, OnchainConfigError
from .core.http import RequestDeferred
from .core.models import EventCandidate, ScoredEvent


def now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def asset_key(asset):
    return f'{asset["chain_id"]}:{asset["proxy"].lower()}'


def program_view(program, policy, changes, status=None):
    assets = {asset_key(asset): asset for asset in discover_assets(policy)}
    for target in program.get('targets', []):
        if target['active'] and target['source_type'] == 'evm':
            config = target['config']
            if config.get('proxy') and config.get('chain_id') and config.get('rpc_env'):
                assets[asset_key(config)] = {**assets.get(asset_key(config), {}), **config}
    if not assets:
        return None
    status = status or {}
    rows = []
    for key, asset in sorted(assets.items()):
        rows.append({**asset, 'address': asset['proxy'], 'chain': asset.get('chain') or f'Chain {asset["chain_id"]}',
                     'label': asset.get('label') or asset['proxy'],
                     'configured': bool(os.getenv(asset['rpc_env'])), 'result': status.get('results', {}).get(key)})
    return {'assets': rows, 'configured_count': sum(row['configured'] for row in rows),
            'has_changes': any('implementation_upgrade' not in event.get('source_tags', []) for event in changes),
            **{key: status.get(key) for key in ('state', 'started_at', 'checked_at', 'total', 'completed', 'error_count', 'error')}}


class OnchainChecks:
    def __init__(self, store, client):
        self.store, self.client = store, client
        self._lock = threading.RLock()
        self._running = set()
        self._terminal = {}
        self._futures = {}
        self._accepted = {}
        self._runs = {}
        self._executor = None
        self._stop = threading.Event()
        self.store.onchain_status = self.status

    def _persist_terminal(self, program_id):
        """Retry only status persistence; never copy an uncommitted baseline."""
        terminal = self._terminal.get(program_id)
        if terminal is None:
            return None
        try:
            with self.store.connect(timeout=0) as connection:
                if not connection.in_transaction:
                    connection.execute('BEGIN IMMEDIATE')
                current = self.store.get_runtime_status(f'onchain:{program_id}') or {}
                if current.get('check_id') != terminal.get('check_id'):
                    self._terminal.pop(program_id, None)
                    return current  # A newer accepted check owns the saved state.
                if terminal.get('_orphaned') and current.get('state') != 'running':
                    self._terminal.pop(program_id, None)
                    return current  # A stale dashboard snapshot raced with completion.
                state = {**current, **{key:terminal[key] for key in ('state','error','checked_at') if key in terminal}}
                self.store.set_runtime_status(f'onchain:{program_id}', state, touch_queue=True)
            self._terminal.pop(program_id, None)
            return state
        except Exception:
            return deepcopy(terminal)  # Expose the terminal state while storage recovers.

    def status(self, program_id, persisted=None):
        with self._lock:
            if program_id in self._terminal:
                return self._persist_terminal(program_id)
            if persisted and persisted.get('state') == 'running' and program_id not in self._running:
                self._terminal[program_id] = {**deepcopy(persisted), 'state':'interrupted',
                    'error':'Previous manual check was interrupted. Click to retry.', 'checked_at':now(), '_orphaned':True}
                return self._persist_terminal(program_id)
            return persisted

    def _finish(self, program_id, state):
        with self._lock:
            if program_id in self._runs and self._runs[program_id] != state.get('check_id'):
                return
            self._terminal[program_id] = deepcopy(state)
            self._running.discard(program_id)
            self._persist_terminal(program_id)
        # Brief lock contention should not require a dashboard read to publish
        # completion. Longer outages retain the overlay for later reconciliation.
        for _ in range(5):
            with self._lock:
                if program_id not in self._terminal:
                    return
            if self._stop.wait(0.05):
                return
            with self._lock:
                self._persist_terminal(program_id)

    def recover(self):
        for key, row in self.store.runtime_status().items():
            if key.startswith('onchain:') and isinstance(row['value'], dict) and row['value'].get('state') == 'running':
                self.status(int(key.split(':',1)[1]), row['value'])

    def queue(self, program_id):
        from .research import dossiers
        if self._stop.is_set():
            raise ValueError('Manual checks are stopping.')
        program = self.store.get_program(program_id)
        if program is None:
            raise KeyError('Program not found')
        if program['lifecycle'] != 'active':
            raise ValueError('On-chain checks are available for active programs only.')
        rows = dossiers(self.store, program_id)
        view = rows[0]['onchain']
        if not view or not view['assets']:
            raise ValueError('This program has no supported scoped on-chain assets.')
        if not view['has_changes']:
            raise ValueError('No code or program changes have been recorded for this program yet.')
        if not view['configured_count']:
            raise ValueError('Configure the required RPC environment variables and restart the app.')
        with self._lock:
            if program_id in self._running:
                return False
            self._running.add(program_id)
            state = {}
            try:
                previous = self.store.get_runtime_status(f'onchain:{program_id}') or {}
                state = {**previous, 'state': 'running', 'started_at': now(), 'checked_at': None,
                         'completed': 0, 'total': len(view['assets']), 'error_count': 0, 'error': None,
                         'check_id':uuid4().hex}
                self._runs[program_id] = state['check_id']
                self.store.set_runtime_status(f'onchain:{program_id}', state, touch_queue=True)
                self._terminal.pop(program_id, None)
                self._accepted[program_id] = deepcopy(state)
                if self._executor is None:
                    self._executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix='manual-onchain')
                self._futures[program_id] = self._executor.submit(self._run, program, view['assets'], state)
            except Exception:
                self._finish(program_id, {**state, 'state':'error',
                    'error':'Unable to start the manual check. Click to retry.', 'checked_at':now()})
                self._runs.pop(program_id, None)
                self._accepted.pop(program_id, None)
                raise
        return True

    def _run(self, program, assets, state):
        pid = program['id']
        key = f'onchain:{pid}'
        results = dict(state.get('results') or {})
        sessions = {}
        durable = deepcopy(state)
        try:
            for asset in assets:
                if self._stop.is_set():
                    state.update(state='interrupted', error='Manual check stopped. Click to retry.')
                    break
                identity = asset_key(asset)
                previous = results.get(identity) or {}
                candidates = []
                try:
                    scope = self.client.request_scope() if hasattr(self.client, 'request_scope') else nullcontext()
                    with scope:
                        observed = inspect_asset(self.client, asset, sessions)
                    result = {**previous, **observed, 'checked_at': now(), 'changed': False, 'error': None}
                    if observed['status'] in ('implementation', 'unsupported'):
                        implementation = observed['implementation']
                        changed = previous.get('baseline_recorded', False) and previous.get('baseline_implementation') != implementation
                        result.update(baseline_recorded=True, baseline_implementation=implementation, changed=changed)
                        if changed:
                            result['previous_implementation'] = previous.get('baseline_implementation')
                            candidates.append(ScoredEvent(EventCandidate(program['protocol_id'],
                                f'evm:program:{pid}:{identity}', 'PROXY_IMPLEMENTATION_CHANGED', asset['proxy'],
                                previous.get('baseline_implementation'), implementation,
                                {'chain_id': asset['chain_id'], 'chain': asset['chain'], 'block': observed['block'],
                                 'label': asset['label'], 'platform': program['platform'], 'manual_program_id': pid,
                                 'changed_files': [], 'url': asset.get('url')}), 0, ('Manual on-chain check',), category='lead'))
                        if observed['status'] == 'implementation':
                            result['status'] = 'changed' if changed else 'unchanged' if previous.get('baseline_recorded') else 'baseline'
                except OnchainConfigError as error:
                    result = {**previous, 'status': 'error', 'error': str(error), 'changed': False}
                    state['error_count'] += 1
                except RequestDeferred:
                    result = {**previous, 'status': 'error', 'error': 'RPC request limits reached. Click to retry later.', 'changed': False}
                    state['error_count'] += 1
                except Exception:
                    result = {**previous, 'status': 'error', 'error': f'RPC check failed. Verify {asset["rpc_env"]} and retry.', 'changed': False}
                    state['error_count'] += 1
                results[identity] = result
                state.update(completed=state['completed'] + 1, results=results)
                self.store.commit_events(candidates, new_observations=True,
                    finalize=lambda: self.store.set_runtime_status(key, state, touch_queue=True))
                durable = deepcopy(state)
            if state['state'] != 'interrupted':
                state['state'] = 'interrupted' if self._stop.is_set() else 'partial' if state['error_count'] else 'completed'
            state['checked_at'] = now()
            self._finish(pid, state)
        except Exception:
            self._finish(pid, {**durable, 'state':'error',
                'error':'Manual check failed. Click to retry.', 'checked_at':now()})
        finally:
            with self._lock:
                if pid not in self._runs or self._runs[pid] == state.get('check_id'):
                    self._running.discard(pid)
                    self._futures.pop(pid, None)
                    self._accepted.pop(pid, None)
                    self._runs.pop(pid, None)

    def close(self):
        self._stop.set()
        with self._lock:
            for pid, future in list(self._futures.items()):
                if future.cancel():
                    state = self._accepted.get(pid, {})
                    self._finish(pid, {**state, 'state':'interrupted', 'error':'Manual check stopped. Click to retry.', 'checked_at':now()})
                    self._futures.pop(pid, None)
                    self._accepted.pop(pid, None)
                    self._runs.pop(pid, None)
            if self._executor is not None:
                self._executor.shutdown(wait=False, cancel_futures=True)
