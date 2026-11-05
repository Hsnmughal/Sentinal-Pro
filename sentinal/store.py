from __future__ import annotations

import json
import os
import sqlite3
import threading
from collections import defaultdict
from collections.abc import Iterable, Sequence
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterator

from .core.bounty_policy import structured_entries, policy_comparison
from .core.diffing import deep_diff
from .core.kinds import LIFECYCLE_STATE_BY_KIND, REMOVAL_KINDS, category_for_tags
from .core.models import (
    EventCandidate,
    ProgramLifecycle,
    ReviewStatus,
    ScoredEvent,
    SourceState,
    utc_now,
)
from .core.registry import DEFAULT_TARGET_KEY, Registry, default_registry
from .config import positive_interval, validate_intervals


#: Bumped for every deliberate schema change. ``initialize`` runs the versioned,
#: data-preserving migration path and never deletes existing rows.
SCHEMA_VERSION = 11

SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS protocols (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    config_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS source_state (
    source_key TEXT PRIMARY KEY,
    protocol_id TEXT NOT NULL,
    source_type TEXT NOT NULL,
    cursor TEXT,
    etag TEXT,
    payload_json TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    program_id INTEGER REFERENCES programs(id),
    FOREIGN KEY (protocol_id) REFERENCES protocols(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT NOT NULL UNIQUE,
    protocol_id TEXT NOT NULL,
    source_key TEXT NOT NULL,
    kind TEXT NOT NULL,
    entity TEXT NOT NULL,
    before_json TEXT,
    after_json TEXT,
    metadata_json TEXT NOT NULL,
    score INTEGER NOT NULL CHECK (score BETWEEN 0 AND 100),
    reasons_json TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT '',
    eligibility TEXT NOT NULL DEFAULT '',
    evidence_json TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'new',
    note TEXT,
    detected_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (protocol_id) REFERENCES protocols(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_events_protocol_time
ON events(protocol_id, detected_at DESC);

CREATE INDEX IF NOT EXISTS idx_events_status_score
ON events(status, score DESC, detected_at DESC);

CREATE TABLE IF NOT EXISTS event_links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    lead_id INTEGER NOT NULL,
    signal_id INTEGER NOT NULL,
    evidence_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (lead_id, signal_id, evidence_json),
    FOREIGN KEY (lead_id) REFERENCES events(id) ON DELETE CASCADE,
    FOREIGN KEY (signal_id) REFERENCES events(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_event_links_lead ON event_links(lead_id);
CREATE INDEX IF NOT EXISTS idx_event_links_signal ON event_links(signal_id);

CREATE TABLE IF NOT EXISTS compare_cache (
    cache_key TEXT PRIMARY KEY,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS poll_jobs (
    job_key TEXT PRIMARY KEY,
    protocol_id TEXT,
    program_id INTEGER,
    source_type TEXT NOT NULL,
    target_key TEXT,
    manually_queued INTEGER NOT NULL DEFAULT 0,
    job_kind TEXT NOT NULL DEFAULT 'poll',
    priority TEXT NOT NULL,
    interval_seconds INTEGER NOT NULL,
    quiet_polls INTEGER NOT NULL DEFAULT 0,
    next_run_at TEXT NOT NULL,
    last_started_at TEXT,
    last_finished_at TEXT,
    last_status TEXT,
    last_error TEXT,
    last_result_json TEXT,
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (protocol_id) REFERENCES protocols(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_poll_jobs_due
ON poll_jobs(next_run_at, source_type);

CREATE TABLE IF NOT EXISTS catalog_programs (
    platform TEXT NOT NULL,
    external_id TEXT NOT NULL,
    name TEXT NOT NULL,
    url TEXT NOT NULL,
    max_bounty INTEGER,
    source_updated_at TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    active INTEGER NOT NULL DEFAULT 1,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    PRIMARY KEY(platform, external_id)
);

CREATE TABLE IF NOT EXISTS runtime_status (
    key TEXT PRIMARY KEY,
    value_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS programs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    platform TEXT NOT NULL,
    external_id TEXT NOT NULL,
    protocol_id TEXT NOT NULL,
    name TEXT NOT NULL,
    url TEXT,
    max_bounty INTEGER,
    priority TEXT NOT NULL DEFAULT 'normal',
    lifecycle TEXT NOT NULL DEFAULT 'active',
    origin TEXT NOT NULL DEFAULT 'discovery',
    lifecycle_since TEXT NOT NULL,
    removal_dismissed_at TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    source_updated_at TEXT,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (platform, external_id),
    FOREIGN KEY (protocol_id) REFERENCES protocols(id)
);

CREATE INDEX IF NOT EXISTS idx_programs_protocol ON programs(protocol_id);

CREATE TABLE IF NOT EXISTS program_transitions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id INTEGER NOT NULL,
    from_state TEXT,
    to_state TEXT NOT NULL,
    reason TEXT NOT NULL,
    detail TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (program_id) REFERENCES programs(id)
);

CREATE INDEX IF NOT EXISTS idx_program_transitions_program
ON program_transitions(program_id, created_at DESC);

CREATE TABLE IF NOT EXISTS program_scope (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id INTEGER NOT NULL,
    kind TEXT NOT NULL,
    identity TEXT,
    category TEXT,
    severity TEXT,
    label TEXT NOT NULL,
    url TEXT,
    address TEXT,
    wording TEXT,
    active INTEGER NOT NULL DEFAULT 1,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    UNIQUE (program_id, kind, identity),
    FOREIGN KEY (program_id) REFERENCES programs(id)
);

CREATE INDEX IF NOT EXISTS idx_program_scope_program ON program_scope(program_id, kind);

CREATE TABLE IF NOT EXISTS program_primacy_rules (
    program_id INTEGER PRIMARY KEY,
    mode TEXT NOT NULL,
    categories_json TEXT NOT NULL DEFAULT '[]',
    severities_json TEXT NOT NULL DEFAULT '[]',
    exclusions_json TEXT NOT NULL DEFAULT '{}',
    source TEXT NOT NULL DEFAULT 'policy',
    raw_json TEXT NOT NULL DEFAULT '{}',
    updated_at TEXT NOT NULL,
    FOREIGN KEY (program_id) REFERENCES programs(id)
);

CREATE TABLE IF NOT EXISTS monitoring_targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id INTEGER NOT NULL,
    source_type TEXT NOT NULL,
    target_key TEXT NOT NULL,
    config_json TEXT NOT NULL DEFAULT '{}',
    origin TEXT NOT NULL DEFAULT 'config',
    active INTEGER NOT NULL DEFAULT 1,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (program_id, source_type, target_key),
    FOREIGN KEY (program_id) REFERENCES programs(id)
);

CREATE INDEX IF NOT EXISTS idx_targets_program ON monitoring_targets(program_id, source_type);

CREATE TABLE IF NOT EXISTS source_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT NOT NULL UNIQUE,
    protocol_id TEXT NOT NULL,
    source_key TEXT NOT NULL,
    kind TEXT NOT NULL,
    entity TEXT NOT NULL,
    before_json TEXT,
    after_json TEXT,
    metadata_json TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    processed_at TEXT,
    event_id INTEGER,
    FOREIGN KEY (event_id) REFERENCES events(id)
);

CREATE INDEX IF NOT EXISTS idx_observations_pending
ON source_observations(processed_at, id);
"""


_TABS = {
    "to_review": ("new", "watching"),
    "reviewed": ("auditing", "resolved"),
    "dismissed": ("dismissed",),
}


class Store:
    """SQLite persistence: source state, events, the watched-program list and its
    monitoring targets.

    ``on_change`` (optional) is invoked after a commit that changed a program's
    lifecycle, so orchestration can reconcile monitoring targets without the store
    knowing anything about schedulers or adapters.
    """

    def __init__(self, path: str | Path, registry: Registry | None = None):
        self.path = Path(path)
        self.registry = registry
        self.on_change: Callable[[], None] | None = None
        self._transaction = threading.local()

    @property

    def adapters(self) -> Registry:
        return self.registry or default_registry()

    def policy_source_types(self) -> tuple[str, ...]:
        return self.adapters.policy_source_types()

    def policy_config_keys(self) -> tuple[str, ...]:
        return self.adapters.policy_config_keys()

    @contextmanager

    def connect(self, *, timeout: float = 30) -> Iterator[sqlite3.Connection]:
        current = getattr(self._transaction, "connection", None)
        if current is not None:
            yield current
            return
        connection = sqlite3.connect(self.path, timeout=timeout)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        self._transaction.connection = connection
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            self._transaction.connection = None
            connection.close()

    # ------------------------------------------------------------------ schema

    def _create_private_database(self) -> None:
        """Create a new database owner-only; SQLite side files inherit its mode.

        Only directories this call creates are tightened, so an existing parent
        (for example a user-chosen data directory) keeps its permissions.
        """
        missing = []
        for directory in (self.path.parent, *self.path.parent.parents):
            if directory.exists():
                break
            missing.append(directory)
        for directory in reversed(missing):
            directory.mkdir(mode=0o700)
        try:
            os.close(os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
        except FileExistsError:
            pass

    @contextmanager
    def _migration_step(self, connection: sqlite3.Connection, version: int) -> Iterator[None]:
        """Apply one schema version atomically.

        ``sqlite3.executescript`` implicitly commits pending work, so migration
        steps use statements that participate in this explicit transaction.
        """
        connection.execute("BEGIN IMMEDIATE")
        try:
            yield
            connection.execute(f"PRAGMA user_version = {version}")
            connection.execute("COMMIT")
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise

    def initialize(self) -> None:
        self._create_private_database()
        with self.connect() as connection:
            row = connection.execute("PRAGMA user_version").fetchone()
            version = int(row[0])
            if version > SCHEMA_VERSION:
                raise RuntimeError(f"Database schema {version} is newer than supported {SCHEMA_VERSION}")
            connection.executescript(SCHEMA)
            if version < 2:
                with self._migration_step(connection, 2):
                    self._migrate_to_2(connection)
            if version < 3:
                with self._migration_step(connection, 3):
                    self._migrate_to_3(connection)
            if version < 4:
                with self._migration_step(connection, 4):
                    self._add_columns(connection, "poll_jobs", {"manually_queued": "INTEGER NOT NULL DEFAULT 0"})
            if version < 5:
                with self._migration_step(connection, 5):
                    for statement in (
                        "CREATE INDEX IF NOT EXISTS idx_state_policy ON source_state(protocol_id, source_type, updated_at DESC)",
                        "CREATE INDEX IF NOT EXISTS idx_state_latest ON source_state(protocol_id, updated_at DESC)",
                        "CREATE INDEX IF NOT EXISTS idx_targets_lookup ON monitoring_targets(source_type, target_key, active, program_id)",
                        "CREATE INDEX IF NOT EXISTS idx_events_category_score ON events(category, score DESC, detected_at DESC)",
                        "CREATE INDEX IF NOT EXISTS idx_events_protocol_category ON events(protocol_id, category, detected_at DESC)",
                        "CREATE INDEX IF NOT EXISTS idx_events_queue ON events(score DESC, detected_at DESC) WHERE category != 'baseline'",
                        "CREATE INDEX IF NOT EXISTS idx_compare_created ON compare_cache(created_at)",
                    ):
                        connection.execute(statement)
            if version < 6:
                with self._migration_step(connection, 6):
                    connection.execute('SAVEPOINT migrate_6')
                    self._migrate_to_6(connection)
                    self._repair_historical_data(connection)
                    self.restore_reviewed_removals()
                    connection.execute('RELEASE migrate_6')
            if version < 7:
                with self._migration_step(connection, 7):
                    self._migrate_to_7(connection)
            if version < 8:
                with self._migration_step(connection, 8):
                    connection.execute("""
                        CREATE TABLE IF NOT EXISTS investigation_reviews (
                            investigation_id TEXT PRIMARY KEY,
                            program_id INTEGER NOT NULL REFERENCES programs(id),
                            state_json TEXT NOT NULL,
                            updated_at TEXT NOT NULL
                        )
                    """)
                    connection.execute("""
                        CREATE TABLE IF NOT EXISTS investigation_review_history (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            investigation_id TEXT NOT NULL,
                            program_id INTEGER NOT NULL REFERENCES programs(id),
                            state_json TEXT NOT NULL,
                            created_at TEXT NOT NULL
                        )
                    """)
            if version < 9:
                with self._migration_step(connection, 9):
                    self._migrate_to_9(connection)
            if version < 10:
                with self._migration_step(connection, 10):
                    self._add_columns(connection, 'source_state', {'program_id': 'INTEGER REFERENCES programs(id)'})
                    connection.execute('CREATE INDEX IF NOT EXISTS idx_state_owner ON source_state(program_id, source_type, updated_at DESC)')
                    for program in connection.execute("SELECT * FROM programs WHERE platform='bounty' AND origin='manual'").fetchall():
                        config = json.loads(program['metadata_json']).get('config', {}).get('bounty', {})
                        platform = config.get('platform', 'custom') if isinstance(config, dict) and config.get('url') else None
                        if isinstance(platform, str) and platform and platform != 'bounty' and not connection.execute(
                                'SELECT 1 FROM programs WHERE platform=? AND external_id=?', (platform,program['external_id'])).fetchone():
                            connection.execute('UPDATE programs SET platform=? WHERE id=?', (platform,program['id']))
                    self.bind_policy_owners()
                    self._migrate_owned_observation_heads(connection)
                    for program in connection.execute('SELECT * FROM programs').fetchall():
                        state = self.latest_policy_payload(program['protocol_id'], self.policy_source_types(), program_id=program['id'])
                        if state:
                            self.sync_program_scope(program['id'], state['payload'])
                            self.sync_primacy_rule(program['id'], state['payload'])
                        elif connection.execute('SELECT 1 FROM source_state WHERE protocol_id=? AND program_id IS NULL AND source_type IN ('
                                + ','.join('?' for _ in self.policy_source_types()) + ') LIMIT 1',
                                (program['protocol_id'], *self.policy_source_types())).fetchone():
                            # Uncertain legacy ownership cannot justify active scope
                            # or automatically discovered repository/RPC targets.
                            self.sync_program_scope(program['id'], {})
                            self.sync_primacy_rule(program['id'], {})
                            self.sync_program_targets(program['id'], [], origin='discovery',
                                source_types=tuple(t for t in self.adapters.source_types() if t not in self.policy_source_types()))
            if version < 11:
                with self._migration_step(connection, 11):
                    self._migrate_to_11(connection)
            if connection.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION:
                raise RuntimeError("Database schema migration did not complete")

    @staticmethod
    def _migrate_to_11(connection: sqlite3.Connection) -> None:
        """Track changes that affect program-card projections across connections.

        Database triggers also cover writes made by another Store instance or a
        separate monitoring process. The counter increments in the writer's
        transaction, so rolled-back changes never invalidate a good snapshot.
        """
        connection.execute("""
            CREATE TABLE IF NOT EXISTS projection_revisions (
                name TEXT PRIMARY KEY,
                revision INTEGER NOT NULL DEFAULT 0
            )
        """)
        connection.execute("INSERT OR IGNORE INTO projection_revisions(name, revision) VALUES ('programs', 0)")
        tables = (
            'events', 'programs', 'source_state', 'monitoring_targets',
            'program_scope', 'program_primacy_rules', 'investigation_reviews',
        )
        for table in tables:
            for operation in ('INSERT', 'UPDATE', 'DELETE'):
                connection.execute(f"""
                    CREATE TRIGGER IF NOT EXISTS projection_{table}_{operation.lower()}
                    AFTER {operation} ON {table}
                    BEGIN
                        UPDATE projection_revisions SET revision = revision + 1
                        WHERE name = 'programs';
                    END
                """)
        # Runtime queue/transport counters change frequently but do not affect
        # program cards. Research evidence, profile and on-chain records do.
        for operation in ('INSERT', 'UPDATE', 'DELETE'):
            reference = 'OLD' if operation == 'DELETE' else 'NEW'
            connection.execute(f"""
                CREATE TRIGGER IF NOT EXISTS projection_research_{operation.lower()}
                AFTER {operation} ON runtime_status
                WHEN {reference}.key = 'hunter_profile'
                  OR {reference}.key LIKE 'research:%'
                  OR {reference}.key LIKE 'research_updated:%'
                  OR {reference}.key LIKE 'onchain:%'
                BEGIN
                    UPDATE projection_revisions SET revision = revision + 1
                    WHERE name = 'programs';
                END
            """)

    def programs_revision(self) -> int:
        """Current committed version of data contributing to program cards."""
        with self.connect() as connection:
            row = connection.execute(
                "SELECT revision FROM projection_revisions WHERE name = 'programs'"
            ).fetchone()
        return int(row[0]) if row else 0

    def _migrate_to_9(self, connection: sqlite3.Connection) -> None:
        connection.execute('''CREATE TABLE IF NOT EXISTS observation_heads (
            protocol_id TEXT NOT NULL, source_key TEXT NOT NULL, kind TEXT NOT NULL,
            entity TEXT NOT NULL, before_json TEXT, after_json TEXT, fingerprint TEXT NOT NULL,
            PRIMARY KEY(protocol_id, source_key, kind, entity))''')
        # Seed from retained history, then prefer the journal (including pending work).
        for table, order in (('events', 'detected_at DESC, id DESC'), ('source_observations', 'id DESC')):
            connection.execute(f'''INSERT OR REPLACE INTO observation_heads
                SELECT protocol_id, source_key, stream_kind, entity, before_json, after_json, fingerprint
                FROM (SELECT *, CASE WHEN kind LIKE 'BOUNTY_%' THEN 'BOUNTY' ELSE kind END AS stream_kind,
                    ROW_NUMBER() OVER (
                    PARTITION BY protocol_id, source_key,
                        CASE WHEN kind LIKE 'BOUNTY_%' THEN 'BOUNTY' ELSE kind END, entity ORDER BY {order}) AS rank
                    FROM {table}) WHERE rank = 1''')
        # Older fallback patches lack per-commit provenance. They cannot be
        # distinguished reliably from range patches after filtering/compaction.
        # Preserve the text, but stop claiming verified revision coverage.
        for row in connection.execute("SELECT id, metadata_json FROM events WHERE kind LIKE 'GITHUB_%'"):
            metadata = json.loads(row['metadata_json'])
            changed = False
            for file in metadata.get('changed_files') or []:
                if isinstance(file, dict) and not file.get('patch_scope'):
                    file.update(patch_scope='legacy_unverified', patch_unverified=True)
                    changed = True
            if changed:
                metadata['patch_coverage_unverified'] = True
                connection.execute('UPDATE events SET metadata_json=? WHERE id=?', (_json(metadata), row['id']))
                self._touch_queue(connection)
        # Old blocks did not identify which resource returned 404. Recheck once
        # after upgrading; a missing child resource must not suppress the repository.
        for row in connection.execute('SELECT * FROM blocked_poll_targets').fetchall():
            job = json.loads(row['failed_job_json'])
            connection.execute('DELETE FROM blocked_poll_targets WHERE source_type=? AND target_key=?',
                               (row['source_type'], row['target_key']))
            self.upsert_job(job_key=job['job_key'], protocol_id=job.get('protocol_id'),
                source_type=row['source_type'], target_key=row['target_key'],
                priority=job.get('priority', 'normal'), interval_seconds=job.get('interval_seconds', 600),
                job_kind=job.get('job_kind', 'poll'))

    def _migrate_to_7(self, connection: sqlite3.Connection) -> None:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS blocked_poll_targets (
                source_type TEXT NOT NULL,
                target_key TEXT NOT NULL,
                error TEXT NOT NULL,
                recorded_at TEXT NOT NULL,
                failed_job_json TEXT NOT NULL,
                PRIMARY KEY(source_type,target_key)
            )
        """)
        connection.execute("""
            CREATE TRIGGER IF NOT EXISTS block_404_poll_job AFTER UPDATE ON poll_jobs
            WHEN NEW.last_status='error' AND (
                NEW.last_error LIKE 'HTTP 404 from %' OR
                NEW.last_error LIKE '%HTTP Error 404:%' OR
                NEW.last_error='Source unavailable (404). Check the URL or repository access.'
            ) BEGIN
                INSERT OR IGNORE INTO blocked_poll_targets VALUES (
                    NEW.source_type,COALESCE(NEW.target_key,NEW.job_key),NEW.last_error,
                    COALESCE(NEW.last_finished_at,strftime('%Y-%m-%dT%H:%M:%S+00:00','now')),
                    json_object('job_key',NEW.job_key,'job_kind',NEW.job_kind,'protocol_id',NEW.protocol_id,
                        'program_id',NEW.program_id,'priority',NEW.priority,'interval_seconds',NEW.interval_seconds,
                        'last_started_at',NEW.last_started_at,'last_finished_at',NEW.last_finished_at,
                        'last_result_json',NEW.last_result_json,'consecutive_failures',NEW.consecutive_failures)
                );
                DELETE FROM poll_jobs WHERE source_type=NEW.source_type
                    AND COALESCE(target_key,job_key)=COALESCE(NEW.target_key,NEW.job_key);
            END
        """)
        connection.execute("""
            CREATE TRIGGER IF NOT EXISTS prevent_blocked_poll_job BEFORE INSERT ON poll_jobs
            WHEN EXISTS (SELECT 1 FROM blocked_poll_targets b
                WHERE b.source_type=NEW.source_type AND b.target_key=COALESCE(NEW.target_key,NEW.job_key))
            BEGIN SELECT RAISE(IGNORE); END
        """)
        connection.execute("""
            INSERT OR IGNORE INTO blocked_poll_targets
            SELECT source_type,COALESCE(target_key,job_key),last_error,
                COALESCE(last_finished_at,?),
                json_object('job_key',job_key,'job_kind',job_kind,'protocol_id',protocol_id,
                    'program_id',program_id,'priority',priority,'interval_seconds',interval_seconds,
                    'last_started_at',last_started_at,'last_finished_at',last_finished_at,
                    'last_result_json',last_result_json,'consecutive_failures',consecutive_failures)
            FROM poll_jobs WHERE last_error LIKE 'HTTP 404 from %'
                OR last_error LIKE '%HTTP Error 404:%'
                OR last_error='Source unavailable (404). Check the URL or repository access.'
        """, (utc_now(),))
        connection.execute("""DELETE FROM poll_jobs WHERE EXISTS (
            SELECT 1 FROM blocked_poll_targets b WHERE b.source_type=poll_jobs.source_type
                AND b.target_key=COALESCE(poll_jobs.target_key,poll_jobs.job_key))""")

    def is_target_blocked(self, source_type: str, target_key: str) -> bool:
        with self.connect() as connection:
            return connection.execute('SELECT 1 FROM blocked_poll_targets WHERE source_type=? AND target_key=?', (source_type,target_key)).fetchone() is not None

    def blocked_targets(self) -> list[dict[str, Any]]:
        with self.connect() as connection:
            return [{**dict(row), 'display_error': 'Source unavailable (404). Check the URL or repository access.'}
                    for row in connection.execute('SELECT * FROM blocked_poll_targets ORDER BY source_type,target_key')]

    def _migrate_to_6(self, connection: sqlite3.Connection) -> None:
        """Preserve scope history and recover identified entries from stored policies."""
        definition = SCHEMA[SCHEMA.index('CREATE TABLE IF NOT EXISTS program_scope ('):SCHEMA.index('CREATE INDEX IF NOT EXISTS idx_program_scope_program')]
        connection.execute(definition.replace('IF NOT EXISTS program_scope', 'program_scope_new'))
        columns = ','.join(row['name'] for row in connection.execute('PRAGMA table_info(program_scope_new)'))
        connection.execute(f'INSERT INTO program_scope_new({columns}) SELECT {columns} FROM program_scope')
        connection.execute('DROP TABLE program_scope')
        connection.execute('ALTER TABLE program_scope_new RENAME TO program_scope')
        connection.execute('CREATE INDEX idx_program_scope_program ON program_scope(program_id, kind)')
        connection.execute('CREATE INDEX idx_program_scope_identity ON program_scope(program_id, identity)')
        connection.execute('CREATE INDEX idx_program_scope_label ON program_scope(program_id, kind, label)')
        connection.execute('CREATE INDEX IF NOT EXISTS idx_observations_processed ON source_observations(processed_at) WHERE event_id IS NOT NULL')
        types = self.policy_source_types()
        marks = ','.join('?' for _ in types) or "''"
        rows = connection.execute(f"""
            SELECT p.id, s.payload_json FROM programs p JOIN (
                SELECT protocol_id, payload_json, ROW_NUMBER() OVER (PARTITION BY protocol_id ORDER BY updated_at DESC, rowid ASC) AS rank
                FROM source_state WHERE source_type IN ({marks})
            ) s ON s.protocol_id = p.protocol_id AND s.rank = 1
        """, types).fetchall()
        for row in rows:
            self.sync_program_scope(row['id'], json.loads(row['payload_json']))

    def _repair_historical_data(self, connection: sqlite3.Connection) -> None:
        # Repair derived categories from older installations; never alter fingerprints.
        for kind, spec in self.adapters.kind_specs().items():
            connection.execute("UPDATE events SET category = ? WHERE kind = ? AND category = ''",
                               (category_for_tags(spec.tags), kind))
        connection.execute(
            "UPDATE events SET category = 'baseline' WHERE kind = 'GITHUB_RELEASE_CHANGED' "
            "AND before_json IN ('{}', 'null') "
            "AND COALESCE(json_array_length(json_extract(metadata_json, '$.changed_files')), 0) = 0"
            " AND json_extract(metadata_json, '$.release_boundary') IS NULL"
        )

        for row in connection.execute(
            "SELECT id, entity, before_json, after_json FROM events "
            "WHERE entity IN ('scope','impacts') AND kind IN ('BOUNTY_SCOPE_UPDATED','BOUNTY_IMPACT_UPDATED')"
        ).fetchall():
            old, new = json.loads(row["before_json"]), json.loads(row["after_json"])
            if isinstance(old, list) and isinstance(new, list):
                before, after = policy_comparison({row["entity"]: old}, {row["entity"]: new})
                if not deep_diff(before, after):
                    connection.execute("UPDATE events SET category = 'baseline' WHERE id = ?", (row["id"],))
        connection.execute(
            "UPDATE poll_jobs SET last_status = 'deferred', manually_queued = 1, "
            "last_error = 'Recovered after restart; queued for retry' "
            "WHERE last_status = 'error' AND last_error = 'Interrupted while running; queued for retry'"
        )

    def restore_reviewed_removals(self) -> int:
        """Restore dismissed catalog removals imported before watched-program rows existed.

        A currently active catalog entry or a later relisting/resumption takes precedence.
        """
        changed = 0
        with self.connect() as connection:
            for row in connection.execute(
                "SELECT * FROM events WHERE kind = 'BOUNTY_PROGRAM_DELISTED' AND status = 'dismissed'"
            ).fetchall():
                program = self._find_program_row(connection, row["protocol_id"],
                                                 _metadata_platform(json.loads(row["metadata_json"])))
                if program is None or program["lifecycle"] == 'dismissed':
                    continue
                catalog = connection.execute(
                    "SELECT active FROM catalog_programs WHERE platform = ? AND external_id = ?",
                    (program["platform"], program["external_id"]),
                ).fetchone()
                later = connection.execute(
                    "SELECT 1 FROM events WHERE protocol_id = ? AND detected_at > ? "
                    "AND kind IN ('BOUNTY_PROGRAM_RELISTED','BOUNTY_PROGRAM_RESUMED') LIMIT 1",
                    (row["protocol_id"], row["detected_at"]),
                ).fetchone()
                if catalog is not None and not catalog["active"] and later is None:
                    changed += int(self._transition_program(connection, program, 'dismissed',
                                                           reason='restored_review', detail=f"event {row['id']}"))
        return changed

    def _migrate_to_2(self, connection: sqlite3.Connection) -> None:
        """Versioned, data-preserving migration: schema v2 adds the watchlist tables
        (created by ``SCHEMA`` above) and links poll jobs to programs. Existing rows
        in ``events``, ``source_state`` and ``poll_jobs`` are never deleted.

        ``audit_runs`` is intentionally absent from ``SCHEMA``: auditing is outside
        this product, so new installations no longer create the table, while any
        existing table and its data are left untouched.
        """
        columns = {row["name"] for row in connection.execute("PRAGMA table_info(poll_jobs)")}
        if "program_id" not in columns:
            connection.execute("ALTER TABLE poll_jobs ADD COLUMN program_id INTEGER")

    def _migrate_to_3(self, connection: sqlite3.Connection) -> None:
        """Versioned, data-preserving migration: schema v3 separates leads from
        signals (``category``), records eligibility confidence with its evidence,
        links signals to leads, caches comparisons by SHA pair, and gives poll jobs
        a target identity, a job kind and quiet-poll adaptive state. Existing rows
        are only extended â€” never deleted or rewritten."""
        self._add_columns(
            connection,
            "events",
            {
                "category": "TEXT NOT NULL DEFAULT ''",
                "eligibility": "TEXT NOT NULL DEFAULT ''",
                "evidence_json": "TEXT NOT NULL DEFAULT '[]'",
            },
        )
        self._add_columns(
            connection,
            "program_scope",
            {
                "identity": "TEXT",
                "address": "TEXT",
                "wording": "TEXT",
            },
        )
        self._add_columns(
            connection,
            "poll_jobs",
            {
                "target_key": "TEXT",
                "job_kind": "TEXT NOT NULL DEFAULT 'poll'",
                "quiet_polls": "INTEGER NOT NULL DEFAULT 0",
            },
        )
        for statement in (
            """
CREATE TABLE IF NOT EXISTS event_links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    lead_id INTEGER NOT NULL,
    signal_id INTEGER NOT NULL,
    evidence_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (lead_id, signal_id, evidence_json),
    FOREIGN KEY (lead_id) REFERENCES events(id) ON DELETE CASCADE,
    FOREIGN KEY (signal_id) REFERENCES events(id) ON DELETE CASCADE
)""",
            "CREATE INDEX IF NOT EXISTS idx_event_links_lead ON event_links(lead_id)",
            "CREATE INDEX IF NOT EXISTS idx_event_links_signal ON event_links(signal_id)",
            """
CREATE TABLE IF NOT EXISTS compare_cache (
    cache_key TEXT PRIMARY KEY,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL
)""",
            "CREATE INDEX IF NOT EXISTS idx_events_category ON events(category, detected_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_poll_jobs_target ON poll_jobs(source_type, target_key, job_kind)",
            "CREATE INDEX IF NOT EXISTS idx_program_scope_identity ON program_scope(program_id, identity)",
        ):
            connection.execute(statement)

    @staticmethod

    def _add_columns(
        connection: sqlite3.Connection, table: str, columns: dict[str, str]
    ) -> None:
        existing = {row["name"] for row in connection.execute(f"PRAGMA table_info({table})")}
        for name, declaration in columns.items():
            if name not in existing:
                connection.execute(f"ALTER TABLE {table} ADD COLUMN {name} {declaration}")

    # --------------------------------------------------------------- protocols

    def sync_protocols(self, protocols: tuple[dict[str, Any], ...] | Sequence[dict[str, Any]]) -> None:
        now = utc_now()
        with self.connect() as connection:
            for protocol in protocols:
                connection.execute(
                    """
                    INSERT INTO protocols(id, name, config_json, updated_at)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        name = excluded.name,
                        config_json = excluded.config_json,
                        updated_at = excluded.updated_at
                    """,
                    (
                        protocol["id"],
                        protocol.get("name", protocol["id"]),
                        _json(protocol),
                        now,
                    ),
                )

    def ensure_protocol(self, protocol_id: str, name: str) -> None:
        with self.connect() as connection:
            self._ensure_protocol(connection, protocol_id, name)

    @staticmethod

    def _ensure_protocol(connection: sqlite3.Connection, protocol_id: str, name: str) -> None:
        connection.execute(
            "INSERT OR IGNORE INTO protocols(id, name, config_json, updated_at) VALUES (?, ?, '{}', ?)",
            (protocol_id, name, utc_now()),
        )

    # ------------------------------------------------------------ source state

    def investigation_reviews(self, program_id: int) -> dict[str, Any]:
        with self.connect() as connection:
            rows = connection.execute("SELECT investigation_id,state_json FROM investigation_reviews WHERE program_id=?", (program_id,)).fetchall()
        return {row["investigation_id"]: json.loads(row["state_json"]) for row in rows}

    def investigation_reviews_by_program(self, program_ids: Iterable[int]) -> dict[int, dict[str, Any]]:
        """Bulk ``investigation_reviews`` for dashboard-wide rebuilds: one connection."""
        ids = tuple(dict.fromkeys(int(program_id) for program_id in program_ids))
        if not ids:
            return {}
        marks = ",".join("?" for _ in ids)
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT program_id, investigation_id, state_json FROM investigation_reviews WHERE program_id IN ({})".format(marks),
                ids,
            ).fetchall()
        grouped: defaultdict[int, dict[str, Any]] = defaultdict(dict)
        for row in rows:
            grouped[row["program_id"]][row["investigation_id"]] = json.loads(row["state_json"])
        return dict(grouped)

    def review_investigation(self, program_id: int, investigation_id: str, state: dict[str, Any]) -> None:
        with self.connect() as connection:
            now = utc_now()
            connection.execute("INSERT INTO investigation_reviews VALUES(?,?,?,?) ON CONFLICT(investigation_id) DO UPDATE SET state_json=excluded.state_json,updated_at=excluded.updated_at", (investigation_id, program_id, _json(state), now))
            connection.execute("INSERT INTO investigation_review_history(investigation_id,program_id,state_json,created_at) VALUES(?,?,?,?)", (investigation_id,program_id,_json(state),now))
            self._touch_queue(connection)

    def get_state(self, source_key: str) -> SourceState | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM source_state WHERE source_key = ?", (source_key,)
            ).fetchone()
        if row is None:
            return None
        return SourceState(
            source_key=row["source_key"],
            protocol_id=row["protocol_id"],
            source_type=row["source_type"],
            cursor=row["cursor"],
            etag=row["etag"],
            payload=json.loads(row["payload_json"]),
            updated_at=row["updated_at"],
            program_id=row['program_id'],
        )

    def _policy_owner(self, connection, protocol_id, source_type, source_key, platform=None, program_id=None):
        programs = connection.execute('SELECT * FROM programs WHERE protocol_id=?', (protocol_id,)).fetchall()
        if program_id is not None:
            owner = next((p for p in programs if p['id'] == program_id and (platform is None or p['platform'] == platform)), None)
            if owner is None:
                raise ValueError('Policy owner does not match the watched program')
            return owner['id']
        manifest_platform = self.adapters[source_type].manifest.platform
        matches = [p for p in programs if (p['platform'] == platform if platform is not None else
            p['platform'] == manifest_platform or source_key == f"{source_type}:{p['platform']}:{protocol_id}" or
            source_key == f"{source_type}:program:{p['id']}")]
        if not matches and platform is None and len(programs) == 1 and programs[0]['platform'] == 'manual':
            matches = programs  # A unique manual watch can use any policy adapter.
        return matches[0]['id'] if len(matches) == 1 else None

    def bind_policy_owners(self) -> None:
        """Bind only unambiguous legacy snapshots; never guess between programs."""
        types = self.policy_source_types()
        if not types:
            return
        with self.connect() as connection:
            columns = {row['name'] for row in connection.execute('PRAGMA table_info(source_state)')}
            if 'program_id' not in columns:
                return  # Older migrations create program rows before the owner column.
            marks = ','.join('?' for _ in types)
            for row in connection.execute(f'SELECT source_key, protocol_id, source_type FROM source_state WHERE program_id IS NULL AND source_type IN ({marks})', types).fetchall():
                owner = self._policy_owner(connection, row['protocol_id'], row['source_type'], row['source_key'])
                if owner is not None:
                    connection.execute('UPDATE source_state SET program_id=? WHERE source_key=?', (owner, row['source_key']))

    def policy_source_key(self, legacy_key, protocol_id, source_type, platform, program_id=None):
        with self.connect() as connection:
            owner = self._policy_owner(connection, protocol_id, source_type, legacy_key, platform, program_id)
            if owner is None:
                count = connection.execute('SELECT COUNT(*) FROM programs WHERE protocol_id=? AND platform=?', (protocol_id, platform)).fetchone()[0]
                if count > 1:
                    raise ValueError('Ambiguous policy owner; a watched program ID is required')
                return legacy_key
            row = connection.execute('SELECT source_key FROM source_state WHERE program_id=? AND source_type=? ORDER BY updated_at DESC, rowid DESC LIMIT 1', (owner, source_type)).fetchone()
            if row:
                return row['source_key']
            matches = connection.execute('SELECT COUNT(*) FROM programs WHERE protocol_id=? AND platform=?', (protocol_id, platform)).fetchone()[0]
            if matches > 1:
                return f'{source_type}:program:{owner}'
            legacy = connection.execute('SELECT program_id FROM source_state WHERE source_key=?', (legacy_key,)).fetchone()
            return legacy_key if legacy is None or legacy['program_id'] == owner else f'{source_type}:program:{owner}'

    def _migrate_owned_observation_heads(self, connection):
        for table in ('events', 'source_observations'):
            for record in connection.execute(f"SELECT id, protocol_id, metadata_json FROM {table} WHERE json_extract(metadata_json,'$.program_id') IS NULL"):
                metadata = json.loads(record['metadata_json'])
                owner = metadata.get('manual_program_id')
                if owner is None:
                    matches = connection.execute('SELECT id FROM programs WHERE protocol_id=? AND (? IS NULL OR platform=?)',
                        (record['protocol_id'], metadata.get('platform'), metadata.get('platform'))).fetchall()
                    owner = matches[0]['id'] if len(matches) == 1 else None
                if owner is not None:
                    metadata['program_id'] = owner
                    connection.execute(f'UPDATE {table} SET metadata_json=? WHERE id=?', (_json(metadata), record['id']))
        for row in connection.execute('SELECT * FROM observation_heads').fetchall():
            if ':program:' in row['kind']:
                continue
            record = connection.execute('SELECT metadata_json FROM source_observations WHERE fingerprint=?', (row['fingerprint'],)).fetchone()
            if record is None:
                record = connection.execute('SELECT metadata_json FROM events WHERE fingerprint=?', (row['fingerprint'],)).fetchone()
            metadata = json.loads(record[0]) if record else {}
            owner = metadata.get('program_id') or metadata.get('manual_program_id')
            if owner is None:
                matches = connection.execute('SELECT id FROM programs WHERE protocol_id=? AND (? IS NULL OR platform=?)',
                    (row['protocol_id'], metadata.get('platform'), metadata.get('platform'))).fetchall()
                owner = matches[0]['id'] if len(matches) == 1 else None
            if owner is not None:
                connection.execute('INSERT OR IGNORE INTO observation_heads VALUES (?,?,?,?,?,?,?)',
                    (row['protocol_id'], row['source_key'], f"{row['kind']}:program:{owner}", row['entity'], row['before_json'], row['after_json'], row['fingerprint']))
        # Direct event inserts from older integrations may have no journal head.
        for table, order in (('events','detected_at DESC,id DESC'),('source_observations','id DESC')):
            for record in connection.execute(f'SELECT * FROM {table} ORDER BY {order}'):
                metadata = json.loads(record['metadata_json'])
                candidate = EventCandidate(record['protocol_id'],record['source_key'],record['kind'],record['entity'],None,None,metadata)
                connection.execute('INSERT OR IGNORE INTO observation_heads VALUES (?,?,?,?,?,?,?)',
                    (*_observation_stream(candidate),record['before_json'],record['after_json'],record['fingerprint']))

    def save_state(
        self,
        *,
        source_key: str,
        protocol_id: str,
        source_type: str,
        payload: Any,
        cursor: str | None = None,
        etag: str | None = None,
        events: Iterable[EventCandidate] = (),
        platform: str | None = None,
        program_id: int | None = None,
    ) -> None:
        """Advance the source cursor together with a durable record of the changes
        the adapter derived from it.

        When ``events`` is given, the observation rows are committed in the SAME
        transaction as the snapshot: a change can therefore never be lost between
        saving the snapshot and inserting its events. Processing the observations
        into review events happens later (:meth:`commit_events`) and is safe to
        interrupt â€” unprocessed observations are re-processed after restart.
        """
        candidates = list(events)
        changed = False
        with self.connect() as connection:
            if source_type in self.policy_source_types():
                program_id = self._policy_owner(connection, protocol_id, source_type, source_key, platform, program_id)
                existing = connection.execute('SELECT program_id FROM source_state WHERE source_key=?', (source_key,)).fetchone()
                if existing and existing['program_id'] is not None and existing['program_id'] != program_id:
                    raise ValueError('Policy snapshot belongs to another watched program')
            connection.execute(
                """
                INSERT INTO source_state(
                    source_key, protocol_id, source_type, cursor, etag, payload_json, updated_at, program_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(source_key) DO UPDATE SET
                    protocol_id = excluded.protocol_id,
                    source_type = excluded.source_type,
                    cursor = excluded.cursor,
                    etag = excluded.etag,
                    payload_json = excluded.payload_json,
                    updated_at = excluded.updated_at,
                    program_id = excluded.program_id
                """,
                (source_key, protocol_id, source_type, cursor, etag, _json(payload), utc_now(), program_id),
            )
            self._journal_observations(connection, candidates)
            if source_type in self.policy_source_types():
                self._touch_queue(connection)
                if platform is not None and payload.get('status') in ('active', 'paused'):
                    program = (connection.execute('SELECT * FROM programs WHERE id=?', (program_id,)).fetchone()
                               if program_id is not None else self._find_program_row(connection, protocol_id, platform))
                    if program and program['lifecycle'] in ('active', 'paused'):
                        changed = self._transition_program(connection, program, payload['status'],
                            reason='policy_snapshot', detail='Current published program status')
        if changed:
            self._notify()

    def sync_policy_status(self, protocol_id: str, platform: str, status: str, *, program_id: int | None = None) -> bool:
        if status not in ('active', 'paused'):
            return False
        with self.connect() as connection:
            program = (connection.execute('SELECT * FROM programs WHERE id=?', (program_id,)).fetchone()
                       if program_id is not None else self._find_program_row(connection, protocol_id, platform))
            changed = bool(program and program['lifecycle'] in ('active', 'paused') and
                self._transition_program(connection, program, status, reason='policy_snapshot',
                                         detail='Current published program status'))
        if changed:
            self._notify()
        return changed

    def record_observations(self, events: Iterable[EventCandidate]) -> int:
        """Journal observations durably (idempotent by change fingerprint)."""
        candidates = list(events)
        with self.connect() as connection:
            return self._journal_observations(connection, candidates)

    @staticmethod

    def _journal_observations(
        connection: sqlite3.Connection, candidates: Sequence[EventCandidate],
        fingerprints: list[str] | None = None,
    ) -> int:
        now = utc_now()
        recorded = 0
        for candidate in candidates:
            identity = _observation_stream(candidate)
            before, after = _json(candidate.before), _json(candidate.after)
            # Serialize read/advance with the snapshot transaction. Heads survive
            # journal cleanup, so a repeated transition remains distinct years later.
            if not connection.in_transaction:
                connection.execute('BEGIN IMMEDIATE')
            head = connection.execute('SELECT * FROM observation_heads WHERE '
                'protocol_id=? AND source_key=? AND kind=? AND entity=?', identity).fetchone()
            fingerprint = _fingerprint_candidate(candidate)
            if head:
                if (head['before_json'], head['after_json']) == (before, after):
                    fingerprint = head['fingerprint']
                else:
                    import hashlib
                    fingerprint = hashlib.sha256((head['fingerprint'] + '|' + fingerprint).encode()).hexdigest()
            connection.execute('INSERT OR REPLACE INTO observation_heads VALUES (?,?,?,?,?,?,?)',
                               (*identity, before, after, fingerprint))
            if fingerprints is not None:
                fingerprints.append(fingerprint)
            cursor = connection.execute(
                """
                INSERT INTO source_observations(
                    fingerprint, protocol_id, source_key, kind, entity,
                    before_json, after_json, metadata_json, observed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(fingerprint) DO UPDATE SET
                    metadata_json = excluded.metadata_json, processed_at = NULL
                WHERE json_extract(source_observations.metadata_json, '$.truncated') = 1
                  AND COALESCE(json_extract(excluded.metadata_json, '$.truncated'), 0) = 0

                """,
                (
                    fingerprint,
                    candidate.protocol_id,
                    candidate.source_key,
                    candidate.kind,
                    candidate.entity,
                    _json(candidate.before),
                    _json(candidate.after),
                    _json(candidate.metadata),
                    now,
                ),
            )
            recorded += cursor.rowcount
        return recorded

    def unprocessed_observations(self, limit: int = 1000) -> list[dict[str, Any]]:
        """Observations not yet turned into review events, oldest first."""
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM source_observations WHERE processed_at IS NULL ORDER BY id ASC LIMIT ?",
                (max(1, min(limit, 10_000)),),
            ).fetchall()
        observations: list[dict[str, Any]] = []
        for row in rows:
            observations.append(
                {
                    "fingerprint": row["fingerprint"],
                    "protocol_id": row["protocol_id"],
                    "source_key": row["source_key"],
                    "kind": row["kind"],
                    "entity": row["entity"],
                    "before": json.loads(row["before_json"]) if row["before_json"] else None,
                    "after": json.loads(row["after_json"]) if row["after_json"] else None,
                    "metadata": json.loads(row["metadata_json"]),
                    "observed_at": row["observed_at"],
                }
            )
        return observations

    def pending_observation_count(self) -> int:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT COUNT(*) FROM source_observations WHERE processed_at IS NULL"
            ).fetchone()
        return int(row[0])

    # ------------------------------------------------------------------- events

    def insert_event(self, event: ScoredEvent) -> int | None:
        """Commit one scored event atomically with its observation bookkeeping.

        Returns the new event's id, or None when an identical event (same change
        fingerprint) already exists â€” re-committing is always safe.
        """
        with self.connect() as connection:
            event_id, created = self._insert_event(connection, event)
            changed = self._apply_lifecycle_effect(connection, event.candidate)
        if changed:
            self._notify()
        return event_id if created else None

    def commit_events(
        self, events: Iterable[ScoredEvent], *, finalize: Callable[[], None] | None = None,
        new_observations: bool = False,
    ) -> dict[str, int]:
        """Atomically commit observations and their resulting events.

        One transaction: insert each event (deduplicated by its fingerprint), mark
        the matching observation processed, and apply any program-lifecycle effect
        the event implies. Interrupting between observation and event is therefore
        never lossy â€” the observation journal survives and is re-processed.
        """
        batch = list(events)
        inserted = duplicates = 0
        changed = False
        with self.connect() as connection:
            if new_observations:
                from dataclasses import replace
                fingerprints: list[str] = []
                self._journal_observations(connection, [event.candidate for event in batch], fingerprints)
                batch = [replace(event, observation_fingerprint=fingerprint)
                         for event, fingerprint in zip(batch, fingerprints)]
            for event in batch:
                _event_id, created = self._insert_event(connection, event)
                if created:
                    inserted += 1
                else:
                    duplicates += 1
                changed |= self._apply_lifecycle_effect(connection, event.candidate)
            if finalize is not None:
                finalize()
        if changed:
            self._notify()
        return {"inserted": inserted, "duplicates": duplicates, "candidates": len(batch)}

    def _insert_event(self, connection: sqlite3.Connection, event: ScoredEvent) -> tuple[int | None, bool]:
        candidate = event.candidate
        fingerprint = _fingerprint(event)
        now = utc_now()
        cursor = connection.execute(
            """
            INSERT OR IGNORE INTO events(
                fingerprint, protocol_id, source_key, kind, entity,
                before_json, after_json, metadata_json, score, reasons_json,
                category, eligibility, evidence_json,
                status, detected_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                fingerprint,
                candidate.protocol_id,
                candidate.source_key,
                candidate.kind,
                candidate.entity,
                _json(candidate.before),
                _json(candidate.after),
                _json(candidate.metadata),
                event.score,
                _json(event.reasons),
                event.category,
                event.eligibility,
                _json(event.evidence),
                ReviewStatus.NEW.value,
                event.detected_at,
                now,
            ),
        )
        created = bool(cursor.rowcount)
        if created:
            event_id: int | None = cursor.lastrowid
            self._touch_queue(connection)
        else:
            existing = connection.execute(
                "SELECT id, metadata_json FROM events WHERE fingerprint = ?", (fingerprint,)
            ).fetchone()
            event_id = existing["id"] if existing is not None else None
            if existing is not None and json.loads(existing["metadata_json"]).get("truncated") and not candidate.metadata.get("truncated"):
                connection.execute(
                    "UPDATE events SET metadata_json = ?, eligibility = ?, evidence_json = ?, updated_at = ? WHERE id = ?",
                    (_json(candidate.metadata), event.eligibility, _json(event.evidence), now, event_id),
                )
                self._touch_queue(connection)
        connection.execute(
            "UPDATE source_observations SET processed_at = ?, event_id = ? WHERE fingerprint = ?",
            (now, event_id, fingerprint),
        )
        return event_id, created

    def _apply_lifecycle_effect(
        self, connection: sqlite3.Connection, candidate: EventCandidate
    ) -> bool:
        to_state = LIFECYCLE_STATE_BY_KIND.get(candidate.kind)
        if to_state is None:
            return False
        if candidate.kind in ('BOUNTY_PROGRAM_PAUSED', 'BOUNTY_PROGRAM_RESUMED'):
            snapshot = connection.execute('SELECT payload_json FROM source_state WHERE source_key=?',
                                          (candidate.source_key,)).fetchone()
            status = json.loads(snapshot[0]).get('status') if snapshot else None
            if status in ('active', 'paused') and status != to_state:
                return False  # A pending historical event cannot override a newer snapshot.
        owner = candidate.metadata.get('program_id') or candidate.metadata.get('manual_program_id')
        if owner is not None:
            program = connection.execute('SELECT * FROM programs WHERE id=? AND protocol_id=?', (owner, candidate.protocol_id)).fetchone()
        else:
            platform = _metadata_platform(candidate.metadata)
            matches = connection.execute('SELECT * FROM programs WHERE protocol_id=? AND (? IS NULL OR platform=?)',
                (candidate.protocol_id, platform, platform)).fetchall()
            program = matches[0] if len(matches) == 1 else None
        if program is None:
            return False
        if program["lifecycle"] == ProgramLifecycle.DISMISSED and to_state != ProgramLifecycle.DISMISSED:
            # A dismissed program is only ever revived by the platform catalogue
            # noticing a relisting, never by a late-arriving event.
            return False
        return self._transition_program(
            connection,
            program,
            to_state,
            reason="event",
            detail=candidate.kind,
        )

    def related_event_kinds(self, protocol_id: str, window_hours: int) -> list[str]:
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=window_hours)).isoformat(timespec="seconds")
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT DISTINCT kind FROM events WHERE protocol_id = ? AND detected_at >= ?",
                (protocol_id, cutoff),
            ).fetchall()
        return [row["kind"] for row in rows]

    def list_events(
        self,
        *,
        status: str | None = None,
        protocol_id: str | None = None,
        tab: str | None = None,
        category: str | None = None,
        limit: int = 200,
        queue_only: bool = False,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        values: list[Any] = []
        if status:
            clauses.append("e.status = ?")
            values.append(status)
        if protocol_id:
            clauses.append("e.protocol_id = ?")
            values.append(protocol_id)
        if category and category != "all":
            clauses.append("e.category = ?")
            values.append(category)
        else:
            clauses.append("e.category != 'baseline'")
        if tab in _TABS:
            placeholders = ",".join("?" for _ in _TABS[tab])
            clauses.append(f"e.status IN ({placeholders})")
            values.extend(_TABS[tab])
        if _hides_retired_programs(tab, status):
            clauses.append("COALESCE(wp.lifecycle, '') != 'dismissed'")
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        values.append(max(1, min(limit, 1000)))
        select, join_params = self._event_select(queue_only=queue_only)
        with self.connect() as connection:
            rows = connection.execute(
                f"""
                {select}
                {where}
                ORDER BY e.detected_at DESC, e.id DESC
                LIMIT ?
                """,
                (*join_params, *values),
            ).fetchall()
        config_keys = self.policy_config_keys()
        events = [_event_row(row, config_keys) for row in rows]
        return events

    def list_program_events(self, program_id: int, *, limit: int = 200) -> list[dict[str, Any]]:
        """Read one program's own compact event history, filtered before LIMIT.

        Ownership follows the dossier read model instead of the protocol-wide
        history: an event belongs to the program when its metadata platform is
        absent or equal to the program's platform, and its ``program_id`` or
        ``manual_program_id`` resolves to this program. Records without either
        owner field stay only while the program's platform is the unambiguous
        claimant for the protocol. The filter runs in SQL before paging, so other
        programs' events never consume the limit and only the compact projection
        leaves SQLite.

        Key presence is distinguished from value with ``json_type``, because the
        dossier's ``dict.get`` fallback stops at a present ``null`` owner and its
        platform truthiness ignores falsy JSON values.
        """
        with self.connect() as connection:
            program = connection.execute(
                "SELECT protocol_id, platform FROM programs WHERE id = ?", (program_id,)
            ).fetchone()
            if program is None:
                return []
            platform = "json_extract(metadata_json,'$.platform')"
            # ``not metadata.get('platform')``: missing, null, empty text, zero/false
            # and empty containers all mean the platform is unknown.
            absent_platform = (
                f"(COALESCE({platform}, '') IN ('', 0)"
                f" OR (json_type(metadata_json,'$.platform') = 'array' AND {platform} = '[]')"
                f" OR (json_type(metadata_json,'$.platform') = 'object' AND {platform} = '{{}}'))"
            )
            # ``dict.get`` precedence: a present key wins even with a null value, so a
            # null program_id must not fall through to manual_program_id.
            owner = ("CASE WHEN json_type(metadata_json,'$.program_id') IS NOT NULL"
                     " THEN json_extract(metadata_json,'$.program_id')"
                     " WHEN json_type(metadata_json,'$.manual_program_id') IS NOT NULL"
                     " THEN json_extract(metadata_json,'$.manual_program_id') ELSE ? END")
            clauses = [
                "category != 'baseline'",
                "protocol_id = ?",
                f"({absent_platform} OR {platform} = ?)",
                f"({owner}) = ?",
            ]
            values: list[Any] = [program['protocol_id'], program['platform'], program_id, program_id]
            if connection.execute(
                "SELECT COUNT(*) FROM programs WHERE protocol_id = ?", (program['protocol_id'],)
            ).fetchone()[0] > 1:
                platform_count = connection.execute(
                    "SELECT COUNT(*) FROM programs WHERE protocol_id = ? AND platform = ?",
                    (program['protocol_id'], program['platform']),
                ).fetchone()[0]
                # Legacy rows without an explicit owner are ambiguous unless this
                # platform is the protocol's only claimant, as in ``dossiers``.
                clauses.append("(json_extract(metadata_json,'$.program_id') IS NOT NULL"
                               " OR json_extract(metadata_json,'$.manual_program_id') IS NOT NULL"
                               f" OR (? = 1 AND NOT {absent_platform}))")
                values.append(platform_count)
            rows = connection.execute(
                f'''SELECT id, protocol_id, kind, category, entity, status, detected_at,
                           score, eligibility,
                           json_extract(metadata_json, '$.repository') AS repository,
                           json_array_length(json_extract(metadata_json, '$.changed_files')) AS file_count
                    FROM events WHERE {' AND '.join(clauses)}
                    ORDER BY detected_at DESC, id DESC LIMIT ?''',
                (*values, limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def event_file_patch(self, event_id: int, index: int) -> str | None:
        """Read exactly one file patch, without joining or unpacking the dossier.

        JSON1 extracts the requested array element on the SQLite side. Callers
        must validate the index before constructing the JSON path.
        """
        if not isinstance(index, int) or not 0 <= index <= 100000:
            raise ValueError('Invalid file index')
        with self.connect() as connection:
            row = connection.execute(
                'SELECT json_extract(metadata_json, ?) AS patch FROM events WHERE id = ?',
                (f'$.changed_files[{index}].patch', event_id),
            ).fetchone()
        if row is None or not isinstance(row['patch'], str) or not row['patch'].strip():
            return None
        return row['patch']

    def get_event(self, event_id: int) -> dict[str, Any] | None:
        select, join_params = self._event_select()
        types = self.policy_source_types()
        marks = ",".join("?" for _ in types) or "''"
        config_keys = self.policy_config_keys()
        with self.connect() as connection:
            row = connection.execute(
                f"{select} WHERE e.id = ?", (*join_params, event_id)
            ).fetchone()
            if row is None:
                return None
            state = connection.execute(
                f"""
                SELECT payload_json, updated_at FROM source_state
                WHERE protocol_id = ? AND source_type IN ({marks})
                  AND (program_id = ? OR (? IS NULL AND program_id IS NULL AND NOT EXISTS (
                      SELECT 1 FROM programs WHERE protocol_id = ?)))
                ORDER BY updated_at DESC, rowid DESC LIMIT 1
                """,
                (row["protocol_id"], *types, row['watched_program_id'], row['watched_program_id'], row['protocol_id']),
            ).fetchone()
            read = connection.execute(
                "SELECT updated_at FROM source_state WHERE source_key = ?",
                (row["source_key"],),
            ).fetchone()
        event = _event_row(row, config_keys)
        event["program"].update(_program_detail(row, state, read))
        event["links"] = self.list_event_links(event_id)
        return event

    def update_event(
        self,
        event_id: int,
        *,
        status: ReviewStatus | None = None,
        note: str | None = None,
    ) -> bool:
        assignments: list[str] = []
        values: list[Any] = []
        if status is not None:
            assignments.append("status = ?")
            values.append(status.value)
        if note is not None:
            assignments.append("note = ?")
            values.append(note)
        assignments.append("updated_at = ?")
        values.append(utc_now())
        values.append(event_id)
        changed = False
        with self.connect() as connection:
            current = connection.execute(
                "SELECT * FROM events WHERE id = ?", (event_id,)
            ).fetchone()
            cursor = connection.execute(
                f"UPDATE events SET {', '.join(assignments)} WHERE id = ?",
                values,
            )
            updated = bool(cursor.rowcount)
            if updated:
                self._touch_queue(connection)
            if updated and current is not None and status is not None:
                changed = self._apply_removal_dismissal(connection, current, status)
        if changed:
            self._notify()
        return updated

    def _apply_removal_dismissal(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
        status: ReviewStatus,
    ) -> bool:
        """Dismissing a removal item retires its program; re-opening it restores the
        delisted state. The program row itself is always retained as the internal
        record that keeps history and later rediscovery unambiguous."""
        if row["kind"] not in REMOVAL_KINDS:
            return False
        platform = _metadata_platform(json.loads(row["metadata_json"]))
        program = self._find_program_row(connection, row["protocol_id"], platform)
        if program is None:
            return False
        previous = ReviewStatus(row["status"])
        if status == ReviewStatus.DISMISSED and previous != ReviewStatus.DISMISSED:
            return self._transition_program(
                connection,
                program,
                ProgramLifecycle.DISMISSED,
                reason="removal_dismissed",
                detail=f"event {row['id']}",
            )
        if previous == ReviewStatus.DISMISSED and status != ReviewStatus.DISMISSED:
            return self._transition_program(
                connection,
                program,
                ProgramLifecycle.DELISTED,
                reason="removal_reopened",
                detail=f"event {row['id']}",
            )
        return False

    def stats(self) -> dict[str, Any]:
        with self.connect() as connection:
            totals = connection.execute(
                """
                SELECT
                    COUNT(*) AS event_count,
                    SUM(CASE WHEN status = 'new' THEN 1 ELSE 0 END) AS new_count,
                    SUM(CASE WHEN score >= 50 THEN 1 ELSE 0 END) AS high_count,
                    SUM(CASE WHEN score < 25 THEN 1 ELSE 0 END) AS quiet_count,
                    SUM(CASE WHEN status IN ('new', 'watching') THEN 1 ELSE 0 END) AS to_review_count,
                    SUM(CASE WHEN status IN ('auditing', 'resolved') THEN 1 ELSE 0 END) AS reviewed_count,
                    SUM(CASE WHEN status = 'dismissed' THEN 1 ELSE 0 END) AS dismissed_count
                FROM events WHERE category != 'baseline'
                """
            ).fetchone()
            protocol_count = connection.execute("SELECT COUNT(*) FROM protocols").fetchone()[0]
            source_count = connection.execute("SELECT COUNT(*) FROM source_state").fetchone()[0]
            catalog_by_platform = {
                row["platform"]: row["program_count"]
                for row in connection.execute(
                    """
                    SELECT platform, COUNT(*) AS program_count
                    FROM catalog_programs WHERE active = 1
                    GROUP BY platform
                    """
                ).fetchall()
            }
            lifecycle_counts = {
                row["lifecycle"]: row["program_count"]
                for row in connection.execute(
                    """
                    SELECT lifecycle, COUNT(*) AS program_count
                    FROM programs GROUP BY lifecycle
                    """
                ).fetchall()
            }
            category_counts = {
                row["category"]: row["event_count"]
                for row in connection.execute(
                    """
                    SELECT category, COUNT(*) AS event_count
                    FROM events WHERE category != '' GROUP BY category
                    """
                ).fetchall()
            }
        return {
            "protocols": protocol_count,
            "sources": source_count,
            "events": totals["event_count"] or 0,
            "new": totals["new_count"] or 0,
            "high_signal": totals["high_count"] or 0,
            "catalog_programs": sum(catalog_by_platform.values()),
            "catalog_by_platform": catalog_by_platform,
            "to_review": totals["to_review_count"] or 0,
            "reviewed": totals["reviewed_count"] or 0,
            "dismissed": totals["dismissed_count"] or 0,
            "quiet": totals["quiet_count"] or 0,
            "leads": category_counts.get("lead", 0),
            "signals": category_counts.get("signal", 0),
            "programs_by_lifecycle": lifecycle_counts,
        }

    # ----------------------------------------------------------------- programs

    def import_program_defs(
        self, defs: Sequence[dict[str, Any]], *, reason: str = "import"
    ) -> dict[str, int]:
        """Upsert manually defined programs and their monitoring targets.

        One transaction for the whole batch. Identity fields and target sets are
        refreshed from the definitions; lifecycle only changes when a definition
        explicitly asks for it (manual overrides), so imports can never clobber a
        lifecycle decision made by discovery or by the reviewer.
        """
        created = updated = targets = 0
        changed = False
        now = utc_now()
        with self.connect() as connection:
            for definition in defs:
                self._ensure_protocol(
                    connection,
                    definition["protocol_id"],
                    definition.get("name") or definition["protocol_id"],
                )
                row = connection.execute(
                    "SELECT * FROM programs WHERE platform = ? AND external_id = ?",
                    (definition["platform"], definition["external_id"]),
                ).fetchone()
                lifecycle = definition.get("lifecycle")
                if row is None:
                    initial = lifecycle or ProgramLifecycle.ACTIVE
                    connection.execute(
                        """
                        INSERT INTO programs(
                            platform, external_id, protocol_id, name, url, max_bounty,
                            priority, lifecycle, origin, lifecycle_since,
                            metadata_json, source_updated_at, first_seen_at, last_seen_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            definition["platform"],
                            definition["external_id"],
                            definition["protocol_id"],
                            definition.get("name") or definition["protocol_id"],
                            definition.get("url"),
                            definition.get("max_bounty"),
                            definition.get("priority", "normal"),
                            str(initial),
                            definition.get("origin", "manual"),
                            now,
                            _json(definition.get("metadata", {})),
                            definition.get("source_updated_at"),
                            now,
                            now,
                            now,
                        ),
                    )
                    program = connection.execute(
                        "SELECT * FROM programs WHERE platform = ? AND external_id = ?",
                        (definition["platform"], definition["external_id"]),
                    ).fetchone()
                    self._record_transition(connection, program["id"], None, str(initial), reason)
                    created += 1
                    changed = True
                else:
                    connection.execute(
                        """
                        UPDATE programs SET
                            protocol_id = ?, name = ?, url = ?, max_bounty = ?, priority = ?,
                            metadata_json = ?, updated_at = ?
                        WHERE id = ?
                        """,
                        (
                            definition["protocol_id"],
                            definition.get("name") or row["name"],
                            definition.get("url", row["url"]),
                            definition.get("max_bounty", row["max_bounty"]),
                            definition.get("priority", row["priority"]),
                            _json(definition.get("metadata", {})) if definition.get("metadata") else row["metadata_json"],
                            now,
                            row["id"],
                        ),
                    )
                    program = connection.execute(
                        "SELECT * FROM programs WHERE id = ?", (row["id"],)
                    ).fetchone()
                    if lifecycle is not None and str(lifecycle) != program["lifecycle"]:
                        changed |= self._transition_program(
                            connection, program, str(lifecycle), reason="manual_override"
                        )
                    updated += 1
                program = connection.execute(
                    "SELECT * FROM programs WHERE platform = ? AND external_id = ?",
                    (definition["platform"], definition["external_id"]),
                ).fetchone()
                targets += self._replace_targets(
                    connection,
                    program,
                    definition.get("targets", ()),
                    origin=definition.get("origin", "manual"),
                )
            if created or updated:
                self._touch_queue(connection)
                self.bind_policy_owners()
        if changed:
            self._notify()
        return {"created": created, "updated": updated, "targets": targets}

    def find_program(
        self, platform: str, external_id: str
    ) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM programs WHERE platform = ? AND external_id = ?",
                (platform, external_id),
            ).fetchone()
        return _program_row(row) if row is not None else None

    def get_program(self, program_id: int) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM programs WHERE id = ?", (program_id,)
            ).fetchone()
        return _program_row(row) if row is not None else None

    def find_program_by_protocol(
        self, protocol_id: str, platform: str | None = None
    ) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = self._find_program_row(connection, protocol_id, platform)
        return _program_row(row) if row is not None else None

    def list_programs(
        self,
        *,
        platform: str | None = None,
        lifecycle: str | Iterable[str] | None = None,
        with_targets: bool = False,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        values: list[Any] = []
        if platform:
            clauses.append("platform = ?")
            values.append(platform)
        if lifecycle is not None:
            states = [lifecycle] if isinstance(lifecycle, str) else list(lifecycle)
            placeholders = ",".join("?" for _ in states)
            clauses.append(f"lifecycle IN ({placeholders})")
            values.extend(states)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self.connect() as connection:
            rows = connection.execute(
                f"SELECT * FROM programs {where} ORDER BY platform, external_id", values
            ).fetchall()
            programs = [_program_row(row) for row in rows]
            if with_targets:
                targets = defaultdict(list)
                for target in connection.execute("SELECT * FROM monitoring_targets ORDER BY source_type, target_key"):
                    item = dict(target)
                    item['config'] = json.loads(item.pop('config_json') or '{}')
                    targets[item['program_id']].append(item)
                for program in programs:
                    program["targets"] = targets[program['id']]
        return programs

    def list_transitions(self, program_id: int) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM program_transitions WHERE program_id = ? ORDER BY id ASC",
                (program_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    @staticmethod

    def _find_program_row(
        connection: sqlite3.Connection, protocol_id: str, platform: str | None
    ) -> sqlite3.Row | None:
        if platform:
            row = connection.execute(
                "SELECT * FROM programs WHERE protocol_id = ? AND platform = ? ORDER BY id ASC LIMIT 1",
                (protocol_id, platform),
            ).fetchone()
            if row is not None:
                return row
        return connection.execute(
            "SELECT * FROM programs WHERE protocol_id = ? ORDER BY id ASC LIMIT 1",
            (protocol_id,),
        ).fetchone()

    def _transition_program(
        self,
        connection: sqlite3.Connection,
        program: sqlite3.Row,
        to_state: str,
        *,
        reason: str,
        detail: str | None = None,
    ) -> bool:
        current = str(program["lifecycle"])
        if current == str(to_state):
            return False
        now = utc_now()
        connection.execute(
            """
            UPDATE programs SET
                lifecycle = ?, lifecycle_since = ?,
                removal_dismissed_at = CASE WHEN ? = 'dismissed' THEN ? ELSE NULL END,
                updated_at = ?
            WHERE id = ?
            """,
            (str(to_state), now, str(to_state), now, now, program["id"]),
        )
        self._record_transition(connection, program["id"], current, str(to_state), reason, detail)
        self._touch_queue(connection)
        return True

    @staticmethod

    def _record_transition(
        connection: sqlite3.Connection,
        program_id: int,
        from_state: str | None,
        to_state: str,
        reason: str,
        detail: str | None = None,
    ) -> None:
        connection.execute(
            """
            INSERT INTO program_transitions(program_id, from_state, to_state, reason, detail, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (program_id, from_state, str(to_state), reason, detail, utc_now()),
        )

    # ------------------------------------------------------------------ targets

    def upsert_target(
        self,
        program_id: int,
        source_type: str,
        target_key: str,
        config: Any,
        *,
        origin: str = "discovery",
    ) -> bool:
        changed = False
        with self.connect() as connection:
            program = connection.execute(
                "SELECT * FROM programs WHERE id = ?", (program_id,)
            ).fetchone()
            if program is None:
                raise KeyError(f"unknown program id {program_id}")
            changed = bool(
                self._replace_targets(
                    connection,
                    program,
                    [{"source_type": source_type, "target_key": target_key, "config": config}],
                    origin=origin,
                    merge=True,
                )
            )
        return changed

    def sync_program_targets(
        self, program_id: int, targets: Sequence[dict[str, Any]], *, origin: str = "discovery",
        source_types: Iterable[str] | None = None,
    ) -> int:
        """Replace this program's managed target set with ``targets`` (by source type)."""
        with self.connect() as connection:
            program = connection.execute(
                "SELECT * FROM programs WHERE id = ?", (program_id,)
            ).fetchone()
            if program is None:
                raise KeyError(f"unknown program id {program_id}")
            return self._replace_targets(connection, program, targets, origin=origin, source_types=source_types)

    def _replace_targets(
        self,
        connection: sqlite3.Connection,
        program: sqlite3.Row,
        targets: Sequence[dict[str, Any]],
        *,
        origin: str,
        merge: bool = False,
        source_types: Iterable[str] | None = None,
    ) -> int:
        """Upsert targets; deactivate managed targets of the same source types that
        the new set no longer contains. Targets of other origins are untouched, so a
        discovery-derived repository is never removed by a manual re-import of other
        sources."""
        now = utc_now()
        count = 0
        by_type: dict[str, list[dict[str, Any]]] = {}
        for target in targets:
            validate_intervals(target.get('config'), 'target.config')
            source_type = str(target["source_type"])
            config = target.get("config")
            if not isinstance(config, dict):
                config = {"value": config}
            by_type.setdefault(source_type, []).append(
                {"target_key": str(target["target_key"]), "config": config}
            )
        if not merge:
            for row in connection.execute(
                "SELECT DISTINCT source_type FROM monitoring_targets WHERE program_id = ? AND origin = ?",
                (program["id"], origin),
            ):
                if source_types is None or row["source_type"] in source_types:
                    by_type.setdefault(row["source_type"], [])
        for source_type, entries in by_type.items():
            wanted = {entry["target_key"] for entry in entries}
            for entry in entries:
                connection.execute(
                    """
                    INSERT INTO monitoring_targets(
                        program_id, source_type, target_key, config_json, origin,
                        active, first_seen_at, last_seen_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)
                    ON CONFLICT(program_id, source_type, target_key) DO UPDATE SET
                        config_json = excluded.config_json,
                        active = 1,
                        last_seen_at = excluded.last_seen_at,
                        updated_at = excluded.updated_at
                    WHERE monitoring_targets.origin = excluded.origin
                    """,
                    (
                        program["id"],
                        source_type,
                        entry["target_key"],
                        _json(entry["config"]),
                        origin,
                        now,
                        now,
                        now,
                    ),
                )
                count += 1
            if not merge:
                stale = connection.execute(
                    f"""
                    SELECT id, target_key FROM monitoring_targets
                    WHERE program_id = ? AND source_type = ? AND origin = ? AND active = 1
                    """,
                    (program["id"], source_type, origin),
                ).fetchall()
                for row in stale:
                    if row["target_key"] not in wanted:
                        connection.execute(
                            "UPDATE monitoring_targets SET active = 0, updated_at = ? WHERE id = ?",
                            (now, row["id"]),
                        )
        return count

    def sync_target_sets(self, replacements: Sequence[tuple[int, Sequence[dict[str, Any]], Sequence[str]]]) -> int:
        """Apply reconciliation's discovery target sets without per-program reads."""
        if not replacements:
            return 0
        now = utc_now()
        inserts, stale = [], []
        wanted = {}
        for program_id, targets, source_types in replacements:
            keys = set()
            managed_types = set(source_types)
            for target in targets:
                validate_intervals(target.get('config'), 'target.config')
                source, key = str(target['source_type']), str(target['target_key'])
                config = target.get('config')
                if not isinstance(config, dict):
                    config = {'value': config}
                managed_types.add(source)
                keys.add((source, key))
                inserts.append((program_id, source, key, _json(config), now, now, now))
            wanted[program_id] = (managed_types, keys)
        with self.connect() as connection:
            for row in connection.execute("SELECT id, program_id, source_type, target_key FROM monitoring_targets WHERE origin='discovery' AND active=1"):
                replacement = wanted.get(row['program_id'])
                if replacement and row['source_type'] in replacement[0] and (row['source_type'], row['target_key']) not in replacement[1]:
                    stale.append((now, row['id']))
            connection.executemany("""
                INSERT INTO monitoring_targets(program_id,source_type,target_key,config_json,origin,active,first_seen_at,last_seen_at,updated_at)
                VALUES (?,?,?,?,'discovery',1,?,?,?)
                ON CONFLICT(program_id,source_type,target_key) DO UPDATE SET
                    config_json=excluded.config_json, active=1, last_seen_at=excluded.last_seen_at, updated_at=excluded.updated_at
                WHERE monitoring_targets.origin=excluded.origin
            """, inserts)
            connection.executemany("UPDATE monitoring_targets SET active=0,updated_at=? WHERE id=? AND origin='discovery' AND active=1", stale)
        return len(inserts)

    def list_targets(
        self,
        program_id: int,
        *,
        source_type: str | None = None,
        active_only: bool = False,
    ) -> list[dict[str, Any]]:
        with self.connect() as connection:
            return self._targets_for(connection, program_id, source_type, active_only)

    def _targets_for(
        self,
        connection: sqlite3.Connection,
        program_id: int,
        source_type: str | None = None,
        active_only: bool = False,
    ) -> list[dict[str, Any]]:
        clauses = ["program_id = ?"]
        values: list[Any] = [program_id]
        if source_type:
            clauses.append("source_type = ?")
            values.append(source_type)
        if active_only:
            clauses.append("active = 1")
        rows = connection.execute(
            f"SELECT * FROM monitoring_targets WHERE {' AND '.join(clauses)} ORDER BY source_type, target_key",
            values,
        ).fetchall()
        targets = []
        for row in rows:
            target = dict(row)
            target["config"] = json.loads(target.pop("config_json"))
            targets.append(target)
        return targets

    def needed_targets(
        self,
        source_type: str,
        lifecycles: Iterable[str] = (ProgramLifecycle.ACTIVE.value,),
    ) -> list[str]:
        """Distinct target keys of ``source_type`` still needed by at least one
        program in ``lifecycles``. A shared target may only stop being polled when
        this set no longer contains it."""
        states = tuple(str(state) for state in lifecycles)
        placeholders = ",".join("?" for _ in states)
        with self.connect() as connection:
            rows = connection.execute(
                f"""
                SELECT DISTINCT t.target_key FROM monitoring_targets t
                JOIN programs p ON p.id = t.program_id
                WHERE t.source_type = ? AND t.active = 1 AND p.lifecycle IN ({placeholders})
                ORDER BY t.target_key
                """,
                (source_type, *states),
            ).fetchall()
        return [row["target_key"] for row in rows]

    def scheduling_targets(
        self,
        lifecycles: Iterable[str] = (ProgramLifecycle.ACTIVE.value, ProgramLifecycle.PAUSED.value),
    ) -> list[dict[str, Any]]:
        """Every monitoring target still needed, grouped by (source_type, target_key)
        with the programs that need it. One shared target appears once, no matter
        how many programs depend on it â€” that is what keeps a repository shared by
        several programs polled exactly once while any of them is active."""
        states = tuple(str(state) for state in lifecycles)
        placeholders = ",".join("?" for _ in states)
        with self.connect() as connection:
            rows = connection.execute(
                f"""
                SELECT t.source_type, t.target_key, t.config_json,
                       p.id AS program_id, p.protocol_id, p.name AS program_name,
                       p.platform, p.external_id, p.priority, p.lifecycle
                FROM monitoring_targets t
                JOIN programs p ON p.id = t.program_id
                WHERE t.active = 1 AND p.lifecycle IN ({placeholders})
                ORDER BY t.source_type, t.target_key, p.id
                """,
                states,
            ).fetchall()
        grouped: dict[tuple[str, str], dict[str, Any]] = {}
        for row in rows:
            key = (row["source_type"], row["target_key"])
            entry = grouped.setdefault(
                key,
                {
                    "source_type": row["source_type"],
                    "target_key": row["target_key"],
                    "config": json.loads(row["config_json"] or "{}"),
                    "programs": [],
                },
            )
            entry["programs"].append(
                {
                    "id": row["program_id"],
                    "protocol_id": row["protocol_id"],
                    "name": row["program_name"],
                    "platform": row["platform"],
                    "external_id": row["external_id"],
                    "priority": row["priority"],
                    "lifecycle": row["lifecycle"],
                    "target_config": json.loads(row["config_json"] or "{}"),
                }
            )
        return list(grouped.values())

    def programs_for_target(
        self,
        source_type: str,
        target_key: str,
        lifecycles: Iterable[str] = (ProgramLifecycle.ACTIVE.value,),
    ) -> list[dict[str, Any]]:
        states = tuple(str(state) for state in lifecycles)
        placeholders = ",".join("?" for _ in states)
        with self.connect() as connection:
            rows = connection.execute(
                f"""
                SELECT p.*, t.config_json AS target_config_json
                FROM monitoring_targets t
                JOIN programs p ON p.id = t.program_id
                WHERE t.source_type = ? AND t.target_key = ? AND t.active = 1
                  AND p.lifecycle IN ({placeholders})
                ORDER BY p.id
                """,
                (source_type, target_key, *states),
            ).fetchall()
        programs: list[dict[str, Any]] = []
        for row in rows:
            program = _program_row(row)
            program["target_config"] = json.loads(row["target_config_json"] or "{}")
            programs.append(program)
        return programs

    def target_config(self, source_type: str, target_key: str) -> Any | None:
        with self.connect() as connection:
            row = connection.execute(
                """
                SELECT config_json FROM monitoring_targets
                WHERE source_type = ? AND target_key = ? AND active = 1
                ORDER BY id ASC LIMIT 1
                """,
                (source_type, target_key),
            ).fetchone()
        return json.loads(row["config_json"] or "{}") if row is not None else None

    # ------------------------------------------------------- scope & primacy

    def sync_program_scope(self, program_id: int, payload: dict[str, Any]) -> dict[str, int]:
        """Refresh the structured scope tables from a normalised policy payload.

        Rows are matched on their structured identity (falling back to
        ``(kind, label)``), so a redefinition of an existing asset updates its row
        â€” identity, category, severity, URL/address and original wording included
        â€” instead of churning rows. Entries missing from the payload are
        deactivated rather than deleted, keeping history while reflecting the
        currently published scope.
        """
        now = utc_now()
        counts = {"added": 0, "refreshed": 0, "deactivated": 0}
        with self.connect() as connection:
            existing = {row['id']: dict(row) for row in connection.execute(
                "SELECT * FROM program_scope WHERE program_id = ? ORDER BY id", (program_id,)
            )}
            rows = dict(existing)
            identities, labels = defaultdict(set), defaultdict(set)
            def index(row, add=True):
                for mapping, key in ((identities, (row['kind'], row['identity'])), (labels, (row['kind'], row['label']))):
                    if add:
                        mapping[key].add(row['id'])
                    else:
                        mapping[key].discard(row['id'])
            for row in rows.values():
                index(row)
            wanted, changed = set(), set()
            next_id = max(rows, default=0) + 1
            for kind, key in (("asset", "scope"), ("impact", "impacts"), ("out_of_scope", "out_of_scope")):
                for entry in structured_entries(kind, payload.get(key) or []):
                    matches = identities[(kind, entry.get('identity'))] if entry.get('identity') else set()
                    matches = matches or {i for i in labels[(kind, entry['label'])] if not rows[i]['identity'] or rows[i]['identity'] == rows[i]['label']}
                    if matches:
                        row = rows[min(matches)]
                        index(row, False)
                        counts['refreshed'] += 1
                    else:
                        row = {'id': next_id, 'program_id': program_id, 'kind': kind, 'first_seen_at': now}
                        rows[next_id] = row
                        next_id += 1
                        counts['added'] += 1
                    row.update({key: entry.get(key) for key in ('identity','category','severity','label','url','address','wording')})
                    row.update(active=1, last_seen_at=now)
                    index(row)
                    wanted.add(row['id'])
                    changed.add(row['id'])
            fields = ('identity','category','severity','label','url','address','wording','active','last_seen_at')
            connection.executemany(
                "UPDATE program_scope SET identity=?, category=?, severity=?, label=?, url=?, address=?, wording=?, active=?, last_seen_at=? WHERE id=?",
                [tuple(rows[i][key] for key in fields) + (i,) for i in sorted(changed & existing.keys())],
            )
            connection.executemany(
                "INSERT INTO program_scope(program_id,kind,identity,category,severity,label,url,address,wording,active,first_seen_at,last_seen_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                [tuple(rows[i][key] for key in ('program_id','kind','identity','category','severity','label','url','address','wording','active','first_seen_at','last_seen_at')) for i in sorted(changed - existing.keys())],
            )
            stale = [(i,) for i, row in existing.items() if row['active'] and i not in wanted]
            connection.executemany("UPDATE program_scope SET active = 0 WHERE id = ?", stale)
            counts['deactivated'] = len(stale)
        return counts

    def sync_primacy_rule(self, program_id: int, payload: dict[str, Any]) -> dict[str, Any]:
        """Store Primacy-of-Impact applicability as structured rule data.

        Primacy applies only to particular categories or severity levels and may
        carry exclusions; it never makes every protocol change eligible. The
        normalised ``policy`` block may carry ``primacy`` (mode), ``primacy_applies_to``
        (``{"categories": [...], "severities": [...]}``) and ``primacy_exclusions``;
        missing applicability is stored as an empty list meaning "as published".
        """
        policy = payload.get("policy") or {}
        applies = policy.get("primacy_applies_to") or {}
        exclusions = policy.get("primacy_exclusions") or {}
        rule = {
            "mode": str(policy.get("primacy") or "unknown"),
            "categories": list(applies.get("categories") or []),
            "severities": list(applies.get("severities") or []),
            "exclusions": {
                "categories": list(exclusions.get("categories") or []),
                "severities": list(exclusions.get("severities") or []),
                "notes": list(exclusions.get("notes") or []),
            },
            "raw": policy.get("primacy"),
        }
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO program_primacy_rules(
                    program_id, mode, categories_json, severities_json,
                    exclusions_json, source, raw_json, updated_at
                ) VALUES (?, ?, ?, ?, ?, 'policy', ?, ?)
                ON CONFLICT(program_id) DO UPDATE SET
                    mode = excluded.mode,
                    categories_json = excluded.categories_json,
                    severities_json = excluded.severities_json,
                    exclusions_json = excluded.exclusions_json,
                    raw_json = excluded.raw_json,
                    updated_at = excluded.updated_at
                """,
                (
                    program_id,
                    rule["mode"],
                    _json(rule["categories"]),
                    _json(rule["severities"]),
                    _json(rule["exclusions"]),
                    _json(rule["raw"]),
                    utc_now(),
                ),
            )
        return rule

    def list_program_scope(self, program_id: int, *, active_only: bool = True) -> list[dict[str, Any]]:
        with self.connect() as connection:
            if active_only:
                rows = connection.execute(
                    "SELECT * FROM program_scope WHERE program_id = ? AND active = 1 ORDER BY kind, label",
                    (program_id,),
                ).fetchall()
            else:
                rows = connection.execute(
                    "SELECT * FROM program_scope WHERE program_id = ? ORDER BY kind, label",
                    (program_id,),
                ).fetchall()
        return [dict(row) for row in rows]

    def get_primacy_rule(self, program_id: int) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM program_primacy_rules WHERE program_id = ?", (program_id,)
            ).fetchone()
        return self._primacy_rule_row(row) if row is not None else None

    @staticmethod

    def _primacy_rule_row(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "program_id": row["program_id"],
            "mode": row["mode"],
            "categories": json.loads(row["categories_json"]),
            "severities": json.loads(row["severities_json"]),
            "exclusions": json.loads(row["exclusions_json"]),
            "source": row["source"],
            "raw": json.loads(row["raw_json"]),
            "updated_at": row["updated_at"],
        }

    def get_primacy_rules(self, program_ids: Iterable[int]) -> dict[int, dict[str, Any]]:
        """Bulk ``get_primacy_rule`` for dashboard-wide rebuilds: one connection.

        Program ids without a stored rule are absent from the result; callers
        treat a missing key exactly like the single-program lookup's ``None``.
        """
        ids = tuple(dict.fromkeys(int(program_id) for program_id in program_ids))
        if not ids:
            return {}
        marks = ",".join("?" for _ in ids)
        with self.connect() as connection:
            rows = connection.execute(
                f"SELECT * FROM program_primacy_rules WHERE program_id IN ({marks})", ids
            ).fetchall()
        return {row["program_id"]: self._primacy_rule_row(row) for row in rows}

    # ------------------------------------------------------------------ catalog

    def sync_catalog(
        self,
        platform: str,
        programs: Sequence[dict[str, Any]],
        *,
        events: Iterable[EventCandidate] = (),
        complete: bool = True,
    ) -> dict[str, Any]:
        """Reconcile the catalogue mirror AND the watched-program list with one
        catalogue response, in one transaction together with the observations the
        adapter derived from the change.

        Destructive reconciliation (marking programs delisted and deactivating
        mirror rows) only runs when ``complete`` is true: a partial page or parser
        failure must never deactivate half the watchlist. Additions and updates are
        always safe and always applied.
        """
        now = utc_now()
        candidates = list(events)
        incoming = {str(program["external_id"]): program for program in programs}
        transitions = 0
        watchlist_changed = False
        with self.connect() as connection:
            existing_rows = connection.execute(
                "SELECT * FROM catalog_programs WHERE platform = ?", (platform,)
            ).fetchall()
            existing = {row["external_id"]: dict(row) for row in existing_rows}
            for program in programs:
                connection.execute(
                    """
                    INSERT INTO catalog_programs(
                        platform, external_id, name, url, max_bounty, source_updated_at,
                        metadata_json, active, first_seen_at, last_seen_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
                    ON CONFLICT(platform, external_id) DO UPDATE SET
                        name = excluded.name, url = excluded.url,
                        max_bounty = excluded.max_bounty,
                        source_updated_at = excluded.source_updated_at,
                        metadata_json = excluded.metadata_json,
                        active = 1, last_seen_at = excluded.last_seen_at
                    """,
                    (
                        platform,
                        program["external_id"],
                        program["name"],
                        program["url"],
                        program.get("max_bounty"),
                        program.get("source_updated_at"),
                        _json(program.get("metadata", {})),
                        now,
                        now,
                    ),
                )
            removed = {key for key, row in existing.items() if row['active'] and key not in incoming} if complete else set()
            if complete and removed:
                placeholders = ",".join("?" for _ in removed)
                connection.execute(
                    f"UPDATE catalog_programs SET active = 0 WHERE platform = ? AND external_id IN ({placeholders})",
                    (platform, *sorted(removed)),
                )

            # --- watched-program reconciliation (additions always, removals only
            # --- against a complete catalogue response)
            for external_id in sorted(incoming):
                record = incoming[external_id]
                row = connection.execute(
                    "SELECT * FROM programs WHERE platform = ? AND external_id = ?",
                    (platform, external_id),
                ).fetchone()
                if row is None:
                    protocol_id = external_id
                    self._ensure_protocol(connection, protocol_id, record.get("name") or external_id)
                    connection.execute(
                        """
                        INSERT INTO programs(
                            platform, external_id, protocol_id, name, url, max_bounty,
                            priority, lifecycle, origin, lifecycle_since,
                            metadata_json, source_updated_at, first_seen_at, last_seen_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, 'normal', ?, 'discovery', ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            platform,
                            external_id,
                            protocol_id,
                            record.get("name") or external_id,
                            record.get("url"),
                            record.get("max_bounty"),
                            ProgramLifecycle.ACTIVE.value,
                            now,
                            _json(record.get("metadata", {})),
                            record.get("source_updated_at"),
                            now,
                            now,
                            now,
                        ),
                    )
                    row = connection.execute(
                        "SELECT * FROM programs WHERE platform = ? AND external_id = ?",
                        (platform, external_id),
                    ).fetchone()
                    self._record_transition(
                        connection, row["id"], None, ProgramLifecycle.ACTIVE.value, "catalog_sync",
                        "appeared in catalogue",
                    )
                    transitions += 1
                else:
                    watchlist_changed |= any((record.get(key) or row[key]) != row[key] for key in ('name', 'url'))
                    watchlist_changed |= record.get('max_bounty', row['max_bounty']) != row['max_bounty']
                    watchlist_changed |= bool(record.get('metadata')) and _json(record['metadata']) != row['metadata_json']
                    connection.execute(
                        """
                        UPDATE programs SET
                            name = ?, url = ?, max_bounty = ?, metadata_json = ?,
                            source_updated_at = ?, last_seen_at = ?, updated_at = ?
                        WHERE id = ?
                        """,
                        (
                            record.get("name") or row["name"],
                            record.get("url") or row["url"],
                            record.get("max_bounty", row["max_bounty"]),
                            _json(record.get("metadata", {})) if record.get("metadata") else row["metadata_json"],
                            record.get("source_updated_at") or row["source_updated_at"],
                            now,
                            now,
                            row["id"],
                        ),
                    )
                    if row["lifecycle"] in (
                        ProgramLifecycle.DELISTED.value,
                        ProgramLifecycle.DISMISSED.value,
                    ):
                        # Relisting: reconcile targets and resume monitoring via the
                        # post-refresh reconciliation; record the transition here and
                        # let the adapter's relisting signal reach the queue.
                        connection.execute(
                            """
                            UPDATE programs SET lifecycle = ?, lifecycle_since = ?,
                                removal_dismissed_at = NULL, updated_at = ? WHERE id = ?
                            """,
                            (ProgramLifecycle.ACTIVE.value, now, now, row["id"]),
                        )
                        self._record_transition(
                            connection, row["id"], row["lifecycle"], ProgramLifecycle.ACTIVE.value,
                            "catalog_sync", "reappeared in catalogue",
                        )
                        transitions += 1
            if complete:
                watched = connection.execute(
                    "SELECT * FROM programs WHERE platform = ?", (platform,)
                ).fetchall()
                for row in watched:
                    if row["external_id"] in incoming:
                        continue
                    if row["external_id"] not in existing:
                        # Never mirrored by any catalogue response: manually defined
                        # and never publicly listed â€” the catalogue cannot delist it.
                        continue
                    if row["lifecycle"] in (ProgramLifecycle.ACTIVE.value, ProgramLifecycle.PAUSED.value):
                        connection.execute(
                            """
                            UPDATE programs SET lifecycle = ?, lifecycle_since = ?, updated_at = ?
                            WHERE id = ?
                            """,
                            (ProgramLifecycle.DELISTED.value, now, now, row["id"]),
                        )
                        self._record_transition(
                            connection, row["id"], row["lifecycle"], ProgramLifecycle.DELISTED.value,
                            "catalog_sync", "missing from complete catalogue",
                        )
                        transitions += 1

            self.bind_policy_owners()
            self._journal_observations(connection, candidates)
            if transitions or watchlist_changed or removed:
                self._touch_queue(connection)

        result = {
            "total": len(incoming),
            "added": len(set(incoming) - set(existing)),
            "removed": len(removed),
            "reactivated": sum(1 for key in incoming if key in existing and not existing[key]["active"]),
            "complete": bool(complete),
            "transitions": transitions,
            "synced_at": now,
        }
        if transitions or watchlist_changed:
            self._notify()
        return result

    def catalog_completeness(self, platform: str) -> dict[str, Any]:
        """The last catalogue-completeness signal recorded for ``platform``."""
        status = self.get_runtime_status(f"{platform}_catalog") or {}
        return {
            "complete": bool(status.get("complete", False)),
            "reason": status.get("completeness_reason", ""),
            "program_count": status.get("program_count"),
            "synced_at": status.get("synced_at"),
        }

    # --------------------------------------------------------------------- jobs

    def upsert_job(
        self,
        *,
        job_key: str,
        protocol_id: str | None,
        source_type: str,
        priority: str,
        interval_seconds: int,
        next_run_at: str | None = None,
        program_id: int | None = None,
        target_key: str | None = None,
        job_kind: str = "poll",
    ) -> None:
        interval_seconds = positive_interval(interval_seconds, f'job {job_key} interval_seconds')
        due = next_run_at or utc_now()
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO poll_jobs(
                    job_key, protocol_id, program_id, source_type, target_key, job_kind,
                    priority, interval_seconds, next_run_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(job_key) DO UPDATE SET
                    protocol_id = excluded.protocol_id,
                    program_id = excluded.program_id,
                    source_type = excluded.source_type,
                    target_key = excluded.target_key,
                    job_kind = excluded.job_kind,
                    priority = excluded.priority,
                    interval_seconds = excluded.interval_seconds,
                    next_run_at = CASE
                        WHEN excluded.interval_seconds < poll_jobs.interval_seconds
                        AND poll_jobs.last_finished_at IS NOT NULL
                        AND COALESCE(poll_jobs.last_status,'') NOT IN ('running','error','deferred')
                        THEN MIN(poll_jobs.next_run_at, strftime('%Y-%m-%dT%H:%M:%S+00:00', poll_jobs.last_finished_at, '+' || excluded.interval_seconds || ' seconds'))
                        ELSE poll_jobs.next_run_at END
                """,
                (job_key, protocol_id, program_id, source_type, target_key, job_kind, priority, interval_seconds, due),
            )

    def prune_jobs(self, keep: Iterable[str]) -> int:
        """Delete job rows that no adapter, program or enabled global job wants anymore."""
        keep = set(keep)
        with self.connect() as connection:
            stale = [
                row["job_key"]
                for row in connection.execute("SELECT job_key FROM poll_jobs").fetchall()
                if row["job_key"] not in keep
            ]
            for job_key in stale:
                connection.execute("DELETE FROM poll_jobs WHERE job_key = ?", (job_key,))
        return len(stale)

    def recover_interrupted_jobs(self, *, job_keys: Sequence[str] | None = None) -> int:
        if job_keys is not None and not job_keys:
            return 0
        with self.connect() as connection:
            cursor = connection.execute(
                """
                UPDATE poll_jobs
                SET last_status = 'deferred', manually_queued = 1,
                    last_error = 'Recovered after restart; queued for retry',
                    next_run_at = ?
                WHERE last_status = 'running'
                """ + (f" AND job_key IN ({','.join('?' for _ in job_keys)})" if job_keys is not None else ''),
                (utc_now(), *(job_keys or ())),
            )
            return cursor.rowcount

    def due_jobs(self, now: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM (
                  SELECT *, ROW_NUMBER() OVER (PARTITION BY source_type ORDER BY manually_queued DESC, next_run_at, job_key) AS source_rank
                  FROM poll_jobs
                  WHERE next_run_at <= ? AND COALESCE(last_status, '') != 'running'
                ) ORDER BY source_rank, next_run_at, job_key LIMIT ?
                """, (now or utc_now(), max(1, min(limit * 2, 1000))),
            ).fetchall()
        selected, seen = [], set()
        for row in rows:
            key = (row["source_type"], row["target_key"] or row["job_key"])
            if key in seen:
                continue
            seen.add(key)
            selected.append({k: row[k] for k in row.keys() if k != 'source_rank'})
            if len(selected) >= limit:
                break
        return selected

    def next_job_delay(self, maximum: float) -> float:
        with self.connect() as connection:
            row = connection.execute("SELECT MIN(next_run_at) FROM poll_jobs WHERE COALESCE(last_status, '') != 'running'").fetchone()
        if not row[0]:
            return maximum
        delay = (datetime.fromisoformat(row[0]) - datetime.now(timezone.utc)).total_seconds()
        # Avoid spinning if another runner currently owns due work.
        return min(maximum, max(0.1, delay))

    def claim_job(self, job_key: str) -> bool:
        with self.connect() as connection:
            cursor = connection.execute(
                """
                UPDATE poll_jobs
                SET last_status = 'running', last_started_at = ?, manually_queued = 0
                WHERE job_key = ? AND COALESCE(last_status, '') != 'running'
                """,
                (utc_now(), job_key),
            )
            return bool(cursor.rowcount)

    def finish_job(
        self,
        job_key: str,
        *,
        success: bool,
        result: dict[str, Any],
        error: str | None = None,
        max_retry_seconds: int = 900,
        retry_at: str | None = None,
        deferred: bool = False,
    ) -> None:
        """Record a job outcome and schedule its next run.

        Failure backoff grows from the job's own interval and is floored at that
        interval: an hourly job never retries sooner than hourly just because
        ``max_retry_seconds`` is a smaller number. ``retry_at`` with ``deferred``
        (an HTTP cooldown blocked the request) reschedules without touching the
        failure streak â€” the cooldown governs when the check may run again.
        """
        with self.connect() as connection:
            row = connection.execute(
                "SELECT interval_seconds, consecutive_failures, quiet_polls FROM poll_jobs WHERE job_key = ?",
                (job_key,),
            ).fetchone()
            if row is None:
                return
            failures = int(row["consecutive_failures"])
            interval = int(row["interval_seconds"])
            quiet_polls = 0
            if deferred:
                status = "deferred"
            elif success:
                status = "ok"
                failures = 0
                changes = int(result.get("changes", 0) or 0) if isinstance(result, dict) else 0
                quiet_polls = int(row["quiet_polls"]) + 1 if changes == 0 else 0
                interval = self._adaptive_interval(interval, quiet_polls)
            else:
                status = "error"
                failures += 1
                interval = max(interval, min(interval * (2 ** max(failures - 1, 0)), max_retry_seconds))
            if retry_at is not None:
                next_run = retry_at
            else:
                next_run = (datetime.now(timezone.utc) + timedelta(seconds=interval)).isoformat(timespec="seconds")
            connection.execute(
                """
                UPDATE poll_jobs SET
                    last_finished_at = ?, last_status = ?, last_error = ?,
                    last_result_json = ?, consecutive_failures = ?, quiet_polls = ?, next_run_at = ?
                WHERE job_key = ?
                """,
                (
                    utc_now(),
                    status,
                    error,
                    _json(result),
                    failures,
                    quiet_polls,
                    next_run,
                    job_key,
                ),
            )

    @staticmethod

    def _adaptive_interval(interval: int, quiet_polls: int) -> int:
        """Adaptive cadence: consecutive change-less checks stretch the gap
        (doubling, capped at 3x), and the first change snaps back to the base."""
        if quiet_polls <= 0:
            return interval
        return min(interval * (2 ** min(quiet_polls, 2)), interval * 3)

    def force_jobs(self, source_type: str | None = None) -> int:
        self.retry_blocked_targets(source_type=source_type)
        with self.connect() as connection:
            if source_type:
                cursor = connection.execute(
                    """UPDATE poll_jobs
                    SET next_run_at = ?, manually_queued = 1
                    WHERE source_type = ? AND COALESCE(last_status, '') != 'running'""",
                    (utc_now(), source_type),
                )
            else:
                cursor = connection.execute(
                    """UPDATE poll_jobs
                    SET next_run_at = ?, manually_queued = 1
                    WHERE COALESCE(last_status, '') != 'running'""",
                    (utc_now(),),
                )
            return cursor.rowcount

    def list_jobs(self) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM poll_jobs ORDER BY next_run_at ASC"
            ).fetchall()
        jobs = [dict(row) for row in rows]
        for job in jobs:
            job["last_result"] = json.loads(job.pop("last_result_json")) if job["last_result_json"] else None
        return jobs

    def list_catalog(self, platform: str | None = None) -> list[dict[str, Any]]:
        with self.connect() as connection:
            if platform:
                rows = connection.execute(
                    "SELECT * FROM catalog_programs WHERE platform = ? ORDER BY name", (platform,)
                ).fetchall()
            else:
                rows = connection.execute("SELECT * FROM catalog_programs ORDER BY platform, name").fetchall()
        programs = [dict(row) for row in rows]
        for program in programs:
            program["metadata"] = json.loads(program.pop("metadata_json"))
        return programs

    def set_runtime_status(self, key: str, value: Any, *, touch_queue: bool = False) -> None:
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO runtime_status(key, value_json, updated_at) VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at
                """,
                (key, _json(value), utc_now()),
            )
            if touch_queue:
                self._touch_queue(connection)

    @staticmethod
    def _touch_queue(connection: sqlite3.Connection) -> None:
        connection.execute("""
            INSERT INTO runtime_status(key,value_json,updated_at) VALUES ('queue_revision','1',?)
            ON CONFLICT(key) DO UPDATE SET value_json=CAST(CAST(value_json AS INTEGER)+1 AS TEXT), updated_at=excluded.updated_at
        """, (utc_now(),))

    def runtime_status(self) -> dict[str, Any]:
        with self.connect() as connection:
            rows = connection.execute("SELECT * FROM runtime_status ORDER BY key").fetchall()
        return {
            row["key"]: {"value": json.loads(row["value_json"]), "updated_at": row["updated_at"]}
            for row in rows
        }

    def get_runtime_status(self, key: str) -> Any | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT value_json FROM runtime_status WHERE key = ?", (key,)
            ).fetchone()
        return json.loads(row["value_json"]) if row else None

    def observation_contexts(self, protocol_ids: Iterable[str], window_hours: int) -> dict[str, Any]:
        ids = tuple(sorted(set(protocol_ids)))
        if not ids:
            return {}
        marks = ','.join('?' for _ in ids)
        contexts = {key: {'related': [], 'programs': []} for key in ids}
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=window_hours)).isoformat(timespec='seconds')
        with self.connect() as connection:
            for row in connection.execute(f"SELECT DISTINCT protocol_id, kind FROM events WHERE protocol_id IN ({marks}) AND detected_at >= ?", (*ids, cutoff)):
                contexts[row['protocol_id']]['related'].append(row['kind'])
            programs = {}
            for row in connection.execute(f"SELECT * FROM programs WHERE protocol_id IN ({marks}) ORDER BY id", ids):
                program = _program_row(row)
                entry = {'program': program, 'assets': [], 'primacy': None}
                programs[program['id']] = entry
                contexts[program['protocol_id']]['programs'].append(entry)
            for row in connection.execute(f"SELECT s.* FROM program_scope s JOIN programs p ON p.id=s.program_id WHERE p.protocol_id IN ({marks}) AND s.active=1 AND s.kind='asset' ORDER BY s.kind,s.label", ids):
                programs[row['program_id']]['assets'].append(dict(row))
            for row in connection.execute(f"SELECT r.* FROM program_primacy_rules r JOIN programs p ON p.id=r.program_id WHERE p.protocol_id IN ({marks})", ids):
                rule = dict(row)
                for key in ('categories','severities','exclusions','raw'):
                    rule[key] = json.loads(rule.pop(key+'_json'))
                programs[row['program_id']]['primacy'] = rule
        return contexts

    def reconciliation_snapshot(self, source_types: Sequence[str]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        """Read programs, active targets and latest policies in three queries."""
        marks = ','.join('?' for _ in source_types) or "''"
        with self.connect() as connection:
            programs = [_program_row(row) for row in connection.execute(
                "SELECT * FROM programs WHERE lifecycle IN ('active','paused') ORDER BY platform, external_id"
            )]
            targets = defaultdict(list)
            for row in connection.execute("SELECT program_id, source_type, target_key, origin FROM monitoring_targets WHERE active = 1"):
                targets[row['program_id']].append(dict(row))
            policies = {}
            for row in connection.execute(f"""
                SELECT program_id, protocol_id, source_key, source_type, payload_json FROM (
                    SELECT *, ROW_NUMBER() OVER (PARTITION BY program_id ORDER BY updated_at DESC, rowid DESC) AS rank
                    FROM source_state WHERE program_id IS NOT NULL AND source_type IN ({marks})
                ) WHERE rank = 1
            """, tuple(source_types)):
                policies[row['program_id']] = {'source_key': row['source_key'], 'source_type': row['source_type'], 'payload': json.loads(row['payload_json'])}
        for program in programs:
            program['active_targets'] = targets[program['id']]
        return programs, policies

    def latest_policy_payload(
        self, protocol_id: str, source_types: Sequence[str], *, program_id: int | None = None
    ) -> dict[str, Any] | None:
        """The most recent normalised policy payload stored for a program."""
        marks = ",".join("?" for _ in source_types) or "''"
        with self.connect() as connection:
            if program_id is None:
                owners = connection.execute('SELECT id FROM programs WHERE protocol_id=?', (protocol_id,)).fetchall()
                if len(owners) > 1:
                    return None  # Callers must name the watched program when ownership is ambiguous.
                program_id = owners[0]['id'] if owners else None
            row = connection.execute(
                f"""
                SELECT * FROM source_state
                WHERE protocol_id = ? AND source_type IN ({marks})
                  AND (program_id = ? OR (? IS NULL AND program_id IS NULL))
                ORDER BY updated_at DESC, rowid DESC LIMIT 1
                """,
                (protocol_id, *tuple(source_types), program_id, program_id),
            ).fetchone()
        if row is None:
            return None
        return {
            "source_key": row["source_key"],
            "source_type": row["source_type"],
            "payload": json.loads(row["payload_json"]),
            "updated_at": row["updated_at"],
        }

    def event_ids_for_fingerprints(self, fingerprints: Iterable[str]) -> dict[str, int]:
        values = tuple(set(fingerprints))
        if not values:
            return {}
        marks = ','.join('?' for _ in values)
        with self.connect() as connection:
            return {row['fingerprint']: row['id'] for row in connection.execute(f'SELECT id,fingerprint FROM events WHERE fingerprint IN ({marks})', values)}

    def get_event_by_fingerprint(self, fingerprint: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM events WHERE fingerprint = ?", (fingerprint,)
            ).fetchone()
        return _plain_event_row(row) if row is not None else None

    # ------------------------------------------------------- links & eligibility

    def link_events(self, lead_id: int, signal_id: int, evidence: dict[str, Any]) -> bool:
        """Link a signal to a lead on concrete asset/repository/path evidence.

        Idempotent on (lead, signal, evidence). Callers must never link on mere
        protocol identity or a shared time window â€” the evidence row is the reason.
        """
        with self.connect() as connection:
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO event_links(lead_id, signal_id, evidence_json, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (lead_id, signal_id, _json(evidence), utc_now()),
            )
        return bool(cursor.rowcount)

    def list_event_links(self, event_id: int) -> list[dict[str, Any]]:
        """Every lead/signal link touching ``event_id``, with its evidence."""
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT l.*, e.id AS other_id, e.kind AS other_kind, e.entity AS other_entity,
                       e.protocol_id AS other_protocol_id, e.detected_at AS other_detected_at,
                       e.category AS other_category, e.score AS other_score
                FROM event_links l
                JOIN events e ON e.id = CASE WHEN l.lead_id = ? THEN l.signal_id ELSE l.lead_id END
                WHERE l.lead_id = ? OR l.signal_id = ?
                ORDER BY l.id ASC
                """,
                (event_id, event_id, event_id),
            ).fetchall()
        links: list[dict[str, Any]] = []
        for row in rows:
            links.append(
                {
                    "lead_id": row["lead_id"],
                    "signal_id": row["signal_id"],
                    "evidence": json.loads(row["evidence_json"]),
                    "created_at": row["created_at"],
                    "other": {
                        "id": row["other_id"],
                        "kind": row["other_kind"],
                        "entity": row["other_entity"],
                        "protocol_id": row["other_protocol_id"],
                        "category": row["other_category"],
                        "score": row["other_score"],
                        "detected_at": row["other_detected_at"],
                    },
                }
            )
        return links

    def leads_for_protocol(self, protocol_id: str) -> list[dict[str, Any]]:
        """Lead events of a protocol â€” the link candidates for its signals."""
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM events
                WHERE protocol_id = ? AND category = 'lead'
                ORDER BY detected_at DESC
                """,
                (protocol_id,),
            ).fetchall()
        return [_plain_event_row(row) for row in rows]

    def update_event_classification(
        self, event_id: int, *, eligibility: str, evidence: Iterable[Any]
    ) -> None:
        with self.connect() as connection:
            connection.execute(
                "UPDATE events SET eligibility = ?, evidence_json = ?, updated_at = ? WHERE id = ?",
                (eligibility, _json(list(evidence)), utc_now(), event_id),
            )
            self._touch_queue(connection)

    # ------------------------------------------------------------- sweep summary

    def sweep_summary(self, stale_factor: float = 2.0) -> dict[str, Any]:
        """Counts of current scheduled checks and their latest outcomes."""
        now = datetime.now(timezone.utc)
        with self.connect() as connection:
            row = connection.execute("""
                SELECT COUNT(*) AS total,
                    COALESCE(SUM(last_status='ok' AND COALESCE(json_array_length(json_extract(last_result_json, '$.warnings')),0)=0),0) AS successful,
                    COALESCE(SUM(last_status='error' OR COALESCE(json_array_length(json_extract(last_result_json, '$.warnings')),0)>0),0) AS failed,
                    COALESCE(SUM(last_status='running'),0) AS running,
                    COALESCE(SUM(last_status='deferred'),0) AS deferred,
                    COALESCE(SUM(COALESCE(last_status,'') NOT IN ('ok','error','running','deferred')),0) AS pending,
                    COALESCE(SUM(COALESCE(last_status,'') != 'running' AND julianday(next_run_at) <= julianday(?)),0) AS due,
                    COALESCE(SUM((julianday(?) - julianday(last_finished_at))*86400 > interval_seconds*?),0) AS stale
                FROM poll_jobs
            """, (now.isoformat(), now.isoformat(), stale_factor)).fetchone()
            blocked = connection.execute('SELECT COUNT(*) FROM blocked_poll_targets').fetchone()[0]
        return {**dict(row), 'total': row['total'] + blocked, 'failed': row['failed'] + blocked,
                'blocked': blocked, 'checked_at': now.isoformat(timespec='seconds')}

    def configured_target_count(self) -> int:
        with self.connect() as connection:
            return connection.execute('SELECT COUNT(*) FROM poll_jobs WHERE target_key IS NOT NULL').fetchone()[0]

    def list_failed_jobs(self) -> list[dict[str, Any]]:
        """Only failed or cooldown-deferred checks, with their error and retry time."""
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM poll_jobs
                WHERE last_status IN ('error', 'deferred')
                   OR json_array_length(json_extract(last_result_json, '$.warnings')) > 0
                ORDER BY next_run_at ASC
                """
            ).fetchall()
        jobs = [dict(row) for row in rows]
        for job in jobs:
            job["last_result"] = json.loads(job.pop("last_result_json")) if job["last_result_json"] else None
            if job['last_status'] == 'ok':
                job.update(last_status='degraded', last_error=' '.join(job['last_result']['warnings']))
            job["retry_at"] = job["next_run_at"]
        for blocked in self.blocked_targets():
            job = json.loads(blocked['failed_job_json'])
            jobs.append({**job, 'source_type': blocked['source_type'], 'target_key': blocked['target_key'],
                'last_status': 'blocked', 'last_error': blocked['error'], 'last_result': None,
                'next_run_at': None, 'retry_at': None, 'manually_queued': 0})
        return jobs

    def retry_blocked_targets(self, *, source_type: str | None = None, job_key: str | None = None) -> int:
        """An explicit retry restores archived work; automatic reconciliation does not."""
        count = 0
        with self.connect() as connection:
            for row in connection.execute('SELECT * FROM blocked_poll_targets').fetchall():
                job = json.loads(row['failed_job_json'])
                if source_type is not None and row['source_type'] != source_type:
                    continue
                if job_key is not None and job['job_key'] != job_key:
                    continue
                connection.execute('DELETE FROM blocked_poll_targets WHERE source_type=? AND target_key=?',
                                   (row['source_type'], row['target_key']))
                self.upsert_job(job_key=job['job_key'], protocol_id=job.get('protocol_id'),
                    source_type=row['source_type'], target_key=row['target_key'],
                    priority=job.get('priority', 'normal'), interval_seconds=job.get('interval_seconds', 600),
                    job_kind=job.get('job_kind', 'poll'))
                count += 1
        if count:
            self._notify()
        return count

    def force_job(self, job_key: str) -> bool:
        """Make one check due now (a manual refresh of a single job)."""
        self.retry_blocked_targets(job_key=job_key)
        with self.connect() as connection:
            cursor = connection.execute(
                """
                UPDATE poll_jobs SET next_run_at = ?, manually_queued = 1
                WHERE job_key = ? AND COALESCE(last_status, '') != 'running'
                """,
                (utc_now(), job_key),
            )
        return bool(cursor.rowcount)

    # ----------------------------------------------------------- compare caching

    def get_compare_cache(self, cache_key: str) -> Any | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT payload_json FROM compare_cache WHERE cache_key = ?", (cache_key,)
            ).fetchone()
        return json.loads(row["payload_json"]) if row is not None else None

    def prune_processed_observations(self, retention_days: int = 90) -> int:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat(timespec='seconds')
        with self.connect() as connection:
            cursor = connection.execute("""
                DELETE FROM source_observations
                WHERE processed_at < ? AND event_id IS NOT NULL
                    AND EXISTS (SELECT 1 FROM events WHERE events.id=source_observations.event_id)
            """, (cutoff,))
        return cursor.rowcount

    def compact_github_patches(self) -> dict[str, int]:
        """Remove unused file patches, preserving all other historical fields.

        Only snapshot rows are compacted. Compare-cache entries are read on a
        cache hit to reconstruct event file evidence, so their patches are kept;
        the previous predicate targeted cache formats no longer written.
        """
        counts = {'source_state': 0, 'bytes_removed': 0}
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT rowid, payload_json FROM source_state WHERE source_type = 'github'"
            ).fetchall()
            for row in rows:
                payload = json.loads(row['payload_json'])
                if not _remove_file_patches(payload):
                    continue
                compact = _json(payload)
                connection.execute("UPDATE source_state SET payload_json = ? WHERE rowid = ?", (compact, row['rowid']))
                counts['source_state'] += 1
                counts['bytes_removed'] += len(row['payload_json'].encode('utf-8')) - len(compact.encode('utf-8'))
        return counts

    def prune_compare_cache(self, retention_days: int = 90) -> int:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat(timespec="seconds")
        with self.connect() as connection:
            cursor = connection.execute("DELETE FROM compare_cache WHERE created_at < ?", (cutoff,))
        return cursor.rowcount

    def run_maintenance(self) -> dict[str, int]:
        """The daily pass: historical patch compaction, retention prunes, WAL truncate."""
        counts = self.compact_github_patches()
        counts['compare_cache_pruned'] = self.prune_compare_cache()
        counts['observations_pruned'] = self.prune_processed_observations()
        with self.connect() as connection:
            connection.execute('PRAGMA wal_checkpoint(TRUNCATE)')
        return counts

    def set_compare_cache(self, cache_key: str, payload: Any) -> None:
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO compare_cache(cache_key, payload_json, created_at)
                VALUES (?, ?, ?)
                ON CONFLICT(cache_key) DO UPDATE SET
                    payload_json = excluded.payload_json,
                    created_at = excluded.created_at
                """,
                (cache_key, _json(payload), utc_now()),
            )

    # ----------------------------------------------------------------- internal

    def _notify(self) -> None:
        if self.on_change is None:
            return
        try:
            self.on_change()
        except Exception as error:  # reconciliation must not fail a commit
            try:
                self.set_runtime_status("reconcile_error", {"error": str(error)[:500], "at": utc_now()})
            except Exception:
                pass

    def _event_select(self, *, queue_only: bool = False) -> tuple[str, tuple[Any, ...]]:
        """Build the event projection with program context joined in.

        Which source supplies the program payload, and which platform owns the
        catalogue row, are adapter facts read from the registry rather than literals.
        Row-multiplying joins are avoided with correlated ``rowid`` subqueries so N
        policy or catalogue adapters can never duplicate an event.
        """
        types = self.policy_source_types()
        platforms = self.adapters.catalog_platforms()
        type_marks = ",".join("?" for _ in types) or "''"
        platform_marks = ",".join("?" for _ in platforms) or "''"
        # ``not metadata.get('platform')``, as in ``list_program_events``: a
        # present-but-empty platform carries no ownership information.
        platform = "json_extract(e.metadata_json,'$.platform')"
        absent_platform = (
            f"(COALESCE({platform}, '') IN ('', 0)"
            f" OR (json_type(e.metadata_json,'$.platform') = 'array' AND {platform} = '[]')"
            f" OR (json_type(e.metadata_json,'$.platform') = 'object' AND {platform} = '{{}}'))"
        )
        sql = f"""
SELECT e.*, COALESCE(wp.name,p.name) AS protocol_name, p.config_json AS protocol_config_json,
       c.url AS program_url, c.max_bounty AS catalog_max_bounty,
       c.active AS catalog_active, c.metadata_json AS catalog_metadata_json,
       c.first_seen_at AS catalog_first_seen_at, c.last_seen_at AS catalog_last_seen_at,
       ss.payload_json AS policy_payload_json,
       wp.id AS watched_program_id, wp.lifecycle AS program_lifecycle,
       wp.url AS watched_program_url, wp.max_bounty AS watched_max_bounty,
       (wp.id IS NULL AND EXISTS(SELECT 1 FROM programs WHERE protocol_id=e.protocol_id)) AS ambiguous_program_context
FROM events e
JOIN protocols p ON p.id = e.protocol_id
LEFT JOIN programs wp ON wp.id = (
    SELECT MIN(p2.id) FROM programs p2 WHERE p2.protocol_id=e.protocol_id
      AND (COALESCE(json_extract(e.metadata_json,'$.program_id'),json_extract(e.metadata_json,'$.manual_program_id')) IS NULL
           OR p2.id=COALESCE(json_extract(e.metadata_json,'$.program_id'),json_extract(e.metadata_json,'$.manual_program_id')))
      AND ({absent_platform} OR p2.platform={platform})
    HAVING COUNT(*)=1)
LEFT JOIN catalog_programs c
  ON c.rowid = (
        SELECT c2.rowid FROM catalog_programs c2
        WHERE c2.platform IN ({platform_marks}) AND c2.platform=wp.platform AND c2.external_id=wp.external_id
        ORDER BY c2.last_seen_at DESC LIMIT 1)
LEFT JOIN source_state ss
  ON ss.rowid = (
        SELECT s2.rowid FROM source_state s2
        WHERE s2.protocol_id = e.protocol_id AND s2.source_type IN ({type_marks})
          AND (s2.program_id=wp.id OR (wp.id IS NULL AND s2.program_id IS NULL
              AND NOT EXISTS (SELECT 1 FROM programs WHERE protocol_id=e.protocol_id)))
        ORDER BY s2.updated_at DESC LIMIT 1)
"""
        if queue_only:
            sql = sql.replace('e.*,', "e.id, e.protocol_id, e.source_key, e.kind, e.entity, e.score, e.category, e.eligibility, e.status, e.detected_at, e.updated_at, 'null' AS before_json, 'null' AS after_json, '{}' AS metadata_json, '[]' AS reasons_json, '[]' AS evidence_json, '' AS note,")
            sql = sql.replace('ss.payload_json AS policy_payload_json', "json_object('max_bounty', json_extract(ss.payload_json, '$.max_bounty'), 'submission_cost', json_extract(ss.payload_json, '$.submission_cost'), 'policy', json_object('pay_to_submit', json_extract(ss.payload_json, '$.policy.pay_to_submit'))) AS policy_payload_json")
            sql = sql.replace('c.metadata_json AS catalog_metadata_json', "json_object('submission_cost', json_extract(c.metadata_json, '$.submission_cost'), 'pay_to_submit', json_extract(c.metadata_json, '$.pay_to_submit')) AS catalog_metadata_json")
        return sql, (*platforms, *types)


def _remove_file_patches(value: Any) -> bool:
    changed = False
    if isinstance(value, dict):
        if 'filename' in value and 'patch' in value:
            del value['patch']
            changed = True
        for child in value.values():
            changed = _remove_file_patches(child) or changed
    elif isinstance(value, list):
        for child in value:
            changed = _remove_file_patches(child) or changed
    return changed


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _fingerprint(event: ScoredEvent) -> str:
    return event.observation_fingerprint or _fingerprint_candidate(event.candidate)


def _observation_stream(candidate: EventCandidate) -> tuple[str, str, str, str]:
    # Opposite policy transitions (pause/resume, add/remove, raise/lower) belong
    # to the same stream; otherwise the second pause looks like a retry of the first.
    kind = 'BOUNTY' if candidate.kind.startswith('BOUNTY_') else candidate.kind
    owner = candidate.metadata.get('program_id') or candidate.metadata.get('manual_program_id')
    if owner is not None:
        kind += f':program:{owner}'
    return candidate.protocol_id, candidate.source_key, kind, candidate.entity


def _fingerprint_candidate(candidate: EventCandidate) -> str:
    import hashlib

    value = "|".join(
        (
            candidate.protocol_id,
            candidate.source_key,
            candidate.kind,
            candidate.entity,
            _json(candidate.before),
            _json(candidate.after),
        )
    )
    owner = candidate.metadata.get('program_id') or candidate.metadata.get('manual_program_id')
    if owner is not None:
        value += f'|program:{owner}'
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _metadata_platform(metadata: Any) -> str | None:
    if isinstance(metadata, dict):
        platform = metadata.get("platform")
        return str(platform) if platform else None
    return None


def _program_row(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    program = dict(row)
    program["metadata"] = json.loads(program.pop("metadata_json") or "{}")
    return program


def _hides_retired_programs(tab: str | None, status: str | None) -> bool:
    """Normal queues hide events of retired (dismissed) programs; the dismissed
    queue and raw history keep showing them."""
    if status == "dismissed" or tab == "dismissed":
        return False
    return tab in ("to_review", "reviewed") or (status is not None and status != "dismissed")


def _plain_event_row(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "fingerprint": row["fingerprint"],
        "protocol_id": row["protocol_id"],
        "source_key": row["source_key"],
        "kind": row["kind"],
        "entity": row["entity"],
        "before": json.loads(row["before_json"]) if row["before_json"] else None,
        "after": json.loads(row["after_json"]) if row["after_json"] else None,
        "metadata": json.loads(row["metadata_json"]),
        "score": row["score"],
        "reasons": json.loads(row["reasons_json"]),
        "category": row["category"],
        "eligibility": row["eligibility"],
        "evidence": json.loads(row["evidence_json"] or "[]"),
        "status": row["status"],
        "note": row["note"],
        "detected_at": row["detected_at"],
        "updated_at": row["updated_at"],
    }


def _event_row(row: sqlite3.Row, config_keys: tuple[str, ...]) -> dict[str, Any]:
    columns = row.keys()
    return {
        "id": row["id"],
        "protocol_id": row["protocol_id"],
        "protocol_name": row["protocol_name"] if "protocol_name" in columns else row["protocol_id"],
        "source_key": row["source_key"],
        "kind": row["kind"],
        "entity": row["entity"],
        "before": json.loads(row["before_json"]) if row["before_json"] else None,
        "after": json.loads(row["after_json"]) if row["after_json"] else None,
        "metadata": json.loads(row["metadata_json"]),
        "score": row["score"],
        "reasons": json.loads(row["reasons_json"]),
        "category": row["category"],
        "eligibility": row["eligibility"],
        "evidence": json.loads(row["evidence_json"] or "[]"),
        "status": row["status"],
        "note": row["note"],
        "detected_at": row["detected_at"],
        "updated_at": row["updated_at"],
        "retired": "program_lifecycle" in columns and row["program_lifecycle"] == ProgramLifecycle.DISMISSED.value,
        "program": _program_summary(row, config_keys),
    }


def _program_summary(row: sqlite3.Row, config_keys: tuple[str, ...]) -> dict[str, Any]:
    columns = row.keys()
    config = json.loads(row["protocol_config_json"]) if "protocol_config_json" in columns and row["protocol_config_json"] else {}
    configured = next((config[key] for key in config_keys if isinstance(config.get(key), dict) and config.get(key)), {})
    if 'watched_program_id' in columns and row['watched_program_id'] is not None:
        configured = {'url':row['watched_program_url'], 'max_bounty':row['watched_max_bounty']}
    elif 'ambiguous_program_context' in columns and row['ambiguous_program_context']:
        configured = {}
    metadata = json.loads(row["catalog_metadata_json"]) if "catalog_metadata_json" in columns and row["catalog_metadata_json"] else {}
    payload = json.loads(row["policy_payload_json"]) if "policy_payload_json" in columns and row["policy_payload_json"] else {}
    policy = payload.get("policy") or {}

    max_bounty = payload.get("max_bounty")
    if max_bounty is None:
        max_bounty = row["catalog_max_bounty"] if "catalog_max_bounty" in columns else None
    if max_bounty is None:
        max_bounty = configured.get("max_bounty")

    url = (row["program_url"] if "program_url" in columns else None) or configured.get("url")
    active = row["catalog_active"] if "catalog_active" in columns else None
    submission_cost = payload.get("submission_cost")
    if submission_cost is None:
        submission_cost = metadata.get("submission_cost")
    return {
        "url": url,
        "max_bounty": max_bounty,
        "active": None if 'ambiguous_program_context' in columns and row['ambiguous_program_context'] else True if active is None else bool(active),
        "rewards": payload.get("rewards") or metadata.get("rewards") or {},
        "submission_cost": submission_cost,
        "pay_to_submit": bool(policy.get("pay_to_submit", metadata.get("pay_to_submit", False))),
    }


def _program_detail(
    row: sqlite3.Row,
    state: sqlite3.Row | None,
    read: sqlite3.Row | None,
) -> dict[str, Any]:
    payload = json.loads(state["payload_json"]) if state is not None else {}
    columns = row.keys()
    detail: dict[str, Any] = {
        "status": 'unknown' if 'ambiguous_program_context' in columns and row['ambiguous_program_context'] else payload.get("status", "active"),
        "scope": payload.get("scope", []),
        "impacts": payload.get("impacts", []),
        "out_of_scope": payload.get("out_of_scope", []),
        "policy": payload.get("policy", {}),
        "first_seen_at": row["catalog_first_seen_at"] if "catalog_first_seen_at" in columns else None,
        "last_seen_at": row["catalog_last_seen_at"] if "catalog_last_seen_at" in columns else None,
        "last_read_at": read["updated_at"] if read is not None else (state["updated_at"] if state is not None else None),
    }
    if payload.get("rewards"):
        detail["rewards"] = payload["rewards"]
    if payload.get("submission_cost") is not None:
        detail["submission_cost"] = payload["submission_cost"]
    return detail
