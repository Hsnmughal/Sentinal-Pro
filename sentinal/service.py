from __future__ import annotations

from dataclasses import dataclass
from contextlib import nullcontext, contextmanager
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import hashlib
import math
from datetime import datetime, timezone
from typing import Any, Callable

from .config import AppConfig
from .core.bounty_policy import (
    normalize_entry,
    ELIGIBILITY_UNRESOLVED,
    asset_match_evidence,
    classify_code_change,
    code_location,
    strongest_eligibility,
)
from .core.contract import GlobalContext, PollContext, validate_kind
from .core.http import HttpClient, RequestBudget, RequestDeferred
from .core.kinds import LEAD, category_for_tags
from .core.models import EventCandidate, ProgramLifecycle, ScoredEvent
from .core.registry import Adapter, Registry, UnknownSourceError, default_registry
from .core.scoring import score_event
from .exporting import export_platforms
from .store import Store
from .onchain import OnchainChecks


#: Marks that config.toml definitions were imported as seeds. Import runs once as
#: the seed/override step; later startups only add definitions the database has
#: never seen, so the database stays authoritative over discovery and review.
SEED_MARKER = "config_seed_imported"

_ACTIVE_PAUSED = (ProgramLifecycle.ACTIVE.value, ProgramLifecycle.PAUSED.value)
_ACTIVE_ONLY = (ProgramLifecycle.ACTIVE.value,)


@dataclass(frozen=True, slots=True)
class PollResult:
    inserted: int
    duplicates: int
    errors: tuple[str, ...]


class SentinalService:
    """Coordination only. Every platform-specific behaviour lives behind an adapter.

    The SQLite watched-program list and its monitoring targets drive scheduling;
    ``config.toml`` is imported once as seeds/manual overrides. Derived work
    (observations, catalog updates) is journaled atomically by adapters and turned
    into scored events by :meth:`drain_observations`, which is idempotent and safe
    to interrupt at any point.
    """

    def __init__(
        self,
        config: AppConfig,
        store: Store | None = None,
        client: HttpClient | None = None,
        registry: Registry | None = None,
    ):
        self.config = config
        self.registry = registry or default_registry()
        self.store = store or Store(config.database, registry=self.registry)
        self.client = client or HttpClient(
            budget=RequestBudget(self.store, config.http_settings)
        )
        self._initialized = False
        self._init_lock = threading.RLock()
        self._reconcile_lock = threading.RLock()
        self._drain_lock = threading.RLock()
        self._job_context = threading.local()
        self._target_locks: dict[Any, list[Any]] = {}
        self._target_locks_guard = threading.Lock()
        self._unfinished_jobs: set[str] = set()
        self._unfinished_jobs_guard = threading.Lock()
        self.store.on_change = self._watchlist_changed
        self.onchain = OnchainChecks(self.store, self.client)

    # ------------------------------------------------------------------ startup

    def initialize(self) -> None:
        with self._init_lock:
            if self._initialized:
                return
            self.store.initialize()
            self.onchain.recover()
            self.store.sync_protocols(self.config.protocols)
            self._seed_watchlist()
            self.store.bind_policy_owners()
            # Repair current lifecycle from existing policy snapshots even when
            # the next source response is unchanged (or the source is offline).
            programs, policies = self.store.reconciliation_snapshot(self.registry.policy_source_types())
            for program in programs:
                state = policies.get(program['id'])
                if state:
                    self.store.sync_policy_status(program['protocol_id'], program['platform'], state['payload'].get('status'), program_id=program['id'])
            self._sync_policy_tables(programs)
            # Old databases may only acquire their watched-program rows during
            # seeding, after the schema migration's repair has already run.
            if self.store.get_runtime_status('reviewed_removals_repaired_v6') is None:
                self.store.restore_reviewed_removals()
                self.store.set_runtime_status('reviewed_removals_repaired_v6', True)
            self.store.prune_compare_cache()
            self.store.prune_processed_observations()
            self.reconcile()
            self.store.recover_interrupted_jobs()
            self.drain_observations()
            self._initialized = True

    def _watchlist_changed(self) -> None:
        """A commit changed program lifecycle (catalog sync, removal dismissal,
        manual override): reconcile targets and exports immediately."""
        if getattr(self._job_context, 'active', False):
            self._job_context.changed = True
        else:
            self.reconcile()

    def _seed_watchlist(self) -> None:
        """Import config.toml definitions once as seeds/manual overrides.

        Existing rows are never re-clobbered by later startups (the database is
        authoritative); definitions the database has never seen are always added.
        The configuration itself is preserved on the program as metadata.
        """
        seeded = self.store.get_runtime_status(SEED_MARKER)
        defs: list[dict[str, Any]] = []
        for protocol in self.config.protocols:
            definition = self._definition_from_config(protocol)
            if definition is None:
                continue
            if seeded and self.store.find_program(definition["platform"], definition["external_id"]):
                continue
            defs.append(definition)
        if defs:
            self.store.import_program_defs(defs, reason="config_seed")
        if not seeded:
            self.store.set_runtime_status(
                SEED_MARKER,
                {"imported": len(defs), "at": _now()},
            )

    def _definition_from_config(self, protocol: dict[str, Any]) -> dict[str, Any] | None:
        protocol_id = str(protocol.get("id", "")).strip()
        if not protocol_id:
            return None
        platform = "manual"
        url = None
        max_bounty = protocol.get("max_bounty")
        for adapter in self.registry.policy_adapters():
            config = protocol.get(adapter.manifest.config_key)
            if isinstance(config, dict) and config.get("url"):
                url = str(config["url"])
                resolved = self.registry.resolve_host(url)
                platform = str(config.get('platform') or ('custom' if adapter.manifest.source_type == 'bounty'
                               else (resolved or adapter).manifest.platform))
                if max_bounty is None:
                    max_bounty = config.get("max_bounty")
                break
        targets: list[dict[str, Any]] = []
        for adapter in self.registry.values():
            config = protocol.get(adapter.manifest.config_key)
            if not config:
                continue
            for target_key, target_config in adapter.split_targets(config):
                if not isinstance(target_config, dict):
                    target_config = {"value": target_config}
                targets.append(
                    {
                        "source_type": adapter.manifest.source_type,
                        "target_key": str(target_key),
                        "config": target_config,
                    }
                )
        return {
            "platform": platform,
            "external_id": protocol_id,
            "protocol_id": protocol_id,
            "name": str(protocol.get("name") or protocol_id),
            "url": url,
            "max_bounty": max_bounty,
            "priority": str(protocol.get("priority", "normal")).lower(),
            "origin": "manual",
            "metadata": {"config": dict(protocol)},
            "targets": targets,
        }

    # ---------------------------------------------------------------- reconcile

    def reconcile(self) -> dict[str, Any]:
        """Bring monitoring targets, jobs and platform exports in line with the
        watched-program list. Runs after every catalog/detail change and removal
        dismissal, and at startup."""
        with self._reconcile_lock:
            with self.store.connect():
                programs, policies = self.store.reconciliation_snapshot(self.registry.policy_source_types())
                detail_targets = self._ensure_detail_targets(programs)
                discovered = self._discover_targets(programs, policies)
                jobs = self._sync_jobs()
            exports = self._export_watchlist()
            return {
                "detail_targets": detail_targets,
                "discovered_targets": discovered,
                "jobs": jobs,
                "exports": exports,
            }

    def _ensure_detail_targets(self, programs: list[dict[str, Any]]) -> int:
        """Every active or paused program with a policy page gets its detail target
        immediately — paused programs keep it (at reduced frequency) so resumption
        is noticed; delisted and dismissed programs stop being polled. Programs
        whose config seed already supplied a target of that source type are left
        alone, so seeding and discovery never duplicate a check."""
        replacements = []
        for program in programs:
            adapter = self.registry.policy_adapter_for_platform(str(program["platform"]))
            if adapter is None or not program.get("url"):
                continue
            source_type = adapter.manifest.source_type
            url = str(program["url"])
            targets = [target for target in program['active_targets'] if target['source_type'] == source_type]
            managed = [target for target in targets if target['origin'] == 'discovery']
            if targets and not managed:
                continue
            if len(managed) == 1 and managed[0]['target_key'] == url:
                continue
            replacements.append((program['id'], [{'source_type': source_type, 'target_key': url, 'config': {'url': url}}], (source_type,)))
        return self.store.sync_target_sets(replacements)

    def _discover_targets(self, programs: list[dict[str, Any]], policies: dict[str, Any]) -> int:
        """Repository (and similar) targets suggested by observed policy payloads.

        New programs get repository jobs only once repository evidence exists in
        their published scope — ownership of a repository is never assumed.
        """
        policy_types = self.registry.policy_source_types()
        replacements = []
        for program in programs:
            if program['lifecycle'] != ProgramLifecycle.ACTIVE.value:
                continue
            state = policies.get(program["id"])
            if state is None:
                continue
            adapter = self.registry[state["source_type"]]
            if adapter.discover_targets is None:
                continue
            targets = []
            for source_type, target_key, config in adapter.discover_targets(state["payload"]):
                if source_type not in self.registry.source_types():
                    continue
                targets.append({"source_type": source_type, "target_key": str(target_key), "config": config})
            replacements.append((program['id'], targets, tuple(source for source in self.registry.source_types() if source not in policy_types)))
        return self.store.sync_target_sets(replacements)

    def _sync_jobs(self) -> dict[str, int]:
        """Schedule one check per unique needed target — never per program — plus
        slower release checks and enabled global jobs. Targets no program needs
        anymore (delisted, dismissed) are pruned; a repository shared by another
        active program keeps its single job."""
        with self.store.connect():
            desired: set[str] = set()
            target_jobs = 0
            for entry in self.store.scheduling_targets(_ACTIVE_PAUSED):
                try:
                    adapter = self.registry[entry["source_type"]]
                except UnknownSourceError:
                    continue
                if adapter.manifest.polling.manual_only:
                    continue
                is_policy = adapter.manifest.policy_payload
                programs = entry["programs"]
                active = [p for p in programs if p["lifecycle"] == ProgramLifecycle.ACTIVE.value]
                if not active and not (is_policy and programs):
                    continue
                interval = self._target_interval(adapter, entry["config"], active or programs)
                if not active and is_policy:
                    interval *= self.config.paused_interval_factor
                priority = _urgest_priority(active or programs)
                job_key = f"{entry['source_type']}:{entry['target_key']}"
                desired.add(job_key)
                self.store.upsert_job(
                    job_key=job_key,
                    protocol_id=None,
                    source_type=entry["source_type"],
                    target_key=entry["target_key"],
                    job_kind="poll",
                    priority=priority,
                    interval_seconds=interval,
                )
                target_jobs += 1
                if adapter.manifest.polling.release_checks and active:
                    release_key = f"{job_key}:release"
                    desired.add(release_key)
                    self.store.upsert_job(
                        job_key=release_key,
                        protocol_id=None,
                        source_type=entry["source_type"],
                        target_key=entry["target_key"],
                        job_kind="release",
                        priority=priority,
                        interval_seconds=interval * self.config.release_interval_factor,
                    )
                    target_jobs += 1
            global_jobs = 0
            for adapter, job in self.registry.global_jobs():
                settings = self.config.global_jobs.get(job.key, {})
                if not bool(settings.get("enabled", job.enabled_by_default)):
                    continue
                job_key = f"{job.key}:{adapter.manifest.platform}"
                desired.add(job_key)
                self.store.upsert_job(
                    job_key=job_key,
                    protocol_id=None,
                    source_type=job.key,
                    priority="normal",
                    interval_seconds=int(settings.get("interval_seconds", job.interval_seconds)),
                )
                global_jobs += 1
            pruned = self.store.prune_jobs(desired)
            return {"target_jobs": target_jobs, "global_jobs": global_jobs, "pruned": pruned}

    def _target_interval(
        self, adapter: Adapter, config: Any, programs: list[dict[str, Any]]
    ) -> int:
        override = None
        if isinstance(config, dict) and "interval_seconds" in config:
            override = int(config["interval_seconds"])
        intervals = [
            adapter.manifest.polling.interval_for(
                self.config.priority_intervals,
                str(program.get("priority", "normal")).lower(),
                int(program["target_config"]["interval_seconds"])
                if "interval_seconds" in program.get("target_config", {})
                else (None if "target_config" in program else override),
            )
            for program in programs
        ]
        return min(intervals) if intervals else adapter.manifest.polling.interval_for(
            self.config.priority_intervals, "normal", override
        )

    def _export_watchlist(self) -> dict[str, str]:
        if self.config.export_directory is None:
            return {}
        try:
            return export_platforms(self.store, self.config.export_directory)
        except OSError as error:
            self.store.set_runtime_status("export_error", {"error": str(error)[:500], "at": _now()})
            return {}

    # --------------------------------------------------------------- execution

    def run_job(self, job: dict[str, Any]) -> dict[str, Any]:
        job = dict(job)
        if job.get('source_type') in self.registry.source_types() and self.registry[job['source_type']].manifest.polling.manual_only:
            return {'changes': 0, 'skipped': 'manual program checks only'}
        if job.get('source_type') is not None and self.store.is_target_blocked(job['source_type'], str(job.get('target_key') or job['job_key'])):
            return {'changes': 0, 'skipped': 'target blocked after HTTP 404'}
        job.setdefault("job_kind", "poll")
        self._job_context.active = True
        self._job_context.changed = False
        try:
            if job.get("target_key"):
                result = self._run_target_job(job)
            elif job.get("protocol_id") is None:
                result = self._run_global_job(job)
            else:
                raise KeyError(f"Job {job['job_key']} has neither a target nor a global adapter")
            self._job_context.changed |= bool(result.pop('_watchlist_changed', False))
            return result
        finally:
            self._job_context.active = False
            if self._job_context.changed:
                self.reconcile()

    def run_jobs(
        self, jobs: list[dict[str, Any]], fail_fast: bool = False, *,
        should_stop: Callable[[], bool] | None = None,
        on_progress: Callable[[dict[str, Any]], None] | None = None,
        executor: ThreadPoolExecutor | None = None,
    ) -> dict[str, Any]:
        """Run a bounded batch fairly, sharing budgets and publishing live progress."""
        summary = {"total": len(jobs), "completed": 0, "failed": 0, "deferred": 0,
                   "skipped": 0, "inserted": 0, "duplicates": 0, "errors": ()}
        def publish(running: bool) -> None:
            summary["running"] = running
            summary["checked_at"] = _now()
            if on_progress:
                on_progress(dict(summary))
        def execute(job: dict[str, Any]) -> dict[str, Any]:
            key = (job["source_type"], job.get("target_key") or job["job_key"])
            with self._target_lock(key):
                if should_stop and should_stop():
                    return {"skipped": 1}
                if not self.store.claim_job(job["job_key"]):
                    return {"skipped": 1}
                with self._unfinished_jobs_guard:
                    self._unfinished_jobs.add(job['job_key'])
                def finish(**kwargs):
                    self.store.finish_job(job['job_key'], **kwargs)
                    with self._unfinished_jobs_guard:
                        self._unfinished_jobs.discard(job['job_key'])
                try:
                    result = self.run_job(job)
                except RequestDeferred as error:
                    finish(success=False, result={}, error=str(error)[:2000],
                        max_retry_seconds=self.config.scheduler_max_retry_seconds,
                        retry_at=datetime.fromtimestamp(math.ceil(max(error.retry_at, datetime.now(timezone.utc).timestamp())
                            + 1 + int(hashlib.sha256(job["job_key"].encode()).hexdigest()[:8], 16) % 60), tz=timezone.utc).isoformat(timespec="seconds"),
                        deferred=True)
                    return {"deferred": 1}
                except Exception as error:
                    message = f"{job['job_key']}: {error}"
                    finish(success=False, result={}, error=str(error)[:2000],
                                          max_retry_seconds=self.config.scheduler_max_retry_seconds)
                    if fail_fast:
                        raise RuntimeError(message) from error
                    return {"failed": 1, "errors": (message,)}
                finish(success=True, result=result,
                                      max_retry_seconds=self.config.scheduler_max_retry_seconds)
                return {"completed": 1, "inserted": int(result.get("inserted", 0)),
                        "duplicates": int(result.get("duplicates", 0))}
        publish(True)
        try:
            with (nullcontext(executor) if executor is not None else ThreadPoolExecutor(max_workers=self.config.scheduler_max_workers)) as pool:
                futures = [pool.submit(execute, job) for job in jobs]
                failure = None
                for future in as_completed(futures):
                    try:
                        result = future.result()
                        for key in ("completed", "failed", "deferred", "skipped", "inserted", "duplicates"):
                            summary[key] += result.get(key, 0)
                        summary["errors"] += result.get("errors", ())
                        publish(True)
                    except Exception as error:
                        failure = failure or error
                # A shared executor must finish the batch before orphan recovery;
                # otherwise a still-running worker could be scheduled twice.
                if failure is not None:
                    raise failure
        finally:
            publish(False)
        return summary

    def recover_unfinished_jobs(self) -> int:
        with self._unfinished_jobs_guard:
            keys = tuple(self._unfinished_jobs)
        if not keys:
            return 0
        recovered = self.store.recover_interrupted_jobs(job_keys=keys)
        with self._unfinished_jobs_guard:
            self._unfinished_jobs.difference_update(keys)
        return recovered

    @contextmanager
    def _target_lock(self, key: Any):
        with self._target_locks_guard:
            entry = self._target_locks.setdefault(key, [threading.RLock(), 0])
            entry[1] += 1
        try:
            with entry[0]:
                yield
        finally:
            with self._target_locks_guard:
                entry[1] -= 1
                if entry[1] == 0:
                    del self._target_locks[key]

    def poll(self, source: str = "all", fail_fast: bool = False) -> PollResult:
        """Manual refresh of one source (or everything) through the exact same
        execution path — and therefore the same request budgets — as scheduled
        work."""
        self.initialize()
        self.store.retry_blocked_targets(source_type=None if source == 'all' else source)
        jobs = [
            dict(job)
            for job in self.store.list_jobs()
            if source == "all" or job["source_type"] == source
        ]
        summary = self.run_jobs(jobs, fail_fast=fail_fast)
        self.drain_observations()
        return PollResult(summary["inserted"], summary["duplicates"], summary["errors"])

    def _run_global_job(self, job: dict[str, Any]) -> dict[str, Any]:
        adapter = self.registry.global_adapter(job["source_type"])
        if adapter is None or adapter.poll_global is None or adapter.manifest.global_job is None:
            raise KeyError(f"No adapter provides global job {job['source_type']!r}")
        scope = self.client.request_scope() if hasattr(self.client, "request_scope") else nullcontext()
        with scope:
            result, candidates = adapter.poll_global(
                GlobalContext(
                    store=self.store,
                    client=self.client,
                    settings=self.config.global_jobs.get(adapter.manifest.global_job.key, {}),
                )
            )
        self.store.record_observations(candidates)
        drain = self.drain_observations()
        return {**result, "changes": len(candidates), **drain}

    def _run_target_job(self, job: dict[str, Any]) -> dict[str, Any]:
        source_type = str(job["source_type"])
        target_key = str(job["target_key"])
        adapter = self.registry[source_type]
        is_policy = adapter.manifest.policy_payload
        programs = self.store.programs_for_target(
            source_type, target_key, _ACTIVE_PAUSED if is_policy else _ACTIVE_ONLY
        )
        distribution = [
            program
            for program in programs
            if is_policy or program["lifecycle"] == ProgramLifecycle.ACTIVE.value
        ]
        if not distribution:
            return {"skipped": "no program needs this target anymore", "changes": 0}
        config = distribution[0].get("target_config") or self.store.target_config(source_type, target_key)
        context = PollContext(
            store=self.store,
            protocol=_protocol_view(distribution[0]),
            config=config,
            client=self.client,
            source_type=source_type,
            source_key=f"{source_type}:{target_key}",
            target={"target_key": target_key, "config": config},
            programs=tuple(_protocol_view(program) for program in distribution),
            job_kind=str(job.get("job_kind", "poll")),
        )
        before = {program["id"]: self.store.latest_policy_payload(program["protocol_id"], self.registry.policy_source_types(), program_id=program['id'])
                  for program in distribution} if is_policy else {}
        scope = self.client.request_scope() if hasattr(self.client, "request_scope") else nullcontext()
        with scope:
            candidates = list(adapter.poll(context) or ())
        self.store.record_observations(candidates)
        changed = is_policy and any(
            (before[program["id"]] or {}).get("payload") !=
            (self.store.latest_policy_payload(program["protocol_id"], self.registry.policy_source_types(), program_id=program['id']) or {}).get("payload")
            for program in distribution
        )
        if changed:
            self._sync_policy_tables(distribution)
        drain = self.drain_observations()
        state = self.store.get_state(context.source_key)
        warnings = (state.payload.get('warnings', {}).get(context.job_kind, [])
                    if state is not None and source_type == 'github' else [])
        return {"changes": len(candidates), "_watchlist_changed": changed, 'warnings': warnings, **drain}

    def _sync_policy_tables(self, programs: list[dict[str, Any]]) -> None:
        """Refresh the structured scope and primacy tables from the payloads the
        adapter just committed (same journal, so they cannot disagree)."""
        policy_types = self.registry.policy_source_types()
        for program in programs:
            state = self.store.latest_policy_payload(program["protocol_id"], policy_types, program_id=program['id'])
            if state is None:
                continue
            self.store.sync_program_scope(program["id"], state["payload"])
            self.store.sync_primacy_rule(program["id"], state["payload"])

    # ------------------------------------------------------------------- drain

    def drain_observations(self) -> dict[str, int]:
        """Drain bounded transactions until the journal is empty or shutdown asks us to stop."""
        with self._drain_lock:
            total = {'inserted': 0, 'duplicates': 0, 'candidates': 0, 'processed': 0}
            while True:
                batch = self._drain_observation_batch()
                for key in total:
                    total[key] += batch[key]
                cancel = getattr(self.client, 'cancel_event', None)
                if not batch['processed'] or (cancel is not None and cancel.is_set()):
                    return total

    def _drain_observation_batch(self) -> dict[str, int]:
        """Turn journaled observations into scored events. Idempotent: observation
        fingerprints deduplicate against history, so replaying after an interrupt
        never loses a change and never duplicates one."""
        with self._drain_lock:
            pending = self.store.unprocessed_observations()
            if not pending:
                return {"inserted": 0, "duplicates": 0, "candidates": 0, "processed": 0}
            kind_specs = self.registry.kind_specs()
            contexts = self.store.observation_contexts(
                (row['protocol_id'] for row in pending), self.config.correlation_window_hours
            )
            scored: list[tuple[dict[str, Any], ScoredEvent]] = []
            for observation in pending:
                candidate = EventCandidate(
                    protocol_id=observation["protocol_id"],
                    source_key=observation["source_key"],
                    kind=observation["kind"],
                    entity=observation["entity"],
                    before=observation["before"],
                    after=observation["after"],
                    metadata=dict(observation["metadata"] or {}),
                )
                spec = validate_kind(candidate.kind, kind_specs)
                category = category_for_tags(spec.tags)
                related = contexts[candidate.protocol_id]['related']
                score, reasons = score_event(candidate, related, kind_specs)
                eligibility, evidence = ("", ())
                if category == LEAD:
                    eligibility, evidence = self._classify_lead(candidate, contexts[candidate.protocol_id])
                scored.append(
                    (
                        observation,
                        ScoredEvent(
                            candidate,
                            score,
                            reasons,
                            category=category,
                            eligibility=eligibility,
                            evidence=evidence,
                            observation_fingerprint=observation['fingerprint'],
                            detected_at=observation['observed_at'],
                        ),
                    )
                )
            result = self.store.commit_events(
                (event for _observation, event in scored), finalize=lambda: self._link_signals(scored, contexts)
            )
            result["processed"] = len(scored)
            return result

    def _classify_lead(self, candidate: EventCandidate, context: dict[str, Any] | None = None) -> tuple[str, tuple[Any, ...]]:
        """Eligibility confidence for a code-change lead, from evidence only.

        Research priority (the score) is computed separately and never mixed in.
        With no program or no changed-file evidence nothing is claimed, except an
        explicit ``unresolved_mapping`` when the change range could not be
        enumerated at all (truncated or rewritten history)."""
        changed_files = _changed_files(candidate)
        if not changed_files:
            if candidate.metadata.get("history_rewritten") or candidate.metadata.get("truncated"):
                return ELIGIBILITY_UNRESOLVED, (
                    {
                        "match": "none",
                        "reason": "change range could not be fully enumerated; mapping unresolved",
                        "entity": candidate.entity,
                    },
                )
            return "", ()
        entry = self._eligibility_context(candidate, context)
        if entry is None:
            return "", ()
        assets, primacy = entry['assets'], entry['primacy']
        classifications: list[str] = []
        evidence: list[Any] = []
        for changed in changed_files:
            eligibility, rows = classify_code_change(changed, assets, primacy)
            classifications.append(eligibility)
            evidence.extend(rows)
        return strongest_eligibility(classifications) or ELIGIBILITY_UNRESOLVED, tuple(evidence)

    def _eligibility_context(self, candidate: EventCandidate, context: dict[str, Any] | None) -> dict[str, Any] | None:
        if context is None:
            context = self.store.observation_contexts([candidate.protocol_id], self.config.correlation_window_hours)[candidate.protocol_id]
        entries = context['programs']
        platform = _metadata_platform(candidate.metadata)
        owner = candidate.metadata.get('program_id') or candidate.metadata.get('manual_program_id')
        matches = [row for row in entries if (owner is None or row['program']['id'] == owner)
                   and (platform is None or row['program']['platform'] == platform)]
        entry = matches[0] if len(matches) == 1 else None
        if entry is None:
            return None
        if 'located_assets' not in entry:
            entry['located_assets'] = [{**row, 'location': code_location(row.get('url'))} for row in entry['assets']]
        return {**entry, 'assets': list(entry['located_assets'])}

    def _link_signals(self, scored: list[tuple[dict[str, Any], ScoredEvent]], contexts: dict[str, Any] | None = None) -> None:
        """Link scope signals to leads on asset/repository/path evidence.

        A signal links to a lead only when the signal's asset location matches a
        file the lead saw change — never on protocol identity or time windows."""
        leads = {}
        signal_kinds = ('BOUNTY_SCOPE_ADDED', 'BOUNTY_SCOPE_UPDATED', 'BOUNTY_SCOPE_REMOVED')
        signal_ids = self.store.event_ids_for_fingerprints(observation['fingerprint'] for observation, event in scored if event.candidate.kind in signal_kinds)
        for observation, event in scored:
            if event.candidate.kind not in (
                "BOUNTY_SCOPE_ADDED",
                "BOUNTY_SCOPE_UPDATED",
                "BOUNTY_SCOPE_REMOVED",
            ):
                continue
            old_asset = event.candidate.metadata.get("asset_before", event.candidate.before)
            new_asset = event.candidate.metadata.get("asset_after", event.candidate.after)
            entries = [normalize_entry(value) for value in (old_asset, new_asset)
                       if isinstance(value, dict) and value.get("identity")]
            if not entries:
                continue
            signal_id = signal_ids.get(observation['fingerprint'])
            if signal_id is None:
                continue
            eligibility_context = self._eligibility_context(event.candidate, contexts.get(event.candidate.protocol_id) if contexts else None)
            if eligibility_context is None:
                continue
            assets = eligibility_context['assets']
            # Apply this signal's before/after even if scope refresh has not run yet.
            old_entry = old_asset
            if isinstance(old_entry, dict):
                old_location = code_location(old_entry.get("url"))
                assets = [row for row in assets if not (
                    row.get("identity") == old_entry.get("identity")
                    or (old_location and row.get("location") == old_location)
                )]
            if isinstance(new_asset, dict):
                entry = normalize_entry(new_asset)
                assets.append({**entry, "location": code_location(entry.get("url"))})
            primacy = eligibility_context['primacy']
            protocol_id = event.candidate.protocol_id
            if protocol_id not in leads:
                leads[protocol_id] = self.store.leads_for_protocol(protocol_id)
            for lead in leads[protocol_id]:
                if _metadata_platform(lead.get("metadata")) != _metadata_platform(event.candidate.metadata):
                    continue
                if event.candidate.metadata.get('program_id') is not None and lead.get('metadata', {}).get('program_id') != event.candidate.metadata['program_id']:
                    continue
                changed_files = _changed_files_dict(lead.get("metadata") or {})
                matched = False
                for entry in entries:
                    entry = {**entry, "location": code_location(entry.get("url"))}
                    for changed in changed_files:
                        evidence = asset_match_evidence(entry, changed)
                        if evidence is not None:
                            matched = True
                            self.store.link_events(lead["id"], signal_id, {
                                "reason": event.candidate.kind, **evidence
                            })
                if not matched:
                    continue
                classifications, evidence = [], []
                for changed in changed_files:
                    eligibility, rows = classify_code_change(changed, assets, primacy)
                    classifications.append(eligibility)
                    evidence.extend(rows)
                self.store.update_event_classification(
                    lead["id"], eligibility=strongest_eligibility(classifications) or ELIGIBILITY_UNRESOLVED,
                    evidence=evidence,
                )



def _protocol_view(program: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": program["protocol_id"],
        "name": program.get("name") or program["protocol_id"],
        "program_id": program["id"],
        "platform": program.get("platform"),
        "external_id": program.get("external_id"),
        "priority": program.get("priority", "normal"),
        "lifecycle": program.get("lifecycle"),
        "target_config": program.get("target_config", {}),
    }


def _changed_files(candidate: EventCandidate) -> list[dict[str, Any]]:
    return _changed_files_dict(candidate.metadata)


def _changed_files_dict(metadata: Any) -> list[dict[str, Any]]:
    if not isinstance(metadata, dict):
        return []
    files = metadata.get("changed_files")
    return [dict(item) for item in files] if isinstance(files, list) else []


def _metadata_platform(metadata: Any) -> str | None:
    if isinstance(metadata, dict):
        platform = metadata.get("platform")
        return str(platform) if platform else None
    return None


_PRIORITY_ORDER = {"high": 0, "normal": 1, "dormant": 2}


def _urgest_priority(programs: list[dict[str, Any]]) -> str:
    priorities = [str(program.get("priority", "normal")).lower() for program in programs]
    return min(priorities, key=lambda name: _PRIORITY_ORDER.get(name, 1)) if priorities else "normal"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
