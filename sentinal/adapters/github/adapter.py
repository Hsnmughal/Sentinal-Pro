from __future__ import annotations

import fnmatch
import os
import re
from typing import Any
from urllib.parse import quote

from ...core.contract import PollContext
from ...core.http import header, RequestDeferred, http_status
from ...core.models import EventCandidate


API_ROOT = "https://api.github.com"

#: Changes under these patterns are documentation, tests, fixtures or scripts and
#: never produce leads on their own. Overridable per target with ``ignore_paths``;
#: ``include_paths`` (when set) whitelists runtime paths instead.
DEFAULT_IGNORE_PATHS: tuple[str, ...] = (
    "docs/*",
    "doc/*",
    "documentation/*",
    "*.md",
    "*.mdx",
    "*.rst",
    "README*",
    "CHANGELOG*",
    "LICENSE*",
    "test/*",
    "tests/*",
    "spec/*",
    "__tests__/*",
    "fixtures/*",
    "testdata/*",
    "mocks/*",
    "scripts/*",
    "script/*",
    "tooling/*",
    ".github/*",
    ".circleci/*",
    "*.sh",
    "*.bash",
    "*.ps1",
    "*.bat",
    "Makefile",
    "justfile",
)

#: The compare endpoint caps its file list; beyond this we must assume truncation
#: and fall back to per-commit file lists so nothing goes silently missing.
_COMPARE_FILE_CAP = 300
_COMPARE_COMMIT_PAGE = 100
#: Per-commit fallback fan-out bound; larger ranges stay flagged as truncated.
_FALLBACK_COMMIT_CAP = 60
#: A repository key is ``owner/repo``. Scope text is remote input, so anything that
#: does not have that shape is skipped rather than handed to the GitHub API.
_REPOSITORY_KEY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")


def derive_targets(config: Any) -> list[tuple[str, Any]]:
    """Split one program's GitHub config into one target per unique repository/ref.

    The target key identifies the repository/ref across programs, so a repository
    shared by several programs is polled exactly once and its observations are
    distributed to every associated program.
    """
    if not isinstance(config, dict):
        return []
    base = {key: value for key, value in config.items() if key != "repositories"}
    entries = config.get("repositories")
    if not entries:
        entries = [config.get("repository")]
    targets: list[tuple[str, Any]] = []
    seen: set[str] = set()
    for item in entries:
        if isinstance(item, dict):
            target = {**base, **item}
        else:
            target = dict(base)
            target["repository"] = item
        repository = str(target.get("repository") or "").strip()
        if not _REPOSITORY_KEY.fullmatch(repository):
            continue
        target["repository"] = repository
        branch = str(target.get("branch") or "").strip()
        key = f"{repository}#{branch}" if branch else repository
        if key in seen:
            continue
        seen.add(key)
        targets.append((key, target))
    return targets


def poll(context: PollContext) -> list[EventCandidate]:
    """Poll one repository/ref once and distribute observations to its programs.

    ``job_kind="release"`` runs only the (slower, separately scheduled) release
    check; the default kind compares everything since the previous successfully
    processed SHA and emits leads only for relevant runtime-code changes.
    """
    config = context.target["config"] if context.target else context.config
    if not config:
        return []
    programs = tuple(context.programs) or (context.protocol,)
    if context.job_kind == "release":
        return _poll_release(context, config, programs)
    return _poll_code(context, config, programs)


def _previous_state(context, repository, programs, state_key):
    """Adopt an existing per-program checkpoint when switching to shared polling."""
    previous = context.store.get_state(state_key)
    if previous is not None and previous.payload.get("head"):
        return previous
    branch = str(((context.target or {}).get("config") or context.config or {}).get("branch") or "")
    legacy = [context.store.get_state(f"github:{program['id']}:{repository}") for program in programs]
    legacy = [state for state in legacy if state and state.payload.get("head")
              and (not branch or state.payload.get("branch") == branch)]
    if not legacy:
        return previous
    latest = max(legacy, key=lambda state: state.updated_at)
    payload = {**latest.payload, "last_processed_sha": latest.payload.get("head"),
               "release_initialized": "release" in latest.payload}
    if previous and previous.payload.get("release_initialized"):
        payload["release"] = previous.payload.get("release", {})
        payload["release_initialized"] = True
    context.store.save_state(source_key=state_key, protocol_id=_state_protocol(programs),
                             source_type=context.source_type, payload=payload,
                             cursor=latest.cursor, etag=latest.etag)
    return context.store.get_state(state_key)


# ---------------------------------------------------------------------- code path


def _poll_code(
    context: PollContext, config: dict[str, Any], programs: tuple[dict[str, Any], ...]
) -> list[EventCandidate]:
    store = context.store
    client = context.client
    programs = tuple({**program, "target_config": program.get("target_config") or config}
                     for program in programs)
    repository = str(config["repository"])
    production_ref = str(config.get("production_ref", ""))
    state_key = context.source_key if context.target else f"github:{repository}"
    previous = _previous_state(context, repository, programs, state_key)
    old_payload = previous.payload if previous else {}

    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    token_env = str(config.get("token_env", "GITHUB_TOKEN"))
    if token := os.getenv(token_env):
        headers["Authorization"] = f"Bearer {token}"
    branch = str(config.get('branch') or '')
    repository_etag = old_payload.get('repository_etag')
    if not branch:
        metadata_headers = dict(headers)
        if repository_etag:
            metadata_headers['If-None-Match'] = repository_etag
        metadata = client.get_json(f"{API_ROOT}/repos/{repository}", metadata_headers)
        _record_rate_limit(store, metadata.headers)
        if metadata.status == 304:
            branch = old_payload.get('branch')
        else:
            branch = metadata.payload.get('default_branch')
        if not isinstance(branch, str) or not branch.strip():
            raise RuntimeError('Repository default branch is unavailable; checks will retry')
        repository_etag = header(metadata.headers, 'etag') or (repository_etag if metadata.status == 304 else None)
    branch_headers = dict(headers)
    if previous and previous.etag and old_payload.get('branch') == branch:
        branch_headers["If-None-Match"] = previous.etag

    branch_url = f"{API_ROOT}/repos/{repository}/commits/{quote(branch, safe='')}"
    try:
        branch_response = client.get_json(branch_url, branch_headers)
    except RuntimeError as error:
        if http_status(error) != 404:
            raise
        # An absent branch is not evidence that the repository has disappeared.
        metadata = client.get_json(f'{API_ROOT}/repos/{repository}', headers)
        default_branch = metadata.payload.get('default_branch')
        if config.get('branch') or not default_branch or default_branch == branch:
            raise RuntimeError(f'Tracked branch {branch!r} is unavailable; check branch configuration') from error
        branch = str(default_branch)
        try:
            branch_response = client.get_json(f'{API_ROOT}/repos/{repository}/commits/{quote(branch, safe="")}', headers)
        except RuntimeError as missing:
            if http_status(missing) != 404:
                raise
            raise RuntimeError('The repository default branch is unavailable; repository checks will retry') from missing
    _record_rate_limit(store, branch_response.headers)
    if branch_response.status == 304:
        head = old_payload.get("head")
        head_url = old_payload.get("head_url")
        message = old_payload.get("message", "")
    else:
        head = branch_response.payload["sha"]
        head_url = branch_response.payload.get("html_url")
        message = branch_response.payload.get("commit", {}).get("message", "")

    previous_sha = old_payload.get("last_processed_sha")
    events: list[EventCandidate] = []
    comparison: dict[str, Any] = old_payload.get("comparison") or {}
    production_diff: dict[str, Any] = old_payload.get("production_diff") or {}
    truncated = False
    if previous and head and previous_sha and head != previous_sha:
        comparison, files, truncated = _compare(
            repository, str(previous_sha or head), str(head), headers, client, store
        )
        if comparison.get("history_rewritten"):
            # The range cannot be enumerated at all: say so explicitly rather
            # than silently dropping whatever changed between the SHAs.
            events.extend(
                _code_events(
                    programs,
                    repository,
                    str(previous_sha),
                    str(head),
                    branch,
                    message,
                    head_url,
                    comparison,
                    [],
                    True,
                )
            )
        else:
            relevant = files
            if relevant or truncated:
                changed_files = [_file_summary(item, repository) for item in relevant]
                events.extend(
                    _code_events(
                        programs,
                        repository,
                        str(previous_sha),
                        str(head),
                        branch,
                        message,
                        head_url,
                        comparison,
                        changed_files,
                        truncated,
                    )
                )

    production_diffs = dict(old_payload.get("production_diffs") or {})
    warnings = []
    ref_states = dict(old_payload.get("production_refs") or {})
    by_ref: dict[str, list[dict[str, Any]]] = {}
    for program in programs:
        ref = str((program.get("target_config") or config).get("production_ref") or "")
        if ref:
            by_ref.setdefault(ref, []).append(program)
    for ref, ref_programs in by_ref.items():
        prior_ref = ref_states.get(ref) or {}
        ref_headers = dict(headers)
        if prior_ref.get("etag"):
            ref_headers["If-None-Match"] = prior_ref["etag"]
        try:
            response = client.get_json(f"{API_ROOT}/repos/{repository}/commits/{quote(ref, safe='')}", ref_headers)
        except RuntimeError as error:
            if http_status(error) != 404:
                raise
            warnings.append(f'Production reference {ref!r} is unavailable (404); repository monitoring continues.')
            continue
        _record_rate_limit(store, response.headers)
        base_sha = prior_ref.get("sha") if response.status == 304 else response.payload["sha"]
        ref_states[ref] = {"sha": base_sha, "etag": header(response.headers, "etag") or prior_ref.get("etag")}
        if not base_sha or not head:
            continue
        old_diff = production_diffs.get(ref) or (old_payload.get("production_diff", {}) if ref == production_ref else {})
        if old_diff.get("base_sha") == base_sha and old_diff.get("head_sha") == head and not old_diff.get("truncated"):
            continue
        production_diff, files, incomplete = _compare(repository, str(base_sha), str(head), headers, client, store)
        production_diff = {**production_diff, "truncated": incomplete}
        if previous and old_diff != production_diff:
            events.extend(_production_events(tuple(ref_programs), repository, ref, branch, old_diff,
                          production_diff, [_file_summary(item, repository) for item in files]))
        production_diffs[ref] = production_diff

    snapshot: dict[str, Any] = {
        "repository": repository,
        "branch": branch,
        'repository_etag': repository_etag,
        "head": head,
        "head_url": head_url,
        "message": message,
        "last_processed_sha": (old_payload.get("last_processed_sha") if truncated and not comparison.get("history_rewritten") else head),
        "comparison": {**comparison, "truncated": truncated} if comparison else {},
        # The release check shares this state row; never drop what it recorded.
        "release": old_payload.get("release") or {},
        "release_initialized": bool(old_payload.get("release_initialized")),
        'warnings': {**old_payload.get('warnings', {}), 'poll': warnings},
    }
    snapshot["production_refs"] = ref_states
    snapshot["production_diffs"] = production_diffs
    if production_ref:
        snapshot["production_ref"] = production_ref
        snapshot["production_diff"] = production_diffs.get(production_ref, {})

    store.save_state(
        source_key=state_key,
        protocol_id=_state_protocol(programs),
        source_type=context.source_type,
        payload=snapshot,
        cursor=head,
        etag=header(branch_response.headers, "etag") or (previous.etag if previous else None),
        events=events,
    )
    return events


def _code_events(
    programs: tuple[dict[str, Any], ...],
    repository: str,
    previous_sha: str,
    head: str,
    branch: str,
    message: str,
    head_url: str | None,
    comparison: dict[str, Any],
    changed_files: list[dict[str, Any]],
    truncated: bool,
) -> list[EventCandidate]:
    """One lead per associated program for a relevant runtime-code change.

    The source key stays per program (``github:<protocol>:<repo>``) so historical
    fingerprints keep their meaning while the underlying poll is shared.
    """
    events: list[EventCandidate] = []
    for program in programs:
        program_files = _relevant_files(changed_files, program.get("target_config") or {})
        if not program_files and not (truncated):
            continue
        events.append(
            EventCandidate(
                protocol_id=program["id"],
                source_key=f"github:{program['id']}:{repository}",
                kind="GITHUB_HEAD_CHANGED",
                entity=repository,
                before=previous_sha,
                after=head,
                metadata={
                    "branch": branch,
                    "message": message,
                    "url": head_url,
                    "compare_url": comparison.get("url"),
                    "changed_files": program_files,
                    "truncated": truncated,
                    "history_rewritten": bool(comparison.get("history_rewritten")),
                    "repository": repository,
                    "platform": program.get("platform"),
                    **({'program_id': program['program_id']} if program.get('program_id') is not None else {}),
                },
            )
        )
    return events


def _production_events(
    programs: tuple[dict[str, Any], ...],
    repository: str,
    production_ref: str,
    branch: str,
    old_diff: dict[str, Any],
    new_diff: dict[str, Any],
    changed_files: list[dict[str, Any]],
) -> list[EventCandidate]:
    events: list[EventCandidate] = []
    for program in programs:
        program_files = _relevant_files(changed_files, program.get("target_config") or {})
        if not program_files and not (new_diff.get("truncated") or new_diff.get("history_rewritten")):
            continue
        events.append(
            EventCandidate(
                protocol_id=program["id"],
                source_key=f"github:{program['id']}:{repository}",
                kind="GITHUB_PRODUCTION_DIFF_CHANGED",
                entity=f"{repository}:{production_ref}...{branch}",
                before=old_diff,
                after=new_diff,
                metadata={
                    "security_paths": [item["path"] for item in program_files],
                    "changed_files": program_files,
                    "truncated": bool(new_diff.get("truncated")),
                    "history_rewritten": bool(new_diff.get("history_rewritten")),
                    "repository": repository,
                    "platform": program.get("platform"),
                    **({'program_id': program['program_id']} if program.get('program_id') is not None else {}),
                },
            )
        )
    return events


# ------------------------------------------------------------------- release path


def _poll_release(
    context: PollContext, config: dict[str, Any], programs: tuple[dict[str, Any], ...]
) -> list[EventCandidate]:
    store = context.store
    client = context.client
    repository = str(config["repository"])
    state_key = context.source_key if context.target else f"github:{repository}"
    previous = _previous_state(context, repository, programs, state_key)
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    token_env = str(config.get("token_env", "GITHUB_TOKEN"))
    if token := os.getenv(token_env):
        headers["Authorization"] = f"Bearer {token}"
    release = _latest_release(repository, headers, client)
    old_payload = previous.payload if previous else {}
    events: list[EventCandidate] = []
    old_release = old_payload.get("release") or {}
    release_pending = False
    warnings = []
    if previous and (old_payload.get("release_initialized") or old_release.get("tag")) and old_release.get("tag") != release.get("tag"):
        if old_release.get("tag") and release.get("tag"):
            try:
                base = client.get_json(f"{API_ROOT}/repos/{repository}/commits/{quote(old_release['tag'], safe='')}", headers)
                head = client.get_json(f"{API_ROOT}/repos/{repository}/commits/{quote(release['tag'], safe='')}", headers)
            except RuntimeError as error:
                if http_status(error) != 404:
                    raise
                warnings.append('A release tag is unavailable (404); release comparison will retry. Repository monitoring continues.')
                comparison, files, incomplete = {}, [], True
            else:
                comparison, files, incomplete = _compare(repository, base.payload["sha"], head.payload["sha"], headers, client, store)
            release_pending = incomplete
            changes = [_file_summary(item, repository) for item in files]
            for program in programs:
                relevant = _relevant_files(changes, program.get("target_config") or config)
                if not relevant and not incomplete:
                    continue
                events.append(EventCandidate(
                    protocol_id=program["id"], source_key=f"github:{program['id']}:{repository}",
                    kind="GITHUB_RELEASE_CHANGED", entity=repository, before=old_release, after=release,
                    metadata={"repository": repository, "changed_files": relevant,
                              "truncated": incomplete, "compare_url": comparison.get("url"),
                              "platform": program.get("platform")},
                ))
                if program.get('program_id') is not None:
                    events[-1].metadata['program_id'] = program['program_id']
        else:
            boundary = 'created' if release.get('tag') else 'removed'
            reason = ('No previous published release exists for a file comparison.' if boundary == 'created'
                      else 'No current published release exists for a file comparison.')
            for program in programs:
                events.append(EventCandidate(protocol_id=program['id'],
                    source_key=f"github:{program['id']}:{repository}", kind='GITHUB_RELEASE_CHANGED',
                    entity=repository, before=old_release, after=release,
                    metadata={'repository':repository, 'platform':program.get('platform'),
                        **({'program_id':program['program_id']} if program.get('program_id') is not None else {}),
                        'release_boundary':boundary, 'changed_files':[], 'patch_range_unavailable':True,
                        'patch_unavailable_reason':reason, 'truncated':False}))
    store.save_state(
        source_key=state_key,
        protocol_id=_state_protocol(programs),
        source_type=context.source_type,
        payload={**old_payload, "repository": repository, "release": old_release if release_pending else release, "release_initialized": True,
                 'warnings': {**old_payload.get('warnings', {}), 'release': warnings}},
        cursor=old_payload.get("head"),
        etag=previous.etag if previous else None,
        events=events,
    )
    return events


def _latest_release(repository: str, headers: dict[str, str], client: Any) -> dict[str, Any]:
    try:
        response = client.get_json(f"{API_ROOT}/repos/{repository}/releases/latest", headers)
    except RuntimeError as error:
        if http_status(error) == 404:
            # An inaccessible repository also returns 404 here. Only record an
            # absent release after proving the repository itself is accessible.
            client.get_json(f'{API_ROOT}/repos/{repository}', headers)
            return {}
        raise
    release = response.payload
    return {
        "tag": release.get("tag_name"),
        "published_at": release.get("published_at"),
        "url": release.get("html_url"),
    }


# -------------------------------------------------------------------- comparison


def _compare(
    repository: str,
    base: str,
    head: str,
    headers: dict[str, str],
    client: Any,
    store: Any,
    resolved_head: str | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]], bool]:
    """Compare ``base...head``, returning (summary, files, truncated).

    Production refs are resolved by the caller; comparisons use immutable SHA pairs.
    Commit lists are
    paginated beyond the compare endpoint's cap; when the file list is truncated
    (or history was rewritten under us) the per-commit file lists are used so
    renames and moves stay visible instead of silently vanishing.
    """
    # Older cache entries could incorrectly claim truncated ranges were complete.
    cache_key = f"compare-v3|{repository}|{base}|{head}"
    if resolved_head:
        cache_key += f"|@{resolved_head}"
    cached = store.get_compare_cache(cache_key)
    if cached is not None:
        return cached["summary"], cached["files"], bool(cached.get("truncated"))

    url = f"{API_ROOT}/repos/{repository}/compare/{quote(base, safe='')}...{quote(head, safe='')}"
    try:
        response = client.get_json(f"{url}?per_page={_COMPARE_COMMIT_PAGE}&page=1", headers)
    except RuntimeError as error:
        if http_status(error) in (404, 409):
            # Rewritten history or no common ancestor: the range cannot be listed.
            summary = {
                "base_sha": base,
                "head_sha": head,
                "history_rewritten": True,
                "url": None,
                "files": [],
            }
            return summary, [], True
        raise
    payload = response.payload
    commits = list(payload.get("commits") or [])
    total_commits = int(payload.get("total_commits") or len(commits))
    page = 2
    while len(commits) < total_commits and len(commits) < _FALLBACK_COMMIT_CAP:
        more = client.get_json(f"{url}?per_page={_COMPARE_COMMIT_PAGE}&page={page}", headers)
        batch = more.payload.get("commits") or []
        if not batch:
            break
        existing = {item.get("sha") for item in commits}
        added = [item for item in batch if item.get("sha") not in existing]
        if not added:
            break
        commits.extend(added)
        page += 1
    files = [{**_file_entry(item), 'patch_scope': 'comparison',
              'patch_before': base, 'patch_after': head} for item in payload.get("files", [])]
    truncated = len(files) >= _COMPARE_FILE_CAP or len(commits) < total_commits
    if truncated:
        per_commit, complete = _files_from_commits(repository, commits, headers, client, store)
        files = _merge_files(files, per_commit)
        truncated = not (complete and len(commits) >= total_commits)
    summary = {
        "base_sha": (payload.get("base_commit") or {}).get("sha") or base,
        "head_sha": head,
        "history_rewritten": payload.get("status") in {"behind", "diverged"},
        "ahead_by": payload.get("ahead_by", 0),
        "behind_by": payload.get("behind_by", 0),
        "total_commits": total_commits,
        "files": files,
        "url": payload.get("html_url"),
    }
    if not truncated:
        store.set_compare_cache(cache_key, {"summary": summary, "files": files, "truncated": truncated})
    return summary, files, truncated


def _files_from_commits(
    repository: str, commits: list[dict[str, Any]], headers: dict[str, str], client: Any, store: Any = None
) -> tuple[list[dict[str, Any]], bool]:
    merged: list[dict[str, Any]] = []
    complete = len(commits) <= _FALLBACK_COMMIT_CAP
    for commit in commits[:_FALLBACK_COMMIT_CAP]:
        sha = commit.get("sha")
        if not sha:
            complete = False
            continue
        cache_key = f"commit-files-v2|{repository}|{sha}"
        cached = store.get_compare_cache(cache_key) if store else None
        if cached is not None:
            merged.extend(cached)
            continue
        commit_files = []
        commit_complete = False
        page = 1
        count = 0
        while True:
            try:
                response = client.get_json(
                    f"{API_ROOT}/repos/{repository}/commits/{sha}?per_page=100&page={page}", headers
                )
            except RequestDeferred as error:
                if error.reason == "check time budget":
                    return merged, False
                raise
            except RuntimeError:
                complete = False
                break
            batch = response.payload.get("files", [])
            parents = response.payload.get('parents')
            parent = parents[0].get('sha') if isinstance(parents, list) and parents else None
            provenance_known = isinstance(parents, list) and (not parents or bool(parent))
            entries = [{**_file_entry(item), 'patch_scope': 'commit',
                        'patch_before': parent, 'patch_after': sha,
                        **({} if provenance_known else {'patch': '',
                           'patch_unavailable_reason': 'Commit parent revision was not supplied by the source'})}
                       for item in batch]
            merged.extend(entries)
            commit_files.extend(entries)
            count += len(batch)
            if count >= 3000:
                complete = False
                break
            next_page = 'rel="next"' in (header(response.headers, "link") or "")
            if not next_page and len(batch) < 100:
                commit_complete = True
                break
            if not batch:
                complete = False
                break
            page += 1
        if commit_complete and store:
            store.set_compare_cache(cache_key, commit_files)
    return merged, complete


def _merge_files(
    listed: list[dict[str, Any]], per_commit: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    # Range patches already cover all commits for their filenames. For omitted
    # filenames retain EVERY individual commit patch with its real revisions.
    # Combining statuses/patches by filename would fabricate a base/head diff.
    listed_names = {item['filename'] for item in listed}
    return [*listed, *(dict(item) for item in per_commit if item['filename'] not in listed_names)]


def _file_entry(file: dict[str, Any]) -> dict[str, Any]:
    return {
        "filename": file.get("filename"),
        "previous_filename": file.get("previous_filename"),
        "status": file.get("status"),
        "additions": file.get("additions", 0),
        "deletions": file.get("deletions", 0),
        "changes": file.get("changes", 0),
        "patch": str(file.get("patch") or "")[:32768],
        "patch_truncated": bool(file.get("patch_truncated")) or len(str(file.get("patch") or "")) > 32768,
    }


def _file_summary(file: dict[str, Any], repository: str) -> dict[str, Any]:
    return {
        "repo": repository,
        "path": file.get("filename"),
        "previous_path": file.get("previous_filename"),
        "status": file.get("status"),
        "additions": file.get("additions", 0),
        "deletions": file.get("deletions", 0),
        'patch_scope': file.get('patch_scope', 'comparison'),
        "patch": str(file.get("patch") or "")[:32768],
        "patch_truncated": bool(file.get("patch_truncated")) or len(str(file.get("patch") or "")) > 32768,
        **{key: file[key] for key in ('patch_scope', 'patch_before', 'patch_after', 'patch_unavailable_reason') if key in file},
    }


# ----------------------------------------------------------------- path filtering


_RUNTIME_EXTENSIONS = frozenset({
    ".sol", ".vy", ".rs", ".go", ".move", ".cairo", ".py", ".js", ".jsx",
    ".ts", ".tsx", ".c", ".h", ".cpp", ".hpp", ".cc", ".java", ".kt", ".wasm",
})
_NOISE_DIRECTORIES = frozenset({
    "test", "tests", "__tests__", "spec", "specs", "fixtures", "testdata", "mocks",
    "docs", "doc", "documentation", "scripts", "script", "deploy", "deployments", "tooling",
})


def _relevant_files(files: list[dict[str, Any]], config: dict[str, Any]) -> list[dict[str, Any]]:
    ignore_paths = tuple(config.get("ignore_paths", DEFAULT_IGNORE_PATHS))
    include_paths = tuple(config.get("include_paths") or ())
    def runtime(name: str) -> bool:
        name = name.lower()
        parts = name.split("/")
        filename = parts[-1]
        if any(part in _NOISE_DIRECTORIES for part in parts[:-1]):
            return False
        if any(token in filename for token in (".test.", ".spec.", ".t.sol", ".s.sol")) or filename.startswith("test_"):
            return False
        return any(filename.endswith(extension) for extension in _RUNTIME_EXTENSIONS)
    relevant = []
    for file in files:
        names = [name for name in (file.get("filename") or file.get("path"),
                 file.get("previous_filename") or file.get("previous_path")) if name]
        if include_paths:
            keep = any(_matches(name, include_paths) for name in names)
        else:
            keep = any(runtime(name) and not _matches(name, ignore_paths) for name in names)
        if keep:
            relevant.append(file)
    return relevant


def _matches(path: str, patterns: tuple[str, ...]) -> bool:
    return any(fnmatch.fnmatch(path, pattern) or fnmatch.fnmatch(path.rsplit("/", 1)[-1], pattern) for pattern in patterns)


# ------------------------------------------------------------------------ helpers


def _state_protocol(programs: tuple[dict[str, Any], ...]) -> str:
    return str(programs[0]["id"]) if programs else "unattached"


def _record_rate_limit(store: Any, headers: dict[str, str]) -> None:
    limit = header(headers, "x-ratelimit-limit")
    remaining = header(headers, "x-ratelimit-remaining")
    reset = header(headers, "x-ratelimit-reset")
    if limit or remaining or reset:
        store.set_runtime_status(
            "github_rate_limit",
            {"limit": _integer(limit), "remaining": _integer(remaining), "reset_epoch": _integer(reset)},
        )


def _integer(value: str | None) -> int | None:
    try:
        return int(value) if value is not None else None
    except ValueError:
        return None
